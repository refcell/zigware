//! commonware's `journal/contiguous/tests.rs` in-flight sync tests, run on both journals with
//! `runtime.storage.mocks.DelayedSync` holding started syncs (`DelayedSyncContext`).
//!
//! commonware asserts an operation is blocked with `now_or_never().is_none()`. Here the
//! operation runs as a spawned task on the deterministic runtime; the test sleeps, checks the
//! task has not finished, releases the parked syncs, and joins.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const variable = @import("variable.zig");

const gpa = testing.allocator;
const Context = runtime.deterministic.Context;
const DelayedSync = runtime.storage.mocks.DelayedSync;
const DelayedSynced = runtime.storage.mocks.DelayedSynced;

/// One journal kind of the shared suite.
fn Kind(comptime variable_kind: bool) type {
    return struct {
        pub const Journal = if (variable_kind) variable.Journal(u64) else fixed.Journal(u64);

        pub fn open(
            storage: runtime.storage.Storage,
            per_blob: u64,
            cache: *paged.CacheRef,
        ) !Journal {
            if (variable_kind) return Journal.init(gpa, storage, .{
                .partition = "start-sync",
                .items_per_section = per_blob,
                .codec_config = {},
                .cache_ref = cache,
                .write_buffer = 2048,
                .replay_buffer = 2048,
            });
            return Journal.init(gpa, storage, .{
                .partition = "start-sync",
                .items_per_blob = per_blob,
                .cache_ref = cache,
                .write_buffer = 2048,
                .replay_buffer = 2048,
            });
        }
    };
}

/// Memory storage behind a `DelayedSynced` wrapper, plus a page cache.
const Fixture = struct {
    inner: runtime.storage.memory.Storage,
    pending: DelayedSync,
    delayed: DelayedSynced,
    cache: paged.CacheRef,

    fn init(self: *Fixture, ctx: Context) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
        self.cache = try paged.CacheRef.init(gpa, 44, 8);
    }

    fn deinit(self: *Fixture) void {
        self.cache.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    fn storage(self: *Fixture) runtime.storage.Storage {
        return self.delayed.storage();
    }
};

fn append_four(journal: anytype) !void {
    for (0..4) |i| _ = try journal.append(@intCast(i));
    try testing.expectEqual(@as(u64, 4), journal.size());
}

fn waiting(ctx: Context, completion: runtime.storage.Completion) anyerror!void {
    _ = ctx;
    try completion.wait_release();
}

fn Suite(comptime K: type) type {
    return struct {
        fn starting(
            ctx: Context,
            journal: *K.Journal,
            done: *bool,
        ) anyerror!runtime.storage.Completion {
            _ = ctx;
            const completion = try journal.start_sync();
            done.* = true;
            return completion;
        }

        fn pruning(ctx: Context, journal: *K.Journal, done: *bool) anyerror!void {
            _ = ctx;
            _ = try journal.prune(3);
            done.* = true;
        }

        /// A sync handle must not block journal use while the backend sync is pending.
        fn overlaps_work(ctx: Context) !void {
            var f: Fixture = undefined;
            try f.init(ctx);
            defer f.deinit();
            var journal = try K.open(f.storage(), 10, &f.cache);
            try append_four(&journal);
            const completion = try journal.start_sync();
            try testing.expect(f.pending.starts() >= 1);
            try testing.expectEqual(@as(u64, 0), f.pending.completions());
            const waiter = try ctx.child("await_sync").spawn(waiting, .{completion});
            while (f.pending.entered() == 0) try ctx.sleep(.fromMilliseconds(1));
            // Append and read complete while the sync is in flight.
            _ = try journal.append(999);
            try testing.expectEqual(@as(u64, 0), try journal.read(0));
            try testing.expectEqual(@as(u64, 0), f.pending.completions());
            f.pending.unblock();
            try try waiter.join();
            try testing.expect(f.pending.completions() >= 1);
            // The mid-sync append is durable after the next sync.
            try (try journal.start_sync()).wait_release();
            journal.deinit();
            var reopened = try K.open(f.storage(), 10, &f.cache);
            defer reopened.deinit();
            try testing.expectEqual(@as(u64, 5), reopened.get_bounds().end);
            for (0..4) |i| try testing.expectEqual(@as(u64, i), try reopened.read(i));
            try testing.expectEqual(@as(u64, 999), try reopened.read(4));
        }

        /// A new sync waits for the prior one before starting a backend sync.
        fn waits_for_prior(ctx: Context) !void {
            var f: Fixture = undefined;
            try f.init(ctx);
            defer f.deinit();
            var journal = try K.open(f.storage(), 10, &f.cache);
            defer journal.deinit();
            try append_four(&journal);
            const first = try journal.start_sync();
            const starts_before = f.pending.starts();
            _ = try journal.append(999);
            var done = false;
            const call = try ctx.child("start").spawn(starting, .{ &journal, &done });
            try ctx.sleep(.fromMilliseconds(10));
            try testing.expect(!done); // start_sync proceeded while the prior sync was pending.
            try testing.expectEqual(starts_before, f.pending.starts());
            f.pending.unblock();
            const second = try try call.join();
            try first.wait_release();
            try second.wait_release();
        }

        /// A sync completes only once the tail and its predecessor's rollover sync are durable.
        fn overlaps_predecessor_and_tail(ctx: Context) !void {
            var f: Fixture = undefined;
            try f.init(ctx);
            defer f.deinit();
            var journal = try K.open(f.storage(), 3, &f.cache);
            defer journal.deinit();
            try append_four(&journal);
            const starts_before = f.pending.starts();
            try testing.expect(starts_before > 0);
            const completion = try journal.start_sync();
            defer completion.release();
            try testing.expect(f.pending.starts() > starts_before);
            try testing.expect(f.pending.parked() >= 2);
            // Releasing the tail alone does not complete it: it joins the predecessor.
            f.pending.last().release({});
            try testing.expect(completion.is_pending());
            f.pending.unblock();
            try completion.wait();
        }

        /// A failed in-flight sync surfaces through its completion and the next durability op.
        fn failure_propagates(ctx: Context) !void {
            var f: Fixture = undefined;
            try f.init(ctx);
            defer f.deinit();
            var journal = try K.open(f.storage(), 10, &f.cache);
            defer journal.deinit();
            try append_four(&journal);
            f.pending.arm_fail();
            f.pending.unblock();
            const completion = try journal.start_sync();
            try testing.expectError(error.Io, completion.wait_release());
            const starts_before = f.pending.starts();
            try testing.expectError(error.Io, journal.commit());
            // The surfaced error is the retained failure, not a fresh sync's.
            try testing.expectEqual(starts_before, f.pending.starts());
        }

        /// Prune drains the in-flight rollover sync before mutating storage.
        fn prune_waits(ctx: Context) !void {
            var f: Fixture = undefined;
            try f.init(ctx);
            defer f.deinit();
            var journal = try K.open(f.storage(), 3, &f.cache);
            defer journal.deinit();
            try append_four(&journal);
            try testing.expect(f.pending.starts() > 0);
            var done = false;
            const prune = try ctx.child("prune").spawn(pruning, .{ &journal, &done });
            try ctx.sleep(.fromMilliseconds(10));
            try testing.expect(!done); // Prune proceeded while the rollover sync was pending.
            f.pending.unblock();
            try try prune.join();
            try testing.expectEqual(@as(u64, 3), journal.get_bounds().start);
            try testing.expectEqual(@as(u64, 4), journal.get_bounds().end);
        }

        /// Prune surfaces a failed in-flight rollover sync instead of proceeding.
        fn prune_surfaces_failure(ctx: Context) !void {
            var f: Fixture = undefined;
            try f.init(ctx);
            defer f.deinit();
            var journal = try K.open(f.storage(), 3, &f.cache);
            defer journal.deinit();
            try append_four(&journal);
            try testing.expect(f.pending.starts() > 0);
            f.pending.arm_fail();
            f.pending.unblock();
            try testing.expectError(error.Io, journal.prune(3));
        }
    };
}

fn run(comptime body: fn (Context) anyerror!void) !void {
    try soak_context(body, .{});
}

const FixedSuite = Suite(Kind(false));
const VariableSuite = Suite(Kind(true));

test "fixed start_sync overlaps work (test_fixed_start_sync_overlaps_work)" {
    try run(FixedSuite.overlaps_work);
}

test "variable start_sync overlaps work (test_variable_start_sync_overlaps_work)" {
    try run(VariableSuite.overlaps_work);
}

test "fixed start_sync waits for prior (test_fixed_start_sync_waits_for_prior)" {
    try run(FixedSuite.waits_for_prior);
}

test "variable start_sync waits for prior (test_variable_start_sync_waits_for_prior)" {
    try run(VariableSuite.waits_for_prior);
}

test "fixed start_sync overlaps predecessor and tail" {
    // commonware `test_fixed_start_sync_overlaps_predecessor_and_tail`.
    try run(FixedSuite.overlaps_predecessor_and_tail);
}

test "variable start_sync overlaps predecessor and tail" {
    // commonware `test_variable_start_sync_overlaps_predecessor_and_tail`.
    try run(VariableSuite.overlaps_predecessor_and_tail);
}

test "fixed start_sync failure propagates (test_fixed_start_sync_failure_propagates)" {
    try run(FixedSuite.failure_propagates);
}

test "variable start_sync failure propagates (test_variable_start_sync_failure_propagates)" {
    try run(VariableSuite.failure_propagates);
}

test "fixed prune waits for pending sync (test_fixed_prune_waits_for_pending_sync)" {
    try run(FixedSuite.prune_waits);
}

test "variable prune waits for pending sync (test_variable_prune_waits_for_pending_sync)" {
    try run(VariableSuite.prune_waits);
}

test "fixed prune surfaces failed sync (test_fixed_prune_surfaces_failed_sync)" {
    try run(FixedSuite.prune_surfaces_failure);
}

test "variable prune surfaces failed sync (test_variable_prune_surfaces_failed_sync)" {
    try run(VariableSuite.prune_surfaces_failure);
}

/// Runs `function` with `args` on a deterministic runner once per `-Dfuzz-soak` round, from the
/// runner's default seed (`runtime.deterministic.soak`).
fn soak_context(comptime function: anytype, args: anytype) !void {
    const Args = @TypeOf(args);
    try runtime.deterministic.soak(gpa, .{}, args, struct {
        fn run(context: Args, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start_context(function, context));
        }
    }.run);
}
