//! The prunable archive's pipelined `start_sync` tests (commonware `archive/prunable/mod.rs`),
//! run on `runtime.storage.mocks.DelayedSync`: a started sync parks until the test releases
//! it, and an operation that must wait runs as a spawned task on the deterministic runtime.
//! Each test names the archive code it exercises in `storage.zig`:
//!
//! - put while a sync is in flight: `put_internal` (no I/O, no wait).
//! - duplicate put: `requested` (the completion re-requests the in-flight section syncs).
//! - overlapping start_sync, sync, destroy: the segmented journals' started syncs, which a
//!   later sync request and `destroy` observe first.
//! - prune: `retain_at_least(&requested, min)` and the journals settling the started syncs of
//!   the sections they remove; a failed one surfaces at once.
//! - restarts: independent per-section syncs, of which only completed ones survive a crash.
//!
//! The marker-pipeline tests (startup marker failure, closed-section boundaries, withheld
//! markers) need metadata syncs in flight and are not ported yet.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const deterministic = runtime.deterministic;
const translator = @import("../../translator.zig");
const prunable = @import("mod.zig");
const tests = @import("tests.zig");

const Harness = tests.Harness;
const Key = [64]u8;
const Archive = prunable.Archive(translator.FourCap, Key, i32);
const Completion = runtime.storage.Completion;
const gpa = testing.allocator;

/// The harness storage behind the delayed-sync mock.
const Delayed = struct {
    syncs: runtime.storage.mocks.DelayedSync,
    wrapper: runtime.storage.mocks.DelayedSynced,

    /// Must not move after `wrap`.
    fn wrap(self: *Delayed, io: std.Io, harness: *Harness) void {
        self.syncs = .init(gpa, io);
        self.wrapper = .init(gpa, harness.storage.interface(), &self.syncs);
    }

    fn deinit(self: *Delayed) void {
        self.syncs.deinit();
        self.* = undefined;
    }

    fn open(self: *Delayed, harness: *Harness, cfg: anytype, name: []const u8) !Archive {
        const scope = metrics.Scope.init(&harness.registry).child(name);
        return Archive.init(gpa, self.wrapper.storage(), scope, cfg);
    }
};

fn expect_index(archive: *Archive, index: u64, expected: ?i32) !void {
    try testing.expectEqual(expected, try archive.get(.{ .index = index }));
}

const default_section: u64 = 65536;

/// Runs `body(ctx)` on the deterministic runtime.
fn run(comptime body: fn (deterministic.Context) anyerror!void) !void {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(body, .{}));
}

const Op = fn (*Archive) anyerror!void;

fn run_op(ctx: deterministic.Context, op: *const Op, archive: *Archive, done: *bool) anyerror!void {
    _ = ctx;
    try op(archive);
    done.* = true;
}

/// The blocked-operation check (step 1's buffer test pattern): `op` runs as a spawned task;
/// after a sleep it has not finished and the oldest parked sync has a waiter; releasing every
/// parked sync lets it finish.
fn expect_waits(
    ctx: deterministic.Context,
    delayed: *Delayed,
    comptime op: Op,
    archive: *Archive,
) !void {
    var done = false;
    const handle = try ctx.child("op").spawn(run_op, .{ &op, archive, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done);
    const oldest = delayed.syncs.next();
    try testing.expect(oldest.blocked());
    oldest.release({});
    delayed.syncs.release_all();
    try try handle.join();
    try testing.expect(done);
}

/// Releases only the newest of exactly three parked syncs, keeping the two older ones
/// parked in order.
fn release_newest_of_three(delayed: *Delayed) [2]runtime.storage.mocks.Deferred {
    std.debug.assert(delayed.syncs.parked() == 3);
    const older = [2]runtime.storage.mocks.Deferred{ delayed.syncs.next(), delayed.syncs.next() };
    delayed.syncs.next().release({});
    return older;
}

const PutAfterStart = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.config("test", default_section, translator.FourCap);
        {
            var delayed: Delayed = undefined;
            delayed.wrap(ctx.io(), &harness);
            defer delayed.deinit();
            var archive = try delayed.open(&harness, cfg, "storage");
            defer archive.deinit();
            const handle = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
            defer handle.release();
            const parked = delayed.syncs.parked();
            try testing.expect(parked > 0);
            // A put while the handle is pending issues no new storage sync.
            try archive.put(2, tests.test_key("bbb"), 20);
            try testing.expectEqual(parked, delayed.syncs.parked());
            try expect_index(&archive, 1, 10);
            delayed.syncs.release_all();
            try handle.wait();
            const follow_up = try archive.start_sync();
            defer follow_up.release();
            try testing.expect(delayed.syncs.parked() > 0);
            delayed.syncs.release_all();
            try follow_up.wait();
        }
        harness.storage.crash();
        var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
        defer archive.deinit();
        try expect_index(&archive, 1, 10);
        try expect_index(&archive, 2, 20);
    }
};

test "prunable put after start_sync is accepted before the handle completes" {
    try run(PutAfterStart.body);
}

const DuplicatePut = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        var delayed: Delayed = undefined;
        delayed.wrap(ctx.io(), &harness);
        defer delayed.deinit();
        const cfg = harness.config("test", default_section, translator.FourCap);
        var archive = try delayed.open(&harness, cfg, "storage");
        defer archive.deinit();
        const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
        defer first.release();
        try testing.expectEqual(@as(usize, 2), delayed.syncs.parked());
        // The duplicate stores nothing and issues no sync, yet observes the first sync.
        const second = try archive.put_start_sync(1, tests.test_key("duplicate"), 99);
        defer second.release();
        try testing.expectEqual(@as(usize, 2), delayed.syncs.parked());
        try testing.expect(second.poll() == null);
        delayed.syncs.release_all();
        try first.wait();
        try second.wait();
        try expect_index(&archive, 1, 10);
    }
};

test "prunable duplicate put_start_sync observes the in-flight sync" {
    try run(DuplicatePut.body);
}

/// One pending put_start_sync at index 1 (one item per section when `section` is 1).
fn start_first(delayed: *Delayed, archive: *Archive) !Completion {
    const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
    try testing.expect(delayed.syncs.parked() > 0);
    return first;
}

fn second_put_start_sync(archive: *Archive) !void {
    const second = try archive.put_start_sync(2, tests.test_key("bbb"), 20);
    second.release();
}

fn blocking_sync(archive: *Archive) !void {
    try archive.sync();
}

fn prune_two(archive: *Archive) !void {
    try archive.prune(2);
}

/// commonware's four "waits for the in-flight sync" tests share one shape: an operation after
/// a pending put_start_sync must not finish until that sync is released.
fn WaitsFor(comptime section: u64, comptime op: fn (*Archive) anyerror!void) type {
    return struct {
        fn body(ctx: deterministic.Context) !void {
            var harness = try Harness.init();
            defer harness.deinit();
            var delayed: Delayed = undefined;
            delayed.wrap(ctx.io(), &harness);
            defer delayed.deinit();
            const cfg = harness.config("test", section, translator.FourCap);
            var archive = try delayed.open(&harness, cfg, "storage");
            defer archive.deinit();
            const first = try start_first(&delayed, &archive);
            defer first.release();
            try expect_waits(ctx, &delayed, op, &archive);
            try first.wait();
            delayed.syncs.release_all();
        }
    };
}

test "prunable overlapping put_start_sync waits for the in-flight sync" {
    try run(WaitsFor(default_section, second_put_start_sync).body);
}

test "prunable sync after put_start_sync waits for the in-flight sync" {
    try run(WaitsFor(default_section, blocking_sync).body);
}

test "prunable prune after put_start_sync waits for in-flight syncs of pruned sections" {
    try run(WaitsFor(1, prune_two).body);
}

const DestroyWaits = struct {
    fn destroy(archive: *Archive) !void {
        try archive.destroy();
    }

    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        var delayed: Delayed = undefined;
        delayed.wrap(ctx.io(), &harness);
        defer delayed.deinit();
        const cfg = harness.config("test", default_section, translator.FourCap);
        var archive = try delayed.open(&harness, cfg, "storage");
        const first = try start_first(&delayed, &archive);
        defer first.release();
        // `destroy` frees the archive whether or not it succeeds.
        try expect_waits(ctx, &delayed, destroy, &archive);
        try first.wait();
    }
};

test "prunable destroy after put_start_sync waits for the in-flight sync" {
    try run(DestroyWaits.body);
}

/// A failed in-flight sync surfaces at the next `op`, and on the handle.
fn Surfaces(comptime section: u64, comptime op: fn (*Archive) anyerror!void) type {
    return struct {
        fn body(ctx: deterministic.Context) !void {
            var harness = try Harness.init();
            defer harness.deinit();
            var delayed: Delayed = undefined;
            delayed.wrap(ctx.io(), &harness);
            defer delayed.deinit();
            const cfg = harness.config("test", section, translator.FourCap);
            var archive = try delayed.open(&harness, cfg, "storage");
            defer archive.deinit();
            const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
            defer first.release();
            try testing.expectEqual(@as(usize, 2), delayed.syncs.parked());
            delayed.syncs.fail_all();
            try testing.expectError(error.Io, op(&archive));
            try testing.expectError(error.Io, first.wait());
        }
    };
}

fn put_then_start_sync(archive: *Archive) !void {
    // The write is accepted before the failed sync is observed.
    try archive.put(2, tests.test_key("bbb"), 20);
    const handle = try archive.start_sync();
    handle.release();
}

test "prunable prune surfaces a failed in-flight sync" {
    try run(Surfaces(1, prune_two).body);
}

test "prunable failed start_sync is returned by the next start_sync" {
    try run(Surfaces(default_section, put_then_start_sync).body);
}

const PruneDropsRequests = struct {
    fn body(ctx: deterministic.Context) !void {
        var harness = try Harness.init();
        defer harness.deinit();
        var delayed: Delayed = undefined;
        delayed.wrap(ctx.io(), &harness);
        defer delayed.deinit();
        const cfg = harness.config("test", 1, translator.FourCap);
        var archive = try delayed.open(&harness, cfg, "storage");
        defer archive.deinit();
        const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
        defer first.release();
        delayed.syncs.release_all();
        try first.wait();
        // Section 1 stays requested until a blocking sync; prune must drop it, or the next
        // request would sync a pruned section.
        try archive.prune(2);
        const second = try archive.put_start_sync(2, tests.test_key("bbb"), 20);
        defer second.release();
        delayed.syncs.release_all();
        try second.wait();
        delayed.syncs.unblock();
        try archive.sync();
        try expect_index(&archive, 1, null);
        try expect_index(&archive, 2, 20);
    }
};

test "prunable put_start_sync after prune drops pruned sync requests" {
    try run(PruneDropsRequests.body);
}

/// Two sections each with an in-flight sync; `released` of the four parked syncs complete,
/// in start order, before a crash.
fn Restarts(comptime released: u64) type {
    return struct {
        fn body(ctx: deterministic.Context) !void {
            var harness = try Harness.init();
            defer harness.deinit();
            const cfg = harness.config("test", 1, translator.FourCap);
            {
                var delayed: Delayed = undefined;
                delayed.wrap(ctx.io(), &harness);
                defer delayed.deinit();
                var archive = try delayed.open(&harness, cfg, "storage");
                defer archive.deinit();
                const first = try archive.put_start_sync(1, tests.test_key("aaa"), 10);
                defer first.release();
                const second = try archive.put_start_sync(2, tests.test_key("bbb"), 20);
                defer second.release();
                // Different sections have independent in-flight syncs.
                try testing.expectEqual(@as(usize, 4), delayed.syncs.parked());
                delayed.syncs.release_next(released);
                try first.wait();
                if (released == 4) try second.wait();
                harness.storage.crash();
                // The syncs still parked never complete.
                delayed.syncs.fail_all();
            }
            var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
            defer archive.deinit();
            try expect_index(&archive, 1, 10);
            try expect_index(&archive, 2, if (released == 4) 20 else null);
        }
    };
}

test "prunable overlapping put_start_sync restarts after all handles complete" {
    try run(Restarts(4).body);
}

test "prunable overlapping put_start_sync restarts only completed handles" {
    try run(Restarts(2).body);
}
