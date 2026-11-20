//! commonware's `segmented/manager.rs` in-flight `start_sync` tests, with
//! `runtime.storage.mocks.DelayedSync` holding started syncs (commonware's test factory parks
//! each buffer's sync on a completion sender).
//!
//! commonware asserts an operation is blocked with `poll(...).is_pending()`. Here the
//! operation runs as a spawned task on the deterministic runtime; the test sleeps, checks the
//! task has not finished, releases the parked syncs, and joins.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const manager_mod = @import("manager.zig");

const gpa = testing.allocator;
const M = manager_mod.Manager(manager_mod.AppendFactory);
const Context = runtime.deterministic.Context;
const Completion = runtime.storage.Completion;

const Fixture = struct {
    inner: runtime.storage.memory.Storage,
    pending: runtime.storage.mocks.DelayedSync,
    delayed: runtime.storage.mocks.DelayedSynced,
    cache_ref: paged.CacheRef,

    fn init(self: *Fixture, ctx: Context) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
        self.cache_ref = try paged.CacheRef.init(gpa, 64, 4);
    }

    fn deinit(self: *Fixture) void {
        self.cache_ref.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    /// A manager with fresh (dirty) `sections`.
    fn open(self: *Fixture, sections: []const u64) !M {
        const cfg: manager_mod.Config(manager_mod.AppendFactory) = .{
            .partition = "manager",
            .factory = .{ .write_buffer = 128, .cache_ref = &self.cache_ref },
        };
        var manager = try M.init(gpa, self.delayed.storage(), cfg, std.math.maxInt(u64));
        errdefer manager.deinit();
        for (sections) |section| _ = try manager.get_or_create(section);
        return manager;
    }
};

fn clearing(ctx: Context, manager: *M, done: *bool) anyerror!void {
    _ = ctx;
    defer done.* = true;
    try manager.clear();
}

fn waiting(ctx: Context, completion: Completion, done: *bool) anyerror!void {
    _ = ctx;
    defer done.* = true;
    try completion.wait_release();
}

fn truncating(ctx: Context, manager: *M, done: *bool) anyerror!void {
    _ = ctx;
    defer done.* = true;
    try manager.truncate_pending(1, 0);
}

fn pruning(ctx: Context, manager: *M, done: *bool) anyerror!void {
    _ = ctx;
    defer done.* = true;
    try testing.expect(try manager.prune(2));
}

fn destroying(ctx: Context, manager: *M, done: *bool) anyerror!void {
    _ = ctx;
    defer done.* = true;
    try manager.destroy();
}

fn concurrent_sync_reports_later_error(ctx: Context, count: u64, clear: bool) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var sections: [8]u64 = undefined;
    for (sections[0..count], 0..) |*section, index| section.* = index;
    var manager = try f.open(sections[0..count]);
    defer manager.deinit();
    const completion = try manager.start_sync(sections[0..count]);
    try testing.expectEqual(@as(usize, count), f.pending.parked());
    // Fail the last section's sync and leave every earlier one pending: the failure surfaces
    // at once, not behind them.
    f.pending.last().release(error.Io);
    var done = false;
    const handle = if (clear) handle: {
        completion.release();
        break :handle try ctx.child("op").spawn(clearing, .{ &manager, &done });
    } else try ctx.child("op").spawn(waiting, .{ completion, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(done);
    try testing.expectError(error.Io, try handle.join());
    f.pending.release_all();
}

test "manager start_sync reports a later section's failure at once" {
    // commonware `test_concurrent_sync_reports_later_error` (counts within one join).
    inline for (.{ 1, 2, 8 }) |count| {
        inline for (.{ false, true }) |clear| {
            try soak_context(concurrent_sync_reports_later_error, .{ count, clear });
        }
    }
}

fn combined(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var manager = try f.open(&.{ 1, 2 });
    const completion = try manager.start_sync(&.{ 1, 2 });
    defer completion.release();
    try testing.expectEqual(@as(usize, 2), f.pending.parked());
    // Completing only the first section's sync leaves the combined completion pending.
    f.pending.next().release({});
    try testing.expect(completion.is_pending());
    f.pending.next().release({});
    try completion.wait();
    try manager.destroy();
}

test "manager start_sync of several sections returns a combined completion" {
    // commonware `test_start_sync_multiple_sections_returns_combined_handle`.
    try soak_context(combined, .{});
}

fn reuses(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var manager = try f.open(&.{1});
    const first = try manager.start_sync(&.{1});
    try testing.expectEqual(@as(usize, 1), f.pending.parked());
    // A repeated start_sync with no newer writes observes the in-flight sync.
    const second = try manager.start_sync(&.{1});
    try testing.expectEqual(@as(usize, 1), f.pending.parked());
    try testing.expect(second.is_pending());
    f.pending.release_all();
    try first.wait_release();
    try second.wait_release();
    try manager.destroy();
}

test "manager start_sync reuses an in-flight section sync without waiting" {
    // commonware `test_start_sync_reuses_in_flight_section_handle_without_waiting`.
    try soak_context(reuses, .{});
}

fn truncate_waits(ctx: Context, fails: bool) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var manager = try f.open(&.{ 1, 2 });
    defer manager.deinit();
    // Hold a sync on the section truncation removes.
    const completion = try manager.start_sync(&.{2});
    defer completion.release();
    var done = false;
    const truncate = try ctx.child("truncate").spawn(truncating, .{ &manager, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done); // Truncation must wait for the section's sync.
    f.pending.next().release(if (fails) error.Io else {});
    if (fails) {
        try testing.expectError(error.Io, try truncate.join());
        try testing.expectError(error.Io, completion.wait());
        return;
    }
    try try truncate.join();
    try completion.wait();
    try testing.expectEqual(@as(?u64, 1), manager.newest_section());
}

test "manager truncate waits for an in-flight start_sync" {
    // commonware `test_truncate_waits_for_in_flight_start_sync`.
    for ([_]bool{ false, true }) |fails| {
        try soak_context(truncate_waits, .{fails});
    }
}

fn prune_waits(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var manager = try f.open(&.{1});
    defer manager.deinit();
    const completion = try manager.start_sync(&.{1});
    var done = false;
    const prune = try ctx.child("prune").spawn(pruning, .{ &manager, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done); // Prune must wait for the in-flight sync.
    f.pending.release_all();
    try completion.wait_release();
    try try prune.join();
    try testing.expect(manager.is_empty());
}

test "manager prune waits for an in-flight start_sync" {
    // commonware `test_prune_waits_for_in_flight_start_sync`.
    try soak_context(prune_waits, .{});
}

fn destroy_waits(ctx: Context, fails: bool) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var manager = try f.open(&.{1});
    const completion = try manager.start_sync(&.{1});
    defer completion.release();
    if (fails) {
        // A failed sync surfaces from destroy and from its completion.
        f.pending.next().release(error.Io);
        try testing.expectError(error.Io, manager.destroy());
        try testing.expectError(error.Io, completion.wait());
        return;
    }
    var done = false;
    const destroy = try ctx.child("destroy").spawn(destroying, .{ &manager, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done); // Destroy must wait for the in-flight sync.
    f.pending.release_all();
    try completion.wait();
    try try destroy.join();
}

test "manager destroy waits for, and surfaces, an in-flight start_sync" {
    // commonware `test_destroy_waits_for_in_flight_start_sync`,
    // `test_destroy_surfaces_failed_in_flight_start_sync`.
    for ([_]bool{ false, true }) |fails| {
        try soak_context(destroy_waits, .{fails});
    }
}

fn skips_clean(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var manager = try f.open(&.{ 1, 2 });
    defer manager.deinit();
    // Freshly opened sections are dirty: the first sync starts one sync per section.
    const first = try manager.start_sync(&.{ 1, 2 });
    try testing.expectEqual(@as(u64, 2), f.pending.starts());
    f.pending.release_all();
    try first.wait_release();
    // Clean sections need no work from sync_all, sync, or start_sync.
    try manager.sync_all();
    try manager.sync(&.{ 1, 2 });
    const clean = try manager.start_sync(&.{ 1, 2 });
    try testing.expect(!clean.is_pending());
    try clean.wait_release();
    try testing.expectEqual(@as(u64, 2), f.pending.starts());
    try testing.expectEqual(@as(usize, 0), f.pending.parked());
    // Only the section with new writes is synced, and both sections stay open.
    _ = try (try manager.get(1)).?.append("x");
    const dirty = try manager.start_sync(&.{ 1, 2 });
    try testing.expectEqual(@as(u64, 3), f.pending.starts());
    f.pending.release_all();
    try dirty.wait_release();
    try testing.expect((try manager.get(2)) != null);
}

test "manager start_sync skips clean sections" {
    // commonware `test_sync_skips_clean_sections` (its sync counts; the metric half is
    // "sync counts every selected section").
    try soak_context(skips_clean, .{});
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
