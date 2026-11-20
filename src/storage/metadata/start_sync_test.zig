//! commonware's `start_sync` metadata tests (`storage/src/metadata/mod.rs`), on
//! `runtime.storage.faulty` where commonware injects faults.
//!
//! The faulty backend completes a started sync at the call, so a parked sync is one whose
//! blob sync fails: its completion reports the failure, and the store retains it until the
//! next durability operation, which fails and consumes the store (only `deinit` may follow).
//! A write failure inside `start_sync` consumes the store at once.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const metadata = @import("mod.zig");
const Faults = @import("../archive/faults.zig").Faults;

const gpa = testing.allocator;
const Store = metadata.Metadata(u64, []const u8);
const config: metadata.Config([]const u8) = .{
    .partition = "test",
    .codec_config = .{ .range = .full(), .item = {} },
};

fn put(store: *Store, key: u64, byte: u8, len: usize) !void {
    const value = try gpa.alloc(u8, len);
    errdefer gpa.free(value);
    @memset(value, byte);
    if (try store.put(key, value)) |previous| gpa.free(previous);
}

fn expect_value(store: *const Store, key: u64, byte: u8, len: usize) !void {
    const value = store.get(key) orelse return error.TestExpectedValue;
    try testing.expectEqual(len, value.len);
    for (value.*) |actual| try testing.expectEqual(byte, actual);
}

fn open(faults: *Faults) !Store {
    return Store.init(gpa, faults.interface(), config);
}

test "start_sync: pipelined syncs then destroy leave nothing" {
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    var store = try open(&faults);
    try put(&store, 1, 3, 1);
    try (try store.start_sync()).wait_release();
    try put(&store, 1, 4, 1);
    try (try store.start_sync()).wait_release();
    try store.destroy();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try testing.expect(reopened.get(1) == null);
}

test "start_sync: the newest copy wins on reopen" {
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    {
        var store = try open(&faults);
        defer store.deinit();
        try put(&store, 1, 3, 1);
        try (try store.start_sync()).wait_release();
        try put(&store, 1, 4, 1);
        try (try store.start_sync()).wait_release();
    }
    try faults.crash();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try expect_value(&reopened, 1, 4, 1);
}

test "start_sync: a dropped handle does not cancel the sync" {
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    {
        var store = try open(&faults);
        defer store.deinit();
        try put(&store, 1, 3, 1);
        try (try store.start_sync()).wait_release();
        try store.sync();
    }
    try faults.crash();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try expect_value(&reopened, 1, 3, 1);
}

test "start_sync: a failed sync consumes the store and keeps the durable copy" {
    // Covers commonware's failure-fails-next-sync, dropped-handle-fails-next-sync, and
    // destroy-after-failed-sync tests: the failure surfaces on the call, and a reopen finds
    // the last acknowledged generation.
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    {
        var store = try open(&faults);
        defer store.deinit();
        for (1..4) |generation| {
            try put(&store, 0, @intCast(generation), 8);
            try store.sync();
        }
        try put(&store, 0, 4, 8);
        faults.layer.config = .{ .sync_rate = .one };
        defer faults.disarm();
        // The fault is rolled at start: the completion reports it, and the store retains it,
        // so the next durability operation fails without writing.
        const started = try store.start_sync();
        try testing.expectError(error.Io, started.wait_release());
        try testing.expect(!store.failed);
        try testing.expectError(error.Io, store.sync());
        try testing.expect(store.failed);
    }
    try faults.crash();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try expect_value(&reopened, 0, 3, 8);
}

test "start_sync: a write failure consumes the store" {
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    {
        var store = try open(&faults);
        defer store.deinit();
        // Equal-size values settle the key order, so later syncs take the overwrite path,
        // which mutates the target copy's state before writing.
        try put(&store, 1, 1, 8);
        try store.sync();
        try put(&store, 1, 2, 8);
        try store.sync();
        try put(&store, 1, 3, 8);
        faults.layer.config = .{ .write_rate = .{
            .failure_rate = .one,
            .retention_rate = .zero,
            .mode = .prefix,
        } };
        defer faults.disarm();
        try testing.expectError(error.Io, store.start_sync());
        try testing.expect(store.failed);
    }
    try faults.crash();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try expect_value(&reopened, 1, 2, 8);
}

fn syncing(ctx: runtime.deterministic.Context, store: *Store, done: *bool) anyerror!void {
    _ = ctx;
    defer done.* = true;
    try store.sync();
}

fn second_sync_waits_for_first(ctx: runtime.deterministic.Context) !void {
    var inner: runtime.storage.memory.Storage = .init(gpa);
    defer inner.deinit();
    var pending: runtime.storage.mocks.DelayedSync = .init(gpa, ctx.io());
    defer pending.deinit();
    var delayed: runtime.storage.mocks.DelayedSynced = .init(gpa, inner.storage(), &pending);
    var store = try Store.init(gpa, delayed.storage(), config);
    var live = true;
    defer if (live) store.deinit();
    // Park the first sync, then start a second: until the first sync completes, its target
    // copy's on-disk state is unknown, so the second must not write a byte to the other (only
    // durable) copy.
    try put(&store, 1, 3, 1);
    const first = try store.start_sync();
    defer first.release();
    try put(&store, 1, 4, 1);
    const before = inner.audit();
    var done = false;
    const second = try ctx.child("second").spawn(syncing, .{ &store, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done);
    try testing.expectEqualSlices(u8, &before, &inner.audit());
    try testing.expectEqual(@as(u64, 1), pending.starts());
    // Releasing the first lets the second write and sync.
    pending.release_all();
    try first.wait();
    while (!done) {
        pending.release_all();
        try ctx.sleep(.fromMilliseconds(1));
    }
    try (try second.join());
    try expect_value(&store, 1, 4, 1);
    live = false;
    try store.destroy();
}

test "start_sync: a second sync waits for the first" {
    // commonware `test_start_sync_second_sync_waits_for_first`.
    try soak_context(second_sync_waits_for_first, .{});
}

/// A store over `delayed`, whose started syncs park in `pending`.
const Delayed = struct {
    inner: runtime.storage.memory.Storage,
    pending: runtime.storage.mocks.DelayedSync,
    delayed: runtime.storage.mocks.DelayedSynced,

    fn init(self: *Delayed, ctx: runtime.deterministic.Context) void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
    }

    fn deinit(self: *Delayed) void {
        self.pending.deinit();
        self.inner.deinit();
    }
};

fn dropped_handle_does_not_cancel(ctx: runtime.deterministic.Context) !void {
    var d: Delayed = undefined;
    d.init(ctx);
    defer d.deinit();
    {
        var store = try Store.init(gpa, d.delayed.storage(), config);
        defer store.deinit();
        // Drop the completion while its sync is still parked: the sync must proceed anyway.
        try put(&store, 1, 3, 1);
        const started = try store.start_sync();
        try testing.expect(started.is_pending());
        started.release();
        d.pending.release_all();
        try store.sync();
    }
    d.inner.crash();
    var reopened = try Store.init(gpa, d.inner.storage(), config);
    defer reopened.deinit();
    try expect_value(&reopened, 1, 3, 1);
}

test "start_sync: a dropped completion does not cancel its sync" {
    // commonware `test_start_sync_dropped_handle_does_not_cancel`, on `DelayedSync`.
    try soak_context(dropped_handle_does_not_cancel, .{});
}

fn failure_fails_next_sync(ctx: runtime.deterministic.Context, dropped: bool) !void {
    var d: Delayed = undefined;
    d.init(ctx);
    defer d.deinit();
    var store = try Store.init(gpa, d.delayed.storage(), config);
    defer store.deinit();
    try put(&store, 1, 3, 1);
    const started = try store.start_sync();
    d.pending.fail_all();
    if (dropped) {
        // Nobody observes the failure directly, but the next sync does.
        started.release();
    } else try testing.expectError(error.Io, started.wait_release());
    // The failed copy's on-disk state is unknown: the next sync fails, consuming the store,
    // without writing the only durable copy.
    try put(&store, 1, 4, 1);
    const before = d.inner.audit();
    if (dropped) {
        try testing.expectError(error.Io, store.sync());
    } else try testing.expectError(error.Io, store.start_sync());
    try testing.expectEqualSlices(u8, &before, &d.inner.audit());
}

test "start_sync: a failed sync fails the next sync" {
    // commonware `test_start_sync_failure_fails_next_sync` and
    // `test_start_sync_dropped_handle_fails_next_sync`, on `DelayedSync`.
    for ([_]bool{ false, true }) |dropped| {
        try soak_context(failure_fails_next_sync, .{dropped});
    }
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
