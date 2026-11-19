//! commonware's `segmented/variable.rs` `test_journal_replay_dropped_during_repair_fails_replay`:
//! a replay whose trailing-byte repair is canceled while its sync is held (by
//! `runtime.storage.mocks.DelayedSync`'s `arm` gate) fails, and reopening repairs from durable
//! state.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const variable = @import("variable.zig");

const gpa = testing.allocator;
const Context = runtime.deterministic.Context;
const PageItem = [1021]u8;
const J = variable.Journal(PageItem);

/// Drain `storage`'s recovery and return the journal.
fn open(storage: runtime.storage.Storage, cfg: variable.Config(PageItem)) !J {
    var recovery = try J.init(gpa, storage, cfg);
    {
        errdefer recovery.deinit();
        while (try recovery.next()) |_| {}
    }
    return recovery.finish();
}

fn replay_next(ctx: Context, recovery: *J.Recovery) anyerror!void {
    _ = ctx;
    _ = try recovery.next();
}

fn dropped_during_repair(ctx: Context) !void {
    var inner: runtime.storage.memory.Storage = .init(gpa);
    defer inner.deinit();
    var pending: runtime.storage.mocks.DelayedSync = .init(gpa, ctx.io());
    defer pending.deinit();
    var delayed: runtime.storage.mocks.DelayedSynced = .init(gpa, inner.storage(), &pending);
    var cache_ref = try paged.CacheRef.init(gpa, 1024, 10);
    defer cache_ref.deinit();
    const cfg: variable.Config(PageItem) = .{
        .partition = "test-partition",
        .codec_config = {},
        .cache_ref = &cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
    {
        // Trailing bytes cross the page boundary, so the repair resizes and syncs.
        var journal = try open(inner.storage(), cfg);
        defer journal.deinit();
        _ = try journal.append(1, @splat(10));
        _ = try (try journal.manager.get(1)).?.append(&.{ 0xFF, 0xFF });
        try journal.sync(&.{1});
    }
    var recovery = try J.init(gpa, delayed.storage(), cfg);
    try testing.expectEqual(@as(PageItem, @splat(10)), (try recovery.next()).?.item);
    // Gate syncs so the repair suspends, then cancel the in-flight `next`.
    try pending.arm();
    const handle = try ctx.child("next").spawn(replay_next, .{&recovery});
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expectEqual(@as(u64, 1), pending.calls()); // The repair's sync is held.
    if (handle.abort()) |result| {
        try testing.expectError(error.Canceled, result);
    } else |err| try testing.expectEqual(error.Closed, err);
    pending.release_all();
    // The interrupted repair fails the replay rather than resuming over it.
    try testing.expect(try recovery.next() == null);
    try testing.expectError(error.ReplayFailed, recovery.finish());
    // Re-initialization repairs from durable state.
    var journal = try open(inner.storage(), cfg);
    defer journal.deinit();
    try testing.expectEqual(@as(u64, 1023), try journal.size(1));
}

test "segmented variable replay canceled during repair fails the replay" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(dropped_during_repair, .{}));
}
