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
    try soak_context(dropped_during_repair, .{});
}

const Wide = [64]u8;
const WideJournal = variable.Journal(Wide);

fn replay_next_wide(ctx: Context, recovery: *WideJournal.Recovery) anyerror!void {
    _ = ctx;
    _ = try recovery.next();
}

fn dropped_during_read(ctx: Context, resume_replay: bool) !void {
    var inner: runtime.storage.memory.Storage = .init(gpa);
    defer inner.deinit();
    var gate: runtime.storage.mocks.ReadGate = .init(ctx.io(), "variable-cancel-read");
    var gated: runtime.storage.mocks.ReadGated = .init(gpa, inner.storage(), &gate);
    var cache_ref = try paged.CacheRef.init(gpa, 16, 8);
    defer cache_ref.deinit();
    const cfg: variable.Config(Wide) = .{
        .partition = "variable-cancel-read",
        .codec_config = {},
        .cache_ref = &cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 16,
    };
    {
        var recovery = try WideJournal.init(gpa, inner.storage(), cfg);
        var journal = try recovery.finish();
        defer journal.deinit();
        // A second section shows whether an interrupted replay goes on.
        for (0..2) |value| _ = try journal.append(0, @splat(@intCast(value)));
        _ = try journal.append(1, @splat(2));
        try journal.sync_all();
    }
    var recovery = try WideJournal.init(gpa, gated.storage(), cfg);
    // Buffer the header, so `next` consumes it before its body read reaches the gate.
    const front = &recovery.replays.items[recovery.head].reader;
    try testing.expect(try front.ensure(5));
    gate.arm();
    const handle = try ctx.child("next").spawn(replay_next_wide, .{&recovery});
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(gate.blocked() > 0);
    if (handle.abort()) |result| {
        try testing.expectError(error.Canceled, result);
    } else |err| try testing.expectEqual(error.Closed, err);
    gate.disarm();
    // A cancellation after consuming a frame header cannot resume or finish its replay.
    if (resume_replay) {
        try testing.expect(try recovery.next() == null);
        try testing.expect(try recovery.next() == null);
    }
    try testing.expectError(error.ReplayFailed, recovery.finish());
    // The durable data is unchanged.
    var reopened = try WideJournal.init(gpa, inner.storage(), cfg);
    for (0..3) |value| {
        const expected: Wide = @splat(@intCast(value));
        try testing.expectEqual(expected, (try reopened.next()).?.item);
    }
    try testing.expect(try reopened.next() == null);
    var journal = try reopened.finish();
    try journal.destroy();
}

test "segmented variable replay canceled during a read fails the replay" {
    // commonware `test_segmented_variable_replay_dropped_during_read_fails_replay` (finish,
    // next). A call is never dropped before it runs here, so the unpolled drop has no
    // counterpart.
    for ([_]bool{ false, true }) |resume_replay| {
        try soak_context(dropped_during_read, .{resume_replay});
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
