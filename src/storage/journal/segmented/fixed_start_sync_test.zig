//! commonware's `segmented/fixed.rs` in-flight `start_sync` tests: prune, destroy, and clear
//! wait for a started section sync, and prune surfaces a failed one. Started syncs are held by
//! `runtime.storage.mocks.DelayedSync` (`DelayedSyncContext`); the blocked operation runs as a
//! spawned task on the deterministic runtime.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const Sha256 = @import("cryptography").sha256.Sha256;
const Digest = @import("cryptography").sha256.Digest;
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");

const gpa = testing.allocator;
const J = fixed.Journal(Digest);
const Context = runtime.deterministic.Context;

fn test_digest(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

const Fixture = struct {
    inner: runtime.storage.memory.Storage,
    pending: runtime.storage.mocks.DelayedSync,
    delayed: runtime.storage.mocks.DelayedSynced,
    cache_ref: paged.CacheRef,

    fn init(self: *Fixture, ctx: Context) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
        self.cache_ref = try paged.CacheRef.init(gpa, 44, 3);
    }

    fn deinit(self: *Fixture) void {
        self.cache_ref.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    /// A journal with one item in section 1 and that section's sync started and parked.
    fn started(self: *Fixture, journal: *J) !runtime.storage.Completion {
        journal.* = try J.init(gpa, self.delayed.storage(), .{
            .partition = "test-partition",
            .cache_ref = &self.cache_ref,
            .write_buffer = 2048,
            .replay_buffer = 1024,
        });
        errdefer journal.deinit();
        _ = try journal.append(1, test_digest(0));
        const completion = try journal.start_sync(&.{1});
        try testing.expect(self.pending.parked() > 0);
        return completion;
    }
};

const Op = enum { prune, destroy, clear };

fn operate(ctx: Context, journal: *J, op: Op, done: *bool) anyerror!void {
    _ = ctx;
    defer done.* = true;
    switch (op) {
        .prune => try testing.expect(try journal.prune(2)),
        .destroy => try journal.destroy(),
        .clear => try journal.clear(),
    }
}

fn waits(ctx: Context, op: Op) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var journal: J = undefined;
    const completion = try f.started(&journal);
    defer if (op != .destroy) journal.deinit();
    var done = false;
    const handle = try ctx.child("op").spawn(operate, .{ &journal, op, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done); // The operation must wait for the in-flight sync.
    f.pending.release_all();
    // The sync completes even though its section is being removed.
    try completion.wait_release();
    try try handle.join();
    if (op == .destroy) return;
    try testing.expectEqual(@as(?u64, null), journal.oldest_section());
    if (op == .clear) {
        // The journal stays usable after clear.
        try testing.expectEqual(@as(u64, 0), try journal.append(1, test_digest(1)));
    }
}

test "segmented fixed prune, destroy, and clear wait for an in-flight start_sync" {
    // commonware `test_segmented_fixed_{prune,destroy,clear}_waits_for_in_flight_start_sync`.
    for ([_]Op{ .prune, .destroy, .clear }) |op| {
        var runner = try runtime.deterministic.Runner.init(gpa, .{});
        defer runner.deinit();
        try (try runner.start_context(waits, .{op}));
    }
}

fn prune_surfaces(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var journal: J = undefined;
    const completion = try f.started(&journal);
    defer journal.deinit();
    f.pending.fail_all();
    try testing.expectError(error.Io, journal.prune(2));
    try testing.expectError(error.Io, completion.wait_release());
}

test "segmented fixed prune surfaces a failed in-flight start_sync" {
    // commonware `test_segmented_fixed_prune_surfaces_failed_in_flight_start_sync`.
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(prune_surfaces, .{}));
}

const IntJournal = fixed.Journal(u64);

/// commonware's `aligned_cfg`: 16-byte pages, so six u64 items fill three pages.
fn aligned_cfg(cache_ref: *paged.CacheRef) fixed.Config {
    return .{
        .partition = "repair",
        .cache_ref = cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
}

fn replay_next(ctx: Context, recovery: *IntJournal.Recovery) anyerror!void {
    _ = ctx;
    _ = try recovery.next();
}

/// Damage section 0 (a torn interior page, or a tail cut inside item 5) and return the items
/// replay drains before it repairs, and the items that survive.
fn damage(storage: runtime.storage.Storage, cache_ref: *paged.CacheRef, torn: bool) ![2]u64 {
    const name = @import("manager.zig").section_name(0);
    if (torn) {
        try paged.corrupt_page(storage, "repair", &name, 1, 16);
        return .{ 0, 2 };
    }
    const opened = try storage.open("repair", &name);
    var writer = try paged.Writer.open_recovery(gpa, opened.blob, opened.len, 1024, cache_ref);
    defer writer.deinit();
    try writer.truncate(44);
    try writer.sync();
    return .{ 5, 5 };
}

fn dropped_during_repair(ctx: Context, torn: bool) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var cache_ref = try paged.CacheRef.init(gpa, 16, 8);
    defer cache_ref.deinit();
    const cfg = aligned_cfg(&cache_ref);
    {
        var journal = try IntJournal.init(gpa, f.inner.storage(), cfg);
        defer journal.deinit();
        for (0..6) |value| _ = try journal.append(0, value);
        try journal.sync_all();
    }
    const drained, const retained = try damage(f.inner.storage(), &cache_ref, torn);
    // Replay up to the damage, gate syncs so the repair suspends, and cancel that `next`.
    var recovery = try IntJournal.preflight_floors(gpa, f.delayed.storage(), cfg, &.{});
    for (0..drained) |value| {
        const item = (try recovery.next()).?;
        try testing.expectEqual(@as(u64, value), item.item);
    }
    try f.pending.arm();
    const handle = try ctx.child("next").spawn(replay_next, .{&recovery});
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expectEqual(@as(u64, 1), f.pending.calls()); // The repair's sync is held.
    if (handle.abort()) |result| {
        try testing.expectError(error.Canceled, result);
    } else |err| try testing.expectEqual(error.Closed, err);
    f.pending.release_all();
    // The interrupted repair fails the replay (commonware reports `ReplayInterrupted` on the
    // next call; a canceled call here returns `Canceled` itself).
    try testing.expectEqual(@as(?IntJournal.Recovery.Item, null), try recovery.next());
    try testing.expectError(error.ReplayFailed, recovery.finish());
    // Re-initialization repairs from durable state.
    var journal = try IntJournal.init(gpa, f.inner.storage(), cfg);
    defer journal.deinit();
    try testing.expectEqual(retained, try journal.section_len(0));
    for (0..retained) |value| try testing.expectEqual(@as(u64, value), try journal.get(0, value));
}

test "segmented fixed replay canceled during repair fails the replay" {
    // commonware `test_segmented_fixed_replay_dropped_during_repair_fails_replay` (tail, torn).
    for ([_]bool{ false, true }) |torn| {
        var runner = try runtime.deterministic.Runner.init(gpa, .{});
        defer runner.deinit();
        try (try runner.start_context(dropped_during_repair, .{torn}));
    }
}
