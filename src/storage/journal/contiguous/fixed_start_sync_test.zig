//! commonware's `journal/contiguous/fixed.rs` tests of started sync handles: the predecessor
//! sync slot, the lagging recovery watermark, parked and failed syncs, and dropped handles whose
//! failure must surface before the blob namespace changes. `runtime.storage.mocks.DelayedSync`
//! holds started syncs (`DelayedSyncContext`, `PendingSyncs`); `runtime.storage.faulty` fails
//! them (`storage_fault_config().sync_rate`). commonware's `test_truncate` (sync, then reopen at
//! most a cap) is a driven `sync` and an `init_at_most` reopen here.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const contiguous = @import("mod.zig");

const gpa = testing.allocator;
const Journal = fixed.Journal(u64);
const Bounds = contiguous.Bounds;
const Context = runtime.deterministic.Context;
const Completion = runtime.storage.Completion;
const DelayedSync = runtime.storage.mocks.DelayedSync;
const DelayedSynced = runtime.storage.mocks.DelayedSynced;
const data_partition = "test-partition-blobs";

/// Memory storage behind a `DelayedSynced` wrapper, plus commonware's 44-byte, 3-page cache.
const Fixture = struct {
    inner: runtime.storage.memory.Storage,
    pending: DelayedSync,
    delayed: DelayedSynced,
    cache: paged.CacheRef,

    fn init(self: *Fixture, ctx: Context) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
        self.cache = try paged.CacheRef.init(gpa, 44, 3);
    }

    fn deinit(self: *Fixture) void {
        self.cache.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    fn cfg(self: *Fixture, items_per_blob: u64) fixed.Config {
        return .{
            .partition = "test-partition",
            .items_per_blob = items_per_blob,
            .cache_ref = &self.cache,
            .write_buffer = 2048,
            .replay_buffer = 2048,
        };
    }

    fn open(self: *Fixture, items_per_blob: u64) !Journal {
        return Journal.init(gpa, self.delayed.storage(), self.cfg(items_per_blob));
    }

    /// Release parked syncs until `completion` completes (commonware `drive_pending_syncs`).
    fn drive(self: *Fixture, completion: Completion) !void {
        while (completion.is_pending()) self.pending.release_all();
        try completion.wait_release();
    }
};

fn Payload(comptime func: anytype) type {
    const Return = @typeInfo(@TypeOf(func)).@"fn".return_type.?;
    return @typeInfo(Return).error_union.payload;
}

/// Run `func(args)` as a task, releasing parked syncs until it returns (commonware
/// `drive_pending_syncs` around a future).
fn drive_call(
    ctx: Context,
    pending: *DelayedSync,
    comptime func: anytype,
    args: anytype,
) !Payload(func) {
    // The result goes through `out`: a task's own result is bounded in size.
    const Task = struct {
        fn run(c: Context, a: @TypeOf(args), done: *bool, out: *Payload(func)) anyerror!void {
            _ = c;
            defer done.* = true;
            out.* = try @call(.auto, func, a);
        }
    };
    var done = false;
    var out: Payload(func) = undefined;
    const handle = try ctx.child("drive").spawn(Task.run, .{ args, &done, &out });
    while (!done) {
        pending.release_all();
        try ctx.sleep(.fromMilliseconds(1));
    }
    // A sync the call started just before returning is released too.
    pending.release_all();
    try try handle.join();
    return out;
}

fn append_values(journal: *Journal, values: []const u64) !void {
    for (values) |value| _ = try journal.append(value);
}

/// The data blobs of `storage`, as sorted blob indices, in `out`.
fn data_blobs(storage: runtime.storage.Storage, out: []u64) ![]u64 {
    const names = storage.scan(gpa, data_partition) catch |err| switch (err) {
        error.PartitionMissing => return out[0..0],
        else => return err,
    };
    defer names.deinit(gpa);
    try testing.expect(names.items.len <= out.len);
    for (names.items, out[0..names.items.len]) |name, *index| {
        try testing.expectEqual(@as(usize, 8), name.len);
        index.* = std.mem.readInt(u64, name[0..8], .big);
    }
    const indices = out[0..names.items.len];
    std.mem.sort(u64, indices, {}, std.sort.asc(u64));
    return indices;
}

fn keeps_predecessor_sync(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    f.pending.unblock();
    var journal = try f.open(3);
    // Rollover starts a predecessor sync.
    _ = try journal.append_many(&.{ 1, 2, 3, 4 });
    try testing.expect(journal.blobs.tail_predecessor_sync != null);
    // The handle includes the predecessor; the slot drains later.
    const completion = try journal.start_sync();
    try testing.expect(journal.blobs.tail_predecessor_sync != null);
    try completion.wait_release();
    try testing.expect(journal.blobs.tail_predecessor_sync != null);
    try journal.destroy();
}

test "fixed start_sync keeps the predecessor sync" {
    // commonware `test_start_sync_keeps_predecessor_sync`.
    try run(keeps_predecessor_sync);
}

fn advances_watermark_lagged(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    {
        var journal = try f.open(100);
        defer journal.deinit();
        // Nothing proven while the first sync is parked: the watermark must not move.
        try append_values(&journal, &.{ 1, 2, 3 });
        const h1 = try journal.start_sync();
        try testing.expectEqual(@as(u64, 0), journal.recovery_watermark());
        f.pending.release_all();
        try h1.wait_release();
        // The first sync is proven, so the next call advances the watermark to its size, one
        // interval behind the tip.
        _ = try journal.append(4);
        const h2 = try journal.start_sync();
        try testing.expectEqual(@as(u64, 3), journal.recovery_watermark());
        try f.drive(h2);
        // A third call catches the watermark up to the second sync's size.
        const h3 = try drive_call(ctx, &f.pending, Journal.start_sync, .{&journal});
        try testing.expectEqual(@as(u64, 4), journal.recovery_watermark());
        try f.drive(h3);
    }
    // The advanced watermark is durable: a reopen resumes from it.
    f.pending.unblock();
    var journal = try f.open(100);
    try testing.expectEqual(@as(u64, 4), journal.recovery_watermark());
    try testing.expectEqual(Bounds{ .start = 0, .end = 4 }, journal.get_bounds());
    try journal.destroy();
}

test "fixed start_sync advances the watermark lagged" {
    // commonware `test_start_sync_advances_watermark_lagged`.
    try run(advances_watermark_lagged);
}

fn failure_blocks_watermark(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var journal = try f.open(3);
    defer journal.deinit();
    // Filling the first blob seals it and starts its sync. The next start_sync syncs the fresh
    // tail.
    try append_values(&journal, &.{ 1, 2, 3 });
    const h1 = try journal.start_sync();
    // Fail the sealed blob's sync and let the tail sync land.
    f.pending.next().release(error.Io);
    f.pending.release_all();
    try testing.expectError(error.Io, h1.wait_release());
    // The failed sync proves nothing. The next call succeeds because the tail sync landed, but
    // it must not advance the watermark past the lost blob.
    try testing.expectEqual(@as(u64, 0), journal.barrier.boundary());
    const h2 = try journal.start_sync();
    try testing.expectEqual(@as(u64, 0), journal.recovery_watermark());
    f.pending.release_all();
    try testing.expectError(error.Io, h2.wait_release());
    // A failed tail sync fails the next call.
    _ = try journal.append(4);
    (try journal.start_sync()).release();
    f.pending.fail_all();
    try testing.expectError(error.Io, journal.start_sync());
}

test "fixed start_sync failure blocks the watermark" {
    // commonware `test_start_sync_failure_blocks_watermark`.
    try run(failure_blocks_watermark);
}

fn truncate_drains_parked_advance(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    {
        var journal = try f.open(100);
        try append_values(&journal, &.{ 1, 2, 3 });
        const h1 = try journal.start_sync();
        f.pending.release_all();
        try h1.wait_release();
        // This parks the metadata sync advancing the watermark to 3.
        _ = try journal.append(4);
        const h2 = try journal.start_sync();
        try testing.expectEqual(@as(u64, 3), journal.recovery_watermark());
        // Truncate below the in-flight advance (a sync, then a reopen of at most two items).
        // The lowered value must win on reopen.
        try drive_call(ctx, &f.pending, Journal.sync, .{&journal});
        h2.release();
        journal.deinit();
        const storage = f.delayed.storage();
        const cfg = f.cfg(100);
        journal = try drive_call(ctx, &f.pending, Journal.init_at_most, .{ gpa, storage, cfg, 2 });
        defer journal.deinit();
        try testing.expectEqual(@as(u64, 2), journal.recovery_watermark());
    }
    // Reopen: the lowered watermark held, and no corruption is reported.
    f.pending.unblock();
    var journal = try f.open(100);
    try testing.expectEqual(@as(u64, 2), journal.recovery_watermark());
    try testing.expectEqual(Bounds{ .start = 0, .end = 2 }, journal.get_bounds());
    try journal.destroy();
}

test "fixed truncate drains a parked watermark advance" {
    // commonware `test_truncate_drains_parked_watermark_advance`.
    try run(truncate_drains_parked_advance);
}

fn advance_deferred_failure(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var journal = try f.open(100);
    defer journal.deinit();
    try append_values(&journal, &.{ 1, 2, 3 });
    const h1 = try journal.start_sync();
    f.pending.release_all();
    try h1.wait_release();
    // Only the advance's metadata fsync is in flight: its failure surfaces on the handle even
    // though the data is durable.
    const h2 = try journal.start_sync();
    f.pending.fail_all();
    try testing.expectError(error.Io, h2.wait_release());
    // An advance at or below the staged value is skipped, so the next handle succeeds: the
    // failure is observed only by the next checkpoint write.
    _ = try journal.append(4);
    const h3 = try journal.start_sync();
    try f.drive(h3);
    // Commit (which does not write the checkpoint) still succeeds, and the next checkpoint
    // write observes the failure and fails.
    try drive_call(ctx, &f.pending, Journal.commit, .{&journal});
    try testing.expectError(error.Io, drive_call(ctx, &f.pending, Journal.sync, .{&journal}));
}

test "fixed watermark advance deferred failure" {
    // commonware `test_start_sync_watermark_advance_deferred_failure`.
    try run(advance_deferred_failure);
}

fn destroy_observes_failed_watermark_sync(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var journal = try f.open(100);
    try append_values(&journal, &.{ 1, 2, 3 });
    try drive_call(ctx, &f.pending, Journal.sync, .{&journal});
    // Make item 4 durable without advancing the watermark, then start the advance to 4, drop
    // its handle, and fail its checkpoint sync, the only sync that advance starts.
    _ = try journal.append(4);
    const first = try journal.start_sync();
    f.pending.release_all();
    try first.wait_release();
    (try journal.start_sync()).release();
    try testing.expectEqual(@as(usize, 1), f.pending.parked());
    f.pending.fail_all();
    try testing.expectError(error.Io, journal.destroy());
    var blobs: [4]u64 = undefined;
    try testing.expectEqualSlices(u64, &.{0}, try data_blobs(f.inner.storage(), &blobs));
    var reopened = try Journal.init(gpa, f.inner.storage(), f.cfg(100));
    try testing.expectEqual(@as(u64, 4), reopened.size());
    try reopened.destroy();
}

test "fixed destroy observes a failed watermark sync" {
    // commonware `test_fixed_destroy_observes_failed_watermark_sync_before_removal`.
    try run(destroy_observes_failed_watermark_sync);
}

/// Memory storage behind `runtime.storage.faulty`, whose sync failure rate a test sets
/// (commonware `storage_fault_config().sync_rate`).
const Faulted = struct {
    const Faulty = runtime.storage.faulty.Storage(utils.rng.TestRng);

    inner: runtime.storage.memory.Storage,
    rng: utils.rng.TestRng,
    storage: Faulty,
    cache: paged.CacheRef,

    fn init(self: *Faulted) !void {
        self.inner = .init(gpa);
        self.rng = .init(0);
        self.storage = .init(gpa, &self.inner, &self.rng, .{});
        self.cache = try paged.CacheRef.init(gpa, 44, 3);
    }

    fn deinit(self: *Faulted) void {
        self.cache.deinit();
        self.storage.deinit();
        self.inner.deinit();
    }

    fn open(self: *Faulted, items_per_blob: u64) !Journal {
        return Journal.init(gpa, self.storage.storage(), .{
            .partition = "test-partition",
            .items_per_blob = items_per_blob,
            .cache_ref = &self.cache,
            .write_buffer = 2048,
            .replay_buffer = 2048,
        });
    }

    fn fail_syncs(self: *Faulted, fail: bool) void {
        self.storage.config = if (fail) .{ .sync_rate = .one } else .{};
    }
};

const FailedSync = enum { tail, predecessor };
const Boundary = enum { rollover, clear, destroy };

/// A failed sync nobody observed prevents data blob creation and removal.
fn dropped_failure_blocks_blob_changes(failed: FailedSync, boundary: Boundary) !void {
    var h: Faulted = undefined;
    try h.init();
    defer h.deinit();
    var journal = try h.open(3);
    var consumed = false;
    defer if (!consumed) journal.deinit();
    // Fail a sync without observing it: either the tail's started sync, whose handle is
    // dropped, or the sync started by the rollover that seals the first blob.
    const blobs: u64 = switch (failed) {
        .tail => blobs: {
            _ = try journal.append(0);
            h.fail_syncs(true);
            (try journal.start_sync()).release();
            break :blobs 1;
        },
        .predecessor => blobs: {
            _ = try journal.append_many(&.{ 0, 1 });
            h.fail_syncs(true);
            _ = try journal.append(2);
            break :blobs 2;
        },
    };
    h.fail_syncs(false);
    // The failure must surface before the operation changes the data blob namespace.
    const size = journal.size();
    switch (boundary) {
        .rollover => {
            const result = journal.append_many(&.{ size, size + 1, size + 2 });
            try testing.expectError(error.Io, result);
        },
        .clear => try testing.expectError(error.Io, journal.clear_to_size(size)),
        .destroy => {
            consumed = true;
            try testing.expectError(error.Io, journal.destroy());
        },
    }
    var names: [4]u64 = undefined;
    const indices = try data_blobs(h.inner.storage(), &names);
    try testing.expectEqual(blobs, indices.len);
    for (indices, 0..) |index, expected| try testing.expectEqual(expected, index);
}

test "fixed dropped failed start_sync blocks blob changes" {
    // commonware `test_fixed_dropped_failed_start_sync_blocks_blob_changes`.
    for ([_]FailedSync{ .tail, .predecessor }) |failed| {
        for ([_]Boundary{ .rollover, .clear, .destroy }) |boundary| {
            try dropped_failure_blocks_blob_changes(failed, boundary);
        }
    }
}

test "fixed dropped failed start_sync surfaces before rollover" {
    // commonware `test_fixed_dropped_failed_start_sync_surfaces_before_rollover`.
    var h: Faulted = undefined;
    try h.init();
    defer h.deinit();
    var journal = try h.open(1000);
    defer journal.deinit();
    // Prove one item durable, then buffer more so the next start_sync rewrites the tail page.
    // Fail the sync it starts and drop the returned handle unobserved.
    _ = try journal.append(0);
    try journal.sync();
    _ = try journal.append_many(&.{ 1, 2, 3 });
    h.fail_syncs(true);
    (try journal.start_sync()).release();
    h.fail_syncs(false);
    // The flush must observe the failed sync before reusing a checksum slot that still protects
    // the durable prefix.
    const overflow: [300]u64 = @splat(0);
    try testing.expectError(error.Io, journal.append_many(&overflow));
}

fn run(comptime body: fn (Context) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(body, .{}));
}
