//! commonware's `journal/contiguous/variable.rs` tests of started sync handles: the predecessor
//! sync slot, offsets staged while the data waits, the lagging offsets watermark and its joint
//! proof, parked and failed syncs, and dropped handles whose failure surfaces at the next
//! rollover, `start_sync`, or destroy. `runtime.storage.mocks.DelayedSync` holds started syncs
//! (`DelayedSyncContext`, `PendingSyncs`). commonware's `test_truncate` (sync, then reopen at
//! most a cap) is a driven `sync` and an `init_at_most` reopen here.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const variable = @import("variable.zig");
const contiguous = @import("mod.zig");

const gpa = testing.allocator;
const Journal = variable.Journal(u64);
const Bounds = contiguous.Bounds;
const Context = runtime.deterministic.Context;
const Completion = runtime.storage.Completion;
const DelayedSync = runtime.storage.mocks.DelayedSync;
const DelayedSynced = runtime.storage.mocks.DelayedSynced;

/// commonware's page geometry: 101-byte pages, two cached, for most tests; the destroy tests
/// use `initialization_cfg` (16-byte pages, four cached, a one-byte write buffer).
const Geometry = enum { standard, initialization };

/// Memory storage behind a `DelayedSynced` wrapper, plus a page cache.
const Fixture = struct {
    inner: runtime.storage.memory.Storage,
    pending: DelayedSync,
    delayed: DelayedSynced,
    cache: paged.CacheRef,
    geometry: Geometry,

    fn init(self: *Fixture, ctx: Context, geometry: Geometry) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
        self.geometry = geometry;
        self.cache = switch (geometry) {
            .standard => try paged.CacheRef.init(gpa, 101, 2),
            .initialization => try paged.CacheRef.init(gpa, 16, 4),
        };
    }

    fn deinit(self: *Fixture) void {
        self.cache.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    fn cfg(self: *Fixture, items_per_section: u64) Journal.Cfg {
        const initialization = self.geometry == .initialization;
        return .{
            .partition = "start-sync-handles",
            .items_per_section = items_per_section,
            .codec_config = {},
            .cache_ref = &self.cache,
            .write_buffer = if (initialization) 1 else 2048,
            .replay_buffer = if (initialization) 256 else 2048,
        };
    }

    fn open(self: *Fixture, items_per_section: u64) !Journal {
        return Journal.init(gpa, self.delayed.storage(), self.cfg(items_per_section));
    }

    /// Release parked syncs until `completion` completes (commonware `drive_pending_syncs`).
    fn drive(self: *Fixture, completion: Completion) !void {
        while (completion.is_pending()) self.pending.release_all();
        try completion.wait_release();
    }

    /// The number of data blobs in the inner storage.
    fn data_blobs(self: *Fixture) !usize {
        const names = try self.inner.storage().scan(gpa, "start-sync-handles_data");
        defer names.deinit(gpa);
        return names.items.len;
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

fn keeps_predecessor_sync(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .standard);
    defer f.deinit();
    f.pending.unblock();
    var journal = try f.open(3);
    _ = try journal.append_many(&.{ 1, 2, 3, 4 });
    try testing.expect(journal.blobs.tail_predecessor_sync != null);
    // The handle includes the predecessor; the slot drains later.
    const completion = try journal.start_sync();
    try testing.expect(journal.blobs.tail_predecessor_sync != null);
    try completion.wait_release();
    try testing.expect(journal.blobs.tail_predecessor_sync != null);
    try journal.destroy();
}

test "variable start_sync keeps the predecessor sync" {
    // commonware `test_start_sync_keeps_predecessor_sync`.
    try run(keeps_predecessor_sync);
}

fn starting(ctx: Context, journal: *Journal, done: *bool) anyerror!Completion {
    _ = ctx;
    defer done.* = true;
    return journal.start_sync();
}

fn StagesOffsets(comptime release_data_first: bool) type {
    return struct {
        fn body(ctx: Context) !void {
            var f: Fixture = undefined;
            try f.init(ctx, .standard);
            defer f.deinit();
            var journal = try f.open(100);
            _ = try journal.append(1);
            const first = try journal.start_sync();
            const prior_data = f.pending.next();
            f.pending.next().release({});
            // The prior data sync gates the next data flush, while offsets can be written.
            _ = try journal.append(2);
            const starts = f.pending.starts();
            var done = false;
            const call = try ctx.child("start").spawn(starting, .{ &journal, &done });
            while (!prior_data.blocked()) try ctx.sleep(.fromMilliseconds(1));
            try testing.expect(!done);
            try testing.expectEqual(starts + 1, f.pending.starts());
            const offsets = f.pending.next();
            prior_data.release({});
            const handle = try try call.join();
            try first.wait_release();
            const data = f.pending.next();
            f.pending.release_all();
            const early, const late = if (release_data_first) .{ data, offsets } else .{
                offsets,
                data,
            };
            early.release({});
            try testing.expect(handle.is_pending());
            try testing.expectEqual(@as(u64, 1), journal.barrier.boundary());
            late.release({});
            try handle.wait_release();
            try testing.expectEqual(@as(u64, 2), journal.barrier.boundary());
            try drive_call(ctx, &f.pending, Journal.destroy, .{&journal});
        }
    };
}

test "variable start_sync stages offsets while the data waits" {
    // commonware `test_start_sync_stages_offsets_while_data_waits`, both release orders.
    try run(StagesOffsets(false).body);
    try run(StagesOffsets(true).body);
}

fn offsets_watermark_lagged(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .standard);
    defer f.deinit();
    {
        var journal = try f.open(100);
        defer journal.deinit();
        // Nothing proven while the first sync is parked: the anchor must not move.
        try append_values(&journal, &.{ 1, 2, 3 });
        const h1 = try journal.start_sync();
        try testing.expectEqual(@as(u64, 0), journal.recovery_watermark());
        f.pending.release_all();
        try f.drive(h1);
        // The first sync is jointly proven (data and offsets), so the next call advances the
        // offsets watermark to its size, one interval behind the tip.
        _ = try journal.append(4);
        const h2 = try journal.start_sync();
        try testing.expectEqual(@as(u64, 3), journal.recovery_watermark());
        try f.drive(h2);
    }
    // The advanced anchor is durable: a reopen replays only past it, then init's align
    // catches the anchor up to the recovered size.
    f.pending.unblock();
    var journal = try f.open(100);
    try testing.expectEqual(@as(u64, 4), journal.recovery_watermark());
    try testing.expectEqual(Bounds{ .start = 0, .end = 4 }, journal.get_bounds());
    for (0..4) |i| try testing.expectEqual(@as(u64, i + 1), try journal.read(i));
    try journal.destroy();
}

test "variable start_sync advances the offsets watermark lagged" {
    // commonware `test_start_sync_advances_offsets_watermark_lagged`.
    try run(offsets_watermark_lagged);
}

fn watermark_requires_joint_proof(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .standard);
    defer f.deinit();
    var journal = try f.open(3);
    defer journal.deinit();
    // Filling the first section seals it in the offsets journal and then in the data blobs,
    // starting each sealed blob's sync. The next start_sync syncs both fresh tails.
    try append_values(&journal, &.{ 1, 2, 3 });
    const h1 = try journal.start_sync();
    // Fail the sealed data blob's sync and let every other sync land.
    const offsets_sealed = f.pending.next();
    const data_sealed = f.pending.next();
    offsets_sealed.release({});
    data_sealed.release(error.Io);
    f.pending.release_all();
    try testing.expectError(error.Io, h1.wait_release());
    // Offsets durability alone proves nothing. The next call succeeds because both tail syncs
    // landed, but it must not advance the anchor past the surviving data.
    try testing.expectEqual(@as(u64, 0), journal.barrier.boundary());
    const h2 = try journal.start_sync();
    try testing.expectEqual(@as(u64, 0), journal.recovery_watermark());
    f.pending.release_all();
    try testing.expectError(error.Io, h2.wait_release());
}

test "variable start_sync watermark requires a joint proof" {
    // commonware `test_start_sync_watermark_requires_joint_proof`.
    try run(watermark_requires_joint_proof);
}

fn truncate_truncates_durable_size(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .standard);
    defer f.deinit();
    var journal = try f.open(100);
    try append_values(&journal, &.{ 1, 2, 3 });
    try drive_call(ctx, &f.pending, Journal.sync, .{&journal});
    try testing.expectEqual(@as(u64, 3), journal.recovery_watermark());
    // Truncate discards the joint proof for position 2 (a sync, then a reopen of at most two
    // items). Re-append it, then fail the data sync while the offsets sync lands. The boundary
    // must not trust the stale proof.
    try drive_call(ctx, &f.pending, Journal.sync, .{&journal});
    journal.deinit();
    const storage = f.delayed.storage();
    const cfg = f.cfg(100);
    journal = try drive_call(ctx, &f.pending, Journal.init_at_most, .{ gpa, storage, cfg, 2 });
    defer journal.deinit();
    _ = try journal.append(9);
    const h1 = try journal.start_sync();
    const data = f.pending.next();
    f.pending.release_all();
    data.release(error.Io);
    try testing.expectError(error.Io, h1.wait_release());
    // The boundary stays at the truncate point, and the next call returns the retained failure.
    try testing.expectEqual(@as(u64, 2), journal.barrier.boundary());
    try testing.expectEqual(@as(u64, 2), journal.recovery_watermark());
    try testing.expectError(error.Io, journal.start_sync());
}

test "variable truncate truncates the durable size" {
    // commonware `test_truncate_truncates_durable_size`.
    try run(truncate_truncates_durable_size);
}

fn advance_deferred_failure(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .standard);
    defer f.deinit();
    var journal = try f.open(100);
    defer journal.deinit();
    try append_values(&journal, &.{ 1, 2, 3 });
    const h1 = try journal.start_sync();
    f.pending.release_all();
    try h1.wait_release();
    // Only the advance's offsets-checkpoint fsync is in flight: its failure surfaces on the
    // handle even though the data is durable.
    const h2 = try journal.start_sync();
    f.pending.fail_all();
    try testing.expectError(error.Io, h2.wait_release());
    // The checkpoint store retained the failure: commit (which does not write the checkpoint)
    // still succeeds, and the next operation that does fails.
    _ = try journal.append(4);
    try drive_call(ctx, &f.pending, Journal.commit, .{&journal});
    try testing.expectError(error.Io, drive_call(ctx, &f.pending, Journal.sync, .{&journal}));
}

test "variable watermark advance deferred failure" {
    // commonware `test_start_sync_watermark_advance_deferred_failure`.
    try run(advance_deferred_failure);
}

fn dropped_failure_surfaces_after_rollover(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .standard);
    defer f.deinit();
    var journal = try f.open(3);
    defer journal.deinit();
    // Buffer an item and drop the started sync's handle unobserved. Fail the data tail sync and
    // let the offsets sync land.
    _ = try journal.append(0);
    (try journal.start_sync()).release();
    f.pending.next().release(error.Io);
    f.pending.release_all();
    // Appending through the blob boundary must surface the failure.
    const items = [_]u64{ 1, 2, 3 };
    const result = drive_call(ctx, &f.pending, Journal.append_many, .{ &journal, &items });
    try testing.expectError(error.Io, result);
}

test "variable dropped failed start_sync surfaces after rollover" {
    // commonware `test_variable_dropped_failed_start_sync_surfaces_after_rollover`.
    try run(dropped_failure_surfaces_after_rollover);
}

fn dropped_offsets_failure_fails_next_start_sync(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .standard);
    defer f.deinit();
    var journal = try f.open(3);
    defer journal.deinit();
    // Buffer an item and drop the started sync's handle unobserved. Let the data tail sync land
    // and fail the offsets sync.
    _ = try journal.append(0);
    (try journal.start_sync()).release();
    f.pending.next().release({});
    f.pending.next().release(error.Io);
    f.pending.release_all();
    // The data sync landed, so commit succeeds.
    try journal.commit();
    // The next start_sync observes the failed offsets sync before starting new syncs.
    try testing.expectError(error.Io, journal.start_sync());
}

test "variable dropped failed offsets sync fails the next start_sync" {
    // commonware `test_variable_dropped_failed_offsets_sync_fails_next_start_sync`.
    try run(dropped_offsets_failure_fails_next_start_sync);
}

/// Three durable items through a driven sync.
fn sync_three(ctx: Context, f: *Fixture, journal: *Journal) !void {
    try append_values(journal, &.{ 1, 2, 3 });
    try drive_call(ctx, &f.pending, Journal.sync, .{journal});
}

fn expect_reopened(f: *Fixture, end: u64) !void {
    var journal = try Journal.init(gpa, f.inner.storage(), f.cfg(100));
    try testing.expectEqual(Bounds{ .start = 0, .end = end }, journal.get_bounds());
    try journal.destroy();
}

fn destroy_observes_failed_watermark_sync(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .initialization);
    defer f.deinit();
    var journal = try f.open(100);
    try sync_three(ctx, &f, &journal);
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
    try testing.expectEqual(@as(usize, 1), try f.data_blobs());
    try expect_reopened(&f, 4);
}

test "variable destroy observes a failed watermark sync" {
    // commonware `test_variable_destroy_observes_failed_watermark_sync_before_removal`.
    try run(destroy_observes_failed_watermark_sync);
}

fn destroy_observes_failed_offsets_blob_sync(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .initialization);
    defer f.deinit();
    var journal = try f.open(100);
    try sync_three(ctx, &f, &journal);
    // A commit makes item 4's data durable while leaving its offset unsynced and the watermark
    // at 3, so the next advance starts only the offsets blob sync. Fail it.
    _ = try journal.append(4);
    try drive_call(ctx, &f.pending, Journal.commit, .{&journal});
    (try journal.start_sync()).release();
    try testing.expectEqual(@as(usize, 1), f.pending.parked());
    f.pending.fail_all();
    try testing.expectError(error.Io, journal.destroy());
    try testing.expectEqual(@as(usize, 1), try f.data_blobs());
    try expect_reopened(&f, 4);
}

test "variable destroy observes a failed offsets blob sync" {
    // commonware `test_variable_destroy_observes_failed_offsets_blob_sync_before_removal`.
    try run(destroy_observes_failed_offsets_blob_sync);
}

fn destroy_observes_failed_data_sync(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx, .initialization);
    defer f.deinit();
    var journal = try f.open(100);
    try sync_three(ctx, &f, &journal);
    // Start a sync of item 4 and drop its handle. The data tail sync starts first. Fail it and
    // let every offsets sync land.
    _ = try journal.append(4);
    (try journal.start_sync()).release();
    f.pending.next().release(error.Io);
    f.pending.unblock();
    // Destroy returns the failure and the synced items survive it.
    try testing.expectError(error.Io, journal.destroy());
    try expect_reopened(&f, 3);
}

test "variable destroy observes a failed data sync" {
    // commonware `test_variable_destroy_observes_failed_data_sync_before_removal`.
    try run(destroy_observes_failed_data_sync);
}

fn run(comptime body: fn (Context) anyerror!void) !void {
    try soak_context(body, .{});
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
