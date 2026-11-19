//! Paged writer waits on an outstanding `start_sync` before flushing or resizing, and the
//! durability operations of buffer and paged writer syncs (commonware `utils/buffer/mod.rs`
//! and `paged/writer.rs` tests over `DelayedSyncBlob` and `SyncTrackingBlob`).
//!
//! commonware's `SyncTrackingBlob` tells full syncs from range syncs; zigware's `Blob` has no
//! range sync (a durable write is a write and a full sync), so the counts here are writes and
//! total syncs: commonware's `full_syncs + range_syncs`.

const std = @import("std");
const testing = std.testing;
const memory = @import("../storage/memory.zig");
const counting = @import("mocks.zig");
const mocks = @import("../storage/mocks.zig");
const deterministic = @import("../deterministic.zig");
const Write = @import("write.zig").Write;
const paged = @import("paged/mod.zig");

const test_gpa = testing.allocator;
const Context = deterministic.Context;
const page_size: u16 = 103;
const capacity: usize = page_size * 2;

/// Counting memory storage, optionally behind a `DelayedSynced` wrapper.
const Fixture = struct {
    inner: counting.Storage,
    pending: mocks.DelayedSync,
    delayed: mocks.DelayedSynced,
    cache_ref: paged.CacheRef,

    fn init(self: *Fixture, io: std.Io) !void {
        self.inner = .init(test_gpa);
        self.pending = .init(test_gpa, io);
        self.delayed = .init(test_gpa, self.inner.interface(), &self.pending);
        self.cache_ref = try paged.CacheRef.init(test_gpa, page_size, 8);
    }

    fn deinit(self: *Fixture) void {
        self.cache_ref.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    /// A paged writer (`recovering` keeps truncation allowed); `delayed` parks its syncs.
    fn writer(self: *Fixture, name: []const u8, delayed: bool, recovering: bool) !paged.Writer {
        const store = if (delayed) self.delayed.storage() else self.inner.interface();
        const opened = try store.open("buffer", name);
        errdefer opened.blob.close();
        var w = try paged.Writer.open_recovery(
            test_gpa,
            opened.blob,
            opened.len,
            capacity,
            &self.cache_ref,
        );
        if (!recovering) w.finish_recovery();
        return w;
    }

    fn write(self: *Fixture, name: []const u8) !Write {
        const opened = try self.inner.interface().open("buffer", name);
        errdefer opened.blob.close();
        return Write.init(test_gpa, opened.blob, opened.len, 8);
    }

    /// Check the writes and syncs that reached storage so far.
    fn expect_ops(self: *Fixture, writes: u64, syncs: u64) !void {
        try testing.expectEqual(writes, self.inner.writes);
        try testing.expectEqual(syncs, self.inner.syncs);
    }

    fn expect_durable(self: *Fixture, name: []const u8, expected: []const u8) !void {
        const contents = (try self.inner.backend.logical_blob(test_gpa, "buffer", name)).?;
        defer test_gpa.free(contents);
        try testing.expectEqualSlices(u8, expected, contents);
    }

    /// Reopen `name` and check its logical bytes.
    fn expect_reopened(self: *Fixture, name: []const u8, expected: []const u8) !void {
        var w = try self.writer(name, false, true);
        defer w.deinit();
        try testing.expectEqual(@as(u64, expected.len), w.size());
        const buf = try test_gpa.alloc(u8, expected.len);
        defer test_gpa.free(buf);
        try w.read_at(0, buf);
        try testing.expectEqualSlices(u8, expected, buf);
    }

    /// Sleep so a spawned task parks, take the oldest parked sync, and check it has a waiter.
    fn parked_with_waiter(self: *Fixture, ctx: Context) !mocks.Deferred {
        try ctx.sleep(.fromMilliseconds(10));
        const deferred = self.pending.next();
        try testing.expect(deferred.blocked());
        return deferred;
    }
};

fn run(comptime body: fn (Context) anyerror!void) !void {
    var runner = try deterministic.Runner.init(test_gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(body, .{}));
}

fn append_past_buffer(ctx: Context, w: *paged.Writer) anyerror!void {
    _ = ctx;
    var data: [capacity + page_size]u8 = undefined;
    @memset(&data, 7);
    _ = try w.append(&data);
}

fn take_snapshot(ctx: Context, w: *paged.Writer) anyerror!paged.Sealed {
    _ = ctx;
    return w.snapshot();
}

fn take_replay(ctx: Context, w: *paged.Writer) anyerror!paged.Replay {
    _ = ctx;
    return w.replay(1024, .{});
}

fn truncate_to_page(ctx: Context, w: *paged.Writer, done: *bool) anyerror!void {
    _ = ctx;
    try w.truncate(page_size);
    done.* = true;
}

const WaitTests = struct {
    fn write_flush(ctx: Context) !void {
        var f: Fixture = undefined;
        try f.init(ctx.io());
        defer f.deinit();
        var w = try f.writer("append", true, false);
        defer w.deinit();
        // A fresh writer starts dirty, so this sync parks.
        const prior = try w.start_sync();
        defer prior.release();
        const handle = try ctx.child("append").spawn(append_past_buffer, .{&w});
        const deferred = try f.parked_with_waiter(ctx);
        try f.expect_ops(0, 0);
        deferred.release({});
        try try handle.join();
        try prior.wait();
        try w.sync();
        try testing.expect(f.inner.writes > 0);
        try testing.expect(f.inner.syncs > 1);
    }

    fn snapshot(ctx: Context) !void {
        var f: Fixture = undefined;
        try f.init(ctx.io());
        defer f.deinit();
        var w = try f.writer("snapshot", true, false);
        defer w.deinit();
        // Start a sync, then buffer a full page and a partial page not covered by it.
        var data: [page_size + 47]u8 = undefined;
        @memset(&data, 7);
        const prior = try w.start_sync();
        defer prior.release();
        _ = try w.append(&data);
        const handle = try ctx.child("snapshot").spawn(take_snapshot, .{&w});
        // Snapshot waits before flushing the full page.
        const deferred = try f.parked_with_waiter(ctx);
        try f.expect_ops(0, 0);
        deferred.release({});
        var sealed = try try handle.join();
        defer sealed.deinit();
        try prior.wait();
        var read: [data.len]u8 = undefined;
        try sealed.read_at(0, &read);
        try testing.expectEqualSlices(u8, &data, &read);
        try f.expect_ops(1, 1);
    }

    fn replay(ctx: Context) !void {
        var f: Fixture = undefined;
        try f.init(ctx.io());
        defer f.deinit();
        var w = try f.writer("replay", true, false);
        defer w.deinit();
        const prior = try w.start_sync();
        defer prior.release();
        _ = try w.append("hello world");
        const handle = try ctx.child("replay").spawn(take_replay, .{&w});
        // Replay waits before flushing the buffered bytes.
        const deferred = try f.parked_with_waiter(ctx);
        try f.expect_ops(0, 0);
        deferred.release({});
        var replayed = try try handle.join();
        defer replayed.deinit();
        try prior.wait();
        try testing.expect(try replayed.ensure(1));
        try testing.expectEqual(@as(u8, 'h'), replayed.bytes()[0]);
        try f.expect_ops(1, 1);
    }

    fn truncate_shrink(ctx: Context) !void {
        var f: Fixture = undefined;
        try f.init(ctx.io());
        defer f.deinit();
        var w = try f.writer("shrink", true, true);
        defer w.deinit();
        // Durable pages, then a started sync for a newer partial page.
        var data: [page_size * 2]u8 = undefined;
        @memset(&data, 3);
        _ = try w.append(&data);
        try w.sync();
        _ = try w.append("x");
        const prior = try w.start_sync();
        defer prior.release();
        try testing.expect(prior.is_pending());
        var done = false;
        const handle = try ctx.child("shrink").spawn(truncate_to_page, .{ &w, &done });
        // The shrink waits before resizing the blob.
        const deferred = try f.parked_with_waiter(ctx);
        try testing.expectEqual(@as(u64, 0), f.inner.resizes);
        try testing.expect(!done);
        deferred.release({});
        try try handle.join();
        try prior.wait();
        try testing.expect(done);
        try testing.expectEqual(@as(u64, 1), f.inner.resizes);
        try testing.expectEqual(@as(u64, page_size), w.size());
    }
};

test "paged write flush waits for an outstanding start_sync" {
    // commonware `test_write_flush_waits_for_outstanding_start_sync`.
    try run(WaitTests.write_flush);
}

test "paged snapshot waits for an outstanding start_sync before flushing" {
    // commonware `test_snapshot_waits_for_outstanding_start_sync_before_flushing`.
    try run(WaitTests.snapshot);
}

test "paged replay waits for an outstanding start_sync before flushing" {
    // commonware `test_replay_waits_for_outstanding_start_sync_before_flushing`.
    try run(WaitTests.replay);
}

test "paged recovery truncate waits for an outstanding start_sync before resizing" {
    // commonware `test_recovery_truncate_shrink_waits_for_outstanding_start_sync_before_resizing`.
    try run(WaitTests.truncate_shrink);
}

test "paged start_sync flush failure returns the error" {
    // commonware `test_start_sync_flush_failure_returns_err`.
    var inner: memory.Storage = .init(test_gpa);
    defer inner.deinit();
    var faults: mocks.WriteFaults = .{};
    var wrapper: mocks.WriteFault = .init(test_gpa, inner.storage(), &faults);
    var cache_ref = try paged.CacheRef.init(test_gpa, page_size, 4);
    defer cache_ref.deinit();
    const opened = try wrapper.storage().open("buffer", "flush");
    var w = try paged.Writer.init(test_gpa, opened.blob, opened.len, capacity, &cache_ref);
    defer w.deinit();
    // A durable partial page, extended so the next flush rewrites it.
    const durable: [24]u8 = @splat(1);
    const extension: [8]u8 = @splat(2);
    _ = try w.append(&durable);
    try w.sync();
    _ = try w.append(&extension);
    faults.arm();
    try testing.expectError(error.Io, w.start_sync());
    try testing.expect(w.failed);
}

test "write sync durability operations (test_write_*_range_sync_*, *_full_sync_after_resize)" {
    // commonware `test_write_start_sync_persists_and_marks_clean`,
    // `test_write_sync_uses_range_sync_for_buffer_only_write`,
    // `test_write_sync_uses_full_sync_after_resize`.
    var f: Fixture = undefined;
    try f.init(testing.io);
    defer f.deinit();
    var started = try f.write("started");
    defer started.deinit();
    // A fresh writer starts dirty: the started sync covers the write and earlier mutations.
    try started.write_at(0, "abc");
    const handle = try started.start_sync();
    try handle.wait();
    handle.release();
    try f.expect_durable("started", "abc");
    try f.expect_ops(1, 1);
    try started.write_at(3, "d");
    try started.sync();
    try f.expect_durable("started", "abcd");
    try f.expect_ops(2, 2);
    // Nothing left to sync.
    const idle = try started.start_sync();
    try testing.expect(!idle.is_pending());
    try started.wait_for_sync();
    try f.expect_ops(2, 2);

    var w = try f.write("resized");
    defer w.deinit();
    try w.sync();
    try f.expect_ops(2, 3);
    try w.write_at(0, "abcdef");
    try w.sync();
    try w.sync();
    try f.expect_ops(3, 4);
    // A resize is an unsynced mutation that the next sync covers.
    try w.resize(4);
    try w.sync();
    try f.expect_durable("resized", "abcd");
    try f.expect_ops(3, 5);
}

test "paged sync durability operations after plain flushes" {
    // commonware `test_sync_uses_range_sync_for_single_flush`,
    // `test_sync_uses_full_sync_after_prior_plain_flush`,
    // `test_sync_uses_full_sync_after_replay_plain_flush`.
    var f: Fixture = undefined;
    try f.init(testing.io);
    defer f.deinit();
    var single = try f.writer("single", false, false);
    try single.sync();
    try f.expect_ops(0, 1);
    _ = try single.append("hello world");
    try single.sync();
    try single.sync();
    try f.expect_ops(1, 2);
    single.deinit();
    try f.expect_reopened("single", "hello world");

    // Overflowing the buffer flushes full pages plainly before sync writes the tip.
    var data: [capacity + 4]u8 = undefined;
    @memset(&data, 7);
    var plain = try f.writer("plain", false, false);
    defer plain.deinit();
    _ = try plain.append(data[0 .. capacity + 1]);
    try plain.sync();
    try plain.sync();
    try f.expect_ops(3, 3);
    _ = try plain.append("tip");
    try plain.sync();
    try f.expect_ops(4, 4);
    @memcpy(data[capacity + 1 ..], "tip");
    var check: [data.len]u8 = undefined;
    try plain.read_at(0, &check);
    try testing.expectEqualSlices(u8, &data, &check);

    // Replay flushes for reading without syncing; the next sync covers that write.
    var replayed = try f.writer("replayed", false, false);
    defer replayed.deinit();
    _ = try replayed.append("replayed");
    var replay = try replayed.replay(1024, .{});
    defer replay.deinit();
    try testing.expect(try replay.ensure(8));
    try testing.expectEqualStrings("replayed", replay.bytes()[0..8]);
    try f.expect_ops(5, 4);
    try replayed.sync();
    try f.expect_ops(5, 5);
}

test "paged recreated writer sync barriers (test_recreated_sync_*)" {
    // commonware `test_recreated_sync_preserves_replay_plain_flush_barrier`,
    // `test_recreated_sync_skips_barrier_after_invalid_truncation`.
    var f: Fixture = undefined;
    try f.init(testing.io);
    defer f.deinit();
    // commonware's tracking blob keeps writes the writer dropped without syncing.
    f.inner.keep_unsynced = true;
    var replayed = try f.writer("replayed", false, false);
    _ = try replayed.append("replayed");
    var replay = try replayed.replay(1024, .{});
    try testing.expect(try replay.ensure(8));
    replay.deinit();
    replayed.deinit();
    try f.expect_ops(1, 0);
    // The reopened writer cannot know the plain write is durable, so its sync is a barrier.
    var reopened = try f.writer("replayed", false, true);
    try testing.expectEqual(@as(u64, 8), reopened.size());
    try reopened.sync();
    reopened.deinit();
    try f.expect_ops(1, 1);
    f.inner.keep_unsynced = false;

    var valid = try f.writer("valid", false, false);
    try valid.sync();
    _ = try valid.append("valid");
    try valid.sync();
    valid.deinit();
    try f.expect_ops(2, 3);
    // Trailing junk is trimmed and synced at open, so the next sync has nothing to do.
    const opened = try f.inner.interface().open("buffer", "valid");
    try opened.blob.write_at(opened.len, "junk", .{});
    try opened.blob.sync();
    opened.blob.close();
    var trimmed = try f.writer("valid", false, false);
    defer trimmed.deinit();
    try testing.expectEqual(@as(u64, 5), trimmed.size());
    try f.expect_ops(3, 5);
    try trimmed.sync();
    try f.expect_ops(3, 5);
}

test "paged recovery truncate durability operations (test_recovery_truncate_*_sync*)" {
    // commonware `test_recovery_truncate_partial_shrink_without_physical_resize_uses_range_sync`,
    // `..._partial_shrink_with_physical_resize_clears_full_sync_requirement`,
    // `test_recovery_truncate_page_boundary_shrink_uses_full_sync`.
    var f: Fixture = undefined;
    try f.init(testing.io);
    defer f.deinit();
    var data: [page_size * 2]u8 = undefined;
    @memset(&data, 9);
    // Within one physical page, a shrink only rewrites checksum slots (3 durable writes).
    var same = try f.writer("same", false, true);
    defer same.deinit();
    try same.sync();
    _ = try same.append(data[0..page_size]);
    try same.sync();
    try same.truncate(50);
    try same.sync();
    try f.expect_ops(4, 5);
    try testing.expectEqual(@as(u64, 0), f.inner.resizes);

    // A shrink across pages also resizes; its checksum rewrites make the resize durable.
    var resized = try f.writer("resized", false, true);
    defer resized.deinit();
    try resized.sync();
    _ = try resized.append(&data);
    try resized.sync();
    try resized.truncate(50);
    try resized.sync();
    try f.expect_ops(8, 10);
    _ = try resized.append("x");
    try resized.sync();
    try f.expect_ops(9, 11);
    var expected = data[0..51].*;
    expected[50] = 'x';
    var check: [51]u8 = undefined;
    try resized.read_at(0, &check);
    try testing.expectEqualSlices(u8, &expected, &check);

    // A page-boundary shrink resizes without rewriting checksums, then syncs once.
    var boundary = try f.writer("boundary", false, true);
    try boundary.sync();
    _ = try boundary.append(&data);
    try boundary.sync();
    try boundary.truncate(page_size);
    try f.expect_ops(10, 14);
    try boundary.sync();
    try f.expect_ops(10, 14);
    try testing.expectEqual(@as(u64, 2), f.inner.resizes);
    boundary.deinit();
    try f.expect_reopened("boundary", data[0..page_size]);
}
