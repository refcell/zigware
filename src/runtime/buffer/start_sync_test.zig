//! In-flight `start_sync` tests of the buffer writers (commonware `utils/buffer/mod.rs`,
//! `paged/writer.rs`, and `paged/sealed.rs` tests that hold a sync with `DelayedSyncBlob`).
//!
//! commonware asserts an operation is blocked with `now_or_never().is_none()`. Here the
//! operation runs as a spawned task on the deterministic runtime; the test sleeps, checks the
//! parked sync has a waiter and the operation has not reached the blob, releases, and joins.

const std = @import("std");
const testing = std.testing;
const iface = @import("../storage.zig");
const memory = @import("../storage/memory.zig");
const counting = @import("mocks.zig");
const mocks = @import("../storage/mocks.zig");
const deterministic = @import("../deterministic.zig");
const Write = @import("write.zig").Write;
const paged = @import("paged/mod.zig");

const gpa = testing.allocator;
const Context = deterministic.Context;
const page_size: u16 = 103;

/// Memory storage behind a `DelayedSynced` wrapper.
const Fixture = struct {
    inner: counting.Storage,
    pending: mocks.DelayedSync,
    delayed: mocks.DelayedSynced,

    fn init(self: *Fixture, ctx: Context) void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.interface(), &self.pending);
    }

    fn deinit(self: *Fixture) void {
        self.pending.deinit();
        self.inner.deinit();
    }

    fn write(self: *Fixture, name: []const u8) !Write {
        const opened = try self.delayed.storage().open("buffer", name);
        errdefer opened.blob.close();
        return Write.init(gpa, opened.blob, opened.len, 8);
    }

    fn writer(self: *Fixture, name: []const u8, cache_ref: *paged.CacheRef) !paged.Writer {
        const opened = try self.delayed.storage().open("buffer", name);
        errdefer opened.blob.close();
        return paged.Writer.init(gpa, opened.blob, opened.len, page_size * 2, cache_ref);
    }

    /// The durable logical length of `name`, 0 if nothing is durable yet.
    fn durable_len(self: *Fixture, name: []const u8) !usize {
        return @intCast(try self.inner.durable_len("buffer", name) orelse 0);
    }

    /// Blob writes that reached storage so far.
    fn writes(self: *Fixture) u64 {
        return self.inner.writes;
    }

    /// Sleep so a spawned task parks, take the oldest parked sync, and check it has a waiter.
    fn parked_with_waiter(self: *Fixture, ctx: Context) !mocks.Deferred {
        try ctx.sleep(.fromMilliseconds(10));
        const deferred = self.pending.next();
        try testing.expect(deferred.blocked());
        return deferred;
    }
};

fn write_sync(ctx: Context, w: *Write) anyerror!void {
    _ = ctx;
    try w.sync();
}

fn write_overlap(ctx: Context, w: *Write) anyerror!void {
    _ = ctx;
    try w.write_at(2, "ZZ");
}

fn write_resize(ctx: Context, w: *Write, done: *bool) anyerror!void {
    _ = ctx;
    try w.resize(3);
    done.* = true;
}

const WriteTests = struct {
    fn needs_sync(ctx: Context) !void {
        var f: Fixture = undefined;
        f.init(ctx);
        defer f.deinit();
        var w = try f.write("needs");
        defer w.deinit();
        try w.sync();
        try testing.expect(!w.needs_sync());
        // A started sync needs observation while in flight and after it completes.
        try w.write_at(0, "abc");
        const started = try w.start_sync();
        defer started.release();
        try testing.expect(w.needs_sync() and started.is_pending());
        f.pending.release_next(1);
        try started.wait();
        try testing.expect(w.needs_sync());
        try w.wait_for_sync();
        try testing.expect(!w.needs_sync());
        // A failed started sync is reported by its completion and by the next sync.
        try w.write_at(3, "d");
        const failed = try w.start_sync();
        defer failed.release();
        f.pending.fail_all();
        try testing.expectError(error.Io, failed.wait());
        try testing.expect(w.needs_sync());
        try testing.expectError(error.Io, w.sync());
        try testing.expect(w.failed);
    }

    fn sync_waits(ctx: Context) !void {
        var f: Fixture = undefined;
        f.init(ctx);
        defer f.deinit();
        var w = try f.write("sync");
        defer w.deinit();
        const started = try w.start_sync();
        defer started.release();
        // A small write stays buffered; the sync that flushes it waits for the started sync.
        try w.write_at(0, "abc");
        const handle = try ctx.child("sync").spawn(write_sync, .{&w});
        const deferred = try f.parked_with_waiter(ctx);
        try testing.expectEqual(@as(u64, 0), f.pending.completions());
        try testing.expectEqual(@as(usize, 0), try f.durable_len("sync"));
        deferred.release({});
        try try handle.join();
        try started.wait();
        try testing.expectEqual(@as(usize, 3), try f.durable_len("sync"));
    }

    fn overlap_waits(ctx: Context) !void {
        var f: Fixture = undefined;
        f.init(ctx);
        defer f.deinit();
        var w = try f.write("overlap");
        defer w.deinit();
        try w.write_at(0, "xxx");
        const started = try w.start_sync();
        const live = f.writes();
        defer started.release();
        try w.write_at(3, "abc"); // Buffered: no I/O while the sync is pending.
        const handle = try ctx.child("write").spawn(write_overlap, .{&w});
        const deferred = try f.parked_with_waiter(ctx);
        // The drained tip has not reached the blob.
        try testing.expectEqual(live, f.writes());
        deferred.release({});
        try try handle.join();
        try started.wait();
        try w.sync();
        var buf: [6]u8 = undefined;
        try w.read_at(0, &buf);
        try testing.expectEqualStrings("xxZZbc", &buf);
    }

    fn resize_waits(ctx: Context) !void {
        var f: Fixture = undefined;
        f.init(ctx);
        defer f.deinit();
        var w = try f.write("resize");
        defer w.deinit();
        try w.write_at(0, "abcdefghij");
        const started = try w.start_sync();
        defer started.release();
        var done = false;
        const handle = try ctx.child("resize").spawn(write_resize, .{ &w, &done });
        const deferred = try f.parked_with_waiter(ctx);
        try testing.expect(!done);
        deferred.release({});
        try try handle.join();
        try started.wait();
        try testing.expect(done);
        try w.sync();
        try testing.expectEqual(@as(usize, 3), try f.durable_len("resize"));
    }
};

test "write needs sync tracks a started sync (test_write_needs_sync_tracks_sync_work)" {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(WriteTests.needs_sync, .{}));
}

test "write sync waits for an outstanding start_sync (test_write_sync_*_waits_*)" {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(WriteTests.sync_waits, .{}));
}

test "write overlap flush waits for an outstanding start_sync" {
    // commonware `test_write_at_overlap_flush_waits_for_outstanding_start_sync`.
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(WriteTests.overlap_waits, .{}));
}

test "write resize waits for an outstanding start_sync before resizing" {
    // commonware `test_write_resize_waits_for_outstanding_start_sync_before_resizing`.
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(WriteTests.resize_waits, .{}));
}

test "write start_sync flush failure returns the error" {
    // commonware `test_write_start_sync_flush_failure_returns_err`.
    var inner: memory.Storage = .init(gpa);
    defer inner.deinit();
    var faults: mocks.WriteFaults = .{};
    var wrapper: mocks.WriteFault = .init(gpa, inner.storage(), &faults);
    const opened = try wrapper.storage().open("buffer", "flush");
    var w = try Write.init(gpa, opened.blob, opened.len, 8);
    defer w.deinit();
    try w.write_at(0, "abc");
    faults.arm();
    try testing.expectError(error.Io, w.start_sync());
    try testing.expect(w.failed);
}

fn paged_sync(ctx: Context, w: *paged.Writer) anyerror!void {
    _ = ctx;
    try w.sync();
}

fn paged_append(ctx: Context, w: *paged.Writer) anyerror!void {
    _ = ctx;
    var bytes: [page_size * 3]u8 = undefined;
    @memset(&bytes, 7);
    _ = try w.append(&bytes);
}

fn paged_seal(ctx: Context, w: *paged.Writer) anyerror!paged.Writer.Sealing {
    _ = ctx;
    return w.seal();
}

const PagedTests = struct {
    fn persists(ctx: Context) !void {
        var f: Fixture = undefined;
        f.init(ctx);
        defer f.deinit();
        var cache_ref = try paged.CacheRef.init(gpa, page_size, 4);
        defer cache_ref.deinit();
        var w = try f.writer("persist", &cache_ref);
        defer w.deinit();
        _ = try w.append("hello");
        const started = try w.start_sync();
        defer started.release();
        // Flushed but not durable until the parked sync is released.
        try testing.expect(w.needs_sync());
        try testing.expectEqual(@as(usize, 0), try f.durable_len("persist"));
        f.pending.release_next(1);
        try started.wait();
        try testing.expect(try f.durable_len("persist") > 0);
        try w.wait_for_sync();
        try testing.expect(!w.needs_sync());
        // With nothing left to sync, a start completes at once and parks nothing.
        const idle = try w.start_sync();
        try testing.expect(!idle.is_pending());
        try testing.expectEqual(@as(usize, 0), f.pending.parked());
    }

    fn sync_waits(ctx: Context) !void {
        var f: Fixture = undefined;
        f.init(ctx);
        defer f.deinit();
        var cache_ref = try paged.CacheRef.init(gpa, page_size, 4);
        defer cache_ref.deinit();
        var w = try f.writer("sync", &cache_ref);
        defer w.deinit();
        _ = try w.append("abc");
        const started = try w.start_sync();
        defer started.release();
        const live = f.writes();
        // The tip rewrite waits: the partial page is never rewritten under a pending sync.
        _ = try w.append("def");
        const handle = try ctx.child("sync").spawn(paged_sync, .{&w});
        const deferred = try f.parked_with_waiter(ctx);
        try testing.expectEqual(live, f.writes());
        deferred.release({});
        try try handle.join();
        try started.wait();
        try testing.expect(!w.needs_sync());
    }

    fn append_waits(ctx: Context) !void {
        var f: Fixture = undefined;
        f.init(ctx);
        defer f.deinit();
        var cache_ref = try paged.CacheRef.init(gpa, page_size, 4);
        defer cache_ref.deinit();
        var w = try f.writer("append", &cache_ref);
        defer w.deinit();
        _ = try w.append("abc");
        const started = try w.start_sync();
        defer started.release();
        const live = f.writes();
        // An append that must write pages waits; a buffered one would not.
        try testing.expect(w.try_append("d") != null);
        const handle = try ctx.child("append").spawn(paged_append, .{&w});
        const deferred = try f.parked_with_waiter(ctx);
        try testing.expectEqual(live, f.writes());
        deferred.release({});
        try try handle.join();
        try started.wait();
        try testing.expectEqual(@as(u64, 4 + page_size * 3), w.size());
    }

    fn seal_waits(ctx: Context) !void {
        var f: Fixture = undefined;
        f.init(ctx);
        defer f.deinit();
        var cache_ref = try paged.CacheRef.init(gpa, page_size, 4);
        defer cache_ref.deinit();
        var w = try f.writer("seal", &cache_ref);
        _ = try w.append("abc");
        const started = try w.start_sync();
        defer started.release();
        _ = try w.append("def");
        const handle = try ctx.child("seal").spawn(paged_seal, .{&w});
        const deferred = try f.parked_with_waiter(ctx);
        deferred.release({});
        const sealing = try try handle.join();
        defer sealing.completion.release();
        var sealed = sealing.sealed;
        defer sealed.deinit();
        // Reads see the sealed bytes while the seal's own sync is still parked.
        try testing.expect(sealing.completion.is_pending());
        var buf: [6]u8 = undefined;
        try sealed.read_at(0, &buf);
        try testing.expectEqualStrings("abcdef", &buf);
        try testing.expectEqual(@as(usize, 1), f.pending.parked());
        f.pending.release_next(1);
        try sealing.completion.wait();
        try testing.expect(try f.durable_len("seal") > 0);
    }
};

test "paged start_sync persists and marks clean (test_start_sync_persists_and_marks_clean)" {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(PagedTests.persists, .{}));
}

test "paged sync waits for an outstanding start_sync before rewriting the tip" {
    // commonware `test_sync_waits_for_outstanding_start_sync`,
    // `test_sync_after_start_sync_and_small_write_waits_before_range_sync`.
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(PagedTests.sync_waits, .{}));
}

test "paged append waits for an outstanding start_sync before writing" {
    // commonware `test_append_waits_for_outstanding_start_sync_before_writing`.
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(PagedTests.append_waits, .{}));
}

test "paged seal waits for an outstanding start_sync and reads while its sync is pending" {
    // commonware `test_seal_waits_for_outstanding_start_sync_before_flushing`,
    // `paged/sealed.rs` `test_sealed_reads_while_seal_sync_pending`.
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(PagedTests.seal_waits, .{}));
}
