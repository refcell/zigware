//! commonware `paged/writer.rs` tests that park one page read after it has captured the
//! blob's bytes (`DelayedReadBlob`), run on the deterministic runtime: the parked read runs on
//! its own task, which the test releases once the writer has moved on.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const mocks = @import("../mocks.zig");
const paged = @import("mod.zig");
const writer_mod = @import("writer.zig");
const storage_iface = @import("../../storage.zig");
const deterministic = @import("../../deterministic.zig");

const Blob = storage_iface.Blob;
const Error = storage_iface.Error;
const CacheRef = paged.CacheRef;
const W = writer_mod.Writer;
const Sealed = @import("sealed.zig").Sealed;
const ReadError = paged.Error;
const gpa = testing.allocator;
const page_size: usize = 103;
const physical_page_size: usize = page_size + 12;
const buffer_size: usize = page_size * 2;

/// Parks the first read of `len` bytes at `offset` after reading them, until `release` is set
/// (commonware `DelayedReadBlob`).
const DelayedRead = struct {
    inner: Blob,
    io: Io,
    offset: u64,
    len: usize,
    reads: u32 = 0,
    started: Io.Event = .unset,
    release: Io.Event = .unset,

    fn blob(self: *DelayedRead) Blob {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize,
        .sync = sync,
        .close = close,
    };

    fn from(ptr: *anyopaque) *DelayedRead {
        return @ptrCast(@alignCast(ptr));
    }

    fn read_at(
        ptr: *anyopaque,
        offset: u64,
        out: []u8,
        options: storage_iface.ReadOptions,
    ) Error!void {
        const self = from(ptr);
        try self.inner.read_at_options(offset, out, options);
        if (offset != self.offset or out.len != self.len) return;
        self.reads += 1;
        if (self.reads != 1) return;
        self.started.set(self.io);
        try self.release.wait(self.io);
    }

    fn write_at(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: storage_iface.WriteOptions,
    ) Error!void {
        const inner = from(ptr).inner;
        return inner.vtable.write_at(inner.ptr, offset, chunks, options);
    }

    fn resize(ptr: *anyopaque, length: u64) Error!void {
        return from(ptr).inner.resize(length);
    }

    fn sync(ptr: *anyopaque) Error!void {
        return from(ptr).inner.sync();
    }

    fn close(ptr: *anyopaque) void {
        from(ptr).inner.close();
    }
};

fn run(comptime body: anytype) !void {
    var runner = try deterministic.Runner.init(gpa, .{ .timeout_ns = 5 * std.time.ns_per_s });
    defer runner.deinit();
    try (try runner.start(body, .{runner.io()}));
}

fn read_sealed_page(sealed: *const Sealed, out: []u8) ReadError!void {
    return sealed.read_at(page_size, out);
}

fn snapshot_fetch_across_append(io: Io) !void {
    var storage = mocks.Storage.init(gpa);
    defer storage.deinit();
    var cache_ref = try CacheRef.init(gpa, page_size, buffer_size);
    defer cache_ref.deinit();
    const opened = try storage.open("test_partition", "snapshot_resize_cache");
    var delayed: DelayedRead = .{
        .inner = opened.blob,
        .io = io,
        .offset = physical_page_size,
        .len = physical_page_size,
    };
    var w = try W.init(gpa, delayed.blob(), opened.len, buffer_size, &cache_ref);
    defer w.deinit();
    const old_page1: [page_size]u8 = @splat(0x22);
    _ = try w.append(&(@as([page_size]u8, @splat(0x11))));
    _ = try w.append(&old_page1);
    try w.sync();
    cache_ref.clear();
    // Start a cache miss through the snapshot, and park its captured read.
    var snapshot = try w.snapshot();
    defer snapshot.deinit();
    var stale: [page_size]u8 = undefined;
    var pending = try io.concurrent(read_sealed_page, .{ &snapshot, &stale });
    errdefer pending.cancel(io) catch {};
    try delayed.started.wait(io);
    // Append while the snapshot still holds its earlier view.
    _ = try w.append(&(@as([page_size]u8, @splat(0x33))));
    try w.sync();
    // The released read returns the old page and fills the cache the writer shares.
    delayed.release.set(io);
    try pending.await(io);
    try testing.expectEqualSlices(u8, &old_page1, &stale);
    var probe: [page_size]u8 = undefined;
    try testing.expect(w.try_read_sync_into(&probe, page_size));
    try testing.expectEqualSlices(u8, &old_page1, &probe);
}

test "a snapshot's parked fetch fills the shared cache across an append" {
    // commonware `test_snapshot_fetch_populates_shared_cache_across_append`.
    try run(snapshot_fetch_across_append);
}
