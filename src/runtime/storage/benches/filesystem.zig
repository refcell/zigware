//! Filesystem helpers (commonware `runtime/src/storage/benches/filesystem.rs`).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");
const iface = @import("runtime").storage;
const WriteShape = @import("config.zig").WriteShape;

const default_fill_chunk_size = 1024 * 1024;

pub const Rng = utils.rng.TestRng;

/// Nanoseconds on `clock`.
pub fn now_ns(io: Io, clock: Io.Clock) u64 {
    const nanoseconds = Io.Timestamp.now(io, clock).toNanoseconds();
    assert(nanoseconds >= 0);
    return @intCast(nanoseconds);
}

/// Creates a unique storage root for one benchmark run under `parent`, returning its path
/// (owned by the caller).
pub fn prepare_root(gpa: Allocator, io: Io, parent: []const u8) ![]u8 {
    var dir = Io.Dir.cwd().openDir(io, parent, .{}) catch |err| switch (err) {
        error.NotDir => return error.RootParentNotDirectory,
        else => return err,
    };
    dir.close(io);
    const pid: u64 = if (builtin.os.tag == .linux) @intCast(std.os.linux.getpid()) else 0;
    const timestamp = now_ns(io, .real);
    const root = try std.fmt.allocPrint(gpa, "{s}/storage-bench-{d}-{d}", .{
        parent,
        pid,
        timestamp,
    });
    errdefer gpa.free(root);
    try Io.Dir.cwd().createDir(io, root, .default_dir);
    return root;
}

/// Removes the per-run root `prepare_root` created; a missing root is fine.
pub fn cleanup_root(io: Io, root: []const u8) !void {
    try Io.Dir.cwd().deleteTree(io, root);
}

/// `partition/hex(name)`, the blob's file below the storage root.
fn blob_path(buffer: []u8, partition: []const u8, name: []const u8) ![]const u8 {
    var writer: Io.Writer = .fixed(buffer);
    try writer.print("{s}/{x}", .{ partition, name });
    return writer.buffered();
}

fn open_blob_file(io: Io, root: Io.Dir, partition: []const u8, name: []const u8) !Io.File {
    var buffer: [512]u8 = undefined;
    const path = try blob_path(&buffer, partition, name);
    return root.openFile(io, path, .{ .mode = .read_write });
}

/// Durably allocates space for a blob that already has the desired size, so overwrite
/// workloads measure the steady-state write path rather than first-write allocation.
/// Linux only (`fallocate`); a no-op elsewhere, as in commonware.
fn preallocate_blob(io: Io, root: Io.Dir, partition: []const u8, name: []const u8) !void {
    if (builtin.os.tag != .linux) return;
    const file = try open_blob_file(io, root, partition, name);
    defer file.close(io);
    const length = try file.length(io);
    const signed = std.math.cast(i64, length) orelse return error.BlobTooLarge;
    const result = std.os.linux.fallocate(file.handle, 0, 0, signed);
    switch (std.os.linux.errno(result)) {
        .SUCCESS => {},
        else => return error.PreallocateFailed,
    }
    try file.sync(io);
}

/// Best-effort eviction of a blob from the OS page cache (`POSIX_FADV_DONTNEED`, per inode).
/// Linux only.
pub fn drop_page_cache(io: Io, root: Io.Dir, partition: []const u8, name: []const u8) !void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const file = try open_blob_file(io, root, partition, name);
    defer file.close(io);
    const result = std.os.linux.fadvise(file.handle, 0, 0, std.os.linux.POSIX_FADV.DONTNEED);
    switch (std.os.linux.errno(result)) {
        .SUCCESS => {},
        else => return error.FadviseFailed,
    }
}

/// Creates a fixed-size, preallocated blob and returns the open handle.
pub fn prepare_blob(
    io: Io,
    storage: iface.Storage,
    root: Io.Dir,
    partition: []const u8,
    name: []const u8,
    file_size: u64,
) !iface.Blob {
    const opened = try storage.open(partition, name);
    errdefer opened.blob.close();
    try opened.blob.resize(file_size);
    try opened.blob.sync();
    if (file_size == 0) return opened.blob;
    // Release the runtime handle before touching the file directly.
    opened.blob.close();
    try preallocate_blob(io, root, partition, name);
    const reopened = try storage.open(partition, name);
    assert(reopened.len == file_size);
    return reopened.blob;
}

/// Creates a fixed-size blob filled with random data and returns the open handle.
pub fn prepare_filled_blob(
    gpa: Allocator,
    rng: *Rng,
    io: Io,
    storage: iface.Storage,
    root: Io.Dir,
    partition: []const u8,
    name: []const u8,
    file_size: u64,
) !iface.Blob {
    const blob = try prepare_blob(io, storage, root, partition, name, file_size);
    errdefer blob.close();
    const chunk = try gpa.alloc(u8, @min(file_size, default_fill_chunk_size));
    defer gpa.free(chunk);
    var offset: u64 = 0;
    while (offset < file_size) {
        const len: usize = @intCast(@min(file_size - offset, default_fill_chunk_size));
        rng.fill_bytes(chunk[0..len]);
        try blob.write_at(offset, chunk[0..len], .{});
        offset += len;
    }
    assert(offset == file_size);
    try blob.sync();
    return blob;
}

/// One write's payload: one contiguous buffer or four vectored chunks of one allocation.
pub const Payload = struct {
    pub const chunks_vectored = 4;

    bytes: []u8,
    chunk_slices: [chunks_vectored][]const u8,
    chunk_count: u8,

    pub fn deinit(self: *Payload, gpa: Allocator) void {
        gpa.free(self.bytes);
        self.* = undefined;
    }

    pub fn chunks(self: *const Payload) []const []const u8 {
        return self.chunk_slices[0..self.chunk_count];
    }
};

/// A random write payload of `io_size` bytes in `shape` (commonware `random_write_payload`):
/// vectored splits it into four chunks, the first `io_size % 4` one byte longer.
pub fn random_write_payload(gpa: Allocator, rng: *Rng, io_size: usize, shape: WriteShape) !Payload {
    assert(io_size > 0);
    var payload: Payload = .{
        .bytes = try gpa.alloc(u8, io_size),
        .chunk_slices = undefined,
        .chunk_count = 1,
    };
    rng.fill_bytes(payload.bytes);
    switch (shape) {
        .contiguous => payload.chunk_slices[0] = payload.bytes,
        .vectored => {
            const base = io_size / Payload.chunks_vectored;
            const remainder = io_size % Payload.chunks_vectored;
            var start: usize = 0;
            for (&payload.chunk_slices, 0..) |*slice, index| {
                const len = base + @intFromBool(index < remainder);
                slice.* = payload.bytes[start..][0..len];
                start += len;
            }
            assert(start == io_size);
            payload.chunk_count = Payload.chunks_vectored;
        },
    }
    return payload;
}
