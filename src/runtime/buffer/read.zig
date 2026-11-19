//! A reader that buffers a blob for a sequential scan (commonware's `buffer/read.rs`).
//!
//! commonware returns zero-copy slices of its refill buffer; here `read` copies into the
//! caller's buffer, so the one refill buffer is allocated at `init` and reused. A failed read
//! restores the starting position (commonware's `Rewind`). A `Read` owns its blob and closes
//! it in `deinit`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const storage = @import("../storage.zig");

const Blob = storage.Blob;
pub const Error = storage.Error;

pub const Read = struct {
    blob: Blob,
    gpa: Allocator,
    /// The refill buffer; `buffer.len` is the maximum refill size.
    buffer: []u8,
    /// Blob position the buffer was filled from.
    blob_position: u64 = 0,
    /// Blob size, as given at `init`.
    blob_size: u64,
    /// Read position within the buffer.
    buffer_position: usize = 0,
    /// Valid bytes in the buffer.
    buffer_valid_len: usize = 0,

    /// Wrap `blob` (holding `blob_size` bytes) with a `buffer_size`-byte refill buffer. On
    /// error the caller still owns `blob`.
    pub fn init(gpa: Allocator, blob: Blob, blob_size: u64, buffer_size: usize) !Read {
        assert(buffer_size > 0);
        const buffer = try gpa.alloc(u8, buffer_size);
        assert(buffer.len == buffer_size);
        return .{ .blob = blob, .gpa = gpa, .buffer = buffer, .blob_size = blob_size };
    }

    /// Close the blob and free the buffer.
    pub fn deinit(self: *Read) void {
        self.blob.close();
        self.gpa.free(self.buffer);
        self.* = undefined;
    }

    /// Valid bytes left in the buffer.
    pub fn buffer_remaining(self: *const Read) usize {
        assert(self.buffer_position <= self.buffer_valid_len);
        return self.buffer_valid_len - self.buffer_position;
    }

    /// Bytes left in the blob from the current position.
    pub fn blob_remaining(self: *const Read) u64 {
        return self.blob_size -| self.position();
    }

    /// The current absolute position in the blob.
    pub fn position(self: *const Read) u64 {
        return self.blob_position + self.buffer_position;
    }

    /// Refill from the current position.
    fn refill(self: *Read) Error!void {
        self.blob_position += self.buffer_position;
        self.buffer_position = 0;
        self.buffer_valid_len = 0;
        const remaining = self.blob_size -| self.blob_position;
        if (remaining == 0) return error.BlobInsufficientLength;
        const len: usize = @intCast(@min(self.buffer.len, remaining));
        try self.blob.read_at(self.blob_position, self.buffer[0..len]);
        self.buffer_valid_len = len;
        assert(self.buffer_valid_len <= self.buffer.len);
    }

    /// Read exactly `out.len` bytes. Fails with `BlobInsufficientLength` if fewer remain;
    /// any failure restores the starting position.
    pub fn read(self: *Read, out: []u8) Error!void {
        if (out.len == 0) return;
        if (self.blob_remaining() < out.len) return error.BlobInsufficientLength;
        const start = self.position();
        errdefer self.seek_to(start) catch unreachable; // `start` is within the blob size.
        var filled: usize = 0;
        while (filled < out.len) {
            if (self.buffer_position >= self.buffer_valid_len) try self.refill();
            const take = @min(out.len - filled, self.buffer_remaining());
            assert(take > 0);
            const from = self.buffer[self.buffer_position..][0..take];
            @memcpy(out[filled..][0..take], from);
            self.buffer_position += take;
            filled += take;
        }
        assert(self.position() == start + out.len);
    }

    /// Move to `target`, keeping the buffer when `target` falls inside it.
    pub fn seek_to(self: *Read, target: u64) Error!void {
        if (target > self.blob_size) return error.BlobInsufficientLength;
        const buffer_end = self.blob_position + self.buffer_valid_len;
        if (target >= self.blob_position and target < buffer_end) {
            self.buffer_position = @intCast(target - self.blob_position);
        } else {
            self.blob_position = target;
            self.buffer_position = 0;
            self.buffer_valid_len = 0;
        }
        assert(self.position() == target);
    }

    /// Resize the blob to `len` and sync it, then close the reader.
    pub fn resize(self: *Read, len: u64) Error!void {
        defer self.deinit();
        try self.blob.resize(len);
        try self.blob.sync();
    }
};

const testing = std.testing;
const mocks = @import("mocks.zig");
const test_gpa = testing.allocator;

/// Durably write `data` to blob `name` and wrap it in a reader of `buffer_size`.
fn reader_over(h: *mocks.Storage, name: []const u8, data: []const u8, size: usize) !Read {
    const opened = try h.open("partition", name);
    errdefer opened.blob.close();
    try testing.expectEqual(0, opened.len);
    try opened.blob.write_at(0, data, .{});
    return Read.init(test_gpa, opened.blob, data.len, size);
}

fn expect_read(reader: *Read, expected: []const u8) !void {
    const out = try test_gpa.alloc(u8, expected.len);
    defer test_gpa.free(out);
    try reader.read(out);
    try testing.expectEqualSlices(u8, expected, out);
}

fn expect_short(reader: *Read, len: usize) !void {
    const out = try test_gpa.alloc(u8, len);
    defer test_gpa.free(out);
    try testing.expectError(error.BlobInsufficientLength, reader.read(out));
}

test "read: basic" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    var reader = try reader_over(&h, "test", "Hello, world! This is a test.", 10);
    defer reader.deinit();
    try expect_read(&reader, "Hello");
    try expect_read(&reader, ", world! This ");
    try testing.expectEqual(19, reader.position());
    try expect_read(&reader, "is a te");
    try expect_short(&reader, 5);
}

test "read: cross boundary" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    var reader = try reader_over(&h, "test", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 10);
    defer reader.deinit();
    try expect_read(&reader, "ABCDEFGHIJKLMNO");
    try testing.expectEqual(15, reader.position());
    try expect_read(&reader, "PQRSTUVWXYZ");
    try testing.expectEqual(26, reader.position());
    try testing.expectEqual(0, reader.blob_remaining());
}

test "read: to end, rewind, and read again (issue 1348)" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    var reader = try reader_over(&h, "test", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 20);
    defer reader.deinit();
    try expect_read(&reader, "ABCDEFGHIJKLMNOPQRSTU");
    try testing.expectEqual(21, reader.position());
    try expect_read(&reader, "VWXYZ");
    try reader.seek_to(0);
    try expect_read(&reader, "ABCDEFGHIJKLMNOPQRSTU");
}

test "read: known size" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    const data = "This is a test with known size limitations.";
    var reader = try reader_over(&h, "test", data, 10);
    defer reader.deinit();
    try testing.expectEqual(data.len, reader.blob_remaining());
    try expect_read(&reader, "This ");
    try testing.expectEqual(data.len - 5, reader.blob_remaining());
    try expect_read(&reader, data[5..]);
    try testing.expectEqual(0, reader.blob_remaining());
    try expect_short(&reader, 1);
}

test "read: an oversized request consumes no buffered bytes" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    var reader = try reader_over(&h, "double-count-regression", "abcdefghij", 8);
    defer reader.deinit();
    try expect_read(&reader, "abcdef");
    try expect_short(&reader, 5);
    try testing.expectEqual(6, reader.position());
    try expect_read(&reader, "ghij");
    try testing.expectEqual(10, reader.position());
}

test "read: a failed refill rewinds" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    const data = "abcdefghijkl";
    // A short backing blob fails the second refill, after a prefix has been gathered.
    const opened = try h.open("partition", "failed-read");
    try opened.blob.write_at(0, data[0..8], .{});
    var reader = try Read.init(test_gpa, opened.blob, data.len, 4);
    defer reader.deinit();
    try expect_read(&reader, "ab");
    try expect_short(&reader, 10);
    try testing.expectEqual(2, reader.position());
    try testing.expectEqual(10, reader.blob_remaining());
    // Once the bytes are available, the retry starts from the original position.
    try reader.blob.write_at(8, data[8..], .{});
    try expect_read(&reader, data[2..]);
    try testing.expectEqual(data.len, reader.position());
    try testing.expectEqual(0, reader.blob_remaining());
}

test "read: large data in chunks" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    const data = try test_gpa.alloc(u8, 256 * 1024);
    defer test_gpa.free(data);
    @memset(data, 0x42);
    var reader = try reader_over(&h, "test", data, 64 * 1024);
    defer reader.deinit();
    var chunk: [8 * 1024]u8 = undefined;
    var total: usize = 0;
    while (total < data.len) : (total += chunk.len) {
        try reader.read(&chunk);
        for (chunk) |byte| try testing.expectEqual(0x42, byte);
    }
    try testing.expectEqual(data.len, total);
    try expect_short(&reader, 1);
}

test "read: exact buffer-size reads" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    const buffer_size = 1024;
    var data: [buffer_size * 5 / 2]u8 = @splat(0x37);
    var reader = try reader_over(&h, "test", &data, buffer_size);
    defer reader.deinit();
    try expect_read(&reader, data[0..buffer_size]);
    try expect_read(&reader, data[0..buffer_size]);
    try expect_read(&reader, data[0 .. buffer_size / 2]);
    try testing.expectEqual(0, reader.blob_remaining());
    try testing.expectEqual(data.len, reader.position());
}

test "read: seek_to" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    const data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var reader = try reader_over(&h, "test", data, 10);
    defer reader.deinit();
    try expect_read(&reader, "ABCDE");
    try reader.seek_to(10);
    try testing.expectEqual(10, reader.position());
    try expect_read(&reader, "KLMNO");
    try reader.seek_to(0);
    try expect_read(&reader, "ABCDE");
    try reader.seek_to(data.len);
    try testing.expectEqual(data.len, reader.position());
    try expect_short(&reader, 1);
    try testing.expectError(error.BlobInsufficientLength, reader.seek_to(data.len + 10));
}

test "read: seek with refill" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    var data: [1000]u8 = @splat(0x41);
    var reader = try reader_over(&h, "test", &data, 10);
    defer reader.deinit();
    try expect_read(&reader, "AAAAA");
    try reader.seek_to(500);
    try expect_read(&reader, "AAAAA");
    try testing.expectEqual(505, reader.position());
    try reader.seek_to(100);
    try expect_read(&reader, "AAAAA");
    try testing.expectEqual(105, reader.position());
}

test "read: seek within the buffered range" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    var reader = try reader_over(&h, "test", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 10);
    defer reader.deinit();
    try expect_read(&reader, "ABCDEF");
    try testing.expectEqual(4, reader.buffer_remaining());
    try reader.seek_to(3);
    try testing.expectEqual(3, reader.position());
    try testing.expectEqual(7, reader.buffer_remaining());
    try expect_read(&reader, "DEFGH");
    try testing.expectEqual(8, reader.position());
    try testing.expectEqual(2, reader.buffer_remaining());
}

test "read: a seek within the unread buffer does not refill" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    var reader = try reader_over(&h, "seek_unread_no_refill", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 10);
    defer reader.deinit();
    try expect_read(&reader, "ABCDEF");
    const reads = h.reads;
    try reader.seek_to(7);
    try testing.expectEqual(3, reader.buffer_remaining());
    try expect_read(&reader, "HIJ");
    try testing.expectEqual(0, reader.buffer_remaining());
    try testing.expectEqual(reads, h.reads);
    // The refill happens only at exhaustion.
    try expect_read(&reader, "K");
    try testing.expectEqual(11, reader.position());
    try testing.expectEqual(9, reader.buffer_remaining());
    try testing.expectEqual(reads + 1, h.reads);
}

test "read: resize" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    const data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var reader = try reader_over(&h, "test", data, 10);
    try reader.resize(data.len / 2);
    var opened = try h.open("partition", "test");
    try testing.expectEqual(data.len / 2, opened.len);
    reader = try Read.init(test_gpa, opened.blob, opened.len, 10);
    try expect_read(&reader, "ABCDEFGHIJKLM");
    try expect_short(&reader, 1);
    try reader.resize(data.len * 2);
    opened = try h.open("partition", "test");
    try testing.expectEqual(data.len * 2, opened.len);
    reader = try Read.init(test_gpa, opened.blob, opened.len, 10);
    defer reader.deinit();
    try expect_read(&reader, "ABCDEFGHIJKLM");
    try expect_read(&reader, &(@as([39]u8, @splat(0))));
}

test "read: resize to zero" {
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    const data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var reader = try reader_over(&h, "test", data, 10);
    try reader.resize(0);
    const opened = try h.open("partition", "test");
    try testing.expectEqual(0, opened.len);
    reader = try Read.init(test_gpa, opened.blob, opened.len, 10);
    defer reader.deinit();
    try expect_short(&reader, 1);
}

/// Parks the next `read_at` once `park` is set, until its task is canceled; counts reads
/// (commonware's `MigratingReadBlob` holding a read pending).
const Parking = struct {
    inner: Blob,
    io: std.Io,
    park: bool = false,
    parked: std.Io.Event = .unset,
    reads: u32 = 0,

    fn blob(self: *Parking) Blob {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize_erased,
        .sync = sync,
        .close = close,
    };

    fn from(ptr: *anyopaque) *Parking {
        return @ptrCast(@alignCast(ptr));
    }

    fn read_at(ptr: *anyopaque, offset: u64, out: []u8, options: storage.ReadOptions) Error!void {
        const self = from(ptr);
        self.reads += 1;
        if (!self.park) return self.inner.read_at_options(offset, out, options);
        self.park = false;
        self.parked.set(self.io);
        var never: std.Io.Event = .unset;
        try never.wait(self.io);
        unreachable; // Nothing sets `never`; only a cancelation ends the wait.
    }

    fn write_at(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: storage.WriteOptions,
    ) Error!void {
        const inner = from(ptr).inner;
        return inner.vtable.write_at(inner.ptr, offset, chunks, options);
    }

    fn resize_erased(ptr: *anyopaque, length: u64) Error!void {
        return from(ptr).inner.resize(length);
    }

    fn sync(ptr: *anyopaque) Error!void {
        return from(ptr).inner.sync();
    }

    fn close(ptr: *anyopaque) void {
        from(ptr).inner.close();
    }
};

fn read_into(reader: *Read, out: []u8) Error!void {
    return reader.read(out);
}

/// A read canceled in its refill leaves the reader where it started.
fn cancelled_refill(io: std.Io, start: usize, seek_after_cancel: bool) !void {
    const data = "abcdefghijkl";
    var h = mocks.Storage.init(test_gpa);
    defer h.deinit();
    const opened = try h.open("partition", "cancelled-read");
    try opened.blob.write_at(0, data, .{});
    var parking: Parking = .{ .inner = opened.blob, .io = io };
    var reader = try Read.init(test_gpa, parking.blob(), data.len, 4);
    defer reader.deinit();
    try expect_read(&reader, data[0..start]);
    const reads = parking.reads;
    // An empty read neither moves the cursor nor reads.
    try expect_read(&reader, "");
    try testing.expectEqual(start, reader.position());
    try testing.expectEqual(reads, parking.reads);
    // With start = 2, the read consumes the buffered bytes before its refill parks.
    parking.park = true;
    var out: [10]u8 = undefined;
    var pending = try io.concurrent(read_into, .{ &reader, &out });
    try parking.parked.wait(io);
    try testing.expectEqual(reads + 1, parking.reads);
    try testing.expectError(error.Canceled, pending.cancel(io));
    try testing.expectEqual(start, reader.position());
    try testing.expectEqual(data.len - start, reader.blob_remaining());
    const resumed: usize = if (seek_after_cancel) 6 else start;
    if (seek_after_cancel) try reader.seek_to(resumed);
    try expect_read(&reader, data[resumed..]);
    try testing.expectEqual(data.len, reader.position());
    try testing.expectEqual(0, reader.blob_remaining());
}

test "read: a canceled refill rewinds (test_read_cancelled_refill_rewinds)" {
    const deterministic = @import("../deterministic.zig");
    for ([_]usize{ 0, 2 }) |start| {
        for ([_]bool{ false, true }) |seek_after_cancel| {
            var runner = try deterministic.Runner.init(test_gpa, .{});
            defer runner.deinit();
            try (try runner.start(cancelled_refill, .{ runner.io(), start, seek_after_cancel }));
        }
    }
}
