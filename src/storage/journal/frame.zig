//! Varint length-prefixed framing for variable-length journal items (journal/frame.rs).
//!
//! Each item is stored as a frame: a varint `u32` length prefix followed by the (optionally
//! zstd-compressed) encoded item.
//!
//! Decoded items own their memory: a compressed payload is decompressed into a scratch buffer
//! that is freed after decoding, and a payload split across reads is staged in one. Item types
//! that borrow their input (`codec.Bytes`) are only valid for uncompressed frames read whole.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const Error = @import("mod.zig").Error;
pub const zstd = @import("zstd.zig");

/// Longest varint prefix of a `u32` payload length.
pub const max_prefix_size: usize = codec.varint.max_u32_varint_size;

/// A decoded length prefix.
pub const LengthPrefix = struct {
    /// Payload length.
    size: u32,
    /// Bytes the varint occupied.
    varint_len: usize,
};

/// Decode a varint length prefix from `reader`.
pub fn decode_length_prefix(reader: *codec.Reader) Error!LengthPrefix {
    const initial = reader.remaining();
    const size = try codec.varint.read(u32, reader);
    const varint_len = initial - reader.remaining();
    assert(varint_len >= 1 and varint_len <= max_prefix_size);
    assert(varint_len == codec.varint.size(u32, size));
    return .{ .size = size, .varint_len = varint_len };
}

/// Payload availability of a frame found in a buffer (offsets and lengths, not slices).
pub const FrameInfo = union(enum) {
    /// The frame's full payload is available in the buffer.
    complete: struct { varint_len: usize, data_len: usize },
    /// Only part of the frame's payload is available.
    incomplete: struct {
        varint_len: usize,
        /// Bytes of item data available in the buffer.
        prefix_len: usize,
        /// Full size of the item.
        total_len: usize,
    },
};

/// A frame located by `find_frame`.
pub const Found = struct {
    /// Offset just past the frame.
    next_offset: u64,
    info: FrameInfo,
};

/// Find the frame at `offset` in the buffered bytes by decoding its length prefix.
pub fn find_frame(buf: []const u8, offset: u64) Error!Found {
    var reader = codec.Reader.init(buf);
    const prefix = try decode_length_prefix(&reader);
    const next_offset = std.math.add(u64, offset, prefix.varint_len) catch
        return error.OffsetOverflow;
    const end = std.math.add(u64, next_offset, prefix.size) catch return error.OffsetOverflow;
    const buffered = buf.len - prefix.varint_len;
    const size: usize = prefix.size;
    const info: FrameInfo = if (buffered >= size)
        .{ .complete = .{ .varint_len = prefix.varint_len, .data_len = size } }
    else
        .{ .incomplete = .{
            .varint_len = prefix.varint_len,
            .prefix_len = buffered,
            .total_len = size,
        } };
    assert(end >= offset);
    return .{ .next_offset = end, .info = info };
}

/// Decompress a journal payload into an owned buffer.
pub fn decompress(gpa: Allocator, compressed: []const u8) Error![]u8 {
    return zstd.decompress(gpa, compressed);
}

/// Decode a frame's payload into an item, decompressing if needed. The payload must hold
/// exactly one item (trailing bytes fail with `ExtraData`).
pub fn decode_item(
    comptime V: type,
    gpa: Allocator,
    payload: []const u8,
    cfg: codec.Cfg(V),
    compressed: bool,
) Error!V {
    if (!compressed) return codec.decode_cfg(V, gpa, payload, cfg);
    const decompressed = try decompress(gpa, payload);
    defer gpa.free(decompressed);
    return codec.decode_cfg(V, gpa, decompressed, cfg);
}

/// An item read by `read_frame_at`.
pub fn ReadFrame(comptime V: type) type {
    return struct {
        /// Offset just past the frame.
        next_offset: u64,
        /// Payload length, excluding the prefix.
        item_size: u32,
        item: V,
    };
}

/// Read and decode the frame at `offset`.
///
/// `reader` provides `size() u64`, the length of its data; `read_up_to(offset: u64, buf: []u8)
/// !usize`, which reads at most `buf.len` bytes and returns how many it read (fewer only at
/// the end of data); and `read_at(offset: u64, buf: []u8) !void`, which reads exactly
/// `buf.len` bytes. A frame that runs past `size()` fails with `EndOfBuffer` before its
/// payload is allocated, so a corrupt prefix cannot request a 4 GiB buffer.
pub fn read_frame_at(
    comptime V: type,
    gpa: Allocator,
    reader: anytype,
    offset: u64,
    cfg: codec.Cfg(V),
    compressed: bool,
) !ReadFrame(V) {
    var header: [max_prefix_size]u8 = undefined;
    const header_len = try reader.read_up_to(offset, &header);
    assert(header_len <= header.len);
    const found = try find_frame(header[0..header_len], offset);
    if (found.next_offset > reader.size()) return error.EndOfBuffer;
    switch (found.info) {
        .complete => |complete| {
            // A header read of a tiny frame can run into the next frame.
            const payload = header[complete.varint_len..][0..complete.data_len];
            const item = try decode_item(V, gpa, payload, cfg, compressed);
            return .{
                .next_offset = found.next_offset,
                .item_size = @intCast(complete.data_len),
                .item = item,
            };
        },
        .incomplete => |incomplete| {
            const payload = try gpa.alloc(u8, incomplete.total_len);
            defer gpa.free(payload);
            const buffered = header[incomplete.varint_len..][0..incomplete.prefix_len];
            @memcpy(payload[0..buffered.len], buffered);
            const read_offset = offset + incomplete.varint_len + incomplete.prefix_len;
            try reader.read_at(read_offset, payload[buffered.len..]);
            const item = try decode_item(V, gpa, payload, cfg, compressed);
            return .{
                .next_offset = found.next_offset,
                .item_size = @intCast(incomplete.total_len),
                .item = item,
            };
        },
    }
}

/// An uncompressed item with its length prefix, sized and validated before encoding.
pub fn UncompressedFrame(comptime V: type) type {
    return struct {
        const Self = @This();

        item: V,
        /// Encoded item length, excluding the length prefix.
        item_len: u32,
        /// Encoded frame length, including the length prefix.
        frame_len: usize,

        /// Size `item` once and reject it if its frame cannot be represented.
        pub fn init(item: V) Error!Self {
            const len = codec.encode_size(V, item);
            const item_len = std.math.cast(u32, len) orelse return error.ItemTooLarge;
            const frame_len = std.math.add(usize, codec.varint.size(u32, item_len), len) catch
                return error.OffsetOverflow;
            assert(frame_len > len);
            return .{ .item = item, .item_len = item_len, .frame_len = frame_len };
        }

        pub fn encode_size(self: Self) usize {
            return self.frame_len;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            const start = writer.end;
            codec.varint.write(u32, self.item_len, writer);
            codec.write(V, self.item, writer);
            assert(writer.end - start == self.frame_len);
        }
    };
}

/// Encode an item as a frame (length prefix plus payload), appending the bytes to `buf`.
///
/// Existing contents of `buf` are preserved, so callers can accumulate several frames in one
/// buffer. Returns the payload length, excluding the length prefix.
pub fn encode_frame_into(
    comptime V: type,
    gpa: Allocator,
    compression: ?u8,
    item: V,
    buf: *std.ArrayList(u8),
) Error!u32 {
    return encode_frame_reusing(V, gpa, compression, null, item, buf);
}

/// `encode_frame_into` compressing through `compressor` when it is set, so a batch of frames
/// shares one encoder's buffers.
pub fn encode_frame_reusing(
    comptime V: type,
    gpa: Allocator,
    compression: ?u8,
    compressor: ?*zstd.Compressor,
    item: V,
    buf: *std.ArrayList(u8),
) Error!u32 {
    assert(compressor == null or compression != null);
    if (compression) |level| {
        return encode_compressed_frame_into(V, gpa, level, compressor, item, buf);
    }
    const frame = try UncompressedFrame(V).init(item);
    const out = try buf.addManyAsSlice(gpa, frame.frame_len);
    var writer = codec.Writer.init(out);
    frame.write(&writer);
    assert(writer.end == out.len);
    return frame.item_len;
}

/// Compressed case of `encode_frame_into`. `level` is accepted for compatibility; see
/// `zstd.zig` for why it does not change the output.
pub fn encode_compressed_frame_into(
    comptime V: type,
    gpa: Allocator,
    level: u8,
    compressor: ?*zstd.Compressor,
    item: V,
    buf: *std.ArrayList(u8),
) Error!u32 {
    _ = level;
    // A byte array encodes as its own bytes, so it compresses in place: a 1 MiB item's
    // temporary copy cost twice its compression (fresh pages from the allocator each item).
    const raw = comptime is_byte_array(V);
    const encoded = if (raw) std.mem.asBytes(&item) else try codec.encode(V, gpa, item);
    defer if (!raw) gpa.free(encoded);
    assert(!raw or encoded.len == @sizeOf(V));

    // Reserve the widest prefix so the frame compresses straight into `buf`.
    const start = buf.items.len;
    const max_len = zstd.compress_bound(encoded.len);
    const max_size_len = codec.varint.size(u32, std.math.cast(u32, max_len) orelse
        std.math.maxInt(u32));
    try buf.ensureUnusedCapacity(gpa, max_size_len + max_len);
    buf.items.len += max_size_len;
    const compressed = if (compressor) |c|
        c.compress_into(gpa, encoded, buf)
    else
        zstd.compress_into(gpa, encoded, buf);
    const compressed_len = (compressed catch |err| {
        buf.items.len = start;
        return err;
    }).len;
    const item_len = std.math.cast(u32, compressed_len) orelse {
        buf.items.len = start;
        return error.ItemTooLarge;
    };

    // Shift the payload down if its size needs a shorter prefix.
    const size_len = codec.varint.size(u32, item_len);
    assert(size_len <= max_size_len);
    if (size_len < max_size_len) {
        const payload = buf.items[start + max_size_len ..];
        std.mem.copyForwards(u8, buf.items[start + size_len ..][0..payload.len], payload);
        buf.items.len = start + size_len + compressed_len;
    }
    var writer = codec.Writer.init(buf.items[start..][0..size_len]);
    codec.varint.write(u32, item_len, &writer);
    assert(buf.items.len == start + size_len + compressed_len);
    return item_len;
}

/// Whether `V` is `[N]u8`, which codec writes as its bytes with no prefix.
fn is_byte_array(comptime V: type) bool {
    const info = @typeInfo(V);
    if (info != .array) return false;
    if (info.array.child != u8 or info.array.sentinel_ptr != null) return false;
    comptime assert(codec.fixed_size(V).? == @sizeOf(V));
    return true;
}

const testing = std.testing;

/// Decode a unit-config item with the testing allocator.
fn decode_test(comptime V: type, payload: []const u8, compressed: bool) Error!V {
    return decode_item(V, testing.allocator, payload, {}, compressed);
}

/// Frame a single item and return the raw frame bytes.
fn frame_bytes(comptime V: type, compression: ?u8, item: V) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(testing.allocator);
    _ = try encode_frame_into(V, testing.allocator, compression, item, &buf);
    return buf.toOwnedSlice(testing.allocator);
}

test "roundtrip uncompressed" {
    const buf = try frame_bytes(u64, null, 42);
    defer testing.allocator.free(buf);
    const found = try find_frame(buf, 0);
    const complete = found.info.complete;
    try testing.expectEqual(@as(usize, 1), complete.varint_len);
    try testing.expectEqual(@as(usize, 8), complete.data_len);
    try testing.expectEqual(@as(u64, 9), found.next_offset);
    const payload = buf[complete.varint_len..][0..complete.data_len];
    try testing.expectEqual(@as(u64, 42), try decode_test(u64, payload, false));
}

test "roundtrip compressed" {
    const buf = try frame_bytes(u64, 3, 42);
    defer testing.allocator.free(buf);
    const complete = (try find_frame(buf, 0)).info.complete;
    const payload = buf[complete.varint_len..][0..complete.data_len];
    try testing.expectEqual(@as(u64, 42), try decode_test(u64, payload, true));
}

test "compressed arrays frame their codec encoding" {
    // `[N]u8` compresses in place; `[N]u16` must still go through codec's big-endian writes.
    var bytes: [300]u8 = undefined;
    var words: [300]u16 = undefined;
    for (&bytes, &words, 0..) |*byte, *word, index| {
        byte.* = @truncate(index *% 7 +% 1);
        word.* = @truncate(index *% 0x0103 +% 0x0201);
    }
    inline for (.{ bytes, words }) |item| {
        const V = @TypeOf(item);
        const buf = try frame_bytes(V, 3, item);
        defer testing.allocator.free(buf);
        const complete = (try find_frame(buf, 0)).info.complete;
        const payload = buf[complete.varint_len..][0..complete.data_len];
        const encoded = try codec.encode(V, testing.allocator, item);
        defer testing.allocator.free(encoded);
        const plain = try decompress(testing.allocator, payload);
        defer testing.allocator.free(plain);
        try testing.expectEqualSlices(u8, encoded, plain);
        try testing.expectEqual(item, try decode_test(V, payload, true));
    }
}

test "compressed frames shift short prefixes and decode independently" {
    const gpa = testing.allocator;
    const Bytes = []const u8;
    const cfg: codec.Cfg(Bytes) = .{ .range = .full(), .item = {} };
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(gpa);
    try frames.appendSlice(gpa, "existing data");
    for ([_]usize{ 0, 1, 64, 1024, 16 * 1024, 130 * 1024, 64, 0 }) |len| {
        const item = try gpa.alloc(u8, len);
        defer gpa.free(item);
        for (item, 0..) |*byte, index| byte.* = @truncate(index % 16);

        const frame_start = frames.items.len;
        const compressed_len = try encode_frame_into(Bytes, gpa, 3, item, &frames);
        var reader = codec.Reader.init(frames.items[frame_start..]);
        const prefix = try decode_length_prefix(&reader);
        try testing.expectEqual(compressed_len, prefix.size);
        try testing.expectEqual(@as(usize, prefix.size), reader.remaining());
        const encoded_len = codec.encode_size(Bytes, item);
        try testing.expectEqual(@as(?u64, encoded_len), zstd.frame_content_size(reader.rest()));

        const decoded = try decode_item(Bytes, gpa, reader.rest(), cfg, true);
        defer gpa.free(decoded);
        try testing.expectEqualSlices(u8, item, decoded);
    }
    try testing.expectEqualStrings("existing data", frames.items[0..13]);
}

test "accumulation preserves existing contents" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    _ = try encode_frame_into(u64, gpa, null, 1, &buf);
    const first_frame_len = buf.items.len;
    _ = try encode_frame_into(u64, gpa, null, 2, &buf);

    const first = try find_frame(buf.items, 0);
    try testing.expectEqual(@as(u64, first_frame_len), first.next_offset);
    try testing.expectEqual(@as(u64, 1), try decode_item(u64, gpa, buf.items[1..9], {}, false));

    const second = try find_frame(buf.items[first_frame_len..], first.next_offset);
    try testing.expectEqual(@as(u64, buf.items.len), second.next_offset);
    const payload = buf.items[first_frame_len + 1 ..];
    try testing.expectEqual(@as(u64, 2), try decode_item(u64, gpa, payload, {}, false));
}

test "uncompressed frame prefixes" {
    const gpa = testing.allocator;
    // Empty payloads and both sides of the transitions to two and three prefix bytes.
    for ([_]usize{ 0, 127, 128, 16_383, 16_384 }) |len| {
        const bytes = try gpa.alloc(u8, len);
        defer gpa.free(bytes);
        @memset(bytes, 7);
        const Raw = struct {
            bytes: []const u8,
            pub fn write(self: @This(), writer: *codec.Writer) void {
                writer.write_bytes(self.bytes);
            }
            pub fn encode_size(self: @This()) usize {
                return self.bytes.len;
            }
            pub fn read(_: Allocator, _: *codec.Reader, _: void) codec.Error!@This() {
                unreachable; // Never decoded.
            }
        };
        const frame = try UncompressedFrame(Raw).init(.{ .bytes = bytes });
        try testing.expectEqual(@as(u32, @intCast(len)), frame.item_len);
        const prefix_len = codec.varint.size(u32, @intCast(len));
        try testing.expectEqual(prefix_len + len, frame.encode_size());

        const encoded = try gpa.alloc(u8, frame.encode_size());
        defer gpa.free(encoded);
        var writer = codec.Writer.init(encoded);
        frame.write(&writer);
        try testing.expectEqual(encoded.len, writer.end);
        var reader = codec.Reader.init(encoded);
        try testing.expectEqual(@as(u32, @intCast(len)), try codec.varint.read(u32, &reader));
        try testing.expectEqualSlices(u8, bytes, reader.rest());
    }
}

test "find frame zero length payload" {
    const found = try find_frame(&.{0x00}, 7);
    try testing.expectEqual(@as(usize, 1), found.info.complete.varint_len);
    try testing.expectEqual(@as(usize, 0), found.info.complete.data_len);
    try testing.expectEqual(@as(u64, 8), found.next_offset);
}

test "find frame incomplete payload" {
    // Prefix declares 5 payload bytes; only 3 are buffered.
    const found = try find_frame(&.{ 0x05, 1, 2, 3 }, 100);
    const incomplete = found.info.incomplete;
    try testing.expectEqual(@as(usize, 1), incomplete.varint_len);
    try testing.expectEqual(@as(usize, 3), incomplete.prefix_len);
    try testing.expectEqual(@as(usize, 5), incomplete.total_len);
    try testing.expectEqual(@as(u64, 106), found.next_offset);
}

test "find frame payload boundary" {
    // Exactly filling the buffer is complete; one byte short is incomplete.
    const full = try find_frame(&.{ 0x03, 1, 2, 3 }, 0);
    try testing.expectEqual(@as(usize, 3), full.info.complete.data_len);
    const short = try find_frame(&.{ 0x03, 1, 2 }, 0);
    try testing.expectEqual(@as(usize, 2), short.info.incomplete.prefix_len);
    try testing.expectEqual(@as(usize, 3), short.info.incomplete.total_len);
}

test "find frame rejects bad prefixes" {
    try testing.expectError(error.EndOfBuffer, find_frame(&.{}, 0));
    // A lone continuation byte is an incomplete varint, not a frame.
    try testing.expectError(error.EndOfBuffer, find_frame(&.{0x80}, 0));
    // A 5-byte varint encoding a value larger than u32::MAX.
    try testing.expectError(error.InvalidVarint, find_frame(&.{ 0xFF, 0xFF, 0xFF, 0xFF, 0x7F }, 0));
}

test "find frame offset overflow" {
    const buf = try frame_bytes(u64, null, 42);
    defer testing.allocator.free(buf);
    try testing.expectError(error.OffsetOverflow, find_frame(buf, std.math.maxInt(u64)));
}

test "decode item rejects trailing bytes and short payloads" {
    // 9 bytes for a u64: decode must consume exactly the payload.
    const buf: [9]u8 = @splat(0);
    try testing.expectError(error.ExtraData, decode_test(u64, &buf, false));
    try testing.expectError(error.EndOfBuffer, decode_test(u64, buf[0..7], false));
    try testing.expectError(error.ExtraData, decode_test(u8, buf[0..8], false));
}

test "decode item corrupt compressed payload" {
    const buf = try frame_bytes(u64, 3, 42);
    defer testing.allocator.free(buf);
    // Corrupt the zstd magic number (first payload byte, after the 1-byte varint).
    buf[1] ^= 0xFF;
    try testing.expectError(error.DecompressionFailed, decode_test(u64, buf[1..], true));
}

test "decompress recovers after errors" {
    const buf = try frame_bytes(u64, 3, 42);
    defer testing.allocator.free(buf);
    const payload = buf[1..];
    for (0..payload.len) |len| {
        const truncated = decompress(testing.allocator, payload[0..len]);
        try testing.expectError(error.DecompressionFailed, truncated);
        try testing.expectEqual(@as(u64, 42), try decode_test(u64, payload, true));
    }
}

test "encode frame rejects oversized item" {
    // An item whose claimed encoded size exceeds the u32 frame limit. The size check happens
    // before any bytes are written, so `write` is unreachable.
    const Oversized = struct {
        pub fn write(_: @This(), _: *codec.Writer) void {
            unreachable; // The size check rejects the item before writing.
        }
        pub fn encode_size(_: @This()) usize {
            return @as(usize, std.math.maxInt(u32)) + 1;
        }
        pub fn read(_: Allocator, _: *codec.Reader, _: void) codec.Error!@This() {
            unreachable; // Never decoded.
        }
    };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const result = encode_frame_into(Oversized, testing.allocator, null, .{}, &buf);
    try testing.expectError(error.ItemTooLarge, result);
    try testing.expectEqual(@as(usize, 0), buf.items.len);
}

/// Serves reads from a byte slice, counting them.
const SliceReader = struct {
    bytes: []const u8,
    reads: u32 = 0,

    pub fn size(self: *const SliceReader) u64 {
        return self.bytes.len;
    }

    pub fn read_up_to(self: *SliceReader, offset: u64, buf: []u8) !usize {
        self.reads += 1;
        const start: usize = @intCast(@min(offset, self.bytes.len));
        const len = @min(buf.len, self.bytes.len - start);
        @memcpy(buf[0..len], self.bytes[start..][0..len]);
        return len;
    }

    pub fn read_at(self: *SliceReader, offset: u64, buf: []u8) !void {
        self.reads += 1;
        if (offset + buf.len > self.bytes.len) return error.BlobInsufficientLength;
        @memcpy(buf, self.bytes[@intCast(offset)..][0..buf.len]);
    }
};

test "read frame at walks small, large, and compressed frames" {
    const gpa = testing.allocator;
    const Bytes = []const u8;
    const cfg: codec.Cfg(Bytes) = .{ .range = .full(), .item = {} };
    for ([_]?u8{ null, 3 }) |compression| {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        const lengths = [_]usize{ 0, 1, 2, 3, 200, 70_000 };
        for (lengths) |len| {
            const item = try gpa.alloc(u8, len);
            defer gpa.free(item);
            for (item, 0..) |*byte, index| byte.* = @truncate(index * 31 + len);
            _ = try encode_frame_into(Bytes, gpa, compression, item, &buf);
        }
        var reader: SliceReader = .{ .bytes = buf.items };
        var offset: u64 = 0;
        var last_offset: u64 = 0;
        for (lengths) |len| {
            last_offset = offset;
            const read = try read_frame_at(Bytes, gpa, &reader, offset, cfg, compression != null);
            defer gpa.free(read.item);
            try testing.expectEqual(len, read.item.len);
            for (read.item, 0..) |byte, index| {
                try testing.expectEqual(@as(u8, @truncate(index * 31 + len)), byte);
            }
            try testing.expect(read.next_offset > offset);
            offset = read.next_offset;
        }
        try testing.expectEqual(@as(u64, buf.items.len), offset);
        // Reading past the end finds no prefix.
        const past_end = read_frame_at(Bytes, gpa, &reader, offset, cfg, false);
        try testing.expectError(error.EndOfBuffer, past_end);
        // A truncated payload surfaces the reader's error.
        reader.bytes = buf.items[0 .. buf.items.len - 1];
        const compressed = compression != null;
        try testing.expectError(
            error.EndOfBuffer,
            read_frame_at(Bytes, gpa, &reader, last_offset, cfg, compressed),
        );
    }
}

const fuzz_bytes = @import("../fuzz_bytes.zig");

/// Arbitrary bytes as a run of frames: every read either fails cleanly or decodes an item
/// that re-frames to the bytes it came from (uncompressed), and arbitrary payloads survive
/// both framings.
fn fuzz_run(bytes: []const u8) anyerror!void {
    const gpa = testing.allocator;
    const Bytes = []const u8;
    const cfg: codec.Cfg(Bytes) = .{ .range = .full(), .item = {} };
    var reader: SliceReader = .{ .bytes = bytes };
    var offset: u64 = 0;
    var frames: u32 = 0;
    while (offset < bytes.len and frames < bytes.len) : (frames += 1) {
        const compressed = bytes[@intCast(offset)] & 1 == 1;
        const read = read_frame_at(Bytes, gpa, &reader, offset, cfg, compressed) catch break;
        defer gpa.free(read.item);
        assert(read.next_offset > offset);
        if (!compressed) {
            const frame_len: usize = @intCast(read.next_offset - offset);
            var reframed: std.ArrayList(u8) = .empty;
            defer reframed.deinit(gpa);
            _ = try encode_frame_into(Bytes, gpa, null, read.item, &reframed);
            // The payload is a `Vec<u8>` encoding, so it may use a longer varint than the
            // frame prefix; only the payload length must agree.
            try testing.expectEqual(frame_len, reframed.items.len);
        }
        offset = read.next_offset;
    }

    for ([_]?u8{ null, 3 }) |compression| {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        _ = try encode_frame_into(Bytes, gpa, compression, bytes, &buf);
        var whole: SliceReader = .{ .bytes = buf.items };
        const read = try read_frame_at(Bytes, gpa, &whole, 0, cfg, compression != null);
        defer gpa.free(read.item);
        try testing.expectEqualSlices(u8, bytes, read.item);
        try testing.expectEqual(@as(u64, buf.items.len), read.next_offset);
    }
}

test "fuzz journal frames (seeded)" {
    try fuzz_bytes.seeded(512, 0x6672616d65, 512, fuzz_run);
}

test "fuzz journal frames" {
    try testing.fuzz({}, fuzz_bytes.smith(512, fuzz_run), .{});
}
