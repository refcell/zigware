//! Zstandard frames for compressed journal items (RFC 8878).
//!
//! commonware compresses journal payloads with libzstd (`zstd::bulk`), one independent frame
//! per item that declares its decompressed size. zigware has no C dependencies, so:
//!
//! - decompression uses `std.compress.zstd` and reads any frame libzstd writes;
//! - compression writes frames with the same header fields libzstd writes (content size, no
//!   checksum, no dictionary). Each block is compressed (LZ77 sequences coded with FSE, Huffman
//!   literals; see `zstd/`) when that is smaller, else stored raw or RLE. The bytes differ
//!   from libzstd's and the level is ignored; commonware never hashes compressed output, and
//!   any zstd decoder reads the frames. Uncompressed journals are byte-identical.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const block = @import("zstd/block.zig");

/// Sample inputs for tests and benchmarks.
pub const corpus = @import("zstd/corpus.zig");

/// Zstandard frame magic number, little-endian on disk.
pub const magic: u32 = 0xFD2FB528;

/// Largest block a frame may hold (`Block_Maximum_Size` with a window of at least 128 KiB).
pub const block_size_max: usize = 128 * 1024;

/// Window descriptor for a 128 KiB window: exponent 7 (`windowLog` 17), mantissa 0.
const window_descriptor_128k: u8 = 7 << 3;

const block_type_raw: u24 = 0;
const block_type_rle: u24 = 1;
const block_type_compressed: u24 = 2;

/// Inputs shorter than this are stored raw: a compressed block would not pay for itself.
const compress_len_min = 16;

comptime {
    assert(block_size_max == std.compress.zstd.block_size_max);
    assert(block_size_max < (1 << 21)); // Block_Size is a 21-bit field.
}

/// Bytes of the frame header (magic, descriptor, window, content size) for `len` bytes.
fn header_size(len: u64) usize {
    const single_segment = len <= block_size_max;
    const window_size: usize = if (single_segment) 0 else 1;
    return 4 + 1 + window_size + content_size_field_size(len);
}

/// Width of `Frame_Content_Size` that libzstd chooses for `len` (`fcsCode`).
fn content_size_field_size(len: u64) usize {
    if (len < 256) return 1;
    if (len < 65536 + 256) return 2;
    if (len < 0xFFFF_FFFF) return 4;
    return 8;
}

/// Upper bound of `compress` output for `len` input bytes.
pub fn compress_bound(len: usize) usize {
    const blocks = @max(1, std.math.divCeil(usize, len, block_size_max) catch unreachable);
    return header_size(len) + blocks * 3 + len;
}

/// Append one zstd frame holding `data` to `out`; returns the frame.
pub fn compress_into(
    gpa: Allocator,
    data: []const u8,
    out: *std.ArrayList(u8),
) Allocator.Error![]u8 {
    return encode_into(gpa, data, out, .compress);
}

/// How `encode_into` writes blocks.
pub const Mode = enum {
    /// Raw and RLE blocks only (the encoder before match finding; kept for comparison).
    store,
    /// Compressed blocks wherever they are smaller.
    compress,
};

/// Append one zstd frame holding `data` to `out` in `mode`; returns the frame.
pub fn encode_into(
    gpa: Allocator,
    data: []const u8,
    out: *std.ArrayList(u8),
    mode: Mode,
) Allocator.Error![]u8 {
    const start = out.items.len;
    try out.ensureUnusedCapacity(gpa, compress_bound(data.len));
    const context: ?*block.Context = if (mode == .compress and data.len >= compress_len_min)
        try block.Context.create(gpa, data.len)
    else
        null;
    defer if (context) |c| c.destroy(gpa);
    write_header(data.len, out);

    var offset: usize = 0;
    var first = true;
    while (first or offset < data.len) : (first = false) {
        const end = @min(data.len, offset + block_size_max);
        write_block(context, data, offset, end, out);
        offset = end;
    }
    assert(offset == data.len);
    assert(out.items.len - start <= compress_bound(data.len));
    return out.items[start..];
}

fn write_header(len: usize, out: *std.ArrayList(u8)) void {
    const single_segment = len <= block_size_max;
    const field_size = content_size_field_size(len);
    const fcs_flag: u8 = switch (field_size) {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        else => unreachable,
    };
    var header: [14]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], magic, .little);
    header[4] = (fcs_flag << 6) | (@as(u8, @intFromBool(single_segment)) << 5);
    var size: usize = 5;
    if (!single_segment) {
        header[size] = window_descriptor_128k;
        size += 1;
    }
    const value: u64 = if (field_size == 2) len - 256 else len;
    std.mem.writeInt(u64, header[size..][0..8], value, .little);
    size += field_size;
    assert(size == header_size(len));
    out.appendSliceAssumeCapacity(header[0..size]);
}

/// Writes block `data[start..end]` as RLE, compressed, or raw, whichever is smallest.
fn write_block(
    context: ?*block.Context,
    data: []const u8,
    start: usize,
    end: usize,
    out: *std.ArrayList(u8),
) void {
    const content = data[start..end];
    assert(content.len <= block_size_max);
    const last = end == data.len;
    if (content.len > 1 and std.mem.allEqual(u8, content, content[0])) {
        write_block_header(last, block_type_rle, content.len, out);
        out.appendAssumeCapacity(content[0]);
        return;
    }
    if (context) |c| {
        if (c.compress(data, start, end)) |compressed| {
            assert(compressed.len < content.len);
            write_block_header(last, block_type_compressed, compressed.len, out);
            out.appendSliceAssumeCapacity(compressed);
            return;
        }
    }
    write_block_header(last, block_type_raw, content.len, out);
    out.appendSliceAssumeCapacity(content);
}

fn write_block_header(last: bool, block_type: u24, size: usize, out: *std.ArrayList(u8)) void {
    assert(block_type <= block_type_compressed);
    assert(size <= block_size_max);
    const header: u24 = @as(u24, @intFromBool(last)) | (block_type << 1) |
        (@as(u24, @intCast(size)) << 3);
    var bytes: [3]u8 = undefined;
    std.mem.writeInt(u24, &bytes, header, .little);
    out.appendSliceAssumeCapacity(&bytes);
}

/// The decompressed size a frame declares, or null if the header is malformed or omits it
/// (`ZSTD_getFrameContentSize`).
pub fn frame_content_size(frame: []const u8) ?u64 {
    if (frame.len < 5) return null;
    if (std.mem.readInt(u32, frame[0..4], .little) != magic) return null;
    const descriptor = frame[4];
    if (descriptor & 0b0000_1000 != 0) return null; // Reserved bit.
    const fcs_flag: u2 = @intCast(descriptor >> 6);
    const single_segment = descriptor & 0b0010_0000 != 0;
    const dictionary_sizes = [4]usize{ 0, 1, 2, 4 };
    const field_sizes = [4]usize{ @intFromBool(single_segment), 2, 4, 8 };
    const field_size = field_sizes[fcs_flag];
    if (field_size == 0) return null;
    const offset = 5 + @as(usize, @intFromBool(!single_segment)) +
        dictionary_sizes[descriptor & 0b11];
    if (frame.len < offset + field_size) return null;
    var bytes: [8]u8 = @splat(0);
    @memcpy(bytes[0..field_size], frame[offset..][0..field_size]);
    const value = std.mem.readInt(u64, &bytes, .little);
    return if (field_size == 2) value + 256 else value;
}

pub const DecompressError = error{DecompressionFailed} || Allocator.Error;

/// Decompress one frame that declares its content size into an owned buffer.
///
/// A frame of `n` bytes holds at most `n / 3` blocks of at most 128 KiB each, so a declared
/// size beyond that is rejected before allocating (libzstd would allocate it and fail).
pub fn decompress(gpa: Allocator, compressed: []const u8) DecompressError![]u8 {
    const declared = frame_content_size(compressed) orelse return error.DecompressionFailed;
    const blocks_max = compressed.len / 3 + 1;
    if (declared > blocks_max * block_size_max) return error.DecompressionFailed;
    const size: usize = @intCast(declared);

    var out = try std.Io.Writer.Allocating.initCapacity(gpa, size);
    defer out.deinit();
    var input: std.Io.Reader = .fixed(compressed);
    var stream: std.compress.zstd.Decompress = .init(&input, &.{}, .{
        .window_len = @intCast(@min(std.math.maxInt(u32) / 2, @max(size, block_size_max))),
    });
    _ = stream.reader.streamRemaining(&out.writer) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        error.ReadFailed => return error.DecompressionFailed,
    };
    // Exactly one frame, holding exactly the declared bytes.
    if (out.written().len != size) return error.DecompressionFailed;
    if (input.bufferedLen() != 0) return error.DecompressionFailed;
    const result = try out.toOwnedSlice();
    assert(result.len == size);
    return result;
}

const testing = std.testing;

test {
    _ = @import("zstd/bits.zig");
    _ = @import("zstd/fse.zig");
    _ = @import("zstd/huffman.zig");
    _ = @import("zstd/match.zig");
    _ = @import("zstd_test.zig");
    _ = block;
}

test "compress round trips through the std decoder" {
    const gpa = testing.allocator;
    const lengths = [_]usize{ 0, 1, 2, 255, 256, 65791, 65792, 131072, 131073, 300_000 };
    for (lengths) |len| {
        for ([_]bool{ false, true }) |repeated| {
            const data = try gpa.alloc(u8, len);
            defer gpa.free(data);
            for (data, 0..) |*byte, index| byte.* = if (repeated) 0xAB else @truncate(index * 7);

            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(gpa);
            const frame = try compress_into(gpa, data, &out);
            try testing.expect(frame.len <= compress_bound(len));
            try testing.expectEqual(@as(?u64, len), frame_content_size(frame));

            const decoded = try decompress(gpa, frame);
            defer gpa.free(decoded);
            try testing.expectEqualSlices(u8, data, decoded);
        }
    }
}

test "decompress reads libzstd frames" {
    const gpa = testing.allocator;
    // `zstd -3 --no-check` (libzstd 1.5.7) of a file holding "hello hello hello hello": one
    // compressed block with a repeat match.
    const hello = [_]u8{
        0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x17, 0x65, 0x00, 0x00, 0x30, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        0x20, 0x01, 0x00, 0x99, 0x4b, 0x11,
    };
    const decoded = try decompress(gpa, &hello);
    defer gpa.free(decoded);
    try testing.expectEqualStrings("hello hello hello hello", decoded);

    // The same for 70 000 bytes of `i % 7` (commonware's split-payload case), with matches
    // reaching back across the whole output.
    const pattern = [_]u8{
        0x28, 0xb5, 0x2f, 0xfd, 0xa0, 0x70, 0x11, 0x01, 0x00, 0x7d, 0x00, 0x00, 0x38, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x00, 0x66, 0x11, 0xca, 0x8b, 0x11,
    };
    try testing.expectEqual(@as(?u64, 70_000), frame_content_size(&pattern));
    const expanded = try decompress(gpa, &pattern);
    defer gpa.free(expanded);
    try testing.expectEqual(@as(usize, 70_000), expanded.len);
    for (expanded, 0..) |byte, index| try testing.expectEqual(@as(u8, @intCast(index % 7)), byte);
}

test "decompress rejects frames without or with a wrong content size" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const data: [100]u8 = @splat(7);
    const frame = try compress_into(gpa, &data, &out);
    // Single segment, one-byte content size after the magic and the descriptor.
    try testing.expectEqual(@as(u8, 100), frame[5]);
    for ([_]u8{ 99, 101 }) |declared| {
        frame[5] = declared;
        try testing.expectEqual(@as(?u64, declared), frame_content_size(frame));
        try testing.expectError(error.DecompressionFailed, decompress(gpa, frame));
    }
    frame[5] = 100;
    // No content size: a multi-segment descriptor with FCS flag 0.
    const no_size = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38, 0x01, 0x00, 0x00 };
    try testing.expectEqual(@as(?u64, null), frame_content_size(&no_size));
    try testing.expectError(error.DecompressionFailed, decompress(gpa, &no_size));
    // Every truncation fails.
    for (0..frame.len) |len| {
        try testing.expectError(error.DecompressionFailed, decompress(gpa, frame[0..len]));
    }
}
