//! Tests of the zstd decoder against `std.compress.zstd`: every frame the encoder writes, in
//! every mode, decodes to its input with both; frames with a checksum, a dictionary, or
//! trailing bytes behave as in libzstd; and mutated frames never crash the decoder and decode
//! as std decodes them whenever both accept them.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const zstd = @import("../zstd.zig");

const gpa = testing.allocator;
const corpus = zstd.corpus;

/// `frame` decoded by `std.compress.zstd`, or null if it rejects it.
pub fn std_decompress(frame: []const u8) !?[]u8 {
    const declared = zstd.frame_content_size(frame) orelse return null;
    if (declared > 1 << 24) return null;
    const size: usize = @intCast(declared);
    var out = try std.Io.Writer.Allocating.initCapacity(gpa, size);
    defer out.deinit();
    var input: std.Io.Reader = .fixed(frame);
    var stream: std.compress.zstd.Decompress = .init(&input, &.{}, .{
        .window_len = @intCast(@max(size, zstd.block_size_max)),
    });
    _ = stream.reader.streamRemaining(&out.writer) catch return null;
    if (out.written().len != size or input.bufferedLen() != 0) return null;
    return try out.toOwnedSlice();
}

/// Encodes `data` in `mode`; both decoders must restore it.
fn check_mode(data: []const u8, mode: zstd.Mode) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const frame = try zstd.encode_into(gpa, data, &out, mode);
    const ours = try zstd.decompress(gpa, frame);
    defer gpa.free(ours);
    try testing.expectEqualSlices(u8, data, ours);
    const theirs = (try std_decompress(frame)).?;
    defer gpa.free(theirs);
    try testing.expectEqualSlices(u8, data, theirs);
}

test "decode restores every encoder mode on the samples" {
    var prng = std.Random.DefaultPrng.init(0x6465636f6465);
    const lengths = [_]usize{ 0, 1, 15, 16, 100, 1000, 4096, 65_536, 131_072, 131_073, 300_000 };
    for (lengths) |len| {
        const data = try gpa.alloc(u8, len);
        defer gpa.free(data);
        for (0..4) |kind| {
            switch (kind) {
                0 => corpus.text(prng.random(), data),
                1 => corpus.records(prng.random(), data),
                2 => prng.random().bytes(data),
                else => for (data, 0..) |*byte, index| {
                    byte.* = if (index < 8) @truncate(index) else 0xAB;
                },
            }
            for ([_]zstd.Mode{ .store, .compress, .exact }) |mode| try check_mode(data, mode);
        }
    }
}

/// `frame` with the content checksum flag set and the XXH64 checksum of `data` appended.
fn with_checksum(frame: []const u8, data: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, frame.len + 4);
    @memcpy(out[0..frame.len], frame);
    out[4] |= 0x04;
    const checksum: u32 = @truncate(std.hash.XxHash64.hash(0, data));
    std.mem.writeInt(u32, out[frame.len..][0..4], checksum, .little);
    return out;
}

test "decode checks a content checksum, as libzstd does" {
    var data: [3000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x636865636b);
    corpus.text(prng.random(), &data);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const frame = try zstd.compress_into(gpa, &data, &out);
    const checked = try with_checksum(frame, &data);
    defer gpa.free(checked);
    const decoded = try zstd.decompress(gpa, checked);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, &data, decoded);
    for (0..4) |index| {
        checked[checked.len - 1 - index] ^= 0x01;
        try testing.expectError(error.DecompressionFailed, zstd.decompress(gpa, checked));
        checked[checked.len - 1 - index] ^= 0x01;
    }
}

test "decode rejects dictionaries, reserved bits, and bytes after the frame" {
    const data = "hello, hello, hello, zstd journal frames";
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const frame = try zstd.compress_into(gpa, data, &out);
    // A one-byte dictionary ID of zero names no dictionary; any other ID fails.
    for ([_]u8{ 0, 7 }) |id| {
        const named = try gpa.alloc(u8, frame.len + 1);
        defer gpa.free(named);
        @memcpy(named[0..5], frame[0..5]);
        named[4] |= 0x01;
        named[5] = id;
        @memcpy(named[6..], frame[5..]);
        const result = zstd.decompress(gpa, named);
        if (id == 0) {
            const decoded = try result;
            defer gpa.free(decoded);
            try testing.expectEqualSlices(u8, data, decoded);
        } else try testing.expectError(error.DecompressionFailed, result);
    }
    const reserved = try gpa.dupe(u8, frame);
    defer gpa.free(reserved);
    reserved[4] |= 0x08;
    try testing.expectError(error.DecompressionFailed, zstd.decompress(gpa, reserved));
    const trailing = try gpa.alloc(u8, frame.len + 1);
    defer gpa.free(trailing);
    @memcpy(trailing[0..frame.len], frame);
    trailing[frame.len] = 0;
    try testing.expectError(error.DecompressionFailed, zstd.decompress(gpa, trailing));
}

/// Encodes drawn data, mutates a few drawn bytes of the frame, and decodes it with both
/// decoders: an unmutated frame restores the data, and whenever both decoders accept a frame
/// they agree on its bytes.
fn fuzz_decode(_: void, smith: *std.testing.Smith) anyerror!void {
    const draws: codec.fuzz.Draws = .init(smith);
    var data: [8192]u8 = undefined;
    const len = draws.range_at_most(usize, 0, data.len);
    var prng = std.Random.DefaultPrng.init(draws.value(u64));
    switch (draws.index(3)) {
        0 => corpus.text(prng.random(), data[0..len]),
        1 => corpus.records(prng.random(), data[0..len]),
        else => for (data[0..len], 0..) |*byte, index| {
            byte.* = if (index % 97 < 8) @truncate(index) else 0xAB;
        },
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const mode: zstd.Mode = if (draws.index(2) == 0) .exact else .compress;
    const frame = try zstd.encode_into(gpa, data[0..len], &out, mode);
    const mutations = draws.range_at_most(usize, 0, 4);
    for (0..mutations) |_| {
        // Keep the magic and the descriptor, so most mutations reach the blocks.
        if (frame.len <= 5) break;
        const index = draws.range_at_most(usize, 5, frame.len - 1);
        frame[index] ^= @max(1, draws.value(u8));
    }
    const ours = zstd.decompress(gpa, frame) catch null;
    defer if (ours) |bytes| gpa.free(bytes);
    const theirs = try std_decompress(frame);
    defer if (theirs) |bytes| gpa.free(bytes);
    if (mutations == 0) try testing.expectEqualSlices(u8, data[0..len], ours.?);
    if (ours != null and theirs != null) try testing.expectEqualSlices(u8, theirs.?, ours.?);
}

// Seeded inputs in `zig build test`, then `std.testing.fuzz` under `--fuzz`.
test "fuzz zstd decode against std (seeded)" {
    try codec.fuzz.run({}, fuzz_decode, 0x7a737464_6465636f, 2_000);
}

/// Decodes arbitrary bytes as a frame of up to 64 KiB: never a crash or a leak.
fn fuzz_decode_bytes(_: void, smith: *std.testing.Smith) anyerror!void {
    const draws: codec.fuzz.Draws = .init(smith);
    var input: [512]u8 = undefined;
    const frame = draws.slice(&input);
    if (frame.len >= 4) std.mem.writeInt(u32, frame[0..4], zstd.magic, .little);
    const declared = zstd.frame_content_size(frame) orelse return;
    if (declared > 1 << 16) return;
    const decoded = zstd.decompress(gpa, frame) catch return;
    gpa.free(decoded);
}

test "fuzz zstd decode arbitrary bytes (seeded)" {
    try codec.fuzz.run({}, fuzz_decode_bytes, 0x7a737464_62797465, 2_000);
}
