//! Tests of the zstd compressor: ratios on sample inputs, and a round-trip fuzz that decodes
//! every frame with `std.compress.zstd`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const zstd = @import("zstd.zig");

const gpa = testing.allocator;
const corpus = zstd.corpus;

/// Compresses `data` and checks that `std.compress.zstd` restores it; returns the frame size.
fn round_trip(data: []const u8, mode: zstd.Mode) !usize {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const frame = try zstd.encode_into(gpa, data, &out, mode);
    try testing.expect(frame.len <= zstd.compress_bound(data.len));
    try testing.expectEqual(@as(?u64, data.len), zstd.frame_content_size(frame));
    const decoded = try zstd.decompress(gpa, frame);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, data, decoded);
    return frame.len;
}

/// Compressed frame size per thousand input bytes.
fn ratio_permille(data: []const u8) !usize {
    const size = try round_trip(data, .compress);
    assert(data.len > 0);
    return size * 1000 / data.len;
}

test "compress shrinks text and records like a low zstd level" {
    var prng = std.Random.DefaultPrng.init(0x7a737464);
    // Frame size per thousand input bytes that `zstd -1 --no-check` (libzstd 1.5) writes for
    // the same inputs; level 3 writes 497, 298, and 281 for the text.
    const Case = struct { len: usize, text: usize, records: usize };
    const libzstd_level_1 = [_]Case{
        .{ .len = 1_000, .text = 505, .records = 564 },
        .{ .len = 64_000, .text = 316, .records = 129 },
        .{ .len = 300_000, .text = 300, .records = 130 },
    };
    for (libzstd_level_1) |case| {
        const data = try gpa.alloc(u8, case.len);
        defer gpa.free(data);
        corpus.text(prng.random(), data);
        try testing.expect(try ratio_permille(data) <= case.text);
        corpus.records(prng.random(), data);
        try testing.expect(try ratio_permille(data) <= case.records);
    }
    // Random bytes stay raw: one header plus three bytes per block.
    const noise = try gpa.alloc(u8, 200_000);
    defer gpa.free(noise);
    prng.random().bytes(noise);
    try testing.expectEqual(zstd.compress_bound(noise.len), try round_trip(noise, .compress));
}

test "compress writes smaller frames than store on every sample" {
    var prng = std.Random.DefaultPrng.init(0x73746f7265);
    var data: [4096]u8 = undefined;
    for ([_]usize{ 16, 40, 100, 255, 256, 1000, 4096 }) |len| {
        corpus.text(prng.random(), data[0..len]);
        const stored = try round_trip(data[0..len], .store);
        try testing.expect(try round_trip(data[0..len], .compress) <= stored);
        corpus.records(prng.random(), data[0..len]);
        try testing.expect(try round_trip(data[0..len], .compress) < stored);
    }
}

const data_max = 300_000;

/// Builds data from drawn steps (literal runs, copies at drawn offsets, byte runs, and
/// doublings that cross block boundaries), so matches, repeat offsets, and every literal
/// and sequence encoding occur, then round trips it in every mode.
fn fuzz_round_trip(_: void, smith: *std.testing.Smith) anyerror!void {
    const draws: codec.fuzz.Draws = .init(smith);
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(gpa);
    const steps = draws.range_at_most(u8, 1, 64);
    for (0..steps) |_| {
        const room = data_max - data.items.len;
        if (room == 0) break;
        switch (draws.index(5)) {
            0, 1 => {
                var literal: [64]u8 = undefined;
                const len = @min(room, draws.range_at_most(usize, 1, literal.len));
                draws.bytes(literal[0..len]);
                try data.appendSlice(gpa, literal[0..len]);
            },
            2 => if (data.items.len > 0) {
                const offset = draws.range_at_most(usize, 1, @min(data.items.len, 140_000));
                const len = @min(room, draws.range_at_most(usize, 1, 2_000));
                for (0..len) |_| try data.append(gpa, data.items[data.items.len - offset]);
            },
            3 => try data.appendNTimes(gpa, draws.value(u8), @min(room, draws.index(1_000) + 1)),
            else => {
                // Reserve first: appending a slice of the list to itself may reallocate it.
                const len = @min(room, data.items.len);
                try data.ensureUnusedCapacity(gpa, len);
                data.appendSliceAssumeCapacity(data.items[0..len]);
            },
        }
    }
    assert(data.items.len <= data_max);
    const stored = try round_trip(data.items, .store);
    try testing.expect(try round_trip(data.items, .compress) <= stored);
    // libzstd stores a first block that is one repeated byte raw, so `exact` may exceed
    // `store`; it still decodes and stays within `compress_bound`.
    _ = try round_trip(data.items, .exact);
}

// Seeded inputs in `zig build test`, then `std.testing.fuzz` under `--fuzz`.
test "fuzz zstd round trip (seeded)" {
    try codec.fuzz.run({}, fuzz_round_trip, 0x7a737464_726f756e, 200);
}
