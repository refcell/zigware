//! Tests for `Prunable` (commonware `utils/src/bitmap/prunable.rs` tests and the
//! `utils/fuzz` prunable target). Tests that only check a panic message are covered by the
//! panics themselves and are not ported (Zig tests cannot catch a panic).

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const codec = @import("codec");
const BitMap = @import("bitmap.zig").BitMap;
const prunable = @import("prunable.zig");
const Prunable = prunable.Prunable;
const rng = @import("../rng.zig");
const fuzz = @import("../fuzz.zig");

const testing = std.testing;
const gpa = testing.allocator;

fn chunk4(bytes: [4]u8) [4]u8 {
    return bytes;
}

fn with_chunks(comptime N: usize, chunks: []const [N]u8) !Prunable(N) {
    var result: Prunable(N) = .empty;
    errdefer result.deinit(gpa);
    for (chunks) |*chunk| try result.push_chunk(gpa, chunk);
    return result;
}

fn pattern(comptime N: usize, len: u64, comptime every: u64) !Prunable(N) {
    var result: Prunable(N) = .empty;
    errdefer result.deinit(gpa);
    for (0..len) |i| try result.push(gpa, i % every == 0);
    return result;
}

fn roundtrip(comptime N: usize, original: *const Prunable(N), cfg: Prunable(N).Cfg) !Prunable(N) {
    const encoded = try codec.encode(Prunable(N), gpa, original.*);
    defer gpa.free(encoded);
    try testing.expectEqual(original.encode_size(), encoded.len);
    return codec.decode_cfg(Prunable(N), gpa, encoded, cfg);
}

test "prunable: new and init_pruned" {
    const fresh: Prunable(32) = .empty;
    try testing.expectEqual(@as(u64, 0), fresh.len());
    try testing.expectEqual(@as(u64, 0), fresh.pruned_bits());
    try testing.expectEqual(@as(usize, 0), fresh.pruned_chunks());
    try testing.expect(fresh.is_empty());
    try testing.expectEqual(@as(usize, 0), fresh.chunks_len());

    const pruned = try Prunable(2).init_pruned(1);
    try testing.expectEqual(@as(u64, 16), pruned.len());
    try testing.expectEqual(@as(u64, 16), pruned.pruned_bits());
    try testing.expectEqual(@as(usize, 1), pruned.pruned_chunks());
    try testing.expectEqual(@as(usize, 1), pruned.chunks_len());

    const overflowing: usize = @intCast(std.math.maxInt(u64) / Prunable(4).CHUNK_SIZE_BITS + 1);
    try testing.expectError(error.PrunedChunksOverflow, Prunable(4).init_pruned(overflowing));
}

test "prunable: push, push_byte, push_chunk, set_bit" {
    var bits: Prunable(4) = .empty;
    defer bits.deinit(gpa);
    try bits.push(gpa, true);
    try bits.push(gpa, false);
    try bits.push(gpa, true);
    try testing.expectEqual(@as(u64, 3), bits.len());
    try testing.expect(bits.get_bit(0) and !bits.get_bit(1) and bits.get_bit(2));
    bits.set_bit(1, true);
    try testing.expect(bits.get_bit(1));
    bits.set_bit(1, false);
    try testing.expect(!bits.get_bit(1));

    var bytes: Prunable(4) = .empty;
    defer bytes.deinit(gpa);
    try bytes.push_byte(gpa, 0xFF);
    try bytes.push_byte(gpa, 0x00);
    try testing.expectEqual(@as(u64, 16), bytes.len());
    for (0..16) |i| try testing.expectEqual(i < 8, bytes.get_bit(i));

    var chunks = try with_chunks(4, &.{.{ 0xAA, 0xBB, 0xCC, 0xDD }});
    defer chunks.deinit(gpa);
    try testing.expectEqual(@as(u64, 32), chunks.len());
    try testing.expectEqual(chunk4(.{ 0xAA, 0xBB, 0xCC, 0xDD }), chunks.get_chunk_containing(0).*);
}

test "prunable: extend_from_bitmap after pruning matches push" {
    var source: BitMap(8) = .empty;
    defer source.deinit(gpa);
    for (0..1000) |i| try source.push(gpa, i % 3 == 0 or i % 7 == 0);
    for ([_]u64{ 128, 129, 191, 255, 256, 300 }) |floor| {
        var actual: Prunable(16) = .empty;
        defer actual.deinit(gpa);
        try actual.extend_to(gpa, 128);
        actual.prune_to_bit(128);
        try actual.extend_to(gpa, floor);
        var expected = try actual.clone(gpa);
        defer expected.deinit(gpa);
        var bit_iter = source.iter();
        while (bit_iter.next()) |bit| try expected.push(gpa, bit);
        try actual.extend_from_bitmap(gpa, 8, &source);
        try testing.expectEqual(expected.len(), actual.len());
        try testing.expectEqual(expected.pruned_bits(), actual.pruned_bits());
        for (actual.pruned_bits()..actual.len()) |bit| {
            try testing.expectEqual(expected.get_bit(bit), actual.get_bit(bit));
        }
    }
}

test "prunable: pruning basic, partial chunk, idempotent, push after" {
    const chunk1 = chunk4(.{ 1, 2, 3, 4 });
    const chunk2 = chunk4(.{ 5, 6, 7, 8 });
    const chunk3 = chunk4(.{ 9, 10, 11, 12 });
    var bits = try with_chunks(4, &.{ chunk1, chunk2, chunk3 });
    defer bits.deinit(gpa);
    try testing.expectEqual(@as(u64, 96), bits.len());
    bits.prune_to_bit(32);
    try testing.expectEqual(@as(usize, 1), bits.pruned_chunks());
    try testing.expectEqual(@as(u64, 32), bits.pruned_bits());
    try testing.expectEqual(@as(u64, 96), bits.len());
    try testing.expectEqual(chunk2, bits.get_chunk_containing(32).*);
    try testing.expectEqual(chunk3, bits.get_chunk_containing(64).*);
    bits.prune_to_bit(64);
    try testing.expectEqual(@as(usize, 2), bits.pruned_chunks());
    try testing.expectEqual(@as(u64, 96), bits.len());
    // Pruning to the same or an earlier point is a no-op.
    bits.prune_to_bit(64);
    bits.prune_to_bit(16);
    try testing.expectEqual(@as(usize, 2), bits.pruned_chunks());
    try bits.push_chunk(gpa, &.{ 13, 14, 15, 16 });
    try testing.expectEqual(@as(u64, 128), bits.len());
    try testing.expectEqual(chunk4(.{ 13, 14, 15, 16 }), bits.get_chunk_containing(96).*);

    var partial = try with_chunks(4, &.{ @splat(0xFF), @splat(0xAA) });
    defer partial.deinit(gpa);
    for ([_]bool{ true, false, true }) |bit| try partial.push(gpa, bit);
    try testing.expectEqual(@as(u64, 67), partial.len());
    partial.prune_to_bit(32);
    try testing.expectEqual(@as(usize, 1), partial.pruned_chunks());
    try testing.expectEqual(@as(u64, 67), partial.len());
    try testing.expect(partial.get_bit(64) and !partial.get_bit(65) and partial.get_bit(66));
}

test "prunable: chunk calculations and get_bit_from_chunk" {
    const P = Prunable(4);
    for ([_]u64{ 0, 31, 32, 63, 64 }, [_]usize{ 0, 0, 1, 1, 2 }) |bit, chunk| {
        try testing.expectEqual(chunk, P.to_chunk_index(bit));
    }
    for ([_]u64{ 0, 8, 16, 24, 32 }, [_]usize{ 0, 1, 2, 3, 0 }) |bit, offset| {
        try testing.expectEqual(offset, P.chunk_byte_offset(bit));
    }
    for ([_]u64{ 0, 1, 7, 8 }, [_]u8{ 0b1, 0b10, 0b1000_0000, 0b1 }) |bit, mask| {
        try testing.expectEqual(mask, P.chunk_byte_bitmask(bit));
    }
    const chunk = chunk4(.{ 0b10101010, 0b11001100, 0b11110000, 0b00001111 });
    for ([_]u64{ 0, 1, 2, 3, 8, 9, 10, 11 }, [_]bool{
        false, true, false, true, false, false, true, true,
    }) |bit, expected| {
        try testing.expectEqual(expected, P.get_bit_from_chunk(&chunk, bit));
    }
}

test "prunable: last_chunk and get_chunk with pruning" {
    var bits = try with_chunks(4, &.{ .{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 } });
    defer bits.deinit(gpa);
    try bits.push(gpa, true);
    try bits.push(gpa, false);
    const before, const used = bits.last_chunk();
    try testing.expectEqual(@as(u64, 2), used);
    bits.prune_to_bit(32);
    const after, const used_after = bits.last_chunk();
    try testing.expectEqual(@as(u64, 2), used_after);
    try testing.expectEqual(before, after);

    const chunks = [_][4]u8{ .{ 0x11, 0x22, 0x33, 0x44 }, .{ 0x55, 0x66, 0x77, 0x88 }, .{
        0x99, 0xAA, 0xBB, 0xCC,
    } };
    var three = try with_chunks(4, &chunks);
    defer three.deinit(gpa);
    for (chunks, 0..) |chunk, index| try testing.expectEqual(chunk, three.get_chunk(index));
    three.prune_to_bit(32);
    try testing.expectEqual(chunks[1], three.get_chunk(1));
    try testing.expectEqual(chunks[2], three.get_chunk(2));
}

test "prunable: different chunk sizes" {
    var p8 = try pattern(8, 10, 2);
    defer p8.deinit(gpa);
    var p16 = try pattern(16, 10, 2);
    defer p16.deinit(gpa);
    var p32 = try pattern(32, 10, 2);
    defer p32.deinit(gpa);
    for (0..10) |i| {
        const expected = i % 2 == 0;
        try testing.expectEqual(expected, p8.get_bit(i));
        try testing.expectEqual(expected, p16.get_bit(i));
        try testing.expectEqual(expected, p32.get_bit(i));
    }
    try testing.expectEqual(@as(u64, 10), p32.len());
}

test "prunable: pop and truncate" {
    var bits: Prunable(4) = .empty;
    defer bits.deinit(gpa);
    for ([_]bool{ true, false, true }) |bit| try bits.push(gpa, bit);
    try testing.expect(bits.pop());
    try testing.expect(!bits.pop());
    try testing.expect(bits.pop());
    try testing.expect(bits.is_empty());
    for (0..100) |i| try bits.push(gpa, i % 3 == 0);
    var remaining: u64 = 100;
    while (remaining > 0) {
        remaining -= 1;
        try testing.expectEqual(remaining % 3 == 0, bits.pop());
        try testing.expectEqual(remaining, bits.len());
    }

    var long = try pattern(4, 96, 3);
    defer long.deinit(gpa);
    long.truncate(65);
    try testing.expectEqual(@as(u64, 65), long.len());
    for (0..65) |i| try testing.expectEqual(i % 3 == 0, long.get_bit(i));
    long.prune_to_bit(32);
    long.truncate(64);
    try testing.expectEqual(@as(u64, 64), long.len());
    for (32..64) |i| try testing.expectEqual(i % 3 == 0, long.get_bit(i));
}

test "prunable: pop_chunk" {
    const P = Prunable(4);
    const first = chunk4(.{ 0xAA, 0xBB, 0xCC, 0xDD });
    const others = [_][4]u8{ .{ 0x11, 0x22, 0x33, 0x44 }, .{ 0x55, 0x66, 0x77, 0x88 } };
    var bits = try with_chunks(4, &(.{first} ++ others));
    defer bits.deinit(gpa);
    try testing.expectEqual(P.CHUNK_SIZE_BITS * 3, bits.len());
    try testing.expectEqual(others[1], bits.pop_chunk());
    try testing.expectEqual(others[0], bits.pop_chunk());
    try testing.expectEqual(P.CHUNK_SIZE_BITS, bits.len());
    for (0..P.CHUNK_SIZE_BITS) |i| {
        try testing.expectEqual((first[i / 8] >> @intCast(i % 8)) & 1 == 1, bits.get_bit(i));
    }
    try testing.expectEqual(first, bits.pop_chunk());
    try testing.expect(bits.is_empty());
}

test "prunable: codec roundtrips" {
    var empty: Prunable(4) = .empty;
    var decoded_empty = try roundtrip(4, &empty, .full());
    defer decoded_empty.deinit(gpa);
    try testing.expect(decoded_empty.is_empty());

    var mixed = try with_chunks(4, &.{ .{ 0xAA, 0xBB, 0xCC, 0xDD }, .{ 0x11, 0x22, 0x33, 0x44 } });
    defer mixed.deinit(gpa);
    for ([_]bool{ true, false, true }) |bit| try mixed.push(gpa, bit);
    var decoded_mixed = try roundtrip(4, &mixed, .full());
    defer decoded_mixed.deinit(gpa);
    try testing.expectEqual(@as(u64, 67), decoded_mixed.len());
    for (0..67) |i| try testing.expectEqual(mixed.get_bit(i), decoded_mixed.get_bit(i));

    var pruned: Prunable(4) = .empty;
    defer pruned.deinit(gpa);
    for (0..5) |i| {
        const base: u8 = @intCast(i * 4);
        try pruned.push_chunk(gpa, &.{ base, base + 1, base + 2, base + 3 });
    }
    pruned.prune_to_bit(96);
    var decoded = try roundtrip(4, &pruned, .full());
    defer decoded.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), decoded.pruned_chunks());
    try testing.expectEqual(@as(u64, 160), decoded.len());
    for (96..160) |i| try testing.expectEqual(pruned.get_bit(i), decoded.get_bit(i));

    inline for (.{ 8, 16, 32 }) |n| {
        var original = try pattern(n, 100, 3);
        defer original.deinit(gpa);
        var copy = try roundtrip(n, &original, .full());
        defer copy.deinit(gpa);
        try testing.expectEqual(original.len(), copy.len());
    }
}

test "prunable: codec wire bytes" {
    var bits = try with_chunks(2, &.{ .{ 1, 2 }, .{ 3, 4 } });
    defer bits.deinit(gpa);
    try bits.push(gpa, true);
    bits.prune_to_bit(16);
    const encoded = try codec.encode(Prunable(2), gpa, bits);
    defer gpa.free(encoded);
    const expected = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 17, 3, 4, 1, 0 };
    try testing.expectEqualSlices(u8, &expected, encoded);
}

test "prunable: codec range bounds retained bits" {
    var ten = try pattern(4, 10, 1);
    defer ten.deinit(gpa);
    var ok = try roundtrip(4, &ten, .to_inclusive(100));
    ok.deinit(gpa);
    try testing.expectError(error.InvalidLength, roundtrip(4, &ten, .to_inclusive(5)));

    var original = try pattern(4, 100, 3);
    defer original.deinit(gpa);
    original.prune_to_bit(64);
    var exact = try roundtrip(4, &original, .exact(36));
    defer exact.deinit(gpa);
    try testing.expectEqual(@as(u64, 100), exact.len());
    try testing.expectEqual(@as(u64, 64), exact.pruned_bits());
    try testing.expectError(error.InvalidLength, roundtrip(4, &original, .exact(100)));
    try testing.expectError(error.InvalidLength, roundtrip(4, &original, .from(37)));

    var all = try pattern(4, 96, 1);
    defer all.deinit(gpa);
    all.prune_to_bit(96);
    var none = try roundtrip(4, &all, .exact(0));
    defer none.deinit(gpa);
    try testing.expectEqual(@as(u64, 96), none.len());
    try testing.expectEqual(@as(u64, 96), none.pruned_bits());
}

fn expect_invalid(bytes: []const u8, message: []const u8) !void {
    var reader = codec.Reader.init(bytes);
    const result = codec.decode_reader(Prunable(4), gpa, &reader, .full());
    try testing.expectError(error.Invalid, result);
    try testing.expectEqualStrings("Prunable", reader.diagnostic.context);
    try testing.expectEqualStrings(message, reader.diagnostic.message);
}

test "prunable: codec overflow errors" {
    const chunk_bits = Prunable(4).CHUNK_SIZE_BITS;
    var overflow: [16]u8 = @splat(0);
    std.mem.writeInt(u64, overflow[0..8], std.math.maxInt(u64) / chunk_bits + 1, .big);
    try expect_invalid(&overflow, "pruned_chunks would overflow when computing pruned_bits");

    const max_safe = std.math.maxInt(u64) / chunk_bits;
    const bitmap_len = std.math.maxInt(u64) - max_safe * chunk_bits + 1;
    const chunk_count = std.math.divCeil(u64, bitmap_len, chunk_bits) catch unreachable;
    var total: [16 + 4]u8 = @splat(0);
    try testing.expectEqual(@as(u64, 1), chunk_count);
    std.mem.writeInt(u64, total[0..8], max_safe, .big);
    std.mem.writeInt(u64, total[8..16], bitmap_len, .big);
    try expect_invalid(&total, "total bitmap length (pruned + unpruned) would overflow u64");
}

test "prunable: is_chunk_aligned" {
    var bits: Prunable(4) = .empty;
    defer bits.deinit(gpa);
    try testing.expect(bits.is_chunk_aligned());
    for (1..65) |i| {
        try bits.push(gpa, i % 2 == 0);
        try testing.expectEqual(i % 32 == 0, bits.is_chunk_aligned());
    }
    try bits.push_chunk(gpa, &.{ 9, 10, 11, 12 });
    bits.prune_to_bit(32);
    try testing.expect(bits.is_chunk_aligned());
    try bits.push(gpa, true);
    try bits.push(gpa, false);
    bits.prune_to_bit(64);
    try testing.expect(!bits.is_chunk_aligned());

    try testing.expect((try Prunable(4).init_pruned(2)).is_chunk_aligned());
    var one = try Prunable(4).init_pruned(1);
    defer one.deinit(gpa);
    try testing.expect(one.is_chunk_aligned());
    try one.push(gpa, true);
    try testing.expect(!one.is_chunk_aligned());

    var bytes: Prunable(4) = .empty;
    defer bytes.deinit(gpa);
    for (0..4) |_| try bytes.push_byte(gpa, 0xFF);
    try testing.expect(bytes.is_chunk_aligned());
    _ = bytes.pop();
    try testing.expect(!bytes.is_chunk_aligned());
    for (0..31) |_| _ = bytes.pop();
    try testing.expect(bytes.is_chunk_aligned());
}

/// `ones_iter_range(from, end).next()` against a bit-by-bit scan, with and without a pruned
/// chunk (commonware `check_ones_iter_ranges`).
fn check_ones_iter_ranges(comptime N: usize) !void {
    const chunk_bits = Prunable(N).CHUNK_SIZE_BITS;
    const len = 3 * chunk_bits + 3;
    for ([_]u64{ 1, 7, 63, 65, len + 1 }) |stride| {
        var bits: Prunable(N) = .empty;
        defer bits.deinit(gpa);
        try bits.extend_to(gpa, len);
        var bit: u64 = 0;
        while (bit < len) : (bit += stride) bits.set_bit(bit, true);
        for ([_]bool{ false, true }) |pruned| {
            if (pruned) bits.prune_to_bit(chunk_bits);
            for (0..len + 2) |from| {
                if (!sampled(N, from)) continue;
                for (from..len + 2) |end| {
                    if (!sampled(N, end)) continue;
                    var ones = bits.ones_iter_range(from, end);
                    try testing.expectEqual(scan(N, &bits, from, end), ones.next());
                }
                var tail = bits.ones_iter_range(from, std.math.maxInt(u64));
                try testing.expectEqual(scan(N, &bits, from, len), tail.next());
            }
        }
    }
}

/// Wide chunks sample range bounds beside byte boundaries to bound the runtime.
fn sampled(comptime N: usize, bit: u64) bool {
    return N <= 9 or bit % 8 <= 1 or bit % 8 == 7;
}

fn scan(comptime N: usize, bits: *const Prunable(N), from: u64, end: u64) ?u64 {
    var bit = @max(from, bits.pruned_bits());
    while (bit < @min(end, bits.len())) : (bit += 1) {
        if (bits.get_bit(bit)) return bit;
    }
    return null;
}

test "prunable: ones_iter_range matches bit scan" {
    // Minutes in Debug, so it runs in optimized builds (CI's ReleaseSafe job) or -Dslow-tests.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    inline for (.{ 1, 7, 8, 9, 32, 64 }) |n| try check_ones_iter_ranges(n);
}

fn collect(iter: anytype) ![]u64 {
    var result: std.ArrayList(u64) = .empty;
    errdefer result.deinit(gpa);
    while (iter.next()) |bit| try result.append(gpa, bit);
    return result.toOwnedSlice(gpa);
}

fn expect_ones(bits: *const Prunable(4), from: u64, expected: []const u64) !void {
    var iter = bits.ones_iter_from(from);
    const ones = try collect(&iter);
    defer gpa.free(ones);
    try testing.expectEqualSlices(u64, expected, ones);
}

test "prunable: ones_iter with pruning" {
    var sparse: Prunable(4) = .empty;
    defer sparse.deinit(gpa);
    try sparse.extend_to(gpa, 96);
    for ([_]u64{ 40, 55, 64, 90 }) |bit| sparse.set_bit(bit, true);
    sparse.prune_to_bit(32);
    try testing.expectEqual(@as(u64, 32), sparse.pruned_bits());
    try expect_ones(&sparse, sparse.pruned_bits(), &.{ 40, 55, 64, 90 });
    try expect_ones(&sparse, 50, &.{ 55, 64, 90 });
    try expect_ones(&sparse, 91, &.{});

    var full = try pattern(4, 96, 1);
    defer full.deinit(gpa);
    full.prune_to_bit(64);
    var expected: [32]u64 = undefined;
    for (&expected, 64..) |*bit, value| bit.* = value;
    try expect_ones(&full, full.pruned_bits(), &expected);

    var zeros: Prunable(4) = .empty;
    defer zeros.deinit(gpa);
    try zeros.extend_to(gpa, 64);
    zeros.prune_to_bit(32);
    try expect_ones(&zeros, zeros.pruned_bits(), &.{});

    // Starting in the pruned region fast-forwards past it.
    var ones = try pattern(4, 64, 1);
    defer ones.deinit(gpa);
    ones.prune_to_bit(32);
    for (&expected, 32..) |*bit, value| bit.* = value;
    try expect_ones(&ones, 0, &expected);
}

test "prunable: ones_iter near u64 max" {
    const max = std.math.maxInt(u64);
    const pruned_count: usize = @intCast(max / 64);
    var near = try Prunable(8).init_pruned(pruned_count);
    defer near.deinit(gpa);
    const from = near.pruned_bits();
    try near.extend_to(gpa, max);
    var none = near.ones_iter_range(from, max);
    try testing.expectEqual(@as(?u64, null), none.next());
    near.set_bit(max - 1, true);
    var below = near.ones_iter_range(from, max - 1);
    try testing.expectEqual(@as(?u64, null), below.next());
    var found = near.ones_iter_range(from, max);
    try testing.expectEqual(@as(?u64, max - 1), found.next());

    const empty = try Prunable(8).init_pruned(pruned_count);
    try testing.expectEqual(max - 63, empty.len());
    var exhausted = empty.ones_iter_from(0);
    try testing.expectEqual(@as(?u64, null), exhausted.next());

    var tail = try Prunable(8).init_pruned(pruned_count);
    defer tail.deinit(gpa);
    const start = tail.pruned_bits();
    for (0..32) |i| try tail.push(gpa, i == 0 or i == 31);
    var iter = tail.ones_iter_from(0);
    const ones = try collect(&iter);
    defer gpa.free(ones);
    try testing.expectEqualSlices(u64, &.{ start, start + 31 }, ones);
}

test "prunable: extend_to" {
    var bits = try pattern(4, 30, 2);
    defer bits.deinit(gpa);
    try bits.extend_to(gpa, 5);
    try testing.expectEqual(@as(u64, 30), bits.len());
    try bits.extend_to(gpa, 65);
    try testing.expectEqual(@as(u64, 65), bits.len());
    for (0..65) |i| try testing.expectEqual(i < 30 and i % 2 == 0, bits.get_bit(i));
    bits.prune_to_bit(32);
    try bits.extend_to(gpa, 100);
    try testing.expectEqual(@as(u64, 100), bits.len());
    try testing.expectEqual(@as(u64, 32), bits.pruned_bits());
    for (65..100) |i| try testing.expect(!bits.get_bit(i));
}

test "prunable: set_chunk_by_index" {
    var partial: Prunable(4) = .empty;
    defer partial.deinit(gpa);
    try partial.extend_to(gpa, 35);
    partial.set_chunk_by_index(1, &.{ 0b0000_0101, 0, 0, 0 });
    try testing.expectEqual(chunk4(.{ 0b0000_0101, 0, 0, 0 }), partial.get_chunk(1));
    var decoded = try roundtrip(4, &partial, .full());
    defer decoded.deinit(gpa);
    try testing.expectEqual(@as(u64, 35), decoded.len());
    try testing.expectEqual(chunk4(.{ 0b0000_0101, 0, 0, 0 }), decoded.get_chunk(1));
    partial.set_chunk_by_index(1, &.{ 0b0000_0111, 0, 0, 0 });
    try testing.expectEqual(chunk4(.{ 0b0000_0111, 0, 0, 0 }), partial.get_chunk(1));

    var full: Prunable(4) = .empty;
    defer full.deinit(gpa);
    try full.extend_to(gpa, 64);
    full.set_chunk_by_index(1, &@splat(0xFF));
    try testing.expectEqual(chunk4(@splat(0xFF)), full.get_chunk(1));
}

test "prunable: unprune_chunks restores pruned chunks" {
    const chunks = [_][4]u8{ .{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 }, .{ 9, 10, 11, 12 } };
    var bits = try with_chunks(4, &chunks);
    defer bits.deinit(gpa);
    try bits.push(gpa, true);
    bits.prune_to_bit(64);
    try bits.unprune_chunks(gpa, &.{ chunks[1], chunks[0] });
    try testing.expectEqual(@as(usize, 0), bits.pruned_chunks());
    try testing.expectEqual(@as(u64, 97), bits.len());
    for (chunks, 0..) |chunk, index| try testing.expectEqual(chunk, bits.get_chunk(index));
}

/// Fuzz (commonware utils/fuzz prunable.rs), extended with a `bool` model: random pushes,
/// pops, prunes, and reads must agree with the model for every chunk size.
fn fuzz_prunable(_: void, generator: *rng.FuzzRng) !void {
    switch (rng.range_less_than(generator, u8, 0, 5)) {
        0 => try fuzz_chunk_size(1, generator),
        1 => try fuzz_chunk_size(4, generator),
        2 => try fuzz_chunk_size(8, generator),
        3 => try fuzz_chunk_size(16, generator),
        else => try fuzz_chunk_size(32, generator),
    }
}

fn fuzz_chunk_size(comptime N: usize, generator: *rng.FuzzRng) !void {
    var model: std.ArrayList(bool) = .empty;
    defer model.deinit(gpa);
    var bits: Prunable(N) = .empty;
    defer bits.deinit(gpa);
    const operations = rng.range_at_most(generator, u32, 1, 256);
    for (0..operations) |_| {
        try fuzz_operation(N, &bits, &model, generator);
        try testing.expectEqual(@as(u64, model.items.len), bits.len());
    }
    for (bits.pruned_bits()..bits.len()) |bit| {
        try testing.expectEqual(model.items[bit], bits.get_bit(bit));
    }
    var decoded = try roundtrip(N, &bits, .full());
    defer decoded.deinit(gpa);
    try testing.expectEqual(bits.len(), decoded.len());
    try testing.expectEqual(bits.pruned_chunks(), decoded.pruned_chunks());
    for (bits.pruned_bits()..bits.len()) |bit| {
        try testing.expectEqual(bits.get_bit(bit), decoded.get_bit(bit));
    }
}

fn fuzz_operation(
    comptime N: usize,
    bits: *Prunable(N),
    model: *std.ArrayList(bool),
    generator: *rng.FuzzRng,
) !void {
    const len = bits.len();
    switch (rng.range_less_than(generator, u8, 0, 6)) {
        0 => {
            const bit = rng.boolean(generator);
            try bits.push(gpa, bit);
            try model.append(gpa, bit);
        },
        1 => if (len % 8 == 0) {
            const byte: u8 = @truncate(generator.next_u32());
            try bits.push_byte(gpa, byte);
            for (0..8) |i| try model.append(gpa, (byte >> @intCast(i)) & 1 == 1);
        },
        2 => if (len % Prunable(N).CHUNK_SIZE_BITS == 0) {
            const seed = std.mem.toBytes(std.mem.nativeToLittle(u64, generator.next_u64()));
            var chunk: [N]u8 = undefined;
            for (&chunk, 0..) |*byte, i| byte.* = seed[i % 8];
            try bits.push_chunk(gpa, &chunk);
            for (0..N * 8) |i| try model.append(gpa, (chunk[i / 8] >> @intCast(i % 8)) & 1 == 1);
        },
        3 => if (len != bits.pruned_bits()) {
            try testing.expectEqual(model.pop().?, bits.pop());
        },
        4 => {
            const bit = if (len != 0) generator.next_u64() % len else 0;
            if (bit > bits.pruned_bits()) bits.prune_to_bit(bit);
            try testing.expect(bits.pruned_bits() <= @max(bit, bits.pruned_bits()));
        },
        else => if (len > bits.pruned_bits()) {
            const bit = rng.range_less_than(generator, u64, bits.pruned_bits(), len);
            try testing.expectEqual(model.items[bit], bits.get_bit(bit));
        },
    }
}

test "fuzz prunable" {
    try fuzz.run({}, fuzz_prunable, 0x7072_756e, 300);
}

const death = @import("../death.zig");

test "prunable: get_bit of a pruned bit panics" {
    // commonware `bitmap/prunable.rs test_get_pruned_bit_panics` (#[should_panic]).
    try death.expect_panic(@src(), "bit pruned", struct {
        fn body() !void {
            var p: Prunable(4) = .empty;
            defer p.deinit(gpa);
            try p.push_chunk(gpa, &.{ 1, 2, 3, 4 });
            try p.push_chunk(gpa, &.{ 5, 6, 7, 8 });
            p.prune_to_bit(32);
            _ = p.get_bit(0);
        }
    }.body);
}

test "prunable: get_chunk_containing a pruned bit panics" {
    // commonware `bitmap/prunable.rs test_get_pruned_chunk_panics` (#[should_panic]).
    try death.expect_panic(@src(), "bit pruned", struct {
        fn body() !void {
            var p: Prunable(4) = .empty;
            defer p.deinit(gpa);
            try p.push_chunk(gpa, &.{ 1, 2, 3, 4 });
            try p.push_chunk(gpa, &.{ 5, 6, 7, 8 });
            p.prune_to_bit(32);
            _ = p.get_chunk_containing(0);
        }
    }.body);
}

test "prunable: set_bit of a pruned bit panics" {
    // commonware `bitmap/prunable.rs test_set_pruned_bit_panics` (#[should_panic]).
    try death.expect_panic(@src(), "bit pruned", struct {
        fn body() !void {
            var p: Prunable(4) = .empty;
            defer p.deinit(gpa);
            try p.push_chunk(gpa, &.{ 1, 2, 3, 4 });
            try p.push_chunk(gpa, &.{ 5, 6, 7, 8 });
            p.prune_to_bit(32);
            p.set_bit(0, true);
        }
    }.body);
}

test "prunable: prune_to_bit out of bounds panics" {
    // commonware `bitmap/prunable.rs test_prune_to_bit_out_of_bounds` (#[should_panic]).
    try death.expect_panic(@src(), "bit 25 out of bounds (len: 24)", struct {
        fn body() !void {
            var p: Prunable(1) = .empty;
            defer p.deinit(gpa);
            try p.push_byte(gpa, 1);
            try p.push_byte(gpa, 2);
            try p.push_byte(gpa, 3);
            p.prune_to_bit(25);
        }
    }.body);
}

test "prunable: truncate into the pruned region panics" {
    // commonware `bitmap/prunable.rs test_truncate_into_pruned_region_panics` (#[should_panic]).
    try death.expect_panic(@src(), "cannot truncate into pruned region", struct {
        fn body() !void {
            var p: Prunable(4) = .empty;
            defer p.deinit(gpa);
            try p.push_chunk(gpa, &.{ 0xFF, 0xFF, 0xFF, 0xFF });
            try p.push_chunk(gpa, &.{ 0xFF, 0xFF, 0xFF, 0xFF });
            p.prune_to_bit(32);
            p.truncate(31);
        }
    }.body);
}

test "prunable: pop_chunk when not chunk aligned panics" {
    // commonware `bitmap/prunable.rs test_pop_chunk_not_aligned` (#[should_panic]).
    try death.expect_panic(@src(), "cannot pop chunk when not chunk aligned", struct {
        fn body() !void {
            var p: Prunable(4) = .empty;
            defer p.deinit(gpa);
            try p.push_chunk(gpa, &.{ 0xFF, 0xFF, 0xFF, 0xFF });
            try p.push(gpa, true);
            _ = p.pop_chunk();
        }
    }.body);
}

test "prunable: pop_chunk with fewer than a chunk of bits panics" {
    // commonware `bitmap/prunable.rs test_pop_chunk_insufficient_bits` (#[should_panic]).
    try death.expect_panic(@src(), "bitmap has fewer than CHUNK_SIZE_BITS bits", struct {
        fn body() !void {
            var p: Prunable(4) = .empty;
            defer p.deinit(gpa);
            try p.push(gpa, true);
            try p.push(gpa, false);
            _ = p.pop_chunk();
        }
    }.body);
}

test "prunable: set_chunk_by_index rejects high bits in the last byte" {
    // commonware `bitmap/prunable.rs` `test_set_chunk_by_index_rejects_high_bits_in_last_byte`
    // (#[should_panic]).
    try death.expect_panic(@src(), "non-zero bits beyond bitmap length", struct {
        fn body() !void {
            var p: Prunable(4) = .empty;
            defer p.deinit(gpa);
            try p.extend_to(gpa, 35);
            p.set_chunk_by_index(1, &.{ 0b0000_1000, 0, 0, 0 });
        }
    }.body);
}

test "prunable: set_chunk_by_index rejects nonzero trailing bytes" {
    // commonware `bitmap/prunable.rs` `test_set_chunk_by_index_rejects_nonzero_trailing_bytes`
    // (#[should_panic]).
    try death.expect_panic(@src(), "non-zero bits beyond bitmap length", struct {
        fn body() !void {
            var p: Prunable(4) = .empty;
            defer p.deinit(gpa);
            try p.extend_to(gpa, 35);
            p.set_chunk_by_index(1, &.{ 0, 0xFF, 0, 0 });
        }
    }.body);
}

test "prunable: set_chunk_by_index rejects a nonzero final byte" {
    // commonware `bitmap/prunable.rs` `test_set_chunk_by_index_rejects_nonzero_final_byte`
    // (#[should_panic]).
    try death.expect_panic(@src(), "non-zero bits beyond bitmap length", struct {
        fn body() !void {
            var p: Prunable(4) = .empty;
            defer p.deinit(gpa);
            try p.extend_to(gpa, 35);
            p.set_chunk_by_index(1, &.{ 0, 0, 0, 1 });
        }
    }.body);
}
