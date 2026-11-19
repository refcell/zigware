//! Tests for `BitMap` (commonware `utils/src/bitmap/mod.rs` tests and fuzz target).

const std = @import("std");
const codec = @import("codec");
const BitMap = @import("bitmap.zig").BitMap;
const readable = @import("readable.zig");
const rng = @import("../rng.zig");
const fuzz = @import("../fuzz.zig");

const testing = std.testing;
const gpa = testing.allocator;

fn from(comptime N: usize, bools: []const bool) !BitMap(N) {
    return BitMap(N).from_bools(gpa, bools);
}

fn pattern(comptime N: usize, len: usize, comptime every: usize) !BitMap(N) {
    var result: BitMap(N) = .empty;
    errdefer result.deinit(gpa);
    for (0..len) |i| try result.push(gpa, i % every == 0);
    return result;
}

fn expect_trailing_zero(comptime N: usize, bitmap: *const BitMap(N)) !void {
    if (bitmap.chunks_len() == 0) return;
    const chunk, const used = bitmap.last_chunk();
    for (used..N * 8) |bit| {
        try testing.expect(chunk[bit / 8] & (@as(u8, 1) << @intCast(bit % 8)) == 0);
    }
}

test "bitmap: constructors, zeroes, ones" {
    var empty = try BitMap(4).init_capacity(gpa, 10);
    defer empty.deinit(gpa);
    try testing.expect(empty.is_empty());
    for ([_]u64{ 0, 1, 10 }) |size| {
        var zeroes = try BitMap(1).zeroes(gpa, size);
        defer zeroes.deinit(gpa);
        var ones = try BitMap(1).ones(gpa, size);
        defer ones.deinit(gpa);
        try testing.expectEqual(size, zeroes.len());
        try testing.expectEqual(@as(u64, 0), zeroes.count_ones());
        try testing.expectEqual(size, zeroes.count_zeros());
        try testing.expectEqual(size, ones.count_ones());
        for (0..size) |bit| try testing.expect(ones.get(bit) and !zeroes.get(bit));
    }
}

test "bitmap: trailing bits stay zero" {
    var ones15 = try BitMap(4).ones(gpa, 15);
    defer ones15.deinit(gpa);
    try expect_trailing_zero(4, &ones15);
    var pushed: BitMap(4) = .empty;
    defer pushed.deinit(gpa);
    for (0..37) |i| {
        try pushed.push(gpa, i % 2 == 0);
        try expect_trailing_zero(4, &pushed);
    }
    var popped = try BitMap(4).ones(gpa, 40);
    defer popped.deinit(gpa);
    for (0..15) |_| {
        _ = popped.pop();
        try expect_trailing_zero(4, &popped);
    }
    var flipped = try BitMap(4).ones(gpa, 25);
    defer flipped.deinit(gpa);
    flipped.flip_all();
    try expect_trailing_zero(4, &flipped);
    try testing.expectEqual(@as(u64, 0), flipped.count_ones());

    var dirty = try BitMap(4).ones(gpa, 20);
    defer dirty.deinit(gpa);
    try testing.expect(!dirty.clear_trailing_bits());
    dirty.chunks.backPtr().?[3] |= 0xF0;
    try testing.expect(dirty.clear_trailing_bits());
    try testing.expect(!dirty.clear_trailing_bits());
}

test "bitmap: get, set, flip, chunks" {
    var bv = try from(4, &.{ true, false, true });
    defer bv.deinit(gpa);
    try testing.expect(bv.get(0) and !bv.get(1) and bv.get(2));
    bv.set(1, true);
    bv.set(2, false);
    try testing.expect(bv.get(1) and !bv.get(2));
    bv.flip(0);
    try testing.expect(!bv.get(0));

    var chunked: BitMap(4) = .empty;
    defer chunked.deinit(gpa);
    const chunk = [_]u8{ 0xAB, 0xCD, 0xEF, 0x12 };
    try chunked.push_chunk(gpa, &chunk);
    try testing.expectEqual(@as(u64, 32), chunked.len());
    try testing.expectEqual(chunk, chunked.get_chunk(0));
    try testing.expectEqual(chunk, chunked.get_chunk_containing(0).*);
    const last, const used = chunked.last_chunk();
    try testing.expectEqual(chunk, last);
    try testing.expectEqual(@as(u64, 32), used);
}

test "bitmap: pop and truncate" {
    var bv: BitMap(3) = .empty;
    defer bv.deinit(gpa);
    for (0..100) |i| try bv.push(gpa, i % 2 == 0);
    var i: usize = 100;
    while (i > 0) {
        i -= 1;
        try testing.expectEqual(i % 2 == 0, bv.pop());
    }
    try testing.expect(bv.is_empty());

    var long = try pattern(4, 70, 3);
    defer long.deinit(gpa);
    for ([_]u64{ 65, 32, 31, 0 }) |len| {
        long.truncate(len);
        try testing.expectEqual(len, long.len());
        for (0..len) |bit| try testing.expectEqual(bit % 3 == 0, long.get(bit));
    }
}

test "bitmap: pop_chunk, push_byte, count" {
    var bv: BitMap(3) = .empty;
    defer bv.deinit(gpa);
    try bv.push_chunk(gpa, &.{ 0xAA, 0xBB, 0xCC });
    try bv.push_chunk(gpa, &.{ 0x11, 0x22, 0x33 });
    try testing.expectEqual([3]u8{ 0x11, 0x22, 0x33 }, bv.pop_chunk());
    try testing.expectEqual(@as(u64, 24), bv.len());

    var bytes: BitMap(4) = .empty;
    defer bytes.deinit(gpa);
    try bytes.push_byte(gpa, 0xFF);
    try bytes.push_byte(gpa, 0x00);
    try bytes.push_byte(gpa, 0xAA);
    try testing.expectEqual(@as(u64, 24), bytes.len());
    try testing.expectEqual(@as(u64, 12), bytes.count_ones());
    try testing.expectEqual(@as(u64, 12), bytes.count_zeros());
    for (0..8) |bit| try testing.expect(bytes.get(bit) and !bytes.get(bit + 8));
}

fn check_extend(comptime N: usize, comptime M: usize) !void {
    var generator = rng.test_rng();
    const chunk_bits = BitMap(N).CHUNK_SIZE_BITS;
    const lens = [_]u64{ 0, 1, 7, 8, 9, chunk_bits - 1, chunk_bits, 3 * chunk_bits + 11 };
    for (0..chunk_bits + 2) |prefix| {
        for (lens) |len| {
            var src: BitMap(M) = .empty;
            defer src.deinit(gpa);
            for (0..len) |_| try src.push(gpa, rng.boolean(&generator));
            // The same chunks stored wrapped around the end of the ring buffer.
            var wrapped: BitMap(M) = .{ .bit_len = len };
            defer wrapped.deinit(gpa);
            try wrapped.chunks.ensureTotalCapacityPrecise(gpa, src.chunks_len() + 1);
            const half = src.chunks_len() / 2;
            for (half..src.chunks_len()) |k| {
                wrapped.chunks.pushBackAssumeCapacity(src.get_chunk(k));
            }
            var k = half;
            while (k > 0) : (k -= 1) wrapped.chunks.pushFrontAssumeCapacity(src.get_chunk(k - 1));

            var dst: BitMap(N) = .empty;
            defer dst.deinit(gpa);
            for (0..prefix) |_| try dst.push(gpa, rng.boolean(&generator));
            var expected = try dst.clone(gpa);
            defer expected.deinit(gpa);
            var bits = src.iter();
            while (bits.next()) |bit| try expected.push(gpa, bit);
            inline for (.{ &src, &wrapped }) |source| {
                var actual = try dst.clone(gpa);
                defer actual.deinit(gpa);
                try actual.extend_from_bitmap(gpa, M, source);
                try testing.expect(actual.eql(&expected));
            }
        }
    }
}

test "bitmap: extend_from_bitmap matches push" {
    try check_extend(1, 1);
    try check_extend(1, 8);
    try check_extend(3, 8);
    try check_extend(8, 8);
    try check_extend(8, 3);
    try check_extend(12, 5);
    try check_extend(32, 1);
    try check_extend(32, 8);
}

test "bitmap: set_all, flip_all, and, or, xor" {
    var a = try from(4, &.{ true, false, true, false, true, true });
    defer a.deinit(gpa);
    var b = try from(4, &.{ true, true, false, false, true, false });
    defer b.deinit(gpa);
    const Case = struct { []const bool, *const fn (*BitMap(4), *const BitMap(4)) void };
    const cases = [_]Case{
        .{ &.{ true, false, false, false, true, false }, BitMap(4).@"and" },
        .{ &.{ true, true, true, false, true, true }, BitMap(4).@"or" },
        .{ &.{ false, true, true, false, false, true }, BitMap(4).xor },
    };
    for (cases) |case| {
        var result = try a.clone(gpa);
        defer result.deinit(gpa);
        case[1](&result, &b);
        var expected = try from(4, case[0]);
        defer expected.deinit(gpa);
        try testing.expect(result.eql(&expected));
    }
    a.set_all(true);
    try testing.expectEqual(@as(u64, 6), a.count_ones());
    try expect_trailing_zero(4, &a);
    a.flip_all();
    try testing.expectEqual(@as(u64, 0), a.count_ones());
    a.set_all(false);
    try testing.expectEqual(@as(u64, 6), a.count_zeros());
}

test "bitmap: equality and chunk sizes" {
    var a = try pattern(4, 33, 3);
    defer a.deinit(gpa);
    var b = try pattern(4, 33, 3);
    defer b.deinit(gpa);
    try testing.expect(a.eql(&b));
    try a.push(gpa, true);
    try testing.expect(!a.eql(&b));
    _ = a.pop();
    a.flip(15);
    try testing.expect(!a.eql(&b));

    var big: BitMap(32) = .empty;
    defer big.deinit(gpa);
    try big.push_chunk(gpa, &@as([32]u8, @splat(0x55)));
    try big.push(gpa, true);
    try big.push(gpa, false);
    try testing.expectEqual(@as(u64, 258), big.len());
    try testing.expectEqual(@as(u64, 129), big.count_ones());
}

test "bitmap: iterator" {
    var bv = try pattern(8, 100, 3);
    defer bv.deinit(gpa);
    var bits = bv.iter();
    try testing.expectEqual(@as(u64, 100), bits.remaining());
    var index: u64 = 0;
    while (bits.next()) |bit| : (index += 1) try testing.expectEqual(index % 3 == 0, bit);
    try testing.expectEqual(@as(u64, 100), index);
    try testing.expectEqual(@as(u64, 0), bits.remaining());
}

fn check_ones_range(comptime N: usize, len: u64, bounds: []const u64) !void {
    var bitmap = try pattern(N, len, 3);
    defer bitmap.deinit(gpa);
    for (bounds) |start| {
        for (bounds) |end| {
            var ones = bitmap.ones_iter_range(start, end);
            var bit = start;
            while (bit < @min(end, len)) : (bit += 1) {
                if (bitmap.get(bit)) try testing.expectEqual(@as(?u64, bit), ones.next());
            }
            try testing.expectEqual(@as(?u64, null), ones.next());
            try testing.expectEqual(@as(?u64, null), ones.next());
        }
    }
}

test "bitmap: ones_iter_range" {
    var every: [152]u64 = undefined;
    for (&every, 0..) |*bound, i| bound.* = i;
    try check_ones_range(9, 150, &every);
    var words: [100]u64 = undefined;
    var count: usize = 0;
    for (0..1102) |bit| {
        if (bit % 64 == 0 or bit % 64 == 1 or bit % 64 == 32 or bit % 64 == 63) {
            words[count] = bit;
            count += 1;
        }
    }
    try check_ones_range(64, 1100, words[0..count]);
}

fn expect_ones(iter: anytype, expected: []const u64) !void {
    var it = iter;
    for (expected) |bit| try testing.expectEqual(@as(?u64, bit), it.next());
    try testing.expectEqual(@as(?u64, null), it.next());
}

test "bitmap: ones_iter cases" {
    var sparse = try BitMap(4).zeroes(gpa, 64);
    defer sparse.deinit(gpa);
    for ([_]u64{ 0, 31, 32, 63 }) |bit| sparse.set(bit, true);
    try expect_ones(sparse.ones_iter(), &.{ 0, 31, 32, 63 });

    var partial = try BitMap(4).zeroes(gpa, 35);
    defer partial.deinit(gpa);
    for ([_]u64{ 31, 32, 34 }) |bit| partial.set(bit, true);
    try expect_ones(partial.ones_iter(), &.{ 31, 32, 34 });

    var midway = try BitMap(4).zeroes(gpa, 64);
    defer midway.deinit(gpa);
    for ([_]u64{ 5, 20, 40, 60 }) |bit| midway.set(bit, true);
    try expect_ones(midway.ones_iter_from(20), &.{ 20, 40, 60 });
    try expect_ones(midway.ones_iter_from(21), &.{ 40, 60 });
    try expect_ones(midway.ones_iter_from(61), &.{});

    const multi = [_]u64{ 0, 63, 64, 127, 128, 255, 256, 511, 512, 599 };
    var words = try BitMap(32).zeroes(gpa, 600);
    defer words.deinit(gpa);
    for (multi) |bit| words.set(bit, true);
    try expect_ones(words.ones_iter(), &multi);

    var aligned = try BitMap(8).ones(gpa, 64);
    defer aligned.deinit(gpa);
    var all: [64]u64 = undefined;
    for (&all, 0..) |*bit, i| bit.* = i;
    try expect_ones(aligned.ones_iter(), &all);
}

fn check_ones_vs_get(comptime N: usize) !void {
    var generator = rng.test_rng();
    var bitmap: BitMap(N) = .empty;
    defer bitmap.deinit(gpa);
    const len = 5 * BitMap(N).CHUNK_SIZE_BITS + 7;
    for (0..len) |_| try bitmap.push(gpa, rng.bernoulli(&generator, 0.375));
    var position: u64 = 0;
    while (position <= len) : (position += 1) {
        var ones = bitmap.ones_iter_from(position);
        var bit = position;
        while (bit < len) : (bit += 1) {
            if (readable.get_bit(N, &bitmap, bit)) {
                try testing.expectEqual(@as(?u64, bit), ones.next());
            }
        }
        try testing.expectEqual(@as(?u64, null), ones.next());
    }
}

test "bitmap: ones_iter matches get_bit for every chunk shape" {
    inline for (.{ 1, 3, 4, 8, 12, 16, 23, 32 }) |n| try check_ones_vs_get(n);
}

test "bitmap: codec roundtrip" {
    inline for (.{ 1, 4, 8, 16 }) |n| {
        for ([_]usize{ 0, 5, 32, 35, 100 }) |len| {
            var original = try pattern(n, len, 7);
            defer original.deinit(gpa);
            const encoded = try codec.encode(BitMap(n), gpa, original);
            defer gpa.free(encoded);
            try testing.expectEqual(original.encode_size(), encoded.len);
            try testing.expectEqual(BitMap(n).encode_size_max(len), encoded.len);
            var decoded = try codec.decode_cfg(BitMap(n), gpa, encoded, .full());
            defer decoded.deinit(gpa);
            try testing.expect(original.eql(&decoded));
        }
    }
    // An exactly full chunk needs no extra chunk; a partial one does.
    var exact = try BitMap(4).ones(gpa, 32);
    defer exact.deinit(gpa);
    try testing.expectEqual(@as(usize, 8 + 4), exact.encode_size());
    const empty: BitMap(4) = .empty;
    try testing.expectEqual(@as(usize, 8), empty.encode_size());
}

test "bitmap: codec wire bytes" {
    var bv = try from(4, &.{ true, false, true, true, false, false, true, false, true });
    defer bv.deinit(gpa);
    const encoded = try codec.encode(BitMap(4), gpa, bv);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 9, 0x4D, 0x01, 0, 0 }, encoded);
}

fn expect_decode_error(bytes: []const u8, cfg: BitMap(4).Cfg, expected: anyerror) !void {
    var reader = codec.Reader.init(bytes);
    const result = codec.decode_reader(BitMap(4), gpa, &reader, cfg);
    try testing.expectError(expected, result);
}

test "bitmap: codec errors" {
    var buffer: [8 + 16]u8 = @splat(0);
    std.mem.writeInt(u64, buffer[0..8], 100, .big);
    var reader = codec.Reader.init(&buffer);
    const too_long = codec.decode_reader(BitMap(4), gpa, &reader, .to_inclusive(99));
    try testing.expectError(error.InvalidLength, too_long);
    try testing.expectEqual(@as(u64, 100), reader.diagnostic.value);
    try expect_decode_error(buffer[0..20], .full(), error.EndOfBuffer);
    try expect_decode_error(buffer[0..8], .to_inclusive(99), error.InvalidLength);
    const max_len: [8]u8 = @splat(0xff);
    try expect_decode_error(&max_len, .full(), error.EndOfBuffer);
    var huge: [8]u8 = undefined;
    std.mem.writeInt(u64, &huge, (@as(u64, std.math.maxInt(u32)) + 1) * 32, .big);
    try expect_decode_error(&huge, .full(), error.EndOfBuffer);

    // A truncated chunk fails before consuming anything past the length.
    var truncated: [8 + 7]u8 = @splat(0);
    std.mem.writeInt(u64, truncated[0..8], 33, .big);
    var short_reader = codec.Reader.init(&truncated);
    const short = codec.read_cfg(BitMap(4), gpa, &short_reader, .full());
    try testing.expectError(error.EndOfBuffer, short);
    try testing.expectEqual(@as(usize, 7), short_reader.remaining());

    // Set trailing bits are rejected.
    var dirty = try BitMap(4).ones(gpa, 20);
    defer dirty.deinit(gpa);
    const encoded = try codec.encode(BitMap(4), gpa, dirty);
    defer gpa.free(encoded);
    encoded[encoded.len - 2] |= 0xF0;
    var dirty_reader = codec.Reader.init(encoded);
    const invalid = codec.decode_reader(BitMap(4), gpa, &dirty_reader, .full());
    try testing.expectError(error.Invalid, invalid);
    try testing.expectEqualStrings("BitMap", dirty_reader.diagnostic.context);
}

test "bitmap: codec range config" {
    var original = try pattern(4, 100, 3);
    defer original.deinit(gpa);
    const encoded = try codec.encode(BitMap(4), gpa, original);
    defer gpa.free(encoded);
    for ([_]BitMap(4).Cfg{ .to_inclusive(100), .to_inclusive(101), .exact(100) }) |cfg| {
        var decoded = try codec.decode_cfg(BitMap(4), gpa, encoded, cfg);
        defer decoded.deinit(gpa);
        try testing.expect(decoded.eql(&original));
    }
    for ([_]BitMap(4).Cfg{ .to_inclusive(50), .exact(99), .from(101) }) |cfg| {
        const result = codec.decode_cfg(BitMap(4), gpa, encoded, cfg);
        try testing.expectError(error.InvalidLength, result);
    }
}

fn repeat(comptime text: []const u8, comptime count: usize) [text.len * count]u8 {
    var out: [text.len * count]u8 = undefined;
    for (0..count) |i| @memcpy(out[i * text.len ..][0..text.len], text);
    return out;
}

test "bitmap: debug formatting" {
    var buffer: [256]u8 = undefined;
    const empty: BitMap(4) = .empty;
    try testing.expectEqualStrings("BitMap[]", try std.fmt.bufPrint(&buffer, "{f}", .{empty}));
    var small = try from(4, &.{ true, false, true, false, true });
    defer small.deinit(gpa);
    try testing.expectEqualStrings("BitMap[10101]", try std.fmt.bufPrint(&buffer, "{f}", .{small}));
    var limit = try pattern(8, 64, 2);
    defer limit.deinit(gpa);
    const alternating = "BitMap[" ++ comptime repeat("10", 32) ++ "]";
    try testing.expectEqualStrings(alternating, try std.fmt.bufPrint(&buffer, "{f}", .{limit}));
    var over = try BitMap(16).zeroes(gpa, 65);
    defer over.deinit(gpa);
    over.set(0, true);
    over.set(64, true);
    const zeros = comptime repeat("0", 31);
    const expected = "BitMap[1" ++ zeros ++ "..." ++ zeros ++ "1]";
    try testing.expectEqualStrings(expected, try std.fmt.bufPrint(&buffer, "{f}", .{over}));
}

test "bitmap: prune and prepend chunks" {
    var bv: BitMap(4) = .empty;
    defer bv.deinit(gpa);
    for ([_][4]u8{ .{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 }, .{ 9, 10, 11, 12 } }) |chunk| {
        try bv.push_chunk(gpa, &chunk);
    }
    bv.prune_chunks(1);
    try testing.expectEqual(@as(u64, 64), bv.len());
    try testing.expectEqual([4]u8{ 5, 6, 7, 8 }, bv.get_chunk(0));
    try bv.push(gpa, true);
    bv.prune_chunks(1);
    try testing.expectEqual(@as(u64, 33), bv.len());
    try testing.expect(bv.get(32));
    try bv.prepend_chunk(gpa, &.{ 0xDE, 0xAD, 0xBE, 0xEF });
    try testing.expectEqual(@as(u64, 65), bv.len());
    try testing.expectEqual([4]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, bv.get_chunk(0));
    bv.set_chunk_by_index(1, &.{ 0, 0, 0, 0 });
    bv.prune_chunks(3);
    try testing.expect(bv.is_empty());
    try bv.push(gpa, true);
    try testing.expect(bv.get(0));
}

test "bitmap: count_ones and write span a wrapped chunk ring" {
    // Pruning the front and pushing again wraps the chunks around the ring buffer, so
    // count_ones and write must read both of its segments.
    const chunks = [_][4]u8{
        .{ 0xFF, 0x00, 0x01, 0x80 }, .{ 0x0F, 0xF0, 0x33, 0xCC }, .{ 0xAA, 0x55, 0x01, 0x02 },
        .{ 0x07, 0x00, 0x00, 0x10 }, .{ 0xFF, 0xFF, 0xFF, 0x7F }, .{ 0x01, 0x02, 0x04, 0x08 },
    };
    var wrapped = try BitMap(4).init_capacity(gpa, 4 * 32);
    defer wrapped.deinit(gpa);
    for (chunks[0..4]) |*chunk| try wrapped.push_chunk(gpa, chunk);
    wrapped.prune_chunks(2);
    for (chunks[4..]) |*chunk| try wrapped.push_chunk(gpa, chunk);
    try testing.expect(wrapped.chunks.head + wrapped.chunks.len > wrapped.chunks.buffer.len);

    var flat: BitMap(4) = .empty;
    defer flat.deinit(gpa);
    for (chunks[2..]) |*chunk| try flat.push_chunk(gpa, chunk);
    // Set bits in chunks 2 to 5: 10 + 4 + 31 + 4.
    try testing.expectEqual(@as(u64, 49), wrapped.count_ones());
    const expected = try codec.encode(BitMap(4), gpa, flat);
    defer gpa.free(expected);
    const actual = try codec.encode(BitMap(4), gpa, wrapped);
    defer gpa.free(actual);
    try testing.expectEqualSlices(u8, expected, actual);
}

test "bitmap: chunk alignment" {
    var bv: BitMap(4) = .empty;
    defer bv.deinit(gpa);
    try testing.expect(bv.is_chunk_aligned());
    for (1..65) |i| {
        try bv.push(gpa, i % 2 == 0);
        try testing.expectEqual(i % 32 == 0, bv.is_chunk_aligned());
    }
    try testing.expectEqual(@as(usize, 2), bv.complete_chunks());
    _ = bv.pop();
    try testing.expectEqual(@as(usize, 1), bv.complete_chunks());
}

test "bitmap: is_unset" {
    var zeros = try BitMap(8).zeroes(gpa, 256);
    defer zeros.deinit(gpa);
    try testing.expect(zeros.is_unset(0, 256));
    var all = try BitMap(8).ones(gpa, 64);
    defer all.deinit(gpa);
    try testing.expect(!all.is_unset(0, 64));
    try testing.expect(all.is_unset(32, 32) and all.is_unset(64, 64));
    var single = try BitMap(8).zeroes(gpa, 64);
    defer single.deinit(gpa);
    single.set(31, true);
    try testing.expect(single.is_unset(0, 31) and !single.is_unset(0, 32));
    try testing.expect(!single.is_unset(31, 32) and single.is_unset(32, 64));
    var spans = try BitMap(4).zeroes(gpa, 128);
    defer spans.deinit(gpa);
    spans.set(96, true);
    try testing.expect(spans.is_unset(0, 96) and !spans.is_unset(0, 97));
    try testing.expect(spans.is_unset(97, 128));
}

test "bitmap: is_unset matches naive scan" {
    var generator = rng.TestRng.init(17);
    for (0..200) |_| {
        const len = rng.range_at_most(&generator, usize, 1, 512);
        var bitmap: BitMap(8) = .empty;
        defer bitmap.deinit(gpa);
        for (0..len) |_| try bitmap.push(gpa, rng.ratio(&generator, 1, 16));
        const start = rng.range_at_most(&generator, u64, 0, len);
        const end = rng.range_at_most(&generator, u64, start, len);
        var expected = true;
        for (start..end) |bit| expected = expected and !bitmap.get(bit);
        try testing.expectEqual(expected, bitmap.is_unset(start, end));
    }
}

/// Fuzz (commonware utils/fuzz bitmap.rs): random operations against a `bool` model.
fn fuzz_bitmap(_: void, generator: *rng.FuzzRng) !void {
    var model: std.ArrayList(bool) = .empty;
    defer model.deinit(gpa);
    var bitmap: BitMap(3) = .empty;
    defer bitmap.deinit(gpa);
    for (0..64) |_| {
        switch (rng.range_less_than(generator, u8, 0, 6)) {
            0 => {
                const bit = rng.boolean(generator);
                try bitmap.push(gpa, bit);
                try model.append(gpa, bit);
            },
            1 => if (model.items.len > 0) try testing.expectEqual(model.pop().?, bitmap.pop()),
            2 => if (model.items.len > 0) {
                const index = rng.range_less_than(generator, usize, 0, model.items.len);
                bitmap.flip(index);
                model.items[index] = !model.items[index];
            },
            3 => {
                const len = rng.range_at_most(generator, usize, 0, model.items.len);
                bitmap.truncate(len);
                model.shrinkRetainingCapacity(len);
            },
            4 => {
                bitmap.flip_all();
                for (model.items) |*bit| bit.* = !bit.*;
            },
            else => try expect_codec_roundtrip(&bitmap, generator),
        }
        try expect_matches(&bitmap, model.items);
    }
}

fn expect_matches(bitmap: *const BitMap(3), model: []const bool) !void {
    try testing.expectEqual(@as(u64, model.len), bitmap.len());
    var ones: u64 = 0;
    for (model, 0..) |bit, index| {
        try testing.expectEqual(bit, bitmap.get(index));
        ones += @intFromBool(bit);
    }
    try testing.expectEqual(ones, bitmap.count_ones());
    try expect_trailing_zero(3, bitmap);
}

fn expect_codec_roundtrip(bitmap: *const BitMap(3), generator: *rng.FuzzRng) !void {
    const encoded = try codec.encode(BitMap(3), gpa, bitmap.*);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(BitMap(3), gpa, encoded, .full());
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(bitmap));
    // Corrupting any byte either fails to decode or decodes to a valid bitmap.
    if (encoded.len == 0) return;
    const position = rng.range_less_than(generator, usize, 0, encoded.len);
    encoded[position] ^= @truncate(generator.next_u32() | 1);
    var corrupt = codec.decode_cfg(BitMap(3), gpa, encoded, .full()) catch return;
    defer corrupt.deinit(gpa);
    try testing.expectEqual(corrupt.encode_size(), encoded.len);
}

test "fuzz bitmap" {
    try fuzz.run({}, fuzz_bitmap, 0x6269_746d_6170, 300);
}

/// `a op b` is 64 bits whose two chunks both equal `expected_chunk`.
fn expect_chunk_op(
    comptime op: enum { @"and", @"or", xor },
    a: *const BitMap(4),
    b: *const BitMap(4),
    expected_chunk: [4]u8,
) !void {
    var result = try a.clone(gpa);
    defer result.deinit(gpa);
    switch (op) {
        .@"and" => result.@"and"(b),
        .@"or" => result.@"or"(b),
        .xor => result.xor(b),
    }
    try testing.expectEqual(@as(u64, 64), result.len());
    for (0..2) |index| try testing.expectEqual(expected_chunk, result.get_chunk(index));
}

test "bitmap: and/or/xor over two full chunks (test_multi_chunk_operations)" {
    // commonware only bounds the counts; the exact bytes are checked here.
    const left = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const right = [4]u8{ 0x55, 0x66, 0x77, 0x88 };
    var a: BitMap(4) = .empty;
    defer a.deinit(gpa);
    var b: BitMap(4) = .empty;
    defer b.deinit(gpa);
    for (0..2) |_| {
        try a.push_chunk(gpa, &left);
        try b.push_chunk(gpa, &right);
    }
    try expect_chunk_op(.@"and", &a, &b, .{ 0x00, 0x22, 0x44, 0x88 });
    try expect_chunk_op(.@"or", &a, &b, .{ 0xFF, 0xFF, 0xFF, 0xDD });
    try expect_chunk_op(.xor, &a, &b, .{ 0xFF, 0xDD, 0xBB, 0x55 });
}

test "bitmap: and/or/xor and flip_all keep a partial chunk's length" {
    // commonware `test_partial_chunk_operations` (35 bits), with each bit checked.
    var a = try pattern(4, 35, 2);
    defer a.deinit(gpa);
    var b = try pattern(4, 35, 3);
    defer b.deinit(gpa);
    inline for (.{ "and", "or", "xor" }) |name| {
        var result = try a.clone(gpa);
        defer result.deinit(gpa);
        @field(BitMap(4), name)(&result, &b);
        try testing.expectEqual(@as(u64, 35), result.len());
        try expect_trailing_zero(4, &result);
        for (0..35) |bit| {
            const x = bit % 2 == 0;
            const y = bit % 3 == 0;
            const expected = if (comptime std.mem.eql(u8, name, "and"))
                x and y
            else if (comptime std.mem.eql(u8, name, "or")) x or y else x != y;
            try testing.expectEqual(expected, result.get(bit));
        }
    }
    var inverted = try a.clone(gpa);
    defer inverted.deinit(gpa);
    inverted.flip_all();
    try testing.expectEqual(a.count_zeros(), inverted.count_ones());
    try testing.expectEqual(a.count_ones(), inverted.count_zeros());
    try expect_trailing_zero(4, &inverted);
}

test "bitmap: ones_iter of empty, zero, and one-bit maps" {
    // commonware `test_ones_iter_empty`, `test_ones_iter_all_zeros`, `test_ones_iter_single_bit`.
    var empty: BitMap(4) = .empty;
    try expect_ones(empty.ones_iter(), &.{});
    var zeroes = try BitMap(4).zeroes(gpa, 100);
    defer zeroes.deinit(gpa);
    try expect_ones(zeroes.ones_iter(), &.{});
    for ([_]bool{ true, false }) |bit| {
        var single: BitMap(4) = .empty;
        defer single.deinit(gpa);
        try single.push(gpa, bit);
        try expect_ones(single.ones_iter(), if (bit) &.{0} else &.{});
    }
}

test "bitmap: ones_iter yields count_ones bits (test_ones_iter_matches_count_ones)" {
    var bitmap = try pattern(8, 200, 7);
    defer bitmap.deinit(gpa);
    var ones = bitmap.ones_iter();
    var count: u64 = 0;
    while (ones.next()) |bit| : (count += 1) try testing.expect(bit % 7 == 0);
    try testing.expectEqual(@as(u64, 29), count);
    try testing.expectEqual(bitmap.count_ones(), count);
}

fn check_from_bools(comptime N: usize) !void {
    const bits = [_]bool{ true, false, true, true, false, false, true };
    var bitmap = try from(N, &bits);
    defer bitmap.deinit(gpa);
    try testing.expectEqual(@as(u64, 7), bitmap.len());
    try testing.expectEqual(@as(u64, 4), bitmap.count_ones());
    try testing.expectEqual(@as(u64, 3), bitmap.count_zeros());
    for (bits, 0..) |bit, index| try testing.expectEqual(bit, bitmap.get(index));
}

test "bitmap: from_bools at several chunk sizes (test_from_different_chunk_sizes)" {
    inline for (.{ 4, 8, 16 }) |N| try check_from_bools(N);
}

test "bitmap: is_unset across one-byte chunks (is_unset_chunk_boundaries)" {
    var bitmap = try BitMap(1).zeroes(gpa, 32);
    defer bitmap.deinit(gpa);
    bitmap.set(7, true);
    try testing.expect(bitmap.is_unset(0, 7));
    try testing.expect(!bitmap.is_unset(0, 8));
    try testing.expect(bitmap.is_unset(8, 32));
}

const death = @import("../death.zig");

test "bitmap: truncate to a larger size panics" {
    // commonware `bitmap/mod.rs test_truncate_larger_size_panics` (#[should_panic]).
    try death.expect_panic(@src(), "cannot truncate to a larger size", struct {
        fn body() !void {
            var bv: BitMap(4) = .empty;
            defer bv.deinit(gpa);
            try bv.push(gpa, true);
            bv.truncate(2);
        }
    }.body);
}

test "bitmap: pop_chunk when not chunk aligned panics" {
    // commonware `bitmap/mod.rs test_pop_chunk_not_aligned` (#[should_panic]).
    try death.expect_panic(@src(), "cannot pop chunk when not chunk aligned", struct {
        fn body() !void {
            var bv: BitMap(3) = .empty;
            defer bv.deinit(gpa);
            try bv.push_chunk(gpa, &.{ 0xFF, 0xFF, 0xFF });
            try bv.push(gpa, true);
            _ = bv.pop_chunk();
        }
    }.body);
}

test "bitmap: pop_chunk with fewer than a chunk of bits panics" {
    // commonware `bitmap/mod.rs test_pop_chunk_insufficient_bits` (#[should_panic]).
    try death.expect_panic(@src(), "bitmap has fewer than CHUNK_SIZE_BITS bits", struct {
        fn body() !void {
            var bv: BitMap(3) = .empty;
            defer bv.deinit(gpa);
            try bv.push(gpa, true);
            try bv.push(gpa, false);
            _ = bv.pop_chunk();
        }
    }.body);
}

test "bitmap: flip out of bounds panics" {
    // commonware `bitmap/mod.rs test_flip_out_of_bounds` (#[should_panic]).
    try death.expect_panic(@src(), "bit 1 out of bounds (len: 1)", struct {
        fn body() !void {
            var bv: BitMap(4) = .empty;
            defer bv.deinit(gpa);
            try bv.push(gpa, true);
            bv.flip(1);
        }
    }.body);
}

test "bitmap: and of mismatched lengths panics" {
    // commonware `bitmap/mod.rs test_and_length_mismatch` (#[should_panic]).
    try death.expect_panic(@src(), "BitMap lengths don't match: 2 vs 1", struct {
        fn body() !void {
            var a = try pattern(4, 2, 2);
            defer a.deinit(gpa);
            var b = try pattern(4, 1, 2);
            defer b.deinit(gpa);
            a.@"and"(&b);
        }
    }.body);
}

test "bitmap: or of mismatched lengths panics" {
    // commonware `bitmap/mod.rs test_or_length_mismatch` (#[should_panic]).
    try death.expect_panic(@src(), "BitMap lengths don't match: 1 vs 2", struct {
        fn body() !void {
            var a = try pattern(4, 1, 2);
            defer a.deinit(gpa);
            var b = try pattern(4, 2, 2);
            defer b.deinit(gpa);
            a.@"or"(&b);
        }
    }.body);
}

test "bitmap: xor of mismatched lengths panics" {
    // commonware `bitmap/mod.rs test_xor_length_mismatch` (#[should_panic]).
    try death.expect_panic(@src(), "BitMap lengths don't match: 3 vs 2", struct {
        fn body() !void {
            var a = try pattern(4, 3, 2);
            defer a.deinit(gpa);
            var b = try pattern(4, 2, 2);
            defer b.deinit(gpa);
            a.xor(&b);
        }
    }.body);
}

test "bitmap: pruning more chunks than exist panics" {
    // commonware `bitmap/mod.rs test_prune_too_many_chunks` (#[should_panic]).
    try death.expect_panic(@src(), "cannot prune", struct {
        fn body() !void {
            var bv: BitMap(4) = .empty;
            defer bv.deinit(gpa);
            try bv.push_chunk(gpa, &.{ 1, 2, 3, 4 });
            try bv.push_chunk(gpa, &.{ 5, 6, 7, 8 });
            try bv.push(gpa, true);
            bv.prune_chunks(4);
        }
    }.body);
}

test "bitmap: is_unset past the end panics" {
    // commonware `bitmap/mod.rs is_unset_out_of_bounds` (#[should_panic]).
    try death.expect_panic(@src(), "range end 65 out of bounds (len: 64)", struct {
        fn body() !void {
            var bitmap = try BitMap(8).zeroes(gpa, 64);
            defer bitmap.deinit(gpa);
            _ = bitmap.is_unset(0, 65);
        }
    }.body);
}
