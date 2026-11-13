//! Striping, tiling, pinned output, and layout tests of the Reed-Solomon scheme.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const mod = @import("mod.zig");
const t = @import("tests.zig");

const rs = cryptography.reed_solomon;
const striped = mod.striped;
const Range = parallel.Range;
const Sha256 = t.Sha256;
const gpa = t.gpa;
const chunk_bytes = striped.shard_chunk_bytes;
const min_stripe = t.min_stripe;

fn tiles_of(k: usize, m: usize, range: Range, out: []Range) usize {
    var tiles: striped.Tiles = .init(k, m, range);
    var count: usize = 0;
    while (tiles.next()) |tile| : (count += 1) out[count] = tile;
    return count;
}

/// Tiles cover a stripe contiguously with block-aligned inner edges and balanced widths; a
/// split uses the fewest tiles within the target that keep every width off 4 KiB.
fn expect_tiles(k: usize, m: usize, range: Range, start: usize) !void {
    const page = 4096 / chunk_bytes;
    const work = 2 * std.math.ceilPowerOfTwoAssert(usize, k + m);
    const target = striped.max_tile_work_bytes / (work * chunk_bytes);
    var buffer: [4096]Range = undefined;
    const tiles = buffer[0..tiles_of(k, m, range, &buffer)];
    try testing.expectEqual(range.start, tiles[0].start);
    try testing.expectEqual(range.end, tiles[tiles.len - 1].end);
    var narrow: usize = std.math.maxInt(usize);
    var wide: usize = 0;
    for (tiles, 0..) |tile, i| {
        if (i > 0) try testing.expectEqual(tiles[i - 1].end, tile.start);
        if (i + 1 < tiles.len) try testing.expect((tile.end - start) % chunk_bytes == 0);
        const width = std.math.divCeil(usize, tile.len(), chunk_bytes) catch unreachable;
        narrow = @min(narrow, width);
        wide = @max(wide, width);
    }
    try testing.expect(narrow >= 1 and wide - narrow <= 1);
    const padded = std.math.divCeil(usize, range.len(), chunk_bytes) catch unreachable;
    if (padded < 2 * target) return testing.expectEqual(@as(usize, 1), tiles.len);
    try testing.expect(wide <= target);
    for (tiles) |tile| {
        const width = std.math.divCeil(usize, tile.len(), chunk_bytes) catch unreachable;
        try testing.expect(width % page != 0);
    }
    for (1..tiles.len) |fewer| {
        const width = padded / fewer;
        const extra = padded % fewer;
        const over = std.math.divCeil(usize, padded, fewer) catch unreachable;
        try testing.expect(over > target or width % page == 0 or
            (extra > 0 and (width + 1) % page == 0));
    }
}

test "striped tiles" {
    const start = 3 * chunk_bytes;
    const shapes = [_][2]usize{ .{ 4, 8 }, .{ 32, 64 }, .{ 100, 100 }, .{ 512, 512 } };
    for (shapes) |shape| {
        for (1..3000) |blocks| {
            for ([_]usize{ 0, 2, chunk_bytes - 2 }) |tail| {
                const range: Range = .init(start, start + blocks * chunk_bytes + tail);
                try expect_tiles(shape[0], shape[1], range, start);
            }
        }
    }
}

/// Whether some stripe of the split `run_batches` makes for `shard_len` spans several tiles.
fn splits_tiles(k: usize, m: usize, shard_len: usize, parallelism: usize) !bool {
    const blocks = shard_len / chunk_bytes;
    const count = @min(parallelism, blocks / (min_stripe / chunk_bytes), parallel.max_chunks);
    try testing.expect(count >= 2);
    for (0..count) |i| {
        const range = striped.byte_range(shard_len, parallel.ops.balanced(blocks, count, i));
        const tiles: striped.Tiles = .init(k, m, range);
        if (tiles.count > 1) return true;
    }
    return false;
}

fn expect_striped_encode(pool: *parallel.ThreadPool, k: usize, m: usize, shard_len: usize) !void {
    const buffer = try gpa.alloc(u8, k * shard_len);
    defer gpa.free(buffer);
    for (buffer, 0..) |*byte, i| byte.* = @intCast(i % 251);
    const originals = try gpa.alloc([]const u8, k);
    defer gpa.free(originals);
    for (originals, 0..) |*shard, i| shard.* = buffer[i * shard_len ..][0..shard_len];
    const recovery = try gpa.alloc(u8, m * shard_len);
    defer gpa.free(recovery);
    try striped.encode_recovery(t.rayon(pool), .{
        .gpa = gpa,
        .k = k,
        .m = m,
        .shard_len = shard_len,
        .originals = originals,
        .recovery = recovery,
    });

    var encoder = try rs.Encoder.init(gpa, k, m, shard_len);
    defer encoder.deinit(gpa);
    for (originals) |shard| try encoder.add_original_shard(shard);
    var result = try encoder.encode();
    defer result.deinit();
    for (0..m) |i| {
        const expected = result.recovery(i).?;
        try testing.expectEqualSlices(u8, expected, recovery[i * shard_len ..][0..shard_len]);
    }
}

test "striped encode matches one full-width encode" {
    const pool = try t.create_pool();
    defer pool.destroy();
    var tiled = false;
    for ([_][2]usize{ .{ 2, 2 }, .{ 32, 64 } }) |shape| {
        const widths = [_]usize{
            2 * min_stripe,      2 * min_stripe + 2,  3 * min_stripe + 62,
            5 * min_stripe + 64, 17 * min_stripe + 2,
        };
        for (widths) |shard_len| {
            tiled = tiled or try splits_tiles(shape[0], shape[1], shard_len, 4);
            try expect_striped_encode(pool, shape[0], shape[1], shard_len);
        }
    }
    try testing.expect(tiled);
}

fn hex(digest: Sha256.Digest) [64]u8 {
    return std.fmt.bytesToHex(digest.bytes, .lower);
}

/// Pins the backend's recovery bytes for a partial final block; striping relies on them.
fn expect_recovery_pinned(k: usize, m: usize, expected: *const [64]u8) !void {
    var shard: [2 * chunk_bytes + 2]u8 = undefined;
    var encoder = try rs.Encoder.init(gpa, k, m, shard.len);
    defer encoder.deinit(gpa);
    for (0..k) |i| {
        for (&shard, 0..) |*byte, j| byte.* = @truncate(i * 31 + j * 7);
        try encoder.add_original_shard(&shard);
    }
    var result = try encoder.encode();
    defer result.deinit();
    var parts: [8][]const u8 = undefined;
    for (parts[0..m], 0..) |*part, i| part.* = result.recovery(i).?;
    try testing.expectEqualStrings(expected, &hex(Sha256.hash(parts[0..m])));
}

test "recovery output format pinned" {
    try expect_recovery_pinned(
        5,
        3,
        "e38bb9dbba4a102c4bd8447e212957742dab0af0c4148d4660c671f2f33d3df2",
    );
    try expect_recovery_pinned(
        4,
        6,
        "9f55e86ae11f9de757087e9052810b6359ed7c3a107ccde5a6b304fa54bd72fa",
    );
    try expect_recovery_pinned(
        3,
        4,
        "aaaeebde791afabb30dc98356130ddd196e600c5a8c33882a8404539df795823",
    );
}

const Pinned = struct { k: u16, m: u16, len: usize, root: *const [64]u8 };

const pinned = [_]Pinned{
    .{
        .k = 2,
        .m = 2,
        .len = 0,
        .root = "87d6a38f0987af00691b75fbfb710b7a50df08115c15254e09f109a1b74170c3",
    },
    .{
        .k = 2,
        .m = 2,
        .len = 1000,
        .root = "b90ea02e9b2eb25cc04f92c80b4f0dc8f68b154feff5a24495a8f090918b10d7",
    },
    .{
        .k = 2,
        .m = 2,
        .len = 70_000,
        .root = "b55ebdadfe51a23ab3a3ee8200a07dded9e10b8226abe34cbad171a11c070189",
    },
    .{
        .k = 3,
        .m = 4,
        .len = 0,
        .root = "85a86686f0c01d863dde8f994dc3c9e063fa4458ff9458e218f5f260ed225c60",
    },
    .{
        .k = 3,
        .m = 4,
        .len = 1000,
        .root = "1fef0811649ed7f925bbc915ec3bf6d97509682e513f595881b2462e5ef1da8e",
    },
    .{
        .k = 3,
        .m = 4,
        .len = 70_000,
        .root = "a460ad1f30a8518a4e91de264deefbed57622c1ee6cf44c8e32573f437df8ba0",
    },
    .{
        .k = 4,
        .m = 6,
        .len = 0,
        .root = "dd18f239803d542063c6dfebc9618c716406b299d1fd84d88476344b05e09d7b",
    },
    .{
        .k = 4,
        .m = 6,
        .len = 1000,
        .root = "e18fcc7b41a8b4ed1ca2420df986787f84452e1fb4d3d294827ebd325bcaaa7d",
    },
    .{
        .k = 4,
        .m = 6,
        .len = 70_000,
        .root = "18e9301ae82f44bf2ce2a16e44bd8901c33f357149a26b7981c6474b1fbd95dd",
    },
    .{
        .k = 5,
        .m = 3,
        .len = 0,
        .root = "dd24cc230c717006fbdea807fe8d14a8e95e34d8b3efb40d8300711c3d1b03f5",
    },
    .{
        .k = 5,
        .m = 3,
        .len = 1000,
        .root = "90cdb8c92a13b9b2d2040f861df5ea24dbc9e27e8d0f10295aec80b93a8397b2",
    },
    .{
        .k = 5,
        .m = 3,
        .len = 70_000,
        .root = "a33bcd6552d8cc593363c994ed4113b59a6da32234846ee0bc1c570ec75f1e7b",
    },
    .{
        .k = 9,
        .m = 16,
        .len = 0,
        .root = "84082dbcb47449967323f8b4893592d1361392387ad0371ee8faf5caad795bd8",
    },
    .{
        .k = 9,
        .m = 16,
        .len = 1000,
        .root = "b7a717d37d93331142139f14a14e61029bc0fac8a2dd3b1b78362d5091f5923f",
    },
    .{
        .k = 9,
        .m = 16,
        .len = 70_000,
        .root = "2f1b1764b12669a09362bfe0dd19e0a5ec1862f81ff67148f4413cfc7ca75cfc",
    },
};

test "commitments are pinned (consensus format)" {
    for (pinned) |case| {
        const data = try gpa.alloc(u8, case.len);
        defer gpa.free(data);
        for (data, 0..) |*byte, i| byte.* = @intCast((i * 31 + 7) % 251);
        const config: t.Config = .{ .minimum_shards = case.k, .extra_shards = case.m };
        var encoding = try t.RS.encode(gpa, config, data, t.seq);
        defer encoding.deinit(gpa);
        try testing.expectEqualStrings(case.root, &hex(encoding.commitment));
    }
}

test "encode rejects unrepresentable widths before allocating" {
    const max: usize = std.math.maxInt(u32);
    // Any configuration rejects a payload longer than the length prefix can express.
    for ([_]usize{ 1, 2 }) |k| {
        try testing.expectError(error.InvalidDataLength, mod.shard_layout(max + 1, k, 1));
    }
    // With one original, the five largest payloads push the width past `u32::MAX`.
    for (max - 4..max + 1) |len| {
        try testing.expect(mod.canonical_shard_len(len, 1) > max);
        try testing.expectError(error.InvalidDataLength, mod.shard_layout(len, 1, 1));
    }
    try testing.expect(mod.canonical_shard_len(max - 5, 1) <= max);
    try testing.expect(mod.canonical_shard_len(max, 2) <= max);

    const limit = utils.MAX_ALLOCATION_BYTES;
    try testing.expect(mod.codeword_fits(3, 1 << 20));
    try testing.expect(mod.codeword_fits(1, limit));
    try testing.expect(!mod.codeword_fits(1, limit + 1));
    try testing.expect(!mod.codeword_fits(2, limit));
    try testing.expect(!mod.codeword_fits(2, std.math.maxInt(usize)));
}

test "read_data_len needs the whole prefix, which may span shards" {
    const prefix: [4]u8 = @splat(0);
    for (0..4) |len| {
        try testing.expectError(error.Inconsistent, mod.read_data_len(&.{prefix[0..len]}));
    }
    try testing.expectEqual(@as(usize, 0), try mod.read_data_len(&.{ prefix[0..1], prefix[1..] }));
}
