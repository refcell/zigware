//! The exact literals encoder against libzstd 1.5.7's `ZSTD_compressLiterals` (dfast)
//! compiled from zstd-sys 2.0.16: each case compresses consecutive chunks of a generated
//! sample, carrying the Huffman tables between chunks as libzstd does between blocks, and
//! pins the SHA-256 of the oracle's output (each chunk's literals section in hex, one line
//! per chunk).

const std = @import("std");
const testing = std.testing;
const huf = @import("huf_exact.zig");

pub const Kind = enum {
    /// A few symbols with tied counts in one log2 bucket, which `HUF_sort` quicksorts.
    ties,
    /// Random bytes at both ends of a skewed middle, which only the suspect sample rejects.
    sandwich,
    /// An exponential distribution whose rate drifts, so tables are reused or replaced.
    drift,
};

/// Sample `index` of `kind` into `out`, deterministic.
pub fn sample(out: []u8, kind: Kind, index: u64) void {
    var prng = std.Random.DefaultPrng.init(0x68756600 + index);
    const random = prng.random();
    switch (kind) {
        .ties => sample_ties(out, random),
        .sandwich => for (out, 0..) |*byte, i| {
            const edge = i % 131072 < 4096 or i % 131072 >= 131072 - 4096;
            byte.* = if (edge) random.int(u8) else exponential(random, 0.3);
        },
        .drift => for (out, 0..) |*byte, i| {
            const phase: f64 = @floatFromInt(i % 65536);
            const offset: u8 = @intCast(i >> 16);
            byte.* = exponential(random, 0.05 + 0.4 * phase / 65536.0) +% offset;
        },
    }
}

fn exponential(random: std.Random, rate: f64) u8 {
    return @intCast(@min(255, @as(u32, @intFromFloat(random.floatExp(f64) / rate))));
}

fn sample_ties(out: []u8, random: std.Random) void {
    var start: usize = 0;
    while (start < out.len) : (start += 8192) {
        const chunk = out[start..@min(out.len, start + 8192)];
        @memset(chunk, 0);
        const symbols = random.intRangeAtMost(u8, 5, 12);
        var pos: usize = 0;
        for (0..symbols) |_| {
            const symbol = random.int(u8);
            const counts = [_]usize{ 600, 600, 700, 800 };
            const count = counts[random.uintLessThan(usize, counts.len)];
            const end = @min(chunk.len, pos + count);
            @memset(chunk[pos..end], symbol);
            pos = end;
        }
        random.shuffle(u8, chunk);
    }
}

pub const Case = struct { kind: Kind, index: u64, chunks: []const u32, suspect: bool };

const ties_chunks: [24]u32 = @splat(8192);

const drift_chunks: [30]u32 = blk: {
    const pattern = [_]u32{ 1025, 2000, 4096, 8000, 20000 };
    var chunks: [30]u32 = undefined;
    for (&chunks, 0..) |*len, i| len.* = pattern[i % pattern.len];
    break :blk chunks;
};

const overshoot_chunks = [_]u32{ 60000, 700, 3000, 300, 300, 300 };
const prefer_repeat_chunks = [_]u32{ 1024, 700, 12000, 300, 6000, 6000, 60000, 300, 12000 };
const tie_chunks = [_]u32{
    300, 12000, 6000, 3000, 6000, 30000, 1000, 30000, 300, 30000, 700, 1500,
};
const boundary_chunks = [_]u32{ 1, 7, 8, 31, 63, 64, 255, 256, 1023, 1024, 16384, 131072 };

pub const cases = [_]Case{
    .{ .kind = .ties, .index = 0, .chunks = &ties_chunks, .suspect = false },
    .{ .kind = .sandwich, .index = 1, .chunks = &.{ 131072, 65536, 40960 }, .suspect = true },
    .{ .kind = .drift, .index = 2, .chunks = &drift_chunks, .suspect = false },
    // Found by searching drift samples for inputs that catch planted bugs: the overshoot
    // repayment in `HUF_setMaxHeight`, `preferRepeat`, and the old table's `<=` tie.
    .{ .kind = .drift, .index = 738, .chunks = &overshoot_chunks, .suspect = false },
    .{ .kind = .drift, .index = 667, .chunks = &prefer_repeat_chunks, .suspect = false },
    .{ .kind = .drift, .index = 222, .chunks = &tie_chunks, .suspect = false },
    .{ .kind = .drift, .index = 3, .chunks = &boundary_chunks, .suspect = false },
};

/// The oracle's output for `case`, written into `out`.
pub fn lines(out: []u8, data: []const u8, case: Case) ![]const u8 {
    const literals = try testing.allocator.alloc(u8, huf.block_size_max + 16);
    defer testing.allocator.free(literals);
    var writer: std.Io.Writer = .fixed(out);
    var tables: [2]huf.Tables = .{ .{}, .{} };
    var pos: usize = 0;
    for (case.chunks, 0..) |len, i| {
        const prev = &tables[i % 2];
        const next = &tables[(i + 1) % 2];
        const src = data[pos..][0..len];
        const n = huf.compress_literals(literals, src, prev, next, case.suspect);
        try writer.print("{x}\n", .{literals[0..n]});
        pos += len;
    }
    return writer.buffered();
}

pub fn total_len(case: Case) usize {
    var total: usize = 0;
    for (case.chunks) |len| total += len;
    return total;
}

const expected = [cases.len][]const u8{
    "72b108cc23196b2da1be676810dac5ab550fee2ab535719a56b24e81da9146b9",
    "c347ebb94815a32eff37197a14632487a6ea31bdfe0f0001d93b1aefce3ecc8a",
    "b029b79af75001c28b7706ed2bc2d9d5bd03a0917c9cf9d1874ea079db21f3ea",
    "8ffb56c1f4135ea7016b9859531720c9277a81e9e8f76427160301572e3fd3ad",
    "01c7cc7c3b334bba3f51d958b610d140583b84383c882b2d748d33057815d6ab",
    "fdd2bad6cdbbe611e078d556faeead434853398d42414a18c2ce12ae79a33fb3",
    "4d09c5ddecec65bc81ed3a00e3263ef29d9adeec78528ed57ecebc785c4c7963",
};

// Tree construction (bucket and quick sort, height limit), the table description, 1X and 4X
// streams, table reuse and its heuristics, the suspect sample, and the literals header.
test "exact huffman literals match libzstd 1.5.7" {
    const gpa = testing.allocator;
    const out = try gpa.alloc(u8, 4 << 20);
    defer gpa.free(out);
    for (cases, expected) |case, hash_hex| {
        const data = try gpa.alloc(u8, total_len(case));
        defer gpa.free(data);
        sample(data, case.kind, case.index);
        const text = try lines(out, data, case);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(text, &hash, .{});
        var want: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, hash_hex);
        try testing.expectEqualSlices(u8, &want, &hash);
    }
}
