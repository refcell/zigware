//! Tests of the Reed-Solomon coding scheme (commonware's `coding::reed_solomon` tests), with
//! the helpers the other test files share.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const build_options = @import("build_options");
const coding = @import("../root.zig");
const mod = @import("mod.zig");

const rs = cryptography.reed_solomon;
pub const Sha256 = cryptography.Sha256;
pub const Digest = Sha256.Digest;
pub const Chunk = mod.Chunk(Digest);
pub const Checked = mod.CheckedChunk(Sha256);
pub const RS = coding.ReedSolomon(Sha256);
pub const Config = coding.Config;
pub const gpa = testing.allocator;
pub const seq = parallel.sequential;
pub const min_stripe = mod.striped.min_stripe_bytes;

/// A shard as `check` would check it against `root`.
pub fn checked(root: Digest, chunk: *const Chunk) Checked {
    const digest = Sha256.hash(&.{chunk.shard});
    return .{ .root = root, .shard = chunk.shard, .index = chunk.index, .digest = digest };
}

pub fn config_of(total: u16, min: u16) Config {
    return .{ .minimum_shards = min, .extra_shards = total - min };
}

pub fn create_pool() !*parallel.ThreadPool {
    return parallel.ThreadPool.create(gpa, testing.io, .{ .threads = 3 });
}

/// A parallel strategy that splits every input with at least two stripes.
pub fn rayon(pool: *parallel.ThreadPool) parallel.Rayon {
    return parallel.Rayon.init(pool).with_parallelism(4);
}

/// Chunks committed with a tree over arbitrary shards (a possibly malicious encoder).
pub const Built = struct {
    root: Digest,
    chunks: []Chunk,

    pub fn deinit(self: *Built) void {
        for (self.chunks) |*chunk| chunk.deinit(gpa);
        gpa.free(self.chunks);
    }

    /// The chunks at `indices`, checked against the root; the caller frees.
    pub fn pieces(self: *const Built, indices: []const usize) ![]Checked {
        return pieces_of(self.root, self.chunks, indices);
    }
};

pub fn build_chunks(shards: []const []const u8) !Built {
    const digests = try gpa.alloc(Digest, shards.len);
    defer gpa.free(digests);
    for (shards, digests) |shard, *digest| digest.* = Sha256.hash(&.{shard});
    var tree = try mod.build_tree(Sha256, gpa, digests);
    defer tree.deinit(gpa);
    const chunks = try gpa.alloc(Chunk, shards.len);
    for (chunks, shards, 0..) |*chunk, shard, i| {
        const proof = try tree.proof(gpa, @intCast(i), null);
        chunk.* = .{ .shard = shard, .index = @intCast(i), .proof = proof };
    }
    return .{ .root = tree.root(), .chunks = chunks };
}

pub fn pieces_of(root: Digest, chunks: []const Chunk, indices: []const usize) ![]Checked {
    const pieces = try gpa.alloc(Checked, indices.len);
    for (indices, pieces) |index, *piece| piece.* = checked(root, &chunks[index]);
    return pieces;
}

/// `0..n` as indices.
pub fn first(comptime n: usize) [n]usize {
    var indices: [n]usize = undefined;
    for (&indices, 0..) |*index, i| index.* = i;
    return indices;
}

/// An owned, mutable copy of a codeword's shards.
pub const Codeword = struct {
    buffer: []u8,
    shards: [][]u8,

    pub fn init(source: []const []const u8) !Codeword {
        var total: usize = 0;
        for (source) |shard| total += shard.len;
        const buffer = try gpa.alloc(u8, total);
        const shards = try gpa.alloc([]u8, source.len);
        var offset: usize = 0;
        for (source, shards) |from, *to| {
            to.* = buffer[offset..][0..from.len];
            @memcpy(to.*, from);
            offset += from.len;
        }
        return .{ .buffer = buffer, .shards = shards };
    }

    pub fn of(encoding: *const mod.Encoding(Digest)) !Codeword {
        const refs = try gpa.alloc([]const u8, encoding.shards.len);
        defer gpa.free(refs);
        for (encoding.shards, refs) |chunk, *ref| ref.* = chunk.shard;
        return init(refs);
    }

    pub fn deinit(self: *Codeword) void {
        gpa.free(self.buffer);
        gpa.free(self.shards);
    }

    pub fn build(self: *const Codeword) !Built {
        return build_chunks(@ptrCast(self.shards));
    }
};

pub fn encode(total: u16, min: u16, data: []const u8, strategy: anytype) !mod.Encoding(Digest) {
    return mod.encode(Sha256, gpa, total, min, data, strategy);
}

pub fn decode(
    total: u16,
    min: u16,
    root: *const Digest,
    pieces: []const Checked,
    strategy: anytype,
) mod.Error![]u8 {
    return mod.decode(Sha256, gpa, total, min, root, pieces, strategy);
}

/// Decodes the chunks at `indices` of `encoding` and checks the result is `data`.
pub fn expect_roundtrip(
    total: u16,
    min: u16,
    encoding: *const mod.Encoding(Digest),
    indices: []const usize,
    data: []const u8,
    strategy: anytype,
) !void {
    const pieces = try pieces_of(encoding.commitment, encoding.shards, indices);
    defer gpa.free(pieces);
    const decoded = try decode(total, min, &encoding.commitment, pieces, strategy);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, data, decoded);
}

/// Expects `result` to be `err`, freeing any data it decoded.
pub fn expect_error(err: anyerror, result: anyerror![]u8) !void {
    const data = result catch |actual| return testing.expectEqual(err, actual);
    gpa.free(data);
    return error.TestExpectedError;
}

/// Data whose `k` shards are exactly `width` bytes wide with one byte of padding.
pub fn filled(len: usize, byte: u8) ![]u8 {
    const data = try gpa.alloc(u8, len);
    @memset(data, byte);
    return data;
}

test "recovery from a mix of originals and recoveries" {
    const data = "Testing recovery pieces";
    var encoding = try encode(8, 3, data, seq);
    defer encoding.deinit(gpa);
    try expect_roundtrip(8, 3, &encoding, &.{ 0, 4, 6 }, data, seq);
}

test "not enough pieces" {
    var encoding = try encode(6, 4, "Test insufficient pieces", seq);
    defer encoding.deinit(gpa);
    const pieces = try pieces_of(encoding.commitment, encoding.shards, &.{ 0, 1 });
    defer gpa.free(pieces);
    try expect_error(error.NotEnoughChunks, decode(6, 4, &encoding.commitment, pieces, seq));
    try expect_error(error.NotEnoughChunks, decode(6, 4, &encoding.commitment, &.{}, seq));
}

test "duplicate index" {
    var encoding = try encode(5, 3, "Test duplicate detection", seq);
    defer encoding.deinit(gpa);
    const pieces = try pieces_of(encoding.commitment, encoding.shards, &.{ 0, 0, 1 });
    defer gpa.free(pieces);
    try expect_error(error.DuplicateIndex, decode(5, 3, &encoding.commitment, pieces, seq));
}

test "check rejects a shard at another index" {
    var encoding = try encode(5, 3, "Test invalid index", seq);
    defer encoding.deinit(gpa);
    const config = config_of(5, 3);
    for (encoding.shards, 0..) |*shard, i| {
        const index: u16 = @intCast(i + 1);
        try testing.expect(
            std.meta.isError(RS.check(config, &encoding.commitment, index, shard, seq)),
        );
    }
}

test "decode rejects a checked shard with an out-of-range index" {
    const data = "Testing recovery pieces";
    var encoding = try encode(8, 3, data, seq);
    defer encoding.deinit(gpa);
    const pieces = try pieces_of(encoding.commitment, encoding.shards, &.{ 0, 1, 6 });
    defer gpa.free(pieces);
    pieces[1].index = 8;
    try expect_error(error.InvalidIndex, decode(8, 3, &encoding.commitment, pieces, seq));
}

test "empty and 1000-byte data" {
    var empty = try encode(100, 30, "", seq);
    defer empty.deinit(gpa);
    try expect_roundtrip(100, 30, &empty, &first(30), "", seq);

    const data = try filled(1000, 42);
    defer gpa.free(data);
    var large = try encode(7, 4, data, seq);
    defer large.deinit(gpa);
    try expect_roundtrip(7, 4, &large, &first(4), data, seq);
}

test "parallel encode matches sequential" {
    const pool = try create_pool();
    defer pool.destroy();
    const widths = [_]usize{
        min_stripe - 2, min_stripe,         2 * min_stripe - 2,
        2 * min_stripe, 2 * min_stripe + 2, 4 * min_stripe + 62,
    };
    for (widths) |shard_len| {
        const data = try filled(8 * shard_len - 4, 42);
        defer gpa.free(data);
        var serial = try encode(24, 8, data, seq);
        defer serial.deinit(gpa);
        var striped = try encode(24, 8, data, rayon(pool));
        defer striped.deinit(gpa);
        try testing.expect(serial.commitment.eql(striped.commitment));
        try testing.expectEqualSlices(u8, serial.codeword, striped.codeword);
    }
}

test "parallel recovery decode" {
    const pool = try create_pool();
    defer pool.destroy();
    const data = try filled(256 * 1024, 42);
    defer gpa.free(data);
    var encoding = try encode(24, 8, data, rayon(pool));
    defer encoding.deinit(gpa);
    const recoveries = [_]usize{ 8, 9, 10, 11, 12, 13, 14, 15 };
    try expect_roundtrip(24, 8, &encoding, &recoveries, data, rayon(pool));
    try expect_roundtrip(24, 8, &encoding, &first(8), data, rayon(pool));
}

/// Decodes as many recoveries as possible in both shapes.
fn expect_striped_recovery(
    pool: *parallel.ThreadPool,
    data_len: usize,
    total: u16,
    min: u16,
) !void {
    const data = try gpa.alloc(u8, data_len);
    defer gpa.free(data);
    for (data, 0..) |*byte, i| byte.* = @as(u8, @truncate(i)) ^ @as(u8, @truncate(i >> 7));
    var encoding = try encode(total, min, data, seq);
    defer encoding.deinit(gpa);
    const originals_needed = min -| (total - min);
    var indices: [64]usize = undefined;
    var count: usize = 0;
    for (0..total) |i| {
        if (count == min) break;
        if (i >= originals_needed and i < min) continue;
        indices[count] = i;
        count += 1;
    }
    try expect_roundtrip(total, min, &encoding, indices[0..count], data, seq);
    try expect_roundtrip(total, min, &encoding, indices[0..count], data, rayon(pool));
}

test "striped recovery matches sequential" {
    const pool = try create_pool();
    defer pool.destroy();
    const lengths = [_]usize{
        128 * 1024, 257 * 1024, 512 * 1024, 1024 * 1024, 4 * 1024 * 1024 + 14,
    };
    const shapes = [_][2]u16{ .{ 12, 4 }, .{ 24, 8 }, .{ 33, 11 }, .{ 20, 13 } };
    // The larger payloads take seconds in Debug; `-Dslow-tests` runs them.
    const count: usize = if (build_options.slow_tests) lengths.len else 2;
    for (lengths[0..count]) |len| {
        for (shapes) |shape| try expect_striped_recovery(pool, len, shape[0], shape[1]);
    }
}

test "striped all-originals decode re-encodes in every shape" {
    const pool = try create_pool();
    defer pool.destroy();
    const data = try filled(256 * 1024, 42);
    defer gpa.free(data);
    try testing.expect(mod.canonical_shard_len(data.len, 8) >= 2 * min_stripe);
    var encoding = try encode(24, 8, data, rayon(pool));
    defer encoding.deinit(gpa);
    try expect_roundtrip(24, 8, &encoding, &first(8), data, seq);
    try expect_roundtrip(24, 8, &encoding, &first(8), data, rayon(pool));
}

test {
    _ = @import("striped_test.zig");
    _ = @import("adversarial_test.zig");
    _ = @import("scheme_test.zig");
}
