//! Scheme-level tests of the Reed-Solomon coder: batched checks, shard size bounds, chunk
//! codec bounds and conformance, and the `lib.rs` scheme tests.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");
const codec = @import("codec");
const conformance = @import("conformance");
const minifuzz = @import("invariants").minifuzz;
const coding = @import("../root.zig");
const mod = @import("mod.zig");
const t = @import("tests.zig");

const Sha256 = t.Sha256;
const Digest = t.Digest;
const Chunk = t.Chunk;
const Config = t.Config;
const RS = t.RS;
const gpa = t.gpa;
const seq = t.seq;

/// Records the digest of every single-part `hash` input and of every `hash_many` message, and
/// each `hash_many` call, so tests can see what was hashed (commonware's `InstrumentedSha256`).
const Instrumented = struct {
    pub const Digest = Sha256.Digest;
    inner: Sha256,

    var inputs: [1024]Sha256.Digest = undefined;
    var input_count: usize = 0;
    var calls: [8][64]Sha256.Digest = undefined;
    var call_lens: [8]usize = undefined;
    var call_count: usize = 0;

    fn reset() void {
        input_count = 0;
        call_count = 0;
    }

    fn record(message: []const u8) void {
        assert(input_count < inputs.len);
        inputs[input_count] = Sha256.hash(&.{message});
        input_count += 1;
    }

    fn hashed(message: []const u8) bool {
        const digest = Sha256.hash(&.{message});
        for (inputs[0..input_count]) |input| if (input.eql(digest)) return true;
        return false;
    }

    /// Expects exactly one `hash_many` call, over `expected` in order.
    fn expect_one_call(expected: []const []const u8) !void {
        try testing.expectEqual(@as(usize, 1), call_count);
        try testing.expectEqual(expected.len, call_lens[0]);
        for (expected, calls[0][0..expected.len]) |message, digest| {
            try testing.expect(digest.eql(Sha256.hash(&.{message})));
        }
    }

    pub fn init() Instrumented {
        return .{ .inner = Sha256.init() };
    }

    pub fn update(self: *Instrumented, bytes: []const u8) void {
        self.inner.update(bytes);
    }

    pub fn finalize(self: *Instrumented) Sha256.Digest {
        return self.inner.finalize();
    }

    pub fn hash(parts: []const []const u8) Sha256.Digest {
        if (parts.len == 1) record(parts[0]);
        return Sha256.hash(parts);
    }

    pub fn hash_across(parts: []const []const u8, strategy: anytype) Sha256.Digest {
        _ = strategy;
        return hash(parts);
    }

    pub fn hash_pair(
        left: []const []const u8,
        right: []const []const u8,
        strategy: anytype,
    ) [2]Sha256.Digest {
        return Sha256.hash_pair(left, right, strategy);
    }

    pub fn hash_many(
        messages: []const []const u8,
        digests: []Sha256.Digest,
        strategy: anytype,
    ) void {
        assert(call_count < calls.len and messages.len <= calls[0].len);
        for (messages, 0..) |message, i| {
            record(message);
            calls[call_count][i] = Sha256.hash(&.{message});
        }
        call_lens[call_count] = messages.len;
        call_count += 1;
        Sha256.hash_many(messages, digests, strategy);
    }
};

const IRS = coding.ReedSolomon(Instrumented);
const Result = mod.Error!t.Checked;

fn expect_same(expected: Result, actual: Result) !void {
    const want = expected catch |err| return testing.expectError(err, actual);
    const got = try actual;
    try testing.expect(want.eql(&got));
}

test "checked shards are bound to their hasher" {
    comptime {
        coding.assert_scheme(RS);
        coding.assert_scheme(IRS);
        assert(RS.Commitment == IRS.Commitment);
        assert(RS.CheckedShard != IRS.CheckedShard);
    }
}

test "check_many hashes payloads together in input order" {
    const config: Config = .{ .minimum_shards = 4, .extra_shards = 4 };
    var encoding = try RS.encode(gpa, config, "ordered batch checking", seq);
    defer encoding.deinit(gpa);
    const requested = [_]u16{ 3, 0, 6, 2 };
    var refs: [4]IRS.ShardRef = undefined;
    var payloads: [4][]const u8 = undefined;
    for (requested, &refs, &payloads) |index, *ref, *payload| {
        ref.* = .{ .index = index, .shard = &encoding.shards[index] };
        payload.* = encoding.shards[index].shard;
    }
    Instrumented.reset();
    var out: [4]mod.Error!IRS.CheckedShard = undefined;
    try IRS.check_many(gpa, config, &encoding.commitment, &refs, &out, seq);
    try Instrumented.expect_one_call(&payloads);
    for (out, refs) |result, ref| {
        const scalar = try IRS.check(config, &encoding.commitment, ref.index, ref.shard, seq);
        const batched = try result;
        try testing.expectEqual(ref.index, batched.index);
        try testing.expect(scalar.eql(&batched));
    }
}

test "instrumented encode matches the Sha256 commitment and wire" {
    const config: Config = .{ .minimum_shards = 5, .extra_shards = 7 };
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i);
    var expected = try RS.encode(gpa, config, &data, seq);
    defer expected.deinit(gpa);
    Instrumented.reset();
    var actual = try IRS.encode(gpa, config, &data, seq);
    defer actual.deinit(gpa);
    try testing.expect(actual.commitment.eql(expected.commitment));
    for (expected.shards, actual.shards) |a, b| {
        try testing.expect(a.eql(&b));
        const encoded_a = try codec.encode(Chunk, gpa, a);
        defer gpa.free(encoded_a);
        const encoded_b = try codec.encode(Chunk, gpa, b);
        defer gpa.free(encoded_b);
        try testing.expectEqualSlices(u8, encoded_a, encoded_b);
    }
    try testing.expectEqual(@as(usize, 1), Instrumented.call_count);
    try testing.expectEqual(@as(usize, config.total_shards()), Instrumented.call_lens[0]);
}

test "decode reuses checked digests and rehashes the trimmed surplus" {
    const config: Config = .{ .minimum_shards = 3, .extra_shards = 3 };
    var data: [1024]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i * 7);
    var encoding = try IRS.encode(gpa, config, &data, seq);
    defer encoding.deinit(gpa);
    var refs: [6]IRS.ShardRef = undefined;
    for (&refs, 0..) |*ref, i| ref.* = .{ .index = @intCast(i), .shard = &encoding.shards[i] };
    var out: [6]mod.Error!IRS.CheckedShard = undefined;
    try IRS.check_many(gpa, config, &encoding.commitment, &refs, &out, seq);
    var selected: [4]IRS.CheckedShard = undefined;
    for ([_]usize{ 0, 3, 4, 5 }, &selected) |index, *piece| piece.* = try out[index];

    Instrumented.reset();
    const decoded = try IRS.decode(gpa, config, &encoding.commitment, &selected, seq);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, &data, decoded);
    const s = encoding.shards;
    try Instrumented.expect_one_call(&.{ s[1].shard, s[2].shard, s[5].shard });
}

test "check_many rejects metadata before hashing" {
    const config: Config = .{ .minimum_shards = 3, .extra_shards = 3 };
    var data: [192]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i);
    var encoding = try RS.encode(gpa, config, &data, seq);
    defer encoding.deinit(gpa);
    const width = encoding.shards[0].shard.len;
    var bytes: [4][256]u8 = undefined;
    for (&bytes, [_]u8{ 0xa1, 0xb2, 0xc3, 0xd4 }) |*buffer, byte| @memset(buffer, byte);
    var invalid_index = encoding.shards[1];
    invalid_index.index = 5;
    invalid_index.shard = bytes[0][0..width];
    var invalid_leaf_count = encoding.shards[2];
    invalid_leaf_count.proof.leaf_count -= 1;
    invalid_leaf_count.shard = bytes[1][0..width];
    var out_of_range = encoding.shards[3];
    out_of_range.shard = bytes[2][0..width];
    var invalid_proof = encoding.shards[4];
    invalid_proof.shard = bytes[3][0..width];
    const refs = [_]IRS.ShardRef{
        .{ .index = 1, .shard = &invalid_index },
        .{ .index = 0, .shard = &encoding.shards[0] },
        .{ .index = 2, .shard = &invalid_leaf_count },
        .{ .index = 6, .shard = &out_of_range },
        .{ .index = 4, .shard = &invalid_proof },
    };
    var expected: [5]mod.Error!IRS.CheckedShard = undefined;
    for (refs, &expected) |ref, *result| {
        result.* = IRS.check(config, &encoding.commitment, ref.index, ref.shard, seq);
    }
    Instrumented.reset();
    var actual: [5]mod.Error!IRS.CheckedShard = undefined;
    try IRS.check_many(gpa, config, &encoding.commitment, &refs, &actual, seq);
    for (expected, actual) |want, got| try expect_same_instrumented(want, got);
    for ([_]*const Chunk{ &invalid_index, &invalid_leaf_count, &out_of_range }) |rejected| {
        try testing.expect(!Instrumented.hashed(rejected.shard));
    }
    for ([_]*const Chunk{ &encoding.shards[0], &invalid_proof }) |eligible| {
        try testing.expect(Instrumented.hashed(eligible.shard));
    }
}

fn expect_same_instrumented(
    expected: mod.Error!IRS.CheckedShard,
    actual: mod.Error!IRS.CheckedShard,
) !void {
    const want = expected catch |err| return testing.expectError(err, actual);
    const got = try actual;
    try testing.expect(want.eql(&got));
}

test "check_many checks mixed widths one by one" {
    const config: Config = .{ .minimum_shards = 32, .extra_shards = 32 };
    var shards: [64][]const u8 = undefined;
    var buffers: [64][8192]u8 = undefined;
    for (&shards, &buffers, 0..) |*shard, *buffer, i| {
        const width: usize = if (i < 8) 8192 - i * 64 else 2;
        @memset(buffer, @intCast(i));
        shard.* = buffer[0..width];
    }
    var built = try t.build_chunks(&shards);
    defer built.deinit();
    var refs: [64]IRS.ShardRef = undefined;
    for (&refs, built.chunks, 0..) |*ref, *chunk, i| {
        ref.* = .{ .index = @intCast(i), .shard = chunk };
    }
    Instrumented.reset();
    var actual: [64]mod.Error!IRS.CheckedShard = undefined;
    try IRS.check_many(gpa, config, &built.root, &refs, &actual, seq);
    try testing.expectEqual(@as(usize, 0), Instrumented.call_count);
    var checked: [64]IRS.CheckedShard = undefined;
    for (refs, actual, &checked) |ref, result, *piece| {
        const scalar = try IRS.check(config, &built.root, ref.index, ref.shard, seq);
        piece.* = try result;
        try testing.expect(scalar.eql(piece));
    }
    const decoded = IRS.decode(gpa, config, &built.root, &checked, seq);
    try t.expect_error(error.Inconsistent, decoded);
}

test "check_many matches check's errors" {
    const config: Config = .{ .minimum_shards = 3, .extra_shards = 3 };
    var encoding = try RS.encode(gpa, config, "mixed check errors", seq);
    defer encoding.deinit(gpa);
    var invalid_leaf_count = encoding.shards[1];
    invalid_leaf_count.proof.leaf_count -= 1;
    var invalid_chunk_index = encoding.shards[2];
    invalid_chunk_index.index = 4;
    var payload: [64]u8 = undefined;
    const original = encoding.shards[3].shard;
    @memcpy(payload[0..original.len], original);
    payload[0] ^= 0xff;
    var invalid_payload = encoding.shards[3];
    invalid_payload.shard = payload[0..original.len];
    const refs = [_]RS.ShardRef{
        .{ .index = 1, .shard = &invalid_leaf_count },
        .{ .index = 0, .shard = &encoding.shards[0] },
        .{ .index = 6, .shard = &encoding.shards[1] },
        .{ .index = 2, .shard = &invalid_chunk_index },
        .{ .index = 3, .shard = &invalid_payload },
    };
    const invalid_config: Config = .{ .minimum_shards = std.math.maxInt(u16), .extra_shards = 1 };
    for ([_]Config{ config, invalid_config }) |cfg| {
        var batched: [5]Result = undefined;
        try RS.check_many(gpa, cfg, &encoding.commitment, &refs, &batched, seq);
        for (refs, batched) |ref, result| {
            try expect_same(RS.check(cfg, &encoding.commitment, ref.index, ref.shard, seq), result);
        }
    }
    var batched: [5]Result = undefined;
    try RS.check_many(gpa, invalid_config, &encoding.commitment, &refs, &batched, seq);
    for (batched) |result| try testing.expectError(error.TooManyTotalShards, result);
}

test "max_shard_size bounds every encoded chunk" {
    const shapes = [_][2]u16{ .{ 1, 1 }, .{ 2, 1 }, .{ 3, 4 }, .{ 171, 342 }, .{ 342, 682 } };
    const lengths = [_]usize{ 0, 1, 2, 3, 333, 612, 4096, 1 << 20 };
    const data = try t.filled(1 << 20, 0x67);
    defer gpa.free(data);
    for (shapes) |shape| {
        const config: Config = .{ .minimum_shards = shape[0], .extra_shards = shape[1] };
        var previous: usize = 0;
        for (lengths) |len| {
            var encoding = try RS.encode(gpa, config, data[0..len], seq);
            defer encoding.deinit(gpa);
            const first = codec.encode_size(Chunk, encoding.shards[0]);
            for (encoding.shards) |chunk| try testing.expect(
                codec.encode_size(Chunk, chunk) <= first,
            );
            const bound = RS.max_shard_size(config, len);
            const siblings = encoding.shards[0].proof.siblings.len;
            try testing.expectEqual(
                encoding.shards[0].shard.len + 2 + 4 + siblings * 32 + 2 * 5,
                bound,
            );
            try testing.expect(first <= bound and bound >= previous);
            previous = bound;
        }
    }
    // Data up to `u32::MAX` bytes has a bound.
    _ = RS.max_shard_size(.{ .minimum_shards = 2, .extra_shards = 1 }, std.math.maxInt(u32));
}

test "max_shard_size at the backend's shard-count limit" {
    // 49153 shards take a while in Debug.
    if (!build_options.slow_tests) return error.SkipZigTest;
    // With 16385 originals the backend supports at most 32768 recoveries.
    const config: Config = .{ .minimum_shards = 16385, .extra_shards = 32768 };
    var encoding = try RS.encode(gpa, config, "", seq);
    defer encoding.deinit(gpa);
    const bound = RS.max_shard_size(config, 0);
    try testing.expect(codec.encode_size(Chunk, encoding.shards[0]) <= bound);
    try testing.expectEqual(@as(usize, 2 + 2 + 4 + 16 * 32 + 2 * 5), bound);
    const over: Config = .{ .minimum_shards = 16385, .extra_shards = 32769 };
    try testing.expectError(error.UnsupportedShardCount, RS.encode(gpa, over, "", seq));
}

fn decode_chunk(bytes: []const u8, cfg: mod.ShardCfg) codec.Error!Chunk {
    return codec.decode_cfg(Chunk, gpa, bytes, cfg);
}

/// Decodes the encoding of `chunk` under `cfg`, freeing the result; returns whether it decoded.
fn chunk_decodes(chunk: Chunk, cfg: mod.ShardCfg) !bool {
    const encoded = try codec.encode(Chunk, gpa, chunk);
    defer gpa.free(encoded);
    var decoded = decode_chunk(encoded, cfg) catch return false;
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&chunk));
    return true;
}

test "chunk read bounds the shard width by the maximum data" {
    const shapes = [_][2]u16{ .{ 1, 1 }, .{ 2, 2 }, .{ 4, 6 }, .{ 34, 66 } };
    const zeros: [8192]u8 = @splat(0);
    for (shapes) |shape| {
        const config: Config = .{ .minimum_shards = shape[0], .extra_shards = shape[1] };
        const min: usize = shape[0];
        for ([_]usize{ 0, 1, 2 * min, 1000, 4099 }) |data_len| {
            const cfg: mod.ShardCfg = .{ .config = config, .maximum_data_bytes = data_len };
            var exact = try RS.encode(gpa, config, zeros[0..data_len], seq);
            defer exact.deinit(gpa);
            try testing.expect(try chunk_decodes(exact.shards[0], cfg));
            // Enough extra data to widen the chunk is rejected.
            const width = exact.shards[0].shard.len;
            var wider = data_len;
            while (mod.canonical_shard_len(wider, min) <= width) wider += 1;
            var wide = try RS.encode(gpa, config, zeros[0..wider], seq);
            defer wide.deinit(gpa);
            try testing.expect(!try chunk_decodes(wide.shards[0], cfg));
        }
        // A maximum beyond what encoding accepts decodes without overflow.
        var small = try RS.encode(gpa, config, zeros[0..8], seq);
        defer small.deinit(gpa);
        const unbounded: mod.ShardCfg = .{
            .config = config,
            .maximum_data_bytes = std.math.maxInt(usize),
        };
        try testing.expect(try chunk_decodes(small.shards[0], unbounded));
    }
}

test "check rejects zero and odd shard widths" {
    const config: Config = .{ .minimum_shards = 4, .extra_shards = 8 };
    const zeros: [2 * t.min_stripe + 1]u8 = @splat(0);
    for ([_]usize{ 0, 3, 2 * t.min_stripe + 1 }) |width| {
        var shards: [12][]const u8 = @splat(zeros[0..width]);
        var built = try t.build_chunks(&shards);
        defer built.deinit();
        var refs: [12]RS.ShardRef = undefined;
        for (built.chunks, &refs) |*chunk, *ref| {
            ref.* = .{ .index = chunk.index, .shard = chunk };
            const result = RS.check(config, &built.root, chunk.index, chunk, seq);
            try testing.expectError(error.InvalidShardSize, result);
        }
        var batched: [12]Result = undefined;
        try RS.check_many(gpa, config, &built.root, &refs, &batched, seq);
        for (batched) |result| try testing.expectError(error.InvalidShardSize, result);
    }
}

test "shard counts beyond u16 or the backend are rejected" {
    const data = try t.filled(1000, 42);
    defer gpa.free(data);
    const max = std.math.maxInt(u16);
    const too_many: Config = .{ .minimum_shards = max / 2 + 1, .extra_shards = max };
    try testing.expectError(error.TooManyTotalShards, RS.encode(gpa, too_many, "", seq));
    try testing.expectError(error.UnsupportedShardCount, t.encode(max, max / 2 - 1, data, seq));

    // Decoding rejects unsupported counts before looking at any chunk.
    var encoding = try t.encode(10, 4, data, seq);
    defer encoding.deinit(gpa);
    const pieces = try t.pieces_of(encoding.commitment, encoding.shards, &t.first(10));
    defer gpa.free(pieces);
    const result = t.decode(max, max / 2 - 1, &encoding.commitment, pieces, seq);
    try t.expect_error(error.UnsupportedShardCount, result);
}

test "the most shards the backend supports" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const data = try t.filled(1000, 42);
    defer gpa.free(data);
    const total = std.math.maxInt(u16);
    var encoding = try t.encode(total, total / 2, data, seq);
    defer encoding.deinit(gpa);
    const indices = try gpa.alloc(usize, total / 2);
    defer gpa.free(indices);
    for (indices, 0..) |*index, i| index.* = i;
    try t.expect_roundtrip(total, total / 2, &encoding, indices, data, seq);
}

// lib.rs scheme tests.

const max_shards: u16 = 32;
const max_data: usize = 1024;

/// Encodes, round-trips every shard through the codec, checks the `selected` shards, and
/// decodes them in reverse order.
fn roundtrip(config: Config, data: []const u8, selected: []const u16) !void {
    var encoding = try RS.encode(gpa, config, data, seq);
    defer encoding.deinit(gpa);
    const cfg: mod.ShardCfg = .{ .config = config, .maximum_data_bytes = @max(data.len, max_data) };
    for (encoding.shards) |shard| try testing.expect(try chunk_decodes(shard, cfg));
    const pieces = try gpa.alloc(RS.CheckedShard, selected.len);
    defer gpa.free(pieces);
    var count: usize = 0;
    for (encoding.shards, 0..) |*shard, i| {
        if (std.mem.indexOfScalar(u16, selected, @intCast(i)) == null) continue;
        pieces[count] = try RS.check(config, &encoding.commitment, @intCast(i), shard, seq);
        count += 1;
    }
    std.mem.reverse(RS.CheckedShard, pieces[0..count]);
    const decoded = try RS.decode(gpa, config, &encoding.commitment, pieces[0..count], seq);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, data, decoded);
}

test "decode rejects shards of mixed commitments and empty shard sets" {
    const config: Config = .{ .minimum_shards = 2, .extra_shards = 1 };
    var a = try RS.encode(gpa, config, "alpha payload", seq);
    defer a.deinit(gpa);
    var b = try RS.encode(gpa, config, "bravo payload", seq);
    defer b.deinit(gpa);
    const pieces = [_]RS.CheckedShard{
        try RS.check(config, &a.commitment, 0, &a.shards[0], seq),
        try RS.check(config, &b.commitment, 1, &b.shards[1], seq),
    };
    try t.expect_error(
        error.CommitmentMismatch,
        RS.decode(gpa, config, &a.commitment, &pieces, seq),
    );
    try t.expect_error(error.NotEnoughChunks, RS.decode(gpa, config, &a.commitment, &.{}, seq));
}

test "roundtrip empty data and 2^16 bytes over 25 shards" {
    var first_30: [30]u16 = undefined;
    for (&first_30, 0..) |*index, i| index.* = @intCast(i);
    try roundtrip(.{ .minimum_shards = 30, .extra_shards = 70 }, "", &first_30);
    const data = try t.filled(1 << 16, 0x67);
    defer gpa.free(data);
    try roundtrip(.{ .minimum_shards = 8, .extra_shards = 17 }, data, first_30[0..8]);
}

/// lib.rs `generate_case`: a config, data, and a shuffled selection of at least `minimum`.
fn roundtrip_body(_: void, u: *minifuzz.Unstructured) !void {
    const minimum = (try u.arbitrary(u16)) % max_shards + 1;
    const extra = 1 + (try u.arbitrary(u16)) % max_shards;
    const total = minimum + extra;
    const data = try u.bytes(@as(usize, try u.arbitrary(u16)) % (max_data + 1));
    const selected_len = @as(usize, minimum) + (try u.arbitrary(u16)) % (@as(usize, extra) + 1);
    var selected: [2 * max_shards]u16 = undefined;
    for (selected[0..total], 0..) |*index, i| index.* = @intCast(i);
    for (0..selected_len) |i| {
        const j = i + (try u.arbitrary(u16)) % (total - i);
        std.mem.swap(u16, &selected[i], &selected[j]);
    }
    try roundtrip(
        .{ .minimum_shards = minimum, .extra_shards = extra },
        data,
        selected[0..selected_len],
    );
}

test "minifuzz roundtrip reed solomon" {
    try minifuzz.run(gpa, {}, roundtrip_body);
}

// `CodecConformance<Chunk<Sha256Digest>>`.

const arbitrary = codec.arbitrary;

fn gen_digest(allocator: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!Digest {
    const len = u.int_in_range(u64, 0, 256);
    const data = try allocator.alloc(u8, len);
    try u.bytes(data);
    return Sha256.hash(&.{data});
}

/// The derived `Chunk::arbitrary`: shard bytes, index, then the proof's leaf count and siblings.
fn gen_chunk(allocator: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!Chunk {
    const shard = try arbitrary.collect(u8, allocator, u);
    const index = u.int(u16);
    const leaf_count = u.int(u32);
    var siblings: std.ArrayList(Digest) = .empty;
    while (u.keep_going()) try siblings.append(allocator, try gen_digest(allocator, u));
    return .{
        .shard = shard,
        .index = index,
        .proof = .{ .leaf_count = leaf_count, .siblings = siblings.items },
    };
}

const ChunkConformance = struct {
    pub fn commit(allocator: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const chunk = try arbitrary.generate(Chunk, gen_chunk, arena.allocator(), seed);
        return codec.encode(Chunk, allocator, chunk);
    }
};

test "conformance CodecConformance<Chunk<Sha256Digest>>" {
    try conformance.verify(
        ChunkConformance,
        std.heap.smp_allocator,
        "commonware_coding::reed_solomon::tests::conformance::" ++
            "CodecConformance<Chunk<Sha256Digest>>",
        conformance.default_cases,
        @embedFile("../conformance.toml"),
    );
}
