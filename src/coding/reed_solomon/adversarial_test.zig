//! Malicious-encoder tests of the Reed-Solomon scheme: tampered codewords committed with a
//! valid tree must never decode, on the single-stripe and the striped paths alike.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const minifuzz = @import("invariants").minifuzz;
const mod = @import("mod.zig");
const t = @import("tests.zig");

const rs = cryptography.reed_solomon;
const Sha256 = t.Sha256;
const Digest = t.Digest;
const gpa = t.gpa;
const seq = t.seq;
const min_stripe = t.min_stripe;

const Tamper = *const fn (shards: [][]u8, k: usize, shard_len: usize) void;

fn tamper_flip_recovery(shards: [][]u8, k: usize, _: usize) void {
    shards[k][0] ^= 0xff;
}

fn tamper_flip_original_data(shards: [][]u8, _: usize, shard_len: usize) void {
    // The first payload byte follows the 4-byte length prefix.
    shards[4 / shard_len][4 % shard_len] ^= 0xff;
}

fn tamper_corrupt_padding(shards: [][]u8, k: usize, shard_len: usize) void {
    // The last byte of the last original is zero padding for the payloads used here.
    shards[k - 1][shard_len - 1] = 0xaa;
}

fn tamper_flip_shard_six(shards: [][]u8, _: usize, _: usize) void {
    shards[6][0] ^= 0xff;
}

/// Encodes `data` canonically, tampers with the codeword, commits to the tampered shards, and
/// decodes the `selected` ones.
fn decode_tampered(
    total: u16,
    min: u16,
    data: []const u8,
    selected: []const usize,
    tamper: Tamper,
    strategy: anytype,
) ![]u8 {
    var encoding = try t.encode(total, min, data, seq);
    defer encoding.deinit(gpa);
    var codeword = try t.Codeword.of(&encoding);
    defer codeword.deinit();
    tamper(codeword.shards, min, codeword.shards[0].len);
    var built = try codeword.build();
    defer built.deinit();
    const pieces = try built.pieces(selected);
    defer gpa.free(pieces);
    return t.decode(total, min, &built.root, pieces, strategy);
}

const Scenario = struct { selected: []const usize, tamper: Tamper };

/// With 12 shards and 4 originals, indices 0..4 are originals and 4..12 recoveries.
const scenarios = [_]Scenario{
    // An unprovided tampered recovery: caught when the root is rebuilt from the re-encoding.
    .{ .selected = &.{ 0, 1, 2, 3 }, .tamper = tamper_flip_recovery },
    // A provided tampered recovery that forces reconstruction of a missing original.
    .{ .selected = &.{ 0, 1, 2, 4 }, .tamper = tamper_flip_recovery },
    // Non-zero padding in an original shard.
    .{ .selected = &.{ 0, 1, 2, 3 }, .tamper = tamper_corrupt_padding },
    // A tampered payload byte, caught by the rebuilt commitment.
    .{ .selected = &.{ 0, 1, 2, 3 }, .tamper = tamper_flip_original_data },
    // A recovery-only decode with one provided recovery tampered.
    .{ .selected = &.{ 4, 5, 6, 7 }, .tamper = tamper_flip_recovery },
};

fn expect_adversarial_rejected(data: []const u8, strategy: anytype) !void {
    for (scenarios) |scenario| {
        const result = decode_tampered(12, 4, data, scenario.selected, scenario.tamper, strategy);
        try t.expect_error(error.Inconsistent, result);
    }
}

test "adversarial codewords are rejected on the single-stripe path" {
    const data: [30]u8 = @splat(0xcd);
    try expect_adversarial_rejected(&data, seq);
}

test "adversarial codewords are rejected on the striped path" {
    const pool = try t.create_pool();
    defer pool.destroy();
    const data = try t.filled(64 * 1024, 0xab);
    defer gpa.free(data);
    try testing.expect(mod.canonical_shard_len(data.len, 4) >= 2 * min_stripe);
    try expect_adversarial_rejected(data, seq);
    try expect_adversarial_rejected(data, t.rayon(pool));

    // An untampered mixed set still decodes, reconstructing a missing original.
    var encoding = try t.encode(12, 4, data, seq);
    defer encoding.deinit(gpa);
    try t.expect_roundtrip(12, 4, &encoding, &.{ 0, 1, 2, 4 }, data, t.rayon(pool));
}

test "striped decode rejects a tampered surplus recovery" {
    // Originals 2 and 3 are missing; the decoder takes 0, 1, 4, 5, and recovery 6 is the
    // trimmed surplus, rebuilt from the reconstruction and bound by the root check.
    const pool = try t.create_pool();
    defer pool.destroy();
    const data = try t.filled(64 * 1024, 0xab);
    defer gpa.free(data);
    const selected = [_]usize{ 0, 1, 4, 5, 6 };
    for (0..2) |shape| {
        const result = if (shape == 0)
            decode_tampered(12, 4, data, &selected, tamper_flip_shard_six, seq)
        else
            decode_tampered(12, 4, data, &selected, tamper_flip_shard_six, t.rayon(pool));
        try t.expect_error(error.Inconsistent, result);
    }
}

test "provided recoveries beyond k are bound to the commitment" {
    const cases = [_]struct { data: []const u8, flipped: usize, selected: []const usize }{
        // Every original present plus a non-canonical recovery.
        .{
            .data = "canonical originals with bad recovery",
            .flipped = 3,
            .selected = &.{ 0, 1, 2, 3 },
        },
        // A reconstructed original plus a non-canonical surplus recovery.
        .{
            .data = "canonical reconstructed originals with bad extra recovery",
            .flipped = 4,
            .selected = &.{ 0, 1, 3, 4 },
        },
    };
    for (cases) |case| {
        var encoding = try t.encode(6, 3, case.data, seq);
        defer encoding.deinit(gpa);
        var codeword = try t.Codeword.of(&encoding);
        defer codeword.deinit();
        codeword.shards[case.flipped][0] ^= 0xff;
        var built = try codeword.build();
        defer built.deinit();
        const pieces = try built.pieces(case.selected);
        defer gpa.free(pieces);
        try t.expect_error(error.Inconsistent, t.decode(6, 3, &built.root, pieces, seq));
    }
}

test "malicious root: check fails and decode rejects shards of another commitment" {
    const data = "Original data that should be protected";
    var encoding = try t.encode(7, 4, data, seq);
    defer encoding.deinit(gpa);
    const malicious = Sha256.hash(&.{"malicious_data_that_wasnt_actually_encoded"});
    const config = t.config_of(7, 4);
    for (encoding.shards, 0..) |*shard, i| {
        const result = t.RS.check(config, &malicious, @intCast(i), shard, seq);
        try testing.expectError(error.InvalidProof, result);
    }
    const pieces = try t.pieces_of(encoding.commitment, encoding.shards, &t.first(4));
    defer gpa.free(pieces);
    try t.expect_error(error.CommitmentMismatch, t.decode(7, 4, &malicious, pieces, seq));
}

test "check rejects a proof made under another config" {
    var encoding = try t.RS.encode(gpa, t.config_of(6, 3), "leaf_count mismatch proof", seq);
    defer encoding.deinit(gpa);
    const result = t.RS.check(t.config_of(4, 2), &encoding.commitment, 0, &encoding.shards[0], seq);
    try testing.expectError(error.InvalidProof, result);
}

test "a manipulated checked shard is rejected" {
    var encoding = try t.encode(6, 3, "Data integrity must be maintained", seq);
    defer encoding.deinit(gpa);
    const pieces = try t.pieces_of(encoding.commitment, encoding.shards, &t.first(6));
    defer gpa.free(pieces);
    const tampered = try gpa.dupe(u8, pieces[1].shard);
    defer gpa.free(tampered);
    tampered[0] ^= 0xff;
    pieces[1].shard = tampered;
    try t.expect_error(error.Inconsistent, t.decode(6, 3, &encoding.commitment, pieces, seq));
}

/// Encodes `padded` (the `k` originals, `width` bytes each) with `m` recoveries.
fn codeword_of(padded: []const u8, k: usize, m: usize) !t.Codeword {
    const width = padded.len / k;
    var encoder = try rs.Encoder.init(gpa, k, m, width);
    defer encoder.deinit(gpa);
    const shards = try gpa.alloc([]const u8, k + m);
    defer gpa.free(shards);
    for (shards[0..k], 0..) |*shard, i| {
        shard.* = padded[i * width ..][0..width];
        try encoder.add_original_shard(shard.*);
    }
    var result = try encoder.encode();
    defer result.deinit();
    for (shards[k..], 0..) |*shard, i| shard.* = result.recovery(i).?;
    return t.Codeword.init(shards);
}

/// The layout encode produces for `data`, with `k` shards of `width` bytes.
fn padded_of(data: []const u8, k: usize, width: usize) ![]u8 {
    const padded = try gpa.alloc(u8, k * width);
    @memset(padded, 0);
    std.mem.writeInt(u32, padded[0..4], @intCast(data.len), .big);
    @memcpy(padded[4..][0..data.len], data);
    return padded;
}

test "inconsistent shards: a tampered recovery under a malicious tree" {
    const data = "Test data for malicious encoding";
    const width = mod.canonical_shard_len(data.len, 3);
    const padded = try padded_of(data, 3, width);
    defer gpa.free(padded);
    var codeword = try codeword_of(padded, 3, 2);
    defer codeword.deinit();
    codeword.shards[3][0] ^= 0xff;
    var built = try codeword.build();
    defer built.deinit();
    const pieces = try built.pieces(&.{ 0, 1, 3 });
    defer gpa.free(pieces);
    try t.expect_error(error.Inconsistent, t.decode(5, 3, &built.root, pieces, seq));
}

test "non-canonical padding and oversized widths are rejected" {
    const data = "X";
    // Non-zero padding after the payload.
    const width = mod.canonical_shard_len(data.len, 3);
    const padded = try padded_of(data, 3, width);
    defer gpa.free(padded);
    padded[4 + data.len] = 0xaa;
    var bad_padding = try codeword_of(padded, 3, 3);
    defer bad_padding.deinit();
    var built = try bad_padding.build();
    defer built.deinit();
    const originals = try built.pieces(&t.first(3));
    defer gpa.free(originals);
    try t.expect_error(error.Inconsistent, t.decode(6, 3, &built.root, originals, seq));

    // Zero padding beyond the canonical width.
    const wide = try padded_of(data, 3, 4);
    defer gpa.free(wide);
    var oversized = try codeword_of(wide, 3, 3);
    defer oversized.deinit();
    var oversized_built = try oversized.build();
    defer oversized_built.deinit();
    var canonical = try t.encode(6, 3, data, seq);
    defer canonical.deinit(gpa);
    try testing.expect(!oversized_built.root.eql(canonical.commitment));
    const mixed = try oversized_built.pieces(&.{ 0, 1, 4 });
    defer gpa.free(mixed);
    try t.expect_error(error.Inconsistent, t.decode(6, 3, &oversized_built.root, mixed, seq));
}

test "parallel decode rejects mismatched shard widths" {
    const pool = try t.create_pool();
    defer pool.destroy();
    const data = try t.filled(256 * 1024, 42);
    defer gpa.free(data);
    var encoding = try t.encode(24, 8, data, t.rayon(pool));
    defer encoding.deinit(gpa);
    var codeword = try t.Codeword.of(&encoding);
    defer codeword.deinit();
    codeword.shards[8] = codeword.shards[8][0 .. codeword.shards[8].len - 1];
    var built = try codeword.build();
    defer built.deinit();
    const pieces = try built.pieces(&.{ 9, 8, 10, 11, 12, 13, 14, 15 });
    defer gpa.free(pieces);
    try t.expect_error(error.Inconsistent, t.decode(24, 8, &built.root, pieces, t.rayon(pool)));
}

const Scene = enum { length_too_large, length_max, padding, width, root };

/// Commits to a recoverable but non-canonical codeword (wrong length prefix, padding, or
/// width), or one whose unprovided original leaf differs from its reconstruction; decoding
/// from recoveries reconstructs it and must reject it.
fn expect_scene_rejected(pool: anytype, scene: Scene) !void {
    const k = 4;
    const width = 2 * min_stripe + 2;
    const data = try t.filled(k * width - 5, 0x5a);
    defer gpa.free(data);
    try testing.expectEqual(width, mod.canonical_shard_len(data.len, k));
    var padded = try padded_of(data, k, width);
    defer gpa.free(padded);
    switch (scene) {
        .length_too_large => std.mem.writeInt(u32, padded[0..4], @intCast(padded.len - 3), .big),
        .length_max => std.mem.writeInt(u32, padded[0..4], std.math.maxInt(u32), .big),
        .padding => padded[padded.len - 1] = 1,
        .width => {
            padded = try gpa.realloc(padded, padded.len + 2 * k);
            @memset(padded[padded.len - 2 * k ..], 0);
        },
        .root => {},
    }
    var codeword = try codeword_of(padded, k, 8);
    defer codeword.deinit();
    if (scene == .root) codeword.shards[0][4] ^= 1;
    var built = try codeword.build();
    defer built.deinit();
    const pieces = try built.pieces(&.{ 4, 5, 6, 7 });
    defer gpa.free(pieces);
    try t.expect_error(error.Inconsistent, t.decode(12, 4, &built.root, pieces, seq));
    try t.expect_error(error.Inconsistent, t.decode(12, 4, &built.root, pieces, t.rayon(pool)));
}

test "owned output rejects authenticated non-canonical codewords" {
    const pool = try t.create_pool();
    defer pool.destroy();
    for (std.enums.values(Scene)) |scene| try expect_scene_rejected(pool, scene);
}

test "owned output recovery and mixed roundtrip" {
    const pool = try t.create_pool();
    defer pool.destroy();
    for ([_]usize{ 2 * min_stripe, 2 * min_stripe + 2, 3 * min_stripe + 62 }) |width| {
        const data = try gpa.alloc(u8, 4 * width - 5);
        defer gpa.free(data);
        for (data, 0..) |*byte, i| byte.* = @truncate(i ^ (i >> 8));
        var encoding = try t.encode(12, 4, data, seq);
        defer encoding.deinit(gpa);
        try testing.expectEqual(width, encoding.shards[0].shard.len);
        for ([_][4]usize{ .{ 4, 5, 6, 7 }, .{ 0, 4, 5, 6 } }) |selected| {
            try t.expect_roundtrip(12, 4, &encoding, &selected, data, seq);
            try t.expect_roundtrip(12, 4, &encoding, &selected, data, t.rayon(pool));
        }
    }
}

const fuzz_max_min_shards = 8;
const fuzz_max_extra_shards = 8;
const fuzz_max_data_len = 256;
const fuzz_max_extra_width = 16;

/// `to_use` distinct indices of `0..total`, at least `minimum`, from a partial shuffle.
fn selected_indices(u: *minifuzz.Unstructured, total: u16, minimum: u16, out: []usize) ![]usize {
    const to_use = u.int_in_range(u16, minimum, total);
    for (out[0..total], 0..) |*index, i| index.* = i;
    for (0..to_use) |i| {
        const j = i + try u.choose_index(total - i);
        std.mem.swap(usize, &out[i], &out[j]);
    }
    return out[0..to_use];
}

/// If the `selected` shards decode, the commitment must be the canonical encoding's.
fn expect_unique_commitment(
    total: u16,
    min: u16,
    built: *const t.Built,
    selected: []const usize,
) !void {
    const config = t.config_of(total, min);
    const pieces = try gpa.alloc(t.Checked, selected.len);
    defer gpa.free(pieces);
    for (selected, pieces) |index, *piece| {
        piece.* = try t.RS.check(config, &built.root, @intCast(index), &built.chunks[index], seq);
    }
    const decoded = t.decode(total, min, &built.root, pieces, seq) catch return;
    defer gpa.free(decoded);
    var canonical = try t.encode(total, min, decoded, seq);
    defer canonical.deinit(gpa);
    try testing.expect(canonical.commitment.eql(built.root));
}

/// A codeword of any (even) width whose padding may be corrupted.
fn fuzz_arbitrary_codeword(u: *minifuzz.Unstructured) !void {
    const min = u.int_in_range(u16, 1, fuzz_max_min_shards);
    const extra = u.int_in_range(u16, 1, fuzz_max_extra_shards);
    const k: usize = min;
    const data = try u.bytes(u.int_in_range(usize, 0, fuzz_max_data_len));
    const extra_width = u.int_in_range(usize, 0, fuzz_max_extra_width / 2) * 2;
    const width = mod.canonical_shard_len(data.len, k) + extra_width;
    const padded = try padded_of(data, k, width);
    defer gpa.free(padded);
    const payload_end = 4 + data.len;
    if (payload_end < padded.len and u.int_in_range(u8, 0, 3) == 0) {
        const offset = payload_end + try u.choose_index(padded.len - payload_end);
        padded[offset] ^= (try u.arbitrary(u8)) | 1;
    }
    var codeword = try codeword_of(padded, k, extra);
    defer codeword.deinit();
    var built = try codeword.build();
    defer built.deinit();
    var buffer: [fuzz_max_min_shards + fuzz_max_extra_shards]usize = undefined;
    const selected = try selected_indices(u, min + extra, min, &buffer);
    try expect_unique_commitment(min + extra, min, &built, selected);
}

/// A canonical codeword with one recovery shard mutated, decoded with every original.
fn fuzz_mixed_codeword(u: *minifuzz.Unstructured) !void {
    const min = u.int_in_range(u16, 1, fuzz_max_min_shards);
    const extra = u.int_in_range(u16, 1, fuzz_max_extra_shards);
    const data = try u.bytes(u.int_in_range(usize, 0, fuzz_max_data_len));
    var encoding = try t.encode(min + extra, min, data, seq);
    defer encoding.deinit(gpa);
    var codeword = try t.Codeword.of(&encoding);
    defer codeword.deinit();
    const mutated = @as(usize, min) + u.int_in_range(u16, 0, extra - 1);
    const offset = try u.choose_index(codeword.shards[mutated].len);
    codeword.shards[mutated][offset] ^= (try u.arbitrary(u8)) | 1;
    var built = try codeword.build();
    defer built.deinit();
    var selected: [fuzz_max_min_shards + 1]usize = undefined;
    for (selected[0..min], 0..) |*index, i| index.* = i;
    selected[min] = mutated;
    try expect_unique_commitment(min + extra, min, &built, selected[0 .. min + 1]);
}

fn unique_commitment_body(_: void, u: *minifuzz.Unstructured) !void {
    try fuzz_arbitrary_codeword(u);
    try fuzz_mixed_codeword(u);
}

test "minifuzz decode unique commitment" {
    const builder = (minifuzz.Builder{}).with_seed(0).with_search_limit(2048);
    try builder.run(gpa, {}, unique_commitment_body);
}
