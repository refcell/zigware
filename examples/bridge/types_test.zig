//! Bridge wire types against commonware: `testdata/types_vectors.txt` holds the encodings
//! commonware's own codec tests build (round 333/12345, parent 54321, payload `[123; 32]`,
//! and the generators times `Scalar::random(test_rng())`), printed by commonware's types.
//! Plus the invalid-tag case and a seeded fuzz of the decoders on mutated vectors.

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const lib = @import("lib.zig");
const types = @import("types.zig");

const codec = zigware.codec;
const consensus = zigware.consensus;
const group = zigware.cryptography.bls12381.primitives.group;

const vectors = @embedFile("testdata/types_vectors.txt");

/// The hex encoding commonware printed under `name`.
fn expected_hex(name: []const u8) []const u8 {
    var lines = std.mem.tokenizeScalar(u8, vectors, '\n');
    while (lines.next()) |line| {
        const space = std.mem.indexOfScalar(u8, line, ' ').?;
        if (std.mem.eql(u8, line[0..space], name)) return line[space + 1 ..];
    }
    std.debug.panic("no vector named {s}", .{name});
}

fn test_scalar() group.Scalar {
    var rng = zigware.utils.rng.test_rng();
    return group.Scalar.random(&rng);
}

fn new_public() types.Public {
    return types.Public.generator.mul(test_scalar());
}

fn new_finalization() types.Finalization {
    const signature = lib.Variant.Signature.generator.mul(test_scalar());
    const round = consensus.types.Round.new(.new(333), .new(12345));
    return .{
        .proposal = .init(round, .new(54321), lib.Digest.fill(123)),
        .certificate = .init(signature),
    };
}

const new_block: types.BlockFormat = .{ .random = 12345678901234567890 };

/// Encodes `value`, checks it against commonware's vector `name`, and decodes it back.
fn expect_vector(comptime T: type, value: T, name: []const u8) !void {
    const gpa = testing.allocator;
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqual(encoded.len, codec.encode_size(T, value));
    const hex = try std.fmt.allocPrint(gpa, "{x}", .{encoded});
    defer gpa.free(hex);
    try testing.expectEqualStrings(expected_hex(name), hex);
    const decoded = try codec.decode(T, gpa, encoded);
    const again = try codec.encode(T, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, encoded, again);
}

/// An unknown tag fails as `InvalidEnum`, as in commonware.
fn expect_invalid_tag(comptime T: type, tag: u8) !void {
    try testing.expectError(error.InvalidEnum, codec.decode(T, testing.allocator, &.{tag}));
}

test "bridge: the test scalar is commonware's Scalar::random(test_rng())" {
    var bytes: [group.Scalar.fixed_size]u8 = undefined;
    const encoded = codec.encode_to(group.Scalar, test_scalar(), &bytes);
    var hex: [2 * bytes.len]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{x}", .{encoded});
    try testing.expectEqualStrings(expected_hex("scalar"), &hex);
}

test "bridge: block codec matches commonware" {
    try expect_vector(types.BlockFormat, new_block, "block_random");
    try expect_vector(types.BlockFormat, .{ .bridge = new_finalization() }, "block_bridge");
    try expect_invalid_tag(types.BlockFormat, 2);
}

test "bridge: inbound codec matches commonware" {
    const network = new_public();
    const put_block: types.Inbound = .{ .put_block = .{ .network = network, .block = new_block } };
    try expect_vector(types.Inbound, put_block, "inbound_put_block");
    const get_block: types.Inbound = .{
        .get_block = .{ .network = network, .digest = lib.Digest.fill(123) },
    };
    try expect_vector(types.Inbound, get_block, "inbound_get_block");
    const put_finalization: types.Inbound = .{
        .put_finalization = .{ .network = network, .finalization = new_finalization() },
    };
    try expect_vector(types.Inbound, put_finalization, "inbound_put_finalization");
    const get_finalization: types.Inbound = .{ .get_finalization = .{ .network = network } };
    try expect_vector(types.Inbound, get_finalization, "inbound_get_finalization");
    try expect_invalid_tag(types.Inbound, 4);
}

test "bridge: outbound codec matches commonware" {
    try expect_vector(types.Outbound, .{ .success = true }, "outbound_success_true");
    try expect_vector(types.Outbound, .{ .success = false }, "outbound_success_false");
    try expect_vector(types.Outbound, .{ .block = new_block }, "outbound_block");
    const finalization: types.Outbound = .{ .finalization = new_finalization() };
    try expect_vector(types.Outbound, finalization, "outbound_finalization");
    try expect_invalid_tag(types.Outbound, 3);
}

const fuzz_names = [_][]const u8{
    "block_random",          "block_bridge",             "inbound_put_block",
    "inbound_get_block",     "inbound_put_finalization", "inbound_get_finalization",
    "outbound_success_true", "outbound_block",           "outbound_finalization",
};

/// Decodes `bytes` as `T`; a value that decodes must encode back to exactly `bytes`.
fn expect_canonical(comptime T: type, bytes: []const u8) !void {
    const gpa = testing.allocator;
    const value = codec.decode(T, gpa, bytes) catch return;
    const again = try codec.encode(T, gpa, value);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, bytes, again);
}

/// Mutates a commonware vector (a few byte changes, then maybe a truncation), so decoding
/// reaches past the tag and the point checks, and checks every decoder stays canonical.
fn fuzz_body(_: void, smith: *testing.Smith) anyerror!void {
    const draws: codec.fuzz.Draws = .init(smith);
    const hex = expected_hex(fuzz_names[draws.index(fuzz_names.len)]);
    var buffer: [512]u8 = undefined;
    const vector = try std.fmt.hexToBytes(&buffer, hex);
    const mutations = draws.range_at_most(u8, 0, 4);
    for (0..mutations) |_| {
        vector[draws.index(vector.len)] ^= draws.range_at_most(u8, 1, 255);
    }
    const length = if (draws.value(bool)) draws.range_at_most(usize, 0, vector.len) else vector.len;
    try expect_canonical(types.BlockFormat, vector[0..length]);
    try expect_canonical(types.Inbound, vector[0..length]);
    try expect_canonical(types.Outbound, vector[0..length]);
}

test "bridge: fuzz decoders" {
    try codec.fuzz.run({}, fuzz_body, 0xb81d6e, 2000);
}
