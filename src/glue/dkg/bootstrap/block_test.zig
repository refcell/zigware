//! Tests of commonware's `glue::dkg::bootstrap` (`mod tests`): the one-shot block's size
//! bound against the widest block, and `max_payload_size` against its components.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const math = @import("math");
const utils = @import("utils");
const network = @import("../network.zig");
const dkg_limits = @import("../limits.zig");
const mocks = @import("../tests/mocks.zig");
const block_api = @import("block.zig");
const limits = @import("limits.zig");

const Epoch = consensus.Epoch;
const Height = consensus.Height;
const View = consensus.View;
const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const Sha256 = cryptography.Sha256;
const ed25519 = cryptography.ed25519;
const P = ed25519.PublicKey;
const MinSig = cryptography.bls12381.primitives.MinSig;
const Sharing = cryptography.bls12381.primitives.sharing.Sharing;
const Transcript = cryptography.transcript.Transcript;
const Addresses = network.Addresses(P);
const Output = cryptography.bls12381.dkg.feldman_desmedt.Output(MinSig, P);
const KeyOnly = block_api.Block(MinSig, Unit);
const Addressed = block_api.Block(MinSig, Addresses);

/// Namespace for the transcripts these tests summarize.
const namespace = "_COMMONWARE_GLUE_DKG_BOOTSTRAP";

/// Participant counts the tests cover; 128 is slow in Debug (128 G2 commitments).
fn counts() []const u32 {
    const slow = builtin.mode == .debug and !build_options.slow_tests;
    return if (slow) &.{ 1, 4 } else &.{ 1, 4, 128 };
}

/// `count` sorted participants.
fn participants(gpa: Allocator, count: u32) !Set(P) {
    const keys = try gpa.alloc(P, count);
    defer gpa.free(keys);
    for (keys, 0..) |*item, seed| item.* = ed25519.PrivateKey.from_seed(seed).public_key();
    return Set(P).from_dedup(gpa, keys);
}

/// The widest output over `players` (dealers, players, and revealed all name them): a
/// sharing committed to a polynomial with one coefficient per player.
fn widest_output(gpa: Allocator, players: Set(P)) !Output {
    const count: u32 = @intCast(players.len());
    var rng = utils.rng.TestRng.init(0);
    const Scalars = math.poly.Poly(cryptography.bls12381.primitives.group.Scalar);
    var scalars = try Scalars.random(gpa, &rng, count - 1);
    defer scalars.deinit(gpa);
    const committed = try math.poly.commit(gpa, MinSig.Public, scalars);
    var public = try Sharing(MinSig).init(gpa, .non_zero_counter, count, committed);
    errdefer public.deinit(gpa);
    const transcript = Transcript.init(namespace, .v1);
    var dealers = try players.clone(gpa);
    errdefer dealers.deinit(gpa);
    var owned_players = try players.clone(gpa);
    errdefer owned_players.deinit(gpa);
    return .{
        .summary = transcript.summarize(),
        .public = public,
        .dealers = dealers,
        .players = owned_players,
        .revealed = try players.clone(gpa),
    };
}

/// The widest block whose artifact names `sets[0]` in its output, `sets[1]` as players, and
/// `sets[2]` as next players, with `directory` (taken). Epochs, views, and height use their
/// widest encodings.
fn widest_block(
    comptime B: type,
    gpa: Allocator,
    sets: [3]Set(P),
    directory: B.Directory,
) !B {
    var owned_directory = directory;
    errdefer network.DirectoryOps(P, B.Directory).deinit(&owned_directory, gpa);
    var output = try widest_output(gpa, sets[0]);
    errdefer output.deinit(gpa);
    var players = try sets[1].clone(gpa);
    errdefer players.deinit(gpa);
    const next_players = try sets[2].clone(gpa);
    const max = std.math.maxInt(u64);
    const parent = Sha256.hash(&.{"parent"});
    const context: B.Context = .{
        .round = .new(.new(max), .new(max)),
        .leader = ed25519.PrivateKey.from_seed(0).public_key(),
        .parent = .{ .new(max), parent },
    };
    const payload: B.Payload = .{ .epoch_info = .{
        .outcome = .success,
        .epoch = .new(max),
        .output = output,
        .players = players,
        .next_players = next_players,
        .directory = owned_directory,
    } };
    return B.init(gpa, context, parent, .new(max), payload);
}

/// Encodes `block`, checks that it decodes back to itself under `cfg`, and returns its size.
fn roundtrip_size(comptime B: type, gpa: Allocator, block: B, cfg: B.Cfg) !usize {
    const bytes = try codec.encode(B, gpa, block);
    defer gpa.free(bytes);
    var decoded = try codec.decode_cfg(B, gpa, bytes, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(block));
    try testing.expect(decoded.digest().eql(Sha256.hash(&.{bytes})));
    return bytes.len;
}

/// Checks the block bound against the widest encoding with a key-only directory: every set
/// names every peer, and the bound adds the unused width of the commitment prefix and five
/// participant-set prefixes.
fn check_key_only(gpa: Allocator, count: u32, cfg: KeyOnly.Cfg) !void {
    const prefix_slack = 5 - codec.varint.size(u32, count);
    var peers = try participants(gpa, count);
    defer peers.deinit(gpa);
    var block = try widest_block(KeyOnly, gpa, .{ peers, peers, peers }, .{});
    defer block.deinit(gpa);
    const size = try roundtrip_size(KeyOnly, gpa, block, cfg);
    try testing.expectEqual(KeyOnly.max_encode_size_for(cfg), size + 6 * prefix_slack);
}

/// Checks the bound with an address directory: disjoint output players, players, and next
/// players behind the widest address. The bound also adds the unused width of the directory's
/// key-set and address-list prefixes and of each address's hostname prefix.
fn check_addressed(gpa: Allocator, count: u32, cfg: Addressed.Cfg) !void {
    const prefix_slack = 5 - codec.varint.size(u32, count);
    var peers = try participants(gpa, 3 * count);
    defer peers.deinit(gpa);
    var sets: [3]Set(P) = undefined;
    for (&sets, 0..) |*set, index| {
        set.* = .{ .items = peers.items[index * count ..][0..count] };
    }
    const directory = try mocks.widest_addresses(gpa, peers);
    var block = try widest_block(Addressed, gpa, sets, directory);
    defer block.deinit(gpa);
    const entries: u32 = 3 * count;
    const address = directory.get(peers.items[0]).?;
    const address_slack = @import("p2p").Address.max_encode_size - address.encode_size();
    const directory_slack = 2 * (5 - codec.varint.size(u32, entries)) + entries * address_slack;
    const size = try roundtrip_size(Addressed, gpa, block, cfg);
    const expected = size + 6 * prefix_slack + directory_slack;
    try testing.expectEqual(Addressed.max_encode_size_for(cfg), expected);
}

// commonware `max_encode_size_covers_widest_block`.
test "bootstrap block bound covers the widest block" {
    for (counts()) |count| {
        const cfg: KeyOnly.Cfg = .{ .max_participants = count, .max_supported_mode = .v0 };
        try check_key_only(testing.allocator, count, cfg);
        try check_addressed(testing.allocator, count, cfg);
    }
}

fn check_components(comptime D: type, count: u32) !void {
    const S = limits.ConsensusScheme;
    const Digest = Sha256.Digest;
    const cfg: KeyOnly.Cfg = .{ .max_participants = count, .max_supported_mode = .v0 };
    const bound = limits.max_payload_size(MinSig, D, count, .v0);
    const terms = [_]usize{
        consensus.simplex.limits.max_payload_size(S, Digest, count),
        consensus.marshal.max_payload_size(limits.MarshalVariant(MinSig, D), S, count, cfg),
        dkg_limits.max_payload_size(MinSig, P, count),
    };
    var found = false;
    for (terms) |term| {
        try testing.expect(term <= bound);
        found = found or term == bound;
    }
    try testing.expect(found);
}

// commonware `covers_every_component`.
test "bootstrap payload bound is the largest component bound" {
    for ([_]u32{ 1, 4, 128 }) |count| {
        try check_components(Unit, count);
        try check_components(Addresses, count);
    }
}

test "bootstrap genesis is the empty epoch-zero block" {
    const leader = ed25519.PrivateKey.from_seed(3).public_key();
    var genesis = try KeyOnly.genesis(testing.allocator, leader);
    defer genesis.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), genesis.height().get());
    try testing.expect(genesis.parent().eql(Sha256.Digest.empty));
    try testing.expect(genesis.epoch_info() == null);
    const cfg: KeyOnly.Cfg = .{ .max_participants = 1, .max_supported_mode = .v0 };
    const size = try roundtrip_size(KeyOnly, testing.allocator, genesis, cfg);
    try testing.expectEqual(genesis.encode_size(), size);
}
