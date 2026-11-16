//! The indexer's store: blocks by digest, the highest verified finalization per network, and
//! refusals for networks it does not serve or certificates that do not verify.

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const lib = @import("lib.zig");
const types = @import("types.zig");
const store_mod = @import("store.zig");

const Store = store_mod.Store;
const standard = zigware.consensus.simplex.scheme.bls12381_threshold.standard;
const simplex_types = zigware.consensus.simplex.types;
const traces = zigware.runtime.telemetry.traces;

pub const namespace = lib.application_namespace ++ lib.consensus_suffix;
pub const Fixture = zigware.cryptography.certificate.mocks.Fixture(lib.Scheme);

/// A network of `n` validators dealt from `seed`.
pub fn network_fixture(gpa: std.mem.Allocator, seed: u64, n: u32) !Fixture {
    var rng = zigware.utils.TestRng.init(seed);
    return standard.fixture(lib.Scheme, gpa, &rng, namespace, n);
}

/// A finalization of `payload` at `view` (epoch 0, parent `view - 1`), signed by a quorum.
pub fn finalize(
    gpa: std.mem.Allocator,
    fixture: *const Fixture,
    view: u64,
    payload: lib.Digest,
) !types.Finalization {
    const round = zigware.consensus.types.Round.new(.new(0), .new(view));
    const proposal: simplex_types.Proposal(lib.Digest) = .init(round, .new(view - 1), payload);
    const quorum = fixture.schemes.len - (fixture.schemes.len - 1) / 3;
    var votes: [16]lib.Scheme.Attestation = undefined;
    for (votes[0..quorum], fixture.schemes[0..quorum]) |*vote, *scheme| {
        vote.* = (try scheme.sign(gpa, .{ .finalize = &proposal })).?;
    }
    const sequential = zigware.parallel.sequential;
    const certificate = try fixture.verifier.assemble(gpa, votes[0..quorum], sequential);
    return .{ .proposal = proposal, .certificate = certificate };
}

fn get_finalization(store: *Store, network: types.Public) !types.Outbound {
    var rng = zigware.utils.rng.test_rng();
    const inbound: types.Inbound = .{ .get_finalization = .{ .network = network } };
    return store.handle(testing.allocator, &rng, inbound);
}

fn put_finalization(store: *Store, network: types.Public, finalization: types.Finalization) !bool {
    var rng = zigware.utils.rng.test_rng();
    const inbound: types.Inbound = .{
        .put_finalization = .{ .network = network, .finalization = finalization },
    };
    return (try store.handle(testing.allocator, &rng, inbound)).success;
}

test "bridge: the store keeps blocks by digest per network" {
    const gpa = testing.allocator;
    var one = try network_fixture(gpa, 1, 4);
    defer one.deinit(gpa);
    var two = try network_fixture(gpa, 2, 4);
    defer two.deinit(gpa);
    var collector: traces.Collector = .init(gpa, .{});
    defer collector.deinit();
    var store: Store = try .init(gpa, &.{one.verifier.identity()}, collector.tracer("indexer"));
    defer store.deinit(gpa);
    var rng = zigware.utils.rng.test_rng();

    const block: types.BlockFormat = .{ .random = 42 };
    const digest = store_mod.block_digest(block);
    const get: types.Inbound = .{
        .get_block = .{ .network = one.verifier.identity(), .digest = digest },
    };
    try testing.expect(!(try store.handle(gpa, &rng, get)).success);
    const put: types.Inbound = .{
        .put_block = .{ .network = one.verifier.identity(), .block = block },
    };
    try testing.expect((try store.handle(gpa, &rng, put)).success);
    try testing.expectEqual(block, (try store.handle(gpa, &rng, get)).block);
    try collector.get_by_level(.info).expect_message_exact("stored block");

    // A network the store does not serve: puts fail and gets find nothing.
    const foreign: types.Inbound = .{
        .put_block = .{ .network = two.verifier.identity(), .block = block },
    };
    try testing.expect(!(try store.handle(gpa, &rng, foreign)).success);
    const foreign_get: types.Inbound = .{
        .get_block = .{ .network = two.verifier.identity(), .digest = digest },
    };
    try testing.expect(!(try store.handle(gpa, &rng, foreign_get)).success);
}

test "bridge: the store answers with the highest verified finalization" {
    const gpa = testing.allocator;
    var one = try network_fixture(gpa, 1, 4);
    defer one.deinit(gpa);
    var two = try network_fixture(gpa, 2, 4);
    defer two.deinit(gpa);
    const publics = [_]types.Public{ one.verifier.identity(), two.verifier.identity() };
    var store: Store = try .init(gpa, &publics, .none);
    defer store.deinit(gpa);

    try testing.expect(!(try get_finalization(&store, publics[0])).success);
    const seven = try finalize(gpa, &one, 7, .fill(7));
    const five = try finalize(gpa, &one, 5, .fill(5));
    try testing.expect(try put_finalization(&store, publics[0], seven));
    // A lower view is stored (commonware inserts it) but is not the answer.
    try testing.expect(try put_finalization(&store, publics[0], five));
    const latest = (try get_finalization(&store, publics[0])).finalization;
    try testing.expect(latest.eql(seven));
    // The other network has none, and rejects one network's certificate as its own.
    try testing.expect(!(try get_finalization(&store, publics[1])).success);
    try testing.expect(!try put_finalization(&store, publics[1], seven));
    try testing.expect(!(try get_finalization(&store, publics[1])).success);
    // A certificate over a different payload than it signed does not verify.
    var forged = try finalize(gpa, &two, 9, .fill(9));
    forged.proposal.payload = .fill(8);
    try testing.expect(!try put_finalization(&store, publics[1], forged));
}
