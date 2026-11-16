//! Tests of commonware's `glue::dkg::state_sync` (`mod tests`). Commonware's `should_panic`
//! cases check `init`'s errors here.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const parallel = @import("parallel");
const runtime = @import("runtime");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const types = @import("types.zig");
const network = @import("network.zig");
const state_sync = @import("state_sync.zig");

const ed25519 = cryptography.ed25519;
const P = ed25519.PublicKey;
const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const Epoch = consensus.Epoch;
const MinPk = cryptography.bls12381.primitives.MinPk;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const simplex = consensus.simplex.types;
const Digest = cryptography.sha256.Digest;
const Sha256 = cryptography.sha256.Sha256;
const certificate_mocks = cryptography.certificate.mocks;
const MemoryStorage = runtime.buffer.mocks.Storage;

/// commonware's `simplex::mocks::scheme`, the `TestScheme` of glue's DKG tests.
pub const Scheme = certificate_mocks.Scheme(simplex.Subject(Digest), utils.N3f1, P, .{});
const Fixture = certificate_mocks.Fixture(Scheme);
const Material = state_sync.StateSync(Scheme, Digest, MinPk, Unit);
const TestPlan = state_sync.Plan(Scheme, Digest, MinPk, Unit);
const namespace = "_COMMONWARE_GLUE_DKG_TEST";
const gpa = testing.allocator;
const io = testing.io;

fn fixture() !Fixture {
    var rng = utils.rng.TestRng.init(0);
    return certificate_mocks.fixture(Scheme, gpa, &rng, namespace, 4);
}

fn trusted_output(epoch: u64, participants: Set(P)) !fd.Output(MinPk, P) {
    var rng = utils.rng.TestRng.init(epoch + 1);
    const owned = try participants.clone(gpa);
    var dealt = try fd.deal(MinPk, P, utils.N3f1, gpa, &rng, .non_zero_counter, owned);
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    return dealt.output;
}

/// A finalized floor at view 1 of `epoch` and that epoch's info, for `fixture`'s committee.
fn material(schemes: *const Fixture, epoch: u64) !Material {
    var participants = try Set(P).from_dedup(gpa, schemes.participants);
    defer participants.deinit(gpa);
    var output = try trusted_output(epoch, participants);
    errdefer output.deinit(gpa);
    const Proposal = simplex.Proposal(Digest);
    const proposal = Proposal.init(
        .new(.new(epoch), .new(1)),
        .zero(),
        Sha256.hash(&.{"state sync floor"}),
    );
    const Finalize = simplex.Finalize(Scheme, Digest);
    var finalizes: [4]Finalize = undefined;
    for (schemes.schemes, &finalizes) |*scheme, *vote| {
        vote.* = (try Finalize.sign(gpa, scheme, proposal)).?;
    }
    const Floor = simplex.Finalization(Scheme, Digest);
    var floor = try Floor.from_votes(gpa, &schemes.schemes[0], &finalizes, parallel.sequential);
    errdefer floor.deinit(gpa);
    return .{
        .info = .{
            .outcome = .success,
            .epoch = .new(epoch),
            .output = output,
            .players = try participants.clone(gpa),
            .next_players = try participants.clone(gpa),
            .directory = .{},
        },
        .floor = floor,
    };
}

fn local(port: u16) @import("p2p").Address {
    return .{ .symmetric = .{ .ip = .{ .v4 = .localhost }, .port = port } };
}

fn config(partition: []const u8) state_sync.Config {
    return .{ .partition_prefix = partition, .max_participants = 16, .max_supported_mode = .v1 };
}

fn open_plan(storage: *MemoryStorage, partition: []const u8, provided: ?Material) !TestPlan {
    return TestPlan.init(gpa, io, storage.interface(), config(partition), provided);
}

fn expect_resolves(plan: *TestPlan, storage: *MemoryStorage, expected: ?Material) !void {
    var actual = try plan.resolve(storage.interface(), null);
    defer if (actual) |*value| value.deinit(gpa);
    if (expected) |value| {
        try testing.expect(actual != null);
        try testing.expect(actual.?.eql(value));
    } else {
        try testing.expect(actual == null);
    }
}

test "state sync: init persists before resolve (init_persists_before_resolve)" {
    var schemes = try fixture();
    defer schemes.deinit(gpa);
    var storage = MemoryStorage.init(gpa);
    defer storage.deinit();
    var expected = try material(&schemes, 2);
    defer expected.deinit(gpa);
    var initialized = try open_plan(&storage, "persist", try expected.clone(gpa));
    initialized.deinit();
    var reopened = try open_plan(&storage, "persist", null);
    defer reopened.deinit();
    try expect_resolves(&reopened, &storage, expected);
}

test "state sync: every caller sees one resolution (two_clones_resolve_identically)" {
    var schemes = try fixture();
    defer schemes.deinit(gpa);
    var storage = MemoryStorage.init(gpa);
    defer storage.deinit();
    var expected = try material(&schemes, 2);
    defer expected.deinit(gpa);
    var plan = try open_plan(&storage, "clones", try expected.clone(gpa));
    defer plan.deinit();
    try expect_resolves(&plan, &storage, expected);
    try expect_resolves(&plan, &storage, expected);
}

// commonware `stale_resolution_deletes_once_and_reopen_sees_none`.
test "state sync: stale resolution deletes once" {
    var schemes = try fixture();
    defer schemes.deinit(gpa);
    var storage = MemoryStorage.init(gpa);
    defer storage.deinit();
    const stale = try material(&schemes, 2);
    var plan = try open_plan(&storage, "stale", stale);
    for (0..2) |_| {
        const resolved = try plan.resolve(storage.interface(), .new(3));
        try testing.expect(resolved == null);
    }
    plan.deinit();
    var reopened = try open_plan(&storage, "stale", null);
    defer reopened.deinit();
    try expect_resolves(&reopened, &storage, null);
}

test "state sync: a recovered epoch at the floor keeps the material" {
    var schemes = try fixture();
    defer schemes.deinit(gpa);
    var storage = MemoryStorage.init(gpa);
    defer storage.deinit();
    var expected = try material(&schemes, 2);
    defer expected.deinit(gpa);
    var plan = try open_plan(&storage, "floor", try expected.clone(gpa));
    defer plan.deinit();
    var resolved = (try plan.resolve(storage.interface(), .new(2))).?;
    defer resolved.deinit(gpa);
    try testing.expect(resolved.eql(expected));
}

// commonware `provided_material_overwrites_persisted_record`.
test "state sync: provided material overwrites the record" {
    var schemes = try fixture();
    defer schemes.deinit(gpa);
    var storage = MemoryStorage.init(gpa);
    defer storage.deinit();
    var replacement = try material(&schemes, 2);
    defer replacement.deinit(gpa);
    var first = try open_plan(&storage, "overwrite", try material(&schemes, 1));
    first.deinit();
    var second = try open_plan(&storage, "overwrite", try replacement.clone(gpa));
    second.deinit();
    var reopened = try open_plan(&storage, "overwrite", null);
    defer reopened.deinit();
    try expect_resolves(&reopened, &storage, replacement);
}

test "state sync: an artifact in another epoch than the floor fails init" {
    var schemes = try fixture();
    defer schemes.deinit(gpa);
    var storage = MemoryStorage.init(gpa);
    defer storage.deinit();
    // artifact_beyond_floor_panics_at_init and artifact_below_floor_panics_at_init.
    for ([_][2]u64{ .{ 2, 3 }, .{ 3, 2 } }) |epochs| {
        var mismatched = try material(&schemes, epochs[0]);
        mismatched.info.epoch = .new(epochs[1]);
        const result = open_plan(&storage, "mismatch", mismatched);
        try testing.expectError(error.EpochMismatch, result);
    }
}

// commonware `oversized_provided_material_panics_at_init`.
test "state sync: oversized material fails init" {
    var schemes = try fixture();
    defer schemes.deinit(gpa);
    var storage = MemoryStorage.init(gpa);
    defer storage.deinit();
    var small = config("oversized");
    small.max_participants = 3;
    const provided = try material(&schemes, 2);
    const result = TestPlan.init(gpa, io, storage.interface(), small, provided);
    try testing.expectError(error.InvalidMaterial, result);
}

// commonware `invalid_addressed_directory_panics_at_init`.
test "state sync: an invalid addressed directory fails init" {
    const Addresses = network.Addresses(P);
    const AddressedPlan = state_sync.Plan(Scheme, Digest, MinPk, Addresses);
    var schemes = try fixture();
    defer schemes.deinit(gpa);
    var storage = MemoryStorage.init(gpa);
    defer storage.deinit();
    var base = try material(&schemes, 2);
    defer base.deinit(gpa);
    // Every peer of the epoch and one more.
    var peers: std.ArrayList(Addresses.Inner.Pair) = .empty;
    defer peers.deinit(gpa);
    for (base.info.players.items, 0..) |peer, index| {
        const port: u16 = @intCast(index + 1);
        try peers.append(gpa, .{ peer, local(port) });
    }
    const extra = ed25519.PrivateKey.from_seed(10_000).public_key();
    try peers.append(gpa, .{ extra, local(99) });
    const invalid: AddressedPlan.Material = .{
        .info = .{
            .outcome = base.info.outcome,
            .epoch = base.info.epoch,
            .output = try base.info.output.clone(gpa),
            .players = try base.info.players.clone(gpa),
            .next_players = try base.info.next_players.clone(gpa),
            .directory = try Addresses.init(gpa, peers.items),
        },
        .floor = try base.floor.clone(gpa),
    };
    const result = AddressedPlan.init(gpa, io, storage.interface(), config("invalid"), invalid);
    try testing.expectError(error.InvalidMaterial, result);
}

test "state sync: a disabled plan resolves none (disabled_resolves_none_without_storage)" {
    var storage = MemoryStorage.init(gpa);
    defer storage.deinit();
    var plan = TestPlan.disabled(gpa, io);
    defer plan.deinit();
    try expect_resolves(&plan, &storage, null);
    _ = types;
}
