//! Tests of commonware's `glue::dkg::reshare::actor::setup` (`mod tests`).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const mocks = @import("../../tests/mocks.zig");
const Fence = @import("../../fence.zig").Fence;
const store_mod = @import("../store.zig");
const setup = @import("setup.zig");

const Epoch = consensus.Epoch;
const Height = consensus.Height;
const Processed = consensus.marshal.core.floor.Processed;
const PrivateKey = mocks.TestSigner;
const P = mocks.TestPublicKey;
const V = mocks.TestBlsVariant;
const Set = utils.ordered.Set(P);
const N3f1 = utils.N3f1;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = cryptography.bls12381.primitives.group.Share;
const Digested = broadcast.Digested(mocks.TestBlock);
const oneshot = utils.channel.oneshot;
const gpa = testing.allocator;
const namespace = "_COMMONWARE_GLUE_DKG_RESHARE_SETUP_TEST";

fn signers() [4]PrivateKey {
    var keys: [4]PrivateKey = undefined;
    for (&keys, 0..) |*key, seed| key.* = .from_seed(seed);
    return keys;
}

fn players() !Set {
    var keys: [4]P = undefined;
    for (&keys, signers()) |*key, signer| key.* = signer.public_key();
    return Set.from_dedup(gpa, &keys);
}

/// A trusted dealing to the four signers, seeded with `seed` (commonware `deal` with
/// `TestRng::new(seed)`).
fn dealt(seed: u64) !fd.Dealt(V, P) {
    var rng = utils.rng.TestRng.init(seed);
    return fd.deal(V, P, N3f1, gpa, &rng, .non_zero_counter, try players());
}

fn free_dealt(result: *fd.Dealt(V, P)) void {
    result.output.deinit(gpa);
    for (result.shares.values) |*share| share.private.zeroize();
    result.shares.deinit(gpa);
}

// commonware `startup_tip_covers_processed_and_floor`: state sync never resumes below its
// certified floor, and marshal's processed position takes its digest from the stored block
// that backs it.
test "setup: startup tip covers the processed position and the floor" {
    var blocks: [5]Digested = undefined;
    var raw = mocks.genesis_block(PrivateKey.from_seed(0).public_key());
    for (&blocks) |*block| {
        block.* = try Digested.precomputed(gpa, raw, raw.digest());
        raw = mocks.child(&raw);
    }
    defer for (&blocks) |*block| block.deinit();
    const Case = struct { processed: ?Processed, floor: ?usize, expected: ?usize };
    const cases = [_]Case{
        // Without state sync, the actor resumes after marshal's processed position.
        .{ .processed = null, .floor = null, .expected = null },
        .{ .processed = .{ .block = .new(2) }, .floor = null, .expected = 2 },
        .{ .processed = .{ .absent = .new(2) }, .floor = null, .expected = 2 },
        // A floor covers every block below it until marshal passes it.
        .{ .processed = null, .floor = 0, .expected = null },
        .{ .processed = null, .floor = 3, .expected = 2 },
        .{ .processed = .{ .block = .new(1) }, .floor = 3, .expected = 2 },
        .{ .processed = .{ .absent = .new(2) }, .floor = 3, .expected = 2 },
        .{ .processed = .{ .block = .new(4) }, .floor = 3, .expected = 4 },
    };
    for (cases) |case| {
        const processed: ?struct { Processed, *const Digested } = if (case.processed) |value|
            .{ value, &blocks[value.anchor().get()] }
        else
            null;
        const floor: ?*const Digested = if (case.floor) |index| &blocks[index] else null;
        const tip = setup.startup(Digested, processed, floor);
        if (case.expected) |index| {
            try testing.expectEqual(@as(u64, index), tip.?.height.get());
            try testing.expect(tip.?.digest.eql(blocks[index].digest()));
        } else try testing.expect(tip == null);
    }
}

// commonware `late_state_sync_floor_skips_inclusion_prefix`.
test "setup: a late state-sync floor skips the inclusion prefix" {
    const epocher = consensus.types.FixedEpocher.new(utils.NonZero(u64).init(64).?);
    const epoch = Epoch.new(3);
    const midpoint = epocher.midpoint(epoch).?;
    const late_floor = midpoint.next();
    try testing.expectEqual(.late, epocher.containing(late_floor).?.phase());
    try testing.expect(setup.state_sync_skips_inclusion_prefix(epocher, late_floor));
    try testing.expect(!setup.state_sync_skips_inclusion_prefix(epocher, midpoint));
    try testing.expect(!setup.state_sync_skips_inclusion_prefix(epocher, null));
}

fn share_of(result: *const fd.Dealt(V, P), key: P) Share {
    return result.shares.get_value(key).?.*;
}

// commonware `recovered_share_matches_carried_output`: after a failed ceremony, the newest
// share stored under an earlier epoch is recovered only if it is a share of the carried
// output. A successful epoch with no stored share recovers nothing, and neither does a node
// that is not a player of the carried output.
test "setup: a recovered share must match the carried output" {
    var carried = try dealt(0);
    defer free_dealt(&carried);
    var other = try dealt(1);
    defer free_dealt(&other);
    const public_key = signers()[0].public_key();
    const share = share_of(&carried, public_key);
    var harness = try mocks.StoreHarness.init(gpa);
    defer harness.deinit();
    var secrets: mocks.MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    try secrets.put_share(.new(2), share);
    var store = try harness.open(gpa, "recovered-share", &secrets);
    defer store.deinit();
    var info: mocks.TestStore.Info = .{
        .outcome = .failure,
        .epoch = .new(5),
        .output = carried.output,
        .players = carried.output.players,
        .next_players = carried.output.players,
        .directory = .{},
    };

    // Three failed ceremonies after the stored epoch still carry the stored output.
    const recovered = try setup.recovered_share(V, &store, public_key, &info);
    try testing.expect(recovered.?.eql(share));

    // A successful ceremony replaces the output, so an unstored epoch has nothing to recover.
    info.outcome = .success;
    try testing.expect(try setup.recovered_share(V, &store, public_key, &info) == null);
    info.outcome = .failure;

    // A node that is not a player of the carried output recovers nothing.
    const outsider = PrivateKey.from_seed(9).public_key();
    try testing.expect(try setup.recovered_share(V, &store, outsider, &info) == null);

    // The newest stored share decides: a share of another output under epoch three wins.
    try testing.expect(!other.output.public.public().eql(carried.output.public.public()));
    try secrets.put_share(.new(3), share_of(&other, public_key));
    try testing.expect(try setup.recovered_share(V, &store, public_key, &info) == null);
}

/// A registrar that reports it was entered, then holds registration until released.
const HeldRegistrar = struct {
    pub const Variant = V;
    pub const PublicKey = P;

    entered: ?oneshot.Sender(void),
    held: ?oneshot.Receiver(void),

    pub fn register(
        self: *HeldRegistrar,
        io: Io,
        epoch: Epoch,
        info: types.SchemeInfo(V, P),
    ) !void {
        _ = .{ io, epoch };
        var owned = info;
        owned.deinit(gpa);
        try self.entered.?.send({});
        self.entered = null;
        var held = self.held.?;
        self.held = null;
        defer held.deinit();
        try held.recv();
    }
};

fn register_task(
    registrar: *HeldRegistrar,
    io: Io,
    fence: *Fence,
    info: types.SchemeInfo(V, P),
) !void {
    return setup.register_and_mark(registrar, io, fence, .new(1), info);
}

// commonware `fence_marks_after_registration_resolves`: the fence marks an epoch only once
// the registrar resolves, so a gate waiting on it never opens before the consensus provider
// serves its scheme.
test "setup: the fence marks after registration resolves" {
    try runtime.deterministic.soak(gpa, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    }, {}, struct {
        fn run_round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start(struct {
                fn body(io: Io) anyerror!void {
                    var output = try dealt(0);
                    defer free_dealt(&output);
                    const sharing = try output.output.public.clone(gpa);
                    const info = types.SchemeInfo(V, P).init(
                        PrivateKey.from_seed(9).public_key(),
                        try output.output.players.clone(gpa),
                        sharing,
                        null,
                    );
                    try testing.expect(info == .verifier);
                    var entered = try oneshot.channel(void, gpa, io);
                    defer entered.receiver.deinit();
                    var held = try oneshot.channel(void, gpa, io);
                    var registrar: HeldRegistrar = .{
                        .entered = entered.sender,
                        .held = held.receiver,
                    };
                    var fence = Fence.init(io);
                    defer fence.close();
                    const gate = fence.gate();
                    const args = .{ &registrar, io, &fence, info };
                    var registration = try io.concurrent(register_task, args);

                    // Registration is suspended inside the registrar, so the gate is still closed.
                    try entered.receiver.recv();
                    try testing.expect(gate.poll(.new(1)) == null);

                    // Once released, registration resolves and the gate opens.
                    try held.sender.send({});
                    try registration.await(io);
                    try gate.wait(.new(1));
                }
            }.body, .{runner.io()}));
        }
    }.run_round);
}

// commonware `recovered_dealer_after_dealing_requires_ack_quorum`.
test "setup: a dealer recovered after dealing needs an ack quorum" {
    const epoch = Epoch.new(1);
    const keys = signers();
    var previous = try dealt(0);
    defer free_dealt(&previous);
    const signer = keys[0];
    const share = share_of(&previous, signer.public_key());
    var info = try fd.Info(V, P).init(
        N3f1,
        gpa,
        namespace,
        epoch.get(),
        try previous.output.clone(gpa),
        .non_zero_counter,
        .v1,
        try players(),
        try players(),
    );
    defer info.deinit(gpa);
    var harness = try mocks.StoreHarness.init(gpa);
    defer harness.deinit();
    var secrets: mocks.MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try harness.open(gpa, "recovered-dealer-after-dealing", &secrets);
    defer store.deinit();
    var rng = utils.rng.TestRng.init(0);
    const seed = try store.seed_or_random(epoch, utils.rng.random(&rng));
    const Dealer = store_mod.Dealer(V, PrivateKey);
    const count = keys.len;

    const early = try store.create_dealer(N3f1, PrivateKey, epoch, signer, &info, share, seed);
    var kept = setup.dealer_for_phase(.early, count, early) orelse return error.DealerDropped;
    kept.deinit();
    const incomplete = try store.create_dealer(N3f1, PrivateKey, epoch, signer, &info, share, seed);
    try testing.expect(setup.dealer_for_phase(.midpoint, count, incomplete) == null);

    var recovered: Dealer = (try store.create_dealer(
        N3f1,
        PrivateKey,
        epoch,
        signer,
        &info,
        share,
        seed,
    )).?;
    for (keys[1..]) |player_signer| {
        const player_key = player_signer.public_key();
        var player = try fd.Player(V, PrivateKey).init(&info, player_signer);
        defer player.deinit(gpa);
        const private = for (recovered.shares_to_distribute()) |item| {
            if (item.player.eql(player_key)) break item.msg;
        } else return error.MissingDealing;
        const ack = (try player.dealer_message(
            N3f1,
            gpa,
            signer.public_key(),
            recovered.public,
            private,
        )).?;
        const outcome = try recovered.handle(&store, epoch, player_key, ack);
        try testing.expectEqual(.recorded, outcome);
    }
    var midpoint = setup.dealer_for_phase(.midpoint, count, @as(?Dealer, recovered)) orelse
        return error.DealerDropped;
    midpoint.deinit();
}
