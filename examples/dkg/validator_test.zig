//! commonware `examples/dkg/src/validator.rs` tests. `probe_resumes_persisted_floor` takes the
//! probe's manager and blocker from the simulated network rather than a discovery network: the
//! configuration only carries them. zigware's probe holds the floor's epoch, not the floor.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const zigware = @import("zigware");
const types = @import("types.zig");
const validator = @import("validator.zig");

const consensus = zigware.consensus;
const p2p = zigware.p2p;
const parallel = zigware.parallel;
const runtime = zigware.runtime;
const utils = zigware.utils;
const glue_dkg = zigware.glue.dkg;
const ed25519 = zigware.cryptography.ed25519;
const fd = zigware.cryptography.bls12381.dkg.feldman_desmedt;
const simplex = consensus.simplex.types;

const gpa = testing.allocator;
const Scheme = types.Scheme;
const Set = types.Set(types.PublicKey);
const Net = p2p.simulated.Network(types.PublicKey);
const Finalization = validator.Plan.Finalization;
const Proposal = simplex.Proposal(types.Digest);

/// A source the probe never reaches in this test.
const NoSource = struct {};

const ProbeTypes = struct {
    pub const Scheme = types.Scheme;
    pub const Variant = validator.Variant;
    pub const Manager = glue_dkg.network.KeyOnlyManager(Net.Manager);
    pub const Source = NoSource;
    pub const Blocker = Net.Control;
    pub const NetSender = Net.Sender;
    pub const NetReceiver = Net.Receiver;
};

/// The genesis committee of `signers`, dealt with commonware's `TestRng::new(0)`.
const Committee = struct {
    info: types.EpochInfo,
    schemes: [4]Scheme,

    fn init(signers: *const [4]ed25519.PrivateKey) !Committee {
        var keys: [4]types.PublicKey = undefined;
        for (signers, &keys) |signer, *key| key.* = signer.public_key();
        const players = try Set.from_dedup(gpa, &keys);
        var rng = utils.rng.TestRng.init(0);
        const mode = types.sharing_mode;
        const N3f1 = utils.N3f1;
        var dealt = try fd.deal(types.MinSig, types.PublicKey, N3f1, gpa, &rng, mode, players);
        defer dealt.shares.deinit(gpa);
        var committee: Committee = undefined;
        committee.info = .{
            .outcome = .success,
            .epoch = .zero(),
            .output = dealt.output,
            .players = try dealt.output.players.clone(gpa),
            .next_players = try dealt.output.players.clone(gpa),
            .directory = .{},
        };
        for (dealt.shares.values, &committee.schemes) |share, *scheme| {
            const set = try dealt.output.players.clone(gpa);
            const sharing = try dealt.output.public.clone(gpa);
            scheme.* = (try Scheme.signer(gpa, types.namespace, set, sharing, share)).?;
        }
        return committee;
    }

    fn deinit(committee: *Committee) void {
        for (&committee.schemes) |*scheme| scheme.deinit(gpa);
        committee.info.deinit(gpa);
    }

    /// The quorum finalization of `proposal`.
    fn finalize(committee: *const Committee, proposal: Proposal) !Finalization {
        const Finalize = simplex.Finalize(Scheme, types.Digest);
        var finalizes: [4]Finalize = undefined;
        for (&committee.schemes, &finalizes) |*scheme, *vote| {
            vote.* = (try Finalize.sign(gpa, scheme, proposal)).?;
        }
        const first = &committee.schemes[0];
        return Finalization.from_votes(gpa, first, &finalizes, parallel.sequential);
    }
};

const Env = struct { gpa: Allocator, storage: runtime.storage.Storage };

fn probe_resumes_persisted_floor(io: Io) !void {
    var signers: [4]ed25519.PrivateKey = undefined;
    for (&signers, 0..) |*signer, seed| signer.* = .from_seed(seed);
    var committee = try Committee.init(&signers);
    defer committee.deinit();
    // Sign a floor in epoch 1 with the genesis committee.
    const digest = types.Sha256.hash(&.{"floor"});
    var floor = try committee.finalize(.init(.new(.new(1), .new(1)), .zero(), digest));
    defer floor.deinit(gpa);

    // Persist the floor, then reload the plan as a restarted node.
    var storage: runtime.buffer.mocks.Storage = .init(gpa);
    defer storage.deinit();
    const env: Env = .{ .gpa = gpa, .storage = storage.interface() };
    {
        var plan = try validator.Plan.init(env, "probe");
        defer plan.deinit();
        try plan.set_floor(&floor);
    }
    var plan = try validator.Plan.init(env, "probe");
    defer plan.deinit();
    try testing.expect(plan.floor().?.eql(floor));

    // The probe carries the persisted floor.
    const peers: p2p.TrackedPeers(types.PublicKey) = .init_primary(.init(&.{}));
    const net = try Net.init_with_peers(gpa, io, .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = 4,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    }, peers);
    defer net.deinit();
    const oracle = net.oracle();
    const public = committee.info.output.public.public();
    var verifier = try Scheme.certificate_verifier(gpa, types.namespace, public);
    defer verifier.deinit(gpa);
    const manager: ProbeTypes.Manager = .init(oracle.manager());
    const blocker = oracle.control(signers[0].public_key());
    var config = try validator.probe_config(
        ProbeTypes,
        gpa,
        manager,
        blocker,
        &committee.info,
        &plan,
        &verifier,
    );
    defer config.discovery.bootstrap.deinit(gpa);
    defer config.discovery.genesis.deinit(gpa);
    try testing.expectEqual(@as(?u64, 1), if (config.discovery.floor_epoch) |e| e.get() else null);
    try testing.expectEqual(@as(u64, 0), config.discovery.bootstrap.epoch.get());
}

const Unit = runtime.context.Handle(anyerror!void);

fn completes(ctx: runtime.deterministic.Context) anyerror!void {
    _ = ctx;
}

/// Runs until aborted, then counts its drop (commonware's `pending_handle`).
fn pending(ctx: runtime.deterministic.Context, dropped: *std.atomic.Value(u32)) anyerror!void {
    defer _ = dropped.fetchAdd(1, .monotonic);
    var never: Io.Event = .unset;
    try never.wait(ctx.io());
    unreachable; // Nothing sets `never`: the wait ends only by cancellation.
}

fn actor_completion_stops_validator(ctx: runtime.deterministic.Context) !void {
    var dropped: std.atomic.Value(u32) = .init(0);
    // Model a clean actor exit alongside siblings that would otherwise run forever.
    var actors: [8]Unit = undefined;
    actors[0] = try ctx.child("completes").spawn(completes, .{});
    for (actors[1..]) |*actor| actor.* = try ctx.child("pending").spawn(pending, .{&dropped});
    // Supervision must complete and abort every pending sibling.
    try (try runtime.context.select(anyerror!void, ctx.io(), &actors));
    try testing.expectEqual(@as(u32, 7), dropped.load(.monotonic));
}

test "dkg: successful actor completion stops validator" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(actor_completion_stops_validator, .{}));
}

test "dkg: validator probe resumes persisted floor" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start(probe_resumes_persisted_floor, .{runner.io()}));
}
