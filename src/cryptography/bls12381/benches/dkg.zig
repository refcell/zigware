//! DKG benchmarks of BLS12-381 (commonware `bls12381/benches/dkg/feldman_desmedt.rs`): one
//! player finalizing a round in which every dealer revealed its share (it acknowledged
//! none), for a fresh DKG and a reshare.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const utils = @import("utils");
const common = @import("common.zig");

const bls12381 = cryptography.bls12381;
const fd = bls12381.dkg.feldman_desmedt;
const MinSig = bls12381.primitives.MinSig;
const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = PrivateKey.PublicKey;
const N3f1 = utils.N3f1;
const Set = utils.ordered.Set;
const Info = fd.Info(MinSig, PublicKey);
const Logs = fd.Logs(MinSig, PublicKey, N3f1);
const Player = fd.Player(MinSig, PrivateKey);
const Dealer = fd.Dealer(MinSig, PrivateKey);
const Share = bls12381.primitives.group.Share;

const bench_namespace = "_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_BENCH";

/// A round's info and every dealer's verified log; the first key is the finalizing player,
/// whom no dealer reached.
const Round = struct {
    info: Info,
    me: PrivateKey,
    logs: Logs,

    /// Builds the round in place (`logs` points at `info`).
    fn init(round: *Round, gpa: Allocator, rng: *utils.TestRng, reshare: bool, n: u32) !void {
        const keys = try gpa.alloc(PrivateKey, n);
        defer gpa.free(keys);
        for (keys) |*key| key.* = PrivateKey.random(rng);
        const publics = try gpa.alloc(PublicKey, n);
        defer gpa.free(publics);
        for (publics, keys) |*public, key| public.* = key.public_key();
        var previous: ?fd.Dealt(MinSig, PublicKey) = null;
        defer if (previous) |*dealt| {
            for (dealt.shares.values) |*share| share.private.zeroize();
            dealt.shares.deinit(gpa);
        };
        if (reshare) {
            const players = try Set(PublicKey).init(gpa, publics);
            previous = try fd.deal(MinSig, PublicKey, N3f1, gpa, rng, .non_zero_counter, players);
        }
        round.me = keys[0];
        round.info = try Info.init(
            N3f1,
            gpa,
            bench_namespace,
            0,
            if (previous) |dealt| dealt.output else null,
            .non_zero_counter,
            .v1,
            try Set(PublicKey).init(gpa, publics),
            try Set(PublicKey).init(gpa, publics),
        );
        errdefer round.info.deinit(gpa);
        round.logs = .init(&round.info);
        errdefer round.logs.deinit(gpa);
        for (keys) |key| {
            const share: ?Share = if (previous) |dealt|
                dealt.shares.get_value(key.public_key()).?.*
            else
                null;
            const log = try deal(gpa, &round.info, keys, key, rng, share);
            _ = try round.logs.record(gpa, key.public_key(), log);
        }
    }

    fn deinit(round: *Round, gpa: Allocator) void {
        round.logs.deinit(gpa);
        round.info.deinit(gpa);
        round.* = undefined;
    }
};

fn find_key(keys: []const PrivateKey, public: PublicKey) PrivateKey {
    for (keys) |key| if (key.public_key().eql(public)) return key;
    unreachable; // Every player is a dealer.
}

/// `dealer`'s verified log: every player but the first acknowledges its dealing.
fn deal(
    gpa: Allocator,
    info: *const Info,
    keys: []const PrivateKey,
    dealer: PrivateKey,
    rng: *utils.TestRng,
    share: ?Share,
) !fd.DealerLog(MinSig, PublicKey) {
    var started = try Dealer.start(N3f1, gpa, rng, info, dealer, share);
    defer {
        started.pub_msg.deinit(gpa);
        gpa.free(started.priv_msgs);
    }
    const me = keys[0].public_key();
    for (started.priv_msgs) |message| {
        if (message.player.eql(me)) continue;
        var receiver = try Player.init(info, find_key(keys, message.player));
        defer receiver.deinit(gpa);
        const dealer_key = dealer.public_key();
        const pub_msg = started.pub_msg;
        const ack = (try receiver.dealer_message(N3f1, gpa, dealer_key, pub_msg, message.msg)).?;
        try started.dealer.receive_player_ack(message.player, ack);
    }
    var signed = try started.dealer.finalize(N3f1, gpa);
    defer signed.deinit(gpa);
    assert(try fd.check_log(MinSig, PublicKey, gpa, info, &signed));
    return signed.log.clone(gpa);
}

/// Finalizes a fresh player against a fresh copy of the logs (copied untimed).
const Finalize = struct {
    gpa: Allocator,
    round: *const Round,
    logs: ?Logs = null,

    pub fn before_iter(workload: *Finalize) !void {
        if (workload.logs) |*logs| logs.deinit(workload.gpa);
        workload.logs = try workload.round.logs.clone(workload.gpa);
    }

    pub fn iter(workload: *Finalize) !void {
        var player = try Player.init(&workload.round.info, workload.round.me);
        defer player.deinit(workload.gpa);
        var rng = utils.test_rng();
        var finalized = try player.finalize(N3f1, workload.gpa, &rng, &workload.logs.?, null);
        finalized.output.deinit(workload.gpa);
    }

    pub fn teardown(workload: *Finalize) void {
        if (workload.logs) |*logs| logs.deinit(workload.gpa);
        workload.logs = null;
    }
};

fn bench_dkg(runner: *bench.Runner, reshare: bool) !void {
    const gpa = runner.allocator;
    const standard = [_]u32{ 5, 10, 20, 50 };
    const full = [_]u32{ 5, 10, 20, 50, 100, 250, 500 };
    const counts = runner.inputs.pick([]const u32, standard[0..1], &standard, &full);
    var rng = utils.test_rng();
    for (counts) |n| {
        const prefix = if (reshare)
            "bls12381::dkg::feldman_desmedt_reshare_recovery"
        else
            "bls12381::dkg::feldman_desmedt_recovery";
        const name = bench.Benchmark.init(prefix)
            .with_param("n", n).with_param("t", N3f1.quorum(n)).with_param("conc", 1);
        if (try common.skip(runner, name)) continue;
        var round: Round = undefined;
        try round.init(gpa, &rng, reshare, n);
        defer round.deinit(gpa);
        var workload: Finalize = .{ .gpa = gpa, .round = &round };
        defer workload.teardown();
        try runner.run(name, &workload);
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_dkg(runner, false);
    try bench_dkg(runner, true);
}
