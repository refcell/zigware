//! Feldman-Desmedt tests (commonware `feldman_desmedt::test`).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const math = @import("math");
const invariants = @import("invariants");
const build_options = @import("build_options");
const plan_mod = @import("plan.zig");
const primitives = @import("../../primitives/root.zig");
const ed25519 = @import("../../../ed25519.zig");
const shared = @import("../../conformance_test.zig");
const fd = @import("../feldman_desmedt.zig");
const transcript_mod = @import("../../../transcript.zig");

const Allocator = std.mem.Allocator;
const minifuzz = invariants.minifuzz;
const N3f1 = utils.N3f1;
const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const TestRng = utils.rng.TestRng;
const Plan = plan_mod.Plan;
const MinPk = primitives.variant.MinPk;
const Scalar = primitives.group.Scalar;
const Poly = primitives.sharing.Poly;
const Sharing = primitives.sharing.Sharing;
const PrivateKey = ed25519.PrivateKey;
const PublicKey = ed25519.PublicKey;
const Info = fd.Info(MinPk, PublicKey);
const Output = fd.Output(MinPk, PublicKey);
const Dealer = fd.Dealer(MinPk, PrivateKey);
const Player = fd.Player(MinPk, PrivateKey);
const DealerLog = fd.DealerLog(MinPk, PublicKey);
const DealerPubMsg = fd.DealerPubMsg(MinPk);
const LogPair = Map(PublicKey, DealerLog).Pair;
const Logs = fd.Logs(MinPk, PublicKey, N3f1);
const Persisted = fd.PersistedDealing(MinPk, PublicKey);
const Failure = fd.Failure(PublicKey);

fn run(num_participants: u32, rounds: []const plan_mod.Round) !void {
    const plan: Plan = .{ .num_participants = num_participants, .rounds = rounds };
    try plan.run(MinPk, testing.allocator, 0);
}

const all4: []const u32 = &.{ 0, 1, 2, 3 };

test "feldman-desmedt: single round" {
    try run(4, &.{.{ .dealers = all4, .players = all4 }});
}

test "feldman-desmedt: multiple rounds" {
    try shared.skip_slow();
    const r: plan_mod.Round = .{ .dealers = all4, .players = all4 };
    try run(4, &.{ r, r, r, r });
}

test "feldman-desmedt: player crash resume after dealer" {
    try run(4, &.{.{ .dealers = all4, .players = all4, .crash_resume_players = &.{.{ 1, 2 }} }});
}

test "feldman-desmedt: resume missing good dealer message fails after checkpoint" {
    try run(4, &.{.{
        .dealers = all4,
        .players = all4,
        .resume_missing_dealer_msg_fails = &.{.{ 2, 1 }},
    }});
}

test "feldman-desmedt: resume missing good dealer message skips unacked players" {
    try run(4, &.{.{
        .dealers = all4,
        .players = all4,
        .no_acks = &.{.{ 1, 0 }},
        .resume_missing_dealer_msg_fails = &.{.{ 2, 1 }},
    }});
}

test "feldman-desmedt: finalize fails after resume without good dealer message" {
    try run(4, &.{.{
        .dealers = all4,
        .players = all4,
        .no_acks = &.{.{ 0, 1 }},
        .finalize_missing_dealer_msg_fails = &.{0},
    }});
}

test "feldman-desmedt: invalid checkpoint configs fail validation" {
    const cases = [_]plan_mod.Round{
        .{ .dealers = all4, .players = all4, .crash_resume_players = &.{.{ 4, 2 }} },
        .{ .dealers = all4, .players = all4, .resume_missing_dealer_msg_fails = &.{.{ 1, 2 }} },
        .{
            .dealers = all4,
            .players = all4,
            .bad_reveals = &.{.{ 1, 0 }},
            .resume_missing_dealer_msg_fails = &.{.{ 2, 1 }},
        },
    };
    for (cases) |case| {
        const plan: Plan = .{ .num_participants = 4, .rounds = &.{case} };
        try testing.expect(!plan.validate());
    }
}

test "feldman-desmedt: changing committee" {
    try shared.skip_slow();
    try run(5, &.{
        .{ .dealers = &.{ 0, 1, 2 }, .players = &.{ 1, 2, 3 } },
        .{ .dealers = &.{ 1, 2, 3 }, .players = &.{ 2, 3, 4 } },
        .{ .dealers = &.{ 2, 3, 4 }, .players = &.{ 3, 4, 0 } },
        .{ .dealers = &.{ 3, 4, 0 }, .players = &.{ 4, 0, 1 } },
    });
}

test "feldman-desmedt: missing ack" {
    try shared.skip_slow();
    // With 4 players, max_faults = 1, so 1 missing ack per dealer is OK.
    try run(4, &.{
        .{ .dealers = all4, .players = all4, .no_acks = &.{.{ 0, 0 }} },
        .{ .dealers = all4, .players = all4, .no_acks = &.{.{ 0, 1 }} },
        .{ .dealers = all4, .players = all4, .no_acks = &.{.{ 0, 2 }} },
        .{ .dealers = all4, .players = all4, .no_acks = &.{.{ 0, 3 }} },
    });
}

test "feldman-desmedt: increasing decreasing committee" {
    try shared.skip_slow();
    try run(5, &.{
        .{ .dealers = &.{ 0, 1 }, .players = &.{ 0, 1, 2 } },
        .{ .dealers = &.{ 0, 1, 2 }, .players = &.{ 0, 1, 2, 3 } },
        .{ .dealers = &.{ 0, 1, 2 }, .players = &.{ 0, 1 } },
        .{ .dealers = &.{ 0, 1 }, .players = &.{ 0, 1, 2, 3, 4 } },
        .{ .dealers = &.{ 0, 1, 2, 3 }, .players = &.{ 0, 1 } },
    });
}

test "feldman-desmedt: bad reveal fails" {
    try run(4, &.{.{ .dealers = &.{0}, .players = all4, .bad_reveals = &.{.{ 0, 1 }} }});
}

test "feldman-desmedt: bad share" {
    try run(4, &.{
        .{ .dealers = all4, .players = all4, .bad_shares = &.{.{ 0, 1 }} },
        .{ .dealers = all4, .players = all4, .bad_shares = &.{.{ 0, 2 }} },
    });
}

test "feldman-desmedt: shift degree fails" {
    try run(4, &.{.{
        .dealers = &.{0},
        .players = all4,
        .shift_degrees = &.{.{ .dealer = 0, .shift = 1 }},
    }});
}

test "feldman-desmedt: replace share fails" {
    try run(4, &.{
        .{ .dealers = all4, .players = all4 },
        .{ .dealers = all4, .players = all4, .replace_shares = &.{0} },
    });
}

test "feldman-desmedt: too many reveals dealer" {
    try run(4, &.{.{ .dealers = all4, .players = all4, .no_acks = &.{ .{ 0, 0 }, .{ 0, 1 } } }});
}

test "feldman-desmedt: too many reveals player" {
    try run(4, &.{.{
        .dealers = all4,
        .players = all4,
        .no_acks = &.{ .{ 0, 0 }, .{ 1, 0 }, .{ 3, 0 } },
    }});
}

test "feldman-desmedt: bad sigs" {
    const ones_array: [8]u8 = @splat(0xFF);
    const ones: []const u8 = &ones_array;
    try run(4, &.{.{
        .dealers = all4,
        .players = all4,
        .bad_dealer_sigs = &.{.{ .dealer = 0, .masks = .{ .log = ones } }},
        .bad_player_sigs = &.{.{ .dealer = 0, .player = 1, .masks = .{ .pub_msg = ones } }},
    }});
}

test "feldman-desmedt: issue 2745 regression" {
    try shared.skip_slow();
    try run(6, &.{
        .{
            .dealers = &.{0},
            .players = &.{ 5, 1, 3, 0, 4 },
            .no_acks = &.{.{ 0, 5 }},
            .bad_shares = &.{.{ 0, 5 }},
        },
        .{ .dealers = &.{ 0, 1, 3, 4 }, .players = &.{0} },
        .{ .dealers = &.{0}, .players = &.{0} },
    });
}

const namespace_test = "_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST";

fn key_set(gpa: Allocator, keys: []const PrivateKey) !Set(PublicKey) {
    const items = try gpa.alloc(PublicKey, keys.len);
    defer gpa.free(items);
    for (items, keys) |*item, key| item.* = key.public_key();
    return Set(PublicKey).init(gpa, items);
}

fn seeded_keys(comptime count: usize, first: u64) [count]PrivateKey {
    var keys: [count]PrivateKey = undefined;
    for (&keys, 0..) |*key, i| key.* = PrivateKey.from_seed(first + i);
    return keys;
}

fn find_key(keys: []const PrivateKey, pk: PublicKey) PrivateKey {
    for (keys) |key| if (key.public_key().eql(pk)) return key;
    unreachable; // Tests only look up their own keys.
}

const InfoOptions = struct {
    namespace: []const u8 = namespace_test,
    round: u64 = 0,
    previous: ?Output = null,
    mode: primitives.sharing.Mode = .non_zero_counter,
    reveal: fd.Reveal = .v1,
};

/// An initial-round `Info` over `dealers` and `players` (taking ownership of `previous`).
fn new_info(
    gpa: Allocator,
    dealers: []const PrivateKey,
    players: []const PrivateKey,
    options: InfoOptions,
) !Info {
    var previous = options.previous;
    var dealer_set = key_set(gpa, dealers) catch |err| {
        if (previous) |*p| p.deinit(gpa);
        return err;
    };
    const player_set = key_set(gpa, players) catch |err| {
        dealer_set.deinit(gpa);
        if (previous) |*p| p.deinit(gpa);
        return err;
    };
    // `Info.init` releases its inputs when it fails.
    return Info.init(
        N3f1,
        gpa,
        options.namespace,
        options.round,
        previous,
        options.mode,
        options.reveal,
        dealer_set,
        player_set,
    );
}

const DealOptions = struct {
    /// A player whose dealing is withheld, so the dealer reveals it.
    skip: ?PublicKey = null,
    /// A player whose dealing is appended to `persisted`.
    persist_for: ?PublicKey = null,
    persisted: ?*std.ArrayList(Persisted) = null,
};

/// Runs `dealer_sk` in `info`'s round: each player (a fresh `Player` from `keys`) acks its
/// dealing, except `skip`. Returns the dealer's log after its signature verifies.
fn deal_round(
    gpa: Allocator,
    info: *const Info,
    keys: []const PrivateKey,
    dealer_sk: PrivateKey,
    rng: anytype,
    options: DealOptions,
) !DealerLog {
    const dealer_pk = dealer_sk.public_key();
    var started = try Dealer.start(N3f1, gpa, rng, info, dealer_sk, null);
    defer {
        started.pub_msg.deinit(gpa);
        gpa.free(started.priv_msgs);
    }
    for (started.priv_msgs) |msg| {
        if (options.skip) |skip| if (msg.player.eql(skip)) continue;
        if (options.persist_for) |target| if (msg.player.eql(target)) {
            try options.persisted.?.append(gpa, .{
                .dealer = dealer_pk,
                .pub_msg = try started.pub_msg.clone(gpa),
                .priv_msg = msg.msg,
            });
        };
        var receiver = try Player.init(info, find_key(keys, msg.player));
        defer receiver.deinit(gpa);
        const ack = (try receiver.dealer_message(N3f1, gpa, dealer_pk, started.pub_msg, msg.msg)).?;
        try started.dealer.receive_player_ack(msg.player, ack);
    }
    var signed = try started.dealer.finalize(N3f1, gpa);
    defer signed.deinit(gpa);
    try testing.expect(try fd.check_log(MinPk, PublicKey, gpa, info, &signed));
    return signed.log.clone(gpa);
}

fn free_persisted(gpa: Allocator, list: *std.ArrayList(Persisted)) void {
    for (list.items) |*entry| entry.pub_msg.deinit(gpa);
    list.deinit(gpa);
}

fn free_pairs(gpa: Allocator, list: *std.ArrayList(LogPair)) void {
    for (list.items) |*pair| pair[1].deinit(gpa);
    list.deinit(gpa);
}

/// Checks one log as `Logs.pre_verify` would, with `test_rng`'s randomness.
fn check_log_with(info: *const Info, dealer: PublicKey, log: *const DealerLog) !fd.Check {
    var rng = utils.test_rng();
    var seed: transcript_mod.Summary = undefined;
    rng.fill_bytes(&seed.bytes);
    const resumed = transcript_mod.Transcript.resume_from(seed, fd.transcript_version);
    var local = resumed.noise("pre_verify");
    const round = info.round_transcript();
    return fd.check_dealer_log(
        MinPk,
        PublicKey,
        N3f1,
        testing.allocator,
        &local,
        info,
        &round,
        dealer,
        log,
    );
}

test "feldman-desmedt: info rejects inconsistent previous output" {
    const gpa = testing.allocator;
    const keys = seeded_keys(4, 0);
    var participants = try key_set(gpa, &keys);
    defer participants.deinit(gpa);
    var rng = TestRng.init(4);
    var dealt = try fd.deal(
        MinPk,
        PublicKey,
        N3f1,
        gpa,
        &rng,
        .non_zero_counter,
        try participants.clone(gpa),
    );
    defer dealt.deinit(gpa);
    // A wrong participant count, an excessive degree, and a threshold below the quorum.
    const cases = [_]struct { total: u32, seed: u64, degree: u32 }{
        .{ .total = 1, .seed = 5, .degree = 2 },
        .{ .total = 4, .seed = 6, .degree = 3 },
        .{ .total = 4, .seed = 7, .degree = 1 },
    };
    for (cases) |case| {
        var previous = try dealt.output.clone(gpa);
        previous.public.deinit(gpa);
        var poly_rng = TestRng.init(case.seed);
        var private = try Poly(Scalar).random(gpa, &poly_rng, case.degree);
        defer private.deinit(gpa);
        const committed = try math.poly.commit(gpa, MinPk.Public, private);
        previous.public = try Sharing(MinPk).init(gpa, .non_zero_counter, case.total, committed);
        if (case.degree == 1) {
            try testing.expectEqual(2, previous.public.required());
            try testing.expectEqual(3, previous.quorum(N3f1));
        }
        const result = new_info(gpa, &keys, &keys, .{
            .namespace = "invalid-previous-output-test",
            .round = 1,
            .previous = previous,
        });
        try testing.expectError(error.InvalidPreviousOutput, result);
    }
}

/// Whether the first player counts as revealed after the first `reveal_count` of the
/// required dealers withhold its dealing.
fn is_revealed_after(
    reveal: fd.Reveal,
    comptime dealer_count: usize,
    comptime player_count: usize,
    reveal_count: usize,
) !bool {
    const gpa = testing.allocator;
    const keys = seeded_keys(dealer_count + player_count, 1_000);
    const dealer_keys = keys[0..dealer_count];
    const player_keys = keys[dealer_count..];
    var info = try new_info(gpa, dealer_keys, player_keys, .{
        .namespace = "reveal-threshold-test",
        .reveal = reveal,
    });
    defer info.deinit(gpa);
    const target = player_keys[0].public_key();
    var pairs: std.ArrayList(LogPair) = .empty;
    defer free_pairs(gpa, &pairs);
    const required = info.required_commitments(N3f1);
    for (dealer_keys[0..required], 0..) |dealer_key, number| {
        var rng = TestRng.init(number);
        const skip: ?PublicKey = if (number < reveal_count) target else null;
        const log = try deal_round(gpa, &info, player_keys, dealer_key, &rng, .{ .skip = skip });
        try pairs.append(gpa, .{ dealer_key.public_key(), log });
    }
    var observed = try reckon_pairs(gpa, &info, pairs.items);
    defer observed.output.deinit(gpa);
    return observed.output.revealed.position(target) != null;
}

const logs_mod = @import("logs.zig");

/// `Observe::reckon` over `pairs` taken as the selected logs.
fn reckon_pairs(
    gpa: Allocator,
    info: *const Info,
    pairs: []LogPair,
) !fd.Observed(MinPk, PublicKey) {
    std.mem.sort(LogPair, pairs, {}, struct {
        fn less(_: void, a: LogPair, b: LogPair) bool {
            return a[0].order(b[0]) == .lt;
        }
    }.less);
    const dealers = try gpa.alloc(PublicKey, pairs.len);
    defer gpa.free(dealers);
    const logs = try gpa.alloc(*const DealerLog, pairs.len);
    defer gpa.free(logs);
    for (dealers, logs, pairs) |*dealer, *log, *pair| {
        dealer.* = pair[0];
        log.* = &pair[1];
    }
    const selection: fd.Selection(MinPk, PublicKey) = .{
        .dealers = .{ .items = dealers },
        .logs = logs,
    };
    var observed = try logs_mod.reckon(MinPk, PublicKey, N3f1, gpa, info, selection);
    if (observed.weights) |*weights| weights.deinit(gpa);
    observed.weights = null;
    return observed;
}

test "feldman-desmedt: reveal threshold uses dealer set when dealers are fewer" {
    try testing.expect(try is_revealed_after(.v1, 4, 10, 2));
}

test "feldman-desmedt: reveal threshold uses dealer set when dealers are more" {
    try shared.skip_slow();
    try testing.expect(!try is_revealed_after(.v1, 13, 4, 4));
}

test "feldman-desmedt: legacy reveal threshold uses player set" {
    try testing.expect(!try is_revealed_after(.v0, 4, 10, 2));
}

test "feldman-desmedt: reveal v1 is committed to summary" {
    const gpa = testing.allocator;
    const keys = seeded_keys(4, 0);
    const combos = [_]struct { primitives.sharing.Mode, fd.Reveal }{
        .{ .non_zero_counter, .v0 }, .{ .roots_of_unity, .v0 },
        .{ .non_zero_counter, .v1 }, .{ .roots_of_unity, .v1 },
    };
    var infos: [combos.len]Info = undefined;
    var built: usize = 0;
    defer for (infos[0..built]) |*info| info.deinit(gpa);
    for (&infos, combos) |*info, combo| {
        info.* = try new_info(gpa, &keys, &keys, .{
            .namespace = "reveal-version-transcript-test",
            .mode = combo[0],
            .reveal = combo[1],
        });
        built += 1;
    }
    // Every combination identifies a distinct ceremony, and identity follows the summary.
    for (infos, 0..) |a, i| for (infos[i + 1 ..]) |b| {
        try testing.expect(!a.summary.eql(b.summary));
        try testing.expect(!a.eql(&b));
    };
}

test "feldman-desmedt: reveals reject cross-configured logs" {
    const gpa = testing.allocator;
    const dealer = [_]PrivateKey{PrivateKey.from_seed(0)};
    var v0 = try new_info(
        gpa,
        &dealer,
        &dealer,
        .{ .namespace = "reveal-version-signature-test", .reveal = .v0 },
    );
    defer v0.deinit(gpa);
    var v1 = try new_info(gpa, &dealer, &dealer, .{ .namespace = "reveal-version-signature-test" });
    defer v1.deinit(gpa);
    var rng = TestRng.init(0);
    var started = try Dealer.start(N3f1, gpa, &rng, &v0, dealer[0], null);
    started.pub_msg.deinit(gpa);
    gpa.free(started.priv_msgs);
    var log = try started.dealer.finalize(N3f1, gpa);
    defer log.deinit(gpa);
    // A V0 log stays valid in its ceremony but cannot enter a V1 ceremony.
    try testing.expect(try fd.check_log(MinPk, PublicKey, gpa, &v0, &log));
    try testing.expect(!try fd.check_log(MinPk, PublicKey, gpa, &v1, &log));
}

const RevealOutcome = struct { finalized: Output, observed: Output, target: PublicKey };

/// Two revealed dealings cross V1's dealer threshold but not V0's player threshold, so the
/// reveal calculation shows in the output; a player and an observer must agree on it.
fn reveal_outcome(gpa: Allocator, reveal: fd.Reveal) !RevealOutcome {
    const keys = seeded_keys(14, 3_000);
    const dealer_keys = keys[0..4];
    const player_keys = keys[4..];
    var info = try new_info(gpa, dealer_keys, player_keys, .{
        .namespace = "public-reveal-calculation-test",
        .reveal = reveal,
    });
    defer info.deinit(gpa);
    const target = player_keys[0].public_key();
    const finalizer = player_keys[1];
    var verified: std.ArrayList(LogPair) = .empty;
    defer free_pairs(gpa, &verified);
    var persisted: std.ArrayList(Persisted) = .empty;
    defer free_persisted(gpa, &persisted);
    var logs: Logs = .init(&info);
    defer logs.deinit(gpa);
    for (dealer_keys[0..3], 0..) |dealer_key, number| {
        var rng = TestRng.init(number + 4_000);
        const log = try deal_round(gpa, &info, player_keys, dealer_key, &rng, .{
            .skip = if (number < 2) target else null,
            .persist_for = finalizer.public_key(),
            .persisted = &persisted,
        });
        try verified.append(gpa, .{ dealer_key.public_key(), log });
        _ = try logs.record(gpa, dealer_key.public_key(), try log.clone(gpa));
    }
    var resumed = try Player.resume_from(
        N3f1,
        gpa,
        &info,
        finalizer,
        verified.items,
        persisted.items,
    );
    defer resumed.player.deinit(gpa);
    resumed.acks.deinit(gpa);
    var observe_logs = try logs.clone(gpa);
    defer observe_logs.deinit(gpa);
    var observe_rng = utils.test_rng();
    var observed = try fd.observe(MinPk, PublicKey, N3f1, gpa, &observe_rng, &observe_logs, null);
    errdefer observed.deinit(gpa);
    var finalize_rng = utils.test_rng();
    const finalized = try resumed.player.finalize(N3f1, gpa, &finalize_rng, &logs, null);
    return .{ .finalized = finalized.output, .observed = observed, .target = target };
}

test "feldman-desmedt: observers match players for each reveal calculation" {
    const gpa = testing.allocator;
    inline for (.{ fd.Reveal.v1, fd.Reveal.v0 }) |reveal| {
        var outcome = try reveal_outcome(gpa, reveal);
        defer {
            outcome.finalized.deinit(gpa);
            outcome.observed.deinit(gpa);
        }
        try testing.expect(outcome.finalized.eql(outcome.observed));
        const revealed = outcome.finalized.revealed.position(outcome.target) != null;
        try testing.expectEqual(reveal == .v1, revealed);
    }
}

test "feldman-desmedt: reveal threshold uses previous players during reshare" {
    const gpa = testing.allocator;
    const keys = seeded_keys(14, 2_000);
    var previous_players = try key_set(gpa, keys[0..10]);
    defer previous_players.deinit(gpa);
    var rng = TestRng.init(0);
    var dealt = try fd.deal(
        MinPk,
        PublicKey,
        N3f1,
        gpa,
        &rng,
        .non_zero_counter,
        try previous_players.clone(gpa),
    );
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    const dealers = try Set(PublicKey).init(gpa, previous_players.items[0..7]);
    const players = key_set(gpa, keys[10..]) catch |err| {
        var copy = dealers;
        copy.deinit(gpa);
        dealt.output.deinit(gpa);
        return err;
    };
    var info = try Info.init(
        N3f1,
        gpa,
        "reshare-reveal-threshold-test",
        1,
        dealt.output,
        .non_zero_counter,
        .v1,
        dealers,
        players,
    );
    defer info.deinit(gpa);
    try testing.expectEqual(7, info.required_commitments(N3f1));
    try testing.expectEqual(4, info.reveal_threshold(N3f1));
}

const pre_verify_dealers = 8;

/// Eight dealers over the same eight players, each with a log valid in round 0 and one whose
/// acks were signed for round 1. Built once (the dealings are slow in Debug) and never freed.
const PreVerifyFixture = struct {
    const Dealer8 = struct { key: PublicKey, valid: DealerLog, invalid: DealerLog };

    keys: [pre_verify_dealers]PrivateKey,
    info: Info,
    wrong_info: Info,
    dealers: [pre_verify_dealers]Dealer8,

    var cache: ?PreVerifyFixture = null;

    fn get() !*const PreVerifyFixture {
        if (cache == null) cache = try build(std.heap.page_allocator);
        return &cache.?;
    }

    fn build(gpa: Allocator) !PreVerifyFixture {
        var self: PreVerifyFixture = undefined;
        self.keys = seeded_keys(pre_verify_dealers, 0);
        self.info = try new_info(gpa, &self.keys, &self.keys, .{});
        self.wrong_info = try new_info(gpa, &self.keys, &self.keys, .{ .round = 1 });
        for (&self.dealers, self.info.dealers.items) |*dealer, key| {
            const index = for (self.keys, 0..) |k, i| {
                if (k.public_key().eql(key)) break i;
            } else unreachable;
            var rng = TestRng.init(index);
            const valid = try deal_round(gpa, &self.info, &self.keys, self.keys[index], &rng, .{});
            rng = TestRng.init(index);
            const invalid = try deal_round(
                gpa,
                &self.wrong_info,
                &self.keys,
                self.keys[index],
                &rng,
                .{},
            );
            // Only the transcript-bound signatures differ.
            try testing.expect(valid.pub_msg.eql(invalid.pub_msg));
            dealer.* = .{ .key = key, .valid = valid, .invalid = invalid };
        }
        return self;
    }

    fn required(self: *const PreVerifyFixture) u32 {
        return self.info.required_commitments(N3f1);
    }

    fn record(
        self: *const PreVerifyFixture,
        gpa: Allocator,
        logs: *Logs,
        index: usize,
        valid: bool,
    ) !void {
        const dealer = &self.dealers[index];
        const log = if (valid) dealer.valid else dealer.invalid;
        _ = try logs.record(gpa, dealer.key, try log.clone(gpa));
    }

    fn logs_for(
        self: *const PreVerifyFixture,
        gpa: Allocator,
        info: *const Info,
        valid: []const bool,
    ) !Logs {
        assert(valid.len == pre_verify_dealers);
        var logs: Logs = .init(info);
        errdefer logs.deinit(gpa);
        for (valid, 0..) |is_valid, index| try self.record(gpa, &logs, index, is_valid);
        return logs;
    }
};

const all_invalid: [pre_verify_dealers]bool = @splat(false);
const all_valid: [pre_verify_dealers]bool = @splat(true);

/// Records the logs in random batches, pre-verifying after each, and checks that selection
/// matches recording them all at once: the first `required` valid dealers in key order.
fn incremental_pre_verify_case(fixture: *const PreVerifyFixture, u: *minifuzz.Unstructured) !void {
    const gpa = testing.allocator;
    var valid: [pre_verify_dealers]bool = undefined;
    for (&valid) |*is_valid| is_valid.* = try u.arbitrary(bool);
    var order: [pre_verify_dealers]usize = undefined;
    for (&order, 0..) |*slot, i| slot.* = i;
    for (0..order.len) |index| {
        std.mem.swap(usize, &order[index], &order[u.int_in_range(usize, index, order.len - 1)]);
    }
    var incremental: Logs = .init(&fixture.info);
    defer incremental.deinit(gpa);
    var incremental_rng = utils.test_rng();
    var start: usize = 0;
    while (start < order.len) {
        const size = u.int_in_range(usize, 1, order.len - start);
        for (order[start..][0..size]) |index| try fixture.record(
            gpa,
            &incremental,
            index,
            valid[index],
        );
        try incremental.pre_verify(gpa, &incremental_rng);
        start += size;
    }
    var expected: std.ArrayList(PublicKey) = .empty;
    defer expected.deinit(gpa);
    for (fixture.dealers, valid) |dealer, is_valid| {
        if (is_valid and expected.items.len < fixture.required()) try expected.append(
            gpa,
            dealer.key,
        );
    }
    var fresh = try fixture.logs_for(gpa, &fixture.info, &valid);
    defer fresh.deinit(gpa);
    var fresh_rng = utils.test_rng();
    var fresh_selected = fresh.select(gpa, &fresh_rng, null);
    defer if (fresh_selected) |*s| s.deinit(gpa) else |_| {};
    var incremental_selected = incremental.select(gpa, &incremental_rng, null);
    defer if (incremental_selected) |*s| s.deinit(gpa) else |_| {};
    if (fresh_selected) |selected| {
        try testing.expectEqualSlices(PublicKey, expected.items, selected.dealers.items);
        const other = try incremental_selected;
        try testing.expectEqualSlices(PublicKey, selected.dealers.items, other.dealers.items);
    } else |err| {
        try testing.expectEqual(error.InsufficientLogs, err);
        try testing.expect(expected.items.len < fixture.required());
        try testing.expectError(error.InsufficientLogs, incremental_selected);
    }
}

test "feldman-desmedt: incremental pre-verify preserves dealer order" {
    const fixture = try PreVerifyFixture.get();
    const limit: u64 = if (builtin.mode == .debug) 8 else 64;
    try (minifuzz.Builder{}).with_search_limit(limit * build_options.fuzz_soak)
        .run(testing.allocator, fixture, incremental_pre_verify_case);
}

/// The results of a clone of `log`, which must hold results.
fn results_of(log: *DealerLog) *fd.DealerResult(PublicKey).Results {
    return &log.results.ok;
}

test "feldman-desmedt: check dealers reports invalid reveal" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    var log = try fixture.dealers[0].valid.clone(gpa);
    defer log.deinit(gpa);
    results_of(&log).values[0] = .{ .reveal = .init(Scalar.zero) };
    const check = try check_log_with(&fixture.info, fixture.dealers[0].key, &log);
    try testing.expect(check.eql(.{ .fault = .invalid_reveal }));
}

test "feldman-desmedt: dealer log identifies unexpected dealer" {
    const fixture = try PreVerifyFixture.get();
    const stranger = PrivateKey.from_seed(std.math.maxInt(u64)).public_key();
    try testing.expect(fixture.info.dealer_index(stranger) == null);
    const check = try check_log_with(&fixture.info, stranger, &fixture.dealers[0].valid);
    try testing.expect(check.eql(.unexpected_dealer));
}

/// A reshare round over participants `seed..seed + 4`, dealt with `TestRng(seed + 4)`.
fn reshare_info(gpa: Allocator, seed: u64) !Info {
    const keys = seeded_keys(4, seed);
    var participants = try key_set(gpa, &keys);
    defer participants.deinit(gpa);
    var rng = TestRng.init(seed + 4);
    var dealt = try fd.deal(
        MinPk,
        PublicKey,
        N3f1,
        gpa,
        &rng,
        .non_zero_counter,
        try participants.clone(gpa),
    );
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    return new_info(gpa, &keys, &keys, .{
        .namespace = "specific-reshare-error-test",
        .round = 1,
        .previous = dealt.output,
    });
}

/// A commitment of the right degree whose constant is not `expected`.
fn pub_msg_with_different_constant(
    gpa: Allocator,
    info: *const Info,
    expected: MinPk.Public,
    seed: u64,
) !DealerPubMsg {
    const degree = info.degree(N3f1);
    for ([_]Scalar{ Scalar.zero, Scalar.one }) |constant| {
        var rng = TestRng.init(seed);
        var poly = try Poly(Scalar).random_with_constant(gpa, &rng, degree, constant);
        defer poly.deinit(gpa);
        const commitment = try math.poly.commit(gpa, MinPk.Public, poly);
        var pub_msg: DealerPubMsg = .{ .commitment = commitment };
        if (!pub_msg.commitment.constant().eql(expected)) {
            try testing.expectEqual(degree, pub_msg.commitment.degree_exact());
            return pub_msg;
        }
        pub_msg.deinit(gpa);
    }
    unreachable; // Zero and one commit to different constants.
}

/// A degree-0 commitment to one: the wrong degree for the fixture's round.
fn degree_zero_pub_msg(gpa: Allocator) !DealerPubMsg {
    var rng = TestRng.init(10_000);
    var poly = try Poly(Scalar).random_with_constant(gpa, &rng, 0, Scalar.one);
    defer poly.deinit(gpa);
    return .{ .commitment = try math.poly.commit(gpa, MinPk.Public, poly) };
}

test "feldman-desmedt: dealer public message distinguishes fault reasons" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    const dealer = &fixture.dealers[0];
    const expected = fixture.info.degree(N3f1);
    try testing.expect(expected != 0);
    var log: DealerLog = .{
        .pub_msg = try degree_zero_pub_msg(gpa),
        .results = try dealer.valid.results.clone(gpa),
    };
    defer log.deinit(gpa);
    const check = try check_log_with(&fixture.info, dealer.key, &log);
    const fault: fd.FaultReason = .{
        .invalid_commitment_degree = .{ .expected = expected, .actual = 0 },
    };
    try testing.expect(check.eql(.{ .fault = fault }));

    var info = try reshare_info(gpa, 20_000);
    defer info.deinit(gpa);
    const reshare_dealer = info.dealers.items[0];
    const share_commitment = info.previous.?.share_commitment(reshare_dealer).?;
    var reshare_log: DealerLog = .{
        .pub_msg = try pub_msg_with_different_constant(gpa, &info, share_commitment, 20_005),
        .results = .too_many_reveals,
    };
    defer reshare_log.deinit(gpa);
    const reshare_check = try check_log_with(&info, reshare_dealer, &reshare_log);
    try testing.expect(reshare_check.eql(.{ .fault = .mismatched_reshare_commitment }));
}

test "feldman-desmedt: dealer public message distinguishes live errors" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    var pub_msg = try degree_zero_pub_msg(gpa);
    defer pub_msg.deinit(gpa);
    try testing.expect(pub_msg.commitment.degree_exact() != fixture.info.degree(N3f1));
    var player = try Player.init(&fixture.info, PrivateKey.from_seed(0));
    defer player.deinit(gpa);
    const zero: fd.DealerPrivMsg = .init(Scalar.zero);
    const degree_result = player.dealer_message(N3f1, gpa, fixture.dealers[0].key, pub_msg, zero);
    try testing.expectError(error.InvalidCommitmentDegree, degree_result);

    var info = try reshare_info(gpa, 20_000);
    defer info.deinit(gpa);
    const dealer = info.dealers.items[0];
    const share_commitment = info.previous.?.share_commitment(dealer).?;
    var reshare_msg = try pub_msg_with_different_constant(gpa, &info, share_commitment, 20_005);
    defer reshare_msg.deinit(gpa);
    var reshare_player = try Player.init(&info, PrivateKey.from_seed(20_000));
    defer reshare_player.deinit(gpa);
    const result = reshare_player.dealer_message(N3f1, gpa, dealer, reshare_msg, zero);
    try testing.expectError(error.MismatchedReshareCommitment, result);
}

test "feldman-desmedt: dealer log distinguishes unavailable and faulty outcomes" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    const dealer = &fixture.dealers[0];
    try testing.expect(
        (try check_log_with(&fixture.info, dealer.key, &dealer.valid)).eql(.available),
    );

    var truncated = try dealer.valid.clone(gpa);
    defer truncated.deinit(gpa);
    const results = results_of(&truncated);
    try results.truncate(gpa, results.len() - 1);
    const mismatched = try check_log_with(&fixture.info, dealer.key, &truncated);
    try testing.expect(mismatched.eql(.{ .fault = .mismatched_log_players }));

    var omitted = try dealer.valid.clone(gpa);
    defer omitted.deinit(gpa);
    omitted.results.deinit(gpa);
    omitted.results = .too_many_reveals;
    try testing.expect((try check_log_with(&fixture.info, dealer.key, &omitted)).eql(.unavailable));

    var excessive = try dealer.valid.clone(gpa);
    defer excessive.deinit(gpa);
    const count = fixture.info.max_reveals(N3f1) + 1;
    for (results_of(&excessive).values[0..count]) |*value| {
        value.* = .{ .reveal = .init(Scalar.one) };
    }
    const check = try check_log_with(&fixture.info, dealer.key, &excessive);
    try testing.expect(check.eql(.{ .fault = .excessive_reveals }));
}

test "feldman-desmedt: dealer log prioritizes excessive reveals" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    const dealer_sk = PrivateKey.from_seed(0);
    const dealer_pk = dealer_sk.public_key();
    const dealer = for (&fixture.dealers) |*d| {
        if (d.key.eql(dealer_pk)) break d;
    } else unreachable;
    // The dealer can authenticate a log holding a malformed acknowledgement.
    var log = try dealer.valid.clone(gpa);
    results_of(&log).values[0].ack.sig.raw = @splat(0xFF);
    var signed = try fd.sign_log(MinPk, PrivateKey, gpa, &dealer_sk, &fixture.info, log);
    defer signed.deinit(gpa);
    try testing.expect(try fd.check_log(MinPk, PublicKey, gpa, &fixture.info, &signed));
    const invalid = try check_log_with(&fixture.info, dealer_pk, &signed.log);
    try testing.expect(invalid.eql(.{ .fault = .invalid_ack }));

    // The reveal limit takes precedence even when the malformed acknowledgement is first.
    var excessive = try signed.log.clone(gpa);
    const count = fixture.info.max_reveals(N3f1) + 1;
    for (results_of(&excessive).values[1..][0..count]) |*value| {
        value.* = .{ .reveal = .init(Scalar.one) };
    }
    var resigned = try fd.sign_log(MinPk, PrivateKey, gpa, &dealer_sk, &fixture.info, excessive);
    defer resigned.deinit(gpa);
    try testing.expect(try fd.check_log(MinPk, PublicKey, gpa, &fixture.info, &resigned));
    const check = try check_log_with(&fixture.info, dealer_pk, &resigned.log);
    try testing.expect(check.eql(.{ .fault = .excessive_reveals }));
}

test "feldman-desmedt: logs are bound to constructor info" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    var logs = try fixture.logs_for(gpa, &fixture.info, &all_invalid);
    defer logs.deinit(gpa);
    var wrong_logs = try fixture.logs_for(gpa, &fixture.wrong_info, &all_invalid);
    defer wrong_logs.deinit(gpa);
    var rng = utils.test_rng();
    try logs.pre_verify(gpa, &rng);
    try wrong_logs.pre_verify(gpa, &rng);
    // Control: the logs verify in the round they were made for.
    var selection = try wrong_logs.select(gpa, &rng, null);
    selection.deinit(gpa);
    var failure: Failure = undefined;
    const result = fd.observe(MinPk, PublicKey, N3f1, gpa, &rng, &logs, &failure);
    try testing.expectError(error.InsufficientLogs, result);
    defer failure.deinit(gpa);
    try testing.expectEqual(fixture.required(), failure.required);
    try testing.expectEqual(0, failure.found);
    try testing.expectEqual(pre_verify_dealers, failure.faults.len);
    try testing.expect(failure.unavailable.is_empty());
    for (fixture.dealers) |dealer| {
        try testing.expectEqual(fd.FaultReason.invalid_ack, failure.fault(dealer.key).?);
    }
}

test "feldman-desmedt: pre-verify preserves classifications and invalidates replacements" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    var logs = try fixture.logs_for(gpa, &fixture.info, &all_valid);
    defer logs.deinit(gpa);
    try fixture.record(gpa, &logs, 0, false);
    var omitted = try fixture.dealers[1].valid.clone(gpa);
    omitted.results.deinit(gpa);
    omitted.results = .too_many_reveals;
    _ = try logs.record(gpa, fixture.dealers[1].key, omitted);
    var wrong_players = try fixture.dealers[2].valid.clone(gpa);
    const results = results_of(&wrong_players);
    results.truncate(gpa, results.len() - 1) catch |err| {
        wrong_players.deinit(gpa);
        return err;
    };
    _ = try logs.record(gpa, fixture.dealers[2].key, wrong_players);
    var rng = utils.test_rng();
    try logs.pre_verify(gpa, &rng);

    var copy = try logs.clone(gpa);
    defer copy.deinit(gpa);
    var failure: Failure = undefined;
    var observe_rng = utils.test_rng();
    const result = fd.observe(MinPk, PublicKey, N3f1, gpa, &observe_rng, &copy, &failure);
    try testing.expectError(error.InsufficientLogs, result);
    defer failure.deinit(gpa);
    try testing.expectEqual(fixture.required(), failure.required);
    try testing.expectEqual(pre_verify_dealers - 3, failure.found);
    try testing.expectEqual(2, failure.faults.len);
    try testing.expectEqual(fd.FaultReason.invalid_ack, failure.fault(fixture.dealers[0].key).?);
    try testing.expectEqual(1, failure.unavailable.len());
    try testing.expect(failure.unavailable.position(fixture.dealers[1].key) != null);
    try testing.expect(failure.fault(fixture.dealers[1].key) == null);
    const players_fault = failure.fault(fixture.dealers[2].key).?;
    try testing.expectEqual(fd.FaultReason.mismatched_log_players, players_fault);

    // Replacing one rejected log restores the exact quorum.
    try fixture.record(gpa, &logs, 0, true);
    var output_rng = utils.test_rng();
    var output = try fd.observe(MinPk, PublicKey, N3f1, gpa, &output_rng, &logs, null);
    output.deinit(gpa);
}

test "feldman-desmedt: missing logs report dealers as unavailable" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    var logs: Logs = .init(&fixture.info);
    defer logs.deinit(gpa);
    var failure: Failure = undefined;
    var rng = utils.test_rng();
    const result = fd.observe(MinPk, PublicKey, N3f1, gpa, &rng, &logs, &failure);
    try testing.expectError(error.InsufficientLogs, result);
    defer failure.deinit(gpa);
    try testing.expectEqual(fixture.required(), failure.required);
    try testing.expectEqual(0, failure.found);
    try testing.expectEqual(0, failure.faults.len);
    try testing.expect(failure.unavailable.eql(fixture.info.dealers));
}

test "feldman-desmedt: finalize wraps reconciliation failure" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    var player = try Player.init(&fixture.info, PrivateKey.from_seed(0));
    defer player.deinit(gpa);
    var logs: Logs = .init(&fixture.info);
    defer logs.deinit(gpa);
    var rng = utils.test_rng();
    try testing.expectError(error.InsufficientLogs, player.finalize(N3f1, gpa, &rng, &logs, null));
}

test "feldman-desmedt: finalize rejects logs bound to different round" {
    const gpa = testing.allocator;
    const fixture = try PreVerifyFixture.get();
    var player = try Player.init(&fixture.info, PrivateKey.from_seed(0));
    defer player.deinit(gpa);
    var wrong_logs = try fixture.logs_for(gpa, &fixture.wrong_info, &all_invalid);
    defer wrong_logs.deinit(gpa);
    var rng = utils.test_rng();
    try testing.expectError(
        error.MismatchedLogs,
        player.finalize(N3f1, gpa, &rng, &wrong_logs, null),
    );
}

/// A malicious dealer gives the target a stale dealing, then deals again; the target
/// resumes with the stale dealing persisted. With `replacement_ack` the target acked the
/// replacement (so finalize must reject the stale dealing); otherwise the replacement log
/// reveals the target's share (so finalize uses the reveal).
fn run_replaced_dealing(gpa: Allocator, replacement_ack: bool) !void {
    var keys = seeded_keys(4, 0);
    std.mem.sort(PrivateKey, &keys, {}, struct {
        fn less(_: void, a: PrivateKey, b: PrivateKey) bool {
            return a.public_key().order(b.public_key()) == .lt;
        }
    }.less);
    var info = try new_info(gpa, &keys, &keys, .{ .namespace = "stale-dealing-test" });
    defer info.deinit(gpa);
    const malicious = keys[0];
    const target_key = keys[3];
    const target = target_key.public_key();
    var persisted: std.ArrayList(Persisted) = .empty;
    defer free_persisted(gpa, &persisted);
    var stale_rng = TestRng.init(100);
    var stale = try Dealer.start(N3f1, gpa, &stale_rng, &info, malicious, null);
    stale.dealer.deinit(gpa);
    defer gpa.free(stale.priv_msgs);
    try persisted.append(gpa, .{
        .dealer = malicious.public_key(),
        .pub_msg = stale.pub_msg,
        .priv_msg = for (stale.priv_msgs) |msg| {
            if (msg.player.eql(target)) break msg.msg;
        } else unreachable,
    });
    var verified: std.ArrayList(LogPair) = .empty;
    defer free_pairs(gpa, &verified);
    var logs: Logs = .init(&info);
    defer logs.deinit(gpa);
    for (keys[0..3], 0..) |dealer_key, number| {
        var rng = TestRng.init(200 + number);
        const skip = number == 0 and !replacement_ack;
        const log = try deal_round(gpa, &info, &keys, dealer_key, &rng, .{
            .skip = if (skip) target else null,
            .persist_for = if (number != 0) target else null,
            .persisted = &persisted,
        });
        if (number == 0) {
            try testing.expect(!log.pub_msg.eql(persisted.items[0].pub_msg));
            try testing.expectEqual(!replacement_ack, log.get_reveal(target) != null);
        }
        try verified.append(gpa, .{ dealer_key.public_key(), log });
        _ = try logs.record(gpa, dealer_key.public_key(), try log.clone(gpa));
    }
    var resumed = try Player.resume_from(
        N3f1,
        gpa,
        &info,
        target_key,
        verified.items,
        persisted.items,
    );
    defer resumed.player.deinit(gpa);
    resumed.acks.deinit(gpa);
    var rng = utils.test_rng();
    const result = resumed.player.finalize(N3f1, gpa, &rng, &logs, null);
    if (replacement_ack) return testing.expectError(error.InvalidPersistedDealing, result);
    var finalized = try result;
    defer finalized.output.deinit(gpa);
    const expected = try finalized.output.public.partial_public(finalized.share.index);
    try testing.expect(finalized.share.public(MinPk).eql(expected));
}

test "feldman-desmedt: stale dealing is not reused for replaced log" {
    try run_replaced_dealing(testing.allocator, false);
}

test "feldman-desmedt: replacement ack rejects stale persisted dealing" {
    try run_replaced_dealing(testing.allocator, true);
}

test "feldman-desmedt: signed dealer log commitment" {
    const gpa = testing.allocator;
    const sk = [_]PrivateKey{PrivateKey.from_seed(0)};
    const pk = sk[0].public_key();
    var info = try new_info(gpa, &sk, &sk, .{});
    defer info.deinit(gpa);
    var rng0 = utils.test_rng();
    var started0 = try Dealer.start(N3f1, gpa, &rng0, &info, sk[0], null);
    started0.pub_msg.deinit(gpa);
    gpa.free(started0.priv_msgs);
    var log0 = try started0.dealer.finalize(N3f1, gpa);
    defer log0.deinit(gpa);
    var rng1 = utils.test_rng();
    var started1 = try Dealer.start(N3f1, gpa, &rng1, &info, sk[0], null);
    defer {
        started1.pub_msg.deinit(gpa);
        gpa.free(started1.priv_msgs);
    }
    var player = try Player.init(&info, sk[0]);
    defer player.deinit(gpa);
    const ack = (try player.dealer_message(
        N3f1,
        gpa,
        pk,
        started1.pub_msg,
        started1.priv_msgs[0].msg,
    )).?;
    try started1.dealer.receive_player_ack(pk, ack);
    var log1 = try started1.dealer.finalize(N3f1, gpa);
    defer log1.deinit(gpa);
    // Each signature binds its own log's contents.
    std.mem.swap(DealerLog, &log0.log, &log1.log);
    try testing.expect(!try fd.check_log(MinPk, PublicKey, gpa, &info, &log0));
    try testing.expect(!try fd.check_log(MinPk, PublicKey, gpa, &info, &log1));
}

test "feldman-desmedt: dealer message reports errors and skips duplicates" {
    const gpa = testing.allocator;
    const members = [_]PrivateKey{ PrivateKey.from_seed(0), PrivateKey.from_seed(1) };
    const a_pk = members[0].public_key();
    const stranger_pk = PrivateKey.from_seed(2).public_key();
    var info = try new_info(gpa, &members, &members, .{});
    defer info.deinit(gpa);
    var rng = utils.test_rng();
    var started = try Dealer.start(N3f1, gpa, &rng, &info, members[0], null);
    defer {
        started.dealer.deinit(gpa);
        started.pub_msg.deinit(gpa);
        gpa.free(started.priv_msgs);
    }
    const pub_msg = started.pub_msg;
    const index_a = info.players.position(a_pk).?;
    const priv_for_a = started.priv_msgs[index_a].msg;
    const priv_for_b = started.priv_msgs[1 - index_a].msg;

    // Persisted invalid input is reported as local state corruption.
    const persisted = [_]Persisted{.{ .dealer = a_pk, .pub_msg = pub_msg, .priv_msg = priv_for_a }};
    const resumed = Player.resume_from(N3f1, gpa, &info, members[1], &.{}, &persisted);
    try testing.expectError(error.InvalidPersistedDealing, resumed);

    var player = try Player.init(&info, members[1]);
    defer player.deinit(gpa);
    try testing.expectError(
        error.InvalidDealerShare,
        player.dealer_message(N3f1, gpa, a_pk, pub_msg, priv_for_a),
    );
    // Live message errors expose the rejection reason without attributing it.
    try testing.expectError(
        error.UnexpectedDealer,
        player.dealer_message(N3f1, gpa, stranger_pk, pub_msg, priv_for_b),
    );
    try testing.expect(try player.dealer_message(N3f1, gpa, a_pk, pub_msg, priv_for_b) != null);
    // Replaying a dealer's message is a benign skip.
    try testing.expect(try player.dealer_message(N3f1, gpa, a_pk, pub_msg, priv_for_b) == null);
}

test "feldman-desmedt: receive player ack reports non-attributable errors" {
    const gpa = testing.allocator;
    const a = [_]PrivateKey{PrivateKey.from_seed(0)};
    const a_pk = a[0].public_key();
    const stranger_pk = PrivateKey.from_seed(1).public_key();
    var info = try new_info(gpa, &a, &a, .{});
    defer info.deinit(gpa);
    var rng = TestRng.init(0);
    var started = try Dealer.start(N3f1, gpa, &rng, &info, a[0], null);
    defer {
        started.dealer.deinit(gpa);
        started.pub_msg.deinit(gpa);
        gpa.free(started.priv_msgs);
    }
    var alternate_rng = TestRng.init(1);
    var alternate = try Dealer.start(N3f1, gpa, &alternate_rng, &info, a[0], null);
    defer {
        alternate.dealer.deinit(gpa);
        alternate.pub_msg.deinit(gpa);
        gpa.free(alternate.priv_msgs);
    }
    try testing.expect(!started.pub_msg.eql(alternate.pub_msg));
    var player = try Player.init(&info, a[0]);
    defer player.deinit(gpa);
    const ack = (try player.dealer_message(
        N3f1,
        gpa,
        a_pk,
        started.pub_msg,
        started.priv_msgs[0].msg,
    )).?;
    // An honest player can ack an equivocating dealer's alternate message, so a signature
    // mismatch cannot identify a faulty player.
    var alternate_player = try Player.init(&info, a[0]);
    defer alternate_player.deinit(gpa);
    const alternate_ack = (try alternate_player.dealer_message(
        N3f1,
        gpa,
        a_pk,
        alternate.pub_msg,
        alternate.priv_msgs[0].msg,
    )).?;
    try testing.expectError(
        error.InvalidAck,
        started.dealer.receive_player_ack(a_pk, alternate_ack),
    );
    try testing.expectError(
        error.UnexpectedPlayer,
        started.dealer.receive_player_ack(stranger_pk, ack),
    );
    try started.dealer.receive_player_ack(a_pk, ack);
}

test "feldman-desmedt: info with different mode is not equal" {
    const gpa = testing.allocator;
    const sk = [_]PrivateKey{PrivateKey.from_seed(0)};
    var counter = try new_info(gpa, &sk, &sk, .{});
    defer counter.deinit(gpa);
    var roots = try new_info(gpa, &sk, &sk, .{ .mode = .roots_of_unity });
    defer roots.deinit(gpa);
    try testing.expect(!counter.eql(&roots));
}

test "feldman-desmedt: resume ignores invalid logged ack signature" {
    const gpa = testing.allocator;
    const dealer_sk = [_]PrivateKey{PrivateKey.from_seed(11)};
    const player_sk = [_]PrivateKey{PrivateKey.from_seed(22)};
    const dealer_pk = dealer_sk[0].public_key();
    const player_pk = player_sk[0].public_key();
    var info = try new_info(gpa, &dealer_sk, &player_sk, .{});
    defer info.deinit(gpa);
    var wrong_round = try new_info(gpa, &dealer_sk, &player_sk, .{ .round = 1 });
    defer wrong_round.deinit(gpa);
    var rng = utils.test_rng();
    var started = try Dealer.start(N3f1, gpa, &rng, &info, dealer_sk[0], null);
    started.dealer.deinit(gpa);
    gpa.free(started.priv_msgs);
    const round = wrong_round.round_transcript();
    const transcript = try fd.transcript_for_ack(
        gpa,
        &round,
        MinPk,
        PublicKey,
        dealer_pk,
        started.pub_msg,
    );
    const bad_ack: fd.PlayerAck(PublicKey) = .{ .sig = transcript.sign(&player_sk[0]) };
    const results = try Map(PublicKey, fd.AckOrReveal(PublicKey)).init(
        gpa,
        &.{.{ player_pk, .{ .ack = bad_ack } }},
    );
    const log: DealerLog = .{ .pub_msg = started.pub_msg, .results = .{ .ok = results } };
    var logs = [_]LogPair{.{ dealer_pk, log }};
    defer logs[0][1].deinit(gpa);
    var resumed = try Player.resume_from(N3f1, gpa, &info, player_sk[0], &logs, &.{});
    defer resumed.player.deinit(gpa);
    defer resumed.acks.deinit(gpa);
    try testing.expect(resumed.acks.is_empty());
}

test "feldman-desmedt: dealer priv msg redacted" {
    var rng = utils.test_rng();
    const msg: fd.DealerPrivMsg = .init(Scalar.random(&rng));
    var buffer: [128]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{msg});
    try testing.expect(std.mem.indexOf(u8, text, "REDACTED") != null);
}

test "feldman-desmedt: dealer priv msg decode rejects zero scalar" {
    const encoded = Scalar.zero.to_bytes();
    try testing.expect(
        std.meta.isError(codec.decode(fd.DealerPrivMsg, testing.allocator, &encoded)),
    );
}

test "feldman-desmedt: dealer pub msg decode rejects zero commitment" {
    const gpa = testing.allocator;
    var rng = utils.test_rng();
    var poly = try Poly(Scalar).random_with_constant(gpa, &rng, 0, Scalar.zero);
    defer poly.deinit(gpa);
    var pub_msg: DealerPubMsg = .{ .commitment = try math.poly.commit(gpa, MinPk.Public, poly) };
    defer pub_msg.deinit(gpa);
    const encoded = try codec.encode(DealerPubMsg, gpa, pub_msg);
    defer gpa.free(encoded);
    const decoded = codec.decode_cfg(DealerPubMsg, gpa, encoded, 1);
    if (decoded) |value| {
        var copy = value;
        copy.deinit(gpa);
        return error.TestUnexpectedResult;
    } else |_| {}
}
