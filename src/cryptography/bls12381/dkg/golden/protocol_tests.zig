//! Golden DKG protocol tests (commonware `dkg/golden/mod.rs` tests that deal): the test
//! plan's happy, perturbed, and reshare cases, the error paths, codec round trips, and the
//! fuzz plan. Every case proves eVRF outputs with bulletproofs, so they run only with
//! `-Dslow-tests` (the nightly workflow): each takes one to two minutes in ReleaseSafe.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const math = @import("math");
const parallel = @import("parallel");
const build_options = @import("build_options");
const minifuzz = @import("invariants").minifuzz;
const golden = @import("../golden.zig");
const plan_mod = @import("plan.zig");
const primitives = @import("../../primitives/root.zig");
const shared = @import("../../conformance_test.zig");

const Info = golden.Info;
const Output = golden.Output(golden.PublicKey);
const Logs = golden.Logs;
const Setup = golden.Setup;
const PrivateKey = golden.PrivateKey;
const PublicKey = golden.PublicKey;
const SignedDealerLog = golden.SignedDealerLog;
const Plan = plan_mod.Plan;
const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const N3f1 = utils.N3f1;
const N5f1 = utils.N5f1;
const TestRng = utils.rng.TestRng;
const Scalar = primitives.group.Scalar;
const gpa = testing.allocator;

const test_namespace = "test";

var cached_setup: ?Setup = null;

/// A setup for up to 7 players, built once per test binary (commonware's `TEST_SETUP`). It
/// lives for the whole run, so it uses the page allocator rather than the leak-checked one.
fn test_setup() !*const Setup {
    if (cached_setup == null) cached_setup = try Setup.init(std.heap.page_allocator, 7);
    return &cached_setup.?;
}

fn run_plan(plan: Plan) !void {
    try shared.skip_heavy();
    try plan.run(gpa, try test_setup(), 42);
}

test "golden: single dealer, single player" {
    try run_plan(.init(1, 1, 0));
}

test "golden: multiple dealers, multiple players" {
    try run_plan(.init(4, 7, 3));
}

test "golden: many dealers" {
    try run_plan(.init(10, 5, 0));
}

test "golden: a bad signature is filtered" {
    try run_plan(Plan.init(4, 7, 3).bad_signature(0));
}

test "golden: too many bad signatures fail the round" {
    try run_plan(Plan.init(4, 7, 3).bad_signature(0).bad_signature(1).bad_signature(2));
}

test "golden: a bad share is filtered" {
    try run_plan(Plan.init(4, 7, 3).bad_share(0, 1));
}

test "golden: too many bad shares fail the round" {
    try run_plan(Plan.init(4, 7, 3).bad_share(0, 1).bad_share(1, 2).bad_share(2, 3));
}

test "golden: a bad commitment is filtered" {
    try run_plan(Plan.init(4, 7, 3).bad_commitment(0));
}

test "golden: a missing share is filtered" {
    try run_plan(Plan.init(4, 7, 3).missing_share(0, 1));
}

test "golden: a shifted degree is filtered" {
    try run_plan(Plan.init(4, 7, 3).shift_degree(0, 1));
}

test "golden: insufficient dealers fail the round" {
    try run_plan(Plan.init(4, 7, 3).drop_dealer(0).drop_dealer(1).drop_dealer(2));
}

test "golden: reshare" {
    try run_plan(Plan.init(4, 7, 3).with_reshare());
}

test "golden: a replaced reshare share is filtered" {
    try run_plan(Plan.init(4, 7, 3).with_reshare().replace_share(0));
}

test "golden: too many replaced reshare shares fail the round" {
    const plan = Plan.init(4, 7, 3).with_reshare();
    try run_plan(plan.replace_share(0).replace_share(1).replace_share(2));
}

// commonware ignores this case: its `check_batch` comment predates the per-dealer fallback.
// With the fallback, the faking dealer alone is dropped and the round succeeds.
test "golden: a fake mask is filtered" {
    try run_plan(Plan.init(4, 7, 3).fake_mask(0));
}

fn random_keys(rng: *TestRng, out: []PrivateKey) void {
    for (out) |*key| key.* = PrivateKey.random(rng);
}

fn round_info(round: u64, dealers: []const PrivateKey, players: []const PrivateKey) !Info {
    return plan_mod.make_info(gpa, round, null, dealers, players);
}

test "golden: output dealers exclude filtered dealers" {
    try shared.skip_heavy();
    const setup = try test_setup();
    var rng = utils.test_rng();
    var dealers: [4]PrivateKey = undefined;
    random_keys(&rng, &dealers);
    var players: [4]PrivateKey = undefined;
    random_keys(&rng, &players);
    var info = try round_info(0, &dealers, &players);
    defer info.deinit(gpa);
    var pairs: std.ArrayList(Logs.Pair) = .empty;
    defer pairs.deinit(gpa);
    for (&dealers, 0..) |*dealer, i| {
        var signed = try golden.deal(gpa, &rng, setup, &info, dealer, null, parallel.sequential);
        // Corrupt one dealer's signature so `identify` drops it.
        if (i == 0) signed.signature.raw[0] ^= 0xFF;
        const identified = (try signed.identify(gpa, &info)) orelse continue;
        try pairs.append(gpa, identified);
    }
    try testing.expectEqual(3, pairs.items.len);
    var logs = try Logs.init(gpa, pairs.items);
    defer logs.deinit(gpa);
    var output = try golden.observe(gpa, &rng, setup, &info, &logs);
    defer output.deinit(gpa);
    try testing.expect(output.dealers.eql(logs.keys));
    try testing.expect(!output.dealers.eql(info.dealers));
}

test "golden: unknown dealer" {
    try shared.skip_heavy();
    const setup = try test_setup();
    var rng = utils.test_rng();
    var keys: [8]PrivateKey = undefined;
    random_keys(&rng, &keys);
    var info = try round_info(0, keys[0..4], keys[4..]);
    defer info.deinit(gpa);
    const outsider = PrivateKey.random(&rng);
    const result = golden.deal(gpa, &rng, setup, &info, &outsider, null, parallel.sequential);
    try testing.expectError(error.UnknownDealer, result);
}

test "golden: unknown player" {
    try shared.skip_heavy();
    const setup = try test_setup();
    var rng = utils.test_rng();
    var keys: [8]PrivateKey = undefined;
    random_keys(&rng, &keys);
    var info = try round_info(0, keys[0..4], keys[4..]);
    defer info.deinit(gpa);
    var logs = try plan_mod.deal_honestly(gpa, &rng, setup, &info, keys[0..4]);
    defer logs.deinit(gpa);
    const outsider = PrivateKey.random(&rng);
    const result = golden.play(gpa, &rng, setup, &info, &logs, &outsider);
    try testing.expectError(error.UnknownPlayer, result);
}

test "golden: a reshare dealer needs its previous share" {
    try shared.skip_heavy();
    const setup = try test_setup();
    var rng = utils.test_rng();
    var keys: [8]PrivateKey = undefined;
    random_keys(&rng, &keys);
    const dealers = keys[0..4];
    var fresh = try plan_mod.run_fresh(gpa, &rng, setup, dealers, dealers);
    defer fresh.deinit(gpa);
    var info = try plan_mod.make_info(gpa, 1, try fresh.output.clone(gpa), dealers, keys[4..]);
    defer info.deinit(gpa);
    const result = golden.deal(gpa, &rng, setup, &info, &dealers[0], null, parallel.sequential);
    try testing.expectError(error.MissingDealerShare, result);
}

const max_players_cfg: golden.dealing.ReadCfg = .{
    .max_players = 7,
    .max_supported_mode = .v0,
};

test "golden: signed dealer log round trip" {
    try shared.skip_heavy();
    const setup = try test_setup();
    var rng = utils.test_rng();
    var keys: [11]PrivateKey = undefined;
    random_keys(&rng, &keys);
    const dealers = keys[0..4];
    var info = try round_info(0, dealers, keys[4..]);
    defer info.deinit(gpa);
    const strategy = parallel.sequential;
    var signed = try golden.deal(gpa, &rng, setup, &info, &dealers[0], null, strategy);
    const bytes = codec.encode(SignedDealerLog, gpa, signed) catch |err| {
        signed.deinit(gpa);
        return err;
    };
    defer gpa.free(bytes);
    signed.deinit(gpa);
    const decoded = try codec.decode_cfg(SignedDealerLog, gpa, bytes, max_players_cfg);
    // The decoded log identifies and finalizes a round with the other dealers' logs.
    const dealer, const log = (try decoded.identify(gpa, &info)).?;
    try testing.expect(dealer.eql(dealers[0].public_key()));
    var others = try plan_mod.deal_honestly(gpa, &rng, setup, &info, dealers[1..]);
    defer others.deinit(gpa);
    var pairs: [4]Logs.Pair = undefined;
    pairs[0] = .{ dealer, log };
    for (pairs[1..], others.keys.items, others.values) |*pair, key, value| pair.* = .{ key, value };
    // The logs moved into `pairs`; release only the containers.
    others.keys.deinit(gpa);
    gpa.free(others.values);
    others = .empty;
    var logs = try Logs.init(gpa, &pairs);
    defer logs.deinit(gpa);
    var output = try golden.observe(gpa, &rng, setup, &info, &logs);
    output.deinit(gpa);
}

test "golden: output round trip" {
    try shared.skip_heavy();
    const setup = try test_setup();
    var rng = utils.test_rng();
    var keys: [11]PrivateKey = undefined;
    random_keys(&rng, &keys);
    var fresh = try plan_mod.run_fresh(gpa, &rng, setup, keys[0..4], keys[4..]);
    defer fresh.deinit(gpa);
    const bytes = try codec.encode(Output, gpa, fresh.output);
    defer gpa.free(bytes);
    var decoded = try codec.decode_cfg(Output, gpa, bytes, .{
        .max_participants = 7,
        .max_supported_mode = .v0,
    });
    defer decoded.deinit(gpa);
    try testing.expect(fresh.output.eql(decoded));
}

test "golden: an unsupported player count is reported" {
    try shared.skip_heavy();
    var small = try Setup.init(gpa, 3);
    defer small.deinit(gpa);
    var rng = utils.test_rng();
    var keys: [8]PrivateKey = undefined;
    random_keys(&rng, &keys);
    var info = try round_info(0, keys[0..4], keys[4..]);
    defer info.deinit(gpa);
    const dealt = golden.deal(gpa, &rng, &small, &info, &keys[0], null, parallel.sequential);
    try testing.expectError(error.UnsupportedNumPlayers, dealt);
    var logs: Logs = .empty;
    try testing.expectError(
        error.UnsupportedNumPlayers,
        golden.observe(gpa, &rng, &small, &info, &logs),
    );
    try testing.expectError(
        error.UnsupportedNumPlayers,
        golden.play(gpa, &rng, &small, &info, &logs, &keys[4]),
    );
}

test "golden: a missing self share in an overlap round is rejected" {
    try shared.skip_heavy();
    const setup = try test_setup();
    var rng = utils.test_rng();
    const me = PrivateKey.random(&rng);
    const me_public = me.public_key();
    // The only dealer is the only player.
    var info = try round_info(0, (&me)[0..1], (&me)[0..1]);
    defer info.deinit(gpa);
    var logs = try plan_mod.deal_honestly(gpa, &rng, setup, &info, (&me)[0..1]);
    defer logs.deinit(gpa);
    const shares = &logs.values[0].dealing.masked_shares;
    try testing.expect(shares.get_value(me_public) != null);
    // Strip the self row, leaving the rest of the dealing intact.
    const stripped = try Map(PublicKey, Scalar).init(gpa, &.{});
    shares.deinit(gpa);
    shares.* = stripped;
    try testing.expectError(error.DkgFailed, golden.observe(gpa, &rng, setup, &info, &logs));
    try testing.expectError(error.DkgFailed, golden.play(gpa, &rng, setup, &info, &logs, &me));
}

/// Checks that `signed` identifies for exactly the first of `rounds`.
fn expect_identifies_first(signed: SignedDealerLog, rounds: []const *const Info) !void {
    const bytes = try codec.encode(SignedDealerLog, gpa, signed);
    defer gpa.free(bytes);
    for (rounds, 0..) |round, index| {
        const copy = try codec.decode_cfg(SignedDealerLog, gpa, bytes, max_players_cfg);
        var result = try copy.identify(gpa, round);
        defer if (result) |*identified| identified[1].deinit(gpa);
        try testing.expectEqual(index == 0, result != null);
    }
}

test "golden: identify is bound to the round number" {
    try shared.skip_heavy();
    const setup = try test_setup();
    var rng = utils.test_rng();
    var keys: [2]PrivateKey = undefined;
    random_keys(&rng, &keys);
    var info = try round_info(0, keys[0..1], keys[1..]);
    defer info.deinit(gpa);
    var next_round = try round_info(1, keys[0..1], keys[1..]);
    defer next_round.deinit(gpa);
    var signed = try golden.deal(gpa, &rng, setup, &info, &keys[0], null, parallel.sequential);
    defer signed.deinit(gpa);
    try expect_identifies_first(signed, &.{ &info, &next_round });
}

test "golden: identify is bound to the round summary" {
    try shared.skip_heavy();
    const setup = try test_setup();
    var rng = utils.test_rng();
    var keys: [6]PrivateKey = undefined;
    random_keys(&rng, &keys);
    const dealers = keys[0..4];
    var info = try round_info(0, dealers, keys[4..]);
    defer info.deinit(gpa);
    var other_namespace = try Info.init(
        N3f1,
        gpa,
        "other",
        0,
        null,
        try info.dealers.clone(gpa),
        try info.players.clone(gpa),
    );
    defer other_namespace.deinit(gpa);
    var other_faults = try Info.init(
        N5f1,
        gpa,
        test_namespace,
        0,
        null,
        try info.dealers.clone(gpa),
        try info.players.clone(gpa),
    );
    defer other_faults.deinit(gpa);
    var signed = try golden.deal(gpa, &rng, setup, &info, &dealers[0], null, parallel.sequential);
    defer signed.deinit(gpa);
    try expect_identifies_first(signed, &.{ &info, &other_namespace, &other_faults });
}

/// commonware's `bls12381_dkg_golden` fuzz target: an arbitrary plan and seed; every
/// generated plan must run to completion.
fn fuzz_plan_body(_: void, u: *minifuzz.Unstructured) !void {
    const plan = plan_mod.arbitrary(u);
    const seed = try u.arbitrary(u64);
    try plan.run(gpa, try test_setup(), seed);
}

test "golden: fuzz plan" {
    try shared.skip_heavy();
    try (minifuzz.Builder{}).with_search_limit(2 * build_options.fuzz_soak)
        .run(gpa, {}, fuzz_plan_body);
}

test "golden: fuzz plan (coverage-guided)" {
    try shared.skip_heavy();
    try testing.fuzz({}, math.testing.smith_body(void, fuzz_plan_body), .{});
}
