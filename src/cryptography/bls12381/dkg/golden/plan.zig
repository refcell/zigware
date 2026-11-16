//! The golden DKG test plan (commonware `golden::test_plan`): a fresh DKG (or a reshare
//! after an honest fresh round) with optional perturbations, checking that a "star" player
//! recovers a share that matches the public output, or that the round fails when too few
//! honest dealers remain. The fuzz target and commonware's tests drive it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const math = @import("math");
const parallel = @import("parallel");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const primitives = @import("../../primitives/root.zig");
const golden = @import("../golden.zig");

const Info = golden.Info;
const Output = golden.Output(golden.PublicKey);
const Logs = golden.Logs;
const Setup = golden.Setup;
const PrivateKey = golden.PrivateKey;
const PublicKey = golden.PublicKey;
const DealerLog = golden.DealerLog;
const SignedDealerLog = golden.SignedDealerLog;
const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const N3f1 = utils.N3f1;
const TestRng = utils.rng.TestRng;
const Poly = math.poly.Poly;
const group = primitives.group;
const Scalar = group.Scalar;
const G1 = group.G1;
const Share = group.Share;
const Private = group.Private;
const MinPk = primitives.MinPk;

/// The largest dealer or player count `arbitrary` generates; a setup this size fits every
/// generated plan.
pub const max_participants: u32 = 7;
/// The most dealers or players a plan holds (commonware's tests use up to 10 dealers).
pub const max_plan_participants = 16;

const Mask = u16;
comptime {
    assert(@bitSizeOf(Mask) == max_plan_participants);
}

fn bit(index: u32) Mask {
    assert(index < max_plan_participants);
    return @as(Mask, 1) << @intCast(index);
}

/// A plan; perturbations are sets of dealers (bit masks) or of `(dealer, player)` pairs
/// (a player mask per dealer).
pub const Plan = struct {
    num_dealers: u32,
    num_players: u32,
    star: u32,
    bad_signatures: Mask = 0,
    bad_shares: [max_plan_participants]Mask = @splat(0),
    bad_commitments: Mask = 0,
    missing_shares: [max_plan_participants]Mask = @splat(0),
    shift_degrees: [max_plan_participants]i32 = @splat(0),
    drop_dealers: Mask = 0,
    reshare: bool = false,
    replace_shares: Mask = 0,
    fake_masks: Mask = 0,

    pub fn init(num_dealers: u32, num_players: u32, star: u32) Plan {
        assert(num_dealers <= max_plan_participants and num_players <= max_plan_participants);
        return .{ .num_dealers = num_dealers, .num_players = num_players, .star = star };
    }

    pub fn bad_signature(self: Plan, dealer: u32) Plan {
        var plan = self;
        plan.bad_signatures |= bit(dealer);
        return plan;
    }

    pub fn bad_share(self: Plan, dealer: u32, player: u32) Plan {
        var plan = self;
        plan.bad_shares[dealer] |= bit(player);
        return plan;
    }

    pub fn bad_commitment(self: Plan, dealer: u32) Plan {
        var plan = self;
        plan.bad_commitments |= bit(dealer);
        return plan;
    }

    pub fn missing_share(self: Plan, dealer: u32, player: u32) Plan {
        var plan = self;
        plan.missing_shares[dealer] |= bit(player);
        return plan;
    }

    pub fn shift_degree(self: Plan, dealer: u32, shift: i32) Plan {
        var plan = self;
        plan.shift_degrees[dealer] = shift;
        return plan;
    }

    pub fn drop_dealer(self: Plan, dealer: u32) Plan {
        var plan = self;
        plan.drop_dealers |= bit(dealer);
        return plan;
    }

    pub fn with_reshare(self: Plan) Plan {
        var plan = self;
        plan.reshare = true;
        return plan;
    }

    pub fn replace_share(self: Plan, dealer: u32) Plan {
        var plan = self;
        plan.replace_shares |= bit(dealer);
        return plan;
    }

    pub fn fake_mask(self: Plan, dealer: u32) Plan {
        var plan = self;
        plan.fake_masks |= bit(dealer);
        return plan;
    }

    pub fn valid(self: *const Plan) bool {
        if (self.num_dealers < 1 or self.num_players < 1) return false;
        if (self.num_dealers > max_plan_participants) return false;
        if (self.num_players > max_plan_participants) return false;
        if (self.star >= self.num_players) return false;
        const dealers: Mask = @truncate((@as(u32, 1) << @intCast(self.num_dealers)) - 1);
        const players: Mask = @truncate((@as(u32, 1) << @intCast(self.num_players)) - 1);
        const masks = [_]Mask{
            self.bad_signatures, self.bad_commitments, self.drop_dealers,
            self.replace_shares, self.fake_masks,
        };
        for (masks) |mask| if (mask & ~dealers != 0) return false;
        if (self.replace_shares != 0 and !self.reshare) return false;
        for (0..max_plan_participants) |d| {
            const pairs = self.bad_shares[d] | self.missing_shares[d];
            const in_range = d < self.num_dealers;
            if (pairs & ~players != 0 or (!in_range and pairs != 0)) return false;
            if (!in_range and self.shift_degrees[d] != 0) return false;
        }
        return true;
    }

    /// Whether `check` filters the dealer's log.
    fn is_bad_dealer(self: *const Plan, dealer: u32) bool {
        const b = bit(dealer);
        return self.bad_commitments & b != 0 or self.shift_degree_effective(dealer) or
            self.replace_shares & b != 0 or self.fake_masks & b != 0 or
            self.bad_shares[dealer] != 0 or self.missing_shares[dealer] != 0;
    }

    fn shifted_degree(self: *const Plan, dealer: u32, degree: u32) u32 {
        const shifted = @as(i64, degree) + self.shift_degrees[dealer];
        return @intCast(@max(shifted, 0));
    }

    fn shift_degree_effective(self: *const Plan, dealer: u32) bool {
        const degree = N3f1.quorum(self.num_players) -| 1;
        return self.shifted_degree(dealer, degree) != degree;
    }

    fn expect_failure(self: *const Plan) bool {
        var honest: u32 = 0;
        for (0..self.num_dealers) |d| {
            const dealer: u32 = @intCast(d);
            const b = bit(dealer);
            if (self.drop_dealers & b != 0 or self.bad_signatures & b != 0) continue;
            if (self.is_bad_dealer(dealer)) continue;
            honest += 1;
        }
        // In a reshare the dealers were the previous round's players.
        return honest < N3f1.quorum(self.num_dealers);
    }

    /// Runs the plan from `seed`; fails (returns an error) when a check does not hold.
    pub fn run(self: Plan, gpa: Allocator, setup: *const Setup, seed: u64) !void {
        if (!self.valid()) return error.InvalidPlan;
        var rng = TestRng.init(seed);
        var dealer_keys: [max_plan_participants]PrivateKey = undefined;
        for (dealer_keys[0..self.num_dealers]) |*key| key.* = PrivateKey.random(&rng);
        var player_keys: [max_plan_participants]PrivateKey = undefined;
        for (player_keys[0..self.num_players]) |*key| key.* = PrivateKey.random(&rng);
        const dealers = dealer_keys[0..self.num_dealers];
        const players = player_keys[0..self.num_players];

        var previous: ?Fresh = null;
        defer if (previous) |*fresh| fresh.deinit(gpa);
        if (self.reshare) previous = try run_fresh(gpa, &rng, setup, dealers, dealers);
        const prior = if (previous) |fresh| try fresh.output.clone(gpa) else null;
        var info = try make_info(gpa, if (self.reshare) 1 else 0, prior, dealers, players);
        defer info.deinit(gpa);

        var logs = try self.deal_all(gpa, &rng, setup, &info, dealers, players, previous);
        defer logs.deinit(gpa);
        try self.finish(gpa, &rng, setup, &info, &logs, &players[self.star]);
    }

    /// Every dealer's identified (and perturbed) log.
    fn deal_all(
        self: *const Plan,
        gpa: Allocator,
        rng: *TestRng,
        setup: *const Setup,
        info: *const Info,
        dealers: []const PrivateKey,
        players: []const PrivateKey,
        previous: ?Fresh,
    ) !Logs {
        var signed_logs: std.ArrayList(struct { u32, SignedDealerLog }) = .empty;
        defer {
            for (signed_logs.items) |*item| item[1].deinit(gpa);
            signed_logs.deinit(gpa);
        }
        for (dealers, 0..) |*dealer, d| {
            const i: u32 = @intCast(d);
            if (self.drop_dealers & bit(i) != 0) continue;
            try signed_logs.ensureUnusedCapacity(gpa, 1);
            const share = self.dealer_share(rng, previous, i);
            var signed = try self.deal_one(gpa, rng, setup, info, dealer, share, i);
            if (self.bad_signatures & bit(i) != 0) signed.signature.raw[0] ^= 0xFF;
            signed_logs.appendAssumeCapacity(.{ i, signed });
        }
        var pairs: std.ArrayList(Logs.Pair) = .empty;
        defer pairs.deinit(gpa);
        errdefer for (pairs.items) |*pair| pair[1].deinit(gpa);
        while (signed_logs.items.len > 0) {
            try pairs.ensureUnusedCapacity(gpa, 1);
            const i, const signed = signed_logs.orderedRemove(0);
            const dealer, var log = (try signed.identify(gpa, info)) orelse continue;
            self.perturb(gpa, rng, info, i, players, &log) catch |err| {
                log.deinit(gpa);
                return err;
            };
            pairs.appendAssumeCapacity(.{ dealer, log });
        }
        const items = try pairs.toOwnedSlice(gpa);
        defer gpa.free(items);
        // `init` takes the items, also when it fails.
        return Logs.init(gpa, items);
    }

    fn dealer_share(self: *const Plan, rng: *TestRng, previous: ?Fresh, dealer: u32) ?Share {
        const fresh = previous orelse return null;
        const share = fresh.shares[dealer];
        if (self.replace_shares & bit(dealer) == 0) return share;
        return Share.init(share.index, Private.init(Scalar.random(rng)));
    }

    /// An honest dealing, or one whose polynomial has a shifted degree (which `check`
    /// rejects).
    fn deal_one(
        self: *const Plan,
        gpa: Allocator,
        rng: *TestRng,
        setup: *const Setup,
        info: *const Info,
        dealer: *const PrivateKey,
        share: ?Share,
        i: u32,
    ) !SignedDealerLog {
        const strategy = parallel.sequential;
        const degree = info.degree();
        const shifted = self.shifted_degree(i, degree);
        if (shifted == degree) return golden.deal(gpa, rng, setup, info, dealer, share, strategy);
        const private: ?Scalar = if (share) |s| s.private.scalar else null;
        const constant = try info.unwrap_or_random_share(rng, private);
        var poly = try Poly(Scalar).random_with_constant(gpa, rng, shifted, constant);
        defer poly.deinit(gpa);
        return golden.deal_poly(gpa, rng, setup, info, dealer, poly, strategy);
    }

    /// The bad share, bad commitment, missing share, and fake mask perturbations.
    fn perturb(
        self: *const Plan,
        gpa: Allocator,
        rng: *TestRng,
        info: *const Info,
        i: u32,
        players: []const PrivateKey,
        log: *DealerLog,
    ) !void {
        const dealing = &log.dealing;
        for (players, 0..) |player, p| {
            if (self.bad_shares[i] & bit(@intCast(p)) == 0) continue;
            const value = dealing.masked_shares.get_value_mut(player.public_key()) orelse continue;
            value.* = value.add(Scalar.random(rng));
        }
        if (self.bad_commitments & bit(i) != 0) {
            var corruption = try Poly(Scalar).random(gpa, rng, dealing.poly.degree());
            defer corruption.deinit(gpa);
            var committed = try math.poly.commit(gpa, G1, corruption);
            defer committed.deinit(gpa);
            try dealing.poly.add_assign(gpa, committed);
        }
        for (players, 0..) |player, p| {
            if (self.missing_shares[i] & bit(@intCast(p)) == 0) continue;
            try remove_share(gpa, &dealing.masked_shares, player.public_key());
        }
        if (self.fake_masks & bit(i) == 0) return;
        for (info.players.items) |player| {
            const delta = Scalar.random(rng);
            if (dealing.masked_shares.get_value_mut(player)) |value| value.* = value.add(delta);
            log.commitments.perturb(player, G1.generator.mul(delta));
        }
    }

    /// Observes and plays the round, then checks the outcome.
    fn finish(
        self: *const Plan,
        gpa: Allocator,
        rng: *TestRng,
        setup: *const Setup,
        info: *const Info,
        logs: *const Logs,
        star: *const PrivateKey,
    ) !void {
        var observed = golden.observe(gpa, rng, setup, info, logs);
        defer if (observed) |*output| output.deinit(gpa) else |_| {};
        var played = golden.play(gpa, rng, setup, info, logs, star);
        defer if (played) |*result| result[0].deinit(gpa) else |_| {};
        if (self.expect_failure()) {
            if (observed) |_| {
                if (played) |_| return error.ExpectedFailure else |err| try expect_failed(err);
            } else |err| try expect_failed(err);
            return;
        }
        const observe_output = try observed;
        const play_output, const share = try played;
        if (!observe_output.eql(play_output)) return error.OutputMismatch;
        const expected = try play_output.public.partial_public(share.index);
        if (!expected.eql(share.public(MinPk))) return error.ShareMismatch;
        if (info.previous) |previous| {
            if (!previous.public.public().eql(play_output.public.public())) {
                return error.ResharePublicChanged;
            }
        }
    }
};

fn expect_failed(err: anyerror) !void {
    if (err != error.DkgFailed) return err;
}

/// Removes `player`'s masked share, if present.
fn remove_share(gpa: Allocator, shares: *Map(PublicKey, Scalar), player: PublicKey) !void {
    const position = shares.position(player) orelse return;
    var pairs: std.ArrayList(Map(PublicKey, Scalar).Pair) = .empty;
    defer pairs.deinit(gpa);
    for (shares.keys.items, shares.values, 0..) |key, value, index| {
        if (index != position) try pairs.append(gpa, .{ key, value });
    }
    const replacement = try Map(PublicKey, Scalar).init(gpa, pairs.items);
    shares.deinit(gpa);
    shares.* = replacement;
}

pub fn make_info(
    gpa: Allocator,
    round: u64,
    previous: ?Output,
    dealers: []const PrivateKey,
    players: []const PrivateKey,
) !Info {
    var owned_previous = previous;
    var dealer_set = public_set(gpa, dealers) catch |err| {
        if (owned_previous) |*output| output.deinit(gpa);
        return err;
    };
    const player_set = public_set(gpa, players) catch |err| {
        if (owned_previous) |*output| output.deinit(gpa);
        dealer_set.deinit(gpa);
        return err;
    };
    // `Info.init` takes (and on error releases) the sets and the previous output.
    return Info.init(N3f1, gpa, "test", round, previous, dealer_set, player_set);
}

fn public_set(gpa: Allocator, keys: []const PrivateKey) !Set(PublicKey) {
    assert(keys.len <= max_plan_participants);
    var publics: [max_plan_participants]PublicKey = undefined;
    for (publics[0..keys.len], keys) |*public, key| public.* = key.public_key();
    return Set(PublicKey).init(gpa, publics[0..keys.len]);
}

/// The output of an honest fresh round and every player's share.
pub const Fresh = struct {
    output: Output,
    shares: []Share,

    pub fn deinit(self: *Fresh, gpa: Allocator) void {
        self.output.deinit(gpa);
        for (self.shares) |*share| share.private.zeroize();
        gpa.free(self.shares);
        self.* = undefined;
    }
};

/// Runs an honest fresh round (commonware `Plan::run_fresh`).
pub fn run_fresh(
    gpa: Allocator,
    rng: *TestRng,
    setup: *const Setup,
    dealers: []const PrivateKey,
    players: []const PrivateKey,
) !Fresh {
    var info = try make_info(gpa, 0, null, dealers, players);
    defer info.deinit(gpa);
    var logs = try deal_honestly(gpa, rng, setup, &info, dealers);
    defer logs.deinit(gpa);
    var output = try golden.observe(gpa, rng, setup, &info, &logs);
    errdefer output.deinit(gpa);
    const shares = try gpa.alloc(Share, players.len);
    errdefer gpa.free(shares);
    for (shares, players) |*share, *player| {
        var played, share.* = try golden.play(gpa, rng, setup, &info, &logs, player);
        played.deinit(gpa);
    }
    return .{ .output = output, .shares = shares };
}

/// Every dealer's honest, identified log.
pub fn deal_honestly(
    gpa: Allocator,
    rng: *TestRng,
    setup: *const Setup,
    info: *const Info,
    dealers: []const PrivateKey,
) !Logs {
    var pairs: std.ArrayList(Logs.Pair) = .empty;
    defer pairs.deinit(gpa);
    errdefer for (pairs.items) |*pair| pair[1].deinit(gpa);
    for (dealers) |*dealer| {
        try pairs.ensureUnusedCapacity(gpa, 1);
        const signed = try golden.deal(gpa, rng, setup, info, dealer, null, parallel.sequential);
        const public, const log = (try signed.identify(gpa, info)) orelse
            return error.IdentifyFailed;
        pairs.appendAssumeCapacity(.{ public, log });
    }
    const items = try pairs.toOwnedSlice(gpa);
    defer gpa.free(items);
    return Logs.init(gpa, items);
}

/// commonware's `Arbitrary` for `Plan`: the shape is capped so a run stays affordable.
/// Dealers span their full range first; reshare plans bound dealers tightly.
pub fn arbitrary(u: *minifuzz.Unstructured) Plan {
    const plain_product_cap: u32 = 21;
    const reshare_dealer_cap: u32 = 3;
    const reshare_product_cap: u32 = 8;
    const reshare = u.ratio(u8, 1, 4);
    const dealer_cap = if (reshare) reshare_dealer_cap else max_participants;
    const product_cap = if (reshare) reshare_product_cap else plain_product_cap;
    const num_dealers = u.int_in_range(u32, 1, dealer_cap);
    const max_players = std.math.clamp(product_cap / num_dealers, 1, max_participants);
    const num_players = u.int_in_range(u32, 1, max_players);
    const star = u.int_in_range(u32, 0, num_players - 1);
    var plan = Plan.init(num_dealers, num_players, star);
    for (0..num_dealers) |d| {
        const dealer: u32 = @intCast(d);
        if (u.ratio(u8, 1, 8)) plan.bad_signatures |= bit(dealer);
        if (u.ratio(u8, 1, 8)) plan.bad_commitments |= bit(dealer);
        if (u.ratio(u8, 1, 8)) plan.drop_dealers |= bit(dealer);
        if (u.ratio(u8, 1, 10)) plan.shift_degrees[d] = u.int_in_range(i32, -2, 2);
        for (0..num_players) |p| {
            if (u.ratio(u8, 1, 12)) plan.bad_shares[d] |= bit(@intCast(p));
            if (u.ratio(u8, 1, 12)) plan.missing_shares[d] |= bit(@intCast(p));
        }
    }
    for (0..num_dealers) |d| {
        if (u.ratio(u8, 1, 8)) plan.fake_masks |= bit(@intCast(d));
    }
    if (reshare) {
        plan.reshare = true;
        for (0..num_dealers) |d| {
            if (u.ratio(u8, 1, 6)) plan.replace_shares |= bit(@intCast(d));
        }
    }
    assert(plan.valid());
    return plan;
}
