//! The golden DKG (commonware `bls12381/dkg/golden`): a one-round DKG and reshare in which
//! each dealer encrypts its shares to the players with an eVRF over Banderwagon and proves
//! the encryption correct with bulletproofs.
//!
//! A round: build an `Info`; each dealer calls `deal` and broadcasts the `SignedDealerLog`;
//! `SignedDealerLog.identify` checks a log against the round. Every participant must then
//! agree on the same set of logs: `observe` computes the public `Output` from them, and
//! `play` also recovers the caller's share. Both select a quorum of valid dealings. Never
//! reuse a round number, including for failed rounds.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const primitives = @import("../primitives/root.zig");
const transcript_mod = @import("../../transcript.zig");

pub const evrf = @import("golden/evrf.zig");
pub const dealing = @import("golden/dealing.zig");
pub const PrivateKey = evrf.PrivateKey;
pub const PublicKey = evrf.PublicKey;
pub const Setup = evrf.Setup;
pub const Dealing = dealing.Dealing;
pub const DealerLog = dealing.DealerLog;
pub const SignedDealerLog = dealing.SignedDealerLog;

const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const Poly = @import("math").poly.Poly;
const Interpolator = @import("math").poly.Interpolator;
const G1 = primitives.group.G1;
const Share = primitives.group.Share;
const Private = primitives.group.Private;
const Participant = utils.Participant;
const Transcript = transcript_mod.Transcript;
const Summary = transcript_mod.Summary;
const Scalar = primitives.group.Scalar;
const MinPk = primitives.MinPk;
const Mode = primitives.sharing.Mode;
const ModeVersion = primitives.sharing.ModeVersion;
const Sharing = primitives.sharing.Sharing;
const NonZeroU32 = codec.NonZero(u32);

const namespace_golden = dealing.namespace_golden;

/// The golden DKG's errors (commonware `Error`). `DkgFailed` (too few valid dealings) is
/// the only one that is not a configuration or usage mistake.
pub const Error = error{
    DkgFailed,
    NumDealers,
    NumPlayers,
    MissingDealerShare,
    UnknownDealer,
    UnknownPlayer,
    UnsupportedNumPlayers,
};

/// The output of a successful DKG: the public sharing, the authenticated quorum, and the
/// selected dealers and the players. Owns its sets and sharing.
pub fn Output(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Cfg = struct { max_participants: u32, max_supported_mode: ModeVersion };

        summary: Summary,
        public: Sharing(MinPk),
        quorum_value: NonZeroU32,
        dealers: Set(P),
        players: Set(P),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.public.deinit(gpa);
            self.dealers.deinit(gpa);
            self.players.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var public = try self.public.clone(gpa);
            errdefer public.deinit(gpa);
            var dealers = try self.dealers.clone(gpa);
            errdefer dealers.deinit(gpa);
            const players = try self.players.clone(gpa);
            return .{
                .summary = self.summary,
                .public = public,
                .quorum_value = self.quorum_value,
                .dealers = dealers,
                .players = players,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.summary.eql(b.summary) and a.public.eql(b.public) and
                a.quorum_value.value == b.quorum_value.value and
                a.dealers.eql(b.dealers) and a.players.eql(b.players);
        }

        /// The authoritative number of players needed to reconstruct the key, as
        /// authenticated in the round summary.
        pub fn quorum(self: Self) u32 {
            assert(self.quorum_value.value <= self.players.len());
            return self.quorum_value.value;
        }

        pub fn encode_size(self: Self) usize {
            return Summary.fixed_size + self.public.encode_size() + NonZeroU32.fixed_size +
                self.dealers.encode_size() + self.players.encode_size();
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(Summary, self.summary, writer);
            self.public.write(writer);
            self.quorum_value.write(writer);
            self.dealers.write(writer);
            self.players.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const max = cfg.max_participants;
            assert(max > 0);
            const summary = try codec.read(Summary, gpa, reader);
            var public = try Sharing(MinPk).read(gpa, reader, .{
                .max_participants = max,
                .max_supported_mode = cfg.max_supported_mode,
            });
            errdefer public.deinit(gpa);
            const quorum_value = try NonZeroU32.read(gpa, reader, {});
            var dealers = try Set(P).read(gpa, reader, .{ .range = .inclusive(1, max) });
            errdefer dealers.deinit(gpa);
            var players = try Set(P).read(gpa, reader, .{ .range = .inclusive(1, max) });
            errdefer players.deinit(gpa);
            if (public.total != players.len()) {
                return reader.invalid("Output", "sharing total must equal players length");
            }
            if (quorum_value.value > players.len()) {
                return reader.invalid("Output", "quorum must not exceed players length");
            }
            return .{
                .summary = summary,
                .public = public,
                .quorum_value = quorum_value,
                .dealers = dealers,
                .players = players,
            };
        }
    };
}

/// One round of the golden DKG: binds the round number, dealers, players, and an optional
/// previous output (for a reshare) into a transcript summary. Owns its sets and `previous`.
pub const Info = struct {
    summary: Summary,
    round: u64,
    previous: ?Output(PublicKey),
    mode: Mode,
    player_quorum: u32,
    required_commitments: u32,
    dealers: Set(PublicKey),
    players: Set(PublicKey),

    /// Builds the round, taking ownership of `previous`, `dealers`, and `players` (released
    /// on error). `round` must exceed every round number used before for this group,
    /// including failed attempts.
    pub fn init(
        comptime M: type,
        gpa: Allocator,
        namespace: []const u8,
        round: u64,
        previous: ?Output(PublicKey),
        dealers: Set(PublicKey),
        players: Set(PublicKey),
    ) (Error || Allocator.Error)!Info {
        var self: Info = .{
            .summary = undefined,
            .round = round,
            .previous = previous,
            .mode = .non_zero_counter,
            .player_quorum = 0,
            .required_commitments = 0,
            .dealers = dealers,
            .players = players,
        };
        errdefer self.deinit(gpa);
        try self.validate();
        self.player_quorum = players.quorum(M);
        const dealer_quorum = dealers.quorum(M);
        assert(self.player_quorum > 0 and dealer_quorum > 0);
        self.required_commitments = if (previous) |prior|
            @max(dealer_quorum, prior.quorum())
        else
            dealer_quorum;
        self.summary = try self.summarize(gpa, namespace);
        return self;
    }

    fn validate(self: *const Info) Error!void {
        const max: usize = std.math.maxInt(u32);
        if (self.dealers.len() == 0 or self.dealers.len() >= max) return error.NumDealers;
        if (self.players.len() == 0 or self.players.len() >= max) return error.NumPlayers;
        const previous = self.previous orelse return;
        for (self.dealers.items) |dealer| {
            if (previous.players.position(dealer) == null) return error.UnknownDealer;
        }
        if (self.dealers.len() < previous.quorum()) return error.NumDealers;
    }

    fn summarize(self: *const Info, gpa: Allocator, namespace: []const u8) !Summary {
        var transcript = Transcript.init(namespace_golden, .v1);
        transcript.commit(namespace);
        transcript.commit(&codec.encode_fixed(u64, self.round));
        try commit_encoded(gpa, &transcript, ?Output(PublicKey), self.previous);
        try commit_encoded(gpa, &transcript, Set(PublicKey), self.dealers);
        try commit_encoded(gpa, &transcript, Set(PublicKey), self.players);
        transcript.commit(&codec.encode_fixed(u32, self.player_quorum));
        transcript.commit(&codec.encode_fixed(u32, self.required_commitments));
        return transcript.summarize();
    }

    pub fn deinit(self: *Info, gpa: Allocator) void {
        if (self.previous) |*previous| previous.deinit(gpa);
        self.dealers.deinit(gpa);
        self.players.deinit(gpa);
        self.* = undefined;
    }

    pub fn player_index(self: *const Info, player: PublicKey) Error!Participant {
        return self.players.index(player) orelse error.UnknownPlayer;
    }

    pub fn dealer_index(self: *const Info, dealer: PublicKey) Error!Participant {
        return self.dealers.index(dealer) orelse error.UnknownDealer;
    }

    /// A random share for a fresh DKG, or the dealer's previous share for a reshare.
    pub fn unwrap_or_random_share(self: *const Info, rng: anytype, share: ?Scalar) Error!Scalar {
        if (share) |value| return value;
        if (self.previous != null) return error.MissingDealerShare;
        return Scalar.random(rng);
    }

    pub fn num_players(self: *const Info) u32 {
        return @intCast(self.players.len());
    }

    pub fn degree(self: *const Info) u32 {
        assert(self.player_quorum > 0);
        return self.player_quorum - 1;
    }

    /// The evaluation point of `player`'s share.
    pub fn player_scalar(self: *const Info, player: PublicKey) Error!Scalar {
        const index = try self.player_index(player);
        return self.mode.scalar(self.num_players(), index) orelse
            @panic("player index should be < num_players");
    }
};

/// The verified dealer logs of a round, keyed by dealer (as commonware's `BTreeMap`).
pub const Logs = Map(PublicKey, DealerLog);

fn check_setup(setup: *const Setup, info: *const Info) Error!void {
    if (!setup.supports(info.num_players())) return error.UnsupportedNumPlayers;
}

/// The dealer `me`'s signed dealing for the round. A reshare needs the dealer's previous
/// `share`; a fresh DKG passes null. `setup` must support the round's player count.
pub fn deal(
    gpa: Allocator,
    rng: anytype,
    setup: *const Setup,
    info: *const Info,
    me: *const PrivateKey,
    share: ?Share,
    strategy: anytype,
) !SignedDealerLog {
    try check_setup(setup, info);
    _ = try info.dealer_index(me.public_key());
    const secret = if (share) |s| s.private.scalar.value else null;
    var constant = try info.unwrap_or_random_share(rng, secret);
    defer constant.zeroize();
    var poly = try Poly(Scalar).random_with_constant(gpa, rng, info.degree(), constant);
    defer {
        for (poly.coeffs) |*coeff| coeff.zeroize();
        poly.deinit(gpa);
    }
    return deal_poly(gpa, rng, setup, info, me, poly, strategy);
}

/// `deal` with a given polynomial (borrowed), skipping `deal`'s checks; the test plan deals
/// wrong-degree polynomials with it.
pub fn deal_poly(
    gpa: Allocator,
    rng: anytype,
    setup: *const Setup,
    info: *const Info,
    me: *const PrivateKey,
    poly: Poly(Scalar),
    strategy: anytype,
) !SignedDealerLog {
    var nonce: Summary = undefined;
    rng.fill_bytes(&nonce.bytes);
    const me_public = me.public_key();
    var t = Transcript.resume_from(info.summary, .v1).fork("dealer vrf");
    t.commit(&me_public.raw);
    const masks, var commitments = try me.vrf_batch_checked(
        gpa,
        rng,
        setup,
        &t,
        nonce,
        info.players.items,
        strategy,
    );
    // `reckon` releases `masks` when it fails, and `sign` the log.
    const dealt = Dealing.reckon(gpa, info, nonce, poly, masks) catch |err| {
        commitments.deinit(gpa);
        return err;
    };
    return SignedDealerLog.sign(gpa, me, info, .{ .commitments = commitments, .dealing = dealt });
}

/// The selected dealings (in dealer order) and, for a reshare, their interpolation weights.
const Selection = struct {
    entries: []dealing.Entry,
    weights: ?Interpolator(PublicKey, Scalar),

    fn deinit(self: *Selection, gpa: Allocator) void {
        gpa.free(self.entries);
        if (self.weights) |*weights| weights.deinit(gpa);
        self.* = undefined;
    }

    fn dealers(self: Selection, gpa: Allocator) Allocator.Error![]PublicKey {
        const out = try gpa.alloc(PublicKey, self.entries.len);
        for (out, self.entries) |*dealer, entry| dealer.* = entry.dealer;
        return out;
    }

    /// The sum of the dealings' commitments (fresh DKG), or their interpolation (reshare).
    fn public_poly(self: Selection, gpa: Allocator) !Poly(G1) {
        assert(self.entries.len > 0);
        const weights = self.weights orelse {
            var public = try Poly(G1).zero(gpa);
            errdefer public.deinit(gpa);
            for (self.entries) |entry| try public.add_assign(gpa, entry.log.dealing.poly);
            return public;
        };
        var count: usize = 0;
        for (self.entries) |entry| count = @max(count, entry.log.dealing.poly.coeffs.len);
        const coeffs = try gpa.alloc(G1, count);
        errdefer gpa.free(coeffs);
        const column = try gpa.alloc(G1, self.entries.len);
        defer gpa.free(column);
        const keys = try self.dealers(gpa);
        defer gpa.free(keys);
        for (coeffs, 0..) |*coeff, c| {
            for (column, self.entries) |*value, entry| {
                const poly = entry.log.dealing.poly;
                value.* = if (c < poly.coeffs.len) poly.coeffs[c] else G1.zero;
            }
            // Proof: `select` built the weights over exactly these dealers.
            coeff.* = weights.interpolate(G1, keys, column).?;
        }
        return Poly(G1).from_owned(coeffs);
    }
};

/// Selects exactly `required_commitments` valid dealings: first checks that many in one
/// batch, then, if any failed, checks all the rest (not one at a time, which strategically
/// placed invalid dealings could make slow) and takes the first that pass.
fn select(
    gpa: Allocator,
    rng: anytype,
    setup: *const Setup,
    info: *const Info,
    logs: *const Logs,
) !Selection {
    const required: usize = info.required_commitments;
    var candidates: std.ArrayList(dealing.Entry) = .empty;
    defer candidates.deinit(gpa);
    for (logs.keys.items, logs.values) |dealer, *log| {
        if (info.dealers.position(dealer) == null) continue;
        try candidates.append(gpa, .{ .dealer = dealer, .log = log });
    }
    if (candidates.items.len < required) return error.DkgFailed;
    const head = candidates.items[0..required];
    var checked = try dealing.batch_check(gpa, rng, setup, info, head);
    errdefer gpa.free(checked);
    const missing = required - checked.len;
    if (missing > 0) {
        const rest = try dealing.batch_check(gpa, rng, setup, info, candidates.items[required..]);
        defer gpa.free(rest);
        if (rest.len < missing) return error.DkgFailed;
        const kept = checked.len;
        checked = try gpa.realloc(checked, required);
        // The rest follow the head in dealer order, so the selection stays sorted.
        @memcpy(checked[kept..], rest[0..missing]);
    }
    assert(checked.len == required);
    var selection: Selection = .{ .entries = checked, .weights = null };
    const previous = info.previous orelse return selection;
    const keys = try selection.dealers(gpa);
    defer gpa.free(keys);
    const mode = previous.public.mode;
    // Proof: `Info.init` checked that the dealers are previous players.
    selection.weights = (try mode.subset_interpolator(
        PublicKey,
        gpa,
        previous.players.items,
        keys,
    )).?;
    return selection;
}

/// The round's output for the selection.
fn reckon(gpa: Allocator, info: *const Info, selection: Selection) !Output(PublicKey) {
    var public = try selection.public_poly(gpa);
    var sharing = Sharing(MinPk).init(gpa, info.mode, info.num_players(), public) catch |err| {
        public.deinit(gpa);
        return err;
    };
    errdefer sharing.deinit(gpa);
    const keys = try selection.dealers(gpa);
    // `from_owned_dedup` releases `keys` when it fails.
    var dealers = try Set(PublicKey).from_owned_dedup(gpa, keys);
    errdefer dealers.deinit(gpa);
    assert(dealers.len() == selection.entries.len);
    return .{
        .summary = info.summary,
        .public = sharing,
        .quorum_value = NonZeroU32.init(info.player_quorum).?,
        .dealers = dealers,
        .players = try info.players.clone(gpa),
    };
}

/// The round's public output from the agreed logs, without a share (the observer path).
/// `DkgFailed` when too few dealings are valid.
pub fn observe(
    gpa: Allocator,
    rng: anytype,
    setup: *const Setup,
    info: *const Info,
    logs: *const Logs,
) !Output(PublicKey) {
    try check_setup(setup, info);
    var selection = try select(gpa, rng, setup, info, logs);
    defer selection.deinit(gpa);
    return reckon(gpa, info, selection);
}

/// The round's public output and the player `me`'s share, unmasked from each selected
/// dealing with the eVRF (the player path).
pub fn play(
    gpa: Allocator,
    rng: anytype,
    setup: *const Setup,
    info: *const Info,
    logs: *const Logs,
    me: *const PrivateKey,
) !struct { Output(PublicKey), Share } {
    try check_setup(setup, info);
    const me_public = me.public_key();
    const my_index = try info.player_index(me_public);
    var selection = try select(gpa, rng, setup, info, logs);
    defer selection.deinit(gpa);
    const shares = try gpa.alloc(Scalar, selection.entries.len);
    defer {
        for (shares) |*value| value.zeroize();
        gpa.free(shares);
    }
    for (shares, selection.entries) |*value, entry| {
        const dealt = &entry.log.dealing;
        const mask = me.vrf_recv(dealt.nonce, entry.dealer);
        // Proof: `Dealing.check` requires a masked share for every player.
        const masked = dealt.masked_shares.get_value(me_public).?;
        value.* = masked.sub(mask);
    }
    var private = Scalar.zero;
    if (selection.weights) |weights| {
        const keys = try selection.dealers(gpa);
        defer gpa.free(keys);
        // Proof: `select` built the weights over exactly these dealers.
        private = weights.interpolate(Scalar, keys, shares).?;
    } else {
        for (shares) |value| private = private.add(value);
    }
    const output = try reckon(gpa, info, selection);
    return .{ output, Share.init(my_index, Private.init(private)) };
}

fn commit_encoded(gpa: Allocator, transcript: *Transcript, comptime T: type, value: T) !void {
    const bytes = try codec.encode(T, gpa, value);
    defer gpa.free(bytes);
    transcript.commit(bytes);
}

test {
    _ = evrf;
    _ = dealing;
    _ = @import("golden/plan.zig");
    _ = @import("golden/protocol_tests.zig");
    _ = @import("golden/tests.zig");
}
