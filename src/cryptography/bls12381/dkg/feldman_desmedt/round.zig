//! A Feldman-Desmedt round (commonware `dkg::feldman_desmedt`): the round information
//! (`Info`) that binds every signature to one DKG round, the transcripts derived from it,
//! and the `Dealer`.
//!
//! `P` is a participant public key type and `S` a signer whose `S.PublicKey == P` (for
//! example `ed25519.PrivateKey`). Where commonware moves `Info` into a dealer or player, they
//! borrow it here: the `Info` must outlive them.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const utils = @import("utils");
const math = @import("math");
const primitives = @import("../../primitives/root.zig");
const transcript_mod = @import("../../../transcript.zig");
const messages = @import("messages.zig");

const Allocator = std.mem.Allocator;
const Participant = utils.Participant;
const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const Transcript = transcript_mod.Transcript;
const Summary = transcript_mod.Summary;
const Scalar = primitives.group.Scalar;
const Share = primitives.group.Share;
const Mode = primitives.sharing.Mode;
const Poly = primitives.sharing.Poly;
const Reveal = messages.Reveal;
const DealerPubMsg = messages.DealerPubMsg;
const DealerPrivMsg = messages.DealerPrivMsg;
const PlayerAck = messages.PlayerAck;
const AckOrReveal = messages.AckOrReveal;
const DealerLog = messages.DealerLog;
const SignedDealerLog = messages.SignedDealerLog;
const Output = messages.Output;

const namespace_dkg = "_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG";
pub const sig_ack = "ack";
pub const sig_log = "log";
pub const noise_pre_verify = "pre_verify";
/// Feldman's packets have canonical encodings at fixed positions, so it uses V0.
pub const transcript_version: transcript_mod.Version = .v0;

/// Invalid caller input or incomplete local state (commonware `Error`).
pub const Error = error{
    MissingDealerShare,
    PlayerNotInRound,
    DealerNotInRound,
    NumDealers,
    NumPlayers,
    InvalidPreviousOutput,
    InvalidPersistedDealing,
    MismatchedLogs,
    MissingPlayerDealing,
};

/// Why a dealer's public message is rejected: a wrong commitment degree, or a reshare
/// commitment whose constant is not the dealer's previous share commitment.
pub const PubMsgError = error{ InvalidCommitmentDegree, MismatchedReshareCommitment };

/// Information about one round of the DKG. Every operation on an `Info` must use the fault
/// model `M` that built it. Owns `previous`, `dealers`, and `players`.
pub fn Info(comptime V: type, comptime P: type) type {
    return struct {
        const Self = @This();

        summary: Summary,
        round: u64,
        previous: ?Output(V, P),
        mode: Mode,
        reveal: Reveal,
        dealers: Set(P),
        players: Set(P),

        /// Builds the round information, taking ownership of `previous`, `dealers`, and
        /// `players` (released on error). `namespace` isolates applications and must stay
        /// fixed for the protocol's lifetime; `round` always increases. `dealers` must be
        /// previous players when resharing.
        pub fn init(
            comptime M: type,
            gpa: Allocator,
            namespace: []const u8,
            round: u64,
            previous: ?Output(V, P),
            mode: Mode,
            reveal: Reveal,
            dealers: Set(P),
            players: Set(P),
        ) (Error || Allocator.Error)!Self {
            var self: Self = .{
                .summary = undefined,
                .round = round,
                .previous = previous,
                .mode = mode,
                .reveal = reveal,
                .dealers = dealers,
                .players = players,
            };
            errdefer self.deinit(gpa);
            try self.validate(M);
            self.summary = try self.summarize(gpa, namespace);
            return self;
        }

        fn validate(self: *const Self, comptime M: type) Error!void {
            const max: usize = std.math.maxInt(u32);
            if (self.dealers.len() == 0 or self.dealers.len() >= max) return error.NumDealers;
            if (self.players.len() == 0 or self.players.len() >= max) return error.NumPlayers;
            const previous = self.previous orelse return;
            if (previous.public.total != previous.players.len() or
                previous.public.required() != previous.quorum(M))
            {
                return error.InvalidPreviousOutput;
            }
            for (self.dealers.items) |dealer| {
                if (previous.players.position(dealer) == null) return error.DealerNotInRound;
            }
            if (self.dealers.len() < previous.quorum(M)) return error.NumDealers;
        }

        fn summarize(self: *const Self, gpa: Allocator, namespace: []const u8) !Summary {
            var transcript = Transcript.init(namespace_dkg, transcript_version);
            transcript.commit(namespace);
            var round_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &round_bytes, self.round, .big);
            transcript.commit(&round_bytes);
            try commit_encoded(gpa, &transcript, ?Output(V, P), self.previous);
            try commit_encoded(gpa, &transcript, Set(P), self.dealers);
            try commit_encoded(gpa, &transcript, Set(P), self.players);
            // The polynomial and reveal modes, omitted while both are zero.
            const modes = [2]u7{
                @intCast(@backingInt(self.mode)),
                @intCast(@backingInt(self.reveal)),
            };
            if (codec.Modes(2).init(modes)) |packet| {
                try commit_encoded(gpa, &transcript, codec.Modes(2), packet);
            }
            return transcript.summarize();
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.previous) |*previous| previous.deinit(gpa);
            self.dealers.deinit(gpa);
            self.players.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var previous: ?Output(V, P) = null;
            if (self.previous) |value| previous = try value.clone(gpa);
            errdefer if (previous) |*value| value.deinit(gpa);
            var dealers = try self.dealers.clone(gpa);
            errdefer dealers.deinit(gpa);
            const players = try self.players.clone(gpa);
            var result = self.*;
            result.previous = previous;
            result.dealers = dealers;
            result.players = players;
            return result;
        }

        /// Infos are equal when their summaries are.
        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.summary.eql(b.summary);
        }

        /// A random share for a fresh DKG, or the dealer's previous share for a reshare.
        pub fn unwrap_or_random_share(self: *const Self, rng: anytype, share: ?Scalar) !Scalar {
            if (share) |value| return value;
            if (self.previous != null) return error.MissingDealerShare;
            return Scalar.random(rng);
        }

        pub fn num_players(self: *const Self) u32 {
            return @intCast(self.players.len());
        }

        pub fn degree(self: *const Self, comptime M: type) u32 {
            return self.players.quorum(M) -| 1;
        }

        pub fn required_commitments(self: *const Self, comptime M: type) u32 {
            const previous_quorum = if (self.previous) |p| p.quorum(M) else 0;
            return @max(self.dealers.quorum(M), previous_quorum);
        }

        pub fn max_reveals(self: *const Self, comptime M: type) u32 {
            return self.players.max_faults(M);
        }

        /// How many dealers must reveal a player's share before it counts as revealed.
        pub fn reveal_threshold(self: *const Self, comptime M: type) u32 {
            switch (self.reveal) {
                .v0 => return self.players.max_faults(M) + 1,
                .v1 => {
                    const max_faults = if (self.previous) |previous|
                        previous.players.max_faults(M)
                    else
                        self.dealers.max_faults(M);
                    const required = self.required_commitments(M);
                    assert(required > max_faults);
                    return required - max_faults;
                },
            }
        }

        pub fn player_index(self: *const Self, player: P) ?Participant {
            return self.players.index(player);
        }

        pub fn dealer_index(self: *const Self, dealer: P) ?Participant {
            return self.dealers.index(dealer);
        }

        pub fn player_scalar(self: *const Self, player: P) ?Scalar {
            const index = self.player_index(player) orelse return null;
            return self.mode.scalar(self.num_players(), index);
        }

        /// Checks a dealer's commitment degree and, when resharing, its constant.
        pub fn check_dealer_pub_msg(
            self: *const Self,
            comptime M: type,
            dealer: P,
            pub_msg: DealerPubMsg(V),
        ) PubMsgError!void {
            if (pub_msg.commitment.degree_exact() != self.degree(M)) {
                return error.InvalidCommitmentDegree;
            }
            const previous = self.previous orelse return;
            // Proof: `init` checked that every dealer is a previous player.
            const expected = previous.share_commitment(dealer).?;
            if (!pub_msg.commitment.constant().eql(expected)) {
                return error.MismatchedReshareCommitment;
            }
        }

        /// Whether the private share matches the commitment at `player`'s point.
        pub fn check_dealer_priv_msg(
            self: *const Self,
            player: Participant,
            pub_msg: DealerPubMsg(V),
            priv_msg: DealerPrivMsg,
        ) bool {
            const point = self.mode.scalar(self.num_players(), player).?;
            const expected = pub_msg.commitment.eval(Scalar, point);
            return expected.eql(V.Public.generator.mul(priv_msg.share));
        }

        /// The round transcript every signature in the round derives from.
        pub fn round_transcript(self: *const Self) Transcript {
            return Transcript.resume_from(self.summary, transcript_version);
        }
    };
}

fn commit_encoded(gpa: Allocator, transcript: *Transcript, comptime T: type, value: T) !void {
    const bytes = try codec.encode(T, gpa, value);
    defer gpa.free(bytes);
    transcript.commit(bytes);
}

/// The transcript a player signs to acknowledge a dealer's public message.
pub fn transcript_for_ack(
    gpa: Allocator,
    round: *const Transcript,
    comptime V: type,
    comptime P: type,
    dealer: P,
    pub_msg: DealerPubMsg(V),
) Allocator.Error!Transcript {
    var out = round.fork(sig_ack);
    try commit_encoded(gpa, &out, P, dealer);
    try commit_encoded(gpa, &out, DealerPubMsg(V), pub_msg);
    return out;
}

/// The transcript a dealer signs over its log.
pub fn transcript_for_log(
    gpa: Allocator,
    info: anytype,
    comptime V: type,
    comptime P: type,
    log: DealerLog(V, P),
) Allocator.Error!Transcript {
    var out = info.round_transcript().fork(sig_log);
    try commit_encoded(gpa, &out, DealerLog(V, P), log);
    return out;
}

/// Signs `log` as dealer `signer` for `info`'s round; takes ownership of `log`.
pub fn sign_log(
    comptime V: type,
    comptime S: type,
    gpa: Allocator,
    signer: *const S,
    info: *const Info(V, S.PublicKey),
    log: DealerLog(V, S.PublicKey),
) Allocator.Error!SignedDealerLog(V, S.PublicKey) {
    var owned = log;
    errdefer owned.deinit(gpa);
    const transcript = try transcript_for_log(gpa, info, V, S.PublicKey, owned);
    const sig = transcript.sign(signer);
    return .{ .dealer = signer.public_key(), .log = owned, .sig = sig };
}

/// Whether `signed`'s dealer signed its log for `info`'s round (commonware
/// `SignedDealerLog::check`).
pub fn check_log(
    comptime V: type,
    comptime P: type,
    gpa: Allocator,
    info: *const Info(V, P),
    signed: *const SignedDealerLog(V, P),
) Allocator.Error!bool {
    const transcript = try transcript_for_log(gpa, info, V, P, signed.log);
    return transcript.verify(&signed.dealer, &signed.sig);
}

/// A player's dealing: its identity and its private share.
pub fn PrivMsgFor(comptime P: type) type {
    return struct { player: P, msg: DealerPrivMsg };
}

/// A dealer in one round. Borrows its `Info`.
pub fn Dealer(comptime V: type, comptime S: type) type {
    const P = S.PublicKey;
    return struct {
        const Self = @This();

        me: S,
        info: *const Info(V, P),
        pub_msg: DealerPubMsg(V),
        /// Per player: a reveal until the player acknowledges.
        results: Map(P, AckOrReveal(P)),
        transcript: Transcript,

        pub const Started = struct {
            dealer: Self,
            pub_msg: DealerPubMsg(V),
            priv_msgs: []PrivMsgFor(P),
        };

        /// Deals a polynomial whose constant is `share` (or random for a fresh DKG): the
        /// public commitment and one private share per player. The caller owns the returned
        /// `pub_msg` copy and `priv_msgs`.
        pub fn start(
            comptime M: type,
            gpa: Allocator,
            rng: anytype,
            info: *const Info(V, P),
            me: S,
            share: ?Share,
        ) !Started {
            if (info.dealer_index(me.public_key()) == null) return error.DealerNotInRound;
            const secret = if (share) |s| s.private.scalar else null;
            var constant = try info.unwrap_or_random_share(rng, secret);
            defer constant.zeroize();
            var poly = try Poly(Scalar).random_with_constant(gpa, rng, info.degree(M), constant);
            defer {
                for (poly.coeffs) |*c| c.zeroize();
                poly.deinit(gpa);
            }
            const priv_msgs = try gpa.alloc(PrivMsgFor(P), info.players.len());
            errdefer gpa.free(priv_msgs);
            const values = try gpa.alloc(AckOrReveal(P), info.players.len());
            errdefer gpa.free(values);
            for (priv_msgs, values, info.players.items) |*msg, *value, player| {
                const point = info.player_scalar(player).?;
                msg.* = .{ .player = player, .msg = .init(poly.eval(Scalar, point)) };
                value.* = .{ .reveal = msg.msg };
            }
            var keys = try info.players.clone(gpa);
            errdefer keys.deinit(gpa);
            const results = Map(P, AckOrReveal(P)).from_parts(keys, values).?;
            const commitment = try math.poly.commit(gpa, V.Public, poly);
            var pub_msg: DealerPubMsg(V) = .{ .commitment = commitment };
            errdefer pub_msg.deinit(gpa);
            const round = info.round_transcript();
            const transcript = try transcript_for_ack(gpa, &round, V, P, me.public_key(), pub_msg);
            const copy = try pub_msg.clone(gpa);
            return .{
                .dealer = .{
                    .me = me,
                    .info = info,
                    .pub_msg = pub_msg,
                    .results = results,
                    .transcript = transcript,
                },
                .pub_msg = copy,
                .priv_msgs = priv_msgs,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.results.values) |*value| if (value.* == .reveal) value.reveal.zeroize();
            self.results.deinit(gpa);
            self.pub_msg.deinit(gpa);
            self.* = undefined;
        }

        /// Records `player`'s acknowledgement in place of its reveal.
        pub fn receive_player_ack(
            self: *Self,
            player: P,
            ack: PlayerAck(P),
        ) error{ UnexpectedPlayer, InvalidAck }!void {
            const slot = self.results.get_value_mut(player) orelse return error.UnexpectedPlayer;
            if (!self.transcript.verify(&player, &ack.sig)) return error.InvalidAck;
            if (slot.* == .reveal) slot.reveal.zeroize();
            slot.* = .{ .ack = ack };
        }

        /// Signs the dealer log: the commitment and every ack or reveal, or only the
        /// commitment when more than `max_reveals` players did not acknowledge. Consumes
        /// the dealer.
        pub fn finalize(
            self: *Self,
            comptime M: type,
            gpa: Allocator,
        ) Allocator.Error!SignedDealerLog(V, P) {
            var reveals: u32 = 0;
            for (self.results.values) |value| reveals += @intFromBool(value.is_reveal());
            var results: messages.DealerResult(P) = .{ .ok = self.results };
            if (reveals > self.info.max_reveals(M)) {
                results.deinit(gpa);
                results = .too_many_reveals;
            }
            const log: DealerLog(V, P) = .{ .pub_msg = self.pub_msg, .results = results };
            const info = self.info;
            const me = self.me;
            self.* = undefined;
            return sign_log(V, S, gpa, &me, info, log);
        }
    };
}
