//! A Feldman-Desmedt player (commonware `dkg::feldman_desmedt::Player`), which receives
//! dealings, acknowledges them, and finalizes its share from the agreed logs; and `deal`,
//! the trusted dealer that skips the protocol.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const math = @import("math");
const primitives = @import("../../primitives/root.zig");
const transcript_mod = @import("../../../transcript.zig");
const messages = @import("messages.zig");
const round = @import("round.zig");
const logs_mod = @import("logs.zig");

const Allocator = std.mem.Allocator;
const Participant = utils.Participant;
const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const Transcript = transcript_mod.Transcript;
const Summary = transcript_mod.Summary;
const Scalar = primitives.group.Scalar;
const Share = primitives.group.Share;
const Private = primitives.group.Private;
const Mode = primitives.sharing.Mode;
const Sharing = primitives.sharing.Sharing;
const Poly = primitives.sharing.Poly;
const DealerPubMsg = messages.DealerPubMsg;
const DealerPrivMsg = messages.DealerPrivMsg;
const PlayerAck = messages.PlayerAck;
const DealerLog = messages.DealerLog;
const Output = messages.Output;
const Info = round.Info;
const Logs = logs_mod.Logs;
const Failure = logs_mod.Failure;

/// Why a dealer's initial message is rejected. The message carries no dealer signature, so
/// the caller authenticates `dealer`; the error attributes nothing.
pub const DealerMessageError = error{
    UnexpectedDealer,
    InvalidCommitmentDegree,
    MismatchedReshareCommitment,
    InvalidDealerShare,
};

/// A dealer's messages to one player, as a player persists them.
pub fn PersistedDealing(comptime V: type, comptime P: type) type {
    return struct { dealer: P, pub_msg: DealerPubMsg(V), priv_msg: DealerPrivMsg };
}

/// A player of one round, attempting to get a share of the key. Borrows its `Info`.
pub fn Player(comptime V: type, comptime S: type) type {
    const P = S.PublicKey;
    return struct {
        const Self = @This();
        const Entry = PersistedDealing(V, P);

        me: S,
        me_pub: P,
        info: *const Info(V, P),
        index: Participant,
        transcript: Transcript,
        /// The dealings this player acknowledged, in arrival order; owned.
        view: std.ArrayList(Entry) = .empty,

        pub const Resumed = struct { player: Self, acks: Map(P, PlayerAck(P)) };
        pub const Finalized = struct { output: Output(V, P), share: Share };

        pub fn init(info: *const Info(V, P), me: S) round.Error!Self {
            const me_pub = me.public_key();
            const index = info.player_index(me_pub) orelse return error.PlayerNotInRound;
            return .{
                .me = me,
                .me_pub = me_pub,
                .info = info,
                .index = index,
                .transcript = info.round_transcript(),
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.view.items) |*entry| {
                entry.pub_msg.deinit(gpa);
                entry.priv_msg.zeroize();
            }
            self.view.deinit(gpa);
            self.* = undefined;
        }

        fn find(self: *const Self, dealer: P) ?*const Entry {
            for (self.view.items) |*entry| {
                if (utils.ordered.order(P, entry.dealer, dealer) == .eq) return entry;
            }
            return null;
        }

        /// Processes a dealer's messages: null if this dealer's message was already
        /// processed, otherwise the acknowledgement. Copies `pub_msg`. The channel must
        /// authenticate `dealer` and keep `priv_msg` private.
        pub fn dealer_message(
            self: *Self,
            comptime M: type,
            gpa: Allocator,
            dealer: P,
            pub_msg: DealerPubMsg(V),
            priv_msg: DealerPrivMsg,
        ) (DealerMessageError || Allocator.Error)!?PlayerAck(P) {
            if (self.find(dealer) != null) return null;
            if (self.info.dealer_index(dealer) == null) return error.UnexpectedDealer;
            try self.info.check_dealer_pub_msg(M, dealer, pub_msg);
            if (!self.info.check_dealer_priv_msg(self.index, pub_msg, priv_msg)) {
                return error.InvalidDealerShare;
            }
            const ack = try round.transcript_for_ack(gpa, &self.transcript, V, P, dealer, pub_msg);
            const sig = ack.sign(&self.me);
            var copy = try pub_msg.clone(gpa);
            errdefer copy.deinit(gpa);
            try self.view.append(gpa, .{ .dealer = dealer, .pub_msg = copy, .priv_msg = priv_msg });
            return .{ .sig = sig };
        }

        /// Rebuilds a player from its persisted dealings `msgs` (as `init` then
        /// `dealer_message` for each), returning the acks it regenerates. `logs` are the
        /// verified public logs: when one holds a valid ack from this player for a dealer
        /// missing from `msgs`, the state is corrupt and this fails with
        /// `MissingPlayerDealing`; an invalid persisted dealing fails with
        /// `InvalidPersistedDealing`.
        pub fn resume_from(
            comptime M: type,
            gpa: Allocator,
            info: *const Info(V, P),
            me: S,
            logs: []const Map(P, DealerLog(V, P)).Pair,
            msgs: []const Entry,
        ) !Resumed {
            var self = try init(info, me);
            errdefer self.deinit(gpa);
            var acks: std.ArrayList(Map(P, PlayerAck(P)).Pair) = .empty;
            defer acks.deinit(gpa);
            for (msgs) |msg| {
                const result = self.dealer_message(M, gpa, msg.dealer, msg.pub_msg, msg.priv_msg);
                const ack = result catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.InvalidPersistedDealing,
                } orelse continue;
                try acks.append(gpa, .{ msg.dealer, ack });
            }
            for (logs) |pair| {
                const ack = pair[1].get_ack(self.me_pub) orelse continue;
                const transcript = try round.transcript_for_ack(
                    gpa,
                    &self.transcript,
                    V,
                    P,
                    pair[0],
                    pair[1].pub_msg,
                );
                // Only trust an ack whose signature is valid for this round.
                if (transcript.verify(&self.me_pub, &ack.sig) and self.find(pair[0]) == null) {
                    return error.MissingPlayerDealing;
                }
            }
            const map = try Map(P, PlayerAck(P)).from_dedup(gpa, acks.items);
            return .{ .player = self, .acks = map };
        }

        /// This player's private share from each selected dealer: the persisted dealing
        /// when its public message matches the log, else the log's reveal.
        fn dealings(
            self: *const Self,
            gpa: Allocator,
            selected: logs_mod.Selection(V, P),
        ) ![]Scalar {
            const out = try gpa.alloc(Scalar, selected.len());
            errdefer {
                for (out) |*value| value.zeroize();
                gpa.free(out);
            }
            for (out, selected.dealers.items, selected.logs) |*value, dealer, log| {
                const persisted = self.find(dealer);
                if (persisted) |entry| if (entry.pub_msg.eql(log.pub_msg)) {
                    value.* = entry.priv_msg.share;
                    continue;
                };
                // A validated reveal can replace missing or stale local state; an ack needs
                // the exact persisted dealing.
                const reveal = log.get_reveal(self.me_pub) orelse {
                    @memset(out, Scalar.zero);
                    if (persisted != null) return error.InvalidPersistedDealing;
                    return error.MissingPlayerDealing;
                };
                value.* = reveal.share;
            }
            return out;
        }

        /// The round's output and this player's share. Agrees with `observe` on success
        /// and on the output, given the same logs, except that `MissingPlayerDealing` and
        /// `InvalidPersistedDealing` mean this player's state is corrupt while the round
        /// succeeded. Fails with `MismatchedLogs` when `logs` belong to another round, and
        /// `InsufficientLogs` (filling `failure`) when the round failed.
        pub fn finalize(
            self: *const Self,
            comptime M: type,
            gpa: Allocator,
            rng: anytype,
            logs: *Logs(V, P, M),
            failure: ?*Failure(P),
            strategy: anytype,
        ) !Finalized {
            if (!logs.info.eql(self.info)) return error.MismatchedLogs;
            var selected = try logs.select(gpa, rng, failure, strategy);
            defer selected.deinit(gpa);
            const shares = try self.dealings(gpa, selected);
            defer {
                for (shares) |*value| value.zeroize();
                gpa.free(shares);
            }
            var observed = try logs_mod.reckon(V, P, M, gpa, self.info, selected, strategy);
            errdefer observed.output.deinit(gpa);
            var private = Scalar.zero;
            if (observed.weights) |*weights| {
                defer weights.deinit(gpa);
                // Proof: `select` returned enough logs to recover.
                private = (try weights.interpolate_strategy(
                    Scalar,
                    gpa,
                    selected.dealers.items,
                    shares,
                    strategy,
                )).?;
            } else {
                for (shares) |value| private = private.add(value);
            }
            const share = Share.init(self.index, Private.init(private));
            return .{ .output = observed.output, .share = share };
        }
    };
}

/// A random degree-`quorum - 1` polynomial evaluated at every participant, with the
/// output summary drawn after it, as commonware's `deal` draws them.
pub fn DealtPoly(comptime V: type) type {
    return struct { public: Sharing(V), shares: []Share, summary: Summary };
}

pub fn deal_poly(
    comptime V: type,
    comptime M: type,
    gpa: Allocator,
    rng: anytype,
    mode: Mode,
    n: u32,
) !DealtPoly(V) {
    assert(n > 0);
    const t = M.quorum(n);
    assert(t >= 1 and t <= n);
    var private = try Poly(Scalar).random(gpa, rng, t - 1);
    defer {
        for (private.coeffs) |*c| c.zeroize();
        private.deinit(gpa);
    }
    const shares = try gpa.alloc(Share, n);
    errdefer gpa.free(shares);
    for (shares, 0..) |*share, i| {
        const participant = Participant.from_usize(i);
        const eval = private.eval(Scalar, mode.scalar(n, participant).?);
        share.* = Share.init(participant, Private.init(eval));
    }
    var summary: Summary = undefined;
    rng.fill_bytes(&summary.bytes);
    var committed = try math.poly.commit(gpa, V.Public, private);
    errdefer committed.deinit(gpa);
    const public = try Sharing(V).init(gpa, mode, n, committed);
    return .{ .public = public, .shares = shares, .summary = summary };
}

/// A trusted dealer's output and every player's share.
pub fn Dealt(comptime V: type, comptime P: type) type {
    return struct {
        const Self = @This();
        output: Output(V, P),
        shares: Map(P, Share),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.output.deinit(gpa);
            for (self.shares.values) |*share| share.private.zeroize();
            self.shares.deinit(gpa);
            self.* = undefined;
        }
    };
}

/// Distributes shares of a random key to `players` (taking ownership), without running
/// the protocol (commonware `deal`). The output can seed a reshare.
pub fn deal(
    comptime V: type,
    comptime P: type,
    comptime M: type,
    gpa: Allocator,
    rng: anytype,
    mode: Mode,
    players: Set(P),
) !Dealt(V, P) {
    var owned = players;
    errdefer owned.deinit(gpa);
    if (owned.is_empty()) return error.NumPlayers;
    const n: u32 = @intCast(owned.len());
    var dealt = try deal_poly(V, M, gpa, rng, mode, n);
    errdefer dealt.public.deinit(gpa);
    defer gpa.free(dealt.shares);
    var dealers = try owned.clone(gpa);
    errdefer dealers.deinit(gpa);
    var keys = try owned.clone(gpa);
    errdefer keys.deinit(gpa);
    const values = try gpa.dupe(Share, dealt.shares);
    for (dealt.shares) |*share| share.private.zeroize();
    const shares = Map(P, Share).from_parts(keys, values).?;
    return .{
        .output = .{
            .summary = dealt.summary,
            .public = dealt.public,
            .dealers = dealers,
            .players = owned,
            .revealed = .empty,
        },
        .shares = shares,
    };
}
