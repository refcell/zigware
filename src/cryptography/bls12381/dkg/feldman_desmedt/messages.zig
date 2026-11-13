//! The wire types of the Feldman-Desmedt DKG (commonware `dkg::feldman_desmedt`): the
//! dealer's public commitment and private shares, player acknowledgements, dealer logs,
//! and the round output.
//!
//! `P` is a participant public key type (for example `ed25519.PublicKey`) and `V` a BLS
//! variant. Owning types have `deinit(gpa)` and `clone(gpa)`; everything encodes through
//! `codec` byte-identically to commonware.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const utils = @import("utils");
const primitives = @import("../../primitives/root.zig");
const Summary = @import("../../../transcript.zig").Summary;

const Allocator = std.mem.Allocator;
const Participant = utils.Participant;
const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const Scalar = primitives.group.Scalar;
const sharing_mod = primitives.sharing;
const Sharing = sharing_mod.Sharing;
const ModeVersion = sharing_mod.ModeVersion;
const Poly = sharing_mod.Poly;

/// Which revealed-share calculation a ceremony uses.
pub const Reveal = enum(u8) {
    /// Deprecated in commonware: counts against the new player set.
    v0 = 0,
    /// Counts against the dealers, or the previous players during a reshare.
    v1 = 1,
};

/// A dealer's public message: the commitment to its polynomial.
pub fn DealerPubMsg(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Commitment = Poly(V.Public);
        /// The maximum number of participants (coefficients).
        pub const Cfg = u32;

        commitment: Commitment,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.commitment.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            return .{ .commitment = try self.commitment.clone(gpa) };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.commitment.eql(b.commitment);
        }

        pub fn max_encode_size_with(max_participants: u32) usize {
            return Commitment.max_encode_size_with(max_participants);
        }

        pub fn encode_size(self: Self) usize {
            return self.commitment.encode_size();
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.commitment.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max_size: u32) codec.Error!Self {
            assert(max_size > 0);
            const cfg: Commitment.Cfg = .{ .range = .inclusive(1, max_size) };
            return .{ .commitment = try Commitment.read(gpa, reader, cfg) };
        }
    };
}

/// A dealer's private message to one player: that player's share of the dealer's
/// polynomial (commonware keeps it in a `Secret`). Formatting redacts it, equality is
/// constant-time, and `zeroize` clears it.
pub const DealerPrivMsg = struct {
    share: Scalar,

    pub const fixed_size: usize = Scalar.fixed_size;

    pub fn init(share: Scalar) DealerPrivMsg {
        return .{ .share = share };
    }

    pub fn zeroize(self: *DealerPrivMsg) void {
        self.share.zeroize();
    }

    pub fn eql(a: DealerPrivMsg, b: DealerPrivMsg) bool {
        const Bytes = [Scalar.fixed_size]u8;
        return std.crypto.timing_safe.eql(Bytes, a.share.to_bytes(), b.share.to_bytes());
    }

    pub fn format(_: DealerPrivMsg, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("DealerPrivMsg(REDACTED)");
    }

    pub fn write(self: DealerPrivMsg, writer: *codec.Writer) void {
        codec.write(Scalar, self.share, writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!DealerPrivMsg {
        return init(try Scalar.read(gpa, reader, .reject_zero));
    }
};

/// A player's signed acknowledgement of a dealer's messages.
pub fn PlayerAck(comptime P: type) type {
    return struct {
        const Self = @This();
        sig: P.Signature,

        pub const fixed_size: usize = codec.fixed_size(P.Signature).?;

        pub fn eql(a: Self, b: Self) bool {
            return a.sig.eql(b.sig);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(P.Signature, self.sig, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{ .sig = try codec.read(P.Signature, gpa, reader) };
        }
    };
}

/// A player's acknowledgement, or the dealer's reveal of that player's share.
pub fn AckOrReveal(comptime P: type) type {
    return union(enum) {
        const Self = @This();
        ack: PlayerAck(P),
        reveal: DealerPrivMsg,

        pub const max_encode_size: usize =
            1 + @max(PlayerAck(P).fixed_size, DealerPrivMsg.fixed_size);

        pub fn is_reveal(self: Self) bool {
            return self == .reveal;
        }

        pub fn eql(a: Self, b: Self) bool {
            return switch (a) {
                .ack => |x| b == .ack and x.eql(b.ack),
                .reveal => |x| b == .reveal and x.eql(b.reveal),
            };
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (self) {
                .ack => try writer.writeAll("Ack"),
                .reveal => try writer.writeAll("Reveal(REDACTED)"),
            }
        }

        pub fn encode_size(self: Self) usize {
            return 1 + switch (self) {
                .ack => PlayerAck(P).fixed_size,
                .reveal => DealerPrivMsg.fixed_size,
            };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            switch (self) {
                .ack => |x| {
                    writer.write_byte(0);
                    x.write(writer);
                },
                .reveal => |x| {
                    writer.write_byte(1);
                    x.write(writer);
                },
            }
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const tag = try reader.read_byte();
            return switch (tag) {
                0 => .{ .ack = try PlayerAck(P).read(gpa, reader, {}) },
                1 => .{ .reveal = try DealerPrivMsg.read(gpa, reader, {}) },
                else => reader.fail(error.InvalidEnum, tag),
            };
        }
    };
}

/// A copy of `map` sharing nothing with it (keys and values own no memory).
fn clone_map(comptime K: type, comptime W: type, gpa: Allocator, map: Map(K, W)) !Map(K, W) {
    var keys = try map.keys.clone(gpa);
    errdefer keys.deinit(gpa);
    const values = try gpa.dupe(W, map.values);
    return Map(K, W).from_parts(keys, values).?;
}

/// A dealer's per-player results, or a marker that publishing them would reveal too many
/// shares.
pub fn DealerResult(comptime P: type) type {
    return union(enum) {
        const Self = @This();
        pub const Results = Map(P, AckOrReveal(P));
        /// The maximum number of players.
        pub const Cfg = u32;

        ok: Results,
        too_many_reveals,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .ok => |*map| {
                    for (map.values) |*value| if (value.* == .reveal) value.reveal.zeroize();
                    map.deinit(gpa);
                },
                .too_many_reveals => {},
            }
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            return switch (self) {
                .ok => |map| .{ .ok = try clone_map(P, AckOrReveal(P), gpa, map) },
                .too_many_reveals => .too_many_reveals,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            return switch (a) {
                .too_many_reveals => b == .too_many_reveals,
                .ok => |x| b == .ok and maps_eql(x, b.ok),
            };
        }

        fn maps_eql(a: Results, b: Results) bool {
            if (!a.keys.eql(b.keys)) return false;
            for (a.values, b.values) |x, y| if (!x.eql(y)) return false;
            return true;
        }

        pub fn max_encode_size_with(max_players: u32) usize {
            return Results.encode_size_max(max_players, AckOrReveal(P).max_encode_size) + 1;
        }

        pub fn encode_size(self: Self) usize {
            return 1 + switch (self) {
                .ok => |map| map.encode_size(),
                .too_many_reveals => 0,
            };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            switch (self) {
                .ok => |map| {
                    writer.write_byte(0);
                    map.write(writer);
                },
                .too_many_reveals => writer.write_byte(1),
            }
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max_players: u32) codec.Error!Self {
            const tag = try reader.read_byte();
            return switch (tag) {
                0 => .{ .ok = try Results.read(gpa, reader, .{
                    .range = .inclusive(0, max_players),
                }) },
                1 => .too_many_reveals,
                else => reader.fail(error.InvalidEnum, tag),
            };
        }
    };
}

/// What a dealer log says about each player, without the shares.
pub fn DealerLogSummary(comptime P: type) type {
    return union(enum) {
        too_many_reveals,
        ok: struct { acks: Set(P), reveals: Set(P) },

        pub fn deinit(self: *@This(), gpa: Allocator) void {
            switch (self.*) {
                .ok => |*sets| {
                    sets.acks.deinit(gpa);
                    sets.reveals.deinit(gpa);
                },
                .too_many_reveals => {},
            }
            self.* = undefined;
        }
    };
}

/// A dealer's public message and its results.
pub fn DealerLog(comptime V: type, comptime P: type) type {
    return struct {
        const Self = @This();
        /// The maximum number of participants.
        pub const Cfg = u32;

        pub_msg: DealerPubMsg(V),
        results: DealerResult(P),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.pub_msg.deinit(gpa);
            self.results.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var pub_msg = try self.pub_msg.clone(gpa);
            errdefer pub_msg.deinit(gpa);
            return .{ .pub_msg = pub_msg, .results = try self.results.clone(gpa) };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.pub_msg.eql(b.pub_msg) and a.results.eql(b.results);
        }

        pub fn max_encode_size_with(max_participants: u32) usize {
            return DealerPubMsg(V).max_encode_size_with(max_participants) +
                DealerResult(P).max_encode_size_with(max_participants);
        }

        pub fn encode_size(self: Self) usize {
            return self.pub_msg.encode_size() + self.results.encode_size();
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.pub_msg.write(writer);
            self.results.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max: u32) codec.Error!Self {
            var pub_msg = try DealerPubMsg(V).read(gpa, reader, max);
            errdefer pub_msg.deinit(gpa);
            return .{ .pub_msg = pub_msg, .results = try DealerResult(P).read(gpa, reader, max) };
        }

        fn result(self: *const Self, player: P) ?*const AckOrReveal(P) {
            return switch (self.results) {
                .ok => |*map| map.get_value(player),
                .too_many_reveals => null,
            };
        }

        pub fn get_ack(self: *const Self, player: P) ?PlayerAck(P) {
            const entry = self.result(player) orelse return null;
            return if (entry.* == .ack) entry.ack else null;
        }

        pub fn get_reveal(self: *const Self, player: P) ?DealerPrivMsg {
            const entry = self.result(player) orelse return null;
            return if (entry.* == .reveal) entry.reveal else null;
        }

        /// The results in `players` order: null when the log omits them, and
        /// `MismatchedLogPlayers` when its players differ from `players`.
        pub fn results_for(
            self: *const Self,
            players: Set(P),
        ) error{MismatchedLogPlayers}!?[]const AckOrReveal(P) {
            return switch (self.results) {
                .too_many_reveals => null,
                .ok => |map| if (map.keys.eql(players)) map.values else {
                    return error.MismatchedLogPlayers;
                },
            };
        }

        /// The acknowledging and revealed players; the caller frees the summary.
        pub fn summary(self: Self, gpa: Allocator) Allocator.Error!DealerLogSummary(P) {
            const map = switch (self.results) {
                .too_many_reveals => return .too_many_reveals,
                .ok => |map| map,
            };
            var acks: std.ArrayList(P) = .empty;
            defer acks.deinit(gpa);
            var reveals: std.ArrayList(P) = .empty;
            defer reveals.deinit(gpa);
            for (map.keys.items, map.values) |player, value| {
                try (if (value.is_reveal()) &reveals else &acks).append(gpa, player);
            }
            var ack_set = try Set(P).from_dedup(gpa, acks.items);
            errdefer ack_set.deinit(gpa);
            const reveal_set = try Set(P).from_dedup(gpa, reveals.items);
            return .{ .ok = .{ .acks = ack_set, .reveals = reveal_set } };
        }
    };
}

/// A dealer log signed by its dealer over the round transcript.
pub fn SignedDealerLog(comptime V: type, comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Cfg = u32;

        dealer: P,
        log: DealerLog(V, P),
        sig: P.Signature,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.log.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            return .{ .dealer = self.dealer, .log = try self.log.clone(gpa), .sig = self.sig };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.dealer.eql(b.dealer) and a.log.eql(b.log) and a.sig.eql(b.sig);
        }

        pub fn max_encode_size_with(max_participants: u32) usize {
            return DealerLog(V, P).max_encode_size_with(max_participants) +
                codec.fixed_size(P).? + codec.fixed_size(P.Signature).?;
        }

        pub fn encode_size(self: Self) usize {
            return codec.fixed_size(P).? + self.log.encode_size() +
                codec.fixed_size(P.Signature).?;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(P, self.dealer, writer);
            self.log.write(writer);
            codec.write(P.Signature, self.sig, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max: u32) codec.Error!Self {
            const dealer = try codec.read(P, gpa, reader);
            var log = try DealerLog(V, P).read(gpa, reader, max);
            errdefer log.deinit(gpa);
            const sig = try codec.read(P.Signature, gpa, reader);
            return .{ .dealer = dealer, .log = log, .sig = sig };
        }
    };
}

/// The output of a successful DKG round: the public sharing and who took part.
pub fn Output(comptime V: type, comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Cfg = struct { max_participants: u32, max_supported_mode: ModeVersion };

        summary: Summary,
        public: Sharing(V),
        dealers: Set(P),
        players: Set(P),
        /// Players whose shares the selected dealers may have revealed.
        revealed: Set(P),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.public.deinit(gpa);
            self.dealers.deinit(gpa);
            self.players.deinit(gpa);
            self.revealed.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var public = try self.public.clone(gpa);
            errdefer public.deinit(gpa);
            var dealers = try self.dealers.clone(gpa);
            errdefer dealers.deinit(gpa);
            var players = try self.players.clone(gpa);
            errdefer players.deinit(gpa);
            const revealed = try self.revealed.clone(gpa);
            return .{
                .summary = self.summary,
                .public = public,
                .dealers = dealers,
                .players = players,
                .revealed = revealed,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.summary.eql(b.summary) and a.public.eql(b.public) and
                a.dealers.eql(b.dealers) and a.players.eql(b.players) and
                a.revealed.eql(b.revealed);
        }

        /// The number of players needed to reconstruct the key.
        pub fn quorum(self: Self, comptime M: type) u32 {
            return self.players.quorum(M);
        }

        /// The public key of `player`'s share, or null when it is not a player.
        pub fn share_commitment(self: Self, player: P) ?V.Public {
            const index = self.players.index(player) orelse return null;
            return self.public.partial_public(index) catch null;
        }

        pub fn max_encode_size_with(max_participants: u32) usize {
            const set = Set(P).encode_size_max(max_participants);
            return Sharing(V).max_encode_size_with(max_participants) + Summary.fixed_size +
                3 * set;
        }

        pub fn encode_size(self: Self) usize {
            return Summary.fixed_size + self.public.encode_size() + self.dealers.encode_size() +
                self.players.encode_size() + self.revealed.encode_size();
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(Summary, self.summary, writer);
            self.public.write(writer);
            self.dealers.write(writer);
            self.players.write(writer);
            self.revealed.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const max = cfg.max_participants;
            assert(max > 0);
            const summary = try codec.read(Summary, gpa, reader);
            var public = try Sharing(V).read(gpa, reader, .{
                .max_participants = max,
                .max_supported_mode = cfg.max_supported_mode,
            });
            errdefer public.deinit(gpa);
            // At least one dealer and one player take part; there may be no reveals.
            var dealers = try Set(P).read(gpa, reader, .{ .range = .inclusive(1, max) });
            errdefer dealers.deinit(gpa);
            var players = try Set(P).read(gpa, reader, .{ .range = .inclusive(1, max) });
            errdefer players.deinit(gpa);
            const revealed = try Set(P).read(gpa, reader, .{ .range = .inclusive(0, max) });
            return .{
                .summary = summary,
                .public = public,
                .dealers = dealers,
                .players = players,
                .revealed = revealed,
            };
        }
    };
}
