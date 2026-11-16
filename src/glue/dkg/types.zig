//! Epoch artifacts, participant sets, and wire messages of the DKG protocol (commonware
//! `glue::dkg::types`).
//!
//! Every type owns its memory: `deinit` frees it, `clone` deep-copies it, `eql` compares
//! values. Encodings are byte-identical to commonware's (`conformance_test.zig`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const network = @import("network.zig");

const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const Epoch = consensus.Epoch;
const primitives = cryptography.bls12381.primitives;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = primitives.group.Share;
const Sharing = primitives.Sharing;
const ModeVersion = primitives.sharing.ModeVersion;

/// The codec's participant cap for committees of at most `participants` members. Panics if
/// `participants` is zero or exceeds `u32` (commonware `max_participants`).
pub fn max_participants(participants: usize) u32 {
    if (participants == 0 or participants > std.math.maxInt(u32)) {
        @panic("participants must be non-zero and fit in u32");
    }
    const max: u32 = @intCast(participants);
    assert(max > 0);
    return max;
}

/// The read configuration of epoch artifacts and payloads: the maximum entries in each
/// participant set and the maximum supported sharing mode version.
pub const InfoCfg = struct { max_participants: u32, max_supported_mode: ModeVersion };

/// Material for an epoch-scoped threshold scheme and this node's role in it.
pub fn SchemeInfo(comptime V: type, comptime P: type) type {
    return union(enum) {
        const Self = @This();

        /// Material for a verifier outside the committee.
        verifier: struct { participants: Set(P), sharing: Sharing(V) },
        /// Material for a committee member without a signing share; `public_key` is one of
        /// `participants`.
        member: struct { participants: Set(P), sharing: Sharing(V), public_key: P },
        /// Material for a committee member that also signs with `share`.
        signer: struct { participants: Set(P), sharing: Sharing(V), share: Share },

        /// Describes the scheme for the node identified by `public_key`, taking ownership of
        /// `participants` and `sharing`: a signer when it holds `share`, a member when it is
        /// one of `participants` without a share, and a verifier otherwise.
        pub fn init(public_key: P, players: Set(P), public: Sharing(V), share: ?Share) Self {
            assert(public.total > 0);
            if (share) |held| {
                return .{ .signer = .{
                    .participants = players,
                    .sharing = public,
                    .share = held,
                } };
            }
            if (players.position(public_key) != null) {
                return .{ .member = .{
                    .participants = players,
                    .sharing = public,
                    .public_key = public_key,
                } };
            }
            return .{ .verifier = .{ .participants = players, .sharing = public } };
        }

        pub fn participants(self: *const Self) *const Set(P) {
            return switch (self.*) {
                inline else => |*info| &info.participants,
            };
        }

        pub fn sharing(self: *const Self) *const Sharing(V) {
            return switch (self.*) {
                inline else => |*info| &info.sharing,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                inline else => |*info| {
                    info.participants.deinit(gpa);
                    info.sharing.deinit(gpa);
                },
            }
            if (self.* == .signer) self.signer.share.private.zeroize();
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var copy = self;
            switch (copy) {
                inline else => |*info| {
                    info.participants = try info.participants.clone(gpa);
                    errdefer info.participants.deinit(gpa);
                    info.sharing = try info.sharing.clone(gpa);
                },
            }
            return copy;
        }

        pub fn eql(a: Self, b: Self) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            if (!a.participants().eql(b.participants().*)) return false;
            if (!a.sharing().eql(b.sharing().*)) return false;
            return switch (a) {
                .verifier => true,
                .member => |info| info.public_key.eql(b.member.public_key),
                .signer => |info| info.share.eql(b.signer.share),
            };
        }
    };
}

/// Result of a DKG or reshare ceremony.
pub const EpochOutcome = enum(u8) {
    /// The ceremony produced a new public output.
    success = 0,
    /// The ceremony failed, and the previous public output carries forward.
    failure = 1,

    pub const fixed_size: usize = 1;

    pub fn write(outcome: EpochOutcome, writer: *codec.Writer) void {
        writer.write_byte(@backingInt(outcome));
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!EpochOutcome {
        const tag = try reader.read_byte();
        return switch (tag) {
            0 => .success,
            1 => .failure,
            else => reader.fail(error.InvalidEnum, tag),
        };
    }

    /// arbitrary 1.4's derive: `(u64::from(u32) * variants) >> 32`.
    pub fn arbitrary(
        _: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!EpochOutcome {
        const variant = (@as(u64, u.int(u32)) * 2) >> 32;
        assert(variant < 2);
        return if (variant == 0) .success else .failure;
    }
};

/// Reasons `Participants.validate` rejects a participant set.
pub const ParticipantsError = error{
    /// The dealer set is empty.
    EmptyDealers,
    /// The player set is empty.
    EmptyPlayers,
    /// A participant set (dealers, players, or next players) exceeds the maximum.
    TooManyParticipants,
    /// In reshare round zero, the dealers are not exactly the previous output's players.
    InitialReshareDealers,
    /// In a later reshare round, a dealer is not one of the previous output's players.
    UnknownReshareDealer,
};

/// Participants for a DKG/reshare epoch.
pub fn Participants(comptime P: type) type {
    return struct {
        const Self = @This();
        /// The maximum number of participants accepted in any single set.
        pub const Cfg = u32;

        /// Peers that distribute dealings in this epoch.
        dealers: Set(P),
        /// Peers that receive shares in this epoch.
        players: Set(P),
        /// Players of the next epoch, tracked early for connectivity.
        next_players: Set(P),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.dealers.deinit(gpa);
            self.players.deinit(gpa);
            self.next_players.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var dealers = try self.dealers.clone(gpa);
            errdefer dealers.deinit(gpa);
            var players = try self.players.clone(gpa);
            errdefer players.deinit(gpa);
            const next_players = try self.next_players.clone(gpa);
            return .{ .dealers = dealers, .players = players, .next_players = next_players };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.dealers.eql(b.dealers) and a.players.eql(b.players) and
                a.next_players.eql(b.next_players);
        }

        /// The peers to activate for this epoch: the dealers as primary peers, and the players
        /// and next players as secondary peers.
        pub fn tracked_peers(self: Self, gpa: Allocator) Allocator.Error!network.Tracked(P) {
            var primary = try self.dealers.clone(gpa);
            errdefer primary.deinit(gpa);
            const union_items = try std.mem.concat(gpa, P, &.{
                self.players.items,
                self.next_players.items,
            });
            const secondary = try Set(P).from_owned_dedup(gpa, union_items);
            assert(secondary.items.len <= self.players.items.len + self.next_players.items.len);
            return .{ .primary = primary, .secondary = secondary };
        }

        /// Checks that the participants are usable for `round` (commonware `validate`). With a
        /// `previous` output, round zero requires the dealers to equal its players, and later
        /// rounds require every dealer to be one of its players.
        pub fn validate(
            self: Self,
            comptime V: type,
            max: u32,
            previous: ?*const fd.Output(V, P),
            round: u64,
        ) ParticipantsError!void {
            assert(max > 0);
            if (self.dealers.is_empty()) return error.EmptyDealers;
            if (self.players.is_empty()) return error.EmptyPlayers;
            for ([_]usize{ self.dealers.len(), self.players.len(), self.next_players.len() }) |
                actual,
            | {
                if (actual > max) return error.TooManyParticipants;
            }
            const output = previous orelse return;
            if (round == 0) {
                if (!self.dealers.eql(output.players)) return error.InitialReshareDealers;
                return;
            }
            for (self.dealers.items) |dealer| {
                if (output.players.position(dealer) == null) return error.UnknownReshareDealer;
            }
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.dealers.write(writer);
            self.players.write(writer);
            self.next_players.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.dealers.encode_size() + self.players.encode_size() +
                self.next_players.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max: u32) codec.Error!Self {
            assert(max > 0);
            const cfg: Set(P).Cfg = .{ .range = .inclusive(0, max) };
            var dealers = try Set(P).read(gpa, reader, cfg);
            errdefer dealers.deinit(gpa);
            var players = try Set(P).read(gpa, reader, cfg);
            errdefer players.deinit(gpa);
            const next_players = try Set(P).read(gpa, reader, cfg);
            return .{ .dealers = dealers, .players = players, .next_players = next_players };
        }
    };
}

/// The public description of an epoch: its threshold output, the participant sets that output
/// does not carry, and the transport directory `D` for every peer of the epoch. Genesis carries
/// the info for epoch 0, and the final block of each epoch carries the info for the next.
pub fn EpochInfo(comptime V: type, comptime P: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const Dir = network.DirectoryOps(P, D);
        pub const Cfg = InfoCfg;

        /// Outcome of the ceremony that produced this artifact (on `failure`, `output` is the
        /// previous output carried forward).
        outcome: EpochOutcome,
        /// Epoch this artifact describes.
        epoch: Epoch,
        /// Public threshold output whose players are this epoch's dealers.
        output: fd.Output(V, P),
        /// Peers that receive shares in this epoch.
        players: Set(P),
        /// Players of the next epoch, tracked early for connectivity.
        next_players: Set(P),
        /// Transport directory containing exactly this epoch's dealers, players, and next
        /// players.
        directory: D,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.output.deinit(gpa);
            self.players.deinit(gpa);
            self.next_players.deinit(gpa);
            Dir.deinit(&self.directory, gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var output = try self.output.clone(gpa);
            errdefer output.deinit(gpa);
            var players = try self.players.clone(gpa);
            errdefer players.deinit(gpa);
            var next_players = try self.next_players.clone(gpa);
            errdefer next_players.deinit(gpa);
            const directory = try Dir.clone(self.directory, gpa);
            return .{
                .outcome = self.outcome,
                .epoch = self.epoch,
                .output = output,
                .players = players,
                .next_players = next_players,
                .directory = directory,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.outcome == b.outcome and a.epoch == b.epoch and a.output.eql(b.output) and
                a.players.eql(b.players) and a.next_players.eql(b.next_players) and
                Dir.eql(a.directory, b.directory);
        }

        /// An upper bound on the encoded size of an artifact whose participant sets each hold
        /// at most `max` participants.
        pub fn max_encode_size_with(max: u32) usize {
            assert(max > 0);
            const set = Set(P).encode_size_max(max);
            // The directory names the union of the output's players, the players, and the
            // next players.
            const directory = Dir.max_encode_size(3 * @as(usize, max));
            return fd.Output(V, P).max_encode_size_with(max) + EpochOutcome.fixed_size +
                Epoch.max_encode_size + set * 2 + directory;
        }

        /// The epoch's participants, with the output's players as dealers (a deep copy).
        pub fn participants(self: Self, gpa: Allocator) Allocator.Error!Participants(P) {
            const view: Participants(P) = .{
                .dealers = self.output.players,
                .players = self.players,
                .next_players = self.next_players,
            };
            return view.clone(gpa);
        }

        /// The union of the output's players, the players, and the next players: the peers the
        /// directory must name exactly.
        pub fn peers(self: Self, gpa: Allocator) Allocator.Error!Set(P) {
            return peer_union(P, gpa, self.output.players, self.players, self.next_players);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.outcome.write(writer);
            self.epoch.write(writer);
            self.output.write(writer);
            self.players.write(writer);
            self.next_players.write(writer);
            codec.write(D, self.directory, writer);
        }

        pub fn encode_size(self: Self) usize {
            return EpochOutcome.fixed_size + self.epoch.encode_size() +
                self.output.encode_size() + self.players.encode_size() +
                self.next_players.encode_size() + codec.encode_size(D, self.directory);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const max = cfg.max_participants;
            assert(max > 0);
            const outcome = try EpochOutcome.read(gpa, reader, {});
            const epoch = try Epoch.read(gpa, reader, {});
            var output = try fd.Output(V, P).read(gpa, reader, .{
                .max_participants = max,
                .max_supported_mode = cfg.max_supported_mode,
            });
            errdefer output.deinit(gpa);
            const set_cfg: Set(P).Cfg = .{ .range = .inclusive(0, max) };
            var players = try Set(P).read(gpa, reader, set_cfg);
            errdefer players.deinit(gpa);
            var next_players = try Set(P).read(gpa, reader, set_cfg);
            errdefer next_players.deinit(gpa);
            var union_peers = try peer_union(P, gpa, output.players, players, next_players);
            defer union_peers.deinit(gpa);
            var directory = try codec.read_cfg(D, gpa, reader, Dir.codec_config(union_peers));
            if (!Dir.matches(directory, union_peers)) {
                Dir.deinit(&directory, gpa);
                return reader.invalid("EpochInfo", "directory does not match participants");
            }
            return .{
                .outcome = outcome,
                .epoch = epoch,
                .output = output,
                .players = players,
                .next_players = next_players,
                .directory = directory,
            };
        }
    };
}

fn peer_union(comptime P: type, gpa: Allocator, a: Set(P), b: Set(P), c: Set(P)) !Set(P) {
    const items = try std.mem.concat(gpa, P, &.{ a.items, b.items, c.items });
    const result = try Set(P).from_owned_dedup(gpa, items);
    assert(result.items.len <= a.items.len + b.items.len + c.items.len);
    return result;
}

/// A public reshare artifact carried by an application block.
pub fn Payload(comptime V: type, comptime P: type, comptime D: type) type {
    return union(enum) {
        const Self = @This();
        pub const Cfg = InfoCfg;
        const Info = EpochInfo(V, P, D);
        const Log = fd.SignedDealerLog(V, P);

        /// A signed dealer log, carried from the epoch midpoint up to, but not including, the
        /// final block.
        dealer_log: fd.SignedDealerLog(V, P),
        /// An epoch's `EpochInfo`: epoch zero's in genesis (and in a one-shot DKG's final
        /// block), and otherwise the next epoch's in the final block of the current epoch.
        epoch_info: Info,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                inline else => |*inner| inner.deinit(gpa),
            }
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            return switch (self) {
                .dealer_log => |log| .{ .dealer_log = try log.clone(gpa) },
                .epoch_info => |info| .{ .epoch_info = try info.clone(gpa) },
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            return switch (a) {
                .dealer_log => |log| b == .dealer_log and log.eql(b.dealer_log),
                .epoch_info => |info| b == .epoch_info and info.eql(b.epoch_info),
            };
        }

        /// An upper bound on the encoded size of a payload for at most `max` participants.
        pub fn max_encode_size_with(max: u32) usize {
            const log = fd.SignedDealerLog(V, P).max_encode_size_with(max);
            const info = Info.max_encode_size_with(max);
            return @max(log, info) + 1;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            switch (self) {
                .dealer_log => |log| {
                    writer.write_byte(0);
                    log.write(writer);
                },
                .epoch_info => |info| {
                    writer.write_byte(1);
                    info.write(writer);
                },
            }
        }

        pub fn encode_size(self: Self) usize {
            return 1 + switch (self) {
                inline else => |inner| inner.encode_size(),
            };
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            assert(cfg.max_participants > 0);
            const tag = try reader.read_byte();
            return switch (tag) {
                0 => .{ .dealer_log = try Log.read(gpa, reader, cfg.max_participants) },
                1 => .{ .epoch_info = try Info.read(gpa, reader, cfg) },
                else => reader.fail(error.InvalidEnum, tag),
            };
        }
    };
}

/// Point-to-point message of a DKG or reshare ceremony.
pub fn Message(comptime V: type, comptime P: type) type {
    return union(enum) {
        const Self = @This();
        /// The maximum number of participants.
        pub const Cfg = u32;

        /// A dealer's public and private messages for one player.
        dealer: struct { pub_msg: fd.DealerPubMsg(V), priv_msg: fd.DealerPrivMsg },
        /// A player's acknowledgement to a dealer.
        ack: fd.PlayerAck(P),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.* == .dealer) {
                self.dealer.pub_msg.deinit(gpa);
                self.dealer.priv_msg.zeroize();
            }
            self.* = undefined;
        }

        pub fn eql(a: Self, b: Self) bool {
            return switch (a) {
                .dealer => |dealer| b == .dealer and dealer.pub_msg.eql(b.dealer.pub_msg) and
                    dealer.priv_msg.eql(b.dealer.priv_msg),
                .ack => |ack| b == .ack and ack.eql(b.ack),
            };
        }

        /// An upper bound on the encoded size of a message for at most `max` participants.
        pub fn max_encode_size_with(max: u32) usize {
            const dealer = fd.DealerPubMsg(V).max_encode_size_with(max) +
                fd.DealerPrivMsg.fixed_size;
            return @max(dealer, fd.PlayerAck(P).fixed_size) + 1;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            switch (self) {
                .dealer => |dealer| {
                    writer.write_byte(0);
                    dealer.pub_msg.write(writer);
                    dealer.priv_msg.write(writer);
                },
                .ack => |ack| {
                    writer.write_byte(1);
                    ack.write(writer);
                },
            }
        }

        pub fn encode_size(self: Self) usize {
            return 1 + switch (self) {
                .dealer => |dealer| dealer.pub_msg.encode_size() + fd.DealerPrivMsg.fixed_size,
                .ack => fd.PlayerAck(P).fixed_size,
            };
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max: u32) codec.Error!Self {
            assert(max > 0);
            const tag = try reader.read_byte();
            switch (tag) {
                0 => {
                    var pub_msg = try fd.DealerPubMsg(V).read(gpa, reader, max);
                    errdefer pub_msg.deinit(gpa);
                    const priv_msg = try fd.DealerPrivMsg.read(gpa, reader, {});
                    return .{ .dealer = .{ .pub_msg = pub_msg, .priv_msg = priv_msg } };
                },
                1 => return .{ .ack = try fd.PlayerAck(P).read(gpa, reader, {}) },
                else => return reader.fail(error.InvalidEnum, tag),
            }
        }
    };
}

test {
    _ = @import("types_test.zig");
}
