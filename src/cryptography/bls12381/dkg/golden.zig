//! The golden DKG (commonware `bls12381/dkg/golden`): a one-round DKG and reshare in which
//! each dealer encrypts its shares to the players with an eVRF over Banderwagon and proves
//! the encryption correct with bulletproofs.
//!
//! Ported so far: the round information (`Info`), the round `Output`, and the eVRF keys and
//! gadget (`evrf`). Dealing, observing, and playing follow once crypto's zk bulletproofs
//! lands, since every dealing carries a bulletproofs proof.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const primitives = @import("../primitives/root.zig");
const transcript_mod = @import("../../transcript.zig");

pub const evrf = @import("golden/evrf.zig");
pub const PrivateKey = evrf.PrivateKey;
pub const PublicKey = evrf.PublicKey;

const Set = utils.ordered.Set;
const Participant = utils.Participant;
const Transcript = transcript_mod.Transcript;
const Summary = transcript_mod.Summary;
const Scalar = primitives.group.Scalar;
const MinPk = primitives.MinPk;
const Mode = primitives.sharing.Mode;
const ModeVersion = primitives.sharing.ModeVersion;
const Sharing = primitives.sharing.Sharing;
const NonZeroU32 = codec.NonZero(u32);

const namespace_golden = "_COMMONWARE_CRYPTOGRAPHY_BLS12381_GOLDEN_DKG";

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

fn commit_encoded(gpa: Allocator, transcript: *Transcript, comptime T: type, value: T) !void {
    const bytes = try codec.encode(T, gpa, value);
    defer gpa.free(bytes);
    transcript.commit(bytes);
}

test {
    _ = evrf;
    _ = @import("golden/tests.zig");
}
