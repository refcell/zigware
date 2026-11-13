//! Leader election for simplex (commonware `simplex/elector.rs`).
//!
//! An elector maps a round to its leader. Every participant must configure the same elector:
//! the choice is consensus-critical and nothing on the wire carries it.
//!
//! An elector `E` is a comptime interface (`assert_elector`):
//!
//! - `E.mode`: `.scheduled` (the leader depends only on the round, so it is known early) or
//!   `.dynamic` (it also depends on the previous round's certificate);
//! - `E.Input`: `void` for scheduled electors, `?*const Certificate` for dynamic ones;
//! - `e.elect(round, input) Participant` and `e.terms() Terms`.
//!
//! Electors are built from their configuration with `build`, which takes the size of the
//! participant set (commonware passes the set itself but only reads its length).
//!
//! - `RoundRobin(H)`: rotates through the participants (optionally in an order shuffled by a
//!   seed), shifted by the epoch, with optional stable leaders for terms of several views.
//! - `Random(H)`: picks the leader from the previous round's threshold VRF seed signature
//!   (`bls12381_threshold.vrf`), with round-robin for view 1.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const vrf = @import("scheme/bls12381_threshold/vrf.zig");

const Participant = consensus_types.Participant;
const Round = consensus_types.Round;
const View = consensus_types.View;
const ViewDelta = consensus_types.ViewDelta;
const TermLength = consensus_types.TermLength;
const Duration = utils.Duration;

pub const Mode = enum { scheduled, dynamic };

/// How leaders map onto views: the term length, and for stable leaders (terms longer than
/// one view) the stall timeout and how many views ahead a leader may optimistically build.
pub const Terms = struct {
    length: TermLength,
    stall_timeout: ?Duration,
    optimistic_views: ViewDelta,

    /// Every view has its own leader.
    pub fn rotating() Terms {
        return .{ .length = .one, .stall_timeout = null, .optimistic_views = .zero() };
    }

    /// One leader per `length` views. Panics unless `length > 1` and the timeout is non-zero.
    pub fn stable(length: TermLength, stall_timeout: Duration, optimistic_views: ViewDelta) Terms {
        if (length.get() <= 1) @panic("stable leaders require a term length greater than 1");
        if (stall_timeout.is_zero()) {
            @panic("stable leaders require a stall timeout greater than zero");
        }
        return .{
            .length = length,
            .stall_timeout = stall_timeout,
            .optimistic_views = optimistic_views,
        };
    }
};

pub fn assert_elector(comptime E: type) void {
    comptime {
        for (.{ "mode", "Input", "elect", "terms" }) |decl| {
            if (!@hasDecl(E, decl)) @compileError(@typeName(E) ++ " lacks Elector." ++ decl);
        }
        assert(@TypeOf(E.mode) == Mode);
        assert((E.mode == .scheduled) == (E.Input == void));
    }
}

/// Round-robin configuration over hasher `H` (used only to shuffle).
pub fn RoundRobin(comptime H: type) type {
    return struct {
        const Self = @This();

        /// Borrowed; must outlive `build`.
        seed: ?[]const u8 = null,
        terms: Terms = .rotating(),

        /// Participants in index order.
        pub fn default() Self {
            return .{};
        }

        /// Participants ordered by `H(seed || index as big-endian u32)`.
        pub fn shuffled(seed: []const u8) Self {
            return .{ .seed = seed };
        }

        pub fn with_term(
            self: Self,
            term_length: TermLength,
            stall_timeout: Duration,
            optimistic_views: ViewDelta,
        ) Self {
            var result = self;
            result.terms = .stable(term_length, stall_timeout, optimistic_views);
            return result;
        }

        /// Builds the elector for `participants` participants. Panics when there are none.
        pub fn build(
            self: Self,
            gpa: Allocator,
            participants: u32,
        ) Allocator.Error!RoundRobinElector {
            if (participants == 0) @panic("no participants");
            const permutation = try gpa.alloc(Participant, participants);
            errdefer gpa.free(permutation);
            for (permutation, 0..) |*slot, index| slot.* = .init(@intCast(index));
            if (self.seed) |seed| try shuffle(gpa, seed, permutation);
            return .{ .permutation = permutation, .terms_config = self.terms };
        }

        /// `sort_by_cached_key(|index| H::hash(&[seed, &index.encode()]))`.
        fn shuffle(gpa: Allocator, seed: []const u8, permutation: []Participant) !void {
            const Keyed = struct { key: H.Digest, participant: Participant };
            const keyed = try gpa.alloc(Keyed, permutation.len);
            defer gpa.free(keyed);
            for (keyed, permutation) |*entry, participant| {
                var index: [4]u8 = undefined;
                std.mem.writeInt(u32, &index, participant.get(), .big);
                entry.* = .{ .key = H.hash(&.{ seed, &index }), .participant = participant };
            }
            std.sort.block(Keyed, keyed, {}, struct {
                fn less_than(_: void, a: Keyed, b: Keyed) bool {
                    return a.key.order(b.key) == .lt;
                }
            }.less_than);
            for (permutation, keyed) |*slot, entry| slot.* = entry.participant;
        }
    };
}

/// Elects `permutation[(epoch + term_index) mod n]`.
pub const RoundRobinElector = struct {
    permutation: []Participant,
    terms_config: Terms,

    pub const mode: Mode = .scheduled;
    pub const Input = void;

    pub fn deinit(self: *RoundRobinElector, gpa: Allocator) void {
        gpa.free(self.permutation);
        self.* = undefined;
    }

    pub fn terms(self: RoundRobinElector) Terms {
        return self.terms_config;
    }

    pub fn elect(self: RoundRobinElector, round: Round, _: void) Participant {
        assert(self.permutation.len > 0);
        // The 1-based term index keeps the leader stable within a term.
        const term_index = round.view.term_index(self.terms_config.length);
        const n: u64 = self.permutation.len;
        const index = (round.epoch.get() +% term_index) % n;
        assert(index < n);
        return self.permutation[@intCast(index)];
    }
};

/// The randomness extraction of `Random`.
pub const RandomVersion = enum {
    /// Deprecated: maps the encoded seed signature directly to a participant, which can bias
    /// selection.
    v0,
    /// Hashes the encoded seed signature before reducing it.
    v1,
};

/// Leader election from the threshold VRF seed over hasher `H`.
pub fn Random(comptime H: type) type {
    return struct {
        const Self = @This();

        version: RandomVersion,

        pub fn init(version: RandomVersion) Self {
            return .{ .version = version };
        }

        /// The leader of `round` among `n` participants. View 1 has no previous seed and uses
        /// round-robin; every later view needs `seed_signature`.
        pub fn select_leader(
            self: Self,
            comptime V: type,
            round: Round,
            n: u32,
            seed_signature: ?V.Signature,
        ) Participant {
            if (n == 0) @panic("no participants");
            assert(seed_signature != null or round.view == View.new(1));
            const signature = seed_signature orelse {
                const index = (round.epoch.get() +% round.view.get()) % n;
                return .init(@intCast(index));
            };
            const encoded = signature.to_bytes();
            const index = switch (self.version) {
                .v0 => utils.modulo(&encoded, n),
                .v1 => utils.modulo(H.hash(&.{&encoded}).as_slice(), n),
            };
            assert(index < n);
            return .init(@intCast(index));
        }

        pub fn build(self: Self, comptime V: type, participants: u32) RandomElector(H, V) {
            if (participants == 0) @panic("no participants");
            return .{ .n = participants, .random = self };
        }
    };
}

/// A dynamic elector over threshold VRF certificates of variant `V`.
pub fn RandomElector(comptime H: type, comptime V: type) type {
    return struct {
        const Self = @This();

        n: u32,
        random: Random(H),

        pub const mode: Mode = .dynamic;
        pub const Input = ?*const vrf.Certificate(V);

        pub fn terms(_: Self) Terms {
            return .rotating();
        }

        /// `certificate` is the previous round's verified certificate (null only for view 1).
        pub fn elect(self: Self, round: Round, certificate: Input) Participant {
            const seed_signature: ?V.Signature = if (certificate) |c|
                (c.get() orelse @panic("verified certificate must decode")).seed_signature
            else
                null;
            return self.random.select_leader(V, round, self.n, seed_signature);
        }
    };
}

comptime {
    assert_elector(RoundRobinElector);
}

test {
    _ = @import("elector_test.zig");
}
