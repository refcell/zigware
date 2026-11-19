//! Reshare end-to-end properties (commonware `glue::dkg::tests::reshare::properties`), checked
//! against each active validator's state after a plan.
//!
//! The state type `S` provides:
//! - `pub const Info`: the `types.EpochInfo` final blocks carry;
//! - `public_key(state) PublicKey`, `processed_height(state) u64`,
//!   `registrations(state) []const Registration` (borrowed), and
//!   `state_sync_height(state) ?u64`;
//! - `boundary(state, gpa, height: u64) !Boundary(Info)`: what the finalized block at `height`
//!   carries in this validator's marshal (commonware's `marshal.get_block(height)` followed by
//!   `payload()`).
//!
//! Rust properties return a message string on failure; these return a named error.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const simulate_tracker = @import("../../../simulate/tracker.zig");

const Epoch = consensus.Epoch;
const PublicKey = cryptography.ed25519.PublicKey;
const Membership = cryptography.certificate.Membership;
const Set = utils.ordered.Set(PublicKey);
pub const Tracker = simulate_tracker.ProgressTracker(PublicKey);

/// Blocks per epoch (commonware `EPOCH_LENGTH`).
pub const epoch_length: u64 = 32;

/// The height of `epoch`'s final block (commonware `final_height`).
pub fn final_height(epoch: u64) u64 {
    const height = (epoch + 1) * epoch_length - 1;
    assert(height >= epoch);
    return height;
}

/// The height of the final block before `epoch`, or zero (genesis) for epoch zero.
pub fn previous_height(epoch: u64) u64 {
    return if (epoch == 0) 0 else final_height(epoch - 1);
}

/// A scheme installed into a node's provider and the membership it reports (commonware
/// `Registration`).
pub const Registration = struct {
    epoch: Epoch,
    membership: ?Membership,

    /// Whether the installed scheme holds signing material.
    pub fn signs(self: Registration) bool {
        const membership = self.membership orelse return false;
        return membership.signer_index() != null;
    }

    pub fn eql(a: Registration, b: Registration) bool {
        if (a.epoch.get() != b.epoch.get()) return false;
        if (a.membership == null or b.membership == null) return a.membership == null and
            b.membership == null;
        return a.membership.?.eql(b.membership.?);
    }
};

/// Each epoch's players: `committee_sizes[epoch % len]` consecutive participants starting at
/// `epoch * rotation_stride`, wrapping (commonware `CommitteeSchedule`).
pub const CommitteeSchedule = struct {
    /// Borrowed; outlives the schedule.
    participants: []const PublicKey,
    /// Borrowed; outlives the schedule.
    committee_sizes: []const usize,
    rotation_stride: usize,

    /// The players of `epoch`, owned by the caller.
    pub fn players(self: CommitteeSchedule, gpa: Allocator, epoch: u64) !Set {
        const total = self.participants.len;
        assert(total > 0 and self.committee_sizes.len > 0);
        const offset = (epoch * self.rotation_stride) % total;
        const size = self.committee_sizes[epoch % self.committee_sizes.len];
        assert(size <= total);
        const keys = try gpa.alloc(PublicKey, size);
        defer gpa.free(keys);
        for (keys, 0..) |*key, index| key.* = self.participants[(offset + index) % total];
        return Set.from_dedup(gpa, keys);
    }
};

/// What a validator's finalized block at a height carries.
pub fn Boundary(comptime Info: type) type {
    return union(enum) {
        /// The validator has no finalized block there.
        missing,
        /// The block carries no DKG payload.
        no_payload,
        /// The block carries a DKG payload other than an epoch info.
        other_payload,
        /// The block's epoch info (owned).
        info: Info,

        pub fn deinit(self: *@This(), gpa: Allocator) void {
            if (self.* == .info) self.info.deinit(gpa);
            self.* = undefined;
        }
    };
}

pub const Error = error{
    /// No validator registered a scheme holding signing material.
    NoSigner,
    /// A validator lacks the finalized final block of an epoch it should hold.
    MissingBoundary,
    /// A final block carried no DKG payload.
    NoPayload,
    /// A final block carried a DKG payload other than an epoch info.
    NotEpochInfo,
    /// A final block's epoch info is for the wrong epoch.
    WrongEpoch,
    /// A boundary succeeded where the plan expected a failure.
    UnexpectedSuccess,
    /// A boundary failed where every epoch should succeed.
    UnexpectedFailure,
    /// A boundary revealed shares where the plan expects none.
    Revealed,
    /// Fewer epochs succeeded than the plan requires.
    TooFewSuccesses,
    /// A boundary's sharing mode differs from the expected one.
    WrongMode,
    /// The active states differ from the expected validators.
    StateCount,
    /// The tracker saw a different number of validators.
    TrackedCount,
    /// An expected validator was not active at shutdown.
    NotRecovered,
};

/// Exit once every one of `participants` validators processed `required` (commonware
/// `AllActiveProcessedHeight`).
pub const AllActiveProcessedHeight = struct {
    pub const name = "all_active_processed_height";
    pub const requires_polling = true;

    required: u64,
    participants: usize,

    pub fn reached(
        self: *const AllActiveProcessedHeight,
        _: anytype,
        states: anytype,
        _: usize,
    ) !bool {
        assert(self.participants > 0);
        if (states.len != self.participants) return false;
        for (states) |state| if (state.processed_height() < self.required) return false;
        return true;
    }
};

/// Some validator registered a scheme holding signing material (commonware
/// `SignerRegistered`).
pub fn SignerRegistered(comptime S: type) type {
    return struct {
        pub const name = "signer_registered";

        pub fn check(_: *const @This(), _: *const Tracker, states: []const *const S) Error!void {
            for (states) |state| {
                for (state.registrations()) |registration| {
                    if (registration.signs()) return;
                }
            }
            return error.NoSigner;
        }
    };
}

/// Every validator's final blocks for epochs `0..epochs` carry the next epoch's info, and at
/// least `min_successes` succeed (commonware `BoundaryEpochInfos`). Boundaries below a
/// validator's state-sync height are skipped. With `expected_failures`, exactly those epochs
/// fail and the rest succeed.
pub fn BoundaryEpochInfos(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const name = "boundary_epoch_infos";

        gpa: Allocator,
        epochs: u64,
        no_reveals: bool = false,
        min_successes: u64,
        /// Borrowed; outlives the property.
        expected_failures: []const u64 = &.{},

        pub fn init(gpa: Allocator, epochs: u64) Self {
            return .{ .gpa = gpa, .epochs = epochs, .min_successes = epochs };
        }

        pub fn check(self: *const Self, _: *const Tracker, states: []const *const S) !void {
            assert(self.min_successes <= self.epochs);
            for (states) |state| try self.check_state(state);
        }

        fn check_state(self: *const Self, state: *const S) !void {
            var checked: u64 = 0;
            var successes: u64 = 0;
            var failures: u64 = 0;
            const synced = state.state_sync_height();
            for (0..self.epochs) |epoch| {
                const height = final_height(epoch);
                if (synced) |floor| if (height < floor) continue;
                checked += 1;
                const listed = std.mem.indexOfScalar(u64, self.expected_failures, epoch);
                const expect_failure = listed != null;
                if (expect_failure) failures += 1;
                if (try self.check_boundary(state, epoch, expect_failure)) successes += 1;
            }
            assert(failures <= checked);
            const required = if (self.expected_failures.len > 0)
                checked - failures
            else if (self.min_successes == self.epochs)
                checked
            else
                @min(self.min_successes, checked);
            if (successes < required) return error.TooFewSuccesses;
        }

        /// Whether `epoch`'s boundary succeeded; fails when its outcome breaks the plan.
        fn check_boundary(
            self: *const Self,
            state: *const S,
            epoch: u64,
            expect_failure: bool,
        ) !bool {
            var boundary = try state.boundary(self.gpa, final_height(epoch));
            defer boundary.deinit(self.gpa);
            const info = switch (boundary) {
                .missing => return error.MissingBoundary,
                .no_payload => return error.NoPayload,
                .other_payload => return error.NotEpochInfo,
                .info => |*info| info,
            };
            if (info.epoch.get() != epoch + 1) return error.WrongEpoch;
            if (info.outcome == .success) {
                if (expect_failure) return error.UnexpectedSuccess;
                if (self.no_reveals and info.output.revealed.len() != 0) return error.Revealed;
                return true;
            }
            const all_succeed = self.min_successes == self.epochs;
            if (!expect_failure and all_succeed) return error.UnexpectedFailure;
            return false;
        }
    };
}

/// The epoch info of the final block at `height`, read from the first validator that holds
/// it (commonware `boundary_info`). Owned by the caller.
pub fn boundary_info(
    comptime S: type,
    gpa: Allocator,
    states: []const *const S,
    height: u64,
) !S.Info {
    for (states) |state| {
        var boundary = try state.boundary(gpa, height);
        switch (boundary) {
            .missing => continue,
            .info => |info| return info,
            .no_payload, .other_payload => {
                boundary.deinit(gpa);
                return error.NotEpochInfo;
            },
        }
    }
    return error.MissingBoundary;
}

/// `epoch`'s boundary output uses sharing mode `mode` (commonware `BoundaryOutputMode`, which
/// reads the encoded output's byte after its summary: the sharing's mode byte).
pub fn BoundaryOutputMode(comptime S: type) type {
    return struct {
        pub const name = "boundary_output_mode";

        gpa: Allocator,
        epoch: u64,
        mode: u8,

        pub fn check(self: *const @This(), _: *const Tracker, states: []const *const S) !void {
            var info = try boundary_info(S, self.gpa, states, final_height(self.epoch));
            defer info.deinit(self.gpa);
            if (@backingInt(info.output.public.mode) != self.mode) return error.WrongMode;
        }
    };
}

/// Exactly the expected validators are active at shutdown and tracked (commonware
/// `AllNodesRecovered`).
pub fn AllNodesRecovered(comptime S: type) type {
    return struct {
        pub const name = "all_nodes_recovered";

        /// Borrowed; outlive the property.
        public_keys: []const PublicKey,

        pub fn check(
            self: *const @This(),
            tracker: *const Tracker,
            states: []const *const S,
        ) Error!void {
            if (states.len != self.public_keys.len) return error.StateCount;
            if (tracker.tracked_count() != self.public_keys.len) return error.TrackedCount;
            for (self.public_keys) |key| {
                for (states) |state| {
                    if (state.public_key().eql(key)) break;
                } else return error.NotRecovered;
            }
        }
    };
}

/// Whether `registrations` holds an `epoch` registration with membership `expected`.
fn registered(registrations: []const Registration, epoch: Epoch, expected: ?Membership) bool {
    const wanted: Registration = .{ .epoch = epoch, .membership = expected };
    for (registrations) |registration| if (registration.eql(wanted)) return true;
    return false;
}

/// The signer membership of `key` in `players`, or null when it is not a player.
fn signer_in(players: Set, key: PublicKey) ?Membership {
    const index = players.index(key) orelse return null;
    return .{ .signer = index };
}

/// Each boundary's players are the previous boundary's next players, its next players follow
/// the schedule, a success's output players are the previous players, and a failure carries
/// the previous output forward (commonware `EpochInfoContinuity`).
pub fn EpochInfoContinuity(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const name = "epoch_info_continuity";

        gpa: Allocator,
        epochs: u64,
        schedule: CommitteeSchedule,

        pub fn check(self: *const Self, _: *const Tracker, states: []const *const S) !void {
            for (0..self.epochs) |epoch| try self.check_epoch(states, epoch);
        }

        fn check_epoch(self: *const Self, states: []const *const S, epoch: u64) !void {
            const gpa = self.gpa;
            var previous = try boundary_info(S, gpa, states, previous_height(epoch));
            defer previous.deinit(gpa);
            var info = try boundary_info(S, gpa, states, final_height(epoch));
            defer info.deinit(gpa);
            if (info.epoch.get() != epoch + 1) return error.WrongEpoch;
            if (!info.players.eql(previous.next_players)) return error.PlayersNotPreviousNext;
            var expected_next = try self.schedule.players(gpa, epoch + 2);
            defer expected_next.deinit(gpa);
            if (!info.next_players.eql(expected_next)) return error.NextPlayersOffSchedule;
            switch (info.outcome) {
                .success => if (!info.output.players.eql(previous.players)) {
                    return error.OutputPlayers;
                },
                .failure => if (!info.output.eql(previous.output)) return error.OutputNotCarried,
            }
        }
    };
}

/// `epoch`'s ceremony failed: its boundary carries the previous output forward, advances to
/// the previous next players, refreshes next players from the schedule, and every validator
/// registered the carried epoch with its previous signer membership (commonware
/// `FailedCeremonyCarryOver`). A state-synced validator whose floor covers the boundary must
/// hold it itself.
pub fn FailedCeremonyCarryOver(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const name = "failed_ceremony_carry_over";

        gpa: Allocator,
        epoch: u64,
        schedule: CommitteeSchedule,

        pub fn check(self: *const Self, _: *const Tracker, states: []const *const S) !void {
            const gpa = self.gpa;
            var previous = try boundary_info(S, gpa, states, previous_height(self.epoch));
            defer previous.deinit(gpa);
            var info = try self.carried(states);
            defer info.deinit(gpa);
            if (info.epoch.get() != self.epoch + 1) return error.WrongEpoch;
            if (info.outcome != .failure) return error.UnexpectedSuccess;
            if (!info.output.eql(previous.output)) return error.OutputNotCarried;
            if (!info.players.eql(previous.next_players)) return error.PlayersNotPreviousNext;
            var expected_next = try self.schedule.players(gpa, self.epoch + 2);
            defer expected_next.deinit(gpa);
            if (!info.next_players.eql(expected_next)) return error.NextPlayersOffSchedule;
            const carried_epoch: Epoch = .new(self.epoch + 1);
            for (states) |state| {
                const expected = signer_in(previous.output.players, state.public_key());
                if (!registered(state.registrations(), carried_epoch, expected)) {
                    return error.NotRegistered;
                }
            }
        }

        /// The carry-over boundary, from a state-synced validator whose floor covers it when
        /// there is one, and otherwise from any validator that holds it.
        fn carried(self: *const Self, states: []const *const S) !S.Info {
            const height = final_height(self.epoch);
            for (states) |state| {
                const floor = state.state_sync_height() orelse continue;
                if (floor > height) continue;
                var boundary = try state.boundary(self.gpa, height);
                switch (boundary) {
                    .info => |info| return info,
                    .missing => return error.MissingBoundary,
                    .no_payload, .other_payload => {
                        boundary.deinit(self.gpa);
                        return error.NotEpochInfo;
                    },
                }
            }
            return boundary_info(S, self.gpa, states, height);
        }
    };
}

/// Every listed validator registered `epoch` with its signer membership in the output of the
/// ceremony that produced it (commonware `SchemesRegistered`). The boundary is read from the
/// first active state.
pub fn SchemesRegistered(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const name = "schemes_registered";

        gpa: Allocator,
        /// Borrowed; outlive the property.
        public_keys: []const PublicKey,
        epoch: u64,

        pub fn check(self: *const Self, _: *const Tracker, states: []const *const S) !void {
            if (self.epoch == 0) return error.NoReshareOutput;
            if (states.len == 0) return error.StateCount;
            const gpa = self.gpa;
            const height = final_height(self.epoch - 1);
            var info = try boundary_info(S, gpa, states[0..1], height);
            defer info.deinit(gpa);
            if (info.epoch.get() != self.epoch) return error.WrongEpoch;
            for (self.public_keys) |key| {
                const state = for (states) |state| {
                    if (state.public_key().eql(key)) break state;
                } else return error.NotRecovered;
                const expected = signer_in(info.output.players, key);
                if (!registered(state.registrations(), .new(self.epoch), expected)) {
                    return error.NotRegistered;
                }
            }
        }
    };
}

/// The records state-sync properties read across restarts (commonware's shared
/// `registrations` and `state_syncs` maps). `L` provides
/// `registrations_of(ledger, key) []const Registration` and `state_sync_of(ledger, key) ?u64`.
fn assert_ledger(comptime L: type) void {
    comptime assert(@hasDecl(L, "registrations_of") and @hasDecl(L, "state_sync_of"));
}

/// `public_key` state synced and later registered as a signer at or after `min_epoch`
/// (commonware `StateSyncedSigner`).
pub fn StateSyncedSigner(comptime S: type, comptime L: type) type {
    assert_ledger(L);
    return struct {
        pub const name = "state_synced_signer";

        public_key: PublicKey,
        min_epoch: u64,
        /// Borrowed; outlives the property.
        ledger: *const L,

        pub fn check(self: *const @This(), _: *const Tracker, _: []const *const S) !void {
            _ = self.ledger.state_sync_of(self.public_key) orelse return error.NotStateSynced;
            for (self.ledger.registrations_of(self.public_key)) |registration| {
                if (registration.signs() and registration.epoch.get() >= self.min_epoch) return;
            }
            return error.NoSigner;
        }
    };
}

/// `public_key` state synced at a height in `min_height..=max_height` (commonware
/// `StateSyncedAtHeight`).
pub fn StateSyncedAtHeight(comptime S: type, comptime L: type) type {
    assert_ledger(L);
    return struct {
        pub const name = "state_synced_at_height";

        public_key: PublicKey,
        min_height: u64,
        max_height: u64,
        /// Borrowed; outlives the property.
        ledger: *const L,

        pub fn check(self: *const @This(), _: *const Tracker, _: []const *const S) !void {
            assert(self.min_height <= self.max_height);
            const height = self.ledger.state_sync_of(self.public_key) orelse
                return error.NotStateSynced;
            if (height < self.min_height or height > self.max_height) {
                return error.StateSyncHeight;
            }
        }
    };
}

/// The schedule makes `public_key` a newcomer at `next_player_epoch`: absent from the epoch
/// before and from that epoch's players, and a player of the epoch after (commonware
/// `StateSyncMembership`).
pub fn StateSyncMembership(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const name = "state_sync_membership";

        gpa: Allocator,
        schedule: CommitteeSchedule,
        public_key: PublicKey,
        next_player_epoch: u64,

        pub fn check(self: *const Self, _: *const Tracker, _: []const *const S) !void {
            const epoch = self.next_player_epoch;
            if (epoch > 0 and try self.plays(epoch - 1)) return error.PresentBeforeSync;
            if (try self.plays(epoch)) return error.PlayerAtSync;
            if (!try self.plays(epoch + 1)) return error.NotNextPlayer;
        }

        fn plays(self: *const Self, epoch: u64) !bool {
            var players = try self.schedule.players(self.gpa, epoch);
            defer players.deinit(self.gpa);
            return players.position(self.public_key) != null;
        }
    };
}
