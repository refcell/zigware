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
