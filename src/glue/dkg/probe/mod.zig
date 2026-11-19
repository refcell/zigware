//! Discovery of the public epoch material a joining node needs before consensus starts
//! (commonware `glue/src/dkg/probe`).
//!
//! A fresh node cannot build epoch-scoped state until it learns the current epoch's
//! participant set, which lives in the `EpochInfo` of a finalized boundary block. The probe
//! discovers that block, publishes the resulting `Artifact` (which also carries the sampled
//! state-sync floor), and then serves the same boundary material to other joining peers.
//!
//! The protocol extends `glue.stateful.probe`'s solicit-and-sample floor discovery with
//! requests for the floor epoch's boundary finalization and block. At startup the node knows a
//! `Bootstrap` checkpoint (the complete participant snapshot of a bootstrap epoch and its
//! transport directory), a constant certificate verifier valid across all epochs, and the
//! epoch length. Solicitation, membership checks, and the `f + 1` sample apply to the
//! snapshot's dealers. See commonware's module docs for the trust model and message sizes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const network = @import("../network.zig");
const types = @import("../types.zig");

pub const wire = @import("wire.zig");
pub const discovery = @import("discovery.zig");
pub const actor = @import("actor.zig");
pub const Message = wire.Message;
pub const Tag = wire.Tag;
pub const max_payload_size = wire.max_payload_size;
pub const Probe = actor.Probe;
pub const Mailbox = actor.Mailbox;
pub const MarshalSource = actor.MarshalSource;

/// The weakly subjective checkpoint a joining node bootstraps from.
pub fn Bootstrap(comptime P: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const Dir = network.DirectoryOps(P, D);

        /// Epoch whose participant snapshot is `participants`. Latest-finalization replies
        /// below it are ignored, so the discovered floor is never older than the trust point.
        epoch: consensus.Epoch,
        /// The complete participant snapshot of `epoch` (a subset mis-derives `f`).
        participants: types.Participants(P),
        /// Transport directory for `participants`.
        directory: D,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.participants.deinit(gpa);
            Dir.deinit(&self.directory, gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var participants = try self.participants.clone(gpa);
            errdefer participants.deinit(gpa);
            const directory = try Dir.clone(self.directory, gpa);
            return .{ .epoch = self.epoch, .participants = participants, .directory = directory };
        }
    };
}

/// Public epoch material discovered during bootstrap, for scheme `S` over digest `D`, BLS
/// variant `V`, and directory `Dir`. It owns its parts and frees them with its allocator, so
/// the subscription channel frees an unreceived one.
pub fn Artifact(comptime S: type, comptime D: type, comptime V: type, comptime Dir: type) type {
    return struct {
        const Self = @This();
        pub const Finalization = consensus.simplex.types.Finalization(S, D);
        pub const Info = types.EpochInfo(V, S.PublicKey, Dir);

        gpa: Allocator,
        /// Finalization of the boundary block that carried `info`; null in epoch zero, which
        /// genesis anchors.
        finalization: ?Finalization,
        /// Public epoch information for the epoch of `floor` (genesis's for epoch zero).
        info: Info,
        /// Highest finalization from the `f + 1` sample: the state-sync floor.
        floor: Finalization,

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            if (self.finalization) |*finalization| finalization.deinit(gpa);
            self.info.deinit(gpa);
            self.floor.deinit(gpa);
            self.* = undefined;
        }

        pub fn discard(self: Self) void {
            var owned = self;
            owned.deinit();
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var finalization: ?Finalization = null;
            if (self.finalization) |*value| finalization = try value.clone(gpa);
            errdefer if (finalization) |*value| value.deinit(gpa);
            var info = try self.info.clone(gpa);
            errdefer info.deinit(gpa);
            const floor = try self.floor.clone(gpa);
            assert(floor.epoch().get() == info.epoch.get());
            return .{ .gpa = gpa, .finalization = finalization, .info = info, .floor = floor };
        }
    };
}

test {
    _ = wire;
    _ = @import("wire_test.zig");
    _ = @import("probe_test.zig");
    _ = @import("discovery_test.zig");
}
