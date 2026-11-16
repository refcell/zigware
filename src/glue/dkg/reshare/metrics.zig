//! Metrics for the reshare actor (commonware `glue::dkg::reshare::metrics`).
//!
//! The telemetry family has no `clear`, so `Metrics` tracks the peers each per-peer family
//! exports and `reconcile` removes those that left their role, which is what commonware's
//! clear-and-restore does.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;

/// Reshare actor phase (the `phase` gauge's value).
pub const Phase = enum(i64) {
    /// Observing the epoch without participating.
    following = 0,
    /// Loading state and participant sets.
    setup = 1,
    /// Exchanging dealer messages and player acknowledgements.
    dealing = 2,
    /// Including signed dealer logs and committing the next epoch when the final block
    /// finalizes.
    inclusion = 3,
};

/// Metrics for the reshare actor, registered under one scope.
pub fn Metrics(comptime P: type) type {
    return struct {
        const Self = @This();

        /// Per-peer metric label.
        pub const Peer = struct { peer: P };
        pub const PeerFamily = metrics.raw.Family(Peer, metrics.raw.Gauge);
        const Set = utils.ordered.Set(P);

        /// A per-peer gauge family and the peers it exports.
        const Tracked = struct {
            family: metrics.Registered(PeerFamily),
            peers: std.ArrayList(P) = .empty,

            fn deinit(tracked: *Tracked, gpa: Allocator) void {
                tracked.family.deinit();
                tracked.peers.deinit(gpa);
            }

            /// Drops every exported peer outside `keep`.
            fn reconcile(tracked: *Tracked, keep: Set) void {
                const family = tracked.family.metric();
                var kept: usize = 0;
                for (tracked.peers.items) |peer| {
                    if (keep.position(peer) != null) {
                        tracked.peers.items[kept] = peer;
                        kept += 1;
                    } else {
                        assert(family.remove(.{ .peer = peer }));
                    }
                }
                tracked.peers.shrinkRetainingCapacity(kept);
                assert(family.count() == tracked.peers.items.len);
            }

            /// Raises `peer`'s gauge to `epoch`. Best effort: a failed allocation skips it.
            fn record(tracked: *Tracked, gpa: Allocator, peer: P, epoch: u64) void {
                const family = tracked.family.metric();
                if (family.get(.{ .peer = peer }) == null) {
                    tracked.peers.ensureUnusedCapacity(gpa, 1) catch return;
                    const gauge = family.get_or_create(.{ .peer = peer }) catch return;
                    tracked.peers.appendAssumeCapacity(peer);
                    _ = gauge.try_set_max(epoch) catch {};
                } else {
                    _ = family.get(.{ .peer = peer }).?.try_set_max(epoch) catch {};
                }
                assert(family.count() == tracked.peers.items.len);
            }
        };

        gpa: Allocator,
        /// Number of successful epochs.
        successful_epochs: metrics.Counter,
        /// Number of failed epochs.
        failed_epochs: metrics.Counter,
        /// Number of successful epochs that revealed the local share.
        our_reveals: metrics.Counter,
        /// Total revealed shares across successful epochs.
        all_reveals: metrics.Counter,
        /// Latest epoch where a valid share was received, per dealer of the installed epoch.
        latest_share: Tracked,
        /// Latest epoch where a valid ack was received, per player of the installed epoch.
        latest_ack: Tracked,
        /// Current DKG epoch.
        current_epoch: metrics.Gauge,
        /// Current DKG round.
        current_round: metrics.Gauge,
        /// Current actor phase.
        phase: metrics.Gauge,

        /// Registers reshare metrics under `scope`.
        pub fn init(gpa: Allocator, scope: *const metrics.Scope) Allocator.Error!Self {
            var current_epoch = try scope.gauge("current_epoch", "Current DKG epoch");
            errdefer current_epoch.deinit();
            var current_round = try scope.gauge("current_round", "Current DKG round");
            errdefer current_round.deinit();
            var phase = try scope.gauge("phase", "Current reshare actor phase");
            errdefer phase.deinit();
            _ = phase.metric().set(@backingInt(Phase.setup));
            var successful = try scope.counter("successful_epochs", "Successful epochs");
            errdefer successful.deinit();
            var failed = try scope.counter("failed_epochs", "Failed epochs");
            errdefer failed.deinit();
            var ours = try scope.counter("our_reveals", "Our share was revealed");
            errdefer ours.deinit();
            var all = try scope.counter("all_reveals", "All share reveals");
            errdefer all.deinit();
            const share_help = "Epoch of latest valid share received per dealer";
            var share = try scope.family(Peer, metrics.raw.Gauge, "latest_share", share_help);
            errdefer share.deinit();
            const ack_help = "Epoch of latest valid ack received per player";
            const ack = try scope.family(Peer, metrics.raw.Gauge, "latest_ack", ack_help);
            const result: Self = .{
                .gpa = gpa,
                .successful_epochs = successful,
                .failed_epochs = failed,
                .our_reveals = ours,
                .all_reveals = all,
                .latest_share = .{ .family = share },
                .latest_ack = .{ .family = ack },
                .current_epoch = current_epoch,
                .current_round = current_round,
                .phase = phase,
            };
            assert(result.current_epoch.metric().get() == 0);
            assert(result.phase.metric().get() == @backingInt(Phase.setup));
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.successful_epochs.deinit();
            self.failed_epochs.deinit();
            self.our_reveals.deinit();
            self.all_reveals.deinit();
            self.latest_share.deinit(self.gpa);
            self.latest_ack.deinit(self.gpa);
            self.current_epoch.deinit();
            self.current_round.deinit();
            self.phase.deinit();
            self.* = undefined;
        }

        /// Installs an epoch's dealers and players by dropping the gauges of every other peer.
        /// A peer that keeps its role keeps its latest epoch.
        pub fn reconcile(self: *Self, dealers: Set, players: Set) void {
            self.latest_share.reconcile(dealers);
            self.latest_ack.reconcile(players);
            assert(self.latest_share.peers.items.len <= dealers.len());
            assert(self.latest_ack.peers.items.len <= players.len());
        }

        /// Records the current epoch and its ceremony round.
        pub fn set_epoch(self: *Self, epoch: u64) void {
            _ = self.current_epoch.metric().try_set(epoch) catch {};
            _ = self.current_round.metric().try_set(epoch) catch {};
        }

        /// Records the current phase.
        pub fn set_phase(self: *Self, phase: Phase) void {
            _ = self.phase.metric().set(@backingInt(phase));
            assert(self.phase.metric().get() == @backingInt(phase));
        }

        /// Records the latest epoch where a valid share was received from `dealer`.
        pub fn record_share(self: *Self, dealer: P, epoch: u64) void {
            self.latest_share.record(self.gpa, dealer, epoch);
        }

        /// Records the latest epoch where a valid ack was received from `player`.
        pub fn record_ack(self: *Self, player: P, epoch: u64) void {
            self.latest_ack.record(self.gpa, player, epoch);
        }

        /// Records a successful ceremony and its reveals, including whether `ours` was
        /// revealed. `output` is a feldman_desmedt `Output`.
        pub fn record_success(self: *Self, output: anytype, ours: P) void {
            const revealed = output.revealed;
            self.successful_epochs.metric().inc();
            self.all_reveals.metric().inc_by(revealed.len());
            if (revealed.position(ours) != null) self.our_reveals.metric().inc();
            assert(self.successful_epochs.metric().get() > 0);
        }
    };
}
