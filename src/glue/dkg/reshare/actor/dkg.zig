//! The reshare actor's one-shot DKG mode (commonware `reshare/actor/dkg.rs`).
//!
//! In DKG mode the actor runs epoch zero once over its configured participants: it tracks
//! them, prepares the epoch without a previous output, and runs its dealing and inclusion
//! windows. It then reports the outcome on the mode's completion and serves requests in a
//! terminal loop. A restart after the final block was applied reports the outcome the stored
//! final block carries instead of running the ceremony again.

const std = @import("std");
const assert = std.debug.assert;
const target = "commonware_glue::dkg::reshare::actor::dkg";
const consensus = @import("consensus");
const utils = @import("utils");
const types = @import("../../types.zig");
const actor_mod = @import("actor.zig");
const run_mod = @import("run.zig");

const Epoch = consensus.Epoch;
const Height = consensus.Height;

/// DKG-mode failures where commonware panics.
pub const DkgError = error{
    /// The actor is not in DKG mode.
    NotDkgMode,
    /// The configured participants are invalid.
    InvalidDkgParticipants,
    /// The outcome was applied, but marshal does not store the final DKG block: bootstrap
    /// storage does not match the secret store.
    MissingFinalDkgBlock,
    /// The final DKG block carries a dealer log.
    UnexpectedFinalPayload,
};

/// The DKG-mode functions for `Actor(T)`.
pub fn Dkg(comptime T: type) type {
    return struct {
        const Actor = actor_mod.Actor(T);
        const P = Actor.P;
        const Info = Actor.Info;
        const Runner = run_mod.Runner(T);

        fn mode(self: *Actor) DkgError!*@FieldType(Actor.Mode, "dkg") {
            return switch (self.mode) {
                .dkg => |*dkg| dkg,
                .reshare => error.NotDkgMode,
            };
        }

        /// Runs the one-shot DKG of epoch zero (commonware `run_dkg`), then serves requests
        /// until the mailbox closes. `mux` is a `p2p.utils.mux.MuxHandle`.
        pub fn run_dkg(self: *Actor, store: *Actor.Store, mux: anytype) !void {
            const epoch = Epoch.zero();
            const last = self.epocher.last(epoch).?;
            // Activate the epoch-zero peer set on every start, including restarts after
            // completion, so this node can fetch and serve the one-shot chain.
            var snapshot = try validated_participants(self);
            defer snapshot.deinit(self.gpa);
            const tracked = track(self, snapshot);
            // A persisted share or a tip at the final height means a prior run applied the
            // final block, which marshal stores before delivering it.
            const applied = self.tip != null and self.tip.?.height.get() >= last.get();
            if (applied or try store.share(epoch) != null) {
                tracked catch |err| self.tracer.with_target(target).event(
                    .warn,
                    "failed to activate DKG peer set after completion",
                    .{ .epoch = Epoch.zero(), .@"error" = err },
                );
                complete(self, try final_info(self, last));
                return terminal(self);
            }
            tracked catch |err| {
                const fields = .{ .epoch = Epoch.zero(), .@"error" = err };
                const text = "failed to activate DKG peer set";
                self.tracer.with_target(target).event(.warn, text, fields);
                try complete_from(self, store);
                return terminal(self);
            };
            var prepared = try setup_dkg(self, store, try snapshot.clone(self.gpa));
            defer prepared.deinit(self.gpa);
            var channel = try mux.register(epoch.get());
            defer channel.sender.deinit();
            defer channel.receiver.deinit();
            const sender = &channel.sender;
            const receiver = &channel.receiver;
            const flow = try Runner.participate(self, store, &prepared, sender, receiver);
            if (flow == .stop) return;
            try complete_from(self, store);
            return terminal(self);
        }

        /// The configured participants as epoch zero's dealers and players, validated.
        fn validated_participants(self: *Actor) !types.Participants(P) {
            const dkg = try mode(self);
            var dealers = try dkg.participants.clone(self.gpa);
            errdefer dealers.deinit(self.gpa);
            var snapshot: types.Participants(P) = .{
                .dealers = dealers,
                .players = try dkg.participants.clone(self.gpa),
                .next_players = .empty,
            };
            errdefer snapshot.deinit(self.gpa);
            const max = self.config.max_participants;
            snapshot.validate(Actor.V, max, null, 0) catch return error.InvalidDkgParticipants;
            assert(snapshot.players.len() > 0);
            return snapshot;
        }

        /// Activates `snapshot`'s peers for epoch zero (commonware `track_dkg`).
        fn track(self: *Actor, snapshot: types.Participants(P)) !void {
            const dkg = try mode(self);
            var tracked = try snapshot.tracked_peers(self.gpa);
            defer tracked.deinit(self.gpa);
            assert(tracked.primary.len() == snapshot.dealers.len());
            try self.config.manager.track(Epoch.zero(), tracked.view(), &dkg.directory);
        }

        /// Prepares epoch zero over `snapshot` (taken), persisting its dealer seed.
        fn setup_dkg(
            self: *Actor,
            store: *Actor.Store,
            snapshot: types.Participants(P),
        ) !Actor.PreparedEpoch {
            self.metrics.set_phase(.setup);
            var participants = snapshot;
            errdefer participants.deinit(self.gpa);
            const height = if (self.tip) |tip| tip.height.next() else Height.zero();
            const bounds = self.epocher.containing(height) orelse return error.UnknownHeight;
            if (bounds.epoch.get() != 0) return error.BoundaryEpochMismatch;
            var rng_state: actor_mod.IoRandom = undefined;
            const seed = try store.seed_or_random(.zero(), self.random(&rng_state));
            try store.put_seed(.zero(), seed);
            return self.prepare_epoch(store, .{
                .epoch = .zero(),
                .phase = bounds.phase(),
                .participants = participants,
                .previous = null,
                .share = null,
                .seed = seed,
            });
        }

        /// The outcome the stored final DKG block carries (null for a failed DKG).
        fn final_info(self: *Actor, last: Height) !?Info {
            var block = try self.config.marshal.get_block(.{ .height = last }) orelse
                return error.MissingFinalDkgBlock;
            defer block.deinit();
            var payload = try block.inner().payload(self.gpa) orelse return null;
            if (payload != .epoch_info) {
                payload.deinit(self.gpa);
                return error.UnexpectedFinalPayload;
            }
            return payload.epoch_info;
        }

        /// Reports the epoch-zero info the store committed, if any (commonware
        /// `complete_dkg`).
        fn complete_from(self: *Actor, store: *const Actor.Store) !void {
            const current = store.current_info();
            const committed = current != null and current.?.epoch.get() == 0;
            complete(self, if (committed) try current.?.clone(self.gpa) else null);
        }

        /// Sends `info` (taken) on the completion, once.
        fn complete(self: *Actor, info: ?Info) void {
            const outcome: Actor.DkgOutcome = .{ .gpa = self.gpa, .info = info };
            const dkg = mode(self) catch unreachable; // Proof: callers run in DKG mode.
            var completion = dkg.completion orelse return outcome.discard();
            dkg.completion = null;
            completion.send(outcome) catch outcome.discard();
            assert(dkg.completion == null);
        }

        /// Serves requests once the outcome is reported, until the mailbox closes: no log, no
        /// epoch info, and every finalized block acknowledged (commonware `terminal`).
        pub fn terminal(self: *Actor) !void {
            assert(self.mode == .dkg);
            // Each pass consumes one message; the mailbox bounds what arrives.
            while (try self.mailbox.recv()) |message| {
                switch (message.body) {
                    .next_log => |body| actor_mod.answer(body.response, null),
                    .release_log => {},
                    .epoch_info => |body| {
                        var ancestry = body.ancestry;
                        ancestry.deinit();
                        actor_mod.answer(body.response, .unavailable);
                    },
                    .finalized => |body| {
                        var block = body.block;
                        block.deinit();
                        var response = body.response;
                        response.acknowledge();
                    },
                }
            }
            assert(self.mode == .dkg);
        }
    };
}
