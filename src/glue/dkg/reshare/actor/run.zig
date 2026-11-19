//! The reshare actor's epoch loop (commonware `reshare/actor/mod.rs`'s `run` loop and
//! `participate`).
//!
//! Each iteration sets up the epoch after the applied tip. A node that cannot participate
//! follows the chain to the epoch's final block; otherwise it registers the epoch's
//! subchannel on the dealing mux and runs the epoch's dealing window (when it entered in the
//! early phase), then its inclusion window, which answers the requests dealing held.
//!
//! `run` is the actor's task (commonware `Actor::start`'s `run`): it multiplexes the
//! dealing channel by epoch, applies the resolved startup, and runs DKG mode or the epoch
//! loop. `resolve_start` resolves that startup from marshal's processed anchor and the
//! state-sync plan (commonware does it at the top of `run`); call it before `run`.

const std = @import("std");
const assert = std.debug.assert;
const dealing = @import("dealing.zig");
const inclusion_window = @import("inclusion_window.zig");
const actor_mod = @import("actor.zig");
const dkg = @import("dkg.zig");
const p2p = @import("p2p");
const consensus = @import("consensus");
const runtime = @import("runtime");
const setup_mod = @import("setup.zig");
const sync = @import("../../state_sync.zig");

const Epoch = consensus.Epoch;
const Processed = consensus.marshal.core.floor.Processed;

/// The epoch-loop functions for `Actor(T)`.
pub fn Runner(comptime T: type) type {
    return struct {
        const Actor = actor_mod.Actor(T);
        const Dealing = dealing.Window(T);
        const Inclusion = inclusion_window.Window(T);

        /// Where the actor starts: the tip it already applied (commonware `startup`'s
        /// result) and the state-synced epoch, if any (owned).
        pub const Start = struct {
            tip: ?Actor.Tip = null,
            state_sync: ?Actor.StateSyncStart = null,
        };

        /// Resolves where the actor starts (the top of commonware's `run`): reads marshal's
        /// processed anchor, resolves the shared state-sync `plan` against the epoch it
        /// recovered, and waits for marshal to yield the synced floor block. `marshal`
        /// provides `get_anchor() !?{ processed, block }` and `subscribe_by_commitment(digest,
        /// .wait) !oneshot.Receiver(Digested)`; `plan` is a `state_sync.Plan` (borrowed).
        /// `error.MissingStateSyncFloor` if marshal drops the floor subscription (commonware
        /// panics).
        pub fn resolve_start(
            self: *Actor,
            storage: runtime.storage.Storage,
            plan: anytype,
            marshal: anytype,
        ) !Start {
            var anchor = try marshal.get_anchor();
            defer if (anchor) |*value| value.block.deinit();
            const processed: ?struct { Processed, *const Actor.Digested } = if (anchor) |*value|
                .{ value.processed, &value.block }
            else
                null;
            const recovered: ?Epoch = if (anchor) |value|
                sync.recovered_epoch(value.processed, self.epocher)
            else
                null;
            var material = try plan.resolve(storage, recovered) orelse
                return .{ .tip = setup_mod.startup(Actor.Digested, processed, null) };
            defer material.floor.deinit(self.gpa);
            errdefer material.info.deinit(self.gpa);
            const commitment = material.floor.proposal.payload;
            var subscription = try marshal.subscribe_by_commitment(commitment, .wait);
            defer subscription.deinit();
            var floor = subscription.recv() catch |err| switch (err) {
                error.Closed => return error.MissingStateSyncFloor,
                error.Canceled => return error.Canceled,
            };
            defer floor.deinit();
            assert(floor.digest().eql(commitment));
            const tip = setup_mod.startup(Actor.Digested, processed, &floor);
            assert(tip != null or floor.inner().height().get() == 0);
            return .{
                .tip = tip,
                .state_sync = .{ .info = material.info, .floor = floor.inner().height() },
            };
        }

        /// Runs the actor on its dealing channel (`sender` and `receiver`, taken) until the
        /// mailbox or a dealing channel closes.
        pub fn run(
            self: *Actor,
            store: *Actor.Store,
            sender: anytype,
            receiver: anytype,
            start: Start,
        ) !void {
            const Mux = p2p.utils.mux.Muxer(@TypeOf(sender), @TypeOf(receiver));
            var state_sync = start.state_sync;
            errdefer if (state_sync) |*synced| synced.info.deinit(self.gpa);
            const built = try Mux.init(self.gpa, self.io, sender, receiver);
            var handle = built.handle;
            defer handle.deinit();
            var demux = try built.muxer.start();
            defer if (demux.cancel(self.io)) |_| {} else |_| {};
            // Register the synced epoch before setup decides whether to participate in it.
            if (state_sync) |*synced| {
                const share = try self.recovered_share(store, &synced.info);
                try self.register_epoch(&synced.info, share);
            }
            assert(self.tip == null);
            self.tip = start.tip;
            if (self.mode == .dkg) {
                if (state_sync) |*synced| synced.info.deinit(self.gpa);
                state_sync = null;
                return dkg.Dkg(T).run_dkg(self, store, &handle);
            }
            const synced = state_sync;
            state_sync = null;
            return run_epochs(self, store, &handle, synced);
        }

        /// Runs `prepared`'s dealing window when the epoch was entered in its early phase,
        /// then its inclusion window (commonware `participate`). `proceed` once the epoch's
        /// final block is applied; `stop` when either window stops.
        pub fn participate(
            self: *Actor,
            store: *Actor.Store,
            prepared: *Actor.PreparedEpoch,
            sender: anytype,
            receiver: anytype,
        ) !actor_mod.Flow {
            assert(self.config.max_participants > 0);
            const dealer = if (prepared.dealer) |*value| value else null;
            const player = if (prepared.player) |*value| value else null;
            const requests: Inclusion.Requests = if (prepared.phase == .early) blk: {
                const session: Dealing.Session = .{
                    .epoch = prepared.epoch,
                    .store = store,
                    .dealer = dealer,
                    .player = player,
                };
                break :blk switch (try Dealing.dealing(self, session, sender, receiver)) {
                    .stop => return .stop,
                    .proceed => |held| held,
                };
            } else .empty;
            const session: Inclusion.Session = .{
                .epoch = prepared.epoch,
                .info = prepared.info,
                .store = store,
                .dealer = dealer,
            };
            const flow = try Inclusion.inclusion_window(self, session, requests);
            assert(flow == .stop or self.tip != null);
            return flow;
        }

        /// Runs epochs until the mailbox or a dealing channel closes (commonware `run`'s
        /// loop in reshare mode). `mux` is a `p2p.utils.mux.MuxHandle`; each participating
        /// epoch registers subchannel `epoch`. Takes `state_sync`, the synced epoch to start
        /// from.
        pub fn run_epochs(
            self: *Actor,
            store: *Actor.Store,
            mux: anytype,
            state_sync: ?Actor.StateSyncStart,
        ) !void {
            assert(self.mode == .reshare);
            var pending = state_sync;
            // Each pass applies at least one epoch's final block or returns.
            while (true) {
                const start = pending;
                pending = null;
                var setup = try self.setup_epoch(store, start);
                switch (setup) {
                    .follow => if (try self.follow(store) == .stop) return,
                    .participate => |*prepared| {
                        defer prepared.deinit(self.gpa);
                        var channel = try mux.register(prepared.epoch.get());
                        defer channel.sender.deinit();
                        defer channel.receiver.deinit();
                        const sender = &channel.sender;
                        const receiver = &channel.receiver;
                        if (try participate(self, store, prepared, sender, receiver) == .stop) {
                            return;
                        }
                    },
                }
            }
        }
    };
}
