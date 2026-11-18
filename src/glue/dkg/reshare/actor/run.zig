//! The reshare actor's epoch loop (commonware `reshare/actor/mod.rs`'s `run` loop and
//! `participate`).
//!
//! Each iteration sets up the epoch after the applied tip. A node that cannot participate
//! follows the chain to the epoch's final block; otherwise it registers the epoch's
//! subchannel on the dealing mux and runs the epoch's dealing window (when it entered in the
//! early phase), then its inclusion window, which answers the requests dealing held.

const std = @import("std");
const assert = std.debug.assert;
const dealing = @import("dealing.zig");
const inclusion_window = @import("inclusion_window.zig");
const actor_mod = @import("actor.zig");

/// The epoch-loop functions for `Actor(T)`.
pub fn Runner(comptime T: type) type {
    return struct {
        const Actor = actor_mod.Actor(T);
        const Dealing = dealing.Window(T);
        const Inclusion = inclusion_window.Window(T);

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
