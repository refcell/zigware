//! The reshare actor's dealing window (commonware `reshare/actor/dealing.rs`).
//!
//! Dealers and players exchange dealings and acknowledgements over the epoch's P2P channel,
//! and this node resends its unacknowledged dealings on each finalized block of the epoch's
//! first half. Dealer-log requests get no log, and final-block requests wait for the
//! inclusion window.
//!
//! Commonware's `select_loop!` is biased toward the mailbox. Here `next_events` first drains
//! the mailbox with `try_recv`, then races the mailbox against the network with `Io.Select`.
//! When both finish in the same race, both events are handled, mailbox first.

const std = @import("std");
const assert = std.debug.assert;
const target = "commonware_glue::dkg::reshare::actor::dealing";
const Io = std.Io;
const codec = @import("codec");
const consensus = @import("consensus");
const p2p = @import("p2p");
const types = @import("../../types.zig");
const inclusion = @import("inclusion.zig");
const actor_mod = @import("actor.zig");

const Epoch = consensus.Epoch;

/// The dealing window's functions for `Actor(T)`.
pub fn Window(comptime T: type) type {
    return struct {
        const Actor = actor_mod.Actor(T);
        const P = Actor.P;
        const Message = Actor.Message;
        const Wire = types.Message(Actor.V, P);
        pub const Requests = inclusion.ArtifactRequests(T.Ancestry, Message.Response);

        /// The epoch a window runs and this node's roles in it (borrowed).
        pub const Session = struct {
            epoch: Epoch,
            store: *Actor.Store,
            dealer: ?*Actor.Dealer,
            player: ?*Actor.Player,
        };

        /// How a dealing window ended: at the block before the midpoint, with the final-block
        /// requests it held (`proceed`), or because the mailbox or the channel closed.
        pub const Outcome = union(enum) { proceed: Requests, stop };

        /// One event of the window: a mailbox message (null once the mailbox closed) or a
        /// network message (null once the channel closed).
        const Event = union(enum) { mailbox: ?Message, network: ?p2p.Message(P) };

        const Step = enum { next, done, stop };

        /// Runs the dealing window of `session.epoch` (commonware `dealing`). Returns the held
        /// requests once the block before the midpoint is acknowledged. Fails with a
        /// `ContractError` on a finalized block outside the epoch's early phase.
        pub fn dealing(
            self: *Actor,
            session: Session,
            sender: anytype,
            receiver: anytype,
        ) !Outcome {
            assert(self.config.max_participants > 0);
            assert(self.epocher.midpoint(session.epoch) != null);
            self.metrics.set_phase(.dealing);
            var requests: Requests = .empty;
            errdefer requests.deinit(self.gpa);
            while (true) {
                var events = try next_events(self, receiver);
                switch (try run_events(self, session, sender, &requests, &events)) {
                    .next => {},
                    .done => return .{ .proceed = requests },
                    .stop => {
                        requests.deinit(self.gpa);
                        return .stop;
                    },
                }
            }
        }

        /// Handles `events` in order until one ends the window; the rest are released.
        fn run_events(
            self: *Actor,
            session: Session,
            sender: anytype,
            requests: *Requests,
            events: *Events,
        ) !Step {
            assert(events.len > 0);
            var index: usize = 0;
            // Each handled event is owned by its handler; release the ones never reached.
            defer for (events.items[index..events.len]) |event| discard(event);
            while (index < events.len) {
                const event = events.items[index];
                index += 1;
                const step = try handle_event(self, session, sender, requests, event);
                if (step != .next) return step;
            }
            assert(index == events.len);
            return .next;
        }

        fn handle_event(
            self: *Actor,
            session: Session,
            sender: anytype,
            requests: *Requests,
            event: Event,
        ) !Step {
            assert(self.config.mailbox_size > 0);
            switch (event) {
                .mailbox => |received| {
                    const message = received orelse {
                        const text = "mailbox closed, shutting down";
                        self.tracer.with_target(target).event(.debug, text, .{});
                        return .stop;
                    };
                    return handle_mailbox(self, session, sender, requests, message);
                },
                .network => |received| {
                    var message = received orelse {
                        const text = "dealing channel closed, shutting down";
                        self.tracer.with_target(target).event(.debug, text, .{});
                        return .stop;
                    };
                    defer message.deinit();
                    try handle_message(self, session, sender, message.peer, message.payload);
                    return .next;
                },
            }
        }

        fn handle_mailbox(
            self: *Actor,
            session: Session,
            sender: anytype,
            requests: *Requests,
            message: Message,
        ) !Step {
            assert(self.config.blocks_per_epoch > 1);
            switch (message.body) {
                .next_log => |body| actor_mod.answer(body.response, null),
                .release_log => {},
                .epoch_info => |body| {
                    const request: Requests.Request = .{
                        .ancestry = body.ancestry,
                        .response = body.response,
                    };
                    if (try requests.push(self.gpa, request)) {
                        const text = "holding final-block request until the epoch midpoint";
                        self.tracer.with_target(target).event(.debug, text, .{});
                    }
                },
                .finalized => |body| {
                    var response = body.response;
                    errdefer response.deinit();
                    const done = try handle_finalized(self, session, sender, body.block);
                    response.acknowledge();
                    if (done) return .done;
                },
            }
            return .next;
        }

        /// Resends unacknowledged dealings on a new finalized block (taken) and applies it;
        /// true when it is the last block before the midpoint.
        fn handle_finalized(
            self: *Actor,
            session: Session,
            sender: anytype,
            finalized: Actor.Digested,
        ) !bool {
            var block = finalized;
            defer block.deinit();
            if (try self.covered(&block)) return false;
            const epoch = session.epoch;
            const height = block.inner().height();
            const bounds = self.epocher.containing(height) orelse return error.UnknownHeight;
            if (bounds.epoch.get() != epoch.get()) return error.OutOfPhaseBlock;
            if (bounds.phase() != .early) return error.OutOfPhaseBlock;
            if (session.dealer) |dealer| try send_dealings(self, session, dealer, sender);
            const before = self.epocher.midpoint(epoch).?.previous();
            self.advance(&block);
            assert(self.tip.?.height.get() == height.get());
            return before != null and before.?.get() == height.get();
        }

        /// The next events: a mailbox message already queued, else the first of the mailbox
        /// and the network to deliver (both when both finish).
        fn next_events(self: *Actor, receiver: anytype) !Events {
            assert(self.config.mailbox_size > 0);
            var events: Events = .{};
            if (self.mailbox.try_recv()) |message| {
                events.push(.{ .mailbox = message });
                return events;
            } else |err| switch (err) {
                error.Disconnected => {
                    events.push(.{ .mailbox = null });
                    return events;
                },
                error.Empty => {},
            }
            const Tasks = RecvTasks(@TypeOf(receiver));
            var buffer: [2]Tasks.Outcome = undefined;
            var select: Io.Select(Tasks.Outcome) = .init(self.io, &buffer);
            try select.concurrent(.mailbox, Tasks.mailbox, .{self});
            select.concurrent(.network, Tasks.network, .{receiver}) catch |err| {
                while (select.cancel()) |outcome| events.collect(outcome);
                return err;
            };
            const first = select.await() catch |err| {
                while (select.cancel()) |outcome| events.collect(outcome);
                return err;
            };
            events.collect(first);
            while (select.cancel()) |outcome| events.collect(outcome);
            events.order();
            // Both receives returned `error.Canceled`, which `collect` drops: the actor's task
            // is being canceled (a shutdown cancels every task at once).
            if (events.len == 0) return error.Canceled;
            assert(events.len > 0);
            return events;
        }

        fn RecvTasks(comptime R: type) type {
            return struct {
                const Outcome = union(enum) {
                    mailbox: Io.Cancelable!?Message,
                    network: Io.Cancelable!?p2p.Message(P),
                };

                fn mailbox(actor: *Actor) Io.Cancelable!?Message {
                    return actor.mailbox.recv();
                }

                fn network(net: R) Io.Cancelable!?p2p.Message(P) {
                    // A receive failure other than cancelation means the channel closed.
                    return net.recv() catch |err| {
                        if (err == error.Canceled) return error.Canceled;
                        return null;
                    };
                }
            };
        }

        const Events = struct {
            items: [2]Event = undefined,
            len: usize = 0,

            fn push(events: *Events, event: Event) void {
                assert(events.len < events.items.len);
                events.items[events.len] = event;
                events.len += 1;
            }

            /// Records a finished receive; a canceled one received nothing.
            fn collect(events: *Events, outcome: anytype) void {
                assert(events.len < events.items.len);
                switch (outcome) {
                    .mailbox => |result| if (result) |message| {
                        events.push(.{ .mailbox = message });
                    } else |_| {},
                    .network => |result| if (result) |message| {
                        events.push(.{ .network = message });
                    } else |_| {},
                }
            }

            /// Puts a mailbox event first, as commonware's biased select would.
            fn order(events: *Events) void {
                assert(events.len <= events.items.len);
                if (events.len == 2 and events.items[1] == .mailbox) {
                    std.mem.swap(Event, &events.items[0], &events.items[1]);
                }
            }
        };

        fn discard(event: Event) void {
            switch (event) {
                .mailbox => |message| if (message) |value| Message.discard(value),
                .network => |message| if (message) |value| {
                    var owned = value;
                    owned.deinit();
                },
            }
        }

        /// Handles one network message from `from` (commonware `handle_message`): a dealing
        /// for this node's player, or an acknowledgement for its dealer. Blocks senders of
        /// undecodable, misdirected, or invalid messages.
        pub fn handle_message(
            self: *Actor,
            session: Session,
            sender: anytype,
            from: P,
            bytes: []const u8,
        ) !void {
            const max = self.config.max_participants;
            assert(max > 0);
            const epoch = session.epoch;
            var message = codec.decode_cfg(Wire, self.gpa, bytes, max) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return block_peer(self, from, epoch, "failed to decode dealing message"),
            };
            defer message.deinit(self.gpa);
            switch (message) {
                .dealer => |offer| {
                    const player = session.player orelse
                        return block_peer(self, from, epoch, "dealing sent to non-player");
                    try handle_dealing(self, session, player, sender, from, offer);
                },
                .ack => |ack| {
                    const dealer = session.dealer orelse
                        return block_peer(self, from, epoch, "ack sent to non-dealer");
                    try handle_ack(self, session, dealer, from, ack);
                },
            }
        }

        fn handle_dealing(
            self: *Actor,
            session: Session,
            player: *Actor.Player,
            sender: anytype,
            from: P,
            offer: @FieldType(Wire, "dealer"),
        ) !void {
            const epoch = session.epoch;
            const store = session.store;
            const ack = player.handle(store, epoch, from, offer.pub_msg, offer.priv_msg) catch |err|
                switch (err) {
                    error.UnexpectedDealer => {
                        return block_peer(self, from, epoch, "dealing from unexpected dealer");
                    },
                    error.InvalidCommitmentDegree,
                    error.MismatchedReshareCommitment,
                    error.InvalidDealerShare,
                    => return block_peer(self, from, epoch, "invalid dealing"),
                    else => |other| return other,
                };
            self.metrics.record_share(from, epoch.get());
            const t = self.tracer.with_target(target);
            t.event(.info, "received dealing", .{ .epoch = epoch, .dealer = from });
            const sent = try send_wire(self, sender, from, .{ .ack = ack });
            if (!sent) t.event(.warn, "failed to send ack", .{ .epoch = epoch, .dealer = from });
            assert(player.acks.len() > 0);
        }

        fn handle_ack(
            self: *Actor,
            session: Session,
            dealer: *Actor.Dealer,
            from: P,
            ack: @FieldType(Wire, "ack"),
        ) !void {
            const epoch = session.epoch;
            assert(dealer.dealer != null);
            const store = session.store;
            const outcome = dealer.handle(store, epoch, from, ack) catch |err| switch (err) {
                // An authenticated non-player cannot acknowledge this round.
                error.UnexpectedPlayer => {
                    return block_peer(self, from, epoch, "ack from unexpected player");
                },
                // This dealer sends one public message per epoch (its seed is persisted) and
                // the channel authenticates the sender, so a mismatched acknowledgement
                // cannot come from an honest player.
                error.InvalidAck => return block_peer(self, from, epoch, "invalid ack signature"),
                else => |other| return other,
            };
            if (outcome == .recorded) {
                self.metrics.record_ack(from, epoch.get());
                const fields = .{ .epoch = epoch, .player = from };
                self.tracer.with_target(target).event(.info, "received ack", fields);
            }
        }

        /// Blocks `peer` for violating the protocol (commonware `block!`).
        fn block_peer(self: *Actor, peer: P, epoch: Epoch, reason: []const u8) void {
            assert(reason.len > 0);
            assert(self.config.max_participants > 0);
            // commonware_p2p's `block!`: a warning naming the peer and the reason.
            const fields = .{ .peer = peer, .epoch = epoch };
            self.tracer.with_target(target).event(.warn, reason, fields);
            // A p2p blocker's `Feedback` only says whether the request was queued.
            _ = self.config.blocker.block(peer);
        }

        /// Sends `message` to `recipient` with priority; false when nobody took it.
        fn send_wire(self: *Actor, sender: anytype, recipient: P, message: Wire) !bool {
            const encoded = try codec.encode(Wire, self.gpa, message);
            defer self.gpa.free(encoded);
            assert(encoded.len == message.encode_size());
            const sent = try sender.send(.{ .one = recipient }, &.{encoded}, true);
            defer self.gpa.free(sent);
            assert(sent.len <= 1);
            return sent.len > 0;
        }

        /// Sends each unacknowledged dealing; this node's own dealing goes straight to its
        /// player (commonware `send_dealings`).
        fn send_dealings(
            self: *Actor,
            session: Session,
            dealer: *Actor.Dealer,
            sender: anytype,
        ) !void {
            const gpa = self.gpa;
            const epoch = session.epoch;
            const key = self.config.signer.public_key();
            // `handle` removes acknowledged players from the dealer's list, so iterate a copy.
            const pending = dealer.shares_to_distribute();
            const unsent = try gpa.dupe(std.meta.Elem(@TypeOf(pending)), pending);
            defer gpa.free(unsent);
            assert(unsent.len == pending.len);
            for (unsent) |item| {
                if (item.player.eql(key)) {
                    const own = session.player orelse continue;
                    const store = session.store;
                    const ack = try own.handle(store, epoch, key, dealer.public, item.msg);
                    _ = try dealer.handle(store, epoch, key, ack);
                    continue;
                }
                const offer: Wire = .{
                    .dealer = .{ .pub_msg = dealer.public, .priv_msg = item.msg },
                };
                const fields = .{ .epoch = epoch, .recipient = item.player };
                if (try send_wire(self, sender, item.player, offer)) {
                    self.tracer.with_target(target).event(.debug, "sent share", fields);
                } else {
                    self.tracer.with_target(target).event(.debug, "failed to send share", fields);
                }
            }
        }
    };
}
