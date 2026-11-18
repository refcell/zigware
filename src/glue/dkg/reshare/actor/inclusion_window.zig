//! The reshare actor's inclusion window (commonware `reshare/actor/inclusion.rs`'s
//! `inclusion`).
//!
//! The window offers this node's signed dealer log until a finalized block includes it,
//! records valid dealer logs from finalized blocks, and answers final-block `EpochInfo`
//! requests, including those held through the dealing window.
//!
//! Commonware's `select_loop!` is biased toward the mailbox, then the running scan. Here
//! each iteration drains a queued mailbox message first; otherwise, while a request is being
//! scanned, it races the mailbox, the scan of a fresh copy of the request's ancestry, and
//! the requester leaving with `Io.Select`. A scan that loses the race restarts on the next
//! iteration, and a finalized block always restarts it, so a scan checks against the latest
//! tip. Verification runs inline (see artifact.zig).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const consensus = @import("consensus");
const p2p = @import("p2p");
const utils = @import("utils");
const inclusion = @import("inclusion.zig");
const artifact = @import("artifact.zig");
const actor_mod = @import("actor.zig");

const Epoch = consensus.Epoch;
const Height = consensus.Height;
const N3f1 = utils.N3f1;
const log = std.log.scoped(.dkg_reshare);

/// The inclusion window's functions for `Actor(T)`.
pub fn Window(comptime T: type) type {
    return struct {
        const Actor = actor_mod.Actor(T);
        const V = Actor.V;
        const P = Actor.P;
        const Message = Actor.Message;
        const Response = Message.Response;
        const Art = artifact.Artifacts(T);
        const Logs = Art.Logs;
        const Scan = inclusion.PendingLogScan(V, P, T.Block.Digest);
        pub const Requests = inclusion.ArtifactRequests(T.Ancestry, Response);
        const Request = Requests.Request;

        /// The epoch a window runs and this node's role in it (borrowed).
        pub const Session = struct {
            epoch: Epoch,
            info: *const Actor.Round,
            store: *Actor.Store,
            dealer: ?*Actor.Dealer,
        };

        /// Request work for one window.
        const State = struct {
            requests: Requests,
            verification: inclusion.Verification(V, P) = .empty,
            cache: Art.Cache = .empty,
            /// The height of the proposal this node's log was last served for.
            served_at: ?Height = null,
            /// The request whose ancestry is being scanned.
            scanning: ?Request = null,
            /// A finalized block arrived after the scan began, so its result is stale.
            stale: bool = false,

            fn deinit(state: *State, gpa: Allocator) void {
                if (state.scanning) |request| Requests.discard(request);
                state.requests.deinit(gpa);
                state.verification.deinit(gpa);
                state.cache.deinit(gpa);
                state.* = undefined;
            }
        };

        const Event = union(enum) { mailbox: ?Message, scan: ?Logs, closed };
        const Step = enum { next, done, stop };

        /// Runs the inclusion window of `session.epoch` (commonware `inclusion`). Returns
        /// `proceed` once the epoch's final block is applied and `stop` when the mailbox
        /// closes. Requests still unanswered on return read as unavailable to their callers.
        pub fn inclusion_window(
            self: *Actor,
            session: Session,
            requests: Requests,
        ) !actor_mod.Flow {
            assert(self.config.max_participants > 0);
            assert(self.epocher.midpoint(session.epoch) != null);
            self.metrics.set_phase(.inclusion);
            var state: State = .{ .requests = requests };
            defer state.deinit(self.gpa);
            if (session.dealer) |dealer| _ = try dealer.finalize(N3f1);
            while (true) {
                try start_scan(self, session, &state);
                state.stale = false;
                var events = try next_events(self, session, &state);
                switch (try run_events(self, session, &state, &events)) {
                    .next => {},
                    .done => return .proceed,
                    .stop => return .stop,
                }
            }
        }

        /// Takes the oldest waiting request for scanning once no scan runs and the block
        /// before the midpoint is applied (commonware `advance_artifact_requests`).
        fn start_scan(self: *Actor, session: Session, state: *State) !void {
            if (state.scanning != null) return;
            const midpoint = self.epocher.midpoint(session.epoch).?;
            // The scan checks its lowest block against the finalized tip, so wait until the
            // tip reaches the block before the midpoint.
            if (midpoint.previous()) |predecessor| {
                const tip = self.tip orelse return;
                if (tip.height.get() < predecessor.get()) return;
            }
            state.scanning = state.requests.pop();
            assert(state.scanning == null or !state.scanning.?.response.is_closed());
        }

        fn scan_of(self: *const Actor, session: Session) Scan {
            assert(self.config.blocks_per_epoch > 1);
            return .{
                .epoch = session.epoch,
                .info = session.info,
                .epocher = self.epocher,
                .finalized_tip = self.tip,
                .final_height = self.epocher.last(session.epoch).?,
            };
        }

        /// The next events: a mailbox message already queued, else the first of the mailbox,
        /// the scan, and the requester leaving to finish (each that finished).
        fn next_events(self: *Actor, session: Session, state: *State) !Events {
            assert(self.config.mailbox_size > 0);
            var events: Events = .{ .gpa = self.gpa };
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
            const request = state.scanning orelse {
                events.push(.{ .mailbox = try self.mailbox.recv() });
                return events;
            };
            const ancestry = try request.ancestry.clone();
            var buffer: [3]Tasks.Outcome = undefined;
            var select: Io.Select(Tasks.Outcome) = .init(self.io, &buffer);
            const params = scan_of(self, session);
            select.concurrent(.scan, Tasks.scan, .{ self.gpa, params, ancestry }) catch |err| {
                var owned = ancestry;
                owned.deinit();
                return err;
            };
            try race(&select, &events, self, request.response);
            if (events.failure) |err| {
                events.release();
                return err;
            }
            events.order();
            return events;
        }

        /// Races the mailbox and the requester against the running scan, then cancels the
        /// rest, collecting every finished outcome.
        fn race(select: anytype, events: *Events, self: *Actor, response: anytype) !void {
            errdefer while (select.cancel()) |outcome| events.collect(outcome);
            try select.concurrent(.mailbox, Tasks.mailbox, .{self});
            try select.concurrent(.closed, Tasks.closed, .{response});
            events.collect(try select.await());
            while (select.cancel()) |outcome| events.collect(outcome);
            assert(events.len > 0 or events.failure != null);
        }

        const Tasks = struct {
            const Outcome = union(enum) {
                mailbox: Io.Cancelable!?Message,
                scan: anyerror!?Logs,
                closed: Io.Cancelable!void,
            };

            fn mailbox(actor: *Actor) Io.Cancelable!?Message {
                return actor.mailbox.recv();
            }

            fn scan(gpa: Allocator, params: Scan, ancestry: T.Ancestry) anyerror!?Logs {
                var owned = ancestry;
                defer owned.deinit();
                return inclusion.pending_logs(T.Block, gpa, params, &owned);
            }

            fn closed(response: @FieldType(Request, "response")) Io.Cancelable!void {
                return response.closed();
            }
        };

        const Events = struct {
            gpa: Allocator,
            items: [3]Event = undefined,
            len: usize = 0,
            failure: ?anyerror = null,

            fn push(events: *Events, event: Event) void {
                assert(events.len < events.items.len);
                events.items[events.len] = event;
                events.len += 1;
            }

            /// Records a finished task; a canceled one produced nothing.
            fn collect(events: *Events, outcome: Tasks.Outcome) void {
                switch (outcome) {
                    .mailbox => |result| if (result) |message| {
                        events.push(.{ .mailbox = message });
                    } else |_| {},
                    .scan => |result| if (result) |logs| {
                        events.push(.{ .scan = logs });
                    } else |err| if (err != error.Canceled) {
                        events.failure = events.failure orelse err;
                    },
                    .closed => |result| if (result) |_| events.push(.closed) else |_| {},
                }
                assert(events.len <= events.items.len);
            }

            /// Puts the mailbox first, then the scan, as commonware's biased select would.
            fn order(events: *Events) void {
                const items = events.items[0..events.len];
                std.mem.sort(Event, items, {}, before);
                assert(events.len <= events.items.len);
            }

            fn before(_: void, a: Event, b: Event) bool {
                return @backingInt(a) < @backingInt(b);
            }

            fn release(events: *Events) void {
                for (events.items[0..events.len]) |event| discard(events.gpa, event);
                events.len = 0;
            }
        };

        fn discard(gpa: Allocator, event: Event) void {
            switch (event) {
                .mailbox => |message| if (message) |value| Message.discard(value),
                .scan => |logs| if (logs) |value| {
                    var owned = value;
                    owned.deinit(gpa);
                },
                .closed => {},
            }
        }

        /// Handles `events` in order until one ends the window; the rest are released.
        fn run_events(self: *Actor, session: Session, state: *State, events: *Events) !Step {
            assert(events.len > 0);
            var index: usize = 0;
            defer for (events.items[index..events.len]) |event| discard(self.gpa, event);
            while (index < events.len) {
                const event = events.items[index];
                index += 1;
                const step = try handle_event(self, session, state, event);
                if (step != .next) return step;
            }
            assert(index == events.len);
            return .next;
        }

        fn handle_event(self: *Actor, session: Session, state: *State, event: Event) !Step {
            assert(self.config.mailbox_size > 0);
            switch (event) {
                .mailbox => |received| {
                    const message = received orelse {
                        log.debug("mailbox closed, shutting down", .{});
                        return .stop;
                    };
                    return handle_mailbox(self, session, state, message);
                },
                .scan => |logs| {
                    if (state.stale) {
                        // The scan began before a finalized block: rescan from the new tip.
                        if (logs) |value| {
                            var owned = value;
                            owned.deinit(self.gpa);
                        }
                        return .next;
                    }
                    try complete_scan(self, session, state, logs);
                },
                .closed => {
                    Requests.discard(state.scanning.?);
                    state.scanning = null;
                },
            }
            return .next;
        }

        fn handle_mailbox(self: *Actor, session: Session, state: *State, message: Message) !Step {
            assert(self.config.blocks_per_epoch > 1);
            switch (message.body) {
                .next_log => |body| try next_log(self, session, state, body.height, body.response),
                .release_log => |height| {
                    const served = state.served_at orelse return .next;
                    if (served.get() == height.get() and holds_log(session)) {
                        state.served_at = null;
                    }
                },
                .epoch_info => |body| {
                    const request: Request = .{
                        .ancestry = body.ancestry,
                        .response = body.response,
                    };
                    _ = try state.requests.push(self.gpa, request);
                },
                .finalized => |body| {
                    var response = body.response;
                    errdefer response.deinit();
                    const done = try handle_finalized(self, session, state, body.block);
                    response.acknowledge();
                    if (done) return .done;
                },
            }
            return .next;
        }

        fn holds_log(session: Session) bool {
            const dealer = session.dealer orelse return false;
            return dealer.finalized != null;
        }

        /// Answers a dealer-log request with this node's signed log unless it is already
        /// served, recording `height` once delivered (commonware `handle_next_log`).
        fn next_log(
            self: *Actor,
            session: Session,
            state: *State,
            height: Height,
            response: anytype,
        ) !void {
            const gpa = self.gpa;
            var payload: ?Art.Payload = null;
            if (state.served_at == null and holds_log(session)) {
                const signed = try session.dealer.?.finalized.?.clone(gpa);
                payload = .{ .dealer_log = signed };
            }
            var responder = response;
            const offered = payload != null;
            responder.send(payload) catch {
                if (payload) |*value| value.deinit(gpa);
                return;
            };
            if (offered) state.served_at = height;
            assert(!offered or state.served_at != null);
        }

        /// Applies a new finalized block (taken) of the inclusion window; true when it is the
        /// epoch's final block, whose `EpochInfo` is then committed.
        fn handle_finalized(
            self: *Actor,
            session: Session,
            state: *State,
            finalized: Actor.Digested,
        ) !bool {
            var block = finalized;
            defer block.deinit();
            if (try self.covered(&block)) return false;
            const epoch = session.epoch;
            const height = block.inner().height();
            const bounds = self.epocher.containing(height) orelse return error.UnknownHeight;
            if (bounds.epoch.get() != epoch.get()) return error.OutOfPhaseBlock;
            if (bounds.phase() == .early) return error.OutOfPhaseBlock;
            state.stale = true;
            const gpa = self.gpa;
            const store = session.store;
            const observed = try block.inner().payload(gpa);
            try Art.observe_dealer_log(self, session.info, store, epoch, session.dealer, observed);
            const done = height.get() == bounds.last.get();
            if (done) {
                const artifact_value = try artifact_for(self, session, state, null);
                const carried = try block.inner().payload(gpa);
                try Art.commit_final(self, epoch, store, artifact_value, carried);
            }
            // A log still held once finalization reaches its served height was not included,
            // so it becomes available to the next request.
            if (state.served_at) |served| {
                if (height.get() >= served.get() and holds_log(session)) state.served_at = null;
            }
            self.advance(&block);
            return done;
        }

        /// The artifact for `logs` (borrowed; the finalized logs when null), from the cache,
        /// the retained verification, or a new verification (commonware
        /// `complete_epoch_artifact`'s and `complete_artifact_scan`'s shared path).
        fn artifact_for(
            self: *Actor,
            session: Session,
            state: *State,
            logs: ?Logs,
        ) !?*const Art.Artifact {
            const gpa = self.gpa;
            const epoch = session.epoch;
            const store = session.store;
            var canonical = try Logs.from_sorted(gpa, store.logs(epoch));
            defer canonical.deinit(gpa);
            const target = logs orelse canonical;
            if (state.cache.get(target)) |cached| return if (cached.artifact) |*a| a else null;
            if (state.verification.ready(target)) |ceremony| {
                const retained = if (ceremony.*) |*value| value else null;
                return Art.derive(self, epoch, store, target, retained, &state.cache);
            }
            var ceremony = try Art.verify(self, epoch, session.info, store, target);
            var verified: inclusion.VerifiedLogs(V, P) = .{ .logs = .empty, .ceremony = ceremony };
            errdefer verified.deinit(gpa);
            const borrowed = if (ceremony) |*value| value else null;
            const result = try Art.derive(self, epoch, store, target, borrowed, &state.cache);
            verified.logs = try target.clone(gpa);
            state.verification.retain(gpa, verified, canonical);
            return result;
        }

        /// Answers the scanned request (commonware `complete_artifact_scan`): unavailable when
        /// the scan failed, otherwise the artifact of the finalized logs with the pending
        /// ones (taken) filling dealer slots the journal has not claimed.
        fn complete_scan(self: *Actor, session: Session, state: *State, pending: ?Logs) !void {
            const gpa = self.gpa;
            const request = state.scanning.?;
            state.scanning = null;
            var ancestry = request.ancestry;
            defer ancestry.deinit();
            var responder = request.response;
            var scanned = pending orelse return respond(&responder, .unavailable);
            defer scanned.deinit(gpa);
            errdefer responder.deinit();
            var logs = try Logs.from_sorted(gpa, session.store.logs(session.epoch));
            defer logs.deinit(gpa);
            for (scanned.entries.items) |entry| {
                _ = try logs.put_first(gpa, entry.key, try entry.log.clone(gpa));
            }
            if (responder.is_closed()) return responder.deinit();
            const value = try artifact_for(self, session, state, logs);
            respond(&responder, try Art.response(self, value));
        }

        /// Sends `value` (taken) and releases `responder`; a requester that left loses
        /// nothing.
        fn respond(responder: anytype, value: Response) void {
            assert(@typeInfo(@TypeOf(responder)) == .pointer);
            responder.send(value) catch value.discard();
        }
    };
}
