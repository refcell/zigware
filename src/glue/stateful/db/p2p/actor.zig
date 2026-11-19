//! The resolver service actor for QMDB sync over P2P (commonware
//! `glue/src/stateful/db/p2p/actor.rs`).
//!
//! `Actor(T)` runs a `resolver.p2p.Engine` whose consumer and producer are a `Handler`, so every
//! engine callback reaches the actor as a message. It fetches for local `Mailbox` callers and
//! serves peers from the attached database (`state_sync.SharedSource`): see `mod.zig` for the
//! fetch and serve contract.
//!
//! The actor owns every caller's reply sender, keyed by subscription id; the engine's
//! subscribers carry only the id (commonware's subscribers carry the sender itself). A delivery
//! reaches the callers its ids still name in that table, so a delivery queued before a caller
//! left can never touch a released sender. Close watchers, serves, and fan-out verdicts run as
//! tasks of one group and report back through the actor's event queue, so all mutable state
//! stays on the actor task.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const resolver = @import("resolver");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const handler_mod = @import("handler.zig");
const mailbox_mod = @import("mailbox.zig");
const metrics_mod = @import("metrics.zig");
const db = @import("../mod.zig");
const state_sync = @import("../state_sync.zig");

const sync = storage.qmdb.sync;
const mpsc = utils.channel.mpsc;
const oneshot = utils.channel.oneshot;
const metrics = runtime.telemetry.metrics;
const Status = metrics.status.Status;
const Duration = utils.Duration;
const Produced = handler_mod.Produced;

/// The actor's type parameters: public keys `P`, peer provider `D`, blocker `B`, database `DB`
/// (declaring `SyncSource` and `sync_source`, see `state_sync.SharedSource`), and the network
/// sender `NetS` and receiver `NetR`.
pub fn Params(
    comptime P: type,
    comptime D: type,
    comptime B: type,
    comptime DB: type,
    comptime NetS: type,
    comptime NetR: type,
) type {
    return struct {
        pub const PublicKey = P;
        pub const Provider = D;
        pub const Blocker = B;
        pub const Database = DB;
        pub const NetSender = NetS;
        pub const NetReceiver = NetR;
    };
}

/// Configuration for `Actor` (commonware `Config`).
pub fn Config(comptime P: type, comptime D: type, comptime B: type, comptime DB: type) type {
    return struct {
        /// Provider for the current peer set.
        peer_provider: D,
        /// Blocker used when peers send invalid data.
        blocker: B,
        /// Database to serve peer requests from, if already open (`Mailbox.attach_database`
        /// can attach one later). Borrowed: its owner keeps it open while the actor runs.
        database: ?db.Shared(DB),
        /// Capacity of resolver mailboxes (non-zero).
        mailbox_size: u32,
        /// Local node identity if available.
        me: ?P,
        /// Request timeout (non-zero).
        fetch_timeout: Duration,
        /// Delay after an unresolved attempt before retrying its fetch. Zero permits immediate
        /// retries, subject to the sender's rate limit.
        fetch_retry_delay: Duration,
        /// Largest `max_ops` served in a peer's operations request; larger requests go
        /// unanswered. Peers fetching from this node must keep their `fetch_batch_size` at or
        /// below it, or their requests never complete. Use the same value across the network.
        max_serve_ops: u64,
        /// Whether fetch requests are sent with network priority.
        priority_requests: bool,
        /// Whether responses are sent with network priority.
        priority_responses: bool,
    };
}

/// A QMDB state sync resolver that fetches from peers and serves them from a local database.
pub fn Actor(comptime T: type) type {
    const P = T.PublicKey;
    const DB = T.Database;
    const NetS = T.NetSender;
    const NetR = T.NetReceiver;
    const Source = state_sync.SharedSource(DB);
    return struct {
        const Self = @This();
        pub const Family = Source.Family;
        pub const Op = Source.Op;
        pub const Digest = Source.Digest;
        pub const Request = sync.Request(Family);
        pub const Response = sync.Response(Family, Op, Digest);
        pub const Mailbox = mailbox_mod.Mailbox(DB, Family, Op, Digest);
        pub const Message = Mailbox.Msg;
        pub const Reply = mailbox_mod.Reply(Response);
        /// The engine's subscriber: a caller's subscription id.
        pub const Subscriber = handler_mod.Subscriber(void);
        pub const Handler = handler_mod.Handler(Family, Subscriber);
        pub const EngineMessage = Handler.Message;
        pub const Deliver = @FieldType(EngineMessage, "deliver");
        pub const Engine = resolver.p2p.Engine(resolver.p2p.engine.Params(
            P,
            T.Provider,
            T.Blocker,
            Handler,
            Handler,
            NetS,
            NetR,
        ));
        pub const Cfg = Config(P, T.Provider, T.Blocker, DB);
        pub const Metrics = metrics_mod.Metrics;
        pub const Error = error{RequestIdOverflow} || Allocator.Error || Io.ConcurrentError;
        const Candidate = sync.source.Candidate(Response);
        const Fetch = resolver.Fetch(Request, Subscriber);
        const Predicate = resolver.Predicate(Request, Subscriber);

        /// Work reported to the actor task.
        pub const Event = union(enum) {
            /// A mailbox message; null once every `Mailbox` is gone.
            mailbox: ?Message,
            /// An engine callback; null once the handler's senders are gone.
            engine: ?EngineMessage,
            /// The caller of subscription `id` closed its reply receiver.
            closed: u64,
            /// A serve finished with this outcome.
            served: Status,
            /// The engine task returned.
            engine_stopped,

            pub fn discard(event: Event) void {
                switch (event) {
                    .mailbox => |message| if (message) |owned| Message.discard(owned),
                    .engine => |message| if (message) |owned| EngineMessage.discard(owned),
                    .closed, .served, .engine_stopped => {},
                }
            }
        };

        /// A created actor and the mailbox callers fetch through.
        pub const Created = struct { actor: *Self, mailbox: Mailbox };

        gpa: Allocator,
        io: Io,
        config: Cfg,
        scope: metrics.Scope,
        mailbox_rx: actor.mailbox.Receiver(Message),
        metrics: Metrics,
        next_id: u64 = 0,
        /// Every live caller's reply sender, by subscription id.
        pending: std.AutoArrayHashMapUnmanaged(u64, Reply) = .empty,
        events_tx: mpsc.Sender(Event),
        events_rx: mpsc.Receiver(Event),
        /// Close watchers, serves, fan-out verdicts, forwarders, and the engine.
        tasks: Io.Group = .init,
        // Set while running.
        handler: ?Handler = null,
        handler_rx: ?actor.mailbox.Receiver(EngineMessage) = null,
        engine_mailbox: ?Engine.Mailbox = null,
        engine_error: ?Engine.Error = null,

        /// Creates the actor and its mailbox (commonware `Actor::new`); `start` runs it.
        /// Metrics register under `scope`, the engine's under `scope.child("resolver")`.
        pub fn create(gpa: Allocator, io: Io, scope: metrics.Scope, config: Cfg) !Created {
            assert(config.mailbox_size > 0);
            assert(config.max_serve_ops > 0);
            var registered = try Metrics.init(&scope);
            errdefer registered.deinit();
            inline for (.{ Status.success, Status.dropped, Status.invalid, Status.failure }) |s| {
                // Creates each status up front, so later increments never allocate.
                try registered.deliveries.inc_by(s, 0);
                try registered.serve_requests.inc_by(s, 0);
            }
            _ = registered.has_database.metric().set(@intFromBool(config.database != null));
            var pair = try actor.mailbox.new(Message, gpa, io, config.mailbox_size);
            errdefer pair.sender.deinit();
            errdefer pair.receiver.deinit();
            const events = try mpsc.unbounded(Event, gpa, io);
            const self = gpa.create(Self) catch |err| {
                var owned = events;
                owned.sender.deinit();
                owned.receiver.deinit();
                return err;
            };
            self.* = .{
                .gpa = gpa,
                .io = io,
                .config = config,
                .scope = scope,
                .mailbox_rx = pair.receiver,
                .metrics = registered,
                .events_tx = events.sender,
                .events_rx = events.receiver,
            };
            return .{ .actor = self, .mailbox = .init(io, pair.sender) };
        }

        /// Cancels every task and frees the actor. Callers waiting on a fetch see it dropped.
        pub fn destroy(self: *Self) void {
            self.tasks.cancel(self.io);
            if (self.engine_mailbox) |*engine_mailbox| engine_mailbox.deinit();
            if (self.handler) |*handler| handler.deinit();
            if (self.handler_rx) |*handler_rx| handler_rx.deinit();
            self.events_tx.deinit();
            self.events_rx.deinit();
            for (self.pending.values()) |*reply| reply.deinit();
            self.pending.deinit(self.gpa);
            self.mailbox_rx.deinit();
            self.metrics.deinit();
            const gpa = self.gpa;
            self.* = undefined;
            gpa.destroy(self);
        }

        /// Starts the actor, fetching and serving over the network channel (commonware
        /// `start`). The task frees the actor when it returns: cancel it to stop.
        pub fn start(self: *Self, sender: NetS, receiver: NetR) Io.ConcurrentError!Io.Future(
            Error!void,
        ) {
            assert(self.handler == null);
            return self.io.concurrent(run, .{ self, sender, receiver });
        }

        /// Multiplexes mailbox messages, engine callbacks, and finished work until the engine
        /// stops or the task is canceled.
        fn run(self: *Self, sender: NetS, receiver: NetR) Error!void {
            defer self.destroy();
            try self.spawn_engine(sender, receiver);
            try self.tasks.concurrent(self.io, forward_mailbox, .{self});
            while (true) {
                const event = (self.events_rx.recv() catch return) orelse return;
                const resolver_mailbox = &self.engine_mailbox.?;
                if (!try self.handle_event(resolver_mailbox, event)) break;
            }
            if (self.engine_error) |err| return err;
        }

        fn spawn_engine(self: *Self, sender: NetS, receiver: NetR) Error!void {
            // Every handler entry is one message the network admitted on the channel, and peer
            // requests are dropped once the ready queue is full, so hold as many as the channel.
            const capacity: u32 = if (@hasDecl(NetR, "capacity"))
                @intCast(@max(1, receiver.capacity()))
            else
                self.config.mailbox_size;
            const handler_pair = try actor.mailbox.new(EngineMessage, self.gpa, self.io, capacity);
            self.handler = .{ .gpa = self.gpa, .io = self.io, .sender = handler_pair.sender };
            self.handler_rx = handler_pair.receiver;
            var engine_pair = try actor.mailbox.new(
                Engine.Message,
                self.gpa,
                self.io,
                self.config.mailbox_size,
            );
            self.engine_mailbox = .{ .gpa = self.gpa, .sender = engine_pair.sender };
            const config = self.config;
            // The engine borrows the handler: the actor releases it after the engine stops.
            const engine = Engine.create(self.gpa, self.io, self.scope.child("resolver"), .{
                .peer_provider = config.peer_provider,
                .blocker = config.blocker,
                .consumer = self.handler.?,
                .producer = self.handler.?,
                .mailbox_size = config.mailbox_size,
                .me = config.me,
                .fetch_timeout = config.fetch_timeout,
                .fetch_retry_delay = config.fetch_retry_delay,
                .priority_requests = config.priority_requests,
                .priority_responses = config.priority_responses,
            }, engine_pair.receiver, sender, receiver) catch |err| {
                engine_pair.receiver.deinit();
                return err;
            };
            self.tasks.concurrent(self.io, run_engine, .{ self, engine }) catch |err| {
                engine.destroy();
                return err;
            };
            try self.tasks.concurrent(self.io, forward_engine, .{self});
        }

        fn run_engine(self: *Self, engine: *Engine) Io.Cancelable!void {
            engine.run() catch |err| {
                self.engine_error = err;
            };
            self.report(.engine_stopped);
        }

        fn forward_mailbox(self: *Self) Io.Cancelable!void {
            while (true) {
                const message = try self.mailbox_rx.recv();
                self.report(.{ .mailbox = message });
                // Without callers the actor keeps serving peers (commonware waits forever).
                if (message == null) return;
            }
        }

        fn forward_engine(self: *Self) Io.Cancelable!void {
            while (true) {
                const message = try self.handler_rx.?.recv();
                self.report(.{ .engine = message });
                if (message == null) return;
            }
        }

        /// Queues `event` for the actor task. The queue is unbounded, so a send fails only
        /// without memory; the event is then dropped like an overflowed message.
        fn report(self: *Self, event: Event) void {
            self.events_tx.send(event) catch Event.discard(event);
        }

        /// Handles one event with `resolver` (the engine's mailbox while running); false when
        /// the actor should stop.
        pub fn handle_event(self: *Self, resolver_handle: anytype, event: Event) Error!bool {
            switch (event) {
                .mailbox => |message| {
                    const owned = message orelse return true;
                    try self.handle_mailbox_message(resolver_handle, owned);
                },
                .engine => |message| switch (message orelse return false) {
                    .deliver => |deliver| try self.handle_deliver(deliver),
                    .produce => |produce| try self.handle_produce(produce.key, produce.response),
                },
                .closed => |id| try self.handle_closed(resolver_handle, id),
                .served => |status| self.count(self.metrics.serve_requests, status),
                .engine_stopped => return false,
            }
            return true;
        }

        /// Waits for the next finished piece of work and handles it with `resolver` (commonware
        /// tests poll `work.next_completed()`).
        pub fn next_work(self: *Self, resolver_handle: anytype) (Error || Io.Cancelable)!void {
            const event = (try self.events_rx.recv()).?;
            assert(event == .closed or event == .served);
            _ = try self.handle_event(resolver_handle, event);
        }

        fn count(self: *Self, counter: metrics.status.Counter, status: Status) void {
            _ = self;
            // Proof: `create` registered every status the actor counts.
            counter.inc(status) catch unreachable;
        }

        /// Processes a database attachment or a fetch request.
        pub fn handle_mailbox_message(
            self: *Self,
            resolver_handle: anytype,
            message: Message,
        ) Error!void {
            switch (message) {
                .attach_database => |database| {
                    // Reads in progress keep the database handle they started with.
                    self.config.database = database;
                    _ = self.metrics.has_database.metric().set(1);
                },
                .get_operations => |fetch| try self.register(resolver_handle, fetch),
            }
        }

        /// Gives each caller a subscription that can be canceled independently.
        fn register(
            self: *Self,
            resolver_handle: anytype,
            fetch: @FieldType(Message, "get_operations"),
        ) Error!void {
            var reply = fetch.response;
            if (reply.is_closed()) {
                reply.deinit();
                return;
            }
            // Exhaustion fails before submission, so an id is never reused.
            if (self.next_id == std.math.maxInt(u64)) {
                reply.deinit();
                return error.RequestIdOverflow;
            }
            const id = self.next_id;
            self.pending.ensureUnusedCapacity(self.gpa, 1) catch |err| {
                reply.deinit();
                return err;
            };
            // The reply stays with the caller through every rejected candidate; closing its
            // receiver retires this exact subscription, even while a verdict is pending.
            self.tasks.concurrent(self.io, watch_closed, .{ self, id, reply }) catch |err| {
                reply.deinit();
                return err;
            };
            self.next_id = id + 1;
            self.pending.putAssumeCapacityNoClobber(id, reply);
            self.metrics.pending_requests.metric().inc();
            const subscriber: Subscriber = .{ .id = id, .reply = {} };
            _ = try resolver_handle.fetch(Fetch{ .key = fetch.request, .subscriber = subscriber });
            self.metrics.fetch_requests.metric().inc();
            assert(self.pending.contains(id));
        }

        fn watch_closed(self: *Self, id: u64, reply: Reply) Io.Cancelable!void {
            try reply.closed();
            self.report(.{ .closed = id });
        }

        /// Retires subscription `id` once its caller left.
        fn handle_closed(self: *Self, resolver_handle: anytype, id: u64) Error!void {
            var entry = self.pending.fetchSwapRemove(id).?;
            entry.value.deinit();
            const predicate = Predicate.init(id, struct {
                fn keep(retired: u64, _: Request, subscriber: Subscriber) bool {
                    return subscriber.id != retired;
                }
            }.keep);
            _ = try resolver_handle.retain(predicate);
            self.metrics.pending_requests.metric().dec();
            assert(!self.pending.contains(id));
        }

        /// Decodes a peer response and reports a verdict on it to the resolver: invalid when
        /// it fails to decode or does not match its request, else the callers' verdict.
        pub fn handle_deliver(self: *Self, deliver: Deliver) Error!void {
            const gpa = deliver.gpa;
            defer gpa.free(deliver.delivery.subscribers);
            defer gpa.free(deliver.value);
            var feedback = deliver.response;
            const key = deliver.delivery.key;
            // Queued deliveries can outlive their callers.
            const subscribers = deliver.delivery.subscribers;
            assert(subscribers.len > 0);
            const live_buffer = gpa.alloc(Reply, subscribers.len) catch |err| {
                feedback.deinit();
                return err;
            };
            defer gpa.free(live_buffer);
            var live: std.ArrayList(Reply) = .initBuffer(live_buffer);
            for (subscribers) |subscriber| {
                const reply = self.pending.get(subscriber.id) orelse continue;
                if (!reply.is_closed()) live.appendAssumeCapacity(reply);
            }
            if (live.items.len == 0) {
                self.count(self.metrics.deliveries, .dropped);
                feedback.deinit(); // Unjudged.
                return;
            }
            // Leave subscriptions intact on invalid data so the resolver can retry.
            var response = decode(gpa, key, deliver.value) orelse {
                self.count(self.metrics.deliveries, .invalid);
                feedback.send(false) catch {}; // The resolver stopped listening.
                return;
            };
            // A single recipient judges the candidate directly.
            if (live.items.len == 1) {
                const candidate: Candidate = .{
                    .gpa = gpa,
                    .response = response,
                    .verdict = feedback,
                };
                live.items[0].try_send(candidate) catch {
                    candidate.discard();
                    self.count(self.metrics.deliveries, .dropped);
                    return;
                };
                self.count(self.metrics.deliveries, .success);
                return;
            }
            response.deinit(gpa);
            try self.fan_out(key, deliver.value, live.items, feedback);
        }

        /// The response in `value` when it decodes and answers `key`'s kind of request.
        fn decode(gpa: Allocator, key: Request, value: []const u8) ?Response {
            const cfg: Response.Cfg = .{
                .max_ops = @intCast(key.max_ops()),
                .op = codec.unit_cfg(codec.Cfg(Op)),
            };
            var response = codec.decode_cfg(Response, gpa, value, cfg) catch return null;
            if (std.mem.eql(u8, @tagName(response), @tagName(key))) return response;
            response.deinit(gpa);
            return null;
        }

        /// Every recipient must consume or drop this candidate before a rejection can trigger
        /// another delivery into its capacity-one reply channel, so each gets its own verdict.
        fn fan_out(
            self: *Self,
            key: Request,
            value: []const u8,
            live: []const Reply,
            feedback: oneshot.Sender(bool),
        ) Error!void {
            assert(live.len > 1);
            var owned_feedback = feedback;
            const gpa = self.gpa;
            const verdicts = gpa.alloc(oneshot.Receiver(bool), live.len) catch |err| {
                owned_feedback.deinit();
                return err;
            };
            var count_sent: usize = 0;
            for (live) |reply| {
                // Proof: `value` decoded into this response kind just before.
                const response = decode(gpa, key, value).?;
                var pair = oneshot.channel(bool, gpa, self.io) catch {
                    var unused = response;
                    unused.deinit(gpa);
                    continue;
                };
                const candidate: Candidate = .{
                    .gpa = gpa,
                    .response = response,
                    .verdict = pair.sender,
                };
                reply.try_send(candidate) catch {
                    candidate.discard();
                    pair.receiver.deinit();
                    continue;
                };
                verdicts[count_sent] = pair.receiver;
                count_sent += 1;
            }
            if (count_sent == 0) {
                gpa.free(verdicts);
                self.count(self.metrics.deliveries, .dropped);
                owned_feedback.deinit();
                return;
            }
            self.count(self.metrics.deliveries, .success);
            const args = .{ self, verdicts[0..count_sent], verdicts.len, owned_feedback };
            self.tasks.concurrent(self.io, await_verdicts, args) catch |err| {
                for (verdicts[0..count_sent]) |*verdict| verdict.deinit();
                gpa.free(verdicts);
                owned_feedback.deinit();
                return err;
            };
        }

        /// All callers verify against the same history, so the first verdict in subscriber
        /// order applies to all. A caller that drops its verdict sender abstains.
        fn await_verdicts(
            self: *Self,
            verdicts: []oneshot.Receiver(bool),
            allocated: usize,
            feedback: oneshot.Sender(bool),
        ) Io.Cancelable!void {
            var owned_feedback = feedback;
            var next: usize = 0;
            defer {
                for (verdicts[next..]) |*verdict| verdict.deinit();
                self.gpa.free(verdicts.ptr[0..allocated]);
            }
            var verdict: ?bool = null;
            while (next < verdicts.len) {
                const received: ?bool = verdicts[next].recv() catch |err| switch (err) {
                    error.Closed => null,
                    error.Canceled => {
                        owned_feedback.deinit();
                        return error.Canceled;
                    },
                };
                verdicts[next].deinit();
                next += 1;
                if (verdict == null) verdict = received;
            }
            if (verdict) |valid| {
                owned_feedback.send(valid) catch {}; // The resolver stopped listening.
            } else owned_feedback.deinit();
        }

        /// Serves a peer's request from the attached database; dropping `response` leaves the
        /// request unanswered.
        pub fn handle_produce(
            self: *Self,
            key: Request,
            response: oneshot.Sender(Produced),
        ) Error!void {
            var owned = response;
            const database = self.config.database orelse {
                self.count(self.metrics.serve_requests, .dropped);
                owned.deinit();
                return;
            };
            if (key == .operations and key.max_ops() > self.config.max_serve_ops) {
                self.count(self.metrics.serve_requests, .dropped);
                owned.deinit();
                return;
            }
            self.tasks.concurrent(self.io, serve, .{ self, database, key, owned }) catch |err| {
                owned.deinit();
                return err;
            };
        }

        fn serve(
            self: *Self,
            database: db.Shared(DB),
            key: Request,
            response: oneshot.Sender(Produced),
        ) Io.Cancelable!void {
            var owned = response;
            const status = self.serve_encoded(database, key, &owned) catch |err| switch (err) {
                error.Canceled => {
                    owned.deinit();
                    return error.Canceled;
                },
            };
            self.report(.{ .served = status });
        }

        /// Reads `key` from `database` and sends its encoding; consumes `response`.
        fn serve_encoded(
            self: *Self,
            database: db.Shared(DB),
            key: Request,
            response: *oneshot.Sender(Produced),
        ) Io.Cancelable!Status {
            const gpa = self.gpa;
            var source: Source = .{ .shared = database };
            var served = source.serve(gpa, key) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {
                    response.deinit();
                    return .failure;
                },
            };
            // Serving never judges the source's response.
            if (served.feedback) |*feedback| feedback.deinit();
            defer served.response.deinit(gpa);
            const bytes = codec.encode(Response, gpa, served.response) catch {
                response.deinit();
                return .failure;
            };
            const produced: Produced = .{ .bytes = bytes, .gpa = gpa };
            response.send(produced) catch produced.deinit(); // The engine stopped waiting.
            return .success;
        }
    };
}

test {
    std.testing.refAllDecls(@This());
}
