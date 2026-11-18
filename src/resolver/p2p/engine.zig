//! The p2p resolver engine (commonware `resolver/src/p2p/engine.rs`): fetches data from other
//! peers for the consumer, and serves data to other peers from the producer.
//!
//! Event loop: every source wakes one `delivery.Signal`. Forwarder tasks move the next
//! mailbox message, network message, peer-set update, and blocked-set update into one-slot
//! inboxes (so each source keeps its backpressure); serve tasks queue produced values; the
//! delivery tracker queues verdicts; fetch deadlines bound the wait. Each turn handles one
//! event in commonware's `select_loop!` order (peer sets, blocked sets, request timeouts,
//! deliveries, mailbox, due pending fetches, serves, network), then sends at most one due
//! request. The engine stops when every mailbox handle is gone, its peer-set subscription or
//! network receiver closes, or its task is canceled.
//!
//! Contracts (comptime):
//! - Provider `D`: `subscribe() !Subscription` whose `recv() !?Update` yields updates with
//!   `index`, `view().latest` (`p2p.TrackedPeers`), and `deinit` (p2p.simulated's `Manager`).
//! - Blocker `B`: `block(peer) Feedback` and `blocked() (!)Subscription` whose
//!   `recv(gpa) !?[]P` yields the blocked set (owned by the caller).
//! - Consumer `C`: a resolver consumer with `C.Value == []const u8`.
//! - Producer `Pro`: `Pro.Key` and `produce(key) !oneshot.Receiver(Produced)`; a closed
//!   receiver answers the peer with an error response.
//! - Network: a limited sender `NetS` (`check`, `send(recipients, parts, priority) ![]P`) and
//!   a receiver `NetR` (`recv() !p2p.Message(P)`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const utils = @import("utils");
const p2p = @import("p2p");
const runtime = @import("runtime");
const resolver = @import("../root.zig");
const delivery_mod = @import("../delivery.zig");
const subscribers_mod = @import("../subscribers.zig");
const wire = @import("wire.zig");
const fetcher_mod = @import("fetcher.zig");
const inflight_mod = @import("inflight.zig");
const ingress = @import("ingress.zig");
const config_mod = @import("config.zig");
const metrics_mod = @import("metrics.zig");
const Produced = @import("produced.zig").Produced;

const metrics = runtime.telemetry.metrics;
const oneshot = utils.channel.oneshot;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const Outcome = resolver.Outcome;
const Metrics = metrics_mod.Metrics;

/// The payload type of a function's (error union) return type.
fn Returned(comptime function: anytype) type {
    const R = @typeInfo(@TypeOf(function)).@"fn".return_type.?;
    return switch (@typeInfo(R)) {
        .error_union => |info| info.payload,
        else => R,
    };
}

/// The engine's type parameters: public keys `P`, peer provider `D`, blocker `B`, consumer
/// `C`, producer `Pro`, network sender `NetS`, and network receiver `NetR`.
pub fn Params(
    comptime P: type,
    comptime D: type,
    comptime B: type,
    comptime C: type,
    comptime Pro: type,
    comptime NetS: type,
    comptime NetR: type,
) type {
    return struct {
        pub const PublicKey = P;
        pub const Provider = D;
        pub const Blocker = B;
        pub const Consumer = C;
        pub const Producer = Pro;
        pub const NetSender = NetS;
        pub const NetReceiver = NetR;
    };
}

/// The received network messages the forwarder may queue ahead of the engine.
const network_inbox_size = 64;

/// The engine over `T = Params(...)`.
pub fn Engine(comptime T: type) type {
    const P = T.PublicKey;
    const D = T.Provider;
    const B = T.Blocker;
    const C = T.Consumer;
    const Pro = T.Producer;
    const NetS = T.NetSender;
    const NetR = T.NetReceiver;
    resolver.assert_consumer(C);
    comptime assert(C.Value == []const u8);
    comptime assert(Pro.Key == C.Key);
    return struct {
        const Self = @This();
        const K = C.Key;
        const S = C.Subscriber;
        pub const Config = config_mod.Config(P, D, B, C, Pro);
        pub const Message = ingress.Message(K, P, S);
        pub const Mailbox = ingress.Mailbox(K, P, S);
        pub const Error = Allocator.Error || Io.ConcurrentError;
        const Fetcher = fetcher_mod.Fetcher(P, K);
        const Inflight = inflight_mod.Inflight(C, P);
        const WireMessage = wire.Message(K);
        const NetworkMessage = p2p.Message(P);
        const PeerSetSubscription = Returned(D.subscribe);
        const PeerSetUpdate = @typeInfo(Returned(PeerSetSubscription.recv)).optional.child;
        const BlockedSubscription = Returned(B.blocked);

        /// A serve in progress: the producer's receiver and, once it resolves, its value.
        const Serve = struct {
            timer: metrics.histogram.Timer,
            peer: P,
            id: u64,
            receiver: oneshot.Receiver(Produced),
            /// Written by the serve task under the signal's mutex; null for a closed receiver.
            result: ?Produced = null,
            future: Io.Future(void) = undefined,
        };

        const Event = union(enum) {
            peer_set: PeerSetUpdate,
            blocked: []P,
            active_deadline,
            delivered,
            message: Message,
            pending_deadline,
            served: *Serve,
            network: NetworkMessage,
            stopped,
        };

        /// A spawned engine: its mailbox, its task, and (for inspection while it runs on a
        /// single-threaded runtime) the engine itself.
        pub const Spawned = struct {
            mailbox: Mailbox,
            future: Io.Future(Error!void),
            engine: *Self,
        };

        gpa: Allocator,
        io: Io,
        producer: Pro,
        peer_provider: D,
        blocker: B,
        /// Used to detect changes in the peer set.
        last_peer_set_id: ?u64 = null,
        mailbox: actor.mailbox.Receiver(Message),
        sender: NetS,
        receiver: NetR,
        peer_sets: PeerSetSubscription,
        blocked: BlockedSubscription,
        fetcher: Fetcher,
        inflight: Inflight,
        subscribers: subscribers_mod.Tracker(K, S) = .empty,
        /// Every serve not yet handled (owner only).
        serves: std.ArrayList(*Serve) = .empty,
        priority_responses: bool,
        metrics: Metrics,
        signal: delivery_mod.Signal = .{},
        forwarders: [4]?Io.Future(void) = @splat(null),
        removed: std.ArrayList(K) = .empty,

        // Guarded by `signal`. Each inbox slot has its own `*_freed` condition, broadcast when
        // the engine empties it; only that slot's forwarder waits on it. The engine is the
        // only waiter on `signal.condition`, so its timed waits cannot consume a wake meant
        // for a forwarder (AGENTS.md: `Io.Condition` counts signals, not waiters).
        inbox: ?Message = null,
        inbox_freed: Io.Condition = .init,
        mailbox_closed: bool = false,
        /// Received network messages, oldest first: a ring, so a burst crosses from the
        /// forwarder in one hand-off rather than one per message.
        network_inbox: [network_inbox_size]NetworkMessage = undefined,
        network_head: usize = 0,
        network_len: usize = 0,
        network_inbox_freed: Io.Condition = .init,
        network_closed: bool = false,
        peer_set_inbox: ?PeerSetUpdate = null,
        peer_set_inbox_freed: Io.Condition = .init,
        peer_sets_closed: bool = false,
        blocked_inbox: ?[]P = null,
        blocked_inbox_freed: Io.Condition = .init,
        /// Finished serves, oldest first. Capacity covers `serves`.
        serve_done: std.ArrayList(*Serve) = .empty,

        /// Creates an engine and its mailbox (commonware `Engine::new`) and starts it on the
        /// network (commonware `start`). Metrics register under `scope`, the fetcher's under
        /// `scope.child("fetcher")`.
        pub fn spawn(
            gpa: Allocator,
            io: Io,
            scope: metrics.Scope,
            config: Config,
            sender: NetS,
            receiver: NetR,
        ) !Spawned {
            assert(config.mailbox_size > 0);
            var pair = try actor.mailbox.new(Message, gpa, io, config.mailbox_size);
            errdefer pair.sender.deinit();
            const created = create(gpa, io, scope, config, pair.receiver, sender, receiver);
            const self = created catch |err| {
                pair.receiver.deinit();
                return err;
            };
            const future = io.concurrent(run, .{self}) catch |err| {
                self.destroy();
                return err;
            };
            return .{
                .mailbox = .{ .gpa = gpa, .sender = pair.sender },
                .future = future,
                .engine = self,
            };
        }

        /// An engine that is not running yet; `run` drives it and `destroy` frees it. Takes
        /// ownership of the mailbox receiver and the network handles.
        pub fn create(
            gpa: Allocator,
            io: Io,
            scope: metrics.Scope,
            config: Config,
            mailbox: actor.mailbox.Receiver(Message),
            sender: NetS,
            receiver: NetR,
        ) !*Self {
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            var engine_metrics = try Metrics.init(&scope);
            errdefer engine_metrics.deinit();
            const fetcher_scope = scope.child("fetcher");
            var fetcher = try Fetcher.init(gpa, io, &fetcher_scope, .{
                .me = config.me,
                .fetch_timeout = config.fetch_timeout,
                .retry_delay = config.fetch_retry_delay,
                .priority_requests = config.priority_requests,
            });
            errdefer fetcher.deinit();
            var peer_sets = try config.peer_provider.subscribe();
            errdefer peer_sets.deinit();
            // Blockers that cannot fail (p2p lookup's oracle) return the subscription itself.
            const blocked_result = config.blocker.blocked();
            const blocked = if (@typeInfo(@TypeOf(blocked_result)) == .error_union)
                try blocked_result
            else
                blocked_result;
            self.* = .{
                .gpa = gpa,
                .io = io,
                .producer = config.producer,
                .peer_provider = config.peer_provider,
                .blocker = config.blocker,
                .mailbox = mailbox,
                .sender = sender,
                .receiver = receiver,
                .peer_sets = peer_sets,
                .blocked = blocked,
                .fetcher = fetcher,
                .inflight = undefined,
                .priority_responses = config.priority_responses,
                .metrics = engine_metrics,
            };
            self.inflight = try .init_with_signal(gpa, io, config.consumer, &self.signal);
            return self;
        }

        /// Cancels every task and frees the engine and the handles it owns.
        pub fn destroy(self: *Self) void {
            for (&self.forwarders) |*forwarder| {
                if (forwarder.*) |*future| future.cancel(self.io);
            }
            for (self.serves.items) |serve| {
                serve.future.cancel(self.io);
                if (serve.result) |produced| produced.deinit();
                serve.receiver.deinit();
                self.gpa.destroy(serve);
            }
            self.serves.deinit(self.gpa);
            self.serve_done.deinit(self.gpa);
            _ = self.inflight.drain();
            self.inflight.deinit();
            self.subscribers.deinit(self.gpa);
            self.removed.deinit(self.gpa);
            self.fetcher.deinit();
            self.metrics.deinit();
            self.discard_inboxes();
            self.mailbox.deinit();
            self.peer_sets.deinit();
            if (@hasDecl(NetS, "deinit")) self.sender.deinit();
            if (@hasDecl(NetR, "deinit")) self.receiver.deinit();
            const gpa = self.gpa;
            self.* = undefined;
            gpa.destroy(self);
        }

        fn discard_inboxes(self: *Self) void {
            if (self.inbox) |message| Message.discard(message);
            while (self.network_len > 0) {
                var owned = self.pop_network_locked();
                owned.deinit();
            }
            if (self.peer_set_inbox) |update| {
                var owned = update;
                owned.deinit();
            }
            if (self.blocked_inbox) |blocked| self.gpa.free(blocked);
        }

        /// The engine task: handle events until a source closes or the task is canceled,
        /// then free the engine.
        pub fn run(self: *Self) Error!void {
            defer self.destroy();
            self.forwarders[0] = try self.io.concurrent(forward_peer_sets, .{self});
            self.forwarders[1] = try self.io.concurrent(forward_blocked, .{self});
            self.forwarders[2] = try self.io.concurrent(forward_mailbox, .{self});
            self.forwarders[3] = try self.io.concurrent(forward_network, .{self});
            // Runs for the engine's lifetime; each turn handles exactly one event.
            while (true) {
                self.update_gauges();
                const event = self.wait_event() catch return; // canceled
                switch (event) {
                    .peer_set => |update| try self.handle_peer_set(update),
                    .blocked => |blocked| {
                        defer self.gpa.free(blocked);
                        try self.fetcher.set_blocked(blocked);
                    },
                    .active_deadline => try self.handle_active_deadline(),
                    .delivered => {
                        const result = self.inflight.try_next_delivery() catch null;
                        if (result) |completed| try self.handle_delivery(completed);
                    },
                    .message => |message| try self.handle_message(message),
                    .pending_deadline => {},
                    .served => |serve| try self.handle_served(serve),
                    .network => |message| try self.handle_network(message),
                    .stopped => return,
                }
                // Attempt at most one due outbound request after each event so sustained
                // event traffic cannot starve pending work.
                if (self.pending_due()) try self.fetcher.fetch(&self.sender);
            }
        }

        fn update_gauges(self: *Self) void {
            Metrics.set_count(self.metrics.fetch_pending, self.fetcher.len_pending());
            Metrics.set_count(self.metrics.fetch_active, self.fetcher.len_active());
            Metrics.set_count(self.metrics.serve_processing, self.serves.items.len);
        }

        fn now(self: *const Self) SystemTime {
            return fetcher_mod.current(self.io);
        }

        fn pending_due(self: *const Self) bool {
            const deadline = self.fetcher.get_pending_deadline() orelse return false;
            return deadline.order(self.now()) != .gt;
        }

        fn active_due(self: *const Self) bool {
            const deadline = self.fetcher.get_active_deadline() orelse return false;
            return deadline.order(self.now()) != .gt;
        }

        /// The earlier of the pending and active deadlines, as a wait timeout.
        fn timeout(self: *const Self) Io.Timeout {
            const pending = self.fetcher.get_pending_deadline();
            const active = self.fetcher.get_active_deadline();
            const deadline = blk: {
                const a = pending orelse break :blk active orelse return .none;
                const b = active orelse break :blk a;
                break :blk if (a.order(b) == .gt) b else a;
            };
            if (deadline.order(SystemTime.limit()) == .eq) return .none;
            const nanos: i96 = @intCast(deadline.nanos_since_epoch);
            return .{ .deadline = .{ .raw = .{ .nanoseconds = nanos }, .clock = .real } };
        }

        fn wait_event(self: *Self) Io.Cancelable!Event {
            self.inflight.deliveries.close_canceled();
            const signal = &self.signal;
            signal.mutex.lockUncancelable(self.io);
            defer signal.mutex.unlock(self.io);
            // Each wake re-checks every source; waits end on a signal, timeout, or cancel.
            while (true) {
                if (self.next_event_locked()) |event| return event;
                signal.condition.waitTimeout(self.io, &signal.mutex, self.timeout()) catch |err|
                    switch (err) {
                        error.Timeout => {},
                        error.Canceled => return error.Canceled,
                    };
            }
        }

        fn next_event_locked(self: *Self) ?Event {
            const io = self.io;
            if (self.peer_set_inbox) |update| {
                self.peer_set_inbox = null;
                self.peer_set_inbox_freed.broadcast(io);
                return .{ .peer_set = update };
            }
            if (self.peer_sets_closed) return .stopped;
            if (self.blocked_inbox) |blocked| {
                self.blocked_inbox = null;
                self.blocked_inbox_freed.broadcast(io);
                return .{ .blocked = blocked };
            }
            if (self.active_due()) return .active_deadline;
            if (self.inflight.deliveries.has_completion_locked()) return .delivered;
            if (self.inbox) |message| {
                self.inbox = null;
                self.inbox_freed.broadcast(io);
                return .{ .message = message };
            }
            if (self.mailbox_closed) return .stopped;
            if (self.pending_due()) return .pending_deadline;
            if (self.serve_done.items.len > 0) {
                return .{ .served = self.serve_done.orderedRemove(0) };
            }
            if (self.network_len > 0) {
                const message = self.pop_network_locked();
                self.network_inbox_freed.broadcast(io);
                return .{ .network = message };
            }
            if (self.network_closed) return .stopped;
            return null;
        }

        /// Removes the oldest received network message (caller holds `signal`).
        fn pop_network_locked(self: *Self) NetworkMessage {
            assert(self.network_len > 0);
            const message = self.network_inbox[self.network_head];
            self.network_head = (self.network_head + 1) % network_inbox_size;
            self.network_len -= 1;
            assert(self.network_len < network_inbox_size);
            return message;
        }

        /// Waits until the caller's inbox slot is free, on that slot's own condition; false
        /// when canceled.
        fn wait_slot(self: *Self, comptime field: []const u8) bool {
            const freed = &@field(self, field ++ "_freed");
            while (@field(self, field) != null) {
                freed.wait(self.io, &self.signal.mutex) catch return false;
            }
            assert(@field(self, field) == null);
            return true;
        }

        fn forward_mailbox(self: *Self) void {
            const signal = &self.signal;
            while (true) {
                const received = self.mailbox.recv() catch return; // canceled
                signal.mutex.lockUncancelable(self.io);
                defer signal.mutex.unlock(self.io);
                const message = received orelse {
                    self.mailbox_closed = true;
                    signal.condition.broadcast(self.io);
                    return;
                };
                if (!self.wait_slot("inbox")) return Message.discard(message);
                self.inbox = message;
                signal.condition.broadcast(self.io);
            }
        }

        fn forward_network(self: *Self) void {
            const signal = &self.signal;
            while (true) {
                const received = self.receiver.recv();
                signal.mutex.lockUncancelable(self.io);
                defer signal.mutex.unlock(self.io);
                var message = received catch |err| switch (err) {
                    error.Canceled => return,
                    else => {
                        self.network_closed = true;
                        signal.condition.broadcast(self.io);
                        return;
                    },
                };
                while (self.network_len == network_inbox_size) {
                    self.network_inbox_freed.wait(self.io, &signal.mutex) catch {
                        return message.deinit();
                    };
                }
                const tail = (self.network_head + self.network_len) % network_inbox_size;
                self.network_inbox[tail] = message;
                self.network_len += 1;
                signal.condition.broadcast(self.io);
            }
        }

        fn forward_peer_sets(self: *Self) void {
            const signal = &self.signal;
            while (true) {
                const received = self.peer_sets.recv() catch return; // canceled
                signal.mutex.lockUncancelable(self.io);
                defer signal.mutex.unlock(self.io);
                var update = received orelse {
                    self.peer_sets_closed = true;
                    signal.condition.broadcast(self.io);
                    return;
                };
                if (!self.wait_slot("peer_set_inbox")) return update.deinit();
                self.peer_set_inbox = update;
                signal.condition.broadcast(self.io);
            }
        }

        /// Forwards blocked-set updates; when the network stops publishing them, the engine
        /// keeps its last blocked set.
        fn forward_blocked(self: *Self) void {
            const signal = &self.signal;
            while (true) {
                const received = self.blocked.recv(self.gpa) catch return; // canceled or OOM
                const blocked = received orelse return;
                signal.mutex.lockUncancelable(self.io);
                defer signal.mutex.unlock(self.io);
                if (!self.wait_slot("blocked_inbox")) return self.gpa.free(blocked);
                self.blocked_inbox = blocked;
                signal.condition.broadcast(self.io);
            }
        }

        fn handle_peer_set(self: *Self, update: PeerSetUpdate) Error!void {
            var owned = update;
            defer owned.deinit();
            const newer = if (self.last_peer_set_id) |last| last < update.index else true;
            if (!newer) return;
            self.last_peer_set_id = update.index;
            const peers = try owned.view().latest.@"union"(self.gpa);
            defer self.gpa.free(peers);
            try self.fetcher.reconcile(peers);
        }

        fn handle_active_deadline(self: *Self) Error!void {
            const key = try self.fetcher.pop_active() orelse return;
            try self.metrics.fetch.inc(.failure);
            try self.fetcher.add_retry(key);
        }

        /// Applies a mailbox message.
        pub fn handle_message(self: *Self, message: Message) Error!void {
            switch (message) {
                .fetch => |batch| {
                    var owned = batch;
                    defer owned.deinit();
                    for (owned.fetches.items) |*item| {
                        const targets = if (item.metadata.peers) |peers| peers.items else null;
                        const spans = item.spans.items;
                        try self.add_fetch(item.key, item.subscribers.items, spans, targets);
                    }
                },
                .retain => |predicate| try self.retain(predicate),
            }
        }

        /// Tracks `added` for `key`, taking the spans of new subscribers from `spans` (one per
        /// subscriber; the caller frees what is left).
        fn add_fetch(
            self: *Self,
            key: K,
            added: []const S,
            spans: []?*resolver.Span,
            targets: ?[]const P,
        ) Error!void {
            assert(added.len > 0);
            assert(spans.len == added.len);
            const is_new = !self.inflight.contains(key);
            _ = try self.subscribers.insert_spanned(self.gpa, key, added, spans);
            if (targets) |peers| {
                // Restrict a new fetch or add to existing targets; an unrestricted fetch in
                // progress stays unrestricted.
                if (is_new or self.fetcher.has_targets(key)) {
                    try self.fetcher.add_targets(key, peers);
                }
            } else {
                self.fetcher.clear_targets(key);
            }
            if (!is_new) return;
            try self.inflight.insert(key, self.metrics.fetch_duration.timer(self.io));
            try self.fetcher.add_ready(key);
        }

        /// Keeps keys that still have subscribers.
        const Tracked = struct {
            subscribers: *const subscribers_mod.Tracker(K, S),

            pub fn call(tracked: Tracked, key: K) bool {
                return tracked.subscribers.contains(key);
            }
        };

        fn retain(self: *Self, predicate: resolver.Predicate(K, S)) Error!void {
            self.removed.clearRetainingCapacity();
            try self.subscribers.retain(self.gpa, &predicate, &self.removed);
            const tracked: Tracked = .{ .subscribers = &self.subscribers };
            self.fetcher.retain(tracked);
            const count = self.inflight.retain(tracked);
            if (count == 0) {
                try self.metrics.cancel.inc(.dropped);
            } else {
                try self.metrics.cancel.inc_by(.success, count);
            }
        }

        fn handle_network(self: *Self, message: NetworkMessage) Error!void {
            var owned = message;
            defer owned.deinit();
            // Undecodable messages are dropped.
            const decoded = codec.decode(WireMessage, self.gpa, owned.payload) catch return;
            switch (decoded.payload) {
                .request => |key| try self.handle_network_request(owned.peer, decoded.id, key),
                .response => |bytes| {
                    try self.handle_network_response(owned.peer, decoded.id, bytes.data);
                },
                .@"error" => try self.handle_network_error_response(owned.peer, decoded.id),
            }
        }

        /// Serves a peer's request: asks the producer and waits for it in a task.
        fn handle_network_request(self: *Self, peer: P, id: u64, key: K) Error!void {
            const serve = try self.gpa.create(Serve);
            errdefer self.gpa.destroy(serve);
            try self.serves.ensureUnusedCapacity(self.gpa, 1);
            {
                self.signal.mutex.lockUncancelable(self.io);
                defer self.signal.mutex.unlock(self.io);
                try self.serve_done.ensureTotalCapacity(self.gpa, self.serves.items.len + 1);
            }
            const timer = self.metrics.serve_duration.timer(self.io);
            var receiver = try self.producer.produce(key);
            errdefer receiver.deinit();
            serve.* = .{ .timer = timer, .peer = peer, .id = id, .receiver = receiver };
            serve.future = try self.io.concurrent(wait_serve, .{ self, serve });
            self.serves.appendAssumeCapacity(serve);
        }

        /// The task behind each serve: wait for the produced value, then queue the serve.
        fn wait_serve(self: *Self, serve: *Serve) void {
            const result: ?Produced = serve.receiver.recv() catch |err| switch (err) {
                error.Closed => null,
                error.Canceled => return, // shutdown: the owner frees the serve
            };
            self.signal.mutex.lockUncancelable(self.io);
            defer self.signal.mutex.unlock(self.io);
            serve.result = result;
            assert(self.serve_done.items.len < self.serve_done.capacity);
            self.serve_done.appendAssumeCapacity(serve);
            self.signal.condition.broadcast(self.io);
        }

        /// Answers a peer once its serve finished: the data, or an error response.
        fn handle_served(self: *Self, serve: *Serve) Error!void {
            serve.future.await(self.io);
            const index = std.mem.indexOfScalar(*Serve, self.serves.items, serve).?;
            _ = self.serves.swapRemove(index);
            defer {
                serve.receiver.deinit();
                self.gpa.destroy(serve);
            }
            const result = serve.result;
            defer if (result) |produced| produced.deinit();
            if (result != null) {
                serve.timer.observe(self.io);
                try self.metrics.serve.inc(.success);
            } else {
                try self.metrics.serve.inc(.failure);
            }
            const payload: wire.Payload(K) = if (result) |produced|
                .{ .response = codec.Bytes.init(produced.bytes) }
            else
                .@"error";
            const message: WireMessage = .{ .id = serve.id, .payload = payload };
            const bytes = try codec.encode(WireMessage, self.gpa, message);
            defer self.gpa.free(bytes);
            // Send failures are not handled: the requester retries.
            const recipients: p2p.Recipients(P) = .{ .one = serve.peer };
            const sent = try self.sender.send(recipients, &.{bytes}, self.priority_responses);
            self.gpa.free(sent);
        }

        /// Hands a data response to the consumer without blocking the engine.
        fn handle_network_response(
            self: *Self,
            peer: P,
            id: u64,
            response: []const u8,
        ) Error!void {
            // The key may be gone if the request was pruned.
            const popped = self.fetcher.pop_response(id, peer) orelse return;
            const pending = self.subscribers.pending(popped.key) orelse {
                _ = self.inflight.cancel(popped.key);
                return;
            };
            const value = try self.gpa.dupe(u8, response);
            const delivery: resolver.Delivery(K, S) = .{
                .key = popped.key,
                .subscribers = pending,
                .spans = self.subscribers.pending_spans(popped.key).?,
            };
            self.inflight.deliver(delivery, peer, popped.elapsed, value) catch |err| {
                self.gpa.free(value);
                return err;
            };
        }

        /// The peer did not have the data, so try again.
        fn handle_network_error_response(self: *Self, peer: P, id: u64) Error!void {
            const key = try self.fetcher.pop_missing(id, peer) orelse return;
            try self.metrics.fetch.inc(.failure);
            try self.fetcher.add_retry(key);
        }

        /// Scores or blocks the source of a judged response, then completes, redelivers, or
        /// retries the key.
        pub fn handle_delivery(self: *Self, completion: Inflight.Completion) Error!void {
            var completed = completion;
            defer completed.deinit(self.gpa);
            const source = completed.context;
            const accepted = completed.previously_accepted;
            // Source feedback belongs to the delivered response even if its fetch was
            // canceled. Local redelivery of an accepted response cannot earn more credit.
            if (completed.outcome) |outcome| switch (outcome) {
                .resolved => if (!accepted) {
                    try self.fetcher.record_response(source.peer, source.elapsed, source.bytes);
                    try self.metrics.fetch.inc(.success);
                },
                .unresolved => if (!accepted) try self.metrics.fetch.inc(.ambiguous),
                .invalid => {
                    // Only the first validation can identify invalid peer data.
                    if (!accepted) _ = self.blocker.block(source.peer);
                    try self.metrics.fetch.inc(.failure);
                },
                .ignored => {},
            };
            // Canceled feedback cannot retire, retry, or redeliver a replacement fetch.
            if (completed.canceled) return;
            const outcome = completed.outcome orelse {
                return self.handle_dropped(completed.key, accepted, completed.subscribers);
            };
            try self.apply_outcome(completed.key, accepted, completed.subscribers, outcome);
        }

        /// A dropped verdict says nothing about the response, only that the consumer did not
        /// judge it for these subscribers: hand it to the remaining ones, or retire the key.
        fn handle_dropped(self: *Self, key: K, accepted: bool, delivered: []const S) Error!void {
            const remaining = self.subscribers.remove_delivered(self.gpa, key, delivered);
            if (remaining) |pending| {
                return self.inflight.redeliver(self.pending_delivery(key, pending));
            }
            if (!accepted) try self.metrics.fetch.inc(.dropped);
            _ = self.inflight.cancel(key);
            self.fetcher.clear(key);
        }

        fn apply_outcome(
            self: *Self,
            key: K,
            accepted: bool,
            delivered: []const S,
            outcome: Outcome,
        ) Error!void {
            switch (outcome) {
                .resolved => |resolution| switch (resolution) {
                    .complete => try self.handle_complete(key, accepted, delivered),
                    // Valid data can leave subscribers unresolved: discard it and retry.
                    .partial => try self.retry_response(key),
                },
                .unresolved => try self.retry_response(key),
                .invalid => {
                    // An accepted response remains valid peer data: retire conflicting local
                    // demand without fetching the same response again.
                    if (accepted) {
                        self.inflight.complete(self.io, key);
                        _ = self.subscribers.remove(self.gpa, key);
                        self.fetcher.clear(key);
                        return;
                    }
                    try self.retry_response(key);
                },
                .ignored => {
                    // The consumer no longer needs the key: retire the whole fetch without
                    // scoring or blocking the response's source.
                    try self.metrics.fetch.inc(.dropped);
                    _ = self.inflight.cancel(key);
                    _ = self.subscribers.remove(self.gpa, key);
                    self.fetcher.clear(key);
                },
            }
        }

        fn handle_complete(self: *Self, key: K, accepted: bool, delivered: []const S) Error!void {
            // Remove only the subscribers that accepted this response. Others still waiting
            // get the same accepted response locally.
            const remaining = self.subscribers.remove_delivered(self.gpa, key, delivered);
            if (remaining) |pending| {
                if (!accepted) self.inflight.accept_response(self.io, key);
                return self.inflight.redeliver(self.pending_delivery(key, pending));
            }
            // Every subscriber observed a valid response: drop the key's targets and history.
            self.inflight.complete(self.io, key);
            self.fetcher.clear(key);
        }

        /// The delivery of `key` to its `pending` subscribers, with their spans.
        fn pending_delivery(self: *const Self, key: K, pending: []const S) resolver.Delivery(K, S) {
            const spans = self.subscribers.pending_spans(key).?;
            assert(spans.len == pending.len);
            return .{ .key = key, .subscribers = pending, .spans = spans };
        }

        fn retry_response(self: *Self, key: K) Error!void {
            self.inflight.discard_response(key);
            try self.fetcher.add_retry(key);
        }
    };
}

test {
    _ = @import("engine_test.zig");
}
