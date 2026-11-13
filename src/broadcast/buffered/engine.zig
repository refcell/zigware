//! The buffered broadcast engine (commonware `broadcast/src/buffered/engine.rs`).
//!
//! The engine broadcasts messages to the network, caches messages received from peers (a
//! bounded deque of digests per peer, each message stored once with a reference count), and
//! answers `get` and `subscribe` requests from the application.
//!
//! Event loop: three tasks feed one `signal`: an ingress task receives raw network messages,
//! decodes them (blocking peers whose messages fail to decode), and queues them in a buffer
//! sized to the receiver's capacity, dropping arrivals when it is full; a forwarder moves
//! mailbox requests into a one-request inbox (so mailbox backpressure is preserved); and a
//! forwarder moves peer-set updates into a one-update slot. Each turn handles one event in
//! commonware's biased `select_loop!` order: peer-set updates, mailbox requests, then decoded
//! network messages. The loop ends when the peer-set subscription closes, every mailbox
//! handle is gone, the network receiver closes and its buffer drains, or the task is
//! canceled; the task then frees the engine.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;

const config_module = @import("config.zig");
const ingress = @import("ingress.zig");
const metrics_module = @import("metrics.zig");

const Digested = @import("../digested.zig").Digested;
const SortedMap = p2p.simulated.sorted_map.SortedMap;
const oneshot = utils.channel.oneshot;
const record = metrics_module.record;

/// The payload of `F`'s error-union return type.
fn Payload(comptime F: type) type {
    const Return = @typeInfo(F).@"fn".return_type.?;
    return switch (@typeInfo(Return)) {
        .error_union => |info| info.payload,
        else => Return,
    };
}

/// Result of buffering an incoming or locally sent digest.
const InsertResult = enum { inserted, duplicate, ineligible };

/// The engine for message type `M` (Digestible and codec), peer-set provider `D` (p2p
/// `Manager`), blocker `B`, and network `N`, whose `N.Sender` and `N.Receiver` are the p2p
/// `Sender` and `Receiver` the engine starts on (`p2p.simulated.Network(P)` provides both).
pub fn Engine(comptime M: type, comptime D: type, comptime B: type, comptime N: type) type {
    const S = N.Sender;
    const R = N.Receiver;
    p2p.assert_manager(D);
    p2p.assert_blocker(B);
    p2p.assert_receiver(R);
    return struct {
        const Self = @This();
        pub const PublicKey = D.PublicKey;
        const P = PublicKey;
        pub const Config = config_module.Config(P, codec.Cfg(M), D, B);
        pub const Mailbox = ingress.Mailbox(P, M);
        pub const Message = ingress.Message(P, M);
        pub const Error = Allocator.Error || Io.ConcurrentError;
        const Item = Digested(M);
        const Digest = M.Digest;
        const Responder = oneshot.Sender(Item);
        const Subscription = Payload(@TypeOf(D.subscribe));
        const Update = Payload(@TypeOf(Subscription.try_recv));
        const Decoded = struct { peer: P, message: M };

        /// A cached message and the number of peer deques containing its digest.
        const Cached = struct { message: Item, references: usize };

        const Event = union(enum) {
            peer_set: Update,
            message: Message,
            network: Decoded,
            stopped,
        };

        gpa: Allocator,
        io: Io,
        public_key: P,
        priority: bool,
        deque_size: usize,
        codec_config: codec.Cfg(M),
        blocker: B,
        peer_provider: D,
        mailbox_receiver: actor.mailbox.Receiver(Message),
        engine_metrics: metrics_module.Metrics(P),
        /// Inbound decode outcomes (commonware's background receiver `ingress_decode`).
        decode: metrics.status.Counter,

        /// Pending subscriptions by digest.
        waiters: SortedMap(Digest, std.ArrayList(Responder)) = .empty,
        /// All cached messages by digest, each stored once however many peers sent it.
        items: SortedMap(Digest, Cached) = .empty,
        /// The latest digests received from each peer, newest first, at most `deque_size`.
        deques: SortedMap(P, std.Deque(Digest)) = .empty,
        /// Primary peers of every tracked peer set (sorted), allowed to keep messages cached.
        primary_peers: []P = &.{},

        // Set by `start`.
        sender: S = undefined,
        receiver: R = undefined,
        subscription: Subscription = undefined,
        started: bool = false,

        /// Guards the slots below; every task signals `condition` when it changes them.
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        peer_slot: ?Update = null,
        message_slot: ?Message = null,
        /// Decoded network messages, at most the receiver's capacity.
        decoded: std.Deque(Decoded) = .empty,
        decoded_capacity: usize = 0,
        subscription_closed: bool = false,
        mailbox_closed: bool = false,
        ingress_closed: bool = false,
        ingress_task: ?Io.Future(void) = null,
        mailbox_task: ?Io.Future(void) = null,
        peer_task: ?Io.Future(void) = null,

        /// The engine (not running yet; `start` runs it, `destroy` frees it unstarted) and
        /// its mailbox. Metrics register under `scope`, the mailbox's under
        /// `scope.child("mailbox")`, and decode outcomes under `scope.child("ingress")`.
        pub fn init(
            gpa: Allocator,
            io: Io,
            scope: *const metrics.Scope,
            config: Config,
        ) Error!struct { engine: *Self, mailbox: Mailbox } {
            assert(config.mailbox_size > 0);
            const mailbox_scope = scope.child("mailbox");
            var pair = try actor.mailbox.new_with_metrics(
                Message,
                gpa,
                io,
                &mailbox_scope,
                config.mailbox_size,
            );
            errdefer pair.receiver.deinit();
            errdefer pair.sender.deinit();
            var engine_metrics = try metrics_module.Metrics(P).init(scope);
            errdefer engine_metrics.deinit();
            const ingress_scope = scope.child("ingress");
            var decode = try metrics.status.Counter.register(
                &ingress_scope,
                "decode",
                "Inbound decode outcomes",
            );
            errdefer decode.deinit();
            const engine = try gpa.create(Self);
            engine.* = .{
                .gpa = gpa,
                .io = io,
                .public_key = config.public_key,
                .priority = config.priority,
                .deque_size = config.deque_size,
                .codec_config = config.codec_config,
                .blocker = config.blocker,
                .peer_provider = config.peer_provider,
                .mailbox_receiver = pair.receiver,
                .engine_metrics = engine_metrics,
                .decode = decode,
            };
            const mailbox: Mailbox = .{ .gpa = gpa, .io = io, .sender = pair.sender };
            assert(!engine.started);
            return .{ .engine = engine, .mailbox = mailbox };
        }

        /// Starts the engine on the network (owned from now on). The engine runs until its
        /// task finishes or is canceled, then frees itself; cancel the returned future to
        /// stop it (commonware `Handle::abort`).
        pub fn start(engine: *Self, sender: S, receiver: R) !Io.Future(Error!void) {
            assert(!engine.started);
            const subscription = try engine.peer_provider.subscribe();
            engine.sender = sender;
            engine.receiver = receiver;
            engine.subscription = subscription;
            engine.decoded_capacity = receiver.capacity();
            engine.started = true;
            assert(engine.decoded_capacity > 0);
            return engine.io.concurrent(run, .{engine}) catch |err| {
                engine.destroy();
                return err;
            };
        }

        /// The engine task: handle events until a source closes, then free the engine.
        fn run(engine: *Self) Error!void {
            defer engine.destroy();
            assert(engine.started);
            // The subscription first yields the current peer set; apply it before any
            // queued request (the loop is biased toward peer-set updates).
            while (true) {
                var update = engine.subscription.try_recv() catch break;
                defer update.deinit();
                try engine.update_primary_peers(update.view().all.primary.items);
            }
            try engine.decoded.ensureTotalCapacity(engine.gpa, engine.decoded_capacity);
            engine.peer_task = try engine.io.concurrent(forward_peer_sets, .{engine});
            engine.mailbox_task = try engine.io.concurrent(forward_mailbox, .{engine});
            engine.ingress_task = try engine.io.concurrent(receive_network, .{engine});
            while (true) {
                engine.cleanup_waiters();
                const waiting: i64 = @intCast(engine.waiters.count());
                _ = engine.engine_metrics.waiters.metric().set(waiting);
                const event = engine.wait_event() catch return; // canceled
                switch (event) {
                    .peer_set => |update| {
                        var owned = update;
                        defer owned.deinit();
                        try engine.update_primary_peers(owned.view().all.primary.items);
                    },
                    .message => |message| try engine.handle_message(message),
                    .network => |decoded| try engine.handle_network(decoded),
                    .stopped => return,
                }
            }
        }

        fn wait_event(engine: *Self) Io.Cancelable!Event {
            engine.mutex.lockUncancelable(engine.io);
            defer engine.mutex.unlock(engine.io);
            // Each wake re-checks every source in priority order.
            while (true) {
                if (engine.peer_slot) |update| {
                    engine.peer_slot = null;
                    engine.condition.broadcast(engine.io);
                    return .{ .peer_set = update };
                }
                if (engine.subscription_closed) return .stopped;
                if (engine.message_slot) |message| {
                    engine.message_slot = null;
                    engine.condition.broadcast(engine.io);
                    return .{ .message = message };
                }
                if (engine.mailbox_closed) return .stopped;
                if (engine.decoded.popFront()) |decoded| return .{ .network = decoded };
                if (engine.ingress_closed) return .stopped;
                try engine.condition.wait(engine.io, &engine.mutex);
            }
        }

        /// Moves peer-set updates into `peer_slot`.
        fn forward_peer_sets(engine: *Self) void {
            while (true) {
                const received = engine.subscription.recv() catch return; // canceled
                engine.mutex.lockUncancelable(engine.io);
                defer engine.mutex.unlock(engine.io);
                var update = received orelse {
                    engine.subscription_closed = true;
                    engine.condition.broadcast(engine.io);
                    return;
                };
                while (engine.peer_slot != null) {
                    engine.condition.wait(engine.io, &engine.mutex) catch {
                        update.deinit();
                        return;
                    };
                }
                engine.peer_slot = update;
                engine.condition.broadcast(engine.io);
            }
        }

        /// Moves mailbox requests into `message_slot`.
        fn forward_mailbox(engine: *Self) void {
            while (true) {
                const received = engine.mailbox_receiver.recv() catch return; // canceled
                engine.mutex.lockUncancelable(engine.io);
                defer engine.mutex.unlock(engine.io);
                const message = received orelse {
                    engine.mailbox_closed = true;
                    engine.condition.broadcast(engine.io);
                    return;
                };
                while (engine.message_slot != null) {
                    engine.condition.wait(engine.io, &engine.mutex) catch {
                        Message.discard(message);
                        return;
                    };
                }
                engine.message_slot = message;
                engine.condition.broadcast(engine.io);
            }
        }

        /// Receives and decodes network messages (commonware `WrappedBackgroundReceiver`
        /// with a strategy that decodes inline).
        fn receive_network(engine: *Self) void {
            while (true) {
                var raw = engine.receiver.recv() catch |err| switch (err) {
                    error.Canceled => return,
                    else => {
                        engine.mutex.lockUncancelable(engine.io);
                        defer engine.mutex.unlock(engine.io);
                        engine.ingress_closed = true;
                        engine.condition.broadcast(engine.io);
                        return;
                    },
                };
                defer raw.deinit();
                const decoded = codec.decode_cfg(M, engine.gpa, raw.payload, engine.codec_config);
                const message = decoded catch {
                    record(engine.decode, .invalid);
                    _ = engine.blocker.block(raw.peer);
                    continue;
                };
                engine.queue_decoded(.{ .peer = raw.peer, .message = message });
            }
        }

        fn queue_decoded(engine: *Self, decoded: Decoded) void {
            engine.mutex.lockUncancelable(engine.io);
            defer engine.mutex.unlock(engine.io);
            assert(engine.decoded.len <= engine.decoded_capacity);
            if (engine.decoded.len == engine.decoded_capacity) {
                var dropped = decoded.message;
                free_message(engine.gpa, &dropped);
                record(engine.decode, .dropped);
                return;
            }
            engine.decoded.pushBackAssumeCapacity(decoded);
            record(engine.decode, .success);
            engine.condition.broadcast(engine.io);
        }

        fn free_message(gpa: Allocator, message: *M) void {
            if (comptime @hasDecl(M, "deinit")) message.deinit(gpa);
        }

        /// Cancels every task and frees the engine and everything it owns.
        fn destroy(engine: *Self) void {
            const io = engine.io;
            if (engine.ingress_task) |*task| task.cancel(io);
            if (engine.mailbox_task) |*task| task.cancel(io);
            if (engine.peer_task) |*task| task.cancel(io);
            if (engine.peer_slot) |*update| update.deinit();
            if (engine.message_slot) |message| Message.discard(message);
            while (engine.decoded.popFront()) |decoded| {
                var message = decoded.message;
                free_message(engine.gpa, &message);
            }
            engine.decoded.deinit(engine.gpa);
            if (engine.started) {
                engine.sender.deinit();
                engine.receiver.deinit();
                engine.subscription.deinit();
            }
            engine.mailbox_receiver.deinit();
            engine.free_cache();
            engine.engine_metrics.deinit();
            engine.decode.deinit();
            const gpa = engine.gpa;
            engine.* = undefined;
            gpa.destroy(engine);
        }

        fn free_cache(engine: *Self) void {
            const gpa = engine.gpa;
            for (engine.waiters.items()) |*entry| {
                for (entry.value.items) |*responder| responder.deinit();
                entry.value.deinit(gpa);
            }
            engine.waiters.deinit(gpa);
            for (engine.items.items()) |*entry| entry.value.message.deinit();
            engine.items.deinit(gpa);
            for (engine.deques.items()) |*entry| entry.value.deinit(gpa);
            engine.deques.deinit(gpa);
            gpa.free(engine.primary_peers);
        }

        ////////////////////////////////////////
        // Handling
        ////////////////////////////////////////

        fn handle_message(engine: *Self, message: Message) Error!void {
            switch (message) {
                .broadcast => |request| {
                    var owned = request.message;
                    defer owned.deinit();
                    defer request.recipients.deinit(request.gpa);
                    try engine.handle_broadcast(request.recipients, owned);
                },
                .subscribe => |request| try engine.handle_subscribe(request),
                .get => |request| engine.handle_get(request),
            }
        }

        /// Caches the message (continuing even if it was already cached) and sends it.
        fn handle_broadcast(engine: *Self, recipients: p2p.Recipients(P), item: Item) Error!void {
            _ = try engine.insert_message(engine.public_key, item);
            const bytes = try codec.encode(M, engine.gpa, item.inner().*);
            defer engine.gpa.free(bytes);
            const attempted = try engine.sender.send(recipients, &.{bytes}, engine.priority);
            engine.gpa.free(attempted);
        }

        /// Answers from the cache, or waits for a matching message.
        fn handle_subscribe(engine: *Self, request: Message.Subscribe) Error!void {
            if (engine.items.get(request.digest)) |cached| {
                engine.respond_subscribe(request.responder, cached.message.clone());
                return;
            }
            var responder = request.responder;
            errdefer responder.deinit();
            const waiters = try engine.waiters.get_or_put(engine.gpa, request.digest, .empty);
            try waiters.append(engine.gpa, responder);
            assert(waiters.items.len > 0);
        }

        fn handle_get(engine: *Self, request: Message.Get) void {
            const cached = engine.items.get(request.digest);
            const value: ?Item = if (cached) |entry| entry.message.clone() else null;
            const found = value != null;
            var responder = request.responder;
            responder.send(.{ .value = value }) catch {
                if (value) |item| item.discard();
                record(engine.engine_metrics.get, .dropped);
                return;
            };
            record(engine.engine_metrics.get, if (found) .success else .failure);
        }

        /// Handles a message decoded from a peer.
        fn handle_network(engine: *Self, decoded: Decoded) Error!void {
            const counter = engine.engine_metrics.peer.metric().get_or_create(.{
                .sequencer = decoded.peer,
            }) catch null;
            if (counter) |peer_counter| peer_counter.inc();
            var item = Item.compute(engine.gpa, decoded.message) catch |err| {
                var message = decoded.message;
                free_message(engine.gpa, &message);
                return err;
            };
            defer item.deinit();
            const result = try engine.insert_message(decoded.peer, item);
            record(engine.engine_metrics.receive, switch (result) {
                .inserted => .success,
                .duplicate, .ineligible => .dropped,
            });
        }

        ////////////////////////////////////////
        // Cache management
        ////////////////////////////////////////

        /// Inserts a message into `peer`'s deque. Waiters are notified even when the peer is
        /// not eligible to keep a cache entry resident.
        fn insert_message(engine: *Self, peer: P, item: Item) Error!InsertResult {
            const gpa = engine.gpa;
            const digest = item.digest();
            if (engine.waiters.remove(digest)) |waiters| {
                var owned = waiters;
                defer owned.deinit(gpa);
                for (owned.items) |responder| engine.respond_subscribe(responder, item.clone());
            }

            // Only primary peers of a tracked peer set may buffer.
            if (!engine.is_primary(peer)) return .ineligible;

            const deque = try engine.deques.get_or_put(gpa, peer, .empty);
            for (0..deque.len) |index| {
                if (!deque.at(index).eql(digest)) continue;
                // Already present: move it to the front.
                var cursor = index;
                while (cursor > 0) : (cursor -= 1) {
                    deque.atPtr(cursor).* = deque.at(cursor - 1);
                }
                deque.atPtr(0).* = digest;
                return .duplicate;
            }

            // The first reference caches the message; later ones only count.
            try deque.ensureTotalCapacity(gpa, engine.deque_size + 1);
            try engine.items.entries.ensureUnusedCapacity(gpa, 1);
            deque.pushFrontAssumeCapacity(digest);
            if (engine.items.get(digest)) |cached| {
                cached.references += 1;
            } else {
                const cached: Cached = .{ .message = item.clone(), .references = 1 };
                assert(engine.items.put(gpa, digest, cached) catch unreachable == null);
            }

            // Remove the oldest digest once the deque is full.
            if (deque.len > engine.deque_size) {
                engine.release_digest(deque.popBack().?);
            }
            assert(deque.len <= engine.deque_size);
            return .inserted;
        }

        /// Evicts the deques of peers that are no longer a primary of any tracked set.
        fn update_primary_peers(engine: *Self, peers: []const P) Error!void {
            const gpa = engine.gpa;
            const primary = try gpa.dupe(P, peers);
            gpa.free(engine.primary_peers);
            engine.primary_peers = primary;
            var index: usize = 0;
            while (index < engine.deques.count()) {
                const entry = &engine.deques.items()[index];
                if (engine.is_primary(entry.key)) {
                    index += 1;
                    continue;
                }
                var deque = entry.value;
                const removed = engine.deques.remove(entry.key);
                assert(removed != null);
                while (deque.popFront()) |digest| engine.release_digest(digest);
                deque.deinit(gpa);
            }
        }

        fn is_primary(engine: *const Self, peer: P) bool {
            const found = std.sort.binarySearch(P, engine.primary_peers, peer, P.order);
            return found != null;
        }

        /// Drops one reference to `digest`, evicting its message with the last.
        fn release_digest(engine: *Self, digest: Digest) void {
            const cached = engine.items.get(digest).?; // Proof: every deque digest is cached.
            assert(cached.references > 0);
            cached.references -= 1;
            if (cached.references > 0) return;
            var removed = engine.items.remove(digest).?;
            removed.message.deinit();
        }

        ////////////////////////////////////////
        // Utilities
        ////////////////////////////////////////

        /// Removes waiters whose receivers were dropped (counted as dropped `get`s, as in
        /// commonware).
        fn cleanup_waiters(engine: *Self) void {
            const gpa = engine.gpa;
            var index: usize = 0;
            while (index < engine.waiters.count()) {
                const entry = &engine.waiters.items()[index];
                var kept: usize = 0;
                for (entry.value.items) |responder| {
                    if (responder.is_closed()) {
                        var closed = responder;
                        closed.deinit();
                        record(engine.engine_metrics.get, .dropped);
                        continue;
                    }
                    entry.value.items[kept] = responder;
                    kept += 1;
                }
                entry.value.shrinkRetainingCapacity(kept);
                if (kept > 0) {
                    index += 1;
                    continue;
                }
                var waiters = engine.waiters.remove(entry.key).?;
                waiters.deinit(gpa);
            }
        }

        /// Sends `item` (owned) to a subscriber.
        fn respond_subscribe(engine: *Self, responder: Responder, item: Item) void {
            var owned = responder;
            owned.send(item) catch {
                item.discard();
                record(engine.engine_metrics.subscribe, .dropped);
                return;
            };
            record(engine.engine_metrics.subscribe, .success);
        }
    };
}
