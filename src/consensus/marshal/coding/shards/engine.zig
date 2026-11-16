//! Shard engine for erasure-coded block distribution and reconstruction (commonware
//! `marshal/coding/shards/engine.rs`).
//!
//! Dispersal: a proposer sends each participant the shard at its index and sends its own shard
//! to peers that are tracked but not participants, then caches the block. Reconstruction: for
//! each commitment consensus observed (`Mailbox.gather`), the engine verifies the local
//! participant's assigned shard eagerly and relays it, holds gossip shards (each at its
//! sender's index), and once enough shards are held, batch-verifies those decoding needs,
//! decodes the block, checks it against the commitment, and caches it. Shards that arrive
//! before their commitment is gathered wait in bounded per-peer queues (primary peers of a
//! tracked peer set only). At most `records` commitment records are kept; the lowest rounds
//! are evicted first.
//!
//! Peers are blocked for: undecodable shards (including ones wider than the coding scheme
//! produces under the claimed config for a block at `limits.max_block_size`), shards from
//! non-participants, shards at an index that is neither the local participant's nor the
//! sender's, equivocation while awaiting quorum, and shards that fail verification.
//!
//! Event loop: like the buffered broadcast engine, tasks feed one signal: a forwarder moves
//! peer-set updates into a slot, another moves mailbox messages into a slot, and an ingress
//! task decodes network shards into a queue sized to the receiver's capacity. Each turn
//! handles one event in commonware's biased `select_loop!` order: peer-set updates, mailbox
//! messages, then network shards. Reconstruction jobs run inline when their shards are held
//! (commonware runs them on its strategy and completes them as events). The loop ends when
//! the peer-set subscription, the mailbox, or the network receiver closes, or the task is
//! canceled; the task then frees the engine.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const coding = @import("coding");
const p2p = @import("p2p");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;

const types = @import("../types.zig");
const validation = @import("../validation.zig");
const limits = @import("../../limits.zig");
const mailbox_module = @import("mailbox.zig");
const metrics_module = @import("metrics.zig");
const state_module = @import("state.zig");
const consensus_types = @import("../../../types.zig");

const Round = consensus_types.Round;
const SortedMap = p2p.simulated.sorted_map.SortedMap;
const oneshot = utils.channel.oneshot;
const CodingConfig = coding.Config;

/// The payload of `F`'s error-union return type.
fn Payload(comptime F: type) type {
    const Return = @typeInfo(F).@"fn".return_type.?;
    return switch (@typeInfo(Return)) {
        .error_union => |info| info.payload,
        else => Return,
    };
}

/// Configuration for an `Engine` of `T` (see `Engine`).
pub fn Config(comptime T: type) type {
    return struct {
        /// The certificate scheme for each epoch (`scheme(epoch) ?*const Scheme`). A scheme
        /// for an epoch in which this node is a member must report its membership (`me`).
        scheme_provider: T.Provider,
        /// Blocks misbehaving peers.
        blocker: T.Blocker,
        /// How blocks decode. Every node must use the same value.
        block_codec_config: codec.Cfg(T.Block),
        /// Checks, decodes, and encodes shards.
        strategy: T.Strategy,
        /// The size of the mailbox.
        mailbox_size: u32,
        /// Shards buffered per peer before their commitment is gathered.
        peer_buffer_size: usize,
        /// The most commitment records retained. Must be at least
        /// `2 * (max(1, optimistic_views) + 2)`.
        records: usize,
        /// Peer sets: primary peers may buffer shards; dispersal reaches every tracked peer.
        peer_provider: T.PeerProvider,
    };
}

/// The shard engine. `T` declares `Block` (certifiable, codec, bounded as `limits.max_block_size`),
/// `Coding` (a coding scheme), `Hasher`, `Provider`, `Blocker`, `PeerProvider` (a p2p
/// `Manager`), `Network` (`Network.Sender`, `Network.Receiver`), and `Strategy`.
pub fn Engine(comptime T: type) type {
    const B = T.Block;
    const C = T.Coding;
    const H = T.Hasher;
    const P = T.PeerProvider.PublicKey;
    const S = T.Network.Sender;
    const R = T.Network.Receiver;
    p2p.assert_manager(T.PeerProvider);
    p2p.assert_blocker(T.Blocker);
    p2p.assert_receiver(R);
    return struct {
        const Self = @This();
        pub const Mailbox = mailbox_module.Mailbox(B, C, H);
        pub const Message = mailbox_module.Message(B, C, H);
        pub const Coded = types.CodedBlock(B, C, H);
        pub const ShardType = types.Shard(B, C, H);
        pub const Commitment = Coded.Commitment;
        pub const Error = Allocator.Error || Io.ConcurrentError;
        const State = state_module.State(P, B, C, H);
        const GetResult = mailbox_module.GetResult(Coded);
        const Subscription = Payload(@TypeOf(T.PeerProvider.subscribe));
        const Update = Payload(@TypeOf(Subscription.try_recv));
        const Decoded = struct { peer: P, shard: ShardType };

        /// The lifecycle of one observed commitment. Its round orders eviction and names
        /// the epoch whose participants classify its shards.
        const Record = struct {
            round: Round,
            /// Null while reconstructing.
            block: ?Coded = null,
            /// Null once cached, unless a late assigned shard is still awaited.
            reconstruction: ?State = null,
            /// Whether this node built and dispersed the block.
            proposed: bool = false,

            fn deinit(record: *Record, gpa: Allocator) void {
                if (record.block) |*block| block.deinit(gpa);
                if (record.reconstruction) |*state| state.deinit(gpa);
                record.* = undefined;
            }

            fn is_assigned_shard_ready(record: *const Record) bool {
                if (record.proposed) return true;
                const state = record.reconstruction orelse return false;
                return state.assigned_verified;
            }
        };

        const Event = union(enum) {
            peer_set: Update,
            message: Message,
            network: Decoded,
            stopped,
        };

        gpa: Allocator,
        io: Io,
        config: Config(T),
        mailbox_receiver: actor.mailbox.Receiver(Message),
        shard_metrics: metrics_module.ShardMetrics(P),

        records: SortedMap(Commitment, Record) = .empty,
        /// Shards received before their commitment is gathered, oldest first.
        peer_buffers: SortedMap(P, std.Deque(ShardType)) = .empty,
        /// Every tracked peer (sorted).
        aggregate_peers: []P = &.{},
        /// Primary peers of every tracked peer set (sorted), allowed to buffer shards.
        primary_peers: []P = &.{},
        assigned_subscriptions: SortedMap(Commitment, std.ArrayList(oneshot.Sender(void))) =
            .empty,
        commitment_subscriptions: SortedMap(Commitment, std.ArrayList(oneshot.Sender(Coded))) =
            .empty,
        digest_subscriptions: SortedMap(B.Digest, std.ArrayList(oneshot.Sender(Coded))) = .empty,

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
        /// `scope.child("mailbox")`.
        pub fn init(
            gpa: Allocator,
            io: Io,
            scope: *const metrics.Scope,
            config: Config(T),
        ) Error!struct { engine: *Self, mailbox: Mailbox } {
            assert(config.mailbox_size > 0);
            assert(config.peer_buffer_size > 0 and config.records > 0);
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
            var shard_metrics = try metrics_module.ShardMetrics(P).init(scope);
            errdefer shard_metrics.deinit();
            const engine = try gpa.create(Self);
            engine.* = .{
                .gpa = gpa,
                .io = io,
                .config = config,
                .mailbox_receiver = pair.receiver,
                .shard_metrics = shard_metrics,
            };
            const mailbox: Mailbox = .{ .gpa = gpa, .io = io, .sender = pair.sender };
            return .{ .engine = engine, .mailbox = mailbox };
        }

        /// Starts the engine on the network (owned from now on). Cancel the returned future
        /// to stop it; the engine frees itself.
        pub fn start(engine: *Self, sender: S, receiver: R) !Io.Future(Error!void) {
            assert(!engine.started);
            const subscription = try engine.config.peer_provider.subscribe();
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

        fn run(engine: *Self) Error!void {
            defer engine.destroy();
            assert(engine.started);
            // The subscription first yields the current peer sets; apply them first.
            while (true) {
                var update = engine.subscription.try_recv() catch break;
                defer update.deinit();
                try engine.apply_peer_set(&update);
            }
            try engine.decoded.ensureTotalCapacity(engine.gpa, engine.decoded_capacity);
            engine.peer_task = try engine.io.concurrent(forward_peer_sets, .{engine});
            engine.mailbox_task = try engine.io.concurrent(forward_mailbox, .{engine});
            engine.ingress_task = try engine.io.concurrent(receive_network, .{engine});
            while (true) {
                engine.cleanup_subscriptions();
                const event = engine.wait_event() catch return; // canceled
                switch (event) {
                    .peer_set => |update| {
                        var owned = update;
                        defer owned.deinit();
                        try engine.apply_peer_set(&owned);
                    },
                    .message => |message| {
                        try engine.handle_message(message);
                        // A consensus signal may have admitted a record beyond the window.
                        engine.trim();
                    },
                    .network => |decoded| try engine.handle_network_shard(decoded),
                    .stopped => return,
                }
            }
        }

        fn wait_event(engine: *Self) Io.Cancelable!Event {
            engine.mutex.lockUncancelable(engine.io);
            defer engine.mutex.unlock(engine.io);
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

        /// Receives and decodes shards (commonware's `WrappedBackgroundReceiver`), blocking
        /// peers whose shards fail to decode and dropping arrivals while the queue is full.
        fn receive_network(engine: *Self) void {
            const max_block_size = limits.max_block_size(B, engine.config.block_codec_config);
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
                const payload = raw.payload;
                const decoded = codec.decode_cfg(ShardType, engine.gpa, payload, max_block_size);
                var shard = decoded catch {
                    _ = engine.config.blocker.block(raw.peer);
                    continue;
                };
                engine.mutex.lockUncancelable(engine.io);
                defer engine.mutex.unlock(engine.io);
                if (engine.decoded.len == engine.decoded_capacity) {
                    shard.deinit(engine.gpa);
                    continue;
                }
                engine.decoded.pushBackAssumeCapacity(.{ .peer = raw.peer, .shard = shard });
                engine.condition.broadcast(engine.io);
            }
        }

        /// Cancels every task and frees the engine and everything it owns. Frees an unstarted
        /// engine too.
        pub fn destroy(engine: *Self) void {
            const gpa = engine.gpa;
            const io = engine.io;
            if (engine.ingress_task) |*task| task.cancel(io);
            if (engine.mailbox_task) |*task| task.cancel(io);
            if (engine.peer_task) |*task| task.cancel(io);
            if (engine.peer_slot) |*update| update.deinit();
            if (engine.message_slot) |message| Message.discard(message);
            while (engine.decoded.popFront()) |decoded| {
                var shard = decoded.shard;
                shard.deinit(gpa);
            }
            engine.decoded.deinit(gpa);
            if (engine.started) {
                engine.sender.deinit();
                engine.receiver.deinit();
                engine.subscription.deinit();
            }
            engine.mailbox_receiver.deinit();
            engine.free_state();
            engine.shard_metrics.deinit();
            engine.* = undefined;
            gpa.destroy(engine);
        }

        fn free_state(engine: *Self) void {
            const gpa = engine.gpa;
            for (engine.records.items()) |*entry| entry.value.deinit(gpa);
            engine.records.deinit(gpa);
            for (engine.peer_buffers.items()) |*entry| free_queue(gpa, &entry.value);
            engine.peer_buffers.deinit(gpa);
            close_all(void, gpa, &engine.assigned_subscriptions);
            close_all(Coded, gpa, &engine.commitment_subscriptions);
            close_all(Coded, gpa, &engine.digest_subscriptions);
            gpa.free(engine.aggregate_peers);
            gpa.free(engine.primary_peers);
        }

        fn free_queue(gpa: Allocator, queue: *std.Deque(ShardType)) void {
            while (queue.popFront()) |shard| {
                var owned = shard;
                owned.deinit(gpa);
            }
            queue.deinit(gpa);
        }

        /// Drops every responder of `map` (closing their receivers) and frees the map.
        fn close_all(comptime V: type, gpa: Allocator, map: anytype) void {
            for (map.items()) |*entry| {
                for (entry.value.items) |*responder| responder.deinit();
                entry.value.deinit(gpa);
            }
            map.deinit(gpa);
            comptime assert(@TypeOf(map.items()[0].value) == std.ArrayList(oneshot.Sender(V)));
        }

        /// Drops closed responders and the keys left without any (commonware `on_start`).
        fn cleanup_subscriptions(engine: *Self) void {
            prune(void, engine.gpa, &engine.assigned_subscriptions);
            prune(Coded, engine.gpa, &engine.commitment_subscriptions);
            prune(Coded, engine.gpa, &engine.digest_subscriptions);
        }

        fn prune(comptime V: type, gpa: Allocator, map: anytype) void {
            var index: usize = 0;
            while (index < map.entries.items.len) {
                const list: *std.ArrayList(oneshot.Sender(V)) = &map.entries.items[index].value;
                var kept: usize = 0;
                for (list.items) |responder| {
                    if (responder.is_closed()) {
                        var dropped = responder;
                        dropped.deinit();
                        continue;
                    }
                    list.items[kept] = responder;
                    kept += 1;
                }
                list.shrinkRetainingCapacity(kept);
                if (kept > 0) {
                    index += 1;
                    continue;
                }
                list.deinit(gpa);
                _ = map.entries.orderedRemove(index);
            }
        }

        ////////////////////////////////////////
        // Peer sets
        ////////////////////////////////////////

        /// Keeps the tracked and primary peers, dropping the buffers of peers that are no
        /// longer a primary of any tracked set.
        fn apply_peer_set(engine: *Self, update: anytype) Allocator.Error!void {
            const gpa = engine.gpa;
            const all = update.view().all;
            const aggregate = try all.@"union"(gpa);
            errdefer gpa.free(aggregate);
            const primary = try gpa.dupe(P, all.primary.items);
            gpa.free(engine.aggregate_peers);
            engine.aggregate_peers = aggregate;
            gpa.free(engine.primary_peers);
            engine.primary_peers = primary;
            var index: usize = 0;
            while (index < engine.peer_buffers.entries.items.len) {
                const entry = &engine.peer_buffers.entries.items[index];
                if (contains(engine.primary_peers, entry.key)) {
                    index += 1;
                    continue;
                }
                free_queue(gpa, &entry.value);
                _ = engine.peer_buffers.entries.orderedRemove(index);
            }
        }

        fn contains(peers: []const P, peer: P) bool {
            return std.sort.binarySearch(P, peers, peer, P.order) != null;
        }

        ////////////////////////////////////////
        // Mailbox
        ////////////////////////////////////////

        fn handle_message(engine: *Self, message: Message) Error!void {
            if (message.response_closed()) return Message.discard(message);
            switch (message) {
                .disperse => |request| try engine.disperse_shards(request.round, request.block),
                .gather => |request| try engine.handle_gather(request.commitment, request.round),
                .get_by_commitment => |request| {
                    const block = engine.block_by_commitment(request.commitment);
                    send_get(request.responder, block);
                },
                .get_by_digest => |request| {
                    send_get(request.responder, engine.block_by_digest(request.digest));
                },
                .subscribe_assigned_shard_verified => |request| {
                    try engine.subscribe_assigned(request.commitment, request.responder);
                },
                .subscribe_by_commitment => |request| {
                    const block = engine.block_by_commitment(request.commitment);
                    const map = &engine.commitment_subscriptions;
                    try engine.subscribe_block(map, request.commitment, block, request.responder);
                },
                .subscribe_by_digest => |request| {
                    const block = engine.block_by_digest(request.digest);
                    const map = &engine.digest_subscriptions;
                    try engine.subscribe_block(map, request.digest, block, request.responder);
                },
            }
        }

        fn block_by_commitment(engine: *const Self, commitment: Commitment) ?*const Coded {
            const record = engine.records.get(commitment) orelse return null;
            return if (record.block) |*block| block else null;
        }

        fn block_by_digest(engine: *const Self, digest: B.Digest) ?*const Coded {
            for (engine.records.items()) |*entry| {
                const block = if (entry.value.block) |*value| value else continue;
                if (block.digest().eql(digest)) return block;
            }
            return null;
        }

        fn send_get(responder: oneshot.Sender(GetResult), block: ?*const Coded) void {
            var owned = responder;
            const result: GetResult = .{ .value = if (block) |value| value.clone() else null };
            owned.send(result) catch result.discard(); // send_lossy
        }

        fn send_block(responder: oneshot.Sender(Coded), block: *const Coded) void {
            var owned = responder;
            const value = block.clone();
            owned.send(value) catch value.discard(); // send_lossy
        }

        /// Answers at once if the local assigned shard is verified or this node proposed the
        /// block; otherwise waits.
        fn subscribe_assigned(
            engine: *Self,
            commitment: Commitment,
            responder: oneshot.Sender(void),
        ) Allocator.Error!void {
            var owned = responder;
            const record = engine.records.get(commitment);
            if (record != null and record.?.is_assigned_shard_ready()) {
                owned.send({}) catch {};
                return;
            }
            errdefer owned.deinit();
            const map = &engine.assigned_subscriptions;
            const list = try map.get_or_put(engine.gpa, commitment, .empty);
            try list.append(engine.gpa, owned);
        }

        /// Answers at once with a cached block; otherwise waits.
        fn subscribe_block(
            engine: *Self,
            map: anytype,
            key: anytype,
            block: ?*const Coded,
            responder: oneshot.Sender(Coded),
        ) Allocator.Error!void {
            if (block) |value| return send_block(responder, value);
            var owned = responder;
            errdefer owned.deinit();
            const list = try map.get_or_put(engine.gpa, key, .empty);
            try list.append(engine.gpa, owned);
        }

        fn notify_assigned(engine: *Self, commitment: Commitment) void {
            var list = engine.assigned_subscriptions.remove(commitment) orelse return;
            for (list.items) |*responder| responder.send({}) catch {};
            list.deinit(engine.gpa);
        }

        fn notify_block(engine: *Self, block: *const Coded) void {
            if (engine.commitment_subscriptions.remove(block.commitment())) |list| {
                var owned = list;
                for (owned.items) |responder| send_block(responder, block);
                owned.deinit(engine.gpa);
            }
            if (engine.digest_subscriptions.remove(block.digest())) |list| {
                var owned = list;
                for (owned.items) |responder| send_block(responder, block);
                owned.deinit(engine.gpa);
            }
        }

        ////////////////////////////////////////
        // Records
        ////////////////////////////////////////

        /// Whether the window admits a new record observed at `round`.
        fn admits(engine: *const Self, round: Round) bool {
            if (engine.records.count() < engine.config.records) return true;
            for (engine.records.items()) |*entry| {
                if (entry.value.round.order(round) == .lt) return true;
            }
            return false;
        }

        /// Evicts the lowest-round records (ties in commitment order) while over capacity.
        fn trim(engine: *Self) void {
            while (engine.records.count() > engine.config.records) {
                const entries = engine.records.items();
                var lowest: usize = 0;
                for (entries, 0..) |*entry, index| {
                    if (entry.value.round.order(entries[lowest].value.round) == .lt) lowest = index;
                }
                engine.evict(entries[lowest].key);
            }
        }

        /// Removes `commitment`'s record without closing any subscription.
        fn evict(engine: *Self, commitment: Commitment) void {
            var record = engine.records.remove(commitment) orelse return;
            const states = engine.shard_metrics.reconstruction_states_count;
            if (record.reconstruction != null) dec(states);
            if (record.block != null) dec(engine.shard_metrics.reconstructed_blocks_cache_count);
            record.deinit(engine.gpa);
        }

        fn inc(gauge: metrics.Gauge) void {
            _ = gauge.metric().inc();
        }

        fn dec(gauge: metrics.Gauge) void {
            _ = gauge.metric().dec();
        }

        /// Caches `block` (owned) at `round` and notifies its subscribers. With a record, the
        /// record must be of `round`'s epoch and keeps a block it already cached; without one,
        /// the block is retained only if the window admits `round`.
        fn cache_block(engine: *Self, round: Round, block: Coded) Allocator.Error!void {
            var owned = block;
            const gpa = engine.gpa;
            if (engine.records.get(owned.commitment())) |record| {
                if (record.round.epoch.get() != round.epoch.get()) return owned.deinit(gpa);
                if (record.round.order(round) == .lt) record.round = round;
                if (record.block == null) {
                    record.block = owned;
                    if (record.reconstruction) |*state| state.into_ready(gpa);
                    inc(engine.shard_metrics.reconstructed_blocks_cache_count);
                } else owned.deinit(gpa);
                return engine.notify_block(&record.block.?);
            }
            if (!engine.admits(round)) {
                engine.notify_block(&owned);
                return owned.deinit(gpa);
            }
            const commitment = owned.commitment();
            _ = engine.records.put(gpa, commitment, .{ .round = round, .block = owned }) catch |err|
                {
                    owned.deinit(gpa);
                    return err;
                };
            inc(engine.shard_metrics.reconstructed_blocks_cache_count);
            engine.notify_block(&engine.records.get(commitment).?.block.?);
        }

        ////////////////////////////////////////
        // Dispersal
        ////////////////////////////////////////

        /// Sends each participant its shard and the tracked non-participants this node's
        /// shard, then caches the block (owned).
        fn disperse_shards(engine: *Self, round: Round, block: Coded) Error!void {
            var owned = block;
            const gpa = engine.gpa;
            const commitment = owned.commitment();
            if (engine.records.get(commitment)) |record| {
                if (record.round.epoch.get() != round.epoch.get()) return owned.deinit(gpa);
            }
            const scheme = engine.config.scheme_provider.scheme(round.epoch) orelse
                return owned.deinit(gpa);
            const participants = scheme.participants();
            const me = scheme.me() orelse return owned.deinit(gpa); // not a participant
            const my_index: u16 = @intCast(me.index().get());
            // Shards map to participants by index: one shard per committee member.
            const shards = owned.shards(gpa, engine.config.strategy) catch |err| {
                owned.deinit(gpa);
                return err;
            };
            if (shards.len != participants.len()) return owned.deinit(gpa);
            for (participants.as_slice(), 0..) |peer, index| {
                if (index == my_index) continue;
                engine.send_shard_at(&owned, @intCast(index), .{ .one = peer }) catch |err| {
                    owned.deinit(gpa);
                    return err;
                };
            }
            engine.send_to_non_participants(&owned, my_index, participants) catch |err| {
                owned.deinit(gpa);
                return err;
            };
            try engine.cache_block(round, owned);
            if (engine.records.get(commitment)) |record| record.proposed = true;
            // Local proposals bypass reconstruction, so assigned-shard subscribers still need
            // a notification.
            engine.notify_assigned(commitment);
        }

        fn send_to_non_participants(
            engine: *Self,
            block: *const Coded,
            my_index: u16,
            participants: anytype,
        ) Allocator.Error!void {
            const gpa = engine.gpa;
            var others: std.ArrayList(P) = .empty;
            defer others.deinit(gpa);
            for (engine.aggregate_peers) |peer| {
                if (participants.position(peer) == null) try others.append(gpa, peer);
            }
            if (others.items.len == 0) return;
            try engine.send_shard_at(block, my_index, .{ .some = others.items });
        }

        fn send_shard_at(
            engine: *Self,
            block: *const Coded,
            index: u16,
            recipients: p2p.Recipients(P),
        ) Allocator.Error!void {
            var shard = (try block.shard(engine.gpa, index)).?;
            defer shard.deinit(engine.gpa);
            try engine.send_shard(&shard, recipients);
        }

        fn send_shard(
            engine: *Self,
            shard: *const ShardType,
            recipients: p2p.Recipients(P),
        ) Allocator.Error!void {
            const gpa = engine.gpa;
            const bytes = try codec.encode(ShardType, gpa, shard.*);
            defer gpa.free(bytes);
            const attempted = try engine.sender.send(recipients, &.{bytes}, true);
            gpa.free(attempted);
        }

        ////////////////////////////////////////
        // Reconstruction
        ////////////////////////////////////////

        /// Starts reconstructing a commitment consensus observed at `round`, ingesting the
        /// shards buffered for it. An existing record only records the observation.
        fn handle_gather(engine: *Self, commitment: Commitment, round: Round) Error!void {
            if (engine.records.get(commitment)) |record| {
                // A conflicting epoch is ignored; the round never moves backward.
                const same_epoch = record.round.epoch.get() == round.epoch.get();
                if (same_epoch and record.round.order(round) == .lt) record.round = round;
                return;
            }
            const scheme = engine.config.scheme_provider.scheme(round.epoch) orelse return;
            // Shards of a commitment the window declines stay in the peer buffers.
            if (!engine.admits(round)) return;
            _ = try engine.records.put(engine.gpa, commitment, .{
                .round = round,
                .reconstruction = .{},
            });
            inc(engine.shard_metrics.reconstruction_states_count);
            if (try engine.ingest_buffered_shards(commitment, scheme)) {
                try engine.try_advance(commitment);
            }
        }

        /// Moves every buffered shard of `commitment` into its new reconstruction state.
        fn ingest_buffered_shards(
            engine: *Self,
            commitment: Commitment,
            scheme: anytype,
        ) Allocator.Error!bool {
            const gpa = engine.gpa;
            var buffered: std.ArrayList(Decoded) = .empty;
            defer {
                for (buffered.items) |*decoded| decoded.shard.deinit(gpa);
                buffered.deinit(gpa);
            }
            for (engine.peer_buffers.items()) |*entry| {
                const queue = &entry.value;
                var index: usize = 0;
                while (index < queue.len) {
                    if (!queue.at(index).commitment().eql(commitment)) {
                        index += 1;
                        continue;
                    }
                    try buffered.ensureUnusedCapacity(gpa, 1);
                    // `swap_remove_back`: the last shard takes the removed one's place.
                    const shard = queue.at(index);
                    queue.atPtr(index).* = queue.at(queue.len - 1);
                    _ = queue.popBack();
                    buffered.appendAssumeCapacity(.{ .peer = entry.key, .shard = shard });
                }
            }
            var progressed = false;
            while (buffered.items.len > 0) {
                const decoded = buffered.orderedRemove(0);
                const state = &engine.records.get(commitment).?.reconstruction.?;
                const strategy = engine.config.strategy;
                const blocker = &engine.config.blocker;
                const shard = decoded.shard;
                const changed = try state.on_network_shard(
                    gpa,
                    decoded.peer,
                    shard,
                    scheme,
                    blocker,
                    strategy,
                );
                progressed = changed or progressed;
            }
            return progressed;
        }

        /// Buffers a shard (owned) from a primary peer until its commitment is gathered,
        /// dropping the peer's oldest shard once its queue is full.
        fn buffer_peer_shard(engine: *Self, peer: P, shard: ShardType) Allocator.Error!void {
            var owned = shard;
            const gpa = engine.gpa;
            if (!contains(engine.primary_peers, peer)) return owned.deinit(gpa);
            errdefer owned.deinit(gpa);
            const queue = try engine.peer_buffers.get_or_put(gpa, peer, .empty);
            if (queue.len >= engine.config.peer_buffer_size) {
                var oldest = queue.popFront().?;
                oldest.deinit(gpa);
            }
            try queue.pushBack(gpa, owned);
        }

        /// Whether a shard for `commitment` still matters: a cached record handles arrivals
        /// only on a participant whose assigned shard is unverified (to relay it late).
        fn should_handle_network_shard(engine: *const Self, commitment: Commitment) bool {
            const record = engine.records.get(commitment) orelse return true;
            if (record.block == null) return true;
            const state = record.reconstruction orelse return false;
            if (state.assigned_verified) return false;
            const scheme = engine.config.scheme_provider.scheme(record.round.epoch) orelse
                return false;
            return scheme.me() != null;
        }

        fn handle_network_shard(engine: *Self, decoded: Decoded) Error!void {
            var shard = decoded.shard;
            const gpa = engine.gpa;
            engine.shard_metrics.shard_received(decoded.peer);
            const commitment = shard.commitment();
            if (!engine.should_handle_network_shard(commitment)) return shard.deinit(gpa);
            const record = engine.records.get(commitment) orelse
                return engine.buffer_peer_shard(decoded.peer, shard);
            const state = if (record.reconstruction) |*value|
                value
            else
                return engine.buffer_peer_shard(decoded.peer, shard);
            const scheme = engine.config.scheme_provider.scheme(record.round.epoch) orelse
                return shard.deinit(gpa);
            const blocker = &engine.config.blocker;
            const strategy = engine.config.strategy;
            if (try state.on_network_shard(gpa, decoded.peer, shard, scheme, blocker, strategy)) {
                try engine.try_advance(commitment);
            }
        }

        /// Relays a newly verified assigned shard, then reconstructs once enough shards are
        /// held.
        fn try_advance(engine: *Self, commitment: Commitment) Error!void {
            const record = engine.records.get(commitment) orelse return;
            const state = if (record.reconstruction) |*value| value else return;
            if (state.take_pending_relay()) |relay| {
                var owned = relay;
                defer owned.deinit(engine.gpa);
                try engine.send_shard(&owned, .all);
                engine.notify_assigned(commitment);
            }
            try engine.try_reconstruct(commitment);
        }

        /// Verifies the pending shards decoding needs (in sender order) and decodes the block
        /// once enough are checked; the shards that fail are replaced by later pending ones.
        fn try_reconstruct(engine: *Self, commitment: Commitment) Error!void {
            const minimum: usize = commitment.config().minimum_shards;
            const started = Io.Clock.awake.now(engine.io);
            while (true) {
                const record = engine.records.get(commitment) orelse return;
                if (record.block != null) return;
                const quorum = &(record.reconstruction.?.quorum.?);
                const checked = quorum.checked.items.len;
                if (checked + quorum.pending.count() < minimum) return;
                if (checked < minimum) {
                    try engine.check_pending(commitment, quorum, minimum - checked);
                    continue;
                }
                return engine.decode_and_cache(commitment, started);
            }
        }

        /// Batch-verifies the first `count` pending shards, blocking the senders of invalid
        /// ones.
        fn check_pending(
            engine: *Self,
            commitment: Commitment,
            quorum: *State.Quorum,
            count: usize,
        ) Allocator.Error!void {
            const gpa = engine.gpa;
            assert(count > 0 and count <= quorum.pending.count());
            const peers = try gpa.alloc(P, count);
            defer gpa.free(peers);
            const refs = try gpa.alloc(C.ShardRef, count);
            defer gpa.free(refs);
            const results = try gpa.alloc(C.Error!C.CheckedShard, count);
            defer gpa.free(results);
            try quorum.checked.ensureUnusedCapacity(gpa, count);
            for (peers, refs) |*peer, *ref| {
                const entry = quorum.pending.entries.orderedRemove(0);
                peer.* = entry.key;
                ref.* = .{ .index = entry.value, .shard = quorum.received.get(entry.value).? };
            }
            const root = commitment.root();
            const config = commitment.config();
            try C.check_many(gpa, config, &root, refs, results, engine.config.strategy);
            for (peers, refs, results) |peer, ref, result| {
                const checked = result catch {
                    _ = engine.config.blocker.block(peer); // invalid shard
                    continue;
                };
                const size = ref.shard.encode_size();
                quorum.checked.appendAssumeCapacity(.{ .shard = checked, .size = size });
            }
        }

        /// Decodes the block from the checked shards and caches it, or drops the record and
        /// closes its commitment's subscriptions if it does not match the commitment.
        fn decode_and_cache(
            engine: *Self,
            commitment: Commitment,
            started: Io.Timestamp,
        ) Error!void {
            const gpa = engine.gpa;
            const record = engine.records.get(commitment).?;
            const round = record.round;
            const quorum = &(record.reconstruction.?.quorum.?);
            const inner = engine.decode(commitment, quorum.checked.items) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                engine.evict(commitment);
                if (engine.assigned_subscriptions.remove(commitment)) |list| {
                    var owned = list;
                    for (owned.items) |*responder| responder.deinit();
                    owned.deinit(gpa);
                }
                // A candidate may claim a digest it cannot reconstruct, so only the
                // commitment's subscriptions close.
                if (engine.commitment_subscriptions.remove(commitment)) |list| {
                    var owned = list;
                    for (owned.items) |*responder| responder.deinit();
                    owned.deinit(gpa);
                }
                _ = engine.shard_metrics.reconstruction_failures_total.metric().inc();
                return;
            };
            const histogram = engine.shard_metrics.reconstruction_duration.metric();
            metrics.histogram.observe_between(histogram, started, Io.Clock.awake.now(engine.io));
            var digested = try Coded.Inner.precomputed(gpa, inner, commitment.block());
            errdefer digested.deinit();
            try engine.cache_block(round, Coded.precomputed(digested, commitment));
            _ = engine.shard_metrics.blocks_reconstructed_total.metric().inc();
        }

        /// Decodes the block from `checked` shards and checks it against `commitment`.
        fn decode(engine: *Self, commitment: Commitment, checked: []const State.Sized) !B {
            const gpa = engine.gpa;
            const shards = try gpa.alloc(C.CheckedShard, checked.len);
            defer gpa.free(shards);
            for (shards, checked) |*shard, sized| shard.* = sized.shard;
            const root = commitment.root();
            const strategy = engine.config.strategy;
            const blob = try C.decode(gpa, commitment.config(), &root, shards, strategy);
            defer gpa.free(blob);
            // The blob is the block followed by its coding config.
            var reader = codec.Reader.init(blob);
            var inner = try codec.read_cfg(B, gpa, &reader, engine.config.block_codec_config);
            errdefer codec.free(B, gpa, inner);
            const config = try codec.read(CodingConfig, gpa, &reader);
            if (reader.remaining() != 0) return error.ExtraData;
            try validation.validate_reconstruction(H, gpa, &inner, config, commitment, strategy);
            return inner;
        }
    };
}
