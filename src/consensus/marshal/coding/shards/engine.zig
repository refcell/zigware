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
//! handles one event in commonware's biased `select_loop!` order: finished reconstruction
//! jobs, peer-set updates, mailbox messages, then network shards. The loop ends when the
//! peer-set subscription, the mailbox, or the network receiver closes, or the task is
//! canceled; the task then frees the engine.
//!
//! Reconstruction jobs (commonware's `jobs` pool): once a record holds enough shards it
//! submits one job on the strategy (`Strategy.spawn`) that batch-verifies the pending shards
//! decoding needs and decodes the block, so the loop keeps handling shards meanwhile. Each
//! job's waiter task awaits it and hands it to the loop as an event, so results apply in the
//! order jobs finish (commonware's `jobs.next_completed()`). Evicting or caching a record
//! discards its job (commonware drops the job's `Aborter`): the job still runs to its end,
//! since it borrows the record's shard bytes, and its result is dropped. Freeing the engine
//! waits for every job.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const coding = @import("coding");
const p2p = @import("p2p");
const parallel = @import("parallel");
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
        pub const Strategy = T.Strategy;
        const CodecConfig = @FieldType(Config(T), "block_codec_config");

        /// What a reconstruction job found (commonware `Outcome`).
        pub const Outcome = union(enum) {
            /// Fewer than the minimum shards passed verification; the job's checked shards
            /// return to the record.
            insufficient,
            /// Enough shards passed verification; the block decoded, or failed to match the
            /// commitment.
            decoded: anyerror!B,
        };

        /// One reconstruction job's work (commonware `reconstruct`): verifies the taken
        /// pending shards and decodes the block once at least the minimum are checked. Runs
        /// off the engine loop, so it touches only its own fields.
        pub const Reconstruct = struct {
            gpa: Allocator,
            strategy: T.Strategy,
            codec_config: CodecConfig,
            commitment: Commitment,
            /// The record's checked shards, then the ones this job checks (owned list; bytes
            /// borrowed from the record's received shards).
            checked: std.ArrayList(State.Sized),
            /// The senders of the pending shards taken, in sender order, and their shards
            /// (shallow copies of the record's received shards).
            peers: []P,
            shards: []C.Shard,
            refs: []C.ShardRef,
            results: []C.Error!C.CheckedShard,
            /// Senders whose shards failed verification (capacity reserved at submission).
            invalid: std.ArrayList(P),

            pub fn call(op: *Reconstruct) Allocator.Error!Outcome {
                assert(op.peers.len == op.shards.len and op.refs.len == op.shards.len);
                assert(op.checked.unusedCapacitySlice().len >= op.shards.len);
                if (op.shards.len > 0) {
                    const root = op.commitment.root();
                    const config = op.commitment.config();
                    const refs = op.refs;
                    try C.check_many(op.gpa, config, &root, refs, op.results, op.strategy);
                    // The batch result order keeps verification failures bound to senders.
                    for (op.peers, op.shards, op.results) |peer, *shard, result| {
                        const checked = result catch {
                            op.invalid.appendAssumeCapacity(peer);
                            continue;
                        };
                        const size = shard.encode_size();
                        op.checked.appendAssumeCapacity(.{ .shard = checked, .size = size });
                    }
                }
                const minimum: usize = op.commitment.config().minimum_shards;
                if (op.checked.items.len < minimum) return .insufficient;
                return .{ .decoded = decode_block(op) };
            }
        };

        /// A submitted reconstruction job (heap; the engine owns it until `complete`).
        pub const Job = struct {
            task: parallel.Task(Reconstruct),
            commitment: Commitment,
            started: Io.Timestamp,
            /// Set once awaited.
            result: ?Allocator.Error!Outcome = null,
            /// Set when the record that submitted the job was evicted or cached: the result is
            /// dropped (commonware drops the job's `Aborter`).
            discarded: bool = false,
            /// A discarded record's shards, kept until the job that borrows them ends.
            orphan: ?State.Quorum = null,
            /// The task awaiting the job on a started engine (`await_job`).
            waiter: ?Io.Future(void) = null,

            /// Waits for the job (once) and keeps its result.
            fn wait(job: *Job, strategy: T.Strategy) void {
                if (job.result != null) return;
                job.result = strategy.block_on(&job.task);
                assert(job.task.is_done());
            }

            fn destroy(job: *Job, gpa: Allocator) void {
                assert(job.result != null);
                const op = &job.task.op;
                if (job.result.?) |outcome| switch (outcome) {
                    .insufficient => {},
                    .decoded => |decoded| if (decoded) |inner| {
                        codec.free(B, gpa, inner);
                    } else |_| {},
                } else |_| {}
                op.checked.deinit(gpa);
                op.invalid.deinit(gpa);
                gpa.free(op.peers);
                gpa.free(op.shards);
                gpa.free(op.refs);
                gpa.free(op.results);
                if (job.orphan) |*quorum| quorum.deinit(gpa);
                gpa.destroy(job);
            }
        };

        /// The lifecycle of one observed commitment. Its round orders eviction and names
        /// the epoch whose participants classify its shards.
        pub const Record = struct {
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
            job: *Job,
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
        /// Whether `sender` is set (by `start` or `attach_sender`).
        sender_attached: bool = false,

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
        /// Finished jobs whose results the loop has not applied, in the order they finished
        /// (guarded by `mutex`).
        finished_jobs: std.Deque(*Job) = .empty,

        /// Every job not yet completed, in submission order (engine loop only).
        jobs: std.ArrayList(*Job) = .empty,

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
            engine.sender_attached = true;
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
                    .network => |decoded| {
                        try engine.handle_network_shard(decoded.peer, decoded.shard);
                    },
                    .job => |job| try engine.complete(job),
                    .stopped => return,
                }
            }
        }

        fn wait_event(engine: *Self) Io.Cancelable!Event {
            engine.mutex.lockUncancelable(engine.io);
            defer engine.mutex.unlock(engine.io);
            while (true) {
                if (engine.finished_jobs.popFront()) |job| return .{ .job = job };
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

        /// Awaits `job` and hands it to the loop once it finished (commonware's
        /// `jobs.next_completed()` yields jobs as they finish).
        fn await_job(engine: *Self, job: *Job) void {
            assert(engine.started);
            job.wait(engine.config.strategy);
            engine.finish_job(job);
        }

        fn finish_job(engine: *Self, job: *Job) void {
            assert(job.result != null);
            engine.mutex.lockUncancelable(engine.io);
            defer engine.mutex.unlock(engine.io);
            // Capacity was reserved when the job was submitted.
            engine.finished_jobs.pushBackAssumeCapacity(job);
            engine.condition.broadcast(engine.io);
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
            engine.free_jobs();
            if (engine.peer_slot) |*update| update.deinit();
            if (engine.message_slot) |message| Message.discard(message);
            while (engine.decoded.popFront()) |decoded| {
                var shard = decoded.shard;
                shard.deinit(gpa);
            }
            engine.decoded.deinit(gpa);
            if (engine.sender_attached) engine.sender.deinit();
            if (engine.started) {
                engine.receiver.deinit();
                engine.subscription.deinit();
            }
            engine.mailbox_receiver.deinit();
            engine.free_state();
            engine.shard_metrics.deinit();
            engine.* = undefined;
            gpa.destroy(engine);
        }

        /// Waits for every job not yet completed and frees it, before the records whose shard
        /// bytes the jobs borrow.
        fn free_jobs(engine: *Self) void {
            assert(engine.finished_jobs.len <= engine.jobs.items.len);
            for (engine.jobs.items) |job| {
                // A waiter's job wait is uncancelable: canceling it waits for the job.
                if (job.waiter) |*waiter| waiter.cancel(engine.io);
                job.wait(engine.config.strategy);
                job.destroy(engine.gpa);
            }
            engine.jobs.deinit(engine.gpa);
            engine.finished_jobs.deinit(engine.gpa);
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
            engine.drop_unbuffered_peers();
        }

        fn drop_unbuffered_peers(engine: *Self) void {
            const gpa = engine.gpa;
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

        ////////////////////////////////////////
        // Direct handlers: commonware's tests drive an unstarted engine through its handlers
        // (`handle_gather`, `handle_network_shard`, `disperse_shards`, `cache_block`, `trim`,
        // `subscribe_assigned`, and these) and inspect its records and peer buffers.
        ////////////////////////////////////////

        /// Gives an unstarted engine the sender (owned) its handlers send through.
        pub fn attach_sender(engine: *Self, sender: S) void {
            assert(!engine.started and !engine.sender_attached);
            engine.sender = sender;
            engine.sender_attached = true;
        }

        /// Replaces the primary peers allowed to buffer shards (commonware
        /// `update_primary_peers`), dropping the buffers of the others.
        pub fn update_primary_peers(engine: *Self, peers: []const P) Allocator.Error!void {
            const primary = try engine.gpa.dupe(P, peers);
            std.sort.pdq(P, primary, {}, less_than);
            engine.gpa.free(engine.primary_peers);
            engine.primary_peers = primary;
            engine.drop_unbuffered_peers();
            assert(engine.peer_buffers.count() <= engine.primary_peers.len);
        }

        fn less_than(_: void, a: P, b: P) bool {
            return P.order(a, b) == .lt;
        }

        /// Subscribes `responder` to the block with `commitment`.
        pub fn subscribe_commitment(
            engine: *Self,
            commitment: Commitment,
            responder: oneshot.Sender(Coded),
        ) Allocator.Error!void {
            const block = engine.block_by_commitment(commitment);
            const map = &engine.commitment_subscriptions;
            try engine.subscribe_block(map, commitment, block, responder);
        }

        /// The shards for `commitment` buffered from `peer`.
        pub fn buffered(engine: *const Self, peer: P, commitment: Commitment) usize {
            const queue = engine.peer_buffers.get(peer) orelse return 0;
            var count: usize = 0;
            for (0..queue.len) |index| {
                if (queue.at(index).commitment().eql(commitment)) count += 1;
            }
            assert(count <= queue.len);
            return count;
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
        pub fn subscribe_assigned(
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
        pub fn trim(engine: *Self) void {
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
        pub fn evict(engine: *Self, commitment: Commitment) void {
            var record = engine.records.remove(commitment) orelse return;
            if (record.reconstruction) |*state| engine.discard_job(commitment, state);
            const states = engine.shard_metrics.reconstruction_states_count;
            if (record.reconstruction != null) dec(states);
            if (record.block != null) dec(engine.shard_metrics.reconstructed_blocks_cache_count);
            record.deinit(engine.gpa);
        }

        /// Discards the in-flight job of the record whose reconstruction `state` is being
        /// dropped: the job keeps the record's shards until it ends, and its result is
        /// dropped.
        fn discard_job(engine: *Self, commitment: Commitment, state: *State) void {
            const quorum = if (state.quorum) |*value| value else return;
            if (!quorum.job) return;
            assert(engine.jobs.items.len > 0);
            for (engine.jobs.items) |job| {
                if (job.discarded or !job.commitment.eql(commitment)) continue;
                job.discarded = true;
                assert(job.orphan == null);
                job.orphan = quorum.*;
                state.quorum = null;
                return;
            }
            unreachable; // A record with a job in flight has exactly one undiscarded job.
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
        pub fn cache_block(engine: *Self, round: Round, block: Coded) Allocator.Error!void {
            var owned = block;
            const gpa = engine.gpa;
            if (engine.records.get(owned.commitment())) |record| {
                if (record.round.epoch.get() != round.epoch.get()) return owned.deinit(gpa);
                if (record.round.order(round) == .lt) record.round = round;
                if (record.block == null) {
                    record.block = owned;
                    if (record.reconstruction) |*state| {
                        engine.discard_job(owned.commitment(), state);
                        state.into_ready(gpa);
                    }
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
        pub fn disperse_shards(engine: *Self, round: Round, block: Coded) Error!void {
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
        pub fn handle_gather(engine: *Self, commitment: Commitment, round: Round) Error!void {
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
            var taken: std.ArrayList(Decoded) = .empty;
            defer {
                for (taken.items) |*decoded| decoded.shard.deinit(gpa);
                taken.deinit(gpa);
            }
            for (engine.peer_buffers.items()) |*entry| {
                const queue = &entry.value;
                var index: usize = 0;
                while (index < queue.len) {
                    if (!queue.at(index).commitment().eql(commitment)) {
                        index += 1;
                        continue;
                    }
                    try taken.ensureUnusedCapacity(gpa, 1);
                    // `swap_remove_back`: the last shard takes the removed one's place.
                    const shard = queue.at(index);
                    queue.atPtr(index).* = queue.at(queue.len - 1);
                    _ = queue.popBack();
                    taken.appendAssumeCapacity(.{ .peer = entry.key, .shard = shard });
                }
            }
            var progressed = false;
            while (taken.items.len > 0) {
                const decoded = taken.orderedRemove(0);
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

        /// Handles a decoded shard (owned) from `peer`.
        pub fn handle_network_shard(engine: *Self, peer: P, shard_value: ShardType) Error!void {
            var shard = shard_value;
            const gpa = engine.gpa;
            engine.shard_metrics.shard_received(peer);
            const commitment = shard.commitment();
            if (!engine.should_handle_network_shard(commitment)) return shard.deinit(gpa);
            const record = engine.records.get(commitment) orelse
                return engine.buffer_peer_shard(peer, shard);
            const state = if (record.reconstruction) |*value|
                value
            else
                return engine.buffer_peer_shard(peer, shard);
            const scheme = engine.config.scheme_provider.scheme(record.round.epoch) orelse
                return shard.deinit(gpa);
            const blocker = &engine.config.blocker;
            const strategy = engine.config.strategy;
            if (try state.on_network_shard(gpa, peer, shard, scheme, blocker, strategy)) {
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

        /// Submits a job that verifies the pending shards decoding needs (in sender order) and
        /// decodes the block, once the checked and pending shards reach the minimum (commonware
        /// `try_reconstruct`). A record holds at most one job.
        fn try_reconstruct(engine: *Self, commitment: Commitment) Error!void {
            const record = engine.records.get(commitment) orelse return;
            if (record.block != null) return;
            const quorum = &(record.reconstruction.?.quorum.?);
            const minimum: usize = commitment.config().minimum_shards;
            const checked = quorum.checked.items.len;
            if (quorum.job or checked + quorum.pending.count() < minimum) return;
            // Verify only the pending shards decoding needs; the rest replace any that fail.
            const count = @min(minimum -| checked, quorum.pending.count());
            const job = try engine.create_job(commitment, quorum, count);
            engine.submit(job, quorum) catch |err| {
                engine.restore_job(job, quorum);
                return err;
            };
            assert(quorum.job and quorum.checked.items.len == 0);
        }

        /// A job taking `quorum`'s checked shards and its first `count` pending shards. The
        /// quorum is unchanged until `submit`.
        fn create_job(
            engine: *Self,
            commitment: Commitment,
            quorum: *const State.Quorum,
            count: usize,
        ) Allocator.Error!*Job {
            const gpa = engine.gpa;
            assert(count <= quorum.pending.count());
            const job = try gpa.create(Job);
            errdefer gpa.destroy(job);
            const peers = try gpa.alloc(P, count);
            errdefer gpa.free(peers);
            const shards = try gpa.alloc(C.Shard, count);
            errdefer gpa.free(shards);
            const refs = try gpa.alloc(C.ShardRef, count);
            errdefer gpa.free(refs);
            const results = try gpa.alloc(C.Error!C.CheckedShard, count);
            errdefer gpa.free(results);
            var invalid = try std.ArrayList(P).initCapacity(gpa, count);
            errdefer invalid.deinit(gpa);
            const total = quorum.checked.items.len + count;
            var checked = try std.ArrayList(State.Sized).initCapacity(gpa, total);
            errdefer checked.deinit(gpa);
            checked.appendSliceAssumeCapacity(quorum.checked.items);
            const taken = quorum.pending.items()[0..count];
            for (taken, peers, shards, refs) |entry, *peer, *shard, *ref| {
                peer.* = entry.key;
                shard.* = quorum.received.get(entry.value).?.*;
                ref.* = .{ .index = entry.value, .shard = shard };
            }
            job.* = .{
                .task = .init(.{
                    .gpa = gpa,
                    .strategy = engine.config.strategy,
                    .codec_config = engine.config.block_codec_config,
                    .commitment = commitment,
                    .checked = checked,
                    .peers = peers,
                    .shards = shards,
                    .refs = refs,
                    .results = results,
                    .invalid = invalid,
                }),
                .commitment = commitment,
                .started = Io.Clock.awake.now(engine.io),
            };
            assert(job.task.op.checked.items.len == quorum.checked.items.len);
            return job;
        }

        /// Takes the job's shards out of `quorum` and hands the job to the strategy and, on a
        /// started engine, to a waiter task.
        fn submit(engine: *Self, job: *Job, quorum: *State.Quorum) Allocator.Error!void {
            const gpa = engine.gpa;
            const op = &job.task.op;
            assert(!quorum.job and !job.task.spawned);
            try engine.jobs.ensureUnusedCapacity(gpa, 1);
            if (engine.started) {
                engine.mutex.lockUncancelable(engine.io);
                defer engine.mutex.unlock(engine.io);
                try engine.finished_jobs.ensureTotalCapacity(gpa, engine.jobs.items.len + 1);
            }
            for (0..op.peers.len) |_| _ = quorum.pending.entries.orderedRemove(0);
            quorum.checked.clearRetainingCapacity();
            quorum.job = true;
            // The spawn hint is the encoded size of the shards the job takes.
            var len: usize = 0;
            for (op.checked.items) |sized| len += sized.size;
            for (op.shards) |*shard| len += shard.encode_size();
            engine.config.strategy.spawn(len, &job.task);
            assert(job.task.spawned);
            engine.jobs.appendAssumeCapacity(job);
            if (!engine.started) return;
            job.waiter = engine.io.concurrent(await_job, .{ engine, job }) catch {
                // Without a task to spare, the loop awaits the job itself.
                job.wait(engine.config.strategy);
                return engine.finish_job(job);
            };
        }

        /// Frees a job `submit` refused; `quorum` still holds every shard.
        fn restore_job(engine: *Self, job: *Job, quorum: *const State.Quorum) void {
            assert(!quorum.job);
            assert(!job.task.spawned);
            job.result = Outcome.insufficient;
            job.destroy(engine.gpa);
        }

        /// Waits for the oldest job not yet completed and returns it (commonware's test helper
        /// `finished`); apply it with `complete`. For an engine driven through its handlers.
        pub fn next_finished(engine: *Self) *Job {
            assert(!engine.started);
            assert(engine.jobs.items.len > 0); // The engine must hold a job.
            const job = engine.jobs.items[0];
            job.wait(engine.config.strategy);
            return job;
        }

        /// Applies a finished job (owned) to the record that submitted it (commonware
        /// `complete`): blocks the senders of invalid shards; then a decoded block is cached,
        /// a failed decode removes the record and closes its commitment's subscriptions, and
        /// too few valid shards return the checked shards to the record and submit another job
        /// once enough are held. A discarded job only blocks.
        pub fn complete(engine: *Self, job: *Job) Error!void {
            const gpa = engine.gpa;
            assert(job.result != null);
            // The waiter handed the job over; let it return.
            if (job.waiter) |*waiter| waiter.await(engine.io);
            job.waiter = null;
            const position = std.mem.indexOfScalar(*Job, engine.jobs.items, job).?;
            _ = engine.jobs.orderedRemove(position);
            defer job.destroy(gpa);
            const op = &job.task.op;
            for (op.invalid.items) |peer| _ = engine.config.blocker.block(peer); // invalid shard
            const outcome = try job.result.?;
            if (job.discarded) return;
            const record = engine.records.get(job.commitment).?;
            const quorum = &(record.reconstruction.?.quorum.?);
            assert(quorum.job);
            quorum.job = false;
            switch (outcome) {
                .insufficient => {
                    try quorum.checked.appendSlice(gpa, op.checked.items);
                    try engine.try_reconstruct(job.commitment);
                },
                .decoded => |decoded| {
                    const inner = decoded catch |err| {
                        if (err == error.OutOfMemory) return error.OutOfMemory;
                        return engine.fail_reconstruction(job.commitment);
                    };
                    // The engine owns the block from here on.
                    job.result = Outcome.insufficient;
                    try engine.cache_reconstructed(job, record.round, inner);
                },
            }
        }

        /// Caches the block (owned) a job decoded.
        fn cache_reconstructed(engine: *Self, job: *const Job, round: Round, inner: B) !void {
            const histogram = engine.shard_metrics.reconstruction_duration.metric();
            const now = Io.Clock.awake.now(engine.io);
            assert(!job.discarded);
            metrics.histogram.observe_between(histogram, job.started, now);
            // Decoding verified the blob against the commitment.
            var digested = try Coded.Inner.precomputed(engine.gpa, inner, job.commitment.block());
            errdefer digested.deinit();
            try engine.cache_block(round, Coded.precomputed(digested, job.commitment));
            _ = engine.shard_metrics.blocks_reconstructed_total.metric().inc();
            assert(engine.block_by_commitment(job.commitment) != null);
        }

        /// Drops a record whose shards decode to a block that does not match its commitment
        /// and closes its commitment's subscriptions.
        fn fail_reconstruction(engine: *Self, commitment: Commitment) void {
            const gpa = engine.gpa;
            assert(engine.records.contains(commitment));
            engine.evict(commitment);
            if (engine.assigned_subscriptions.remove(commitment)) |list| {
                var owned = list;
                for (owned.items) |*responder| responder.deinit();
                owned.deinit(gpa);
            }
            // A candidate may claim a digest it cannot reconstruct, so only the commitment's
            // subscriptions close.
            if (engine.commitment_subscriptions.remove(commitment)) |list| {
                var owned = list;
                for (owned.items) |*responder| responder.deinit();
                owned.deinit(gpa);
            }
            _ = engine.shard_metrics.reconstruction_failures_total.metric().inc();
            assert(!engine.records.contains(commitment));
        }

        /// Decodes the block from a job's checked shards and checks it against its commitment.
        fn decode_block(op: *const Reconstruct) !B {
            const gpa = op.gpa;
            assert(op.checked.items.len >= op.commitment.config().minimum_shards);
            const shards = try gpa.alloc(C.CheckedShard, op.checked.items.len);
            defer gpa.free(shards);
            for (shards, op.checked.items) |*shard, sized| shard.* = sized.shard;
            const commitment = op.commitment;
            const root = commitment.root();
            const strategy = op.strategy;
            const blob = try C.decode(gpa, commitment.config(), &root, shards, strategy);
            defer gpa.free(blob);
            // The blob is the block followed by its coding config.
            var reader = codec.Reader.init(blob);
            var inner = try codec.read_cfg(B, gpa, &reader, op.codec_config);
            errdefer codec.free(B, gpa, inner);
            const config = try codec.read(CodingConfig, gpa, &reader);
            if (reader.remaining() != 0) return error.ExtraData;
            try validation.validate_reconstruction(H, gpa, &inner, config, commitment, strategy);
            return inner;
        }
    };
}
