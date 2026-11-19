//! Reconstruction job tests, ported from commonware `marshal/coding/shards/engine.rs`: jobs run
//! on the strategy while the engine keeps handling shards, a discarded record drops its job's
//! result, shards that arrive mid-job merge with an insufficient result, and a job's spawn
//! `len` counts the shards it takes. Also checks that a job on a thread pool reconstructs the
//! same bytes as one run inline.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const coding = @import("coding");
const parallel = @import("parallel");

const harness = @import("engine_harness.zig");
const engine_module = @import("engine.zig");

const gpa = harness.gpa;
const C = harness.C;
const Key = harness.Key;
const Net = harness.Net;
const at = harness.at;
const shard_of = harness.shard_of;
const Unstarted = harness.Unstarted;

/// A decode held by `Gated` until the test releases it (commonware `Gate`).
const Gate = struct {
    io: Io,
    /// Set once the held decode started.
    started: Io.Event = .unset,
    /// Releases the held decode.
    release: Io.Event = .unset,
};

/// The armed gate; the next decode takes it.
var armed_gate: ?*Gate = null;

/// Reed-Solomon coding whose decode holds while a gate is armed (commonware `Gated`).
const Gated = struct {
    pub const Commitment = C.Commitment;
    pub const Shard = C.Shard;
    pub const CheckedShard = C.CheckedShard;
    pub const ShardRef = C.ShardRef;
    pub const Error = C.Error;

    pub fn max_shard_size(config: coding.Config, data: usize) usize {
        return C.max_shard_size(config, data);
    }

    pub fn encode(
        allocator: Allocator,
        config: coding.Config,
        data: []const u8,
        strategy: anytype,
    ) @typeInfo(@TypeOf(C.encode)).@"fn".return_type.? {
        return C.encode(allocator, config, data, strategy);
    }

    pub fn check(
        config: coding.Config,
        commitment: *const Commitment,
        index: u16,
        shard: *const Shard,
        strategy: anytype,
    ) Error!CheckedShard {
        return C.check(config, commitment, index, shard, strategy);
    }

    pub fn check_many(
        allocator: Allocator,
        config: coding.Config,
        commitment: *const Commitment,
        shards: []const ShardRef,
        out: []Error!CheckedShard,
        strategy: anytype,
    ) Allocator.Error!void {
        try C.check_many(allocator, config, commitment, shards, out, strategy);
    }

    pub fn decode(
        allocator: Allocator,
        config: coding.Config,
        commitment: *const Commitment,
        checked: []const CheckedShard,
        strategy: anytype,
    ) Error![]u8 {
        if (@atomicRmw(?*Gate, &armed_gate, .Xchg, null, .acq_rel)) |gate| {
            gate.started.set(gate.io);
            gate.release.waitUncancelable(gate.io);
        }
        return C.decode(allocator, config, commitment, checked, strategy);
    }
};

/// The `len` of every job a `Recording` spawned.
const Lens = struct {
    values: [8]usize = undefined,
    count: usize = 0,

    fn slice(lens: *const Lens) []const usize {
        return lens.values[0..lens.count];
    }
};

/// Sequential execution that records the `len` of each spawned job (commonware `Recording`).
const Recording = struct {
    lens: *Lens,

    pub fn spawn(recording: Recording, len: usize, task: anytype) void {
        assert(recording.lens.count < recording.lens.values.len);
        recording.lens.values[recording.lens.count] = len;
        recording.lens.count += 1;
        parallel.sequential.spawn(len, task);
    }

    pub fn parallelism(_: Recording) usize {
        return 1;
    }

    pub fn split(_: Recording, len: usize) usize {
        return parallel.sequential.split(len);
    }

    pub fn execute(
        _: Recording,
        count: usize,
        context: anytype,
        comptime body: fn (@TypeOf(context), usize) void,
    ) void {
        parallel.sequential.execute(count, context, body);
    }

    pub fn scratch(_: Recording) ?Allocator {
        return null;
    }

    const S = parallel.Sequential;
    pub const block_on = S.block_on;
    pub const run = S.run;
    pub const try_run = S.try_run;
    pub const run_batches = S.run_batches;
    pub const try_run_batches = S.try_run_batches;
    pub const run_tiles = S.run_tiles;
    pub const fold = S.fold;
    pub const fold_init = S.fold_init;
    pub const try_fold = S.try_fold;
    pub const map_into = S.map_into;
    pub const map_init_into = S.map_init_into;
    pub const try_map_into = S.try_map_into;
    pub const map_collect = S.map_collect;
    pub const map_init_collect = S.map_init_collect;
    pub const map_collect_with_multiplier = S.map_collect_with_multiplier;
    pub const map_init_collect_with_multiplier = S.map_init_collect_with_multiplier;
    pub const try_map_collect = S.try_map_collect;
    pub const map_partition_collect = S.map_partition_collect;
    pub const join = S.join;
    pub const sort_by = S.sort_by;
    pub const sort_unstable_by = S.sort_unstable_by;
};

const Rayon = parallel.Rayon;
const PooledEngine = engine_module.Engine(harness.TypesWith(C, Rayon));
const Pooled = harness.UnstartedOf(PooledEngine);
const RecordingEngine = engine_module.Engine(harness.TypesWith(C, Recording));
const Recorded = harness.UnstartedOf(RecordingEngine);
const GatedEngine = engine_module.Engine(harness.TypesWith(Gated, Rayon));

fn record_of(engine: anytype, commitment: harness.Commitment) !*@TypeOf(engine.engine.*).Record {
    return engine.engine.records.get(commitment) orelse error.NoRecord;
}

// commonware `test_reconstruction_result_discarded_with_its_record`: evicting or caching a
// record discards its job's result, so a stale result never recreates, caches, or removes the
// record.
test "reconstruction result discarded with its record" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            const engine = try Unstarted.init(io, .{});
            defer engine.deinit();
            for ([_]bool{ false, true }, 0..) |proposed, id| {
                var block = try harness.encode(engine.coding_config, 1, id);
                defer block.deinit(gpa);
                const commitment = block.commitment();
                // Two own-index shards reach the minimum and submit a job.
                try engine.gather(commitment, at(1));
                for ([_]usize{ 1, 2 }) |index| try engine.shard(index, try shard_of(&block, index));
                try testing.expectEqual(@as(usize, 1), engine.jobs());
                // The record is evicted or cached before the job's result is applied.
                if (proposed) {
                    try engine.engine.cache_block(at(1), block.clone());
                } else {
                    engine.engine.evict(commitment);
                }
                // The job yields nothing, and the record keeps the state the action left.
                const job = engine.engine.next_finished();
                try testing.expect(job.discarded);
                try engine.engine.complete(job);
                try testing.expectEqual(@as(usize, 0), engine.jobs());
                if (proposed) {
                    try testing.expect((try record_of(engine, commitment)).block != null);
                } else {
                    try testing.expect(!engine.has_record(commitment));
                }
            }
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(engine.network));
        }
    }.run);
}

// commonware `test_mid_job_shards_merge_with_insufficient_result`: while a job is in flight
// the record still classifies shards. The assigned shard is verified and joins the shards an
// insufficient job returns, an exact duplicate of a shard the job took is ignored, and a
// conflicting copy blocks its sender.
test "mid-job shards merge with insufficient result" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            // The pool's workers never start: a job stays queued until it is awaited.
            const strategy = try parallel.mocks.pending(gpa, io, 1);
            defer strategy.pool.destroy();
            const engine = try Pooled.init_with(io, .{}, strategy);
            defer engine.deinit();
            const config = engine.coding_config;
            var block = try harness.encode(config, 1, 100);
            defer block.deinit(gpa);
            var other = try harness.encode(config, 1, 200);
            defer other.deinit(gpa);
            const commitment = block.commitment();
            // Peer 2's forged shard and peer 3's valid shard reach the minimum: one job.
            try engine.gather(commitment, at(1));
            try engine.shard(2, try harness.shard_for(&other, 2, commitment));
            try engine.shard(3, try shard_of(&block, 3));
            try testing.expectEqual(@as(usize, 1), engine.jobs());
            try testing.expect(!engine.engine.jobs.items[0].task.is_done());
            try classify_mid_job(engine, &block, &other);
            // The job finds peer 2's shard invalid and returns peer 3's checked shard, which
            // joins the assigned shard; the two submit a job that rebuilds the block.
            const first = engine.engine.next_finished();
            try testing.expect(try first.result.? == .insufficient);
            try engine.engine.complete(first);
            try harness.expect_blocked(engine.network, engine.me(), engine.peers[2]);
            try testing.expectEqual(@as(usize, 1), engine.jobs());
            try engine.finish();
            const cached = (try record_of(engine, commitment)).block orelse
                return error.NotReconstructed;
            try testing.expect(cached.commitment().eql(commitment));
            try testing.expectEqual(@as(usize, 2), try harness.blocked_count(engine.network));
        }

        /// Peer 1 delivers the assigned shard, which is verified; peer 3 resends its shard,
        /// which is ignored, then sends a conflicting one, which blocks it.
        fn classify_mid_job(
            engine: *Pooled,
            block: *const harness.Coded,
            other: *const harness.Coded,
        ) !void {
            const commitment = block.commitment();
            try engine.shard(1, try shard_of(block, 0));
            try engine.shard(3, try shard_of(block, 3));
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(engine.network));
            try engine.shard(3, try harness.shard_for(other, 3, commitment));
            try harness.expect_blocked(engine.network, engine.me(), engine.peers[3]);
            const state = (try record_of(engine, commitment)).reconstruction.?;
            try testing.expect(state.assigned_verified);
            const quorum = state.quorum.?;
            try testing.expectEqual(@as(usize, 1), quorum.checked.items.len);
            try testing.expectEqual(@as(usize, 0), quorum.pending.count());
            try testing.expect(quorum.job);
        }
    }.run);
}

// commonware `test_job_len_counts_taken_shards`: a job's spawn `len` is the encoded size of
// the checked shards and the pending shards it takes. It excludes surplus pending shards and
// shards an earlier job found invalid.
test "job len counts taken shards" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            var lens: Lens = .{};
            const engine = try Recorded.init_with(io, .{ .count = 10 }, .{ .lens = &lens });
            defer engine.deinit();
            const config = engine.coding_config;
            var block = try harness.encode(config, 1, 100);
            defer block.deinit(gpa);
            var other = try harness.encode(config, 1, 200);
            defer other.deinit(gpa);
            const commitment = block.commitment();
            const invalid = try harness.shard_for(&other, 2, commitment);
            const expected = [_]usize{
                try size(&block, 0) + invalid.inner.encode_size() + try size(&block, 3) +
                    try size(&block, 4),
                try size(&block, 0) + try size(&block, 3) + try size(&block, 4) +
                    try size(&block, 5),
            };
            // Before the gather, peer 1 delivers the assigned shard, peer 2 an invalid
            // shard, and peers 3 through 6 their own shards.
            try engine.shard(1, try shard_of(&block, 0));
            try engine.shard(2, invalid);
            for (3..7) |index| try engine.shard(index, try shard_of(&block, index));
            // The gather verifies the assigned shard and submits a job taking it and the
            // shards of peers 2 through 4; the shards of peers 5 and 6 stay pending.
            try engine.gather(commitment, at(1));
            const quorum = (try record_of(engine, commitment)).reconstruction.?.quorum.?;
            try testing.expectEqual(@as(usize, 2), quorum.pending.count());
            // Peer 2's shard fails verification. The next job takes the three checked shards
            // and peer 5's shard and rebuilds the block.
            try engine.finish();
            try engine.finish();
            try testing.expect((try record_of(engine, commitment)).block != null);
            try testing.expectEqualSlices(usize, &expected, lens.slice());
        }

        fn size(block: *const harness.Coded, index: usize) !usize {
            var shard = try shard_of(block, index);
            defer shard.deinit(gpa);
            return shard.inner.encode_size();
        }
    }.run);
}

// A job on a thread pool reconstructs the same block bytes as one run inline (the engine's
// former synchronous path), and both match the block that was dispersed.
test "pooled reconstruction matches inline reconstruction" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            var block = try harness.encode(harness.types.coding_config_for_participants(4), 7, 7);
            defer block.deinit(gpa);
            const expected = try codec.encode(harness.B, gpa, block.inner().*);
            defer gpa.free(expected);
            const inline_engine = try Unstarted.init(io, .{});
            defer inline_engine.deinit();
            const inline_bytes = try reconstruct(inline_engine, &block);
            defer gpa.free(inline_bytes);
            const strategy = try parallel.mocks.pooled(gpa, io, 2, 2);
            defer strategy.pool.destroy();
            const pooled_engine = try Pooled.init_with(io, .{}, strategy);
            defer pooled_engine.deinit();
            const pooled_bytes = try reconstruct(pooled_engine, &block);
            defer gpa.free(pooled_bytes);
            try testing.expect(pooled_engine.engine.jobs.items.len == 0);
            try testing.expectEqualSlices(u8, expected, inline_bytes);
            try testing.expectEqualSlices(u8, inline_bytes, pooled_bytes);
        }

        /// Gathers `block` and delivers two gossip shards; returns the cached block's bytes.
        fn reconstruct(engine: anytype, block: *const harness.Coded) ![]u8 {
            const commitment = block.commitment();
            try engine.gather(commitment, at(1));
            for ([_]usize{ 2, 3 }) |index| try engine.shard(index, try shard_of(block, index));
            try testing.expectEqual(@as(usize, 1), engine.jobs());
            try engine.finish();
            const cached = (try record_of(engine, commitment)).block orelse
                return error.NotReconstructed;
            try testing.expect(cached.commitment().eql(commitment));
            try testing.expect(cached.digest().eql(block.digest()));
            return codec.encode(harness.B, gpa, cached.inner().*);
        }
    }.run);
}

// commonware `test_reconstruction_job_does_not_stall_engine`: a reconstruction job runs on
// the strategy, so the engine keeps verifying assigned shards for other commitments while a
// decode is in flight.
test "reconstruction job does not stall engine" {
    try harness.run_deterministic(struct {
        fn run(io: Io) !void {
            var network: Network = undefined;
            try network.init(io);
            defer network.deinit();
            // Peer 2 runs its engine on a two-worker pool that hands off every job.
            const strategy = try parallel.mocks.pooled(gpa, io, 2, 2);
            defer strategy.pool.destroy();
            var receiver = try network.start_engine(2, strategy);
            defer receiver.stop();
            const mailbox = receiver.mailbox;
            const config = harness.types.coding_config_for_participants(4);
            // The leader delivers the receiver's shard of A and peer 1 gossips its own, which
            // submits a job whose decode holds.
            var gate: Gate = .{ .io = io };
            defer gate.release.set(io);
            armed_gate = &gate;
            var a = try encode_gated(config, 1);
            defer a.deinit(gpa);
            try mailbox.gather(a.commitment(), at(1));
            try network.send(0, 2, &a, 2);
            try network.send(1, 2, &a, 1);
            try wait_set(io, &gate.started);
            // The engine verifies the receiver's shard of B while A's decode holds.
            var b = try encode_gated(config, 2);
            defer b.deinit(gpa);
            try mailbox.gather(b.commitment(), at(2));
            var verified = try mailbox.subscribe_assigned_shard_verified(b.commitment());
            defer verified.deinit();
            try network.send(0, 2, &b, 2);
            try harness.expect_resolves(io, &verified);
            try testing.expect(try mailbox.get(a.commitment()) == null);
            // Releasing the decode reconstructs A.
            gate.release.set(io);
            try wait_reconstructed(io, mailbox, a.commitment());
            try testing.expectEqual(@as(usize, 0), try harness.blocked_count(network.net));
        }

        fn encode_gated(config: coding.Config, id: u64) !GatedEngine.Coded {
            const inner = harness.B.init(.empty, .new(id), id);
            const shared = try GatedEngine.Coded.Inner.compute(gpa, inner);
            return GatedEngine.Coded.encode(gpa, shared, config, parallel.sequential);
        }

        fn wait_set(io: Io, event: *const Io.Event) !void {
            for (0..5_000) |_| {
                if (event.isSet()) return;
                try harness.sleep_ms(io, 1);
            }
            return error.Timeout;
        }

        fn wait_reconstructed(
            io: Io,
            mailbox: GatedEngine.Mailbox,
            commitment: GatedEngine.Commitment,
        ) !void {
            for (0..5_000) |_| {
                if (try mailbox.get(commitment)) |value| return harness.free_value(value);
                try harness.sleep_ms(io, 1);
            }
            return error.NotReconstructed;
        }
    }.run);
}

/// Four linked, tracked participants on channel 0 (the setup of commonware's
/// `test_reconstruction_job_does_not_stall_engine`).
const Network = struct {
    const count = 4;

    io: Io,
    net: *Net,
    task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    registry: *harness.metrics.Registry,
    keys: [count]harness.PrivateKey = undefined,
    peers: [count]Key = undefined,
    registered: [count]?Net.Registered = @splat(null),
    provider: harness.MultiEpochProvider = .{},

    fn init(network: *Network, io: Io) !void {
        const net = try Net.init(gpa, io, harness.network_config(count, count));
        const registry = try gpa.create(harness.metrics.Registry);
        registry.* = .init(gpa);
        network.* = .{
            .io = io,
            .net = net,
            .task = try io.concurrent(Net.run, .{net}),
            .registry = registry,
        };
        harness.sorted_keys(&network.keys, &network.peers, 0);
        const oracle = net.oracle();
        for (network.peers, &network.registered) |peer, *slot| {
            slot.* = try oracle.control(peer).register(0, harness.test_quota);
        }
        for (network.peers) |from| for (network.peers) |to| {
            if (!from.eql(to)) try oracle.add_link(from, to, harness.default_link);
        };
        try harness.track(net, 0, &network.peers, &.{});
        try harness.sleep_ms(io, 10);
    }

    const Running = struct {
        io: Io,
        mailbox: GatedEngine.Mailbox,
        future: Io.Future(GatedEngine.Error!void),

        fn stop(running: *Running) void {
            running.future.cancel(running.io) catch |err| std.debug.panic("engine: {t}", .{err});
            running.mailbox.deinit();
        }
    };

    /// Starts peer `index`'s engine on `strategy`; the engine owns that peer's registration.
    fn start_engine(network: *Network, index: usize, strategy: Rayon) !Running {
        const set = try harness.Scheme.Participants.init(gpa, &network.peers);
        const scheme = try harness.Scheme.signer(
            gpa,
            harness.scheme_namespace,
            set,
            network.keys[index],
        );
        try network.provider.add(0, scheme.?);
        const peer = network.peers[index];
        const scope = harness.metrics.Scope.init(network.registry).child("receiver");
        const created = try GatedEngine.init(gpa, network.io, &scope, .{
            .scheme_provider = .{ .provider = &network.provider },
            .blocker = network.net.oracle().control(peer),
            .block_codec_config = {},
            .strategy = strategy,
            .mailbox_size = 1024,
            .peer_buffer_size = 64,
            .records = 16,
            .peer_provider = network.net.oracle().manager(),
        });
        const registered = network.registered[index].?;
        network.registered[index] = null;
        const future = try created.engine.start(registered.sender, registered.receiver);
        return .{ .io = network.io, .mailbox = created.mailbox, .future = future };
    }

    /// Sends `block`'s shard at `index` from peer `from` to peer `to`.
    fn send(network: *Network, from: usize, to: usize, block: anytype, index: u16) !void {
        var shard = (try block.shard(gpa, index)) orelse return error.MissingShard;
        defer shard.deinit(gpa);
        const bytes = try codec.encode(@TypeOf(shard), gpa, shard);
        defer gpa.free(bytes);
        const sender = &network.registered[from].?.sender;
        const attempted = try sender.send(.{ .one = network.peers[to] }, &.{bytes}, true);
        gpa.free(attempted);
    }

    fn deinit(network: *Network) void {
        for (&network.registered) |*slot| if (slot.*) |*value| value.deinit();
        network.provider.deinit();
        network.net.close();
        network.task.await(network.io) catch |err| std.debug.panic("run: {t}", .{err});
        network.net.deinit();
        network.registry.deinit();
        gpa.destroy(network.registry);
    }
};
