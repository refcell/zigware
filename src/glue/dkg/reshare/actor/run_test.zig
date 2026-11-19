//! Tests of the reshare actor's epoch loop (commonware `run` and `participate`).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const p2p = @import("p2p");
const utils = @import("utils");
const mocks = @import("../../tests/mocks.zig");
const actor_test = @import("actor_test.zig");
const run_mod = @import("run.zig");

const Exact = utils.acknowledgement.Exact;
const P = mocks.TestPublicKey;
const Harness = actor_test.Harness;
const TestActor = @import("actor.zig").Actor(mocks.ActorTypes);
const Digested = TestActor.Digested;
const Runner = run_mod.Runner(mocks.ActorTypes);
const mocks_p2p = p2p.utils.mocks;
const gpa = testing.allocator;

fn run_actor(h: *Harness, channel: Channel) anyerror!void {
    return Runner.run(&h.actor, &h.store, channel.sender, channel.receiver, .{});
}

const Channel = @TypeOf(mocks_p2p.inert_channel(P, gpa, undefined, &.{}));

// The loop participates in a committed epoch: it deals and includes through the epoch's
// final block, commits and registers the next epoch's info, then enters that epoch.
test "run: a participating epoch commits the next epoch at its final block" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "run-participate", 4);
            defer h.deinit();
            // The store takes the committed info.
            const current = try h.singleton_info(0);
            var seed_rng = utils.rng.TestRng.init(0);
            const seed = try h.store.seed_or_random(.zero(), utils.rng.random(&seed_rng));
            try h.store.commit_epoch(current, seed, null);
            var blocks: [4]Digested = undefined;
            try h.chain(blocks[0..3]);
            var next = try h.singleton_info(1);
            defer next.deinit(gpa);
            blocks[3] = try h.boundary(&blocks[2], next);
            defer for (&blocks) |*block| block.deinit();
            var waiters: [4]Exact.Waiter = undefined;
            for (&waiters, &blocks) |*waiter, *block| waiter.* = try h.deliver(block);
            defer for (&waiters) |*waiter| waiter.deinit();

            const peers = (&h.public_key)[0..1];
            const channel = mocks_p2p.inert_channel(P, gpa, io, peers);
            var running = try io.concurrent(run_actor, .{ &h, channel });
            try waiters[3].wait();
            // The loop has entered epoch one's dealing window, which waits for blocks.
            if (running.cancel(io)) |_| {} else |err| try testing.expectEqual(error.Canceled, err);
            for (&waiters) |*waiter| try (waiter.poll() orelse return error.Unacknowledged);
            try testing.expectEqual(@as(u64, 1), h.store.current_info().?.epoch.get());
            try testing.expectEqualSlices(u64, &.{1}, h.consumer.entered.items);
        }
    }.body);
}

const consensus = @import("consensus");
const runtime = @import("runtime");
const state_sync_test = @import("../../state_sync_test.zig");
const state_sync = @import("../../state_sync.zig");
const oneshot = utils.channel.oneshot;
const Processed = consensus.marshal.core.floor.Processed;
const StartPlan = state_sync.Plan(
    state_sync_test.Scheme,
    mocks.TestDigest,
    mocks.TestBlsVariant,
    utils.sequence.Unit,
);

/// The part of marshal `resolve_start` reads: an optional processed anchor and the block it
/// yields for the state-sync floor subscription (dropped when null).
const StartMarshal = struct {
    io: Io,
    anchor: ?struct { processed: Processed, block: *const Digested } = null,
    floor: ?*const Digested = null,

    const Anchor = struct { processed: Processed, block: Digested };

    pub fn get_anchor(self: StartMarshal) !?Anchor {
        const anchor = self.anchor orelse return null;
        return .{ .processed = anchor.processed, .block = anchor.block.clone() };
    }

    pub fn subscribe_by_commitment(
        self: StartMarshal,
        commitment: mocks.TestDigest,
        fallback: anytype,
    ) !oneshot.Receiver(Digested) {
        _ = fallback;
        var pair = try oneshot.channel(Digested, gpa, self.io);
        const block = self.floor orelse {
            pair.sender.deinit();
            return pair.receiver;
        };
        try testing.expect(block.digest().eql(commitment));
        try pair.sender.send(block.clone());
        return pair.receiver;
    }
};

fn release_start(start: *Runner.Start) void {
    if (start.state_sync) |*synced| synced.info.deinit(gpa);
}

// The top of commonware's `run`: without state sync, the actor starts from marshal's
// processed anchor.
test "run: resolve_start starts from marshal's processed anchor" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "resolve-anchor", 10);
            defer h.deinit();
            var blocks: [3]Digested = undefined;
            try h.chain(&blocks);
            defer for (&blocks) |*block| block.deinit();
            var storage = runtime.buffer.mocks.Storage.init(gpa);
            defer storage.deinit();
            var plan = StartPlan.disabled(gpa, io);
            defer plan.deinit();
            const marshal: StartMarshal = .{
                .io = io,
                .anchor = .{ .processed = .{ .block = .new(2) }, .block = &blocks[2] },
            };
            var start = try Runner.resolve_start(&h.actor, storage.interface(), &plan, marshal);
            defer release_start(&start);
            try testing.expect(start.state_sync == null);
            try testing.expectEqual(@as(u64, 2), start.tip.?.height.get());
            try testing.expect(start.tip.?.digest.eql(blocks[2].digest()));
        }
    }.body);
}

// With state-sync material, the actor starts from the synced epoch at the floor block marshal
// yields, and the tip is the floor's parent when that is past the anchor.
test "run: resolve_start starts from the state-synced floor" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "resolve-synced", 10);
            defer h.deinit();
            var blocks: [4]Digested = undefined;
            try h.chain(&blocks);
            defer for (&blocks) |*block| block.deinit();
            var schemes = try state_sync_test.fixture();
            defer schemes.deinit(gpa);
            const material = try state_sync_test.material_with(&schemes, 0, blocks[3].digest());
            var storage = runtime.buffer.mocks.Storage.init(gpa);
            defer storage.deinit();
            const config = state_sync_test.config("resolve-synced");
            var plan = try StartPlan.init(gpa, io, storage.interface(), config, material);
            defer plan.deinit();
            const marshal: StartMarshal = .{
                .io = io,
                .anchor = .{ .processed = .{ .block = .new(1) }, .block = &blocks[1] },
                .floor = &blocks[3],
            };
            var start = try Runner.resolve_start(&h.actor, storage.interface(), &plan, marshal);
            defer release_start(&start);
            try testing.expect(start.state_sync != null);
            try testing.expectEqual(@as(u64, 0), start.state_sync.?.info.epoch.get());
            try testing.expectEqual(@as(u64, 3), start.state_sync.?.floor.get());
            try testing.expectEqual(@as(u64, 2), start.tip.?.height.get());
            try testing.expect(start.tip.?.digest.eql(blocks[2].digest()));
        }
    }.body);
}

// commonware panics with "marshal must yield state sync floor block".
test "run: resolve_start fails when marshal drops the state-sync floor" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "resolve-dropped", 10);
            defer h.deinit();
            var schemes = try state_sync_test.fixture();
            defer schemes.deinit(gpa);
            const digest = mocks.genesis_block(h.public_key).digest();
            const material = try state_sync_test.material_with(&schemes, 0, digest);
            var storage = runtime.buffer.mocks.Storage.init(gpa);
            defer storage.deinit();
            const config = state_sync_test.config("resolve-dropped");
            var plan = try StartPlan.init(gpa, io, storage.interface(), config, material);
            defer plan.deinit();
            const marshal: StartMarshal = .{ .io = io };
            const storage_handle = storage.interface();
            try testing.expectError(
                error.MissingStateSyncFloor,
                Runner.resolve_start(&h.actor, storage_handle, &plan, marshal),
            );
        }
    }.body);
}
