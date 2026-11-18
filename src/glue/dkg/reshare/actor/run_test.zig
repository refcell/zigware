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
