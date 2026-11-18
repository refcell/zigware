//! Whole-window tests of commonware's `glue::dkg::reshare::actor::inclusion` (`mod tests`),
//! driven through the actor's mailbox in one-shot DKG mode over a singleton set, as
//! commonware's `InclusionHarness` is.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");
const mocks = @import("../../tests/mocks.zig");
const actor_test = @import("actor_test.zig");
const dealing = @import("dealing.zig");
const window = @import("inclusion_window.zig");

const Epoch = consensus.Epoch;
const Exact = utils.acknowledgement.Exact;
const P = mocks.TestPublicKey;
const V = mocks.TestBlsVariant;
const Set = utils.ordered.Set(P);
const N3f1 = utils.N3f1;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Harness = actor_test.Harness;
const TestActor = @import("actor.zig").Actor(mocks.ActorTypes);
const Digested = TestActor.Digested;
const Dealing = dealing.Window(mocks.ActorTypes);
const Inclusion = window.Window(mocks.ActorTypes);
const gpa = testing.allocator;
const namespace = "_COMMONWARE_GLUE_DKG_RESHARE_INCLUSION_TEST";

/// A singleton harness switched to one-shot DKG mode, with epoch zero's round.
const Fixture = struct {
    h: Harness,
    round: fd.Info(V, P),

    fn init(self: *Fixture, io: Io, partition: []const u8, length: u64) !void {
        try self.h.init(io, partition, length);
        errdefer self.h.deinit();
        const key = self.h.public_key;
        const participants = try Set.from_dedup(gpa, &.{key});
        self.h.actor.mode = .{ .dkg = .{ .participants = participants, .directory = .{} } };
        const mode = .non_zero_counter;
        const dealers = try Set.from_dedup(gpa, &.{key});
        const players = try Set.from_dedup(gpa, &.{key});
        self.round = try .init(N3f1, gpa, namespace, 0, null, mode, .v1, dealers, players);
    }

    fn deinit(self: *Fixture) void {
        self.round.deinit(gpa);
        self.h.deinit();
    }

    fn dealing(self: *Fixture, epoch: u64) !Dealing.Outcome {
        const peers = (&self.h.public_key)[0..1];
        var channel = p2p.utils.mocks.inert_channel(P, gpa, self.h.io, peers);
        const session: Dealing.Session = .{
            .epoch = .new(epoch),
            .store = &self.h.store,
            .dealer = null,
            .player = null,
        };
        return Dealing.dealing(&self.h.actor, session, &channel.sender, &channel.receiver);
    }

    fn inclusion(self: *Fixture, requests: Inclusion.Requests) !@import("actor.zig").Flow {
        const session: Inclusion.Session = .{
            .epoch = .zero(),
            .info = &self.round,
            .store = &self.h.store,
            .dealer = null,
        };
        return Inclusion.inclusion_window(&self.h.actor, session, requests);
    }

    /// Delivers `blocks[index]` for each index and returns the waiters.
    fn deliver(self: *Fixture, blocks: []const Digested, indices: []const usize) ![4]Exact.Waiter {
        var waiters: [4]Exact.Waiter = undefined;
        for (indices, waiters[0..indices.len]) |index, *waiter| {
            waiter.* = try self.h.deliver(&blocks[index]);
        }
        return waiters;
    }
};

fn expect_acknowledged(waiters: []Exact.Waiter) !void {
    for (waiters) |*waiter| {
        defer waiter.deinit();
        try (waiter.poll() orelse return error.Unacknowledged);
    }
}

fn free_blocks(blocks: []Digested) void {
    for (blocks) |*block| block.deinit();
}

// commonware `redelivered_receipts_survive_phase_changes`: marshal may redeliver blocks the
// actor already applied; every window acknowledges them.
test "inclusion: redelivered receipts survive phase changes" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var f: Fixture = undefined;
            try f.init(io, "redelivered-receipts", 4);
            defer f.deinit();
            var blocks: [6]Digested = undefined;
            try f.h.chain(&blocks);
            defer free_blocks(&blocks);

            // Dealing completes epoch zero's early phase.
            var early = try f.deliver(&blocks, &.{ 0, 1 });
            var first = try f.dealing(0);
            try testing.expect(first == .proceed);
            first.proceed.deinit(gpa);
            try expect_acknowledged(early[0..2]);

            // Inclusion receives a redelivered early block and a repeated midpoint before the
            // final block completes the epoch.
            var late = try f.deliver(&blocks, &.{ 1, 2, 2, 3 });
            try testing.expectEqual(.proceed, try f.inclusion(.empty));
            try expect_acknowledged(&late);

            // The next epoch's dealing receives redelivered epoch-zero blocks first.
            var next = try f.deliver(&blocks, &.{ 2, 3, 4, 5 });
            var second = try f.dealing(1);
            try testing.expect(second == .proceed);
            second.proceed.deinit(gpa);
            try expect_acknowledged(&next);
        }
    }.body);
}

const Response = TestActor.Mailbox.Response;

fn ask(mailbox: TestActor.Mailbox, blocks: []const Digested) !Response {
    var handles: [2]Digested = undefined;
    for (blocks, &handles) |block, *handle| handle.* = block.clone();
    const ancestry = try consensus.marshal.ancestry.from_iter(mocks.TestBlock, gpa, &handles);
    return mailbox.epoch_info(ancestry);
}

// commonware `pr_5263_regression`: a final-block request made while dealing still applies
// blocks is held through dealing and answered by inclusion on entry, from the request's
// ancestry.
test "inclusion: a request held through dealing is answered on entry (pr 5263)" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var f: Fixture = undefined;
            try f.init(io, "dealing-holds-requests", 4);
            defer f.deinit();
            var blocks: [4]Digested = undefined;
            try f.h.chain(&blocks);
            defer free_blocks(&blocks);

            // Verification of the final block asks for epoch info before dealing applies
            // any block.
            const ancestry = [_]Digested{ blocks[3], blocks[2] };
            var request = try io.concurrent(ask, .{ f.h.mailbox, &ancestry });
            var waiters = try f.deliver(&blocks, &.{ 0, 1 });
            const outcome = try f.dealing(0);
            try testing.expect(outcome == .proceed);
            try expect_acknowledged(waiters[0..2]);

            // No further message arrives, so inclusion starts the held request on entry.
            var running = try io.concurrent(Fixture.inclusion, .{ &f, outcome.proceed });
            var response = try request.await(io);
            defer response.deinit();
            if (running.cancel(io)) |_| {} else |_| {}
            try testing.expect(response == .available);
            try testing.expect(response.available.payload == null);
        }
    }.body);
}
