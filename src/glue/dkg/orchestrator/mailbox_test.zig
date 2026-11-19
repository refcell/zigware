//! Tests of commonware's `glue::dkg::orchestrator::mailbox` (it has none upstream): a tip is
//! ignored, and finalized blocks reach the orchestrator in order even past capacity.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const broadcast = @import("broadcast");
const utils = @import("utils");
const mocks = @import("../tests/mocks.zig");
const mailbox_mod = @import("mailbox.zig");

const gpa = testing.allocator;
const Exact = utils.acknowledgement.Exact;
const TestMailbox = mailbox_mod.Mailbox(mocks.TestBlock, Exact);
const TestMessage = TestMailbox.M;
const Digested = broadcast.Digested(mocks.TestBlock);

fn finalized(seed: u64) !struct { Digested, Exact.Handle } {
    const leader = mocks.TestSigner.from_seed(seed).public_key();
    const genesis = mocks.genesis_block(leader);
    const block = try Digested.precomputed(gpa, genesis, genesis.digest());
    return .{ block, try Exact.handle(gpa, testing.io) };
}

test "orchestrator mailbox: tips are ignored and blocks overflow in order" {
    var pair = try actor.mailbox.new(TestMessage, gpa, testing.io, 1);
    defer pair.receiver.deinit();
    var mailbox = TestMailbox.init(pair.sender);
    defer mailbox.deinit();
    const tip = try mailbox.report(.{ .tip = .{
        .round = .{ .epoch = .new(0), .view = .new(1) },
        .height = .new(1),
        .digest = mocks.genesis_block(mocks.TestSigner.from_seed(0).public_key()).digest(),
    } });
    try testing.expect(tip == .ok);
    try testing.expectError(error.Empty, pair.receiver.try_recv());
    var waiters: [3]utils.acknowledgement.ExactWaiter = undefined;
    var digests: [3]mocks.TestDigest = undefined;
    for (0..3) |index| {
        const block, const handle = try finalized(index);
        waiters[index] = handle.waiter;
        digests[index] = block.digest();
        const feedback = try mailbox.report(.{ .block = .{
            .block = block,
            .ack = handle.acknowledgement,
        } });
        try testing.expect(feedback.accepted());
    }
    defer for (&waiters) |*waiter| waiter.deinit();
    for (0..3) |index| {
        var message = try pair.receiver.try_recv();
        try testing.expect(message == .finalized);
        try testing.expect(message.finalized.block.digest().eql(digests[index]));
        message.finalized.ack.acknowledge();
        try waiters[index].wait();
        message.finalized.block.deinit();
    }
    try testing.expectError(error.Empty, pair.receiver.try_recv());
}
