//! commonware `glue/src/stateful/actor/core/mailbox.rs` tests, plus the mailbox's answers:
//! declined proposals, verdicts, and a verify without a verdict that never votes.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const utils = @import("utils");
const harness_mod = @import("../processor/testing.zig");
const mailbox_mod = @import("mailbox.zig");

const gpa = testing.allocator;
const Exact = utils.acknowledgement.Exact;
const TestBlock = harness_mod.TestBlock;
const Mailbox = mailbox_mod.Mailbox(harness_mod.TestP);
const Message = Mailbox.Message;

fn new_mailbox(capacity: u32) !struct { Mailbox, actor.mailbox.Receiver(Message) } {
    const pair = try actor.mailbox.new(Message, gpa, test_io.io, capacity);
    return .{ Mailbox.init(gpa, test_io.io, pair.sender), pair.receiver };
}

fn block_at(view: u64) !Mailbox.Digested {
    const genesis = TestBlock.genesis();
    const at_round = harness_mod.round(view);
    const block = TestBlock.init(genesis.digest(), .new(view), at_round, genesis.target);
    return harness_mod.digested(block);
}

fn finalized(mailbox: *Mailbox, view: u64) !struct { actor.Feedback, Exact.Waiter } {
    const handle = try Exact.handle(gpa, test_io.io);
    const update: Mailbox.Update = .{ .block = .{
        .block = try block_at(view),
        .ack = handle.acknowledgement,
    } };
    return .{ mailbox.report(update), handle.waiter };
}

fn check_queued_finalizations(drain: bool) !void {
    var mailbox, var receiver = try new_mailbox(1);
    // The second report overflows the one-slot mailbox and is retained.
    const first, var first_receipt = try finalized(&mailbox, 1);
    defer first_receipt.deinit();
    const second, var second_receipt = try finalized(&mailbox, 2);
    defer second_receipt.deinit();
    try testing.expectEqual(.ok, first);
    try testing.expectEqual(.backoff, second);

    // Once the last mailbox drops, draining yields both reports, then the closed channel.
    mailbox.deinit();
    if (drain) {
        const one = (try receiver.recv()).?;
        const two = (try receiver.recv()).?;
        try testing.expectEqual(null, try receiver.recv());
        Message.discard(one);
        Message.discard(two);
    }
    // Reports dropped unacknowledged cancel their acknowledgements.
    receiver.deinit();
    try testing.expectError(error.AcknowledgementCanceled, first_receipt.wait());
    try testing.expectError(error.AcknowledgementCanceled, second_receipt.wait());
}

test "stateful core mailbox: queued finalizations do not keep ingress open" {
    try check_queued_finalizations(false);
    try check_queued_finalizations(true);
}

test "stateful core mailbox: tips need no message" {
    var mailbox, var receiver = try new_mailbox(1);
    defer receiver.deinit();
    defer mailbox.deinit();
    const tip: Mailbox.Update = .{ .tip = .{
        .round = harness_mod.round(1),
        .height = .new(1),
        .digest = TestBlock.genesis().digest(),
    } };
    try testing.expectEqual(.ok, mailbox.report(tip));
    try testing.expectError(error.Empty, receiver.try_recv());
}

/// Runs one mailbox call on its own task while the test plays the actor.
fn Call(comptime kind: enum { prepare, propose, verify }) type {
    return struct {
        mailbox: *Mailbox,

        fn run(self: *@This()) anyerror!switch (kind) {
            .prepare => consensus_handoff,
            .propose => ?Mailbox.Digested,
            .verify => bool,
        } {
            const genesis = TestBlock.genesis();
            const head = try harness_mod.digested(genesis);
            const ancestry = try Mailbox.Ancestry.from_blocks(gpa, &.{head});
            const context = genesis.context();
            return switch (kind) {
                .prepare => self.mailbox.prepare({}, context, ancestry, {}),
                .propose => self.mailbox.propose({}, context, ancestry, {}),
                .verify => self.mailbox.verify({}, context, ancestry),
            };
        }
    };
}
const consensus_handoff = @import("consensus").Handoff(Mailbox.Digested);
const test_io = @import("../../test_io.zig");

test "stateful core mailbox: declined proposals answer wait and null" {
    var mailbox, var receiver = try new_mailbox(4);
    defer receiver.deinit();
    defer mailbox.deinit();

    var prepare: Call(.prepare) = .{ .mailbox = &mailbox };
    var prepared = try test_io.io.concurrent(Call(.prepare).run, .{&prepare});
    var message = (try receiver.recv()).?;
    try testing.expect(message.propose.proposal == .prepare);
    message.propose.decline();
    try testing.expect((try prepared.await(test_io.io)) == .wait);

    var propose: Call(.propose) = .{ .mailbox = &mailbox };
    var proposed = try test_io.io.concurrent(Call(.propose).run, .{&propose});
    message = (try receiver.recv()).?;
    try testing.expect(message.propose.proposal == .propose);
    message.propose.decline();
    try testing.expectEqual(null, try proposed.await(test_io.io));
}

test "stateful core mailbox: verify answers the verdict" {
    var mailbox, var receiver = try new_mailbox(4);
    defer receiver.deinit();
    defer mailbox.deinit();
    for ([_]bool{ true, false }) |verdict| {
        var call: Call(.verify) = .{ .mailbox = &mailbox };
        var future = try test_io.io.concurrent(Call(.verify).run, .{&call});
        var message = (try receiver.recv()).?;
        message.verify.ancestry.deinit();
        try message.verify.verification.send(verdict);
        try testing.expectEqual(verdict, try future.await(test_io.io));
    }
}

test "stateful core mailbox: a verify without a verdict waits instead of voting" {
    try test_io.run_on_deterministic(verify_without_verdict_waits);
}

fn verify_without_verdict_waits() anyerror!void {
    var mailbox, var receiver = try new_mailbox(4);
    defer receiver.deinit();
    defer mailbox.deinit();
    var call: Call(.verify) = .{ .mailbox = &mailbox };
    var future = try test_io.io.concurrent(Call(.verify).run, .{&call});
    // The actor drops the verdict unsent (a waiting verification).
    var message = (try receiver.recv()).?;
    Message.discard(message);
    message = undefined;
    // The call stays unanswered until consensus cancels it: no `false` vote.
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectError(error.Canceled, future.cancel(test_io.io));
}

test "stateful core mailbox: overflow drops requests whose callers left" {
    var overflow: Message.Overflow = .empty;
    defer overflow.deinit(gpa);
    const utils_oneshot = utils.channel.oneshot;
    const live = try utils_oneshot.channel(bool, gpa, test_io.io);
    var live_receiver = live.receiver;
    defer live_receiver.deinit();
    const gone = try utils_oneshot.channel(bool, gpa, test_io.io);
    var gone_receiver = gone.receiver;
    const ancestry = try Mailbox.Ancestry.from_blocks(gpa, &.{try block_at(1)});
    try Message.handle(gpa, &overflow, .{ .verify = .{
        .ancestry = ancestry,
        .verification = gone.sender,
    } });
    try Message.handle(gpa, &overflow, .{ .verify = .{
        .ancestry = try Mailbox.Ancestry.from_blocks(gpa, &.{try block_at(2)}),
        .verification = live.sender,
    } });
    gone_receiver.deinit();

    const Collector = struct {
        messages: std.ArrayList(Message) = .empty,
        pub fn push(self: *@This(), message: Message) ?Message {
            self.messages.append(gpa, message) catch @panic("test allocation");
            return null;
        }
    };
    var collector: Collector = .{};
    defer {
        for (collector.messages.items) |message| Message.discard(message);
        collector.messages.deinit(gpa);
    }
    overflow.drain(&collector);
    try testing.expect(overflow.is_empty());
    try testing.expectEqual(1, collector.messages.items.len);
    const kept = collector.messages.items[0].verify.ancestry.peek().?;
    try testing.expectEqual(2, kept.inner().height().get());
}
