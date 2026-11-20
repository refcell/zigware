//! Tests of commonware's `glue::dkg::reshare::mailbox` (`mod tests`).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const actor = @import("actor");
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const runtime = @import("runtime");
const utils = @import("utils");
const mocks = @import("../tests/mocks.zig");
const mailbox_mod = @import("mailbox.zig");

const ancestry = consensus.marshal.ancestry;
const gpa = testing.allocator;

const Types = struct {
    pub const Block = mocks.TestBlock;
    pub const Ack = utils.acknowledgement.Exact;
    pub const Ancestry = ancestry.Bounded(mocks.TestBlock);
};
const TestMailbox = mailbox_mod.Mailbox(Types);
const TestMessage = TestMailbox.M;
const Digested = broadcast.Digested(mocks.TestBlock);

fn run(comptime body: fn (Io) anyerror!void) !void {
    try runtime.deterministic.soak(gpa, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    }, {}, struct {
        fn run_round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start(body, .{runner.io()}));
        }
    }.run_round);
}

/// An ancestry yielding the genesis block led by seed zero's key, and its digest.
fn parent_ancestry() !struct { Types.Ancestry, mocks.TestDigest } {
    const leader = mocks.TestSigner.from_seed(0).public_key();
    const genesis = mocks.genesis_block(leader);
    const parent = try Digested.precomputed(gpa, genesis, genesis.digest());
    return .{ try ancestry.from_iter(mocks.TestBlock, gpa, &.{parent}), genesis.digest() };
}

fn request_epoch_info(mailbox: TestMailbox, stream: Types.Ancestry) !TestMailbox.Response {
    return mailbox.epoch_info(stream);
}

// commonware `next_log_returns_none_when_actor_gone`.
test "mailbox: next_log returns null when the actor is gone" {
    var pair = try actor.mailbox.new(TestMessage, gpa, testing.io, 1);
    pair.receiver.deinit();
    var mailbox = TestMailbox.init(gpa, testing.io, pair.sender);
    defer mailbox.deinit();
    try testing.expect(try mailbox.next_log(.new(1)) == null);
}

// commonware `epoch_info_forwards_delayed_parent_without_polling`: the request reaches the
// actor before anything reads its ancestry, and the ancestry still yields the parent.
test "mailbox: epoch_info forwards its ancestry unread" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var pair = try actor.mailbox.new(TestMessage, gpa, io, 1);
            defer pair.receiver.deinit();
            var mailbox = TestMailbox.init(gpa, io, pair.sender);
            defer mailbox.deinit();
            const stream, const parent = try parent_ancestry();
            var request = try io.concurrent(request_epoch_info, .{ mailbox, stream });
            const message = (try pair.receiver.recv()).?;
            try testing.expect(message.body == .epoch_info);
            var forwarded = message.body.epoch_info;
            defer forwarded.ancestry.deinit();
            try testing.expect(forwarded.ancestry.peek() != null);
            var block = (try forwarded.ancestry.next()).?;
            defer block.deinit();
            try testing.expect(block.digest().eql(parent));
            try forwarded.response.send(.{ .available = .{ .gpa = gpa, .payload = null } });
            var response = try request.await(io);
            defer response.deinit();
            try testing.expect(response == .available);
            try testing.expect(response.available.payload == null);
        }
    }.body);
}

// commonware `canceled_epoch_info_closes_forwarded_response_without_polling_ancestry`.
test "mailbox: a canceled epoch_info closes the forwarded response" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var pair = try actor.mailbox.new(TestMessage, gpa, io, 1);
            defer pair.receiver.deinit();
            var mailbox = TestMailbox.init(gpa, io, pair.sender);
            defer mailbox.deinit();
            const stream, _ = try parent_ancestry();
            var request = try io.concurrent(request_epoch_info, .{ mailbox, stream });
            const message = (try pair.receiver.recv()).?;
            try testing.expect(message.body == .epoch_info);
            defer TestMessage.discard(message);
            try testing.expect(!message.response_closed());
            try testing.expectError(error.Canceled, request.cancel(io));
            try testing.expect(message.response_closed());
        }
    }.body);
}

// A dropped reservation hands its log back to the actor; an included one does not.
test "mailbox: a released reservation returns its log to the actor" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var pair = try actor.mailbox.new(TestMessage, gpa, io, 4);
            defer pair.receiver.deinit();
            var mailbox = TestMailbox.init(gpa, io, pair.sender);
            defer mailbox.deinit();
            const Payload = mailbox_mod.PayloadOf(Types);
            const Reservation = TestMailbox.Reservation;
            const placeholder = undefined_payload(Payload);
            var dropped = Reservation.init(gpa, .new(5), placeholder, mailbox.sender.clone());
            dropped.payload = null;
            dropped.deinit();
            const released = (try pair.receiver.recv()).?;
            try testing.expect(released.body == .release_log);
            try testing.expectEqual(@as(u64, 5), released.body.release_log.get());
            var kept = Reservation.init(gpa, .new(6), placeholder, mailbox.sender.clone());
            kept.payload = null;
            kept.included();
            try testing.expectError(error.Empty, pair.receiver.try_recv());
        }

        /// A placeholder the test clears before the reservation would free it.
        fn undefined_payload(comptime Payload: type) Payload {
            var payload: Payload = undefined;
            payload = .{ .epoch_info = undefined };
            return payload;
        }
    }.body);
}
