//! commonware `glue/src/stateful/db/p2p/mailbox.rs` tests: the overflow policy, abandoned and
//! dropped fetches, and candidate feedback.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("../mod.zig");
const mailbox_mod = @import("mailbox.zig");

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
const Family = storage.mmr.Family;
const Digest = @import("cryptography").Sha256.Digest;

/// A database that is only a value.
const TestDb = struct {
    value: u64,

    pub fn deinit(_: *TestDb) void {}
};

const Mailbox = mailbox_mod.Mailbox(TestDb, Family, u64, Digest);
const Message = Mailbox.Msg;
const Request = Message.Request;
const Response = Message.Response;
const Candidate = storage.qmdb.sync.source.Candidate(Response);

comptime {
    storage.qmdb.sync.source.assert_source(Mailbox);
}

const request: Request = .{ .operations = .{ .size = 10, .start = 3, .max_ops = 2 } };

fn shared(value: u64) !db.Shared(TestDb) {
    return db.Shared(TestDb).init(gpa, io, "overflow", .{ .value = value });
}

/// Collects messages, refusing those `accept` rejects (a full ready queue).
const Collector = struct {
    messages: *std.ArrayList(Message),
    accept: enum { all, attachments, none },

    pub fn push(self: *Collector, message: Message) ?Message {
        const taken = switch (self.accept) {
            .all => true,
            .attachments => message == .attach_database,
            .none => false,
        };
        if (!taken) return message;
        self.messages.append(gpa, message) catch @panic("test allocation");
        return null;
    }
};

test "stateful p2p mailbox: overflow keeps the latest database and orders live requests" {
    var overflow: Message.Overflow = .empty;
    defer overflow.deinit(gpa);
    const old = try shared(1);
    defer old.deinit();
    const new = try shared(2);
    defer new.deinit();
    try Message.handle(gpa, &overflow, .{ .attach_database = old });

    // A closed reply channel lets the overflow drop a fetch whose caller left.
    const canceled = try utils.channel.mpsc.channel(Candidate, gpa, io, 1);
    try Message.handle(gpa, &overflow, .{
        .get_operations = .{ .request = request, .response = canceled.sender },
    });
    var canceled_receiver = canceled.receiver;
    canceled_receiver.deinit();
    const waiting = try utils.channel.mpsc.channel(Candidate, gpa, io, 1);
    var waiting_receiver = waiting.receiver;
    defer waiting_receiver.deinit();
    try Message.handle(gpa, &overflow, .{
        .get_operations = .{ .request = request, .response = waiting.sender },
    });
    try Message.handle(gpa, &overflow, .{ .attach_database = new });

    // A full ready queue keeps both the attachment and the first queued fetch.
    var messages: std.ArrayList(Message) = .empty;
    defer {
        for (messages.items) |message| Message.discard(message);
        messages.deinit(gpa);
    }
    var none: Collector = .{ .messages = &messages, .accept = .none };
    overflow.drain(&none);
    var attachments: Collector = .{ .messages = &messages, .accept = .attachments };
    overflow.drain(&attachments);
    var all: Collector = .{ .messages = &messages, .accept = .all };
    overflow.drain(&all);
    try testing.expect(overflow.is_empty());

    try testing.expectEqual(2, messages.items.len);
    try testing.expectEqual(new.cell, messages.items[0].attach_database.cell);
    const fetch = messages.items[1].get_operations;
    try testing.expect(fetch.request.eql(request));
    try testing.expect(!fetch.response.is_closed());
}

fn new_mailbox() !struct { Mailbox, actor.mailbox.Receiver(Message) } {
    const pair = try actor.mailbox.new(Message, gpa, io, 4);
    return .{ Mailbox.init(io, pair.sender), pair.receiver };
}

fn candidate(value: u64) !Response {
    const operations = try gpa.alloc(u64, 1);
    operations[0] = value;
    return .{ .operations = .{ .proof = .{ .leaves = 1 }, .operations = operations } };
}

const Fetching = struct {
    mailbox: *Mailbox,

    fn run(self: *Fetching) anyerror!storage.qmdb.sync.Served(Response) {
        return self.mailbox.serve(gpa, request);
    }
};

test "stateful p2p mailbox: a closed response ends the fetch" {
    var mailbox, var receiver = try new_mailbox();
    defer mailbox.deinit();
    defer receiver.deinit();
    var fetching: Fetching = .{ .mailbox = &mailbox };
    var future = try io.concurrent(Fetching.run, .{&fetching});
    var message = (try receiver.recv()).?;
    try testing.expect(message.get_operations.request.eql(request));
    message.get_operations.response.deinit();
    try testing.expectError(error.ResponseDropped, future.await(io));
    try testing.expectError(error.Empty, receiver.try_recv());
}

/// Sends candidate `value` through `reply` and returns the receiver of its verdict.
fn offer(reply: mailbox_mod.Reply(Response), value: u64) !oneshot.Receiver(bool) {
    const verdict = try oneshot.channel(bool, gpa, io);
    const response = try candidate(value);
    try reply.try_send(.{ .gpa = gpa, .response = response, .verdict = verdict.sender });
    return verdict.receiver;
}

fn check_rejected_candidate(cancel: bool) !void {
    var mailbox, var receiver = try new_mailbox();
    defer mailbox.deinit();
    defer receiver.deinit();
    var fetching: Fetching = .{ .mailbox = &mailbox };
    var future = try io.concurrent(Fetching.run, .{&fetching});
    var message = (try receiver.recv()).?;
    const reply = message.get_operations.response;
    defer message.get_operations.response.deinit();

    var rejected = try offer(reply, 1);
    defer rejected.deinit();
    var served = try future.await(io);
    defer served.response.deinit(gpa);
    try testing.expectEqualSlices(u64, &.{1}, served.response.operations.operations);
    var feedback = served.feedback.?;

    // Rejecting keeps the fetch open for another candidate.
    var second = try offer(reply, 2);
    defer second.deinit();
    var next = (try feedback.reject()).?;
    try testing.expect(!try rejected.recv());
    try testing.expect(!reply.is_closed());
    defer next.response.deinit(gpa);
    try testing.expectEqualSlices(u64, &.{2}, next.response.operations.operations);
    if (cancel) {
        next.feedback.?.deinit();
        try testing.expectError(error.Closed, second.recv());
    } else {
        next.feedback.?.accept();
        try testing.expect(try second.recv());
    }
    try testing.expect(reply.is_closed());
    try testing.expectError(error.Empty, receiver.try_recv());
}

test "stateful p2p mailbox: a rejected candidate keeps the fetch until accept or cancel" {
    try check_rejected_candidate(false);
    try check_rejected_candidate(true);
}
