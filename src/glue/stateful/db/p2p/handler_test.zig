//! commonware `glue/src/stateful/db/p2p/handler.rs` tests, plus the handler's callbacks through
//! a full mailbox.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const storage = @import("storage");
const utils = @import("utils");
const handler_mod = @import("handler.zig");

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
const Family = storage.mmr.Family;
const Subscriber = handler_mod.Subscriber(void);
const Handler = handler_mod.Handler(Family, Subscriber);
const Message = Handler.Message;

const key: Message.Request = .{ .operations = .{ .size = 10, .start = 0, .max_ops = 1 } };

fn delivery_message(value: []const u8, response: oneshot.Sender(bool)) !Message {
    const subscribers = try gpa.dupe(Subscriber, &.{.{ .id = 0, .reply = {} }});
    errdefer gpa.free(subscribers);
    return .{ .deliver = .{
        .gpa = gpa,
        .delivery = .{ .key = key, .subscribers = subscribers },
        .value = try gpa.dupe(u8, value),
        .response = response,
    } };
}

const Collector = struct {
    messages: std.ArrayList(Message) = .empty,

    pub fn push(collector: *Collector, message: Message) ?Message {
        collector.messages.append(gpa, message) catch return message;
        return null;
    }

    fn deinit(collector: *Collector) void {
        for (collector.messages.items) |*message| message.deinit();
        collector.messages.deinit(gpa);
    }
};

test "stateful p2p handler: overflow retains open deliveries only" {
    var overflow: Message.Overflow = .empty;
    defer overflow.deinit(gpa);

    // An overflowed produce request is dropped, and its requester sees the closed response.
    var produce = try oneshot.channel(handler_mod.Produced, gpa, io);
    defer produce.receiver.deinit();
    try Message.handle(gpa, &overflow, .{ .produce = .{ .key = key, .response = produce.sender } });
    try testing.expectError(error.Closed, produce.receiver.try_recv());
    try testing.expect(overflow.is_empty());

    // Deliveries are retained, and drain skips one whose requester left.
    var closed = try oneshot.channel(bool, gpa, io);
    try Message.handle(gpa, &overflow, try delivery_message("", closed.sender));
    var open = try oneshot.channel(bool, gpa, io);
    defer open.receiver.deinit();
    try Message.handle(gpa, &overflow, try delivery_message("open", open.sender));
    closed.receiver.deinit();

    var collector: Collector = .{};
    defer collector.deinit();
    overflow.drain(&collector);
    try testing.expect(overflow.is_empty());
    try testing.expectEqual(1, collector.messages.items.len);
    try testing.expectEqualStrings("open", collector.messages.items[0].deliver.value);
}

test "stateful p2p handler: callbacks reach the actor and full mailboxes drop requests" {
    var pair = try actor.mailbox.new(Message, gpa, io, 1);
    defer pair.receiver.deinit();
    var handler: Handler = .{ .gpa = gpa, .io = io, .sender = pair.sender };
    defer handler.deinit();

    // The handler copies what the engine lends it.
    var value = "first".*;
    const subscribers = [_]Subscriber{ .{ .id = 7, .reply = {} }, .{ .id = 9, .reply = {} } };
    var first = try handler.deliver(.{ .key = key, .subscribers = &subscribers }, &value);
    defer first.deinit();
    value = "xxxxx".*;

    // Ready is full: the peer request is dropped, the second delivery waits in overflow.
    var produced = try handler.produce(key);
    defer produced.deinit();
    try testing.expectError(error.Closed, produced.try_recv());
    var second = try handler.deliver(.{ .key = key, .subscribers = subscribers[0..1] }, "second");
    defer second.deinit();

    var message = (try pair.receiver.recv()).?;
    try testing.expectEqualStrings("first", message.deliver.value);
    try testing.expectEqual(2, message.deliver.delivery.subscribers.len);
    try testing.expectEqual(9, message.deliver.delivery.subscribers[1].id);
    try message.deliver.response.send(true);
    message.deliver.response = undefined;
    message.deliver.gpa.free(message.deliver.delivery.subscribers);
    message.deliver.gpa.free(message.deliver.value);
    try testing.expect(try first.recv());

    // An unjudged delivery closes its receiver.
    var next = (try pair.receiver.recv()).?;
    try testing.expectEqualStrings("second", next.deliver.value);
    next.deinit();
    try testing.expectError(error.Closed, second.recv());
}
