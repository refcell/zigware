//! Unbounded channels for the simulator (commonware `utils::channel::mpsc::unbounded_channel`),
//! built on actor's mailbox with a `std.Deque` overflow, so sends never wait and never drop
//! while the receiver is open.
//!
//! A value that cannot be delivered (the receiver closed, or it was still buffered when the
//! receiver closed) is released with its `deinit()` method when `T` has one, the way Rust drops
//! it. `send` returns whether the receiver took the value (`send_lossy`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const mailbox = actor.mailbox;

/// Ready capacity before values spill into the (unbounded) overflow.
const ready_capacity = 64;

fn release(comptime T: type, value: T) void {
    if (comptime @typeInfo(T) == .@"struct" and @hasDecl(T, "deinit")) {
        var owned = value;
        owned.deinit();
    }
}

pub fn Unbounded(comptime T: type) type {
    return struct {
        pub const Item = struct {
            value: T,

            pub const Overflow = std.Deque(Item);

            pub fn handle(gpa: Allocator, overflow: *Overflow, item: Item) Allocator.Error!void {
                try overflow.pushBack(gpa, item);
            }

            pub fn discard(item: Item) void {
                release(T, item.value);
            }
        };

        pub const Sender = struct {
            inner: mailbox.Sender(Item),

            /// Delivers `value`, or releases it and returns false when the receiver is gone.
            pub fn send(sender: Sender, value: T) Allocator.Error!bool {
                const feedback = try sender.inner.enqueue(.{ .value = value });
                return feedback.accepted();
            }

            pub fn clone(sender: Sender) Sender {
                return .{ .inner = sender.inner.clone() };
            }

            pub fn is_closed(sender: Sender) bool {
                return sender.inner.is_closed();
            }

            pub fn deinit(sender: *Sender) void {
                sender.inner.deinit();
                sender.* = undefined;
            }
        };

        pub const Receiver = struct {
            inner: mailbox.Receiver(Item),

            /// The next value, or null once every sender is gone and the buffer is empty.
            pub fn recv(receiver: *Receiver) Io.Cancelable!?T {
                const item = try receiver.inner.recv() orelse return null;
                return item.value;
            }

            /// The next value if one is buffered.
            pub fn try_recv(receiver: *Receiver) mailbox.TryRecvError!T {
                const item = try receiver.inner.try_recv();
                return item.value;
            }

            /// Closes the channel and releases every buffered value.
            pub fn deinit(receiver: *Receiver) void {
                receiver.inner.deinit();
                receiver.* = undefined;
            }
        };

        pub const Pair = struct { sender: Sender, receiver: Receiver };

        pub fn init(gpa: Allocator, io: Io) Allocator.Error!Pair {
            const pair = try mailbox.new(Item, gpa, io, ready_capacity);
            assert(pair.sender.capacity() == ready_capacity);
            const sender: Sender = .{ .inner = pair.sender };
            return .{ .sender = sender, .receiver = .{ .inner = pair.receiver } };
        }
    };
}

const testing = std.testing;

test "unbounded channel never drops while open and releases on close" {
    const Counted = struct {
        counter: *u32,
        pub fn deinit(self: *@This()) void {
            self.counter.* += 1;
        }
    };
    const Channel = Unbounded(Counted);
    var released: u32 = 0;
    var pair = try Channel.init(testing.allocator, Io.failing);
    for (0..ready_capacity * 3) |_| {
        try testing.expect(try pair.sender.send(.{ .counter = &released }));
    }
    for (0..ready_capacity) |_| _ = try pair.receiver.try_recv();
    try testing.expectEqual(@as(u32, 0), released);
    pair.receiver.deinit();
    try testing.expectEqual(@as(u32, 2 * ready_capacity), released);
    try testing.expect(pair.sender.is_closed());
    try testing.expect(!try pair.sender.send(.{ .counter = &released }));
    try testing.expectEqual(@as(u32, 2 * ready_capacity + 1), released);
    pair.sender.deinit();
}

test "receiver sees disconnect after draining" {
    const Channel = Unbounded(u32);
    var pair = try Channel.init(testing.allocator, Io.failing);
    try testing.expect(try pair.sender.send(7));
    pair.sender.deinit();
    try testing.expectEqual(@as(?u32, 7), try pair.receiver.recv());
    try testing.expectEqual(@as(?u32, null), try pair.receiver.recv());
    pair.receiver.deinit();
}
