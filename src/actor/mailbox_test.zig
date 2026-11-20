//! Tests for `mailbox.zig`, ported from commonware `actor/src/mailbox.rs`, plus tests on the
//! deterministic runtime (parked receivers, many producers, replay) and a seeded fuzz.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Smith = std.testing.Smith;
const Draws = @import("utils").fuzz.Draws;
const build_options = @import("build_options");
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;

const actor = @import("root.zig");
const mailbox = @import("mailbox.zig");
const Feedback = actor.Feedback;
const U = actor.Unreliable(Feedback);

fn remove_at(comptime T: type, deque: *std.Deque(T), index: usize) void {
    assert(index < deque.len);
    var cursor = index;
    while (cursor + 1 < deque.len) : (cursor += 1) deque.atPtr(cursor).* = deque.at(cursor + 1);
    _ = deque.popBack();
}

/// The unreliable policy from commonware's mailbox tests.
const Message = union(enum) {
    update: u64,
    vote: u64,
    required: u64,
    buffered: u64,
    hint: u64,

    pub const Overflow = std.Deque(Message);

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: Message) Allocator.Error!bool {
        switch (message) {
            .update => {
                if (last_update(overflow)) |index| remove_at(Message, overflow, index);
                try overflow.pushBack(gpa, message);
            },
            .required, .buffered => try overflow.pushBack(gpa, message),
            .hint => {
                const index = last_update(overflow) orelse return true;
                remove_at(Message, overflow, index);
                try overflow.pushBack(gpa, message);
            },
            .vote => return false,
        }
        return true;
    }

    fn last_update(overflow: *const Overflow) ?usize {
        var index = overflow.len;
        while (index > 0) {
            index -= 1;
            if (overflow.at(index) == .update) return index;
        }
        return null;
    }
};

/// A message owning a responder: the mailbox must `discard` it when it drops it.
const Ack = struct {
    dropped: *u32,

    pub const Overflow = std.Deque(Ack);

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: Ack) Allocator.Error!void {
        try overflow.pushBack(gpa, message);
    }

    pub fn discard(message: Ack) void {
        message.dropped.* += 1;
    }
};

const ClearingMessage = enum {
    fill_ready,
    clear_overflow,

    pub const Overflow = std.Deque(ClearingMessage);

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: ClearingMessage) !void {
        try overflow.pushBack(gpa, message);
        while (overflow.popFront()) |_| {}
    }
};

const SpillMessage = enum {
    fill_ready,
    spill,

    pub const Overflow = std.Deque(SpillMessage);

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: SpillMessage) !void {
        try overflow.pushBack(gpa, message);
    }
};

/// Keeps only the newest overflow message in a fixed slot: a custom `Overflow` with an
/// infallible policy (like glue's `Option<Message>` overflow).
const Latest = struct {
    value: u64,

    pub const Overflow = struct {
        pending: ?Latest = null,

        pub const empty: Overflow = .{};

        pub fn deinit(overflow: *Overflow, gpa: Allocator) void {
            _ = gpa;
            assert(overflow.pending == null);
        }

        pub fn is_empty(overflow: *const Overflow) bool {
            return overflow.pending == null;
        }

        pub fn drain(overflow: *Overflow, pusher: anytype) void {
            const message = overflow.pending orelse return;
            overflow.pending = pusher.push(message);
        }
    };

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: Latest) void {
        _ = gpa;
        overflow.pending = message;
    }
};

fn open(comptime T: type, capacity: u32) !mailbox.Pair(T) {
    return mailbox.new(T, testing.allocator, testing.io, capacity);
}

fn expect_enqueue(sender: mailbox.Sender(Message), message: Message, expected: U) !void {
    try testing.expectEqual(expected, try sender.enqueue(message));
}

fn expect_recv(receiver: *mailbox.Receiver(Message), expected: Message) !void {
    try testing.expectEqual(@as(?Message, expected), try receiver.recv());
}

fn expect_try_recv(receiver: *mailbox.Receiver(Message), expected: Message) !void {
    try testing.expectEqual(expected, try receiver.try_recv());
}

test "deque overflow drain stops after rejected message" {
    const gpa = testing.allocator;
    var overflow: std.Deque(Message) = .empty;
    defer overflow.deinit(gpa);
    for ([_]u64{ 1, 2, 3 }) |value| try overflow.pushBack(gpa, .{ .vote = value });
    var drained: std.ArrayList(Message) = try .initCapacity(gpa, 3);
    defer drained.deinit(gpa);

    const Pusher = struct {
        drained: *std.ArrayList(Message),

        pub fn push(pusher: *@This(), message: Message) ?Message {
            pusher.drained.appendAssumeCapacity(message);
            if (pusher.drained.items.len == 2) return pusher.drained.pop();
            return null;
        }
    };
    var pusher: Pusher = .{ .drained = &drained };
    mailbox.drain_overflow(Message, &overflow, &pusher);

    try testing.expectEqual(@as(usize, 1), drained.items.len);
    try testing.expectEqual(Message{ .vote = 1 }, drained.items[0]);
    try testing.expectEqual(@as(usize, 2), overflow.len);
    try testing.expectEqual(Message{ .vote = 2 }, overflow.at(0));
    try testing.expectEqual(Message{ .vote = 3 }, overflow.at(1));
}

test "full inbox replaces stale overflow message" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .update = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .update = 2 }, .new(.backoff));
    try expect_enqueue(pair.sender, .{ .update = 3 }, .new(.backoff));
    try expect_recv(&pair.receiver, .{ .update = 1 });
    try expect_recv(&pair.receiver, .{ .update = 3 });
}

test "policy can replace stale overflow at back" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .update = 2 }, .new(.backoff));
    try expect_enqueue(pair.sender, .{ .required = 3 }, .new(.backoff));
    try expect_enqueue(pair.sender, .{ .update = 4 }, .new(.backoff));
    try expect_recv(&pair.receiver, .{ .vote = 1 });
    try expect_recv(&pair.receiver, .{ .required = 3 });
    try expect_recv(&pair.receiver, .{ .update = 4 });
}

test "full inbox rejects non-replaceable message" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .vote = 2 }, .rejected);
    try expect_recv(&pair.receiver, .{ .vote = 1 });
    try testing.expectError(error.Empty, pair.receiver.try_recv());
}

test "full inbox retains required message" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .buffered = 2 }, .new(.backoff));
    try expect_recv(&pair.receiver, .{ .vote = 1 });
    try expect_recv(&pair.receiver, .{ .buffered = 2 });
}

test "try_recv refills from overflow" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .buffered = 2 }, .new(.backoff));
    try expect_try_recv(&pair.receiver, .{ .vote = 1 });
    try expect_try_recv(&pair.receiver, .{ .buffered = 2 });
}

test "backoff metric counts backoff feedback" {
    var registry: metrics.Registry = .init(testing.allocator);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("mailbox");
    var pair = try mailbox.new_with_metrics(Message, testing.allocator, testing.io, &scope, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .buffered = 2 }, .new(.backoff));
    try expect_enqueue(pair.sender, .{ .buffered = 3 }, .new(.backoff));
    const text = try registry.encode(testing.allocator);
    defer testing.allocator.free(text);
    try testing.expect(metrics.has_metric_value(text, "mailbox_backoff_total", 2));
    try testing.expectEqual(@as(u64, 2), pair.sender.backoff_total());
    try testing.expectEqual(@as(u64, 2), pair.receiver.backoff_total());
}

test "unreliable rejected feedback is not accepted or counted as backoff" {
    var registry: metrics.Registry = .init(testing.allocator);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("mailbox");
    var pair = try mailbox.new_with_metrics(Message, testing.allocator, testing.io, &scope, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    const feedback = try pair.sender.enqueue(.{ .vote = 2 });
    try testing.expectEqual(@as(U, .rejected), feedback);
    try testing.expect(!feedback.accepted());
    const text = try registry.encode(testing.allocator);
    defer testing.allocator.free(text);
    try testing.expect(metrics.has_metric_value(text, "mailbox_backoff_total", 0));
    try testing.expectEqual(@as(u64, 0), pair.sender.backoff_total());
}

test "dropping the mailbox unregisters the backoff metric" {
    var registry: metrics.Registry = .init(testing.allocator);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("mailbox");
    var pair = try mailbox.new_with_metrics(Message, testing.allocator, testing.io, &scope, 1);
    try testing.expectEqual(@as(usize, 1), registry.count());
    pair.sender.deinit();
    pair.receiver.deinit();
    try testing.expectEqual(@as(usize, 0), registry.count());
}

test "receiver drains buffered messages after senders drop" {
    for ([_]bool{ false, true }) |blocking| {
        var pair = try open(Message, 1);
        defer pair.receiver.deinit();
        try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
        try expect_enqueue(pair.sender, .{ .buffered = 2 }, .new(.backoff));
        pair.sender.deinit();

        if (blocking) {
            try expect_recv(&pair.receiver, .{ .vote = 1 });
            try expect_recv(&pair.receiver, .{ .buffered = 2 });
            try testing.expectEqual(@as(?Message, null), try pair.receiver.recv());
        } else {
            try expect_try_recv(&pair.receiver, .{ .vote = 1 });
            try expect_try_recv(&pair.receiver, .{ .buffered = 2 });
            try testing.expectError(error.Disconnected, pair.receiver.try_recv());
        }
    }
}

test "enqueue uses ready capacity after partial drain" {
    var pair = try open(Message, 2);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .vote = 2 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .required = 3 }, .new(.backoff));
    try expect_try_recv(&pair.receiver, .{ .vote = 1 });
    try expect_try_recv(&pair.receiver, .{ .vote = 2 });
    try expect_enqueue(pair.sender, .{ .vote = 4 }, .new(.ok));
    try expect_try_recv(&pair.receiver, .{ .required = 3 });
    try expect_try_recv(&pair.receiver, .{ .vote = 4 });
}

test "receiver refills overflow after partial drain" {
    var pair = try open(Message, 3);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .vote = 2 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .vote = 3 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .required = 4 }, .new(.backoff));
    try expect_try_recv(&pair.receiver, .{ .vote = 1 });
    try expect_try_recv(&pair.receiver, .{ .vote = 2 });
    try expect_enqueue(pair.sender, .{ .vote = 5 }, .new(.ok));
    try expect_try_recv(&pair.receiver, .{ .vote = 3 });
    try expect_try_recv(&pair.receiver, .{ .required = 4 });
    try expect_try_recv(&pair.receiver, .{ .vote = 5 });
}

test "full inbox retains unmatched replaceable message" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .required = 2 }, .new(.backoff));
    try expect_recv(&pair.receiver, .{ .vote = 1 });
    try expect_recv(&pair.receiver, .{ .required = 2 });
}

test "full inbox replaces stale overflow after ready fills" {
    var pair = try open(Message, 2);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .update = 2 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .update = 3 }, .new(.backoff));
    try expect_enqueue(pair.sender, .{ .update = 4 }, .new(.backoff));
    try expect_recv(&pair.receiver, .{ .vote = 1 });
    try expect_recv(&pair.receiver, .{ .update = 2 });
    try expect_recv(&pair.receiver, .{ .update = 4 });
}

test "mailbox capacity is a soft limit for required messages" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .required = 2 }, .new(.backoff));
    try expect_enqueue(pair.sender, .{ .required = 3 }, .new(.backoff));
    try expect_recv(&pair.receiver, .{ .vote = 1 });
    try expect_recv(&pair.receiver, .{ .required = 2 });
    try expect_recv(&pair.receiver, .{ .required = 3 });
}

test "full inbox drops hint without a stale update" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .hint = 2 }, .new(.backoff));
    try expect_recv(&pair.receiver, .{ .vote = 1 });
    try testing.expectError(error.Empty, pair.receiver.try_recv());
}

test "full inbox can replace or drop by message" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try expect_enqueue(pair.sender, .{ .update = 2 }, .new(.backoff));
    try expect_enqueue(pair.sender, .{ .hint = 3 }, .new(.backoff));
    try expect_recv(&pair.receiver, .{ .vote = 1 });
    try expect_recv(&pair.receiver, .{ .hint = 3 });
}

test "empty inbox closes when senders drop" {
    var pair = try open(Message, 1);
    defer pair.receiver.deinit();
    pair.sender.deinit();
    try testing.expectError(error.Disconnected, pair.receiver.try_recv());
    try testing.expectEqual(@as(?Message, null), try pair.receiver.recv());
}

test "a pending poll parks the receiver until the next receive" {
    var pair = try open(Message, 1);
    defer pair.receiver.deinit();
    const word = &pair.receiver.state.waker.word;
    try testing.expect(pair.receiver.poll_recv() == .pending);
    // Parked, so the enqueue takes the waiting-receiver wake path, as after commonware's
    // pending poll registers its waker.
    try testing.expectEqual(@as(u32, 1), word.load(.monotonic));
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
    try testing.expectEqual(@as(u32, 0b11), word.load(.monotonic));
    try expect_recv(&pair.receiver, .{ .vote = 1 });
    try testing.expectEqual(@as(u32, 0b10), word.load(.monotonic));

    try testing.expect(pair.receiver.poll_recv() == .pending);
    try testing.expectError(error.Empty, pair.receiver.try_recv());
    try testing.expectEqual(@as(u32, 0b10), word.load(.monotonic));
    try expect_enqueue(pair.sender, .{ .vote = 2 }, .new(.ok));
    try testing.expectEqual(Message{ .vote = 2 }, pair.receiver.poll_recv().ready.?);
    pair.sender.deinit();
    try testing.expectEqual(@as(?Message, null), pair.receiver.poll_recv().ready);
    try testing.expect(!pair.receiver.polled);
}

test "cloned senders keep the mailbox connected" {
    var pair = try open(Message, 1);
    defer pair.receiver.deinit();
    var clone = pair.sender.clone();
    pair.sender.deinit();
    try testing.expectError(error.Empty, pair.receiver.try_recv());
    try expect_enqueue(clone, .{ .vote = 7 }, .new(.ok));
    clone.deinit();
    try expect_try_recv(&pair.receiver, .{ .vote = 7 });
    try testing.expectError(error.Disconnected, pair.receiver.try_recv());
}

test "enqueue after receiver drop returns closed" {
    var pair = try open(Message, 1);
    defer pair.sender.deinit();
    pair.receiver.deinit();
    try testing.expect(pair.sender.is_closed());
    try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.closed));
    try expect_enqueue(pair.sender, .{ .required = 2 }, .new(.closed));
}

test "receiver drop cancels buffered responders" {
    var pair = try open(Ack, 1);
    defer pair.sender.deinit();
    var dropped: u32 = 0;
    try testing.expectEqual(Feedback.ok, try pair.sender.enqueue(.{ .dropped = &dropped }));
    try testing.expectEqual(Feedback.backoff, try pair.sender.enqueue(.{ .dropped = &dropped }));
    try testing.expectEqual(@as(u32, 0), dropped);
    pair.receiver.deinit();
    try testing.expectEqual(@as(u32, 2), dropped);
    try testing.expectEqual(Feedback.closed, try pair.sender.enqueue(.{ .dropped = &dropped }));
    try testing.expectEqual(@as(u32, 3), dropped);
}

test "policy can clear overflow and request backoff" {
    var pair = try open(ClearingMessage, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    try testing.expectEqual(Feedback.ok, try pair.sender.enqueue(.fill_ready));
    try testing.expectEqual(Feedback.backoff, try pair.sender.enqueue(.clear_overflow));
    try testing.expectEqual(ClearingMessage.fill_ready, try pair.receiver.try_recv());
    try testing.expectError(error.Empty, pair.receiver.try_recv());
}

test "custom overflow with an infallible policy" {
    var pair = try open(Latest, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    // `handle` cannot fail, so `enqueue` returns plain feedback.
    try testing.expectEqual(Feedback.ok, pair.sender.enqueue(.{ .value = 1 }));
    try testing.expectEqual(Feedback.backoff, pair.sender.enqueue(.{ .value = 2 }));
    try testing.expectEqual(Feedback.backoff, pair.sender.enqueue(.{ .value = 3 }));
    try testing.expectEqual(@as(u64, 1), (try pair.receiver.try_recv()).value);
    try testing.expectEqual(@as(u64, 3), (try pair.receiver.try_recv()).value);
    try testing.expectError(error.Empty, pair.receiver.try_recv());
}

/// Holds a sender of its own mailbox, forming a cycle the receiver's close must break.
const CyclicMessage = struct {
    sender: mailbox.Sender(CyclicMessage),
    drops: *u32,

    pub const Overflow = std.Deque(CyclicMessage);

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: CyclicMessage) !void {
        try overflow.pushBack(gpa, message);
    }

    pub fn discard(message: CyclicMessage) void {
        var sender = message.sender;
        sender.deinit();
        message.drops.* += 1;
    }
};

test "receiver drop breaks message sender cycle" {
    var pair = try open(CyclicMessage, 1);
    defer pair.sender.deinit();
    var drops: u32 = 0;
    const sender = pair.sender;
    try testing.expectEqual(
        Feedback.ok,
        try sender.enqueue(.{ .sender = sender.clone(), .drops = &drops }),
    );
    try testing.expectEqual(
        Feedback.backoff,
        try sender.enqueue(.{ .sender = sender.clone(), .drops = &drops }),
    );
    pair.receiver.deinit();
    try testing.expectEqual(@as(u32, 2), drops);
    try testing.expectEqual(
        Feedback.closed,
        try sender.enqueue(.{ .sender = sender.clone(), .drops = &drops }),
    );
    try testing.expectEqual(@as(u32, 3), drops);
}

// Deterministic runtime: parked receivers and many producers.

fn run_deterministic(comptime function: fn (Io) anyerror!void) !void {
    try runtime.deterministic.soak(testing.allocator, .{}, {}, struct {
        fn run(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start(function, .{runner.io()}));
        }
    }.run);
}

fn recv_flagged(comptime T: type) fn (*mailbox.Receiver(T), *bool) Io.Cancelable!?T {
    return struct {
        fn run(receiver: *mailbox.Receiver(T), received: *bool) Io.Cancelable!?T {
            const message = try receiver.recv();
            received.* = true;
            return message;
        }
    }.run;
}

test "empty inbox wakes on enqueue" {
    const Root = struct {
        fn run(io: Io) !void {
            var pair = try mailbox.new(Message, testing.allocator, io, 1);
            defer pair.sender.deinit();
            defer pair.receiver.deinit();
            var received = false;
            var future = try io.concurrent(recv_flagged(Message), .{ &pair.receiver, &received });
            try io.sleep(.fromMilliseconds(5), .awake);
            try testing.expect(!received);
            try expect_enqueue(pair.sender, .{ .vote = 1 }, .new(.ok));
            try testing.expectEqual(@as(?Message, .{ .vote = 1 }), try future.await(io));
            try testing.expect(received);
        }
    };
    try run_deterministic(Root.run);
}

test "pending recv wakes when senders drop" {
    const Root = struct {
        fn run(io: Io) !void {
            var pair = try mailbox.new(Message, testing.allocator, io, 1);
            defer pair.receiver.deinit();
            var received = false;
            var future = try io.concurrent(recv_flagged(Message), .{ &pair.receiver, &received });
            try io.sleep(.fromMilliseconds(5), .awake);
            try testing.expect(!received);
            pair.sender.deinit();
            try testing.expectEqual(@as(?Message, null), try future.await(io));
        }
    };
    try run_deterministic(Root.run);
}

/// The receiver parks, ready is primed without a wake, then an overflow enqueue must wake it.
fn expect_overflow_wakes(comptime T: type, io: Io, fill: T, spill: T) !void {
    var pair = try mailbox.new(T, testing.allocator, io, 1);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    var received = false;
    var future = try io.concurrent(recv_flagged(T), .{ &pair.receiver, &received });
    try io.sleep(.fromMilliseconds(5), .awake);
    try testing.expect(!received);

    // Prime ready directly to isolate the overflow wake (single-threaded runtime).
    try testing.expectEqual(@as(?T, null), pair.sender.state.ready.push(fill));
    try io.sleep(.fromMilliseconds(5), .awake);
    try testing.expect(!received);

    const feedback = try pair.sender.enqueue(spill);
    if (comptime mailbox.is_unreliable(T)) {
        try testing.expectEqual(U.new(.backoff), feedback);
    } else {
        try testing.expectEqual(Feedback.backoff, feedback);
    }
    try testing.expectEqual(@as(?T, fill), try future.await(io));
    try testing.expectEqual(spill, try pair.receiver.try_recv());
}

test "pending recv wakes on handled overflow enqueue" {
    const Root = struct {
        fn run(io: Io) !void {
            try expect_overflow_wakes(Message, io, .{ .vote = 1 }, .{ .buffered = 2 });
        }
    };
    try run_deterministic(Root.run);
}

test "pending recv wakes when policy spills" {
    const Root = struct {
        fn run(io: Io) !void {
            try expect_overflow_wakes(SpillMessage, io, .fill_ready, .spill);
        }
    };
    try run_deterministic(Root.run);
}

/// Reliable FIFO policy: every overflow message is retained in order.
const Sequenced = struct {
    producer: u32,
    index: u64,

    pub const Overflow = std.Deque(Sequenced);

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: Sequenced) !void {
        try overflow.pushBack(gpa, message);
    }
};

const producers_count = 3;
const messages_per_producer = 50;
const ProduceError = Allocator.Error || Io.Cancelable;

fn produce(io: Io, sender: mailbox.Sender(Sequenced), producer: u32) ProduceError!void {
    var owned = sender;
    defer owned.deinit();
    var index: u64 = 0;
    while (index < messages_per_producer) : (index += 1) {
        const feedback = try owned.enqueue(.{ .producer = producer, .index = index });
        assert(feedback.accepted());
        if (index % 7 == producer) try io.sleep(.fromMilliseconds(1), .awake);
    }
}

/// Many producers, one receiver: per-sender order holds and nothing is lost. Returns a hash
/// of the delivery order so runs can be compared.
fn many_producers(io: Io) !u64 {
    var pair = try mailbox.new(Sequenced, testing.allocator, io, 4);
    defer pair.receiver.deinit();
    var futures: [producers_count]Io.Future(ProduceError!void) = undefined;
    for (&futures, 0..) |*future, producer| {
        future.* = try io.concurrent(produce, .{ io, pair.sender.clone(), @intCast(producer) });
    }
    pair.sender.deinit();

    var next: [producers_count]u64 = @splat(0);
    var order = std.hash.Wyhash.init(0);
    var received: u64 = 0;
    while (try pair.receiver.recv()) |message| : (received += 1) {
        try testing.expectEqual(next[message.producer], message.index);
        next[message.producer] += 1;
        order.update(std.mem.asBytes(&message.producer));
    }
    try testing.expectEqual(@as(u64, producers_count * messages_per_producer), received);
    for (&futures) |*future| try future.await(io);
    return order.final();
}

test "many producers keep per-sender order and replay from the seed" {
    var digests: [3]u64 = undefined;
    for (&digests, [_]u64{ 1, 1, 2 }) |*digest, seed| {
        var runner = try runtime.deterministic.Runner.init(testing.allocator, .{ .seed = seed });
        defer runner.deinit();
        digest.* = try (try runner.start(many_producers, .{runner.io()}));
    }
    try testing.expectEqual(digests[0], digests[1]);
    try testing.expect(digests[0] != digests[2]);
}

// Threads: `std.Io.Threaded` interleaves the lock-free ready queue, the overflow activity
// word, and the waker for real (commonware checks these with loom).

/// Reliable FIFO policy that counts discarded messages.
const Counted = struct {
    producer: u32,
    index: u64,

    pub const Overflow = std.Deque(Counted);
    var discarded: std.atomic.Value(u64) = .init(0);

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: Counted) !void {
        try overflow.pushBack(gpa, message);
    }

    pub fn discard(_: Counted) void {
        _ = discarded.fetchAdd(1, .monotonic);
    }
};

const threaded_producers = 4;
const threaded_messages = 20_000;

fn produce_counted(sender: mailbox.Sender(Counted), producer: u32) Allocator.Error!void {
    var owned = sender;
    defer owned.deinit();
    var index: u64 = 0;
    while (index < threaded_messages) : (index += 1) {
        _ = try owned.enqueue(.{ .producer = producer, .index = index });
    }
}

/// Receive from producer threads until `stop` messages arrived (then close) or all senders
/// left; every message is received in per-sender order or discarded, exactly once.
fn threaded_round(capacity: u32, stop: u64) !void {
    const io = testing.io;
    Counted.discarded.store(0, .monotonic);
    var pair = try mailbox.new(Counted, testing.allocator, io, capacity);
    var receiver_open = true;
    defer if (receiver_open) pair.receiver.deinit();
    var futures: [threaded_producers]Io.Future(Allocator.Error!void) = undefined;
    for (&futures, 0..) |*future, producer| {
        future.* = try io.concurrent(produce_counted, .{ pair.sender.clone(), @intCast(producer) });
    }
    pair.sender.deinit();

    var next: [threaded_producers]u64 = @splat(0);
    var received: u64 = 0;
    while (received < stop) : (received += 1) {
        // Alternate the parking and polling receive paths.
        const message = if (received % 2 == 0)
            (try pair.receiver.recv()) orelse break
        else
            pair.receiver.try_recv() catch |err| switch (err) {
                error.Empty => (try pair.receiver.recv()) orelse break,
                error.Disconnected => break,
            };
        try testing.expectEqual(next[message.producer], message.index);
        next[message.producer] += 1;
    }
    pair.receiver.deinit();
    receiver_open = false;
    for (&futures) |*future| try future.await(io);
    const sent: u64 = threaded_producers * threaded_messages;
    try testing.expectEqual(sent, received + Counted.discarded.load(.monotonic));
}

test "threads keep per-sender order and lose nothing" {
    try threaded_round(2, threaded_producers * threaded_messages);
}

test "threads racing receiver close discard every unreceived message" {
    // Close at spread-out points; a roomy ready queue keeps senders on the fast path, so
    // some rounds close while a sender is mid push.
    const total: u64 = threaded_producers * threaded_messages;
    var round: u64 = 0;
    while (round < 40) : (round += 1) try threaded_round(256, round * 7_919 % total);
}

// Seeded fuzz: a reliable FIFO mailbox against a counting model.

fn fuzz_run(comptime body: fn (void, *Smith) anyerror!void, seed: u64, iterations: u32) !void {
    assert(iterations > 0);
    var prng = std.Random.DefaultPrng.init(seed ^ build_options.fuzz_seed);
    const random = prng.random();
    var input: [1024]u8 = undefined;
    const total: u64 = @as(u64, iterations) * build_options.fuzz_soak;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        const len = random.uintAtMost(usize, input.len);
        random.bytes(input[0..len]);
        var smith: Smith = .{ .in = input[0..len] };
        body({}, &smith) catch |err| {
            std.debug.print("fuzz: seed {d} iteration {d} failed: {t}\n", .{
                seed ^ build_options.fuzz_seed, iteration, err,
            });
            return err;
        };
    }
    assert(iteration == total);
    try std.testing.fuzz({}, body, .{});
}

fn fuzz_fifo(_: void, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    const capacity = draws.range_at_most(u32, 1, 8);
    var pair = try open(Sequenced, capacity);
    defer pair.receiver.deinit();
    var sent: u64 = 0;
    var received: u64 = 0;
    var backoffs: u64 = 0;
    const steps = draws.range_at_most(u32, 0, 512);
    for (0..steps) |_| {
        if (draws.value(bool)) {
            // Overflow is only non-empty while ready is full, so feedback follows the count.
            const queued = sent - received;
            const feedback = try pair.sender.enqueue(.{ .producer = 0, .index = sent });
            const expected: Feedback = if (queued < capacity) .ok else .backoff;
            try testing.expectEqual(expected, feedback);
            if (feedback == .backoff) backoffs += 1;
            sent += 1;
        } else if (pair.receiver.try_recv()) |message| {
            try testing.expectEqual(received, message.index);
            received += 1;
        } else |err| {
            try testing.expect(err == error.Empty);
            try testing.expectEqual(sent, received);
        }
    }
    try testing.expectEqual(backoffs, pair.sender.backoff_total());
    pair.sender.deinit();
    while (received < sent) : (received += 1) {
        try testing.expectEqual(received, (try pair.receiver.try_recv()).index);
    }
    try testing.expectError(error.Disconnected, pair.receiver.try_recv());
}

test "fuzz mailbox fifo against a model" {
    try fuzz_run(fuzz_fifo, 0x6d61_696c_626f_78, 200);
}
