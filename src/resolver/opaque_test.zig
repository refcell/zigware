//! Tests for `opaque.zig`, ported from commonware `resolver/src/opaque.rs`, on the
//! deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const runtime = @import("runtime");
const utils = @import("utils");
const resolver = @import("root.zig");
const opaque_resolver = @import("opaque.zig");
const metrics = runtime.telemetry.metrics;

const oneshot = utils.channel.oneshot;
const Outcome = resolver.Outcome;
const Predicate = resolver.Predicate(u8, u16);
const PublicKey = [32]u8;

const retry_delay_ns: u64 = 100 * std.time.ns_per_ms;
const config: opaque_resolver.Config = .{
    .mailbox_size = 16,
    .fetch_retry_delay_ns = retry_delay_ns,
};
const complete: Outcome = .{ .resolved = .complete };

fn run(comptime body: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try try runner.start(body, .{runner.io()});
}

fn sleep_ms(io: Io, ms: u64) !void {
    try io.sleep(.fromMilliseconds(@intCast(ms)), .awake);
}

/// Serves queued responses per key, counting calls.
const MockFetcher = struct {
    pub const Key = u8;
    pub const Value = []const u8;

    const Response = struct { key: u8, value: ?[]const u8 };
    const Shared = struct {
        responses: std.ArrayList(Response) = .empty,
        calls: u32 = 0,
    };

    shared: *Shared,

    fn init() !MockFetcher {
        const shared = try testing.allocator.create(Shared);
        shared.* = .{};
        return .{ .shared = shared };
    }

    fn deinit(self: MockFetcher) void {
        self.shared.responses.deinit(testing.allocator);
        testing.allocator.destroy(self.shared);
    }

    fn push(self: MockFetcher, key: u8, value: ?[]const u8) !void {
        try self.shared.responses.append(testing.allocator, .{ .key = key, .value = value });
    }

    fn calls(self: MockFetcher) u32 {
        return self.shared.calls;
    }

    pub fn fetch(self: MockFetcher, _: Io, key: u8) Io.Cancelable!?[]const u8 {
        // The deterministic runtime is single-threaded, so the shared state needs no lock.
        self.shared.calls += 1;
        for (self.shared.responses.items, 0..) |response, index| {
            if (response.key != key) continue;
            return self.shared.responses.orderedRemove(index).value;
        }
        return null;
    }
};

/// Signals when the first fetch starts, then waits for the test's response.
const BlockingFetcher = struct {
    pub const Key = u8;
    pub const Value = []const u8;

    const Shared = struct {
        started: ?oneshot.Sender(void),
        response: ?oneshot.Receiver(?[]const u8),
    };

    shared: *Shared,

    const Parts = struct {
        fetcher: BlockingFetcher,
        started: oneshot.Receiver(void),
        response: oneshot.Sender(?[]const u8),
    };

    fn init(io: Io) !Parts {
        const gpa = testing.allocator;
        const started = try oneshot.channel(void, gpa, io);
        const response = try oneshot.channel(?[]const u8, gpa, io);
        const shared = try gpa.create(Shared);
        shared.* = .{ .started = started.sender, .response = response.receiver };
        return .{
            .fetcher = .{ .shared = shared },
            .started = started.receiver,
            .response = response.sender,
        };
    }

    fn deinit(self: BlockingFetcher) void {
        if (self.shared.started) |*sender| sender.deinit();
        if (self.shared.response) |*receiver| receiver.deinit();
        testing.allocator.destroy(self.shared);
    }

    pub fn fetch(self: BlockingFetcher, _: Io, _: u8) Io.Cancelable!?[]const u8 {
        if (self.shared.started) |*sender| sender.send({}) catch {};
        self.shared.started = null;
        var receiver = self.shared.response.?; // missing response
        self.shared.response = null;
        defer receiver.deinit();
        return receiver.recv() catch |err| switch (err) {
            error.Closed => null,
            error.Canceled => error.Canceled,
        };
    }
};

/// A delivery captured by `TestConsumer`, with the verdict sender.
const Captured = struct {
    key: u8,
    subscribers: []u16,
    value: []const u8,
    response: oneshot.Sender(Outcome),

    fn send(self: *Captured, outcome: Outcome) !void {
        defer testing.allocator.free(self.subscribers);
        try self.response.send(outcome);
    }

    /// Drop the delivery without a verdict.
    fn drop(self: *Captured) void {
        self.response.deinit();
        testing.allocator.free(self.subscribers);
    }
};

const TestConsumer = struct {
    pub const Key = u8;
    pub const Value = []const u8;
    pub const Subscriber = u16;
    pub const Outcome = resolver.Outcome;

    const Shared = struct { io: Io, captured: std.ArrayList(Captured) = .empty };

    shared: *Shared,

    fn init(io: Io) !TestConsumer {
        const shared = try testing.allocator.create(Shared);
        shared.* = .{ .io = io };
        return .{ .shared = shared };
    }

    fn deinit(self: TestConsumer) void {
        for (self.shared.captured.items) |*captured| captured.drop();
        self.shared.captured.deinit(testing.allocator);
        testing.allocator.destroy(self.shared);
    }

    pub fn deliver(
        self: TestConsumer,
        delivery: resolver.Delivery(u8, u16),
        value: []const u8,
    ) Allocator.Error!oneshot.Receiver(resolver.Outcome) {
        const gpa = testing.allocator;
        var pair = try oneshot.channel(resolver.Outcome, gpa, self.shared.io);
        errdefer pair.receiver.deinit();
        const subscribers = try gpa.dupe(u16, delivery.subscribers);
        errdefer gpa.free(subscribers);
        try self.shared.captured.append(gpa, .{
            .key = delivery.key,
            .subscribers = subscribers,
            .value = value,
            .response = pair.sender,
        });
        return pair.receiver;
    }

    fn pop(self: TestConsumer) ?Captured {
        if (self.shared.captured.items.len == 0) return null;
        return self.shared.captured.orderedRemove(0);
    }

    fn len(self: TestConsumer) usize {
        return self.shared.captured.items.len;
    }

    fn wait(self: TestConsumer, io: Io) !Captured {
        for (0..50) |_| {
            if (self.pop()) |captured| return captured;
            try sleep_ms(io, 10);
        }
        return error.TimedOutWaitingForDelivery;
    }
};

fn Harness(comptime F: type) type {
    return struct {
        const Self = @This();
        const TestActor = opaque_resolver.Actor(F, TestConsumer);

        consumer: TestConsumer,
        spawned: TestActor.Spawned(PublicKey),

        fn start(io: Io, registry: *metrics.Registry, fetcher: F) !Self {
            const consumer = try TestConsumer.init(io);
            errdefer consumer.deinit();
            const scope = metrics.Scope.init(registry).child("resolver");
            const gpa = testing.allocator;
            const spawned =
                try TestActor.spawn(PublicKey, gpa, io, scope, fetcher, consumer, config);
            return .{ .consumer = consumer, .spawned = spawned };
        }

        fn fetch(self: *Self, key: u8, subscriber: u16) !void {
            const item: resolver.Fetch(u8, u16) = .{ .key = key, .subscriber = subscriber };
            const feedback = try self.spawned.resolver.fetch(item);
            try testing.expect(feedback.accepted());
        }

        fn retain(self: *Self, predicate: Predicate) !void {
            try testing.expect((try self.spawned.resolver.retain(predicate)).accepted());
        }

        fn count(self: *const Self, status: opaque_resolver.Status) u64 {
            return self.spawned.actor.fetch_count(status);
        }

        fn stop(self: *Self, io: Io) !void {
            self.spawned.resolver.deinit();
            try self.spawned.future.await(io);
            self.consumer.deinit();
        }
    };
}

fn subscriber_is_not(value: u16, _: u8, subscriber: u16) bool {
    return subscriber != value;
}

fn subscriber_is(value: u16, _: u8, subscriber: u16) bool {
    return subscriber == value;
}

fn keep_none(_: void, _: u8, _: u16) bool {
    return false;
}

fn expect_subscribers(captured: Captured, expected: []const u16) !void {
    try testing.expectEqual(@as(u8, 1), captured.key);
    try testing.expectEqualSlices(u16, expected, captured.subscribers);
}

var outcome_under_test: Outcome = undefined;

fn fetch_during_validation_body(io: Io) !void {
    const fetcher = try MockFetcher.init();
    defer fetcher.deinit();
    try fetcher.push(1, "value");
    try fetcher.push(1, "refetched");
    var registry = metrics.Registry.init(testing.allocator);
    defer registry.deinit();
    var harness = try Harness(MockFetcher).start(io, &registry, fetcher);
    // Add two late subscribers while the original snapshot is being judged.
    try harness.fetch(1, 10);
    var first = try harness.consumer.wait(io);
    try expect_subscribers(first, &.{10});
    try testing.expectEqualStrings("value", first.value);
    const late: []const resolver.Fetch(u8, u16) = &.{
        .{ .key = 1, .subscriber = 11 },
        .{ .key = 1, .subscriber = 12 },
    };
    try testing.expect((try harness.spawned.resolver.fetch_all(late)).accepted());
    try sleep_ms(io, 10);
    try first.send(complete);
    // Acceptance reuses the same value for the late snapshot and counts it once.
    var second = try harness.consumer.wait(io);
    try testing.expectEqualStrings("value", second.value);
    try expect_subscribers(second, &.{ 11, 12 });
    try testing.expectEqual(@as(u32, 1), fetcher.calls());
    try testing.expectEqual(@as(u64, 1), harness.count(.success));
    const partial = outcome_under_test.eql(.{ .resolved = .partial });
    if (partial) try harness.retain(.init(@as(u16, 11), subscriber_is_not));
    try second.send(outcome_under_test);
    var expected_successes: u64 = 1;
    if (!outcome_under_test.eql(complete)) {
        // A fresh fetch confirms the cached verdict was processed without another count.
        var third = try harness.consumer.wait(io);
        try testing.expectEqualStrings("refetched", third.value);
        if (partial) try expect_subscribers(third, &.{12}) else {
            try expect_subscribers(third, &.{ 11, 12 });
        }
        try testing.expectEqual(@as(u64, 1), harness.count(.success));
        try testing.expectEqual(@as(u64, 0), harness.count(.ambiguous));
        try third.send(complete);
        expected_successes = 2;
    }
    try sleep_ms(io, 10);
    try testing.expectEqual(@as(usize, 0), harness.consumer.len());
    try testing.expectEqual(expected_successes, fetcher.calls());
    try testing.expectEqual(expected_successes, harness.count(.success));
    try testing.expectEqual(@as(u64, 0), harness.count(.ambiguous));
    const text = try registry.encode(testing.allocator);
    defer testing.allocator.free(text);
    var line_buffer: [64]u8 = undefined;
    const line = try std.fmt.bufPrint(
        &line_buffer,
        "resolver_actor_fetch_total{{status=\"Success\"}} {d}\n",
        .{expected_successes},
    );
    try testing.expect(std.mem.indexOf(u8, text, line) != null);
    try testing.expect(std.mem.indexOf(u8, text, "status=\"Ambiguous\"") == null);
    try harness.stop(io);
}

test "fetch during validation reuses response after success" {
    const outcomes = [_]Outcome{ complete, .{ .resolved = .partial }, .unresolved };
    for (outcomes) |outcome| {
        outcome_under_test = outcome;
        try run(fetch_during_validation_body);
    }
}

const DirectActor = opaque_resolver.Actor(MockFetcher, TestConsumer);

/// An actor driven by the test, without its event loop.
const Direct = struct {
    actor: *DirectActor,
    sender: actor.mailbox.Sender(DirectActor.Message),
    consumer: TestConsumer,

    fn init(io: Io, registry: *metrics.Registry, fetcher: MockFetcher) !Direct {
        const gpa = testing.allocator;
        const consumer = try TestConsumer.init(io);
        const pair = try actor.mailbox.new(DirectActor.Message, gpa, io, 16);
        const scope = metrics.Scope.init(registry).child("actor");
        const created = try DirectActor.create(
            gpa,
            io,
            scope,
            fetcher,
            consumer,
            pair.receiver,
            config,
        );
        return .{ .actor = created, .sender = pair.sender, .consumer = consumer };
    }

    fn deinit(self: *Direct) void {
        self.actor.destroy();
        self.sender.deinit();
        self.consumer.deinit();
    }

    fn fetch_once(self: *Direct) !void {
        const task = try self.actor.next_fetched();
        try self.actor.handle_fetched(task);
    }

    fn deliver_next(self: *Direct) !void {
        const completed = try self.actor.deliveries.next_completion();
        try self.actor.handle_delivered(completed);
    }
};

var reinsert_under_test: bool = undefined;

fn canceled_retry_body(io: Io) !void {
    // A value becomes available only after two failed fetches.
    const fetcher = try MockFetcher.init();
    defer fetcher.deinit();
    try fetcher.push(1, null);
    try fetcher.push(1, null);
    try fetcher.push(1, "new");
    var registry = metrics.Registry.init(testing.allocator);
    defer registry.deinit();
    var direct = try Direct.init(io, &registry, fetcher);
    defer direct.deinit();
    const reinsert = reinsert_under_test;
    // A missing value schedules a retry for the original request.
    try direct.actor.add_fetch(1, &.{10});
    try direct.fetch_once();
    try testing.expectEqual(@as(u32, 1), fetcher.calls());
    // Cancel halfway to its deadline; a replacement gets a later retry deadline.
    try sleep_ms(io, 50);
    try direct.actor.retain(.init({}, keep_none));
    if (reinsert) {
        try direct.actor.add_fetch(1, &.{10});
        try direct.fetch_once();
        try testing.expectEqual(@as(u32, 2), fetcher.calls());
    }
    // Reaching the canceled deadline must not start another fetch.
    try sleep_ms(io, 50);
    try direct.actor.process_retries();
    try testing.expect(direct.actor.try_next_fetched() == null);
    try testing.expectEqual(@as(u32, if (reinsert) 2 else 1), fetcher.calls());
    // At the later deadline, only a reinserted key may fetch again.
    try sleep_ms(io, 50);
    try direct.actor.process_retries();
    if (reinsert) {
        try direct.fetch_once();
        try testing.expectEqual(@as(u32, 3), fetcher.calls());
        var delivered = direct.consumer.pop().?;
        defer delivered.drop();
        try testing.expectEqualStrings("new", delivered.value);
        try testing.expectEqual(@as(u16, 10), delivered.subscribers[0]);
    } else {
        try testing.expect(direct.actor.try_next_fetched() == null);
        try testing.expectEqual(@as(u32, 1), fetcher.calls());
    }
}

test "canceled retry cannot restart reinserted key early" {
    for ([_]bool{ false, true }) |reinsert| {
        reinsert_under_test = reinsert;
        try run(canceled_retry_body);
    }
}

var previously_accepted_under_test: bool = undefined;

/// Canceled verdicts retain source feedback without changing a replacement's demand.
fn canceled_delivery_body(io: Io) !void {
    const previously_accepted = previously_accepted_under_test;
    const outcome = outcome_under_test;
    const fetcher = try MockFetcher.init();
    defer fetcher.deinit();
    try fetcher.push(1, "old");
    try fetcher.push(1, "new");
    var registry = metrics.Registry.init(testing.allocator);
    defer registry.deinit();
    var direct = try Direct.init(io, &registry, fetcher);
    defer direct.deinit();
    const subject = direct.actor;
    try subject.add_fetch(1, &.{10});
    try subject.add_fetch(1, &.{12});
    try direct.fetch_once();
    var old = direct.consumer.pop().?;
    if (previously_accepted) {
        // Hold a verdict from an accepted redelivery instead of a fresh response.
        try subject.add_fetch(1, &.{11});
        try subject.add_fetch(1, &.{13});
        try old.send(complete);
        try direct.deliver_next();
        old = direct.consumer.pop().?;
        try testing.expectEqualStrings("old", old.value);
    }
    try testing.expectEqual(@as(usize, 2), old.subscribers.len);
    // Remove the old entry and reuse its key and subscriber before reading the accepted
    // verdict. The new response stays unjudged throughout.
    try old.send(outcome);
    try subject.retain(.init({}, keep_none));
    try subject.add_fetch(1, &.{if (previously_accepted) 11 else 10});
    try direct.fetch_once();
    var new = direct.consumer.pop().?;
    try testing.expectEqualStrings("new", new.value);
    const completed = try subject.deliveries.next_completion();
    try testing.expect(completed.canceled);
    try testing.expectEqual(previously_accepted, completed.previously_accepted);
    try subject.handle_delivered(completed);
    // No old outcome may retire subscribers, discard the new response, or schedule
    // another attempt for the replacement.
    try testing.expectEqualSlices(u16, new.subscribers, subject.subscribers.pending(1).?);
    try testing.expect(subject.deliveries.state_mut(1).?.* == .delivering);
    try testing.expectEqual(@as(usize, 0), subject.retry_schedule.items.len);
    try testing.expect(try subject.deliveries.try_next_completion() == null);
    try testing.expectEqual(@as(u32, 2), fetcher.calls());
    const resolved = outcome == .resolved;
    const successes: u64 = @intFromBool(previously_accepted or resolved);
    const unresolved: u64 = @intFromBool(!previously_accepted and outcome == .unresolved);
    try testing.expectEqual(successes, subject.fetch_count(.success));
    try testing.expectEqual(unresolved, subject.fetch_count(.ambiguous));
    // A late subscriber receives the replacement's cached response after its first
    // verdict, without another source fetch.
    try subject.add_fetch(1, &.{20});
    try new.send(complete);
    const replacement = try subject.deliveries.next_completion();
    try testing.expect(!replacement.canceled);
    try subject.handle_delivered(replacement);
    var late = direct.consumer.pop().?;
    try testing.expectEqualStrings("new", late.value);
    try testing.expectEqualSlices(u16, &.{20}, late.subscribers);
    try testing.expectEqual(@as(u32, 2), fetcher.calls());
    try late.send(complete);
    try direct.deliver_next();
    try testing.expect(!subject.subscribers.contains(1));
    try testing.expect(!subject.deliveries.contains(1));
}

test "canceled delivery cannot change reinserted key" {
    const outcomes = [_]Outcome{
        complete,
        .{ .resolved = .partial },
        .unresolved,
        .invalid,
        .ignored,
    };
    for ([_]bool{ false, true }) |previously_accepted| {
        for (outcomes) |outcome| {
            previously_accepted_under_test = previously_accepted;
            outcome_under_test = outcome;
            try run(canceled_delivery_body);
        }
    }
}

var repeat_outcome_under_test: ?Outcome = undefined;

/// commonware `issue_5720_regression`, first part: with no other subscriber keeping the key
/// in flight, a repeat fetch after an accepted, ignored, or dropped verdict starts a second
/// source fetch and is delivered the new response.
fn repeat_after_verdict_body(io: Io) !void {
    const fetcher = try MockFetcher.init();
    defer fetcher.deinit();
    try fetcher.push(1, "old");
    try fetcher.push(1, "new");
    var registry = metrics.Registry.init(testing.allocator);
    defer registry.deinit();
    var direct = try Direct.init(io, &registry, fetcher);
    defer direct.deinit();
    const subject = direct.actor;
    // The first fetch is served the old response, and its delivery to 10 awaits a verdict.
    try subject.add_fetch(1, &.{10});
    try direct.fetch_once();
    var first = direct.consumer.pop().?;

    // The consumer answers, then fetches again before the actor reads the verdict.
    if (repeat_outcome_under_test) |outcome| try first.send(outcome) else first.drop();
    try subject.add_fetch(1, &.{10});

    // The fetch applied the verdict, so it is not reported again and cannot retire the
    // repeat (commonware's pool reports `Aborted` for it instead).
    try testing.expect(try subject.deliveries.try_next_completion() == null);
    try testing.expectEqualSlices(u16, &.{10}, subject.subscribers.pending(1).?);

    // The repeat causes a second source fetch and a second delivery.
    try direct.fetch_once();
    var second = direct.consumer.pop().?;
    defer second.drop();
    try testing.expectEqualStrings("new", second.value);
    try testing.expectEqualSlices(u16, &.{10}, second.subscribers);
    try testing.expectEqual(@as(u32, 2), fetcher.calls());
}

/// commonware `issue_5720_regression`, second part: when a later subscriber keeps the key in
/// flight, the repeat joins it and both are served from the accepted response.
fn repeat_joins_inflight_body(io: Io) !void {
    const fetcher = try MockFetcher.init();
    defer fetcher.deinit();
    try fetcher.push(1, "value");
    var registry = metrics.Registry.init(testing.allocator);
    defer registry.deinit();
    var direct = try Direct.init(io, &registry, fetcher);
    defer direct.deinit();
    const subject = direct.actor;
    try subject.add_fetch(1, &.{10});
    try direct.fetch_once();
    var first = direct.consumer.pop().?;

    // 11 joins while the delivery to 10 is judged. The consumer then accepts that delivery
    // and fetches for 10 again before the actor reads the verdict.
    try subject.add_fetch(1, &.{11});
    try first.send(complete);
    try subject.add_fetch(1, &.{10});

    // The accepted response is redelivered to 11 and then to the repeat for 10, each after
    // the previous verdict is applied, and the source is not asked again.
    for ([_]u16{ 11, 10 }, 0..) |subscriber, index| {
        if (index > 0) try direct.deliver_next();
        var delivery = direct.consumer.pop().?;
        try testing.expectEqualStrings("value", delivery.value);
        try testing.expectEqualSlices(u16, &.{subscriber}, delivery.subscribers);
        try delivery.send(complete);
    }
    try direct.deliver_next();
    try testing.expect(!subject.subscribers.contains(1));
    try testing.expectEqual(@as(u32, 1), fetcher.calls());
}

test "verdict sent before a repeat fetch does not retire it (issue_5720_regression)" {
    for ([_]?Outcome{ complete, .ignored, null }) |outcome| {
        repeat_outcome_under_test = outcome;
        try run(repeat_after_verdict_body);
    }
    try run(repeat_joins_inflight_body);
}

test "missing fetch retries until value is available" {
    try run(struct {
        fn body(io: Io) !void {
            const fetcher = try MockFetcher.init();
            defer fetcher.deinit();
            try fetcher.push(1, null);
            try fetcher.push(1, "value");
            var registry = metrics.Registry.init(testing.allocator);
            defer registry.deinit();
            var harness = try Harness(MockFetcher).start(io, &registry, fetcher);
            try harness.fetch(1, 10);
            // The first attempt finds nothing, so the retry waits for its deadline.
            try sleep_ms(io, 90);
            try testing.expectEqual(@as(u32, 1), fetcher.calls());
            try testing.expectEqual(@as(usize, 0), harness.consumer.len());
            var delivered = try harness.consumer.wait(io);
            try testing.expectEqualStrings("value", delivered.value);
            try delivered.send(complete);
            try testing.expectEqual(@as(u32, 2), fetcher.calls());
            try harness.stop(io);
        }
    }.body);
}

test "unresolved delivery retries without retiring subscribers" {
    try run(struct {
        fn body(io: Io) !void {
            const fetcher = try MockFetcher.init();
            defer fetcher.deinit();
            try fetcher.push(1, "unhelpful");
            try fetcher.push(1, "partial");
            try fetcher.push(1, "complete");
            var registry = metrics.Registry.init(testing.allocator);
            defer registry.deinit();
            var harness = try Harness(MockFetcher).start(io, &registry, fetcher);
            const both: []const resolver.Fetch(u8, u16) = &.{
                .{ .key = 1, .subscriber = 10 },
                .{ .key = 1, .subscriber = 11 },
            };
            try testing.expect((try harness.spawned.resolver.fetch_all(both)).accepted());
            // A valid response that resolves neither subscriber counts as ambiguous.
            var first = try harness.consumer.wait(io);
            try testing.expectEqualStrings("unhelpful", first.value);
            try expect_subscribers(first, &.{ 10, 11 });
            try first.send(.unresolved);
            var second = try harness.consumer.wait(io);
            try testing.expectEqualStrings("partial", second.value);
            try expect_subscribers(second, &.{ 10, 11 });
            try testing.expectEqual(@as(u32, 2), fetcher.calls());
            try testing.expectEqual(@as(u64, 1), harness.count(.ambiguous));
            try testing.expectEqual(@as(u64, 0), harness.count(.success));
            // Resolving one subscriber earns success while the remaining one retries.
            try harness.retain(.init(@as(u16, 10), subscriber_is_not));
            try second.send(.{ .resolved = .partial });
            var third = try harness.consumer.wait(io);
            try testing.expectEqualStrings("complete", third.value);
            try expect_subscribers(third, &.{11});
            try testing.expectEqual(@as(u64, 1), harness.count(.ambiguous));
            try testing.expectEqual(@as(u64, 1), harness.count(.success));
            // A second useful response completes the fetch and adds its own success.
            try third.send(complete);
            try sleep_ms(io, 10);
            try testing.expectEqual(@as(usize, 0), harness.consumer.len());
            try testing.expectEqual(@as(u32, 3), fetcher.calls());
            try testing.expectEqual(@as(u64, 1), harness.count(.ambiguous));
            try testing.expectEqual(@as(u64, 2), harness.count(.success));
            try harness.stop(io);
        }
    }.body);
}

var drop_verdict_under_test: bool = undefined;

/// An ignored or dropped verdict retires the key without a retry or a tombstone.
fn retire_without_retry_body(io: Io) !void {
    const fetcher = try MockFetcher.init();
    defer fetcher.deinit();
    try fetcher.push(1, "obsolete");
    try fetcher.push(1, "fresh");
    var registry = metrics.Registry.init(testing.allocator);
    defer registry.deinit();
    var harness = try Harness(MockFetcher).start(io, &registry, fetcher);
    try harness.fetch(1, 10);
    var first = try harness.consumer.wait(io);
    try testing.expectEqualStrings("obsolete", first.value);
    if (drop_verdict_under_test) first.drop() else try first.send(.ignored);
    try sleep_ms(io, 110);
    try testing.expectEqual(@as(u32, 1), fetcher.calls());
    try testing.expectEqual(@as(usize, 0), harness.consumer.len());
    try testing.expectEqual(@as(u64, 1), harness.count(.dropped));
    // The retired key is not deduplicated against, so a fresh fetch runs.
    try harness.fetch(1, 10);
    var second = try harness.consumer.wait(io);
    try testing.expectEqualStrings("fresh", second.value);
    try second.send(complete);
    try testing.expectEqual(@as(u32, 2), fetcher.calls());
    try harness.stop(io);
}

test "ignored delivery retires without retry" {
    drop_verdict_under_test = false;
    try run(retire_without_retry_body);
}

test "dropped verdict retires without retry" {
    drop_verdict_under_test = true;
    try run(retire_without_retry_body);
}

test "dropped verdict hands response to late subscriber" {
    try run(struct {
        fn body(io: Io) !void {
            const fetcher = try MockFetcher.init();
            defer fetcher.deinit();
            try fetcher.push(1, "unjudged");
            var registry = metrics.Registry.init(testing.allocator);
            defer registry.deinit();
            var harness = try Harness(MockFetcher).start(io, &registry, fetcher);
            try harness.fetch(1, 10);
            var first = try harness.consumer.wait(io);
            try testing.expectEqualStrings("unjudged", first.value);
            // A late subscriber joins while the first delivery is unjudged, then that
            // verdict is dropped: the late subscriber gets the same response, no refetch.
            try harness.fetch(1, 11);
            try sleep_ms(io, 10);
            first.drop();
            var second = try harness.consumer.wait(io);
            try expect_subscribers(second, &.{11});
            try testing.expectEqualStrings("unjudged", second.value);
            try second.send(complete);
            try sleep_ms(io, 110);
            try testing.expectEqual(@as(u32, 1), fetcher.calls());
            try testing.expectEqual(@as(usize, 0), harness.consumer.len());
            try harness.stop(io);
        }
    }.body);
}

test "accepted redelivery rejection does not refetch" {
    try run(struct {
        fn body(io: Io) !void {
            const fetcher = try MockFetcher.init();
            defer fetcher.deinit();
            try fetcher.push(1, "value");
            var registry = metrics.Registry.init(testing.allocator);
            defer registry.deinit();
            var harness = try Harness(MockFetcher).start(io, &registry, fetcher);
            try harness.fetch(1, 10);
            var first = try harness.consumer.wait(io);
            try harness.fetch(1, 11);
            try sleep_ms(io, 10);
            try first.send(complete);
            var second = try harness.consumer.wait(io);
            try second.send(.invalid);
            try sleep_ms(io, 110);
            try testing.expectEqual(@as(u32, 1), fetcher.calls());
            try testing.expectEqual(@as(usize, 0), harness.consumer.len());
            try harness.stop(io);
        }
    }.body);
}

test "retain prunes active fetch subscribers" {
    try run(struct {
        fn body(io: Io) !void {
            var parts = try BlockingFetcher.init(io);
            defer parts.fetcher.deinit();
            defer parts.started.deinit();
            var registry = metrics.Registry.init(testing.allocator);
            defer registry.deinit();
            var harness = try Harness(BlockingFetcher).start(io, &registry, parts.fetcher);
            try harness.fetch(1, 10);
            try harness.fetch(1, 11);
            try parts.started.recv();
            try harness.retain(.init(@as(u16, 11), subscriber_is));
            try sleep_ms(io, 10);
            try parts.response.send("value");
            var delivered = try harness.consumer.wait(io);
            try expect_subscribers(delivered, &.{11});
            try delivered.send(complete);
            try harness.stop(io);
        }
    }.body);
}

test "retain drops last subscriber aborts active fetch" {
    try run(struct {
        fn body(io: Io) !void {
            var parts = try BlockingFetcher.init(io);
            defer parts.fetcher.deinit();
            defer parts.started.deinit();
            var registry = metrics.Registry.init(testing.allocator);
            defer registry.deinit();
            var harness = try Harness(BlockingFetcher).start(io, &registry, parts.fetcher);
            try harness.fetch(1, 10);
            try parts.started.recv();
            try harness.retain(.init({}, keep_none));
            try sleep_ms(io, 10);
            // The fetch was aborted after its last subscriber was pruned.
            try testing.expectError(error.Closed, parts.response.send("value"));
            try sleep_ms(io, 110);
            try testing.expectEqual(@as(usize, 0), harness.consumer.len());
            try harness.stop(io);
        }
    }.body);
}

test "retain drops last subscriber aborts active delivery" {
    try run(struct {
        fn body(io: Io) !void {
            const fetcher = try MockFetcher.init();
            defer fetcher.deinit();
            try fetcher.push(1, "value");
            var registry = metrics.Registry.init(testing.allocator);
            defer registry.deinit();
            var harness = try Harness(MockFetcher).start(io, &registry, fetcher);
            try harness.fetch(1, 10);
            var delivered = try harness.consumer.wait(io);
            try harness.retain(.init({}, keep_none));
            try sleep_ms(io, 10);
            // The delivery was aborted after its last subscriber was pruned.
            try testing.expectError(error.Closed, delivered.send(.invalid));
            try sleep_ms(io, 110);
            try testing.expectEqual(@as(u32, 1), fetcher.calls());
            try testing.expectEqual(@as(usize, 0), harness.consumer.len());
            try harness.stop(io);
        }
    }.body);
}

test "targeted fetch uses same opaque fetch path" {
    try run(struct {
        fn body(io: Io) !void {
            const fetcher = try MockFetcher.init();
            defer fetcher.deinit();
            try fetcher.push(1, "value");
            var registry = metrics.Registry.init(testing.allocator);
            defer registry.deinit();
            var harness = try Harness(MockFetcher).start(io, &registry, fetcher);
            const target: PublicKey = @splat(7);
            const item: resolver.Fetch(u8, u16) = .{ .key = 1, .subscriber = 10 };
            const feedback = try harness.spawned.resolver.fetch_targeted(item, &.{target});
            try testing.expect(feedback.accepted());
            var delivered = try harness.consumer.wait(io);
            try testing.expectEqualStrings("value", delivered.value);
            try delivered.send(complete);
            try testing.expectEqual(@as(u32, 1), fetcher.calls());
            try harness.stop(io);
        }
    }.body);
}

test "stopping with work in flight frees everything" {
    try run(struct {
        fn body(io: Io) !void {
            var parts = try BlockingFetcher.init(io);
            defer parts.fetcher.deinit();
            defer parts.started.deinit();
            defer parts.response.deinit();
            var registry = metrics.Registry.init(testing.allocator);
            defer registry.deinit();
            var harness = try Harness(BlockingFetcher).start(io, &registry, parts.fetcher);
            try harness.fetch(1, 10);
            try harness.fetch(1, 11);
            try parts.started.recv();
            // The leak checker proves the blocked fetch and queued state were freed.
            try harness.stop(io);
        }
    }.body);
}

comptime {
    resolver.assert_targeted_resolver(opaque_resolver.Resolver(u8, u16, PublicKey));
}
