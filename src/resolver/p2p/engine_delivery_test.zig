//! Engine tests that gate or hold the consumer's verdicts (commonware
//! `resolver/src/p2p/mod.rs` tests with `HoldingConsumer`, `BlockingConsumer`, and their
//! subscriber-recording variants), on p2p's simulated network and the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");
const runtime = @import("runtime");
const resolver = @import("../root.zig");
const base = @import("engine_test.zig");
const MockKey = @import("mocks/key.zig").Key;
const Produced = @import("produced.zig").Produced;

const gpa = testing.allocator;
const oneshot = utils.channel.oneshot;
const Duration = utils.Duration;
const Outcome = resolver.Outcome;
const key = base.key;

const complete: Outcome = .{ .resolved = .complete };
const partial: Outcome = .{ .resolved = .partial };

/// A delivery as the consumer saw it: its key and subscribers (owned copies).
fn Seen(comptime S: type) type {
    return struct {
        key: MockKey,
        subscribers: []S,

        fn init(delivery: resolver.Delivery(MockKey, S)) Allocator.Error!@This() {
            assert(delivery.subscribers.len > 0);
            return .{ .key = delivery.key, .subscribers = try gpa.dupe(S, delivery.subscribers) };
        }

        pub fn deinit(seen: *@This()) void {
            gpa.free(seen.subscribers);
            seen.* = undefined;
        }

        /// Checks the key and the subscribers (in delivery order).
        pub fn expect(seen: @This(), value: u8, subscribers: []const S) !void {
            try testing.expectEqual(key(value), seen.key);
            try testing.expectEqualSlices(S, subscribers, seen.subscribers);
        }
    };
}

/// A consumer that hands each delivery, a copy of its value, and its verdict sender to the
/// test, which resolves the verdict without a task yield (commonware `HoldingConsumer` and
/// `HoldingSubscriberConsumer`). Copies share one state; call `deinit` once.
fn Holding(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Key = MockKey;
        pub const Value = []const u8;
        pub const Subscriber = S;
        pub const Outcome = resolver.Outcome;

        pub const Held = struct {
            seen: Seen(S),
            value: []u8,
            verdict: ?oneshot.Sender(resolver.Outcome),

            /// Sends the verdict; a delivery the engine already dropped ignores it.
            pub fn send(held: *Held, outcome: resolver.Outcome) void {
                var verdict = held.verdict.?;
                held.verdict = null;
                verdict.send(outcome) catch {};
            }

            /// Sends the verdict and expects the engine to still wait for it.
            pub fn send_open(held: *Held, outcome: resolver.Outcome) !void {
                var verdict = held.verdict.?;
                held.verdict = null;
                try verdict.send(outcome);
            }

            /// Drops the verdict without a value, as a stopping consumer does.
            pub fn drop(held: *Held) void {
                var verdict = held.verdict.?;
                held.verdict = null;
                verdict.deinit();
            }

            pub fn deinit(held: *Held) void {
                if (held.verdict) |*verdict| verdict.deinit();
                held.seen.deinit();
                gpa.free(held.value);
                held.* = undefined;
            }
        };

        const Shared = struct {
            io: Io,
            mutex: Io.Mutex = .init,
            condition: Io.Condition = .init,
            held: std.ArrayList(Held) = .empty,
        };

        shared: *Shared,

        pub fn init(allocator: Allocator, io: Io) Allocator.Error!Self {
            assert(allocator.ptr == gpa.ptr);
            const shared = try gpa.create(Shared);
            shared.* = .{ .io = io };
            return .{ .shared = shared };
        }

        pub fn deinit(self: Self) void {
            for (self.shared.held.items) |*held| held.deinit();
            self.shared.held.deinit(gpa);
            gpa.destroy(self.shared);
        }

        pub fn deliver(
            self: Self,
            delivery: resolver.Delivery(MockKey, S),
            value: []const u8,
        ) Allocator.Error!oneshot.Receiver(resolver.Outcome) {
            const shared = self.shared;
            var pair = try oneshot.channel(resolver.Outcome, gpa, shared.io);
            errdefer pair.receiver.deinit();
            errdefer pair.sender.deinit();
            var seen = try Seen(S).init(delivery);
            errdefer seen.deinit();
            const copy = try gpa.dupe(u8, value);
            errdefer gpa.free(copy);
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            try shared.held.append(gpa, .{ .seen = seen, .value = copy, .verdict = pair.sender });
            shared.condition.broadcast(shared.io);
            assert(!pair.receiver.is_ready());
            return pair.receiver;
        }

        /// Waits for the next delivery.
        pub fn next(self: Self) Io.Cancelable!Held {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            while (shared.held.items.len == 0) try shared.condition.wait(shared.io, &shared.mutex);
            return shared.held.orderedRemove(0);
        }

        /// The next delivery, if one arrived.
        pub fn try_next(self: Self) ?Held {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            if (shared.held.items.len == 0) return null;
            return shared.held.orderedRemove(0);
        }
    };
}

/// A consumer whose deliveries wait on test-controlled gates (commonware `BlockingConsumer`
/// and `BlockingSubscriberRecordingConsumer`). Each delivery reports that it started, then
/// takes the next gate added with `gate`; a delivery without a gate resolves complete at once.
/// `open` releases a gate with its outcome, `drop` (a dropped gate sender) answers invalid, and
/// a delivery the engine stopped waiting for answers nothing. Complete deliveries are recorded
/// as events. The test drives the gates in place of commonware's per-delivery task, so a gate
/// resolves on the test's task instead of one yield later.
fn Blocking(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Key = MockKey;
        pub const Value = []const u8;
        pub const Subscriber = S;
        pub const Outcome = resolver.Outcome;

        pub const Event = struct {
            seen: Seen(S),
            value: []u8,

            pub fn deinit(event: *Event) void {
                event.seen.deinit();
                gpa.free(event.value);
                event.* = undefined;
            }
        };

        const Gate = struct {
            outcome: resolver.Outcome,
            state: enum { waiting, opened, dropped } = .waiting,
            /// The delivery that took this gate, until the gate resolves it.
            response: ?oneshot.Sender(resolver.Outcome) = null,
            event: ?Event = null,
            taken: bool = false,
        };

        const Shared = struct {
            io: Io,
            mutex: Io.Mutex = .init,
            condition: Io.Condition = .init,
            gates: std.ArrayList(Gate) = .empty,
            gates_taken: usize = 0,
            started: std.ArrayList(Seen(S)) = .empty,
            events: std.ArrayList(Event) = .empty,
        };

        shared: *Shared,

        pub fn init(allocator: Allocator, io: Io) Allocator.Error!Self {
            assert(allocator.ptr == gpa.ptr);
            const shared = try gpa.create(Shared);
            shared.* = .{ .io = io };
            return .{ .shared = shared };
        }

        pub fn deinit(self: Self) void {
            const shared = self.shared;
            for (shared.gates.items) |*item| {
                if (item.response) |*response| response.deinit();
                if (item.event) |*event| event.deinit();
            }
            shared.gates.deinit(gpa);
            for (shared.started.items) |*seen| seen.deinit();
            shared.started.deinit(gpa);
            for (shared.events.items) |*event| event.deinit();
            shared.events.deinit(gpa);
            gpa.destroy(shared);
        }

        /// Adds a gate for the next ungated delivery; returns its index.
        pub fn gate(self: Self, outcome: resolver.Outcome) Allocator.Error!usize {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            try shared.gates.append(gpa, .{ .outcome = outcome });
            return shared.gates.items.len - 1;
        }

        pub fn deliver(
            self: Self,
            delivery: resolver.Delivery(MockKey, S),
            value: []const u8,
        ) Allocator.Error!oneshot.Receiver(resolver.Outcome) {
            const shared = self.shared;
            var pair = try oneshot.channel(resolver.Outcome, gpa, shared.io);
            errdefer pair.receiver.deinit();
            errdefer pair.sender.deinit();
            var started = try Seen(S).init(delivery);
            errdefer started.deinit();
            var pending: Event = .{ .seen = try .init(delivery), .value = undefined };
            errdefer pending.seen.deinit();
            pending.value = try gpa.dupe(u8, value);
            errdefer gpa.free(pending.value);
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            try shared.started.ensureUnusedCapacity(gpa, 1);
            try shared.events.ensureUnusedCapacity(gpa, 1);
            shared.started.appendAssumeCapacity(started);
            shared.condition.broadcast(shared.io);
            if (shared.gates_taken == shared.gates.items.len) {
                shared.events.appendAssumeCapacity(pending);
                pair.sender.send(complete) catch unreachable; // Proof: the receiver is open.
                return pair.receiver;
            }
            const taken = &shared.gates.items[shared.gates_taken];
            shared.gates_taken += 1;
            assert(!taken.taken);
            taken.taken = true;
            taken.response = pair.sender;
            taken.event = pending;
            resolve_locked(shared, taken);
            return pair.receiver;
        }

        /// Answers a taken gate once it is opened or dropped. Capacity for its event is
        /// reserved by `deliver`.
        fn resolve_locked(shared: *Shared, item: *Gate) void {
            if (item.state == .waiting) return;
            var response = item.response orelse return;
            var event = item.event.?;
            item.response = null;
            item.event = null;
            if (response.is_closed()) {
                response.deinit();
                event.deinit();
                return;
            }
            const dropped = item.state == .dropped;
            const outcome: resolver.Outcome = if (dropped) .invalid else item.outcome;
            if (outcome.eql(complete)) {
                shared.events.appendAssumeCapacity(event);
                shared.condition.broadcast(shared.io);
            } else {
                event.deinit();
            }
            // A receiver closed since the check refuses the outcome, as commonware's late send.
            response.send(outcome) catch {};
        }

        /// Releases gate `index` (commonware `gate_sender.send(())`).
        pub fn open(self: Self, index: usize) void {
            self.set(index, .opened);
        }

        /// Drops gate `index`'s sender: its delivery answers invalid.
        pub fn drop(self: Self, index: usize) void {
            self.set(index, .dropped);
        }

        fn set(self: Self, index: usize, state: @FieldType(Gate, "state")) void {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            const item = &shared.gates.items[index];
            assert(item.state == .waiting);
            item.state = state;
            resolve_locked(shared, item);
        }

        /// Waits until gate `index`'s delivery stops waiting for an answer (commonware
        /// `gate_sender.closed()`): the engine dropped it, or the gate resolved it.
        pub fn closed(self: Self, index: usize) Io.Cancelable!void {
            const shared = self.shared;
            const response = blk: {
                shared.mutex.lockUncancelable(shared.io);
                defer shared.mutex.unlock(shared.io);
                const items = &shared.gates.items;
                while (!items.*[index].taken) try shared.condition.wait(shared.io, &shared.mutex);
                break :blk items.*[index].response orelse return;
            };
            // The gate is waiting, so only this test task could resolve the sender.
            try response.closed();
        }

        /// Waits for the next delivery to start.
        pub fn next_started(self: Self) Io.Cancelable!Seen(S) {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            const started = &shared.started;
            while (started.items.len == 0) try shared.condition.wait(shared.io, &shared.mutex);
            return started.orderedRemove(0);
        }

        /// Waits for the next complete delivery.
        pub fn next_event(self: Self) Io.Cancelable!Event {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            const events = &shared.events;
            while (events.items.len == 0) try shared.condition.wait(shared.io, &shared.mutex);
            return events.orderedRemove(0);
        }

        /// The next complete delivery, if one was recorded.
        pub fn try_event(self: Self) ?Event {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            if (shared.events.items.len == 0) return null;
            return shared.events.orderedRemove(0);
        }
    };
}

/// A producer that serves each key's values in insertion order, one per request (commonware
/// `SequencedProducer`). Copies share one state; call `deinit` once.
const Sequenced = struct {
    pub const Key = MockKey;

    const Entry = struct { key: MockKey, value: []u8 };
    const Shared = struct {
        io: Io,
        mutex: Io.Mutex = .init,
        /// Values not served yet, oldest first.
        entries: std.ArrayList(Entry) = .empty,
    };

    shared: *Shared,

    pub fn init(allocator: Allocator, io: Io) Allocator.Error!Sequenced {
        assert(allocator.ptr == gpa.ptr);
        const shared = try gpa.create(Shared);
        shared.* = .{ .io = io };
        return .{ .shared = shared };
    }

    pub fn deinit(self: Sequenced) void {
        for (self.shared.entries.items) |entry| gpa.free(entry.value);
        self.shared.entries.deinit(gpa);
        gpa.destroy(self.shared);
    }

    /// Queues `value` (copied) after the values already queued for `item`.
    pub fn insert(self: Sequenced, item: MockKey, value: []const u8) Allocator.Error!void {
        const shared = self.shared;
        const copy = try gpa.dupe(u8, value);
        errdefer gpa.free(copy);
        shared.mutex.lockUncancelable(shared.io);
        defer shared.mutex.unlock(shared.io);
        try shared.entries.append(gpa, .{ .key = item, .value = copy });
    }

    pub fn produce(self: Sequenced, item: MockKey) Allocator.Error!oneshot.Receiver(Produced) {
        const shared = self.shared;
        var pair = try oneshot.channel(Produced, gpa, shared.io);
        shared.mutex.lockUncancelable(shared.io);
        defer shared.mutex.unlock(shared.io);
        for (shared.entries.items, 0..) |entry, index| {
            if (!resolver.eql(MockKey, entry.key, item)) continue;
            _ = shared.entries.orderedRemove(index);
            // Proof: the receiver is open, so the send cannot be refused.
            pair.sender.send(.{ .bytes = entry.value, .gpa = gpa }) catch unreachable;
            return pair.receiver;
        }
        pair.sender.deinit();
        return pair.receiver;
    }

    /// Checks the values still queued for `item`.
    pub fn expect_remaining(self: Sequenced, item: MockKey, values: []const []const u8) !void {
        const shared = self.shared;
        shared.mutex.lockUncancelable(shared.io);
        defer shared.mutex.unlock(shared.io);
        var count: usize = 0;
        for (shared.entries.items) |entry| {
            if (!resolver.eql(MockKey, entry.key, item)) continue;
            try testing.expect(count < values.len);
            try testing.expectEqualStrings(values[count], entry.value);
            count += 1;
        }
        try testing.expectEqual(values.len, count);
    }
};

const HoldingSetup = base.SetupWith(Holding(void));
const HoldingTagged = base.SetupWith(Holding(u16));
const BlockingSetup = base.SetupWith(Blocking(void));
const BlockingTagged = base.SetupOf(Blocking(u16), Sequenced);

/// The sum of every encoded sample named `name`.
fn metric_total(setup: anytype, name: []const u8) !u64 {
    const text = try setup.encode();
    defer gpa.free(text);
    var samples = runtime.telemetry.metrics.metric_samples(text, name);
    var total: u64 = 0;
    while (samples.next()) |sample| total += try std.fmt.parseInt(u64, sample.value, 10);
    return total;
}

/// Accepted network responses credited to a serving peer (commonware `peer_resolve_count`).
fn resolves(setup: anytype) !u64 {
    return metric_total(setup, "actor_fetcher_resolves_count");
}

/// The first exported peer weight (commonware `peer_weight`).
fn weight(setup: anytype) !u64 {
    const text = try setup.encode();
    defer gpa.free(text);
    var samples = runtime.telemetry.metrics.metric_samples(text, "actor_fetcher_peer_performance");
    const sample = samples.next() orelse return error.MissingPeerWeight;
    return std.fmt.parseInt(u64, sample.value, 10);
}

fn status(setup: anytype, label: []const u8) !u64 {
    const text = try setup.encode();
    defer gpa.free(text);
    return base.status_total(text, "actor_fetch_total", label);
}

fn blocked_count(setup: anytype) !usize {
    const pairs = try setup.oracle().blocked(gpa);
    defer gpa.free(pairs);
    return pairs.len;
}

/// Polls each simulated millisecond until `count` responses are credited.
fn wait_resolves(setup: anytype, count: u64) !void {
    for (0..10_000) |_| {
        if (try resolves(setup) == count) return;
        try setup.sleep(Duration.from_millis(1));
    }
    return error.ResolvesNotReached;
}

fn fetch_as(mailbox: anytype, value: u8, subscriber: u16) !void {
    _ = try mailbox.fetch(.{ .key = key(value), .subscriber = subscriber });
}

fn fetch_all_as(mailbox: anytype, value: u8, subscribers: []const u16) !void {
    var items: [8]resolver.Fetch(MockKey, u16) = undefined;
    for (subscribers, 0..) |subscriber, index| {
        items[index] = .{ .key = key(value), .subscriber = subscriber };
    }
    _ = try mailbox.fetch_all(items[0..subscribers.len]);
}

fn retain_none(mailbox: anytype, comptime S: type) !void {
    const predicate = resolver.Predicate(MockKey, S).init({}, struct {
        fn keep(_: void, _: MockKey, _: S) bool {
            return false;
        }
    }.keep);
    _ = try mailbox.retain(predicate);
}

test "fetch after accepted verdict restarts" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try HoldingSetup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            const consumer = try setup.make_consumer();
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 2, "data for key 2" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            try base.fetch(mailbox, 2);
            var first = try consumer.next();
            defer first.deinit();
            try first.seen.expect(2, &.{{}});
            // Accept the response and re-fetch the key before yielding: both the completion
            // and the fetch are pending when the engine next runs, and it must settle the
            // completion first so the re-fetch starts fresh instead of being deduplicated
            // against the completing key and dropped with it (the runner's timeout fails a
            // dropped re-fetch).
            first.send(complete);
            try base.fetch(mailbox, 2);
            var second = try consumer.next();
            defer second.deinit();
            try second.seen.expect(2, &.{{}});
            second.send(complete);
        }
    }.body);
}

const Captured = struct { held: *Holding(u16).Held, outcome: Outcome };

/// Submits the held verdict from inside the retain predicate, after the engine selected the
/// retain, so cancellation removes the entry before it can poll the verdict.
fn retain_submitting(mailbox: anytype, held: *Holding(u16).Held, outcome: Outcome) !void {
    const predicate = resolver.Predicate(MockKey, u16).init(Captured{
        .held = held,
        .outcome = outcome,
    }, struct {
        fn keep(captured: Captured, _: MockKey, _: u16) bool {
            if (captured.held.verdict != null) {
                captured.held.send_open(captured.outcome) catch unreachable; // Proof: held.
            }
            return false;
        }
    }.keep);
    _ = try mailbox.retain(predicate);
}

fn cancellation_case(io: Io, previously_accepted: bool, outcome: Outcome) !void {
    const setup = try HoldingTagged.init(io, &.{ 1, 2 }, .{});
    defer setup.deinit();
    try setup.add_link(base.link, 0, 1);
    // Hold the first response's verdict while the resolver waits for work.
    const consumer = try setup.make_consumer();
    const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const producer = try setup.make_producer(&.{.{ 2, "data for key 2" }});
    _ = try setup.spawn(1, try setup.make_consumer(), producer);
    try fetch_all_as(mailbox, 2, &.{ 1, 2 });
    var held = try consumer.next();
    defer held.deinit();
    try held.seen.expect(2, &.{ 1, 2 });
    try testing.expectEqual(0, try resolves(setup));

    // An accepted response can be judged again by a late subscriber, but that local verdict
    // must never earn another source observation.
    if (previously_accepted) {
        try fetch_all_as(mailbox, 2, &.{ 3, 4 });
        try setup.sleep(Duration.from_millis(10));
        try held.send_open(complete);
        const next = try consumer.next();
        held.deinit();
        held = next;
        try held.seen.expect(2, &.{ 3, 4 });
        try testing.expectEqual(1, try resolves(setup));
    }
    try retain_submitting(mailbox, &held, outcome);

    // An invalid first verdict still blocks its source after the fetch is canceled; an
    // accepted response's redelivery must not block it.
    if (!previously_accepted and outcome.eql(.invalid)) {
        try setup.wait_for_blocked(0, 1);
        try testing.expectEqual(1, try blocked_count(setup));
        try testing.expectEqual(0, try resolves(setup));
        try testing.expectEqual(1, try status(setup, "Failure"));
        return;
    }
    try fetch_as(mailbox, 2, 1);

    // Cancellation permits a fresh fetch. The first response retains its credit, and the
    // replacement earns none until its own verdict.
    var replacement = try consumer.next();
    defer replacement.deinit();
    try testing.expectEqual(key(2), replacement.seen.key);
    const successes: u64 = @intFromBool(previously_accepted or outcome == .resolved);
    try testing.expectEqual(successes, try resolves(setup));
    try testing.expectEqual(0, try blocked_count(setup));
    try replacement.send_open(complete);
    try wait_resolves(setup, successes + 1);
    try testing.expectEqual(successes + 1, try status(setup, "Success"));
    const ambiguous = !previously_accepted and outcome.eql(.unresolved);
    try testing.expectEqual(@intFromBool(ambiguous), try status(setup, "Ambiguous"));
}

test "cancellation preserves submitted verdict" {
    const outcomes = [_]Outcome{ complete, partial, .unresolved, .invalid, .ignored };
    for ([_]bool{ false, true }) |previously_accepted| {
        for (outcomes) |outcome| {
            var runner = try runtime.deterministic.Runner.init(gpa, .{
                .timeout_ns = 10 * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start(cancellation_case, .{ runner.io(), previously_accepted, outcome });
        }
    }
}

test "pending delivery does not block engine" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try BlockingSetup.init(io, &.{ 1, 2, 3 }, .{});
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            try setup.add_link(base.link, 0, 2);
            const consumer = try setup.make_consumer();
            const gate1 = try consumer.gate(complete);
            const gate2 = try consumer.gate(complete);
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            const prod3 = try setup.make_producer(&.{.{ 2, "data for key 2" }});
            _ = try setup.spawn(2, try setup.make_consumer(), prod3);

            try base.fetch(mailbox, 1);
            var started1 = try consumer.next_started();
            defer started1.deinit();
            try started1.expect(1, &.{{}});
            // The second delivery starts while the first still waits for its verdict.
            try base.fetch(mailbox, 2);
            var started2 = try consumer.next_started();
            defer started2.deinit();
            try started2.expect(2, &.{{}});

            consumer.open(gate2);
            var event2 = try consumer.next_event();
            defer event2.deinit();
            try event2.seen.expect(2, &.{{}});
            try testing.expectEqualStrings("data for key 2", event2.value);
            consumer.open(gate1);
            var event1 = try consumer.next_event();
            defer event1.deinit();
            try event1.seen.expect(1, &.{{}});
            try testing.expectEqualStrings("data for key 1", event1.value);
        }
    }.body);
}

test "retain drops pending delivery" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try BlockingSetup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            const consumer = try setup.make_consumer();
            const first_gate = try consumer.gate(complete);
            const second_gate = try consumer.gate(complete);
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            try base.fetch(mailbox, 1);
            var started = try consumer.next_started();
            started.deinit();
            try base.retain_except(mailbox, 1);
            try base.fetch(mailbox, 1);
            // The retain dropped the first delivery's verdict wait.
            try consumer.closed(first_gate);
            started = try consumer.next_started();
            defer started.deinit();
            try started.expect(1, &.{{}});
            consumer.open(second_gate);
            var event = try consumer.next_event();
            defer event.deinit();
            try event.seen.expect(1, &.{{}});
            try testing.expectEqualStrings("data for key 1", event.value);
            try setup.sleep(Duration.from_millis(100));
            try testing.expect(consumer.try_event() == null);
        }
    }.body);
}
