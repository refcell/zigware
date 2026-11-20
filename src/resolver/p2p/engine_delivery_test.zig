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
const actor = @import("actor");
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
            const Case = struct { previously_accepted: bool, outcome: Outcome };
            const config: runtime.deterministic.Config = .{ .timeout_ns = 10 * std.time.ns_per_s };
            const case: Case = .{ .previously_accepted = previously_accepted, .outcome = outcome };
            try runtime.deterministic.soak(gpa, config, case, struct {
                fn round(c: Case, runner: *runtime.deterministic.Runner) anyerror!void {
                    const args = .{ runner.io(), c.previously_accepted, c.outcome };
                    try try runner.start(cancellation_case, args);
                }
            }.round);
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

test "larger responses earn more throughput credit" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try base.Setup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            // Fix network latency to isolate the effect of payload size on the peer's weight.
            var steady = base.link;
            steady.jitter = Duration.from_millis(0);
            try setup.add_link(steady, 0, 1);
            const small = [_]u8{1};
            const large: [1024]u8 = @splat(2);
            const consumer = try setup.make_consumer();
            try consumer.add_expected(key(1), &small);
            try consumer.add_expected(key(2), &large);
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const producer = try setup.make_producer(&.{ .{ 1, &small }, .{ 2, &large } });
            _ = try setup.spawn(1, try setup.make_consumer(), producer);

            // Fetch in size order so the first weight is the small-response baseline.
            var weights: [2]u64 = undefined;
            const values = [_][]const u8{ &small, &large };
            for (values, 0..) |value, index| {
                try base.fetch(mailbox, @intCast(index + 1));
                try base.expect_event(consumer, @intCast(index + 1), value);
                // Delivery starts before its verdict is processed. Read the weight only
                // after the engine has credited the accepted network response.
                try wait_resolves(setup, index + 1);
                weights[index] = try weight(setup);
            }
            // Averaging with the small response reduces the gain, but the larger payload
            // must still produce a much higher weight at the same latency.
            try testing.expect(weights[1] > weights[0] * 100);
        }
    }.body);
}

test "invalid delivery retries and rearms slot" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try BlockingSetup.init(io, &.{ 1, 2, 3 }, .{});
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            const consumer = try setup.make_consumer();
            const first_gate = try consumer.gate(.invalid);
            const second_gate = try consumer.gate(complete);
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const data = "data for key 1";
            _ = try setup.spawn(1, try setup.make_consumer(), try setup.make_producer(&.{
                .{ 1, data },
            }));
            _ = try setup.spawn(2, try setup.make_consumer(), try setup.make_producer(&.{
                .{ 1, data },
            }));

            var targets = [_]base.PublicKey{ setup.peers[1], setup.peers[2] };
            _ = try mailbox.fetch_targeted(.{ .key = key(1), .subscriber = {} }, &targets);
            var started = try consumer.next_started();
            started.deinit();
            consumer.open(first_gate);
            try setup.wait_for_blocked(0, 1);
            try testing.expectEqual(0, try resolves(setup));

            // The invalid response blocks its source and rearms the fetch for the other target.
            try setup.add_link(base.link, 0, 2);
            try setup.track_roles(1, &.{ 0, 2 }, &.{});
            started = try consumer.next_started();
            defer started.deinit();
            try started.expect(1, &.{{}});
            consumer.open(second_gate);
            var event = try consumer.next_event();
            defer event.deinit();
            try event.seen.expect(1, &.{{}});
            try testing.expectEqualStrings(data, event.value);
        }
    }.body);
}

fn retain_except_subscriber(mailbox: anytype, dropped: u16) !void {
    const predicate = resolver.Predicate(MockKey, u16).init(dropped, struct {
        fn keep(excluded: u16, _: MockKey, subscriber: u16) bool {
            return subscriber != excluded;
        }
    }.keep);
    _ = try mailbox.retain(predicate);
}

/// Checks the next held delivery's key, subscribers, and value; the caller owns the result.
fn expect_held(
    consumer: Holding(u16),
    value: u8,
    subscribers: []const u16,
    data: []const u8,
) !Holding(u16).Held {
    var held = try consumer.next();
    errdefer held.deinit();
    try held.seen.expect(value, subscribers);
    try testing.expectEqualStrings(data, held.value);
    return held;
}

fn credits_only_useful(io: Io) !void {
    const setup = try HoldingTagged.init(io, &.{ 1, 2 }, .{});
    defer setup.deinit();
    var steady = base.link;
    steady.jitter = Duration.from_millis(0);
    try setup.add_link(steady, 0, 1);
    const data: [1024]u8 = @splat(1);
    const consumer = try setup.make_consumer();
    const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const producer = try setup.make_producer(&.{ .{ 0, &.{0} }, .{ 1, &data } });
    _ = try setup.spawn(1, try setup.make_consumer(), producer);

    // Establish a weight above the minimum so both rewards and penalties are visible.
    try fetch_as(mailbox, 0, 0);
    var warmup = try expect_held(consumer, 0, &.{0}, &.{0});
    defer warmup.deinit();
    try warmup.send_open(complete);
    try wait_resolves(setup, 1);
    const original_weight = try weight(setup);
    try testing.expect(original_weight > 1);

    try fetch_all_as(mailbox, 1, &.{ 1, 2 });
    var first = try expect_held(consumer, 1, &.{ 1, 2 }, &data);
    defer first.deinit();
    try first.send_open(.unresolved);
    // A new network delivery proves the neutral verdict was processed and retried.
    var second = try expect_held(consumer, 1, &.{ 1, 2 }, &data);
    defer second.deinit();
    try testing.expectEqual(1, try resolves(setup));
    try testing.expectEqual(original_weight, try weight(setup));
    try testing.expectEqual(1, try status(setup, "Success"));
    try testing.expectEqual(1, try status(setup, "Ambiguous"));

    // Only one subscriber is satisfied. The other still needs another response.
    try retain_except_subscriber(mailbox, 1);
    try second.send_open(partial);
    var third = try expect_held(consumer, 1, &.{2}, &data);
    defer third.deinit();
    try testing.expectEqual(2, try resolves(setup));
    try testing.expect(try weight(setup) > original_weight);
    try testing.expectEqual(2, try status(setup, "Success"));
    try testing.expectEqual(1, try status(setup, "Ambiguous"));

    try third.send_open(complete);
    try wait_resolves(setup, 3);
    try testing.expectEqual(0, try blocked_count(setup));
    try testing.expectEqual(3, try status(setup, "Success"));
    try testing.expectEqual(1, try status(setup, "Ambiguous"));
}

test "delivery credits only useful responses" {
    try base.run(10, credits_only_useful);
}

test "dropped verdict retires fetch without blocking peer" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try HoldingSetup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            const consumer = try setup.make_consumer();
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            try base.fetch(mailbox, 1);
            var held = try consumer.next();
            defer held.deinit();
            try held.seen.expect(1, &.{{}});
            // Drop the verdict, as a consumer does when it stops with the delivery still
            // queued. No one is waiting on the key, so the fetch is retired rather than
            // retried, and the peer stays unblocked because nothing is known about what it
            // served.
            held.drop();
            try setup.sleep(Duration.from_secs(1));
            try testing.expect(consumer.try_next() == null);
            try testing.expectEqual(0, try blocked_count(setup));
            try testing.expectEqual(0, try resolves(setup));

            // The retired key is not deduplicated against, so a fresh fetch runs.
            try base.fetch(mailbox, 1);
            var fresh = try consumer.next();
            defer fresh.deinit();
            try fresh.seen.expect(1, &.{{}});
            fresh.send(complete);
            try testing.expectEqual(1, try status(setup, "Dropped"));
        }
    }.body);
}

test "dropped verdict hands response to late subscriber" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try HoldingTagged.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            const data = "data for key 1";
            const consumer = try setup.make_consumer();
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            _ = try setup.spawn(1, try setup.make_consumer(), try setup.make_producer(&.{
                .{ 1, data },
            }));

            try fetch_as(mailbox, 1, 1);
            var first = try expect_held(consumer, 1, &.{1}, data);
            defer first.deinit();
            // A late subscriber joins while the first delivery is unjudged, then that
            // delivery's verdict is dropped. The late subscriber is handed the same response
            // to judge instead of the key being retired.
            try fetch_as(mailbox, 1, 2);
            try setup.sleep(Duration.from_millis(100));
            first.drop();
            var late = try expect_held(consumer, 1, &.{2}, data);
            defer late.deinit();
            try testing.expectEqual(0, try resolves(setup));
            late.send(complete);
            try setup.sleep(Duration.from_millis(100));
            try testing.expectEqual(0, try blocked_count(setup));
            try testing.expectEqual(1, try resolves(setup));
            try testing.expectEqual(1, try status(setup, "Success"));
            try testing.expectEqual(0, try status(setup, "Dropped"));
        }
    }.body);
}

fn ignored_retires_late(io: Io) !void {
    const setup = try BlockingTagged.init(io, &.{ 1, 2 }, .{});
    defer setup.deinit();
    try setup.add_link(base.link, 0, 1);
    const consumer = try setup.make_consumer();
    const ignored_gate = try consumer.gate(.ignored);
    const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const producer = try setup.make_producer(&.{
        .{ 1, "obsolete response" },
        .{ 1, "fresh response" },
    });
    _ = try setup.spawn(1, try setup.make_consumer(), producer);

    try fetch_as(mailbox, 1, 1);
    var started = try consumer.next_started();
    try started.expect(1, &.{1});
    started.deinit();
    // A subscriber attached after the delivery snapshot is still retired by the key-global
    // ignored outcome.
    try fetch_as(mailbox, 1, 2);
    try setup.sleep(Duration.from_millis(100));
    try producer.expect_remaining(key(1), &.{"fresh response"});
    consumer.open(ignored_gate);
    try setup.sleep(base.fetch_retry_delay.saturating_add(Duration.from_millis(100)));
    try producer.expect_remaining(key(1), &.{"fresh response"});
    try testing.expectEqual(0, try blocked_count(setup));
    try testing.expectEqual(1, try status(setup, "Dropped"));
    try testing.expectEqual(0, try resolves(setup));

    // A new request for the same key starts cleanly after the ignored fetch is retired.
    try fetch_as(mailbox, 1, 3);
    started = try consumer.next_started();
    defer started.deinit();
    try started.expect(1, &.{3});
    var event = try consumer.next_event();
    defer event.deinit();
    try event.seen.expect(1, &.{3});
    try testing.expectEqualStrings("fresh response", event.value);
    try producer.expect_remaining(key(1), &.{});
}

test "ignored delivery retires late subscribers without rating or retry" {
    try base.run(10, ignored_retires_late);
}

fn pending_invalid_race(io: Io, validation_first: bool) !void {
    const setup = try BlockingSetup.init(io, &.{ 1, 2 }, .{});
    defer setup.deinit();
    try setup.add_link(base.link, 0, 1);
    const consumer = try setup.make_consumer();
    const invalid_gate = try consumer.gate(.invalid);
    const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
    _ = try setup.spawn(1, try setup.make_consumer(), prod2);

    try base.fetch(mailbox, 1);
    var started = try consumer.next_started();
    defer started.deinit();
    try started.expect(1, &.{{}});
    if (validation_first) {
        // A verdict judged before the retain still blocks its source.
        consumer.open(invalid_gate);
        try setup.wait_for_blocked(0, 1);
        try retain_none(mailbox, void);
        const pairs = try setup.oracle().blocked(gpa);
        defer gpa.free(pairs);
        try testing.expectEqual(1, pairs.len);
        try testing.expect(pairs[0].origin.order(setup.peers[0]) == .eq);
        try testing.expect(pairs[0].recipient.order(setup.peers[1]) == .eq);
    } else {
        // A retain before the verdict drops it: nothing is known about the source.
        try retain_none(mailbox, void);
        try consumer.closed(invalid_gate);
        try testing.expectEqual(0, try blocked_count(setup));
    }
    try setup.sleep(Duration.from_millis(100));
    try testing.expect(consumer.try_event() == null);
    try testing.expectEqual(0, try resolves(setup));
}

test "retain pending invalid delivery race" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            try pending_invalid_race(io, false);
            try pending_invalid_race(io, true);
        }
    }.body);
}

/// A blocker whose blocked-set subscription is already closed (commonware `ClosedBlocker`).
const ClosedBlocker = struct {
    const Subscription = struct {
        pub fn recv(_: *Subscription, _: Allocator) Allocator.Error!?[]base.PublicKey {
            return null;
        }
    };

    pub fn block(_: ClosedBlocker, _: base.PublicKey) resolver.Feedback {
        return .ok;
    }

    pub fn blocked(_: ClosedBlocker) Allocator.Error!Subscription {
        return .{};
    }
};

test "closed blocked subscription keeps fetching" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const ClosedSetup = base.SetupFull(base.Consumer, base.Producer, ClosedBlocker);
            const setup = try ClosedSetup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            const consumer = try setup.make_consumer();
            // The engine keeps serving fetches when the blocked-set stream ends.
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            // The serving peer's engine uses the closed blocker as well; it never blocks.
            const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);
            try base.fetch(mailbox, 1);
            try base.expect_event(consumer, 1, "data for key 1");
        }
    }.body);
}

test "unblocked peer becomes eligible again" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try BlockingSetup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            // The first response is judged invalid, the second one is accepted.
            const consumer = try setup.make_consumer();
            const first_gate = try consumer.gate(.invalid);
            const second_gate = try consumer.gate(complete);
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            var target = [_]base.PublicKey{setup.peers[1]};
            _ = try mailbox.fetch_targeted(.{ .key = key(1), .subscriber = {} }, &target);
            var started = try consumer.next_started();
            try started.expect(1, &.{{}});
            started.deinit();
            consumer.open(first_gate);
            try setup.wait_for_blocked(0, 1);
            // The only target is blocked, so the fetch waits.
            try setup.sleep(Duration.from_secs(1));
            {
                const shared = consumer.shared;
                shared.mutex.lockUncancelable(io);
                defer shared.mutex.unlock(io);
                try testing.expectEqual(0, shared.started.items.len);
            }
            // Once the network lifts the block, the same target is tried again.
            try setup.oracle().unblock(setup.peers[0], setup.peers[1]);
            started = try consumer.next_started();
            defer started.deinit();
            try started.expect(1, &.{{}});
            consumer.open(second_gate);
            var event = try consumer.next_event();
            defer event.deinit();
            try event.seen.expect(1, &.{{}});
            try testing.expectEqualStrings("data for key 1", event.value);
        }
    }.body);
}

const HoldingSequenced = base.SetupOf(Holding(u16), Sequenced);

fn validation_case(io: Io, outcome: Outcome) !void {
    const first_response = "data for key 5";
    const second_response = "refetched data for key 5";
    const setup = try HoldingSequenced.init(io, &.{ 1, 2 }, .{});
    defer setup.deinit();
    try setup.add_link(base.link, 0, 1);
    const consumer = try setup.make_consumer();
    const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const producer = try setup.make_producer(&.{ .{ 5, first_response }, .{ 5, second_response } });
    _ = try setup.spawn(1, try setup.make_consumer(), producer);

    // Late subscribers join while the first delivery is still being judged.
    try fetch_as(mailbox, 5, 49);
    var first = try expect_held(consumer, 5, &.{49}, first_response);
    defer first.deinit();
    try fetch_all_as(mailbox, 5, &.{ 50, 51 });
    try setup.sleep(Duration.from_millis(100));
    try producer.expect_remaining(key(5), &.{second_response});
    try first.send_open(complete);
    // The same response serves the late snapshot without another network fetch.
    var late = try expect_held(consumer, 5, &.{ 50, 51 }, first_response);
    defer late.deinit();
    try testing.expectEqual(1, try resolves(setup));
    try testing.expectEqual(1, try status(setup, "Success"));

    // Local redelivery must not add another outcome for the accepted response, whether it
    // satisfies all, some, or none of the late subscribers.
    if (outcome.eql(partial)) try retain_except_subscriber(mailbox, 50);
    try late.send_open(outcome);
    var expected_successes: u64 = 1;
    if (outcome.eql(complete)) {
        try setup.sleep(Duration.from_millis(100));
        try producer.expect_remaining(key(5), &.{second_response});
    } else {
        // A new response proves the unresolved redelivery was processed. Only accepting these
        // new bytes may add a second success and peer reward.
        const remaining: []const u16 = if (outcome.eql(partial)) &.{51} else &.{ 50, 51 };
        var refetched = try expect_held(consumer, 5, remaining, second_response);
        defer refetched.deinit();
        try producer.expect_remaining(key(5), &.{});
        try testing.expectEqual(1, try resolves(setup));
        try testing.expectEqual(1, try status(setup, "Success"));
        try testing.expectEqual(0, try status(setup, "Ambiguous"));
        try refetched.send_open(complete);
        expected_successes = 2;
    }
    try wait_resolves(setup, expected_successes);
    try testing.expectEqual(expected_successes, try status(setup, "Success"));
    try testing.expectEqual(0, try status(setup, "Ambiguous"));
}

test "fetch during validation reuses response after success" {
    for ([_]Outcome{ complete, partial, .unresolved }) |outcome| {
        const config: runtime.deterministic.Config = .{ .timeout_ns = 10 * std.time.ns_per_s };
        try runtime.deterministic.soak(gpa, config, outcome, struct {
            fn round(o: Outcome, runner: *runtime.deterministic.Runner) anyerror!void {
                try try runner.start(validation_case, .{ runner.io(), o });
            }
        }.round);
    }
}

fn late_targeted_joins_retry(io: Io) !void {
    const unresolved_response = "unresolved data for key 5";
    const unexpected_refetch = "unexpected refetch for key 5";
    const valid_response = "valid data for key 5";
    const setup = try BlockingTagged.init(io, &.{ 1, 2, 3 }, .{});
    defer setup.deinit();
    try setup.add_link(base.link, 0, 1);
    const consumer = try setup.make_consumer();
    const first_gate = try consumer.gate(.unresolved);
    const second_gate = try consumer.gate(complete);
    const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const prod2 = try setup.make_producer(&.{
        .{ 5, unresolved_response },
        .{ 5, unexpected_refetch },
    });
    _ = try setup.spawn(1, try setup.make_consumer(), prod2);
    const prod3 = try setup.make_producer(&.{.{ 5, valid_response }});
    _ = try setup.spawn(2, try setup.make_consumer(), prod3);

    // Start unrestricted repair and park its first response in validation.
    try fetch_as(mailbox, 5, 49);
    var started = try consumer.next_started();
    try started.expect(5, &.{49});
    started.deinit();
    // A targeted objection for the same key attaches to the parked fetch without issuing
    // another network request.
    try setup.add_link(base.link, 0, 2);
    var target = [_]base.PublicKey{setup.peers[2]};
    _ = try mailbox.fetch_targeted(.{ .key = key(5), .subscriber = 50 }, &target);
    try setup.sleep(Duration.from_millis(100));
    try prod2.expect_remaining(key(5), &.{unexpected_refetch});
    try prod3.expect_remaining(key(5), &.{valid_response});
    try setup.oracle().remove_link(setup.peers[0], setup.peers[1]);
    try setup.oracle().remove_link(setup.peers[1], setup.peers[0]);

    // An unresolved response retries unrestricted repair with both subscribers and does not
    // penalize the serving peer.
    consumer.open(first_gate);
    try setup.track_roles(1, &.{ 0, 2 }, &.{});
    started = try consumer.next_started();
    defer started.deinit();
    try started.expect(5, &.{ 49, 50 });
    consumer.open(second_gate);
    var event = try consumer.next_event();
    defer event.deinit();
    try event.seen.expect(5, &.{ 49, 50 });
    try testing.expectEqualStrings(valid_response, event.value);
    try prod2.expect_remaining(key(5), &.{unexpected_refetch});
    try prod3.expect_remaining(key(5), &.{});
    try testing.expectEqual(0, try blocked_count(setup));
}

test "late targeted subscriber joins retry after unresolved delivery" {
    try base.run(10, late_targeted_joins_retry);
}

test "due retry precedes queued fresh request" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const quota = @import("p2p").Quota.per_second(2);
            const setup = try HoldingSetup.init(io, &.{ 1, 2 }, .{ .quota = quota });
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            const consumer = try setup.make_consumer();
            const producer = try setup.make_producer(&.{ .{ 60, "retry" }, .{ 61, "fresh" } });
            _ = try setup.spawn(1, try setup.make_consumer(), producer);
            setup.retry_delay = Duration.from_millis(0);
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));

            try base.fetch(mailbox, 60);
            var first = try consumer.next();
            defer first.deinit();
            try first.seen.expect(60, &.{{}});
            // Resolving the delivery makes its retry due before the queued mailbox request is
            // admitted. The two-token quota admits the retry and holds the fresh request.
            try base.fetch(mailbox, 61);
            first.send(.unresolved);
            var retry = try consumer.next();
            defer retry.deinit();
            try retry.seen.expect(60, &.{{}});
            retry.send(complete);
            var fresh = try consumer.next();
            defer fresh.deinit();
            try fresh.seen.expect(61, &.{{}});
            fresh.send(complete);
        }
    }.body);
}

fn late_subscriber_unrelated_waiter(io: Io) !void {
    const setup = try BlockingTagged.init(io, &.{ 1, 2, 3 }, .{});
    defer setup.deinit();
    try setup.add_link(base.link, 0, 1);
    try setup.add_link(base.link, 0, 2);
    const consumer = try setup.make_consumer();
    const first_gate = try consumer.gate(.invalid);
    const second_gate = try consumer.gate(complete);
    const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const prod2 = try setup.make_producer(&.{.{ 4, "bad data" }});
    _ = try setup.spawn(1, try setup.make_consumer(), prod2);
    const prod3 = try setup.make_producer(&.{.{ 6, "data for key 6" }});
    _ = try setup.spawn(2, try setup.make_consumer(), prod3);

    // Block peer 1, then arm a waiter that can only be served by it.
    try fetch_as(mailbox, 4, 1);
    var started = try consumer.next_started();
    started.deinit();
    consumer.open(first_gate);
    try setup.wait_for_blocked(0, 1);
    var target = [_]base.PublicKey{setup.peers[1]};
    _ = try mailbox.fetch_targeted(.{ .key = key(5), .subscriber = 2 }, &target);
    try setup.sleep(Duration.from_millis(100));

    try fetch_as(mailbox, 6, 3);
    started = try consumer.next_started();
    try started.expect(6, &.{3});
    started.deinit();
    try fetch_as(mailbox, 6, 4);
    try setup.sleep(Duration.from_millis(100));
    consumer.open(second_gate);
    var event = try consumer.next_event();
    defer event.deinit();
    try event.seen.expect(6, &.{3});
    try testing.expectEqualStrings("data for key 6", event.value);
    // The late subscriber is delivered while the unrelated waiter stays armed.
    started = try consumer.next_started();
    defer started.deinit();
    try started.expect(6, &.{4});
}

test "late subscriber delivery ignores unrelated waiter" {
    try base.run(10, late_subscriber_unrelated_waiter);
}

const TaggedSetup = base.SetupWith(@import("mocks/consumer.zig").Consumer(MockKey, u16));

fn single_subscriber(io: Io, retain_first: bool) !void {
    const setup = try TaggedSetup.init(io, &.{ 1, 2 }, .{});
    defer setup.deinit();
    const consumer = try setup.make_consumer();
    const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
    const prod2 = try setup.make_producer(&.{.{ 5, "data for key 5" }});
    _ = try setup.spawn(1, try setup.make_consumer(), prod2);

    try fetch_as(mailbox, 5, 50);
    if (retain_first) {
        // Retaining the only subscriber keeps the fetch.
        try setup.sleep(Duration.from_millis(100));
        const predicate = resolver.Predicate(MockKey, u16).init({}, struct {
            fn keep(_: void, _: MockKey, subscriber: u16) bool {
                return subscriber == 50;
            }
        }.keep);
        _ = try mailbox.retain(predicate);
        try setup.sleep(Duration.from_millis(100));
    }
    try setup.add_link(base.link, 0, 1);
    var event = try consumer.next_event();
    defer event.deinit(gpa);
    try testing.expectEqual(key(5), event.key);
    try testing.expectEqualSlices(u16, &.{50}, event.subscribers);
    try testing.expectEqualStrings("data for key 5", event.value);
}

test "deliver receives distinct subscriber type" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            try single_subscriber(io, true);
        }
    }.body);
}

test "deliver receives single subscriber" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            try single_subscriber(io, false);
        }
    }.body);
}

test "retain drops all" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try base.Setup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            // No link yet, so the fetch stays in flight.
            const consumer = try setup.make_consumer();
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 6, "data for key 6" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            // Pruning before fetching has no effect.
            try retain_none(mailbox, void);
            try base.expect_no_event(setup, consumer, 100);
            try base.fetch(mailbox, 6);
            try retain_none(mailbox, void);
            try setup.add_link(base.link, 0, 1);
            // Had the in-flight entry survived, this fetch would be dropped as a duplicate.
            try base.fetch(mailbox, 6);
            try base.expect_event(consumer, 6, "data for key 6");
        }
    }.body);
}

test "shutdown aborts pending delivery" {
    try base.run(10, struct {
        fn body(io: Io) !void {
            const setup = try BlockingSetup.init(io, &.{ 1, 2 }, .{});
            defer setup.deinit();
            try setup.add_link(base.link, 0, 1);
            const consumer = try setup.make_consumer();
            const pending_gate = try consumer.gate(complete);
            const mailbox = try setup.spawn(0, consumer, try setup.make_producer(&.{}));
            const prod2 = try setup.make_producer(&.{.{ 1, "data for key 1" }});
            _ = try setup.spawn(1, try setup.make_consumer(), prod2);

            try base.fetch(mailbox, 1);
            var started = try consumer.next_started();
            defer started.deinit();
            try started.expect(1, &.{{}});
            setup.stop(0);
            setup.stop(1);
            try setup.sleep(Duration.from_millis(100));
            // Aborting the engine dropped the pending verdict wait. Commonware also counts
            // the actor's running tasks; here the abort awaits every engine task, and
            // testing.allocator reports anything the engine left behind.
            try consumer.closed(pending_gate);
            try setup.sleep(Duration.from_millis(100));
            try testing.expect(consumer.try_event() == null);
        }
    }.body);
}

/// Drops every fetch from the fetcher, standing in for a request answered by its peer.
const DropAll = struct {
    pub fn call(_: DropAll, _: MockKey) bool {
        return false;
    }
};

/// Adds a fetch for `value` with one subscriber and no span.
fn add_one(engine: *base.Engine, value: MockKey) !void {
    var spans = [_]?*resolver.Span{null};
    try engine.add_fetch(value, &.{{}}, &spans, null);
}

/// commonware `engine.rs` `issue_5720_regression`: a verdict sent before the consumer fetches
/// the key again does not retire that fetch, even when the engine takes the fetch before it
/// reads the verdict.
fn repeat_after_verdict(io: Io) !void {
    const setup = try base.SetupWith(base.Consumer).init(io, &.{1}, .{});
    defer setup.deinit();
    const consumer = try setup.make_consumer();
    const producer = try setup.make_producer(&.{});
    // An engine that never runs, so the test calls its handlers in the order under test.
    const connection = setup.connections[0].?;
    setup.connections[0] = null;
    var pair = try actor.mailbox.new(base.Engine.Message, gpa, io, 1);
    defer pair.sender.deinit();
    const scope = runtime.telemetry.metrics.Scope.init(&setup.registry).child("actor");
    const engine = try base.Engine.create(gpa, io, scope, .{
        .peer_provider = setup.oracle().manager(),
        .blocker = setup.oracle().control(setup.peers[0]),
        .consumer = consumer,
        .producer = producer,
        .mailbox_size = 1,
        .me = null,
        .fetch_timeout = Duration.from_secs(1),
        .fetch_retry_delay = Duration.from_secs(1),
        .priority_requests = false,
        .priority_responses = false,
    }, pair.receiver, connection.sender, connection.receiver);
    defer engine.destroy();
    const k = key(1);

    // Stand in for a request and its response: the fetcher drops the key and the consumer
    // receives the value, answering inside `deliver`.
    try add_one(engine, k);
    engine.fetcher.retain(DropAll{});
    const value = try gpa.dupe(u8, "value");
    const delivery: resolver.Delivery(MockKey, void) = .{
        .key = k,
        .subscribers = engine.subscribers.pending(k).?,
    };
    try engine.inflight.deliver(delivery, base.key_of(1), Duration.zero, value);
    var event = consumer.try_event().?;
    event.deinit(gpa);

    // The consumer fetches again; the engine takes the fetch before it reads the verdict.
    try add_one(engine, k);

    // The fetch applied the verdict, so the wait for the first delivery aborts and cannot
    // complete the repeat.
    try testing.expectError(error.Aborted, engine.inflight.try_next_delivery());
    try testing.expect(try engine.inflight.try_next_delivery() == null);

    // The repeat keeps its subscriber and waits for a request of its own.
    try testing.expect(engine.subscribers.contains(k));
    try testing.expect(engine.inflight.contains(k));
    try testing.expectEqual(@as(usize, 1), engine.fetcher.len_pending());
}

test "verdict sent before a repeat fetch does not retire it (issue_5720_regression)" {
    try base.run(10, repeat_after_verdict);
}
