//! Deterministic scheduler simulating link bandwidth and delivery order (commonware
//! `p2p/src/simulated/transmitter.rs`).
//!
//! - `enqueue` records a send and calls `launch`, which may start a flow; `begin` installs it
//!   and `rebalance` recomputes rates with the bandwidth planner.
//! - The network drives time with `next`/`advance`. `next` is the earlier of the next
//!   bandwidth event and the next queued transmission becoming ready. `advance(now)` handles
//!   due events in time order: a bandwidth event rebalances and hands finished flows to
//!   `finish`; a ready event `wake`s queued transmissions. A final `wake` at `now` starts
//!   anything eligible by then.
//! - `finish` turns flows into completions (in flow-id order, via `stash` and `drain`, so a
//!   link delivers in send order) and launches the next queued message of each pair at once.
//!
//! Messages on one link start no earlier than `arrival_complete - latency` of the previous
//! one, so its first byte arrives right after the previous message fully arrived.
//!
//! Message payloads are opaque values of type `M` with a `len` (bytes on the wire); the
//! transmitter hands them back in `Completion`s and never frees them. After an allocation
//! error the state is unspecified.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const bandwidth = @import("bandwidth.zig");
const Rational = @import("rational.zig").Rational;
const SortedMap = @import("sorted_map.zig").SortedMap;

const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const Channel = u64;
const Rate = bandwidth.Rate;

fn min_time(a: ?SystemTime, b: ?SystemTime) ?SystemTime {
    const x = a orelse return b;
    const y = b orelse return x;
    return x.min(y);
}

fn le(a: SystemTime, b: SystemTime) bool {
    return a.order(b) != .gt;
}

/// `later - earlier`, or zero when `later` is earlier (Rust `duration_since().unwrap_or(0)`).
fn elapsed_between(earlier: SystemTime, later: SystemTime) Duration {
    const delta = later.nanos_since_epoch - earlier.nanos_since_epoch;
    if (delta <= 0) return Duration.zero;
    return Duration.from_nanos_saturating(@intCast(delta));
}

fn add_latency(time: SystemTime, latency: Duration) SystemTime {
    return time.checked_add(latency) orelse @panic("latency overflow computing arrival completion");
}

pub fn State(comptime P: type, comptime M: type) type {
    return struct {
        const Self = @This();

        pub const Pair = struct {
            origin: P,
            recipient: P,

            pub fn order(a: Pair, b: Pair) std.math.Order {
                const first = P.order(a.origin, b.origin);
                return if (first != .eq) first else P.order(a.recipient, b.recipient);
            }
        };

        /// A message leaving the transmitter: delivered at `deliver_at`, or dropped when null.
        pub const Completion = struct {
            origin: P,
            recipient: P,
            channel: Channel,
            message: M,
            deliver_at: ?SystemTime,
        };

        const Queued = struct {
            channel: Channel,
            message: M,
            latency: Duration,
            should_deliver: bool,
            ready_at: ?SystemTime,
        };

        const Bandwidth = struct { egress: ?u64, ingress: ?u64 };

        const Status = struct {
            id: u64,
            origin: P,
            recipient: P,
            latency: Duration,
            channel: Channel,
            message: M,
            /// Delivered when set.
            sequence: ?u64,
            remaining: Rational,
            rate: Rate,
            last_update: SystemTime,

            fn release(status: *Status) void {
                status.remaining.deinit();
                status.rate.deinit();
            }
        };

        const Buffered = struct { channel: Channel, message: M, arrival_complete_at: SystemTime };

        const SequenceKey = struct {
            pair: Pair,
            sequence: u64,

            pub fn order(a: SequenceKey, b: SequenceKey) std.math.Order {
                const first = Pair.order(a.pair, b.pair);
                return if (first != .eq) first else std.math.order(a.sequence, b.sequence);
            }
        };

        const Queue = std.ArrayList(Queued);
        const Statuses = std.ArrayList(Status);
        pub const Completions = std.ArrayList(Completion);

        gpa: Allocator,
        bandwidth_caps: SortedMap(P, Bandwidth) = .empty,
        next_flow_id: u64 = 0,
        assign_sequences: SortedMap(Pair, u64) = .empty,
        active_flows: SortedMap(Pair, u64) = .empty,
        /// Ascending by flow id.
        all_flows: Statuses = .empty,
        queued: SortedMap(Pair, Queue) = .empty,
        last_arrival_complete: SortedMap(Pair, SystemTime) = .empty,
        next_bandwidth_event: ?SystemTime = null,
        next_transmission_ready: ?SystemTime = null,
        expected_sequences: SortedMap(Pair, u64) = .empty,
        buffered: SortedMap(SequenceKey, Buffered) = .empty,

        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa };
        }

        /// Frees the state. Messages still in flight are dropped without being released; the
        /// owner of the payloads accounts for them.
        pub fn deinit(state: *Self) void {
            const gpa = state.gpa;
            for (state.all_flows.items) |*status| status.release();
            state.all_flows.deinit(gpa);
            for (state.queued.items()) |*entry| entry.value.deinit(gpa);
            state.queued.deinit(gpa);
            state.bandwidth_caps.deinit(gpa);
            state.assign_sequences.deinit(gpa);
            state.active_flows.deinit(gpa);
            state.last_arrival_complete.deinit(gpa);
            state.expected_sequences.deinit(gpa);
            state.buffered.deinit(gpa);
            state.* = undefined;
        }

        /// Records the bandwidth limits for `peer` in bytes per second (null is unlimited) and
        /// rebalances active flows.
        pub fn limit(
            state: *Self,
            now: SystemTime,
            peer: P,
            egress: ?u64,
            ingress: ?u64,
            out: *Completions,
        ) Allocator.Error!void {
            const caps: Bandwidth = .{ .egress = egress, .ingress = ingress };
            _ = try state.bandwidth_caps.put(state.gpa, peer, caps);
            if (state.all_flows.items.len == 0) {
                state.schedule(now);
                return;
            }
            var finished = try state.rebalance(now);
            try state.finish(&finished, now, out);
        }

        /// The earliest scheduled event (bandwidth update or send readiness).
        pub fn next(state: *const Self) ?SystemTime {
            return min_time(state.next_bandwidth_event, state.next_transmission_ready);
        }

        /// Advances the simulation to `now`, appending completed transmissions to `out`.
        pub fn advance(state: *Self, now: SystemTime, out: *Completions) Allocator.Error!void {
            while (true) {
                const band = due(state.next_bandwidth_event, now);
                const ready = due(state.next_transmission_ready, now);
                if (band == null and ready == null) break;
                if (band != null and (ready == null or le(band.?, ready.?))) {
                    state.next_bandwidth_event = null;
                    var finished = try state.rebalance(band.?);
                    try state.finish(&finished, band.?, out);
                } else {
                    state.next_transmission_ready = null;
                    try state.wake(ready.?, out);
                }
            }
            try state.wake(now, out);
        }

        fn due(event: ?SystemTime, now: SystemTime) ?SystemTime {
            const time = event orelse return null;
            return if (le(time, now)) time else null;
        }

        /// Enqueues a message for transmission from `origin` to `recipient`.
        pub fn enqueue(
            state: *Self,
            now: SystemTime,
            origin: P,
            recipient: P,
            channel: Channel,
            message: M,
            latency: Duration,
            should_deliver: bool,
            out: *Completions,
        ) Allocator.Error!void {
            const pair: Pair = .{ .origin = origin, .recipient = recipient };
            if (state.bandwidth_caps.count() == 0) {
                const queued: Queued = .{
                    .channel = channel,
                    .message = message,
                    .latency = latency,
                    .should_deliver = should_deliver,
                    .ready_at = null,
                };
                return state.fulfill_unconstrained(now, pair, queued, out);
            }
            const queue = try state.queued.get_or_put(state.gpa, pair, .empty);
            try queue.append(state.gpa, .{
                .channel = channel,
                .message = message,
                .latency = latency,
                .should_deliver = should_deliver,
                .ready_at = null,
            });
            var finished = try state.launch(pair, now);
            try state.finish(&finished, now, out);
        }

        /// Completes a transmission at once when no bandwidth limits are registered.
        fn fulfill_unconstrained(
            state: *Self,
            now: SystemTime,
            pair: Pair,
            entry: Queued,
            out: *Completions,
        ) Allocator.Error!void {
            const last_arrival = if (state.last_arrival_complete.get(pair)) |t| t.* else null;
            if (entry.should_deliver) {
                const ready_at = compute_ready_at(null, now, last_arrival, entry.latency);
                const arrival_complete_at = add_latency(ready_at, entry.latency);
                const sequence = try state.increment(pair);
                try state.register_completion(
                    pair,
                    entry.channel,
                    entry.message,
                    arrival_complete_at,
                    sequence,
                    out,
                );
            } else {
                try state.register_completion(pair, entry.channel, entry.message, now, null, out);
            }
            state.next_bandwidth_event = null;
            state.schedule(now);
        }

        /// The earliest time a message may start sending.
        fn compute_ready_at(
            stored: ?SystemTime,
            now: SystemTime,
            last_arrival_complete: ?SystemTime,
            latency: Duration,
        ) SystemTime {
            var ready_at = (stored orelse now).max(now);
            if (last_arrival_complete) |arrival| {
                if (arrival.checked_sub(latency)) |limit_time| {
                    ready_at = ready_at.max(limit_time);
                }
            }
            assert(le(now, ready_at));
            return ready_at;
        }

        /// Refreshes when the head of `queue` may send; null for an empty queue.
        fn refresh_front_ready_at(
            queue: *Queue,
            now: SystemTime,
            last_arrival_complete: ?SystemTime,
        ) ?SystemTime {
            if (queue.items.len == 0) return null;
            const front = &queue.items[0];
            const ready_at =
                compute_ready_at(front.ready_at, now, last_arrival_complete, front.latency);
            front.ready_at = if (le(ready_at, now)) null else ready_at;
            return ready_at;
        }

        fn last_arrival_of(state: *const Self, pair: Pair) ?SystemTime {
            return if (state.last_arrival_complete.get(pair)) |time| time.* else null;
        }

        /// Starts queued transmissions that are ready at `now`.
        fn wake(state: *Self, now: SystemTime, out: *Completions) Allocator.Error!void {
            var ready_pairs: std.ArrayList(Pair) = .empty;
            defer ready_pairs.deinit(state.gpa);
            for (state.queued.items()) |*entry| {
                if (state.active_flows.contains(entry.key)) continue;
                const last_arrival = state.last_arrival_of(entry.key);
                const queue = &entry.value;
                const ready_at = refresh_front_ready_at(queue, now, last_arrival) orelse continue;
                if (le(ready_at, now)) try ready_pairs.append(state.gpa, entry.key);
            }
            for (ready_pairs.items) |pair| {
                var finished = try state.launch(pair, now);
                try state.finish(&finished, now, out);
            }
            state.schedule(now);
        }

        /// Advances every flow to `now`, removes the finished ones (returned for `finish`),
        /// and recomputes rates and the next bandwidth event for the rest.
        fn rebalance(state: *Self, now: SystemTime) Allocator.Error!Statuses {
            const gpa = state.gpa;
            var finished: Statuses = .empty;
            errdefer finished.deinit(gpa);
            var active: std.ArrayList(bandwidth.Flow(P)) = .empty;
            defer active.deinit(gpa);
            var kept: usize = 0;
            for (state.all_flows.items) |status_value| {
                var status = status_value;
                if (!status.remaining.is_zero()) {
                    const elapsed = elapsed_between(status.last_update, now);
                    if (!elapsed.is_zero()) {
                        const remaining =
                            try bandwidth.transfer(status.rate, elapsed, status.remaining);
                        status.remaining.deinit();
                        status.remaining = remaining;
                    }
                }
                status.last_update = now;
                if (status.remaining.is_zero()) {
                    try finished.append(gpa, status);
                    continue;
                }
                state.all_flows.items[kept] = status;
                kept += 1;
                try active.append(gpa, .{
                    .id = status.id,
                    .origin = status.origin,
                    .recipient = status.recipient,
                    .delivered = status.sequence != null,
                });
            }
            state.all_flows.shrinkRetainingCapacity(kept);
            if (active.items.len == 0) {
                state.next_bandwidth_event = null;
                return finished;
            }
            try state.apply_rates(now, active.items, &finished);
            return finished;
        }

        /// Assigns planned rates to the active flows (which are `all_flows` in order). Unlimited
        /// flows finish at once; the earliest finite completion is the next bandwidth event.
        fn apply_rates(
            state: *Self,
            now: SystemTime,
            active: []const bandwidth.Flow(P),
            finished: *Statuses,
        ) Allocator.Error!void {
            assert(active.len == state.all_flows.items.len);
            const rates = try bandwidth.allocate(P, state.gpa, active, Caps{ .state = state });
            defer state.gpa.free(rates);
            var earliest: ?Duration = null;
            var kept: usize = 0;
            for (state.all_flows.items, rates, active) |status_value, rate, flow| {
                var status = status_value;
                assert(status.id == flow.id);
                status.rate.deinit();
                status.rate = rate;
                status.last_update = now;
                if (rate == .unlimited) {
                    try finished.append(state.gpa, status);
                    continue;
                }
                state.all_flows.items[kept] = status;
                kept += 1;
                const needed =
                    try bandwidth.duration(status.rate, status.remaining) orelse continue;
                // Advance by at least the clock precision so time actually moves forward.
                const step = if (needed.is_zero())
                    Duration.zero
                else if (needed.order(utils.time.SYSTEM_TIME_PRECISION) == .lt)
                    utils.time.SYSTEM_TIME_PRECISION
                else
                    needed;
                if (earliest == null or step.order(earliest.?) == .lt) earliest = step;
            }
            state.all_flows.shrinkRetainingCapacity(kept);
            state.next_bandwidth_event = if (earliest) |step| now.saturating_add(step) else null;
        }

        const Caps = struct {
            state: *const Self,

            pub fn egress(caps: Caps, peer: P) ?u128 {
                const limits = caps.state.bandwidth_caps.get(peer) orelse return null;
                return if (limits.egress) |cap| cap else null;
            }

            pub fn ingress(caps: Caps, peer: P) ?u128 {
                const limits = caps.state.bandwidth_caps.get(peer) orelse return null;
                return if (limits.ingress) |cap| cap else null;
            }
        };

        /// Finalizes finished flows in flow-id order and launches each pair's next message.
        fn finish(
            state: *Self,
            finished: *Statuses,
            now: SystemTime,
            out: *Completions,
        ) Allocator.Error!void {
            defer finished.deinit(state.gpa);
            std.sort.pdq(Status, finished.items, {}, by_id);
            var head: usize = 0;
            while (head < finished.items.len) : (head += 1) {
                var status = finished.items[head];
                status.release();
                const pair: Pair = .{ .origin = status.origin, .recipient = status.recipient };
                _ = state.active_flows.remove(pair);
                const arrival_complete_at = if (status.sequence != null)
                    add_latency(now, status.latency)
                else
                    now;
                try state.register_completion(
                    pair,
                    status.channel,
                    status.message,
                    arrival_complete_at,
                    status.sequence,
                    out,
                );
                // Existing flows are already at `now`, so a flow this launch finishes is the new
                // one; its id exceeds every pending id, so appending keeps flow-id order.
                var launched = try state.launch(pair, now);
                defer launched.deinit(state.gpa);
                try finished.appendSlice(state.gpa, launched.items);
            }
            state.schedule(now);
        }

        fn by_id(_: void, a: Status, b: Status) bool {
            return a.id < b.id;
        }

        /// Records the outcome of a transmission: buffers deliveries until they are in order,
        /// and emits drops at once.
        fn register_completion(
            state: *Self,
            pair: Pair,
            channel: Channel,
            message: M,
            arrival_complete_at: SystemTime,
            sequence: ?u64,
            out: *Completions,
        ) Allocator.Error!void {
            _ = try state.last_arrival_complete.put(state.gpa, pair, arrival_complete_at);
            const value = sequence orelse {
                return out.append(state.gpa, .{
                    .origin = pair.origin,
                    .recipient = pair.recipient,
                    .channel = channel,
                    .message = message,
                    .deliver_at = null,
                });
            };
            const sequence_key: SequenceKey = .{ .pair = pair, .sequence = value };
            const buffered: Buffered = .{
                .channel = channel,
                .message = message,
                .arrival_complete_at = arrival_complete_at,
            };
            const replaced = try state.buffered.put(state.gpa, sequence_key, buffered);
            assert(replaced == null);
            try state.drain(pair, out);
        }

        /// Emits the buffered deliveries of `pair` that are next in sequence.
        fn drain(state: *Self, pair: Pair, out: *Completions) Allocator.Error!void {
            const expected = try state.expected_sequences.get_or_put(state.gpa, pair, 0);
            while (state.buffered.remove(.{ .pair = pair, .sequence = expected.* })) |buffered| {
                try out.append(state.gpa, .{
                    .origin = pair.origin,
                    .recipient = pair.recipient,
                    .channel = buffered.channel,
                    .message = buffered.message,
                    .deliver_at = buffered.arrival_complete_at,
                });
                expected.* += 1;
            }
        }

        /// Sets `next_transmission_ready` from the head of every idle queue.
        fn schedule(state: *Self, now: SystemTime) void {
            var next_ready: ?SystemTime = null;
            for (state.queued.items()) |*entry| {
                if (state.active_flows.contains(entry.key)) continue;
                const last_arrival = state.last_arrival_of(entry.key);
                const queue = &entry.value;
                const ready_at = refresh_front_ready_at(queue, now, last_arrival) orelse continue;
                next_ready = min_time(next_ready, ready_at.max(now));
            }
            state.next_transmission_ready = next_ready;
        }

        /// Starts the next flow for `pair` when it is idle and its head is ready, returning the
        /// flows that finished in the rebalance this triggers.
        fn launch(state: *Self, pair: Pair, now: SystemTime) Allocator.Error!Statuses {
            if (state.active_flows.contains(pair)) return .empty;
            var start: ?Queued = null;
            var remove_queue = false;
            if (state.queued.get(pair)) |queue| {
                const last_arrival = state.last_arrival_of(pair);
                if (refresh_front_ready_at(queue, now, last_arrival)) |ready_at| {
                    if (le(ready_at, now)) {
                        start = queue.orderedRemove(0);
                        remove_queue = queue.items.len == 0;
                    }
                } else {
                    remove_queue = true;
                }
            }
            if (remove_queue) {
                var queue = state.queued.remove(pair).?;
                queue.deinit(state.gpa);
            }
            const entry = start orelse return .empty;
            const flow_id = state.next_flow_id;
            state.next_flow_id += 1;
            _ = try state.active_flows.put(state.gpa, pair, flow_id);
            return state.begin(pair, flow_id, entry, now);
        }

        /// Installs a flow and rebalances, returning the flows that finished.
        fn begin(
            state: *Self,
            pair: Pair,
            flow_id: u64,
            entry: Queued,
            now: SystemTime,
        ) Allocator.Error!Statuses {
            const deliver = entry.should_deliver and P.order(pair.origin, pair.recipient) != .eq;
            var remaining = try Rational.init_int(state.gpa, entry.message.len);
            errdefer remaining.deinit();
            var rate: Rate = .{ .finite = try .init_int(state.gpa, 0) };
            errdefer rate.deinit();
            const sequence = if (deliver) try state.increment(pair) else null;
            try state.all_flows.append(state.gpa, .{
                .id = flow_id,
                .origin = pair.origin,
                .recipient = pair.recipient,
                .latency = entry.latency,
                .channel = entry.channel,
                .message = entry.message,
                .sequence = sequence,
                .remaining = remaining,
                .rate = rate,
                .last_update = now,
            });
            return state.rebalance(now);
        }

        /// The next sequence number for `pair`, which keeps each link FIFO.
        fn increment(state: *Self, pair: Pair) Allocator.Error!u64 {
            const counter = try state.assign_sequences.get_or_put(state.gpa, pair, 0);
            const sequence = counter.*;
            counter.* += 1;
            return sequence;
        }
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const Key = cryptography.ed25519.PublicKey;
const TestState = State(Key, []const u8);
const channel_test: Channel = 0;

fn key(seed: u64) Key {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

fn at_ms(ms: u64) SystemTime {
    return .{ .nanos_since_epoch = @as(i128, ms) * std.time.ns_per_ms };
}

const epoch = SystemTime.UNIX_EPOCH;

/// A transmitter plus a completion buffer that each step clears.
const Harness = struct {
    state: TestState,
    out: TestState.Completions = .empty,

    fn init() Harness {
        return .{ .state = .init(testing.allocator) };
    }

    fn deinit(h: *Harness) void {
        h.out.deinit(testing.allocator);
        h.state.deinit();
    }

    fn limit(
        h: *Harness,
        now: SystemTime,
        peer: Key,
        egress: ?u64,
        ingress: ?u64,
    ) ![]TestState.Completion {
        h.out.clearRetainingCapacity();
        try h.state.limit(now, peer, egress, ingress, &h.out);
        return h.out.items;
    }

    fn enqueue(
        h: *Harness,
        now: SystemTime,
        origin: Key,
        recipient: Key,
        message: []const u8,
        latency: Duration,
        deliver: bool,
    ) ![]TestState.Completion {
        h.out.clearRetainingCapacity();
        const state = &h.state;
        try state.enqueue(now, origin, recipient, channel_test, message, latency, deliver, &h.out);
        return h.out.items;
    }

    /// Sends a delivered message and expects no completion yet.
    fn send_quiet(
        h: *Harness,
        now: SystemTime,
        origin: Key,
        recipient: Key,
        message: []const u8,
        latency: Duration,
    ) !void {
        const completions = try h.enqueue(now, origin, recipient, message, latency, true);
        try testing.expectEqual(@as(usize, 0), completions.len);
    }

    fn advance(h: *Harness, now: SystemTime) ![]TestState.Completion {
        h.out.clearRetainingCapacity();
        try h.state.advance(now, &h.out);
        return h.out.items;
    }
};

fn expect_time(expected: SystemTime, actual: ?SystemTime) !void {
    try testing.expect(actual != null);
    if (expected.order(actual.?) != .eq) {
        const got = actual.?.nanos_since_epoch;
        std.debug.print("expected {d} got {d}\n", .{ expected.nanos_since_epoch, got });
        return error.TestUnexpectedResult;
    }
}

test "unlimited capacity completes at once; drops are recorded" {
    var h = Harness.init();
    defer h.deinit();
    const delivered = try h.enqueue(epoch, key(1), key(2), "hello", Duration.zero, true);
    try testing.expectEqual(@as(usize, 1), delivered.len);
    try expect_time(epoch, delivered[0].deliver_at);
    const dropped = try h.enqueue(epoch, key(3), key(4), "drop", Duration.zero, false);
    try testing.expectEqual(@as(usize, 1), dropped.len);
    try testing.expect(dropped[0].deliver_at == null);
}

test "rebalance schedules an event for huge transfers" {
    var h = Harness.init();
    defer h.deinit();
    try testing.expectEqual(@as(usize, 0), (try h.limit(epoch, key(20), 1, null)).len);
    try testing.expectEqual(@as(usize, 0), (try h.limit(epoch, key(21), null, 1)).len);
    try h.send_quiet(epoch, key(20), key(21), "x", .zero);
    var finished = try h.state.rebalance(epoch);
    finished.deinit(testing.allocator);
    try testing.expect(h.state.next() != null);
}

test "fifo delivery per pair (fifo_delivery_per_pair)" {
    var h = Harness.init();
    defer h.deinit();
    const origin = key(10);
    const recipient = key(11);
    const one: [1_000]u8 = @splat(1);
    const two: [1_000]u8 = @splat(2);
    _ = try h.limit(epoch, origin, 1_000, null);
    try h.send_quiet(epoch, origin, recipient, &one, .from_secs(1));
    const first_finish = h.state.next().?;
    try expect_time(at_ms(1_000), first_finish);
    const a = try h.advance(first_finish);
    try testing.expectEqual(@as(usize, 1), a.len);
    try expect_time(at_ms(2_000), a[0].deliver_at);

    try h.send_quiet(epoch, origin, recipient, &two, .zero);
    try testing.expectEqual(@as(usize, 0), (try h.advance(epoch)).len);
    const next_ready = h.state.next().?;
    try expect_time(at_ms(2_000), next_ready);
    try testing.expectEqual(@as(usize, 0), (try h.advance(next_ready)).len);
    const second_finish = h.state.next().?;
    try expect_time(at_ms(3_000), second_finish);
    const b = try h.advance(second_finish);
    try testing.expectEqual(@as(usize, 1), b.len);
    try expect_time(second_finish, b[0].deliver_at);
    try testing.expectEqual(@as(usize, 1_000), b[0].message.len);
    try testing.expectEqual(@as(u8, 2), b[0].message[0]);
}

test "staggered latencies allow overlap (staggered_latencies_allow_overlap)" {
    var h = Harness.init();
    defer h.deinit();
    const origin = key(21);
    const recipient = key(22);
    _ = try h.limit(epoch, origin, 500_000, null);
    const msg_a = try testing.allocator.alloc(u8, 1_000_000);
    defer testing.allocator.free(msg_a);
    const msg_b = msg_a[0..500_000];
    _ = try h.enqueue(epoch, origin, recipient, msg_a, .from_millis(500), true);
    _ = try h.enqueue(epoch, origin, recipient, msg_b, .from_millis(100), true);
    const first_finish = h.state.next().?;
    try expect_time(at_ms(2_000), first_finish);
    const a = try h.advance(first_finish);
    try testing.expectEqual(@as(usize, 1), a.len);
    try testing.expectEqual(msg_a.len, a[0].message.len);
    try expect_time(at_ms(2_500), a[0].deliver_at);
    const next_ready = h.state.next().?;
    try expect_time(at_ms(2_400), next_ready);
    try testing.expectEqual(@as(usize, 0), (try h.advance(next_ready)).len);
    const second_finish = h.state.next().?;
    try expect_time(at_ms(3_400), second_finish);
    const b = try h.advance(second_finish);
    try testing.expectEqual(@as(usize, 1), b.len);
    try testing.expectEqual(msg_b.len, b[0].message.len);
    try expect_time(at_ms(3_500), b[0].deliver_at);
}

test "advancing long after next drains once; past instants are no-ops" {
    var h = Harness.init();
    defer h.deinit();
    const origin = key(42);
    const recipient = key(43);
    const payload: [1_000]u8 = @splat(7);
    _ = try h.limit(epoch, origin, 1_000, null);
    _ = try h.enqueue(epoch, origin, recipient, &payload, .from_millis(250), true);
    const deadline = h.state.next().?;
    try expect_time(at_ms(1_000), deadline);
    const late = try h.advance(at_ms(6_000));
    try testing.expectEqual(@as(usize, 1), late.len);
    try testing.expect(late[0].origin.eql(origin) and late[0].recipient.eql(recipient));
    try expect_time(at_ms(1_250), late[0].deliver_at);
    try testing.expect(h.state.next() == null);
    try testing.expectEqual(@as(usize, 0), (try h.advance(at_ms(7_000))).len);
    try testing.expectEqual(@as(usize, 0), (try h.advance(at_ms(1_000))).len);
    try testing.expectEqual(@as(usize, 0), (try h.advance(epoch)).len);
}

test "unconstrained delivery is immediate and FIFO" {
    var h = Harness.init();
    defer h.deinit();
    const first = try h.enqueue(epoch, key(46), key(47), "first", .from_millis(100), true);
    try testing.expectEqual(@as(usize, 1), first.len);
    try expect_time(at_ms(100), first[0].deliver_at);
    const second = try h.enqueue(epoch, key(46), key(47), "second", .from_millis(50), true);
    try testing.expectEqual(@as(usize, 1), second.len);
    try expect_time(at_ms(100), second[0].deliver_at);
    try testing.expect(h.state.next() == null);
}

test "wake, schedule, and launch serialize a pair" {
    var h = Harness.init();
    defer h.deinit();
    const origin = key(40);
    const recipient = key(41);
    const pair: TestState.Pair = .{ .origin = origin, .recipient = recipient };
    _ = try h.limit(epoch, origin, 1_000_000, null);
    const buffer = try testing.allocator.alloc(u8, 3_000_000);
    defer testing.allocator.free(buffer);
    _ = try h.enqueue(epoch, origin, recipient, buffer, .from_secs(10), true);
    _ = try h.enqueue(epoch, origin, recipient, buffer[0..1_000_000], .from_secs(8), true);
    _ = try h.enqueue(epoch, origin, recipient, buffer[0..1_000_000], .from_secs(2), true);
    const queue = h.state.queued.get(pair).?;
    try testing.expectEqual(@as(usize, 2), queue.items.len);
    try testing.expect(queue.items[0].ready_at == null and queue.items[1].ready_at == null);
    try testing.expect(h.state.active_flows.contains(pair));

    try expect_time(at_ms(3_000), h.state.next());
    try testing.expectEqual(@as(usize, 1), (try h.advance(at_ms(3_000))).len);
    try testing.expect(!h.state.active_flows.contains(pair));
    const waiting = h.state.queued.get(pair).?;
    try testing.expectEqual(@as(usize, 2), waiting.items.len);
    try expect_time(at_ms(5_000), waiting.items[0].ready_at);
    try testing.expect(waiting.items[1].ready_at == null);
    try expect_time(at_ms(5_000), h.state.next());

    try testing.expectEqual(@as(usize, 0), (try h.advance(at_ms(5_000))).len);
    try testing.expect(h.state.active_flows.contains(pair));
    try testing.expect(h.state.queued.get(pair).?.items[0].ready_at == null);
    try expect_time(at_ms(6_000), h.state.next());
    try testing.expectEqual(@as(usize, 1), (try h.advance(at_ms(6_000))).len);
    try expect_time(at_ms(12_000), h.state.queued.get(pair).?.items[0].ready_at);
    try expect_time(at_ms(12_000), h.state.next());
    try testing.expectEqual(@as(usize, 0), (try h.advance(at_ms(12_000))).len);
    try testing.expect(h.state.active_flows.contains(pair));
    try testing.expect(!h.state.queued.contains(pair));
    try expect_time(at_ms(13_000), h.state.next());
    try testing.expectEqual(@as(usize, 1), (try h.advance(at_ms(13_000))).len);
    try testing.expect(h.state.next() == null);
}

test "lifting a limit completes an active flow at once" {
    var h = Harness.init();
    defer h.deinit();
    const payload: [1_000]u8 = @splat(0xdd);
    _ = try h.limit(epoch, key(50), 1_000, null);
    _ = try h.enqueue(epoch, key(50), key(51), &payload, Duration.zero, true);
    try expect_time(at_ms(1_000), h.state.next());
    const done = try h.limit(epoch, key(50), null, null);
    try testing.expectEqual(@as(usize, 1), done.len);
    try expect_time(epoch, done[0].deliver_at);
    try testing.expect(h.state.next() == null);
}

test "equal split across destinations" {
    var h = Harness.init();
    defer h.deinit();
    const payload: [1_000]u8 = @splat(0xbb);
    _ = try h.limit(epoch, key(30), 1_000, null);
    _ = try h.enqueue(epoch, key(30), key(31), &payload, Duration.zero, true);
    _ = try h.enqueue(epoch, key(30), key(32), &payload, Duration.zero, true);
    try expect_time(at_ms(2_000), h.state.next());
    const done = try h.advance(at_ms(2_000));
    try testing.expectEqual(@as(usize, 2), done.len);
    for (done) |completion| try expect_time(at_ms(2_000), completion.deliver_at);
    try testing.expect(h.state.next() == null);
}

test "carry accumulates across rebalances" {
    var h = Harness.init();
    defer h.deinit();
    const large: [10_000]u8 = @splat(0xbb);
    _ = try h.limit(epoch, key(60), 30_000, null);
    _ = try h.limit(epoch, key(61), 30_000, null);
    _ = try h.limit(epoch, key(62), null, 30_000);
    _ = try h.enqueue(epoch, key(60), key(62), large[0..1], Duration.zero, true);
    _ = try h.enqueue(epoch, key(61), key(62), &large, Duration.zero, true);
    var sizes: [2]usize = undefined;
    var delivered: usize = 0;
    var last = epoch;
    var steps: usize = 0;
    while (delivered < 2) : (steps += 1) {
        try testing.expect(steps < 100);
        const deadline = h.state.next().?;
        try testing.expect(le(last, deadline));
        last = deadline;
        for (try h.advance(deadline)) |completion| {
            try testing.expect(completion.deliver_at != null);
            sizes[delivered] = completion.message.len;
            delivered += 1;
        }
    }
    std.sort.pdq(usize, &sizes, {}, std.sort.asc(usize));
    try testing.expectEqualSlices(usize, &.{ 1, 10_000 }, &sizes);
    try testing.expect(h.state.next() == null);
}

test "completions at one instant finish in flow order" {
    var h = Harness.init();
    defer h.deinit();
    const b = key(71);
    const c = key(72);
    const zeros: [100]u8 = @splat(0);
    _ = try h.limit(epoch, key(70), 1_000, null);
    const sends = [_]struct { Key, usize }{
        .{ b, 100 }, .{ b, 0 }, .{ b, 50 }, .{ c, 100 }, .{ c, 50 },
    };
    for (sends) |send| {
        try h.send_quiet(epoch, key(70), send[0], zeros[0..send[1]], .zero);
    }
    const done = try h.limit(epoch, key(70), null, null);
    const expected = [_]struct { Key, usize }{
        .{ b, 100 }, .{ c, 100 }, .{ b, 0 }, .{ c, 50 }, .{ b, 50 },
    };
    try testing.expectEqual(expected.len, done.len);
    for (expected, done) |e, completion| {
        try testing.expect(completion.recipient.eql(e[0]));
        try testing.expectEqual(e[1], completion.message.len);
    }
    try testing.expect(h.state.next() == null);
}

test "rebalance returns finished flows without finalizing" {
    var h = Harness.init();
    defer h.deinit();
    const origin = key(80);
    const b = key(81);
    const c = key(82);
    const zeros: [100]u8 = @splat(0);
    _ = try h.limit(epoch, origin, 1_000, null);
    for ([_]Key{ b, c, b }) |recipient| try h.send_quiet(epoch, origin, recipient, &zeros, .zero);
    const finish_at = h.state.next().?;
    try expect_time(at_ms(200), finish_at);

    var finished = try h.state.rebalance(finish_at);
    try testing.expectEqual(@as(usize, 2), finished.items.len);
    try testing.expectEqual(@as(u64, 0), finished.items[0].id);
    try testing.expectEqual(@as(u64, 1), finished.items[1].id);
    try testing.expectEqual(@as(usize, 0), h.state.all_flows.items.len);
    try testing.expectEqual(@as(usize, 2), h.state.active_flows.count());

    h.out.clearRetainingCapacity();
    try h.state.finish(&finished, finish_at, &h.out);
    try testing.expectEqual(@as(usize, 2), h.out.items.len);
    try testing.expect(h.out.items[0].recipient.eql(b) and h.out.items[1].recipient.eql(c));
    for (h.out.items) |completion| try expect_time(finish_at, completion.deliver_at);
    try testing.expectEqual(@as(usize, 1), h.state.all_flows.items.len);
    try testing.expectEqual(@as(u64, 2), h.state.all_flows.items[0].id);
    const pair_b: TestState.Pair = .{ .origin = origin, .recipient = b };
    try testing.expectEqual(@as(u64, 2), h.state.active_flows.get(pair_b).?.*);
    try expect_time(at_ms(300), h.state.next());
}

test "followers launched at finish complete together" {
    var h = Harness.init();
    defer h.deinit();
    const zeros: [1_000]u8 = @splat(0);
    _ = try h.limit(epoch, key(90), 3_000, null);
    for ([_]u64{ 91, 92, 93 }) |seed| {
        for (0..2) |_| _ = try h.enqueue(epoch, key(90), key(seed), &zeros, Duration.zero, true);
    }
    try expect_time(at_ms(1_000), h.state.next());
    const first = try h.advance(at_ms(1_000));
    try testing.expectEqual(@as(usize, 3), first.len);
    for (first) |completion| try expect_time(at_ms(1_000), completion.deliver_at);
    try expect_time(at_ms(2_000), h.state.next());
    const second = try h.advance(at_ms(2_000));
    try testing.expectEqual(@as(usize, 3), second.len);
    for (second) |completion| try expect_time(at_ms(2_000), completion.deliver_at);
    try testing.expect(h.state.next() == null);
}

test "a long queue drains at unlimited rate in one call (issue_5229_regression)" {
    var h = Harness.init();
    defer h.deinit();
    // commonware's 2,000 outside Debug (or with `-Dslow-tests`); Debug drains 200.
    const full = @import("builtin").mode != .debug or @import("build_options").slow_tests;
    const queued: usize = if (full) 2_000 else 200;
    const zeros: [100]u8 = @splat(0);
    _ = try h.limit(epoch, key(100), 1_000, null);
    for (0..queued + 1) |_| {
        try h.send_quiet(epoch, key(100), key(101), &zeros, .zero);
    }
    const done = try h.limit(epoch, key(100), null, null);
    try testing.expectEqual(queued + 1, done.len);
    for (done) |completion| try expect_time(epoch, completion.deliver_at);
    try testing.expect(h.state.next() == null);
}
