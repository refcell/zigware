//! commonware `resolver/src/p2p/inflight.rs` tests: the fetch-duration timer records only on
//! completion, and network responses complete with their source context.
//! `test_complete_panics_on_missing_key` expects a panic, which Zig tests cannot catch.

const std = @import("std");
const runtime = @import("runtime");
const utils = @import("utils");
const resolver = @import("../root.zig");
const inflight_mod = @import("inflight.zig");
const MockKey = @import("mocks/key.zig").Key;
const MockConsumer = @import("mocks/consumer.zig").Consumer(MockKey, void);

const testing = std.testing;
const gpa = testing.allocator;
const Io = std.Io;
const Duration = utils.Duration;
const metrics = runtime.telemetry.metrics;
const TestInflight = inflight_mod.Inflight(MockConsumer, u64);
const complete: resolver.Outcome = .{ .resolved = .complete };

fn key(value: u8) MockKey {
    return .init(value);
}

fn delivery(k: MockKey) resolver.Delivery(MockKey, void) {
    return .{ .key = k, .subscribers = &.{{}} };
}

fn run(comptime body: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try try runner.start(body, .{runner.io()});
}

/// A fetch-duration histogram and the inflight state under test.
const Fixture = struct {
    histogram: metrics.raw.Histogram,
    consumer: MockConsumer,
    inflight: TestInflight,

    fn init(fixture: *Fixture, io: Io) !void {
        fixture.histogram = .init(&metrics.Buckets.local);
        fixture.consumer = try .init(gpa, io);
        errdefer fixture.consumer.deinit();
        fixture.inflight = try .init(gpa, io, fixture.consumer);
    }

    fn deinit(fixture: *Fixture) void {
        fixture.inflight.deinit();
        fixture.consumer.deinit();
    }

    fn timer(fixture: *Fixture, io: Io) metrics.histogram.Timer {
        return .{ .histogram = &fixture.histogram, .start = Io.Clock.real.now(io) };
    }

    fn deliver(
        fixture: *Fixture,
        k: MockKey,
        peer: u64,
        elapsed: Duration,
        value: []const u8,
    ) !void {
        const owned = try gpa.dupe(u8, value);
        try fixture.inflight.deliver(delivery(k), peer, elapsed, owned);
    }
};

test "inflight: insert, contains, and cancel round trip" {
    try run(struct {
        fn body(io: Io) !void {
            var f: Fixture = undefined;
            try f.init(io);
            defer f.deinit();
            try testing.expect(!f.inflight.contains(key(1)));
            try f.inflight.insert(key(1), f.timer(io));
            try testing.expect(f.inflight.contains(key(1)));
            try testing.expect(f.inflight.cancel(key(1)));
            try testing.expect(!f.inflight.contains(key(1)));
            // A second cancel finds no entry.
            try testing.expect(!f.inflight.cancel(key(1)));
        }
    }.body);
}

test "inflight: cancel records no duration, complete records one" {
    try run(struct {
        fn body(io: Io) !void {
            var f: Fixture = undefined;
            try f.init(io);
            defer f.deinit();
            try f.inflight.insert(key(1), f.timer(io));
            _ = f.inflight.cancel(key(1));
            try testing.expectEqual(0, f.histogram.get_count());
            try f.inflight.insert(key(2), f.timer(io));
            f.inflight.complete(io, key(2));
            try testing.expectEqual(1, f.histogram.get_count());
            try testing.expect(!f.inflight.contains(key(2)));
        }
    }.body);
}

test "inflight: retain and drain drop entries without recording" {
    try run(struct {
        fn body(io: Io) !void {
            var f: Fixture = undefined;
            try f.init(io);
            defer f.deinit();
            for ([_]u8{ 1, 2, 3 }) |value| try f.inflight.insert(key(value), f.timer(io));
            const Odd = struct {
                pub fn call(_: @This(), k: MockKey) bool {
                    return k.value % 2 == 1;
                }
            };
            try testing.expectEqual(1, f.inflight.retain(Odd{}));
            try testing.expect(f.inflight.contains(key(1)));
            try testing.expect(!f.inflight.contains(key(2)));
            try testing.expect(f.inflight.contains(key(3)));
            try testing.expectEqual(2, f.inflight.drain());
            try testing.expect(!f.inflight.contains(key(1)) and !f.inflight.contains(key(3)));
            try testing.expectEqual(0, f.histogram.get_count());
        }
    }.body);
}

test "inflight: deliver completes with the source context and consumer result" {
    try run(struct {
        fn body(io: Io) !void {
            var f: Fixture = undefined;
            try f.init(io);
            defer f.deinit();
            try f.inflight.insert(key(7), f.timer(io));
            try f.deliver(key(7), 42, .from_millis(17), "data");
            var completed = try f.inflight.next_delivery();
            defer completed.deinit(gpa);
            try testing.expect(completed.key.eql(key(7)));
            try testing.expectEqual(42, completed.context.peer);
            try testing.expectEqual(Duration.from_millis(17), completed.context.elapsed);
            try testing.expectEqual(4, completed.context.bytes);
            try testing.expect(completed.outcome.?.eql(complete));
            try testing.expect(!completed.canceled);
            var event = try f.consumer.next_event();
            defer event.deinit(gpa);
            try testing.expect(event.key.eql(key(7)));
            try testing.expectEqualStrings("data", event.value);
            // A late cancel after completion finds no entry.
            f.inflight.complete(io, key(7));
            try testing.expect(!f.inflight.cancel(key(7)));
        }
    }.body);
}

test "inflight: cancellation keeps a ready verdict without recording the duration" {
    try run(struct {
        fn body(io: Io) !void {
            for ([_]bool{ false, true }) |drain| {
                var f: Fixture = undefined;
                try f.init(io);
                defer f.deinit();
                try f.inflight.insert(key(1), f.timer(io));
                try f.deliver(key(1), 5, .zero, "v");
                if (drain) {
                    try testing.expectEqual(1, f.inflight.drain());
                } else {
                    try testing.expect(f.inflight.cancel(key(1)));
                }
                // Source feedback survives independently of the canceled fetch timer.
                var completed = try f.inflight.next_delivery();
                defer completed.deinit(gpa);
                try testing.expect(completed.canceled);
                try testing.expectEqual(5, completed.context.peer);
                try testing.expectEqual(Duration.zero, completed.context.elapsed);
                try testing.expectEqual(1, completed.context.bytes);
                try testing.expect(completed.outcome.?.eql(complete));
                try testing.expect(!f.inflight.contains(key(1)));
                try testing.expectEqual(0, f.histogram.get_count());
                var event = try f.consumer.next_event();
                event.deinit(gpa);
            }
        }
    }.body);
}

test "inflight: complete panics on a missing key" {
    // commonware `test_complete_panics_on_missing_key` (`should_panic`, "inflight entry").
    try utils.death.expect_panic(@src(), "attempt to use null value", struct {
        fn body() !void {
            try run(struct {
                fn run_body(io: Io) !void {
                    var f: Fixture = undefined;
                    try f.init(io);
                    defer f.deinit();
                    f.inflight.complete(io, key(1));
                }
            }.run_body);
        }
    }.body);
}
