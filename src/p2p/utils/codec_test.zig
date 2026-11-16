//! Tests for the codec wrappers (commonware `p2p/src/utils/codec.rs` tests), run on the
//! deterministic runtime over the simulated network or a mock receiver.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const gpa = testing.allocator;
const codec = @import("codec");
const parallel = @import("parallel");
const utils_pkg = @import("utils");
const metrics = @import("runtime").telemetry.metrics;

const p2p = @import("../root.zig");
const codec_utils = @import("codec.zig");
const net = @import("../simulated/network_test.zig");

const Key = net.Key;
const Message = p2p.Message(Key);
const mpsc = utils_pkg.channel.mpsc;
const Quota = p2p.Quota;
const Feedback = p2p.Feedback;

const test_quota = Quota.per_second(64);
const link = net.link_ms(0, 0, 1.0);

/// A receiver over an unbounded queue with a fixed reported capacity. Counts its `recv`
/// calls when `received` is set (commonware's `CountingReceiver`).
const MockReceiver = struct {
    pub const PublicKey = Key;

    receiver: mpsc.Receiver(Message),
    capacity_value: usize,
    received: ?*std.atomic.Value(usize) = null,

    pub fn recv(self: *MockReceiver) (Io.Cancelable || error{BrokenPipe})!Message {
        if (self.received) |received| _ = received.fetchAdd(1, .seq_cst);
        return (try self.receiver.recv()) orelse error.BrokenPipe;
    }

    pub fn capacity(self: *const MockReceiver) usize {
        return self.capacity_value;
    }

    pub fn deinit(self: *MockReceiver) void {
        while (self.receiver.try_recv()) |message| {
            var owned = message;
            owned.deinit();
        } else |_| {}
        self.receiver.deinit();
    }
};

const NoopBlocker = struct {
    pub const PublicKey = Key;

    pub fn block(_: NoopBlocker, _: Key) Feedback {
        return .ok;
    }

    pub fn blocked(_: NoopBlocker) error{}!void {}
};

/// Queues an owned copy of `value`'s encoding from `peer`.
fn queue_encoded(sender: mpsc.Sender(Message), peer: Key, comptime V: type, value: V) !void {
    const payload = try codec.encode(V, gpa, value);
    errdefer gpa.free(payload);
    try sender.send(.{ .peer = peer, .payload = payload, .gpa = gpa });
}

fn send_u32(sender: *net.Net.Sender, to: Key, value: u32) !void {
    const encoded = codec.encode_fixed(u32, value);
    _ = try net.send_one(sender, to, &encoded, true);
}

/// Two peers on the simulated network, linked both ways, with a background receiver on
/// peer 1's channel 0 using `strategy`.
fn Pair(comptime T: type) type {
    return struct {
        const Self = @This();
        const Background = codec_utils.WrappedBackgroundReceiver(
            net.Net.Control,
            net.Net.Receiver,
            u32,
            T,
        );

        harness: net.Harness,
        registry: *metrics.Registry,
        keys: [3]Key,
        sender: net.Net.Sender,
        rx: Background.Receiver,
        task: Io.Future(void),

        fn start(self: *Self, io: Io, strategy: T) !void {
            self.harness = try net.Harness.start(io, net.config(3, 1));
            errdefer self.harness.deinit();
            self.keys = .{ net.key(0), net.key(1), net.key(2) };
            const oracle = self.harness.oracle();
            try self.harness.track(&self.keys);
            try link_both(oracle, self.keys[0], self.keys[1]);
            var one = try oracle.control(self.keys[0]).register(0, test_quota);
            one.receiver.deinit();
            self.sender = one.sender;
            var two = try oracle.control(self.keys[1]).register(0, test_quota);
            two.sender.deinit();
            self.registry = try gpa.create(metrics.Registry);
            self.registry.* = .init(gpa);
            const scope = metrics.Scope.init(self.registry).child("bg");
            const created = try Background.init(
                gpa,
                io,
                &scope,
                two.receiver,
                {},
                oracle.control(self.keys[1]),
                strategy,
            );
            self.rx = created.receiver;
            self.task = try created.background.start();
        }

        fn expect_from(self: *Self, from: Key) !u32 {
            const message = (try self.rx.recv()).?;
            try testing.expect(Key.order(message.peer, from) == .eq);
            return message.value;
        }

        fn expect_blocked(self: *Self, blocker: Key, blocked: Key, innocent: ?Key) !void {
            const oracle = self.harness.oracle();
            while (true) {
                const pairs = try oracle.blocked(gpa);
                defer gpa.free(pairs);
                var found = false;
                for (pairs) |pair| {
                    if (Key.order(pair.origin, blocker) != .eq) continue;
                    if (innocent) |key| try testing.expect(Key.order(pair.recipient, key) != .eq);
                    found = found or Key.order(pair.recipient, blocked) == .eq;
                }
                if (found) return;
                try self.harness.io.sleep(.fromMilliseconds(1), .awake);
            }
        }

        fn deinit(self: *Self) void {
            self.harness.network.close();
            self.task.await(self.harness.io);
            self.rx.deinit();
            self.sender.deinit();
            self.harness.deinit();
            self.registry.deinit();
            gpa.destroy(self.registry);
        }
    };
}

fn link_both(oracle: net.Net.Oracle, a: Key, b: Key) !void {
    try oracle.add_link(a, b, link);
    try oracle.add_link(b, a, link);
}

fn expect_metric(registry: *metrics.Registry, line: []const u8) !void {
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    if (std.mem.indexOf(u8, text, line) == null) {
        std.debug.print("missing metric line {s} in:\n{s}\n", .{ line, text });
        return error.MissingMetric;
    }
}

test "valid messages are forwarded" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var pair: Pair(parallel.Sequential) = undefined;
            try pair.start(io, parallel.sequential);
            defer pair.deinit();
            try send_u32(&pair.sender, pair.keys[1], 42);
            try testing.expectEqual(42, try pair.expect_from(pair.keys[0]));
        }
    }.run);
}

test "invalid codec blocks peer" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var pair: Pair(parallel.Sequential) = undefined;
            try pair.start(io, parallel.sequential);
            defer pair.deinit();
            // A truncated payload (1 byte, but u32 needs 4).
            _ = try net.send_one(&pair.sender, pair.keys[1], &.{0xFF}, true);
            // Then a valid message from a different peer confirms the receiver still runs.
            const oracle = pair.harness.oracle();
            try link_both(oracle, pair.keys[2], pair.keys[1]);
            var three = try oracle.control(pair.keys[2]).register(0, test_quota);
            defer three.deinit();
            try send_u32(&three.sender, pair.keys[1], 99);
            try testing.expectEqual(99, try pair.expect_from(pair.keys[2]));
            try pair.expect_blocked(pair.keys[1], pair.keys[0], null);
            try expect_metric(pair.registry, "bg_decode_total{status=\"Invalid\"} 1\n");
        }
    }.run);
}

test "multiple valid messages" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var pair: Pair(parallel.Sequential) = undefined;
            try pair.start(io, parallel.sequential);
            defer pair.deinit();
            try expect_burst(&pair, 20);
        }
    }.run);
}

/// Sends `0..count` from peer 0 and expects every value at peer 1, in any order.
fn expect_burst(pair: anytype, comptime count: u32) !void {
    for (0..count) |i| try send_u32(&pair.sender, pair.keys[1], @intCast(i));
    var received: [count]u32 = undefined;
    for (&received) |*value| value.* = try pair.expect_from(pair.keys[0]);
    std.mem.sort(u32, &received, {}, std.sort.asc(u32));
    for (received, 0..) |value, i| try testing.expectEqual(i, value);
}

test "decode with strategy" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            const strategy = try parallel.mocks.inlined(gpa, io, 4);
            defer strategy.pool.destroy();
            var pair: Pair(parallel.Rayon) = undefined;
            try pair.start(io, strategy);
            defer pair.deinit();
            // Keep the message count below the mailbox capacity so every decode is checked.
            try expect_burst(&pair, 50);
        }
    }.run);
}

test "invalid among valid only blocks offender" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var pair: Pair(parallel.Sequential) = undefined;
            try pair.start(io, parallel.sequential);
            defer pair.deinit();
            const oracle = pair.harness.oracle();
            try link_both(oracle, pair.keys[2], pair.keys[1]);
            var three = try oracle.control(pair.keys[2]).register(0, test_quota);
            defer three.deinit();
            try send_u32(&three.sender, pair.keys[1], 10);
            _ = try net.send_one(&pair.sender, pair.keys[1], &.{0xFF}, true);
            try send_u32(&three.sender, pair.keys[1], 20);
            var values: [2]u32 = undefined;
            for (&values) |*value| value.* = try pair.expect_from(pair.keys[2]);
            std.mem.sort(u32, &values, {}, std.sort.asc(u32));
            try testing.expectEqualSlices(u32, &.{ 10, 20 }, &values);
            try pair.expect_blocked(pair.keys[1], pair.keys[0], pair.keys[2]);
        }
    }.run);
}

/// A background receiver over a `MockReceiver` and a `NoopBlocker`.
fn MockBackground(comptime V: type, comptime T: type) type {
    return codec_utils.WrappedBackgroundReceiver(NoopBlocker, MockReceiver, V, T);
}

test "decoded mailbox holds receiver capacity" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            // Queue more messages than the decoded mailbox can hold.
            const capacity = 3;
            const overflow = 2;
            var channel = try mpsc.unbounded(Message, gpa, io);
            for (0..capacity + overflow) |i| {
                try queue_encoded(channel.sender, net.key(0), u32, @intCast(i));
            }
            channel.sender.deinit();
            var registry: metrics.Registry = .init(gpa);
            defer registry.deinit();
            const scope = metrics.Scope.init(&registry).child("bg");
            const Background = MockBackground(u32, parallel.Sequential);
            const created = try Background.init(gpa, io, &scope, .{
                .receiver = channel.receiver,
                .capacity_value = capacity,
            }, {}, .{}, parallel.sequential);
            var rx = created.receiver;
            defer rx.deinit();
            // Keep the metric registered after the receiver exits.
            var decode = created.background.decode.clone();
            defer decode.deinit();
            // Finish decoding before consuming any messages.
            var task = try created.background.start();
            task.await(io);
            // Only the first `capacity` messages survive.
            for (0..capacity) |expected| {
                const message = (try rx.recv()).?;
                try testing.expect(Key.order(message.peer, net.key(0)) == .eq);
                try testing.expectEqual(expected, message.value);
            }
            try testing.expectEqual(null, try rx.recv());
            try expect_metric(&registry, "bg_decode_total{status=\"Dropped\"} 2\n");
            try expect_metric(&registry, "bg_decode_total{status=\"Success\"} 3\n");
            comptime assert(overflow == 2 and capacity == 3);
        }
    }.run);
}

test "pending decodes do not stall raw receives" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            const strategy = try parallel.mocks.pending(gpa, io, 2);
            defer strategy.pool.destroy();
            var channel = try mpsc.unbounded(Message, gpa, io);
            defer channel.sender.deinit();
            const count = 10;
            for (0..count) |i| try queue_encoded(channel.sender, net.key(0), u32, @intCast(i));
            var received: std.atomic.Value(usize) = .init(0);
            var registry: metrics.Registry = .init(gpa);
            defer registry.deinit();
            const scope = metrics.Scope.init(&registry).child("bg");
            const created = try MockBackground(u32, parallel.Rayon).init(gpa, io, &scope, .{
                .receiver = channel.receiver,
                .capacity_value = 16,
                .received = &received,
            }, {}, .{}, strategy);
            var rx = created.receiver;
            defer rx.deinit();
            var task = try created.background.start();
            // The receiver reads all `count` messages, then calls `recv` once more.
            while (received.load(.seq_cst) < count + 1) try io.sleep(.fromMilliseconds(1), .awake);
            _ = task.cancel(io);
        }
    }.run);
}

test "drain decode pool after receiver closure" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var channel = try mpsc.unbounded(Message, gpa, io);
            const count = 64;
            for (0..count) |i| try queue_encoded(channel.sender, net.key(0), u32, @intCast(i));
            channel.sender.deinit();
            var registry: metrics.Registry = .init(gpa);
            defer registry.deinit();
            const scope = metrics.Scope.init(&registry).child("bg");
            const Background = MockBackground(u32, parallel.Sequential);
            const created = try Background.init(gpa, io, &scope, .{
                .receiver = channel.receiver,
                .capacity_value = 64,
            }, {}, .{}, parallel.sequential);
            var rx = created.receiver;
            defer rx.deinit();
            var task = try created.background.start();
            defer task.await(io);
            var values: [count]u32 = undefined;
            var len: usize = 0;
            while (try rx.recv()) |message| : (len += 1) {
                try testing.expect(Key.order(message.peer, net.key(0)) == .eq);
                values[len] = message.value;
            }
            try testing.expectEqual(count, len);
            std.mem.sort(u32, &values, {}, std.sort.asc(u32));
            for (values, 0..) |value, i| try testing.expectEqual(i, value);
        }
    }.run);
}

/// Eight 17-byte fields (commonware's `Vec<IoBuf>` of `vec![1u8; 17]`).
const Fields = []const []const u8;
const fields_cfg: codec.Cfg(Fields) = .{ .range = .full(), .item = .{ .range = .full() } };
const field: [17]u8 = @splat(1);
const fields_value: [8][]const u8 = @splat(&field);

fn expect_fields(decoded: Fields) !void {
    try testing.expectEqual(fields_value.len, decoded.len);
    for (decoded) |item| try testing.expectEqualSlices(u8, &field, item);
}

test "recv decodes a frame (recv_view)" {
    // Payloads are byte slices, so the decoded fields are copies rather than views.
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var channel = try mpsc.unbounded(Message, gpa, io);
            defer channel.sender.deinit();
            try queue_encoded(channel.sender, net.key(0), Fields, &fields_value);
            const mock: MockReceiver = .{ .receiver = channel.receiver, .capacity_value = 1 };
            var receiver = codec_utils.WrappedReceiver(MockReceiver, Fields).init(
                gpa,
                fields_cfg,
                mock,
            );
            defer receiver.deinit();
            const message = try receiver.recv();
            try testing.expect(Key.order(message.peer, net.key(0)) == .eq);
            const decoded = try message.value;
            defer codec.free(Fields, gpa, decoded);
            try expect_fields(decoded);
        }
    }.run);
}

test "background recv decodes a frame (background_recv_view)" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            const strategy = try parallel.mocks.inlined(gpa, io, 2);
            defer strategy.pool.destroy();
            var channel = try mpsc.unbounded(Message, gpa, io);
            try queue_encoded(channel.sender, net.key(0), Fields, &fields_value);
            channel.sender.deinit();
            var registry: metrics.Registry = .init(gpa);
            defer registry.deinit();
            const scope = metrics.Scope.init(&registry).child("bg");
            const created = try MockBackground(Fields, parallel.Rayon).init(gpa, io, &scope, .{
                .receiver = channel.receiver,
                .capacity_value = 1,
            }, fields_cfg, .{}, strategy);
            var rx = created.receiver;
            defer rx.deinit();
            var task = try created.background.start();
            task.await(io);
            const message = (try rx.recv()).?;
            defer codec.free(Fields, gpa, message.value);
            try testing.expect(Key.order(message.peer, net.key(0)) == .eq);
            try expect_fields(message.value);
            try testing.expectEqual(null, try rx.recv());
        }
    }.run);
}

test "wrapped sender and receiver round trip" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var harness = try net.Harness.start(io, net.config(2, 1));
            defer harness.deinit();
            const oracle = harness.oracle();
            const keys = [_]Key{ net.key(0), net.key(1) };
            try harness.track(&keys);
            try link_both(oracle, keys[0], keys[1]);
            const one = try oracle.control(keys[0]).register(0, test_quota);
            var two = try oracle.control(keys[1]).register(0, test_quota);
            defer two.sender.deinit();
            var wrapped_one = codec_utils.wrap(u64, gpa, {}, one.sender, one.receiver);
            defer wrapped_one.sender.deinit();
            defer wrapped_one.receiver.deinit();
            var receiver = codec_utils.WrappedReceiver(net.Net.Receiver, u64).init(
                gpa,
                {},
                two.receiver,
            );
            defer receiver.deinit();
            const sent = try wrapped_one.sender.send(.{ .one = keys[1] }, 0xDEAD_BEEF, false);
            defer gpa.free(sent);
            try testing.expectEqual(1, sent.len);
            const checked = switch (try wrapped_one.sender.check(.{ .one = keys[1] })) {
                .checked => |checked| checked,
                .limited => return error.Limited,
            };
            try testing.expectEqual(1, checked.recipients().len);
            try testing.expect(checked.send(7, true).accepted());
            for ([_]u64{ 0xDEAD_BEEF, 7 }) |expected| {
                const message = try receiver.recv();
                try testing.expect(Key.order(message.peer, keys[0]) == .eq);
                try testing.expectEqual(expected, try message.value);
            }
        }
    }.run);
}
