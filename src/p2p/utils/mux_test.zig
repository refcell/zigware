//! Tests for the muxer (commonware `p2p/src/utils/mux.rs` tests), run on the deterministic
//! runtime over the simulated network or a mock receiver.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const testing = std.testing;
const gpa = testing.allocator;
const codec = @import("codec");
const utils_pkg = @import("utils");

const p2p = @import("../root.zig");
const mux = @import("mux.zig");
const mocks = @import("mocks/mod.zig");
const net = @import("../simulated/network_test.zig");

const Key = net.Key;
const Message = p2p.Message(Key);
const mpsc = utils_pkg.channel.mpsc;
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;

/// Messages each burst sends per subchannel, and the mock receiver's capacity.
const capacity = 5;

/// Per-peer rate. Every test sends fewer messages than this burst from one peer.
const test_quota = p2p.Quota.per_second(32);

/// Largest payload the simulated network carries.
const max_size = 1024 * 1024;

const Mux = mux.Muxer(net.Net.Sender, net.Net.Receiver);
const Handle = Mux.Handle;
const Backup = mux.BackupResponse(Key);
const Global = mux.GlobalSender(net.Net.Sender);
const Registered = Handle.Registered;

/// A peer with a running muxer over its channel 0.
const Peer = struct {
    key: Key,
    handle: Handle,
    task: Io.Future(Mux.RunError!void),
    backup: ?mpsc.Receiver(Backup) = null,
    global: ?Global = null,
};

/// The simulated network and up to two peers with muxers. Release every subchannel receiver
/// before `deinit`, so the muxers stop.
const Fixture = struct {
    harness: net.Harness,
    peers: [2]Peer = undefined,
    count: usize = 0,

    fn start(io: Io) !Fixture {
        var config = net.config(2, 1);
        config.max_size = max_size;
        return .{ .harness = try net.Harness.start(io, config) };
    }

    fn add_peer(fixture: *Fixture, seed: u64, options: Mux.Options) !*Peer {
        assert(fixture.count < fixture.peers.len);
        const key = net.key(seed);
        const registered = try fixture.harness.oracle().control(key).register(0, test_quota);
        const io = fixture.harness.io;
        const built = try Mux.build(gpa, io, registered.sender, registered.receiver, options);
        const peer = &fixture.peers[fixture.count];
        peer.* = .{
            .key = key,
            .handle = built.handle,
            .task = try built.muxer.start(),
            .backup = built.backup,
            .global = built.global_sender,
        };
        fixture.count += 1;
        return peer;
    }

    /// Tracks every peer and links each pair both ways.
    fn link(fixture: *Fixture) !void {
        assert(fixture.count == 2);
        const a = fixture.peers[0].key;
        const b = fixture.peers[1].key;
        try fixture.harness.track(&.{ a, b });
        const oracle = fixture.harness.oracle();
        try oracle.add_link(a, b, net.link_ms(0, 0, 1.0));
        try oracle.add_link(b, a, net.link_ms(0, 0, 1.0));
    }

    fn deinit(fixture: *Fixture) void {
        const io = fixture.harness.io;
        for (fixture.peers[0..fixture.count]) |*peer| {
            if (peer.backup) |*backup| backup.deinit();
            if (peer.global) |*global| global.deinit();
            peer.handle.deinit();
            // A muxer stops cleanly once its handles are gone, or with the network.
            peer.task.await(io) catch |err| {
                if (err != error.NetworkClosed) std.debug.panic("muxer: {t}", .{err});
            };
        }
        fixture.harness.deinit();
    }
};

/// Registers `subchannel` and releases its sender, keeping the receiver.
fn register_receiver(peer: *Peer, subchannel: p2p.Channel) !mux.SubReceiver(Key) {
    var registered = try peer.handle.register(subchannel);
    registered.sender.deinit();
    return registered.receiver;
}

/// Registers `subchannel` and releases its receiver, keeping the sender.
fn register_sender(peer: *Peer, subchannel: p2p.Channel) !mux.SubSender(net.Net.Sender) {
    var registered = try peer.handle.register(subchannel);
    registered.receiver.deinit();
    return registered.sender;
}

/// Sends `count` one-byte messages to every peer on each of `senders`.
fn send_burst(senders: []mux.SubSender(net.Net.Sender), count: usize) !void {
    for (0..count) |i| {
        const payload = [_]u8{@intCast(i)};
        for (senders) |*sender| {
            const sent = try sender.send(.all, &.{&payload}, false);
            gpa.free(sent);
        }
    }
}

fn expect_n_messages(receiver: anytype, n: usize) !void {
    for (0..n) |_| {
        var message = try receiver.recv();
        message.deinit();
    }
}

fn expect_message(receiver: anytype, from: Key, payload: []const u8) !void {
    var message = try receiver.recv();
    defer message.deinit();
    try testing.expect(Key.order(message.peer, from) == .eq);
    try testing.expectEqualSlices(u8, payload, message.payload);
}

/// A sender whose every check is rate limited.
const RateLimitedSender = struct {
    pub const PublicKey = Key;
    pub const Checked = UnusedCheckedSender;

    pub fn check(_: *RateLimitedSender, _: p2p.Recipients(Key)) error{}!p2p.Check(Checked) {
        return .{ .limited = utils_pkg.SystemTime.UNIX_EPOCH };
    }

    pub fn clone(self: *const RateLimitedSender) RateLimitedSender {
        return self.*;
    }
};

const UnusedCheckedSender = struct {
    pub const PublicKey = Key;

    pub fn recipients(_: *const UnusedCheckedSender) []const Key {
        unreachable; // Proof: a rate-limited sender produces no checked sender.
    }

    pub fn send(_: UnusedCheckedSender, _: []const []const u8, _: bool) Unreliable(Feedback) {
        unreachable; // Proof: a rate-limited sender produces no checked sender.
    }
};

test "global sender rate limited send rejected" {
    var sender = mux.GlobalSender(RateLimitedSender).init(gpa, .{});
    const feedback = sender.send(0, .{ .one = net.key(0) }, &.{"rate-limited"}, false);
    try testing.expect(feedback == .rejected);
    try testing.expect(!feedback.accepted());
}

test "prefixed" {
    try testing.expectEqual(10, mux.prefixed(0));
    try testing.expectEqual(1034, mux.prefixed(1024));
    const max = std.math.maxInt(usize);
    try testing.expectEqual(max, mux.prefixed(max - 10));
}

test "parse splits the subchannel prefix" {
    var frame: [12]u8 = undefined;
    var writer = codec.Writer.init(&frame);
    codec.varint.write(u64, 300, &writer);
    writer.write_bytes("hi");
    const subchannel, const payload = try mux.parse(writer.written());
    try testing.expectEqual(300, subchannel);
    try testing.expectEqualSlices(u8, "hi", payload);
    try testing.expectError(error.EndOfBuffer, mux.parse(&.{0x80}));
}

test "sub sender accepts limit less prefix" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            const two = try fixture.add_peer(1, .{});
            try fixture.link();
            // Subchannel `maxInt(u64)` takes the longest prefix.
            var rx = try register_receiver(one, std.math.maxInt(u64));
            defer rx.deinit();
            var tx = try register_sender(two, std.math.maxInt(u64));
            defer tx.deinit();
            // A payload of the network limit less that prefix arrives intact.
            const payload = try gpa.alloc(u8, max_size - codec.varint.max_u64_varint_size);
            defer gpa.free(payload);
            @memset(payload, 0);
            gpa.free(try tx.send(.{ .one = one.key }, &.{payload}, false));
            try expect_message(&rx, two.key, payload);
        }
    }.run);
}

test "sub sender panics above limit less prefix" {
    // commonware `test_sub_sender_panics_above_limit_less_prefix`.
    try utils_pkg.death.expect_panic(@src(), "message too large", struct {
        fn body() !void {
            _ = try net.run_deterministic(0, struct {
                fn run(io: Io) !void {
                    var fixture = try Fixture.start(io);
                    defer fixture.deinit();
                    const one = try fixture.add_peer(0, .{});
                    const two = try fixture.add_peer(1, .{});
                    try fixture.link();
                    var tx = try register_sender(two, std.math.maxInt(u64));
                    defer tx.deinit();
                    // One byte above the limit less the longest prefix is too large once
                    // prefixed.
                    const size = max_size - codec.varint.max_u64_varint_size + 1;
                    const payload = try gpa.alloc(u8, size);
                    defer gpa.free(payload);
                    @memset(payload, 0);
                    gpa.free(try tx.send(.{ .one = one.key }, &.{payload}, false));
                }
            }.run);
        }
    }.body);
}

test "basic routing" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            const two = try fixture.add_peer(1, .{});
            try fixture.link();
            var rx = try register_receiver(one, 7);
            defer rx.deinit();
            var tx = try register_sender(two, 7);
            defer tx.deinit();
            gpa.free(try tx.send(.{ .one = one.key }, &.{"hello"}, false));
            try expect_message(&rx, two.key, "hello");
        }
    }.run);
}

test "multiple routes" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            const two = try fixture.add_peer(1, .{});
            try fixture.link();
            var rx_a = try register_receiver(one, 10);
            defer rx_a.deinit();
            var rx_b = try register_receiver(one, 20);
            defer rx_b.deinit();
            var tx_a = try register_sender(two, 10);
            defer tx_a.deinit();
            var tx_b = try register_sender(two, 20);
            defer tx_b.deinit();
            gpa.free(try tx_a.send(.{ .one = one.key }, &.{"A"}, false));
            gpa.free(try tx_b.send(.{ .one = one.key }, &.{"B"}, false));
            try expect_message(&rx_a, two.key, "A");
            try expect_message(&rx_b, two.key, "B");
        }
    }.run);
}

/// A receiver with an unbounded input queue and a fixed reported capacity.
const MockReceiver = struct {
    pub const PublicKey = Key;

    receiver: mpsc.Receiver(Message),
    capacity_value: usize,

    pub fn recv(self: *MockReceiver) (Io.Cancelable || error{RecvFailed})!Message {
        return (try self.receiver.recv()) orelse error.RecvFailed;
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

test "mailbox capacity drops when full" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            // Subchannels report the capacity of the receiver the muxer wraps.
            var queue = try mpsc.unbounded(Message, gpa, io);
            defer queue.sender.deinit();
            const peers = [_]Key{net.key(0)};
            const inert = mocks.inert_channel(Key, gpa, io, &peers);
            const Muxer = mux.Muxer(mocks.InertSender(Key), MockReceiver);
            const created = try Muxer.init(gpa, io, inert.sender, .{
                .receiver = queue.receiver,
                .capacity_value = capacity,
            });
            var handle = created.handle;
            var task = try created.muxer.start();
            var one = try handle.register(99);
            one.sender.deinit();
            var two = try handle.register(100);
            two.sender.deinit();
            try testing.expectEqual(capacity, one.receiver.capacity());
            try testing.expectEqual(capacity, two.receiver.capacity());

            // Queue twice the capacity for each subchannel before reading either one.
            for (0..capacity * 2) |i| {
                for ([_]u64{ 99, 100 }) |subchannel| {
                    const frame = try gpa.alloc(u8, 2);
                    frame[0] = @intCast(subchannel);
                    frame[1] = @intCast(i);
                    try queue.sender.send(.{ .peer = net.key(1), .payload = frame, .gpa = gpa });
                }
            }

            // Each subchannel retains exactly its capacity.
            for ([_]*mux.SubReceiver(Key){ &one.receiver, &two.receiver }) |rx| {
                try expect_n_messages(rx, capacity);
                try io.sleep(.fromMilliseconds(10), .awake);
                try testing.expectError(error.Empty, rx.try_recv());
            }
            one.receiver.deinit();
            two.receiver.deinit();
            handle.deinit();
            try task.await(io);
        }
    }.run);
}

test "drop subchannel receiver deregisters route" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            const two = try fixture.add_peer(1, .{});
            try fixture.link();
            var senders = [_]mux.SubSender(net.Net.Sender){
                try register_sender(one, 99),
                try register_sender(one, 100),
            };
            defer for (&senders) |*sender| sender.deinit();
            var rx1 = try register_receiver(two, 99);
            var rx2 = try register_receiver(two, 100);
            defer rx2.deinit();
            // Drop rx1 before any messages are sent, so its route is deregistered.
            rx1.deinit();
            // Messages to subchannel 99 are dropped; rx2 receives all of subchannel 100's.
            try send_burst(&senders, capacity);
            try expect_n_messages(&rx2, capacity);
        }
    }.run);
}

test "drop messages for unregistered subchannel" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            const two = try fixture.add_peer(1, .{});
            try fixture.link();
            var senders = [_]mux.SubSender(net.Net.Sender){
                try register_sender(one, 1),
                try register_sender(one, 2),
            };
            defer for (&senders) |*sender| sender.deinit();
            // Subchannel 1 is not registered on the second peer.
            var rx2 = try register_receiver(two, 2);
            defer rx2.deinit();
            try send_burst(&senders, capacity);
            try expect_n_messages(&rx2, capacity);
        }
    }.run);
}

test "backup for unregistered subchannel" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            const two = try fixture.add_peer(1, .{ .backup = true, .global_sender = true });
            try fixture.link();
            var senders = [_]mux.SubSender(net.Net.Sender){
                try register_sender(one, 1),
                try register_sender(one, 2),
            };
            defer for (&senders) |*sender| sender.deinit();
            var rx2 = try register_receiver(two, 2);
            defer rx2.deinit();
            // Subchannel 1 messages go to the backup, subchannel 2 messages to rx2.
            try send_burst(&senders, capacity);
            try expect_n_messages(&rx2, capacity);
            for (0..capacity) |_| {
                var response = (try two.backup.?.recv()).?;
                defer response.deinit();
                try testing.expectEqual(1, response.subchannel);
            }
        }
    }.run);
}

test "backup for unregistered subchannel response" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            const two = try fixture.add_peer(1, .{ .backup = true, .global_sender = true });
            try fixture.link();
            // No subchannels are registered on the second peer.
            var registered = try one.handle.register(1);
            defer registered.receiver.deinit();
            defer registered.sender.deinit();
            const tx1 = &registered.sender;
            gpa.free(try tx1.send(.{ .one = two.key }, &.{"REQUEST"}, false));

            // Take the message from the second peer's backup channel and respond.
            var response = (try two.backup.?.recv()).?;
            defer response.deinit();
            try testing.expectEqual(1, response.subchannel);
            try testing.expect(Key.order(response.message.peer, one.key) == .eq);
            const checked = switch (try two.global.?.check(.{ .one = one.key })) {
                .checked => |checked| checked,
                .limited => return error.Limited,
            };
            try testing.expectEqual(1, checked.recipients().len);
            try testing.expect(Key.order(checked.recipients()[0], one.key) == .eq);
            const feedback = checked.with_subchannel(response.subchannel).send(&.{"TEST"}, true);
            try testing.expect(feedback.accepted());

            // The first peer's receiver gets the response.
            try expect_message(&registered.receiver, two.key, "TEST");
        }
    }.run);
}

test "message dropped for closed subchannel" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            const two = try fixture.add_peer(1, .{});
            try fixture.link();
            var tx1 = try register_sender(one, 1);
            defer tx1.deinit();
            var tx2 = try register_sender(one, 2);
            defer tx2.deinit();
            var rx1 = try register_receiver(two, 1);
            var rx2 = try register_receiver(two, 2);
            defer rx2.deinit();
            // Close the first subchannel, then send to it: it must not block subchannel 2.
            rx1.deinit();
            gpa.free(try tx1.send(.{ .one = two.key }, &.{"closed"}, false));
            gpa.free(try tx2.send(.{ .one = two.key }, &.{"open"}, false));
            try expect_message(&rx2, one.key, "open");
        }
    }.run);
}

test "dropped backup channel doesn't block" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            const two = try fixture.add_peer(1, .{ .backup = true, .global_sender = true });
            try fixture.link();
            // Drop the backup receiver.
            two.backup.?.deinit();
            two.backup = null;
            var senders = [_]mux.SubSender(net.Net.Sender){
                try register_sender(one, 1),
                try register_sender(one, 2),
            };
            defer for (&senders) |*sender| sender.deinit();
            var rx2 = try register_receiver(two, 2);
            defer rx2.deinit();
            // Subchannel 1 messages are dropped (the backup is closed).
            try send_burst(&senders, capacity);
            try expect_n_messages(&rx2, capacity);
        }
    }.run);
}

test "duplicate registration" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            var rx = try register_receiver(one, 7);
            defer rx.deinit();
            try testing.expectError(error.AlreadyRegistered, one.handle.register(7));
        }
    }.run);
}

test "register after deregister" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            var rx = try register_receiver(one, 7);
            rx.deinit();
            var again = try one.handle.register(7);
            again.sender.deinit();
            again.receiver.deinit();
        }
    }.run);
}

test "registering on a stopped muxer fails" {
    _ = try net.run_deterministic(0, struct {
        fn run(io: Io) !void {
            var fixture = try Fixture.start(io);
            defer fixture.deinit();
            const one = try fixture.add_peer(0, .{});
            var clone = one.handle.clone();
            defer clone.deinit();
            // Closing the network fails the wrapped receiver, which stops the muxer.
            fixture.harness.network.close();
            try testing.expectError(error.NetworkClosed, one.task.await(io));
            try testing.expectError(error.Closed, clone.register(7));
        }
    }.run);
}
