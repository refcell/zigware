//! The production TCP network against the network conformance suite, and tokio's own tests
//! (commonware `runtime/src/network/tokio.rs`).

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const network = @import("../network.zig");
const production = @import("network.zig");

const Network = production.Network;

fn new_network(io: Io) Network {
    return .init(testing.allocator, io, .{});
}

test "tcp network passes the network suite (run_network_tests)" {
    try network.tests.run_network_tests(testing.io, Network, new_network);
}

test "tcp network passes the stress suite (stress_concurrent_streams)" {
    try network.tests.run_network_stress_tests(testing.io, Network, new_network);
}

const builtin = @import("builtin");
const net = Io.net;
const Address = network.Address;
const any_port: Address = .{ .ip4 = .loopback(0) };

fn accept_and_recv(listener: *Network.Listener, out: []u8) !Network.Accepted {
    var accepted = try listener.accept();
    errdefer accepted.deinit();
    try accepted.stream.recv(out);
    return accepted;
}

fn now(io: Io) Io.Clock.Timestamp {
    return Io.Clock.Timestamp.now(io, .awake);
}

test "a small message reads well before the timeout (test_small_send_read_quickly)" {
    const io = testing.io;
    var tcp: Network = .init(testing.allocator, io, .{ .read_timeout = .fromSeconds(30) });
    defer tcp.deinit();
    const listener = try tcp.bind(any_port);
    defer listener.deinit();
    var received: [10]u8 = undefined;
    const start = now(io);
    var reader = try io.concurrent(accept_and_recv, .{ listener, &received });
    var connection = try tcp.dial(listener.local_addr());
    defer connection.deinit();
    const message = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    try connection.sink.send(&.{&message});
    var accepted = try reader.await(io);
    defer accepted.deinit();
    try testing.expectEqualSlices(u8, &message, &received);
    try testing.expect(start.durationTo(now(io)).raw.toSeconds() < 30);
}

fn accept_and_expect_timeout(io: Io, listener: *Network.Listener) !Network.Accepted {
    var accepted = try listener.accept();
    errdefer accepted.deinit();
    var buffer: [100]u8 = undefined;
    const start = now(io);
    try testing.expectError(error.Timeout, accepted.stream.recv(&buffer));
    const elapsed_ms = start.durationTo(now(io)).raw.toMilliseconds();
    try testing.expect(elapsed_ms >= 100 and elapsed_ms < 200);
    try testing.expectError(error.Closed, accepted.stream.recv(buffer[0..1]));
    return accepted;
}

test "a recv of partial data times out (test_read_timeout_with_partial_data)" {
    const io = testing.io;
    var tcp: Network = .init(testing.allocator, io, .{ .read_timeout = .fromMilliseconds(100) });
    defer tcp.deinit();
    const listener = try tcp.bind(any_port);
    defer listener.deinit();
    var reader = try io.concurrent(accept_and_expect_timeout, .{ io, listener });
    var connection = try tcp.dial(listener.local_addr());
    defer connection.deinit();
    try connection.sink.send(&.{&[_]u8{ 1, 2, 3, 4, 5 }});
    var accepted = try reader.await(io);
    defer accepted.deinit();
}

fn accept_unbuffered(listener: *Network.Listener, out: *[2][5]u8) !Network.Accepted {
    var accepted = try listener.accept();
    errdefer accepted.deinit();
    const stream = &accepted.stream;
    try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
    for (out) |*message| {
        try stream.recv(message);
        try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
    }
    return accepted;
}

test "a zero read buffer reads unbuffered (test_unbuffered_mode)" {
    const io = testing.io;
    var tcp: Network = .init(testing.allocator, io, .{ .read_buffer_size = 0 });
    defer tcp.deinit();
    const listener = try tcp.bind(any_port);
    defer listener.deinit();
    var received: [2][5]u8 = undefined;
    var reader = try io.concurrent(accept_unbuffered, .{ listener, &received });
    var connection = try tcp.dial(listener.local_addr());
    defer connection.deinit();
    try connection.sink.send(&.{&[_]u8{ 1, 2, 3, 4, 5 }});
    try connection.sink.send(&.{&[_]u8{ 6, 7, 8, 9, 10 }});
    var accepted = try reader.await(io);
    defer accepted.deinit();
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, &received[0]);
    try testing.expectEqualSlices(u8, &.{ 6, 7, 8, 9, 10 }, &received[1]);
}

fn accept_and_peek(listener: *Network.Listener) !Network.Accepted {
    var accepted = try listener.accept();
    errdefer accepted.deinit();
    const stream = &accepted.stream;
    try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
    var first: [5]u8 = undefined;
    try stream.recv(&first);
    try testing.expectEqualStrings("hello", &first);
    try testing.expectEqualStrings(" world", stream.peek(100));
    try testing.expectEqualStrings(" world", stream.peek(100));
    try testing.expectEqualStrings(" wo", stream.peek(3));
    var rest: [6]u8 = undefined;
    try stream.recv(&rest);
    try testing.expectEqualStrings(" world", &rest);
    try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
    return accepted;
}

test "peek sees the buffered remainder (test_peek_with_buffered_data)" {
    const io = testing.io;
    var tcp = new_network(io);
    defer tcp.deinit();
    const listener = try tcp.bind(any_port);
    defer listener.deinit();
    var reader = try io.concurrent(accept_and_peek, .{listener});
    var connection = try tcp.dial(listener.local_addr());
    defer connection.deinit();
    try connection.sink.send(&.{"hello world"});
    var accepted = try reader.await(io);
    defer accepted.deinit();
}

test "a dial to a full accept queue times out (test_connect_timeout)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;
    // A backlog of zero queues one connection; the next stays pending.
    var server = try any_port.listen(io, .{ .kernel_backlog = 0 });
    defer server.deinit(io);
    const queued = try server.socket.address.connect(io, .{ .mode = .stream });
    defer queued.close(io);
    var tcp: Network = .init(testing.allocator, io, .{ .connect_timeout = .fromMilliseconds(100) });
    defer tcp.deinit();
    const start = now(io);
    try testing.expectError(error.Timeout, tcp.dial(server.socket.address));
    const elapsed_ms = start.durationTo(now(io)).raw.toMilliseconds();
    try testing.expect(elapsed_ms >= 100 and elapsed_ms < 200);
}
