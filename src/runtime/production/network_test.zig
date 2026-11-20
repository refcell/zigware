//! The production TCP network against the network conformance suite, and tokio's own tests
//! (commonware `runtime/src/network/tokio.rs`).

const std = @import("std");
const build_options = @import("build_options");
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

test "tcp network passes the stress suite (stress_concurrent_streams, slow)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    try network.tests.run_network_stress_tests(testing.io, Network, new_network);
}

const builtin = @import("builtin");
const net = Io.net;
const Address = network.Address;
const Error = network.Error;
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

fn accept_and_close(listener: *Network.Listener) !void {
    var accepted = try listener.accept();
    accepted.deinit();
}

test "a port rebinds while its closed connection is in TIME_WAIT (SO_REUSEADDR)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;
    // Without zero linger, the side that closes first keeps the port in TIME_WAIT.
    var tcp: Network = .init(testing.allocator, io, .{ .zero_linger = false });
    defer tcp.deinit();
    const listener = try tcp.bind(any_port);
    const address = listener.local_addr();
    var acceptor = try io.concurrent(accept_and_close, .{listener});
    var connection = try tcp.dial(address);
    try acceptor.await(io);
    var byte: [1]u8 = undefined;
    try testing.expectError(error.RecvFailed, connection.stream.recv(&byte));
    connection.deinit();
    listener.deinit();
    const rebound = try tcp.bind(address);
    defer rebound.deinit();
    try testing.expectEqual(address.getPort(), rebound.local_addr().getPort());
}

test "a dial to a full accept queue times out (test_connect_timeout)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;
    // A backlog of zero queues one connection; the next stays pending.
    var server = try any_port.listen(io, .{ .kernel_backlog = 0 });
    defer server.deinit(io);
    const queued = try production.connect(io, server.socket.address, .fromSeconds(10));
    defer queued.close(io);
    var tcp: Network = .init(testing.allocator, io, .{ .connect_timeout = .fromMilliseconds(100) });
    defer tcp.deinit();
    const start = now(io);
    try testing.expectError(error.Timeout, tcp.dial(server.socket.address));
    const elapsed_ms = start.durationTo(now(io)).raw.toMilliseconds();
    try testing.expect(elapsed_ms >= 100 and elapsed_ms < 200);
}

fn dial_pending(tcp: *Network, address: Address) anyerror!void {
    var connection = try tcp.dial(address);
    connection.deinit();
    return error.TestUnexpectedResult; // The accept queue is full: the dial never connects.
}

test "canceling a pending dial returns promptly" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;
    // A backlog of zero queues one connection; the next stays pending.
    var server = try any_port.listen(io, .{ .kernel_backlog = 0 });
    defer server.deinit(io);
    const queued = try production.connect(io, server.socket.address, .fromSeconds(10));
    defer queued.close(io);
    var tcp: Network = .init(testing.allocator, io, .{ .connect_timeout = .fromSeconds(30) });
    defer tcp.deinit();
    var dial = try io.concurrent(dial_pending, .{ &tcp, server.socket.address });
    try io.sleep(.fromMilliseconds(50), .awake);
    const start = now(io);
    try testing.expectError(error.Canceled, dial.cancel(io));
    try testing.expect(start.durationTo(now(io)).raw.toMilliseconds() < 1000);
}

const Ring = @import("ring.zig").Ring;

/// The ring every io_uring network test shares, or null where io_uring is unavailable.
var test_ring: Ring = undefined;

fn new_ring_network(io: Io) Network {
    return .init(testing.allocator, io, .{ .ring = &test_ring });
}

fn init_test_ring() !void {
    return @import("ring_test.zig").init_or_skip(&test_ring, .{});
}

test "io_uring tcp network passes the network suite (run_network_tests)" {
    try init_test_ring();
    defer test_ring.deinit();
    try network.tests.run_network_tests(testing.io, Network, new_ring_network);
}

test "io_uring tcp network passes the stress suite (stress_concurrent_streams, slow)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    try init_test_ring();
    defer test_ring.deinit();
    try network.tests.run_network_stress_tests(testing.io, Network, new_ring_network);
}

test "an io_uring recv of partial data times out (test_read_timeout_with_partial_data)" {
    try init_test_ring();
    defer test_ring.deinit();
    const io = testing.io;
    var tcp: Network = .init(testing.allocator, io, .{
        .read_timeout = .fromMilliseconds(100),
        .ring = &test_ring,
    });
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

/// A network with `config`, over the shared test ring when `ring` is set.
fn network_with(config: production.Config, ring: bool) Network {
    var with_ring = config;
    if (ring) with_ring.ring = &test_ring;
    return .init(testing.allocator, testing.io, with_ring);
}

/// One loopback connection: a dial completes into the accept queue, so one task drives both
/// ends and controls what each of the stream's fills sees.
const Pair = struct {
    listener: *Network.Listener,
    connection: Network.Connection,
    accepted: Network.Accepted,

    fn init(tcp: *Network) !Pair {
        const listener = try tcp.bind(any_port);
        errdefer listener.deinit();
        var connection = try tcp.dial(listener.local_addr());
        errdefer connection.deinit();
        const accepted = try listener.accept();
        return .{ .listener = listener, .connection = connection, .accepted = accepted };
    }

    fn deinit(pair: *Pair) void {
        pair.accepted.deinit();
        pair.connection.deinit();
        pair.listener.deinit();
    }
};

/// Runs `body(ring)` on std.Io, then over io_uring where the kernel gives a ring.
fn on_both(comptime body: fn (bool) anyerror!void) !void {
    try body(false);
    init_test_ring() catch return; // Skipped: the kernel gives no ring.
    defer test_ring.deinit();
    try body(true);
}

fn empty_operations(ring: bool) !void {
    var tcp = network_with(.{}, ring);
    defer tcp.deinit();
    var pair = try Pair.init(&tcp);
    defer pair.deinit();
    try testing.expectEqual(@as(usize, 0), pair.accepted.stream.peek(1).len);
    try pair.accepted.sink.send(&.{});
    try pair.accepted.sink.send(&.{""});
    try pair.accepted.stream.recv(&.{});
}

test "empty sends, recv(0), and peek on a fresh accept succeed" {
    // commonware `test_queued_accept_and_empty_operations_without_worker`.
    try on_both(empty_operations);
}

fn unbuffered(ring: bool) !void {
    var tcp = network_with(.{ .read_buffer_size = 0 }, ring);
    defer tcp.deinit();
    var pair = try Pair.init(&tcp);
    defer pair.deinit();
    const stream = &pair.accepted.stream;
    for ([_][5]u8{ .{ 1, 2, 3, 4, 5 }, .{ 6, 7, 8, 9, 10 } }) |message| {
        try pair.connection.sink.send(&.{&message});
        try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
        var received: [5]u8 = undefined;
        try stream.recv(&received);
        try testing.expectEqualSlices(u8, &message, &received);
        try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
    }
}

test "a zero read buffer reads unbuffered, also over io_uring (iouring.rs test_unbuffered_mode)" {
    try on_both(unbuffered);
}

fn expect_recv(stream: *production.Stream, comptime expected: []const u8) !void {
    var received: [expected.len]u8 = undefined;
    try stream.recv(&received);
    try testing.expectEqualStrings(expected, &received);
}

fn buffered_peek(ring: bool) !void {
    var tcp = network_with(.{ .read_buffer_size = 64 }, ring);
    defer tcp.deinit();
    var pair = try Pair.init(&tcp);
    defer pair.deinit();
    const sink = &pair.connection.sink;
    const stream = &pair.accepted.stream;
    try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
    try sink.send(&.{"hello world"});
    try expect_recv(stream, "hello");
    // Peeking does not consume bytes and respects the requested limit.
    try testing.expectEqualStrings(" world", stream.peek(100));
    try testing.expectEqualStrings(" wo", stream.peek(3));
    try testing.expectEqual(@as(usize, 0), stream.peek(0).len);
    // A shorter refill replaces the previous readable extent.
    try sink.send(&.{"xy"});
    try expect_recv(stream, " worldx");
    try testing.expectEqualStrings("y", stream.peek(100));
    // A buffered prefix survives the direct path.
    const direct: [64]u8 = @splat('z');
    try sink.send(&.{&direct});
    try expect_recv(stream, "y" ++ direct);
    try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
    try sink.send(&.{"next"});
    try expect_recv(stream, "ne");
    try testing.expectEqualStrings("xt", stream.peek(100));
    try expect_recv(stream, "xt");
    try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
}

test "buffered peek, a shorter refill, and the direct path keep their prefix" {
    // commonware iouring.rs `test_peek_with_buffered_data`.
    try on_both(buffered_peek);
}

fn large_recv(ring: bool) !void {
    var tcp = network_with(.{ .read_buffer_size = 8 }, ring);
    defer tcp.deinit();
    var pair = try Pair.init(&tcp);
    defer pair.deinit();
    try pair.connection.sink.send(&.{"abcdefgh"});
    try expect_recv(&pair.accepted.stream, "abcdefgh");
    try testing.expectEqual(@as(usize, 0), pair.accepted.stream.peek(1).len);
}

test "a recv of the read buffer's size skips it (test_large_recv_skips_internal_buffer)" {
    try on_both(large_recv);
}

const linux = std.os.linux;

/// TCP_NODELAY and whether SO_LINGER is on with a zero timeout.
fn socket_options(fd: linux.fd_t) !struct { bool, bool } {
    var nodelay: i32 = 0;
    var nodelay_len: linux.socklen_t = @sizeOf(i32);
    const level_tcp: i32 = linux.IPPROTO.TCP;
    var rc = linux.getsockopt(fd, level_tcp, linux.TCP.NODELAY, @ptrCast(&nodelay), &nodelay_len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    var linger: extern struct { on: i32, seconds: i32 } = undefined;
    var linger_len: linux.socklen_t = @sizeOf(@TypeOf(linger));
    rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.LINGER, @ptrCast(&linger), &linger_len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    return .{ nodelay != 0, linger.on != 0 and linger.seconds == 0 };
}

fn socket_policy(ring: bool) !void {
    const cases = [_]struct { ?bool, bool }{ .{ true, true }, .{ false, false }, .{ null, false } };
    for (cases) |case| {
        const nodelay, const zero_linger = case;
        var tcp = network_with(.{ .tcp_nodelay = nodelay, .zero_linger = zero_linger }, ring);
        defer tcp.deinit();
        var pair = try Pair.init(&tcp);
        defer pair.deinit();
        // Unconfigured sockets keep Nagle on and lingering off.
        const expected = .{ nodelay orelse false, zero_linger };
        for ([_]*production.Sink{ &pair.connection.sink, &pair.accepted.sink }) |sink| {
            const options = try socket_options(sink.shared.stream.socket.handle);
            try testing.expectEqual(expected, options);
        }
    }
}

test "socket options apply on accept and dial (test_socket_options_on_accept_and_dial)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try on_both(socket_policy);
}

fn close_with_cancel_pending(sink: *production.Sink) Io.Cancelable!void {
    // Spin until the cancel request arrives, then leave it pending for the close's shutdown.
    while (true) {
        testing.io.checkCancel() catch {
            testing.io.recancel();
            break;
        };
        std.atomic.spinLoopHint();
    }
    sink.deinit();
    // The shutdown took the cancel, so it must re-arm it: this wait ends at once, not in 5 s.
    try testing.io.sleep(.fromSeconds(5), .awake);
}

test "a sink closed while canceled leaves the cancel for the task's next wait" {
    var tcp = new_network(testing.io);
    defer tcp.deinit();
    var pair = try Pair.init(&tcp);
    defer {
        pair.accepted.stream.deinit();
        pair.connection.deinit();
        pair.listener.deinit();
    }
    var task = try testing.io.concurrent(close_with_cancel_pending, .{&pair.accepted.sink});
    try testing.expectError(error.Canceled, task.cancel(testing.io));
}

fn accept_pending(listener: *Network.Listener) Error!void {
    var accepted = try listener.accept();
    accepted.deinit();
}

// commonware `test_cancel_accept_before_service_preserves_next_connection`.
test "a canceled io_uring accept keeps the next connection" {
    try init_test_ring();
    defer test_ring.deinit();
    const io = testing.io;
    var tcp = new_ring_network(io);
    defer tcp.deinit();
    const listener = try tcp.bind(any_port);
    defer listener.deinit();
    // An accept canceled with nothing to accept must not take the next connection.
    var pending = try io.concurrent(accept_pending, .{listener});
    try io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectError(error.Canceled, pending.cancel(io));
    var connection = try tcp.dial(listener.local_addr());
    defer connection.deinit();
    var accepted = try listener.accept();
    defer accepted.deinit();
    // The ring's accept reports the dialer's address.
    const local = local_address(connection.sink.shared.stream.socket.handle);
    try testing.expect(local.eql(&accepted.address));
    try connection.sink.send(&.{"kept"});
    var out: [4]u8 = undefined;
    try accepted.stream.recv(&out);
    try testing.expectEqualStrings("kept", &out);
}

/// The local address of the connected socket `fd`.
fn local_address(fd: std.posix.fd_t) Address {
    var storage: std.posix.sockaddr.in = undefined;
    var length: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
    std.debug.assert(std.posix.errno(std.posix.system.getsockname(
        fd,
        @ptrCast(&storage),
        &length,
    )) == .SUCCESS);
    const bytes: *const [4]u8 = @ptrCast(&storage.addr);
    return .{ .ip4 = .{ .bytes = bytes.*, .port = std.mem.bigToNative(u16, storage.port) } };
}
