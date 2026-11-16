//! The network conformance suite every backend runs (commonware `network::tests`).
//!
//! A backend `N` declares `Listener`, `Accepted` (`address`, `sink`, `stream`, `deinit`), and
//! `Connection` (`sink`, `stream`, `deinit`), with `bind(*N, Address) !*Listener`,
//! `dial(*N, Address) !Connection`, `Listener.accept`, `Listener.local_addr`, and
//! `Listener.deinit`. Each case runs on a fresh network from `new_network`.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const testing = std.testing;
const network = @import("../network.zig");
const Address = network.Address;

const client_send_data = "client_send_data";
const server_send_data = "server_send_data";
const any_port: Address = .{ .ip4 = .loopback(0) };

/// Runs every network test, each on a fresh network.
pub fn run_network_tests(io: Io, comptime N: type, comptime new_network: fn (Io) N) !void {
    const C = Cases(N);
    const cases = .{
        C.bind_and_dial,                C.vectored_send,
        C.multiple_clients,             C.large_data,
        C.connection_errors,            C.peek,
        C.canceled_recv_poisons_stream, C.canceled_send_poisons_sink,
        C.recv_error_poisons_stream,    C.send_error_poisons_sink,
    };
    inline for (cases) |case| {
        var net = new_network(io);
        defer net.deinit();
        try case(io, &net);
    }
}

/// The slow stress test: many clients echo many messages at once.
pub fn run_network_stress_tests(io: Io, comptime N: type, comptime new_network: fn (Io) N) !void {
    var net = new_network(io);
    defer net.deinit();
    try Cases(N).stress_concurrent_streams(io, &net);
}

fn expect_recv(stream: anytype, comptime expected: []const u8) !void {
    var buffer: [expected.len]u8 = undefined;
    try stream.recv(&buffer);
    try testing.expectEqualStrings(expected, &buffer);
}

fn Cases(comptime N: type) type {
    return struct {
        const Listener = N.Listener;
        const Accepted = N.Accepted;
        const Connection = N.Connection;

        fn echo_server(listener: *Listener) !Accepted {
            var accepted = try listener.accept();
            errdefer accepted.deinit();
            try expect_recv(&accepted.stream, client_send_data);
            try accepted.sink.send(&.{server_send_data});
            return accepted;
        }

        fn echo_client(net: *N, address: Address) !Connection {
            var connection = try net.dial(address);
            errdefer connection.deinit();
            try connection.sink.send(&.{client_send_data});
            try expect_recv(&connection.stream, server_send_data);
            return connection;
        }

        /// The halves stay open until both sides finish.
        fn bind_and_dial(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var server = try io.concurrent(echo_server, .{listener});
            var client = try io.concurrent(echo_client, .{ net, listener.local_addr() });
            var accepted = try server.await(io);
            defer accepted.deinit();
            var connection = try client.await(io);
            defer connection.deinit();
        }

        fn vectored_server(listener: *Listener) !Accepted {
            var accepted = try listener.accept();
            errdefer accepted.deinit();
            try expect_recv(&accepted.stream, "client_vectored_send");
            return accepted;
        }

        fn vectored_client(net: *N, address: Address) !Connection {
            var connection = try net.dial(address);
            errdefer connection.deinit();
            try connection.sink.send(&.{ "client_", "vectored_", "send" });
            return connection;
        }

        /// A multi-buffer send arrives as one logical byte sequence.
        fn vectored_send(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var server = try io.concurrent(vectored_server, .{listener});
            var client = try io.concurrent(vectored_client, .{ net, listener.local_addr() });
            var accepted = try server.await(io);
            defer accepted.deinit();
            var connection = try client.await(io);
            defer connection.deinit();
        }

        const clients_count = 3;

        fn serve_connection(accepted: *Accepted) !void {
            try expect_recv(&accepted.stream, client_send_data);
            try accepted.sink.send(&.{server_send_data});
        }

        fn multiple_server(io: Io, listener: *Listener, out: *[clients_count]Accepted) !void {
            var accepted_count: usize = 0;
            defer for (out[0..accepted_count]) |*accepted| accepted.deinit();
            while (accepted_count < clients_count) : (accepted_count += 1) {
                out[accepted_count] = try listener.accept();
            }
            var futures: [clients_count]Io.Future(anyerror!void) = undefined;
            for (&futures, out) |*future, *accepted| {
                future.* = try io.concurrent(serve_connection_erased, .{accepted});
            }
            for (&futures) |*future| try future.await(io);
            accepted_count = 0; // The caller closes them once every client is done.
        }

        fn serve_connection_erased(accepted: *Accepted) anyerror!void {
            return serve_connection(accepted);
        }

        fn multiple_clients(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var accepted: [clients_count]Accepted = undefined;
            var server = try io.concurrent(multiple_server, .{ io, listener, &accepted });
            var clients: [clients_count]Io.Future(anyerror!Connection) = undefined;
            for (&clients) |*client| {
                client.* = try io.concurrent(echo_client_erased, .{ net, listener.local_addr() });
            }
            var connections: [clients_count]Connection = undefined;
            for (&clients, &connections) |*client, *connection| connection.* = try client.await(io);
            defer for (&connections) |*connection| connection.deinit();
            try server.await(io);
            for (&accepted) |*connection| connection.deinit();
        }

        fn echo_client_erased(net: *N, address: Address) anyerror!Connection {
            return echo_client(net, address);
        }

        const chunks_count = 1_000;
        const chunk_size = 8 * 1024;

        fn large_server(listener: *Listener) !Accepted {
            var accepted = try listener.accept();
            errdefer accepted.deinit();
            var chunk: [chunk_size]u8 = undefined;
            for (0..chunks_count) |_| {
                try accepted.stream.recv(&chunk);
                try accepted.sink.send(&.{&chunk});
            }
            return accepted;
        }

        fn large_client(net: *N, address: Address) !Connection {
            var connection = try net.dial(address);
            errdefer connection.deinit();
            var pattern: [chunk_size]u8 = undefined;
            for (&pattern, 0..) |*byte, i| byte.* = @truncate(i);
            var received: [chunk_size]u8 = undefined;
            for (0..chunks_count) |_| {
                try connection.sink.send(&.{&pattern});
                try connection.stream.recv(&received);
                try testing.expectEqualSlices(u8, &pattern, &received);
            }
            return connection;
        }

        /// 8 MiB echoed in 8 KiB chunks.
        fn large_data(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var server = try io.concurrent(large_server, .{listener});
            var client = try io.concurrent(large_client, .{ net, listener.local_addr() });
            var accepted = try server.await(io);
            defer accepted.deinit();
            var connection = try client.await(io);
            defer connection.deinit();
        }

        fn connection_errors(_: Io, net: *N) !void {
            const invalid: Address = .{ .ip4 = .loopback(1) };
            try testing.expectError(error.ConnectionFailed, net.dial(invalid));
            const listener = try net.bind(any_port);
            defer listener.deinit();
            try testing.expectError(error.BindFailed, net.bind(listener.local_addr()));
        }

        const peek_data = "hello world - peek test data";

        fn peek_server(listener: *Listener) !Accepted {
            var accepted = try listener.accept();
            errdefer accepted.deinit();
            try accepted.sink.send(&.{peek_data});
            return accepted;
        }

        fn peek_client(net: *N, address: Address) !Connection {
            var connection = try net.dial(address);
            errdefer connection.deinit();
            const stream = &connection.stream;
            try expect_recv(stream, "hello");
            const peeked = stream.peek(100);
            try testing.expect(peeked.len > 0);
            // Peeking does not consume.
            try testing.expectEqualSlices(u8, peeked, stream.peek(100));
            if (peeked.len >= 3) try testing.expectEqualSlices(u8, peeked[0..3], stream.peek(3));
            try expect_recv(stream, peek_data[5..]);
            try testing.expectEqual(@as(usize, 0), stream.peek(100).len);
            return connection;
        }

        fn peek(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var server = try io.concurrent(peek_server, .{listener});
            var client = try io.concurrent(peek_client, .{ net, listener.local_addr() });
            var accepted = try server.await(io);
            defer accepted.deinit();
            var connection = try client.await(io);
            defer connection.deinit();
        }

        fn recv_100(stream: *@FieldType(Accepted, "stream")) !void {
            var buffer: [100]u8 = undefined;
            try stream.recv(&buffer);
            return error.TestUnexpectedResult;
        }

        fn canceled_recv_server(io: Io, listener: *Listener) !Accepted {
            var accepted = try listener.accept();
            errdefer accepted.deinit();
            var receive = try io.concurrent(recv_100, .{&accepted.stream});
            try io.sleep(.fromMilliseconds(5), .awake);
            try testing.expectError(error.Canceled, receive.cancel(io));
            var byte: [1]u8 = undefined;
            try testing.expectError(error.Closed, accepted.stream.recv(&byte));
            // The sink stays usable after the stream is canceled.
            try accepted.sink.send(&.{"ok"});
            return accepted;
        }

        fn ok_client(net: *N, address: Address) !Connection {
            var connection = try net.dial(address);
            errdefer connection.deinit();
            try expect_recv(&connection.stream, "ok");
            return connection;
        }

        fn canceled_recv_poisons_stream(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var server = try io.concurrent(canceled_recv_server, .{ io, listener });
            var client = try io.concurrent(ok_client, .{ net, listener.local_addr() });
            var accepted = try server.await(io);
            defer accepted.deinit();
            var connection = try client.await(io);
            defer connection.deinit();
        }

        fn send_large(sink: *@FieldType(Accepted, "sink")) !void {
            const block: [128 * 1024]u8 = @splat(0);
            for (0..1024) |_| try sink.send(&.{&block});
            return error.TestUnexpectedResult; // Backpressure must block a send.
        }

        fn canceled_send_server(io: Io, listener: *Listener, canceled: *Io.Event) !Accepted {
            var accepted = try listener.accept();
            errdefer accepted.deinit();
            var sending = try io.concurrent(send_large, .{&accepted.sink});
            try io.sleep(.fromMilliseconds(5), .awake);
            try testing.expectError(error.Canceled, sending.cancel(io));
            try testing.expectError(error.Closed, accepted.sink.send(&.{"after"}));
            canceled.set(io);
            // The stream stays usable after the sink is canceled.
            try expect_recv(&accepted.stream, "ok");
            return accepted;
        }

        fn canceled_send_client(
            net: *N,
            address: Address,
            io: Io,
            canceled: *Io.Event,
        ) !Connection {
            var connection = try net.dial(address);
            errdefer connection.deinit();
            try canceled.wait(io);
            try connection.sink.send(&.{"ok"});
            return connection;
        }

        fn canceled_send_poisons_sink(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var canceled: Io.Event = .unset;
            var server = try io.concurrent(canceled_send_server, .{ io, listener, &canceled });
            const address = listener.local_addr();
            var client = try io.concurrent(canceled_send_client, .{ net, address, io, &canceled });
            var accepted = try server.await(io);
            defer accepted.deinit();
            var connection = try client.await(io);
            defer connection.deinit();
        }

        fn recv_error_server(listener: *Listener) !Accepted {
            var accepted = try listener.accept();
            errdefer accepted.deinit();
            var buffer: [100]u8 = undefined;
            // The peer sends 50 bytes and closes its sink.
            try testing.expectError(error.RecvFailed, accepted.stream.recv(&buffer));
            try testing.expectError(error.Closed, accepted.stream.recv(buffer[0..1]));
            try accepted.sink.send(&.{"ok"});
            return accepted;
        }

        fn recv_error_client(net: *N, address: Address) !@FieldType(Connection, "stream") {
            var connection = try net.dial(address);
            const ones: [50]u8 = @splat(1);
            connection.sink.send(&.{&ones}) catch |err| {
                connection.deinit();
                return err;
            };
            connection.sink.deinit();
            errdefer connection.stream.deinit();
            try expect_recv(&connection.stream, "ok");
            return connection.stream;
        }

        fn recv_error_poisons_stream(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var server = try io.concurrent(recv_error_server, .{listener});
            var client = try io.concurrent(recv_error_client, .{ net, listener.local_addr() });
            var accepted = try server.await(io);
            defer accepted.deinit();
            var stream = try client.await(io);
            defer stream.deinit();
        }

        const Signals = struct { buffered: Io.Event = .unset, closed: Io.Event = .unset };

        fn send_error_server(io: Io, listener: *Listener, signals: *Signals) !void {
            var accepted = try listener.accept();
            {
                errdefer accepted.deinit();
                try accepted.sink.send(&.{"okay"});
                try signals.buffered.wait(io);
            }
            accepted.deinit();
            signals.closed.set(io);
        }

        fn send_error_client(io: Io, net: *N, address: Address, signals: *Signals) !Connection {
            var connection = try net.dial(address);
            errdefer connection.deinit();
            try expect_recv(&connection.stream, "ok");
            try testing.expectEqualStrings("ay", connection.stream.peek(2));
            signals.buffered.set(io);
            try signals.closed.wait(io);
            var attempts: u32 = 0;
            const failure: anyerror = while (attempts < 10) : (attempts += 1) {
                connection.sink.send(&.{"\x09"}) catch |err| break err;
                try io.sleep(.fromMilliseconds(5), .awake);
            } else return error.TestUnexpectedResult;
            try testing.expectEqual(error.SendFailed, failure);
            try testing.expectError(error.Closed, connection.sink.send(&.{"\x09"}));
            // Bytes received before the peer closed stay readable.
            try expect_recv(&connection.stream, "ay");
            return connection;
        }

        fn send_error_poisons_sink(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var signals: Signals = .{};
            var server = try io.concurrent(send_error_server, .{ io, listener, &signals });
            const address = listener.local_addr();
            var client = try io.concurrent(send_error_client, .{ io, net, address, &signals });
            try server.await(io);
            var connection = try client.await(io);
            defer connection.deinit();
        }

        const stress_clients = 96;
        const stress_messages = 16_384;
        const stress_message_size = 4096;

        fn stress_echo(accepted: *Accepted) anyerror!void {
            var message: [stress_message_size]u8 = undefined;
            for (0..stress_messages) |index| {
                accepted.stream.recv(&message) catch |err| {
                    std.log.err("stress server: recv {d} failed: {t}", .{ index, err });
                    return err;
                };
                accepted.sink.send(&.{&message}) catch |err| {
                    std.log.err("stress server: send {d} failed: {t}", .{ index, err });
                    return err;
                };
            }
        }

        /// Accepts every client and echoes each on its own task. It closes what it accepted,
        /// also when it fails or is canceled.
        fn stress_server(io: Io, listener: *Listener) anyerror!void {
            var accepted: [stress_clients]Accepted = undefined;
            var count: usize = 0;
            defer for (accepted[0..count]) |*connection| connection.deinit();
            while (count < stress_clients) : (count += 1) {
                accepted[count] = listener.accept() catch |err| {
                    std.log.err("stress server: accept {d} failed: {t}", .{ count, err });
                    return err;
                };
            }
            var futures: [stress_clients]Io.Future(anyerror!void) = undefined;
            var started: usize = 0;
            defer for (futures[0..started]) |*future| future.cancel(io) catch {};
            while (started < stress_clients) : (started += 1) {
                futures[started] = try io.concurrent(stress_echo, .{&accepted[started]});
            }
            for (&futures) |*future| try future.await(io);
        }

        fn stress_client(net: *N, address: Address) anyerror!Connection {
            var connection = net.dial(address) catch |err| {
                std.log.err("stress client: dial failed: {t}", .{err});
                return err;
            };
            errdefer connection.deinit();
            const payload: [stress_message_size]u8 = @splat(42);
            var received: [stress_message_size]u8 = undefined;
            for (0..stress_messages) |message| {
                // Name the failing step: ReleaseSafe failures carry no stack trace.
                connection.sink.send(&.{&payload}) catch |err| {
                    std.log.err("stress client: send {d} failed: {t}", .{ message, err });
                    return err;
                };
                connection.stream.recv(&received) catch |err| {
                    std.log.err("stress client: recv {d} failed: {t}", .{ message, err });
                    return err;
                };
                try testing.expectEqualSlices(u8, &payload, &received);
            }
            return connection;
        }

        /// Closes a client's connection once it is done or canceled.
        fn stress_close(io: Io, client: *Io.Future(anyerror!Connection)) void {
            var connection = client.cancel(io) catch return;
            connection.deinit();
        }

        fn stress_concurrent_streams(io: Io, net: *N) !void {
            const listener = try net.bind(any_port);
            defer listener.deinit();
            var server = try io.concurrent(stress_server, .{ io, listener });
            defer server.cancel(io) catch {};
            var clients: [stress_clients]Io.Future(anyerror!Connection) = undefined;
            var started: usize = 0;
            // Every path closes every connection: a failed client cancels the rest.
            defer for (clients[0..started]) |*client| stress_close(io, client);
            const address = listener.local_addr();
            while (started < stress_clients) : (started += 1) {
                clients[started] = try io.concurrent(stress_client, .{ net, address });
            }
            for (&clients) |*client| _ = try client.await(io);
            try server.await(io);
        }
    };
}
