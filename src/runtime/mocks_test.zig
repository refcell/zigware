//! Tests of the mock channel (commonware `mocks::tests`), on the deterministic runtime.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const mocks = @import("mocks.zig");
const deterministic = @import("deterministic.zig");

fn run(comptime body: fn (Io) anyerror!void) !void {
    var runner = try deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(body, .{runner.io()}));
}

fn expect_recv(stream: *mocks.Stream, expected: []const u8) !void {
    var buffer: [64]u8 = undefined;
    std.debug.assert(expected.len <= buffer.len);
    try stream.recv(buffer[0..expected.len]);
    try testing.expectEqualStrings(expected, buffer[0..expected.len]);
}

fn sleep_ms(io: Io, ms: i64) !void {
    try io.sleep(.fromMilliseconds(ms), .awake);
}

test "send recv" {
    try run(struct {
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            try pair.sink.send(&.{"hello world"});
            try expect_recv(&pair.stream, "hello world");
        }
    }.body);
}

test "send recv partial multiple" {
    try run(struct {
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            try pair.sink.send(&.{"hello"});
            try pair.sink.send(&.{" world"});
            try expect_recv(&pair.stream, "hello");
            try expect_recv(&pair.stream, " worl");
            try expect_recv(&pair.stream, "d");
        }
    }.body);
}

test "send recv async" {
    try run(struct {
        fn receive(stream: *mocks.Stream) !void {
            try expect_recv(stream, "hello world");
        }
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            var receiver = try io.concurrent(receive, .{&pair.stream});
            try sleep_ms(io, 50);
            try pair.sink.send(&.{"hello world"});
            try receiver.await(io);
        }
    }.body);
}

test "recv error when the sink is dropped while waiting" {
    try run(struct {
        fn receive(stream: *mocks.Stream) !void {
            var buffer: [5]u8 = undefined;
            try testing.expectError(error.RecvFailed, stream.recv(&buffer));
            try testing.expectError(error.Closed, stream.recv(&buffer));
        }
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.stream.deinit();
            var receiver = try io.concurrent(receive, .{&pair.stream});
            try sleep_ms(io, 50);
            pair.sink.deinit();
            try receiver.await(io);
        }
    }.body);
}

test "recv error when the sink is dropped before recv" {
    try run(struct {
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.stream.deinit();
            pair.sink.deinit();
            var buffer: [5]u8 = undefined;
            try testing.expectError(error.RecvFailed, pair.stream.recv(&buffer));
            try testing.expectError(error.Closed, pair.stream.recv(&buffer));
        }
    }.body);
}

test "send error when the stream is dropped" {
    try run(struct {
        // The first recv succeeds; the second blocks until the task is aborted, which drops
        // the stream.
        fn receive(stream_value: mocks.Stream) !void {
            var stream = stream_value;
            defer stream.deinit();
            var buffer: [5]u8 = undefined;
            try stream.recv(&buffer);
            try stream.recv(&buffer);
        }
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.sink.deinit();
            try pair.sink.send(&.{"7 bytes"});
            var receiver = try io.concurrent(receive, .{pair.stream});
            try sleep_ms(io, 50);
            try testing.expectError(error.Canceled, receiver.cancel(io));
            try testing.expectError(error.SendFailed, pair.sink.send(&.{"hello world"}));
            try testing.expectError(error.Closed, pair.sink.send(&.{"hello world"}));
        }
    }.body);
}

test "send error when the stream is dropped before send" {
    try run(struct {
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.sink.deinit();
            pair.stream.deinit();
            try testing.expectError(error.SendFailed, pair.sink.send(&.{"hello world"}));
            try testing.expectError(error.Closed, pair.sink.send(&.{"hello world"}));
        }
    }.body);
}

test "recv blocks until a timeout cancels it" {
    try run(struct {
        fn receive(stream: *mocks.Stream) !void {
            var buffer: [5]u8 = undefined;
            try stream.recv(&buffer);
            return error.TestUnexpectedResult;
        }
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            var receiver = try io.concurrent(receive, .{&pair.stream});
            try sleep_ms(io, 100);
            try testing.expectError(error.Canceled, receiver.cancel(io));
            // The canceled recv poisoned the stream.
            var buffer: [1]u8 = undefined;
            try testing.expectError(error.Closed, pair.stream.recv(&buffer));
        }
    }.body);
}

test "canceled send closes the sink" {
    try run(struct {
        fn send(sink: *mocks.Sink) !void {
            try sink.send(&.{"0123456789ABCDEF"});
        }
        fn body(io: Io) !void {
            var pair = try mocks.channel_with_buffer_size(testing.allocator, io, 10);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            var sender = try io.concurrent(send, .{&pair.sink});
            try sleep_ms(io, 10);
            try testing.expectError(error.Canceled, sender.cancel(io));
            try testing.expectError(error.Closed, pair.sink.send(&.{"after"}));
            // The bytes already sent stay readable; then the closed sink fails the recv.
            try expect_recv(&pair.stream, "0123456789ABCDEF");
            var buffer: [1]u8 = undefined;
            try testing.expectError(error.RecvFailed, pair.stream.recv(&buffer));
        }
    }.body);
}

test "peek empty" {
    var pair = try mocks.channel(testing.allocator, testing.io);
    defer pair.stream.deinit();
    defer pair.sink.deinit();
    try testing.expectEqual(@as(usize, 0), pair.stream.peek(10).len);
}

test "peek after partial recv" {
    try run(struct {
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            try pair.sink.send(&.{"hello world"});
            try expect_recv(&pair.stream, "hello");
            try testing.expectEqualStrings(" world", pair.stream.peek(100));
            try testing.expectEqualStrings(" wo", pair.stream.peek(3));
            try testing.expectEqualStrings(" world", pair.stream.peek(100));
            try expect_recv(&pair.stream, " world");
            try testing.expectEqual(@as(usize, 0), pair.stream.peek(100).len);
        }
    }.body);
}

test "peek after recv wakeup" {
    try run(struct {
        fn receive(stream: *mocks.Stream) !void {
            try expect_recv(stream, "ABC");
        }
        fn body(io: Io) !void {
            var pair = try mocks.channel_with_buffer_size(testing.allocator, io, 64);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            var receiver = try io.concurrent(receive, .{&pair.stream});
            try sleep_ms(io, 10);
            try pair.sink.send(&.{"ABCDEFGHIJ"});
            try receiver.await(io);
            try testing.expectEqualStrings("DEFGHIJ", pair.stream.peek(100));
        }
    }.body);
}

test "peek multiple sends" {
    try run(struct {
        fn body(io: Io) !void {
            var pair = try mocks.channel(testing.allocator, io);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            try pair.sink.send(&.{"aaa"});
            try pair.sink.send(&.{"bbb"});
            try pair.sink.send(&.{"ccc"});
            try expect_recv(&pair.stream, "aaab");
            try testing.expectEqualStrings("bbccc", pair.stream.peek(100));
        }
    }.body);
}

test "buffer size limit" {
    try run(struct {
        fn send(sink: *mocks.Sink) !void {
            try sink.send(&.{"0123456789ABCDEF"});
        }
        fn body(io: Io) !void {
            var pair = try mocks.channel_with_buffer_size(testing.allocator, io, 10);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            var sender = try io.concurrent(send, .{&pair.sink});
            // A recv pulls only up to the buffer size (10 bytes).
            try expect_recv(&pair.stream, "01");
            try testing.expectEqualStrings("23456789", pair.stream.peek(100));
            try expect_recv(&pair.stream, "23456789");
            try expect_recv(&pair.stream, "AB");
            try testing.expectEqualStrings("CDEF", pair.stream.peek(100));
            try sender.await(io);
        }
    }.body);
}

test "recv before send" {
    try run(struct {
        fn receive(stream: *mocks.Stream) !void {
            try expect_recv(stream, "ABC");
        }
        fn body(io: Io) !void {
            var pair = try mocks.channel_with_buffer_size(testing.allocator, io, 10);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            var receiver = try io.concurrent(receive, .{&pair.stream});
            try sleep_ms(io, 10);
            try pair.sink.send(&.{"ABCDEFGHIJKLMNOP"});
            try receiver.await(io);
        }
    }.body);
}

// A zero-size buffer (commonware allows it): every non-empty send waits until the receiver
// drains the channel, and a recv pulls exactly what it asks for, so peek stays empty.
test "zero buffer size" {
    try run(struct {
        fn send(sink: *mocks.Sink, bytes: []const u8) !void {
            try sink.send(&.{bytes});
        }
        fn body(io: Io) !void {
            var pair = try mocks.channel_with_buffer_size(testing.allocator, io, 0);
            defer pair.stream.deinit();
            defer pair.sink.deinit();
            // Send first: the sender blocks until every byte is pulled.
            var sender = try io.concurrent(send, .{ &pair.sink, "hello" });
            try sleep_ms(io, 10);
            try expect_recv(&pair.stream, "he");
            try testing.expectEqual(@as(usize, 0), pair.stream.peek(100).len);
            try expect_recv(&pair.stream, "llo");
            try sender.await(io);
            // Receive first: the sink hands over what the receiver asked for, then blocks on
            // the rest.
            var receiver = try io.concurrent(expect_abc, .{&pair.stream});
            try sleep_ms(io, 10);
            var rest = try io.concurrent(send, .{ &pair.sink, "abcdef" });
            try receiver.await(io);
            try expect_recv(&pair.stream, "def");
            try rest.await(io);
            // Empty sends never block.
            try pair.sink.send(&.{""});
        }
        fn expect_abc(stream: *mocks.Stream) !void {
            try expect_recv(stream, "abc");
        }
    }.body);
}
