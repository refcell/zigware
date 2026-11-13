//! Tests for `codec.zig`, ported from commonware `stream/src/utils/codec.rs`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");

const framing = @import("codec.zig");
const mocks = runtime.mocks;

const max_message_size: u32 = 1024;
const max_prefix_size = codec.varint.max_u32_varint_size;

fn varint_prefix(len: u32, out: *[max_prefix_size]u8) []const u8 {
    var writer = codec.Writer.init(out);
    codec.varint.write(u32, len, &writer);
    return writer.written();
}

fn random_bytes(seed: u64, out: []u8) void {
    var rng = utils.rng.TestRng.init(seed);
    rng.fill_bytes(out);
}

/// Records receive request sizes while preserving the mock stream's buffering.
const RecordingStream = struct {
    inner: *mocks.Stream,
    lengths: [8]usize = undefined,
    count: usize = 0,

    pub fn recv(stream: *RecordingStream, out: []u8) mocks.Error!void {
        stream.lengths[stream.count] = out.len;
        stream.count += 1;
        return stream.inner.recv(out);
    }

    pub fn peek(stream: *const RecordingStream, max_len: usize) []const u8 {
        return stream.inner.peek(max_len);
    }

    fn recorded(stream: *const RecordingStream) []const usize {
        return stream.lengths[0..stream.count];
    }
};

fn run_deterministic(comptime function: anytype, args: anytype) !void {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
        .timeout_ns = 5 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()} ++ args));
}

const large_max: u32 = 1 << 15;

// Reuses buffered prefix bytes after a refill and preserves the following frame.
fn reuses_buffered_prefix(io: Io, len: u32) !void {
    const gpa = testing.allocator;
    const payload = try gpa.alloc(u8, len);
    defer gpa.free(payload);
    @memset(payload, 7);
    var prefix_bytes: [max_prefix_size]u8 = undefined;
    const prefix_len = varint_prefix(len, &prefix_bytes).len;

    // Queue both frames with enough capacity to buffer them in the first read.
    var pair = try mocks.channel_with_buffer_size(gpa, io, prefix_len + payload.len + 5);
    defer pair.sink.deinit();
    defer pair.stream.deinit();
    var stream: RecordingStream = .{ .inner = &pair.stream };
    try framing.send_frame(&pair.sink, &.{payload}, large_max);
    try framing.send_frame(&pair.sink, &.{"next"}, large_max);
    try testing.expectEqual(@as(usize, 0), stream.peek(max_prefix_size).len);

    // Only the first prefix byte needs its own read; the rest accompanies the payload.
    const buffer = try gpa.alloc(u8, large_max);
    defer gpa.free(buffer);
    try testing.expectEqualSlices(u8, payload, try framing.recv_frame(&stream, buffer, large_max));
    const expected = [_]usize{ 1, prefix_len - 1 + payload.len };
    try testing.expectEqualSlices(usize, &expected, stream.recorded());

    // The next frame is already buffered and must arrive intact in a single read.
    stream.count = 0;
    try testing.expectEqualStrings("next", try framing.recv_frame(&stream, buffer, large_max));
    try testing.expectEqualSlices(usize, &.{5}, stream.recorded());
}

test "recv_frame reuses buffered prefix" {
    for ([_]u32{ 0, 127, 128, 300, 16_383, 16_384 }) |len| {
        try run_deterministic(reuses_buffered_prefix, .{len});
    }
}

fn send_prefix(sink: *mocks.Sink, prefix: []const u8) mocks.Error!void {
    try sink.send(&.{prefix});
}

// Decodes one- through five-byte prefixes across varying refill boundaries.
fn length_across_refills(io: Io, len: u32, buffer_size: usize) !void {
    // Send concurrently so prefixes larger than the channel capacity can progress.
    var pair = try mocks.channel_with_buffer_size(testing.allocator, io, buffer_size);
    defer pair.sink.deinit();
    defer pair.stream.deinit();
    var prefix_bytes: [max_prefix_size]u8 = undefined;
    const prefix = varint_prefix(len, &prefix_bytes);
    var sender = try io.concurrent(send_prefix, .{ &pair.sink, prefix });

    // The decoded length must survive refills. Consume any prefix still buffered.
    const length = try framing.recv_length(&pair.stream);
    try testing.expectEqual(@as(usize, len), length.len);
    var skipped: [max_prefix_size]u8 = undefined;
    try pair.stream.recv(skipped[0..length.skip]);
    try sender.await(io);
}

test "recv_length across refills" {
    const lens = [_]u32{ 0, 127, 128, 300, 16_384, 1 << 21, 0x1234_5678, std.math.maxInt(u32) };
    for (lens) |len| {
        for (0..max_prefix_size + 1) |buffer_size| {
            try run_deterministic(length_across_refills, .{ len, buffer_size });
        }
    }
}

const Channel = struct {
    pair: mocks.Pair,
    buffer: [max_message_size]u8 = undefined,

    fn init(channel: *Channel) !void {
        channel.* = .{ .pair = try mocks.channel(testing.allocator, testing.io) };
    }

    fn deinit(channel: *Channel) void {
        channel.pair.stream.deinit();
        channel.pair.sink.deinit();
    }

    fn recv(channel: *Channel, max: u32) framing.Error![]u8 {
        return framing.recv_frame(&channel.pair.stream, &channel.buffer, max);
    }
};

test "send and recv at max message size" {
    var channel: Channel = undefined;
    try channel.init();
    defer channel.deinit();
    var message: [max_message_size]u8 = undefined;
    random_bytes(42, &message);
    try framing.send_frame(&channel.pair.sink, &.{&message}, max_message_size);
    try testing.expectEqualSlices(u8, &message, try channel.recv(max_message_size));
}

test "send and recv multiple" {
    var channel: Channel = undefined;
    try channel.init();
    defer channel.deinit();
    var first: [max_message_size]u8 = undefined;
    var second: [max_message_size / 2]u8 = undefined;
    random_bytes(42, &first);
    random_bytes(43, &second);

    // Send two messages of different sizes, then read both in order.
    try framing.send_frame(&channel.pair.sink, &.{&first}, max_message_size);
    try framing.send_frame(&channel.pair.sink, &.{&second}, max_message_size);
    try testing.expectEqualSlices(u8, &first, try channel.recv(max_message_size));
    try testing.expectEqualSlices(u8, &second, try channel.recv(max_message_size));
}

test "send_frame writes a varint prefix" {
    var channel: Channel = undefined;
    try channel.init();
    defer channel.deinit();
    var message: [max_message_size]u8 = undefined;
    random_bytes(42, &message);
    // Several parts form one frame.
    const parts = [_][]const u8{ message[0..100], message[100..1000], message[1000..] };
    try framing.send_frame(&channel.pair.sink, &parts, max_message_size);

    // Read manually: 1024 encodes as the varint [0x80, 0x08].
    var prefix: [2]u8 = undefined;
    try channel.pair.stream.recv(&prefix);
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x08 }, &prefix);
    var read: [max_message_size]u8 = undefined;
    try channel.pair.stream.recv(&read);
    try testing.expectEqualSlices(u8, &message, &read);
}

test "send_frame too large" {
    var channel: Channel = undefined;
    try channel.init();
    defer channel.deinit();
    var message: [max_message_size]u8 = undefined;
    random_bytes(42, &message);
    try testing.expectError(
        error.SendTooLarge,
        framing.send_frame(&channel.pair.sink, &.{&message}, max_message_size - 1),
    );
    try testing.expectError(error.SendTooLarge, framing.validate_frame_len(1 << 33, 1 << 31));
    try testing.expectEqual(@as(u32, 7), try framing.validate_frame_len(7, 7));
}

test "recv_frame reads a manually written frame" {
    var channel: Channel = undefined;
    try channel.init();
    defer channel.deinit();
    var message: [max_message_size]u8 = undefined;
    random_bytes(42, &message);
    try channel.pair.sink.send(&.{ &.{ 0x80, 0x08 }, &message });
    try testing.expectEqualSlices(u8, &message, try channel.recv(max_message_size));
}

test "recv_frame too large" {
    var channel: Channel = undefined;
    try channel.init();
    defer channel.deinit();
    // A prefix declaring 1024 bytes, one more than allowed.
    try channel.pair.sink.send(&.{&.{ 0x80, 0x08 }});
    try testing.expectError(error.RecvTooLarge, channel.recv(max_message_size - 1));
}

test "recv_frame incomplete varint" {
    var channel: Channel = undefined;
    try channel.init();
    defer channel.pair.stream.deinit();
    // Continuation bit set but no following byte, then the sink closes.
    try channel.pair.sink.send(&.{&.{0x80}});
    channel.pair.sink.deinit();
    try testing.expectError(error.RecvFailed, channel.recv(max_message_size));
}

test "recv_frame invalid varint overflow" {
    var channel: Channel = undefined;
    try channel.init();
    defer channel.deinit();
    // More than five bytes with continuation bits overflows u32.
    try channel.pair.sink.send(&.{&.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 }});
    try testing.expectError(error.InvalidVarint, channel.recv(max_message_size));
}

fn send_payload(sink: *mocks.Sink, payload: []const u8) framing.Error!void {
    try framing.send_frame(sink, &.{payload}, max_message_size);
}

fn recv_through(io: Io, buffer_size: usize, payload: []const u8) !void {
    var pair = try mocks.channel_with_buffer_size(testing.allocator, io, buffer_size);
    defer pair.sink.deinit();
    defer pair.stream.deinit();
    var sender = try io.concurrent(send_payload, .{ &pair.sink, payload });
    var buffer: [max_message_size]u8 = undefined;
    const received = try framing.recv_frame(&pair.stream, &buffer, max_message_size);
    try testing.expectEqualSlices(u8, payload, received);
    try sender.await(io);
}

fn peek_paths(io: Io) !void {
    // 300 encodes as [0xAC, 0x02] (a two-byte varint).
    var payload: [300]u8 = undefined;
    random_bytes(42, &payload);
    // Normal buffering: after the first prefix byte is read, `peek` supplies the rest.
    try recv_through(io, mocks.default_buffer_size, &payload);
    // Slow path: peek is empty (buffer size 0 means every send blocks until read).
    try recv_through(io, 0, &payload);
    // One-byte buffering: each prefix byte takes a separate read.
    try recv_through(io, 1, &payload);
}

test "recv_frame peek paths" {
    try run_deterministic(peek_paths, .{});
}

fn send_frames(sink: *mocks.Sink, payloads: []const []const u8) framing.Error!void {
    for (payloads) |payload| try framing.send_frame(sink, &.{payload}, max_message_size);
}

// Many frames through every small channel size arrive intact and in order.
fn frames_through_small_buffers(io: Io, buffer_size: usize) !void {
    var storage: [max_message_size]u8 = undefined;
    random_bytes(buffer_size, &storage);
    const sizes = [_]usize{ 0, 1, 127, 128, 129, 300, 1023, 1024, 5 };
    var payloads: [sizes.len][]const u8 = undefined;
    for (&payloads, sizes) |*payload, size| payload.* = storage[0..size];

    var pair = try mocks.channel_with_buffer_size(testing.allocator, io, buffer_size);
    defer pair.sink.deinit();
    defer pair.stream.deinit();
    const frames: []const []const u8 = &payloads;
    var sender = try io.concurrent(send_frames, .{ &pair.sink, frames });
    var buffer: [max_message_size]u8 = undefined;
    for (payloads) |payload| {
        const received = try framing.recv_frame(&pair.stream, &buffer, max_message_size);
        try testing.expectEqualSlices(u8, payload, received);
    }
    try sender.await(io);
}

test "frames survive every small buffer size" {
    for (0..8) |buffer_size| try run_deterministic(frames_through_small_buffers, .{buffer_size});
}

// Seeded fuzz: arbitrary bytes on the wire. Every frame `recv_frame` accepts re-encodes to the
// exact bytes it consumed, and it stops with an error only where the input ends or turns bad.

fn fuzz_run(comptime body: fn (void, *std.testing.Smith) anyerror!void, seed: u64) !void {
    const build_options = @import("build_options");
    var prng = std.Random.DefaultPrng.init(seed ^ build_options.fuzz_seed);
    const random = prng.random();
    var input: [2048]u8 = undefined;
    const total: u64 = @as(u64, 300) * build_options.fuzz_soak;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        const len = random.uintAtMost(usize, input.len);
        random.bytes(input[0..len]);
        // Bias the first byte toward short frames so several decode.
        if (len > 0 and random.boolean()) input[0] &= 0x3f;
        var smith: std.testing.Smith = .{ .in = input[0..len] };
        body({}, &smith) catch |err| {
            std.debug.print("fuzz: seed {d} iteration {d} failed: {t}\n", .{
                seed ^ build_options.fuzz_seed, iteration, err,
            });
            return err;
        };
    }
    try std.testing.fuzz({}, body, .{});
}

fn fuzz_recv_frame(_: void, smith: *std.testing.Smith) anyerror!void {
    var wire: [2048]u8 = undefined;
    const wire_len = smith.slice(&wire);
    const max = smith.valueRangeAtMost(u32, 0, 512);
    var pair = try mocks.channel(testing.allocator, testing.io);
    defer pair.stream.deinit();
    try pair.sink.send(&.{wire[0..wire_len]});
    pair.sink.deinit();

    var buffer: [512]u8 = undefined;
    var offset: usize = 0;
    var frames: usize = 0;
    while (frames <= wire_len) : (frames += 1) {
        const payload = framing.recv_frame(&pair.stream, &buffer, max) catch |err| {
            // Errors only at a bad prefix, an oversized frame, or the end of the input.
            try testing.expect(err == error.InvalidVarint or err == error.RecvTooLarge or
                err == error.RecvFailed);
            return;
        };
        var prefix_bytes: [max_prefix_size]u8 = undefined;
        const prefix = varint_prefix(@intCast(payload.len), &prefix_bytes);
        try testing.expect(payload.len <= max);
        try testing.expectEqualSlices(u8, prefix, wire[offset..][0..prefix.len]);
        offset += prefix.len;
        try testing.expectEqualSlices(u8, payload, wire[offset..][0..payload.len]);
        offset += payload.len;
    }
    unreachable; // Each frame consumes at least one byte.
}

test "fuzz recv_frame against arbitrary wire bytes" {
    try fuzz_run(fuzz_recv_frame, 0x7374_7265_616d);
}
