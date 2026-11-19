//! Tests of one lookup connection (commonware `lookup/actors/peer/actor.rs` tests): an
//! unregistered channel ends the connection without a metric series of its own, queued frames
//! go out batched into single writes, and an oversized payload fails to decode. Commonware
//! runs them over an encrypted mock channel; `Peer.run` is generic over its stream halves, so
//! these drive it with scripted halves instead.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const types = @import("types.zig");
const labels = @import("metrics.zig");
const peer_mod = @import("peer.zig");
const outbox_mod = @import("../outbox.zig");
const channels_mod = @import("../channels.zig");

const Key = cryptography.ed25519.PublicKey;
const Peer = peer_mod.Peer(Key);
const Label = labels.Message(Key);
const Outbox = outbox_mod.Outbox;
const Frame = outbox_mod.Frame;
const gpa = testing.allocator;

const max_message_size: u32 = 64 * 1024;

fn local_key() Key {
    return cryptography.ed25519.PrivateKey.from_seed(1).public_key();
}

/// Records each `send_many` (one runtime write) and the frames in it.
const Sink = struct {
    writes: u32 = 0,
    frames: std.ArrayList([]u8) = .empty,

    pub fn send_many(sink: *Sink, parts: []const []const u8) !void {
        sink.writes += 1;
        for (parts) |part| try sink.frames.append(gpa, try gpa.dupe(u8, part));
    }

    fn deinit(sink: *Sink) void {
        for (sink.frames.items) |frame| gpa.free(frame);
        sink.frames.deinit(gpa);
    }

    fn message(sink: *const Sink, index: usize) !types.Message {
        const bytes = sink.frames.items[index];
        return codec.decode_cfg(types.Message, gpa, bytes, bytes.len);
    }
};

/// Hands out scripted frames, then waits until canceled.
const Source = struct {
    io: Io,
    frames: []const []const u8,
    next: usize = 0,

    pub fn recv(source: *Source) ![]const u8 {
        if (source.next == source.frames.len) {
            try source.io.sleep(.fromSeconds(3600), .awake);
            return error.Closed;
        }
        defer source.next += 1;
        return source.frames[source.next];
    }
};

/// A connection's surroundings: metric families, one registered channel, and an outbox.
const Setup = struct {
    registry: metrics.Registry,
    families: Peer.Families,
    router: Peer.Channels.Router,
    channels: Peer.Channels,
    registered: Peer.Channels.Registered,
    outbox: Outbox,
    config: Peer.Config,

    /// Must not move afterwards: the channels point at the router.
    fn init(setup: *Setup, io: Io, send_batch_size: usize, max_size: u32) !void {
        setup.registry = metrics.Registry.init(gpa);
        setup.families = try .init(metrics.Scope.init(&setup.registry));
        setup.router = try .init(gpa, io);
        setup.channels = .init(gpa, io, &setup.router, max_size, 1);
        setup.registered = try setup.channels.register(0, .per_second(100));
        setup.outbox = .init(gpa, io, 10);
        setup.config = .{
            .ping_frequency = .from_secs(30),
            .send_batch_size = send_batch_size,
            .max_message_size = max_size,
        };
    }

    fn deinit(setup: *Setup) void {
        setup.outbox.kill();
        setup.outbox.deinit();
        setup.registered.deinit();
        setup.channels.deinit();
        setup.router.deinit();
        setup.families.deinit();
        setup.registry.deinit();
    }

    fn run(setup: *Setup, io: Io, sink: *Sink, source: *Source) anyerror!void {
        return Peer.run(
            gpa,
            io,
            &setup.config,
            &setup.families,
            local_key(),
            sink,
            source,
            &setup.outbox,
            &setup.channels,
        );
    }

    fn queue(setup: *Setup, payload: []const u8) !void {
        const frame = try Frame.create(gpa, 0, &.{payload});
        // The outbox takes its own reference.
        defer frame.release();
        try testing.expect(setup.outbox.send(frame, false).accepted());
    }
};

fn encode(message: types.Message) ![]u8 {
    return codec.encode(types.Message, gpa, message);
}

fn invalid_channel(io: Io) !void {
    var setup: Setup = undefined;
    try setup.init(io, 8, max_message_size);
    defer setup.deinit();
    const ping = try encode(.ping);
    defer gpa.free(ping);
    const attack = try encode(.{ .data = .{ .channel = 99_999, .message = "attack" } });
    defer gpa.free(attack);
    var sink: Sink = .{};
    defer sink.deinit();
    var source: Source = .{ .io = io, .frames = &.{ ping, attack } };
    try testing.expectError(error.InvalidChannel, setup.run(io, &sink, &source));
    const received = setup.families.received.metric();
    const limited = setup.families.rate_limited.metric();
    const key = local_key();
    // The ping is counted and not rate limited.
    try testing.expectEqual(@as(u64, 1), received.get(.new_ping(key)).?.get());
    try testing.expectEqual(@as(u64, 0), limited.get(.new_ping(key)).?.get());
    // The registered channel has a series at zero from connection start.
    try testing.expectEqual(@as(u64, 0), received.get(.new_data(key, 0)).?.get());
    // The attacker's channel makes no series; the bounded invalid one counts it.
    try testing.expect(received.get(.new_data(key, 99_999)) == null);
    try testing.expect(limited.get(.new_data(key, 99_999)) == null);
    try testing.expectEqual(@as(u64, 1), received.get(.new_invalid(key)).?.get());
}

test "an invalid channel ends the connection without a metric series of its own" {
    // commonware `test_invalid_channel_no_unbounded_metric_cardinality`.
    try run(invalid_channel);
}

fn expect_data(sink: *const Sink, index: usize, payload: []const u8) !void {
    const message = try sink.message(index);
    try testing.expect(message == .data);
    try testing.expectEqual(@as(u64, 0), message.data.channel);
    try testing.expectEqualStrings(payload, message.data.message);
}

/// Waits until `sink` holds `frames` frames.
fn wait_frames(io: Io, sink: *const Sink, frames: usize, timeout_ms: u32) !void {
    for (0..timeout_ms) |_| {
        if (sink.frames.items.len >= frames) return;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

const Result = @typeInfo(@TypeOf(Setup.run)).@"fn".return_type.?;

fn batching(io: Io) !void {
    var setup: Setup = undefined;
    try setup.init(io, 2, max_message_size);
    defer setup.deinit();
    var sink: Sink = .{};
    defer sink.deinit();
    var source: Source = .{ .io = io, .frames = &.{} };
    try setup.queue("first");
    try setup.queue("second");
    var task = try io.concurrent(Setup.run, .{ &setup, io, &sink, &source });
    defer _ = task.cancel(io) catch {};
    try wait_frames(io, &sink, 2, 1_000);
    try expect_data(&sink, 0, "first");
    try expect_data(&sink, 1, "second");
    try testing.expectEqual(@as(u32, 1), sink.writes);
    const sent = setup.families.sent.metric();
    const key = local_key();
    try testing.expectEqual(@as(u64, 2), sent.get(.new_data(key, 0)).?.get());
    try testing.expectEqual(@as(u64, 0), sent.get(.new_ping(key)).?.get());
    // A full batch leaves the rest for the next write.
    const payloads = [_][]const u8{ "data3", "data4", "data5" };
    for (payloads) |payload| try setup.queue(payload);
    try wait_frames(io, &sink, 5, 1_000);
    for (payloads, 2..) |payload, index| try expect_data(&sink, index, payload);
    try testing.expectEqual(@as(u32, 3), sink.writes);
    // The next write is the periodic ping, counted under its own label.
    try wait_frames(io, &sink, 6, 60_000);
    try testing.expect(try sink.message(5) == .ping);
    try testing.expectEqual(@as(u64, 1), sent.get(.new_ping(key)).?.get());
    setup.outbox.kill();
    try testing.expectError(error.Killed, task.await(io));
}

test "queued frames go out batched into single writes" {
    // commonware `test_batches_outbound_sends_into_single_runtime_write`.
    try run(batching);
}

fn oversized(io: Io) !void {
    const limit: u32 = 1024;
    var setup: Setup = undefined;
    try setup.init(io, 8, limit);
    defer setup.deinit();
    const payload = try gpa.alloc(u8, limit + 1);
    defer gpa.free(payload);
    @memset(payload, 0);
    const frame = try encode(.{ .data = .{ .channel = 0, .message = payload } });
    defer gpa.free(frame);
    var sink: Sink = .{};
    defer sink.deinit();
    var source: Source = .{ .io = io, .frames = &.{frame} };
    try testing.expectError(error.InvalidLength, setup.run(io, &sink, &source));
}

test "an oversized payload fails to decode and ends the connection" {
    // commonware `test_oversized_data_returns_error`.
    try run(oversized);
}

fn run(comptime function: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .timeout_ns = 120 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
}

test "two kills into a full one-slot mailbox leave one kill and nothing after" {
    // commonware lookup `kill_retained_on_overflow`. A kill here is a state that drains the
    // queues, so it lands with the mailbox full and nothing is left behind it.
    var outbox = Outbox.init(gpa, Io.failing, 1);
    defer outbox.deinit();
    const frame = try Frame.create(gpa, 0, &.{"queued"});
    defer frame.release();
    try testing.expect(outbox.send(frame, false).accepted());
    try testing.expect(!outbox.send(frame, false).accepted());
    try testing.expectEqual(@as(u32, 2), frame.refs.load(.monotonic));
    outbox.kill();
    outbox.kill();
    // The kill dropped the queued frame's reference.
    try testing.expectEqual(@as(u32, 1), frame.refs.load(.monotonic));
    for (0..2) |_| try testing.expect(outbox.try_next().? == .killed);
    try testing.expect(!outbox.send(frame, false).accepted());
}
