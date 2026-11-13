//! Tests for `sake.zig`, ported from commonware `stream/src/sake/protocol.rs`: SAKE handshakes
//! carrying CUPS records over mock channels on the deterministic runtime.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");

const stream = @import("root.zig");
const cups = @import("cups.zig");
const sake = @import("sake.zig");
const mocks = runtime.mocks;

const ed25519 = cryptography.ed25519;
const PrivateKey = ed25519.PrivateKey;
const PublicKey = ed25519.PublicKey;
const Protocol = cryptography.handshake.sake.Sake(PrivateKey);

const namespace = "fuzz_transport";
const max_message_size: u32 = 64 * 1024;
const gpa = testing.allocator;

const Upgrade = cups.Cups(sake.Sake(PrivateKey), cryptography.ChaCha20Poly1305);

fn upgrader(signer: PrivateKey, sake_version: sake.Version, cups_version: cups.Version) Upgrade {
    return .init(.{
        .signer = signer,
        .synchrony_bound_ms = 1000,
        .max_handshake_age_ms = 1000,
        .version = sake_version,
    }, cups_version);
}

const AdmitAll = struct {
    pub fn admit(_: AdmitAll, _: PublicKey) Io.Cancelable!bool {
        return true;
    }
};

fn run_deterministic(comptime function: anytype, args: anytype) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 5 * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()} ++ args));
}

fn Listened(comptime Sink: type) type {
    return Upgrade.Accepted(mocks.Stream, Sink);
}

fn listen_task(
    io: Io,
    listener: Upgrade,
    max: u32,
    listener_stream: mocks.Stream,
    listener_sink: mocks.Sink,
) anyerror!Listened(mocks.Sink) {
    return listener.listen(gpa, io, namespace, max, AdmitAll{}, listener_stream, listener_sink);
}

fn dial_task(
    io: Io,
    dialer: Upgrade,
    max: u32,
    peer: PublicKey,
    dialer_stream: mocks.Stream,
    dialer_sink: mocks.Sink,
) anyerror!Upgrade.Connection(mocks.Stream, mocks.Sink) {
    return dialer.dial(gpa, io, namespace, max, peer, dialer_stream, dialer_sink);
}

fn frame_errors_surface(io: Io) !void {
    // A closed peer fails the first handshake frame with a send error.
    const d2l = try mocks.channel(gpa, io);
    var l2d = try mocks.channel(gpa, io);
    defer l2d.sink.deinit();
    var peer_stream = d2l.stream;
    peer_stream.deinit();
    const dialer = upgrader(.from_seed(0), .v1, .v1);
    const peer = PrivateKey.from_seed(1).public_key();
    try testing.expectError(
        error.SendFailed,
        dialer.dial(gpa, io, namespace, max_message_size, peer, l2d.stream, d2l.sink),
    );
}

test "frame errors surface as handshake errors" {
    try run_deterministic(frame_errors_surface, .{});
}

fn bounds_reach_dropped_channels(io: Io) !void {
    // Within the limit, an attempt reaches the closed channel ends and fails without panicking.
    for ([_]u32{ 0, Upgrade.max_size }) |max| {
        for ([_]bool{ true, false }) |dialer| {
            var out = try mocks.channel(gpa, io);
            var in = try mocks.channel(gpa, io);
            out.stream.deinit();
            in.sink.deinit();
            const handshake = upgrader(.from_seed(0), .v1, .v1);
            if (dialer) {
                const peer = PrivateKey.from_seed(1).public_key();
                const result = handshake.dial(gpa, io, namespace, max, peer, in.stream, out.sink);
                try testing.expectError(error.SendFailed, result);
            } else {
                const admit: AdmitAll = .{};
                const result =
                    handshake.listen(gpa, io, namespace, max, admit, in.stream, out.sink);
                try testing.expectError(error.RecvFailed, result);
            }
        }
    }
}

test "max message size bounds" {
    try testing.expectEqual(cups.max_payload(cryptography.ChaCha20Poly1305), Upgrade.max_size);
    try run_deterministic(bounds_reach_dropped_channels, .{});
}

const Peers = struct {
    dialer: Upgrade.Connection(mocks.Stream, mocks.Sink),
    listener: Listened(mocks.Sink),

    fn deinit(peers: *Peers) void {
        peers.dialer.deinit(gpa);
        peers.listener.connection.deinit(gpa);
    }
};

/// Connects a dialer (seed 42) and a listener (seed 24) with the given versions.
fn connect(
    io: Io,
    dialer: struct { sake.Version, cups.Version },
    listener: struct { sake.Version, cups.Version },
    max: u32,
) !Peers {
    const dialer_signer = PrivateKey.from_seed(42);
    const listener_signer = PrivateKey.from_seed(24);
    const d2l = try mocks.channel(gpa, io);
    const l2d = try mocks.channel(gpa, io);
    const listening = upgrader(listener_signer, listener[0], listener[1]);
    var listen_future =
        try io.concurrent(listen_task, .{ io, listening, max, d2l.stream, l2d.sink });
    const dialing = upgrader(dialer_signer, dialer[0], dialer[1]);
    const peer = listener_signer.public_key();
    var dial_future =
        try io.concurrent(dial_task, .{ io, dialing, max, peer, l2d.stream, d2l.sink });

    // The listener verifies the first signed message, so its error is the informative one.
    var accepted = listen_future.await(io) catch |err| {
        if (dial_future.await(io)) |connection| {
            var dialed = connection;
            dialed.deinit(gpa);
        } else |_| {}
        return err;
    };
    errdefer accepted.connection.deinit(gpa);
    try testing.expect(accepted.peer.eql(dialer_signer.public_key()));
    return .{ .dialer = try dial_future.await(io), .listener = accepted };
}

fn setup_and_send(io: Io, cups_version: cups.Version, max: u32) !void {
    // Handshake frames are bounded by their fixed sizes, so the handshake succeeds even when
    // `max` is 0.
    var peers = try connect(io, .{ .v1, cups_version }, .{ .v1, cups_version }, max);
    defer peers.deinit();
    const dialer = &peers.dialer;
    const listener = &peers.listener.connection;

    // The established streams accept only payloads within the configured limit.
    const oversized = try gpa.alloc(u8, max + 1);
    defer gpa.free(oversized);
    @memset(oversized, 0);
    try testing.expectError(error.SendTooLarge, dialer.sender.send(oversized));
    try testing.expectError(error.SendTooLarge, listener.sender.send(oversized));

    // Exchange each message within the limit in both directions.
    for ([_][]const u8{ "", "A", "B", "C" }) |message| {
        if (message.len > max) continue;
        try dialer.sender.send(message);
        try testing.expectEqualStrings(message, try listener.receiver.recv());
        try listener.sender.send(message);
        try testing.expectEqualStrings(message, try dialer.receiver.recv());
    }
}

test "can set up and send messages" {
    for ([_]cups.Version{ .v0, .v1 }) |cups_version| {
        for ([_]u32{ 0, 1, 100, max_message_size }) |max| {
            try run_deterministic(setup_and_send, .{ cups_version, max });
        }
    }
}

const Versions = struct { sake.Version, cups.Version };

fn connect_with(io: Io, dialer: Versions, listener: Versions) !void {
    var peers = try connect(io, dialer, listener, max_message_size);
    defer peers.deinit();
    const dialing = &peers.dialer;
    const listening = &peers.listener.connection;

    // Matching record formats deliver; a V1 receiver rejects V0 records.
    if (dialer[1] == listener[1]) {
        try dialing.sender.send("hello");
        try testing.expectEqualStrings("hello", try listening.receiver.recv());
        try listening.sender.send("world");
        try testing.expectEqualStrings("world", try dialing.receiver.recv());
    } else if (dialer[1] == .v0) {
        // Send enough V0 bytes to reach V1 header authentication.
        try dialing.sender.send("hello");
        try testing.expectError(error.OpenFailed, listening.receiver.recv());
    } else {
        try listening.sender.send("hello");
        try testing.expectError(error.OpenFailed, dialing.receiver.recv());
    }
}

test "versions: mismatched SAKE fails, matching SAKE carries matching CUPS" {
    const versions = [_]Versions{ .{ .v0, .v0 }, .{ .v0, .v1 }, .{ .v1, .v0 }, .{ .v1, .v1 } };
    for (versions) |dialer| {
        for (versions) |listener| {
            var runner = try runtime.deterministic.Runner.init(gpa, .{
                .timeout_ns = 5 * std.time.ns_per_s,
            });
            defer runner.deinit();
            const result = try runner.start(connect_with, .{ runner.io(), dialer, listener });
            if (dialer[0] == listener[0]) {
                try result;
            } else {
                try testing.expectError(error.InvalidSignature, result);
            }
        }
    }
}

/// Counts `send` calls and records how many buffers each call carried.
const CountingSink = struct {
    inner: mocks.Sink,
    chunk_counts: *std.ArrayList(usize),

    pub fn send(sink: *CountingSink, bufs: []const []const u8) mocks.Error!void {
        try sink.chunk_counts.append(gpa, bufs.len);
        return sink.inner.send(bufs);
    }

    pub fn deinit(sink: *CountingSink) void {
        sink.inner.deinit();
    }
};

fn dial_counting(
    io: Io,
    peer: PublicKey,
    dialer_stream: mocks.Stream,
    dialer_sink: CountingSink,
    cups_version: cups.Version,
) anyerror!Upgrade.Connection(mocks.Stream, CountingSink) {
    const dialing = upgrader(.from_seed(42), .v1, cups_version);
    return dialing.dial(gpa, io, namespace, max_message_size, peer, dialer_stream, dialer_sink);
}

/// Connects a dialer whose sink counts sends; the dialer-to-listener channel holds `buffer_size`.
fn connect_counting(
    io: Io,
    cups_version: cups.Version,
    buffer_size: usize,
    chunk_counts: *std.ArrayList(usize),
) !struct { Upgrade.Connection(mocks.Stream, CountingSink), Listened(mocks.Sink) } {
    const listener_signer = PrivateKey.from_seed(24);
    const d2l = try mocks.channel_with_buffer_size(gpa, io, buffer_size);
    const l2d = try mocks.channel(gpa, io);
    const listening = upgrader(listener_signer, .v1, cups_version);
    var listen_future =
        try io.concurrent(listen_task, .{ io, listening, max_message_size, d2l.stream, l2d.sink });
    const sink: CountingSink = .{ .inner = d2l.sink, .chunk_counts = chunk_counts };
    const peer = listener_signer.public_key();
    var dial_future =
        try io.concurrent(dial_counting, .{ io, peer, l2d.stream, sink, cups_version });
    var dialed = try dial_future.await(io);
    errdefer dialed.deinit(gpa);
    return .{ dialed, try listen_future.await(io) };
}

fn send_many_one_chunk(io: Io, cups_version: cups.Version) !void {
    // Size the dialer-to-listener channel to hold the largest batch, so `send_many` returns
    // before the listener reads.
    var chunk_counts: std.ArrayList(usize) = .empty;
    defer chunk_counts.deinit(gpa);
    var dialer, var listener = try connect_counting(io, cups_version, 1 << 20, &chunk_counts);
    defer dialer.deinit(gpa);
    defer listener.connection.deinit(gpa);

    // Batches of zero through nine 60,000-byte messages: the largest are several times the
    // message limit.
    const payload_len = 60_000;
    var payloads: [9][payload_len]u8 = undefined;
    var messages: [9][]const u8 = undefined;
    for (&payloads, &messages, 0..) |*payload, *message, index| {
        payload.* = @splat(@intCast(index));
        message.* = payload;
    }
    for (0..10) |count| {
        chunk_counts.clearRetainingCapacity();
        try dialer.sender.send_many(messages[0..count]);
        if (count == 0) {
            try testing.expectEqual(@as(usize, 0), chunk_counts.items.len);
        } else {
            try testing.expectEqualSlices(usize, &.{1}, chunk_counts.items);
        }
        for (messages[0..count]) |message| {
            try testing.expectEqualSlices(u8, message, try listener.connection.receiver.recv());
        }
    }
}

test "send_many sends a batch in one chunk" {
    for ([_]cups.Version{ .v0, .v1 }) |cups_version| {
        try run_deterministic(send_many_one_chunk, .{cups_version});
    }
}

fn send_many_too_large(io: Io, cups_version: cups.Version) !void {
    var chunk_counts: std.ArrayList(usize) = .empty;
    defer chunk_counts.deinit(gpa);
    var dialer, var listener =
        try connect_counting(io, cups_version, mocks.default_buffer_size, &chunk_counts);
    defer dialer.deinit(gpa);
    defer listener.connection.deinit(gpa);
    // Discard the counts from the handshake frames.
    chunk_counts.clearRetainingCapacity();

    // Reject a batch whose second message exceeds the limit.
    const valid: [32]u8 = @splat(7);
    const oversized = try gpa.alloc(u8, max_message_size + 1);
    defer gpa.free(oversized);
    @memset(oversized, 9);
    try testing.expectError(error.SendTooLarge, dialer.sender.send_many(&.{ &valid, oversized }));
    try testing.expectEqual(@as(usize, 0), chunk_counts.items.len);

    // The next record opens, so the rejected batch sealed nothing.
    try dialer.sender.send("recovered");
    try testing.expectEqual(@as(usize, 1), chunk_counts.items.len);
    try testing.expectEqualStrings("recovered", try listener.connection.receiver.recv());
}

test "send_many too large preserves sender state" {
    for ([_]cups.Version{ .v0, .v1 }) |cups_version| {
        try run_deterministic(send_many_too_large, .{cups_version});
    }
}

/// A frame length prefix declaring one byte more than `size`.
fn oversized_prefix(size: usize, out: *[5]u8) []const u8 {
    var writer = codec.Writer.init(out);
    codec.varint.write(u32, @intCast(size + 1), &writer);
    return writer.written();
}

fn listen_rejects_oversized_peer_key(io: Io) !void {
    // Even with a large application limit, the listener bounds the unauthenticated peer-key
    // frame to the fixed public-key size, and rejects without waiting for more bytes.
    var d2l = try mocks.channel(gpa, io);
    defer d2l.sink.deinit();
    var l2d = try mocks.channel(gpa, io);
    defer l2d.stream.deinit();
    var prefix: [5]u8 = undefined;
    try d2l.sink.send(&.{oversized_prefix(codec.fixed_size(PublicKey).?, &prefix)});
    const listening = upgrader(.from_seed(24), .v1, .v1);
    const admit: AdmitAll = .{};
    const result = listening.listen(gpa, io, namespace, 1 << 20, admit, d2l.stream, l2d.sink);
    try testing.expectError(error.RecvTooLarge, result);
}

test "listen rejects an oversized fixed-size peer key frame" {
    try run_deterministic(listen_rejects_oversized_peer_key, .{});
}

fn dial_rejects_oversized_syn_ack(io: Io) !void {
    var d2l = try mocks.channel(gpa, io);
    defer d2l.stream.deinit();
    var l2d = try mocks.channel(gpa, io);
    defer l2d.sink.deinit();
    // A prefix claiming one byte more than the fixed SynAck encoding, and no payload.
    var prefix: [5]u8 = undefined;
    try l2d.sink.send(&.{oversized_prefix(codec.fixed_size(Protocol.SynAck).?, &prefix)});
    const dialing = upgrader(.from_seed(42), .v1, .v1);
    const peer = PrivateKey.from_seed(24).public_key();
    const result = dialing.dial(gpa, io, namespace, 1 << 20, peer, l2d.stream, d2l.sink);
    try testing.expectError(error.RecvTooLarge, result);
}

test "dial rejects an oversized fixed-size SynAck frame" {
    try run_deterministic(dial_rejects_oversized_syn_ack, .{});
}

test "the handshake prelude is the dialer's encoded public key" {
    // Stream-level check of the cleartext prelude: varint(32) then the 32-byte key.
    try testing.expectEqual(@as(?usize, 32), codec.fixed_size(PublicKey));
    _ = stream.Accepted(PublicKey);
}

// Over the deterministic network: the listener binds and accepts, the dialer dials.

const listen_address: runtime.network.Address = .{ .ip4 = .loopback(3000) };

fn accept_and_listen(
    io: Io,
    listener: *runtime.network.deterministic.Network.Listener,
) anyerror!Listened(mocks.Sink) {
    const accepted = try listener.accept();
    const listening = upgrader(.from_seed(24), .v1, .v1);
    const admit: AdmitAll = .{};
    return listening.listen(
        gpa,
        io,
        namespace,
        max_message_size,
        admit,
        accepted.stream,
        accepted.sink,
    );
}

fn over_network(io: Io, network: *runtime.network.deterministic.Network) !void {
    const listener = try network.bind(listen_address);
    defer listener.deinit();
    var listening = try io.concurrent(accept_and_listen, .{ io, listener });
    const connection = try network.dial(listen_address);
    const dialing = upgrader(.from_seed(42), .v1, .v1);
    const peer = PrivateKey.from_seed(24).public_key();
    var dialer = dialing.dial(
        gpa,
        io,
        namespace,
        max_message_size,
        peer,
        connection.stream,
        connection.sink,
    ) catch |err| {
        if (listening.cancel(io)) |accepted| {
            var owned = accepted;
            owned.connection.deinit(gpa);
        } else |_| {}
        return err;
    };
    defer dialer.deinit(gpa);
    var listened = try listening.await(io);
    defer listened.connection.deinit(gpa);
    try testing.expect(listened.peer.eql(PrivateKey.from_seed(42).public_key()));

    try dialer.sender.send_many(&.{ "hello", "", "network" });
    for ([_][]const u8{ "hello", "", "network" }) |message| {
        try testing.expectEqualStrings(message, try listened.connection.receiver.recv());
    }
    try listened.connection.sender.send("reply");
    try testing.expectEqualStrings("reply", try dialer.receiver.recv());
}

test "SakeCups over the deterministic network" {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 5 * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try (try runner.start(over_network, .{ runner.io(), runner.network() }));
}
