//! SAKE and CUPS wire conformance, ported from commonware `stream/src/sake/conformance.rs`.
//!
//! Each case runs a full connection on the deterministic runtime, seeded by the case, and
//! commits every byte each peer wrote: the handshake messages and one record of each length
//! class in each direction. Ephemeral keys, timestamps, and payloads come from the runtime's
//! RNG, drawn in commonware's order, so the hashes match commonware's `conformance.toml`.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const build_options = @import("build_options");
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");

const cups = @import("cups.zig");
const sake = @import("sake.zig");
const mocks = runtime.mocks;

const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Upgrade = cups.Cups(sake.Sake(PrivateKey), cryptography.ChaCha20Poly1305);

const conformance_file = @embedFile("conformance.toml");
const namespace = "_COMMONWARE_STREAM_CUPS_CONFORMANCE_TESTS";

/// Largest payload either peer accepts.
const max_message_size: u32 = 1 << 17;

/// Payload lengths covering one-, two-, and three-byte version 0 length prefixes. The top range
/// holds payloads within the message limit whose version 0 frame exceeds that limit.
const lengths = [4][2]usize{
    .{ 0, 111 },
    .{ 112, 16_367 },
    .{ 16_368, 131_053 },
    .{ 131_054, max_message_size },
};

/// Forwards writes to a mock sink while recording their bytes.
const Tap = struct {
    sink: mocks.Sink,
    log: *std.ArrayList(u8),
    gpa: Allocator,

    pub fn send(tap: *Tap, bufs: []const []const u8) mocks.Error!void {
        for (bufs) |chunk| try tap.log.appendSlice(tap.gpa, chunk);
        try tap.sink.send(bufs);
    }

    pub fn deinit(tap: *Tap) void {
        tap.sink.deinit();
    }
};

const Connection = Upgrade.Connection(mocks.Stream, Tap);
const Accepted = Upgrade.Accepted(mocks.Stream, Tap);

const AdmitAll = struct {
    pub fn admit(_: AdmitAll, _: PublicKey) Io.Cancelable!bool {
        return true;
    }
};

fn upgrader(signer: PrivateKey, versions: Versions) Upgrade {
    return .init(.{
        .signer = signer,
        .synchrony_bound_ms = 5_000,
        .max_handshake_age_ms = 10_000,
        .version = versions.sake,
    }, versions.cups);
}

const Versions = struct { sake: sake.Version, cups: cups.Version };

fn listen_task(
    gpa: Allocator,
    io: Io,
    listener: Upgrade,
    stream: mocks.Stream,
    sink: Tap,
) anyerror!Accepted {
    return listener.listen(gpa, io, namespace, max_message_size, AdmitAll{}, stream, sink);
}

/// commonware's executor queues a task once per wake, and joining the finished listener wakes
/// the root task twice, so the iteration that resumes it holds the root twice and shuffles that
/// batch (one `shuffle` of two entries, seen in its executor's trace). zigware's runtime queues a
/// woken task once and draws nothing there. Draw the same shuffle here, so the records' lengths
/// and payloads come from the same RNG position as commonware's.
fn consume_join_shuffle(rng: *utils.rng.TestRng) void {
    var batch = [2]u8{ 0, 1 };
    runtime.rng.shuffle(rng, u8, &batch);
    assert(batch[0] != batch[1]);
}

/// Sends a seeded payload drawn from `range` and checks the peer receives it.
fn send_checked(
    gpa: Allocator,
    rng: *utils.rng.TestRng,
    range: [2]usize,
    sender: anytype,
    receiver: anytype,
) !void {
    const len = utils.rng.range_at_most(rng, usize, range[0], range[1]);
    const message = try gpa.alloc(u8, len);
    defer gpa.free(message);
    rng.fill_bytes(message);
    try sender.send(message);
    try testing.expectEqualSlices(u8, message, try receiver.recv());
}

/// The connection itself, as commonware's `exchange` closure; writes land in `d2l` and `l2d`.
fn exchange_root(
    gpa: Allocator,
    runner: *runtime.deterministic.Runner,
    versions: Versions,
    d2l: *std.ArrayList(u8),
    l2d: *std.ArrayList(u8),
) !void {
    const io = runner.io();
    // Start at a seeded time so handshake timestamps have nonzero upper bytes.
    const start_ms = utils.rng.range_less_than(&runner.rng, u64, 1 << 40, 1 << 41);
    try io.sleep(.fromMilliseconds(@intCast(start_ms)), .awake);
    const dialer = PrivateKey.from_seed(runner.rng.next_u64());
    const listener = PrivateKey.from_seed(runner.rng.next_u64());

    const to_listener = try mocks.channel_with_buffer_size(gpa, io, 1 << 20);
    const to_dialer = try mocks.channel_with_buffer_size(gpa, io, 1 << 20);
    const dialer_sink: Tap = .{ .sink = to_listener.sink, .log = d2l, .gpa = gpa };
    const listener_sink: Tap = .{ .sink = to_dialer.sink, .log = l2d, .gpa = gpa };

    var listening = try io.concurrent(listen_task, .{
        gpa, io, upgrader(listener, versions), to_listener.stream, listener_sink,
    });
    var dialed = upgrader(dialer, versions).dial(
        gpa,
        io,
        namespace,
        max_message_size,
        listener.public_key(),
        to_dialer.stream,
        dialer_sink,
    ) catch |err| {
        if (listening.await(io)) |accepted| {
            var owned = accepted;
            owned.deinit(gpa);
        } else |_| {}
        return err;
    };
    defer dialed.deinit(gpa);
    var accepted = try listening.await(io);
    defer accepted.deinit(gpa);
    consume_join_shuffle(&runner.rng);
    try testing.expect(accepted.peer.eql(dialer.public_key()));

    // Send one record of each length class in each direction.
    const listened = &accepted.connection;
    for (lengths) |range| {
        try send_checked(gpa, &runner.rng, range, &dialed.sender, &listened.receiver);
        try send_checked(gpa, &runner.rng, range, &listened.sender, &dialed.receiver);
    }
}

/// Every byte each peer wrote in a connection at `versions`, dialer's first (caller frees).
fn exchange(gpa: Allocator, seed: u64, versions: Versions) ![]u8 {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = seed });
    defer runner.deinit();
    var d2l: std.ArrayList(u8) = .empty;
    defer d2l.deinit(gpa);
    var l2d: std.ArrayList(u8) = .empty;
    defer l2d.deinit(gpa);
    try (try runner.start(exchange_root, .{ gpa, &runner, versions, &d2l, &l2d }));
    assert(d2l.items.len > 0 and l2d.items.len > 0);

    // Keep the directions apart so the log does not depend on how the writes interleave.
    const log = try gpa.alloc(u8, d2l.items.len + l2d.items.len);
    @memcpy(log[0..d2l.items.len], d2l.items);
    @memcpy(log[d2l.items.len..], l2d.items);
    return log;
}

fn Exchange(comptime versions: Versions) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            return exchange(gpa, seed, versions);
        }
    };
}

/// 256 connections of up to 300 KiB each: run in Debug only with `-Dslow-tests`.
fn skip_unless_fast() error{SkipZigTest}!void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
}

fn verify(comptime name: []const u8, comptime versions: Versions) !void {
    try skip_unless_fast();
    try conformance.verify(
        Exchange(versions),
        testing.allocator,
        "commonware_stream::sake::conformance::" ++ name,
        256,
        conformance_file,
    );
}

test "conformance CupsV0" {
    try verify("CupsV0", .{ .sake = .v0, .cups = .v0 });
}

test "conformance CupsV1" {
    try verify("CupsV1", .{ .sake = .v1, .cups = .v1 });
}

test "conformance SakeV0CupsV1" {
    try verify("SakeV0CupsV1", .{ .sake = .v0, .cups = .v1 });
}

test "conformance SakeV1CupsV0" {
    try verify("SakeV1CupsV0", .{ .sake = .v1, .cups = .v0 });
}
