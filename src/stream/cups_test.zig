//! Tests for `cups.zig`, ported from commonware `stream/src/cups/protocol.rs`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const build_options = @import("build_options");
const runtime = @import("runtime");
const utils = @import("utils");

const stream = @import("root.zig");
const cups = @import("cups.zig");
const mocks = runtime.mocks;

const Transcript = cryptography.Transcript;
const RecordCipher = cryptography.ChaCha20Poly1305;
const Version = cups.Version;

/// Message limit, in bytes, of the test senders and receivers.
const max_message_size: u32 = 64 * 1024;
const tag_size = cups.tag_size(RecordCipher);

/// Supplies a deterministic test transcript to both roles, or rejects the handshake.
const TestHandshake = struct {
    framing: ?cryptography.transcript.Version,

    fn transcript(self: TestHandshake, namespace: []const u8) error{Rejected}!Transcript {
        const framing = self.framing orelse return error.Rejected;
        var result = Transcript.init(namespace, framing);
        result.commit("test shared secret");
        return result;
    }

    pub fn public_key(_: TestHandshake) void {}

    pub fn dial(
        self: TestHandshake,
        _: Io,
        namespace: []const u8,
        _: void,
        _: *mocks.Stream,
        _: *mocks.Sink,
    ) error{Rejected}!Transcript {
        assert(std.mem.eql(u8, namespace, "application"));
        return self.transcript(namespace);
    }

    pub fn listen(
        self: TestHandshake,
        _: Io,
        namespace: []const u8,
        bouncer: anytype,
        _: *mocks.Stream,
        _: *mocks.Sink,
    ) !stream.Accepted(void) {
        assert(std.mem.eql(u8, namespace, "application"));
        if (!try bouncer.admit({})) return error.Rejected;
        return .{ .peer = {}, .transcript = try self.transcript(namespace) };
    }
};

const AdmitAll = struct {
    pub fn admit(_: AdmitAll, _: void) Io.Cancelable!bool {
        return true;
    }
};

const TestCups = cups.Cups(TestHandshake, RecordCipher);

test "header len rejects oversized payload" {
    // commonware `test_header_len_rejects_oversized_payload` (`should_panic`, "payload exceeds
    // stream limit"): the assert that guards `header_len`.
    try utils.death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            _ = cups.header_len(RecordCipher, .v1, std.math.maxInt(u32));
        }
    }.body);
}

fn run_deterministic(comptime function: anytype, args: anytype) !void {
    for (0..build_options.fuzz_soak) |round| {
        const config: runtime.deterministic.Config = .{ .seed = soak_seed(0, round) };
        var runner = try runtime.deterministic.Runner.init(testing.allocator, config);
        defer runner.deinit();
        try (try runner.start(function, .{runner.io()} ++ args));
    }
}

/// The `round`-th seed of a deterministic test whose unsoaked seed is `base`: `base` first, then
/// `-Dfuzz-soak` rounds in all, spread by `-Dfuzz-seed`. Soaked rounds print their seed, so a
/// failure names the seed to replay.
fn soak_seed(base: u64, round: u64) u64 {
    if (round == 0) return base;
    const seed = base +% build_options.fuzz_seed *% 0x9e3779b97f4a7c15 +% round;
    std.debug.print("dst: seed {d}\n", .{seed});
    return seed;
}

/// The cipher every test peer derives, so each side replays the other's positions.
fn cipher() RecordCipher {
    var rng = utils.rng.TestRng.init(0);
    return RecordCipher.random(&rng);
}

/// Seals `message` with `sealer` into `out` (ciphertext then tag) and returns it.
fn sealed(sealer: *RecordCipher, message: []const u8, out: []u8) []u8 {
    @memcpy(out[0..message.len], message);
    const tag = sealer.seal(&.{}, out[0..message.len]) catch unreachable; // Fresh cipher.
    @memcpy(out[message.len..][0..tag_size], &tag);
    return out[0 .. message.len + tag_size];
}

const TestSender = cups.Sender(RecordCipher, mocks.Sink);
const TestReceiver = cups.Receiver(RecordCipher, mocks.Stream);

test "cipher derivation pins the fork, mode, and directions" {
    for ([_]cryptography.transcript.Version{ .v0, .v1 }) |framing| {
        for ([_]Version{ .v0, .v1 }) |version| {
            // Derive the traffic ciphers through the CUPS setup path.
            const handshake: TestHandshake = .{ .framing = framing };
            const secret = try handshake.transcript("application");
            const actual = cups.ciphers(RecordCipher, secret, version);

            // Build an oracle from the specified namespace, mode, and direction labels.
            var expected = try handshake.transcript("application");
            if (version == .v1) {
                expected = expected.fork("_COMMONWARE_STREAM_CUPS");
                expected.commit(&.{1});
            }
            var l2d_noise = expected.noise("cipher_l2d");
            var d2l_noise = expected.noise("cipher_d2l");
            const oracle = [2]RecordCipher{
                RecordCipher.random(&l2d_noise),
                RecordCipher.random(&d2l_noise),
            };

            // Each directional key must produce the oracle's ciphertext and tag.
            for ([2]RecordCipher{ actual[0], actual[1] }, oracle) |actual_cipher, oracle_cipher| {
                var a = actual_cipher;
                var b = oracle_cipher;
                var a_bytes = "oracle".*;
                var b_bytes = "oracle".*;
                try testing.expectEqual(try b.seal(&.{}, &b_bytes), try a.seal(&.{}, &a_bytes));
                try testing.expectEqualSlices(u8, &b_bytes, &a_bytes);
            }
            // The two directions differ.
            try testing.expect(!std.mem.eql(u8, &actual[0].key, &actual[1].key));
        }
    }
}

fn round_trip(io: Io, framing: cryptography.transcript.Version, version: Version) !void {
    const gpa = testing.allocator;
    // Establish both CUPS roles from the same handshake transcript.
    const d2l = try mocks.channel(gpa, io);
    const l2d = try mocks.channel(gpa, io);
    const upgrader = TestCups.init(.{ .framing = framing }, version);
    var dialer = try upgrader.dial(gpa, io, "application", 64, {}, l2d.stream, d2l.sink);
    defer dialer.deinit(gpa);
    const admit: AdmitAll = .{};
    var listener = try upgrader.listen(gpa, io, "application", 64, admit, d2l.stream, l2d.sink);
    defer listener.connection.deinit(gpa);

    // Exchange records in both directions to check the send/receive key assignment.
    try dialer.sender.send("dial");
    try testing.expectEqualStrings("dial", try listener.connection.receiver.recv());
    try listener.connection.sender.send("listen");
    try testing.expectEqualStrings("listen", try dialer.receiver.recv());
}

test "custom handshake round trip" {
    for ([_]cryptography.transcript.Version{ .v0, .v1 }) |framing| {
        for ([_]Version{ .v0, .v1 }) |version| {
            try run_deterministic(round_trip, .{ framing, version });
        }
    }
}

fn custom_handshake_errors(io: Io) !void {
    const gpa = testing.allocator;
    for ([_]Version{ .v0, .v1 }) |version| {
        const upgrader = TestCups.init(.{ .framing = null }, version);

        // Dialing returns the handshake's error and releases the connection.
        var dial_pair = try mocks.channel(gpa, io);
        var dial_peer = try mocks.channel(gpa, io);
        try testing.expectError(
            error.Rejected,
            upgrader.dial(gpa, io, "application", 1, {}, dial_pair.stream, dial_peer.sink),
        );
        try testing.expectError(error.SendFailed, dial_pair.sink.send(&.{"x"}));
        var byte: [1]u8 = undefined;
        try testing.expectError(error.RecvFailed, dial_peer.stream.recv(&byte));
        dial_pair.sink.deinit();
        dial_peer.stream.deinit();

        // Listening does the same.
        var listen_pair = try mocks.channel(gpa, io);
        var listen_peer = try mocks.channel(gpa, io);
        try testing.expectError(error.Rejected, upgrader.listen(
            gpa,
            io,
            "application",
            1,
            AdmitAll{},
            listen_pair.stream,
            listen_peer.sink,
        ));
        try testing.expectError(error.SendFailed, listen_pair.sink.send(&.{"x"}));
        try testing.expectError(error.RecvFailed, listen_peer.stream.recv(&byte));
        listen_pair.sink.deinit();
        listen_peer.stream.deinit();
    }
}

test "custom handshake errors surface and release the connection" {
    try run_deterministic(custom_handshake_errors, .{});
}

fn record_encoding(io: Io, version: Version) !void {
    const gpa = testing.allocator;
    var pair = try mocks.channel(gpa, io);
    defer pair.stream.deinit();
    var sender = try TestSender.init(gpa, cipher(), pair.sink, 64, version);
    defer sender.deinit();
    const sevens: [64]u8 = @splat(7);
    const messages = [_][]const u8{ "", "hello", &sevens };
    try sender.send_many(&messages);

    // A cipher from the same seed reproduces the sender's key and nonce sequence.
    var replay = cipher();
    for (messages) |message| {
        const len: u32 = @intCast(message.len);
        var expected_bytes: [128]u8 = undefined;
        var expected_len: usize = 0;
        switch (version) {
            // V0 prefixes a plaintext length that counts the tag; V1 a sealed length without.
            .v0 => {
                var writer = codec.Writer.init(&expected_bytes);
                codec.varint.write(u32, len + tag_size, &writer);
                expected_len = writer.written().len;
            },
            .v1 => {
                var be: [4]u8 = undefined;
                std.mem.writeInt(u32, &be, len, .big);
                expected_len = sealed(&replay, &be, &expected_bytes).len;
            },
        }
        expected_len += sealed(&replay, message, expected_bytes[expected_len..]).len;
        try testing.expectEqual(expected_len, cups.record_len(RecordCipher, version, message.len));
        var received: [128]u8 = undefined;
        try pair.stream.recv(received[0..expected_len]);
        const expected = expected_bytes[0..expected_len];
        try testing.expectEqualSlices(u8, expected, received[0..expected_len]);
    }
}

test "record encoding" {
    for ([_]Version{ .v0, .v1 }) |version| try run_deterministic(record_encoding, .{version});
}

test "max size fits the tag" {
    try testing.expectEqual(std.math.maxInt(u32), TestCups.max_size + tag_size);
    try testing.expectEqual(@as(usize, 20), cups.header_len(RecordCipher, .v1, 0));
    try testing.expectEqual(@as(usize, 1), cups.header_len(RecordCipher, .v0, 111));
    try testing.expectEqual(@as(usize, 2), cups.header_len(RecordCipher, .v0, 112));
}

/// A receiver whose peer sends `bytes` (or closes, for null) and keeps its sink open.
fn expect_recv_error(io: Io, version: Version, bytes: ?[]const u8, expected: cups.Error) !void {
    const gpa = testing.allocator;
    var pair = try mocks.channel(gpa, io);
    var receiver = try TestReceiver.init(gpa, cipher(), pair.stream, max_message_size, version);
    defer receiver.deinit(gpa);
    if (bytes) |payload| {
        try pair.sink.send(&.{payload});
    } else {
        pair.sink.deinit();
    }
    defer if (bytes != null) pair.sink.deinit();

    // The runtime reports a stall if rejection waited for bytes that never come.
    try testing.expectError(expected, receiver.recv());
    // Nothing more is read: a receiver that still read would block on the open sink.
    try testing.expectError(error.StreamClosed, receiver.recv());
}

fn v0_prefix(len: u32, out: *[5]u8) []const u8 {
    var writer = codec.Writer.init(out);
    codec.varint.write(u32, len, &writer);
    return writer.written();
}

fn recv_error_cases(io: Io) !void {
    const oversized = max_message_size + 1;
    var prefix: [5]u8 = undefined;

    // V0: a corrupted empty record, an oversized length, a prefix that is not a varint.
    var v0_corrupt: [1 + tag_size]u8 = undefined;
    _ = v0_prefix(tag_size, v0_corrupt[0..5]);
    var v0_cipher = cipher();
    _ = sealed(&v0_cipher, "", v0_corrupt[1..]);
    v0_corrupt[1] ^= 1;
    try expect_recv_error(io, .v0, &v0_corrupt, error.OpenFailed);
    try expect_recv_error(io, .v0, v0_prefix(oversized + tag_size, &prefix), error.RecvTooLarge);
    try expect_recv_error(io, .v0, &(@as([5]u8, @splat(0xFF))), error.InvalidVarint);
    try expect_recv_error(io, .v0, null, error.RecvFailed);
    // A record shorter than a tag.
    var short: [tag_size]u8 = @splat(0);
    short[0] = tag_size - 1;
    try expect_recv_error(io, .v0, &short, error.OpenFailed);

    // V1: a corrupted header, an oversized sealed length, a closed peer.
    var header: [4 + tag_size]u8 = undefined;
    var v1_cipher = cipher();
    _ = sealed(&v1_cipher, &.{ 0, 0, 0, 0 }, &header);
    header[0] ^= 1;
    try expect_recv_error(io, .v1, &header, error.OpenFailed);
    var be: [4]u8 = undefined;
    std.mem.writeInt(u32, &be, oversized, .big);
    var oversized_cipher = cipher();
    try expect_recv_error(io, .v1, sealed(&oversized_cipher, &be, &header), error.RecvTooLarge);
    try expect_recv_error(io, .v1, null, error.RecvFailed);
}

test "every receive error closes the receiver" {
    try run_deterministic(recv_error_cases, .{});
}

fn invalid_header_cases(io: Io) !void {
    // A flipped length byte, a flipped tag byte, one above the limit, and u32 max.
    const Case = struct { length: u32, corrupt: ?usize, expected: cups.Error };
    const cases = [_]Case{
        .{ .length = 0, .corrupt = 0, .expected = error.OpenFailed },
        .{ .length = 0, .corrupt = 4, .expected = error.OpenFailed },
        .{ .length = max_message_size + 1, .corrupt = null, .expected = error.RecvTooLarge },
        .{ .length = std.math.maxInt(u32), .corrupt = null, .expected = error.RecvTooLarge },
    };
    for (cases) |case| {
        var be: [4]u8 = undefined;
        std.mem.writeInt(u32, &be, case.length, .big);
        var header: [4 + tag_size]u8 = undefined;
        var header_cipher = cipher();
        _ = sealed(&header_cipher, &be, &header);
        if (case.corrupt) |offset| header[offset] ^= 1;
        try expect_recv_error(io, .v1, &header, case.expected);
    }
}

test "v1 rejects an invalid header before the body" {
    try run_deterministic(invalid_header_cases, .{});
}

fn frame_errors(io: Io) !void {
    // Senders without a cipher (after a failed seal) refuse every record, writing nothing.
    const gpa = testing.allocator;
    for ([_]Version{ .v0, .v1 }) |version| {
        var pair = try mocks.channel(gpa, io);
        defer pair.stream.deinit();
        var sender = try TestSender.init(gpa, cipher(), pair.sink, max_message_size, version);
        defer sender.deinit();

        // Oversized records report SendTooLarge without consuming the cipher.
        const oversized = try gpa.alloc(u8, max_message_size + 1);
        defer gpa.free(oversized);
        @memset(oversized, 0);
        try testing.expectError(error.SendTooLarge, sender.send(oversized));
        try testing.expectError(error.SendTooLarge, sender.send_many(&.{ "ok", oversized }));
        try testing.expectEqual(@as(u128, 0), sender.cipher.?.nonce);
        try testing.expectEqual(@as(usize, 0), pair.stream.shared.channel.items.len);

        // An empty batch sends nothing.
        try sender.send_many(&.{});
        try testing.expectEqual(@as(usize, 0), pair.stream.shared.channel.items.len);

        sender.cipher = null;
        try testing.expectError(error.StreamClosed, sender.send("x"));
        try testing.expectError(error.StreamClosed, sender.send_many(&.{"x"}));
        try testing.expectEqual(@as(usize, 0), pair.stream.shared.channel.items.len);
    }
}

test "send failures refuse without writing" {
    try run_deterministic(frame_errors, .{});
}

fn whole_batch_sized_first(io: Io, version: Version) !void {
    // 65,536 valid messages through one shared buffer total more than 4 GiB of records; one
    // message over the limit ends the batch and nothing is sealed or sent.
    const gpa = testing.allocator;
    const limit = 65_536;
    var pair = try mocks.channel(gpa, io);
    defer pair.stream.deinit();
    var sender = try TestSender.init(gpa, cipher(), pair.sink, limit, version);
    defer sender.deinit();
    const payload = try gpa.alloc(u8, limit + 1);
    defer gpa.free(payload);
    @memset(payload, 0);
    const batch = try gpa.alloc([]const u8, 65_537);
    defer gpa.free(batch);
    for (batch[0..65_536]) |*message| message.* = payload[0..limit];
    batch[65_536] = payload;
    try testing.expectError(error.SendTooLarge, sender.send_many(batch));
    try testing.expectEqual(@as(u128, 0), sender.cipher.?.nonce);
    try testing.expectEqual(@as(usize, 0), pair.stream.shared.channel.items.len);
}

test "send_many sizes the whole batch before sealing" {
    for ([_]Version{ .v0, .v1 }) |version| {
        try run_deterministic(whole_batch_sized_first, .{version});
    }
}

fn many_records(io: Io, version: Version) !void {
    // A batch larger than the sender buffer splits across sink calls and still decodes in order.
    const gpa = testing.allocator;
    const pair = try mocks.channel(gpa, io);
    var sender = try TestSender.init(gpa, cipher(), pair.sink, 100, version);
    defer sender.deinit();
    var receiver = try TestReceiver.init(gpa, cipher(), pair.stream, 100, version);
    defer receiver.deinit(gpa);
    var storage: [100]u8 = undefined;
    var rng = utils.rng.TestRng.init(7);
    rng.fill_bytes(&storage);
    var messages: [40][]const u8 = undefined;
    for (&messages, 0..) |*message, index| message.* = storage[0 .. (index * 37) % 101];
    try sender.send_many(&messages);
    for (messages) |message| try testing.expectEqualSlices(u8, message, try receiver.recv());
}

test "batches larger than one buffer keep their order" {
    for ([_]Version{ .v0, .v1 }) |version| try run_deterministic(many_records, .{version});
}
