//! SAKE tests (commonware `handshake/sake/protocol.rs` tests), the `SakeV0`/`SakeV1`
//! conformance hashes, and decode fuzzing of the three messages.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const ed25519 = @import("../ed25519.zig");
const fuzz = @import("../fuzz.zig");
const conformance = @import("../conformance.zig");
const transcript_mod = @import("../transcript.zig");
const sake = @import("sake.zig");

const PrivateKey = ed25519.PrivateKey;
const PublicKey = ed25519.PublicKey;
const Protocol = sake.Sake(PrivateKey);
const Context = Protocol.Context;
const Version = sake.Version;
const versions = [_]Version{ .v0, .v1 };
const namespace = "test_namespace";
const zero_range: sake.Range = .{ .start = 0, .end = 1 };

fn roundtrip(comptime T: type, value: T) !void {
    const encoded = codec.encode_fixed(T, value);
    const decoded = try codec.decode(T, testing.allocator, &encoded);
    try testing.expectEqualSlices(u8, &encoded, &codec.encode_fixed(T, decoded));
}

const Peers = struct {
    rng: utils.rng.TestRng,
    dialer: PrivateKey,
    listener: PrivateKey,

    fn init() Peers {
        var rng = utils.rng.test_rng();
        const dialer = PrivateKey.random(&rng);
        const listener = PrivateKey.random(&rng);
        return .{ .rng = rng, .dialer = dialer, .listener = listener };
    }

    fn dial(self: *Peers, ns: []const u8, version: Version) Protocol.DialStart {
        const listener = self.listener.public_key();
        const ctx = Context.init(ns, 0, zero_range, self.dialer, listener, version);
        return Protocol.dial_start(&self.rng, ctx);
    }

    fn listen(
        self: *Peers,
        ns: []const u8,
        version: Version,
        expected: PublicKey,
        syn: Protocol.Syn,
    ) sake.Error!Protocol.ListenStart {
        const ctx = Context.init(ns, 0, zero_range, self.listener, expected, version);
        return Protocol.listen_start(&self.rng, ctx, syn);
    }
};

test "sake handshake completes with matching transcripts" {
    for (versions) |version| {
        var peers = Peers.init();
        const dial = peers.dial(namespace, version);
        try roundtrip(Protocol.Syn, dial.syn);
        const listen = try peers.listen(namespace, version, peers.dialer.public_key(), dial.syn);
        try roundtrip(Protocol.SynAck, listen.syn_ack);
        const end = try Protocol.dial_end(dial.state, listen.syn_ack);
        try roundtrip(sake.Ack, end.ack);
        const listener = try Protocol.listen_end(listen.state, end.ack);
        try testing.expect(end.transcript.summarize().eql(listener.summarize()));
    }
}

test "sake rejects mismatched confirmations" {
    for (versions) |version| {
        var peers = Peers.init();
        const wrong_version = version.transcript_version();
        const wrong_transcript = transcript_mod.Transcript.init("wrong", wrong_version);
        const wrong = wrong_transcript.summarize();
        const first = peers.dial(namespace, version);
        const dialer = peers.dialer.public_key();
        var syn_ack = (try peers.listen(namespace, version, dialer, first.syn)).syn_ack;
        syn_ack.confirmation = wrong;
        try testing.expectError(error.InvalidConfirmation, Protocol.dial_end(first.state, syn_ack));

        const second = peers.dial(namespace, version);
        const listen = try peers.listen(namespace, version, dialer, second.syn);
        var ack = (try Protocol.dial_end(second.state, listen.syn_ack)).ack;
        ack.confirmation = wrong;
        try testing.expectError(error.InvalidConfirmation, Protocol.listen_end(listen.state, ack));
    }
}

test "sake rejects mismatched namespace, version, and dialer identity" {
    for (versions) |version| {
        var peers = Peers.init();
        const dial = peers.dial("namespace_a", version);
        const result = peers.listen("namespace_b", version, peers.dialer.public_key(), dial.syn);
        try testing.expectError(error.InvalidSignature, result);
    }
    for ([_][2]Version{ .{ .v0, .v1 }, .{ .v1, .v0 } }) |pair| {
        var peers = Peers.init();
        const dial = peers.dial(namespace, pair[0]);
        const result = peers.listen(namespace, pair[1], peers.dialer.public_key(), dial.syn);
        try testing.expectError(error.InvalidSignature, result);
    }
    for (versions) |version| {
        var peers = Peers.init();
        const impostor = PrivateKey.random(&peers.rng).public_key();
        const dial = peers.dial(namespace, version);
        const result = peers.listen(namespace, version, impostor, dial.syn);
        try testing.expectError(error.InvalidSignature, result);
    }
}

test "sake rejects timestamps outside the accepted range" {
    for (versions) |version| {
        var peers = Peers.init();
        var dial = peers.dial(namespace, version);
        dial.syn.time_ms = 1;
        const late = peers.listen(namespace, version, peers.dialer.public_key(), dial.syn);
        try testing.expectError(error.InvalidTimestamp, late);

        const fresh = peers.dial(namespace, version);
        const dialer = peers.dialer.public_key();
        var syn_ack = (try peers.listen(namespace, version, dialer, fresh.syn)).syn_ack;
        syn_ack.time_ms = 7;
        try testing.expectError(error.InvalidTimestamp, Protocol.dial_end(fresh.state, syn_ack));
    }
}

/// A transcript over the dialer's signed fields, with or without its identity.
fn syn_transcript(
    version: Version,
    syn: *const Protocol.Syn,
    listener: PublicKey,
    dialer: ?PublicKey,
) transcript_mod.Transcript {
    const base = transcript_mod.Transcript.init(namespace, version.transcript_version());
    var t = base.fork(version.namespace());
    if (version == .v1) t.commit(&.{1});
    t.commit(&codec.encode_fixed(u64, syn.time_ms));
    t.commit(&codec.encode_fixed(PublicKey, listener));
    if (dialer) |key| t.commit(&codec.encode_fixed(PublicKey, key));
    t.commit(&syn.epk.bytes);
    return t;
}

test "sake syn signature covers the dialer identity only in v1" {
    for ([_]struct { Version, bool }{ .{ .v0, false }, .{ .v1, true } }) |case| {
        var peers = Peers.init();
        const dialer = peers.dialer.public_key();
        const listener = peers.listener.public_key();
        const dial = peers.dial(namespace, case[0]);
        const with = syn_transcript(case[0], &dial.syn, listener, dialer);
        const without = syn_transcript(case[0], &dial.syn, listener, null);
        try testing.expectEqual(case[1], with.verify(&dialer, &dial.syn.signature));
        try testing.expectEqual(!case[1], without.verify(&dialer, &dial.syn.signature));
    }
}

test "sake rejects a low-order ephemeral key" {
    for (versions) |version| {
        var peers = Peers.init();
        var dial = peers.dial(namespace, version);
        // A valid signature over a zero ephemeral key: re-sign the dialer's transcript.
        dial.syn.epk = .{ .bytes = @splat(0) };
        const dialer = peers.dialer.public_key();
        const binds = version.binds_identity_before_syn();
        const listener = peers.listener.public_key();
        const t = syn_transcript(version, &dial.syn, listener, if (binds) dialer else null);
        dial.syn.signature = t.sign(&peers.dialer);
        const result = peers.listen(namespace, version, dialer, dial.syn);
        try testing.expectError(error.InvalidEphemeralKey, result);
    }
}

/// Commonware's `SakeV0`/`SakeV1` conformance case: a full handshake from `TestRng(seed)`,
/// logging every message and the final summary.
fn exchange_log(
    gpa: std.mem.Allocator,
    seed: u64,
    version: Version,
    log: *std.ArrayList(u8),
) !void {
    var rng = utils.rng.TestRng.init(seed);
    var namespace_buffer: [300]u8 = undefined;
    const ns = namespace_buffer[0..utils.rng.range_at_most(&rng, u32, 0, 300)];
    rng.fill_bytes(ns);
    const dialer_time = utils.rng.range_less_than(&rng, u64, 1 << 56, 1 << 63);
    const listener_time = dialer_time + utils.rng.range_less_than(&rng, u64, 1, 1000);
    const dialer_key = PrivateKey.random(&rng);
    const listener_key = PrivateKey.random(&rng);

    const listener_range: sake.Range = .{ .start = listener_time, .end = listener_time + 1 };
    const dialer_range: sake.Range = .{ .start = dialer_time, .end = dialer_time + 1 };
    const listener_public = listener_key.public_key();
    const dialer_public = dialer_key.public_key();
    const dial_ctx =
        Context.init(ns, dialer_time, listener_range, dialer_key, listener_public, version);
    const dial = Protocol.dial_start(&rng, dial_ctx);
    try log.appendSlice(gpa, &codec.encode_fixed(Protocol.Syn, dial.syn));

    const listen_ctx =
        Context.init(ns, listener_time, dialer_range, listener_key, dialer_public, version);
    const listen = try Protocol.listen_start(&rng, listen_ctx, dial.syn);
    try log.appendSlice(gpa, &codec.encode_fixed(Protocol.SynAck, listen.syn_ack));

    const end = try Protocol.dial_end(dial.state, listen.syn_ack);
    try log.appendSlice(gpa, &codec.encode_fixed(sake.Ack, end.ack));
    const listener = try Protocol.listen_end(listen.state, end.ack);
    const summary = end.transcript.summarize();
    try testing.expect(summary.eql(listener.summarize()));
    try log.appendSlice(gpa, &summary.bytes);
}

fn sake_v0(gpa: std.mem.Allocator, seed: u64, log: *std.ArrayList(u8)) !void {
    try exchange_log(gpa, seed, .v0, log);
}

fn sake_v1(gpa: std.mem.Allocator, seed: u64, log: *std.ArrayList(u8)) !void {
    try exchange_log(gpa, seed, .v1, log);
}

test "sake conformance: SakeV0" {
    try conformance.skip_slow();
    const expected = "7334b4f046d39deb32066592cd2428730efa93fba0d93cf4a7c0bca125d2176e";
    try conformance.expect(4096, expected, sake_v0);
}

test "sake conformance: SakeV1" {
    try conformance.skip_slow();
    const expected = "5050ef7d884501c20b8a3d871a5f929b57ae0e35db922debb178b476d38255c4";
    try conformance.expect(4096, expected, sake_v1);
}

test "sake conformance: first seeds (fast)" {
    // A short prefix of the conformance logs runs in every build.
    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(testing.allocator);
    for (0..4) |seed| {
        log.clearRetainingCapacity();
        try sake_v1(testing.allocator, seed, &log);
        const size = Protocol.Syn.fixed_size + Protocol.SynAck.fixed_size + 64;
        try testing.expectEqual(size, log.items.len);
    }
}

/// Decodes arbitrary bytes as each message; whatever decodes re-encodes to the same bytes.
fn fuzz_decode(bytes: []const u8) !void {
    inline for (.{ Protocol.Syn, Protocol.SynAck, sake.Ack }) |T| {
        if (codec.decode(T, testing.allocator, bytes)) |value| {
            try testing.expectEqualSlices(u8, bytes, &codec.encode_fixed(T, value));
        } else |err| {
            try testing.expect(bytes.len != T.fixed_size);
            try testing.expect(err == error.EndOfBuffer or err == error.ExtraData);
        }
    }
}

test "sake fuzz decode (seeded)" {
    var random = fuzz.prng(0x5a4e);
    var bytes: [256]u8 = undefined;
    for (0..fuzz.iterations(512)) |_| {
        random.random().bytes(&bytes);
        const sizes = [_]usize{ 32, Protocol.Syn.fixed_size, Protocol.SynAck.fixed_size };
        const length = if (random.random().boolean())
            sizes[random.random().uintLessThan(usize, sizes.len)]
        else
            random.random().uintAtMost(usize, bytes.len);
        try fuzz_decode(bytes[0..length]);
    }
}

test "sake fuzz decode (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [256]u8 = undefined;
            const length = smith.slice(&bytes);
            try fuzz_decode(bytes[0..length]);
        }
    }.run, .{});
}
