//! Transcript tests (commonware `transcript.rs` tests) and its `TranscriptV0Ops` and
//! `TranscriptV1Ops` conformance hashes.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const ed25519 = @import("ed25519.zig");
const signer = @import("signer.zig");
const conformance = @import("conformance.zig");
const transcript = @import("transcript.zig");

const Transcript = transcript.Transcript;
const Summary = transcript.Summary;
const Version = transcript.Version;
const Blake3 = std.crypto.hash.Blake3;

fn v0(namespace: []const u8) Transcript {
    return Transcript.init(namespace, .v0);
}

fn v1(namespace: []const u8) Transcript {
    return Transcript.init(namespace, .v1);
}

fn committed(version: Version, namespace: []const u8, parts: []const []const u8) Summary {
    var t = Transcript.init(namespace, version);
    for (parts) |part| t.commit(part);
    return t.summarize();
}

fn noise_bytes(t: *const Transcript, label: []const u8, out: []u8) void {
    var rng = t.noise(label);
    rng.fill_bytes(out);
}

test "transcript separates namespaces, data, and commits" {
    try testing.expect(!v0("Test-A").summarize().eql(v0("Test-B").summarize()));
    try testing.expect(!v0("Test-A").summarize().eql(committed(.v0, "Test-", &.{""})));
    try testing.expect(!committed(.v0, "", &.{"AB"}).eql(committed(.v0, "", &.{ "A", "B" })));

    var appended = v0("");
    appended.append("A");
    appended.commit("B");
    try testing.expect(appended.summarize().eql(committed(.v0, "", &.{"AB"})));

    var unfinished = v0("foo");
    unfinished.append("AB");
    var split = v0("foo");
    split.append("A");
    split.commit("B");
    try testing.expect(unfinished.summarize().eql(split.summarize()));
}

test "transcript v1 separates adversarial data that v0 does not" {
    const zeros: [127]u8 = @splat(0);
    const merged = zeros ++ [_]u8{0x7f};
    const split_v0 = committed(.v0, "", &.{ &zeros, &.{0x80} });
    try testing.expect(split_v0.eql(committed(.v0, "", &.{&merged})));
    const split_v1 = committed(.v1, "", &.{ &zeros, &.{0x80} });
    try testing.expect(!split_v1.eql(committed(.v1, "", &.{&merged})));
}

test "transcript versions match for single-byte lengths and differ for long labels" {
    const a = v0("test");
    const b = v1("test");
    try testing.expect(a.summarize().eql(b.summarize()));
    try testing.expect(a.fork("fork").summarize().eql(b.fork("fork").summarize()));
    var resumed_v0 = Transcript.resume_from(a.summarize(), .v0);
    var resumed_v1 = Transcript.resume_from(a.summarize(), .v1);
    resumed_v0.commit("x");
    resumed_v1.commit("x");
    try testing.expect(resumed_v0.summarize().eql(resumed_v1.summarize()));
    var noise_v0: [32]u8 = undefined;
    var noise_v1: [32]u8 = undefined;
    noise_bytes(&a, "noise", &noise_v0);
    noise_bytes(&b, "noise", &noise_v1);
    try testing.expectEqualSlices(u8, &noise_v0, &noise_v1);

    const long_label: [128]u8 = @splat(0);
    try testing.expect(!a.fork(&long_label).summarize().eql(b.fork(&long_label).summarize()));
    noise_bytes(&a, &long_label, &noise_v0);
    noise_bytes(&b, &long_label, &noise_v1);
    try testing.expect(!std.mem.eql(u8, &noise_v0, &noise_v1));
}

test "transcript flush supports the maximum packet length" {
    // u64::MAX as a varint: nine 0xff bytes then 0x01.
    const varint = @as([9]u8, @splat(0xff)) ++ [_]u8{0x01};
    for ([_]Version{ .v0, .v1 }) |version| {
        var t = Transcript.init("", version);
        t.pending = std.math.maxInt(u64);
        var expected = t.hasher;
        var framed = varint;
        if (version == .v1) std.mem.reverse(u8, &framed);
        expected.update(&framed);
        var expected_summary: Summary = undefined;
        expected.final(&expected_summary.bytes);
        try testing.expect(t.summarize().eql(expected_summary));
    }
}

test "transcript forks, noise, and resume are distinct" {
    const t1 = v0("");
    const t2 = t1.fork("");
    try testing.expect(!t1.summarize().eql(t2.summarize()));
    try testing.expect(!t1.fork("A").summarize().eql(t1.fork("A").fork("B").summarize()));

    var noise: Summary = undefined;
    noise_bytes(&t1, "foo", &noise.bytes);
    try testing.expect(!noise.eql(t1.summarize()));
    var other: [32]u8 = undefined;
    noise_bytes(&t1, "bar", &other);
    try testing.expect(!std.mem.eql(u8, &noise.bytes, &other));

    const summary = v0("test").summarize();
    const as_namespace = v0(&summary.bytes).summarize();
    const resumed = Transcript.resume_from(summary, .v0).summarize();
    try testing.expect(!as_namespace.eql(resumed));
}

test "transcript noise stream chunking does not matter" {
    const t = v0("test");
    var whole: [2 * Blake3.block_length]u8 = undefined;
    noise_bytes(&t, "NOISE", &whole);
    for (0..whole.len) |split| {
        var chunked: [2 * Blake3.block_length]u8 = undefined;
        var rng = t.noise("NOISE");
        rng.fill_bytes(chunked[0..split]);
        rng.fill_bytes(chunked[split..]);
        try testing.expectEqualSlices(u8, &whole, &chunked);
    }
}

test "transcript summary codec and signatures" {
    const summary = v0("test").summarize();
    const encoded = codec.encode_fixed(Summary, summary);
    try testing.expect(summary.eql(try codec.decode(Summary, testing.allocator, &encoded)));

    const key = ed25519.PrivateKey.from_seed(7);
    const public_key = key.public_key();
    var t = v0("test");
    t.commit("DATA");
    const signature = transcript.sign_summary(t.summarize(), &key);
    try testing.expect(signature.eql(t.sign(&key)));
    try testing.expect(transcript.verify_summary(t.summarize(), &public_key, &signature));
    try testing.expect(t.verify(&public_key, &signature));
    const summary_bytes = t.summarize().bytes;
    const entry = [1]ed25519.PublicKey.Entry{.{
        .namespace = "",
        .message = &summary_bytes,
        .public_key = &public_key,
        .signature = &signature,
    }};
    var rng = utils.rng.test_rng();
    try testing.expect(ed25519.PublicKey.verify_batch(&rng, &entry, signer.entries, {}));
}

test "transcript shuffle and sample" {
    var items: [1000]u32 = undefined;
    for (&items, 0..) |*item, i| item.* = @intCast(i);
    const t = v0("test");
    t.shuffle("shuffle", @as([]u32, &items));
    var sorted = items;
    std.mem.sort(u32, &sorted, {}, std.sort.asc(u32));
    for (sorted, 0..) |item, i| try testing.expectEqual(@as(u32, @intCast(i)), item);
    var moved = false;
    for (items, 0..) |item, i| moved = moved or item != i;
    try testing.expect(moved);

    var a: [100]u32 = undefined;
    for (&a, 0..) |*item, i| item.* = @intCast(i);
    var b = a;
    var c = a;
    var d = a;
    var with_data = v0("test");
    with_data.commit("DATA");
    with_data.shuffle("shuffle", @as([]u32, &a));
    with_data.shuffle("shuffle", @as([]u32, &b));
    try testing.expectEqualSlices(u32, &a, &b);
    t.shuffle("A", @as([]u32, &c));
    t.shuffle("B", @as([]u32, &d));
    try testing.expect(!std.mem.eql(u32, &c, &d));
    try testing.expect(!std.mem.eql(u32, &a, &c));

    var rng = t.noise("sample");
    for ([_]u64{ 1, 2, 3, 7, 100, 1 << 40, std.math.maxInt(u64) }) |bound| {
        try testing.expect(transcript.sample(&rng, bound) < bound);
    }
    try testing.expectEqual(@as(u64, 0), t.sample_label("sample", 1));
    var one_shot = t.noise("one shot");
    try testing.expectEqual(transcript.sample(&one_shot, 1000), t.sample_label("one shot", 1000));
}

fn append_encoded(
    gpa: std.mem.Allocator,
    log: *std.ArrayList(u8),
    comptime T: type,
    value: T,
) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try log.appendSlice(gpa, encoded);
}

/// Commonware's `transcript_ops` conformance case for `version`.
fn transcript_ops(
    gpa: std.mem.Allocator,
    seed: u64,
    version: Version,
    log: *std.ArrayList(u8),
) !void {
    var seed_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seed_bytes, seed, .little);
    const namespace = seed_bytes[0 .. seed % 8 + 1];
    var data_buffer: [256]u8 = undefined;
    const data = data_buffer[0 .. seed % 256];
    for (data, 0..) |*byte, i| byte.* = @as(u8, @truncate(seed)) +% @as(u8, @truncate(3 * i));
    const split = data.len / 2;

    var t = Transcript.init(namespace, version);
    t.append(data[0..split]);
    t.commit(data[split..]);
    try log.appendSlice(gpa, &t.summarize().bytes);
    const halves = committed(version, namespace, &.{ data[0..split], data[split..] });
    try log.appendSlice(gpa, &halves.bytes);
    var appended = Transcript.init(namespace, version);
    appended.append(data);
    appended.commit("");
    try log.appendSlice(gpa, &appended.summarize().bytes);
    try log.appendSlice(gpa, &Transcript.resume_from(t.summarize(), version).summarize().bytes);
    try log.appendSlice(gpa, &t.fork("left").summarize().bytes);
    try log.appendSlice(gpa, &t.fork("right").summarize().bytes);

    var rng = t.noise("noise");
    try append_encoded(gpa, log, u32, rng.next_u32());
    try append_encoded(gpa, log, u64, rng.next_u64());
    var noise: [80]u8 = undefined;
    rng.fill_bytes(noise[0..31]);
    rng.fill_bytes(noise[31..]);
    try log.appendSlice(gpa, &noise);

    var indices: [100]u32 = undefined;
    for (&indices, 0..) |*index, i| index.* = @intCast(i);
    const shuffled = indices[0 .. seed % 100];
    t.shuffle("shuffle", shuffled);
    for (shuffled) |index| try append_encoded(gpa, log, u32, index);
    try append_encoded(gpa, log, u64, t.sample_label("sample", seed | 1));

    try sign_ops(gpa, seed, &t, log);

    var pending = Transcript.init(namespace, version);
    pending.append(data);
    try log.appendSlice(gpa, &pending.summarize().bytes);
    try log.appendSlice(gpa, &pending.fork("pending fork").summarize().bytes);
    var pending_noise: [37]u8 = undefined;
    noise_bytes(&pending, "pending noise", &pending_noise);
    try log.appendSlice(gpa, &pending_noise);
    const key = ed25519.PrivateKey.from_seed(seed);
    const pending_signature = pending.sign(&key);
    try log.appendSlice(gpa, &pending_signature.raw);
    try append_encoded(gpa, log, bool, pending.verify(&key.public_key(), &pending_signature));
}

/// The signing part of `transcript_ops`: summary and transcript signatures, single and batch.
fn sign_ops(
    gpa: std.mem.Allocator,
    seed: u64,
    t: *const Transcript,
    log: *std.ArrayList(u8),
) !void {
    const key = ed25519.PrivateKey.from_seed(seed);
    const public_key = key.public_key();
    const summary = t.summarize();
    const summary_signature = transcript.sign_summary(summary, &key);
    const transcript_signature = t.sign(&key);
    try log.appendSlice(gpa, &summary_signature.raw);
    try log.appendSlice(gpa, &transcript_signature.raw);
    const summary_valid = transcript.verify_summary(summary, &public_key, &summary_signature);
    try append_encoded(gpa, log, bool, summary_valid);
    try append_encoded(gpa, log, bool, t.verify(&public_key, &transcript_signature));
    for ([_]struct { []const u8, *const ed25519.Signature }{
        .{ "summary batch", &summary_signature },
        .{ "transcript batch", &transcript_signature },
    }) |batch| {
        const entry = [1]ed25519.PublicKey.Entry{.{
            .namespace = "",
            .message = &summary.bytes,
            .public_key = &public_key,
            .signature = batch[1],
        }};
        var rng = t.noise(batch[0]);
        try append_encoded(gpa, log, bool, true);
        const valid = ed25519.PublicKey.verify_batch(&rng, &entry, signer.entries, {});
        try append_encoded(gpa, log, bool, valid);
    }
}

fn transcript_v0_ops(gpa: std.mem.Allocator, seed: u64, log: *std.ArrayList(u8)) !void {
    try transcript_ops(gpa, seed, .v0, log);
}

fn transcript_v1_ops(gpa: std.mem.Allocator, seed: u64, log: *std.ArrayList(u8)) !void {
    try transcript_ops(gpa, seed, .v1, log);
}

test "transcript conformance: TranscriptV0Ops" {
    try conformance.skip_slow();
    try conformance.expect(
        4096,
        "9115bb89c941947d7bfabb3c67b7812c842c3ab8be196a61e3378a873e2e5837",
        transcript_v0_ops,
    );
}

test "transcript conformance: TranscriptV1Ops" {
    try conformance.skip_slow();
    try conformance.expect(
        4096,
        "8b67a5feb9019c290bb51a632a042cf302a66eb16f69a91c45f599602ce27fcf",
        transcript_v1_ops,
    );
}
