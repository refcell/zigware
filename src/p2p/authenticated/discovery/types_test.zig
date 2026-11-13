//! Tests of the discovery wire types (commonware `discovery/types.rs` tests).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const cryptography = @import("cryptography");
const types = @import("types.zig");
const data_mod = @import("../data.zig");
const p2p_types = @import("../../types.zig");

const standard = cryptography.secp256r1.standard;
const PublicKey = standard.PublicKey;
const PrivateKey = standard.PrivateKey;
const Info = types.Info(PublicKey);
const Payload = types.Payload(PublicKey);
const Verifier = types.InfoVerifier(PublicKey);
const BitVec = types.BitVec;
const BitMap = types.BitMap;
const Ingress = p2p_types.Ingress;
const Hostname = utils.Hostname;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;

const namespace = "test";

fn socket(a: u8, b: u8, c: u8, d: u8, port: u16) Ingress {
    return .{ .socket = .{ .ip = .{ .v4 = codec.Ipv4.init(a, b, c, d) }, .port = port } };
}

fn signed_peer_info(rng: anytype) Info {
    const signer = PrivateKey.random(rng);
    return .{
        .ingress = socket(127, 0, 0, 1, 8080),
        .timestamp = 1234567890,
        .public_key = signer.public_key(),
        .signature = signer.sign(namespace, &.{ 1, 2, 3, 4, 5 }),
    };
}

fn expect_info_eql(expected: Info, actual: Info) !void {
    try testing.expect(expected.ingress.eql(actual.ingress));
    try testing.expectEqual(expected.timestamp, actual.timestamp);
    try testing.expect(expected.public_key.eql(actual.public_key));
    try testing.expect(expected.signature.eql(actual.signature));
}

const default_cfg: types.PayloadConfig = .{
    .max_bit_vec = 1024,
    .max_peers = 10,
    .max_data_length = 100,
};

fn roundtrip(gpa: Allocator, payload: Payload, cfg: types.PayloadConfig) !Payload {
    const encoded = try codec.encode(Payload, gpa, payload);
    defer gpa.free(encoded);
    return codec.decode_cfg(Payload, gpa, encoded, cfg);
}

test "data prefix value" {
    try testing.expectEqual(@as(u8, 0), types.data_prefix);
}

test "bit vec codec" {
    const gpa = testing.allocator;
    var original: BitVec = .{ .index = 1234, .bits = try BitMap.ones(gpa, 71) };
    defer original.deinit(gpa);
    const encoded = try codec.encode(BitVec, gpa, original);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(BitVec, gpa, encoded, 71);
    defer decoded.deinit(gpa);
    try testing.expect(original.eql(&decoded));
}

test "signed peer info codec" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    const original = [_]Info{
        signed_peer_info(&rng),
        signed_peer_info(&rng),
        signed_peer_info(&rng),
    };
    const encoded = try codec.encode([]const Info, gpa, &original);
    defer gpa.free(encoded);
    const decoded = try codec.decode_range([]const Info, gpa, encoded, .exact(3));
    defer gpa.free(decoded);
    for (original, decoded) |a, b| try expect_info_eql(a, b);

    const too_short = codec.decode_range([]const Info, gpa, encoded, .to(3));
    try testing.expectError(error.InvalidLength, too_short);
    const too_long = codec.decode_range([]const Info, gpa, encoded, .from(4));
    try testing.expectError(error.InvalidLength, too_long);
}

test "payload codec" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();

    const greeting = signed_peer_info(&rng);
    var decoded = try roundtrip(gpa, .{ .greeting = greeting }, default_cfg);
    try expect_info_eql(greeting, decoded.greeting);
    decoded.deinit(gpa);

    var bit_vec: BitVec = .{ .index = 1234, .bits = try BitMap.ones(gpa, 100) };
    defer bit_vec.deinit(gpa);
    decoded = try roundtrip(gpa, .{ .bit_vec = bit_vec }, default_cfg);
    try testing.expect(bit_vec.eql(&decoded.bit_vec));
    decoded.deinit(gpa);

    const peers = [_]Info{ signed_peer_info(&rng), signed_peer_info(&rng) };
    decoded = try roundtrip(gpa, .{ .peers = &peers }, default_cfg);
    try testing.expectEqual(@as(usize, 2), decoded.peers.len);
    for (peers, decoded.peers) |a, b| try expect_info_eql(a, b);
    decoded.deinit(gpa);

    const data: data_mod.Data = .{ .channel = 12345, .message = "Hello, world!" };
    const encoded = try codec.encode(Payload, gpa, .{ .data = data });
    defer gpa.free(encoded);
    decoded = try codec.decode_cfg(Payload, gpa, encoded, default_cfg);
    try testing.expectEqual(data.channel, decoded.data.channel);
    try testing.expectEqualStrings(data.message, decoded.data.message);
}

test "payload decode invalid type" {
    const invalid = [_]u8{ 4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const result = codec.decode_cfg(Payload, testing.allocator, &invalid, default_cfg);
    try testing.expectError(error.InvalidEnum, result);
}

test "payload limits: bit vec, peers, and data" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();

    var bit_vec: BitVec = .{ .index = 5, .bits = try BitMap.ones(gpa, 9) };
    defer bit_vec.deinit(gpa);
    const cfg_bits: types.PayloadConfig = .{
        .max_bit_vec = 8,
        .max_peers = 10,
        .max_data_length = 32,
    };
    try testing.expectError(error.InvalidLength, roundtrip(gpa, .{ .bit_vec = bit_vec }, cfg_bits));

    const peers = [_]Info{ signed_peer_info(&rng), signed_peer_info(&rng) };
    const cfg_peers: types.PayloadConfig = .{
        .max_bit_vec = 1024,
        .max_peers = 1,
        .max_data_length = 32,
    };
    try testing.expectError(error.InvalidLength, roundtrip(gpa, .{ .peers = &peers }, cfg_peers));

    const data: data_mod.Data = .{ .channel = 1, .message = "hello" };
    const cfg_data: types.PayloadConfig = .{
        .max_bit_vec = 1024,
        .max_peers = 10,
        .max_data_length = 4,
    };
    try testing.expectError(error.InvalidLength, roundtrip(gpa, .{ .data = data }, cfg_data));
}

test "max payload data overhead" {
    const message_len: usize = 1 << 29;
    // Only the size matters, so the message need not point at real memory.
    const message = @as([*]const u8, @ptrFromInt(0x1000))[0..message_len];
    const payload: Payload = .{ .data = .{ .channel = std.math.maxInt(u64), .message = message } };
    try testing.expectEqual(message_len + data_mod.max_payload_overhead, payload.encode_size());
}

fn max_info(signer: *const PrivateKey) Info {
    const a: [63]u8 = @splat('a');
    const b: [63]u8 = @splat('b');
    const c: [63]u8 = @splat('c');
    const d: [61]u8 = @splat('d');
    const host = Hostname.literal(&(a ++ ".".* ++ b ++ ".".* ++ c ++ ".".* ++ d));
    const ingress: Ingress = .{ .dns = .{ .host = host, .port = std.math.maxInt(u16) } };
    const timestamp = std.math.maxInt(u64);
    return Info.sign(signer.public_key(), namespace, ingress, timestamp, signer);
}

test "max gossip size bounds payloads" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    const signer = PrivateKey.random(&rng);

    // A maximum-length hostname and timestamp give the largest info. Its bound also reserves
    // the hostname length prefix at its type's maximum width.
    const info = max_info(&signer);
    const ingress_slack = Ingress.max_encode_size - info.ingress.encode_size();
    try testing.expectEqual(Info.max_encode_size, info.encode_size() + ingress_slack);

    const max_bit_vec: u64 = 1_000;
    const max_peers: usize = 32;
    const bound = types.max_gossip_size(PublicKey, max_bit_vec, max_peers);
    const max_index = std.math.maxInt(u64);
    var bits: BitVec = .{ .index = max_index, .bits = try BitMap.ones(gpa, max_bit_vec) };
    defer bits.deinit(gpa);
    const peers: [max_peers]Info = @splat(info);
    const peers_payload: Payload = .{ .peers = &peers };
    try testing.expect((Payload{ .greeting = info }).encode_size() <= bound);
    try testing.expect((Payload{ .bit_vec = bits }).encode_size() <= bound);
    try testing.expect(peers_payload.encode_size() <= bound);

    // The peer-list bound reserves each length prefix at its type's maximum width.
    const count_slack = codec.varint.max_u32_varint_size - codec.encode_size(usize, max_peers);
    const expected = peers_payload.encode_size() + count_slack + max_peers * ingress_slack;
    try testing.expectEqual(expected, bound);

    // Without peer gossip, the largest bit vector determines the bound exactly.
    const big: u64 = 100_000;
    var big_bits: BitVec = .{ .index = std.math.maxInt(u64), .bits = try BitMap.ones(gpa, big) };
    defer big_bits.deinit(gpa);
    const big_size = (Payload{ .bit_vec = big_bits }).encode_size();
    try testing.expectEqual(big_size, types.max_gossip_size(PublicKey, big, 0));
}

/// A deterministic runtime starts at the epoch; tests pass the time directly.
const start: SystemTime = .UNIX_EPOCH;
const synchrony_bound = Duration.from_secs(30);

fn now_millis(now: SystemTime) u64 {
    return now.epoch_millis();
}

fn sign_at(signer: *const PrivateKey, ns: []const u8, ingress: Ingress, timestamp: u64) Info {
    return Info.sign(signer.public_key(), ns, ingress, timestamp, signer);
}

fn verifier(me: PublicKey, max_count: usize) Verifier {
    return .{
        .me = me,
        .peer_gossip_max_count = max_count,
        .synchrony_bound = synchrony_bound,
        .ip_namespace = namespace,
    };
}

test "info verifier accepts a valid peer" {
    var rng = utils.rng.test_rng();
    const validator = PrivateKey.random(&rng);
    const signer = PrivateKey.random(&rng);
    const peer = sign_at(&signer, namespace, socket(8, 8, 8, 8, 8080), now_millis(start));
    try verifier(validator.public_key(), 4).validate(start, &.{peer});
}

test "info verifier rejects too many peers" {
    var rng = utils.rng.test_rng();
    const signer = PrivateKey.random(&rng);
    const timestamp = now_millis(start);
    const signer_a = PrivateKey.random(&rng);
    const signer_b = PrivateKey.random(&rng);
    const peers = [_]Info{
        sign_at(&signer_a, namespace, socket(8, 8, 8, 8, 9000), timestamp),
        sign_at(&signer_b, namespace, socket(8, 8, 4, 4, 9001), timestamp),
    };
    const result = verifier(signer.public_key(), 1).validate(start, &peers);
    try testing.expectError(error.TooManyPeers, result);
}

test "info verifier rejects self" {
    var rng = utils.rng.test_rng();
    const signer = PrivateKey.random(&rng);
    const peer = sign_at(&signer, namespace, socket(203, 0, 113, 1, 8080), now_millis(start));
    const result = verifier(signer.public_key(), 4).validate(start, &.{peer});
    try testing.expectError(error.ReceivedSelf, result);
}

test "info verifier rejects a future timestamp and allows a past one" {
    var rng = utils.rng.test_rng();
    const validator = verifier(PrivateKey.random(&rng).public_key(), 4);
    const signer = PrivateKey.random(&rng);
    const ingress = socket(198, 51, 100, 1, 8080);

    const future = start.epoch().saturating_add(synchrony_bound).saturating_add(.from_secs(1));
    const ahead = sign_at(&signer, namespace, ingress, future.as_millis_u64());
    try testing.expectError(error.SynchronyBound, validator.validate(start, &.{ahead}));

    // Exactly at the bound is still accepted.
    const edge_millis = start.epoch().saturating_add(synchrony_bound).as_millis_u64();
    const edge = sign_at(&signer, namespace, ingress, edge_millis);
    try validator.validate(start, &.{edge});

    // After time advances, a peer older than the synchrony bound is still accepted.
    const later = start.checked_add(Duration.from_secs(60)).?;
    const past = later.epoch().checked_sub(synchrony_bound).?.checked_sub(.from_secs(1)).?;
    const behind = sign_at(&signer, namespace, ingress, past.as_millis_u64());
    try validator.validate(later, &.{behind});
}

test "info verifier rejects an invalid signature" {
    var rng = utils.rng.test_rng();
    const validator = PrivateKey.random(&rng);
    const signer = PrivateKey.random(&rng);
    const timestamp = now_millis(start);
    const peer = sign_at(&signer, "wrong-namespace", socket(8, 8, 4, 4, 8080), timestamp);
    const result = verifier(validator.public_key(), 4).validate(start, &.{peer});
    try testing.expectError(error.InvalidSignature, result);
}

test "info with dns ingress signs, verifies, and round-trips" {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    const signer = PrivateKey.random(&rng);
    const timestamp = now_millis(start);
    const dns: Ingress = .{ .dns = .{ .host = .literal("node.example.com"), .port = 8080 } };
    const peer = sign_at(&signer, namespace, dns, timestamp);
    try testing.expect(peer.ingress.eql(dns));
    try testing.expectEqual(timestamp, peer.timestamp);
    try testing.expect(peer.public_key.eql(signer.public_key()));
    try testing.expect(peer.verify(namespace));

    const validator_dns: Ingress = .{
        .dns = .{ .host = .literal("validator-1.network.io"), .port = 9090 },
    };
    const original = sign_at(&signer, namespace, validator_dns, timestamp);
    const encoded = try codec.encode(Info, gpa, original);
    defer gpa.free(encoded);
    const decoded = try codec.decode(Info, gpa, encoded);
    try expect_info_eql(original, decoded);
    try testing.expect(decoded.verify(namespace));
}

test "info verifier accepts dns ingress, including internal hostnames" {
    var rng = utils.rng.test_rng();
    const validator = verifier(PrivateKey.random(&rng).public_key(), 4);
    const signer = PrivateKey.random(&rng);
    const timestamp = now_millis(start);
    for ([_][]const u8{ "peer.network.com", "internal.local" }) |host| {
        const dns: Ingress = .{ .dns = .{ .host = try Hostname.init(host), .port = 8080 } };
        try validator.validate(start, &.{sign_at(&signer, namespace, dns, timestamp)});
    }
}

test "info verifier validates a greeting without a gossip limit" {
    var rng = utils.rng.test_rng();
    // A gossip limit of zero disables peer gossip, but every connection still starts with
    // one self-signed greeting.
    const validator = verifier(PrivateKey.random(&rng).public_key(), 0);
    const signer = PrivateKey.random(&rng);
    const greeting = sign_at(&signer, namespace, socket(8, 8, 8, 8, 8080), now_millis(start));
    try validator.validate_info(start, &greeting);
    try testing.expectError(error.TooManyPeers, validator.validate(start, &.{greeting}));
}

test "decoding a data payload does not allocate or copy" {
    const gpa = testing.allocator;
    const original: data_mod.Data = .{ .channel = 12345, .message = "Hello, world!" };
    const encoded = try codec.encode(Payload, gpa, .{ .data = original });
    defer gpa.free(encoded);
    const cfg: types.PayloadConfig = .{ .max_bit_vec = 8, .max_peers = 8, .max_data_length = 1024 };
    const decoded = try codec.decode_cfg(Payload, testing.failing_allocator, encoded, cfg);
    try testing.expectEqual(original.channel, decoded.data.channel);
    try testing.expectEqualStrings(original.message, decoded.data.message);
    const start_address = @intFromPtr(encoded.ptr);
    const message_address = @intFromPtr(decoded.data.message.ptr);
    try testing.expect(message_address > start_address);
    try testing.expect(message_address < start_address + encoded.len);
}

// Conformance: ports of the `Arbitrary` impls behind commonware's hashes.

/// `PrivateKey::random(StdRng::from_seed(u.arbitrary::<[u8; 32]>()))`.
fn gen_private_key(gpa: Allocator, u: *Unstructured) ArbitraryError!PrivateKey {
    var rng = utils.rng.TestRng.init_key(try codec.arbitrary.value([32]u8, gpa, u));
    return PrivateKey.random(&rng);
}

/// A random key signs up to 255 arbitrary bytes under the empty namespace.
fn gen_signature(gpa: Allocator, u: *Unstructured) ArbitraryError!PublicKey.Signature {
    const private_key = try gen_private_key(gpa, u);
    const len = try codec.arbitrary.value(usize, gpa, u) % 256;
    // `arbitrary_iter().take(len)`: a continuation byte before each element, none after.
    var message: std.ArrayList(u8) = .empty;
    while (message.items.len < len and u.keep_going()) try message.append(gpa, u.int(u8));
    assert(message.items.len <= len);
    return private_key.sign("", message.items);
}

fn gen_info(gpa: Allocator, u: *Unstructured) ArbitraryError!Info {
    const ingress = try Ingress.arbitrary(gpa, u);
    const timestamp = u.int(u64);
    const public_key = (try gen_private_key(gpa, u)).public_key();
    return .{
        .ingress = ingress,
        .timestamp = timestamp,
        .public_key = public_key,
        .signature = try gen_signature(gpa, u),
    };
}

/// `int_in_range(0..=3)` picks the variant; a peer list is `arbitrary_iter().collect()`.
fn gen_payload(gpa: Allocator, u: *Unstructured) ArbitraryError!Payload {
    return switch (u.int_in_range(u64, 0, 3)) {
        0 => .{ .data = try data_mod.Data.arbitrary(gpa, u) },
        1 => .{ .greeting = try gen_info(gpa, u) },
        2 => .{ .bit_vec = try BitVec.arbitrary(gpa, u) },
        3 => peers: {
            var list: std.ArrayList(Info) = .empty;
            while (u.keep_going()) try list.append(gpa, try gen_info(gpa, u));
            break :peers .{ .peers = try list.toOwnedSlice(gpa) };
        },
        else => unreachable, // Proof: int_in_range returns a value in 0..=3.
    };
}

fn CodecConformance(comptime T: type, comptime gen: codec.arbitrary.Generator(T)) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const value = try codec.arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

fn verify(
    comptime T: type,
    comptime gen: codec.arbitrary.Generator(T),
    comptime name: []const u8,
) !void {
    const conformance = @import("conformance");
    const file = @embedFile("../../conformance.toml");
    const full = "commonware_p2p::authenticated::discovery::types::tests::conformance::" ++
        "CodecConformance<" ++ name ++ ">";
    const entry = (try conformance.find(file, full)).?;
    try conformance.verify(CodecConformance(T, gen), testing.allocator, full, entry.n_cases, file);
}

test "conformance: discovery BitVec encoding matches commonware" {
    try verify(BitVec, codec.arbitrary.default_generator(BitVec), "BitVec");
}

test "conformance: discovery Info encoding matches commonware" {
    try verify(Info, gen_info, "Info<PublicKey>");
}

test "conformance: discovery Payload encoding matches commonware" {
    try verify(Payload, gen_payload, "Payload<PublicKey>");
}
