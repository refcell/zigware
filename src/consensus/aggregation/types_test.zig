//! Tests of the aggregation types (commonware `aggregation/types.rs` and `limits.rs` tests)
//! with every certificate scheme, and the aggregation `CodecConformance` hashes in
//! commonware's `consensus/conformance.toml`.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");
const codec = @import("codec");
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const types = @import("types.zig");
const scheme = @import("scheme.zig");
const limits = @import("limits.zig");
const vrf = @import("../simplex/scheme/bls12381_threshold/vrf.zig");

const Epoch = consensus_types.Epoch;
const Height = consensus_types.Height;
const Participant = consensus_types.Participant;
const Sha256 = cryptography.Sha256;
const MinPk = cryptography.bls12381.primitives.MinPk;
const MinSig = cryptography.bls12381.primitives.MinSig;
const PublicKey = cryptography.ed25519.PublicKey;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;
const sequential = parallel.sequential;

const D = Sha256.Digest;
const namespace = "test";

fn skip_slow() error{SkipZigTest}!void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
}

/// Each scheme with its fixture builder: the individual-signature schemes, then BLS.
const individual_schemes = .{
    .{ scheme.ed25519.Scheme(D), scheme.ed25519.fixture },
    .{ scheme.secp256r1.Scheme(D, PublicKey), scheme.secp256r1.fixture },
};
const bls_schemes = .{
    .{ scheme.bls12381_multisig.Scheme(D, PublicKey, MinPk), scheme.bls12381_multisig.fixture },
    .{ scheme.bls12381_multisig.Scheme(D, PublicKey, MinSig), scheme.bls12381_multisig.fixture },
    .{
        scheme.bls12381_threshold.Scheme(D, PublicKey, MinPk),
        scheme.bls12381_threshold.fixture,
    },
    .{
        scheme.bls12381_threshold.Scheme(D, PublicKey, MinSig),
        scheme.bls12381_threshold.fixture,
    },
};

test "ack namespace appends the suffix" {
    const gpa = testing.allocator;
    var derived: types.Namespace = try .derive(gpa, "test_namespace");
    defer derived.deinit(gpa);
    try testing.expectEqualStrings("test_namespace_AGG_ACK", derived.bytes);
    var copy = try derived.clone(gpa);
    defer copy.deinit(gpa);
    try testing.expectEqualStrings(derived.bytes, copy.bytes);
}

test "errors that are blockable" {
    try testing.expect(types.blockable(error.PeerMismatch));
    try testing.expect(types.blockable(error.InvalidAckSignature));
    try testing.expect(!types.blockable(error.AckDuplicate));
    try testing.expect(!types.blockable(error.UnknownEpoch));
}

fn expect_roundtrip(comptime T: type, value: T, cfg: codec.Cfg(T)) !void {
    const gpa = testing.allocator;
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(T, value), encoded.len);
    const decoded = try codec.decode_cfg(T, gpa, encoded, cfg);
    defer codec.free(T, gpa, decoded);
    try testing.expect(decoded.eql(value));
}

fn check_codec(comptime S: type, comptime fixture: anytype) !void {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var built = try fixture(S, gpa, &rng, namespace, 4);
    defer built.deinit(gpa);
    const signers = built.schemes;
    const item: types.Item(D) = .{ .height = .new(100), .digest = Sha256.hash(&.{"test_item"}) };
    try expect_roundtrip(types.Item(D), item, {});

    const Ack = types.Ack(S, D);
    const ack = (try Ack.sign(gpa, &signers[0], .new(1), item)).?;
    try expect_roundtrip(Ack, ack, {});
    try testing.expect(try ack.verify(gpa, &rng, &signers[0], sequential));
    try expect_roundtrip(types.TipAck(S, D), .{ .tip = .new(42), .ack = ack }, {});

    const Activity = types.Activity(S, D);
    const cfg = signers[0].certificate_codec_config();
    try expect_roundtrip(Activity, .{ .ack = ack }, cfg);

    // A quorum of acks assembles; one fewer reports the shortfall.
    const quorum = signers[0].participants().quorum(utils.N3f1);
    var acks: [4]Ack = undefined;
    for (acks[0..quorum], signers[0..quorum]) |*slot, *signer| {
        slot.* = (try Ack.sign(gpa, signer, .new(1), item)).?;
    }
    const Certificate = types.Certificate(S, D);
    try testing.expectError(
        error.InsufficientAttestations,
        Certificate.from_acks(gpa, &signers[0], acks[0 .. quorum - 1], sequential),
    );
    var certificate = try Certificate.from_acks(gpa, &signers[0], acks[0..quorum], sequential);
    defer certificate.deinit(gpa);
    try testing.expect(try certificate.verify(gpa, &rng, &signers[0], sequential));
    try expect_roundtrip(Activity, .{ .certified = certificate }, cfg);
    try expect_roundtrip(Activity, .{ .tip = .new(123) }, cfg);

    // An unknown tag is rejected.
    try testing.expectError(error.Invalid, codec.decode_cfg(Activity, gpa, &.{3}, cfg));
}

test "codec with ed25519 and secp256r1" {
    inline for (individual_schemes) |entry| try check_codec(entry[0], entry[1]);
}

test "codec with bls12381 multisig and threshold" {
    try skip_slow();
    inline for (bls_schemes) |entry| try check_codec(entry[0], entry[1]);
}

/// Asserts that the widest tip ack encodes to exactly `max_payload_size`.
fn check_widest(comptime S: type, comptime fixture: anytype) !void {
    const gpa = testing.allocator;
    var rng = utils.rng.test_rng();
    var built = try fixture(S, gpa, &rng, "_COMMONWARE_CONSENSUS_AGGREGATION_LIMITS", 4);
    defer built.deinit(gpa);
    const item: types.Item(D) = .{ .height = .new(std.math.maxInt(u64)), .digest = .fill(7) };
    const Ack = types.Ack(S, D);
    var ack = (try Ack.sign(gpa, &built.schemes[0], .new(std.math.maxInt(u64)), item)).?;
    ack.attestation.signer = .init(std.math.maxInt(u32));
    const tip_ack: types.TipAck(S, D) = .{ .tip = .new(std.math.maxInt(u64)), .ack = ack };
    const encoded = try codec.encode(types.TipAck(S, D), gpa, tip_ack);
    defer gpa.free(encoded);
    try testing.expectEqual(limits.max_payload_size(S, D), encoded.len);
}

test "widest encodings with ed25519 and secp256r1" {
    inline for (individual_schemes) |entry| try check_widest(entry[0], entry[1]);
}

test "widest encodings with bls12381 multisig and threshold" {
    try skip_slow();
    inline for (bls_schemes) |entry| try check_widest(entry[0], entry[1]);
}

// Conformance.

/// A SHA-256 digest with commonware's `Arbitrary` (the hash of up to 256 drawn bytes).
const ArbitraryDigest = struct {
    inner: Sha256.Digest,

    pub const fixed_size: usize = 32;

    pub fn order(a: ArbitraryDigest, b: ArbitraryDigest) std.math.Order {
        return a.inner.order(b.inner);
    }

    pub fn write(self: ArbitraryDigest, writer: *codec.Writer) void {
        self.inner.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!ArbitraryDigest {
        return .{ .inner = try Sha256.Digest.read(gpa, reader, {}) };
    }

    pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!ArbitraryDigest {
        const len = u.int_in_range(u64, 0, 256);
        const data = try gpa.alloc(u8, len);
        try u.bytes(data);
        return .{ .inner = Sha256.hash(&.{data}) };
    }
};

/// A MinSig signature point with commonware's `G1::arbitrary`.
const Point = struct {
    point: MinSig.Signature,

    pub const fixed_size: usize = MinSig.Signature.fixed_size;

    pub fn write(self: Point, writer: *codec.Writer) void {
        codec.write(MinSig.Signature, self.point, writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Point {
        return .{ .point = try codec.read(MinSig.Signature, gpa, reader) };
    }

    pub fn arbitrary(_: Allocator, u: *Unstructured) ArbitraryError!Point {
        return .{ .point = vrf.arbitrary_point(MinSig.Signature, u) };
    }
};

/// A threshold certificate: exactly one signature point.
const PointCertificate = struct {
    signature: Point,

    pub const fixed_size: usize = Point.fixed_size;

    pub fn eql(a: *const PointCertificate, b: *const PointCertificate) bool {
        return a.signature.point.eql(b.signature.point);
    }

    pub fn deinit(self: *PointCertificate, _: Allocator) void {
        self.* = undefined;
    }

    pub fn write(self: PointCertificate, writer: *codec.Writer) void {
        self.signature.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!PointCertificate {
        return .{ .signature = try Point.read(gpa, reader, {}) };
    }

    pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!PointCertificate {
        return .{ .signature = try Point.arbitrary(gpa, u) };
    }
};

/// The wire types of `bls12381_threshold::Scheme<ed25519::PublicKey, MinSig>`.
const ConformanceScheme = struct {
    pub const Signature = Point;
    pub const Certificate = PointCertificate;
};

const conformance_file = @embedFile("../conformance.toml");
const prefix = "commonware_consensus::aggregation::types::tests::conformance::CodecConformance<";

fn CodecConformance(comptime T: type) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const gen = codec.arbitrary.default_generator(T);
            const value = try codec.arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

fn verify(comptime path: []const u8, comptime T: type) !void {
    const cases = conformance.default_cases;
    const gpa = std.heap.smp_allocator;
    try conformance.verify(CodecConformance(T), gpa, prefix ++ path, cases, conformance_file);
}

test "aggregation item conformance hash matches commonware" {
    try verify("Item<Sha256Digest>>", types.Item(ArbitraryDigest));
}

// Nightly only (`-Dslow-tests`): generating the BLS points takes about 18 s even in
// ReleaseSafe. The item hash above runs on every push.
test "aggregation message conformance hashes match commonware" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const S = ConformanceScheme;
    const Dg = ArbitraryDigest;
    try verify("Ack<Scheme,Sha256Digest>>", types.Ack(S, Dg));
    try verify("TipAck<Scheme,Sha256Digest>>", types.TipAck(S, Dg));
    try verify("Certificate<Scheme,Sha256Digest>>", types.Certificate(S, Dg));
    try verify("Activity<Scheme,Sha256Digest>>", types.Activity(S, Dg));
}
