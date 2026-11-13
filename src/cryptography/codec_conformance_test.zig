//! `CodecConformance` hashes of the cryptography types (every `conformance_tests!` that names
//! `CodecConformance<...>` in commonware's cryptography crate).
//!
//! Each entry regenerates commonware's 65536 values with the same `arbitrary` + ChaCha8 inputs,
//! using a port of the type's Rust `Arbitrary` impl, encodes them with zigware, and checks the
//! SHA-256 against `conformance.toml` (copied unchanged from commonware). A match proves the
//! encodings, hashes, and key derivations are byte-identical to commonware's.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const arbitrary = codec.arbitrary;
const Unstructured = arbitrary.Unstructured;
const Error = arbitrary.Error;
const slow = @import("conformance.zig");
const Sha256 = @import("sha256.zig").Sha256;
const Sha512 = @import("sha512.zig").Sha512;
const Blake3 = @import("blake3.zig").Blake3;
const Keccak256 = @import("keccak256.zig").Keccak256;
const Crc32 = @import("crc32.zig").Crc32;
const ed25519 = @import("ed25519.zig");
const secp256r1 = @import("secp256r1.zig");
const LtHash = @import("lthash.zig").LtHash;
const Summary = @import("transcript.zig").Summary;
const sake = @import("handshake/sake.zig");
const certificate = @import("certificate.zig");

const conformance_file = @embedFile("conformance.toml");
const prefix = "commonware_cryptography::";

fn CodecConformance(comptime T: type, comptime gen: arbitrary.Generator(T)) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const value = try arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

fn verify(comptime name: []const u8, comptime T: type, comptime gen: arbitrary.Generator(T)) !void {
    try conformance.verify(
        CodecConformance(T, gen),
        std.heap.smp_allocator,
        prefix ++ name,
        conformance.default_cases,
        conformance_file,
    );
}

/// Like `verify`, with the case count recorded in the conformance file (`=> 1024`).
fn verify_n(
    comptime name: []const u8,
    comptime T: type,
    comptime gen: arbitrary.Generator(T),
) !void {
    const entry = (try conformance.find(conformance_file, prefix ++ name)).?;
    try conformance.verify(
        CodecConformance(T, gen),
        std.heap.smp_allocator,
        prefix ++ name,
        entry.n_cases,
        conformance_file,
    );
}

/// The digest impls: `int_in_range(0..=256)` bytes of data, then their hash.
fn gen_digest(comptime H: type) arbitrary.Generator(H.Digest) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!H.Digest {
            const len = u.int_in_range(u64, 0, 256);
            assert(len <= 256);
            const data = try gpa.alloc(u8, len);
            try u.bytes(data);
            return H.hash(&.{data});
        }
    }.generate;
}

/// `[u8; 32]::arbitrary`, behind `Summary`, `Ack`, and `EphemeralPublicKey`.
fn bytes32(gpa: Allocator, u: *Unstructured) Error![32]u8 {
    return arbitrary.value([32]u8, gpa, u);
}

fn gen_summary(gpa: Allocator, u: *Unstructured) Error!Summary {
    return .{ .bytes = try bytes32(gpa, u) };
}

fn gen_ack(gpa: Allocator, u: *Unstructured) Error!sake.Ack {
    return .{ .confirmation = try gen_summary(gpa, u) };
}

fn gen_epk(gpa: Allocator, u: *Unstructured) Error!sake.EphemeralPublicKey {
    return .{ .bytes = try bytes32(gpa, u) };
}

/// `PrivateKey::random(StdRng::from_seed(u.arbitrary::<[u8; 32]>()))`.
fn gen_private_key(gpa: Allocator, u: *Unstructured) Error!ed25519.PrivateKey {
    var rng = utils.rng.TestRng.init_key(try bytes32(gpa, u));
    return ed25519.PrivateKey.random(&rng);
}

fn gen_public_key(gpa: Allocator, u: *Unstructured) Error!ed25519.PublicKey {
    const private_key = try gen_private_key(gpa, u);
    return private_key.public_key();
}

/// A random key signs up to 255 arbitrary bytes under the empty namespace.
fn gen_signature(gpa: Allocator, u: *Unstructured) Error!ed25519.Signature {
    const private_key = try gen_private_key(gpa, u);
    const len = try arbitrary.value(usize, gpa, u) % 256;
    // `arbitrary_iter().take(len)`: a continuation byte before each element, none after.
    var message: std.ArrayList(u8) = .empty;
    while (message.items.len < len and u.keep_going()) try message.append(gpa, u.int(u8));
    assert(message.items.len <= len);
    return private_key.sign("", message.items);
}

/// The secp256r1 `PrivateKeyInner::random(StdRng::from_seed(..))` for either scheme.
fn gen_secp_private_key(comptime M: type) arbitrary.Generator(M.PrivateKey) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!M.PrivateKey {
            var rng = utils.rng.TestRng.init_key(try bytes32(gpa, u));
            return M.PrivateKey.random(&rng);
        }
    }.generate;
}

fn gen_secp_public_key(gpa: Allocator, u: *Unstructured) Error!secp256r1.standard.PublicKey {
    const private_key = try gen_secp_private_key(secp256r1.standard)(gpa, u);
    return private_key.public_key();
}

/// Like `gen_signature`: a random key signs up to 255 bytes under the empty namespace.
fn gen_secp_signature(comptime M: type) arbitrary.Generator(M.Signature) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!M.Signature {
            const private_key = try gen_secp_private_key(M)(gpa, u);
            const len = try arbitrary.value(usize, gpa, u) % 256;
            var message: std.ArrayList(u8) = .empty;
            while (message.items.len < len and u.keep_going()) {
                try message.append(gpa, u.int(u8));
            }
            assert(message.items.len <= len);
            return private_key.sign("", message.items);
        }
    }.generate;
}

/// The derived `Arbitrary` of `LtHash`: 1024 arbitrary `u16`s.
fn gen_lthash(gpa: Allocator, u: *Unstructured) Error!LtHash {
    return .{ .state = try arbitrary.value([1024]u16, gpa, u) };
}

const Protocol = sake.Sake(ed25519.PrivateKey);

fn gen_syn(gpa: Allocator, u: *Unstructured) Error!Protocol.Syn {
    return .{
        .time_ms = u.int(u64),
        .epk = try gen_epk(gpa, u),
        .signature = try gen_signature(gpa, u),
    };
}

fn gen_syn_ack(gpa: Allocator, u: *Unstructured) Error!Protocol.SynAck {
    return .{
        .time_ms = u.int(u64),
        .epk = try gen_epk(gpa, u),
        .signature = try gen_signature(gpa, u),
        .confirmation = try gen_summary(gpa, u),
    };
}

/// `Signers::arbitrary`: up to 9 participants, the first `signer_count` of them signing.
fn gen_signers(gpa: Allocator, u: *Unstructured) Error!certificate.Signers {
    const participants: u32 = @intCast(u.byte_size() % 10);
    const signer_count = @min(u.byte_size(), participants);
    const signers = try gpa.alloc(utils.Participant, signer_count);
    for (signers, 0..) |*signer, index| signer.* = .from_usize(index);
    return certificate.Signers.init(gpa, participants, signers) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Proof: the indices `0..signer_count` are unique and below `participants`.
        else => unreachable,
    };
}

/// The certificate tests' ed25519 fixture scheme, as far as `Attestation` uses it.
const Ed25519Attesting = struct {
    pub const Signature = ed25519.Signature;
};
const Ed25519Attestation = certificate.Attestation(Ed25519Attesting);

/// `Attestation::arbitrary`: the signer (`u32`), then a signature.
fn gen_attestation(gpa: Allocator, u: *Unstructured) Error!Ed25519Attestation {
    const signer = try arbitrary.value(u32, gpa, u);
    return .init(.init(signer), try gen_signature(gpa, u));
}

/// The ed25519 `Certificate::arbitrary`: signers, then one signature per signer.
fn gen_ed25519_certificate(gpa: Allocator, u: *Unstructured) Error!ed25519.certificate.Certificate {
    const signers = try gen_signers(gpa, u);
    const Deferred = certificate.Deferred(ed25519.Signature);
    const signatures = try gpa.alloc(Deferred, signers.count());
    for (signatures) |*signature| signature.* = .init(try gen_signature(gpa, u));
    return .{ .signers = signers, .signatures = signatures };
}

test "conformance: certificate signers, attestation, and ed25519 certificate" {
    try slow.skip_slow();
    const tests = "certificate::tests::conformance::";
    try verify(tests ++ "CodecConformance<Signers>", certificate.Signers, gen_signers);
    try verify(
        tests ++ "CodecConformance<Attestation<Scheme>>",
        Ed25519Attestation,
        gen_attestation,
    );
    try verify(
        "ed25519::" ++ tests ++ "CodecConformance<Certificate>",
        ed25519.certificate.Certificate,
        gen_ed25519_certificate,
    );
}

test "conformance: digests" {
    const digest = "::tests::conformance::CodecConformance<Digest>";
    try verify("sha256" ++ digest, Sha256.Digest, gen_digest(Sha256));
    try verify("sha512" ++ digest, Sha512.Digest, gen_digest(Sha512));
    try verify("blake3" ++ digest, Blake3.Digest, gen_digest(Blake3));
    try verify("keccak256" ++ digest, Keccak256.Digest, gen_digest(Keccak256));
    try verify("crc32" ++ digest, Crc32.Digest, gen_digest(Crc32));
}

test "conformance: transcript summary and sake messages" {
    try verify("transcript::test::conformance::CodecConformance<Summary>", Summary, gen_summary);
    try verify("handshake::sake::conformance::CodecConformance<Ack>", sake.Ack, gen_ack);
    try verify(
        "handshake::sake::exchange::conformance::CodecConformance<EphemeralPublicKey>",
        sake.EphemeralPublicKey,
        gen_epk,
    );
}

test "conformance: ed25519 keys and signatures" {
    try slow.skip_slow();
    const scheme = "ed25519::scheme::tests::conformance::";
    try verify(scheme ++ "CodecConformance<PrivateKey>", ed25519.PrivateKey, gen_private_key);
    try verify(scheme ++ "CodecConformance<PublicKey>", ed25519.PublicKey, gen_public_key);
    try verify(scheme ++ "CodecConformance<Signature>", ed25519.Signature, gen_signature);
}

test "conformance: sake syn and syn_ack" {
    try slow.skip_slow();
    const sake_prefix = "handshake::sake::conformance::";
    try verify(
        sake_prefix ++ "CodecConformance<Syn<crate::ed25519::Signature>>",
        Protocol.Syn,
        gen_syn,
    );
    try verify(
        sake_prefix ++ "CodecConformance<SynAck<crate::ed25519::Signature>>",
        Protocol.SynAck,
        gen_syn_ack,
    );
}

test "conformance: secp256r1 keys and signatures" {
    try slow.skip_slow();
    const standard = secp256r1.standard;
    const recoverable = secp256r1.recoverable;
    try verify_n(
        "secp256r1::common::tests::conformance::CodecConformance<PrivateKeyInner>",
        standard.PrivateKey,
        gen_secp_private_key(standard),
    );
    try verify_n(
        "secp256r1::common::tests::conformance::CodecConformance<PublicKeyInner>",
        standard.PublicKey,
        gen_secp_public_key,
    );
    try verify_n(
        "secp256r1::standard::tests::conformance::CodecConformance<Signature>",
        standard.Signature,
        gen_secp_signature(standard),
    );
    try verify_n(
        "secp256r1::recoverable::tests::conformance::CodecConformance<Signature>",
        recoverable.Signature,
        gen_secp_signature(recoverable),
    );
}

test "conformance: lthash" {
    try verify("lthash::tests::conformance::CodecConformance<LtHash>", LtHash, gen_lthash);
}
