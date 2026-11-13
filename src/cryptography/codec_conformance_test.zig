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
const Summary = @import("transcript.zig").Summary;
const sake = @import("handshake/sake.zig");

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
