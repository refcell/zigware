//! Codec conformance of MMR proofs (commonware's
//! `merkle::mmr::proof::tests::conformance::CodecConformance<Proof<Family,Sha256Digest>>`).
//!
//! Each case regenerates commonware's proof from the same `arbitrary` input and commits its
//! encoding, so a match means proofs encode byte-identically.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const merkle = @import("mod.zig");

const arbitrary = codec.arbitrary;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Family = merkle.mmr.Family;
const Proof = merkle.proof.Proof(Family, Digest);

const conformance_file = @embedFile("../conformance.toml");

/// `sha256::Digest::arbitrary`: `int_in_range(0..=256)` bytes of data, then their hash.
fn gen_digest(gpa: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!Digest {
    const len = u.int_in_range(u64, 0, 256);
    assert(len <= 256);
    const data = try gpa.alloc(u8, len);
    try u.bytes(data);
    return Sha256.hash(&.{data});
}

/// `Proof::arbitrary`: `Location::arbitrary` (`int_in_range(0..=MAX_LEAVES)`), a `usize`, then
/// `Vec<Digest>::arbitrary`.
fn gen_proof(gpa: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!Proof {
    const leaves = u.int_in_range(u64, 0, Family.max_leaves);
    const inactive_peaks: usize = @intCast(u.int(u64));
    var digests: std.ArrayList(Digest) = .empty;
    while (u.keep_going()) try digests.append(gpa, try gen_digest(gpa, u));
    assert(leaves <= Family.max_leaves);
    return .{ .leaves = leaves, .inactive_peaks = inactive_peaks, .digests = digests.items };
}

const ProofConformance = struct {
    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const proof = try arbitrary.generate(Proof, gen_proof, arena.allocator(), seed);
        return codec.encode(Proof, gpa, proof);
    }
};

test "conformance CodecConformance<Proof<Family,Sha256Digest>>" {
    // commonware `mmr::proof::tests::conformance::CodecConformance<Proof<Family,Sha256Digest>>`.
    try conformance.verify(
        ProofConformance,
        std.heap.smp_allocator,
        "commonware_storage::merkle::mmr::proof::tests::conformance::" ++
            "CodecConformance<Proof<Family,Sha256Digest>>",
        conformance.default_cases,
        conformance_file,
    );
}
