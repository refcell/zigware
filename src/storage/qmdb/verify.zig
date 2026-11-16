//! Verification of Merkle proofs over QMDB operations (qmdb/verify.rs, `ProofExt`).
//!
//! Unlike `merkle.Proof`'s own methods, which take pre-encoded elements and a hasher, these
//! take operations and a cryptography hasher type `H`, and encode and hash them the way QMDB
//! databases do (`qmdb.hasher(H)`, backward-fold bagging). A proof from a database therefore
//! verifies against that database's root. Operations are any codec type `O`; they are encoded
//! into scratch memory from `gpa` for the duration of the call.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../merkle/mod.zig");
const qmdb = @import("mod.zig");

/// The proof type for family `F` over hasher `H`.
pub fn Proof(comptime F: type, comptime H: type) type {
    return merkle.Proof(F, H.Digest);
}

/// The proof store type for family `F` over hasher `H`.
pub fn ProofStore(comptime F: type, comptime H: type) type {
    return merkle.ProofStore(F, H.Digest);
}

/// The encodings of `ops`, in order. Free with `free_encoded`.
pub fn encode_all(comptime O: type, gpa: Allocator, ops: []const O) Allocator.Error![][]u8 {
    const encoded = try gpa.alloc([]u8, ops.len);
    var count: usize = 0;
    errdefer {
        for (encoded[0..count]) |bytes| gpa.free(bytes);
        gpa.free(encoded);
    }
    for (ops) |op| {
        encoded[count] = try codec.encode(O, gpa, op);
        count += 1;
    }
    assert(count == ops.len);
    return encoded;
}

pub fn free_encoded(gpa: Allocator, encoded: [][]u8) void {
    for (encoded) |bytes| gpa.free(bytes);
    gpa.free(encoded);
}

/// Whether `proof` authenticates `ops` at `start..start + ops.len` under `root`.
pub fn verify(
    comptime F: type,
    comptime H: type,
    comptime O: type,
    gpa: Allocator,
    proof: *const Proof(F, H),
    start: u64,
    ops: []const O,
    root: *const H.Digest,
) Allocator.Error!bool {
    const encoded = try encode_all(O, gpa, ops);
    defer free_encoded(gpa, encoded);
    const hasher = qmdb.hasher(H);
    return proof.verify_range_inclusion(&hasher, start, encoded, root);
}

/// Whether `proof` verifies as `verify` checks and `pinned` are exactly the nodes pinned at
/// `start` in the database with `root`. When `start` is 0, `pinned` must be empty.
pub fn verify_with_pinned_nodes(
    comptime F: type,
    comptime H: type,
    comptime O: type,
    gpa: Allocator,
    proof: *const Proof(F, H),
    start: u64,
    ops: []const O,
    pinned: []const H.Digest,
    root: *const H.Digest,
) Allocator.Error!bool {
    const encoded = try encode_all(O, gpa, ops);
    defer free_encoded(gpa, encoded);
    const hasher = qmdb.hasher(H);
    return proof.verify_range_inclusion_with_pinned_nodes(
        gpa,
        &hasher,
        start,
        encoded,
        pinned,
        root,
    );
}

/// Verifies `proof` as `verify` does and appends every digest needed to reconstruct `root`,
/// with its position, to `out`. Fails with `RootMismatch` for another root and `InvalidProof`
/// for a malformed proof.
pub fn verify_and_extract_digests(
    comptime F: type,
    comptime H: type,
    comptime O: type,
    gpa: Allocator,
    proof: *const Proof(F, H),
    start: u64,
    ops: []const O,
    root: *const H.Digest,
    out: *std.ArrayList(Proof(F, H).NodeDigest),
) (merkle.Error || Allocator.Error)!void {
    const encoded = try encode_all(O, gpa, ops);
    defer free_encoded(gpa, encoded);
    const hasher = qmdb.hasher(H);
    try proof.verify_range_inclusion_and_extract_digests(
        gpa,
        &hasher,
        start,
        encoded,
        root,
        out,
    );
}

/// Verifies `proof` as `verify` does and converts it into a `ProofStore`, from which
/// sub-range and multi-proofs within the range can be built. Caller owns the store.
pub fn to_proof_store(
    comptime F: type,
    comptime H: type,
    comptime O: type,
    gpa: Allocator,
    proof: *const Proof(F, H),
    start: u64,
    ops: []const O,
    root: *const H.Digest,
) (merkle.Error || Allocator.Error)!ProofStore(F, H) {
    const encoded = try encode_all(O, gpa, ops);
    defer free_encoded(gpa, encoded);
    const hasher = qmdb.hasher(H);
    return ProofStore(F, H).init(gpa, &hasher, proof, start, encoded, root);
}

/// Whether the multi-proof `proof` authenticates `ops[i]` at `locations[i]` for every `i`
/// under `root`. Locations must be strictly increasing; a repeated or decreasing location
/// fails even for genuine operations. (commonware takes `(location, op)` pairs; here they are
/// two parallel slices, as in `merkle.Proof.verify_multi_inclusion`.)
pub fn verify_multi(
    comptime F: type,
    comptime H: type,
    comptime O: type,
    gpa: Allocator,
    proof: *const Proof(F, H),
    locations: []const u64,
    ops: []const O,
    root: *const H.Digest,
) Allocator.Error!bool {
    if (locations.len != ops.len) return false;
    const encoded = try encode_all(O, gpa, ops);
    defer free_encoded(gpa, encoded);
    const hasher = qmdb.hasher(H);
    return proof.verify_multi_inclusion(gpa, &hasher, locations, encoded, root);
}

test {
    _ = @import("verify_test.zig");
}
