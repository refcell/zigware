//! Verification of current's range and operation proofs (commonware's
//! `RangeProof::reconstruct_root`, `verify_with_chunk_size`, and `operation::Proof::verify`).
//!
//! A range proof reconstructs the grafted root from the encoded operations, the bitmap chunks
//! covering them, and the Merkle digests, grafting each graftable chunk onto its height-`G`
//! node; the pending and partial chunk digests in the proof must match the bitmap shape the
//! proof's leaf count implies (and the supplied chunks when the range covers them). The
//! canonical root combines the ops root, that grafted root, and the two chunk digests.

const std = @import("std");
const assert = std.debug.assert;
const merkle = @import("../../merkle/mod.zig");
const grafting = @import("grafting.zig");
const proof_mod = @import("proof.zig");

pub const Error = error{InvalidProof};

/// The canonical root `range_proof` commits to for the operations `encoded` (each one's codec
/// encoding) from `start` and the `chunks` covering them, each `chunk_size` bytes.
pub fn reconstruct_root(
    comptime F: type,
    comptime H: type,
    range_proof: *const proof_mod.RangeProof(F, H.Digest),
    start: u64,
    encoded: []const []const u8,
    chunks: []const []const u8,
    chunk_size: usize,
) Error!H.Digest {
    const chunk_bits = proof_mod.chunk_bits(chunk_size) orelse return error.InvalidProof;
    if (encoded.len == 0 or chunks.len == 0) return error.InvalidProof;
    const end = std.math.add(u64, start, encoded.len) catch return error.InvalidProof;
    const leaves = range_proof.proof.leaves;
    if (end > leaves) return error.InvalidProof;
    const start_chunk = start / chunk_bits;
    const end_chunk = (end - 1) / chunk_bits;
    const complete = leaves / chunk_bits;
    if (end_chunk - start_chunk + 1 != chunks.len) return error.InvalidProof;
    for (chunks) |chunk| if (chunk.len != chunk_size) return error.InvalidProof;
    const height: u32 = @ctz(chunk_bits);
    const graftable = @min(grafting.graftable_chunks(F, leaves, height), complete);
    if (complete - graftable > 1) return error.InvalidProof; // Multiple pending chunks.
    try check_chunk_digests(F, H, range_proof, .{
        .chunks = chunks,
        .start_chunk = start_chunk,
        .end_chunk = end_chunk,
        .complete = complete,
        .graftable = graftable,
        .next_bit = leaves % chunk_bits,
    });
    const verifier = grafting.Verifier(F, H).init(height, start_chunk, chunks, graftable);
    const grafted_root = range_proof.proof.reconstruct_root(&verifier, start, encoded) catch
        return error.InvalidProof;
    const pending = proof_mod.pending_digest(F, H.Digest, range_proof.pending_chunk_digest);
    const next_bit = leaves % chunk_bits;
    var partial: ?proof_mod.PartialChunk(H.Digest) = null;
    if (next_bit != 0) {
        partial = .{ .next_bit = next_bit, .digest = range_proof.partial_chunk_digest.? };
    }
    return proof_mod.combine_roots(
        H,
        &range_proof.ops_root,
        &grafted_root,
        if (pending) |*digest| digest else null,
        partial,
    );
}

const Shape = struct {
    chunks: []const []const u8,
    start_chunk: u64,
    end_chunk: u64,
    complete: u64,
    graftable: u64,
    next_bit: u64,
};

/// The proof's pending and partial chunk digests match the shape its leaf count implies, and
/// the supplied chunks when the range covers the pending or partial chunk.
fn check_chunk_digests(
    comptime F: type,
    comptime H: type,
    range_proof: *const proof_mod.RangeProof(F, H.Digest),
    shape: Shape,
) Error!void {
    assert(shape.end_chunk >= shape.start_chunk);
    assert(shape.graftable <= shape.complete);
    const pending = proof_mod.pending_digest(F, H.Digest, range_proof.pending_chunk_digest);
    const has_pending = shape.complete - shape.graftable == 1;
    if ((pending != null) != has_pending) return error.InvalidProof;
    if (shape.next_bit != 0) {
        const partial = range_proof.partial_chunk_digest orelse return error.InvalidProof;
        if (shape.end_chunk == shape.complete) {
            const last = shape.chunks[shape.chunks.len - 1];
            if (!partial.eql(H.hash(&.{last}))) return error.InvalidProof;
        }
    } else if (range_proof.partial_chunk_digest != null) return error.InvalidProof;
    const digest = pending orelse return;
    const index = shape.graftable;
    if (index < shape.start_chunk or index > shape.end_chunk) return;
    const local: usize = @intCast(index - shape.start_chunk);
    if (local >= shape.chunks.len) return error.InvalidProof;
    if (!digest.eql(H.hash(&.{shape.chunks[local]}))) return error.InvalidProof;
}

/// Whether `range_proof` proves the operations `encoded` from `start`, with activity chunks
/// `chunks` of `chunk_size` bytes, under `root`.
pub fn verify_range(
    comptime F: type,
    comptime H: type,
    range_proof: *const proof_mod.RangeProof(F, H.Digest),
    start: u64,
    encoded: []const []const u8,
    chunks: []const []const u8,
    chunk_size: usize,
    root: *const H.Digest,
) bool {
    const reconstructed =
        reconstruct_root(F, H, range_proof, start, encoded, chunks, chunk_size) catch
            return false;
    return reconstructed.eql(root.*);
}

/// Whether the operation proof shows that `encoded` (an operation's encoding) is active at its
/// location under `root`: its bit is set in the proof's chunk and the range proof verifies.
pub fn verify_operation(
    comptime F: type,
    comptime H: type,
    operation_proof: anytype,
    encoded: []const u8,
    root: *const H.Digest,
) bool {
    const chunk: []const u8 = if (@typeInfo(@TypeOf(operation_proof.chunk)) == .array)
        &operation_proof.chunk
    else
        operation_proof.chunk;
    if (!operation_proof.is_active()) return false;
    const elements = [_][]const u8{encoded};
    const chunks = [_][]const u8{chunk};
    return verify_range(
        F,
        H,
        &operation_proof.range_proof,
        operation_proof.loc,
        &elements,
        &chunks,
        chunk.len,
        root,
    );
}
