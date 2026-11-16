//! current's proof types (commonware's `qmdb/current/proof/{mod,operation}.rs`): the
//! `OpsRootWitness` binding an ops root to a canonical `current` root, the `RangeProof` over a
//! span of operations and their activity bitmap, and the `OperationProof` that one operation
//! is active. Verification against the grafted tree lands with current's database.
//!
//! commonware's `Graftable::PendingChunk<D>` is `Option<D>` for MMB and `Unused` (zero bytes)
//! for MMR; here it is `Pending(F, D)`, `?D` or `void`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const operation = @import("../operation.zig");
const qmdb = @import("../mod.zig");
const value = @import("../value.zig");
const source = @import("../sync/source.zig");

/// Whether family `F` carries a pending-chunk digest (MMB does, MMR does not).
pub fn has_pending(comptime F: type) bool {
    merkle.check_family(F);
    return F == merkle.mmb.Family;
}

/// The pending-chunk slot of family `F`: `?D` for MMB, `void` (encoded as nothing) for MMR.
pub fn Pending(comptime F: type, comptime D: type) type {
    return if (has_pending(F)) ?D else void;
}

/// The slot as an optional digest.
pub fn pending_digest(comptime F: type, comptime D: type, slot: Pending(F, D)) ?D {
    return if (comptime has_pending(F)) slot else null;
}

/// The slot holding `digest`, or `error.Invalid` when `F` has no pending chunk but a digest
/// is present (commonware's `TryFrom<Option<D>> for Unused`).
pub fn pending_from(comptime F: type, comptime D: type, digest: ?D) error{Invalid}!Pending(F, D) {
    if (comptime has_pending(F)) return digest;
    if (digest != null) return error.Invalid;
}

fn pending_size(comptime F: type, comptime D: type, slot: Pending(F, D)) usize {
    return if (comptime has_pending(F)) codec.encode_size(?D, slot) else 0;
}

fn write_pending(
    comptime F: type,
    comptime D: type,
    slot: Pending(F, D),
    writer: *codec.Writer,
) void {
    if (comptime has_pending(F)) codec.write(?D, slot, writer);
}

fn read_pending(
    comptime F: type,
    comptime D: type,
    gpa: Allocator,
    reader: *codec.Reader,
) codec.Error!Pending(F, D) {
    if (comptime has_pending(F)) return codec.read(?D, gpa, reader);
}

fn arbitrary_pending(
    comptime F: type,
    comptime D: type,
    gpa: Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error!Pending(F, D) {
    if (comptime has_pending(F)) return value.arbitrary(?D, gpa, u);
}

/// The bit width of a bitmap chunk of `chunk_size` bytes, or null unless it is a power of two
/// below `2^63` (commonware's `chunk_bits`).
pub fn chunk_bits(chunk_size: usize) ?u64 {
    const bits = std.math.mul(u64, chunk_size, 8) catch return null;
    if (bits == 0 or !std.math.isPowerOfTwo(bits) or @ctz(bits) >= 63) return null;
    assert(bits >= 8);
    return bits;
}

/// The canonical `current` root committing to `ops_root`, the grafted root, the pending
/// chunk, and the trailing partial chunk `(next_bit, digest)` (commonware's `combine_roots`).
pub fn combine_roots(
    comptime H: type,
    ops_root: *const H.Digest,
    grafted_root: *const H.Digest,
    pending: ?*const H.Digest,
    partial: ?PartialChunk(H.Digest),
) H.Digest {
    const hasher = qmdb.hasher(H);
    var parts: [5][]const u8 = undefined;
    var count: usize = 0;
    parts[count] = ops_root.as_slice();
    count += 1;
    parts[count] = grafted_root.as_slice();
    count += 1;
    if (pending) |digest| {
        parts[count] = digest.as_slice();
        count += 1;
    }
    var next_bit: [8]u8 = undefined;
    if (partial) |*chunk| {
        std.mem.writeInt(u64, &next_bit, chunk.next_bit, .big);
        parts[count] = &next_bit;
        parts[count + 1] = chunk.digest.as_slice();
        count += 2;
    }
    assert(count >= 2 and count <= parts.len);
    return hasher.hash(parts[0..count]);
}

/// The trailing partial chunk's contribution: the next bit to set and the chunk's digest.
pub fn PartialChunk(comptime D: type) type {
    return struct { next_bit: u64, digest: D };
}

/// Witness that an `ops_root` is committed by a `current` canonical root.
pub fn OpsRootWitness(comptime F: type, comptime D: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Partial = PartialChunk(D);

        /// The grafted-tree root committed by the canonical root.
        grafted_root: D,
        /// The pending-chunk contribution, if any.
        pending_chunk_digest: Pending(F, D),
        /// The trailing partial chunk, if the bitmap length is not chunk-aligned.
        partial_chunk: ?Partial,

        /// The canonical root that commits to `ops_root` through this witness.
        pub fn root(self: *const Self, comptime H: type, ops_root: *const D) D {
            comptime assert(H.Digest == D);
            comptime assert(@sizeOf(D) > 0);
            const pending = pending_digest(F, D, self.pending_chunk_digest);
            return combine_roots(
                H,
                ops_root,
                &self.grafted_root,
                if (pending) |*digest| digest else null,
                self.partial_chunk,
            );
        }

        /// Whether this witness proves that `canonical` commits to `ops_root`.
        pub fn verify(
            self: *const Self,
            comptime H: type,
            ops_root: *const D,
            canonical: *const D,
        ) bool {
            return self.root(H, ops_root).eql(canonical.*);
        }

        pub fn eql(a: Self, b: Self) bool {
            if (!a.grafted_root.eql(b.grafted_root)) return false;
            const pa = pending_digest(F, D, a.pending_chunk_digest);
            const pb = pending_digest(F, D, b.pending_chunk_digest);
            if (!value.eql(?D, pa, pb)) return false;
            if (a.partial_chunk == null or b.partial_chunk == null) {
                return a.partial_chunk == null and b.partial_chunk == null;
            }
            return a.partial_chunk.?.next_bit == b.partial_chunk.?.next_bit and
                a.partial_chunk.?.digest.eql(b.partial_chunk.?.digest);
        }

        pub fn encode_size(self: Self) usize {
            var size = codec.encode_size(D, self.grafted_root) +
                pending_size(F, D, self.pending_chunk_digest) + 1;
            if (self.partial_chunk) |chunk| {
                size += codec.varint.size(u64, chunk.next_bit) + codec.encode_size(D, chunk.digest);
            }
            assert(size > codec.encode_size(D, self.grafted_root));
            return size;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(D, self.grafted_root, writer);
            write_pending(F, D, self.pending_chunk_digest, writer);
            codec.write(bool, self.partial_chunk != null, writer);
            if (self.partial_chunk) |chunk| {
                codec.varint.write(u64, chunk.next_bit, writer);
                codec.write(D, chunk.digest, writer);
            }
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const grafted_root = try codec.read(D, gpa, reader);
            const pending = try read_pending(F, D, gpa, reader);
            var partial: ?Partial = null;
            if (try codec.read(bool, gpa, reader)) {
                const next_bit = try codec.varint.read(u64, reader);
                partial = .{ .next_bit = next_bit, .digest = try codec.read(D, gpa, reader) };
            }
            return .{
                .grafted_root = grafted_root,
                .pending_chunk_digest = pending,
                .partial_chunk = partial,
            };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const grafted_root = try value.arbitrary(D, gpa, u);
            const pending = try arbitrary_pending(F, D, gpa, u);
            var partial: ?Partial = null;
            if (u.boolean()) {
                const next_bit = u.int(u64);
                partial = .{ .next_bit = next_bit, .digest = try value.arbitrary(D, gpa, u) };
            }
            return .{
                .grafted_root = grafted_root,
                .pending_chunk_digest = pending,
                .partial_chunk = partial,
            };
        }
    };
}

/// A proof that a range of operations exists in the database, with their activity status.
/// Owns its Merkle proof's digests: free it with `deinit`.
pub fn RangeProof(comptime F: type, comptime D: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Proof = merkle.Proof(F, D);
        /// codec: the maximum digest count of the embedded Merkle proof.
        pub const Cfg = usize;

        /// The Merkle digest material required to verify the proof.
        proof: Proof,
        /// The pending-chunk contribution, if any.
        pending_chunk_digest: Pending(F, D),
        /// Digest of the bitmap's trailing partial chunk, if any.
        partial_chunk_digest: ?D,
        /// The ops-tree root.
        ops_root: D,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.proof.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var copy = self.*;
            copy.proof = try self.proof.clone(gpa);
            return copy;
        }

        pub fn eql(a: Self, b: Self) bool {
            const pa = pending_digest(F, D, a.pending_chunk_digest);
            const pb = pending_digest(F, D, b.pending_chunk_digest);
            return a.proof.eql(&b.proof) and value.eql(?D, pa, pb) and
                value.eql(?D, a.partial_chunk_digest, b.partial_chunk_digest) and
                a.ops_root.eql(b.ops_root);
        }

        pub fn encode_size(self: Self) usize {
            const size = self.proof.encode_size() +
                pending_size(F, D, self.pending_chunk_digest) +
                codec.encode_size(?D, self.partial_chunk_digest) +
                codec.encode_size(D, self.ops_root);
            assert(size > codec.encode_size(D, self.ops_root));
            return size;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.proof.write(writer);
            write_pending(F, D, self.pending_chunk_digest, writer);
            codec.write(?D, self.partial_chunk_digest, writer);
            codec.write(D, self.ops_root, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max_digests: Cfg) codec.Error!Self {
            var proof = try Proof.read(gpa, reader, max_digests);
            errdefer proof.deinit(gpa);
            assert(proof.digests.len <= max_digests);
            const pending = try read_pending(F, D, gpa, reader);
            const partial = try codec.read(?D, gpa, reader);
            const ops_root = try codec.read(D, gpa, reader);
            return .{
                .proof = proof,
                .pending_chunk_digest = pending,
                .partial_chunk_digest = partial,
                .ops_root = ops_root,
            };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            var proof = try source.arbitrary_proof(F, D, gpa, u);
            errdefer proof.deinit(gpa);
            const pending = try arbitrary_pending(F, D, gpa, u);
            const partial = try value.arbitrary(?D, gpa, u);
            return .{
                .proof = proof,
                .pending_chunk_digest = pending,
                .partial_chunk_digest = partial,
                .ops_root = try value.arbitrary(D, gpa, u),
            };
        }
    };
}

/// A proof that the operation at `loc` is active. `chunk_size` is the bitmap chunk size in
/// bytes when it is fixed at compile time (commonware's `[u8; N]`), or null when the decoder
/// supplies it (`Bytes`); both encode the chunk without a length prefix. A runtime-sized
/// chunk is owned: free the proof with `deinit`.
pub fn OperationProof(comptime F: type, comptime D: type, comptime chunk_size: ?usize) type {
    merkle.check_family(F);
    if (chunk_size) |size| comptime assert(chunk_bits(size) != null);
    return struct {
        const Self = @This();
        pub const Range = RangeProof(F, D);
        pub const Chunk = if (chunk_size) |size| [size]u8 else []const u8;
        /// codec: the digest budget of the range proof, and the chunk size when not fixed.
        pub const Cfg = if (chunk_size == null)
            struct { chunk_size: usize, max_digests: usize }
        else
            usize;

        /// The location of the operation.
        loc: u64,
        /// The status bitmap chunk holding the operation's activity bit.
        chunk: Chunk,
        /// The range proof authenticating the operation and its activity status.
        range_proof: Range,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (comptime chunk_size == null) gpa.free(self.chunk);
            self.range_proof.deinit(gpa);
            self.* = undefined;
        }

        /// Whether the operation's bit is set in its chunk.
        pub fn is_active(self: *const Self) bool {
            const bits = chunk_bits(self.chunk.len) orelse return false;
            const bit = self.loc % bits;
            assert(bit / 8 < self.chunk.len);
            return self.chunk[@intCast(bit / 8)] & (@as(u8, 1) << @intCast(bit % 8)) != 0;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.loc == b.loc and std.mem.eql(u8, a.chunk_slice(), b.chunk_slice()) and
                a.range_proof.eql(b.range_proof);
        }

        fn chunk_slice(self: *const Self) []const u8 {
            return if (comptime chunk_size == null) self.chunk else &self.chunk;
        }

        pub fn encode_size(self: Self) usize {
            const size = operation.location_size(self.loc) + self.chunk_slice().len +
                self.range_proof.encode_size();
            assert(size > self.chunk_slice().len);
            return size;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            assert(self.chunk_slice().len > 0);
            operation.write_location(self.loc, writer);
            writer.write_bytes(self.chunk_slice());
            self.range_proof.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const size, const max_digests = if (comptime chunk_size) |n|
                .{ n, cfg }
            else
                .{ cfg.chunk_size, cfg.max_digests };
            if (chunk_bits(size) == null) {
                return reader.invalid("current proof", "invalid bitmap chunk size");
            }
            const loc = try operation.read_location(F, reader);
            var chunk: Chunk = undefined;
            if (comptime chunk_size == null) {
                chunk = try gpa.dupe(u8, try reader.take(size));
            } else {
                chunk = (try reader.take_array(size)).*;
            }
            errdefer if (comptime chunk_size == null) gpa.free(chunk);
            const range_proof = try Range.read(gpa, reader, max_digests);
            return .{ .loc = loc, .chunk = chunk, .range_proof = range_proof };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const loc = operation.arbitrary_location(F, u);
            var chunk: Chunk = undefined;
            if (comptime chunk_size == null) {
                const size = @as(usize, 1) << @intCast(u.int_in_range(u8, 0, 8));
                const bytes = try gpa.alloc(u8, size);
                errdefer gpa.free(bytes);
                try u.bytes(bytes);
                chunk = bytes;
            } else {
                u.fill(&chunk);
            }
            errdefer if (comptime chunk_size == null) gpa.free(chunk);
            const range_proof = try Range.arbitrary(gpa, u);
            return .{ .loc = loc, .chunk = chunk, .range_proof = range_proof };
        }
    };
}

/// Proofs with fixed-size bitmap chunks.
pub const constant = struct {
    pub fn Operation(comptime F: type, comptime D: type, comptime N: usize) type {
        return OperationProof(F, D, N);
    }
};

/// Proofs with runtime-sized bitmap chunks.
pub const dynamic = struct {
    pub fn Operation(comptime F: type, comptime D: type) type {
        return OperationProof(F, D, null);
    }
};
