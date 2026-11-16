//! The grafted view of an ops tree (commonware's `grafting::Storage`) and the range proofs
//! built over it (`RangeProof::build`).
//!
//! Nodes below the grafting height come from the ops tree; nodes at or above it come from the
//! grafted tree at the converted position. A grafted node missing after pruning (an ancestor
//! of the pinned peaks that a later merge created) is rebuilt from its children with the
//! grafted hasher; a missing grafted leaf cannot be rebuilt.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const merkle = @import("../../merkle/mod.zig");
const merkle_verification = @import("../../merkle/verification.zig");
const merkle_storage = @import("../../merkle/storage.zig");
const qmdb = @import("../mod.zig");
const grafting = @import("grafting.zig");
const canonical = @import("canonical.zig");
const proof_mod = @import("proof.zig");

/// A combined view over `grafted` (anything with `get_node(position) ?Digest`) and `ops` (a
/// source with `size()` and `get_node(position)` returning `?Digest` or `!?Digest`, such as a
/// persisted Merkle). Borrows both; reads fail only as `ops` reads do.
pub fn Storage(
    comptime F: type,
    comptime H: type,
    comptime Grafted: type,
    comptime Ops: type,
) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Digest = H.Digest;
        pub const ReadError = SourceError(Ops);

        grafted: Grafted,
        ops: Ops,
        grafting_height: u32,

        pub fn size(self: *const Self) u64 {
            return self.ops.size();
        }

        pub fn get_node(self: *const Self, position: u64) ReadError!?Digest {
            if (F.pos_to_height(position) < self.grafting_height) {
                return merkle_storage.get_node(self.ops, position);
            }
            const grafted_pos = grafting.ops_to_grafted_pos(F, position, self.grafting_height);
            return self.reconstruct(grafted_pos);
        }

        const Work = union(enum) { visit: u64, combine: u64 };
        /// A missing node's rebuild descends at most one level per height of a 64-bit tree.
        const stack_capacity = 2 * 64 + 2;

        /// The grafted node at `grafted_pos`, rebuilt from its descendants when missing.
        fn reconstruct(self: *const Self, grafted_pos: u64) ?Digest {
            const hasher = grafting.GraftedHasher(F, H).init(self.grafting_height);
            var work: merkle.BoundedList(Work, stack_capacity) = .{};
            var values: merkle.BoundedList(Digest, 64) = .{};
            work.append(.{ .visit = grafted_pos });
            while (work.pop()) |item| switch (item) {
                .visit => |position| {
                    if (self.grafted.get_node(position)) |digest| {
                        values.append(digest);
                        continue;
                    }
                    const height = F.pos_to_height(position);
                    if (height == 0) return null; // A grafted leaf holds bitmap data.
                    const children = F.children(position, height);
                    work.append(.{ .combine = position });
                    work.append(.{ .visit = children.right });
                    work.append(.{ .visit = children.left });
                },
                .combine => |position| {
                    const right = values.pop().?;
                    const left = values.pop().?;
                    values.append(hasher.node_digest(position, &left, &right));
                },
            };
            assert(values.len == 1);
            return values.buffer[0];
        }
    };
}

/// The error set of `Source.get_node` (empty for an in-memory source); `Source` may be a
/// pointer.
fn SourceError(comptime Source: type) type {
    const Child = switch (@typeInfo(Source)) {
        .pointer => |pointer| pointer.child,
        else => Source,
    };
    const Return = @typeInfo(@TypeOf(Child.get_node)).@"fn".return_type.?;
    return switch (@typeInfo(Return)) {
        .error_union => |error_union| error_union.error_set,
        else => error{},
    };
}

/// The range proof of operations `range` over the grafted `storage`, whose bitmap `bitmap` (of
/// `chunk_size`-byte chunks) and `ops_root` describe the same snapshot (commonware's
/// `RangeProof::new`). Owns its digests.
pub fn build_range_proof(
    comptime F: type,
    comptime H: type,
    comptime chunk_size: usize,
    gpa: Allocator,
    bitmap: anytype,
    storage: anytype,
    inactivity_floor: u64,
    range: merkle.Range,
    ops_root: H.Digest,
) !proof_mod.RangeProof(F, H.Digest) {
    const leaves = F.position_to_location(storage.size()) orelse return error.InvalidSize;
    const height = grafting.height(chunk_size);
    const inactive =
        try grafting.chunk_aligned_inactive_peaks(F, leaves, inactivity_floor, height);
    const hasher = qmdb.hasher(H);
    const build = merkle_verification.historical_range_proof;
    var merkle_proof_value = try build(F, gpa, &hasher, storage, leaves, range, inactive);
    errdefer merkle_proof_value.deinit(gpa);
    var partial: ?H.Digest = null;
    if (canonical.partial_chunk(chunk_size, bitmap)) |chunk| partial = H.hash(&.{&chunk[0]});
    const pending_bytes = try canonical.pending_chunk(F, chunk_size, bitmap, leaves);
    const pending: ?H.Digest = if (pending_bytes) |chunk| H.hash(&.{&chunk}) else null;
    const slot = proof_mod.pending_from(F, H.Digest, pending) catch
        unreachable; // Proof: MMR has no pending chunk (graftable equals complete).
    assert(merkle_proof_value.leaves == leaves);
    return .{
        .proof = merkle_proof_value,
        .pending_chunk_digest = slot,
        .partial_chunk_digest = partial,
        .ops_root = ops_root,
    };
}
