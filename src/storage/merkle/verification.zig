//! Proofs from any Merkle source, and a `ProofStore` that re-proves sub-ranges of a verified
//! range proof. Port of commonware's `storage/src/merkle/verification.rs`.
//!
//! `range_proof` proves against a source's current state and `historical_range_proof`
//! against the state when it had `leaves` leaves (what sync needs). Sources follow
//! `storage.zig`. `ProofStore` keeps every node digest a verified proof reveals, plus the
//! proof's fold-prefix and backward-fold suffix accumulators, so sub-range proofs need no
//! access to the structure.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const merkle = @import("mod.zig");
const proof_module = @import("proof.zig");
const storage = @import("storage.zig");

const BoundedList = merkle.BoundedList;
const Range = merkle.Range;
const max_peaks = merkle.max_pinned_nodes;
const max_plan_positions = proof_module.max_plan_positions;

/// The digest type `hasher` produces.
fn HasherDigest(comptime Hasher: type) type {
    return switch (@typeInfo(Hasher)) {
        .pointer => |pointer| pointer.child.Digest,
        else => Hasher.Digest,
    };
}

/// A range proof of `range` against the source's current state.
pub fn range_proof(
    comptime F: type,
    gpa: Allocator,
    hasher: anytype,
    source: anytype,
    range: Range,
    inactive_peaks: usize,
) !proof_module.Proof(F, HasherDigest(@TypeOf(hasher))) {
    const leaves = try merkle.location_from_position(F, source.size());
    assert(leaves <= F.max_leaves);
    return historical_range_proof(F, gpa, hasher, source, leaves, range, inactive_peaks);
}

/// A range proof of `range` against the source's state when it had `leaves` leaves. Reads
/// the plan's nodes with `storage.get_nodes`, then builds the proof from them.
pub fn historical_range_proof(
    comptime F: type,
    gpa: Allocator,
    hasher: anytype,
    source: anytype,
    leaves: u64,
    range: Range,
    inactive_peaks: usize,
) !proof_module.Proof(F, HasherDigest(@TypeOf(hasher))) {
    const Digest = HasherDigest(@TypeOf(hasher));
    const plan = try proof_module.RangePlan(F).init(leaves, range);
    const positions = plan.positions();
    const blueprint = try proof_module.Blueprint(F).from_plan(
        &plan,
        inactive_peaks,
        hasher.root_bagging(),
    );
    var digests: [max_plan_positions]Digest = undefined;
    try storage.get_nodes(source, positions.slice(), digests[0..positions.len]);
    const fetched: Fetched(Digest) = .{
        .positions = positions.slice(),
        .digests = digests[0..positions.len],
    };
    assert(fetched.positions.len == fetched.digests.len);
    return blueprint.build_proof(gpa, hasher, inactive_peaks, &fetched);
}

/// Nodes read for a proof plan, looked up by position (commonware's fetched map).
fn Fetched(comptime Digest: type) type {
    return struct {
        positions: []const u64,
        digests: []const Digest,

        pub fn get_node(self: *const @This(), position: u64) ?Digest {
            assert(self.positions.len == self.digests.len);
            const slot = std.sort.binarySearch(u64, self.positions, position, order) orelse
                return null;
            assert(self.positions[slot] == position);
            return self.digests[slot];
        }

        fn order(target: u64, item: u64) std.math.Order {
            return std.math.order(target, item);
        }
    };
}

/// A multi-element proof of `locations` (strictly increasing) committing to
/// `inactive_peaks`. Caller owns the proof.
pub fn multi_proof(
    comptime F: type,
    gpa: Allocator,
    source: anytype,
    inactive_peaks: usize,
    locations: []const u64,
) !proof_module.Proof(F, SourceDigest(@TypeOf(source))) {
    const Digest = SourceDigest(@TypeOf(source));
    const size = source.size();
    const leaves = try merkle.location_from_position(F, size);
    const positions = try proof_module.multi_proof_positions(F, gpa, leaves, locations);
    defer gpa.free(positions);
    if (inactive_peaks > peak_count(F, size)) return error.InvalidProof;
    const digests = try gpa.alloc(Digest, positions.len);
    errdefer gpa.free(digests);
    try storage.get_nodes(source, positions, digests);
    assert(digests.len == positions.len);
    return .{ .leaves = leaves, .inactive_peaks = inactive_peaks, .digests = digests };
}

fn SourceDigest(comptime T: type) type {
    const Source = switch (@typeInfo(T)) {
        .pointer => |pointer| pointer.child,
        else => T,
    };
    const Return = @typeInfo(@TypeOf(Source.get_node)).@"fn".return_type.?;
    const Node = switch (@typeInfo(Return)) {
        .error_union => |error_union| error_union.payload,
        else => Return,
    };
    return @typeInfo(Node).optional.child;
}

fn peak_count(comptime F: type, size: u64) usize {
    var count: usize = 0;
    var peaks = F.peaks(size);
    while (peaks.next()) |_| count += 1;
    assert(count <= max_peaks);
    return count;
}

/// The node digests revealed by a verified range proof, able to prove any sub-range of it.
pub fn ProofStore(comptime F: type, comptime Digest: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Proof = proof_module.Proof(F, Digest);
        pub const NodeDigest = Proof.NodeDigest;

        digests: std.AutoHashMapUnmanaged(u64, Digest),
        size: u64,
        /// The proof's fold-prefix accumulator, if peaks preceded the proven range.
        fold_accumulator: ?Digest,
        /// The number of peaks folded into `fold_accumulator`.
        fold_peak_count: usize,
        /// Suffix peaks hidden behind `suffix_accumulator`.
        suffix_peaks: BoundedList(u64, max_peaks),
        /// The backward-folded accumulator of `suffix_peaks`.
        suffix_accumulator: ?Digest,
        inactive_peaks: usize,
        bagging: merkle.Bagging,

        /// Verifies `proof` of `elements` at `start..` under `root` (with `hasher`'s bagging)
        /// and keeps what it reveals. Fails if the proof does not verify.
        pub fn init(
            gpa: Allocator,
            hasher: anytype,
            proof: *const Proof,
            start: u64,
            elements: anytype,
            root: *const Digest,
        ) (merkle.Error || Allocator.Error)!Self {
            const bagging = hasher.root_bagging();
            var extracted: std.ArrayList(NodeDigest) = .empty;
            defer extracted.deinit(gpa);
            try proof.verify_range_inclusion_and_extract_digests(
                gpa,
                hasher,
                start,
                elements,
                root,
                &extracted,
            );
            const size = try merkle.position_from_location(F, proof.leaves);
            // Count fold-prefix peaks by leaf coverage, as proof construction does: an MMB
            // does not order its peaks by position.
            const end = merkle.checked_add(start, elements.len, F.max_leaves) orelse
                return error.LocationOverflow;
            const range: Range = .{ .start = start, .end = end };
            const blueprint = try proof_module.Blueprint(F).init(
                proof.leaves,
                proof.inactive_peaks,
                bagging,
                range,
            );
            const layout = blueprint.split_proof_digests(Digest, proof.digests) catch
                return error.InvalidProof;
            var digests: std.AutoHashMapUnmanaged(u64, Digest) = .empty;
            errdefer digests.deinit(gpa);
            try digests.ensureTotalCapacity(gpa, @intCast(extracted.items.len));
            for (extracted.items) |node| digests.putAssumeCapacity(node.position, node.digest);
            assert((layout.fold_prefix != null) == (blueprint.fold_prefix.len > 0));
            assert((layout.suffix_accumulator != null) == (blueprint.suffix_peaks.len > 0));
            return .{
                .digests = digests,
                .size = size,
                .fold_accumulator = if (layout.fold_prefix) |digest| digest.* else null,
                .fold_peak_count = blueprint.fold_prefix.len,
                .suffix_peaks = blueprint.suffix_peaks,
                .suffix_accumulator = if (layout.suffix_accumulator) |d| d.* else null,
                .inactive_peaks = proof.inactive_peaks,
                .bagging = bagging,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.digests.deinit(gpa);
            self.* = undefined;
        }

        fn digest_at(self: *const Self, position: u64) merkle.Error!Digest {
            return self.digests.get(position) orelse error.ElementPruned;
        }

        /// A range proof of `range`, a sub-range of the stored one. Its fold accumulator
        /// starts from the stored one and folds in stored peaks that now precede the range.
        /// Caller owns the proof.
        pub fn range_proof(
            self: *const Self,
            gpa: Allocator,
            hasher: anytype,
            range: Range,
        ) (merkle.Error || Allocator.Error)!Proof {
            const leaves = try merkle.location_from_position(F, self.size);
            const blueprint = try proof_module.Blueprint(F).init(
                leaves,
                self.inactive_peaks,
                self.bagging,
                range,
            );
            const count = blueprint.digest_count();
            const digests = try gpa.alloc(Digest, count);
            errdefer gpa.free(digests);
            var index: usize = 0;
            const fold = blueprint.fold_prefix.slice();
            if (fold.len > 0) {
                var accumulator = self.fold_accumulator;
                for (fold[@min(self.fold_peak_count, fold.len)..]) |peak| {
                    const digest = try self.digest_at(peak.position);
                    accumulator = if (accumulator) |a| hasher.fold(&a, &digest) else digest;
                }
                // A sub-range's fold prefix holds at least the stored one's peaks, so a
                // stored accumulator or a folded peak always sets it.
                digests[index] = accumulator.?;
                index += 1;
            }
            for (blueprint.prefix_active_peaks.slice()) |peak| {
                digests[index] = try self.digest_at(peak.position);
                index += 1;
            }
            for (blueprint.after_peaks.slice()) |position| {
                digests[index] = try self.digest_at(position);
                index += 1;
            }
            if (blueprint.suffix_peaks.len > 0) {
                digests[index] = try self.suffix_digest(hasher, blueprint.suffix_peaks.slice());
                index += 1;
            }
            for (blueprint.siblings.slice()) |position| {
                digests[index] = try self.digest_at(position);
                index += 1;
            }
            assert(index == count);
            return .{ .leaves = leaves, .inactive_peaks = self.inactive_peaks, .digests = digests };
        }

        /// The backward-folded accumulator of `suffix_peaks`: from stored peaks alone, or the
        /// stored accumulator extended by the visible peaks in front of its hidden ones.
        fn suffix_digest(
            self: *const Self,
            hasher: anytype,
            suffix_peaks: []const u64,
        ) merkle.Error!Digest {
            assert(suffix_peaks.len > 0);
            const hidden = self.suffix_peaks.slice();
            var accumulator: Digest = undefined;
            var visible = suffix_peaks.len;
            if (hidden.len == 0) {
                visible -= 1;
                accumulator = try self.digest_at(suffix_peaks[visible]);
            } else {
                if (!std.mem.endsWith(u64, suffix_peaks, hidden)) return error.ElementPruned;
                accumulator = self.suffix_accumulator orelse return error.InvalidProof;
                visible -= hidden.len;
            }
            assert(visible < suffix_peaks.len);
            while (visible > 0) {
                visible -= 1;
                const digest = try self.digest_at(suffix_peaks[visible]);
                accumulator = hasher.fold(&digest, &accumulator);
            }
            return accumulator;
        }

        /// A multi-element proof of `locations` (strictly increasing). Peaks the source proof
        /// did not keep individually (fold-prefix peaks, and backward-fold suffix peaks, see
        /// `suffix_peak_positions`) come from `peaks`; the last entry for a position wins.
        /// A needed suffix peak missing from `peaks` fails with `CompressedDigest`.
        pub fn multi_proof(
            self: *const Self,
            gpa: Allocator,
            locations: []const u64,
            peaks: []const NodeDigest,
        ) (merkle.Error || Allocator.Error)!Proof {
            const leaves = try merkle.location_from_position(F, self.size);
            const positions = try proof_module.multi_proof_positions(F, gpa, leaves, locations);
            defer gpa.free(positions);
            const digests = try gpa.alloc(Digest, positions.len);
            errdefer gpa.free(digests);
            for (positions, digests) |position, *digest| {
                digest.* = self.digests.get(position) orelse
                    supplied(peaks, position) orelse {
                    const hidden = self.suffix_peaks.slice();
                    if (std.mem.indexOfScalar(u64, hidden, position) != null) {
                        return error.CompressedDigest;
                    }
                    return error.ElementPruned;
                };
            }
            assert(digests.len == positions.len);
            return .{ .leaves = leaves, .inactive_peaks = self.inactive_peaks, .digests = digests };
        }

        fn supplied(peaks: []const NodeDigest, position: u64) ?Digest {
            var index = peaks.len;
            while (index > 0) {
                index -= 1;
                if (peaks[index].position == position) return peaks[index].digest;
            }
            return null;
        }

        /// Suffix peaks collapsed into the source proof's backward-fold accumulator; empty for
        /// forward-folded proofs and for ranges with no active suffix.
        pub fn suffix_peak_positions(self: *const Self) []const u64 {
            return self.suffix_peaks.slice();
        }
    };
}
