//! Inclusion proofs for Merkle-family structures (MMR, MMB): planning, generation, and
//! verification of single-element, range, and multi-element proofs.
//!
//! Port of commonware's `storage/src/merkle/proof.rs`. The family supplies the topology; the
//! logic here is shared. Commonware walks subtrees recursively; zigware walks them over
//! explicit stacks whose capacity follows from the 64-peak, 63-level bound of a u64 structure.
//!
//! Wire format (byte-identical to commonware):
//! `leaves (varint u64) || inactive_peaks (varint u64) || count (varint u32) || digests`.
//!
//! A range proof's digests are, in order: the folded prefix accumulator (if any peaks before
//! the range fold), the individual prefix peaks, the individual after-peaks, the suffix
//! accumulator (backward bagging only), and the path siblings in left-first DFS order.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("mod.zig");
const hasher_module = @import("hasher.zig");

const BoundedList = merkle.BoundedList;
const Range = merkle.Range;

const max_peaks = merkle.max_pinned_nodes;
/// A contiguous range has at most two partial nodes per level, so at most two siblings per
/// level of a 63-level structure.
const max_siblings = 2 * max_peaks;
/// Explicit DFS stacks hold at most a few pending items per level.
const stack_capacity = 4 * max_peaks;

/// Upper bound on the positions a range plan reads (`RangePlan.positions`).
pub const max_plan_positions = max_peaks + max_siblings;

/// Upper bound on the digests in a single-element proof of any family.
pub const max_proof_digests_per_element = 122;

/// Why a range proof failed to reconstruct a root.
pub const ReconstructionError = error{
    InvalidProof,
    MissingDigests,
    ExtraDigests,
    InvalidStartLoc,
    InvalidEndLoc,
    MissingElements,
    InvalidSize,
};

/// A perfect subtree: its root position, height, and leftmost leaf.
pub const Subtree = struct {
    position: u64,
    height: u32,
    leaf_start: u64,

    pub fn leaf_end(self: Subtree) u64 {
        assert(self.height <= 62);
        return self.leaf_start + (@as(u64, 1) << @intCast(self.height));
    }

    fn is_before(self: Subtree, range: Range) bool {
        return self.leaf_end() <= range.start;
    }

    fn is_outside(self: Subtree, range: Range) bool {
        return self.is_before(range) or self.leaf_start >= range.end;
    }

    fn is_inside(self: Subtree, range: Range) bool {
        return self.leaf_start >= range.start and self.leaf_end() <= range.end;
    }

    fn children(self: Subtree, comptime F: type) [2]Subtree {
        assert(self.height > 0);
        const positions = F.children(self.position, self.height);
        const height = self.height - 1;
        const middle = self.leaf_start + (@as(u64, 1) << @intCast(height));
        assert(positions.left < positions.right and positions.right < self.position);
        return .{
            .{ .position = positions.left, .height = height, .leaf_start = self.leaf_start },
            .{ .position = positions.right, .height = height, .leaf_start = middle },
        };
    }
};

/// The peaks of a structure of `size` nodes as subtrees, oldest first.
pub fn peak_subtrees(comptime F: type, size: u64) BoundedList(Subtree, max_peaks) {
    var out: BoundedList(Subtree, max_peaks) = .{};
    var leaf_start: u64 = 0;
    var peaks = F.peaks(size);
    while (peaks.next()) |peak| {
        const subtree: Subtree = .{
            .position = peak.position,
            .height = peak.height,
            .leaf_start = leaf_start,
        };
        out.append(subtree);
        leaf_start = subtree.leaf_end();
    }
    return out;
}

/// Appends, in left-first DFS order, the roots of the maximal subtrees of `peak` that lie
/// outside `range`: the siblings a verifier needs to rebuild `peak` from the range.
fn collect_siblings(
    comptime F: type,
    peak: Subtree,
    range: Range,
    out: *BoundedList(u64, max_siblings),
) void {
    var stack: BoundedList(Subtree, stack_capacity) = .{};
    stack.append(peak);
    while (stack.pop()) |node| {
        if (node.is_outside(range)) {
            out.append(node.position);
            continue;
        }
        if (node.is_inside(range)) continue;
        assert(node.height > 0); // A partial node is never a leaf.
        const kids = node.children(F);
        stack.append(kids[1]);
        stack.append(kids[0]);
    }
}

/// Appends the subtrees of `peak` that end at or before `range.start` along the path to it.
fn collect_prefix_siblings(
    comptime F: type,
    peak: Subtree,
    range: Range,
    out: *BoundedList(Subtree, max_peaks),
) void {
    var stack: BoundedList(Subtree, stack_capacity) = .{};
    stack.append(peak);
    while (stack.pop()) |node| {
        if (node.is_before(range)) {
            out.append(node);
            continue;
        }
        if (node.leaf_start >= range.start or node.height == 0) continue;
        const kids = node.children(F);
        stack.append(kids[1]);
        stack.append(kids[0]);
    }
}

/// The nodes a range proof reads, split by peak: peaks wholly before or after the range enter
/// the proof whole; peaks overlapping it are rebuilt from the elements and path siblings.
pub fn RangePlan(comptime F: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();

        leaves: u64,
        range: Range,
        before: BoundedList(Subtree, max_peaks) = .{},
        overlapping: BoundedList(Subtree, max_peaks) = .{},
        after: BoundedList(u64, max_peaks) = .{},
        siblings: BoundedList(u64, max_siblings) = .{},

        /// Plans a proof of `range` in a structure of `leaves` leaves.
        pub fn init(leaves: u64, range: Range) merkle.Error!Self {
            if (range.start >= range.end) return error.Empty;
            if (range.end > leaves) return error.RangeOutOfBounds;
            const size = try merkle.position_from_location(F, leaves);
            var plan: Self = .{ .leaves = leaves, .range = range };
            const peaks = peak_subtrees(F, size);
            for (peaks.slice()) |peak| {
                if (peak.is_before(range)) {
                    plan.before.append(peak);
                } else if (peak.leaf_start >= range.end) {
                    plan.after.append(peak.position);
                } else {
                    plan.overlapping.append(peak);
                }
            }
            assert(plan.overlapping.len > 0); // At least one peak holds range elements.
            for (plan.overlapping.slice()) |peak| {
                collect_siblings(F, peak, range, &plan.siblings);
            }
            return plan;
        }

        /// Plans a proof of the single element at `location` (commonware's `ElementPlan`).
        pub fn init_element(leaves: u64, location: u64) merkle.Error!Self {
            const end = merkle.checked_add(location, 1, F.max_leaves) orelse
                return error.LocationOverflow;
            return init(leaves, .{ .start = location, .end = end });
        }

        /// The positions the proof reads, strictly increasing.
        pub fn positions(self: *const Self) BoundedList(u64, max_peaks + max_siblings) {
            var out: BoundedList(u64, max_peaks + max_siblings) = .{};
            for (self.before.slice()) |peak| out.append(peak.position);
            for (self.after.slice()) |position| out.append(position);
            for (self.siblings.slice()) |position| out.append(position);
            std.mem.sort(u64, out.slice_mut(), {}, std.sort.asc(u64));
            return out;
        }

        /// Builds the proof, reading nodes from `source.get_node(position) ?Digest`.
        pub fn build(
            self: *const Self,
            gpa: Allocator,
            hasher: anytype,
            inactive_peaks: usize,
            source: anytype,
        ) (merkle.Error || Allocator.Error)!Proof(F, @TypeOf(hasher.*).Digest) {
            const bagging = hasher.root_bagging();
            const blueprint = try Blueprint(F).from_plan(self, inactive_peaks, bagging);
            return blueprint.build_proof(gpa, hasher, inactive_peaks, source);
        }
    };
}

/// A range plan arranged for a bagging policy and inactive-peak boundary: which peaks fold
/// into accumulators and which enter the proof individually.
pub fn Blueprint(comptime F: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();

        leaves: u64,
        range: Range,
        fold_prefix: BoundedList(Subtree, max_peaks),
        prefix_active_peaks: BoundedList(Subtree, max_peaks),
        after_peaks: BoundedList(u64, max_peaks),
        suffix_peaks: BoundedList(u64, max_peaks),
        range_peaks: BoundedList(Subtree, max_peaks),
        siblings: BoundedList(u64, max_siblings),

        pub fn init(
            leaves: u64,
            inactive_peaks: usize,
            bagging: merkle.Bagging,
            range: Range,
        ) merkle.Error!Self {
            const plan = try RangePlan(F).init(leaves, range);
            return from_plan(&plan, inactive_peaks, bagging);
        }

        pub fn from_plan(
            plan: *const RangePlan(F),
            inactive_peaks: usize,
            bagging: merkle.Bagging,
        ) merkle.Error!Self {
            const before = plan.before.slice();
            const after = plan.after.slice();
            // The inactive boundary indexes the tree's global peak order; it may point into or
            // past the range, and the final root comparison rejects non-canonical proofs.
            if (inactive_peaks > before.len + plan.overlapping.len + after.len) {
                return error.InvalidProof;
            }
            // Before-peaks fold into one accumulator when inactive or forward-bagged; active
            // ones under backward bagging fold only after the range peaks, so stay individual.
            const fold_count = switch (bagging) {
                .forward_fold => before.len,
                .backward_fold => @min(inactive_peaks, before.len),
            };
            // Backward bagging collapses the active after-peaks into one suffix accumulator.
            const first_after = before.len + plan.overlapping.len;
            const individual_count = switch (bagging) {
                .forward_fold => after.len,
                .backward_fold => @min(inactive_peaks -| first_after, after.len),
            };
            return .{
                .leaves = plan.leaves,
                .range = plan.range,
                .fold_prefix = .from_slice(before[0..fold_count]),
                .prefix_active_peaks = .from_slice(before[fold_count..]),
                .after_peaks = .from_slice(after[0..individual_count]),
                .suffix_peaks = .from_slice(after[individual_count..]),
                .range_peaks = plan.overlapping,
                .siblings = plan.siblings,
            };
        }

        /// The number of digests a proof built from this blueprint holds.
        pub fn digest_count(self: *const Self) usize {
            return @as(usize, @intFromBool(self.fold_prefix.len > 0)) +
                self.prefix_active_peaks.len + self.after_peaks.len +
                @intFromBool(self.suffix_peaks.len > 0) + self.siblings.len;
        }

        /// Siblings in the first range peak that lie wholly before the range.
        pub fn prefix_siblings(self: *const Self) BoundedList(Subtree, max_peaks) {
            var out: BoundedList(Subtree, max_peaks) = .{};
            if (self.range_peaks.len > 0) {
                collect_prefix_siblings(F, self.range_peaks.buffer[0], self.range, &out);
            }
            return out;
        }

        pub fn Layout(comptime Digest: type) type {
            return struct {
                fold_prefix: ?*const Digest,
                prefix_active_peaks: []const Digest,
                after_peaks: []const Digest,
                suffix_accumulator: ?*const Digest,
                siblings: []const Digest,
            };
        }

        /// Splits a proof's digests into their roles, rejecting a wrong count.
        pub fn split_proof_digests(
            self: *const Self,
            comptime Digest: type,
            digests: []const Digest,
        ) ReconstructionError!Layout(Digest) {
            const fold_count: usize = @intFromBool(self.fold_prefix.len > 0);
            const prefix_start = fold_count;
            const after_start = prefix_start + self.prefix_active_peaks.len;
            const suffix_start = after_start + self.after_peaks.len;
            const suffix_end = suffix_start + @intFromBool(self.suffix_peaks.len > 0);
            const required = suffix_end + self.siblings.len;
            assert(required == self.digest_count());
            if (digests.len < required) return error.MissingDigests;
            if (digests.len > required) return error.ExtraDigests;
            return .{
                .fold_prefix = if (fold_count > 0) &digests[0] else null,
                .prefix_active_peaks = digests[prefix_start..after_start],
                .after_peaks = digests[after_start..suffix_start],
                .suffix_accumulator = if (suffix_end > suffix_start)
                    &digests[suffix_start]
                else
                    null,
                .siblings = digests[suffix_end..],
            };
        }

        /// The inactive-peak count once the before-peaks have folded into one accumulator.
        pub fn inactive_peaks_after_prefix_fold(self: *const Self, inactive_peaks: usize) usize {
            if (self.fold_prefix.len == 0) return inactive_peaks;
            return (inactive_peaks -| self.fold_prefix.len) + 1;
        }

        /// Builds the proof, reading nodes from `source.get_node(position) ?Digest`. Fails with
        /// `ElementPruned` at the first node the source lacks.
        pub fn build_proof(
            self: *const Self,
            gpa: Allocator,
            hasher: anytype,
            inactive_peaks: usize,
            source: anytype,
        ) (merkle.Error || Allocator.Error)!Proof(F, @TypeOf(hasher.*).Digest) {
            const count = self.digest_count();
            const digests = try gpa.alloc(@TypeOf(hasher.*).Digest, count);
            errdefer gpa.free(digests);
            var index: usize = 0;
            const fold = self.fold_prefix.slice();
            if (fold.len > 0) {
                var accumulator = source.get_node(fold[0].position) orelse
                    return error.ElementPruned;
                for (fold[1..]) |peak| {
                    const digest = source.get_node(peak.position) orelse return error.ElementPruned;
                    accumulator = hasher.fold(&accumulator, &digest);
                }
                digests[index] = accumulator;
                index += 1;
            }
            for (self.prefix_active_peaks.slice()) |peak| {
                digests[index] = source.get_node(peak.position) orelse return error.ElementPruned;
                index += 1;
            }
            for (self.after_peaks.slice()) |position| {
                digests[index] = source.get_node(position) orelse return error.ElementPruned;
                index += 1;
            }
            const suffix = self.suffix_peaks.slice();
            if (suffix.len > 0) {
                var accumulator = source.get_node(suffix[suffix.len - 1]) orelse
                    return error.ElementPruned;
                var cursor = suffix.len - 1;
                while (cursor > 0) {
                    cursor -= 1;
                    const digest = source.get_node(suffix[cursor]) orelse
                        return error.ElementPruned;
                    accumulator = hasher.fold(&digest, &accumulator);
                }
                digests[index] = accumulator;
                index += 1;
            }
            for (self.siblings.slice()) |position| {
                digests[index] = source.get_node(position) orelse return error.ElementPruned;
                index += 1;
            }
            assert(index == count);
            return .{ .leaves = self.leaves, .inactive_peaks = inactive_peaks, .digests = digests };
        }
    };
}

/// The element bytes of `element`, a pointer to a byte slice, a byte array, or a digest.
fn element_bytes(element: anytype) []const u8 {
    const T = @typeInfo(@TypeOf(element)).pointer.child;
    if (T == []const u8 or T == []u8) return element.*;
    if (@typeInfo(T) == .array) return element;
    return &element.bytes;
}

/// Number of `items` (sorted ascending) that are less than `bound`.
fn partition_point(items: []const u64, bound: u64) usize {
    var low: usize = 0;
    var high: usize = items.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (items[middle] < bound) low = middle + 1 else high = middle;
    }
    assert(low == items.len or items[low] >= bound);
    return low;
}

fn check_bounds(comptime F: type, leaves: u64, location: u64) merkle.Error!void {
    const end = merkle.checked_add(location, 1, F.max_leaves) orelse return error.LocationOverflow;
    if (end > leaves) return error.RangeOutOfBounds;
}

/// The positions a multi-element proof of `locations` (strictly increasing) holds, sorted:
/// every peak that does not hold all the locations, plus the siblings along each path. The
/// first invalid location in input order decides the error. Caller frees the result.
pub fn multi_proof_positions(
    comptime F: type,
    gpa: Allocator,
    leaves: u64,
    locations: []const u64,
) (merkle.Error || Allocator.Error)![]u64 {
    if (locations.len == 0) return error.Empty;
    try check_bounds(F, leaves, locations[0]);
    const size = try merkle.position_from_location(F, leaves);
    for (locations[1..], locations[0 .. locations.len - 1]) |location, previous| {
        if (location == previous) return error.DuplicateLocation;
        if (location < previous) return error.UnsortedLocation;
        try check_bounds(F, leaves, location);
    }
    var positions: std.ArrayList(u64) = .empty;
    errdefer positions.deinit(gpa);
    const peaks = peak_subtrees(F, size);
    var low: usize = 0;
    for (peaks.slice()) |peak| {
        const high = low + partition_point(locations[low..], peak.leaf_end());
        if (high > low) try collect_multi_siblings(F, gpa, peak, locations[low..high], &positions);
        if (high - low != locations.len) try positions.append(gpa, peak.position);
        low = high;
    }
    assert(low == locations.len);
    // An MMB can append a parent after leaves to its right, so sort.
    std.mem.sort(u64, positions.items, {}, std.sort.asc(u64));
    return positions.toOwnedSlice(gpa);
}

fn collect_multi_siblings(
    comptime F: type,
    gpa: Allocator,
    peak: Subtree,
    locations: []const u64,
    out: *std.ArrayList(u64),
) Allocator.Error!void {
    const Item = struct { node: Subtree, low: usize, high: usize };
    var stack: BoundedList(Item, stack_capacity) = .{};
    stack.append(.{ .node = peak, .low = 0, .high = locations.len });
    while (stack.pop()) |item| {
        if (item.node.height == 0) continue;
        const kids = item.node.children(F);
        const middle = item.low +
            partition_point(locations[item.low..item.high], kids[1].leaf_start);
        if (item.high > middle) {
            try out.append(gpa, kids[0].position);
            stack.append(.{ .node = kids[1], .low = middle, .high = item.high });
        }
        if (middle > item.low) {
            try out.append(gpa, kids[1].position);
            stack.append(.{ .node = kids[0], .low = item.low, .high = middle });
        }
    }
}

/// An inclusion proof for a range of elements (or a multi-element selection).
pub fn Proof(comptime F: type, comptime Digest: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();

        /// Leaf count of the structure the proof is for.
        leaves: u64 = 0,
        /// The committed inactive-peak boundary.
        inactive_peaks: usize = 0,
        /// The proof's digests; owned (free with `deinit`).
        digests: []Digest = &.{},

        /// codec: the maximum digest count to accept.
        pub const Cfg = usize;

        pub const NodeDigest = struct { position: u64, digest: Digest };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.digests);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return .{
                .leaves = self.leaves,
                .inactive_peaks = self.inactive_peaks,
                .digests = try gpa.dupe(Digest, self.digests),
            };
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            if (a.leaves != b.leaves or a.inactive_peaks != b.inactive_peaks) return false;
            if (a.digests.len != b.digests.len) return false;
            for (a.digests, b.digests) |x, y| if (!x.eql(y)) return false;
            return true;
        }

        /// The largest encoding of a proof with `digests` digests.
        pub fn max_encode_size(digests: usize) usize {
            return codec.util.max_items_size(digests, Digest.fixed_size) +
                2 * codec.varint.max_size(u64);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.varint.write(u64, self.leaves, writer);
            codec.varint.write(u64, self.inactive_peaks, writer);
            codec.write([]const Digest, self.digests, writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.varint.size(u64, self.leaves) +
                codec.varint.size(u64, self.inactive_peaks) +
                codec.encode_size([]const Digest, self.digests);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max_digests: usize) codec.Error!Self {
            const leaves = try codec.varint.read(u64, reader);
            if (leaves > F.max_leaves) {
                return reader.invalid("Location", "value exceeds MAX_LEAVES");
            }
            const inactive = try codec.varint.read(u64, reader);
            const inactive_peaks = std.math.cast(usize, inactive) orelse
                return reader.invalid("Proof", "inactive_peaks exceeds usize");
            const range: codec.RangeCfg(usize) = .to_inclusive(max_digests);
            const digests = try codec.read_range([]const Digest, gpa, reader, range);
            // The decoder allocated `digests` for us, so the proof owns it mutably.
            const owned: []Digest = @constCast(digests);
            return .{ .leaves = leaves, .inactive_peaks = inactive_peaks, .digests = owned };
        }

        /// Whether the committed boundary is the canonical one for `inactivity_floor`.
        pub fn matches_canonical_inactive_peaks(
            self: *const Self,
            leaves: u64,
            inactivity_floor: u64,
        ) bool {
            return self.inactive_peaks == merkle.inactive_peaks(F, leaves, inactivity_floor);
        }

        pub fn verify_element_inclusion(
            self: *const Self,
            hasher: anytype,
            location: u64,
            element: []const u8,
            root: *const Digest,
        ) bool {
            return self.verify_range_inclusion(hasher, location, &[_][]const u8{element}, root);
        }

        /// Whether `elements` sit at `start..start + elements.len` under `root`.
        pub fn verify_range_inclusion(
            self: *const Self,
            hasher: anytype,
            start: u64,
            elements: anytype,
            root: *const Digest,
        ) bool {
            const reconstructed = self.reconstruct_root(hasher, start, elements) catch return false;
            return reconstructed.eql(root.*);
        }

        pub fn reconstruct_root(
            self: *const Self,
            hasher: anytype,
            start: u64,
            elements: anytype,
        ) ReconstructionError!Digest {
            const result = self.reconstruct_root_inner(hasher, start, elements, null);
            return result catch |err| switch (err) {
                error.OutOfMemory => unreachable, // No collector, so nothing allocates.
                else => |e| e,
            };
        }

        /// Verifies the range and appends every node digest it reconstructed or read to `out`.
        pub fn verify_range_inclusion_and_extract_digests(
            self: *const Self,
            gpa: Allocator,
            hasher: anytype,
            start: u64,
            elements: anytype,
            root: *const Digest,
            out: *std.ArrayList(NodeDigest),
        ) (merkle.Error || Allocator.Error)!void {
            const collector: Collector = .{ .gpa = gpa, .list = out };
            const result = self.reconstruct_root_inner(hasher, start, elements, collector);
            const reconstructed = result catch |err|
                switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.InvalidProof,
                };
            if (!reconstructed.eql(root.*)) return error.RootMismatch;
        }

        const Collector = struct { gpa: Allocator, list: *std.ArrayList(NodeDigest) };

        fn collect(collector: ?Collector, position: u64, digest: Digest) Allocator.Error!void {
            const c = collector orelse return;
            try c.list.append(c.gpa, .{ .position = position, .digest = digest });
        }

        fn reconstruct_empty(
            self: *const Self,
            hasher: anytype,
            start: u64,
        ) ReconstructionError!Digest {
            if (start != 0) return error.MissingElements;
            if (self.inactive_peaks != 0) return error.InvalidProof;
            if (self.leaves != 0) return error.MissingElements;
            if (self.digests.len != 0) return error.ExtraDigests;
            // Zero inactive peaks over zero peaks is always valid.
            return hasher_module.root(F, hasher, 0, 0, &.{}) catch unreachable;
        }

        fn reconstruct_root_inner(
            self: *const Self,
            hasher: anytype,
            start: u64,
            elements: anytype,
            collector: ?Collector,
        ) (ReconstructionError || Allocator.Error)!Digest {
            if (elements.len == 0) return self.reconstruct_empty(hasher, start);
            if (start >= F.max_leaves) return error.InvalidStartLoc;
            const end = merkle.checked_add(start, elements.len, F.max_leaves) orelse
                return error.InvalidEndLoc;
            if (end > self.leaves) return error.InvalidEndLoc;
            const range: Range = .{ .start = start, .end = end };
            const bagging = hasher.root_bagging();
            const inactive = self.inactive_peaks;
            const blueprint = Blueprint(F).init(self.leaves, inactive, bagging, range) catch
                return error.InvalidSize;
            const layout = try blueprint.split_proof_digests(Digest, self.digests);

            var peaks: BoundedList(Digest, max_peaks) = .{};
            if (layout.fold_prefix) |digest| peaks.append(digest.*);
            for (blueprint.prefix_active_peaks.slice(), layout.prefix_active_peaks) |peak, digest| {
                peaks.append(digest);
                try collect(collector, peak.position, digest);
            }
            var walk: RangeWalk = .{ .range = range, .siblings = layout.siblings };
            for (blueprint.range_peaks.slice()) |peak| {
                const digest = try walk.reconstruct(hasher, peak, elements, collector);
                try collect(collector, peak.position, digest);
                peaks.append(digest);
            }
            for (blueprint.after_peaks.slice(), layout.after_peaks) |position, digest| {
                try collect(collector, position, digest);
                peaks.append(digest);
            }
            if (layout.suffix_accumulator) |digest| peaks.append(digest.*);
            if (walk.element_index != elements.len) return error.ExtraDigests;
            if (walk.sibling_index != layout.siblings.len) return error.ExtraDigests;
            const to_fold = blueprint.inactive_peaks_after_prefix_fold(self.inactive_peaks);
            return hasher_module.root_with_folded_peaks(
                F,
                hasher,
                self.leaves,
                to_fold,
                self.inactive_peaks,
                peaks.slice(),
            ) orelse error.InvalidProof;
        }

        /// Rebuilds range peaks from the elements and the path siblings, consuming both in
        /// the left-first DFS order the prover emitted them.
        const RangeWalk = struct {
            range: Range,
            siblings: []const Digest,
            sibling_index: usize = 0,
            element_index: usize = 0,

            const Work = union(enum) { visit: Subtree, combine: Subtree };

            fn reconstruct(
                walk: *RangeWalk,
                hasher: anytype,
                peak: Subtree,
                elements: anytype,
                collector: ?Collector,
            ) (ReconstructionError || Allocator.Error)!Digest {
                var work: BoundedList(Work, stack_capacity) = .{};
                var values: BoundedList(Digest, 2 * max_peaks) = .{};
                work.append(.{ .visit = peak });
                while (work.pop()) |item| {
                    switch (item) {
                        .visit => |node| {
                            const digest = try walk.visit(hasher, node, elements, &work);
                            values.append(digest orelse continue);
                        },
                        .combine => |node| {
                            const right = values.pop().?;
                            const left = values.pop().?;
                            const kids = node.children(F);
                            try collect(collector, kids[0].position, left);
                            try collect(collector, kids[1].position, right);
                            values.append(hasher.node_digest(node.position, &left, &right));
                        },
                    }
                }
                assert(values.len == 1);
                return values.buffer[0];
            }

            /// The digest of `node` when known now, or null after scheduling its children.
            fn visit(
                walk: *RangeWalk,
                hasher: anytype,
                node: Subtree,
                elements: anytype,
                work: *BoundedList(Work, stack_capacity),
            ) ReconstructionError!?Digest {
                if (node.is_outside(walk.range)) {
                    if (walk.sibling_index >= walk.siblings.len) return error.MissingDigests;
                    walk.sibling_index += 1;
                    return walk.siblings[walk.sibling_index - 1];
                }
                if (node.height == 0) {
                    if (walk.element_index >= elements.len) return error.MissingElements;
                    walk.element_index += 1;
                    const element = element_bytes(&elements[walk.element_index - 1]);
                    return hasher.leaf_digest(node.position, element);
                }
                const kids = node.children(F);
                work.append(.{ .combine = node });
                work.append(.{ .visit = kids[1] });
                work.append(.{ .visit = kids[0] });
                return null;
            }
        };

        /// Whether `elements[i]` sits at `locations[i]` for every `i` under `root`.
        /// `locations` must be strictly increasing.
        pub fn verify_multi_inclusion(
            self: *const Self,
            gpa: Allocator,
            hasher: anytype,
            locations: []const u64,
            elements: anytype,
            root: *const Digest,
        ) Allocator.Error!bool {
            if (locations.len != elements.len) return false;
            if (locations.len == 0) {
                if (self.digests.len != 0 or self.leaves != 0 or self.inactive_peaks != 0) {
                    return false;
                }
                const empty = hasher_module.root(F, hasher, 0, 0, &.{}) catch unreachable;
                return empty.eql(root.*);
            }
            const positions = multi_proof_positions(F, gpa, self.leaves, locations) catch |err|
                switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return false,
                };
            defer gpa.free(positions);
            if (positions.len != self.digests.len) return false;
            const multi: MultiWalk = .{ .positions = positions, .digests = self.digests };
            // Valid locations imply a valid leaf count.
            const size = merkle.position_from_location(F, self.leaves) catch unreachable;
            var peaks: BoundedList(Digest, max_peaks) = .{};
            const subtrees = peak_subtrees(F, size);
            var low: usize = 0;
            for (subtrees.slice()) |peak| {
                const high = low + partition_point(locations[low..], peak.leaf_end());
                const digest = if (high == low)
                    multi.witness(peak.position)
                else
                    multi.reconstruct(hasher, peak, locations, elements, .{
                        .low = low,
                        .high = high,
                        .check = high - low != locations.len,
                    });
                peaks.append(digest orelse return false);
                low = high;
            }
            const leaves = self.leaves;
            const inactive = self.inactive_peaks;
            const result = hasher_module.root(F, hasher, leaves, inactive, peaks.slice());
            const reconstructed = result catch return false;
            return reconstructed.eql(root.*);
        }

        /// Rebuilds peaks holding selected elements. A child's digest comes from the proof
        /// if it holds no selected elements and is computed otherwise; when both children
        /// hold selected elements, their digests are also in the proof and must match.
        const MultiWalk = struct {
            positions: []const u64,
            digests: []const Digest,

            const Span = struct { low: usize, high: usize, check: bool };
            const Visit = struct { node: Subtree, span: Span };
            const Combine = struct { node: Subtree, check: bool };
            const Work = union(enum) { visit: Visit, combine: Combine };

            fn witness(multi: *const MultiWalk, position: u64) ?Digest {
                const index = partition_point(multi.positions, position);
                if (index == multi.positions.len or multi.positions[index] != position) return null;
                return multi.digests[index];
            }

            fn matches(multi: *const MultiWalk, check: bool, position: u64, digest: Digest) bool {
                if (!check) return true;
                const expected = multi.witness(position) orelse return false;
                return expected.eql(digest);
            }

            fn reconstruct(
                multi: *const MultiWalk,
                hasher: anytype,
                peak: Subtree,
                locations: []const u64,
                elements: anytype,
                span: Span,
            ) ?Digest {
                var work: BoundedList(Work, stack_capacity) = .{};
                var values: BoundedList(Digest, 2 * max_peaks) = .{};
                work.append(.{ .visit = .{ .node = peak, .span = span } });
                while (work.pop()) |item| {
                    switch (item) {
                        .visit => |v| {
                            const digest = multi.visit(hasher, v, locations, elements, &work) orelse
                                return null;
                            if (digest) |d| values.append(d);
                        },
                        .combine => |c| {
                            const right = values.pop().?;
                            const left = values.pop().?;
                            const digest = hasher.node_digest(c.node.position, &left, &right);
                            if (!multi.matches(c.check, c.node.position, digest)) return null;
                            values.append(digest);
                        },
                    }
                }
                assert(values.len == 1);
                return values.buffer[0];
            }

            /// Null when verification fails; `.{null}` after scheduling children.
            fn visit(
                multi: *const MultiWalk,
                hasher: anytype,
                v: Visit,
                locations: []const u64,
                elements: anytype,
                work: *BoundedList(Work, stack_capacity),
            ) ??Digest {
                const span = v.span;
                if (span.low == span.high) {
                    const digest = multi.witness(v.node.position) orelse return null;
                    return digest;
                }
                if (v.node.height == 0) {
                    if (span.high - span.low != 1) return null;
                    const element = element_bytes(&elements[span.low]);
                    const digest = hasher.leaf_digest(v.node.position, element);
                    if (!multi.matches(span.check, v.node.position, digest)) return null;
                    return digest;
                }
                const kids = v.node.children(F);
                const middle = span.low +
                    partition_point(locations[span.low..span.high], kids[1].leaf_start);
                work.append(.{ .combine = .{ .node = v.node, .check = span.check } });
                work.append(.{ .visit = .{ .node = kids[1], .span = .{
                    .low = middle,
                    .high = span.high,
                    .check = middle > span.low,
                } } });
                work.append(.{ .visit = .{ .node = kids[0], .span = .{
                    .low = span.low,
                    .high = middle,
                    .check = span.high > middle,
                } } });
                return @as(?Digest, null);
            }
        };

        /// Verifies the range and that `pinned` are exactly the nodes a structure pruned to
        /// `start` keeps (`merkle.nodes_to_pin`), as a sync target needs.
        pub fn verify_range_inclusion_with_pinned_nodes(
            self: *const Self,
            gpa: Allocator,
            hasher: anytype,
            start: u64,
            elements: anytype,
            pinned: []const Digest,
            root: *const Digest,
        ) Allocator.Error!bool {
            var collected: std.ArrayList(NodeDigest) = .empty;
            defer collected.deinit(gpa);
            const verified = self.verify_range_inclusion_and_extract_digests(
                gpa,
                hasher,
                start,
                elements,
                root,
                &collected,
            );
            verified catch |err|
                switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return false,
                };
            if (elements.len == 0) return pinned.len == 0;
            if (start > F.max_leaves or start > self.leaves) return false;
            const end = merkle.checked_add(start, elements.len, F.max_leaves) orelse return false;
            const range: Range = .{ .start = start, .end = end };
            const bagging = hasher.root_bagging();
            const inactive = self.inactive_peaks;
            const blueprint = Blueprint(F).init(self.leaves, inactive, bagging, range) catch
                return false;
            var pins = Pins.init(start, pinned) orelse return false;
            std.mem.sort(NodeDigest, collected.items, {}, node_digest_less_than);
            if (!self.check_fold_prefix(hasher, &blueprint, &pins)) return false;
            for (blueprint.prefix_active_peaks.slice()) |peak| {
                if (!pins.matches_extracted(hasher, peak, collected.items)) return false;
            }
            const prefix = blueprint.prefix_siblings();
            for (prefix.slice()) |sibling| {
                if (!pins.matches_extracted(hasher, sibling, collected.items)) return false;
            }
            // Every pin must have been consumed by one of the reconstructions above.
            return pins.all_used();
        }

        fn node_digest_less_than(_: void, a: NodeDigest, b: NodeDigest) bool {
            return a.position < b.position;
        }

        /// Fold-prefix peaks of the larger tree may have merged several pins: rebuild each
        /// from the pins and compare the folded accumulator with the proof's.
        fn check_fold_prefix(
            self: *const Self,
            hasher: anytype,
            blueprint: anytype,
            pins: *Pins,
        ) bool {
            const fold = blueprint.fold_prefix.slice();
            if (fold.len == 0) return true;
            if (self.digests.len == 0) return false;
            var accumulator = pins.reconstruct(hasher, fold[0]) orelse return false;
            for (fold[1..]) |peak| {
                const digest = pins.reconstruct(hasher, peak) orelse return false;
                accumulator = hasher.fold(&accumulator, &digest);
            }
            return accumulator.eql(self.digests[0]);
        }

        /// The pinned nodes for a pruning boundary, each usable once.
        const Pins = struct {
            positions: [max_peaks]u64,
            digests: [max_peaks]Digest,
            used: [max_peaks]bool,
            count: usize,

            fn init(prune_location: u64, pinned: []const Digest) ?Pins {
                var pins: Pins = undefined;
                const positions = merkle.nodes_to_pin(F, prune_location, &pins.positions);
                if (positions.len != pinned.len) return null;
                pins.count = positions.len;
                @memcpy(pins.digests[0..pinned.len], pinned);
                @memset(pins.used[0..pinned.len], false);
                return pins;
            }

            fn take(pins: *Pins, position: u64) ?Digest {
                for (pins.positions[0..pins.count], 0..) |pinned, index| {
                    if (pinned != position or pins.used[index]) continue;
                    pins.used[index] = true;
                    return pins.digests[index];
                }
                return null;
            }

            fn all_used(pins: *const Pins) bool {
                for (pins.used[0..pins.count]) |used| if (!used) return false;
                return true;
            }

            /// The digest of `subtree` hashed up from pins, consuming them; null if a leaf
            /// under it has no pin.
            fn reconstruct(pins: *Pins, hasher: anytype, subtree: Subtree) ?Digest {
                const Work = union(enum) { visit: Subtree, combine: Subtree };
                var work: BoundedList(Work, stack_capacity) = .{};
                var values: BoundedList(Digest, 2 * max_peaks) = .{};
                work.append(.{ .visit = subtree });
                while (work.pop()) |item| switch (item) {
                    .visit => |node| {
                        if (pins.take(node.position)) |digest| {
                            values.append(digest);
                            continue;
                        }
                        if (node.height == 0) return null;
                        const kids = node.children(F);
                        work.append(.{ .combine = node });
                        work.append(.{ .visit = kids[1] });
                        work.append(.{ .visit = kids[0] });
                    },
                    .combine => |node| {
                        const right = values.pop().?;
                        const left = values.pop().?;
                        values.append(hasher.node_digest(node.position, &left, &right));
                    },
                };
                assert(values.len == 1);
                return values.buffer[0];
            }

            fn matches_extracted(
                pins: *Pins,
                hasher: anytype,
                subtree: Subtree,
                extracted: []const NodeDigest,
            ) bool {
                const expected = find(extracted, subtree.position) orelse return false;
                const digest = pins.reconstruct(hasher, subtree) orelse return false;
                return digest.eql(expected);
            }

            fn find(extracted: []const NodeDigest, position: u64) ?Digest {
                var low: usize = 0;
                var high: usize = extracted.len;
                while (low < high) {
                    const middle = low + (high - low) / 2;
                    if (extracted[middle].position < position) low = middle + 1 else high = middle;
                }
                if (low == extracted.len or extracted[low].position != position) return null;
                return extracted[low].digest;
            }
        };
    };
}
