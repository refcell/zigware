//! Stateless Binary Merkle Tree (BMT).
//!
//! Port of commonware's `storage/src/bmt`. The tree is built level by level. The first level
//! holds position-hashed leaf digests. Each further level hashes pairs of nodes from the level
//! below; when a level has an odd number of nodes, its last node is paired with itself. The
//! finalized root binds the leaf count, `root = hash(leaf_count || tree_root)`, so proofs that
//! claim different leaf counts cannot verify against the same root.
//!
//! For three leaves A, B, and C:
//!
//! ```text
//!     Level 2 (tree_root):  [hash(hash(hash(0,A),hash(1,B)),hash(hash(2,C),hash(2,C)))]
//!     Level 1:              [hash(hash(0,A),hash(1,B)),hash(hash(2,C),hash(2,C))]
//!     Level 0 (leaves):     [hash(0,A),hash(1,B),hash(2,C)]
//!     Finalized root:       hash(3 || tree_root)
//! ```
//!
//! A proof for one or more leaves holds the siblings needed to rebuild the root, ordered by
//! level and then by index within the level.
//!
//! Zig errors carry no payload: functions that commonware reports a position from take an
//! optional `*Diagnostic`, which receives that position.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");

/// The most sibling levels a proof can need: a tree has at most `u32::MAX` leaves.
pub const max_levels: usize = 32;

/// Levels in the largest tree, `levels_in_tree(u32::MAX)`.
const max_tree_levels: usize = max_levels + 1;

/// Caps reservations sized from untrusted counts; larger inputs grow as needed.
const max_initial_capacity: usize = 16 * 1024;

/// Errors from building, proving, and verifying (commonware's `bmt::Error`).
pub const Error = error{
    InvalidPosition,
    InvalidProof,
    NoLeaves,
    UnalignedProof,
    DuplicatePosition,
    UnsortedPosition,
};

/// The position an `InvalidPosition`, `DuplicatePosition`, or `UnsortedPosition` error names.
pub const Diagnostic = struct {
    position: u32 = 0,
};

fn fail(diagnostic: ?*Diagnostic, err: Error, position: u32) Error {
    if (diagnostic) |out| out.position = position;
    return err;
}

/// The number of levels in a tree with `leaf_count` leaves: one leaf has one level, two
/// leaves have two, three or four leaves have three.
pub fn levels_in_tree(leaf_count: u32) usize {
    const used: usize = 32 - @clz(leaf_count -| 1);
    assert(used <= max_levels);
    return used + 1;
}

fn be32(value: u32) [4]u8 {
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, value, .big);
    return out;
}

fn hash_leaf(comptime H: type, position: u32, leaf: *const H.Digest) H.Digest {
    const prefix = be32(position);
    return H.hash(&[_][]const u8{ &prefix, &leaf.bytes });
}

fn hash_node(comptime H: type, left: *const H.Digest, right: *const H.Digest) H.Digest {
    return H.hash(&[_][]const u8{ &left.bytes, &right.bytes });
}

fn hash_node_pair(
    comptime H: type,
    a: *const H.Digest,
    b: *const H.Digest,
    c: *const H.Digest,
    d: *const H.Digest,
) [2]H.Digest {
    return H.hash_pair(
        &[_][]const u8{ &a.bytes, &b.bytes },
        &[_][]const u8{ &c.bytes, &d.bytes },
        {},
    );
}

fn finalize_root(comptime H: type, leaf_count: u32, tree_root: *const H.Digest) H.Digest {
    const prefix = be32(leaf_count);
    return H.hash(&[_][]const u8{ &prefix, &tree_root.bytes });
}

/// Collects leaves and builds a `Tree` (commonware's `bmt::Builder`).
pub fn Builder(comptime H: type) type {
    cryptography.assert_hasher(H);
    return struct {
        const Self = @This();

        /// Position-hashed leaves added so far.
        leaves: std.ArrayList(H.Digest) = .empty,

        /// A builder with room for `leaves` leaves.
        pub fn init(gpa: Allocator, leaves: usize) Allocator.Error!Self {
            var self: Self = .{};
            try self.leaves.ensureTotalCapacityPrecise(gpa, leaves);
            assert(self.leaves.items.len == 0);
            return self;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.leaves.deinit(gpa);
            self.* = undefined;
        }

        /// Adds a leaf, hashed with its position, and returns that position. Asserts that
        /// the tree has fewer than `u32::MAX` leaves.
        pub fn add(self: *Self, gpa: Allocator, leaf: *const H.Digest) Allocator.Error!u32 {
            assert(self.leaves.items.len < std.math.maxInt(u32));
            const position: u32 = @intCast(self.leaves.items.len);
            try self.leaves.append(gpa, hash_leaf(H, position, leaf));
            assert(self.leaves.items.len == @as(usize, position) + 1);
            return position;
        }

        /// Builds the tree from the leaves added so far. A tree without leaves holds one
        /// placeholder node, and no leaf of it is provable. The builder stays valid.
        pub fn build(self: *const Self, gpa: Allocator) Allocator.Error!Tree(H.Digest) {
            return Tree(H.Digest).init(H, gpa, self.leaves.items);
        }
    };
}

/// A sibling's place in the tree: `level` 0 is the leaf level.
const Node = struct {
    level: usize,
    index: usize,
};

/// A built Binary Merkle Tree (commonware's `bmt::Tree`).
pub fn Tree(comptime D: type) type {
    return struct {
        const Self = @This();

        /// Whether the tree was built without leaves.
        empty: bool,
        /// Every level's digests, leaves first and the tree root last.
        nodes: []D,
        /// `starts[level]` is where `level` begins in `nodes`; `starts[levels]` is its length.
        starts: [max_tree_levels + 1]usize,
        levels: usize,
        /// `hash(leaf_count || tree_root)`.
        finalized: D,

        /// Builds the tree over position-hashed `leaves` with hasher `H`.
        pub fn init(comptime H: type, gpa: Allocator, leaves: []const D) Allocator.Error!Self {
            comptime assert(H.Digest == D);
            assert(leaves.len < std.math.maxInt(u32));
            const width: u32 = @intCast(@max(leaves.len, 1));
            var self: Self = .{
                .empty = leaves.len == 0,
                .nodes = &.{},
                .starts = undefined,
                .levels = levels_in_tree(width),
                .finalized = undefined,
            };
            var total: usize = 0;
            var size: usize = width;
            for (0..self.levels) |depth| {
                self.starts[depth] = total;
                total += size;
                size = std.math.divCeil(usize, size, 2) catch unreachable;
            }
            self.starts[self.levels] = total;
            self.nodes = try gpa.alloc(D, total);
            if (self.empty) {
                self.nodes[0] = H.hash(&.{});
            } else {
                @memcpy(self.nodes[0..leaves.len], leaves);
            }
            for (1..self.levels) |depth| {
                const above = self.nodes[self.starts[depth]..self.starts[depth + 1]];
                hash_level(H, self.level(depth - 1), above);
            }
            assert(self.level(self.levels - 1).len == 1);
            self.finalized = finalize_root(H, @intCast(leaves.len), &self.nodes[total - 1]);
            return self;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.nodes);
            self.* = undefined;
        }

        /// The finalized root, which binds the leaf count.
        pub fn root(self: *const Self) D {
            return self.finalized;
        }

        /// The digests of `index`, leaves at 0.
        pub fn level(self: *const Self, index: usize) []const D {
            assert(index < self.levels);
            return self.nodes[self.starts[index]..self.starts[index + 1]];
        }

        fn leaf_count(self: *const Self) u32 {
            assert(!self.empty);
            return @intCast(self.level(0).len);
        }

        /// The proof for the leaf at `position`: the other child of each parent on its path,
        /// equal to the single-element multi-proof.
        pub fn proof(
            self: *const Self,
            gpa: Allocator,
            position: u32,
            diagnostic: ?*Diagnostic,
        ) (Error || Allocator.Error)!Proof(D) {
            if (self.empty or position >= self.leaf_count()) {
                return fail(diagnostic, error.InvalidPosition, position);
            }
            var siblings: [max_levels]D = undefined;
            var count: usize = 0;
            var index: usize = position;
            for (0..self.levels - 1) |depth| {
                const nodes = self.level(depth);
                if ((index ^ 1) < nodes.len) {
                    siblings[count] = nodes[index ^ 1];
                    count += 1;
                }
                index /= 2;
            }
            assert(index == 0);
            return .{
                .leaf_count = self.leaf_count(),
                .siblings = try gpa.dupe(D, siblings[0..count]),
            };
        }

        /// The proof for the contiguous leaves `start..=end`: at most two siblings per level.
        /// The empty tree proves only `0..=0`, with an empty proof.
        pub fn range_proof(
            self: *const Self,
            gpa: Allocator,
            start: u32,
            end: u32,
            diagnostic: ?*Diagnostic,
        ) (Error || Allocator.Error)!Proof(D) {
            if (self.empty) {
                if (start == 0 and end == 0) return .{};
                return fail(diagnostic, error.InvalidPosition, start);
            }
            var nodes: [2 * max_levels]Node = undefined;
            const count = try range_siblings(self.leaf_count(), start, end, &nodes, diagnostic);
            const siblings = try gpa.alloc(D, count);
            for (nodes[0..count], siblings) |node, *sibling| {
                sibling.* = self.level(node.level)[node.index];
            }
            return .{ .leaf_count = self.leaf_count(), .siblings = siblings };
        }

        /// The proof for the leaves at `positions`, which must be strictly ascending and in
        /// range. Siblings shared by several paths appear once.
        pub fn multi_proof(
            self: *const Self,
            gpa: Allocator,
            positions: []const u32,
            diagnostic: ?*Diagnostic,
        ) (Error || Allocator.Error)!Proof(D) {
            if (positions.len == 0) return error.NoLeaves;
            if (self.empty) return fail(diagnostic, error.InvalidPosition, positions[0]);
            const nodes = try multi_siblings(gpa, self.leaf_count(), positions, diagnostic);
            defer gpa.free(nodes);
            const siblings = try gpa.alloc(D, nodes.len);
            for (nodes, siblings) |node, *sibling| {
                sibling.* = self.level(node.level)[node.index];
            }
            return .{ .leaf_count = self.leaf_count(), .siblings = siblings };
        }
    };
}

/// Hashes the level `below` into `above`, four nodes (two sibling pairs) at a time so the
/// hasher can interleave both pairs; an unpaired trailing node is paired with itself.
fn hash_level(comptime H: type, below: []const H.Digest, above: []H.Digest) void {
    assert(below.len > 1);
    assert(above.len == (below.len + 1) / 2);
    var i: usize = 0;
    var out: usize = 0;
    while (i + 4 <= below.len) : ({
        i += 4;
        out += 2;
    }) {
        above[out..][0..2].* = hash_node_pair(
            H,
            &below[i],
            &below[i + 1],
            &below[i + 2],
            &below[i + 3],
        );
    }
    switch (below.len - i) {
        0 => {},
        1 => above[out] = hash_node(H, &below[i], &below[i]),
        2 => above[out] = hash_node(H, &below[i], &below[i + 1]),
        3 => above[out..][0..2].* = hash_node_pair(
            H,
            &below[i],
            &below[i + 1],
            &below[i + 2],
            &below[i + 2],
        ),
        else => unreachable,
    }
}

/// Checks that `positions` are strictly ascending and below `leaf_count`, naming the first
/// one in input order that is not.
fn check_positions(leaf_count: u32, positions: []const u32, diagnostic: ?*Diagnostic) Error!void {
    for (positions, 0..) |position, i| {
        if (position >= leaf_count) return fail(diagnostic, error.InvalidPosition, position);
        if (i == 0) continue;
        const previous = positions[i - 1];
        if (position == previous) return fail(diagnostic, error.DuplicatePosition, position);
        if (position < previous) return fail(diagnostic, error.UnsortedPosition, position);
    }
    if (positions.len == 0) return error.NoLeaves;
    assert(positions[positions.len - 1] < leaf_count);
}

/// The siblings needed to prove the leaves at `positions`, ordered by level and then by
/// index. Each level costs work proportional to the number of positions.
fn multi_siblings(
    gpa: Allocator,
    leaf_count: u32,
    positions: []const u32,
    diagnostic: ?*Diagnostic,
) (Error || Allocator.Error)![]Node {
    try check_positions(leaf_count, positions, diagnostic);
    const buffer = try gpa.alloc(usize, 2 * positions.len);
    defer gpa.free(buffer);
    var current = buffer[0..positions.len];
    var next = buffer[positions.len..];
    for (positions, current) |position, *index| index.* = position;

    var siblings: std.ArrayList(Node) = try .initCapacity(gpa, positions.len);
    errdefer siblings.deinit(gpa);
    var len = current.len;
    var level_size: usize = leaf_count;
    for (0..levels_in_tree(leaf_count) - 1) |level| {
        var next_len: usize = 0;
        for (current[0..len], 0..) |index, offset| {
            // The sibling is known exactly when it is the adjacent entry, because `current`
            // is sorted and unique. The last node of an odd level pairs with itself.
            const sibling = index ^ 1;
            const known = if (index % 2 == 0)
                offset + 1 < len and current[offset + 1] == sibling
            else
                offset > 0 and current[offset - 1] == sibling;
            if (sibling < level_size and !known) {
                try siblings.append(gpa, .{ .level = level, .index = sibling });
            }
            // Parents of sorted indices are sorted; children of one parent are adjacent.
            const parent = index / 2;
            if (next_len == 0 or next[next_len - 1] != parent) {
                next[next_len] = parent;
                next_len += 1;
            }
        }
        assert(next_len > 0 and next_len <= len);
        std.mem.swap([]usize, &current, &next);
        len = next_len;
        level_size = (level_size + 1) / 2;
    }
    assert(len == 1);
    return siblings.toOwnedSlice(gpa);
}

/// Writes the siblings needed to prove the leaves `start..=end` into `out` and returns how
/// many: at most two per level, the left neighbor of the range start, then the right
/// neighbor of the range end.
fn range_siblings(
    leaf_count: u32,
    start: u32,
    end: u32,
    out: *[2 * max_levels]Node,
    diagnostic: ?*Diagnostic,
) Error!usize {
    if (leaf_count == 0) return error.NoLeaves;
    if (start > end) return fail(diagnostic, error.InvalidPosition, start);
    if (start >= leaf_count) return fail(diagnostic, error.InvalidPosition, start);
    if (end >= leaf_count) return fail(diagnostic, error.InvalidPosition, end);

    var count: usize = 0;
    var level_start: usize = start;
    var level_end: usize = end;
    var level_size: usize = leaf_count;
    for (0..levels_in_tree(leaf_count) - 1) |level| {
        if (level_start % 2 == 1) {
            out[count] = .{ .level = level, .index = level_start - 1 };
            count += 1;
        }
        if (level_end % 2 == 0 and level_end + 1 < level_size) {
            out[count] = .{ .level = level, .index = level_end + 1 };
            count += 1;
        }
        level_start /= 2;
        level_end /= 2;
        level_size = (level_size + 1) / 2;
    }
    assert(level_start == 0 and level_end == 0);
    return count;
}

/// A proof for one leaf, a range, or several leaves of a Binary Merkle Tree.
pub fn Proof(comptime D: type) type {
    comptime assert(D.fixed_size > 0);
    return struct {
        const Self = @This();

        /// The leaf count of the tree, bound into the finalized root.
        leaf_count: u32 = 0,
        /// The deduplicated siblings, ordered by level and then by index; owned.
        siblings: []D = &.{},

        /// codec: the most items the proof may prove; it may hold `max_levels` siblings each.
        pub const Cfg = usize;

        /// A leaf digest at its position, for multi-proof verification.
        pub const Element = struct {
            position: u32,
            digest: D,
        };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.siblings);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return .{ .leaf_count = self.leaf_count, .siblings = try gpa.dupe(D, self.siblings) };
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            if (a.leaf_count != b.leaf_count) return false;
            if (a.siblings.len != b.siblings.len) return false;
            for (a.siblings, b.siblings) |x, y| if (!x.eql(y)) return false;
            return true;
        }

        /// The largest encoding of a proof with at most `siblings` siblings.
        pub fn max_encode_size(siblings: usize) usize {
            return codec.util.max_items_size(siblings, D.fixed_size) + 4;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(u32, self.leaf_count, writer);
            codec.write([]const D, self.siblings, writer);
        }

        pub fn encode_size(self: Self) usize {
            return 4 + codec.encode_size([]const D, self.siblings);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max_items: Cfg) codec.Error!Self {
            const leaf_count = try codec.read(u32, gpa, reader);
            const max_siblings = max_items *| max_levels;
            const range: codec.RangeCfg(usize) = .to_inclusive(max_siblings);
            const siblings = try codec.read_range([]const D, gpa, reader, range);
            return .{ .leaf_count = leaf_count, .siblings = @constCast(siblings) };
        }

        /// Verifies that `leaf` is at `position` in the tree with `root`. At each level a
        /// left child (even index) takes its sibling on the right, and a right child on the
        /// left; the last node of an odd level pairs with itself and consumes no sibling.
        pub fn verify_element_inclusion(
            self: *const Self,
            comptime H: type,
            position: u32,
            leaf: *const D,
            root: *const D,
            diagnostic: ?*Diagnostic,
        ) Error!void {
            comptime assert(H.Digest == D);
            if (position >= self.leaf_count) {
                return fail(diagnostic, error.InvalidPosition, position);
            }
            var computed = hash_leaf(H, position, leaf);
            var index: usize = position;
            var level_size: usize = self.leaf_count;
            var consumed: usize = 0;
            while (level_size > 1) {
                if (index % 2 == 0 and index + 1 >= level_size) {
                    computed = hash_node(H, &computed, &computed);
                } else {
                    if (consumed == self.siblings.len) return error.UnalignedProof;
                    const sibling = &self.siblings[consumed];
                    consumed += 1;
                    computed = if (index % 2 == 0)
                        hash_node(H, &computed, sibling)
                    else
                        hash_node(H, sibling, &computed);
                }
                index /= 2;
                level_size = (level_size + 1) / 2;
            }
            if (consumed != self.siblings.len) return error.UnalignedProof;
            const finalized = finalize_root(H, self.leaf_count, &computed);
            if (!finalized.eql(root.*)) return error.InvalidProof;
        }

        /// Verifies that each of `elements` is at its position in the tree with `root`.
        /// Positions must be strictly ascending and in range; the diagnostic names the first
        /// position in input order that is out of range, repeats the previous one, or
        /// precedes it.
        pub fn verify_multi_inclusion(
            self: *const Self,
            comptime H: type,
            gpa: Allocator,
            elements: []const Element,
            root: *const D,
            diagnostic: ?*Diagnostic,
        ) (Error || Allocator.Error)!void {
            comptime assert(H.Digest == D);
            for (elements, 0..) |element, i| {
                const position = element.position;
                if (position >= self.leaf_count) {
                    return fail(diagnostic, error.InvalidPosition, position);
                }
                if (i == 0) continue;
                const previous = elements[i - 1].position;
                if (position == previous) return fail(
                    diagnostic,
                    error.DuplicatePosition,
                    position,
                );
                if (position < previous) return fail(diagnostic, error.UnsortedPosition, position);
            }
            if (elements.len == 0) return self.verify_empty(H, root);

            const current = try gpa.dupe(Element, elements);
            defer gpa.free(current);
            hash_elements(H, current);
            const parents = try gpa.alloc(Parent, current.len);
            defer gpa.free(parents);

            var len = current.len;
            var level_size: usize = self.leaf_count;
            var consumed: usize = 0;
            for (0..levels_in_tree(self.leaf_count) - 1) |_| {
                len = try self.climb(H, current[0..len], parents, level_size, &consumed);
                level_size = (level_size + 1) / 2;
            }
            if (consumed != self.siblings.len or len != 1) return error.UnalignedProof;
            const finalized = finalize_root(H, self.leaf_count, &current[0].digest);
            if (!finalized.eql(root.*)) return error.InvalidProof;
        }

        /// Verifies that `leaves` sit at `position`, `position + 1`, and so on, in the tree
        /// with `root`. No leaves prove only position 0 of the empty tree.
        pub fn verify_range_inclusion(
            self: *const Self,
            comptime H: type,
            gpa: Allocator,
            position: u32,
            leaves: []const D,
            root: *const D,
            diagnostic: ?*Diagnostic,
        ) (Error || Allocator.Error)!void {
            if (leaves.len == 0 and position != 0) {
                return fail(diagnostic, error.InvalidPosition, position);
            }
            if (leaves.len != 0) {
                const count = std.math.cast(u32, leaves.len) orelse
                    return fail(diagnostic, error.InvalidPosition, position);
                const end = std.math.add(u32, position, count - 1) catch
                    return fail(diagnostic, error.InvalidPosition, position);
                if (end >= self.leaf_count) return fail(diagnostic, error.InvalidPosition, end);
            }
            const elements = try gpa.alloc(Element, leaves.len);
            defer gpa.free(elements);
            for (leaves, elements, 0..) |leaf, *element, i| {
                element.* = .{ .position = position + @as(u32, @intCast(i)), .digest = leaf };
            }
            return self.verify_multi_inclusion(H, gpa, elements, root, diagnostic);
        }

        /// No elements verify only the empty tree's proof: no leaves and no siblings, against
        /// `hash(0 || hash())`.
        fn verify_empty(self: *const Self, comptime H: type, root: *const D) Error!void {
            if (self.leaf_count != 0 or self.siblings.len != 0) return error.NoLeaves;
            const empty_tree_root = H.hash(&.{});
            const finalized = finalize_root(H, 0, &empty_tree_root);
            if (!finalized.eql(root.*)) return error.InvalidProof;
        }

        const Parent = struct {
            position: u32,
            left: D,
            right: D,
        };

        /// Replaces each element's leaf with its position-hashed leaf, two at a time.
        fn hash_elements(comptime H: type, elements: []Element) void {
            assert(elements.len > 0);
            var i: usize = 0;
            while (i + 2 <= elements.len) : (i += 2) {
                const a = &elements[i];
                const b = &elements[i + 1];
                const prefix_a = be32(a.position);
                const prefix_b = be32(b.position);
                const pair = H.hash_pair(
                    &[_][]const u8{ &prefix_a, &a.digest.bytes },
                    &[_][]const u8{ &prefix_b, &b.digest.bytes },
                    {},
                );
                a.digest = pair[0];
                b.digest = pair[1];
            }
            if (i < elements.len) {
                const last = &elements[i];
                last.digest = hash_leaf(H, last.position, &last.digest);
            }
        }

        /// Hashes one level of `current` into its parents, written back to the front of
        /// `current`, and returns how many parents there are. Children found in `current`
        /// pair directly; otherwise a sibling comes from the proof, and the last node of an
        /// odd level pairs with itself.
        fn climb(
            self: *const Self,
            comptime H: type,
            current: []Element,
            parents: []Parent,
            level_size: usize,
            consumed: *usize,
        ) Error!usize {
            assert(current.len > 0 and parents.len >= current.len);
            var count: usize = 0;
            var i: usize = 0;
            while (i < current.len) : (i += 1) {
                const node = current[i];
                var parent: Parent = .{
                    .position = node.position / 2,
                    .left = node.digest,
                    .right = node.digest,
                };
                if (node.position % 2 == 0) {
                    if (i + 1 < current.len and current[i + 1].position == node.position + 1) {
                        i += 1;
                        parent.right = current[i].digest;
                    } else if (@as(usize, node.position) + 1 < level_size) {
                        parent.right = try self.next_sibling(consumed);
                    }
                } else {
                    parent.left = try self.next_sibling(consumed);
                }
                parents[count] = parent;
                count += 1;
            }
            hash_parents(H, parents[0..count], current[0..count]);
            assert(count <= current.len);
            return count;
        }

        fn next_sibling(self: *const Self, consumed: *usize) Error!D {
            if (consumed.* == self.siblings.len) return error.UnalignedProof;
            const sibling = self.siblings[consumed.*];
            consumed.* += 1;
            return sibling;
        }

        /// Hashes each parent's children into `out`, two parents at a time.
        fn hash_parents(comptime H: type, parents: []const Parent, out: []Element) void {
            assert(parents.len == out.len);
            var i: usize = 0;
            while (i + 2 <= parents.len) : (i += 2) {
                const a = &parents[i];
                const b = &parents[i + 1];
                const pair = hash_node_pair(H, &a.left, &a.right, &b.left, &b.right);
                out[i] = .{ .position = a.position, .digest = pair[0] };
                out[i + 1] = .{ .position = b.position, .digest = pair[1] };
            }
            if (i < parents.len) {
                const last = &parents[i];
                out[i] = .{ .position = last.position, .digest = hash_node(
                    H,
                    &last.left,
                    &last.right,
                ) };
            }
        }
    };
}

pub const fuzz = @import("fuzz.zig");

test {
    _ = @import("tests.zig");
}
