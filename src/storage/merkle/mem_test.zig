//! Tests for `merkle.mem.Mem`, ported from commonware's `storage/src/merkle/mem.rs` (the
//! family-generic ones run under every family) and `merkle/mmb/mem.rs`.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const merkle = @import("mod.zig");

const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const H = merkle.hasher.Standard(Sha256);
const gpa = testing.allocator;

/// Every family the generic checks run under.
const families = .{ merkle.mmr.Family, merkle.mmb.Family };

fn Mem(comptime F: type) type {
    return merkle.mem.Mem(F, D);
}

fn be(value: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return bytes;
}

/// A structure whose element `i` is `hasher.digest(i_be64)`.
fn build(comptime F: type, hasher: *const H, n: u64) !Mem(F) {
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    for (0..n) |i| {
        const element = hasher.digest(&be(i));
        try mem.add(gpa, hasher, &element.bytes);
    }
    return mem;
}

/// A structure whose element `i` is `i_be64`.
fn build_raw(comptime F: type, hasher: *const H, n: u64) !Mem(F) {
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    for (0..n) |i| try mem.add(gpa, hasher, &be(i));
    return mem;
}

fn expect_provable(comptime F: type, mem: *const Mem(F), hasher: *const H, location: u64) !void {
    var proof = try mem.proof(gpa, hasher, location, 0);
    proof.deinit(gpa);
}

test "empty" {
    inline for (families) |F| {
        var mem: Mem(F) = .empty;
        defer mem.deinit(gpa);
        try testing.expectEqual(@as(u64, 0), mem.leaves());
        try testing.expectEqual(@as(u64, 0), mem.size());
        try testing.expectEqual(mem.leaves(), mem.pruning_boundary());
    }
}

test "validity" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem: Mem(F) = .empty;
        defer mem.deinit(gpa);
        for (0..256) |i| {
            try testing.expect(F.is_valid_size(mem.size()));
            const old_size = mem.size();
            try mem.add(gpa, &hasher, &be(i));
            for (old_size + 1..mem.size()) |size| try testing.expect(!F.is_valid_size(size));
        }
    }
}

test "prune all then append" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem: Mem(F) = .empty;
        defer mem.deinit(gpa);
        for (0..256) |i| {
            mem.prune_all();
            try mem.add(gpa, &hasher, &be(i));
            try testing.expectEqual(@as(u64, i + 1), mem.leaves());
        }
    }
}

test "range proof and proof out of bounds" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var empty: Mem(F) = .empty;
        const first: merkle.Range = .{ .start = 0, .end = 1 };
        const range_empty = empty.range_proof(gpa, &hasher, first, 0);
        try testing.expectError(error.RangeOutOfBounds, range_empty);
        try testing.expectError(error.LeafOutOfBounds, empty.proof(gpa, &hasher, 0, 0));
        var mem = try build(F, &hasher, 10);
        defer mem.deinit(gpa);
        const past: merkle.Range = .{ .start = 5, .end = 11 };
        try testing.expectError(error.RangeOutOfBounds, mem.range_proof(gpa, &hasher, past, 0));
        var proof = try mem.range_proof(gpa, &hasher, .{ .start = 5, .end = 10 }, 0);
        proof.deinit(gpa);
        try testing.expectError(error.LeafOutOfBounds, mem.proof(gpa, &hasher, 10, 0));
        try expect_provable(F, &mem, &hasher, 9);
    }
}

test "init pinned nodes validation" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        const none: []const D = &.{};
        var empty = try Mem(F).init(gpa, none, 0, none);
        empty.deinit(gpa);
        try testing.expectError(error.InvalidPinnedNodes, Mem(F).init(gpa, none, 8, none));
        const dummy = [_]D{hasher.digest("dummy")};
        try testing.expectError(error.InvalidPinnedNodes, Mem(F).init(gpa, none, 0, &dummy));
        var mem = try build(F, &hasher, 50);
        defer mem.deinit(gpa);
        var buffer: [merkle.max_pinned_nodes]D = undefined;
        const pinned = mem.node_digests_to_pin(25, &buffer);
        var restored = try Mem(F).init(gpa, none, 25, pinned);
        restored.deinit(gpa);
    }
}

test "root stable under pruning" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var reference: Mem(F) = .empty;
        defer reference.deinit(gpa);
        var pruned: Mem(F) = .empty;
        defer pruned.deinit(gpa);
        for (0..200) |i| {
            const element = hasher.digest(&be(i));
            try reference.add(gpa, &hasher, &element.bytes);
            try pruned.add(gpa, &hasher, &element.bytes);
            pruned.prune_all();
            const expected = try reference.root(&hasher, 0);
            try testing.expect(expected.eql(try pruned.root(&hasher, 0)));
        }
    }
}

test "root changes with each append" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem: Mem(F) = .empty;
        defer mem.deinit(gpa);
        var previous = try mem.root(&hasher, 0);
        for (0..16) |i| {
            try mem.add(gpa, &hasher, &be(i));
            const root = try mem.root(&hasher, 0);
            try testing.expect(!root.eql(previous));
            previous = root;
        }
    }
}

test "single element and exhaustive range proof roundtrip" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        for (1..25) |n| {
            var mem = try build_raw(F, &hasher, n);
            defer mem.deinit(gpa);
            const root = try mem.root(&hasher, 0);
            var elements: [24][8]u8 = undefined;
            for (&elements, 0..) |*element, i| element.* = be(i);
            for (0..n) |start| {
                var single = try mem.proof(gpa, &hasher, start, 0);
                defer single.deinit(gpa);
                try testing.expect(single.verify_element_inclusion(
                    &hasher,
                    start,
                    &elements[start],
                    &root,
                ));
                for (start + 1..n + 1) |end| {
                    const range: merkle.Range = .{ .start = start, .end = end };
                    var proof = try mem.range_proof(gpa, &hasher, range, 0);
                    defer proof.deinit(gpa);
                    const slice = elements[start..end];
                    try testing.expect(proof.verify_range_inclusion(&hasher, start, slice, &root));
                }
            }
        }
    }
}

test "root with repeated pruning" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem = try build(F, &hasher, 32);
        defer mem.deinit(gpa);
        const root = try mem.root(&hasher, 0);
        for (1..mem.leaves()) |location| {
            try mem.prune(location);
            try testing.expect(root.eql(try mem.root(&hasher, 0)));
            try testing.expectEqual(@as(u64, location), mem.pruning_boundary());
            try expect_provable(F, &mem, &hasher, location);
            try expect_provable(F, &mem, &hasher, mem.leaves() - 1);
        }
        mem.prune_all();
        try testing.expect(root.eql(try mem.root(&hasher, 0)));
        try testing.expectEqual(mem.leaves(), mem.pruning_boundary());
    }
}

test "append after partial prune" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem = try build_raw(F, &hasher, 20);
        defer mem.deinit(gpa);
        try mem.prune(7);
        for (20..48) |i| try mem.add(gpa, &hasher, &be(i));
        const root = try mem.root(&hasher, 0);
        for (mem.pruning_boundary()..mem.leaves()) |location| {
            var proof = try mem.proof(gpa, &hasher, location, 0);
            defer proof.deinit(gpa);
            const element = be(location);
            try testing.expect(proof.verify_element_inclusion(&hasher, location, &element, &root));
        }
    }
}

test "split root matches recompute" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem = try build(F, &hasher, 49);
        defer mem.deinit(gpa);
        var buffer: [merkle.max_pinned_nodes]D = undefined;
        const peaks = mem.peaks(&buffer);
        const expected = try merkle.hasher.root(F, &hasher, mem.leaves(), 1, peaks);
        try testing.expect(expected.eql(try mem.root(&hasher, 1)));
    }
}

fn expect_verifies(
    comptime F: type,
    mem: *const Mem(F),
    hasher: *const H,
    location: u64,
    element: []const u8,
) !bool {
    var proof = try mem.proof(gpa, hasher, location, 0);
    defer proof.deinit(gpa);
    const root = try mem.root(hasher, 0);
    return proof.verify_element_inclusion(hasher, location, element, &root);
}

test "update leaf" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem = try build_raw(F, &hasher, 11);
        defer mem.deinit(gpa);
        const root_before = try mem.root(&hasher, 0);
        try mem.update_leaf(&hasher, 5, "updated-5");
        try testing.expect(!root_before.eql(try mem.root(&hasher, 0)));
        try testing.expectEqual(@as(u64, 11), mem.leaves());
        try testing.expect(try expect_verifies(F, &mem, &hasher, 5, "updated-5"));
        try testing.expect(!try expect_verifies(F, &mem, &hasher, 5, &be(5)));
        for ([_]u64{ 0, 3, 7, 10 }) |i| {
            try testing.expect(try expect_verifies(F, &mem, &hasher, i, &be(i)));
        }
    }
}

test "update leaf every position" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem = try build(F, &hasher, 20);
        defer mem.deinit(gpa);
        for (0..20) |location| {
            try mem.update_leaf(&hasher, location, "new-value");
            try testing.expect(try expect_verifies(F, &mem, &hasher, location, "new-value"));
        }
    }
}

test "update leaf errors" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem = try build(F, &hasher, 10);
        defer mem.deinit(gpa);
        try testing.expectError(error.LeafOutOfBounds, mem.update_leaf(&hasher, 10, "x"));
        try mem.prune(5);
        const root = try mem.root(&hasher, 0);
        try testing.expectError(error.ElementPruned, mem.update_leaf(&hasher, 3, "x"));
        try testing.expect(root.eql(try mem.root(&hasher, 0)));
        try mem.update_leaf(&hasher, 5, "x");
    }
}

test "update leaf with append and under merge parent" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        var mem = try build(F, &hasher, 8);
        defer mem.deinit(gpa);
        try mem.update_leaf(&hasher, 3, "updated-3");
        try mem.add(gpa, &hasher, &be(100));
        try mem.add(gpa, &hasher, &be(101));
        try testing.expectEqual(@as(u64, 10), mem.leaves());
        try testing.expect(try expect_verifies(F, &mem, &hasher, 3, "updated-3"));
        try testing.expect(try expect_verifies(F, &mem, &hasher, 8, &be(100)));
        // Updating before or after the append that merges the leaf's parent agrees.
        var before = try build(F, &hasher, 2);
        defer before.deinit(gpa);
        try before.update_leaf(&hasher, 0, "updated-0");
        try before.add(gpa, &hasher, &be(2));
        var after = try build(F, &hasher, 2);
        defer after.deinit(gpa);
        try after.add(gpa, &hasher, &be(2));
        try after.update_leaf(&hasher, 0, "updated-0");
        try testing.expect((try before.root(&hasher, 0)).eql(try after.root(&hasher, 0)));
        try testing.expect(try expect_verifies(F, &after, &hasher, 0, "updated-0"));
    }
}

test "update leaf after prune" {
    inline for (families) |F| {
        const hasher = H.init(.forward_fold);
        for (1..21) |n| {
            for (1..n) |prune_to| {
                for (prune_to..n) |location| {
                    var mem = try build_raw(F, &hasher, n);
                    defer mem.deinit(gpa);
                    try mem.prune(prune_to);
                    try mem.update_leaf(&hasher, location, "new");
                    try testing.expect(try expect_verifies(F, &mem, &hasher, location, "new"));
                }
            }
        }
    }
}

const Mmb = Mem(merkle.mmb.Family);

test "mmb append and size" {
    const hasher = H.init(.forward_fold);
    var mmb: Mmb = .empty;
    defer mmb.deinit(gpa);
    for (0..8) |i| {
        try testing.expectEqual(@as(u64, i), mmb.leaves());
        try mmb.add(gpa, &hasher, &be(i));
    }
    try testing.expectEqual(@as(u64, 8), mmb.leaves());
    try testing.expectEqual(@as(u64, 13), mmb.size());
}

test "mmb add eight values structure" {
    const hasher = H.init(.forward_fold);
    var mmb = try build_raw(merkle.mmb.Family, &hasher, 8);
    defer mmb.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), mmb.pruning_boundary());
    try testing.expectEqual(@as(u64, 13), mmb.size());
    const leaf_positions = [_]u64{ 0, 1, 3, 4, 6, 8, 10, 11 };
    for (leaf_positions, 0..) |position, i| {
        const expected = hasher.leaf_digest(position, &be(i));
        try testing.expect(expected.eql(mmb.get_node(position).?));
    }
    const node = struct {
        fn node(mem: *const Mmb, position: u64) D {
            return mem.get_node(position).?;
        }
    }.node;
    const digest2 = hasher.node_digest(2, &node(&mmb, 0), &node(&mmb, 1));
    try testing.expect(digest2.eql(node(&mmb, 2)));
    const digest5 = hasher.node_digest(5, &node(&mmb, 3), &node(&mmb, 4));
    try testing.expect(digest5.eql(node(&mmb, 5)));
    const digest7 = hasher.node_digest(7, &digest2, &digest5);
    try testing.expect(digest7.eql(node(&mmb, 7)));
    const digest9 = hasher.node_digest(9, &node(&mmb, 6), &node(&mmb, 8));
    try testing.expect(digest9.eql(node(&mmb, 9)));
    const digest12 = hasher.node_digest(12, &node(&mmb, 10), &node(&mmb, 11));
    try testing.expect(digest12.eql(node(&mmb, 12)));
    const peaks = [_]D{ digest7, digest9, digest12 };
    const expected_root = try merkle.hasher.root(merkle.mmb.Family, &hasher, 8, 0, &peaks);
    try testing.expect(expected_root.eql(try mmb.root(&hasher, 0)));
}

/// The retained nodes of `mem` from position `first` to its end.
fn retained_nodes(mem: *const Mmb, first: u64) ![]D {
    const nodes = try gpa.alloc(D, @intCast(mem.size() - first));
    for (nodes, first..) |*digest, position| digest.* = mem.get_node(position).?;
    return nodes;
}

test "mmb prune and reinit" {
    const hasher = H.init(.forward_fold);
    var mmb = try build(merkle.mmb.Family, &hasher, 24);
    defer mmb.deinit(gpa);
    const root = try mmb.root(&hasher, 0);
    try mmb.prune(9);
    try testing.expectEqual(@as(u64, 9), mmb.pruning_boundary());
    try testing.expect(root.eql(try mmb.root(&hasher, 0)));
    try testing.expectError(error.ElementPruned, mmb.proof(gpa, &hasher, 0, 0));
    for (9..mmb.leaves()) |location| {
        try expect_provable(merkle.mmb.Family, &mmb, &hasher, location);
    }
    const nodes = try retained_nodes(&mmb, merkle.mmb.Family.location_to_position(9));
    defer gpa.free(nodes);
    var buffer: [merkle.max_pinned_nodes]D = undefined;
    const pinned = mmb.node_digests_to_pin(9, &buffer);
    var copy = try Mmb.init(gpa, nodes, 9, pinned);
    defer copy.deinit(gpa);
    try testing.expectEqual(mmb.size(), copy.size());
    try testing.expectEqual(mmb.leaves(), copy.leaves());
    try testing.expectEqual(mmb.pruning_boundary(), copy.pruning_boundary());
    try testing.expect(root.eql(try copy.root(&hasher, 0)));
    try expect_provable(merkle.mmb.Family, &copy, &hasher, 17);
}

test "mmb init size validation" {
    const hasher = H.init(.forward_fold);
    const none: []const D = &.{};
    var empty = try Mmb.init(gpa, none, 0, none);
    empty.deinit(gpa);
    const two = [_]D{ hasher.digest("node1"), hasher.digest("node2") };
    try testing.expectError(error.InvalidSize, Mmb.init(gpa, &two, 0, none));
    const three = [_]D{ hasher.digest("leaf1"), hasher.digest("leaf2"), hasher.digest("parent") };
    var small = try Mmb.init(gpa, &three, 0, none);
    small.deinit(gpa);
    var full = try build(merkle.mmb.Family, &hasher, 64);
    defer full.deinit(gpa);
    const all = try retained_nodes(&full, 0);
    defer gpa.free(all);
    var copy = try Mmb.init(gpa, all, 0, none);
    copy.deinit(gpa);
    var pruned = try build(merkle.mmb.Family, &hasher, 11);
    defer pruned.deinit(gpa);
    try pruned.prune(4);
    const nodes = try retained_nodes(&pruned, 6);
    defer gpa.free(nodes);
    var buffer: [merkle.max_pinned_nodes]D = undefined;
    const pinned = pruned.node_digests_to_pin(4, &buffer);
    var restored = try Mmb.init(gpa, nodes, 4, pinned);
    restored.deinit(gpa);
    try testing.expectError(error.InvalidSize, Mmb.init(gpa, nodes, 2, pinned));
}
