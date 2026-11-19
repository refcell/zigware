//! Tests of merkleizing across a `parallel` strategy, ported from commonware's
//! `storage/src/merkle/batch.rs` (`level_batches_keep_pairs`, `add_many_at_limit`, and
//! `add_many_mixed_operations` on worker threads), `merkle/mem.rs`
//! (`batch_parallel_update_leaf`), and `merkle/mmr/mem.rs` (`test_mem_mmr_batched_root_parallel`).
//! Every check runs under both families.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const merkle = @import("mod.zig");

const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const H = merkle.hasher.Standard(Sha256);
const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const hasher = H.init(.forward_fold);

fn Mem(comptime F: type) type {
    return merkle.mem.Mem(F, D);
}

fn be(value: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return bytes;
}

fn element(i: u64) D {
    return hasher.digest(&be(i));
}

/// A strategy on `workers` threads planning `workers` tasks, taking its most parallel shape at
/// every call (commonware's `Explorer::parallel(&mocks::pooled(..))`).
fn pooled(workers: u32) !parallel.mocks.Explorer {
    const strategy = try parallel.mocks.pooled(gpa, testing.io, workers, workers);
    return .parallel(strategy);
}

/// Counts the paired and lone node hashes a merkleization performs.
const Counting = struct {
    pub const Digest = D;
    pub const NodeInput = H.NodeInput;

    inner: H,
    pairs: std.atomic.Value(u64) = .init(0),
    singles: std.atomic.Value(u64) = .init(0),

    pub fn hash(self: *const Counting, parts: []const []const u8) D {
        return self.inner.hash(parts);
    }

    pub fn root_bagging(self: *const Counting) merkle.Bagging {
        return self.inner.root_bagging();
    }

    pub fn leaf_digest(self: *const Counting, position: u64, bytes: []const u8) D {
        return self.inner.leaf_digest(position, bytes);
    }

    pub fn node_digest(self: *Counting, position: u64, left: *const D, right: *const D) D {
        _ = self.singles.fetchAdd(1, .monotonic);
        return self.inner.node_digest(position, left, right);
    }

    pub fn node_digest_pair(self: *Counting, nodes: [2]NodeInput) [2]D {
        _ = self.pairs.fetchAdd(1, .monotonic);
        return self.inner.node_digest_pair(nodes);
    }

    pub fn fold(self: *const Counting, accumulator: *const D, peak: *const D) D {
        return self.inner.fold(accumulator, peak);
    }
};

const Counted = struct { root: D, pairs: u64, singles: u64 };

/// Merkleizes `n` appended elements on `strategy`, returning the root and the hash counts.
fn merkleize_counting(comptime F: type, n: u64, strategy: anytype) !Counted {
    var counting: Counting = .{ .inner = hasher };
    var base: Mem(F) = .empty;
    defer base.deinit(gpa);
    var batch = try base.new_batch(gpa);
    errdefer batch.deinit(gpa);
    for (0..n) |i| try batch.add(gpa, &counting, &element(i).bytes);
    const merkleized = try batch.merkleize_with(gpa, &base, &counting, strategy);
    defer merkleized.release(gpa);
    return .{
        .root = try merkleized.root(&counting, 0),
        .pairs = counting.pairs.load(.monotonic),
        .singles = counting.singles.load(.monotonic),
    };
}

fn LevelPairs(comptime F: type) type {
    return struct {
        n: u64,

        pub fn run(op: @This(), strategy: parallel.mocks.Explorer) !Counted {
            return merkleize_counting(F, op.n, strategy);
        }
    };
}

// A split level hashes the same node pairs as a serial one: batches hold whole adjacent pairs,
// so splitting changes neither the root nor the counts of paired and lone node hashes, under
// every shape `explore` tries.
test "batch level splits keep node pairs" {
    inline for (families) |F| {
        for ([_]u64{ 1, 2, 3, 10, 100, 199 }) |n| {
            const serial = try merkleize_counting(F, n, parallel.sequential);
            const op: LevelPairs(F) = .{ .n = n };
            const explored = try parallel.mocks.explore(gpa, testing.io, op);
            try testing.expect(explored.root.eql(serial.root));
            try testing.expectEqual(serial.pairs, explored.pairs);
            try testing.expectEqual(serial.singles, explored.singles);
        }
    }
    // The 199-leaf MMR level of height 1 has 99 nodes: 49 pairs and one lone node.
    const counted = try merkleize_counting(merkle.mmr.Family, 199, parallel.sequential);
    try testing.expect(counted.pairs > 0 and counted.singles > 0);
}

/// Mem with `n` elements added one batch at a time through `strategy`.
fn build_with(comptime F: type, n: u64, strategy: anytype) !Mem(F) {
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    var batch = try mem.new_batch(gpa);
    errdefer batch.deinit(gpa);
    for (0..n) |i| try batch.add(gpa, &hasher, &element(i).bytes);
    const merkleized = try batch.merkleize_with(gpa, &mem, &hasher, strategy);
    defer merkleized.release(gpa);
    try mem.apply_batch(gpa, merkleized);
    return mem;
}

// A batched root merkleized on worker threads matches one built serially
// (commonware's `test_mem_mmr_batched_root_parallel`, run for both families).
test "batch root merkleized on workers matches the serial root" {
    const strategy = try pooled(4);
    defer strategy.strategy.pool.destroy();
    inline for (families) |F| {
        var serial = try build_with(F, 199, parallel.sequential);
        defer serial.deinit(gpa);
        var threaded = try build_with(F, 199, strategy);
        defer threaded.deinit(gpa);
        try testing.expectEqual(serial.size(), threaded.size());
        try testing.expect((try threaded.root(&hasher, 0)).eql(try serial.root(&hasher, 0)));
    }
}

/// Commonware's `do_batch_update`: update eight leaves of a 200-leaf structure on `strategy`,
/// apply, and check the root changes; restoring them restores the root.
fn batch_update(comptime F: type, strategy: anytype) !void {
    var mem = try build_with(F, 200, parallel.sequential);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    const leaves = [_]u64{ 0, 1, 10, 50, 100, 150, 197, 198 };
    const fixed = "01234567012345670123456701234567";
    for ([_]bool{ false, true }) |restore| {
        var batch = try mem.new_batch(gpa);
        errdefer batch.deinit(gpa);
        for (leaves) |leaf| {
            const bytes = element(leaf).bytes;
            try batch.update_leaf(gpa, &hasher, leaf, if (restore) &bytes else fixed);
        }
        const merkleized = try batch.merkleize_with(gpa, &mem, &hasher, strategy);
        defer merkleized.release(gpa);
        try mem.apply_batch(gpa, merkleized);
        try testing.expectEqual(restore, (try mem.root(&hasher, 0)).eql(root));
    }
}

// Leaf updates merkleized on worker threads change the root, and restoring them restores it.
test "batch leaf updates on workers" {
    const strategy = try pooled(4);
    defer strategy.strategy.pool.destroy();
    inline for (families) |F| {
        try batch_update(F, parallel.sequential);
        try batch_update(F, strategy);
    }
}

/// Repeated `add_many_with` calls on `strategy`, interleaved with `add` and `update_leaf` on a
/// pruned base, against the same operations one leaf at a time in a child of a merkleized
/// parent batch.
fn add_many_mixed(comptime F: type, strategy: anytype) !void {
    var base = try build_with(F, 63, parallel.sequential);
    defer base.deinit(gpa);
    base.prune_all();
    var batch_p = try base.new_batch(gpa);
    try batch_p.add(gpa, &hasher, "parent");
    const parent = try batch_p.merkleize(gpa, &base, &hasher);
    defer parent.release(gpa);
    var actual = try base.new_batch(gpa);
    errdefer actual.deinit(gpa);
    try actual.add(gpa, &hasher, "parent");
    var expected = parent.new_batch();
    errdefer expected.deinit(gpa);
    var items: [1000]u64 = undefined;
    for (&items, 0..) |*item, i| item.* = i;
    for ([_]u64{ 0, 1, 2, 63, 64, 127, 128, 129, 256, 511, 1000 }) |count| {
        try actual.add(gpa, &hasher, "prefix");
        try expected.add(gpa, &hasher, "prefix");
        try actual.add_many_with(gpa, &hasher, u64, items[0..count], strategy);
        for (items[0..count]) |item| try expected.add(gpa, &hasher, &be(item));
        // Leaf 63 is new in `actual` but a parent leaf in `expected`.
        for ([_]u64{ 63, actual.leaves() / 2 + 32, actual.leaves() - 1 }) |location| {
            try actual.update_leaf(gpa, &hasher, location, "update");
            try expected.update_leaf(gpa, &hasher, location, "update");
        }
    }
    const a = try actual.merkleize_with(gpa, &base, &hasher, strategy);
    defer a.release(gpa);
    const e = try expected.merkleize(gpa, &base, &hasher);
    defer e.release(gpa);
    try testing.expect((try a.root(&hasher, 0)).eql(try e.root(&hasher, 0)));
    for (parent.size()..a.size()) |position| {
        try testing.expect(a.get_node(position).?.eql(e.get_node(position).?));
    }
}

// `add_many` split across 1, 2, 3, and 8 worker threads matches adding one leaf at a time.
test "batch add_many on workers matches add" {
    inline for (families) |F| {
        for ([_]u32{ 1, 2, 3, 8 }) |workers| {
            const strategy = try pooled(workers);
            defer strategy.strategy.pool.destroy();
            try add_many_mixed(F, strategy);
        }
    }
}

/// `add_many` up to the family's leaf limit, split into up to three ranges on one thread,
/// matches `add`, including the leaf that creates the family's tallest node.
fn add_many_at_limit(comptime F: type, strategy: anytype) !void {
    var tallest: u32 = 1;
    while (tallest + 1 < 63 and F.birth_offset(tallest + 1) <= F.max_leaves) tallest += 1;
    var items: [300]u64 = undefined;
    for (&items, 0..) |*item, i| item.* = i;
    const cases = [_][2]u64{
        .{ F.birth_offset(tallest) - 1, 1 }, .{ F.max_leaves - 7, 7 }, .{ F.max_leaves - 300, 300 },
    };
    for (cases) |case| {
        const first, const count = case;
        // Distinct pins, so reading the wrong one changes the root.
        var positions: [merkle.max_pinned_nodes]u64 = undefined;
        const pin_count = merkle.nodes_to_pin(F, first, &positions).len;
        var pins: [merkle.max_pinned_nodes]D = undefined;
        for (pins[0..pin_count], 0..) |*pin, i| pin.* = .{ .bytes = @splat(@intCast(i)) };
        var base = try Mem(F).init(gpa, &.{}, first, pins[0..pin_count]);
        defer base.deinit(gpa);
        var batch = try base.new_batch(gpa);
        errdefer batch.deinit(gpa);
        try batch.add_many_with(gpa, &hasher, u64, items[0..count], strategy);
        const actual = try batch.merkleize_with(gpa, &base, &hasher, strategy);
        defer actual.release(gpa);
        var reference = try base.new_batch(gpa);
        errdefer reference.deinit(gpa);
        for (items[0..count]) |item| try reference.add(gpa, &hasher, &be(item));
        const expected = try reference.merkleize(gpa, &base, &hasher);
        defer expected.release(gpa);
        const a = actual.data.appended.items;
        const e = expected.data.appended.items;
        try testing.expectEqual(e.len, a.len);
        for (a, e) |x, y| try testing.expect(x.eql(y));
        try testing.expect((try actual.root(&hasher, 0)).eql(try expected.root(&hasher, 0)));
    }
}

// commonware's `split_strategy(3)`: a pool without workers planning three tasks.
test "batch add_many at the leaf limit split into ranges" {
    const inlined = try parallel.mocks.inlined(gpa, testing.io, 3);
    const strategy: parallel.mocks.Explorer = .parallel(inlined);
    defer strategy.strategy.pool.destroy();
    inline for (families) |F| try add_many_at_limit(F, strategy);
}
