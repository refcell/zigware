//! Tests for `batch.zig` and `Mem.apply_batch`, ported from commonware's
//! `storage/src/merkle/batch.rs` and the `apply_batch_*` tests of `merkle/mem.rs`. Every check
//! runs under both families. Commonware's `drop(batch)` is `batch.release(gpa)` here.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
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

fn Batch(comptime F: type) type {
    return Mem(F).Batch;
}

fn Merkleized(comptime F: type) type {
    return Mem(F).MerkleizedBatch;
}

fn fill(byte: u8) D {
    return .{ .bytes = @splat(byte) };
}

fn be(value: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return bytes;
}

/// Commonware's test element `i`: the digest of `i` as big-endian bytes.
fn element(i: u64) D {
    return hasher.digest(&be(i));
}

fn add_elements(comptime F: type, batch: *Batch(F), from: u64, to: u64) !void {
    for (from..to) |i| try batch.add(gpa, &hasher, &element(i).bytes);
}

/// A batch over `base` adding elements `from..to`, merkleized.
fn merkleized(comptime F: type, base: *const Mem(F), from: u64, to: u64) !*Merkleized(F) {
    var batch = try base.new_batch(gpa);
    errdefer batch.deinit(gpa);
    try add_elements(F, &batch, from, to);
    return batch.merkleize(gpa, base, &hasher);
}

/// A child of `parent` adding elements `from..to`, merkleized against `base`.
fn child(
    comptime F: type,
    parent: *Merkleized(F),
    base: *const Mem(F),
    from: u64,
    to: u64,
) !*Merkleized(F) {
    var batch = parent.new_batch();
    errdefer batch.deinit(gpa);
    try add_elements(F, &batch, from, to);
    return batch.merkleize(gpa, base, &hasher);
}

/// Commonware's `build_reference`: elements `0..n` through one batch.
fn build_reference(comptime F: type, n: u64) !Mem(F) {
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    const batch = try merkleized(F, &mem, 0, n);
    defer batch.release(gpa);
    try mem.apply_batch(gpa, batch);
    return mem;
}

/// Commonware's mem.rs `build_raw`: element `i` is `i` as big-endian bytes.
fn build_raw(comptime F: type, n: u64) !Mem(F) {
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    for (0..n) |i| try mem.add(gpa, &hasher, &be(i));
    return mem;
}

fn root_of(structure: anytype) !D {
    return structure.root(&hasher, 0);
}

fn update(
    comptime F: type,
    parent: *Merkleized(F),
    base: *const Mem(F),
    location: u64,
    data: []const u8,
) !*Merkleized(F) {
    var batch = parent.new_batch();
    errdefer batch.deinit(gpa);
    try batch.update_leaf(gpa, &hasher, location, data);
    return batch.merkleize(gpa, base, &hasher);
}

fn consistency_with_reference(comptime F: type) !void {
    for ([_]u64{ 1, 2, 10, 100, 199 }) |n| {
        var reference = try build_raw_digests(F, n);
        defer reference.deinit(gpa);
        const base: Mem(F) = .empty;
        const batch = try merkleized(F, &base, 0, n);
        defer batch.release(gpa);
        var result: Mem(F) = .empty;
        defer result.deinit(gpa);
        try result.apply_batch(gpa, batch);
        try testing.expect((try root_of(&result)).eql(try root_of(&reference)));
    }
}

/// The reference built leaf by leaf with `Mem.add` (no batches).
fn build_raw_digests(comptime F: type, n: u64) !Mem(F) {
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    for (0..n) |i| try mem.add(gpa, &hasher, &element(i).bytes);
    return mem;
}

fn lifecycle_and_proofs(comptime F: type) !void {
    var base = try build_reference(F, 50);
    defer base.deinit(gpa);
    const base_root = try root_of(&base);
    const batch = try merkleized(F, &base, 50, 60);
    defer batch.release(gpa);
    const batch_root = try root_of(batch);
    try testing.expect(!batch_root.eql(base_root));
    try testing.expect((try root_of(&base)).eql(base_root));

    // Proofs straight from the speculative batch read committed nodes from `base`.
    for ([_]u64{ 52, 49 }) |location| {
        var proof = try batch.proof(gpa, &base, &hasher, location, 0);
        defer proof.deinit(gpa);
        const bytes = element(location).bytes;
        try testing.expect(proof.verify_element_inclusion(&hasher, location, &bytes, &batch_root));
    }
    for ([_]merkle.Range{ .{ .start = 50, .end = 55 }, .{ .start = 45, .end = 55 } }) |range| {
        var elements: [10]D = undefined;
        for (elements[0 .. range.end - range.start], range.start..) |*e, i| e.* = element(i);
        var proof = try batch.range_proof(gpa, &base, &hasher, range, 0);
        defer proof.deinit(gpa);
        const proven = elements[0 .. range.end - range.start];
        try testing.expect(proof.verify_range_inclusion(&hasher, range.start, proven, &batch_root));
    }

    try base.apply_batch(gpa, batch);
    try testing.expect((try root_of(&base)).eql(batch_root));
    var proof = try base.proof(gpa, &hasher, 55, 0);
    defer proof.deinit(gpa);
    const bytes = element(55).bytes;
    try testing.expect(proof.verify_element_inclusion(&hasher, 55, &bytes, &batch_root));
    var reference = try build_reference(F, 60);
    defer reference.deinit(gpa);
    try testing.expect((try root_of(&reference)).eql(batch_root));
}

fn forks_and_stacking(comptime F: type) !void {
    var base = try build_reference(F, 50);
    defer base.deinit(gpa);
    const base_root = try root_of(&base);
    const a = try merkleized(F, &base, 50, 60);
    defer a.release(gpa);
    const fork = try merkleized(F, &base, 100, 105);
    defer fork.release(gpa);
    try testing.expect(!(try root_of(a)).eql(try root_of(fork)));
    try testing.expect(!(try root_of(a)).eql(base_root));
    try testing.expect((try root_of(&base)).eql(base_root));

    // A fork of a fork reads its parent's nodes.
    const b = try child(F, a, &base, 60, 70);
    defer b.release(gpa);
    var reference = try build_reference(F, 70);
    defer reference.deinit(gpa);
    try testing.expect((try root_of(b)).eql(try root_of(&reference)));
    try base.apply_batch(gpa, a);
    try base.apply_batch(gpa, b);
    const b_root = try root_of(b);
    for ([_]u64{ 0, 25, 55, 65, 69 }) |location| {
        var proof = try base.proof(gpa, &hasher, location, 0);
        defer proof.deinit(gpa);
        const bytes = element(location).bytes;
        try testing.expect(proof.verify_element_inclusion(&hasher, location, &bytes, &b_root));
    }
}

fn leaf_digest_updates(comptime F: type) !void {
    var base = try build_reference(F, 100);
    defer base.deinit(gpa);
    const base_root = try root_of(&base);
    const position = F.location_to_position(5);
    const original = base.get_node(position).?;
    for ([_]D{ fill(0xff), original }, [_]bool{ false, true }) |digest, restores| {
        var batch = try base.new_batch(gpa);
        try batch.update_leaf_digest(gpa, 5, digest);
        const m = try batch.merkleize(gpa, &base, &hasher);
        defer m.release(gpa);
        try testing.expectEqual(restores, (try root_of(m)).eql(base_root));
    }

    // Batched updates, then restoring the originals.
    const locations = [_]u64{ 0, 10, 50, 99 };
    var updates: [locations.len]Batch(F).LeafUpdate = undefined;
    for (&updates, locations) |*u, l| u.* = .{ .location = l, .digest = fill(0xbb) };
    var restores: [locations.len]Batch(F).LeafUpdate = undefined;
    for (&restores, locations) |*u, l| {
        u.* = .{ .location = l, .digest = base.get_node(F.location_to_position(l)).? };
    }
    const sets = [_][]const Batch(F).LeafUpdate{ &updates, &restores };
    for (sets, [_]bool{ false, true }) |set, same| {
        var batch = try base.new_batch(gpa);
        try batch.update_leaf_batched(gpa, set);
        const m = try batch.merkleize(gpa, &base, &hasher);
        defer m.release(gpa);
        try testing.expectEqual(same, (try root_of(m)).eql(base_root));
    }

    // An update plus appends; the batch reads its own update.
    var batch = try base.new_batch(gpa);
    try batch.update_leaf_digest(gpa, 10, fill(0xaa));
    try add_elements(F, &batch, 100, 105);
    const m = try batch.merkleize(gpa, &base, &hasher);
    defer m.release(gpa);
    try testing.expect(!(try root_of(m)).eql(base_root));
    try testing.expect(m.get_node(F.location_to_position(10)).?.eql(fill(0xaa)));

    // Out of bounds.
    var bad = try base.new_batch(gpa);
    defer bad.deinit(gpa);
    try testing.expectError(error.LeafOutOfBounds, bad.update_leaf_digest(gpa, 100, fill(0xff)));
    const out: [1]Batch(F).LeafUpdate = .{.{ .location = 100, .digest = fill(0xff) }};
    try testing.expectError(error.LeafOutOfBounds, bad.update_leaf_batched(gpa, &out));
}

fn empty_and_roundtrip(comptime F: type) !void {
    var base = try build_reference(F, 50);
    defer base.deinit(gpa);
    const base_root = try root_of(&base);
    const empty = try merkleized(F, &base, 0, 0);
    defer empty.release(gpa);
    try testing.expect((try root_of(empty)).eql(base_root));
    const empty_child = try child(F, empty, &base, 0, 0);
    defer empty_child.release(gpa);
    try base.apply_batch(gpa, empty_child);
    try testing.expect((try root_of(&base)).eql(base_root));

    const first = try merkleized(F, &base, 50, 55);
    defer first.release(gpa);
    const second = try child(F, first, &base, 55, 60);
    defer second.release(gpa);
    var reference = try build_reference(F, 60);
    defer reference.deinit(gpa);
    try testing.expect((try root_of(second)).eql(try root_of(&reference)));

    // Sequential applies.
    try base.apply_batch(gpa, first);
    const next = try merkleized(F, &base, 55, 70);
    defer next.release(gpa);
    try base.apply_batch(gpa, next);
    var reference_70 = try build_reference(F, 70);
    defer reference_70.deinit(gpa);
    try testing.expect((try root_of(&base)).eql(try root_of(&reference_70)));
}

fn pruned_base_and_deep_stacks(comptime F: type) !void {
    var base = try build_reference(F, 100);
    defer base.deinit(gpa);
    try base.prune(27);
    const m = try merkleized(F, &base, 100, 110);
    defer m.release(gpa);
    const expected = try root_of(m);
    try base.apply_batch(gpa, m);
    var proof = try base.proof(gpa, &hasher, 80, 0);
    defer proof.deinit(gpa);
    const bytes = element(80).bytes;
    try testing.expect(proof.verify_element_inclusion(&hasher, 80, &bytes, &expected));
    try testing.expectError(error.ElementPruned, base.proof(gpa, &hasher, 0, 0));

    // Three deep: two overwrite-only batches, then appends; also overwrite collisions.
    var fresh = try build_reference(F, 100);
    defer fresh.deinit(gpa);
    var batch_a = try fresh.new_batch(gpa);
    try batch_a.update_leaf_digest(gpa, 5, fill(0xdd));
    const a = try batch_a.merkleize(gpa, &fresh, &hasher);
    defer a.release(gpa);
    var batch_b = a.new_batch();
    try batch_b.update_leaf_digest(gpa, 5, fill(0xee));
    try batch_b.update_leaf_digest(gpa, 10, fill(0xee));
    const b = try batch_b.merkleize(gpa, &fresh, &hasher);
    defer b.release(gpa);
    const c = try child(F, b, &fresh, 300, 310);
    defer c.release(gpa);
    try fresh.apply_batch(gpa, c);
    try testing.expect((try root_of(&fresh)).eql(try root_of(c)));
    try testing.expect(fresh.get_node(F.location_to_position(5)).?.eql(fill(0xee)));
}

fn update_appended_and_elements(comptime F: type) !void {
    var base = try build_reference(F, 50);
    defer base.deinit(gpa);
    var batch = try base.new_batch(gpa);
    try add_elements(F, &batch, 50, 60);
    try batch.update_leaf_digest(gpa, 52, fill(0xee));
    const m = try batch.merkleize(gpa, &base, &hasher);
    defer m.release(gpa);
    try testing.expect(m.get_node(F.location_to_position(52)).?.eql(fill(0xee)));
    var reference = try build_reference(F, 60);
    defer reference.deinit(gpa);
    try reference.update_leaf_digest(&hasher, 52, fill(0xee));
    try testing.expect((try root_of(m)).eql(try root_of(&reference)));

    const root_batch = try Merkleized(F).from_mem(gpa, &base);
    defer root_batch.release(gpa);
    const updated = try update(F, root_batch, &base, 5, "updated-element");
    defer updated.release(gpa);
    try testing.expect(!(try root_of(updated)).eql(try root_of(&base)));
    try base.update_leaf(&hasher, 5, "updated-element");
    try testing.expect((try root_of(updated)).eql(try root_of(&base)));
}

fn get_node_resolves_from_writing_batch(comptime F: type) !void {
    var base = try build_reference(F, 10);
    defer base.deinit(gpa);
    const leaf_0 = F.location_to_position(0);
    const leaf_5 = F.location_to_position(5);
    const leaf_9 = F.location_to_position(9);
    const leaf_10 = F.location_to_position(10);
    const leaf_11 = F.location_to_position(11);
    var batch_a = try base.new_batch(gpa);
    try batch_a.add_leaf_digest(gpa, fill(0xa1));
    const a = try batch_a.merkleize(gpa, &base, &hasher);
    defer a.release(gpa);
    try testing.expectEqual(leaf_10, a.data.parent_size);
    try testing.expect(a.get_node(leaf_10).?.eql(fill(0xa1)));
    var batch_b = a.new_batch();
    try batch_b.update_leaf_digest(gpa, 0, fill(0xb2));
    const b = try batch_b.merkleize(gpa, &base, &hasher);
    defer b.release(gpa);
    var peaks = F.peaks(b.size());
    const peak = peaks.next().?.position;
    const peak_digest = b.data.tip_peaks.slice()[0];
    const empty = try child(F, b, &base, 0, 0);
    defer empty.release(gpa);
    var batch_c = empty.new_batch();
    try batch_c.update_leaf_digest(gpa, 9, fill(0xc3));
    try batch_c.add_leaf_digest(gpa, fill(0xd4));
    const c = try batch_c.merkleize(gpa, &base, &hasher);
    defer c.release(gpa);
    try testing.expectEqual(leaf_11, c.data.parent_size);
    try testing.expect(c.get_node(leaf_9).?.eql(fill(0xc3)));
    try testing.expect(c.get_node(leaf_11).?.eql(fill(0xd4)));
    for ([_]*Merkleized(F){ empty, c }) |batch| {
        try testing.expect(batch.get_node(leaf_0).?.eql(fill(0xb2)));
        try testing.expect(batch.get_node(peak).?.eql(peak_digest));
        try testing.expect(batch.get_node(leaf_10).?.eql(fill(0xa1)));
        try testing.expectEqual(@as(?D, null), batch.get_node(leaf_5));
        try testing.expectEqual(@as(?D, null), batch.get_node(batch.size()));
    }
}

test "batch consistency, lifecycle, proofs, and forks" {
    inline for (families) |F| {
        try consistency_with_reference(F);
        try lifecycle_and_proofs(F);
        try forks_and_stacking(F);
    }
}

test "batch leaf updates" {
    inline for (families) |F| {
        try leaf_digest_updates(F);
        try update_appended_and_elements(F);
    }
}

test "batch empty, roundtrip, pruned base, and deep stacks" {
    inline for (families) |F| {
        try empty_and_roundtrip(F);
        try pruned_base_and_deep_stacks(F);
    }
}

test "batch get_node resolves from the writing batch" {
    inline for (families) |F| try get_node_resolves_from_writing_batch(F);
}

// Mem.apply_batch: which chain states a batch applies from.

fn expect_same_state(
    comptime F: type,
    actual: *const Mem(F),
    expected: *const Mem(F),
    root: D,
) !void {
    try testing.expect((try root_of(actual)).eql(root));
    try testing.expectEqual(expected.size(), actual.size());
    try testing.expectEqual(expected.pruning_boundary(), actual.pruning_boundary());
    for (0..expected.size()) |position| {
        const a = actual.get_node(position);
        const e = expected.get_node(position);
        try testing.expectEqual(e == null, a == null);
        if (e) |digest| try testing.expect(digest.eql(a.?));
    }
}

fn applies_after_committed_ancestors(comptime F: type) !void {
    // Applying C after only A replays B and C.
    var mem: Mem(F) = .empty;
    defer mem.deinit(gpa);
    const a = try merkleized(F, &mem, 0, 1);
    defer a.release(gpa);
    const b = try child(F, a, &mem, 1, 2);
    defer b.release(gpa);
    const c = try child(F, b, &mem, 2, 3);
    defer c.release(gpa);
    try mem.apply_batch(gpa, a);
    try mem.apply_batch(gpa, c);
    var reference = try build_reference(F, 3);
    defer reference.deinit(gpa);
    try testing.expect((try root_of(&mem)).eql(try root_of(&reference)));

    // An unapplied ancestor released before a descendant is merkleized is detected.
    var other: Mem(F) = .empty;
    defer other.deinit(gpa);
    const x = try merkleized(F, &other, 0, 1);
    const y = try child(F, x, &other, 1, 2);
    defer y.release(gpa);
    x.release(gpa);
    const z = try child(F, y, &other, 2, 3);
    defer z.release(gpa);
    try testing.expectError(error.AncestorDropped, other.apply_batch(gpa, z));
}

fn applies_after_committed_ancestor_released(comptime F: type, overwrite: bool) !void {
    var mem = try build_raw(F, 10);
    defer mem.deinit(gpa);
    var batch_a = try mem.new_batch(gpa);
    for (100..105) |i| try batch_a.add(gpa, &hasher, &be(i));
    const a = try batch_a.merkleize(gpa, &mem, &hasher);
    var batch_b = a.new_batch();
    if (overwrite) try batch_b.update_leaf(gpa, &hasher, 0, "updated-0") else {
        try batch_b.add(gpa, &hasher, &be(105));
    }
    const b = try batch_b.merkleize(gpa, &mem, &hasher);
    try mem.apply_batch(gpa, a);
    a.release(gpa);
    var batch_c = b.new_batch();
    if (overwrite) try batch_c.update_leaf(gpa, &hasher, 9, "updated-9") else {
        try batch_c.add(gpa, &hasher, &be(106));
    }
    const c = try batch_c.merkleize(gpa, &mem, &hasher);
    defer c.release(gpa);
    // Only the live, uncommitted suffix is retained, starting right after the committed one.
    try testing.expectEqual(@as(usize, 1), c.ancestors.len);
    try testing.expectEqual(mem.size(), c.ancestors[0].parent_size);
    b.release(gpa);
    try mem.apply_batch(gpa, c);

    var reference = try build_raw(F, 10);
    defer reference.deinit(gpa);
    for (100..105) |i| try reference.add(gpa, &hasher, &be(i));
    if (overwrite) {
        try reference.update_leaf(&hasher, 0, "updated-0");
        try reference.update_leaf(&hasher, 9, "updated-9");
    } else {
        try reference.add(gpa, &hasher, &be(105));
        try reference.add(gpa, &hasher, &be(106));
    }
    try testing.expect((try root_of(&mem)).eql(try root_of(&reference)));
}

fn applies_overwrite_only_ancestor(comptime F: type) !void {
    var mem = try build_raw(F, 10);
    defer mem.deinit(gpa);
    var batch_a = try mem.new_batch(gpa);
    for (100..105) |i| try batch_a.add(gpa, &hasher, &be(i));
    const a = try batch_a.merkleize(gpa, &mem, &hasher);
    defer a.release(gpa);
    const b = try update(F, a, &mem, 0, "updated-0");
    defer b.release(gpa);
    var batch_c = b.new_batch();
    for (200..205) |i| try batch_c.add(gpa, &hasher, &be(i));
    const c = try batch_c.merkleize(gpa, &mem, &hasher);
    defer c.release(gpa);
    try mem.apply_batch(gpa, a);
    try mem.apply_batch(gpa, c);
    const position = F.location_to_position(0);
    try testing.expect(mem.get_node(position).?.eql(hasher.leaf_digest(position, "updated-0")));
}

fn applies_from_each_chain_state(comptime F: type, append: bool) !void {
    var base = try build_raw(F, 10);
    defer base.deinit(gpa);
    var chain: [5]*Merkleized(F) = undefined;
    var batch_a = try base.new_batch(gpa);
    try batch_a.add(gpa, &hasher, "a");
    chain[0] = try batch_a.merkleize(gpa, &base, &hasher);
    chain[1] = try update(F, chain[0], &base, 0, "b");
    chain[2] = try child(F, chain[1], &base, 0, 0);
    chain[3] = try update(F, chain[2], &base, 9, "c");
    var batch_d = chain[3].new_batch();
    try batch_d.update_leaf(gpa, &hasher, 0, "d");
    if (append) try batch_d.add(gpa, &hasher, "d");
    chain[4] = try batch_d.merkleize(gpa, &base, &hasher);
    defer for (chain) |batch| batch.release(gpa);
    const tip = chain[4];
    const root = try root_of(tip);
    var expected = try base.clone(gpa);
    defer expected.deinit(gpa);
    for (chain) |batch| try expected.apply_batch(gpa, batch);
    for (0..chain.len + 1) |applied| {
        var actual = try base.clone(gpa);
        defer actual.deinit(gpa);
        for (chain[0..applied]) |batch| try actual.apply_batch(gpa, batch);
        if (applied == chain.len) {
            try testing.expectError(error.StaleBatch, actual.apply_batch(gpa, tip));
        } else {
            try actual.apply_batch(gpa, tip);
        }
        try expect_same_state(F, &actual, &expected, root);
    }
}

fn prune_then_apply_matches_apply_then_prune(comptime F: type) !void {
    for (1..13) |n| {
        var mem = try build_raw(F, n);
        defer mem.deinit(gpa);
        for (0..n) |location| for ([_]bool{ false, true }) |append| {
            var batch = try mem.new_batch(gpa);
            try batch.update_leaf(gpa, &hasher, location, "new");
            if (append) try batch.add(gpa, &hasher, "appended");
            const m = try batch.merkleize(gpa, &mem, &hasher);
            defer m.release(gpa);
            const root = try root_of(m);
            for (location + 1..n + 1) |prune_to| {
                var expected = try mem.clone(gpa);
                defer expected.deinit(gpa);
                try expected.apply_batch(gpa, m);
                try expected.prune(prune_to);
                var actual = try mem.clone(gpa);
                defer actual.deinit(gpa);
                try actual.prune(prune_to);
                try actual.apply_batch(gpa, m);
                try expect_same_state(F, &actual, &expected, root);
            }
        };
    }
}

fn rejects_sibling_forks(comptime F: type) !void {
    for (0..8) |n| {
        var mem = try build_raw(F, n);
        defer mem.deinit(gpa);
        var batch_a = try mem.new_batch(gpa);
        try batch_a.add(gpa, &hasher, "a");
        const a = try batch_a.merkleize(gpa, &mem, &hasher);
        defer a.release(gpa);
        const b = try child(F, a, &mem, 0, 1);
        defer b.release(gpa);
        var batch_s = try mem.new_batch(gpa);
        try batch_s.add(gpa, &hasher, "a-prime");
        const sibling = try batch_s.merkleize(gpa, &mem, &hasher);
        defer sibling.release(gpa);
        try mem.apply_batch(gpa, sibling);
        const root = try root_of(&mem);
        const size = mem.size();
        try testing.expectError(error.StaleBatch, mem.apply_batch(gpa, b));
        try testing.expectEqual(size, mem.size());
        try testing.expect((try root_of(&mem)).eql(root));
    }

    // An overwrite-only sibling leaves the size unchanged; the recorded peaks reject the fork.
    var mem = try build_raw(F, 8);
    defer mem.deinit(gpa);
    const root_batch = try Merkleized(F).from_mem(gpa, &mem);
    defer root_batch.release(gpa);
    const a = try update(F, root_batch, &mem, 0, "a");
    defer a.release(gpa);
    const b = try update(F, a, &mem, 1, "b");
    defer b.release(gpa);
    const sibling = try update(F, root_batch, &mem, 0, "a-prime");
    defer sibling.release(gpa);
    try mem.apply_batch(gpa, sibling);
    try testing.expectError(error.StaleBatch, mem.apply_batch(gpa, b));
    try testing.expectError(error.StaleBatch, mem.apply_batch(gpa, a));
    var fresh = try build_raw(F, 8);
    defer fresh.deinit(gpa);
    try fresh.apply_batch(gpa, a);
    try fresh.apply_batch(gpa, b);
    try testing.expect((try root_of(&fresh)).eql(try root_of(b)));
}

fn released_ancestor_cases(comptime F: type) !void {
    // A released overwrite-only ancestor leaves its grandchild stale at the fork state.
    var mem = try build_raw(F, 8);
    defer mem.deinit(gpa);
    const root_batch = try Merkleized(F).from_mem(gpa, &mem);
    defer root_batch.release(gpa);
    const a = try update(F, root_batch, &mem, 0, "a");
    const b = try child(F, a, &mem, 0, 1);
    defer b.release(gpa);
    var batch_c = b.new_batch();
    try batch_c.add(gpa, &hasher, "c");
    a.release(gpa);
    const c = try batch_c.merkleize(gpa, &mem, &hasher);
    defer c.release(gpa);
    try testing.expectError(error.StaleBatch, mem.apply_batch(gpa, c));

    // A child of empty ancestors needs the state after the last ancestor with writes.
    for ([_]bool{ false, true }) |commit| {
        var base = try build_raw(F, 8);
        defer base.deinit(gpa);
        const start = try Merkleized(F).from_mem(gpa, &base);
        defer start.release(gpa);
        const x = try update(F, start, &base, 0, "a");
        const y = try child(F, x, &base, 0, 0);
        const z = try child(F, y, &base, 0, 0);
        if (commit) try base.apply_batch(gpa, x);
        x.release(gpa);
        var batch_d = z.new_batch();
        try batch_d.add(gpa, &hasher, "d");
        const d = try batch_d.merkleize(gpa, &base, &hasher);
        defer d.release(gpa);
        y.release(gpa);
        z.release(gpa);
        const root = try root_of(&base);
        if (commit) {
            try base.apply_batch(gpa, d);
            try testing.expect((try root_of(&base)).eql(try root_of(d)));
        } else {
            try testing.expectError(error.StaleBatch, base.apply_batch(gpa, d));
            try testing.expect((try root_of(&base)).eql(root));
        }
    }
}

test "apply_batch replays uncommitted ancestors" {
    inline for (families) |F| {
        try applies_after_committed_ancestors(F);
        try applies_after_committed_ancestor_released(F, false);
        try applies_after_committed_ancestor_released(F, true);
        try applies_overwrite_only_ancestor(F);
    }
}

test "apply_batch from each chain state" {
    inline for (families) |F| {
        try applies_from_each_chain_state(F, false);
        try applies_from_each_chain_state(F, true);
    }
}

test "apply_batch after prune matches prune after apply" {
    inline for (families) |F| try prune_then_apply_matches_apply_then_prune(F);
}

test "apply_batch rejects sibling forks and released ancestors" {
    inline for (families) |F| {
        try rejects_sibling_forks(F);
        try released_ancestor_cases(F);
    }
}

fn chain_case(comptime F: type, mem: *const Mem(F), n: u64, flags: [3]bool, location: u64) !void {
    const parent_append, const middle, const append = flags;
    var batch_p = try mem.new_batch(gpa);
    if (parent_append) try batch_p.add(gpa, &hasher, "parent") else {
        try batch_p.update_leaf(gpa, &hasher, 0, "parent");
    }
    const parent = try batch_p.merkleize(gpa, mem, &hasher);
    defer parent.release(gpa);
    const child_parent = if (middle) try update(F, parent, mem, 0, "middle") else parent.retain();
    defer child_parent.release(gpa);
    var batch_c = child_parent.new_batch();
    try batch_c.update_leaf(gpa, &hasher, location, "child");
    if (append) try batch_c.add(gpa, &hasher, "appended");
    const c = try batch_c.merkleize(gpa, mem, &hasher);
    defer c.release(gpa);
    const root = try root_of(c);
    for (1..n + @intFromBool(parent_append) + 1) |prune_to| {
        var expected = try mem.clone(gpa);
        defer expected.deinit(gpa);
        try expected.apply_batch(gpa, parent);
        try expected.apply_batch(gpa, c);
        try expected.prune(prune_to);
        var actual = try mem.clone(gpa);
        defer actual.deinit(gpa);
        try actual.apply_batch(gpa, parent);
        try actual.prune(prune_to);
        try actual.apply_batch(gpa, c);
        try expect_same_state(F, &actual, &expected, root);
    }
}

test "apply_batch chain after prune matches prune after apply" {
    inline for (families) |F| {
        for (1..13) |n| {
            var mem = try build_raw(F, n);
            defer mem.deinit(gpa);
            for (0..n) |location| for (0..8) |bits| {
                const flags = [3]bool{ bits & 1 != 0, bits & 2 != 0, bits & 4 != 0 };
                try chain_case(F, &mem, n, flags, location);
            };
        }
    }
}

// add_many: the same nodes as `add` on each item's encoding.

fn expect_same_batch(
    comptime F: type,
    actual: *const Merkleized(F),
    expected: *const Merkleized(F),
) !void {
    const a = actual.data.appended.items;
    const e = expected.data.appended.items;
    try testing.expectEqual(e.len, a.len);
    for (a, e) |x, y| try testing.expect(x.eql(y));
    try testing.expectEqual(expected.data.overwrites.count(), actual.data.overwrites.count());
    var entries = expected.data.overwrites.iterator();
    while (entries.next()) |entry| {
        try testing.expect(actual.data.overwrites.get(entry.key_ptr.*).?.eql(entry.value_ptr.*));
    }
    try testing.expect((try root_of(actual)).eql(try root_of(expected)));
}

fn add_items(comptime F: type, batch: *Batch(F), from: u64, to: u64) !void {
    for (from..to) |i| try batch.add(gpa, &hasher, &be(i));
}

fn add_many_matches_add(comptime F: type) !void {
    var items: [907]u64 = undefined;
    for (&items, 0..) |*item, i| item.* = i;
    const cases = [_][2]u64{
        .{ 0, 1 },   .{ 0, 127 },   .{ 0, 129 }, .{ 0, 300 },
        .{ 5, 200 }, .{ 130, 777 },
    };
    for ([_]u64{ 0, 1, 2, 3, 6, 7, 14, 30, 62, 63, 100 }) |committed| {
        var base = try build_reference(F, committed);
        defer base.deinit(gpa);
        for (cases) |case| {
            const parent_count, const count = case;
            var batch_p = try base.new_batch(gpa);
            try batch_p.add_many(gpa, &hasher, u64, items[0..parent_count]);
            const parent = try batch_p.merkleize(gpa, &base, &hasher);
            defer parent.release(gpa);
            var batch_c = parent.new_batch();
            try batch_c.add_many(gpa, &hasher, u64, items[parent_count..][0..count]);
            const c = try batch_c.merkleize(gpa, &base, &hasher);
            defer c.release(gpa);
            var expected_p = try base.new_batch(gpa);
            try add_items(F, &expected_p, 0, parent_count);
            const parent_expected = try expected_p.merkleize(gpa, &base, &hasher);
            defer parent_expected.release(gpa);
            var expected_c = parent_expected.new_batch();
            try add_items(F, &expected_c, parent_count, parent_count + count);
            const child_expected = try expected_c.merkleize(gpa, &base, &hasher);
            defer child_expected.release(gpa);
            try expect_same_batch(F, parent, parent_expected);
            try expect_same_batch(F, c, child_expected);
        }
    }
}

fn add_many_then_mutate(comptime F: type) !void {
    var base = try build_reference(F, 30);
    defer base.deinit(gpa);
    var items: [600]u64 = undefined;
    for (&items, 0..) |*item, i| item.* = i;
    var batch = try base.new_batch(gpa);
    try batch.add_many(gpa, &hasher, u64, &items);
    var expected = try base.new_batch(gpa);
    try add_items(F, &expected, 0, 600);
    for ([_]u64{ 3, 47, 629 }) |location| {
        try batch.update_leaf(gpa, &hasher, location, "updated");
        try expected.update_leaf(gpa, &hasher, location, "updated");
    }
    try batch.add(gpa, &hasher, "extra");
    try expected.add(gpa, &hasher, "extra");
    const actual = try batch.merkleize(gpa, &base, &hasher);
    defer actual.release(gpa);
    const reference = try expected.merkleize(gpa, &base, &hasher);
    defer reference.release(gpa);
    try expect_same_batch(F, actual, reference);
}

fn add_many_mixed_operations(comptime F: type) !void {
    var base = try build_reference(F, 63);
    defer base.deinit(gpa);
    base.prune_all();
    var batch_p = try base.new_batch(gpa);
    try batch_p.add(gpa, &hasher, "parent");
    const parent = try batch_p.merkleize(gpa, &base, &hasher);
    defer parent.release(gpa);
    var actual = try base.new_batch(gpa);
    try actual.add(gpa, &hasher, "parent");
    var expected = parent.new_batch();
    var items: [1000]u64 = undefined;
    for (&items, 0..) |*item, i| item.* = i;
    for ([_]u64{ 0, 1, 2, 63, 64, 127, 128, 129, 256, 511, 1000 }) |count| {
        try actual.add(gpa, &hasher, "prefix");
        try expected.add(gpa, &hasher, "prefix");
        try actual.add_many(gpa, &hasher, u64, items[0..count]);
        try add_items(F, &expected, 0, count);
        for ([_]u64{ 63, actual.leaves() / 2 + 32, actual.leaves() - 1 }) |location| {
            try actual.update_leaf(gpa, &hasher, location, "update");
            try expected.update_leaf(gpa, &hasher, location, "update");
        }
    }
    const a = try actual.merkleize(gpa, &base, &hasher);
    defer a.release(gpa);
    const e = try expected.merkleize(gpa, &base, &hasher);
    defer e.release(gpa);
    try testing.expect((try root_of(a)).eql(try root_of(e)));
    for (parent.size()..a.size()) |position| {
        try testing.expect(a.get_node(position).?.eql(e.get_node(position).?));
    }
}

fn add_many_at_limit(comptime F: type) !void {
    var tallest: u32 = 1;
    while (tallest + 1 < 63 and F.birth_offset(tallest + 1) <= F.max_leaves) tallest += 1;
    var items: [300]u64 = undefined;
    for (&items, 0..) |*item, i| item.* = i;
    const cases = [_][2]u64{
        .{ F.birth_offset(tallest) - 1, 1 },
        .{ F.max_leaves - 7, 7 },
        .{ F.max_leaves - 300, 300 },
    };
    for (cases) |case| {
        const first, const count = case;
        var positions: [merkle.max_pinned_nodes]u64 = undefined;
        const pin_count = merkle.nodes_to_pin(F, first, &positions).len;
        var pinned: [merkle.max_pinned_nodes]D = undefined;
        for (pinned[0..pin_count], 0..) |*digest, i| digest.* = fill(@intCast(i));
        var base = try Mem(F).init(gpa, &.{}, first, pinned[0..pin_count]);
        defer base.deinit(gpa);
        var batch = try base.new_batch(gpa);
        try batch.add_many(gpa, &hasher, u64, items[0..count]);
        const actual = try batch.merkleize(gpa, &base, &hasher);
        defer actual.release(gpa);
        var expected = try base.new_batch(gpa);
        try add_items(F, &expected, 0, count);
        const reference = try expected.merkleize(gpa, &base, &hasher);
        defer reference.release(gpa);
        try expect_same_batch(F, actual, reference);
    }
    // Past the limit: commonware panics, zigware returns LocationOverflow.
    var positions: [merkle.max_pinned_nodes]u64 = undefined;
    const last = F.max_leaves - 1;
    const pin_count = merkle.nodes_to_pin(F, last, &positions).len;
    const pinned: [merkle.max_pinned_nodes]D = @splat(fill(0));
    var full = try Mem(F).init(gpa, &.{}, last, pinned[0..pin_count]);
    defer full.deinit(gpa);
    var batch = try full.new_batch(gpa);
    defer batch.deinit(gpa);
    try testing.expectError(error.LocationOverflow, batch.add_many(gpa, &hasher, u64, &.{ 0, 1 }));
}

fn add_many_hashes_nodes_in_range(comptime F: type) !void {
    var items: [64]u64 = undefined;
    for (&items, 0..) |*item, i| item.* = i;
    for (0..70) |committed| {
        var base = try build_reference(F, committed);
        defer base.deinit(gpa);
        var batch = try base.new_batch(gpa);
        defer batch.deinit(gpa);
        try batch.add_many(gpa, &hasher, u64, &items);
        for (batch.appended.items, base.size()..) |digest, position| {
            if (F.position_to_location(position) != null) continue;
            const leftmost = F.leftmost_leaf(position, F.pos_to_height(position));
            try testing.expectEqual(leftmost < committed, digest.eql(std.mem.zeroes(D)));
        }
    }
}

test "add_many matches add" {
    inline for (families) |F| {
        try add_many_matches_add(F);
        try add_many_then_mutate(F);
        try add_many_mixed_operations(F);
        try add_many_at_limit(F);
        try add_many_hashes_nodes_in_range(F);
    }
}

fn updates_match_append_only_rebuild(comptime F: type) !void {
    for (1..10) |initial_len| {
        var base: Mem(F) = .empty;
        defer base.deinit(gpa);
        var initial: [9]D = undefined;
        for (initial[0..initial_len], 0..) |*digest, i| digest.* = fill(@intCast(i));
        var batch_0 = try base.new_batch(gpa);
        try batch_0.add_leaf_digests(gpa, initial[0..initial_len]);
        const committed = try batch_0.merkleize(gpa, &base, &hasher);
        defer committed.release(gpa);
        try base.apply_batch(gpa, committed);
        for (0..@as(usize, 1) << @intCast(initial_len)) |mask| {
            try update_mask_case(F, &base, initial[0..initial_len], mask);
        }
    }
}

fn update_mask_case(comptime F: type, base: *const Mem(F), initial: []const D, mask: usize) !void {
    var expected: std.ArrayList(D) = .empty;
    defer expected.deinit(gpa);
    try expected.appendSlice(gpa, initial);
    var batch = try base.new_batch(gpa);
    var index = initial.len;
    while (index > 0) {
        index -= 1;
        if (mask & (@as(usize, 1) << @intCast(index)) == 0) continue;
        const digest = fill(@intCast(32 + index));
        try batch.update_leaf(gpa, &hasher, index, "temporary");
        try batch.update_leaf_digest(gpa, index, fill(254));
        try batch.update_leaf_batched(gpa, &.{
            .{ .location = index, .digest = fill(255) },
            .{ .location = index, .digest = digest },
        });
        expected.items[index] = digest;
        if (index % 2 == 0) {
            const appended = fill(@intCast(expected.items.len));
            try batch.add_leaf_digest(gpa, appended);
            try expected.append(gpa, appended);
        }
    }
    try batch.add_leaf_digest(gpa, fill(254));
    try batch.update_leaf_digest(gpa, expected.items.len, fill(253));
    try expected.append(gpa, fill(253));
    try batch.add_leaf_digest(gpa, fill(252));
    try expected.append(gpa, fill(252));
    try testing.expectEqual(@as(usize, @popCount(mask)), batch.overwrites.count());
    const m = try batch.merkleize(gpa, base, &hasher);
    defer m.release(gpa);
    const empty: Mem(F) = .empty;
    var reference = try empty.new_batch(gpa);
    try reference.add_leaf_digests(gpa, expected.items);
    const r = try reference.merkleize(gpa, &empty, &hasher);
    defer r.release(gpa);
    try testing.expect((try root_of(m)).eql(try root_of(r)));
}

test "batch updates match an append-only rebuild" {
    inline for (families) |F| try updates_match_append_only_rebuild(F);
}

// Fuzz (`merkle_batch_operations`): appends, `add_many`, digest appends, and leaf updates
// across stacked batches, with merkleizes, applies, and prunes. Every merkleized root must
// equal a tree built by appending each final leaf digest. Commonware also splits `add_many`
// across a parallel strategy; zigware hashes it sequentially (the same digests).

const fuzz_bytes = @import("../fuzz_bytes.zig");
const codec = @import("codec");

const batch_leaf_cap = 1024;
const batch_operations_max = 48;

fn reference_root(comptime F: type, leaves: []const D) !D {
    const empty: Mem(F) = .empty;
    var batch = try empty.new_batch(gpa);
    batch.add_leaf_digests(gpa, leaves) catch |err| {
        batch.deinit(gpa);
        return err;
    };
    const m = try batch.merkleize(gpa, &empty, &hasher);
    defer m.release(gpa);
    return root_of(m);
}

fn BatchFuzz(comptime F: type) type {
    return struct {
        const Self = @This();

        base: Mem(F) = .empty,
        /// Merkleized batches not yet applied, oldest first.
        chain: std.ArrayList(*Merkleized(F)) = .empty,
        batch: ?Batch(F) = null,
        leaves: std.ArrayList(D) = .empty,

        fn deinit(self: *Self) void {
            if (self.batch) |*batch| batch.deinit(gpa);
            self.clear_chain();
            self.chain.deinit(gpa);
            self.leaves.deinit(gpa);
            self.base.deinit(gpa);
        }

        fn clear_chain(self: *Self) void {
            for (self.chain.items) |batch| batch.release(gpa);
            self.chain.clearRetainingCapacity();
        }

        fn new_batch(self: *const Self) !Batch(F) {
            const items = self.chain.items;
            if (items.len > 0) return items[items.len - 1].new_batch();
            return self.base.new_batch(gpa);
        }

        fn merkleize(self: *Self) !void {
            assert(self.batch != null);
            var batch = self.batch.?;
            self.batch = null;
            const m = try batch.merkleize(gpa, &self.base, &hasher);
            self.chain.append(gpa, m) catch |err| {
                m.release(gpa);
                return err;
            };
            const expected = try reference_root(F, self.leaves.items);
            try testing.expect((try root_of(m)).eql(expected));
        }

        fn apply(self: *Self) !void {
            try self.merkleize();
            try self.base.apply_batch(gpa, self.chain.items[self.chain.items.len - 1]);
            self.clear_chain();
        }

        fn leaf(self: *const Self, element_bytes: []const u8) D {
            const position = F.location_to_position(self.leaves.items.len);
            return hasher.leaf_digest(position, element_bytes);
        }
    };
}

fn read_limited(reader: *fuzz_bytes.Reader, buffer: *[16]u8) []const u8 {
    const len = reader.below(buffer.len + 1);
    for (buffer[0..len]) |*byte| byte.* = reader.int(u8);
    return buffer[0..len];
}

fn fuzz_add_many(comptime F: type, state: *BatchFuzz(F), reader: *fuzz_bytes.Reader) !void {
    const count = @min(reader.below(600), batch_leaf_cap - state.leaves.items.len);
    const seed = reader.int(u8);
    const storage = try gpa.alloc([6]u8, count);
    defer gpa.free(storage);
    const items = try gpa.alloc([]const u8, count);
    defer gpa.free(items);
    for (items, storage, 0..) |*item, *bytes, i| {
        const len = i % 5;
        @memset(bytes[0..len], seed);
        bytes[len] = @truncate(i);
        item.* = bytes[0 .. len + 1];
    }
    try state.batch.?.add_many(gpa, &hasher, []const u8, items);
    for (items) |item| {
        const encoded = try codec.encode([]const u8, gpa, item);
        defer gpa.free(encoded);
        try state.leaves.append(gpa, state.leaf(encoded));
    }
}

fn fuzz_add_digests(comptime F: type, state: *BatchFuzz(F), reader: *fuzz_bytes.Reader) !void {
    const count = @min(reader.below(600), batch_leaf_cap - state.leaves.items.len);
    const seed = [1]u8{reader.int(u8)};
    const digests = try gpa.alloc(D, count);
    defer gpa.free(digests);
    for (digests, 0..) |*digest, i| {
        var index: [2]u8 = undefined;
        std.mem.writeInt(u16, &index, @intCast(i), .big);
        digest.* = Sha256.hash(&.{ &seed, &index });
    }
    if (count == 1) {
        try state.batch.?.add_leaf_digest(gpa, digests[0]);
    } else {
        try state.batch.?.add_leaf_digests(gpa, digests);
    }
    try state.leaves.appendSlice(gpa, digests);
}

fn fuzz_update(comptime F: type, state: *BatchFuzz(F), reader: *fuzz_bytes.Reader) !void {
    const index = reader.int(u16) % state.leaves.items.len;
    var buffer: [16]u8 = undefined;
    const data = read_limited(reader, &buffer);
    if (index < state.base.pruning_boundary()) {
        var spare = try state.new_batch();
        defer spare.deinit(gpa);
        const result = spare.update_leaf(gpa, &hasher, index, data);
        try testing.expectError(error.ElementPruned, result);
        return;
    }
    try state.batch.?.update_leaf(gpa, &hasher, index, data);
    const position = F.location_to_position(index);
    state.leaves.items[index] = hasher.leaf_digest(position, data);
}

fn fuzz_update_digests(comptime F: type, state: *BatchFuzz(F), reader: *fuzz_bytes.Reader) !void {
    const len: u64 = state.leaves.items.len;
    const boundary = state.base.pruning_boundary();
    const seed = reader.int(u8);
    var updates: [65]Batch(F).LeafUpdate = undefined;
    var count: usize = 0;
    for (0..reader.below(65)) |_| {
        const location = reader.int(u16);
        const index = boundary + location % @max(len - boundary, 1);
        if (index >= len) continue;
        var location_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &location_bytes, location, .big);
        const digest = Sha256.hash(&.{ &.{seed}, &location_bytes });
        updates[count] = .{ .location = index, .digest = digest };
        count += 1;
    }
    if (seed % 4 == 0) {
        // A location past the end fails the whole update (checked on a spare batch).
        var invalid = updates;
        invalid[count] = .{ .location = len, .digest = Sha256.hash(&.{&.{seed}}) };
        var spare = try state.new_batch();
        defer spare.deinit(gpa);
        const result = spare.update_leaf_batched(gpa, invalid[0 .. count + 1]);
        try testing.expectError(error.LeafOutOfBounds, result);
    }
    if (count == 1) {
        try state.batch.?.update_leaf_digest(gpa, updates[0].location, updates[0].digest);
    } else {
        try state.batch.?.update_leaf_batched(gpa, updates[0..count]);
    }
    // Later updates to the same leaf win.
    for (updates[0..count]) |u| state.leaves.items[@intCast(u.location)] = u.digest;
}

fn batch_fuzz_step(comptime F: type, state: *BatchFuzz(F), reader: *fuzz_bytes.Reader) !void {
    const full = state.leaves.items.len >= batch_leaf_cap;
    const empty = state.leaves.items.len == 0;
    switch (reader.below(8)) {
        0 => if (!full) {
            var buffer: [16]u8 = undefined;
            const data = read_limited(reader, &buffer);
            try state.batch.?.add(gpa, &hasher, data);
            try state.leaves.append(gpa, state.leaf(data));
        },
        1 => try fuzz_add_many(F, state, reader),
        2 => try fuzz_add_digests(F, state, reader),
        3 => if (!empty) try fuzz_update(F, state, reader),
        4 => if (!empty) try fuzz_update_digests(F, state, reader),
        5 => {
            try state.merkleize();
            state.batch = try state.new_batch();
        },
        6 => {
            try state.apply();
            state.batch = try state.new_batch();
        },
        7 => {
            // Apply everything first, so no later batch builds on nodes pruning removes.
            try state.apply();
            const location = reader.int(u16) % (state.leaves.items.len + 1);
            if (location > state.base.pruning_boundary()) try state.base.prune(location);
            state.batch = try state.new_batch();
        },
        else => unreachable,
    }
}

fn batch_fuzz_run(bytes: []const u8) anyerror!void {
    inline for (families) |F| {
        var reader = fuzz_bytes.Reader.init(bytes);
        var state: BatchFuzz(F) = .{};
        defer state.deinit();
        for (0..reader.int(u8)) |i| {
            try state.leaves.append(gpa, Sha256.hash(&.{&.{@as(u8, @intCast(i))}}));
        }
        var initial = try state.base.new_batch(gpa);
        initial.add_leaf_digests(gpa, state.leaves.items) catch |err| {
            initial.deinit(gpa);
            return err;
        };
        const committed = try initial.merkleize(gpa, &state.base, &hasher);
        defer committed.release(gpa);
        try state.base.apply_batch(gpa, committed);
        state.batch = try state.new_batch();
        var operations: u32 = 0;
        while (!reader.done() and operations < batch_operations_max) : (operations += 1) {
            try batch_fuzz_step(F, &state, &reader);
        }
        try state.merkleize();
    }
}

test "fuzz merkle batch operations (seeded)" {
    try fuzz_bytes.seeded(512, 0x6261746368, 32, batch_fuzz_run);
}

test "fuzz merkle batch operations" {
    try testing.fuzz({}, fuzz_bytes.smith(512, batch_fuzz_run), .{});
}
