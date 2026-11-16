//! Tests of the persisted MMR, ported from commonware's `storage/src/merkle/mmr/full.rs`.
//! Commonware's elements are `Sha256(i as big-endian u64)`, which is `test_digest(i)` here.
//! The batched-root, pop, and stacking tests also run under the MMB family. A failed reopen
//! leaves the structure closed, so those tests free it only on success.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../mod.zig");
const support = @import("full_test.zig");

const D = support.D;
const Harness = support.Harness;
const Merkle = support.Merkle;
const add_digests = support.add_digests;
const families = support.families;
const gpa = support.gpa;
const hasher = &support.hasher;
const test_digest = support.test_digest;

const elements_count = 200;

/// `roots[i]` is the root of an in-memory tree over `test_digest(0..i)`.
fn reference_roots(comptime F: type) ![elements_count + 1]D {
    var mem: merkle.mem.Mem(F, D) = .empty;
    defer mem.deinit(gpa);
    var roots: [elements_count + 1]D = undefined;
    roots[0] = try mem.root(hasher, 0);
    for (1..elements_count + 1) |leaves| {
        try mem.add(gpa, hasher, &test_digest(leaves - 1).bytes);
        roots[leaves] = try mem.root(hasher, 0);
    }
    assert(mem.leaves() == elements_count);
    assert(!roots[0].eql(roots[elements_count]));
    return roots;
}

fn batched_root(comptime F: type) !void {
    const roots = try reference_roots(F);
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 199);
    try testing.expect((try structure.root(hasher, 0)).eql(roots[199]));
}

test "persisted mmr batched root" {
    inline for (families) |F| try batched_root(F);
}

/// Syncs, closes, and reopens `structure` with at most `cap` leaves.
fn reopen_at_most(comptime F: type, harness: *Harness, structure: *Merkle(F), cap: u64) !void {
    assert(cap <= structure.leaves());
    try structure.sync();
    structure.deinit();
    const storage = harness.storage.interface();
    structure.* = try Merkle(F).init_at_most(gpa, storage, hasher, harness.cfg(), cap);
    assert(structure.leaves() <= cap);
}

/// Syncs, closes, and reopens `structure` without a bound.
fn reopen(comptime F: type, harness: *Harness, structure: *Merkle(F)) !void {
    try structure.sync();
    structure.deinit();
    structure.* = try harness.open(F);
    assert(structure.size() >= structure.mem.size());
}

/// Appends all elements in two batches with a sync after the first 102, so later bounded
/// openings cross the boundary from cached to journaled leaves.
fn add_with_sync(comptime F: type, structure: *Merkle(F)) !void {
    assert(structure.leaves() == 0);
    try add_digests(F, structure, 0, 102);
    try structure.sync();
    try add_digests(F, structure, 102, elements_count);
    assert(structure.leaves() == elements_count);
}

/// Reopens one leaf earlier, then two leaves earlier, until empty, checking every root.
fn pop_unpruned(comptime F: type, harness: *Harness, roots: []const D) !Merkle(F) {
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, elements_count);
    var leaves: u64 = elements_count;
    while (leaves > 0) {
        leaves -= 1;
        try reopen_at_most(F, harness, &structure, leaves);
        try testing.expect((try structure.root(hasher, 0)).eql(roots[@intCast(leaves)]));
    }
    try reopen_at_most(F, harness, &structure, 0);
    try reopen(F, harness, &structure);

    try add_with_sync(F, &structure);
    leaves = elements_count;
    while (leaves > 0) {
        leaves -= 2;
        try reopen_at_most(F, harness, &structure, leaves);
        try testing.expect((try structure.root(hasher, 0)).eql(roots[@intCast(leaves)]));
    }
    try reopen(F, harness, &structure);
    try testing.expectEqual(@as(u64, 0), structure.leaves());
    return structure;
}

fn pop(comptime F: type) !void {
    const roots = try reference_roots(F);
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try pop_unpruned(F, &harness, &roots);

    // Repeat after pruning: reopening below the cached boundary keeps the boundary pins.
    try add_with_sync(F, &structure);
    const prune_location = 50;
    const prune_position = F.location_to_position(prune_location);
    try structure.prune(prune_location);
    try reopen_at_most(F, &harness, &structure, structure.leaves() - 80);
    var oldest = try structure.proof(hasher, prune_location, 0);
    oldest.deinit(gpa);
    while (structure.size() > prune_position) {
        try reopen_at_most(F, &harness, &structure, structure.leaves() - 1);
    }
    try testing.expectEqual(@as(u64, prune_location), structure.leaves());
    try testing.expect((try structure.root(hasher, 0)).eql(roots[prune_location]));

    // Pruning to an older location is a no-op.
    try structure.prune(prune_location - 1);
    try testing.expectEqual(@as(u64, prune_location), structure.bounds().start);
    try structure.sync();
    structure.deinit();
    const storage = harness.storage.interface();
    const below = Merkle(F).init_at_most(gpa, storage, hasher, harness.cfg(), prune_location - 1);
    try testing.expectError(error.ElementPruned, below);
}

test "persisted mmr pop" {
    inline for (families) |F| try pop(F);
}

fn batch_stacking(comptime F: type) !void {
    const roots = try reference_roots(F);
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 10);
    try structure.sync();

    var batch_a = try structure.new_batch();
    for (10..15) |i| try batch_a.add(gpa, hasher, &test_digest(i).bytes);
    const merkleized_a = try batch_a.merkleize(&structure, hasher);
    defer merkleized_a.release(gpa);
    // Batch B stacks on merkleized A without applying it.
    var batch_b = merkleized_a.new_batch();
    for (15..20) |i| try batch_b.add(gpa, hasher, &test_digest(i).bytes);
    const merkleized_b = try batch_b.merkleize(gpa, &structure.mem, hasher);
    defer merkleized_b.release(gpa);
    const expected = try merkleized_b.root(hasher, 0);

    try structure.apply_batch(merkleized_b);
    try testing.expect((try structure.root(hasher, 0)).eql(expected));
    try testing.expect(expected.eql(roots[20]));
}

test "persisted mmr batch stacking" {
    inline for (families) |F| try batch_stacking(F);
}

/// init_sync's fresh start (the recovered tree ends at or before the sync start) resets the
/// journal to the range start. Two local blobs of 7 nodes recover a tree of size 8. Location
/// 100 (position 197) lies past every blob, so the journal stays unopened; location 6
/// (position 10) lies inside the second blob, so the journal opens and is found too short.
fn fresh_start_updates_journal_size(leaves: u64, opened: bool) !void {
    const F = merkle.mmr.Family;
    var harness = try Harness.init();
    defer harness.deinit();
    var local = try harness.open(F);
    try add_digests(F, &local, 0, 5);
    try local.sync();
    local.deinit();

    const storage = harness.storage.interface();
    const reference_cfg = harness.cfg_in("ref-journal", "ref-metadata");
    var reference = try Merkle(F).init(gpa, storage, hasher, reference_cfg);
    defer reference.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &reference, 0, leaves);
    var pins_buffer: [merkle.max_pinned_nodes]D = undefined;
    const pins = try reference.pinned_nodes_at(leaves, &pins_buffer);

    const expected_size = F.location_to_position(leaves);
    assert(expected_size > 8);
    assert((expected_size < 14) == opened);
    var synced = try Merkle(F).init_sync(gpa, storage, .{
        .config = harness.cfg(),
        .range = .{ .start = leaves, .end = 200 },
        .pinned_nodes = pins,
    });
    defer synced.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(expected_size, synced.size());

    // Below its start the synced tree holds only the pins, so equal roots after one more leaf
    // show init_sync placed the pins and sized the tree at the boundary.
    try add_digests(F, &synced, 999, 1000);
    try add_digests(F, &reference, 999, 1000);
    const root = try reference.root(hasher, 0);
    try testing.expect((try synced.root(hasher, 0)).eql(root));

    // Ordinary init recovers the appended leaf from the reset journal and the pins from
    // metadata.
    try reopen(F, &harness, &synced);
    try testing.expectEqual(merkle.Range{ .start = leaves, .end = leaves + 1 }, synced.bounds());
    try testing.expect((try synced.root(hasher, 0)).eql(root));
}

test "persisted mmr init_sync fresh start updates journal size" {
    try fresh_start_updates_journal_size(100, false);
    try fresh_start_updates_journal_size(6, true);
}
