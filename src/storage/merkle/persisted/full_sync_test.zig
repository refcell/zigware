//! `init_sync` tests of `full.zig`, ported from commonware's
//! `storage/src/merkle/persisted/full.rs`. Every test runs under both families. Commonware's
//! storage fault injection becomes the mock storage's removal and mutation budgets, swept
//! deterministically instead of sampled by seed.

const std = @import("std");
const testing = std.testing;
const merkle = @import("../mod.zig");
const full = @import("full.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const support = @import("full_test.zig");

const D = support.D;
const Harness = support.Harness;
const Key = support.Key;
const Merkle = support.Merkle;
const add_digests = support.add_digests;
const gpa = support.gpa;
const hasher = &support.hasher;
const max_pins = merkle.max_pinned_nodes;
const write_boundary = support.write_boundary;

fn init_sync(
    comptime F: type,
    harness: *Harness,
    start: u64,
    end: u64,
    pins: ?[]const D,
) !Merkle(F) {
    return Merkle(F).init_sync(gpa, harness.storage.interface(), .{
        .config = harness.cfg(),
        .range = .{ .start = start, .end = end },
        .pinned_nodes = pins,
    });
}

/// A synced tree of `test_digest(0..leaves)` in `cfg`'s partitions.
fn seed_tree(comptime F: type, harness: *Harness, cfg: full.Config, leaves: u64) !Merkle(F) {
    const storage = harness.storage.interface();
    var structure = try Merkle(F).init(gpa, storage, hasher, cfg);
    errdefer structure.deinit();
    try add_digests(F, &structure, 0, leaves);
    try structure.sync();
    return structure;
}

fn expect_bounds(structure: anytype, start: u64, end: u64) !void {
    try testing.expectEqual(merkle.Range{ .start = start, .end = end }, structure.bounds());
}

fn expect_root(structure: anytype, expected: D) !void {
    try testing.expect((try structure.root(hasher, 0)).eql(expected));
}

fn init_sync_empty(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    // Fresh initialization must not reset or remove any journal storage.
    harness.storage.remove_failures_after = 0;
    var structure = try init_sync(F, &harness, 0, 52, null);
    harness.storage.remove_failures_after = null;
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(@as(u64, 0), structure.size());
    try expect_bounds(&structure, 0, 0);
    try add_digests(F, &structure, 999, 1000);
    _ = try structure.root(hasher, 0);
}

/// A retry over a node journal the first attempt left empty at the sync start keeps it.
fn empty_at_start_keeps_journal(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const start = 16;
    const end = 32;
    const prune_pos = F.location_to_position(start);
    // Take the boundary pins and the expected root from a reference tree of `end` leaves.
    const reference_cfg = harness.cfg_in("reference-journal", "reference-metadata");
    var reference = try seed_tree(F, &harness, reference_cfg, end);
    const root = try reference.root(hasher, 0);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try reference.pinned_nodes_at(start, &pins_buffer);
    try reference.destroy();

    // The first sync resets fresh storage, leaving the node journal empty at the sync start.
    var structure = try init_sync(F, &harness, start, end, pins);
    try testing.expectEqual(prune_pos, structure.size());
    structure.deinit();

    // The retry finds the journal empty at the sync start and keeps it: any removal fails.
    harness.storage.remove_failures_after = 0;
    structure = try init_sync(F, &harness, start, end, pins);
    harness.storage.remove_failures_after = null;
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(prune_pos, structure.size());
    // The kept journal extends from the boundary pins to the reference root.
    try add_digests(F, &structure, start, end);
    try expect_root(&structure, root);
}

/// Reads every node in `[from, to)`.
fn read_nodes(comptime F: type, structure: *Merkle(F), from: u64, to: u64) ![]?D {
    const nodes = try gpa.alloc(?D, @intCast(to - from));
    errdefer gpa.free(nodes);
    for (nodes, from..) |*node, position| node.* = try structure.get_node(position);
    return nodes;
}

/// `init_sync` over a range that contains the persisted data, optionally pruned to
/// `prune_to`, reuses it; the range ends `extend` leaves past the data.
fn init_sync_reuses(comptime F: type, leaves: u64, prune_to: u64, extend: u64) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try seed_tree(F, &harness, harness.cfg(), leaves);
    if (prune_to > 0) try structure.prune(prune_to);
    const size = structure.size();
    const root = try structure.root(hasher, 0);
    const boundary = structure.bounds().start;
    const boundary_pos = F.location_to_position(boundary);
    const expected = try read_nodes(F, &structure, boundary_pos, size);
    defer gpa.free(expected);
    try structure.sync();
    structure.deinit();

    structure = try init_sync(F, &harness, boundary, leaves + extend, null);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(size, structure.size());
    try testing.expectEqual(leaves, structure.leaves());
    try expect_bounds(&structure, boundary, leaves);
    try expect_root(&structure, root);
    const actual = try read_nodes(F, &structure, boundary_pos, size);
    defer gpa.free(actual);
    for (expected, actual) |a, b| try testing.expect(a.?.eql(b.?));
}

/// Syncing from pins recovered from local storage reopens, and extends, as the same tree.
fn recovered_pins_reopen(comptime F: type, leaves: u64, start: u64, end: u64) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try seed_tree(F, &harness, harness.cfg(), leaves);
    const root = try structure.root(hasher, 0);
    structure.deinit();

    structure = try init_sync(F, &harness, start, end, null);
    try expect_root(&structure, root);
    try structure.sync();
    structure.deinit();

    // Reopen the synchronized prefix and extend it by one leaf.
    structure = try harness.open(F);
    try expect_bounds(&structure, start, leaves);
    try expect_root(&structure, root);
    try add_digests(F, &structure, leaves, leaves + 1);
    const appended_root = try structure.root(hasher, 0);
    try structure.sync();
    structure.deinit();

    // A second reopen recovers the extended root.
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(leaves + 1, structure.leaves());
    try expect_root(&structure, appended_root);
}

/// An interrupted sync left metadata (boundary 16 and its pins) ahead of a 4-leaf journal.
fn metadata_ahead_of_journal(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const source_cfg = harness.cfg_in("source-journal", "source-metadata");
    var source = try seed_tree(F, &harness, source_cfg, 16);
    const root = try source.root(hasher, 0);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try source.pinned_nodes_at(16, &pins_buffer);
    try source.destroy();
    var structure = try seed_tree(F, &harness, harness.cfg(), 4);
    structure.deinit();
    try write_boundary(F, &harness, 16, pins);

    try testing.expectError(error.MissingNode, harness.open(F));
    structure = try init_sync(F, &harness, 16, 32, null);
    try expect_bounds(&structure, 16, 16);
    try expect_root(&structure, root);
    structure.deinit();
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try expect_bounds(&structure, 16, 16);
    try expect_root(&structure, root);
}

/// A crash at every mutation of a sync from recovered pins leaves a tree that reopens whole
/// and a retry that completes the sync.
fn recovered_pins_crash(comptime F: type, leaves: u64, start: u64, end: u64) !void {
    var budget: u64 = 0;
    while (budget < 1_000) : (budget += 1) {
        var harness = try Harness.init();
        defer harness.deinit();
        var structure = try seed_tree(F, &harness, harness.cfg(), leaves);
        const root = try structure.root(hasher, 0);
        structure.deinit();
        harness.storage.allow_mutations(budget);
        if (init_sync(F, &harness, start, end, null)) |synced| {
            var interrupted = synced;
            interrupted.deinit();
        } else |_| {}
        const refused = harness.storage.mutation_refused;
        harness.storage.mutations_allowed = null;
        harness.storage.crash();

        structure = try harness.open(F);
        try testing.expectEqual(leaves, structure.leaves());
        try expect_root(&structure, root);
        structure.deinit();
        structure = try init_sync(F, &harness, start, end, null);
        defer structure.deinit();
        try expect_bounds(&structure, start, leaves);
        try expect_root(&structure, root);
        if (!refused) return;
    }
    return error.TestUnexpectedResult; // The sync never completed within the budget.
}

test "persisted merkle init_sync empty" {
    inline for (support.families) |F| try init_sync_empty(F);
}

test "persisted merkle init_sync empty at start keeps journal" {
    inline for (support.families) |F| try empty_at_start_keeps_journal(F);
}

test "persisted merkle init_sync nonempty exact match and partial overlap" {
    inline for (support.families) |F| {
        try init_sync_reuses(F, 50, 0, 0);
        try init_sync_reuses(F, 30, 6, 6);
    }
}

test "persisted merkle init_sync recovered pins reopen" {
    inline for (support.families) |F| {
        try recovered_pins_reopen(F, 16, 16, 32); // Reset at an exact end.
        try recovered_pins_reopen(F, 100, 32, 128); // Reuse of a retained suffix.
    }
}

test "persisted merkle init_sync metadata ahead of journal" {
    inline for (support.families) |F| try metadata_ahead_of_journal(F);
}

test "persisted merkle init_sync recovered pins crash" {
    inline for (support.families) |F| {
        try recovered_pins_crash(F, 16, 16, 32);
        try recovered_pins_crash(F, 100, 32, 128);
    }
}

/// A metadata pin stays authoritative even when the journal holds its digest.
fn rejects_malformed_metadata_pin(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const boundary = 11;
    // Pruning to 10 stores the pins of 10 in metadata; pick one also pinned by 11.
    var structure = try seed_tree(F, &harness, harness.cfg(), 22);
    try structure.prune(10);
    var positions_buffer: [max_pins]u64 = undefined;
    const position = for (merkle.nodes_to_pin(F, boundary, &positions_buffer)) |position| {
        if (structure.metadata.get(Key.init(full.node_prefix, position)) != null) break position;
    } else unreachable; // Every family shares a pin between adjacent boundaries here.
    _ = try structure.journal.read(position);
    const key = Key.init(full.node_prefix, position);
    if (try structure.metadata.put(key, try gpa.dupe(u8, ""))) |old| gpa.free(old);
    try structure.metadata.sync();
    structure.deinit();
    try testing.expectError(error.DataCorrupted, init_sync(F, &harness, boundary, 22, null));
}

/// Without caller pins, a boundary pin in neither metadata nor the journal fails with
/// `MissingNode` before any reset, so the local tree still reopens.
fn rejects_missing_pin(comptime F: type, leaves: u64) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try seed_tree(F, &harness, harness.cfg(), leaves);
    const root = try structure.root(hasher, 0);
    structure.deinit();
    try testing.expectError(error.MissingNode, init_sync(F, &harness, 6, 12, null));
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(leaves, structure.leaves());
    try expect_root(&structure, root);
}

/// Local state past the range end is truncated to it.
fn truncates_state_beyond_range(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 20);
    const target_root = try structure.root(hasher, 0);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try structure.pinned_nodes_at(7, &pins_buffer);
    try add_digests(F, &structure, 20, 50);
    try structure.sync();
    structure.deinit();

    structure = try init_sync(F, &harness, 7, 20, pins);
    try testing.expectEqual(@as(u64, 20), structure.leaves());
    try expect_root(&structure, target_root);
    try structure.sync();
    structure.deinit();
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(@as(u64, 20), structure.leaves());
    try expect_root(&structure, target_root);
}

/// Local state pruned past the range start cannot serve it and is discarded.
fn discards_state_pruned_past_range(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 50);
    const target_root = try structure.root(hasher, 0);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try structure.pinned_nodes_at(7, &pins_buffer);
    try structure.sync();
    try structure.prune(30);
    try structure.sync();
    try testing.expect(structure.bounds().start > 7);
    structure.deinit();

    structure = try init_sync(F, &harness, 7, 60, pins);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try expect_bounds(&structure, 7, 7);
    try add_digests(F, &structure, 7, 50);
    try expect_root(&structure, target_root);
}

/// Pins of an older pruning boundary left in metadata never override the synced tree's.
fn discards_stale_pinned_metadata(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try seed_tree(F, &harness, harness.cfg(), 40);
    try structure.prune(30);
    try structure.sync();
    structure.deinit();
    const target_cfg = harness.cfg_in("target-journal-partition", "target-metadata-partition");
    var target = try Merkle(F).init(gpa, harness.storage.interface(), hasher, target_cfg);
    try add_digests(F, &target, 1_000, 1_020);
    const target_root = try target.root(hasher, 0);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try target.pinned_nodes_at(7, &pins_buffer);
    try target.destroy();

    structure = try init_sync(F, &harness, 7, 20, pins);
    try add_digests(F, &structure, 1_007, 1_020);
    try expect_root(&structure, target_root);
    try structure.sync();
    structure.deinit();
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try expect_root(&structure, target_root);
}

fn rejects_extra_pinned_nodes(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const pins = [_]D{ support.test_digest(1), support.test_digest(2), support.test_digest(3) };
    try testing.expectError(error.InvalidPinnedNodes, init_sync(F, &harness, 6, 20, &pins));
}

/// Without caller pins over an unpruned journal, the pins are read before pruning.
fn computes_pinned_nodes_before_pruning(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try seed_tree(F, &harness, harness.cfg(), 100);
    const size = structure.size();
    const root = try structure.root(hasher, 0);
    structure.deinit();
    structure = try init_sync(F, &harness, 32, 128, null);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(size, structure.size());
    try expect_root(&structure, root);
    try testing.expectEqual(@as(u64, 32), structure.bounds().start);
}

test "persisted merkle init_sync rejects malformed, missing, and extra pins" {
    inline for (support.families) |F| {
        try rejects_malformed_metadata_pin(F);
        try rejects_missing_pin(F, 5); // The journal opens; the pin lies past its end.
        try rejects_missing_pin(F, 3); // The journal stays unopened.
        try rejects_extra_pinned_nodes(F);
    }
}

test "persisted merkle init_sync truncates or discards local state outside the range" {
    inline for (support.families) |F| {
        try truncates_state_beyond_range(F);
        try discards_state_pruned_past_range(F);
        try discards_stale_pinned_metadata(F);
        try computes_pinned_nodes_before_pruning(F);
    }
}

/// A journal at an invalid size (a crash wrote a leaf but not its parents) is truncated to
/// the last complete tree.
fn recovers_from_invalid_journal_size(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try seed_tree(F, &harness, harness.cfg(), 3);
    const valid_size = structure.size();
    const valid_root = try structure.root(hasher, 0);
    structure.deinit();
    {
        const journal_cfg = harness.cfg().journal();
        var journal = try fixed.Journal(D).init(gpa, harness.storage.interface(), journal_cfg);
        defer journal.deinit();
        try testing.expectEqual(valid_size, journal.size());
        _ = try journal.append(support.test_digest(999));
        try journal.sync();
        try testing.expectEqual(valid_size + 1, journal.size());
    }
    structure = try init_sync(F, &harness, 0, 100, null);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(valid_size, structure.size());
    try expect_root(&structure, valid_root);
}

/// Appends `test_digest(from..16)`, syncs, and checks that a reopen recovers the root.
fn rebuild_and_reopen(comptime F: type, harness: *Harness, structure: *Merkle(F), from: u64) !void {
    try add_digests(F, structure, from, 16);
    const root = try structure.root(hasher, 0);
    try structure.sync();
    structure.deinit();
    structure.* = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try expect_root(structure, root);
}

/// A genesis sync after an interrupted sync persisted pins of another history drops them.
fn genesis_drops_stale_pins(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var positions_buffer: [max_pins]u64 = undefined;
    var pins: [max_pins]D = undefined;
    const positions = merkle.nodes_to_pin(F, 16, &positions_buffer);
    for (pins[0..positions.len], 0..) |*pin, i| pin.* = support.test_digest(1_000 + i);
    try write_boundary(F, &harness, 16, pins[0..positions.len]);
    var structure = try init_sync(F, &harness, 0, 16, null);
    try expect_bounds(&structure, 0, 0);
    try rebuild_and_reopen(F, &harness, &structure, 0);
}

/// A sync to a lower range drops the pins an interrupted sync to a higher one persisted.
fn lower_range_drops_future_pins(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try seed_tree(F, &harness, harness.cfg(), 8);
    structure.deinit();
    const source_cfg = harness.cfg_in("journal-source", "metadata-source");
    var source = try seed_tree(F, &harness, source_cfg, 16);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try source.pinned_nodes_at(16, &pins_buffer);
    try source.destroy();
    try write_boundary(F, &harness, 16, pins);

    structure = try init_sync(F, &harness, 2, 8, null);
    try expect_bounds(&structure, 2, 8);
    // A replacement suffix through the abandoned boundary.
    try add_digests(F, &structure, 1_008, 1_016);
    const root = try structure.root(hasher, 0);
    try structure.sync();
    structure.deinit();
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try expect_root(&structure, root);
}

test "persisted merkle init_sync recovers from an invalid journal size" {
    inline for (support.families) |F| try recovers_from_invalid_journal_size(F);
}

test "persisted merkle init_sync drops stale and future pins" {
    inline for (support.families) |F| {
        try genesis_drops_stale_pins(F);
        try lower_range_drops_future_pins(F);
    }
}
