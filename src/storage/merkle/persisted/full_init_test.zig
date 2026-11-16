//! `init` recovery tests of `full.zig` against inconsistent metadata and journal states,
//! ported from commonware's `storage/src/merkle/persisted/full.rs`. Every test runs under both
//! families.

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

fn open_store(comptime F: type, harness: *Harness) !Merkle(F).Store {
    return Merkle(F).Store.init(gpa, harness.storage.interface(), .{
        .partition = "metadata-partition",
        .codec_config = .{ .range = .full(), .item = {} },
    });
}

/// A crash after the journal prune but before the metadata update left a stale boundary of 0
/// with no pins: some pins of the journal's boundary are lost, so `init` fails closed.
fn stale_metadata_returns_error(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 50);
    try structure.sync();
    try structure.prune(25);
    structure.deinit();
    var store = try open_store(F, &harness);
    store.clear();
    var bytes: [8]u8 = @splat(0);
    try store.put_sync(Key.init(full.pruned_to_prefix, 0), try gpa.dupe(u8, &bytes));
    store.deinit();
    try testing.expectError(error.MissingNode, harness.open(F));
}

/// A journal reset below the persisted pruning boundary cannot serve it.
fn rejects_prune_boundary_beyond_recovered_size(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 12);
    try structure.sync();
    try structure.prune(12);
    try structure.sync();
    structure.deinit();
    const journal_cfg = harness.cfg().journal();
    const storage = harness.storage.interface();
    const recovered_size = F.location_to_position(8);
    var journal = try fixed.Journal(D).init(gpa, storage, journal_cfg);
    try testing.expect(journal.get_bounds().start > recovered_size);
    journal.deinit();
    journal = try fixed.Journal(D).init_at_size(gpa, storage, journal_cfg, recovered_size);
    journal.deinit();
    try testing.expectError(error.MissingNode, harness.open(F));
}

/// A metadata boundary ahead of the blob-aligned journal boundary recovers to the metadata.
fn metadata_ahead(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 50);
    try structure.sync();
    try structure.prune(16);
    const root = try structure.root(hasher, 0);
    const size = structure.size();
    structure.deinit();
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(@as(u64, 16), structure.bounds().start);
    try testing.expectEqual(size, structure.size());
    try testing.expect((try structure.root(hasher, 0)).eql(root));
}

/// Adds the big-endian bytes of `0..count` as leaves.
fn add_counters(comptime F: type, structure: *Merkle(F), count: u64) !void {
    var batch = try structure.new_batch();
    for (0..count) |i| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, i, .big);
        batch.add(gpa, hasher, &bytes) catch |err| {
            batch.deinit(gpa);
            return err;
        };
    }
    const merkleized = try batch.merkleize(structure, hasher);
    defer merkleized.release(gpa);
    try structure.apply_batch(merkleized);
}

fn open_at_most(comptime F: type, harness: *Harness, cfg: full.Config, cap: u64) !Merkle(F) {
    return Merkle(F).init_at_most(gpa, harness.storage.interface(), hasher, cfg, cap);
}

fn initialization_bounds_preserve_state(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    // A cap below the pruning boundary fails without changing the retained tree.
    var structure = try harness.open(F);
    try add_counters(F, &structure, 32);
    try structure.prune(8);
    const leaves_before = structure.leaves();
    structure.deinit();
    try testing.expectError(error.ElementPruned, open_at_most(F, &harness, harness.cfg(), 7));
    structure = try harness.open(F);
    try testing.expectEqual(leaves_before, structure.leaves());
    try structure.destroy();

    // A cap above the end preserves the complete tree, including after another open.
    const cfg = harness.cfg_in("overshooting-journal", "overshooting-metadata");
    const storage = harness.storage.interface();
    structure = try Merkle(F).init(gpa, storage, hasher, cfg);
    try add_counters(F, &structure, 8);
    const root = try structure.root(hasher, 0);
    try structure.sync();
    structure.deinit();
    structure = try open_at_most(F, &harness, cfg, std.math.maxInt(u64));
    try testing.expectEqual(@as(u64, 8), structure.leaves());
    try testing.expect((try structure.root(hasher, 0)).eql(root));
    structure.deinit();
    structure = try Merkle(F).init(gpa, storage, hasher, cfg);
    try testing.expectEqual(@as(u64, 8), structure.leaves());
    try testing.expect((try structure.root(hasher, 0)).eql(root));
    structure.deinit();

    // A zero cap publishes and preserves an empty tree.
    structure = try open_at_most(F, &harness, cfg, 0);
    try testing.expectEqual(@as(u64, 0), structure.leaves());
    structure.deinit();
    structure = try Merkle(F).init(gpa, storage, hasher, cfg);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(@as(u64, 0), structure.leaves());
}

/// A crash inside a bounded open, after it truncated and pruned the journal to the durable
/// boundary but before publication, still reopens at that boundary.
fn recovery_prune_crash(comptime F: type, per_blob: u64, unbounded: bool) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    harness.items_per_blob = per_blob;
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 16);
    try structure.sync();
    // Stop a prune to 8 after its boundary and pins became durable.
    var pins_buffer: [max_pins]D = undefined;
    const pins = try structure.pinned_nodes_at(8, &pins_buffer);
    structure.deinit();
    try support.write_boundary(F, &harness, 8, pins);
    const storage = harness.storage.interface();
    var pending = try Merkle(F).Recovery.prepare(gpa, storage, hasher, harness.cfg(), .{
        .at_most = 8,
    });
    const root = try pending.mem.root(hasher, 0);
    try pending.journal.truncate(pending.retained_size);
    if (unbounded) {
        // An interrupted bounded open can leave no empty tail for ordinary recovery.
        pending.deinit();
        pending = try Merkle(F).Recovery.prepare(gpa, storage, hasher, harness.cfg(), .all);
        try pending.journal.truncate(pending.retained_size);
    }
    _ = try pending.journal.prune(pending.metadata_prune_pos);
    // Crash before publication opens the retained tail.
    pending.deinit();
    harness.storage.crash();

    structure = try harness.open(F);
    try testing.expectEqual(merkle.Range{ .start = 8, .end = 8 }, structure.bounds());
    try testing.expect((try structure.root(hasher, 0)).eql(root));
    structure.deinit();
    structure = try open_at_most(F, &harness, harness.cfg(), 8);
    defer structure.deinit();
    try testing.expect((try structure.root(hasher, 0)).eql(root));
}

test "persisted merkle init rejects stale or reset state" {
    inline for (support.families) |F| {
        try stale_metadata_returns_error(F);
        try rejects_prune_boundary_beyond_recovered_size(F);
        try metadata_ahead(F);
    }
}

test "persisted merkle initialization bounds preserve state" {
    inline for (support.families) |F| try initialization_bounds_preserve_state(F);
}

test "persisted merkle init recovery prune crash" {
    inline for (support.families) |F| {
        const boundary = F.location_to_position(8);
        for ([_]u64{ 1, 5, 7, boundary }) |per_blob| {
            try recovery_prune_crash(F, per_blob, false);
            try recovery_prune_crash(F, per_blob, true);
        }
    }
}
