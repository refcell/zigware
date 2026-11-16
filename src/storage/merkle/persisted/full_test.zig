//! Tests of `full.zig`, ported from commonware's `storage/src/merkle/persisted/full.rs`. Every
//! test runs under both families. Commonware's `drop(merkle)` is `deinit` here, and an unclean
//! shutdown is `deinit` (unsynced changes are discarded on close) or `Storage.crash`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../mod.zig");
const full = @import("full.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");

const Sha256 = cryptography.Sha256;
pub const D = Sha256.Digest;
const H = merkle.hasher.Standard(Sha256);
pub const gpa = testing.allocator;
pub const families = .{ merkle.mmr.Family, merkle.mmb.Family };
pub const hasher = H.init(.forward_fold);
pub const Key = utils.sequence.PrefixedU64;

pub fn Merkle(comptime F: type) type {
    return full.Merkle(F, D);
}

/// Commonware's `test_digest(v)`: the hash of `v` as 8 big-endian bytes.
pub fn test_digest(value: u64) D {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

pub const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    items_per_blob: u64 = 7,

    pub fn init() !Harness {
        return .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 111, 5),
        };
    }

    pub fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    pub fn cfg(self: *Harness) full.Config {
        return self.cfg_in("journal-partition", "metadata-partition");
    }

    pub fn cfg_in(self: *Harness, journal: []const u8, meta: []const u8) full.Config {
        return .{
            .journal_partition = journal,
            .metadata_partition = meta,
            .items_per_blob = self.items_per_blob,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &self.cache_ref,
        };
    }

    pub fn open(self: *Harness, comptime F: type) !Merkle(F) {
        return Merkle(F).init(gpa, self.storage.interface(), &hasher, self.cfg());
    }
};

/// Appends `test_digest(from..to)` through one batch.
pub fn add_digests(comptime F: type, structure: *Merkle(F), from: u64, to: u64) !void {
    var batch = try structure.new_batch();
    for (from..to) |i| {
        batch.add(gpa, &hasher, &test_digest(i).bytes) catch |err| {
            batch.deinit(gpa);
            return err;
        };
    }
    const merkleized = try batch.merkleize(structure, &hasher);
    defer merkleized.release(gpa);
    try structure.apply_batch(merkleized);
}

fn empty_journal_rejects_pruned_metadata(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var store = try Merkle(F).Store.init(gpa, harness.storage.interface(), .{
        .partition = "metadata-partition",
        .codec_config = .{ .range = .full(), .item = {} },
    });
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, 1, .big);
    try store.put_sync(Key.init(full.pruned_to_prefix, 0), try gpa.dupe(u8, &bytes));
    store.deinit();
    try testing.expectError(error.MissingNode, harness.open(F));
}

fn full_empty(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    try testing.expectEqual(@as(u64, 0), structure.size());
    try testing.expectError(error.ItemOutOfRange, structure.get_node(0));
    try testing.expectEqual(structure.bounds().start, structure.bounds().end);
    try structure.prune_all();
    try structure.prune(0);
    try structure.sync();
    structure.deinit();

    structure = try harness.open(F);
    try add_digests(F, &structure, 0, 1);
    try testing.expectEqual(@as(u64, 1), structure.size());
    try structure.sync();
    try testing.expect((try structure.get_node(0)) != null);
    structure.deinit();

    const storage = harness.storage.interface();
    structure = try Merkle(F).init_at_most(gpa, storage, &hasher, harness.cfg(), 0);
    try testing.expectEqual(@as(u64, 0), structure.size());
    try structure.sync();
    structure.deinit();

    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(@as(u64, 0), structure.size());
    const empty: Merkle(F).Proof = .{ .leaves = 0, .inactive_peaks = 0, .digests = &.{} };
    const no_elements: []const D = &.{};
    var root = try structure.root(&hasher, 0);
    try testing.expect(empty.verify_range_inclusion(&hasher, 0, no_elements, &root));
    try testing.expect(try empty.verify_multi_inclusion(gpa, &hasher, &.{}, no_elements, &root));
    try add_digests(F, &structure, 0, 1);
    root = try structure.root(&hasher, 0);
    try testing.expect(!empty.verify_range_inclusion(&hasher, 0, no_elements, &root));
    try testing.expect(!try empty.verify_multi_inclusion(gpa, &hasher, &.{}, no_elements, &root));
}

fn prune_out_of_bounds(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.deinit();
    try add_digests(F, &structure, 0, 1);
    try testing.expectError(error.LeafOutOfBounds, structure.prune(2));
}

fn full_basic(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable;
    const leaf_count = 255;
    try add_digests(F, &structure, 0, leaf_count);
    try testing.expectEqual(F.location_to_position(leaf_count), structure.size());
    // A proof of an element still in memory, then after the sync flushed it to the journal.
    const element = 133;
    var proof = try structure.proof(&hasher, element, 0);
    defer proof.deinit(gpa);
    const root = try structure.root(&hasher, 0);
    const bytes = test_digest(element).bytes;
    try testing.expect(proof.verify_element_inclusion(&hasher, element, &bytes, &root));
    try structure.sync();
    var flushed = try structure.proof(&hasher, element, 0);
    defer flushed.deinit(gpa);
    try testing.expect(proof.eql(&flushed));
    // A range spanning flushed elements and the last one.
    var elements: [leaf_count - element]D = undefined;
    for (&elements, element..) |*e, i| e.* = test_digest(i);
    var range = try structure.range_proof(&hasher, .{ .start = element, .end = leaf_count }, 0);
    defer range.deinit(gpa);
    try testing.expect(range.verify_range_inclusion(&hasher, element, &elements, &root));
}

fn get_nodes_matches_get_node(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable;
    // Journal-resident leaves, a pruned prefix, then memory-resident leaves on top.
    try add_digests(F, &structure, 0, 200);
    try structure.sync();
    try structure.prune(50);
    try add_digests(F, &structure, 200, 210);
    var available: std.ArrayList(u64) = .empty;
    defer available.deinit(gpa);
    var nodes: std.ArrayList(D) = .empty;
    defer nodes.deinit(gpa);
    var absent: std.ArrayList(u64) = .empty;
    defer absent.deinit(gpa);
    const all = try gpa.alloc(u64, structure.size());
    defer gpa.free(all);
    for (all, 0..) |*position, i| {
        position.* = i;
        if (try structure.get_node(i)) |node| {
            try available.append(gpa, i);
            try nodes.append(gpa, node);
        } else try absent.append(gpa, i);
    }
    try testing.expect(absent.items.len > 0 and available.items.len > 0);
    const out = try gpa.alloc(D, all.len);
    defer gpa.free(out);
    try testing.expectError(error.ElementPruned, structure.get_nodes(all, out));
    try structure.get_nodes(available.items, out[0..available.items.len]);
    for (nodes.items, out[0..available.items.len]) |e, a| try testing.expect(e.eql(a));
    var sparse: std.ArrayList(u64) = .empty;
    defer sparse.deinit(gpa);
    var index: usize = 0;
    while (index < available.items.len) : (index += 7) {
        try sparse.append(gpa, available.items[index]);
    }
    try structure.get_nodes(sparse.items, out[0..sparse.items.len]);
    for (sparse.items, out[0..sparse.items.len]) |position, node| {
        try testing.expect((try structure.get_node(position)).?.eql(node));
    }
    try structure.get_nodes(&.{}, out[0..0]);
}

fn full_flush(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable;
    try add_digests(F, &structure, 0, 100);
    const expected_size = F.location_to_position(100);
    const root = try structure.root(&hasher, 0);
    // A flush writes every cached node to the journal and prunes them from memory.
    try structure.flush();
    try testing.expectEqual(expected_size, structure.journal.size());
    try testing.expectEqual(expected_size, structure.size());
    try testing.expectEqual(@as(u64, 100), structure.mem.pruning_boundary());
    try structure.flush();
    try testing.expectEqual(expected_size, structure.journal.size());
    try testing.expect((try structure.root(&hasher, 0)).eql(root));
    var proof = try structure.proof(&hasher, 42, 0);
    defer proof.deinit(gpa);
    const bytes = test_digest(42).bytes;
    try testing.expect(proof.verify_element_inclusion(&hasher, 42, &bytes, &root));
    try structure.sync();
}

fn flush_crash(comptime F: type, sync_after_flush: bool) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    // 512 items per blob keeps both batches in the tail blob: a rollover would sync the
    // sealed predecessor.
    harness.items_per_blob = 512;
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 50);
    if (!sync_after_flush) try structure.sync();
    const synced_size = structure.size();
    try add_digests(F, &structure, 50, 100);
    try structure.flush();
    try testing.expectEqual(structure.size(), structure.journal.size());
    if (sync_after_flush) try structure.sync();
    const full_size = structure.size();
    harness.storage.crash();
    structure.deinit();
    var recovered = try harness.open(F);
    defer recovered.deinit();
    try testing.expectEqual(if (sync_after_flush) full_size else synced_size, recovered.size());
}

fn full_recovery(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    const leaf_count = 252;
    try add_digests(F, &structure, 0, leaf_count);
    const expected_size = F.location_to_position(leaf_count);
    try structure.sync();
    structure.deinit();
    // A crash that wrote a leaf but not its parents: one extra digest in the journal.
    {
        const journal_cfg = harness.cfg().journal();
        var journal = try fixed.Journal(D).init(gpa, harness.storage.interface(), journal_cfg);
        defer journal.deinit();
        try testing.expectEqual(expected_size, journal.size());
        _ = try journal.append(Sha256.hash(&.{"orphan"}));
        try journal.sync();
    }
    // The orphan leaf is replayed: the previous state plus one leaf, persisted on reopen.
    const recovered_size = F.location_to_position(leaf_count + 1);
    structure = try harness.open(F);
    try testing.expectEqual(recovered_size, structure.size());
    structure.deinit();
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable;
    try testing.expectEqual(recovered_size, structure.size());
}

fn add_one(comptime F: type, structure: *Merkle(F), value: u64) !void {
    try add_digests(F, structure, value, value + 1);
}

fn expect_same_root(comptime F: type, a: *const Merkle(F), b: *const Merkle(F)) !void {
    try testing.expect((try a.root(&hasher, 0)).eql(try b.root(&hasher, 0)));
}

fn full_pruning(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const storage = harness.storage.interface();
    const leaf_count = 2000;
    var pruned = try harness.open(F);
    const unpruned_cfg = harness.cfg_in("unpruned-journal-partition", "unpruned-metadata");
    var reference = try Merkle(F).init(gpa, storage, &hasher, unpruned_cfg);
    defer reference.destroy() catch unreachable;
    try add_digests(F, &reference, 0, leaf_count);
    try add_digests(F, &pruned, 0, leaf_count);
    for (0..300) |i| {
        const prune_loc = @min(i * 10, pruned.leaves());
        try pruned.prune(prune_loc);
        try testing.expectEqual(prune_loc, pruned.bounds().start);
        try add_one(F, &pruned, leaf_count + i);
        try add_one(F, &reference, leaf_count + i);
        try expect_same_root(F, &pruned, &reference);
    }
    try pruned.sync();
    try expect_same_root(F, &pruned, &reference);
    pruned.deinit();

    // Reopen, prune everything, and grow past a blob boundary.
    pruned = try harness.open(F);
    try expect_same_root(F, &pruned, &reference);
    const size = pruned.size();
    try pruned.prune_all();
    try expect_same_root(F, &pruned, &reference);
    const leaves_at_size = F.position_to_location(size).?;
    const emptied: merkle.Range = .{ .start = leaves_at_size, .end = leaves_at_size };
    try testing.expectEqual(emptied, pruned.bounds());
    try add_one(F, &reference, leaf_count);
    try add_one(F, &pruned, leaf_count);
    try testing.expect(pruned.size() % harness.items_per_blob != 0);
    try pruned.sync();
    pruned.deinit();

    pruned = try harness.open(F);
    defer pruned.destroy() catch unreachable;
    try expect_same_root(F, &pruned, &reference);
    try testing.expectEqual(leaves_at_size, pruned.bounds().start);
    try testing.expect(pruned.bounds().start < pruned.bounds().end);
    // Pruning below the boundary is a no-op.
    try pruned.prune(leaves_at_size - 1);
    try testing.expectEqual(leaves_at_size, pruned.bounds().start);
    while (pruned.size() % harness.items_per_blob != 0) try add_one(F, &pruned, leaf_count);
    try pruned.prune_all();
    try testing.expectEqual(pruned.bounds().end, pruned.bounds().start);
}

fn recovery_with_pruning(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const leaf_count = 2000;
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, leaf_count);
    try testing.expectEqual(F.location_to_position(leaf_count), structure.size());
    try structure.sync();
    structure.deinit();
    for (0..200) |i| {
        structure = try harness.open(F);
        // Reopening completes an interrupted prune: the journal starts within a blob of it.
        const journal_start = structure.journal.pruning_boundary();
        try testing.expect(structure.pruned_to_pos - journal_start < harness.items_per_blob);
        const start_size = structure.size();
        const prune_loc = @min(i * 50, structure.leaves());
        if (i % 5 == 0) {
            try structure.simulate_pruning_failure(prune_loc);
            continue;
        }
        try structure.prune(prune_loc);
        for (0..10) |j| {
            // Commonware adds each digest twice.
            for ([_]u64{ 100 * (i + 1) + j, leaf_count + i }) |value| {
                var batch = try structure.new_batch();
                try batch.add(gpa, &hasher, &test_digest(value).bytes);
                try batch.add(gpa, &hasher, &test_digest(value).bytes);
                const merkleized = try batch.merkleize(&structure, &hasher);
                defer merkleized.release(gpa);
                try structure.apply_batch(merkleized);
            }
        }
        const total = structure.size() - start_size;
        try structure.simulate_partial_sync(i % total);
    }
    structure = try harness.open(F);
    try structure.destroy();
}

test "persisted merkle rejects pruned metadata over an empty journal" {
    inline for (families) |F| try empty_journal_rejects_pruned_metadata(F);
}

test "persisted merkle empty, basic, and out-of-bounds prune" {
    inline for (families) |F| {
        try full_empty(F);
        try full_basic(F);
        try prune_out_of_bounds(F);
    }
}

test "persisted merkle get_nodes matches get_node" {
    inline for (families) |F| try get_nodes_matches_get_node(F);
}

test "persisted merkle flush and crash recovery" {
    inline for (families) |F| {
        try full_flush(F);
        try flush_crash(F, false);
        try flush_crash(F, true);
        try full_recovery(F);
    }
}

test "persisted merkle pruning" {
    inline for (families) |F| try full_pruning(F);
}

test "persisted merkle recovery with pruning" {
    inline for (families) |F| try recovery_with_pruning(F);
}
