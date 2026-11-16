//! The `merkle_full_operations` fuzz target from commonware's storage/fuzz: random adds,
//! batched adds, reads, proofs, historical proofs, syncs, prunes, reopens, and syncs into a
//! second structure, under both families, against a reference list of leaves. Each run also
//! checks the final root against one rebuilt from the reference, which commonware's target
//! does not. Leaf data is capped at 16 bytes (commonware: 64), and proof ranges are drawn
//! within the current leaves (commonware: any `u8` pair), so short inputs reach verification.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const support = @import("full_test.zig");

const D = support.D;
const Harness = support.Harness;
const Merkle = support.Merkle;
const gpa = support.gpa;
const hasher = &support.hasher;

const operations_max = 64;
const data_max = 16;
const range_max = 1_000;

const Leaf = struct { data: [data_max]u8, len: usize };

fn read_leaf(reader: *fuzz_bytes.Reader) Leaf {
    var leaf: Leaf = .{ .data = undefined, .len = reader.below(data_max + 1) };
    for (leaf.data[0..leaf.len]) |*byte| byte.* = reader.int(u8);
    return leaf;
}

/// The root of a fresh tree over the first `count` reference leaves.
fn reference_root(comptime F: type, leaves: []const Leaf, count: u64) !D {
    var mem: merkle.mem.Mem(F, D) = .empty;
    defer mem.deinit(gpa);
    for (leaves[0..@intCast(count)]) |*leaf| try mem.add(gpa, hasher, leaf.data[0..leaf.len]);
    return mem.root(hasher, 0);
}

fn contains(range: merkle.Range, location: u64) bool {
    return location >= range.start and location < range.end;
}

fn State(comptime F: type) type {
    return struct {
        const Self = @This();

        harness: *Harness,
        structure: Merkle(F),
        leaves: std.ArrayList(Leaf) = .empty,
        /// Leaf counts valid for historical proofs against the current lineage.
        historical: std.ArrayList(u64) = .empty,

        fn deinit(self: *Self) void {
            self.structure.deinit();
            self.leaves.deinit(gpa);
            self.historical.deinit(gpa);
        }

        /// Adds `items` (non-empty ones only) through one batch.
        fn add(self: *Self, items: []const Leaf) !void {
            const size_before = self.structure.size();
            const leaves_before = self.structure.leaves();
            var added: u64 = 0;
            var batch = try self.structure.new_batch();
            for (items) |*item| {
                if (item.len == 0) continue;
                try testing.expectEqual(leaves_before + added, batch.leaves());
                batch.add(gpa, hasher, item.data[0..item.len]) catch |err| {
                    batch.deinit(gpa);
                    return err;
                };
                try self.leaves.append(gpa, item.*);
                added += 1;
                try self.historical.append(gpa, leaves_before + added);
            }
            const merkleized = try batch.merkleize(&self.structure, hasher);
            defer merkleized.release(gpa);
            try self.structure.apply_batch(merkleized);
            try testing.expectEqual(leaves_before + added, self.structure.leaves());
            if (added > 0) try testing.expect(self.structure.size() > size_before);
        }

        fn elements(self: *const Self, range: merkle.Range) ![][]const u8 {
            const out = try gpa.alloc([]const u8, @intCast(range.end - range.start));
            for (out, self.leaves.items[@intCast(range.start)..@intCast(range.end)]) |*e, *l| {
                e.* = l.data[0..l.len];
            }
            return out;
        }

        fn proof(self: *Self, reader: *fuzz_bytes.Reader) !void {
            const leaves = self.structure.leaves();
            if (leaves == 0) return;
            const location = reader.int(u64) % leaves;
            if (!contains(self.structure.bounds(), location)) return;
            var result = self.structure.proof(hasher, location, 0) catch return;
            defer result.deinit(gpa);
            const root = try self.structure.root(hasher, 0);
            const leaf = &self.leaves.items[@intCast(location)];
            const element = leaf.data[0..leaf.len];
            try testing.expect(result.verify_element_inclusion(hasher, location, element, &root));
        }

        fn range_proof(self: *Self, reader: *fuzz_bytes.Reader) !void {
            const leaves = self.structure.leaves();
            if (leaves == 0) return;
            const start = reader.below(leaves);
            const end = start + 1 + reader.below(leaves - start);
            if (!contains(self.structure.bounds(), start)) return;
            const range: merkle.Range = .{ .start = start, .end = end };
            var result = self.structure.range_proof(hasher, range, 0) catch return;
            defer result.deinit(gpa);
            const root = try self.structure.root(hasher, 0);
            const items = try self.elements(range);
            defer gpa.free(items);
            try testing.expect(result.verify_range_inclusion(hasher, start, items, &root));
        }

        fn historical_range_proof(self: *Self, reader: *fuzz_bytes.Reader) !void {
            const requested = if (self.historical.items.len == 0)
                self.structure.leaves()
            else
                self.historical.items[reader.below(self.historical.items.len)];
            // Mostly within the requested leaves; one in eight spills past them.
            const spill: u64 = if (reader.below(8) == 0) 4 else 0;
            const span = requested + 1 + spill;
            const start = reader.below(span);
            const end = start + reader.below(span - start + 1);
            const range: merkle.Range = .{ .start = start, .end = end };
            const expected_root = try reference_root(F, self.leaves.items, requested);
            const structure = &self.structure;
            var result = structure.historical_range_proof(hasher, requested, range, 0) catch |err|
                switch (err) {
                    error.RangeOutOfBounds => return testing.expect(range.end > requested),
                    error.Empty => return testing.expectEqual(start, end),
                    error.ElementPruned => {
                        return testing.expect(!contains(self.structure.bounds(), start));
                    },
                    else => return err,
                };
            defer result.deinit(gpa);
            const items = try self.elements(range);
            defer gpa.free(items);
            try testing.expect(result.verify_range_inclusion(hasher, start, items, &expected_root));
        }

        /// Reopens the structure; unsynced leaves are lost.
        fn reinit(self: *Self) !void {
            self.structure.deinit();
            self.structure = undefined;
            self.structure = try self.harness.open(F);
            const recovered: usize = @intCast(self.structure.leaves());
            assert(recovered <= self.leaves.items.len);
            self.leaves.shrinkRetainingCapacity(recovered);
            self.historical.shrinkRetainingCapacity(@min(recovered, self.historical.items.len));
        }

        /// Syncs a second structure (in other partitions) to a random range.
        fn init_sync(self: *Self, reader: *fuzz_bytes.Reader) !void {
            const lower = reader.int(u16) % range_max;
            const upper = lower + reader.int(u16) % range_max + 1;
            const cfg = self.harness.cfg_in("sync-journal", "sync-metadata");
            var synced = Merkle(F).init_sync(gpa, self.harness.storage.interface(), .{
                .config = cfg,
                .range = .{ .start = lower, .end = upper },
            }) catch return;
            try testing.expect(synced.leaves() <= upper);
            try testing.expectEqual(lower, synced.bounds().start);
            try synced.destroy();
        }
    };
}

fn step(comptime F: type, state: *State(F), reader: *fuzz_bytes.Reader) !void {
    const structure = &state.structure;
    switch (reader.below(16)) {
        0 => try state.add(&.{read_leaf(reader)}),
        1 => {
            var items: [4]Leaf = undefined;
            const count = reader.below(items.len + 1);
            for (items[0..count]) |*item| item.* = read_leaf(reader);
            try state.add(items[0..count]);
        },
        2 => if (structure.get_node(reader.int(u64))) |_| {} else |_| {},
        3 => try state.proof(reader),
        4 => try state.range_proof(reader),
        5 => try state.historical_range_proof(reader),
        6 => try structure.sync(),
        7 => try structure.prune_all(),
        8 => if (structure.size() > 0) {
            try structure.prune(reader.int(u64) % (structure.leaves() + 1));
            try testing.expect(structure.bounds().start <= structure.leaves());
        },
        9 => _ = try structure.root(hasher, 0),
        10, 11 => try testing.expect(structure.leaves() <= structure.size()),
        12 => try testing.expect(structure.bounds().start <= structure.leaves()),
        13 => {
            const bounds = structure.bounds();
            if (bounds.start != bounds.end) try testing.expect(bounds.start < structure.leaves());
        },
        14 => try state.reinit(),
        15 => try state.init_sync(reader),
        else => unreachable,
    }
}

fn run_family(comptime F: type, bytes: []const u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var state: State(F) = .{ .harness = &harness, .structure = try harness.open(F) };
    defer state.deinit();
    var reader = fuzz_bytes.Reader.init(bytes);
    var operations: u32 = 0;
    while (!reader.done() and operations < operations_max) : (operations += 1) {
        try step(F, &state, &reader);
    }
    const leaves: u64 = state.leaves.items.len;
    try testing.expectEqual(leaves, state.structure.leaves());
    const expected = try reference_root(F, state.leaves.items, leaves);
    try testing.expect(expected.eql(try state.structure.root(hasher, 0)));
}

fn full_operations_run(bytes: []const u8) anyerror!void {
    inline for (support.families) |F| try run_family(F, bytes);
}

test "fuzz merkle full operations (seeded)" {
    try fuzz_bytes.seeded(1024, 0x66756c6c6f7073, 32, full_operations_run);
}

test "fuzz merkle full operations" {
    try testing.fuzz({}, fuzz_bytes.smith(1024, full_operations_run), .{});
}

// merkle_full_recovery: appends interleaved with sync, flush, start_sync, and prunes under a
// mutation budget (every mutation after the first `n` fails, as a dead disk), with removal
// faults armed only around prunes so a prune can fail after removing some blobs. After the
// first failure the storage crashes; a faulted recovery attempt may crash again; then a clean
// recovery must land within the tracked durable floors and attempted ceilings, match a
// rebuilt reference tree node for node, and still write durably. Commonware samples fault
// rates per operation; syncs complete synchronously here, so `start_sync` is a barrier.

const recovery_operations_max = 48;

const Faults = struct { harness: *Harness, remove_budget: ?u32 };

const Expected = struct {
    min_size: u64 = 0,
    max_size: u64 = 0,
    min_leaves: u64 = 0,
    max_leaves: u64 = 0,
    min_pruned: u64 = 0,
    max_pruned: u64 = 0,
    leaves: std.ArrayList([8]u8) = .empty,

    /// A completed barrier made the structure's current state durable.
    fn barrier(self: *Expected, structure: anytype) void {
        self.min_size = structure.size();
        self.min_leaves = structure.leaves();
        self.max_size = @max(self.max_size, self.min_size);
        self.max_leaves = @max(self.max_leaves, self.min_leaves);
        assert(self.min_size <= self.max_size);
    }
};

/// Prunes to `location` with removal faults armed; false once the prune fails.
fn faulted_prune(structure: anytype, faults: Faults, expected: *Expected, location: u64) bool {
    if (location <= structure.bounds().start) return true;
    faults.harness.storage.remove_failures_after = faults.remove_budget;
    defer faults.harness.storage.remove_failures_after = null;
    structure.prune(location) catch {
        // A torn removal fails after metadata durably recorded the boundary.
        expected.max_pruned = @max(expected.max_pruned, location);
        return false;
    };
    expected.min_pruned = structure.bounds().start;
    expected.max_pruned = expected.min_pruned;
    // Prune completes a durable sync before touching metadata.
    expected.barrier(structure);
    return true;
}

/// Runs operations until one fails; returns the bounds a recovery must respect.
fn recovery_operations(
    comptime F: type,
    structure: *Merkle(F),
    faults: Faults,
    reader: *fuzz_bytes.Reader,
    expected: *Expected,
) !void {
    var operations: u32 = 0;
    while (!reader.done() and operations < recovery_operations_max) : (operations += 1) {
        switch (reader.below(6)) {
            0 => {
                const data: [8]u8 = @bitCast(reader.int(u64));
                try support_add(F, structure, &data);
                try expected.leaves.append(gpa, data);
                expected.max_size = @max(expected.max_size, structure.size());
                expected.max_leaves = @max(expected.max_leaves, structure.leaves());
            },
            1, 3 => {
                const result = if (reader.boolean()) structure.sync() else structure.start_sync();
                result catch return;
                expected.barrier(structure);
                expected.min_pruned = structure.bounds().start;
                expected.max_pruned = @max(expected.max_pruned, expected.min_pruned);
            },
            2 => structure.flush() catch return, // No barrier: only a sync raises the floor.
            4 => {
                const location = @min(reader.int(u64), structure.leaves());
                if (!faulted_prune(structure, faults, expected, location)) return;
            },
            5 => {
                const location = structure.leaves();
                if (!faulted_prune(structure, faults, expected, location)) return;
            },
            else => unreachable,
        }
    }
}

fn support_add(comptime F: type, structure: *Merkle(F), data: []const u8) !void {
    var batch = try structure.new_batch();
    batch.add(gpa, hasher, data) catch |err| {
        batch.deinit(gpa);
        return err;
    };
    const merkleized = try batch.merkleize(structure, hasher);
    defer merkleized.release(gpa);
    try structure.apply_batch(merkleized);
}

fn expect_node(
    comptime F: type,
    structure: *Merkle(F),
    reference: *const merkle.mem.Mem(F, D),
    position: u64,
) !void {
    const node = (try structure.get_node(position)) orelse return error.TestUnexpectedResult;
    try testing.expect(node.eql(reference.get_node(position).?));
}

/// Checks a clean recovery against `expected`, node for node, then proves it still writes
/// durably with a sentinel leaf.
fn check_recovery(comptime F: type, harness: *Harness, expected: *const Expected) !void {
    var structure = try harness.open(F);
    const size = structure.size();
    const leaves = structure.leaves();
    const pruned = structure.bounds().start;
    try testing.expect(size >= expected.min_size and size <= expected.max_size);
    try testing.expect(leaves >= expected.min_leaves and leaves <= expected.max_leaves);
    try testing.expect(pruned >= expected.min_pruned and pruned <= expected.max_pruned);
    var reference: merkle.mem.Mem(F, D) = .empty;
    defer reference.deinit(gpa);
    for (expected.leaves.items[0..@intCast(leaves)]) |*data| try reference.add(gpa, hasher, data);
    try testing.expect((try structure.root(hasher, 0)).eql(try reference.root(hasher, 0)));
    // Every readable node: the pins of the boundary and everything from it on.
    var pins_buffer: [merkle.max_pinned_nodes]u64 = undefined;
    for (merkle.nodes_to_pin(F, pruned, &pins_buffer)) |position| {
        try expect_node(F, &structure, &reference, position);
    }
    var position = F.location_to_position(pruned);
    while (position < size) : (position += 1) try expect_node(F, &structure, &reference, position);
    try support_add(F, &structure, &@as([8]u8, @splat(0xab)));
    try structure.sync();
    const root = try structure.root(hasher, 0);
    structure.deinit();
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expect((try structure.root(hasher, 0)).eql(root));
}

fn recovery_family(comptime F: type, bytes: []const u8) !void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var harness = try Harness.init();
    defer harness.deinit();
    harness.items_per_blob = 1 + reader.below(16);
    const mutation_budget = reader.int(u8) % 64;
    const remove_byte = reader.int(u8);
    const faults: Faults = .{
        .harness = &harness,
        .remove_budget = if (remove_byte < 128) remove_byte % 4 else null,
    };
    const recovery_budget = reader.int(u8) % 64;
    var expected: Expected = .{};
    defer expected.leaves.deinit(gpa);

    // Phase 1: operations until a fault, then a crash.
    var structure = try harness.open(F);
    harness.storage.allow_mutations(mutation_budget);
    try recovery_operations(F, &structure, faults, &reader, &expected);
    harness.storage.crash();
    structure.deinit();
    // A faulted recovery attempt is abandoned and crashes again.
    harness.storage.allow_mutations(recovery_budget);
    if (harness.open(F)) |opened| {
        var abandoned = opened;
        abandoned.deinit();
    } else |_| {}
    harness.storage.crash();
    harness.storage.mutations_allowed = null;
    // Phase 2: a clean recovery.
    try check_recovery(F, &harness, &expected);
}

fn full_recovery_run(bytes: []const u8) anyerror!void {
    inline for (support.families) |F| try recovery_family(F, bytes);
}

test "fuzz merkle full recovery (seeded)" {
    try fuzz_bytes.seeded(512, 0x7265636f76, 32, full_recovery_run);
}

test "fuzz merkle full recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(512, full_recovery_run), .{});
}
