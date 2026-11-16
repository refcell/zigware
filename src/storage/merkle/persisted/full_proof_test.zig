//! Historical proof tests of `full.zig`, ported from commonware's
//! `storage/src/merkle/persisted/full.rs`. Every test runs under both families.

const std = @import("std");
const testing = std.testing;
const merkle = @import("../mod.zig");
const support = @import("full_test.zig");

const D = support.D;
const Harness = support.Harness;
const Merkle = support.Merkle;
const add_digests = support.add_digests;
const gpa = support.gpa;
const hasher = &support.hasher;
const test_digest = support.test_digest;

fn digests(comptime from: u64, comptime to: u64) [to - from]D {
    var out: [to - from]D = undefined;
    for (&out, from..) |*digest, i| digest.* = test_digest(i);
    return out;
}

fn expect_same_proof(a: anytype, b: anytype) !void {
    try testing.expectEqual(a.leaves, b.leaves);
    try testing.expectEqual(a.inactive_peaks, b.inactive_peaks);
    try testing.expectEqual(a.digests.len, b.digests.len);
    for (a.digests, b.digests) |x, y| try testing.expect(x.eql(y));
}

/// The root of a fresh tree over `test_digest(0..leaves)`, in its own partitions.
fn reference_root(comptime F: type, harness: *Harness, leaves: u64) !D {
    const cfg = harness.cfg_in("reference-journal", "reference-metadata");
    var reference = try Merkle(F).init(gpa, harness.storage.interface(), hasher, cfg);
    defer reference.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &reference, 0, leaves);
    return reference.root(hasher, 0);
}

fn historical_proof_basic(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 10);
    const original_leaves = structure.leaves();
    const range: merkle.Range = .{ .start = 2, .end = 6 };
    // A historical proof at the current size matches the regular proof.
    var historical = try structure.historical_range_proof(hasher, original_leaves, range, 0);
    defer historical.deinit(gpa);
    try testing.expectEqual(original_leaves, historical.leaves);
    const root = try structure.root(hasher, 0);
    const elements = digests(2, 6);
    try testing.expect(historical.verify_range_inclusion(hasher, 2, &elements, &root));
    var regular = try structure.range_proof(hasher, range, 0);
    defer regular.deinit(gpa);
    try expect_same_proof(regular, historical);
    // After more appends the historical proof is unchanged.
    try add_digests(F, &structure, 10, 20);
    var later = try structure.historical_range_proof(hasher, original_leaves, range, 0);
    defer later.deinit(gpa);
    try expect_same_proof(later, historical);
}

fn historical_proof_with_pruning(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 50);
    try structure.prune(16);
    const historical_root = try reference_root(F, &harness, 41);
    const range: merkle.Range = .{ .start = 35, .end = 39 };
    var proof = try structure.historical_range_proof(hasher, 41, range, 0);
    defer proof.deinit(gpa);
    try testing.expectEqual(@as(u64, 41), proof.leaves);
    const elements = digests(35, 39);
    try testing.expect(proof.verify_range_inclusion(hasher, 35, &elements, &historical_root));
}

fn historical_proof_large(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 100);
    const range: merkle.Range = .{ .start = 30, .end = 61 };
    const expected_root = try reference_root(F, &harness, range.end);
    var proof = try structure.historical_range_proof(hasher, range.end, range, 0);
    defer proof.deinit(gpa);
    const elements = digests(30, 61);
    try testing.expect(proof.verify_range_inclusion(hasher, 30, &elements, &expected_root));
}

fn historical_proof_singleton(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 1);
    var proof = try structure.historical_range_proof(hasher, 1, .{ .start = 0, .end = 1 }, 0);
    defer proof.deinit(gpa);
    const root = try structure.root(hasher, 0);
    const elements = digests(0, 1);
    try testing.expect(proof.verify_range_inclusion(hasher, 0, &elements, &root));
}

/// A location whose single-leaf proof is pruned stays pruned after more appends.
fn historical_proof_pruned_elements(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 64);
    try structure.prune(16);
    const leaves = structure.leaves();
    const pruned = for (0..leaves) |location| {
        const range: merkle.Range = .{ .start = location, .end = location + 1 };
        if (structure.historical_range_proof(hasher, leaves, range, 0)) |found| {
            var proof = found;
            proof.deinit(gpa);
        } else |err| {
            if (err == error.ElementPruned) break location;
            return err;
        }
    } else return error.TestUnexpectedResult; // Expected at least one pruned location.
    try add_digests(F, &structure, 10_000, 10_008);
    const range: merkle.Range = .{ .start = pruned, .end = pruned + 1 };
    const result = structure.historical_range_proof(hasher, structure.leaves(), range, 0);
    try testing.expectError(error.ElementPruned, result);
}

/// Appends stay allowed while historical proofs are served, and reads after a sync come
/// from the journal with the same result.
fn historical_proof_stable(comptime F: type, sync: bool) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    const leaves: u64 = if (sync) 64 else 20;
    try add_digests(F, &structure, 0, leaves);
    if (sync) try structure.sync() else try add_digests(F, &structure, 100, 102);
    const historical_leaves: u64 = if (sync) 20 else 10;
    const range: merkle.Range = if (sync)
        .{ .start = 5, .end = 15 }
    else
        .{ .start = 2, .end = 8 };
    var first = try structure.historical_range_proof(hasher, historical_leaves, range, 0);
    defer first.deinit(gpa);
    var second = try structure.historical_range_proof(hasher, historical_leaves, range, 0);
    defer second.deinit(gpa);
    try expect_same_proof(first, second);
}

fn historical_proof_after_pruning(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 30);
    try structure.prune(10);
    var proof = try structure.historical_range_proof(hasher, 20, .{ .start = 10, .end = 20 }, 0);
    defer proof.deinit(gpa);
    try testing.expect(proof.leaves > 0);
}

fn expect_proof_ok(structure: anytype, leaves: u64, range: merkle.Range) !void {
    var proof = try structure.historical_range_proof(hasher, leaves, range, 0);
    proof.deinit(gpa);
}

fn historical_proof_edge_cases(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    // Case 1: an empty structure.
    var structure = try harness.open(F);
    const empty = structure.historical_range_proof(hasher, 0, .{ .start = 0, .end = 0 }, 0);
    try testing.expectError(error.Empty, empty);
    const oob = structure.historical_range_proof(hasher, 1, .{ .start = 0, .end = 1 }, 0);
    try testing.expectError(error.RangeOutOfBounds, oob);
    try structure.destroy();

    // Case 2: nodes, but fully pruned.
    structure = try harness.open(F);
    try add_digests(F, &structure, 0, 20);
    var end = structure.leaves();
    try structure.prune_all();
    try testing.expectEqual(structure.bounds().start, structure.bounds().end);
    var range: merkle.Range = .{ .start = end - 1, .end = end };
    try testing.expectError(error.ElementPruned, expect_proof_ok(&structure, end, range));
    try testing.expectError(error.RangeOutOfBounds, expect_proof_ok(&structure, end + 1, range));
    try structure.destroy();

    // Case 3: every leaf but one pruned.
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 11);
    end = structure.leaves();
    const keep = end - 1;
    try structure.prune(keep);
    range = .{ .start = keep, .end = end };
    try expect_proof_ok(&structure, end, range);
    const pruned_range: merkle.Range = .{ .start = 1, .end = keep };
    try testing.expectError(error.ElementPruned, expect_proof_ok(&structure, end, pruned_range));
    try testing.expectError(error.RangeOutOfBounds, expect_proof_ok(&structure, end + 1, range));
}

fn historical_proof_range_validation(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 32);
    const requested = 5;
    const leaves = structure.leaves();
    const oob = error.RangeOutOfBounds;
    const Case = struct { leaves: u64, start: u64 = 0, end: u64, err: anyerror };
    const cases = [_]Case{
        // An empty range.
        .{ .leaves = requested, .start = 5, .end = 5, .err = error.Empty },
        // A historical size past the structure (also commonware's out_of_bounds test).
        .{ .leaves = leaves + 1, .end = 1, .err = oob },
        .{ .leaves = leaves + 1, .end = leaves + 1, .err = oob },
        // A range end past the structure, past the requested size, and overflowing.
        .{ .leaves = requested, .end = leaves + 1, .err = oob },
        .{ .leaves = requested, .end = requested + 1, .err = oob },
        .{ .leaves = requested, .end = std.math.maxInt(u64), .err = oob },
    };
    for (cases) |case| {
        const range: merkle.Range = .{ .start = case.start, .end = case.end };
        try testing.expectError(case.err, expect_proof_ok(&structure, case.leaves, range));
    }
}

/// After pruning to any leaf, single-leaf proofs fail only for pruned leaves.
fn non_size_prune_excludes_pruned_leaves(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try add_digests(F, &structure, 0, 16);
    const end = structure.leaves();
    for (1..end) |prune_leaf| {
        try structure.prune(prune_leaf);
        for (0..end) |location| {
            if (structure.historical_proof(hasher, end, location, 0)) |found| {
                var proof = found;
                proof.deinit(gpa);
            } else |err| {
                if (err != error.ElementPruned or location >= prune_leaf) return err;
            }
        }
    }
}

test "persisted merkle historical proofs" {
    inline for (support.families) |F| {
        try historical_proof_basic(F);
        try historical_proof_with_pruning(F);
        try historical_proof_large(F);
        try historical_proof_singleton(F);
        try historical_proof_pruned_elements(F);
        try historical_proof_stable(F, false);
        try historical_proof_stable(F, true);
        try historical_proof_after_pruning(F);
    }
}

test "persisted merkle historical proof edge cases and range validation" {
    inline for (support.families) |F| {
        try historical_proof_edge_cases(F);
        try historical_proof_range_validation(F);
        try non_size_prune_excludes_pruned_leaves(F);
    }
}
