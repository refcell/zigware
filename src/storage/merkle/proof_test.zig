//! Tests for `proof.zig`, ported from commonware's `storage/src/merkle/proof.rs` and
//! `merkle/mmr/proof.rs`. Each check is generic over the family so MMB reuses it.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const codec = @import("codec");
const utils = @import("utils");
const merkle = @import("mod.zig");
const proof_module = @import("proof.zig");

const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const H = merkle.hasher.Standard(Sha256);
const gpa = testing.allocator;
const Range = merkle.Range;
const RangePlan = proof_module.RangePlan;
const Blueprint = proof_module.Blueprint;
const multi_proof_positions = proof_module.multi_proof_positions;

fn Mem(comptime F: type) type {
    return merkle.mem.Mem(F, D);
}

fn Proof(comptime F: type) type {
    return proof_module.Proof(F, D);
}

fn test_digest(value: u8) D {
    return Sha256.hash(&.{&.{value}});
}

fn be(value: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return bytes;
}

/// A structure whose element `i` is `i_be64`.
fn build_raw(comptime F: type, hasher: *const H, n: u64) !Mem(F) {
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    for (0..n) |i| try mem.add(gpa, hasher, &be(i));
    return mem;
}

/// A structure whose element `i` is `test_digest(i)`; also returns the elements.
fn build_digests(comptime F: type, hasher: *const H, elements: []D) !Mem(F) {
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    for (elements, 0..) |*element, i| {
        element.* = test_digest(@intCast(i));
        try mem.add(gpa, hasher, &element.bytes);
    }
    return mem;
}

fn peak_count(comptime F: type, leaves: u64) usize {
    var count: usize = 0;
    var peaks = F.peaks(F.location_to_position(leaves));
    while (peaks.next()) |_| count += 1;
    return count;
}

/// A multi-element proof assembled from the node digests at `multi_proof_positions`.
fn multi_proof(
    comptime F: type,
    mem: *const Mem(F),
    locations: []const u64,
    inactive: usize,
) !Proof(F) {
    const positions = try multi_proof_positions(F, gpa, mem.leaves(), locations);
    defer gpa.free(positions);
    const digests = try gpa.alloc(D, positions.len);
    for (positions, digests) |position, *digest| digest.* = mem.get_node(position).?;
    return .{ .leaves = mem.leaves(), .inactive_peaks = inactive, .digests = digests };
}

fn multi_ok(
    proof: anytype,
    hasher: *const H,
    locations: []const u64,
    elements: anytype,
    root: *const D,
) !bool {
    return proof.verify_multi_inclusion(gpa, hasher, locations, elements, root);
}

fn expect_strictly_increasing(positions: []const u64) !void {
    if (positions.len < 2) return;
    for (positions[1..], positions[0 .. positions.len - 1]) |b, a| try testing.expect(a < b);
}

const Recorder = struct {
    reads: merkle.BoundedList(u64, 512) = .{},
    missing: ?u64 = null,
    mem: ?*const Mem(merkle.mmr.Family) = null,

    pub fn get_node(self: *Recorder, position: u64) ?D {
        self.reads.append(position);
        if (self.missing == position) return null;
        if (self.mem) |mem| return mem.get_node(position);
        return test_digest(0);
    }
};

test "proof max encode size uses wire types" {
    const integer = codec.varint.size(u64, std.math.maxInt(u64));
    const prefix = codec.varint.size(u32, std.math.maxInt(u32));
    for ([_]usize{ 0, 1, 128 }) |digests| {
        const expected = 2 * integer + prefix + digests * D.fixed_size;
        try testing.expectEqual(expected, Proof(merkle.mmr.Family).max_encode_size(digests));
    }
}

fn check_range_plan(comptime F: type) !void {
    for (1..25) |leaves| {
        const peaks = peak_count(F, leaves);
        for (0..leaves) |start| {
            for (start + 1..leaves + 1) |end| {
                const plan = try RangePlan(F).init(leaves, .{ .start = start, .end = end });
                const positions = plan.positions();
                try expect_strictly_increasing(positions.slice());
                for ([_]merkle.Bagging{ .forward_fold, .backward_fold }) |bagging| {
                    const hasher = H.init(bagging);
                    for (0..peaks + 1) |inactive| {
                        var recorder: Recorder = .{};
                        var proof = try plan.build(gpa, &hasher, inactive, &recorder);
                        proof.deinit(gpa);
                        std.mem.sort(u64, recorder.reads.slice_mut(), {}, std.sort.asc(u64));
                        const reads = recorder.reads.slice();
                        try testing.expectEqualSlices(u64, positions.slice(), reads);
                    }
                }
            }
        }
    }
}

test "range plan positions independent of bagging and inactive peaks" {
    try check_range_plan(merkle.mmr.Family);
}

test "range plan rejects invalid inputs" {
    const F = merkle.mmr.Family;
    const past_end = RangePlan(F).init(8, .{ .start = 8, .end = 9 });
    try testing.expectError(error.RangeOutOfBounds, past_end);
    try testing.expectError(error.Empty, RangePlan(F).init(8, .{ .start = 3, .end = 3 }));
    for ([_]u64{ F.max_leaves + 1, std.math.maxInt(u64) }) |leaves| {
        const plan = RangePlan(F).init(leaves, .{ .start = 0, .end = 1 });
        try testing.expectError(error.LocationOverflow, plan);
    }
    try testing.expectError(error.RangeOutOfBounds, RangePlan(F).init_element(8, 8));
    for ([_]u64{ F.max_leaves, std.math.maxInt(u64) }) |location| {
        try testing.expectError(error.LocationOverflow, RangePlan(F).init_element(8, location));
    }
}

test "multi proof positions reject invalid inputs" {
    const F = merkle.mmr.Family;
    try testing.expectError(error.RangeOutOfBounds, multi_proof_positions(F, gpa, 8, &.{ 2, 8 }));
    try testing.expectError(error.Empty, multi_proof_positions(F, gpa, 8, &.{}));
    const overflow = multi_proof_positions(F, gpa, 8, &.{std.math.maxInt(u64)});
    try testing.expectError(error.LocationOverflow, overflow);
}

fn check_first_invalid_location(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var mem = try build_raw(F, &hasher, 4);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    var proof = try multi_proof(F, &mem, &.{ 0, 1, 2, 3 }, 0);
    defer proof.deinit(gpa);
    const all_elements = [_][8]u8{ be(0), be(1), be(2), be(3) };
    try testing.expect(try multi_ok(&proof, &hasher, &.{ 0, 1, 2, 3 }, &all_elements, &root));

    const Case = struct { locations: []const u64, expected: anyerror };
    const cases = [_]Case{
        .{ .locations = &.{}, .expected = error.Empty },
        .{ .locations = &.{ 0, 0, 4 }, .expected = error.DuplicateLocation },
        .{ .locations = &.{ 4, 0, 0 }, .expected = error.RangeOutOfBounds },
        .{ .locations = &.{ 3, 4 }, .expected = error.RangeOutOfBounds },
        .{ .locations = &.{ 2, 1 }, .expected = error.UnsortedLocation },
        .{ .locations = &.{ 3, 1, 1, 3 }, .expected = error.UnsortedLocation },
        .{ .locations = &.{ 1, 3, 3, 1 }, .expected = error.DuplicateLocation },
        .{ .locations = &.{ 0, 1, 2, 3, 0, 4 }, .expected = error.UnsortedLocation },
        .{ .locations = &.{ 0, 1, 2, 3, 4, 0 }, .expected = error.RangeOutOfBounds },
    };
    for (cases) |case| {
        try testing.expectError(case.expected, multi_proof_positions(F, gpa, 4, case.locations));
        var elements: [8][8]u8 = undefined;
        for (case.locations, 0..) |location, i| elements[i] = be(location);
        const verified = try proof.verify_multi_inclusion(
            gpa,
            &hasher,
            case.locations,
            elements[0..case.locations.len],
            &root,
        );
        try testing.expect(!verified);
    }
}

test "multi proofs report first invalid location" {
    try check_first_invalid_location(merkle.mmr.Family);
}

/// The union of the single-element proof positions, with the same validation order.
fn union_of_element_positions(comptime F: type, leaves: u64, locations: []const u64) ![]u64 {
    if (locations.len == 0) return error.Empty;
    var union_positions: std.ArrayList(u64) = .empty;
    defer union_positions.deinit(gpa);
    for (locations, 0..) |location, i| {
        if (i > 0 and location == locations[i - 1]) return error.DuplicateLocation;
        if (i > 0 and location < locations[i - 1]) return error.UnsortedLocation;
        const plan = try RangePlan(F).init_element(leaves, location);
        try union_positions.appendSlice(gpa, plan.positions().slice());
    }
    std.mem.sort(u64, union_positions.items, {}, std.sort.asc(u64));
    var out: std.ArrayList(u64) = .empty;
    errdefer out.deinit(gpa);
    for (union_positions.items, 0..) |position, i| {
        if (i > 0 and position == union_positions.items[i - 1]) continue;
        try out.append(gpa, position);
    }
    return out.toOwnedSlice(gpa);
}

fn check_union(comptime F: type, leaves: u64, locations: []const u64) !void {
    const expected = union_of_element_positions(F, leaves, locations);
    const actual = multi_proof_positions(F, gpa, leaves, locations);
    if (expected) |positions| {
        defer gpa.free(positions);
        const got = try actual;
        defer gpa.free(got);
        try testing.expectEqualSlices(u64, positions, got);
    } else |err| {
        try testing.expectError(err, actual);
    }
}

fn check_union_small(comptime F: type) !void {
    var selection: [64]u64 = undefined;
    for (1..65) |leaves| {
        if (leaves <= 10) {
            for (1..@as(u64, 1) << @intCast(leaves)) |mask| {
                var count: usize = 0;
                for (0..leaves) |location| {
                    if (mask & (@as(u64, 1) << @intCast(location)) == 0) continue;
                    selection[count] = location;
                    count += 1;
                }
                try check_union(F, leaves, selection[0..count]);
            }
        }
        for (0..leaves) |first| {
            try check_union(F, leaves, &.{first});
            for (first + 1..leaves) |second| try check_union(F, leaves, &.{ first, second });
        }
        for (0..leaves) |location| selection[location] = location;
        try check_union(F, leaves, selection[0..leaves]);
        const subtrees = proof_module.peak_subtrees(F, F.location_to_position(leaves));
        for (subtrees.slice()) |peak| {
            const span: usize = @intCast(peak.leaf_end() - peak.leaf_start);
            for (selection[0..span], 0..) |*location, i| location.* = peak.leaf_start + i;
            try check_union(F, leaves, selection[0..span]);
        }
    }
}

fn check_union_random_and_edges(comptime F: type) !void {
    var rng = utils.test_rng();
    var selection: [64]u64 = undefined;
    for (0..256) |_| {
        const leaves = utils.rng.range_at_most(&rng, u64, 1, 1 << 20);
        const count = utils.rng.range_at_most(&rng, usize, 1, 64);
        for (selection[0..count]) |*location| {
            location.* = utils.rng.range_less_than(&rng, u64, 0, leaves);
        }
        std.mem.sort(u64, selection[0..count], {}, std.sort.asc(u64));
        var unique: usize = 0;
        for (selection[0..count]) |location| {
            if (unique > 0 and selection[unique - 1] == location) continue;
            selection[unique] = location;
            unique += 1;
        }
        try check_union(F, leaves, selection[0..unique]);
    }
    const max = F.max_leaves;
    const maximum = std.math.maxInt(u64);
    const Case = struct { leaves: u64, locations: []const u64 };
    for ([_]Case{
        .{ .leaves = 8, .locations = &.{} },
        .{ .leaves = 8, .locations = &.{8} },
        .{ .leaves = 8, .locations = &.{ 2, 8, 1 } },
        .{ .leaves = 8, .locations = &.{ 3, 3 } },
        .{ .leaves = 8, .locations = &.{ 3, 1, 9 } },
        .{ .leaves = 8, .locations = &.{maximum} },
        .{ .leaves = max, .locations = &.{ max - 1, max } },
        .{ .leaves = max + 1, .locations = &.{ 0, 0 } },
        .{ .leaves = max + 1, .locations = &.{maximum} },
        .{ .leaves = maximum, .locations = &.{maximum - 1} },
    }) |case| try check_union(F, case.leaves, case.locations);
}

test "multi proof positions match union of element positions" {
    try check_union_small(merkle.mmr.Family);
    try check_union_random_and_edges(merkle.mmr.Family);
}

fn check_multi_binding(
    comptime F: type,
    mem: *const Mem(F),
    hasher: *const H,
    inactive: usize,
    selection: []const u64,
) !void {
    const root = try mem.root(hasher, inactive);
    var proof = try multi_proof(F, mem, selection, inactive);
    defer proof.deinit(gpa);
    var elements: [64][8]u8 = undefined;
    for (selection, 0..) |location, i| elements[i] = be(location);
    const chosen = elements[0..selection.len];
    try testing.expect(try multi_ok(&proof, hasher, selection, chosen, &root));
    for (proof.digests) |*digest| {
        digest.bytes[0] ^= 1;
        try testing.expect(!try multi_ok(&proof, hasher, selection, chosen, &root));
        digest.bytes[0] ^= 1;
    }
    for (chosen) |*element| {
        element[0] ^= 1;
        try testing.expect(!try multi_ok(&proof, hasher, selection, chosen, &root));
        element[0] ^= 1;
    }
}

fn check_multi_bind_every_digest(comptime F: type) !void {
    for ([_]u64{ 1, 2, 3, 7, 8, 11, 31, 64 }) |leaves| {
        var mem = try build_raw(F, &H.init(.forward_fold), leaves);
        defer mem.deinit(gpa);
        var all: [64]u64 = undefined;
        var evens: [32]u64 = undefined;
        for (0..leaves) |i| all[i] = i;
        var even_count: usize = 0;
        var i: u64 = 0;
        while (i < leaves) : (i += 2) {
            evens[even_count] = i;
            even_count += 1;
        }
        var selections: merkle.BoundedList([]const u64, 6) = .{};
        selections.append(&.{0});
        selections.append(all[leaves - 1 .. leaves]);
        selections.append(all[0..leaves]);
        if (leaves > 1) {
            selections.append(&.{ 0, 1 });
            selections.append(&.{ 0, leaves - 1 });
            selections.append(evens[0..even_count]);
        }
        for ([_]merkle.Bagging{ .forward_fold, .backward_fold }) |bagging| {
            const hasher = H.init(bagging);
            for (0..peak_count(F, leaves) + 1) |inactive| {
                for (selections.slice()) |selection| {
                    try check_multi_binding(F, &mem, &hasher, inactive, selection);
                }
            }
        }
    }
}

test "multi proofs bind every digest and element" {
    try check_multi_bind_every_digest(merkle.mmr.Family);
}

test "range plan build reports the first missing node and rejects before reading" {
    const F = merkle.mmr.Family;
    const hasher = H.init(.backward_fold);
    var mem = try build_raw(F, &hasher, 11);
    defer mem.deinit(gpa);
    const plan = try RangePlan(F).init(mem.leaves(), .{ .start = 3, .end = 5 });
    const missing = plan.positions().slice()[1];
    var recorder: Recorder = .{ .missing = missing, .mem = &mem };
    try testing.expectError(error.ElementPruned, plan.build(gpa, &hasher, 0, &recorder));
    try testing.expectEqual(missing, recorder.reads.slice()[recorder.reads.len - 1]);
    recorder.reads = .{};
    const peaks = peak_count(F, mem.leaves());
    try testing.expectError(error.InvalidProof, plan.build(gpa, &hasher, peaks + 1, &recorder));
    try testing.expectEqual(@as(usize, 0), recorder.reads.len);
}

fn check_empty_proof(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var mem: Mem(F) = .empty;
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    var proof: Proof(F) = .{};
    const none: []const D = &.{};
    try testing.expect(proof.verify_range_inclusion(&hasher, 0, none, &root));
    try testing.expect(try multi_ok(&proof, &hasher, &.{}, none, &root));
    proof.inactive_peaks = 1;
    try testing.expect(!proof.verify_range_inclusion(&hasher, 0, none, &root));
    try testing.expect(!try multi_ok(&proof, &hasher, &.{}, none, &root));
    try testing.expectError(error.InvalidProof, proof.reconstruct_root(&hasher, 0, none));
    proof.inactive_peaks = 0;
    try testing.expect(!proof.verify_range_inclusion(&hasher, 1, none, &root));
    const wrong = test_digest(0);
    try testing.expect(!proof.verify_range_inclusion(&hasher, 0, none, &wrong));
    try testing.expect(!proof.verify_range_inclusion(&hasher, 0, &[_]D{wrong}, &root));
}

test "empty proof" {
    try check_empty_proof(merkle.mmr.Family);
}

fn expect_element_fails(
    comptime F: type,
    proof: *const Proof(F),
    hasher: *const H,
    location: u64,
    element: []const u8,
    root: *const D,
) !void {
    try testing.expect(!proof.verify_element_inclusion(hasher, location, element, root));
}

fn check_verify_element(comptime F: type) !void {
    const element = "01234567012345670123456701234567";
    const hasher = H.init(.forward_fold);
    var mem: Mem(F) = .empty;
    defer mem.deinit(gpa);
    for (0..11) |_| try mem.add(gpa, &hasher, element);
    const root = try mem.root(&hasher, 0);
    for (0..11) |leaf| {
        var proof = try mem.proof(gpa, &hasher, leaf, 0);
        defer proof.deinit(gpa);
        try testing.expect(proof.verify_element_inclusion(&hasher, leaf, element, &root));
    }
    var proof = try mem.proof(gpa, &hasher, 10, 0);
    defer proof.deinit(gpa);
    try testing.expect(proof.verify_element_inclusion(&hasher, 10, element, &root));
    try expect_element_fails(F, &proof, &hasher, 11, element, &root);
    try expect_element_fails(F, &proof, &hasher, 9, element, &root);
    try expect_element_fails(F, &proof, &hasher, 10, &test_digest(0).bytes, &root);
    try expect_element_fails(F, &proof, &hasher, 10, element, &test_digest(0));
    var mangled = try proof.clone(gpa);
    const mangled_owned = mangled.digests;
    defer gpa.free(mangled_owned);
    mangled.digests[0] = test_digest(0);
    try expect_element_fails(F, &mangled, &hasher, 10, element, &root);
    mangled.digests[0] = proof.digests[0];
    mangled.leaves = 10;
    try expect_element_fails(F, &mangled, &hasher, 10, element, &root);
    mangled.leaves = proof.leaves;

    var longer = try gpa.alloc(D, proof.digests.len + 1);
    defer gpa.free(longer);
    @memcpy(longer[0..proof.digests.len], proof.digests);
    longer[proof.digests.len] = test_digest(0);
    mangled.digests = longer;
    try expect_element_fails(F, &mangled, &hasher, 10, element, &root);
    var len = proof.digests.len;
    while (len > 0) {
        len -= 1;
        mangled.digests = longer[0..len];
        try expect_element_fails(F, &mangled, &hasher, 10, element, &root);
    }
    if (proof.digests.len >= 2) {
        // An extra digest fails even where the computation would not use it.
        longer[0] = proof.digests[0];
        longer[1] = test_digest(0);
        @memcpy(longer[2..], proof.digests[1..]);
        mangled.digests = longer;
        try expect_element_fails(F, &mangled, &hasher, 10, element, &root);
    }
}

test "verify element" {
    try check_verify_element(merkle.mmr.Family);
}

fn check_verify_range_valid(
    comptime F: type,
    mem: *const Mem(F),
    hasher: *const H,
    elements: []const D,
    root: *const D,
) !void {
    for (0..elements.len) |i| {
        for (i + 1..elements.len) |j| {
            var proof = try mem.range_proof(gpa, hasher, .{ .start = i, .end = j }, 0);
            defer proof.deinit(gpa);
            try testing.expect(proof.verify_range_inclusion(hasher, i, elements[i..j], root));
        }
    }
}

fn check_verify_range(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var elements: [49]D = undefined;
    var mem = try build_digests(F, &hasher, &elements);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    try check_verify_range_valid(F, &mem, &hasher, &elements, &root);

    var proof = try mem.range_proof(gpa, &hasher, .{ .start = 33, .end = 40 }, 0);
    defer proof.deinit(gpa);
    const valid = elements[33..40];
    try testing.expect(proof.verify_range_inclusion(&hasher, 33, valid, &root));
    var invalid = try proof.clone(gpa);
    defer invalid.deinit(gpa);
    invalid.inactive_peaks = 1;
    try testing.expect(!invalid.verify_range_inclusion(&hasher, 33, valid, &root));
    invalid.inactive_peaks = 0;
    const owned = invalid.digests;
    for (1..owned.len + 1) |removed| {
        invalid.digests = owned[removed..];
        try testing.expect(!invalid.verify_range_inclusion(&hasher, 33, valid, &root));
    }
    invalid.digests = owned;
    for (0..elements.len) |i| {
        for (i + 1..elements.len) |j| {
            if (i == 33 and j == 40) continue;
            try testing.expect(!proof.verify_range_inclusion(&hasher, 33, elements[i..j], &root));
        }
    }
    try testing.expect(!proof.verify_range_inclusion(&hasher, 33, valid, &test_digest(1)));
    for (invalid.digests, proof.digests) |*digest, original| {
        digest.* = test_digest(0);
        try testing.expect(!invalid.verify_range_inclusion(&hasher, 33, valid, &root));
        digest.* = original;
    }
    try check_verify_range_inserted(F, &proof, &hasher, valid, &root);
    for (0..elements.len) |location| {
        if (location == 33) continue;
        try testing.expect(!proof.verify_range_inclusion(&hasher, location, valid, &root));
    }
}

fn check_verify_range_inserted(
    comptime F: type,
    proof: *const Proof(F),
    hasher: *const H,
    valid: []const D,
    root: *const D,
) !void {
    const longer = try gpa.alloc(D, proof.digests.len + 1);
    defer gpa.free(longer);
    var inserted: Proof(F) = .{ .leaves = proof.leaves, .digests = longer };
    for (0..proof.digests.len) |i| {
        @memcpy(longer[0..i], proof.digests[0..i]);
        longer[i] = test_digest(0);
        @memcpy(longer[i + 1 ..], proof.digests[i..]);
        try testing.expect(!inserted.verify_range_inclusion(hasher, 33, valid, root));
    }
}

test "verify range" {
    try check_verify_range(merkle.mmr.Family);
}

fn check_retained_after_pruning(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var elements: [49]D = undefined;
    var mem = try build_digests(F, &hasher, &elements);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    for (1..mem.leaves()) |prune_location| {
        try mem.prune(prune_location);
        try testing.expect((try mem.root(&hasher, 0)).eql(root));
        for (prune_location..elements.len) |location| {
            var proof = try mem.proof(gpa, &hasher, location, 0);
            defer proof.deinit(gpa);
            const element = &elements[location].bytes;
            try testing.expect(proof.verify_element_inclusion(&hasher, location, element, &root));
        }
    }
}

test "retained nodes provable after pruning" {
    try check_retained_after_pruning(merkle.mmr.Family);
}

fn check_ranges_after_pruning(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var elements: [49 + 37]D = undefined;
    var mem = try build_digests(F, &hasher, elements[0..49]);
    defer mem.deinit(gpa);
    try mem.prune(32);
    try testing.expectEqual(@as(u64, 32), mem.pruning_boundary());
    const root = try mem.root(&hasher, 0);
    for (32..48) |i| {
        for (i + 2..49) |j| {
            var proof = try mem.range_proof(gpa, &hasher, .{ .start = i, .end = j }, 0);
            defer proof.deinit(gpa);
            try testing.expect(proof.verify_range_inclusion(&hasher, i, elements[i..j], &root));
        }
    }
    for (elements[49..], 0..) |*element, i| {
        element.* = test_digest(@intCast(i));
        try mem.add(gpa, &hasher, &element.bytes);
    }
    try mem.prune(66);
    try testing.expectEqual(@as(u64, 66), mem.pruning_boundary());
    const updated = try mem.root(&hasher, 0);
    const range: Range = .{ .start = elements.len - 10, .end = elements.len };
    var proof = try mem.range_proof(gpa, &hasher, range, 0);
    defer proof.deinit(gpa);
    const slice = elements[range.start..range.end];
    try testing.expect(proof.verify_range_inclusion(&hasher, range.start, slice, &updated));
}

test "ranges provable after pruning" {
    try check_ranges_after_pruning(merkle.mmr.Family);
}

fn check_serialization(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var elements: [25]D = undefined;
    var mem = try build_digests(F, &hasher, &elements);
    defer mem.deinit(gpa);
    for (0..elements.len) |i| {
        for (i + 1..elements.len) |j| {
            var proof = try mem.range_proof(gpa, &hasher, .{ .start = i, .end = j }, 0);
            defer proof.deinit(gpa);
            const encoded = try codec.encode(Proof(F), gpa, proof);
            defer gpa.free(encoded);
            try testing.expectEqual(codec.encode_size(Proof(F), proof), encoded.len);
            const count = proof.digests.len;
            var decoded = try codec.decode_cfg(Proof(F), gpa, encoded, count);
            defer decoded.deinit(gpa);
            try testing.expect(proof.eql(&decoded));
            const truncated = codec.decode_cfg(Proof(F), gpa, encoded[0 .. encoded.len - 1], count);
            try testing.expect(std.meta.isError(truncated));
            const extended = try gpa.alloc(u8, encoded.len + 10);
            defer gpa.free(extended);
            @memcpy(extended[0..encoded.len], encoded);
            @memset(extended[encoded.len..], 0);
            const extra = codec.decode_cfg(Proof(F), gpa, extended, count);
            try testing.expectError(error.ExtraData, extra);
            if (count > 0) {
                const small = codec.decode_cfg(Proof(F), gpa, encoded, count - 1);
                try testing.expectError(error.InvalidLength, small);
            }
        }
    }
}

test "proof serialization" {
    try check_serialization(merkle.mmr.Family);
}

test "proof decode rejects leaves past max" {
    const F = merkle.mmr.Family;
    var buffer: [32]u8 = undefined;
    var writer = codec.Writer.init(&buffer);
    codec.varint.write(u64, F.max_leaves + 1, &writer);
    codec.varint.write(u64, 0, &writer);
    codec.varint.write(u32, 0, &writer);
    const decoded = codec.decode_cfg(Proof(F), gpa, writer.written(), 0);
    try testing.expectError(error.Invalid, decoded);
}

fn check_multi_generation(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var elements: [20]D = undefined;
    var mem = try build_digests(F, &hasher, &elements);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    var proof = try multi_proof(F, &mem, &.{ 0, 5, 10 }, 0);
    defer proof.deinit(gpa);
    try testing.expectEqual(mem.leaves(), proof.leaves);
    const chosen = [_]D{ elements[0], elements[5], elements[10] };
    try testing.expect(try multi_ok(&proof, &hasher, &.{ 0, 5, 10 }, &chosen, &root));
    const reversed = [_]D{ elements[10], elements[5], elements[0] };
    try testing.expect(!try multi_ok(&proof, &hasher, &.{ 10, 5, 0 }, &reversed, &root));
    proof.inactive_peaks = 1;
    try testing.expect(!try multi_ok(&proof, &hasher, &.{ 0, 5, 10 }, &chosen, &root));
    proof.inactive_peaks = 0;
    const doubled = [_]D{ elements[0], elements[5], elements[5], elements[10] };
    try testing.expect(!try multi_ok(&proof, &hasher, &.{ 0, 5, 5, 10 }, &doubled, &root));
    proof.leaves = F.max_leaves + 2;
    try testing.expect(!try multi_ok(&proof, &hasher, &.{ 0, 5, 10 }, &chosen, &root));
    proof.leaves = mem.leaves();
    try testing.expect(!try multi_ok(&proof, &hasher, &.{ 1, 6, 11 }, &chosen, &root));
    const wrong = [_][]const u8{ &.{ 255, 254, 253 }, &.{ 252, 251, 250 }, &.{ 249, 248, 247 } };
    try testing.expect(!try multi_ok(&proof, &hasher, &.{ 0, 5, 10 }, &wrong, &root));
    try testing.expect(!try multi_ok(&proof, &hasher, &.{ 0, 5, 1000 }, &chosen, &root));
    try testing.expect(!try multi_ok(&proof, &hasher, &.{ 0, 5, 10 }, &chosen, &test_digest(99)));

    var empty: Mem(F) = .empty;
    defer empty.deinit(gpa);
    const empty_root = try empty.root(&hasher, 0);
    var empty_proof: Proof(F) = .{};
    const none: []const D = &.{};
    try testing.expect(try multi_ok(&empty_proof, &hasher, &.{}, none, &empty_root));
    var extra = [_]D{test_digest(0)};
    empty_proof.digests = &extra;
    try testing.expect(!try multi_ok(&empty_proof, &hasher, &.{}, none, &empty_root));
}

test "multi proof generation and verify" {
    try check_multi_generation(merkle.mmr.Family);
}

fn check_multi_deduplication(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var elements: [30]D = undefined;
    var mem = try build_digests(F, &hasher, &elements);
    defer mem.deinit(gpa);
    var first = try mem.proof(gpa, &hasher, 0, 0);
    defer first.deinit(gpa);
    var second = try mem.proof(gpa, &hasher, 1, 0);
    defer second.deinit(gpa);
    var multi = try multi_proof(F, &mem, &.{ 0, 1 }, 0);
    defer multi.deinit(gpa);
    try testing.expect(multi.digests.len < first.digests.len + second.digests.len);
    const root = try mem.root(&hasher, 0);
    const chosen = [_]D{ elements[0], elements[1] };
    try testing.expect(try multi_ok(&multi, &hasher, &.{ 0, 1 }, &chosen, &root));
}

test "multi proof deduplication" {
    try check_multi_deduplication(merkle.mmr.Family);
}

fn check_leaves_malleability(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var mem: Mem(F) = .empty;
    defer mem.deinit(gpa);
    var elements: [252]D = undefined;
    for (&elements, 0..) |*element, i| {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(i), .big);
        element.* = Sha256.hash(&.{&bytes});
        try mem.add(gpa, &hasher, &element.bytes);
    }
    const root = try mem.root(&hasher, 0);
    var proof = try mem.proof(gpa, &hasher, 240, 0);
    defer proof.deinit(gpa);
    const element = &elements[240].bytes;
    try testing.expect(proof.verify_element_inclusion(&hasher, 240, element, &root));
    proof.leaves = 249;
    try testing.expect(!proof.verify_element_inclusion(&hasher, 240, element, &root));
    proof.leaves = 252;
    proof.inactive_peaks = 1;
    try testing.expect(!proof.verify_element_inclusion(&hasher, 240, element, &root));
}

test "proof leaves malleability" {
    try check_leaves_malleability(merkle.mmr.Family);
}

fn check_blueprint_errors(comptime F: type) !void {
    const B = Blueprint(F);
    try testing.expectError(error.Empty, B.init(10, 0, .forward_fold, .{ .start = 3, .end = 3 }));
    const out_of_bounds = B.init(10, 0, .forward_fold, .{ .start = 0, .end = 11 });
    try testing.expectError(error.RangeOutOfBounds, out_of_bounds);
    const peaks = peak_count(F, 10);
    const too_many = B.init(10, peaks + 1, .forward_fold, .{ .start = 0, .end = 1 });
    try testing.expectError(error.InvalidProof, too_many);
    try testing.expectError(error.Empty, multi_proof_positions(F, gpa, 10, &.{}));
}

test "blueprint errors" {
    try check_blueprint_errors(merkle.mmr.Family);
}

fn check_reconstruction(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    for (1..65) |n| {
        var mem = try build_raw(F, &hasher, n);
        defer mem.deinit(gpa);
        const root = try mem.root(&hasher, 0);
        for (0..n) |location| {
            var proof = try mem.proof(gpa, &hasher, location, 0);
            defer proof.deinit(gpa);
            const element = [_][8]u8{be(location)};
            try testing.expect((try proof.reconstruct_root(&hasher, location, &element)).eql(root));
            if (n > 32) continue;
            const right = be(location);
            try testing.expect(proof.verify_element_inclusion(&hasher, location, &right, &root));
            const wrong = be(location + 1000);
            try testing.expect(!proof.verify_element_inclusion(&hasher, location, &wrong, &root));
        }
        if (n < 2 or n > 32) continue;
        const ranges = [_]Range{
            .{ .start = 0, .end = n },      .{ .start = 0, .end = 1 },
            .{ .start = n - 1, .end = n },  .{ .start = 0, .end = @min(n, 3) },
            .{ .start = n -| 3, .end = n },
        };
        for (ranges) |range| try check_range_reconstruction(F, &mem, &hasher, range, &root);
    }
}

fn check_range_reconstruction(
    comptime F: type,
    mem: *const Mem(F),
    hasher: *const H,
    range: Range,
    root: *const D,
) !void {
    var proof = try mem.range_proof(gpa, hasher, range, 0);
    defer proof.deinit(gpa);
    var elements: [32][8]u8 = undefined;
    const count: usize = @intCast(range.end - range.start);
    for (elements[0..count], 0..) |*element, i| element.* = be(range.start + i);
    const reconstructed = try proof.reconstruct_root(hasher, range.start, elements[0..count]);
    try testing.expect(reconstructed.eql(root.*));
    if (range.start == 0 and range.end == mem.leaves()) {
        try testing.expectEqual(@as(usize, 0), proof.digests.len); // A full range needs none.
    }
}

test "single element, range, and full range reconstruction" {
    try check_reconstruction(merkle.mmr.Family);
}

fn check_every_element_contributes(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    for ([_]u64{ 8, 13, 20, 32 }) |n| {
        var mem = try build_raw(F, &hasher, n);
        defer mem.deinit(gpa);
        const root = try mem.root(&hasher, 0);
        var proof = try mem.range_proof(gpa, &hasher, .{ .start = 1, .end = n - 1 }, 0);
        defer proof.deinit(gpa);
        var elements: [32][8]u8 = undefined;
        const tail = elements[0 .. n - 2];
        for (tail, 0..) |*element, i| element.* = be(1 + i);
        try testing.expect(proof.verify_range_inclusion(&hasher, 1, tail, &root));
        for (tail) |*element| {
            element[0] ^= 0xff;
            try testing.expect(!proof.verify_range_inclusion(&hasher, 1, tail, &root));
            element[0] ^= 0xff;
        }
    }
}

test "every element contributes to root" {
    try check_every_element_contributes(merkle.mmr.Family);
}

fn check_tampered_digests(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    for ([_]u64{ 8, 13, 20, 32 }) |n| {
        var mem = try build_raw(F, &hasher, n);
        defer mem.deinit(gpa);
        const root = try mem.root(&hasher, 0);
        for ([_]u64{ 0, n / 2, n - 1 }) |location| {
            var proof = try mem.proof(gpa, &hasher, location, 0);
            defer proof.deinit(gpa);
            const element = be(location);
            try testing.expect(proof.verify_element_inclusion(&hasher, location, &element, &root));
            for (proof.digests) |*digest| {
                digest.bytes[0] ^= 1;
                const ok = proof.verify_element_inclusion(&hasher, location, &element, &root);
                try testing.expect(!ok);
                digest.bytes[0] ^= 1;
            }
        }
    }
}

test "tampered proof digests rejected" {
    try check_tampered_digests(merkle.mmr.Family);
}

fn check_no_duplicate_positions(comptime F: type) !void {
    for (1..65) |n| {
        for (0..n) |location| {
            const plan = try RangePlan(F).init_element(n, location);
            const positions = plan.positions();
            try expect_strictly_increasing(positions.slice());
        }
    }
}

test "no duplicate positions" {
    try check_no_duplicate_positions(merkle.mmr.Family);
}

fn check_full_peak_blueprint(comptime F: type) !void {
    const leaves = @as(u64, 1) << 40;
    const range: Range = .{ .start = 0, .end = leaves };
    const blueprint = try Blueprint(F).init(leaves, 0, .forward_fold, range);
    var large = false;
    for (blueprint.range_peaks.slice()) |peak| large = large or peak.height >= 39;
    try testing.expect(large);
    try testing.expectEqual(@as(usize, 0), blueprint.siblings.len);
}

test "full peak range blueprint does not descend" {
    try check_full_peak_blueprint(merkle.mmr.Family);
}

fn check_pinned_nodes_across_sizes(comptime F: type) !void {
    const Case = struct { n: u64, start: u64 };
    const cases = [_]Case{
        .{ .n = 5, .start = 4 },      .{ .n = 10, .start = 3 },     .{ .n = 20, .start = 5 },
        .{ .n = 50, .start = 10 },    .{ .n = 100, .start = 10 },   .{ .n = 100, .start = 30 },
        .{ .n = 200, .start = 50 },   .{ .n = 500, .start = 100 },  .{ .n = 1000, .start = 100 },
        .{ .n = 1000, .start = 300 }, .{ .n = 2000, .start = 500 },
    };
    const hasher = H.init(.forward_fold);
    for (cases) |case| {
        var mem = try build_raw(F, &hasher, case.n);
        defer mem.deinit(gpa);
        const root = try mem.root(&hasher, 0);
        var pinned_buffer: [merkle.max_pinned_nodes]D = undefined;
        const pinned = mem.node_digests_to_pin(case.start, &pinned_buffer);
        const range: Range = .{ .start = case.start, .end = case.start + 1 };
        var proof = try mem.range_proof(gpa, &hasher, range, 0);
        defer proof.deinit(gpa);
        const element = [_][8]u8{be(case.start)};
        try testing.expect(try proof.verify_range_inclusion_with_pinned_nodes(
            gpa,
            &hasher,
            case.start,
            &element,
            pinned,
            &root,
        ));
        if (pinned.len == 0) continue;
        // A wrong pin, a missing pin, or an extra pin all fail.
        pinned[0].bytes[0] ^= 1;
        try testing.expect(!try proof.verify_range_inclusion_with_pinned_nodes(
            gpa,
            &hasher,
            case.start,
            &element,
            pinned,
            &root,
        ));
        pinned[0].bytes[0] ^= 1;
        try testing.expect(!try proof.verify_range_inclusion_with_pinned_nodes(
            gpa,
            &hasher,
            case.start,
            &element,
            pinned[1..],
            &root,
        ));
        pinned_buffer[pinned.len] = test_digest(9);
        try testing.expect(!try proof.verify_range_inclusion_with_pinned_nodes(
            gpa,
            &hasher,
            case.start,
            &element,
            pinned_buffer[0 .. pinned.len + 1],
            &root,
        ));
    }
}

test "verify range inclusion with pinned nodes across sizes" {
    try check_pinned_nodes_across_sizes(merkle.mmr.Family);
}

/// The first leaf a range of `width` can start at past the inactive peaks, or the last
/// window that fits.
fn active_start(comptime F: type, leaves: u64, inactive: usize, width: u64) u64 {
    var floor: u64 = 0;
    var peaks = F.peaks(F.location_to_position(leaves));
    for (0..inactive) |_| floor += @as(u64, 1) << @intCast(peaks.next().?.height);
    if (floor + width <= leaves) return floor;
    return leaves - width;
}

fn check_range_shapes(comptime F: type) !void {
    var mem = try build_raw(F, &H.init(.forward_fold), 123);
    defer mem.deinit(gpa);
    const leaves = mem.leaves();
    for ([_]merkle.Bagging{ .forward_fold, .backward_fold }) |bagging| {
        const hasher = H.init(bagging);
        for (0..peak_count(F, leaves) + 1) |inactive| {
            const start = active_start(F, leaves, inactive, 3);
            const root = try mem.root(&hasher, inactive);
            const elements = [_][8]u8{ be(start), be(start + 1), be(start + 2) };
            const range: Range = .{ .start = start, .end = start + 3 };
            var proof = try mem.range_proof(gpa, &hasher, range, inactive);
            defer proof.deinit(gpa);
            try testing.expectEqual(inactive, proof.inactive_peaks);
            try testing.expect(proof.verify_range_inclusion(&hasher, start, &elements, &root));
            proof.inactive_peaks = if (inactive == 0) 1 else 0;
            try testing.expect(!proof.verify_range_inclusion(&hasher, start, &elements, &root));
            proof.inactive_peaks = inactive;
            if (proof.digests.len == 0) continue;
            proof.digests[0].bytes[0] ^= 1;
            try testing.expect(!proof.verify_range_inclusion(&hasher, start, &elements, &root));
        }
    }
}

fn check_multi_shapes(comptime F: type) !void {
    var mem = try build_raw(F, &H.init(.forward_fold), 123);
    defer mem.deinit(gpa);
    const leaves = mem.leaves();
    for ([_]merkle.Bagging{ .forward_fold, .backward_fold }) |bagging| {
        const hasher = H.init(bagging);
        for (0..peak_count(F, leaves) + 1) |inactive| {
            const first = active_start(F, leaves, inactive, 12);
            const locations = [_]u64{ first, first + 5, first + 11 };
            var proof = try multi_proof(F, &mem, &locations, inactive);
            defer proof.deinit(gpa);
            const root = try mem.root(&hasher, inactive);
            var elements = [_][8]u8{ be(first), be(first + 5), be(first + 11) };
            try testing.expect(try multi_ok(&proof, &hasher, &locations, &elements, &root));
            const doubled_locations = [_]u64{ first, first + 5, first + 11, first + 11 };
            var doubled = [_][8]u8{ elements[0], elements[1], elements[2], elements[2] };
            try testing.expect(!try multi_ok(&proof, &hasher, &doubled_locations, &doubled, &root));
            doubled[3][0] ^= 1;
            try testing.expect(!try multi_ok(&proof, &hasher, &doubled_locations, &doubled, &root));
            const descending = [_]u64{ first + 11, first + 5, first };
            std.mem.reverse([8]u8, &elements);
            try testing.expect(!try multi_ok(&proof, &hasher, &descending, &elements, &root));
            std.mem.reverse([8]u8, &elements);
            proof.inactive_peaks = if (inactive == 0) 1 else 0;
            try testing.expect(!try multi_ok(&proof, &hasher, &locations, &elements, &root));
            proof.inactive_peaks = inactive;
            if (proof.digests.len == 0) continue;
            proof.digests[0].bytes[0] ^= 1;
            try testing.expect(!try multi_ok(&proof, &hasher, &locations, &elements, &root));
        }
    }
}

test "range and multi proofs verify for supported root shapes" {
    try check_range_shapes(merkle.mmr.Family);
    try check_multi_shapes(merkle.mmr.Family);
}

test "mmr proving digests from range" {
    const F = merkle.mmr.Family;
    const hasher = H.init(.forward_fold);
    var elements: [49]D = undefined;
    var mem = try build_digests(F, &hasher, &elements);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    var proof = try mem.range_proof(gpa, &hasher, .{ .start = 0, .end = mem.leaves() }, 0);
    defer proof.deinit(gpa);
    const NodeDigest = Proof(F).NodeDigest;
    var collected: std.ArrayList(NodeDigest) = .empty;
    defer collected.deinit(gpa);
    try proof.verify_range_inclusion_and_extract_digests(
        gpa,
        &hasher,
        0,
        &elements,
        &root,
        &collected,
    );
    // A full-range proof reconstructs every node exactly once.
    try testing.expectEqual(mem.size(), collected.items.len);
    const less = struct {
        fn less(_: void, a: NodeDigest, b: NodeDigest) bool {
            return a.position < b.position;
        }
    }.less;
    std.mem.sort(NodeDigest, collected.items, {}, less);
    for (collected.items, 0..) |item, i| {
        try testing.expectEqual(@as(u64, i), item.position);
        try testing.expect(mem.get_node(i).?.eql(item.digest));
    }
    collected.clearRetainingCapacity();
    const wrong = elements[0];
    const mismatch = proof.verify_range_inclusion_and_extract_digests(
        gpa,
        &hasher,
        0,
        &elements,
        &wrong,
        &collected,
    );
    try testing.expectError(error.RootMismatch, mismatch);
    const ranges = [_]Range{
        .{ .start = 0, .end = 1 },   .{ .start = 24, .end = 25 },
        .{ .start = 48, .end = 49 }, .{ .start = 0, .end = 5 },
    };
    for (ranges) |range| {
        var partial = try mem.range_proof(gpa, &hasher, range, 0);
        defer partial.deinit(gpa);
        collected.clearRetainingCapacity();
        const slice = elements[range.start..range.end];
        try partial.verify_range_inclusion_and_extract_digests(
            gpa,
            &hasher,
            range.start,
            slice,
            &root,
            &collected,
        );
        // The last leaf is a peak of its own, so its proof reconstructs only itself.
        const minimum: usize = if (range.end == 49) 1 else @intCast(range.end - range.start + 1);
        try testing.expect(collected.items.len >= minimum);
        for (collected.items) |item| {
            try testing.expect(mem.get_node(item.position).?.eql(item.digest));
        }
    }
}

test "roots commit family and bagging" {
    const F = merkle.mmr.Family;
    for (0..65) |n| {
        var mem = try build_raw(F, &H.init(.forward_fold), n);
        defer mem.deinit(gpa);
        var roots: merkle.BoundedList(D, 2 * (merkle.max_pinned_nodes + 1)) = .{};
        for ([_]merkle.Bagging{ .forward_fold, .backward_fold }) |bagging| {
            for (0..peak_count(F, n) + 1) |inactive| {
                const root = try mem.root(&H.init(bagging), inactive);
                for (roots.slice()) |other| try testing.expect(!other.eql(root));
                roots.append(root);
            }
        }
    }
}

// Fuzz: decode arbitrary bytes as a proof (any accepted encoding must re-encode to the same
// bytes), then verify it against a fixed structure at a fuzzed range. Verification must never
// crash, and a decoded proof that verifies must be the honest proof for that range.

const fuzz_bytes = @import("../fuzz_bytes.zig");
const fuzz_leaves = 37;

fn fuzz_proof_run(bytes: []const u8) anyerror!void {
    const F = merkle.mmr.Family;
    if (bytes.len < 3) return;
    const bagging: merkle.Bagging = if (bytes[0] & 1 == 0) .forward_fold else .backward_fold;
    const start: u64 = bytes[1] % (fuzz_leaves + 2);
    const count: usize = bytes[2] % 8;
    const hasher = H.init(bagging);
    var mem = try build_raw(F, &hasher, fuzz_leaves);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    var proof = codec.decode_cfg(Proof(F), gpa, bytes[3..], 64) catch return;
    defer proof.deinit(gpa);
    const encoded = try codec.encode(Proof(F), gpa, proof);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, bytes[3..], encoded);
    var elements: [8][8]u8 = undefined;
    for (elements[0..count], 0..) |*element, i| element.* = be(start + i);
    if (!proof.verify_range_inclusion(&hasher, start, elements[0..count], &root)) return;
    var honest = try mem.range_proof(gpa, &hasher, .{ .start = start, .end = start + count }, 0);
    defer honest.deinit(gpa);
    try testing.expect(proof.eql(&honest));
}

test "fuzz merkle proof decode and verify (seeded)" {
    try fuzz_bytes.seeded(512, 0x70726f6f66, 256, fuzz_proof_run);
}

test "fuzz merkle proof decode and verify" {
    try testing.fuzz({}, fuzz_bytes.smith(512, fuzz_proof_run), .{});
}

test "fuzz merkle proof accepts honest proofs" {
    // Seed the fuzz shape with real proofs so the verifier path is exercised, not only decoding.
    const F = merkle.mmr.Family;
    const hasher = H.init(.forward_fold);
    var mem = try build_raw(F, &hasher, fuzz_leaves);
    defer mem.deinit(gpa);
    for (0..fuzz_leaves) |start| {
        var proof = try mem.range_proof(gpa, &hasher, .{ .start = start, .end = start + 1 }, 0);
        defer proof.deinit(gpa);
        const encoded = try codec.encode(Proof(F), gpa, proof);
        defer gpa.free(encoded);
        var input: [512]u8 = undefined;
        input[0] = 0;
        input[1] = @intCast(start);
        input[2] = 1;
        @memcpy(input[3..][0..encoded.len], encoded);
        try fuzz_proof_run(input[0 .. 3 + encoded.len]);
    }
}
