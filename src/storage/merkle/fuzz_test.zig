//! Merkle fuzz targets from commonware's storage/fuzz: `merkle_family_operations`,
//! `merkle_range_proof`, and the Merkle half of `proofs_malleability` (its BMT half belongs
//! with bmt). Each runs under both families, seeded in `zig build test` and under
//! `std.testing.fuzz`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const codec = @import("codec");
const merkle = @import("mod.zig");
const verification = @import("verification.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");

const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const H = merkle.hasher.Standard(Sha256);
const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };

fn Mem(comptime F: type) type {
    return merkle.mem.Mem(F, D);
}

fn peak_count(comptime F: type, size: u64) usize {
    var count: usize = 0;
    var peaks = F.peaks(size);
    while (peaks.next()) |_| count += 1;
    assert(count <= merkle.max_pinned_nodes);
    return count;
}

// merkle_family_operations: random adds, leaf updates, reads, proofs, and prunes against a
// reference list of leaf data. The reference also rebuilds the root from scratch, which
// commonware's target does not check.

const family_operations_max = 96;
const family_data_max = 16;

const Leaf = struct { data: [family_data_max]u8, len: usize };

fn read_data(reader: *fuzz_bytes.Reader) Leaf {
    var leaf: Leaf = .{ .data = undefined, .len = reader.below(family_data_max + 1) };
    for (leaf.data[0..leaf.len]) |*byte| byte.* = reader.int(u8);
    return leaf;
}

fn rebuilt_root(comptime F: type, hasher: *const H, leaves: []const Leaf) !D {
    var mem: Mem(F) = .empty;
    defer mem.deinit(gpa);
    for (leaves) |*leaf| try mem.add(gpa, hasher, leaf.data[0..leaf.len]);
    return mem.root(hasher, 0);
}

fn family_update(
    comptime F: type,
    mem: *Mem(F),
    hasher: *const H,
    leaves: []Leaf,
    reader: *fuzz_bytes.Reader,
) !void {
    const location = reader.int(u8) % leaves.len;
    const leaf = read_data(reader);
    if (location < mem.pruning_boundary()) {
        const result = mem.update_leaf(hasher, location, leaf.data[0..leaf.len]);
        try testing.expectError(error.ElementPruned, result);
        return;
    }
    const size = mem.size();
    const root = try mem.root(hasher, 0);
    const old = &leaves[location];
    const changes = !std.mem.eql(u8, old.data[0..old.len], leaf.data[0..leaf.len]);
    try mem.update_leaf(hasher, location, leaf.data[0..leaf.len]);
    old.* = leaf;
    try testing.expectEqual(size, mem.size());
    if (changes) try testing.expect(!root.eql(try mem.root(hasher, 0)));
}

fn family_step(
    comptime F: type,
    mem: *Mem(F),
    hasher: *const H,
    leaves: *std.ArrayList(Leaf),
    reader: *fuzz_bytes.Reader,
) !void {
    switch (reader.below(7)) {
        0 => {
            const leaf = read_data(reader);
            const size = mem.size();
            try mem.add(gpa, hasher, leaf.data[0..leaf.len]);
            try leaves.append(gpa, leaf);
            try testing.expect(mem.size() > size);
            try testing.expectEqual(@as(u64, leaves.items.len), mem.leaves());
            const position = F.location_to_position(mem.leaves() - 1);
            try testing.expect(mem.get_node(position) != null);
        },
        1 => if (leaves.items.len > 0) try family_update(F, mem, hasher, leaves.items, reader),
        2 => if (mem.size() > 0) {
            const position = reader.int(u64) % mem.size();
            const boundary = F.location_to_position(mem.pruning_boundary());
            if (position >= boundary) try testing.expect(mem.get_node(position) != null);
        },
        3 => {
            const leaves_count: u64 = leaves.items.len;
            try testing.expectEqual(F.location_to_position(leaves_count), mem.size());
            const expected = try rebuilt_root(F, hasher, leaves.items);
            try testing.expect(expected.eql(try mem.root(hasher, 0)));
        },
        4 => if (leaves.items.len > 0) {
            const location = reader.int(u64) % leaves.items.len;
            if (location < mem.pruning_boundary()) return;
            var proof = try mem.proof(gpa, hasher, location, 0);
            defer proof.deinit(gpa);
            const root = try mem.root(hasher, 0);
            const leaf = &leaves.items[location];
            const element = leaf.data[0..leaf.len];
            try testing.expect(proof.verify_element_inclusion(hasher, location, element, &root));
        },
        5 => {
            const size = mem.size();
            mem.prune_all();
            try testing.expectEqual(size, mem.size());
            try testing.expectEqual(mem.leaves(), mem.pruning_boundary());
            _ = try mem.root(hasher, 0);
        },
        6 => if (mem.size() > 0) {
            const location = reader.int(u64) % (mem.leaves() + 1);
            const before = mem.pruning_boundary();
            if (location <= before) return;
            const size = mem.size();
            try mem.prune(location);
            try testing.expectEqual(size, mem.size());
            try testing.expectEqual(location, mem.pruning_boundary());
            _ = try mem.root(hasher, 0);
        },
        else => unreachable,
    }
}

fn family_run(bytes: []const u8) anyerror!void {
    const hasher = H.init(.forward_fold);
    inline for (families) |F| {
        var reader = fuzz_bytes.Reader.init(bytes);
        var mem: Mem(F) = .empty;
        defer mem.deinit(gpa);
        var leaves: std.ArrayList(Leaf) = .empty;
        defer leaves.deinit(gpa);
        var operations: u32 = 0;
        while (!reader.done() and operations < family_operations_max) : (operations += 1) {
            try family_step(F, &mem, &hasher, &leaves, &reader);
        }
        const expected = try rebuilt_root(F, &hasher, leaves.items);
        try testing.expect(expected.eql(try mem.root(&hasher, 0)));
    }
}

test "fuzz merkle family operations (seeded)" {
    try fuzz_bytes.seeded(512, 0x66616d696c79, 64, family_run);
}

test "fuzz merkle family operations" {
    try testing.fuzz({}, fuzz_bytes.smith(512, family_run), .{});
}

// merkle_range_proof: `Mem.init` from arbitrary nodes, boundary, and pins (often rejected),
// then range proofs from a start to the end under every bagging and inactive-peak count.
// Half the inputs get a valid node and pin count so `init` succeeds; proving from a retained
// start must then succeed.

fn range_input_digests(reader: *fuzz_bytes.Reader, out: []D) void {
    for (out) |*digest| digest.* = .{ .bytes = @bitCast(reader.int(u256)) };
}

fn range_run_family(comptime F: type, reader: *fuzz_bytes.Reader) !void {
    var boundary = reader.int(u64);
    var node_count = reader.below(64);
    var pin_count = reader.below(merkle.max_pinned_nodes + 1);
    if (reader.boolean()) {
        boundary %= 48;
        const total = F.location_to_position(boundary + reader.below(48));
        node_count = total - F.location_to_position(boundary);
        var pins: [merkle.max_pinned_nodes]u64 = undefined;
        pin_count = merkle.nodes_to_pin(F, boundary, &pins).len;
    }
    var nodes: [128]D = undefined;
    var pinned: [merkle.max_pinned_nodes]D = undefined;
    range_input_digests(reader, nodes[0..node_count]);
    range_input_digests(reader, pinned[0..pin_count]);
    const start_input = reader.int(u64);
    var mem = Mem(F).init(gpa, nodes[0..node_count], boundary, pinned[0..pin_count]) catch
        return;
    defer mem.deinit(gpa);
    const leaves = mem.leaves();
    if (leaves == 0) return;
    const start = start_input % leaves;
    for (0..peak_count(F, mem.size()) + 1) |inactive_peaks| {
        for ([_]merkle.Bagging{ .forward_fold, .backward_fold }) |bagging| {
            const hasher = H.init(bagging);
            const range: merkle.Range = .{ .start = start, .end = leaves };
            var proof = mem.range_proof(gpa, &hasher, range, inactive_peaks) catch |err| {
                if (start >= mem.pruning_boundary()) return err;
                continue;
            };
            proof.deinit(gpa);
        }
    }
}

fn range_run(bytes: []const u8) anyerror!void {
    inline for (families) |F| {
        var reader = fuzz_bytes.Reader.init(bytes);
        try range_run_family(F, &reader);
    }
}

test "fuzz merkle range proof (seeded)" {
    try fuzz_bytes.seeded(4096, 0x72616e6765, 64, range_run);
}

test "fuzz merkle range proof" {
    try testing.fuzz({}, fuzz_bytes.smith(4096, range_run), .{});
}

// proofs_malleability (Merkle half): any change to a valid element or range proof, through
// its encoding or its inactive-peak count, must fail verification.

const malleability_elements_max = 40;
const malleability_mutations_max = 8;

const Mutations = struct {
    bytes: [malleability_mutations_max][5]u16,
    count: usize,
    inactive_mask: usize,

    fn read(reader: *fuzz_bytes.Reader) Mutations {
        var self: Mutations = .{
            .bytes = undefined,
            .count = 1 + reader.below(malleability_mutations_max),
            .inactive_mask = @max(1, reader.int(u64)),
        };
        for (self.bytes[0..self.count]) |*mutation| {
            mutation.* = .{ @intCast(reader.below(5)), reader.int(u16), reader.int(u16), 0, 0 };
        }
        return self;
    }
};

/// Applies one byte-level mutation to `encoded` (with one spare byte of capacity) and
/// returns the mutated length, or null when the mutation does not apply.
fn mutate(encoded: []u8, len: usize, mutation: [5]u16) ?usize {
    assert(encoded.len == len + 1);
    const kind = mutation[0];
    const a = mutation[1];
    const b = mutation[2];
    if (len == 0 and kind != 1) return null;
    switch (kind) {
        0 => encoded[a % len] ^= @as(u8, 1) << @intCast(b % 8),
        1 => {
            const at = a % (len + 1);
            std.mem.copyBackwards(u8, encoded[at + 1 .. len + 1], encoded[at..len]);
            encoded[at] = @truncate(b);
            return len + 1;
        },
        2 => {
            const at = a % len;
            std.mem.copyForwards(u8, encoded[at .. len - 1], encoded[at + 1 .. len]);
            return len - 1;
        },
        3 => encoded[a % len] = @truncate(b),
        4 => {
            if (a % len == b % len) return null;
            std.mem.swap(u8, &encoded[a % len], &encoded[b % len]);
        },
        else => unreachable,
    }
    return len;
}

/// Checks every mutation of `proof`: a decodable result that differs must not verify.
fn expect_malleability_rejected(
    proof: anytype,
    mutations: *const Mutations,
    hasher: *const H,
    start: u64,
    elements: []const D,
    root: *const D,
) !void {
    const Proof = @TypeOf(proof.*);
    var changed = try proof.clone(gpa);
    defer changed.deinit(gpa);
    changed.inactive_peaks ^= mutations.inactive_mask;
    try testing.expect(!changed.eql(proof));
    try testing.expect(!changed.verify_range_inclusion(hasher, start, elements, root));
    const encoded = try codec.encode(Proof, gpa, proof.*);
    defer gpa.free(encoded);
    const buffer = try gpa.alloc(u8, encoded.len + 1);
    defer gpa.free(buffer);
    for (mutations.bytes[0..mutations.count]) |mutation| {
        @memcpy(buffer[0..encoded.len], encoded);
        const len = mutate(buffer, encoded.len, mutation) orelse continue;
        var mutated = codec.decode_cfg(Proof, gpa, buffer[0..len], 256) catch continue;
        defer mutated.deinit(gpa);
        if (mutated.eql(proof)) continue;
        try testing.expect(!mutated.verify_range_inclusion(hasher, start, elements, root));
    }
}

fn malleability_family(comptime F: type, reader: *fuzz_bytes.Reader, element_proofs: bool) !void {
    const mutations = Mutations.read(reader);
    var digests: [malleability_elements_max]D = undefined;
    const count = reader.below(malleability_elements_max + 1);
    for (digests[0..count]) |*digest| digest.* = Sha256.hash(&.{&.{reader.int(u8)}});
    const first = reader.below(@max(count, 1));
    const last = reader.below(@max(count, 1));
    var mem: Mem(F) = .empty;
    defer mem.deinit(gpa);
    const build_hasher = H.init(.forward_fold);
    for (digests[0..count]) |*digest| try mem.add(gpa, &build_hasher, &digest.bytes);
    for (0..peak_count(F, mem.size()) + 1) |inactive_peaks| {
        for ([_]merkle.Bagging{ .forward_fold, .backward_fold }) |bagging| {
            const hasher = H.init(bagging);
            const root = try mem.root(&hasher, inactive_peaks);
            const range: merkle.Range = if (element_proofs or count == 0)
                .{ .start = first, .end = first + 1 }
            else
                .{ .start = @min(first, last), .end = @max(first, last) + 1 };
            if (range.end > count) continue;
            var proof = try verification.range_proof(F, gpa, &hasher, &mem, range, inactive_peaks);
            defer proof.deinit(gpa);
            const elements = digests[range.start..range.end];
            try testing.expect(proof.verify_range_inclusion(&hasher, range.start, elements, &root));
            const start = range.start;
            try expect_malleability_rejected(&proof, &mutations, &hasher, start, elements, &root);
        }
    }
}

fn malleability_run(bytes: []const u8) anyerror!void {
    inline for (families) |F| {
        var reader = fuzz_bytes.Reader.init(bytes);
        const element_proofs = reader.boolean();
        try malleability_family(F, &reader, element_proofs);
    }
}

test "fuzz merkle proofs malleability (seeded)" {
    try fuzz_bytes.seeded(512, 0x6d616c6c, 64, malleability_run);
}

test "fuzz merkle proofs malleability" {
    try testing.fuzz({}, fuzz_bytes.smith(512, malleability_run), .{});
}
