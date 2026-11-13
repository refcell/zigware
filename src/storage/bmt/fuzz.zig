//! Operation fuzzing for the Binary Merkle Tree (commonware's `storage/fuzz` target
//! `bmt_operations`).
//!
//! Each run draws operations from `invariants.minifuzz.Unstructured`: building trees, adding
//! leaves, generating and verifying single, range, and multi-proofs (correct, tampered,
//! reordered, out of range), and decoding arbitrary proof bytes. Results are checked where
//! commonware asserts them. An operation tag comes from `Unstructured.arbitrary` on an enum and
//! its fields follow, so inputs differ from commonware's derived layout while the operations
//! and checks are the same.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const minifuzz = @import("invariants").minifuzz;
const bmt = @import("mod.zig");

const Unstructured = minifuzz.Unstructured;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Proof = bmt.Proof(Digest);
const Element = Proof.Element;

/// Operations per run; bounds a run whose input never runs out.
const operations_max: usize = 256;
/// Positions and elements per multi-proof operation (commonware's `take(20)`).
const items_max: usize = 20;
/// Leaves per range verification.
const range_leaves_max: usize = 64;

const Operation = enum {
    build_tree,
    add_leaf,
    build_from_leaves,
    get_root,
    generate_proof,
    verify_proof,
    serialize_proof,
    deserialize_proof,
    build_empty_tree,
    build_large_tree,
    generate_range_proof,
    verify_range_proof,
    serialize_range_proof,
    deserialize_range_proof,
    range_proof_single_element,
    range_proof_full_tree,
    verify_range_proof_wrong_position,
    verify_range_proof_wrong_leaves,
    generate_multi_proof,
    verify_multi_proof,
    deserialize_multi_proof,
    multi_proof_duplicate_positions,
    verify_multi_proof_wrong_elements,
    verify_multi_proof_partial_elements,
    verify_multi_proof_correct,
    verify_multi_proof_unsorted,
    verify_multi_proof_out_of_bounds,
    verify_multi_proof_empty_elements,
    verify_multi_proof_wrong_root,
    verify_multi_proof_single_element,
    verify_multi_proof_duplicate_positions,
};

/// The state one run threads through its operations. Everything lives in the run's arena.
const State = struct {
    gpa: Allocator,
    builder: ?bmt.Builder(Sha256) = null,
    tree: ?bmt.Tree(Digest) = null,
    proof: ?Proof = null,
    range_proof: ?Proof = null,
    multi_proof: ?Proof = null,
    multi_positions: []const u32 = &.{},
    leaf_values: std.ArrayList(u64) = .empty,

    fn root(self: *const State) ?Digest {
        const tree = self.tree orelse return null;
        return tree.root();
    }

    /// `(p, hash(leaf_values[p]))` for each of `positions` that has a leaf value.
    fn known_elements(self: *const State, positions: []const u32) ![]Element {
        var elements: std.ArrayList(Element) = .empty;
        for (positions) |position| {
            if (position >= self.leaf_values.items.len) continue;
            const digest = hash_value(self.leaf_values.items[position]);
            try elements.append(self.gpa, .{ .position = position, .digest = digest });
        }
        return elements.items;
    }
};

fn hash_value(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

/// Runs operations until the input runs out or `operations_max` operations ran.
pub fn run(gpa: Allocator, u: *Unstructured) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var state: State = .{ .gpa = arena.allocator() };
    var count: usize = 0;
    while (count < operations_max and !u.is_empty()) : (count += 1) {
        const operation = try u.arbitrary(Operation);
        try step(&state, operation, u);
    }
    assert(count <= operations_max);
}

fn step(state: *State, operation: Operation, u: *Unstructured) !void {
    switch (operation) {
        .build_tree,
        .add_leaf,
        .build_from_leaves,
        .get_root,
        .build_empty_tree,
        .build_large_tree,
        => try step_tree(state, operation, u),
        .generate_proof,
        .verify_proof,
        .serialize_proof,
        .deserialize_proof,
        => try step_proof(state, operation, u),
        .generate_range_proof,
        .verify_range_proof,
        .serialize_range_proof,
        .deserialize_range_proof,
        .range_proof_single_element,
        .range_proof_full_tree,
        .verify_range_proof_wrong_position,
        .verify_range_proof_wrong_leaves,
        => try step_range(state, operation, u),
        .generate_multi_proof,
        .deserialize_multi_proof,
        .multi_proof_duplicate_positions,
        .verify_multi_proof_single_element,
        => try step_multi(state, operation, u),
        else => try step_verify_multi(state, operation, u),
    }
}

fn step_tree(state: *State, operation: Operation, u: *Unstructured) !void {
    const gpa = state.gpa;
    switch (operation) {
        .build_tree => {
            const count = @min(try u.arbitrary(u8), 50);
            state.builder = try .init(gpa, count);
            state.leaf_values.clearRetainingCapacity();
        },
        .add_leaf => {
            const value = try u.arbitrary(u64);
            if (state.builder) |*builder| {
                _ = try builder.add(gpa, &hash_value(value));
                try state.leaf_values.append(gpa, value);
            }
        },
        .build_from_leaves => if (state.builder) |*builder| {
            state.tree = try builder.build(gpa);
            state.builder = null;
        },
        .get_root => _ = state.root(),
        .build_empty_tree => {
            const empty = try bmt.Builder(Sha256).init(gpa, 0);
            state.tree = try empty.build(gpa);
            state.leaf_values.clearRetainingCapacity();
        },
        .build_large_tree => {
            const count = @min(try u.arbitrary(u8), 100);
            var builder = try bmt.Builder(Sha256).init(gpa, count);
            state.leaf_values.clearRetainingCapacity();
            for (0..count) |i| {
                _ = try builder.add(gpa, &hash_value(i));
                try state.leaf_values.append(gpa, i);
            }
            state.tree = try builder.build(gpa);
        },
        else => unreachable,
    }
}

fn step_proof(state: *State, operation: Operation, u: *Unstructured) !void {
    const gpa = state.gpa;
    switch (operation) {
        .generate_proof => {
            const position = try u.arbitrary(u32);
            if (state.tree) |*tree| {
                if (tree.proof(gpa, position, null)) |proof| state.proof = proof else |err| {
                    if (err == error.OutOfMemory) return err;
                }
            }
        },
        .verify_proof => {
            const value = try u.arbitrary(u64);
            const position = try u.arbitrary(u32);
            const proof = state.proof orelse return;
            const root = state.root() orelse return;
            proof.verify_element_inclusion(
                Sha256,
                position,
                &hash_value(value),
                &root,
                null,
            ) catch {};
        },
        .serialize_proof => if (state.proof) |proof| try round_trip(gpa, proof, 1),
        .deserialize_proof => try decode_arbitrary(gpa, u, 1),
        else => unreachable,
    }
}

/// Encodes `proof` and checks that it decodes to itself under `max_items`.
fn round_trip(gpa: Allocator, proof: Proof, max_items: usize) !void {
    const encoded = try codec.encode(Proof, gpa, proof);
    if (proof.siblings.len > max_items * bmt.max_levels) return;
    const decoded = try codec.decode_cfg(Proof, gpa, encoded, max_items);
    try testing.expect(decoded.eql(&proof));
}

/// Decodes arbitrary bytes as a proof; a decoded proof must re-encode to the same bytes.
fn decode_arbitrary(gpa: Allocator, u: *Unstructured, max_items: usize) !void {
    const len = u.arbitrary_len(u8);
    const data = try u.bytes(len);
    const proof = codec.decode_cfg(Proof, gpa, data, max_items) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
    const encoded = try codec.encode(Proof, gpa, proof);
    try testing.expectEqualSlices(u8, data, encoded);
}

fn store_range(state: *State, start: u32, end: u32) !void {
    const tree = &(state.tree orelse return);
    if (tree.range_proof(
        state.gpa,
        start,
        end,
        null,
    )) |proof| state.range_proof = proof else |err| {
        if (err == error.OutOfMemory) return err;
    }
}

/// Up to `range_leaves_max` digests of arbitrary values.
fn arbitrary_digests(gpa: Allocator, u: *Unstructured) ![]Digest {
    const len = @min(u.arbitrary_len(u64), range_leaves_max);
    const digests = try gpa.alloc(Digest, len);
    for (digests) |*digest| digest.* = hash_value(try u.arbitrary(u64));
    return digests;
}

fn verify_range(state: *State, position: u32, leaves: []const Digest) !void {
    const proof = state.range_proof orelse return;
    const root = state.root() orelse return;
    proof.verify_range_inclusion(Sha256, state.gpa, position, leaves, &root, null) catch |err| {
        if (err == error.OutOfMemory) return err;
    };
}

fn step_range(state: *State, operation: Operation, u: *Unstructured) !void {
    const gpa = state.gpa;
    switch (operation) {
        .generate_range_proof => try store_range(state, try u.arbitrary(u32), try u.arbitrary(u32)),
        .verify_range_proof, .verify_range_proof_wrong_leaves => {
            const position = try u.arbitrary(u32);
            try verify_range(state, position, try arbitrary_digests(gpa, u));
        },
        .serialize_range_proof => if (state.range_proof) |proof| try round_trip(gpa, proof, 32),
        .deserialize_range_proof => try decode_arbitrary(gpa, u, 32),
        .range_proof_single_element => {
            const position = try u.arbitrary(u32);
            try store_range(state, position, position);
        },
        .range_proof_full_tree => {
            const last: u32 = @intCast(state.leaf_values.items.len -| 1);
            try store_range(state, 0, last);
        },
        .verify_range_proof_wrong_position => try range_wrong_position(state, u),
        else => unreachable,
    }
}

/// Proves real leaves from `proof_start` and verifies them at `verify_start`, which must
/// fail unless the two positions agree.
fn range_wrong_position(state: *State, u: *Unstructured) !void {
    const proof_start = try u.arbitrary(u32);
    const verify_start = try u.arbitrary(u32);
    const count: usize = std.math.clamp(try u.arbitrary(u8), 1, 10);
    const tree = &(state.tree orelse return);
    const values = state.leaf_values.items;
    if (proof_start >= values.len) return;
    const actual = @min(count, values.len - proof_start);
    const end = proof_start +| @as(u32, @intCast(actual - 1));
    const proof = tree.range_proof(state.gpa, proof_start, end, null) catch |err| {
        if (err == error.OutOfMemory) return err;
        return;
    };
    const leaves = try state.gpa.alloc(Digest, actual);
    for (leaves, values[proof_start..][0..actual]) |*leaf, value| leaf.* = hash_value(value);
    const root = tree.root();
    const result = proof.verify_range_inclusion(
        Sha256,
        state.gpa,
        verify_start,
        leaves,
        &root,
        null,
    );
    if (verify_start != proof_start) try testing.expect(std.meta.isError(result));
}

fn step_multi(state: *State, operation: Operation, u: *Unstructured) !void {
    const gpa = state.gpa;
    switch (operation) {
        .generate_multi_proof => try generate_multi(state, u),
        .deserialize_multi_proof => {
            const max: usize = std.math.clamp(try u.arbitrary(u8), 1, 100);
            try decode_arbitrary(gpa, u, max);
        },
        .multi_proof_duplicate_positions => {
            const position = try u.arbitrary(u32);
            const count: usize = std.math.clamp(try u.arbitrary(u8), 2, 10);
            const tree = &(state.tree orelse return);
            const positions = try gpa.alloc(u32, count);
            @memset(positions, position);
            // Repeated positions are never strictly ascending.
            const result = tree.multi_proof(gpa, positions, null);
            if (result == error.OutOfMemory) return error.OutOfMemory;
            try testing.expect(std.meta.isError(result));
        },
        .verify_multi_proof_single_element => {
            const position = try u.arbitrary(u32);
            const tree = &(state.tree orelse return);
            if (position >= state.leaf_values.items.len) return;
            const proof = tree.multi_proof(gpa, &.{position}, null) catch |err| {
                if (err == error.OutOfMemory) return err;
                return;
            };
            const element: Element = .{
                .position = position,
                .digest = hash_value(state.leaf_values.items[position]),
            };
            const root = tree.root();
            proof.verify_multi_inclusion(Sha256, gpa, &.{element}, &root, null) catch |err| {
                if (err == error.OutOfMemory) return err;
            };
        },
        else => unreachable,
    }
}

/// Proves the sorted, deduplicated positions; when that changed the input, the raw input is
/// not strictly ascending and must be rejected, as a repeat or descent if the clean set proves.
fn generate_multi(state: *State, u: *Unstructured) !void {
    const gpa = state.gpa;
    const len = @min(u.arbitrary_len(u32), items_max);
    const raw = try gpa.alloc(u32, len);
    for (raw) |*position| position.* = try u.arbitrary(u32);
    const tree = &(state.tree orelse return);

    const positions = try gpa.dupe(u32, raw);
    std.mem.sort(u32, positions, {}, std.sort.asc(u32));
    var unique: usize = 0;
    for (positions) |position| {
        if (unique > 0 and positions[unique - 1] == position) continue;
        positions[unique] = position;
        unique += 1;
    }
    const limited = positions[0..unique];
    const result = tree.multi_proof(gpa, limited, null);
    if (result == error.OutOfMemory) return error.OutOfMemory;
    if (!std.mem.eql(u32, raw, limited)) {
        const raw_result = tree.multi_proof(gpa, raw, null);
        if (raw_result == error.OutOfMemory) return error.OutOfMemory;
        if (result) |_| {
            const err = if (raw_result) |_| return error.TestUnexpectedResult else |e| e;
            try testing.expect(err == error.DuplicatePosition or err == error.UnsortedPosition);
        } else |_| try testing.expect(std.meta.isError(raw_result));
    }
    if (result) |proof| {
        state.multi_proof = proof;
        state.multi_positions = limited;
    } else |_| {}
}

fn verify_multi(state: *State, elements: []const Element, root: *const Digest) !?bmt.Error {
    const proof = state.multi_proof orelse return null;
    proof.verify_multi_inclusion(Sha256, state.gpa, elements, root, null) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => |e| return e,
    };
    return null;
}

/// Up to `items_max` elements at arbitrary positions with arbitrary values.
fn arbitrary_elements(gpa: Allocator, u: *Unstructured) ![]Element {
    const len = @min(u.arbitrary_len(u64), items_max);
    const elements = try gpa.alloc(Element, len);
    for (elements) |*element| {
        const value = try u.arbitrary(u64);
        element.* = .{ .position = try u.arbitrary(u32), .digest = hash_value(value) };
    }
    return elements;
}

fn step_verify_multi(state: *State, operation: Operation, u: *Unstructured) !void {
    const gpa = state.gpa;
    switch (operation) {
        .verify_multi_proof, .verify_multi_proof_wrong_elements => {
            const elements = try arbitrary_elements(gpa, u);
            const root = state.root() orelse return;
            _ = try verify_multi(state, elements, &root);
        },
        .verify_multi_proof_partial_elements => {
            const skip_count = try u.arbitrary(u8);
            const positions = state.multi_positions;
            if (state.multi_proof == null or positions.len == 0) return;
            const root = state.root() orelse return;
            const skip = skip_count % positions.len;
            _ = try verify_multi(state, try state.known_elements(positions[skip..]), &root);
        },
        .verify_multi_proof_correct => {
            const root = state.root() orelse return;
            if (state.multi_positions.len == 0) return;
            _ = try verify_multi(state, try state.known_elements(state.multi_positions), &root);
        },
        .verify_multi_proof_unsorted => try verify_unsorted(state),
        .verify_multi_proof_out_of_bounds => {
            const position = try u.arbitrary(u32);
            const root = state.root() orelse return;
            const element: Element = .{ .position = position, .digest = hash_value(0) };
            _ = try verify_multi(state, &.{element}, &root);
        },
        .verify_multi_proof_empty_elements => {
            const root = state.root() orelse return;
            _ = try verify_multi(state, &.{}, &root);
        },
        .verify_multi_proof_wrong_root => try verify_wrong_root(state, u),
        .verify_multi_proof_duplicate_positions => try verify_duplicate(state, u),
        else => unreachable,
    }
}

/// Descending elements report the first descent, the second element's position.
fn verify_unsorted(state: *State) !void {
    if (state.multi_proof == null or state.multi_positions.len <= 1) return;
    const root = state.root() orelse return;
    const elements = try state.known_elements(state.multi_positions);
    std.mem.reverse(Element, elements);
    const proof = state.multi_proof.?;
    var diagnostic: bmt.Diagnostic = .{};
    const result = proof.verify_multi_inclusion(Sha256, state.gpa, elements, &root, &diagnostic);
    if (elements.len > 1) {
        try testing.expectError(error.UnsortedPosition, result);
        try testing.expectEqual(elements[1].position, diagnostic.position);
    }
}

fn verify_wrong_root(state: *State, u: *Unstructured) !void {
    const modifier = try u.arbitrary(u64);
    if (state.multi_proof == null or state.multi_positions.len == 0) return;
    const root = state.root() orelse return;
    var modifier_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &modifier_bytes, modifier, .big);
    const wrong_root = Sha256.hash(&.{ &root.bytes, &modifier_bytes });
    const elements = try state.known_elements(state.multi_positions);
    _ = try verify_multi(state, elements, &wrong_root);
}

/// A repeated position is reported as a repeat, unless it is out of range.
fn verify_duplicate(state: *State, u: *Unstructured) !void {
    const position = try u.arbitrary(u32);
    const proof = state.multi_proof orelse return;
    const root = state.root() orelse return;
    const digest = hash_value(0);
    const elements = [_]Element{
        .{ .position = position, .digest = digest },
        .{ .position = position, .digest = digest },
    };
    var diagnostic: bmt.Diagnostic = .{};
    const result = proof.verify_multi_inclusion(Sha256, state.gpa, &elements, &root, &diagnostic);
    if (position < proof.leaf_count) {
        try testing.expectError(error.DuplicatePosition, result);
    } else {
        try testing.expectError(error.InvalidPosition, result);
    }
    try testing.expectEqual(position, diagnostic.position);
}

/// Runs `bytes` as one input, as the coverage-guided target does.
pub fn run_input(gpa: Allocator, bytes: []const u8) !void {
    var u = Unstructured.init(bytes);
    run(gpa, &u) catch |err| switch (err) {
        error.NotEnoughData, error.IncorrectFormat => {},
        else => return err,
    };
}

fn run_body(_: void, u: *Unstructured) !void {
    return run(testing.allocator, u);
}

test "fuzz bmt operations (minifuzz)" {
    try (minifuzz.Builder{}).with_seed(0).with_search_limit(2000).run(
        testing.allocator,
        {},
        run_body,
    );
}

test "fuzz bmt operations (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [4096]u8 = undefined;
            const length = smith.slice(&bytes);
            try run_input(testing.allocator, bytes[0..length]);
        }
    }.run, .{});
}
