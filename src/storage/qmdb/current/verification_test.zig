//! Tests that current's range and operation proofs built over the grafted view verify against
//! the canonical root, and reject tampering (commonware's `check_dynamic_proofs` and range
//! rejection tests over an in-memory ops tree).

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const grafting = @import("grafting.zig");
const canonical = @import("canonical.zig");
const grafted = @import("grafted.zig");
const proof_mod = @import("proof.zig");
const verification = @import("verification.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;

fn element(index: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, index, .big);
    return bytes;
}

/// An ops tree of `leaves` elements, a bitmap with every third bit set, its grafted tree, and
/// the canonical root.
fn Fixture(comptime F: type, comptime N: usize) type {
    return struct {
        const Self = @This();
        const Bits = utils.bitmap.Prunable(N);
        const Mem = merkle.mem.Mem(F, D);
        const View = grafted.Storage(F, Sha256, *const Mem, *const Mem);

        ops: Mem = .empty,
        bits: Bits = .empty,
        tree: Mem = .empty,
        roots: canonical.GraftRoots(D) = .{},
        ops_root: D = undefined,
        root: D = undefined,

        fn init(self: *Self, leaves: u64) !void {
            self.* = .{};
            const hasher = qmdb.hasher(Sha256);
            for (0..leaves) |i| {
                try self.ops.add(gpa, &hasher, &element(i));
                try self.bits.push(gpa, i % 3 == 0);
            }
            const build = canonical.build_grafted_tree;
            const bits = &self.bits;
            self.tree, self.roots = try build(F, Sha256, N, gpa, bits, &.{}, &self.ops, leaves);
            self.ops_root = try self.ops.root(&hasher, 0);
            const witness_of = canonical.compute_ops_root_witness;
            const view_value = self.view();
            const witness = try witness_of(F, Sha256, N, &self.bits, &view_value, leaves, 0);
            self.root = witness.root(Sha256, &self.ops_root);
        }

        fn deinit(self: *Self) void {
            self.ops.deinit(gpa);
            self.bits.deinit(gpa);
            self.tree.deinit(gpa);
            self.roots.deinit(gpa);
        }

        fn view(self: *const Self) View {
            const height = grafting.height(N);
            return .{ .grafted = &self.tree, .ops = &self.ops, .grafting_height = height };
        }

        fn range_proof(self: *const Self, start: u64, end: u64) !proof_mod.RangeProof(F, D) {
            const range: merkle.Range = .{ .start = start, .end = end };
            const view_value = self.view();
            const build = grafted.build_range_proof;
            return build(F, Sha256, N, gpa, &self.bits, &view_value, 0, range, self.ops_root);
        }

        /// The chunks covering `start..end`.
        fn chunks(
            self: *const Self,
            start: u64,
            end: u64,
            out: *[8][N]u8,
            slices: *[8][]const u8,
        ) []const []const u8 {
            const first = start / (N * 8);
            const last = (end - 1) / (N * 8);
            for (first..last + 1, 0..) |chunk, i| {
                out[i] = self.bits.get_chunk(chunk);
                slices[i] = &out[i];
            }
            return slices[0 .. last - first + 1];
        }
    };
}

fn vr(
    comptime F: type,
    range: *const proof_mod.RangeProof(F, D),
    start: u64,
    ops: []const []const u8,
    chunks: []const []const u8,
    chunk_size: usize,
    root: *const D,
) bool {
    return verification.verify_range(F, Sha256, range, start, ops, chunks, chunk_size, root);
}

fn check_ranges(comptime F: type, comptime N: usize, leaves: u64) !void {
    var fixture: Fixture(F, N) = undefined;
    try fixture.init(leaves);
    defer fixture.deinit();
    const chunk_bits: u64 = N * 8;
    const starts = [_]u64{ 0, chunk_bits -| 2, leaves / 2, leaves - 1 };
    for (starts) |start| {
        if (start >= leaves) continue;
        const end = @min(leaves, start + chunk_bits + 3);
        var range = try fixture.range_proof(start, end);
        defer range.deinit(gpa);
        var element_bytes: [512][8]u8 = undefined;
        var elements: [512][]const u8 = undefined;
        for (start..end, 0..) |loc, i| {
            element_bytes[i] = element(loc);
            elements[i] = &element_bytes[i];
        }
        const ops = elements[0 .. end - start];
        var chunk_store: [8][N]u8 = undefined;
        var chunk_slices: [8][]const u8 = undefined;
        const chunks = fixture.chunks(start, end, &chunk_store, &chunk_slices);
        const root = fixture.root;
        try testing.expect(vr(F, &range, start, ops, chunks, N, &root));
        // A wrong root, a flipped chunk bit, a wrong operation, or a short chunk list fail.
        const wrong = Sha256.hash(&.{"wrong root"});
        try testing.expect(!vr(F, &range, start, ops, chunks, N, &wrong));
        chunk_store[0][0] ^= 1;
        try testing.expect(!vr(F, &range, start, ops, chunks, N, &root));
        chunk_store[0][0] ^= 1;
        var tampered = element(start + 1);
        const original = elements[0];
        elements[0] = &tampered;
        try testing.expect(!vr(F, &range, start, ops, chunks, N, &root));
        elements[0] = original;
        try testing.expect(!vr(F, &range, start, ops, chunks[0..0], N, &root));
        for ([_]usize{ 0, 3, N * 2 }) |size| {
            try testing.expect(!vr(F, &range, start, ops, chunks, size, &root));
        }
        try check_operation(F, N, &fixture, start);
    }
}

/// An operation proof verifies exactly when the operation is active and unmodified.
fn check_operation(
    comptime F: type,
    comptime N: usize,
    fixture: *const Fixture(F, N),
    loc: u64,
) !void {
    const Operation = proof_mod.OperationProof(F, D, N);
    var range = try fixture.range_proof(loc, loc + 1);
    var operation: Operation = .{
        .loc = loc,
        .chunk = fixture.bits.get_chunk(@intCast(loc / (N * 8))),
        .range_proof = range,
    };
    defer operation.deinit(gpa);
    _ = &range;
    const bytes = element(loc);
    const active = loc % 3 == 0;
    const verify = verification.verify_operation;
    try testing.expectEqual(active, verify(F, Sha256, &operation, &bytes, &fixture.root));
    const other = element(loc + 1);
    try testing.expect(!verify(F, Sha256, &operation, &other, &fixture.root));
}

test "range and operation proofs verify (mmr)" {
    for ([_]u64{ 6, 8, 9, 17, 18, 40 }) |leaves| try check_ranges(Mmr, 1, leaves);
    for ([_]u64{ 255, 256, 257, 520 }) |leaves| try check_ranges(Mmr, 32, leaves);
}

test "range and operation proofs verify (mmb)" {
    for ([_]u64{ 6, 8, 9, 17, 18, 40 }) |leaves| try check_ranges(Mmb, 1, leaves);
    for ([_]u64{ 255, 256, 257, 520 }) |leaves| try check_ranges(Mmb, 32, leaves);
}

test "pending chunk digest presence must match the leaf count" {
    var fixture: Fixture(Mmb, 1) = undefined;
    try fixture.init(18);
    defer fixture.deinit();
    var range = try fixture.range_proof(6, 18);
    defer range.deinit(gpa);
    const flipped = range.pending_chunk_digest;
    range.pending_chunk_digest = if (flipped == null) Sha256.hash(&.{"x"}) else null;
    var bytes: [12][8]u8 = undefined;
    var ops: [12][]const u8 = undefined;
    for (0..12) |i| {
        bytes[i] = element(6 + i);
        ops[i] = &bytes[i];
    }
    var chunk_store: [8][1]u8 = undefined;
    var chunk_slices: [8][]const u8 = undefined;
    const chunks = fixture.chunks(6, 18, &chunk_store, &chunk_slices);
    try testing.expect(!vr(Mmb, &range, 6, &ops, chunks, 1, &fixture.root));
    range.pending_chunk_digest = flipped;
    try testing.expect(vr(Mmb, &range, 6, &ops, chunks, 1, &fixture.root));
}
