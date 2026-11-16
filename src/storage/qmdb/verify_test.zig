//! Tests for qmdb/verify.rs, run under both Merkle families.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const merkle = @import("../merkle/mod.zig");
const qmdb = @import("mod.zig");
const verify = @import("verify.zig");

const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };

fn test_digest(v: u8) Digest {
    return Sha256.hash(&.{&.{v}});
}

fn Fixture(comptime F: type) type {
    return struct {
        const Self = @This();
        const P = verify.Proof(F, Sha256);

        mem: merkle.mem.Mem(F, Digest) = .empty,
        hasher: merkle.hasher.Standard(Sha256) = qmdb.hasher(Sha256),

        fn init(gpa: Allocator, ops: []const u64) !Self {
            var self: Self = .{};
            errdefer self.mem.deinit(gpa);
            for (ops) |op| {
                const encoded = codec.encode_fixed(u64, op);
                try self.mem.add(gpa, &self.hasher, &encoded);
            }
            return self;
        }

        fn deinit(self: *Self, gpa: Allocator) void {
            self.mem.deinit(gpa);
        }

        fn root(self: *const Self, inactive_peaks: usize) !Digest {
            return self.mem.root(&self.hasher, inactive_peaks);
        }

        fn range_proof(
            self: *const Self,
            gpa: Allocator,
            inactive: usize,
            start: u64,
            end: u64,
        ) !P {
            const plan = try merkle.proof.RangePlan(F).init(self.mem.leaves(), .{
                .start = start,
                .end = end,
            });
            return plan.build(gpa, &self.hasher, inactive, &self.mem);
        }
    };
}

fn range(comptime n: u64) [n]u64 {
    var out: [n]u64 = undefined;
    for (&out, 0..) |*op, i| op.* = i;
    return out;
}

fn verify_proof(comptime F: type) !void {
    const gpa = testing.allocator;
    const ops = [_]u64{ 1, 2, 3 };
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    const root = try fixture.root(0);
    var proof = try fixture.range_proof(gpa, 0, 0, 3);
    defer proof.deinit(gpa);
    try testing.expect(try verify.verify(F, Sha256, u64, gpa, &proof, 0, &ops, &root));
    const wrong_root = test_digest(99);
    try testing.expect(!try verify.verify(F, Sha256, u64, gpa, &proof, 0, &ops, &wrong_root));
    const wrong_ops = [_]u64{ 9, 10, 11 };
    try testing.expect(!try verify.verify(F, Sha256, u64, gpa, &proof, 0, &wrong_ops, &root));
}

test "verify proof" {
    inline for (families) |F| try verify_proof(F);
}

fn verify_proof_with_offset(comptime F: type) !void {
    const gpa = testing.allocator;
    const all = [_]u64{ 0, 1, 2, 3, 4, 10, 11, 12 };
    const ops = all[5..];
    var fixture = try Fixture(F).init(gpa, &all);
    defer fixture.deinit(gpa);
    const root = try fixture.root(0);
    var proof = try fixture.range_proof(gpa, 0, 5, 8);
    defer proof.deinit(gpa);
    try testing.expect(try verify.verify(F, Sha256, u64, gpa, &proof, 5, ops, &root));
    try testing.expect(!try verify.verify(F, Sha256, u64, gpa, &proof, 0, ops, &root));
}

test "verify proof with offset" {
    inline for (families) |F| try verify_proof_with_offset(F);
}

fn verify_and_extract_digests(comptime F: type) !void {
    const gpa = testing.allocator;
    const P = verify.Proof(F, Sha256);
    const ops = [_]u64{ 1, 2, 3, 4 };
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    const root = try fixture.root(0);
    var proof = try fixture.range_proof(gpa, 0, 1, 4);
    defer proof.deinit(gpa);
    var digests: std.ArrayList(P.NodeDigest) = .empty;
    defer digests.deinit(gpa);
    const extract = verify.verify_and_extract_digests;
    try extract(F, Sha256, u64, gpa, &proof, 1, ops[1..4], &root, &digests);
    try testing.expect(digests.items.len > 0);
    const wrong_root = test_digest(99);
    digests.clearRetainingCapacity();
    try testing.expectError(
        error.RootMismatch,
        extract(F, Sha256, u64, gpa, &proof, 1, ops[1..4], &wrong_root, &digests),
    );
}

test "verify and extract digests" {
    inline for (families) |F| try verify_and_extract_digests(F);
}

fn to_proof_store(comptime F: type) !void {
    const gpa = testing.allocator;
    const ops = range(15);
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    const root = try fixture.root(0);
    var proof = try fixture.range_proof(gpa, 0, 0, 3);
    defer proof.deinit(gpa);
    var store = try verify.to_proof_store(F, Sha256, u64, gpa, &proof, 0, ops[0..3], &root);
    defer store.deinit(gpa);
    var sub_proof = try store.range_proof(gpa, &fixture.hasher, .{ .start = 0, .end = 2 });
    defer sub_proof.deinit(gpa);
    try testing.expect(try verify.verify(F, Sha256, u64, gpa, &sub_proof, 0, ops[0..2], &root));
}

test "to proof store" {
    inline for (families) |F| try to_proof_store(F);
}

fn to_proof_store_invalid_proof(comptime F: type) !void {
    const gpa = testing.allocator;
    const ops = [_]u64{ 1, 2, 3 };
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    var proof = try fixture.range_proof(gpa, 0, 0, 2);
    defer proof.deinit(gpa);
    const wrong_root = test_digest(99);
    const result = verify.to_proof_store(F, Sha256, u64, gpa, &proof, 0, &ops, &wrong_root);
    if (result) |store| {
        var owned = store;
        owned.deinit(gpa);
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "to proof store invalid proof" {
    inline for (families) |F| try to_proof_store_invalid_proof(F);
}

fn multi_proof(comptime F: type) !void {
    const gpa = testing.allocator;
    const ops = range(20);
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    const root = try fixture.root(0);
    var proof = try fixture.range_proof(gpa, 0, 0, 20);
    defer proof.deinit(gpa);
    var store = try verify.to_proof_store(F, Sha256, u64, gpa, &proof, 0, &ops, &root);
    defer store.deinit(gpa);
    const locations = [_]u64{ 2, 5, 10, 15, 18 };
    var multi = try store.multi_proof(gpa, &locations, &.{});
    defer multi.deinit(gpa);
    // Locations must be strictly ascending.
    const duplicate = [_]u64{ 2, 2, 5, 10, 15, 18 };
    try testing.expectError(error.DuplicateLocation, store.multi_proof(gpa, &duplicate, &.{}));
    const unsorted = [_]u64{ 5, 2, 10, 15, 18 };
    try testing.expectError(error.UnsortedLocation, store.multi_proof(gpa, &unsorted, &.{}));
    var selected: [locations.len]u64 = undefined;
    for (locations, &selected) |location, *op| op.* = ops[location];
    try testing.expect(
        try verify.verify_multi(F, Sha256, u64, gpa, &multi, &locations, &selected, &root),
    );
}

test "multi proof" {
    inline for (families) |F| try multi_proof(F);
}

fn multi_proof_with_fold_prefix_peaks(comptime F: type) !void {
    const gpa = testing.allocator;
    const P = verify.Proof(F, Sha256);
    // Peaks covering locations 0-31, 32-47, and 48.
    const ops = range(49);
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    const inactive_peaks = 1;
    const root = try fixture.root(inactive_peaks);
    // The store starts at 32, so the first peak folds into the proof prefix.
    var proof = try fixture.range_proof(gpa, inactive_peaks, 32, 49);
    defer proof.deinit(gpa);
    try testing.expectEqual(@as(usize, inactive_peaks), proof.inactive_peaks);
    var store = try verify.to_proof_store(F, Sha256, u64, gpa, &proof, 32, ops[32..], &root);
    defer store.deinit(gpa);

    for ([_]usize{ 0, inactive_peaks + 1 }) |tampered_peaks| {
        var tampered = try proof.clone(gpa);
        defer tampered.deinit(gpa);
        tampered.inactive_peaks = tampered_peaks;
        const verified = verify.verify(F, Sha256, u64, gpa, &tampered, 32, ops[32..], &root);
        try testing.expect(!try verified);
        const result = verify.to_proof_store(F, Sha256, u64, gpa, &tampered, 32, ops[32..], &root);
        if (result) |s| {
            var owned = s;
            owned.deinit(gpa);
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    // The peaks entirely before the range start.
    var fold_prefix: std.ArrayList(P.NodeDigest) = .empty;
    defer fold_prefix.deinit(gpa);
    var leaf_cursor: u64 = 0;
    var peaks = F.peaks(fixture.mem.size());
    while (peaks.next()) |peak| {
        const leaf_end = leaf_cursor + (@as(u64, 1) << @intCast(peak.height));
        if (leaf_end > 32) break;
        leaf_cursor = leaf_end;
        const digest = fixture.mem.get_node(peak.position).?;
        try fold_prefix.append(gpa, .{ .position = peak.position, .digest = digest });
    }
    try testing.expect(fold_prefix.items.len > 0);

    const locations = [_]u64{ 33, 48 };
    try testing.expectError(error.ElementPruned, store.multi_proof(gpa, &locations, &.{}));
    var multi = try store.multi_proof(gpa, &locations, fold_prefix.items);
    defer multi.deinit(gpa);
    const selected = [_]u64{ ops[33], ops[48] };
    try testing.expect(
        try verify.verify_multi(F, Sha256, u64, gpa, &multi, &locations, &selected, &root),
    );
    multi.inactive_peaks = 0;
    try testing.expect(
        !try verify.verify_multi(F, Sha256, u64, gpa, &multi, &locations, &selected, &root),
    );
}

test "multi proof with fold prefix peaks" {
    inline for (families) |F| try multi_proof_with_fold_prefix_peaks(F);
}

fn verify_multi(comptime F: type) !void {
    const gpa = testing.allocator;
    const ops = range(10);
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    const root = try fixture.root(0);
    var proof = try fixture.range_proof(gpa, 0, 0, 10);
    defer proof.deinit(gpa);
    var store = try verify.to_proof_store(F, Sha256, u64, gpa, &proof, 0, &ops, &root);
    defer store.deinit(gpa);
    const locations = [_]u64{ 1, 4, 7 };
    var multi = try store.multi_proof(gpa, &locations, &.{});
    defer multi.deinit(gpa);
    const Check = struct {
        fn run(p: anytype, locs: []const u64, selected: []const u64, r: *const Digest) !bool {
            return verify.verify_multi(F, Sha256, u64, testing.allocator, p, locs, selected, r);
        }
    };
    try testing.expect(try Check.run(&multi, &locations, &.{ 1, 4, 7 }, &root));
    // Genuine operations fail when a location repeats or precedes the one before it.
    try testing.expect(!try Check.run(&multi, &.{ 1, 1, 4, 7 }, &.{ 1, 1, 4, 7 }, &root));
    try testing.expect(!try Check.run(&multi, &.{ 1, 1, 4, 7 }, &.{ 1, 0, 4, 7 }, &root));
    try testing.expect(!try Check.run(&multi, &.{ 4, 1, 7 }, &.{ 4, 1, 7 }, &root));
    // Wrong operations and wrong locations fail.
    try testing.expect(!try Check.run(&multi, &locations, &.{ 99, 4, 7 }, &root));
    try testing.expect(!try Check.run(&multi, &.{ 0, 4, 7 }, &.{ 1, 4, 7 }, &root));
    // Mismatched lengths fail.
    try testing.expect(!try Check.run(&multi, &locations, &.{ 1, 4 }, &root));
}

test "verify multi" {
    inline for (families) |F| try verify_multi(F);
}

fn multi_proof_empty(comptime F: type) !void {
    const gpa = testing.allocator;
    var empty = try Fixture(F).init(gpa, &.{});
    defer empty.deinit(gpa);
    const empty_root = try empty.root(0);
    const empty_proof: verify.Proof(F, Sha256) = .{};
    try testing.expect(
        try verify.verify_multi(F, Sha256, u64, gpa, &empty_proof, &.{}, &.{}, &empty_root),
    );
    const ops = range(5);
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    const root = try fixture.root(0);
    var proof = try fixture.range_proof(gpa, 0, 0, 5);
    defer proof.deinit(gpa);
    var store = try verify.to_proof_store(F, Sha256, u64, gpa, &proof, 0, &ops, &root);
    defer store.deinit(gpa);
    try testing.expectError(error.Empty, store.multi_proof(gpa, &.{}, &.{}));
}

test "multi proof empty" {
    inline for (families) |F| try multi_proof_empty(F);
}

fn multi_proof_single_element(comptime F: type) !void {
    const gpa = testing.allocator;
    const ops = [_]u64{ 1, 2, 3 };
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    const root = try fixture.root(0);
    var proof = try fixture.range_proof(gpa, 0, 0, 3);
    defer proof.deinit(gpa);
    var store = try verify.to_proof_store(F, Sha256, u64, gpa, &proof, 0, &ops, &root);
    defer store.deinit(gpa);
    var multi = try store.multi_proof(gpa, &.{1}, &.{});
    defer multi.deinit(gpa);
    try testing.expect(try verify.verify_multi(F, Sha256, u64, gpa, &multi, &.{1}, &.{2}, &root));
}

test "multi proof single element" {
    inline for (families) |F| try multi_proof_single_element(F);
}

fn verify_with_pinned_nodes(comptime F: type) !void {
    const gpa = testing.allocator;
    const ops = range(20);
    var fixture = try Fixture(F).init(gpa, &ops);
    defer fixture.deinit(gpa);
    const root = try fixture.root(0);
    var proof = try fixture.range_proof(gpa, 0, 7, 20);
    defer proof.deinit(gpa);
    var positions: [merkle.max_pinned_nodes]u64 = undefined;
    const pinned_positions = merkle.nodes_to_pin(F, 7, &positions);
    var pinned: [merkle.max_pinned_nodes]Digest = undefined;
    for (pinned_positions, 0..) |position, i| pinned[i] = fixture.mem.get_node(position).?;
    const good = pinned[0..pinned_positions.len];
    try testing.expect(good.len > 0);
    const check = verify.verify_with_pinned_nodes;
    try testing.expect(try check(F, Sha256, u64, gpa, &proof, 7, ops[7..], good, &root));
    // A wrong pinned digest or a missing one fails.
    var bad = pinned;
    bad[0] = test_digest(1);
    const bad_pinned = bad[0..good.len];
    try testing.expect(!try check(F, Sha256, u64, gpa, &proof, 7, ops[7..], bad_pinned, &root));
    try testing.expect(!try check(F, Sha256, u64, gpa, &proof, 7, ops[7..], good[1..], &root));
}

test "verify with pinned nodes" {
    inline for (families) |F| try verify_with_pinned_nodes(F);
}
