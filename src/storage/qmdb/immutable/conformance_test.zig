//! Root conformance of the immutable database (commonware's `qmdb/conformance.rs`
//! `Immutable{Mmr,Mmb}{Fixed,Variable}Conf`): the root after a three-batch set workload, over
//! 200 seeds.

const std = @import("std");
const Allocator = std.mem.Allocator;
const conformance = @import("conformance");
const merkle = @import("../../merkle/mod.zig");
const test_support = @import("../test_support.zig");
const support = @import("test_support.zig");

const to_digest = support.to_digest;
const to_val = support.to_val;

/// Sets `keys` to `values` in one batch at the database's floor.
fn apply_sets(db: anytype, keys: []const support.Digest, values: []const support.Digest) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (keys, values) |k, v| try batch.set(k, v);
        batch.with_inactivity_floor(db.inactivity_floor());
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn ImmutableConformance(comptime Db: type) type {
    return struct {
        /// The root after commonware's `immutable_root!` workload for `seed`.
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var harness = try support.Harness.init(gpa);
            defer harness.deinit();
            var db = try harness.open_db(Db, null);
            errdefer db.deinit();
            const n = seed % 30 + 5;
            const prefix: u8 = @intCast(seed % 256);
            const keys = try gpa.alloc(support.Digest, 2 * n);
            defer gpa.free(keys);
            const values = try gpa.alloc(support.Digest, 2 * n);
            defer gpa.free(values);
            for (0..n) |i| {
                keys[i] = to_digest(i);
                values[i] = to_val(i, 1);
            }
            try apply_sets(&db, keys[0..n], values[0..n]);
            for (n..2 * n) |i| {
                keys[i] = to_digest(i);
                values[i] = to_val(i, 2);
            }
            try apply_sets(&db, keys[n .. 2 * n], values[n .. 2 * n]);
            for (0..n / 2) |i| {
                keys[i] = support.colliding_digest(prefix, 10000 + i);
                values[i] = to_val(i, 3);
            }
            try apply_sets(&db, keys[0 .. n / 2], values[0 .. n / 2]);
            const root = db.root();
            try db.destroy();
            return gpa.dupe(u8, &root.bytes);
        }
    };
}

const name_prefix = "commonware_storage::qmdb::conformance::tests::";

test "immutable root conformance (MMR fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = ImmutableConformance(support.Fixed(merkle.mmr.Family));
    const name = name_prefix ++ "ImmutableMmrFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "immutable root conformance (MMB fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = ImmutableConformance(support.Fixed(merkle.mmb.Family));
    const name = name_prefix ++ "ImmutableMmbFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "immutable root conformance (MMR variable)" {
    const gpa = std.heap.smp_allocator;
    const C = ImmutableConformance(support.Variable(merkle.mmr.Family));
    const name = name_prefix ++ "ImmutableMmrVariableConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "immutable root conformance (MMB variable)" {
    const gpa = std.heap.smp_allocator;
    const C = ImmutableConformance(support.Variable(merkle.mmb.Family));
    const name = name_prefix ++ "ImmutableMmbVariableConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}
