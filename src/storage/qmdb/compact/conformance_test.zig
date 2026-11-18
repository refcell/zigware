//! Conformance of the compact db (commonware's `qmdb/conformance.rs`
//! `{Keyless,Immutable}{Mmr,Mmb}Compact{Fixed,Variable}Conf`, whose hashes equal the full dbs'
//! because the workloads and roots match) and of the witness codec
//! (`compact/witness.rs` `CodecConformance<StoredWitness<..>>`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const merkle = @import("../../merkle/mod.zig");
const value = @import("../value.zig");
const test_support = @import("../test_support.zig");
const immutable_support = @import("../immutable/test_support.zig");
const witness = @import("witness.zig");
const support = @import("test_support.zig");

const Digest = support.Digest;
const to_digest = immutable_support.to_digest;
const to_val = immutable_support.to_val;

/// Appends the values made from `first + i` (wrapping), `count` of them, in one batch.
fn apply_appends(comptime Db: type, db: *Db, first: u64, count: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (0..count) |i| {
            const made = try support.make_value(Db, db.gpa, first +% i);
            errdefer codec.free(Db.Value, db.gpa, made);
            try batch.append(made);
        }
        batch.with_inactivity_floor(db.inactivity_floor());
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn apply_sets(comptime Db: type, db: *Db, keys: []const Digest, values: []const Digest) !void {
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

/// commonware's `immutable_root!` workload.
fn immutable_workload(comptime Db: type, db: *Db, seed: u64) !void {
    const gpa = db.gpa;
    const n = seed % 30 + 5;
    const collide: u8 = @intCast(seed % 256);
    const keys = try gpa.alloc(Digest, 2 * n);
    defer gpa.free(keys);
    const values = try gpa.alloc(Digest, 2 * n);
    defer gpa.free(values);
    for (0..2 * n) |i| {
        keys[i] = to_digest(i);
        values[i] = to_val(i, if (i < n) 1 else 2);
    }
    try apply_sets(Db, db, keys[0..n], values[0..n]);
    try apply_sets(Db, db, keys[n .. 2 * n], values[n .. 2 * n]);
    for (0..n / 2) |i| {
        keys[i] = immutable_support.colliding_digest(collide, 10000 + i);
        values[i] = to_val(i, 3);
    }
    try apply_sets(Db, db, keys[0 .. n / 2], values[0 .. n / 2]);
}

fn CompactConformance(comptime Db: type) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var harness = try support.Harness.init(gpa);
            defer harness.deinit();
            var db = try harness.open(Db, null);
            errdefer db.deinit();
            if (Db.keyed) {
                try immutable_workload(Db, &db, seed);
            } else {
                // commonware's `keyless_root!` workload.
                const n = seed % 30 + 5;
                try apply_appends(Db, &db, seed, n);
                try apply_appends(Db, &db, seed +% n, n);
                try apply_appends(Db, &db, ~seed, n / 2);
            }
            const root = db.root();
            try db.destroy();
            return gpa.dupe(u8, &root.bytes);
        }
    };
}

const prefix = "commonware_storage::qmdb::conformance::tests::";

fn verify_root(comptime Db: type, comptime name: []const u8) !void {
    const gpa = std.heap.smp_allocator;
    const C = CompactConformance(Db);
    try conformance.verify(C, gpa, prefix ++ name, 200, test_support.conformance_file);
}

const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;

test "compact keyless root conformance (MMR fixed)" {
    try verify_root(support.KeylessFixed(Mmr), "KeylessMmrCompactFixedConf");
}

test "compact keyless root conformance (MMB fixed)" {
    try verify_root(support.KeylessFixed(Mmb), "KeylessMmbCompactFixedConf");
}

test "compact keyless root conformance (MMR variable)" {
    try verify_root(support.KeylessVariable(Mmr), "KeylessMmrCompactVariableConf");
}

test "compact keyless root conformance (MMB variable)" {
    try verify_root(support.KeylessVariable(Mmb), "KeylessMmbCompactVariableConf");
}

test "compact immutable root conformance (MMR fixed)" {
    try verify_root(support.ImmutableFixed(Mmr), "ImmutableMmrCompactFixedConf");
}

test "compact immutable root conformance (MMB fixed)" {
    try verify_root(support.ImmutableFixed(Mmb), "ImmutableMmbCompactFixedConf");
}

test "compact immutable root conformance (MMR variable)" {
    try verify_root(support.ImmutableVariable(Mmr), "ImmutableMmrCompactVariableConf");
}

test "compact immutable root conformance (MMB variable)" {
    try verify_root(support.ImmutableVariable(Mmb), "ImmutableMmbCompactVariableConf");
}

const witness_prefix = "commonware_storage::qmdb::compact::witness::tests::conformance::";

test "conformance CodecConformance<StoredWitness>" {
    try test_support.verify_codec(witness.Stored(Mmr, Digest), witness_prefix ++
        "CodecConformance<StoredWitness<mmr::Family,sha256::Digest>>");
    try test_support.verify_codec(witness.Stored(Mmb, Digest), witness_prefix ++
        "CodecConformance<StoredWitness<mmb::Family,sha256::Digest>>");
}
