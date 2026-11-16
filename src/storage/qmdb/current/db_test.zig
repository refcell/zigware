//! Tests of the unordered fixed `current` database, ported from commonware's
//! `qmdb/current/{mod,unordered/mod,unordered/fixed}.rs` and `qmdb/conformance.rs`
//! (`Current{Mmr,Mmb}UnorderedFixedConf`), plus randomized batch chains whose speculative
//! canonical roots must match the roots rebuilt on reopen.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const qmdb_support = @import("../test_support.zig");
const any_conformance = @import("../any/conformance_test.zig");
const unordered_proof = @import("unordered/proof.zig");
const ordered_proof = @import("ordered/proof.zig");
const proof_mod = @import("proof.zig");
const verification = @import("verification.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const Digest = support.Digest;
const Sha256 = support.Sha256;
const Write = support.Write;
const key = support.to_digest;
const val = support.to_val;

fn CurrentConformance(comptime Db: type) type {
    return struct {
        pub fn commit(allocator: Allocator, seed: u64) ![]u8 {
            var harness = try support.Harness.init(allocator);
            defer harness.deinit();
            var db = try harness.open(Db, null);
            errdefer db.deinit();
            const batches = try any_conformance.keyed_batches(allocator, seed);
            defer for (batches) |list| allocator.free(list);
            for (batches) |writes| try support.apply_writes(Db, &db, writes);
            const root = db.root();
            try db.destroy();
            return allocator.dupe(u8, &root.bytes);
        }
    };
}

const name_prefix = "commonware_storage::qmdb::conformance::tests::";

test "current root conformance (MMR unordered variable)" {
    const allocator = std.heap.smp_allocator;
    const C = CurrentConformance(support.UnorderedVariable(merkle.mmr.Family));
    const name = name_prefix ++ "CurrentMmrUnorderedVariableConf";
    try conformance.verify(C, allocator, name, 200, qmdb_support.conformance_file);
}

test "current root conformance (MMR unordered fixed)" {
    const allocator = std.heap.smp_allocator;
    const C = CurrentConformance(support.UnorderedFixed(merkle.mmr.Family));
    const name = name_prefix ++ "CurrentMmrUnorderedFixedConf";
    try conformance.verify(C, allocator, name, 200, qmdb_support.conformance_file);
}

test "current root conformance (MMB unordered variable)" {
    const allocator = std.heap.smp_allocator;
    const C = CurrentConformance(support.UnorderedVariable(merkle.mmb.Family));
    const name = name_prefix ++ "CurrentMmbUnorderedVariableConf";
    try conformance.verify(C, allocator, name, 200, qmdb_support.conformance_file);
}

test "current root conformance (MMB unordered fixed)" {
    const allocator = std.heap.smp_allocator;
    const C = CurrentConformance(support.UnorderedFixed(merkle.mmb.Family));
    const name = name_prefix ++ "CurrentMmbUnorderedFixedConf";
    try conformance.verify(C, allocator, name, 200, qmdb_support.conformance_file);
}

test "current root conformance (MMR ordered variable)" {
    const allocator = std.heap.smp_allocator;
    const C = CurrentConformance(support.OrderedVariable(merkle.mmr.Family));
    const name = name_prefix ++ "CurrentMmrOrderedVariableConf";
    try conformance.verify(C, allocator, name, 200, qmdb_support.conformance_file);
}

test "current root conformance (MMR ordered fixed)" {
    const allocator = std.heap.smp_allocator;
    const C = CurrentConformance(support.OrderedFixed(merkle.mmr.Family));
    const name = name_prefix ++ "CurrentMmrOrderedFixedConf";
    try conformance.verify(C, allocator, name, 200, qmdb_support.conformance_file);
}

test "current root conformance (MMB ordered variable)" {
    const allocator = std.heap.smp_allocator;
    const C = CurrentConformance(support.OrderedVariable(merkle.mmb.Family));
    const name = name_prefix ++ "CurrentMmbOrderedVariableConf";
    try conformance.verify(C, allocator, name, 200, qmdb_support.conformance_file);
}

test "current root conformance (MMB ordered fixed)" {
    const allocator = std.heap.smp_allocator;
    const C = CurrentConformance(support.OrderedFixed(merkle.mmb.Family));
    const name = name_prefix ++ "CurrentMmbOrderedFixedConf";
    try conformance.verify(C, allocator, name, 200, qmdb_support.conformance_file);
}

/// One database per variant, alternating families (conformance covers every combination).
const all_dbs = .{
    support.UnorderedFixed(merkle.mmb.Family),
    support.OrderedFixed(merkle.mmr.Family),
    support.UnorderedVariable(merkle.mmr.Family),
    support.OrderedVariable(merkle.mmb.Family),
};

fn expect_value(db: anytype, k: Digest, expected: ?Digest) !void {
    const actual = try db.get(&k);
    if (expected) |e| {
        try testing.expect(actual != null and actual.?.eql(e));
    } else {
        try testing.expect(actual == null);
    }
}

/// Reopens `db` (dropped without syncing) on `harness`.
fn reopen(comptime Db: type, harness: *support.Harness, db: *Db) !void {
    db.deinit();
    db.* = try harness.open(Db, null);
}

// Commonware's `test_build_small_close_reopen`.
test "current build small, close, and reopen" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        errdefer db.deinit();
        try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
        const root0 = db.root();
        try reopen(Db, &harness, &db);
        try testing.expect(db.root().eql(root0));
        try support.apply_writes(Db, &db, &.{.{ .key = key(0), .value = val(10, 0) }});
        try db.commit();
        const root1 = db.root();
        try testing.expect(!root1.eql(root0));
        try reopen(Db, &harness, &db);
        try testing.expect(db.root().eql(root1));
        try expect_value(&db, key(0), val(10, 0));
        var batch = try db.new_batch();
        try batch.write(key(0), null);
        batch.with_metadata(val(1, 1));
        const merkleized = try batch.merkleize(&db);
        try db.apply_batch(merkleized);
        merkleized.release();
        try db.commit();
        try testing.expect((try db.get_metadata()).?.eql(val(1, 1)));
        const root2 = db.root();
        try support.apply_writes(Db, &db, &.{});
        try db.sync();
        const root3 = db.root();
        try testing.expect(!root3.eql(root2));
        try reopen(Db, &harness, &db);
        try testing.expect(try db.get_metadata() == null);
        try testing.expect(db.root().eql(root3));
        const end = db.bounds().end;
        for (0..end - 1) |bit| try testing.expect(!db.any.bitmap.get_bit(bit));
        try testing.expect(db.any.bitmap.get_bit(end - 1));
        try support.apply_writes(Db, &db, &.{.{ .key = key(0), .value = val(10, 0) }});
        try testing.expect(!db.root().eql(root3));
        try db.destroy();
    }
}

/// Commonware's `apply_random_ops`: `elements` keys written, then ten times as many random
/// updates and deletes (one in seven), committed in batches of about twenty.
fn apply_random_ops(comptime Db: type, db: *Db, elements: u64, seed: u64) !void {
    var rng = utils.rng.TestRng.init(seed);
    var writes: std.ArrayList(Write) = .empty;
    defer writes.deinit(gpa);
    for (0..elements) |i| {
        try writes.append(gpa, .{ .key = key(i), .value = val(rng.next_u64(), 0) });
    }
    try support.apply_writes(Db, db, writes.items);
    writes.clearRetainingCapacity();
    for (0..elements * 10) |_| {
        const k = key(rng.next_u64() % elements);
        if (rng.next_u32() % 7 == 0) {
            try writes.append(gpa, .{ .key = k, .value = null });
            continue;
        }
        try writes.append(gpa, .{ .key = k, .value = val(rng.next_u64(), 0) });
        if (rng.next_u32() % 20 == 0) {
            try support.apply_writes(Db, db, writes.items);
            writes.clearRetainingCapacity();
        }
    }
    try support.apply_writes(Db, db, writes.items);
    assert(db.bounds().end > elements);
}

fn expect_key_value_proof(
    comptime Db: type,
    proof: anytype,
    k: Digest,
    value: Digest,
    root: *const Digest,
) !void {
    const verify = @TypeOf(proof.*).verify;
    try testing.expect(verify(proof, Sha256, Db.Any.Update, k, value, root));
    const wrong_value = Sha256.hash(&.{&[_]u8{0xFF}});
    const wrong_key = Sha256.hash(&.{&[_]u8{0xEE}});
    const wrong_root = Sha256.hash(&.{&[_]u8{0xDD}});
    try testing.expect(!verify(proof, Sha256, Db.Any.Update, k, wrong_value, root));
    try testing.expect(!verify(proof, Sha256, Db.Any.Update, wrong_key, value, root));
    try testing.expect(!verify(proof, Sha256, Db.Any.Update, k, value, &wrong_root));
}

/// Checks the key-value proof of every active update from the floor, in both the constant
/// and the dynamic codec forms.
fn check_key_value_proofs(comptime Db: type, db: *Db) !void {
    const F = Db.Family;
    const root = db.root();
    const bad_key = Digest{ .bytes = @splat(0xAA) };
    try testing.expectError(error.KeyNotFound, db.key_value_proof(&bad_key));
    var checked: usize = 0;
    var location = db.inactivity_floor();
    while (location < db.any.bitmap.len()) : (location += 1) {
        if (!db.any.bitmap.get_bit(location)) continue;
        const op = try db.any.log.read(location);
        if (op != .update) continue;
        var proved = try db.key_value_proof(&op.update.key);
        defer proved.deinit(gpa);
        try testing.expect(proved.value.eql(op.update.value));
        try expect_key_value_proof(Db, &proved.proof, op.update.key, proved.value, &root);
        const verify = Db.verify_key_value_proof;
        try testing.expect(verify(&proved.proof, op.update.key, proved.value, &root));
        const ordered = Db.Any.Update.siblings;
        const Dynamic = if (ordered)
            ordered_proof.KeyValueProof(F, Digest, Digest, null)
        else
            unordered_proof.KeyValueProof(F, Digest, null);
        const encoded = try codec.encode(Db.KeyValueProof, gpa, proved.proof);
        defer gpa.free(encoded);
        const max_digests = proved.proof.proof.range_proof.proof.digests.len;
        const OpCfg = proof_mod.OperationProof(F, Digest, null).Cfg;
        const op_cfg: OpCfg = .{ .chunk_size = Db.chunk_bytes, .max_digests = max_digests };
        const cfg: Dynamic.Cfg = if (ordered) .{ op_cfg, {} } else op_cfg;
        var dynamic = try codec.decode_cfg(Dynamic, gpa, encoded, cfg);
        defer dynamic.deinit(gpa);
        try expect_key_value_proof(Db, &dynamic, op.update.key, proved.value, &root);
        checked += 1;
    }
    try testing.expectEqual(@as(usize, db.any.active_keys), checked);
}

// Commonware's `test_current_db_key_value_proof`.
test "current key-value proofs of every active key" {
    // Minutes in Debug, so it runs in optimized builds (CI's ReleaseSafe job) or -Dslow-tests.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try apply_random_ops(Db, &db, 300, 0x6b76);
        try support.apply_writes(Db, &db, &.{});
        try testing.expect(db.any.bitmap.complete_chunks() > 1);
        try check_key_value_proofs(Db, &db);
    }
}

// Commonware's `test_current_db_proving_repeated_updates`.
test "current proofs track a repeatedly updated key" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        const k = Digest{ .bytes = @splat(0) };
        var old: Digest = .{ .bytes = @splat(0) };
        for (1..256) |i| {
            const v = Digest{ .bytes = @splat(@intCast(i)) };
            try support.apply_writes(Db, &db, &.{.{ .key = k, .value = v }});
            try expect_value(&db, k, v);
            const root = db.root();
            var proved = try db.key_value_proof(&k);
            defer proved.deinit(gpa);
            try testing.expect(proved.value.eql(v));
            try testing.expect(proved.proof.verify(Sha256, Db.Any.Update, k, v, &root));
            try testing.expect(!proved.proof.verify(Sha256, Db.Any.Update, k, old, &root));
            old = v;
        }
    }
}

// Commonware's `test_current_db_range_proofs`.
test "current range proofs verify from the floor to the tip" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try apply_random_ops(Db, &db, 120, 0x7261);
        try support.apply_writes(Db, &db, &.{});
        const root = db.root();
        var location = db.inactivity_floor();
        while (location < db.bounds().end) : (location += 1) {
            var ranged = try db.range_proof(location, 4);
            defer ranged.deinit(gpa);
            try testing.expect(try verify_ranged(Db, &ranged, location, &root, false));
            try testing.expect(!try verify_ranged(Db, &ranged, location, &root, true));
        }
    }
}

/// Verifies `ranged` from `start`, with its last chunk repeated when `extra_chunk`.
fn verify_ranged(
    comptime Db: type,
    ranged: *const Db.Ranged,
    start: u64,
    root: *const Digest,
    extra_chunk: bool,
) !bool {
    var encoded: [4][]const u8 = undefined;
    assert(ranged.operations.len <= encoded.len);
    var done: usize = 0;
    defer for (encoded[0..done]) |bytes| gpa.free(bytes);
    for (ranged.operations, 0..) |op, i| {
        encoded[i] = try codec.encode(Db.Operation, gpa, op);
        done += 1;
    }
    var chunks: [4][]const u8 = undefined;
    assert(ranged.chunks.len < chunks.len);
    for (ranged.chunks, 0..) |*chunk, i| chunks[i] = chunk;
    var count = ranged.chunks.len;
    if (extra_chunk) {
        chunks[count] = &ranged.chunks[count - 1];
        count += 1;
    }
    const ops = encoded[0..ranged.operations.len];
    const N = Db.chunk_bytes;
    const Family = Db.Family;
    const used = chunks[0..count];
    return verification.verify_range(Family, Sha256, &ranged.proof, start, ops, used, N, root);
}

// Commonware's `test_sync_persists_bitmap_pruning_boundary`, then more writes on the pruned
// database and another reopen.
test "current prune and sync persist the bitmap pruning boundary" {
    // Minutes in Debug, so it runs in optimized builds (CI's ReleaseSafe job) or -Dslow-tests.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try apply_random_ops(Db, &db, 300, 0x7072);
        try support.apply_writes(Db, &db, &.{});
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(db.sync_boundary() + 1));
        try db.prune(db.sync_boundary());
        const pruned = db.any.bitmap.pruned_bits();
        try testing.expect(pruned > 0);
        try db.sync();
        const root = db.root();
        try reopen(Db, &harness, &db);
        try testing.expectEqual(pruned, db.any.bitmap.pruned_bits());
        try testing.expect(db.root().eql(root));
        try apply_random_ops(Db, &db, 300, 0x7073);
        try db.prune(db.sync_boundary());
        const root_after = db.root();
        try reopen(Db, &harness, &db);
        try testing.expect(db.root().eql(root_after));
        try check_key_value_proofs(Db, &db);
    }
}

fn apply_and_prune(comptime Db: type, db: *Db, writes: []const Write) !void {
    try support.apply_writes(Db, db, writes);
    try db.prune(db.sync_boundary());
    try db.sync();
}

/// Reopens `db` within `max_size` operations. A refused bound leaves `db` closed.
fn open_bounded(comptime Db: type, harness: *support.Harness, db: *Db, max_size: u64) !bool {
    db.deinit();
    db.* = harness.open(Db, max_size) catch |err| switch (err) {
        error.HistoricalFloorPruned => return false,
        else => return err,
    };
    return true;
}

// Clearing's `test_bounded_reopen_fails_once_the_floor_is_pruned` at the storage level: pruned
// to its sync boundary, the database reopens at the previous commit while that commit's floor
// is retained, and otherwise refuses without discarding the commits after the bound.
test "current bounded reopen rewinds or refuses without losing history" {
    const Db = support.UnorderedFixed(merkle.mmb.Family);
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var db = try harness.open(Db, null);
    defer db.deinit();
    var rng = utils.rng.TestRng.init(0x7265);
    var writes: [24]Write = undefined;
    var rewound: u32 = 0;
    var refused: u32 = 0;
    for (0..40) |round| {
        const previous_size = db.bounds().end;
        const previous_root = db.root();
        for (&writes, 0..) |*w, i| {
            w.* = .{ .key = key(rng.next_u64() % 48), .value = val(round, i) };
        }
        try apply_and_prune(Db, &db, &writes);
        if (round == 0) continue;
        const root = db.root();
        const size = db.bounds().end;
        if (try open_bounded(Db, &harness, &db, previous_size)) {
            rewound += 1;
            try testing.expect(db.root().eql(previous_root));
            try testing.expectEqual(previous_size, db.bounds().end);
            // Writing the same batch again returns to the latest commit.
            try apply_and_prune(Db, &db, &writes);
        } else {
            refused += 1;
            db = try harness.open(Db, null);
        }
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(size, db.bounds().end);
    }
    try testing.expect(rewound > 0 and refused > 0);
}

// Commonware's `test_commit_after_sync_recovery`.
test "current reopens a commit made after the last sync" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try support.apply_writes(Db, &db, &.{.{ .key = key(0), .value = val(100, 0) }});
        try db.sync();
        try support.apply_writes(Db, &db, &.{.{ .key = key(1), .value = val(200, 0) }});
        try db.commit();
        const root = db.root();
        const size = db.bounds().end;
        try reopen(Db, &harness, &db);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(size, db.bounds().end);
        try expect_value(&db, key(0), val(100, 0));
        try expect_value(&db, key(1), val(200, 0));
    }
}

fn random_write(random: std.Random, salt: u64) Write {
    const k = random.uintLessThan(u64, 400);
    const value: ?Digest = if (random.uintLessThan(u8, 5) == 0) null else val(k, salt);
    return .{ .key = key(k), .value = value };
}

/// Merkleizes a chain of up to three batches and applies them, some as soon as they are
/// merkleized; the tip's canonical root must become the database's.
fn apply_random_chain(comptime Db: type, db: *Db, random: std.Random, salt: *u64) !void {
    const depth = random.uintLessThan(usize, 3) + 1;
    var chain: [3]?*Db.MerkleizedBatch = .{ null, null, null };
    defer for (chain) |batch| if (batch) |b| b.release();
    var applied: usize = 0;
    for (0..depth) |level| {
        const merkleized = merkleized: {
            const parent = if (level > 0) chain[level - 1] else null;
            var batch = if (parent) |p| p.new_batch() else try db.new_batch();
            errdefer batch.deinit();
            const count = random.uintLessThan(usize, 60);
            for (0..count) |_| {
                salt.* += 1;
                const w = random_write(random, salt.*);
                try batch.write(w.key, w.value);
            }
            break :merkleized try batch.merkleize(db);
        };
        chain[level] = merkleized;
        if (random.boolean()) {
            try db.apply_batch(merkleized);
            try testing.expect(db.root().eql(merkleized.root()));
            applied = level + 1;
        }
        const releasable = applied >= level or level + 1 == depth;
        if (level > 0 and releasable and random.boolean()) {
            chain[level - 1].?.release();
            chain[level - 1] = null;
        }
    }
    const tip = chain[depth - 1].?;
    if (applied < depth) try db.apply_batch(tip);
    try testing.expect(db.root().eql(tip.root()));
}

/// Random chains, sometimes pruning to the sync boundary, with the canonical root checked
/// against the reopened rebuild every few rounds.
fn check_random_chains(comptime Db: type, seed: u64) !void {
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var db = try harness.open(Db, null);
    defer db.deinit();
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var salt: u64 = 0;
    for (0..60) |round| {
        try apply_random_chain(Db, &db, random, &salt);
        if (random.uintLessThan(u8, 4) == 0) try db.prune(db.sync_boundary());
        if (round % 6 != 5) continue;
        const root = db.root();
        if (random.boolean()) try db.sync() else try db.commit();
        try reopen(Db, &harness, &db);
        try testing.expect(db.root().eql(root));
    }
    try testing.expect(db.any.bitmap.complete_chunks() > 2);
}

test "current randomized chains match the rebuilt canonical root" {
    // Minutes in Debug, so it runs in optimized builds (CI's ReleaseSafe job) or -Dslow-tests.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    inline for (all_dbs) |Db| {
        try check_random_chains(Db, 0xc0ffee);
    }
}

/// Merkleizes on `parent` (or `db`) the staged reads of keys 0..8 with slots keep, put, and
/// delete in turn, plus one unstaged write; returns the batch and checks the staged reads.
fn merkleize_staged(
    comptime Db: type,
    db: *Db,
    parent: ?*Db.MerkleizedBatch,
) !*Db.MerkleizedBatch {
    var batch = if (parent) |p| p.new_batch() else try db.new_batch();
    var keys: [8]Digest = undefined;
    var values: [8]?Digest = undefined;
    for (&keys, 0..) |*k, i| k.* = key(i);
    var staged = staged: {
        errdefer batch.deinit();
        break :staged try batch.stage(&keys, db, &values);
    };
    for (keys, values) |k, v| {
        const expected = if (parent) |p| try p.get(&k, db) else try db.get(&k);
        try testing.expectEqual(expected == null, v == null);
        if (v) |value| try testing.expect(value.eql(expected.?));
    }
    staged.with_metadata(val(9, 9));
    var slots: [8]Db.Slot = undefined;
    for (&slots, 0..) |*slot, i| slot.* = switch (i % 3) {
        0 => .keep,
        1 => .{ .put = val(i, 7) },
        else => .delete,
    };
    const unstaged = [_]Db.StagedBatch.Mutation{.{ .key = key(20), .value = val(20, 7) }};
    return staged.merkleize(&slots, &unstaged, db);
}

/// The same writes as `merkleize_staged`, recorded explicitly.
fn merkleize_explicit(
    comptime Db: type,
    db: *Db,
    parent: ?*Db.MerkleizedBatch,
) !*Db.MerkleizedBatch {
    var batch = if (parent) |p| p.new_batch() else try db.new_batch();
    errdefer batch.deinit();
    batch.with_metadata(val(9, 9));
    for (0..8) |i| switch (i % 3) {
        0 => {},
        1 => try batch.write(key(i), val(i, 7)),
        else => try batch.write(key(i), null),
    };
    try batch.write(key(20), val(20, 7));
    return batch.merkleize(db);
}

// Commonware's staged parity tests (`test_current_unordered_fixed_read_merkleize_parity` and
// `..._staged_ancestor_applied_before_merkleize`): staged reads and slots give the explicit
// writes' canonical root, on the database and on an unapplied or applied parent.
test "current staged merkleize matches explicit writes" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try apply_random_ops(Db, &db, 40, 0x57a6);
        const staged = try merkleize_staged(Db, &db, null);
        defer staged.release();
        const explicit = try merkleize_explicit(Db, &db, null);
        defer explicit.release();
        try testing.expect(staged.root().eql(explicit.root()));
        const child_staged = try merkleize_staged(Db, &db, staged);
        defer child_staged.release();
        const child_explicit = try merkleize_explicit(Db, &db, explicit);
        defer child_explicit.release();
        try testing.expect(child_staged.root().eql(child_explicit.root()));
        try db.apply_batch(staged);
        try testing.expect(db.root().eql(staged.root()));
        const after = try merkleize_staged(Db, &db, staged);
        defer after.release();
        try testing.expect(after.root().eql(child_explicit.root()));
        try db.apply_batch(after);
        try testing.expect(db.root().eql(child_explicit.root()));
        try testing.expect((try db.get_metadata()).?.eql(val(9, 9)));
    }
}

fn fill(byte: u8) Digest {
    return .{ .bytes = @splat(byte) };
}

/// Whether `db`'s exclusion proof of `absent` verifies for each of `keys` (in order).
fn expect_exclusions(
    comptime Db: type,
    db: *Db,
    absent: Digest,
    keys: []const Digest,
    expected: []const bool,
) !void {
    var proof = try db.exclusion_proof(&absent);
    defer proof.deinit(gpa);
    const root = db.root();
    for (keys, expected) |k, ok| {
        try testing.expectEqual(ok, Db.verify_exclusion_proof(&proof, k, &root));
    }
    const wrong_root = fill(0xDD);
    try testing.expect(!Db.verify_exclusion_proof(&proof, absent, &wrong_root));
}

// Commonware's ordered `test_exclusion_proofs`.
test "current ordered exclusion proofs" {
    inline for (families) |F| {
        const Db = support.OrderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        const k1 = fill(0x10);
        const k2 = fill(0x30);
        try expect_exclusions(Db, &db, k1, &.{ k1, k2 }, &.{ true, true });
        const empty_root = db.root();
        var empty_proof = try db.exclusion_proof(&k1);
        defer empty_proof.deinit(gpa);
        try support.apply_writes(Db, &db, &.{.{ .key = k1, .value = fill(0xA1) }});
        try testing.expectError(error.KeyExists, db.exclusion_proof(&k1));
        const any_keys = [_]Digest{ fill(0xFF), fill(0x00), k1 };
        try expect_exclusions(Db, &db, fill(0xFF), &any_keys, &.{ true, true, false });
        try expect_exclusions(Db, &db, fill(0x00), &any_keys, &.{ true, true, false });
        try support.apply_writes(Db, &db, &.{.{ .key = k2, .value = fill(0xB2) }});
        const keys = [_]Digest{ fill(0x31), fill(0x0F), fill(0x20), k1, k2, fill(0x11) };
        // The span wrapping from k2 to k1, then the inner span [k1, k2).
        const outer = [_]bool{ true, true, false, false, false, false };
        const inner = [_]bool{ false, false, true, false, false, true };
        try expect_exclusions(Db, &db, fill(0x31), &keys, &outer);
        try expect_exclusions(Db, &db, fill(0x0F), &keys, &outer);
        try expect_exclusions(Db, &db, fill(0x20), &keys, &inner);
        try testing.expectEqual(@as(?Digest, null), try db.get_next_key(&k2));
        try testing.expect((try db.get_next_key(&k1)).?.eql(k2));
        try testing.expect((try db.get_prev_key(&k2)).?.eql(k1));
        try support.apply_writes(Db, &db, &.{
            .{ .key = k1, .value = null },
            .{ .key = k2, .value = null },
        });
        try db.sync();
        try testing.expect(db.is_empty());
        try testing.expect(!db.root().eql(empty_root));
        try expect_exclusions(Db, &db, k1, &.{ k1, k2 }, &.{ true, true });
        const root = db.root();
        try testing.expect(!Db.verify_exclusion_proof(&empty_proof, k1, &root));
    }
}
