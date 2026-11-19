//! Tests of the unordered `any` database, ported from commonware's `qmdb/any/{mod,batch}.rs`
//! scenarios, plus a randomized model check: chained batches against a key-value model, with
//! the live snapshot and bitmap compared to the reopened database's rebuild.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const verify = @import("../verify.zig");
const floor_mod = @import("../floor.zig");
const support = @import("test_support.zig");
const qmdb = @import("../mod.zig");
const metrics = @import("runtime").telemetry.metrics;
const qmdb_support = @import("../test_support.zig");
const death = @import("utils").death;

const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const Digest = support.Digest;
const Sha256 = support.Sha256;
const Write = support.Write;
const key = support.to_digest;
const val = support.to_val;

fn expect_value(db: anytype, k: Digest, expected: ?Digest) !void {
    const actual = try db.get(&k);
    if (expected) |e| {
        try testing.expect(actual != null and actual.?.eql(e));
    } else {
        try testing.expect(actual == null);
    }
}

test "any empty database and initial root" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try testing.expectEqual(merkle.Range{ .start = 0, .end = 1 }, db.bounds());
        try testing.expect(db.is_empty());
        try testing.expect(db.root().eql(@import("mod.zig").initial_root(F, Db.Update, Sha256)));
        try testing.expect(try db.get_metadata() == null);
        try expect_value(&db, key(1), null);
    }
}

test "any writes, deletes, and recovery" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        errdefer db.deinit();
        try support.apply_writes(Db, &db, &.{
            .{ .key = key(1), .value = val(1, 1) },
            .{ .key = key(2), .value = val(2, 1) },
            .{ .key = key(3), .value = val(3, 1) },
        });
        try expect_value(&db, key(2), val(2, 1));
        try testing.expectEqual(@as(usize, 3), db.active_keys);
        try support.apply_writes(Db, &db, &.{
            .{ .key = key(2), .value = null },
            .{ .key = key(3), .value = val(3, 2) },
            .{ .key = key(4), .value = null }, // Deleting an absent key does nothing.
        });
        try expect_value(&db, key(2), null);
        try expect_value(&db, key(3), val(3, 2));
        try testing.expectEqual(@as(usize, 2), db.active_keys);
        try db.commit();
        const committed = db.root();
        // A batch applied without a commit is durable only as far as the journal synced it
        // (here a filled blob syncs before rolling over), so a crash keeps the database at one
        // of the two commit points.
        try support.apply_writes(Db, &db, &.{.{ .key = key(5), .value = val(5, 1) }});
        const applied = db.root();
        harness.storage.crash();
        db.deinit();
        db = try harness.open(Db, null);
        const kept = db.root().eql(applied);
        try testing.expect(kept or db.root().eql(committed));
        try testing.expectEqual(@as(usize, if (kept) 3 else 2), db.active_keys);
        try expect_value(&db, key(1), val(1, 1));
        try expect_value(&db, key(3), val(3, 2));
        try expect_value(&db, key(5), if (kept) val(5, 1) else null);
        // A batch that fills no blob is lost.
        const reopened = db.root();
        try support.apply_writes(Db, &db, &.{.{ .key = key(6), .value = val(6, 1) }});
        try testing.expect(db.bounds().end % 7 != 0);
        harness.storage.crash();
        db.deinit();
        db = try harness.open(Db, null);
        try testing.expect(db.root().eql(reopened));
        try expect_value(&db, key(6), null);
        try db.destroy();
    }
}

test "any later writes of a key in one batch win" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var batch = try db.new_batch();
        try batch.write(key(1), val(1, 1));
        try batch.write(key(1), null);
        try batch.write(key(1), val(1, 2));
        try testing.expect((try batch.get(&key(1), &db)).?.eql(val(1, 2)));
        // `Hold` keeps the floor, so no active operation moves.
        var hold: floor_mod.Hold = .{};
        const merkleized = try batch.merkleize_with(&db, &hold);
        defer merkleized.release();
        try db.apply_batch(merkleized);
        try expect_value(&db, key(1), val(1, 2));
        // The initial commit, one update, and the commit.
        try testing.expectEqual(@as(u64, 3), db.bounds().end);
    }
}

test "any chained batches read through and apply with dropped parents" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try support.apply_writes(Db, &db, &.{.{ .key = key(1), .value = val(1, 1) }});
        var parent_batch = try db.new_batch();
        try parent_batch.write(key(1), null);
        try parent_batch.write(key(2), val(2, 1));
        const parent = try parent_batch.merkleize(&db);
        var child_batch = parent.new_batch();
        try testing.expect(try child_batch.get(&key(1), &db) == null);
        try child_batch.write(key(1), val(1, 3));
        try child_batch.write(key(2), null);
        const child = try child_batch.merkleize(&db);
        defer child.release();
        // The child keeps the parent's changes after the parent is released.
        parent.release();
        try testing.expect((try child.get(&key(1), &db)).?.eql(val(1, 3)));
        try testing.expect(try child.get(&key(2), &db) == null);
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        try expect_value(&db, key(1), val(1, 3));
        try expect_value(&db, key(2), null);
        try testing.expectEqual(@as(usize, 1), db.active_keys);
    }
}

test "any sequential parent then child apply matches the chained root" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var parent_batch = try db.new_batch();
        try parent_batch.write(key(1), val(1, 1));
        const parent = try parent_batch.merkleize(&db);
        defer parent.release();
        var child_batch = parent.new_batch();
        try child_batch.write(key(1), val(1, 2));
        try child_batch.write(key(2), val(2, 2));
        const child = try child_batch.merkleize(&db);
        defer child.release();
        try db.apply_batch(parent);
        try testing.expect((try child.get(&key(2), &db)).?.eql(val(2, 2)));
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        try expect_value(&db, key(1), val(1, 2));
        // A sibling of the applied chain is stale.
        var sibling_batch = try db.new_batch();
        try sibling_batch.write(key(3), val(3, 3));
        const sibling = try sibling_batch.merkleize(&db);
        defer sibling.release();
        try support.apply_writes(Db, &db, &.{.{ .key = key(4), .value = val(4, 4) }});
        try testing.expectError(error.StaleBatch, db.apply_batch(sibling));
        try testing.expectError(error.StaleRead, sibling.get(&key(3), &db));
    }
}

test "any proofs verify and pruning respects the floor" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        for (0..6) |round| {
            var writes: [10]Write = undefined;
            for (&writes, 0..) |*w, i| w.* = .{ .key = key(i), .value = val(i, round) };
            try support.apply_writes(Db, &db, &writes);
        }
        const root = db.root();
        const end = db.bounds().end;
        var all = try db.proof(0, end);
        defer all.deinit(gpa);
        try testing.expectEqual(@as(usize, @intCast(end)), all.items.len);
        const Op = Db.Operation;
        try testing.expect(try verify.verify(F, Sha256, Op, gpa, &all.proof, 0, all.items, &root));
        try testing.expect(!try verify.verify(F, Sha256, Op, gpa, &all.proof, 1, all.items, &root));
        const floor = db.inactivity_floor();
        try testing.expect(floor > 0);
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(floor + 1));
        try db.prune(floor);
        try testing.expect(db.root().eql(root));
        for (0..10) |i| try expect_value(&db, key(i), val(i, 5));
        var tail = try db.proof(floor, 4);
        defer tail.deinit(gpa);
        const proof = &tail.proof;
        try testing.expect(try verify.verify(F, Sha256, Op, gpa, proof, floor, tail.items, &root));
    }
}

/// A random write over a small key space, so keys are often updated, deleted, and recreated.
fn random_write(random: std.Random, salt: u64) Write {
    const k = random.uintLessThan(u64, 24);
    const k_digest = if (k >= 16) support.colliding_digest(7, k) else key(k);
    const value: ?Digest = if (random.uintLessThan(u8, 4) == 0) null else val(k, salt);
    return .{ .key = k_digest, .value = value };
}

const Model = std.AutoHashMapUnmanaged([32]u8, [32]u8);

fn model_apply(model: *Model, writes: []const Write) !void {
    for (writes) |w| {
        if (w.value) |v| {
            try model.put(gpa, w.key.bytes, v.bytes);
        } else {
            _ = model.remove(w.key.bytes);
        }
    }
}

/// Checks `db` against `model`, then reopens it and checks the rebuilt snapshot and bitmap.
fn check_and_reopen(comptime Db: type, harness: *support.Harness, db: *Db, model: *Model) !void {
    try testing.expectEqual(@as(usize, model.count()), db.active_keys);
    for (0..24) |k| {
        const k_digest = if (k >= 16) support.colliding_digest(7, k) else key(k);
        const expected: ?Digest = if (model.get(k_digest.bytes)) |v| .{ .bytes = v } else null;
        try expect_value(db, k_digest, expected);
    }
    var bits: std.DynamicBitSetUnmanaged = try .initEmpty(gpa, @intCast(db.bitmap.len()));
    defer bits.deinit(gpa);
    var bit = db.inactivity_floor_loc;
    while (bit < db.bitmap.len()) : (bit += 1) {
        if (db.bitmap.get_bit(bit)) bits.set(@intCast(bit));
    }
    const root = db.root();
    const floor = db.inactivity_floor_loc;
    try db.sync();
    db.deinit();
    db.* = try harness.open(Db, null);
    try testing.expect(db.root().eql(root));
    try testing.expectEqual(@as(usize, model.count()), db.active_keys);
    try testing.expectEqual(@as(u64, bits.bit_length), db.bitmap.len());
    bit = floor;
    while (bit < db.bitmap.len()) : (bit += 1) {
        try testing.expectEqual(bits.isSet(@intCast(bit)), db.bitmap.get_bit(bit));
    }
}

/// Merkleizes a random chain of up to three batches on `db` and applies it. Each batch may be
/// applied as soon as it is merkleized, and the batch below it released, so the tip applies
/// with applied, pending, and dropped ancestors in every mix.
fn apply_random_chain(
    comptime Db: type,
    db: *Db,
    model: *Model,
    random: std.Random,
    salt: *u64,
) !void {
    const depth = random.uintLessThan(usize, 3) + 1;
    var chain: [3]?*Db.MerkleizedBatch = .{ null, null, null };
    defer for (chain) |batch| if (batch) |b| b.release();
    var applied: usize = 0;
    for (0..depth) |level| {
        const merkleized = merkleized: {
            const parent = if (level > 0) chain[level - 1] else null;
            var batch = if (parent) |p| p.new_batch() else try db.new_batch();
            errdefer batch.deinit();
            var writes: [6]Write = undefined;
            const count = random.uintLessThan(usize, writes.len + 1);
            for (writes[0..count]) |*w| {
                salt.* += 1;
                w.* = random_write(random, salt.*);
                try batch.write(w.key, w.value);
            }
            try model_apply(model, writes[0..count]);
            break :merkleized try batch.merkleize(db);
        };
        chain[level] = merkleized;
        if (random.boolean()) {
            try db.apply_batch(merkleized);
            applied = level + 1;
        }
        // Merkleizing past a dropped, unapplied ancestor is stale (as in commonware), so an
        // ancestor is released early only once applied or after the last batch.
        const releasable = applied >= level or level + 1 == depth;
        if (level > 0 and releasable and random.boolean()) {
            chain[level - 1].?.release();
            chain[level - 1] = null;
        }
        if (comptime Db.Update.siblings) try check_batch_neighbors(Db, db, chain[level].?, model);
    }
    const tip = chain[depth - 1].?;
    if (applied < depth) try db.apply_batch(tip);
    try testing.expect(db.root().eql(tip.root()));
}

/// Random chains against a model, sometimes pruning to the floor, with every round checked
/// against the reopened rebuild.
fn check_random_chains(comptime Db: type, seed: u64) !void {
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var db = try harness.open(Db, null);
    defer db.deinit();
    var model: Model = .empty;
    defer model.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var salt: u64 = 0;
    for (0..40) |_| {
        try apply_random_chain(Db, &db, &model, random, &salt);
        if (random.uintLessThan(u8, 4) == 0) try db.prune(db.inactivity_floor());
        try check_and_reopen(Db, &harness, &db, &model);
        if (comptime Db.Update.siblings) try check_links(Db, &db, &model);
    }
}

fn digest_less(_: void, a: Digest, b: Digest) bool {
    return std.mem.order(u8, &a.bytes, &b.bytes) == .lt;
}

/// Checks the ordered links against `model`: each active key links to its successor in key
/// order (wrapping), and the next/previous key lookups agree for active and absent keys.
fn check_links(comptime Db: type, db: *Db, model: *Model) !void {
    var keys: std.ArrayList(Digest) = .empty;
    defer keys.deinit(gpa);
    var it = model.keyIterator();
    while (it.next()) |k| try keys.append(gpa, .{ .bytes = k.* });
    std.mem.sort(Digest, keys.items, {}, digest_less);
    const n = keys.items.len;
    for (keys.items, 0..) |k, i| {
        const found = (try db.get_with_next_key(&k)).?;
        try testing.expect(found.next_key.eql(keys.items[(i + 1) % n]));
        const next = try db.get_next_key(&k);
        try expect_optional(next, if (i + 1 < n) keys.items[i + 1] else null);
        const prev = try db.get_prev_key(&k);
        try expect_optional(prev, if (i > 0) keys.items[i - 1] else null);
    }
    // Absent keys: the nearest active keys around them.
    for (0..24) |k| {
        const probe = if (k >= 16) support.colliding_digest(7, k) else key(k);
        if (model.contains(probe.bytes)) continue;
        try testing.expect(try db.get_with_next_key(&probe) == null);
        var above: ?Digest = null;
        var below: ?Digest = null;
        for (keys.items) |active| {
            if (digest_less({}, probe, active)) {
                if (above == null) above = active;
            } else {
                below = active;
            }
        }
        try expect_optional(try db.get_next_key(&probe), above);
        try expect_optional(try db.get_prev_key(&probe), below);
    }
}

/// Checks a merkleized batch's next and previous key lookups against `model`, its view, for
/// active keys and absent probes.
fn check_batch_neighbors(
    comptime Db: type,
    db: *Db,
    batch: *Db.MerkleizedBatch,
    model: *Model,
) !void {
    var keys: std.ArrayList(Digest) = .empty;
    defer keys.deinit(gpa);
    var it = model.keyIterator();
    while (it.next()) |k| try keys.append(gpa, .{ .bytes = k.* });
    std.mem.sort(Digest, keys.items, {}, digest_less);
    var probes: std.ArrayList(Digest) = .empty;
    defer probes.deinit(gpa);
    try probes.appendSlice(gpa, keys.items);
    for (0..24) |k| try probes.append(gpa, if (k >= 16) support.colliding_digest(7, k) else key(k));
    try probes.append(gpa, .{ .bytes = @splat(0) });
    try probes.append(gpa, .{ .bytes = @splat(0xff) });
    for (probes.items) |probe| {
        var above: ?Digest = null;
        var below: ?Digest = null;
        for (keys.items) |active| {
            if (digest_less({}, probe, active)) {
                if (above == null) above = active;
            } else if (digest_less({}, active, probe)) {
                below = active;
            }
        }
        try expect_optional(try batch.get_next_key(&probe, db), above);
        try expect_optional(try batch.get_prev_key(&probe, db), below);
    }
}

test "any ordered randomized chains keep links and match the rebuild" {
    inline for (families) |F| try check_random_chains(support.OrderedFixed(F), 0x0dde_ed11);
}

test "any randomized chains match a model and the rebuilt snapshot" {
    inline for (families) |F| {
        try check_random_chains(support.UnorderedFixed(F), 0x5eed_a11);
        // One-byte chunks put many chunk boundaries and bitmap prunes under the walk.
        try check_random_chains(support.UnorderedFixedChunks(F, 1), 0x5eed_a12);
    }
}

/// Seeds `count` keys `key(i)` with `val(i, 0)`.
fn seed_keys(comptime Db: type, db: *Db, comptime count: usize) !void {
    var writes: [count]Write = undefined;
    for (&writes, 0..) |*w, i| w.* = .{ .key = key(i), .value = val(i, 0) };
    try support.apply_writes(Db, db, &writes);
}

/// Merkleizes `writes` on `parent`, or on `db` if null.
fn merkleize_writes(
    comptime Db: type,
    db: *Db,
    parent: ?*Db.MerkleizedBatch,
    writes: []const Write,
) !*Db.MerkleizedBatch {
    var batch = if (parent) |p| p.new_batch() else try db.new_batch();
    errdefer batch.deinit();
    for (writes) |w| try batch.write(w.key, w.value);
    return batch.merkleize(db);
}

/// The resolution a staged read of `k` must report over the unapplied `chain` (oldest first)
/// on `db`, derived from the chain's operations: the last operation on the key, else the
/// database's location of it.
fn expected_resolution(
    comptime Db: type,
    db: *Db,
    chain: []const *Db.MerkleizedBatch,
    k: Digest,
) !?Db.StagedLoc {
    const base = try db.get_with_loc(&k);
    const base_loc: ?u64 = if (base) |b| b.location else null;
    var touched = false;
    var found: ?Db.StagedLoc = null;
    for (chain) |batch| {
        const start, const ops = batch.operations();
        for (ops, 0..) |op, i| switch (op) {
            .update => |u| if (u.key.eql(k)) {
                touched = true;
                found = .{ .ancestor = .{ .loc = start + i, .base_old_loc = base_loc } };
            },
            .delete => |deleted| if (deleted.eql(k)) {
                touched = true;
                found = null;
            },
            .commit => {},
        };
    }
    if (touched) return found;
    return if (base_loc) |loc| .{ .committed = loc } else null;
}

fn expect_optional(actual: ?Digest, expected: ?Digest) !void {
    if (expected) |e| {
        try testing.expect(actual != null and actual.?.eql(e));
    } else {
        try testing.expect(actual == null);
    }
}

test "any staged reads report where each key resolved" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try seed_keys(Db, &db, 12);
        const grandparent = try merkleize_writes(Db, &db, null, &.{
            .{ .key = key(0), .value = val(0, 1) },
            .{ .key = key(100), .value = val(100, 1) },
            .{ .key = key(2), .value = null },
        });
        defer grandparent.release();
        const parent = try merkleize_writes(Db, &db, grandparent, &.{
            .{ .key = key(1), .value = val(1, 2) },
        });
        defer parent.release();
        var batch = parent.new_batch();
        try batch.write(key(3), val(3, 3));
        const keys = [_]Digest{ key(0), key(100), key(1), key(3), key(2), key(9000) };
        var values: [keys.len]?Digest = undefined;
        var staged = staged: {
            errdefer batch.deinit();
            break :staged try batch.stage(&keys, &db, &values);
        };
        defer staged.deinit();
        const expected = [_]?Digest{ val(0, 1), val(100, 1), val(1, 2), val(3, 3), null, null };
        for (values, expected) |actual, e| try expect_optional(actual, e);
        // Expansion appends slots; the untouched seed keys resolve in the database unless an
        // ancestor's floor walk moved them.
        var more: [8]?Digest = undefined;
        var more_keys: [8]Digest = undefined;
        for (&more_keys, 4..) |*k, i| k.* = key(i);
        const range = try staged.expand(&more_keys, &db, &more);
        try testing.expectEqual(@as(usize, keys.len), range.start);
        try testing.expectEqual(@as(usize, keys.len + more_keys.len), staged.len());
        for (more, 4..) |actual, i| try expect_optional(actual, val(i, 0));
        const chain = [_]*Db.MerkleizedBatch{ grandparent, parent };
        var committed: usize = 0;
        for (staged.keys.items, staged.resolutions.items, 0..) |k, actual, slot| {
            // This batch's own write answers its slot, so it resolves nowhere.
            const want = if (slot == 3) null else try expected_resolution(Db, &db, &chain, k);
            try testing.expectEqual(want, actual);
            if (actual != null and actual.? == .committed) committed += 1;
        }
        try testing.expect(staged.resolutions.items[0].? == .ancestor);
        try testing.expect(staged.resolutions.items[1].?.ancestor.base_old_loc == null);
        try testing.expect(committed > 0);
    }
}

test "any staged merkleize matches explicit writes" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        const Mutation = Db.UnmerkleizedBatch.Mutation;
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try seed_keys(Db, &db, 40);
        // key(5) in slots 0 and 3, read-only key(6), missing key(9000), key(20) deleted in a
        // slot but recreated by an unstaged write (unstaged writes win).
        const keys = [_]Digest{ key(5), key(6), key(9000), key(5), key(20) };
        const slots = [_]Db.Slot{
            .{ .put = val(5, 5000) }, .keep,   .{ .put = val(9000, 5001) },
            .{ .put = val(5, 5002) }, .delete,
        };
        const unstaged = [_]Mutation{
            .{ .key = key(7000), .value = val(7000, 6000) },
            .{ .key = key(30), .value = val(30, 6001) },
            .{ .key = key(31), .value = null },
            .{ .key = key(20), .value = val(20, 6002) },
        };
        const metadata = val(1, 99);
        const explicit = explicit: {
            var batch = try db.new_batch();
            errdefer batch.deinit();
            for (keys, slots) |k, slot| switch (slot) {
                .keep => {},
                .put => |v| try batch.write(k, v),
                .delete => try batch.write(k, null),
            };
            for (unstaged) |w| try batch.write(w.key, w.value);
            batch.with_metadata(metadata);
            break :explicit try batch.merkleize(&db);
        };
        defer explicit.release();
        var batch = try db.new_batch();
        var values: [keys.len]?Digest = undefined;
        var staged = staged: {
            errdefer batch.deinit();
            break :staged try batch.stage(&keys, &db, &values);
        };
        const expected = [_]?Digest{ val(5, 0), val(6, 0), null, val(5, 0), val(20, 0) };
        for (values, expected) |actual, e| try expect_optional(actual, e);
        staged.with_metadata(metadata);
        const merkleized = staged.merkleize(&slots, &unstaged, &db) catch |err| {
            staged.deinit();
            return err;
        };
        defer merkleized.release();
        try testing.expect(merkleized.root().eql(explicit.root()));
        try db.apply_batch(merkleized);
        try expect_value(&db, key(5), val(5, 5002));
        try expect_value(&db, key(6), val(6, 0));
        try expect_value(&db, key(9000), val(9000, 5001));
        try expect_value(&db, key(20), val(20, 6002));
        try expect_value(&db, key(31), null);
        try testing.expect((try db.get_metadata()).?.eql(metadata));
    }
}

/// Commonware's staged-ancestor scenarios: reads resolved in a grandparent's and a parent's
/// diffs, then the grandparent applied before merkleize (`shape` 0), or the ancestors applied
/// separately (1) or with the staged batch (2) after it.
fn check_staged_ancestors(comptime Db: type, shape: u8) !void {
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var db = try harness.open(Db, null);
    defer db.deinit();
    try seed_keys(Db, &db, 8);
    const grandparent = try merkleize_writes(Db, &db, null, &.{
        .{ .key = key(0), .value = val(0, 1000) },
        .{ .key = key(100), .value = val(100, 1001) },
    });
    defer grandparent.release();
    const parent = try merkleize_writes(Db, &db, grandparent, &.{
        .{ .key = key(1), .value = val(1, 1002) },
    });
    defer parent.release();
    const keys = [_]Digest{ key(0), key(100), key(1), key(3) };
    var values: [keys.len]?Digest = undefined;
    var batch = parent.new_batch();
    var staged = staged: {
        errdefer batch.deinit();
        break :staged try batch.stage(&keys, &db, &values);
    };
    const expected = [_]?Digest{ val(0, 1000), val(100, 1001), val(1, 1002), val(3, 0) };
    for (values, expected) |actual, e| try expect_optional(actual, e);
    if (shape == 0) try db.apply_batch(grandparent);
    const slots = [_]Db.Slot{
        .{ .put = val(0, 2000) }, .{ .put = val(100, 2001) }, .delete, .{ .put = val(3, 2002) },
    };
    const merkleized = staged.merkleize(&slots, &.{}, &db) catch |err| {
        staged.deinit();
        return err;
    };
    defer merkleized.release();
    const explicit = try merkleize_writes(Db, &db, parent, &.{
        .{ .key = key(0), .value = val(0, 2000) },
        .{ .key = key(100), .value = val(100, 2001) },
        .{ .key = key(1), .value = null },
        .{ .key = key(3), .value = val(3, 2002) },
    });
    defer explicit.release();
    try testing.expect(merkleized.root().eql(explicit.root()));
    if (shape == 1) try db.apply_batch(grandparent);
    if (shape != 2) try db.apply_batch(parent);
    try db.apply_batch(merkleized);
    try db.commit();
    try expect_value(&db, key(0), val(0, 2000));
    try expect_value(&db, key(100), val(100, 2001));
    try expect_value(&db, key(1), null);
    try expect_value(&db, key(3), val(3, 2002));
}

test "any staged reads through ancestors survive every apply order" {
    inline for (families) |F| {
        for ([_]u8{ 0, 1, 2 }) |shape| {
            try check_staged_ancestors(support.UnorderedFixed(F), shape);
            // Ordered staging resolves the same way; its merkleize also rewrites links.
            try check_staged_ancestors(support.OrderedFixed(F), shape);
        }
    }
}

test "any staged batches refuse stale forks" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var batch = try db.new_batch();
        var values: [1]?Digest = undefined;
        var staged = staged: {
            errdefer batch.deinit();
            break :staged try batch.stage(&.{key(1)}, &db, &values);
        };
        defer staged.deinit();
        try support.apply_writes(Db, &db, &.{.{ .key = key(2), .value = val(2, 0) }});
        try testing.expectError(error.StaleRead, staged.expand(&.{key(2)}, &db, &values));
        try testing.expectEqual(@as(usize, 1), staged.len());
        const slots = [_]Db.Slot{.{ .put = val(1, 1) }};
        try testing.expectError(error.StaleBatch, staged.merkleize(&slots, &.{}, &db));
    }
}

/// commonware's `staged_merkleize_rejects_slot_count_mismatch!`: merkleizing a one-key staged
/// read with `slot_count` slots, other than one, violates the caller contract and panics.
fn staged_slot_mismatch(comptime Db: type, comptime slot_count: usize) !void {
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var db = try harness.open(Db, null);
    defer db.deinit();
    var batch = try db.new_batch();
    var values: [1]?Digest = undefined;
    const k0 = support.colliding_digest(0x40, 0);
    var staged = staged: {
        errdefer batch.deinit();
        break :staged try batch.stage(&.{k0}, &db, &values);
    };
    defer staged.deinit();
    const two = [_]Db.Slot{ .keep, .{ .put = support.colliding_digest(0x50, 0) } };
    const merkleized = try staged.merkleize(two[0..slot_count], &.{}, &db);
    merkleized.release();
}

fn StagedMismatch(comptime Db: type, comptime slot_count: usize) type {
    return struct {
        fn body() !void {
            try staged_slot_mismatch(Db, slot_count);
        }
    };
}

const Unordered = support.UnorderedFixed(merkle.mmr.Family);
const Ordered = support.OrderedFixed(merkle.mmr.Family);
const unreachable_code = "reached unreachable code";

test "staged merkleize rejects an extra slot (unordered)" {
    try death.expect_panic(@src(), unreachable_code, StagedMismatch(Unordered, 2).body);
}

test "staged merkleize rejects an extra slot (ordered)" {
    try death.expect_panic(@src(), unreachable_code, StagedMismatch(Ordered, 2).body);
}

test "staged merkleize rejects a missing slot (unordered)" {
    try death.expect_panic(@src(), unreachable_code, StagedMismatch(Unordered, 0).body);
}

test "staged merkleize rejects a missing slot (ordered)" {
    try death.expect_panic(@src(), unreachable_code, StagedMismatch(Ordered, 0).body);
}

test "any ordered predecessor rewrites take the nearest ancestor's update" {
    inline for (families) |F| {
        const Db = support.OrderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        const seed = support.colliding_digest(0x10, 0);
        const a = support.colliding_digest(0x50, 1);
        const c = support.colliding_digest(0x50, 2);
        const b = support.colliding_digest(0x50, 3);
        try support.apply_writes(Db, &db, &.{.{ .key = seed, .value = val(0, 0) }});
        const grandparent = try merkleize_writes(Db, &db, null, &.{
            .{ .key = a, .value = val(1, 1) },
            .{ .key = b, .value = val(3, 1) },
        });
        defer grandparent.release();
        const parent = try merkleize_writes(Db, &db, grandparent, &.{
            .{ .key = a, .value = val(1, 2) },
            .{ .key = b, .value = null },
        });
        defer parent.release();
        const child = try merkleize_writes(Db, &db, parent, &.{.{ .key = c, .value = val(2, 3) }});
        defer child.release();
        try db.apply_batch(child);
        var model: Model = .empty;
        defer model.deinit(gpa);
        try model_apply(&model, &.{
            .{ .key = seed, .value = val(0, 0) },
            .{ .key = a, .value = val(1, 2) },
            .{ .key = c, .value = val(2, 3) },
        });
        try expect_value(&db, a, val(1, 2));
        try expect_value(&db, b, null);
        try check_links(Db, &db, &model);
    }
}

test "any init_from_log rebuilds an opened log and refuses an empty one" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        const cfg = harness.cfg(Db);
        const storage = harness.storage.interface();
        const scope = metrics.Scope.init(&harness.registry).child("db");
        const options: qmdb.InitOptions = .{ .replay_from_floor = true };
        const empty = try qmdb.init_journal(Db.Log, gpa, storage, cfg.merkle, cfg.log, options);
        const refused = Db.init_from_log(gpa, scope, empty, cfg.translator, cfg.init_cache);
        try testing.expectError(error.HistoricalFloorPruned, refused);
        var db = try harness.open(Db, null);
        errdefer db.deinit();
        try support.apply_writes(Db, &db, &.{
            .{ .key = key(1), .value = val(1, 1) },
            .{ .key = key(2), .value = val(2, 1) },
        });
        try support.apply_writes(Db, &db, &.{.{ .key = key(1), .value = null }});
        try db.sync();
        const root = db.root();
        const floor = db.inactivity_floor();
        db.deinit();
        const log = try qmdb.init_journal(Db.Log, gpa, storage, cfg.merkle, cfg.log, options);
        harness.registry.deinit();
        harness.registry = metrics.Registry.init(gpa);
        const reopened = metrics.Scope.init(&harness.registry).child("db");
        db = try Db.init_from_log(gpa, reopened, log, cfg.translator, cfg.init_cache);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(floor, db.inactivity_floor());
        try expect_value(&db, key(1), null);
        try expect_value(&db, key(2), val(2, 1));
        try db.destroy();
    }
}

/// A floor policy that evicts the keys in `targets` and keeps every other update it reaches,
/// recording the locations it decides (commonware's `Script` with `Choice::Evict`/`Keep`).
const EvictKeys = struct {
    targets: []const Digest,
    locations: [16]u64 = undefined,
    decided: usize = 0,

    pub fn evicts(_: *const EvictKeys) bool {
        return true;
    }

    pub fn limits(_: *const EvictKeys, _: usize) floor_mod.Limits {
        return .{ .entries = std.math.maxInt(usize), .skips = std.math.maxInt(u64) };
    }

    pub fn decide(
        self: *EvictKeys,
        comptime K: type,
        comptime V: type,
        entry: floor_mod.Entry(K, V),
    ) floor_mod.Decision(V) {
        assert(self.decided < self.locations.len);
        self.locations[self.decided] = entry.location;
        self.decided += 1;
        for (self.targets) |target| {
            if (!target.eql(entry.key.*)) continue;
            const decision, _ = entry.evict(); // Digest values own no memory.
            return decision;
        }
        return entry.keep();
    }
};

test "any a key the batch creates and the walk evicts ends deleted with no base" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        const kept = Digest{ .bytes = @splat(1) };
        const created = Digest{ .bytes = @splat(2) };
        var seed = try db.new_batch();
        try seed.write(kept, kept);
        var hold: floor_mod.Hold = .{};
        const seeded = try seed.merkleize_with(&db, &hold);
        try db.apply_batch(seeded);
        seeded.release();
        var policy: EvictKeys = .{ .targets = &.{created} };
        var batch = try db.new_batch();
        try batch.write(created, created);
        const merkleized = try batch.merkleize_with(&db, &policy);
        defer merkleized.release();
        try testing.expectEqualSlices(u64, &.{ 1, 3 }, policy.locations[0..policy.decided]);
        const entries = merkleized.diff.entries;
        try testing.expectEqual(@as(usize, 2), entries.len);
        try testing.expect(entries[0].key.eql(kept));
        try testing.expectEqual(@as(?u64, 4), entries[0].entry.loc());
        try testing.expectEqual(@as(?u64, 1), entries[0].entry.base_old_loc());
        try testing.expect(entries[1].key.eql(created));
        try testing.expectEqual(@as(?u64, null), entries[1].entry.loc());
        try testing.expectEqual(@as(?u64, null), entries[1].entry.base_old_loc());
        try testing.expectEqual(@as(usize, 1), merkleized.total_active_keys);
        _, const ops = merkleized.operations();
        try testing.expect(ops[0] == .update and ops[0].update.key.eql(created));
        try testing.expect(ops[1] == .update and ops[1].update.key.eql(kept));
        try testing.expect(ops[2] == .delete and ops[2].delete.eql(created));
        try db.apply_batch(merkleized);
        try expect_value(&db, created, null);
        try expect_value(&db, kept, kept);
        try testing.expectEqual(@as(usize, 1), db.active_keys);
        // The reopened rebuild agrees.
        const root = db.root();
        try db.sync();
        db.deinit();
        db = try harness.open(Db, null);
        try testing.expect(db.root().eql(root));
        try expect_value(&db, created, null);
        try testing.expectEqual(@as(usize, 1), db.active_keys);
    }
}

test "any evicting every committed key empties the database and survives reopen" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var writes: [4]Write = undefined;
        var targets: [4]Digest = undefined;
        for (&writes, &targets, 0..) |*w, *t, i| {
            w.* = .{ .key = key(i), .value = val(i, 1) };
            t.* = key(i);
        }
        try support.apply_writes(Db, &db, &writes);
        var policy: EvictKeys = .{ .targets = &targets };
        var batch = try db.new_batch();
        try batch.write(key(9), val(9, 1));
        const merkleized = try batch.merkleize_with(&db, &policy);
        defer merkleized.release();
        try db.apply_batch(merkleized);
        for (targets) |t| try expect_value(&db, t, null);
        try expect_value(&db, key(9), val(9, 1));
        try testing.expectEqual(@as(usize, 1), db.active_keys);
        const root = db.root();
        try db.sync();
        db.deinit();
        db = try harness.open(Db, null);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(@as(usize, 1), db.active_keys);
        for (targets) |t| try expect_value(&db, t, null);
    }
}

test "any evicting the batch's own update of a committed key deletes the committed one" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try support.apply_writes(Db, &db, &.{
            .{ .key = key(1), .value = val(1, 1) },
            .{ .key = key(2), .value = val(2, 1) },
        });
        // The batch rewrites key(1); the walk reaches that rewrite and evicts it, so the key's
        // committed update must leave the snapshot too.
        var policy: EvictKeys = .{ .targets = &.{key(1)} };
        var batch = try db.new_batch();
        try batch.write(key(1), val(1, 2));
        const merkleized = try batch.merkleize_with(&db, &policy);
        defer merkleized.release();
        const entry = merkleized.diff.lookup(&key(1)).?;
        try testing.expect(entry.* == .deleted);
        try testing.expect(entry.base_old_loc() != null);
        try db.apply_batch(merkleized);
        try expect_value(&db, key(1), null);
        try expect_value(&db, key(2), val(2, 1));
        try testing.expectEqual(@as(usize, 1), db.active_keys);
        const root = db.root();
        try db.sync();
        db.deinit();
        db = try harness.open(Db, null);
        try testing.expect(db.root().eql(root));
        try expect_value(&db, key(1), null);
    }
}

test "any ordered range scans match a sorted model under every bound" {
    inline for (families) |F| {
        const Db = support.OrderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        // Keys in several translated buckets plus a colliding bucket, some deleted.
        var keys: [24]Digest = undefined;
        var writes: [24]Write = undefined;
        for (&keys, &writes, 0..) |*k, *w, i| {
            k.* = if (i < 16) key(i) else support.colliding_digest(0x80, i);
            w.* = .{ .key = k.*, .value = val(i, 1) };
        }
        try support.apply_writes(Db, &db, &writes);
        try support.apply_writes(Db, &db, &.{
            .{ .key = keys[3], .value = null },
            .{ .key = keys[17], .value = null },
        });
        var model: [22]Digest = undefined;
        var count: usize = 0;
        for (keys, 0..) |k, i| {
            if (i == 3 or i == 17) continue;
            model[count] = k;
            count += 1;
        }
        std.mem.sort(Digest, model[0..count], {}, struct {
            fn less(_: void, a: Digest, b: Digest) bool {
                return std.mem.order(u8, &a.bytes, &b.bytes) == .lt;
            }
        }.less);
        const sorted = model[0..count];
        // Bounds at model keys, deleted keys, and the extremes.
        const probes = [_]Digest{ sorted[0], sorted[5], keys[3], sorted[count - 1], keys[17] };
        const Bound = Db.Bound;
        var bounds: std.ArrayList(Bound) = .empty;
        defer bounds.deinit(gpa);
        try bounds.append(gpa, .unbounded);
        for (probes) |p| {
            try bounds.append(gpa, .{ .included = p });
            try bounds.append(gpa, .{ .excluded = p });
        }
        for (bounds.items) |start| for (bounds.items) |end| {
            var it = db.range(start, end);
            defer it.deinit();
            for (sorted, 0..) |k, i| {
                const above = switch (start) {
                    .unbounded => true,
                    .included => |s| std.mem.order(u8, &k.bytes, &s.bytes) != .lt,
                    .excluded => |s| std.mem.order(u8, &k.bytes, &s.bytes) == .gt,
                };
                const below = switch (end) {
                    .unbounded => true,
                    .included => |e| std.mem.order(u8, &k.bytes, &e.bytes) != .gt,
                    .excluded => |e| std.mem.order(u8, &k.bytes, &e.bytes) == .lt,
                };
                if (!above or !below) continue;
                const pair = (try it.next()) orelse return error.TestUnexpectedResult;
                try testing.expect(pair.key.eql(k));
                const index = for (keys, 0..) |orig, j| {
                    if (orig.eql(k)) break j;
                } else unreachable;
                _ = i;
                try testing.expect(pair.value.eql(val(index, 1)));
            }
            try testing.expect(try it.next() == null);
        };
        var all = db.range(.unbounded, .unbounded);
        defer all.deinit();
        for (sorted) |k| try testing.expect((try all.next_key()).?.eql(k));
        try testing.expect(try all.next_key() == null);
    }
}

// Commonware's any/unordered/fixed.rs test_any_unordered_fixed_metrics: the gauges, call
// counters, and duration histograms after one of each operation, timed on the config's `io`.
test "any metrics count and time each operation" {
    const D = support.UnorderedFixed(merkle.mmr.Family);
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var cfg = harness.cfg(D);
    cfg.io = testing.io;
    // The log names no clock of its own, so the database's times it too.
    cfg.log.metrics = metrics.Scope.init(&harness.registry).child("log");
    const scope = metrics.Scope.init(&harness.registry).child("db");
    var db = try D.init(gpa, harness.storage.interface(), scope, cfg, null);
    defer db.deinit();
    try support.apply_writes(D, &db, &.{.{ .key = key(1), .value = val(1, 0) }});
    try expect_value(&db, key(1), val(1, 0));
    var many: [1]?Digest = undefined;
    try db.get_many(&.{key(1)}, &many);
    try testing.expect(many[0].?.eql(val(1, 0)));
    try db.commit();
    try (try db.start_sync()).wait_release();
    try db.sync();
    try db.prune(0);
    try qmdb_support.expect_metric_values(gpa, &harness.registry, &.{
        .{ "db_size", "4" },                       .{ "db_pruning_boundary", "0" },
        .{ "db_retained", "4" },                   .{ "db_inactivity_floor", "2" },
        .{ "db_last_commit", "3" },                .{ "db_get_calls_total", "1" },
        .{ "db_get_many_calls_total", "1" },       .{ "db_lookups_requested_total", "2" },
        .{ "db_apply_batch_calls_total", "1" },    .{ "db_operations_applied_total", "3" },
        .{ "db_commit_calls_total", "1" },         .{ "db_start_sync_calls_total", "1" },
        .{ "db_sync_calls_total", "1" },           .{ "db_prune_calls_total", "1" },
        .{ "db_get_duration_count", "1" },         .{ "db_get_many_duration_count", "1" },
        .{ "db_apply_batch_duration_count", "1" }, .{ "db_commit_duration_count", "1" },
        .{ "db_sync_duration_count", "1" },        .{ "db_prune_duration_count", "1" },
    });
    const text = try harness.registry.encode(gpa);
    defer gpa.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "log_commit_duration_count") != null);
    try testing.expect(!metrics.has_metric_value(text, "log_commit_duration_count", "0"));
}
