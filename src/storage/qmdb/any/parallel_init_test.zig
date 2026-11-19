//! commonware's any/{unordered,ordered}/fixed.rs `*_partitioned_*parallel_init*` tests: a
//! database over a partitioned index, reopened with a sweep of `init_concurrency` budgets,
//! rebuilds the same root, active key count, activity bitmap, and values every time.

const std = @import("std");
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const partitioned = @import("../../index/partitioned/mod.zig");
const translator = @import("../../translator.zig");
const metrics = @import("runtime").telemetry.metrics;
const support = @import("test_support.zig");
const qmdb_support = @import("../test_support.zig");
const any = @import("mod.zig");

const gpa = testing.allocator;
const Digest = support.Digest;
const key = support.to_digest;
const val = support.to_val;
const T = translator.OneCap;

fn PartitionedDb(comptime ordered: bool) type {
    const F = merkle.mmr.Family;
    if (ordered) {
        const Journal = fixed.Journal(any.operation.Ordered(F, Digest, support.Encoding));
        const U = any.operation.update.Ordered(Digest, support.Encoding);
        return any.Db(F, U, Journal, partitioned.ordered.Index(T, u64, 1), support.Sha256, 32);
    }
    const Journal = fixed.Journal(any.operation.Unordered(F, Digest, support.Encoding));
    const U = any.operation.update.Unordered(Digest, support.Encoding);
    return any.Db(F, U, Journal, partitioned.unordered.Index(T, u64, 1), support.Sha256, 32);
}

fn open(comptime D: type, harness: *support.Harness, concurrency: usize) !D {
    // `Harness.cfg`'s fields, with a partitioned translator.
    const cfg: D.Cfg = .{
        .merkle = .{
            .journal_partition = "cf-mj",
            .metadata_partition = "cf-mm",
            .items_per_blob = 11,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &harness.cache_ref,
        },
        .log = qmdb_support.log_config(@FieldType(D.Cfg, "log"), &harness.cache_ref),
        .translator = partitioned.Translator(T, 1).init(.{}),
        .init_cache = 1024,
        .init_concurrency = concurrency,
        .io = testing.io,
    };
    harness.registry.deinit();
    harness.registry = metrics.Registry.init(gpa);
    const scope = metrics.Scope.init(&harness.registry).child("db");
    return D.init(gpa, harness.storage.interface(), scope, cfg, null);
}

const keys = 300;

/// Writes, updates a third, deletes a seventh, then reinserts a third of the deleted keys, so
/// the log holds delete-then-reinsert sequences.
fn populate(comptime D: type, db: *D) !void {
    var writes: [keys]support.Write = undefined;
    for (&writes, 0..) |*w, i| w.* = .{ .key = key(i), .value = val(i, 1) };
    try support.apply_writes(D, db, &writes);
    try db.commit();
    var count: usize = 0;
    var i: usize = 0;
    while (i < keys) : (i += 3) {
        writes[count] = .{ .key = key(i), .value = val(i, 2) };
        count += 1;
    }
    i = 1;
    while (i < keys) : (i += 7) {
        writes[count] = .{ .key = key(i), .value = null };
        count += 1;
    }
    try support.apply_writes(D, db, writes[0..count]);
    try db.commit();
    count = 0;
    i = 1;
    while (i < keys) : (i += 21) {
        writes[count] = .{ .key = key(i), .value = val(i, 3) };
        count += 1;
    }
    // Two keys of one partition and translated sub-key resolve a collision through the log.
    writes[count] = .{ .key = support.colliding_digest(0x10, 1), .value = val(1, 9) };
    writes[count + 1] = .{ .key = support.colliding_digest(0x10, 2), .value = val(2, 9) };
    try support.apply_writes(D, db, writes[0 .. count + 2]);
    try db.commit();
    try db.sync();
}

fn bits_of(comptime D: type, db: *const D) !std.DynamicBitSetUnmanaged {
    var bits: std.DynamicBitSetUnmanaged = try .initEmpty(gpa, @intCast(db.bitmap.len()));
    var bit = db.inactivity_floor_loc;
    while (bit < db.bitmap.len()) : (bit += 1) {
        if (db.bitmap.get_bit(bit)) bits.set(@intCast(bit));
    }
    return bits;
}

fn check_equivalence(comptime ordered: bool) !void {
    const D = PartitionedDb(ordered);
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var db = try open(D, &harness, 1);
    try populate(D, &db);
    const root = db.root();
    const active_keys = db.active_keys;
    var bits = try bits_of(D, &db);
    defer bits.deinit(gpa);
    var values: [keys]?Digest = undefined;
    for (&values, 0..) |*v, i| v.* = try db.get(&key(i));
    db.deinit();
    // Budgets cover the serial path, a lone worker, range rounding, and budgets beyond the
    // partition and chunk counts.
    for ([_]usize{ 1, 2, 3, 5, 9, 201, 301, std.math.maxInt(usize) }) |concurrency| {
        db = try open(D, &harness, concurrency);
        defer db.deinit();
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(active_keys, db.active_keys);
        var reopened = try bits_of(D, &db);
        defer reopened.deinit(gpa);
        try testing.expect(bits.eql(reopened));
        for (values, 0..) |expected, i| {
            const actual = try db.get(&key(i));
            try testing.expectEqual(expected == null, actual == null);
            if (expected) |e| try testing.expect(actual.?.eql(e));
        }
    }
}

test "any partitioned parallel init matches the serial init" {
    try check_equivalence(false);
    try check_equivalence(true);
}

test "any partitioned fresh database reopens with a parallel init" {
    inline for (.{ false, true }) |ordered| {
        const D = PartitionedDb(ordered);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try open(D, &harness, 1);
        const root = db.root();
        db.deinit();
        db = try open(D, &harness, 4);
        defer db.deinit();
        try testing.expect(db.root().eql(root));
    }
}
