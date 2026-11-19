//! Tests of the store (qmdb/store/db.rs's tests) over Blake3 digest keys and owned byte
//! values, with commonware's journal configuration (7 items per section), so sizes, floors, and
//! pruning boundaries match commonware's.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const translator = @import("../../translator.zig");
const value = @import("../value.zig");
const floor_mod = @import("../floor.zig");
const test_support = @import("../test_support.zig");
const store = @import("mod.zig");

const gpa = testing.allocator;
const Digest = cryptography.Blake3.Digest;
const Bytes = []const u8;
const Db = store.Db(Digest, value.Variable(Bytes), translator.TwoCap);
const Write = Db.Write;
const Storage = runtime.storage.Storage;
const CacheRef = runtime.buffer.paged.CacheRef;

/// Commonware's `Blake3::hash(&[&i.to_be_bytes()])`.
const CodecCfg = @FieldType(Db.Journal.Cfg, "codec_config");

fn key(i: u64) Digest {
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, i, .big);
    return cryptography.Blake3.hash(&.{&be});
}

/// Storage and a page cache for opening test stores (commonware's `test_config`).
const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,

    fn init(self: *Harness) !void {
        self.storage = .init(gpa);
        errdefer self.storage.deinit();
        self.cache_ref = try .init(gpa, 77, 9);
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn open(self: *Harness, max_size: ?u64) !Db {
        return open_on(self.storage.interface(), &self.cache_ref, max_size);
    }
};

/// Opens the test store (commonware's `test_config`) on `storage`.
fn open_on(storage: Storage, cache_ref: *CacheRef, max_size: ?u64) !Db {
    const cfg: Db.Cfg = .{
        .log = .{
            .partition = "journal",
            .items_per_section = 7,
            .codec_config = test_support.codec_config(CodecCfg),
            .cache_ref = cache_ref,
            .write_buffer = 64 * 1024,
            .replay_buffer = 64 * 1024,
        },
        .translator = .{},
        .init_cache = 1024,
    };
    return Db.init(gpa, storage, cfg, max_size);
}

/// Applies `writes` (copied) as one batch with `metadata`; returns the applied range's end.
fn apply(db: *Db, writes: []const Write, metadata: ?Bytes) !u64 {
    var changeset = try Db.Changeset.init(gpa, writes);
    if (metadata) |m| {
        changeset.metadata = gpa.dupe(u8, m) catch |err| {
            changeset.deinit();
            return err;
        };
    }
    try db.apply_batch(&changeset);
    return db.bounds().end;
}

fn expect_value(db: *Db, k: Digest, want: ?Bytes) !void {
    const got = try db.get(&k);
    defer codec.free(?Bytes, gpa, got);
    try testing.expectEqual(want == null, got == null);
    if (want) |w| try testing.expectEqualSlices(u8, w, got.?);
}

fn expect_metadata(db: *Db, want: ?Bytes) !void {
    const got = try db.get_metadata();
    defer codec.free(?Bytes, gpa, got);
    try testing.expectEqual(want == null, got == null);
    if (want) |w| try testing.expectEqualSlices(u8, w, got.?);
}

/// The bitmap marks exactly the snapshot's locations and the last commit.
fn expect_bitmap_consistent(db: *Db) !void {
    const span = db.bounds();
    var active: u64 = 0;
    var loc = @max(span.start, db.bitmap.pruned_bits());
    while (loc < span.end) : (loc += 1) {
        if (!db.bitmap.get_bit(loc)) continue;
        active += 1;
        var op = try db.log.read(loc);
        defer op.deinit(gpa);
        switch (op) {
            .update => |u| {
                const got = try db.get(&u.key);
                defer codec.free(?Bytes, gpa, got);
                try testing.expectEqualSlices(u8, u.value, got.?);
            },
            .commit => try testing.expectEqual(span.end - 1, loc),
            .delete => return error.TestUnexpectedResult,
        }
    }
    try testing.expectEqual(@as(u64, db.active_keys) + 1, active);
    try testing.expectEqual(span.end, db.bitmap.len());
}

test "store construct empty" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    try testing.expectEqual(@as(u64, 1), db.bounds().end);
    try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
    try expect_metadata(&db, null);
    try db.prune(db.inactivity_floor());
    try testing.expectError(error.PruneBeyondMinRequired, db.prune(1));
    // An uncommitted batch does not survive a reopen.
    _ = try apply(&db, &.{.{ .key = key(1), .value = &.{ 1, 2, 3 } }}, null);
    db.deinit();
    db = try h.open(null);
    try testing.expectEqual(@as(u64, 1), db.bounds().end);
    // An empty batch with metadata makes the store durably non-empty.
    try testing.expectEqual(@as(u64, 2), try apply(&db, &.{}, &.{ 1, 2, 3 }));
    try db.commit();
    try db.prune(db.inactivity_floor());
    try expect_metadata(&db, &.{ 1, 2, 3 });
    db.deinit();
    db = try h.open(null);
    try expect_metadata(&db, &.{ 1, 2, 3 });
    // The floor keeps up with repeated empty commits.
    _ = try apply(&db, &.{.{ .key = key(2), .value = &.{ 1, 2, 3 } }}, null);
    try db.commit();
    for (1..100) |_| {
        _ = try apply(&db, &.{}, null);
        try db.commit();
        try testing.expect(db.bounds().end - db.inactivity_floor() <= 3);
        try expect_metadata(&db, null);
    }
    try expect_bitmap_consistent(&db);
    try db.destroy();
}

test "store construct basic" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    const k = key(0);
    const v: Bytes = &.{ 2, 3, 4, 5 };
    try expect_value(&db, k, null);
    // The update, the floor walk's move of it, and the commit.
    try testing.expectEqual(@as(u64, 4), try apply(&db, &.{.{ .key = k, .value = v }}, null));
    try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
    try expect_value(&db, k, v);
    db.deinit(); // A crash before commit.
    db = try h.open(null);
    try testing.expectEqual(@as(u64, 1), db.bounds().end);
    try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
    try expect_metadata(&db, null);
    const with_metadata = try apply(&db, &.{.{ .key = k, .value = v }}, &.{ 99, 100 });
    try testing.expectEqual(@as(u64, 4), with_metadata);
    try db.commit();
    try expect_metadata(&db, &.{ 99, 100 });
    db.deinit();
    db = try h.open(null);
    try testing.expectEqual(@as(u64, 4), db.bounds().end);
    try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
    try expect_value(&db, k, v);
    const v1: Bytes = &.{ 2, 3, 4, 5, 6 };
    const v2: Bytes = &.{ 6, 7, 8 };
    _ = try apply(&db, &.{.{ .key = key(1), .value = v1 }}, null);
    const end = try apply(&db, &.{.{ .key = key(2), .value = v2 }}, null);
    try testing.expectEqual(@as(u64, 10), end);
    try testing.expectEqual(@as(u64, 5), db.inactivity_floor());
    try expect_metadata(&db, null);
    try db.commit();
    try expect_value(&db, k, v);
    try expect_value(&db, key(1), v1);
    try expect_value(&db, key(2), v2);
    _ = try apply(&db, &.{.{ .key = key(1), .value = &.{ 2, 3, 4, 5, 6, 7 } }}, null);
    try db.commit();
    try expect_value(&db, key(1), &.{ 2, 3, 4, 5, 6, 7 });
    try expect_bitmap_consistent(&db);
    try db.destroy();
}

test "store log replay" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    const k = key(7);
    for (0..100) |_| _ = try apply(&db, &.{.{ .key = k, .value = &.{ 1, 2, 3, 4, 5 } }}, null);
    try testing.expectEqual(@as(usize, 1), db.snapshot.get(&k.bytes).count());
    try db.commit();
    try db.sync();
    db.deinit();
    db = try h.open(null);
    try db.prune(db.inactivity_floor());
    try testing.expectEqual(@as(usize, 1), db.snapshot.get(&k.bytes).count());
    // 1 (init) + 100 * (update, its move, commit).
    try testing.expectEqual(@as(u64, 301), db.bounds().end);
    try testing.expectEqual(@as(u64, 299), db.inactivity_floor());
    const floor = db.inactivity_floor();
    try testing.expectEqual(floor - floor % 7, db.bounds().start);
    try expect_bitmap_consistent(&db);
    try db.destroy();
}

test "store get many" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    defer db.deinit();
    const k1 = key(1);
    var k2 = key(2);
    @memcpy(k2.bytes[0..2], k1.bytes[0..2]); // Collides with `k1` under TwoCap.
    const k3 = key(3);
    const k4 = key(4);
    _ = try apply(&db, &.{
        .{ .key = k1, .value = &.{1} },
        .{ .key = k2, .value = &.{2} },
        .{ .key = k3, .value = &.{3} },
    }, null);
    _ = try apply(&db, &.{.{ .key = k3, .value = null }}, null);
    const keys = [_]Digest{ k2, k4, k1, k3, k2 };
    var out: [keys.len]?Bytes = undefined;
    try db.get_many(&keys, &out);
    defer for (out) |o| codec.free(?Bytes, gpa, o);
    const want = [_]?Bytes{ &.{2}, null, &.{1}, null, &.{2} };
    for (out, want) |got, w| {
        try testing.expectEqual(w == null, got == null);
        if (w) |x| try testing.expectEqualSlices(u8, x, got.?);
    }
    var batch = db.new_batch();
    defer batch.deinit();
    try batch.write(k1, null);
    try batch.write(k4, try gpa.dupe(u8, &.{4}));
    var batch_out: [3]?Bytes = undefined;
    try batch.get_many(&.{ k1, k2, k4 }, &db, &batch_out);
    defer for (batch_out) |o| codec.free(?Bytes, gpa, o);
    try testing.expect(batch_out[0] == null);
    try testing.expectEqualSlices(u8, &.{2}, batch_out[1].?);
    try testing.expectEqualSlices(u8, &.{4}, batch_out[2].?);
}

test "store rebuilds the snapshot for keys that share a translated prefix" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    const k1 = key(11);
    var k2 = key(12);
    @memcpy(k2.bytes[0..2], k1.bytes[0..2]); // Collides with `k1` under TwoCap.
    _ = try apply(&db, &.{.{ .key = k1, .value = &.{ 1, 2, 3, 4, 5 } }}, null);
    _ = try apply(&db, &.{.{ .key = k2, .value = &.{ 6, 7, 8, 9, 10 } }}, null);
    try expect_value(&db, k1, &.{ 1, 2, 3, 4, 5 });
    try expect_value(&db, k2, &.{ 6, 7, 8, 9, 10 });
    try db.commit();
    try db.sync();
    db.deinit();
    // Reopening resolves the shared bucket from the log.
    db = try h.open(null);
    try testing.expectEqual(@as(usize, 2), db.snapshot.get(&k1.bytes).count());
    try expect_value(&db, k1, &.{ 1, 2, 3, 4, 5 });
    try expect_value(&db, k2, &.{ 6, 7, 8, 9, 10 });
    try expect_bitmap_consistent(&db);
    try db.destroy();
}

test "store delete" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    const k = key(11);
    const v: Bytes = &.{ 1, 2, 3, 4, 5 };
    _ = try apply(&db, &.{.{ .key = k, .value = v }}, null);
    try db.commit();
    try expect_value(&db, k, v);
    _ = try apply(&db, &.{.{ .key = k, .value = null }}, null);
    try expect_value(&db, k, null);
    try db.commit();
    db.deinit();
    db = try h.open(null);
    try expect_value(&db, k, null);
    _ = try apply(&db, &.{.{ .key = k, .value = v }}, null);
    try expect_value(&db, k, v);
    try db.commit();
    db.deinit();
    db = try h.open(null);
    try expect_value(&db, k, v);
    // Deleting an absent key appends only the walk's move and the commit.
    const start = db.bounds().end;
    try testing.expectEqual(@as(u64, 9), start);
    const end = try apply(&db, &.{.{ .key = key(12), .value = null }}, null);
    try testing.expectEqual(@as(u64, 11), end);
    try db.commit();
    try expect_value(&db, key(12), null);
    try expect_value(&db, k, v);
    try expect_bitmap_consistent(&db);
    try db.destroy();
}

test "store pruning example" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    defer db.deinit();
    const a = key(21);
    const b = key(22);
    _ = try apply(&db, &.{.{ .key = a, .value = &.{1} }}, null);
    _ = try apply(&db, &.{.{ .key = b, .value = &.{} }}, null);
    try db.commit();
    try testing.expectEqual(@as(u64, 7), db.bounds().end);
    try testing.expectEqual(@as(u64, 3), db.inactivity_floor());
    try expect_value(&db, a, &.{1});
    _ = try apply(&db, &.{.{ .key = b, .value = &.{1} }}, null);
    _ = try apply(&db, &.{.{ .key = a, .value = &.{ 4, 5, 6 } }}, null);
    try db.commit();
    try testing.expectEqual(@as(u64, 15), db.bounds().end);
    try testing.expectEqual(@as(u64, 12), db.inactivity_floor());
    try expect_value(&db, a, &.{ 4, 5, 6 });
    try expect_value(&db, b, &.{1});
}

/// Commonware's value for key `i` in the recovery test: `i % 255` repeated `i % 13 + 7` times.
fn recovery_value(buffer: []u8, i: u64, bump: u64) Bytes {
    const len: usize = @intCast(i % 13 + 7 + bump);
    @memset(buffer[0..len], @intCast((i + bump) % 255));
    return buffer[0..len];
}

test "store recovery" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    // commonware's 1000 keys, shortened in plain Debug builds.
    const keys: u64 = if (test_support.heavy()) 1000 else 200;
    // A batch dropped before apply leaves nothing behind.
    var dropped = db.new_batch();
    for (0..keys) |i| try dropped.write(key(i), try gpa.dupe(u8, &.{@intCast(i % 255)}));
    dropped.deinit();
    db.deinit();
    db = try h.open(null);
    try testing.expectEqual(@as(u64, 1), db.bounds().end);
    var buffer: [32]u8 = undefined;
    for (0..keys) |i| {
        _ = try apply(&db, &.{.{ .key = key(i), .value = recovery_value(&buffer, i, 0) }}, null);
    }
    try db.commit();
    var i: u64 = 0;
    while (i < keys) : (i += 3) {
        _ = try apply(&db, &.{.{ .key = key(i), .value = recovery_value(&buffer, i, 1) }}, null);
    }
    try db.commit();
    try testing.expectEqual(keys, db.snapshot.items());
    i = 1;
    while (i < keys) : (i += 7) _ = try apply(&db, &.{.{ .key = key(i), .value = null }}, null);
    try db.commit();
    const end = db.bounds().end;
    const floor = db.inactivity_floor();
    try db.sync();
    db.deinit();
    db = try h.open(null);
    try testing.expectEqual(end, db.bounds().end);
    try testing.expectEqual(floor, db.inactivity_floor());
    try db.prune(floor);
    try testing.expectEqual(floor - floor % 7, db.bounds().start);
    // Every seventh key from 1 was deleted: 857 of 1000 remain.
    try testing.expectEqual(keys - (keys + 5) / 7, db.snapshot.items());
    for (0..keys) |n| {
        const bump: u64 = @intFromBool(n % 3 == 0);
        const want: ?Bytes = if (n % 7 == 1) null else recovery_value(&buffer, n, bump);
        try expect_value(&db, key(n), want);
    }
    try expect_bitmap_consistent(&db);
    try db.destroy();
}

test "store bounded initialization selects commits" {
    for (0..4) |cap_case| {
        var h: Harness = undefined;
        try h.init();
        defer h.deinit();
        var db = try h.open(null);
        const a = key(100);
        const b = key(101);
        const c = key(102);
        const first = try apply(&db, &.{
            .{ .key = a, .value = &.{1} },
            .{ .key = b, .value = &.{2} },
        }, &.{10});
        const latest = try apply(&db, &.{
            .{ .key = a, .value = &.{3} },
            .{ .key = b, .value = null },
            .{ .key = c, .value = &.{4} },
        }, &.{20});
        try db.sync();
        db.deinit();
        try testing.expect(first + 1 < latest);
        const cap = switch (cap_case) {
            0 => first,
            1 => first + 1,
            2 => latest,
            else => std.math.maxInt(u64),
        };
        const old = cap_case < 2;
        db = try h.open(cap);
        try testing.expectEqual(if (old) first else latest, db.bounds().end);
        try expect_bitmap_consistent(&db);
        try expect_metadata(&db, &.{if (old) 10 else 20});
        try expect_value(&db, a, &.{if (old) 1 else 3});
        try expect_value(&db, b, if (old) &.{2} else null);
        try expect_value(&db, c, if (old) null else &.{4});
        // The selection is durable, and appends continue from it.
        db.deinit();
        db = try h.open(null);
        try testing.expectEqual(if (old) first else latest, db.bounds().end);
        const appended = try apply(&db, &.{
            .{ .key = a, .value = &.{5} },
            .{ .key = c, .value = &.{6} },
        }, null);
        try db.commit();
        db.deinit();
        db = try h.open(null);
        try testing.expectEqual(appended, db.bounds().end);
        try expect_bitmap_consistent(&db);
        try expect_value(&db, a, &.{5});
        try expect_value(&db, b, if (old) &.{2} else null);
        try expect_value(&db, c, &.{6});
        db.deinit();
    }
}

test "store bounded initialization rejects zero and a pruned floor" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    const keys = 64;
    for ([_]u8{ 1, 2 }) |v| {
        for (0..keys) |i| _ = try apply(&db, &.{.{ .key = key(i), .value = &.{v} }}, null);
    }
    try db.sync();
    try testing.expectError(error.InvalidInitializationBound, h.open(0));
    const target = db.bounds().end;
    const prune_loc = db.inactivity_floor() + keys / 2;
    try testing.expect(prune_loc < target);
    var v: u8 = 2;
    while (db.inactivity_floor() < prune_loc) {
        v += 1;
        try testing.expect(v <= 60);
        for (0..keys) |i| _ = try apply(&db, &.{.{ .key = key(i), .value = &.{v} }}, null);
    }
    try db.prune(prune_loc);
    const span = db.bounds();
    try testing.expect(span.start < target);
    try db.sync();
    db.deinit();
    try testing.expectError(error.HistoricalFloorPruned, h.open(target));
    db = try h.open(null);
    defer db.deinit();
    try testing.expectEqual(span, db.bounds());
    for (0..keys) |i| try expect_value(&db, key(i), &.{v});
}

test "store batch reads its writes and applies them" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    const k = key(31);
    const v: Bytes = &.{ 2, 3, 4, 5 };
    var batch = db.new_batch();
    const missing = try batch.get(&k, &db);
    try testing.expect(missing == null);
    try batch.write(k, try gpa.dupe(u8, v));
    // A later write of a key replaces the earlier one.
    try batch.write(k, try gpa.dupe(u8, &.{9}));
    try batch.write(k, try gpa.dupe(u8, v));
    batch.with_metadata(try gpa.dupe(u8, &.{ 99, 100 }));
    try testing.expectEqual(@as(u64, 1), db.bounds().end); // Not applied yet.
    const got = try batch.get(&k, &db);
    defer codec.free(?Bytes, gpa, got);
    try testing.expectEqualSlices(u8, v, got.?);
    var changeset = try batch.finalize();
    try testing.expectEqual(@as(usize, 1), changeset.entries.len);
    try db.apply_batch(&changeset);
    try testing.expectEqual(@as(u64, 4), db.bounds().end);
    try db.commit();
    db.deinit();
    db = try h.open(null);
    try testing.expectEqual(@as(u64, 4), db.bounds().end);
    try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
    try expect_value(&db, k, v);
    try expect_metadata(&db, &.{ 99, 100 });
    try db.destroy();
}

/// A policy that decides each update with a fixed action and records the locations it saw.
const Script = struct {
    entries: usize,
    skips: u64,
    action: enum { keep, stop, replace, evict },
    visited: [16]u64 = undefined,
    count: usize = 0,

    pub fn evicts(self: *const Script) bool {
        return self.action == .evict;
    }

    pub fn limits(self: *const Script, _: usize) floor_mod.Limits {
        return .{ .entries = self.entries, .skips = self.skips };
    }

    pub fn decide(
        self: *Script,
        comptime K: type,
        comptime V: type,
        entry: floor_mod.Entry(K, V),
    ) floor_mod.Decision(V) {
        self.visited[self.count] = entry.location;
        self.count += 1;
        return switch (self.action) {
            .keep => entry.keep(),
            .stop => entry.stop(),
            .replace => entry.replace(gpa.dupe(u8, &.{0xee}) catch @panic("test allocation")),
            .evict => evict: {
                const decision, const evicted = entry.evict();
                codec.free(V, gpa, evicted); // The policy owns the evicted value.
                break :evict decision;
            },
        };
    }
};

fn apply_with(db: *Db, writes: []const Write, policy: anytype) !u64 {
    var changeset = try Db.Changeset.init(gpa, writes);
    try db.apply_batch_with(&changeset, policy);
    return db.bounds().end;
}

/// The seeded keys' values: key `i` holds the byte `i`.
const seed_values = [4][1]u8{ .{0}, .{1}, .{2}, .{3} };

/// Four keys, in key order at locations 1..5, under a held floor.
fn seed_four(db: *Db) ![4]Digest {
    var keys = [_]Digest{ key(40), key(41), key(42), key(43) };
    std.mem.sort(Digest, &keys, {}, struct {
        fn less(_: void, x: Digest, y: Digest) bool {
            return std.mem.order(u8, &x.bytes, &y.bytes) == .lt;
        }
    }.less);
    var hold: floor_mod.Hold = .{};
    var writes: [4]Write = undefined;
    for (&writes, keys, &seed_values) |*w, k, *v| w.* = .{ .key = k, .value = v };
    try testing.expectEqual(@as(u64, 6), try apply_with(db, &writes, &hold));
    try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
    return keys;
}

test "store hold policy keeps the floor until the store empties" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    defer db.deinit();
    const keys = try seed_four(&db);
    var hold: floor_mod.Hold = .{};
    const created = key(44);
    _ = try apply_with(&db, &.{
        .{ .key = keys[0], .value = &.{200} },
        .{ .key = keys[1], .value = null },
        .{ .key = created, .value = &.{104} },
    }, &hold);
    try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
    try expect_value(&db, keys[0], &.{200});
    try expect_value(&db, keys[1], null);
    try expect_value(&db, keys[2], &.{2});
    try expect_value(&db, created, &.{104});
    try expect_bitmap_consistent(&db);
    // Deleting every key moves the floor to the new commit.
    _ = try apply_with(&db, &.{
        .{ .key = keys[0], .value = null },
        .{ .key = keys[2], .value = null },
        .{ .key = keys[3], .value = null },
        .{ .key = created, .value = null },
    }, &hold);
    try testing.expect(db.is_empty());
    try testing.expectEqual(db.bounds().end - 1, db.inactivity_floor());
    try expect_bitmap_consistent(&db);
}

test "store stop policy leaves the floor at the stopped update" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    defer db.deinit();
    const keys = try seed_four(&db);
    const unlimited = std.math.maxInt(usize);
    var stop: Script = .{ .entries = unlimited, .skips = std.math.maxInt(u64), .action = .stop };
    // Only the commit is appended; the walk passes the initial commit and stops at 1.
    try testing.expectEqual(@as(u64, 7), try apply_with(&db, &.{}, &stop));
    try testing.expectEqualSlices(u64, &.{1}, stop.visited[0..stop.count]);
    try testing.expectEqual(@as(u64, 1), db.inactivity_floor());
    // The next batch decides the stopped update without spending a skip.
    var keep: Script = .{ .entries = 1, .skips = 0, .action = .keep };
    _ = try apply_with(&db, &.{}, &keep);
    try testing.expectEqualSlices(u64, &.{1}, keep.visited[0..keep.count]);
    try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
    for (keys, &seed_values) |k, *v| try expect_value(&db, k, v);
    try expect_bitmap_consistent(&db);
}

test "store replace and evict policies rewrite and delete reached updates" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    const keys = try seed_four(&db);
    var replace: Script = .{ .entries = 2, .skips = std.math.maxInt(u64), .action = .replace };
    _ = try apply_with(&db, &.{}, &replace);
    try testing.expectEqualSlices(u64, &.{ 1, 2 }, replace.visited[0..replace.count]);
    try expect_value(&db, keys[0], &.{0xee});
    try expect_value(&db, keys[1], &.{0xee});
    try expect_value(&db, keys[2], &.{2});
    var evict: Script = .{ .entries = 2, .skips = std.math.maxInt(u64), .action = .evict };
    _ = try apply_with(&db, &.{}, &evict);
    try testing.expectEqualSlices(u64, &.{ 3, 4 }, evict.visited[0..evict.count]);
    try expect_value(&db, keys[2], null);
    try expect_value(&db, keys[3], null);
    try testing.expectEqual(@as(usize, 2), db.active_keys);
    try expect_bitmap_consistent(&db);
    // The decisions replay on reopen.
    try db.commit();
    db.deinit();
    db = try h.open(null);
    try expect_value(&db, keys[0], &.{0xee});
    try expect_value(&db, keys[3], null);
    try expect_bitmap_consistent(&db);
    try db.destroy();
}

/// A seed index and a new value byte, or null to delete.
const Pair = struct { usize, ?u8 };

/// `n` keys in key order, each holding its index as one byte.
fn seed_keys(comptime n: usize) [n]Digest {
    var keys: [n]Digest = undefined;
    for (&keys, 0..) |*k, i| k.* = key(1000 + i);
    std.mem.sort(Digest, &keys, {}, digest_less);
    return keys;
}

fn digest_less(_: void, x: Digest, y: Digest) bool {
    return std.mem.order(u8, &x.bytes, &y.bytes) == .lt;
}

const byte_values = blk: {
    var values: [256][1]u8 = undefined;
    for (&values, 0..) |*v, i| v.* = .{i};
    break :blk values;
};

/// Commonware's `test_store_proportional_entries` case: seeds `n` keys (under a held or
/// proportional floor), writes `writes` (a seed index and a new value byte, or null to delete),
/// and expects the batch's range, floor, and the seed indices its walk moves, in order.
fn check_proportional(
    comptime n: usize,
    held: bool,
    writes: []const Pair,
    range: [2]u64,
    floor: u64,
    moved: []const usize,
) !void {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    defer db.deinit();
    const keys = seed_keys(n);
    var seed: [n]Write = undefined;
    for (&seed, keys, 0..) |*w, k, i| w.* = .{ .key = k, .value = &byte_values[i] };
    if (held) {
        var hold: floor_mod.Hold = .{};
        _ = try apply_with(&db, &seed, &hold);
    } else {
        _ = try apply(&db, &seed, null);
        // The previous commit's entry moves the first update to 21; the commit lies at 22.
        try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
        try testing.expectEqual(@as(u64, 23), db.bounds().end);
    }
    var batch: [n]Write = undefined;
    for (writes, 0..) |w, i| {
        const v: ?Bytes = if (w[1]) |b| &byte_values[b] else null;
        batch[i] = .{ .key = keys[w[0]], .value = v };
    }
    const start = db.bounds().end;
    try testing.expectEqual(range[1], try apply(&db, batch[0..writes.len], null));
    try testing.expectEqual(range[0], start);
    try testing.expectEqual(floor, db.inactivity_floor());
    // The writes in key order, the updates the walk moved with their latest values, the commit.
    var loc = start;
    for (batch[0..writes.len]) |w| {
        var op = try db.log.read(loc);
        defer op.deinit(gpa);
        if (w.value) |v| {
            try testing.expect(op == .update and op.update.key.eql(w.key));
            try testing.expectEqualSlices(u8, v, op.update.value);
        } else {
            try testing.expect(op == .delete and op.delete.eql(w.key));
        }
        loc += 1;
    }
    for (moved) |i| {
        var op = try db.log.read(loc);
        defer op.deinit(gpa);
        try testing.expect(op == .update and op.update.key.eql(keys[i]));
        loc += 1;
    }
    var commit = try db.log.read(loc);
    defer commit.deinit(gpa);
    try testing.expectEqual(@as(?u64, floor), commit.inactivity_floor());
    try testing.expectEqual(range[1], loc + 1);
    try expect_bitmap_consistent(&db);
}

test "store proportional entries" {
    // The deletes lie at 23..28; their 2 * 5 entries and the previous commit's move the updates
    // at 2..13 to 28..39, so the commit at 39 records the floor 13.
    var moved: [11]usize = undefined;
    for (&moved, 1..) |*m, i| m.* = i;
    const first_and_last_four = [_]Pair{
        .{ 0, null }, .{ 16, null }, .{ 17, null }, .{ 18, null }, .{ 19, null },
    };
    try check_proportional(20, false, &first_and_last_four, .{ 23, 40 }, 13, &moved);
    // The 19 deletes lie at 23..42; the walk moves the survivor to 42 and passes every delete.
    var all_but_first: [19]Pair = undefined;
    for (&all_but_first, 1..) |*w, i| w.* = .{ i, null };
    try check_proportional(20, false, &all_but_first, .{ 23, 44 }, 42, &.{0});
    // Over six held updates, two updates and a delete make four operations inactive, so with the
    // previous commit the walk moves five updates: three seeds and the two written updates.
    const update_delete_update = [_]Pair{ .{ 0, 200 }, .{ 1, null }, .{ 2, 202 } };
    try check_proportional(6, true, &update_delete_update, .{ 8, 17 }, 11, &.{ 3, 4, 5, 0, 2 });
    // One update supersedes one operation, so with the previous commit the walk moves exactly
    // the two updates at the floor (seeds 1 and 2 at 2 and 3) and stops at 4.
    try check_proportional(20, false, &.{.{ 5, 99 }}, .{ 23, 27 }, 4, &.{ 1, 2 });
}

test "store walk with entries left passes the inactive tail" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    defer db.deinit();
    var hold: floor_mod.Hold = .{};
    _ = try apply_with(&db, &.{.{ .key = key(50), .value = &.{1} }}, &hold);
    // The update at 1 moves to 3; the remaining entry passes the inactive tail to 3.
    var keep: Script = .{ .entries = 2, .skips = std.math.maxInt(u64), .action = .keep };
    try testing.expectEqual(@as(u64, 5), try apply_with(&db, &.{}, &keep));
    try testing.expectEqualSlices(u64, &.{1}, keep.visited[0..keep.count]);
    try testing.expectEqual(@as(u64, 3), db.inactivity_floor());
    try expect_value(&db, key(50), &.{1});
    try expect_bitmap_consistent(&db);
}

/// Each key's latest update location (commonware's `live` map in `any::test::churn`).
const Live = std.AutoArrayHashMapUnmanaged(Digest, u64);

/// Commonware's `test_store_floor_bound` driver: every batch goes through `apply_bounded`,
/// which replays the batch's operations into `live` and checks the floor bound.
const Churn = struct {
    db: *Db,
    live: Live = .empty,
    arena: std.heap.ArenaAllocator = .init(gpa),
    writes: std.ArrayList(Write) = .empty,

    fn deinit(self: *Churn) void {
        self.live.deinit(gpa);
        self.writes.deinit(gpa);
        self.arena.deinit();
    }

    /// Commonware's `i.to_be_bytes().to_vec()`, alive until the batch applies.
    fn value(self: *Churn, i: u64) !Bytes {
        const bytes = try self.arena.allocator().alloc(u8, 8);
        std.mem.writeInt(u64, bytes[0..8], i, .big);
        return bytes;
    }

    fn put(self: *Churn, k: Digest, v: ?u64) !void {
        try self.writes.append(gpa, .{ .key = k, .value = if (v) |i| try self.value(i) else null });
    }

    /// The live keys, oldest update first (commonware's `age`).
    fn age(self: *const Churn) ![]Digest {
        const Ctx = struct {
            locs: []const u64,
            pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                return ctx.locs[a] < ctx.locs[b];
            }
        };
        const order = try gpa.alloc(usize, self.live.count());
        defer gpa.free(order);
        for (order, 0..) |*o, i| o.* = i;
        std.mem.sort(usize, order, Ctx{ .locs = self.live.values() }, Ctx.lessThan);
        const keys = try gpa.alloc(Digest, order.len);
        for (keys, order) |*k, o| k.* = self.live.keys()[o];
        return keys;
    }

    /// The live keys in key order.
    fn sorted(self: *const Churn) ![]Digest {
        const keys = try gpa.dupe(Digest, self.live.keys());
        std.mem.sort(Digest, keys, {}, digest_less);
        return keys;
    }

    /// Deletes the `n` newest (or, with `oldest`, oldest) live keys in one batch.
    fn delete_aged(self: *Churn, n: usize, oldest: bool) !void {
        const keys = try self.age();
        defer gpa.free(keys);
        std.debug.assert(n <= keys.len);
        for (0..n) |i| try self.put(keys[if (oldest) i else keys.len - 1 - i], null);
        try self.apply_bounded();
    }

    /// Commonware's `bounded`: applies the pending writes as one proportional batch, replays
    /// its operations into `live` (each update moves at most once; a written key may appear
    /// twice), and checks the keys and `assert_bound`.
    fn apply_bounded(self: *Churn) !void {
        defer {
            self.writes.clearRetainingCapacity();
            _ = self.arena.reset(.retain_capacity);
        }
        var expected = try self.keys_after();
        defer expected.deinit(gpa);
        const start = self.db.bounds().end;
        var changeset = try Db.Changeset.init(gpa, self.writes.items);
        try self.db.apply_batch(&changeset);
        const end = self.db.bounds().end;
        var updated: std.AutoHashMapUnmanaged(Digest, usize) = .empty;
        defer updated.deinit(gpa);
        for (start..end) |loc| {
            var op = try self.db.log.read(loc);
            defer op.deinit(gpa);
            switch (op) {
                .update => |u| {
                    const count = try updated.getOrPutValue(gpa, u.key, 0);
                    count.value_ptr.* += 1;
                    const limit = 1 + @as(usize, @intFromBool(self.written(u.key)));
                    try testing.expect(count.value_ptr.* <= limit); // Moved twice.
                    try self.live.put(gpa, u.key, loc);
                },
                .delete => |k| _ = self.live.swapRemove(k),
                .commit => {},
            }
        }
        try testing.expectEqual(expected.count(), self.live.count());
        for (self.live.keys()) |k| try testing.expect(expected.contains(k));
        try testing.expectEqual(self.live.count(), self.db.active_keys);
        try self.expect_bound(end);
    }

    fn written(self: *const Churn, k: Digest) bool {
        for (self.writes.items) |w| if (w.key.eql(k)) return true;
        return false;
    }

    /// Commonware's `keys_after`.
    fn keys_after(self: *const Churn) !std.AutoHashMapUnmanaged(Digest, void) {
        var keys: std.AutoHashMapUnmanaged(Digest, void) = .empty;
        errdefer keys.deinit(gpa);
        for (self.live.keys()) |k| try keys.put(gpa, k, {});
        for (self.writes.items) |w| {
            if (w.value != null) try keys.put(gpa, w.key, {}) else _ = keys.remove(w.key);
        }
        return keys;
    }

    /// Commonware's `assert_bound`: every live update lies in `[floor, tip - 1)` and the gap
    /// from the floor to the tip is at most `3 * live + 1`.
    fn expect_bound(self: *const Churn, tip: u64) !void {
        const floor = self.db.inactivity_floor();
        try testing.expect(floor < tip);
        for (self.live.values()) |loc| try testing.expect(loc >= floor and loc < tip - 1);
        try testing.expect(tip - floor <= 3 * @as(u64, self.live.count()) + 1);
    }
};

/// Commonware's `any::test::churn`.
fn churn(c: *Churn) !void {
    for (0..256) |i| try c.put(key(i), i);
    try c.apply_bounded();
    for (0..64) |round| {
        for (0..4) |i| try c.put(key(i), 1000 + round);
        try c.apply_bounded();
    }
    // Delete a window of eight, then recreate it while deleting the next, 64 times.
    for (0..8) |i| try c.put(key(i), null);
    try c.apply_bounded();
    for (0..64) |round| {
        for (8 * round..8 * round + 8) |i| try c.put(key(i % 256), 2000 + round);
        for (8 * round + 8..8 * round + 16) |i| try c.put(key(i % 256), null);
        try c.apply_bounded();
    }
    while (c.live.count() > 8) try c.delete_aged(8, false);
    for (0..4) |burst| {
        const first = 1000 + 64 * burst;
        for (first..first + 64) |i| try c.put(key(i), i);
        try c.apply_bounded();
        for (0..8) |_| try c.delete_aged(8, false);
    }
    for (2000..2512) |i| try c.put(key(i), i);
    try c.apply_bounded();
    for (0..4) |round| {
        const keys = try c.sorted();
        defer gpa.free(keys);
        for (keys[0..64]) |k| try c.put(k, null);
        for (keys[64..192]) |k| try c.put(k, round);
        const first = 3000 + 32 * round;
        for (first..first + 32) |i| try c.put(key(i), i);
        try c.apply_bounded();
    }
}

/// Commonware's `any::test::randomized_churn`, drawing from `TestRng(seed)` (commonware draws
/// from the deterministic runtime's rng, so the batches differ; the checks are the same).
fn randomized_churn(c: *Churn, seed: u64) !void {
    var rng: utils.TestRng = .init(seed);
    for (0..20) |i| try c.put(key(i), i);
    try c.apply_bounded();
    try c.delete_aged(19, false);
    try testing.expectEqual(@as(usize, 1), c.live.count());
    try c.delete_aged(1, false);
    try c.apply_bounded();
    for (0..19) |i| try c.put(key(i), i);
    try c.apply_bounded();
    while (c.live.count() > 1) try c.delete_aged(@min(3, c.live.count() - 1), false);
    try c.delete_aged(1, false);
    for (0..2) |epoch| try randomized_epoch(c, &rng, epoch);
}

fn randomized_epoch(c: *Churn, rng: *utils.TestRng, epoch: u64) !void {
    const urng = utils.rng;
    for (0..96) |i| try c.put(key(i), epoch * 1000 + i);
    try c.apply_bounded();
    const hot = try c.sorted();
    defer gpa.free(hot);
    for (0..32) |round| {
        const count = urng.range_at_most(rng, u64, 0, 4);
        for (0..count) |i| {
            const k = hot[urng.range_less_than(rng, usize, 0, 8)];
            try c.put(k, epoch * 1000 + round * 8 + i);
        }
        try c.apply_bounded();
    }
    while (c.live.count() > 1) {
        const n = urng.range_at_most(rng, usize, 1, @min(8, c.live.count() - 1));
        try c.delete_aged(n, epoch == 1);
    }
    for (0..48) |round| {
        const count = urng.range_at_most(rng, usize, 0, 12);
        for (0..count) |_| {
            const k = key(urng.range_less_than(rng, u64, 0, 160));
            try c.put(k, if (urng.bernoulli(rng, 0.55)) rng.next_u64() else null);
        }
        try c.apply_bounded();
        if (round % 8 == 0) try c.apply_bounded();
    }
    if (c.live.count() == 0) {
        try c.put(key(0), epoch);
        try c.apply_bounded();
    }
    try c.delete_aged(c.live.count() - 1, false); // All but the oldest.
    try testing.expectEqual(@as(usize, 1), c.live.count());
    try c.apply_bounded();
    try c.delete_aged(1, false);
    for (0..3) |_| {
        try c.apply_bounded();
        try testing.expectEqual(@as(usize, 0), c.live.count());
    }
}

test "store floor bound under churn and randomized churn" {
    for ([_]?u64{ null, 0, 1, 7, 0x5133 }) |seed| {
        // Plain Debug builds run the scripted churn and one seed; -Dslow-tests and
        // release builds run every seed.
        if (!test_support.heavy() and seed != null and seed != 0x5133) continue;
        var h: Harness = undefined;
        try h.init();
        defer h.deinit();
        var db = try h.open(null);
        var c: Churn = .{ .db = &db };
        defer c.deinit();
        if (seed) |s| try randomized_churn(&c, s) else try churn(&c);
        try expect_bitmap_consistent(&db);
        try db.destroy();
    }
}

/// `count` keys in one TwoCap bucket: `a5 5a` then zeros, with `i` in the last eight bytes.
fn bucket_key(i: u64) Digest {
    var d: Digest = .{ .bytes = @splat(0) };
    d.bytes[0] = 0xa5;
    d.bytes[1] = 0x5a;
    std.mem.writeInt(u64, d.bytes[24..32], i, .big);
    return d;
}

const CollisionCase = struct {
    count: u64,
    positions: []const usize,
    /// Commonware's bucket reads, which resolve the batch's keys in rounds.
    rounds_reads: u64,
    walk_reads: u64,
    floor: u64,
    value_len: usize,
};

fn collision_case(
    count: u64,
    positions: []const usize,
    rounds_reads: u64,
    walk_reads: u64,
    floor: u64,
    value_len: usize,
) CollisionCase {
    return .{
        .count = count,
        .positions = positions,
        .rounds_reads = rounds_reads,
        .walk_reads = walk_reads,
        .floor = floor,
        .value_len = value_len,
    };
}

/// db.rs `test_store_collision_reads`. Commonware resolves a batch's keys in rounds, reading
/// one bucket location per unresolved key each round; zigware resolves each key alone
/// (db.zig), reading the bucket up to the key's position. The values, floors, and walk reads
/// match; the bucket reads are commonware's when each key resolves in its own round.
fn check_collision_reads(case: CollisionCase) !void {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    var buffers: [64][4096]u8 = undefined;
    const writes = try gpa.alloc(Write, case.count);
    defer gpa.free(writes);
    for (writes, 0..) |*w, i| {
        @memset(buffers[i][0..case.value_len], @intCast(i));
        w.* = .{ .key = bucket_key(i), .value = buffers[i][0..case.value_len] };
    }
    _ = try apply(&db, writes, null);
    // The previous commit's entry moves the first key to `count + 1`, so it leads the bucket.
    var bucket = db.snapshot.get(&bucket_key(0).bytes);
    try testing.expectEqual(case.count + 1, bucket.next().?.*);
    for (2..case.count + 1) |loc| try testing.expectEqual(@as(u64, loc), bucket.next().?.*);
    try testing.expectEqual(@as(u64, 2), db.inactivity_floor());

    try testing.expectEqual(@as(u64, case.positions.len) + 1, case.walk_reads);
    var own_reads: u64 = 0;
    for (case.positions) |p| own_reads += p + 1;
    if (case.positions.len == 1) try testing.expectEqual(case.rounds_reads, own_reads);
    const before = db.log.metrics.items_read.metric().get();
    var rewrite: [8]Write = undefined;
    const ff: [4096]u8 = @splat(0xff);
    for (case.positions, 0..) |p, i| {
        rewrite[i] = .{ .key = bucket_key(p), .value = ff[0..case.value_len] };
    }
    _ = try apply(&db, rewrite[0..case.positions.len], null);
    const reads = db.log.metrics.items_read.metric().get() - before;
    try testing.expectEqual(own_reads + case.walk_reads, reads);
    try testing.expectEqual(case.floor, db.inactivity_floor());
    try testing.expectEqual(@as(usize, @intCast(case.count)), db.active_keys);
    for (0..case.count) |i| {
        const rewritten = std.mem.indexOfScalar(usize, case.positions, i) != null;
        const want = if (rewritten) ff[0..case.value_len] else writes[i].value;
        try expect_value(&db, bucket_key(i), want);
    }
    try expect_bitmap_consistent(&db);
    try db.commit();
    db.deinit();
    db = try h.open(null);
    try expect_value(&db, bucket_key(case.positions[0]), ff[0..case.value_len]);
    try db.destroy();
}

test "store collision reads resolve each key within its bucket" {
    // (count, positions, bucket reads, walk reads, floor, value length), as commonware's cases.
    const cases = [_]CollisionCase{
        collision_case(8, &.{0}, 1, 2, 4, 4096),
        collision_case(64, &.{0}, 1, 2, 4, 4096),
        collision_case(8, &.{5}, 6, 2, 4, 1),
        collision_case(8, &.{ 1, 2, 3 }, 4, 4, 9, 1),
        collision_case(8, &.{ 5, 6, 7 }, 8, 4, 6, 1),
    };
    for (cases) |case| try check_collision_reads(case);
}

/// Even keys share the translated prefix `a5 5a`, odd keys lead with `i` as a big-endian u16,
/// and bytes 24.. hold `i` big-endian.
fn cached_key(i: u64) Digest {
    var bytes: [32]u8 = @splat(0);
    if (i % 2 == 0) {
        bytes[0..2].* = .{ 0xa5, 0x5a };
    } else {
        std.mem.writeInt(u16, bytes[0..2], @truncate(i), .big);
    }
    std.mem.writeInt(u64, bytes[24..32], i, .big);
    return .{ .bytes = bytes };
}

fn expect_cached_reads(db: *Db, ids: []const u8) !void {
    var keys: [8]Digest = undefined;
    var out: [8]?Bytes = undefined;
    for (ids, keys[0..ids.len]) |i, *k| k.* = cached_key(i);
    try db.get_many(keys[0..ids.len], out[0..ids.len]);
    defer for (out[0..ids.len]) |o| codec.free(?Bytes, gpa, o);
    for (ids, out[0..ids.len]) |i, got| {
        try testing.expectEqual(i >= 32, got == null);
        const want: [64]u8 = @splat(i);
        if (i < 32) try testing.expectEqualSlices(u8, &want, got.?);
    }
}

// db.rs `test_store_get_many_cached_and_uncached`: half the keys share a translated key, the
// values outgrow the page cache, and a reopened store (with a fresh page cache, as commonware's
// `test_config`) serves reads both from the cache and from storage.
test "store get_many reads cached and uncached positions" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var values: [32][64]u8 = undefined;
    var writes: [32]Write = undefined;
    for (&writes, &values, 0..) |*w, *v, i| {
        v.* = @splat(@intCast(i));
        w.* = .{ .key = cached_key(i), .value = v };
    }
    {
        var seeded = try h.open(null);
        defer seeded.deinit();
        _ = try apply(&seeded, &writes, null);
        try seeded.sync();
    }
    var cache_ref: CacheRef = try .init(gpa, 77, 9);
    defer cache_ref.deinit();
    var db = try open_on(h.storage.interface(), &cache_ref, null);
    defer db.deinit();
    const ids = [_]u8{ 3, 40, 8, 3, 17, 8, 30, 1 };
    const metrics = &db.log.metrics;
    const hits_before = metrics.cache_hits.metric().get();
    const reads_before = metrics.items_read.metric().get();
    try expect_cached_reads(&db, &ids);
    try expect_cached_reads(&db, &ids);
    const hits = metrics.cache_hits.metric().get() - hits_before;
    const reads = metrics.items_read.metric().get() - reads_before;
    try testing.expect(hits > 0 and hits < reads);
    // Reading one key leaves its pages in the cache, so reading it again never reaches the
    // log's batched read. zigware reads key by key (never through `read_many`), so this also
    // checks that the cache served every read.
    try expect_cached_reads(&db, ids[0..1]);
    const calls_before = metrics.read_many_calls.metric().get();
    const hits_one = metrics.cache_hits.metric().get();
    const reads_one = metrics.items_read.metric().get();
    try expect_cached_reads(&db, ids[0..1]);
    try testing.expectEqual(calls_before, metrics.read_many_calls.metric().get());
    const reads_again = metrics.items_read.metric().get() - reads_one;
    try testing.expect(reads_again > 0);
    try testing.expectEqual(reads_again, metrics.cache_hits.metric().get() - hits_one);
}

// db.rs `test_store_get_many_moves_values`: commonware moves each decoded value to its last
// matching slot and clones it for earlier duplicates. zigware's `get_many` returns an owned
// value per slot, so each duplicate holds its own allocation.
test "store get_many returns an owned value for every duplicate slot" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    defer db.deinit();
    const other: Digest = .{ .bytes = @splat(0xbb) };
    var seed: [4]Write = undefined;
    const tags = [_][1]u8{ .{0}, .{1}, .{2}, .{3} };
    for (seed[0..3], 0..) |*w, i| w.* = .{ .key = bucket_key(i), .value = &tags[i] };
    seed[3] = .{ .key = other, .value = &tags[3] };
    var hold: floor_mod.Hold = .{};
    _ = try apply_with(&db, &seed, &hold);
    const keys = [_]Digest{
        bucket_key(1), bucket_key(3), other, bucket_key(0), bucket_key(1), bucket_key(1),
    };
    var out: [keys.len]?Bytes = undefined;
    try db.get_many(&keys, &out);
    defer for (out) |o| codec.free(?Bytes, gpa, o);
    const want = [_]?u8{ 1, null, 3, 0, 1, 1 };
    for (out, want) |got, w| {
        try testing.expectEqual(w == null, got == null);
        if (w) |tag| try testing.expectEqualSlices(u8, &.{tag}, got.?);
    }
    try testing.expect(out[0].?.ptr != out[4].?.ptr and out[4].?.ptr != out[5].?.ptr);
}

/// Commonware's `vec![(i % 255) as u8; (i % 13) + 7 + bump]`.
fn sized_value(buffer: *[32]u8, i: u64, bump: u64) Bytes {
    const len: usize = @intCast(i % 13 + 7 + bump);
    @memset(buffer[0..len], @intCast((i + bump) % 255));
    return buffer[0..len];
}

test "store reopens at a floor pruned before any further commit" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    var buffer: [32]u8 = undefined;
    // commonware's 1000 keys, shortened in plain Debug builds.
    const keys: u64 = if (test_support.heavy()) 1000 else 200;
    for (0..keys) |i| {
        _ = try apply(&db, &.{.{ .key = key(i), .value = sized_value(&buffer, i, 0) }}, null);
    }
    try db.commit();
    const durable_floor = db.inactivity_floor();
    // Apply, without committing, writes that advance the floor past the durable one.
    for (0..keys) |i| {
        _ = try apply(&db, &.{.{ .key = key(i), .value = sized_value(&buffer, i, 1) }}, null);
    }
    const unsynced_floor = db.inactivity_floor();
    try testing.expect(unsynced_floor > durable_floor);
    // Prune commits the buffered operations first, so the replay reproduces the floor.
    try db.prune(unsynced_floor);
    const size = db.bounds().end;
    db.deinit();
    db = try h.open(null);
    try testing.expectEqual(size, db.bounds().end);
    try testing.expectEqual(unsynced_floor, db.inactivity_floor());
    try db.destroy();
}

test "store recovers a commit made after a sync without a second sync" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    _ = try apply(&db, &.{.{ .key = key(0), .value = &.{ 0, 1, 2 } }}, null);
    try db.commit();
    try db.sync();
    _ = try apply(&db, &.{.{ .key = key(1), .value = &.{ 3, 4, 5, 6 } }}, null);
    try db.commit();
    const end = db.bounds().end;
    const floor = db.inactivity_floor();
    db.deinit();
    db = try h.open(null);
    try testing.expectEqual(end, db.bounds().end);
    try testing.expectEqual(floor, db.inactivity_floor());
    try expect_value(&db, key(0), &.{ 0, 1, 2 });
    try expect_value(&db, key(1), &.{ 3, 4, 5, 6 });
    try db.destroy();
}

// db.rs `test_store_recovery_warns_when_discarding_uncommitted_suffix`, without the trace.
test "store recovery discards an update persisted without its commit" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    const k = cryptography.Blake3.hash(&.{"uncommitted"});
    // A crash during apply_batch can persist an update before its trailing commit.
    _ = try db.log.append(.{ .update = .{ .key = k, .value = &.{7} } });
    try db.log.sync();
    db.deinit();
    db = try h.open(null);
    defer db.deinit();
    try testing.expectEqual(@as(u64, 1), db.bounds().end);
    try expect_value(&db, k, null);
}

// db.rs `test_store_start_sync_recovery`. the completion is awaited before
// the reopen.
test "store state persisted by start_sync is recovered" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    const ones: [8]u8 = @splat(1);
    _ = try apply(&db, &.{.{ .key = key(0), .value = &ones }}, null);
    try (try db.start_sync()).wait_release();
    const size = db.bounds().end;
    db.deinit();
    db = try h.open(null);
    try testing.expectEqual(size, db.bounds().end);
    try expect_value(&db, key(0), &ones);
    try db.destroy();
}

/// db.rs `BitmapPolicy`: three entries, unlimited skips, and one action per round, applied to
/// the value model.
const BitmapPolicy = struct {
    action: usize,
    expected: *Model,
    decisions: *[4]usize,

    pub fn evicts(_: *const BitmapPolicy) bool {
        return true;
    }

    pub fn limits(_: *const BitmapPolicy, _: usize) floor_mod.Limits {
        return .{ .entries = 3, .skips = std.math.maxInt(u64) };
    }

    pub fn decide(
        self: *BitmapPolicy,
        comptime K: type,
        comptime V: type,
        entry: floor_mod.Entry(K, V),
    ) floor_mod.Decision(V) {
        self.decisions[self.action] += 1;
        switch (self.action) {
            0 => return entry.keep(),
            1 => {
                self.expected.put(entry.key.*, &.{0xff});
                return entry.replace(gpa.dupe(u8, &.{0xff}) catch @panic("test allocation"));
            },
            2 => {
                self.expected.remove(entry.key.*);
                const decision, const evicted = entry.evict();
                codec.free(V, gpa, evicted);
                return decision;
            },
            else => return entry.stop(),
        }
    }
};

/// Each key's expected value, over at most 24 keys.
const Model = struct {
    keys: [24]Digest = undefined,
    values: [24][8]u8 = undefined,
    lens: [24]usize = undefined,
    count: usize = 0,

    fn find(self: *const Model, k: Digest) ?usize {
        for (self.keys[0..self.count], 0..) |key_i, i| if (key_i.eql(k)) return i;
        return null;
    }

    fn get(self: *const Model, k: Digest) ?Bytes {
        const i = self.find(k) orelse return null;
        return self.values[i][0..self.lens[i]];
    }

    fn put(self: *Model, k: Digest, v: Bytes) void {
        const i = self.find(k) orelse i: {
            self.keys[self.count] = k;
            self.count += 1;
            break :i self.count - 1;
        };
        @memcpy(self.values[i][0..v.len], v);
        self.lens[i] = v.len;
    }

    fn remove(self: *Model, k: Digest) void {
        const i = self.find(k) orelse return;
        self.count -= 1;
        self.keys[i] = self.keys[self.count];
        self.values[i] = self.values[self.count];
        self.lens[i] = self.lens[self.count];
    }
};

fn expect_model(db: *Db, keys: []const Digest, expected: *const Model) !void {
    try expect_bitmap_consistent(db);
    try testing.expectEqual(expected.count, db.active_keys);
    for (keys) |k| try expect_value(db, k, expected.get(k));
}

/// One round of `test_store_bitmap_tracks_activity`: random writes, then an empty batch whose
/// policy takes the round's action.
fn bitmap_round(
    db: *Db,
    rng: *utils.TestRng,
    keys: []const Digest,
    model: *Model,
    round: u64,
    decisions: *[4]usize,
) !void {
    const urng = utils.rng;
    var writes: [12]Write = undefined;
    var round_value: [8]u8 = undefined;
    std.mem.writeInt(u64, &round_value, round, .big);
    const count = urng.range_less_than(rng, usize, 0, 12);
    for (writes[0..count]) |*w| {
        const k = keys[urng.range_less_than(rng, usize, 0, keys.len)];
        if (urng.bernoulli(rng, 0.3)) {
            w.* = .{ .key = k, .value = null };
            model.remove(k);
        } else {
            w.* = .{ .key = k, .value = &round_value };
            model.put(k, &round_value);
        }
    }
    _ = try apply(db, writes[0..count], null);
    try expect_model(db, keys, model);
    var policy: BitmapPolicy = .{
        .action = @intCast(round % 4),
        .expected = model,
        .decisions = decisions,
    };
    _ = try apply_with(db, &.{}, &policy);
    try expect_model(db, keys, model);
}

// db.rs `test_store_bitmap_tracks_activity` (its rng is `test_rng()`; batches differ from
// commonware's, the checks are the same).
test "store bitmap tracks activity through every policy action, prune, and reopen" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open(null);
    var rng = utils.test_rng();
    // 24 keys sharing three translated prefixes, so batches collide often.
    var keys: [24]Digest = undefined;
    for (&keys, 0..) |*k, i| {
        k.* = cryptography.Blake3.hash(&.{&[_]u8{@intCast(i)}});
        k.bytes[0] = 0;
        k.bytes[1] = @intCast(i % 3);
    }
    var model: Model = .{};
    var decisions: [4]usize = @splat(0);
    for (0..60) |round| {
        try bitmap_round(&db, &rng, &keys, &model, round, &decisions);
        if (round % 10 == 9) {
            try db.prune(db.inactivity_floor());
            try expect_model(&db, &keys, &model);
        }
        if (round % 20 == 19) {
            try db.commit();
            try db.sync();
            db.deinit();
            db = try h.open(null);
            try expect_model(&db, &keys, &model);
        }
    }
    for (decisions) |count| try testing.expect(count > 0);
    try db.destroy();
}

/// A store keyed by variable-length byte strings (commonware's `VecKeyStore`).
const VecKeyDb = store.Db(Bytes, value.Variable(Bytes), translator.TwoCap);

fn open_vec_keys(self: *Harness) !VecKeyDb {
    const Cfg = @FieldType(VecKeyDb.Journal.Cfg, "codec_config");
    var codec_config = test_support.codec_config(Cfg);
    codec_config[0].range = .inclusive(0, 64); // Keys of up to 64 bytes.
    const cfg: VecKeyDb.Cfg = .{
        .log = .{
            .partition = "journal",
            .items_per_section = 7,
            .codec_config = codec_config,
            .cache_ref = &self.cache_ref,
            .write_buffer = 64 * 1024,
            .replay_buffer = 64 * 1024,
        },
        .translator = .{},
        .init_cache = 1024,
    };
    return VecKeyDb.init(gpa, self.storage.interface(), cfg, null);
}

fn expect_vec_value(db: *VecKeyDb, k: Bytes, want: ?Bytes) !void {
    const got = try db.get(&k);
    defer codec.free(?Bytes, gpa, got);
    try testing.expectEqual(want == null, got == null);
    if (want) |w| try testing.expectEqualSlices(u8, w, got.?);
}

fn write_vec(batch: *VecKeyDb.Batch, k: Bytes, v: ?Bytes) !void {
    const owned: ?Bytes = if (v) |bytes| try gpa.dupe(u8, bytes) else null;
    errdefer codec.free(?Bytes, gpa, owned);
    try batch.write(k, owned);
}

fn apply_vec(db: *VecKeyDb, batch: *VecKeyDb.Batch) !void {
    var changeset = try batch.finalize();
    try db.apply_batch(&changeset);
}

// Commonware's test_store_variable_length_keys: keys of different lengths that share a
// translated prefix keep their own values, also after reopening.
test "store variable-length keys share a translated prefix and survive reopening" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const short: Bytes = "key";
    const long: Bytes = "key-extended";
    {
        var db = try open_vec_keys(&harness);
        defer db.deinit();
        var batch = db.new_batch();
        try write_vec(&batch, short, &.{1});
        try write_vec(&batch, long, &.{2});
        try apply_vec(&db, &batch);
        try db.commit();
        try expect_vec_value(&db, short, &.{1});
        try expect_vec_value(&db, long, &.{2});
    }
    var db = try open_vec_keys(&harness);
    try expect_vec_value(&db, short, &.{1});
    try expect_vec_value(&db, long, &.{2});
    try db.destroy();
}

// The store owns copies of variable-length keys through overwrites, deletes, and the floor
// walk's rewrites (the testing allocator reports any key it leaks or frees twice).
test "store variable-length keys stay owned through overwrite, delete, and floor raising" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var db = try open_vec_keys(&harness);
    defer db.deinit();
    var names: [16][8]u8 = undefined;
    for (&names, 0..) |*name, i| _ = std.fmt.bufPrint(name, "k{d:0>7}", .{i}) catch unreachable;
    var round: u8 = 0;
    while (round < 8) : (round += 1) {
        var batch = db.new_batch();
        errdefer batch.deinit();
        for (&names, 0..) |*name, i| {
            const k: Bytes = name[0 .. 1 + i % 8];
            const deleted = (i + round) % 5 == 0;
            try write_vec(&batch, k, if (deleted) null else &.{ round, @intCast(i) });
        }
        try apply_vec(&db, &batch);
    }
    try db.commit();
    try testing.expect(db.inactivity_floor() > 0);
    for (&names, 0..) |*name, i| {
        const k: Bytes = name[0 .. 1 + i % 8];
        // Within a batch the last write of a key wins.
        var last = i;
        for (i + 1..names.len) |j| {
            if (std.mem.eql(u8, k, names[j][0 .. 1 + j % 8])) last = j;
        }
        const want: ?Bytes = if ((last + 7) % 5 == 0) null else &.{ 7, @intCast(last) };
        try expect_vec_value(&db, k, want);
    }
}
