//! Tests for qmdb/snapshot.rs: a serial build over seeded logs of keyed operations, checked
//! against a model of each key's latest update, with and without the key cache, under a
//! colliding translator (`OneCap`) and a collision-free one (`EightCap`).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const merkle = @import("../merkle/mod.zig");
const translator = @import("../translator.zig");
const index = @import("../index/mod.zig");
const contiguous = @import("../journal/contiguous/mod.zig");
const value = @import("value.zig");
const any = @import("any/operation.zig");
const snapshot = @import("snapshot.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");

const U64 = utils.sequence.U64;
const Op = any.Unordered(merkle.mmr.Family, U64, value.Fixed(U64));

/// An in-memory log that counts its reads.
const Log = struct {
    ops: []const Op,
    start: u64 = 0,
    reads: u64 = 0,

    pub fn get_bounds(self: *const Log) contiguous.Bounds {
        return .{ .start = self.start, .end = self.ops.len };
    }

    pub fn read(self: *Log, position: u64) !Op {
        if (position < self.start) return error.ItemPruned;
        if (position >= self.ops.len) return error.ItemOutOfRange;
        self.reads += 1;
        return self.ops[position];
    }
};

/// Keys spread over three `OneCap` buckets (their first byte), so most keys collide.
fn key_of(k: u64) U64 {
    return U64.init((k % 3) << 56 | k);
}

/// A random log of updates, deletes, and commits over `keys` keys, ending with a commit.
fn random_log(gpa: Allocator, random: std.Random, len: usize, keys: u64) ![]Op {
    const ops = try gpa.alloc(Op, len);
    for (ops[0 .. len - 1]) |*op| {
        const k = key_of(random.uintLessThan(u64, keys));
        op.* = switch (random.uintLessThan(u8, 10)) {
            0...5 => .{ .update = .{ .key = k, .value = U64.init(random.int(u64)) } },
            6...7 => .{ .delete = k },
            else => .{ .commit = .{ .metadata = null, .floor = 0 } },
        };
    }
    ops[len - 1] = .{ .commit = .{ .metadata = null, .floor = 0 } };
    return ops;
}

/// The expected activity of each location from `floor`, and the number of active keys.
fn model(gpa: Allocator, ops: []const Op, floor: u64) !struct { []bool, usize } {
    const expected = try gpa.alloc(bool, ops.len - floor);
    var latest: std.AutoHashMapUnmanaged(u64, u64) = .empty;
    defer latest.deinit(gpa);
    for (ops[floor..], floor..) |op, location| {
        const slot = location - floor;
        switch (op) {
            .update => |u| {
                expected[slot] = true;
                const entry = try latest.getOrPut(gpa, u.key.get());
                if (entry.found_existing) expected[entry.value_ptr.* - floor] = false;
                entry.value_ptr.* = location;
            },
            .delete => |k| {
                expected[slot] = false;
                if (latest.fetchRemove(k.get())) |old| expected[old.value - floor] = false;
            },
            .commit => expected[slot] = location == ops.len - 1,
        }
    }
    return .{ expected, latest.count() };
}

fn check_build(comptime T: type, ops: []const Op, floor: u64, cache_size: ?usize) !u64 {
    const gpa = testing.allocator;
    var log: Log = .{ .ops = ops };
    var snap = index.unordered.Index(T, u64).init(gpa, .{});
    defer snap.deinit();
    var result = try snapshot.build(Op, gpa, floor, &log, &snap, cache_size);
    defer result.deinit(gpa);
    const expected, const active_keys = try model(gpa, ops, floor);
    defer gpa.free(expected);
    try testing.expectEqual(active_keys, result.active_keys);
    try testing.expectEqual(@as(u64, expected.len), result.activity.len());
    for (expected, 0..) |bit, i| try testing.expectEqual(bit, result.activity.get(i));
    // Every active update is in the snapshot under its key, and nothing else is.
    try testing.expectEqual(@as(u64, active_keys), snap.items());
    for (expected, floor..) |active, location| {
        if (!active or ops[location] != .update) continue;
        const key = ops[location].update.key;
        var values = snap.get(&key.bytes);
        var found = false;
        while (values.next()) |v| found = found or v.* == location;
        try testing.expect(found);
    }
    return log.reads;
}

test "snapshot build matches the model" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(fuzz_bytes.seed(0x736e6170));
    for (0..fuzz_bytes.iterations(24)) |_| {
        const len = prng.random().intRangeAtMost(usize, 1, 300);
        const keys = 1 + prng.random().uintLessThan(u64, 40);
        const ops = try random_log(gpa, prng.random(), len, keys);
        defer gpa.free(ops);
        const floor = prng.random().uintAtMost(u64, len - 1);
        inline for (.{ translator.OneCap, translator.EightCap }) |T| {
            for ([_]?usize{ null, 1, 16, 1024 }) |cache_size| {
                _ = try check_build(T, ops, floor, cache_size);
            }
        }
    }
}

test "snapshot cache saves log reads under collisions" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(7);
    const ops = try random_log(gpa, prng.random(), 2000, 60);
    defer gpa.free(ops);
    const uncached = try check_build(translator.OneCap, ops, 0, null);
    const cached = try check_build(translator.OneCap, ops, 0, 4096);
    // Without a cache every candidate is a log read; with one, the replay's own updates
    // answer most collisions.
    try testing.expect(cached * 4 < uncached);
}

test "snapshot build refuses a pruned floor" {
    const gpa = testing.allocator;
    const ops = [_]Op{.{ .commit = .{ .metadata = null, .floor = 0 } }};
    var log: Log = .{ .ops = &ops, .start = 1 };
    var snap = index.unordered.Index(translator.EightCap, u64).init(gpa, .{});
    defer snap.deinit();
    try testing.expectError(error.ItemPruned, snapshot.build(Op, gpa, 0, &log, &snap, null));
}

test "update and delete keys through colliding cursors" {
    const gpa = testing.allocator;
    const a = key_of(3);
    const b = key_of(6); // Same OneCap bucket as `a`.
    const commit: Op = .{ .commit = .{ .metadata = null, .floor = 0 } };
    const ops = [_]Op{
        .{ .update = .{ .key = a, .value = U64.init(1) } },
        .{ .update = .{ .key = b, .value = U64.init(2) } },
        commit,
        commit,
        commit,
        .{ .update = .{ .key = a, .value = U64.init(3) } },
    };
    const update = snapshot.update_key;
    const delete = snapshot.delete_key;
    var log: Log = .{ .ops = &ops };
    var snap = index.unordered.Index(translator.OneCap, u64).init(gpa, .{});
    defer snap.deinit();
    try testing.expectEqual(@as(?u64, null), try update(Op, gpa, &snap, &log, &a, 0, null));
    try testing.expectEqual(@as(?u64, null), try update(Op, gpa, &snap, &log, &b, 1, null));
    try testing.expectEqual(@as(u64, 2), snap.items());
    try testing.expectEqual(@as(?u64, 0), try update(Op, gpa, &snap, &log, &a, 5, null));
    try testing.expectEqual(@as(?u64, 1), try delete(Op, gpa, &snap, &log, &b, null));
    try testing.expectEqual(@as(?u64, null), try delete(Op, gpa, &snap, &log, &b, null));
    try testing.expectEqual(@as(u64, 1), snap.items());
    var values = snap.get(&a.bytes);
    try testing.expectEqual(@as(u64, 5), values.next().?.*);
    try testing.expect(values.next() == null);
}
