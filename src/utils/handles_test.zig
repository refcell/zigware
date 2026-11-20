//! Tests for `handles.Table` (commonware `utils/src/handles.rs`). commonware's should_panic
//! test for a partition count that is not a power of two is an assertion here.

const std = @import("std");
const handles = @import("handles.zig");
const rng = @import("rng.zig");

const testing = std.testing;
const gpa = testing.allocator;
const Table = handles.Table(usize);

/// Maps each handle to `hashes[handle]`, counting calls.
const Hashes = struct {
    hashes: []const u64,
    calls: ?*usize = null,

    pub fn rehash(context: Hashes, handle: usize) u64 {
        if (context.calls) |calls| calls.* += 1;
        return context.hashes[handle];
    }
};

/// Every handle hashes to `hash`.
const Constant = struct {
    hash: u64,

    pub fn rehash(context: Constant, _: usize) u64 {
        return context.hash;
    }
};

/// For inserts that must not grow the table.
const NoRehash = struct {
    pub fn rehash(_: NoRehash, _: usize) u64 {
        @panic("rehash without growth");
    }
};

/// Records each candidate offered and accepts `accept` (or every candidate).
const Recorder = struct {
    offered: *std.ArrayList(usize),
    accept: ?usize,
    accept_all: bool = false,

    pub fn matches(context: Recorder, handle: usize) bool {
        context.offered.append(gpa, handle) catch @panic("out of memory");
        return context.accept_all or context.accept == handle;
    }
};

const Equal = struct {
    handle: usize,

    pub fn matches(context: Equal, handle: usize) bool {
        return handle == context.handle;
    }
};

/// Spreads `i` across all 64 bits.
fn spread(i: u64) u64 {
    return i *% 0x9E37_79B9_7F4A_7C15;
}

fn metas(table: *const Table) ![]u32 {
    return gpa.dupe(u32, table.metas);
}

/// The candidates of `hash`, in probe order (caller frees).
fn candidates(table: *const Table, hash: u64) ![]usize {
    var result: std.ArrayList(usize) = .empty;
    errdefer result.deinit(gpa);
    var it = table.get(hash);
    while (it.next()) |handle| try result.append(gpa, handle);
    return result.toOwnedSlice(gpa);
}

fn expect_sorted_candidates(table: *const Table, hash: u64, expected: []const usize) !void {
    const actual = try candidates(table, hash);
    defer gpa.free(actual);
    std.mem.sort(usize, actual, {}, std.sort.asc(usize));
    try testing.expectEqualSlices(usize, expected, actual);
}

fn first_candidate(table: *const Table, hash: u64) ?usize {
    var it = table.get(hash);
    return it.next();
}

fn has_candidate(table: *const Table, hash: u64, handle: usize) bool {
    var it = table.get(hash);
    while (it.next()) |candidate| if (candidate == handle) return true;
    return false;
}

/// Slot metadata, Robin Hood order, and `len` agree with each handle's hash.
fn check_invariants(table: *const Table, context: anytype) !void {
    const slots = table.metas.len;
    try testing.expectEqual(slots * 3 / 4, table.capacity());
    try testing.expect(table.len <= table.capacity());
    if (slots == 0) return;
    try testing.expect(std.math.isPowerOfTwo(slots) and slots >= handles.MIN_SLOTS);
    const mask = slots - 1;
    var occupied: usize = 0;
    for (table.metas, table.handles, 0..) |meta, handle, index| {
        if (meta == handles.EMPTY) continue;
        occupied += 1;
        const hash = context.rehash(handle);
        const displacement = (index -% @as(usize, @truncate(hash))) & mask;
        try testing.expect(displacement <= handles.MAX_DISPLACEMENT);
        try testing.expectEqual(handles.slot_meta(hash, @intCast(displacement)), meta);
        // Each entry is at most one slot further from its home than its predecessor.
        const next = table.metas[(index + 1) & mask];
        try testing.expect(next == handles.EMPTY or next >> 8 <= (meta >> 8) + 1);
    }
    try testing.expectEqual(table.len, occupied);
}

test "handles: find_or_insert finds or places" {
    const hashes = [_]u64{ spread(1), spread(1), spread(2) };
    const context: Hashes = .{ .hashes = &hashes };
    var table: Table = .empty;
    defer table.deinit(gpa);
    const Found = Table.Found;
    try testing.expectEqual(
        Found{ .handle = 0, .inserted = true },
        try table.find_or_insert(gpa, hashes[0], {}, 0, context),
    );
    try testing.expectEqual(
        Found{ .handle = 0, .inserted = false },
        try table.find_or_insert(gpa, hashes[0], Equal{ .handle = 0 }, 7, context),
    );
    try testing.expectEqual(
        Found{ .handle = 1, .inserted = true },
        try table.find_or_insert(gpa, hashes[1], Equal{ .handle = 1 }, 1, context),
    );
    const both = try candidates(&table, hashes[0]);
    defer gpa.free(both);
    try testing.expectEqualSlices(usize, &.{ 0, 1 }, both);

    // A walk that accepts every candidate stops at the first one get yields.
    var offered: std.ArrayList(usize) = .empty;
    defer offered.deinit(gpa);
    const recorder: Recorder = .{ .offered = &offered, .accept = null, .accept_all = true };
    try testing.expectEqual(
        Found{ .handle = 0, .inserted = false },
        try table.find_or_insert(gpa, hashes[0], recorder, 7, context),
    );
    try testing.expectEqualSlices(usize, &.{0}, offered.items);

    try testing.expectEqual(
        Found{ .handle = 2, .inserted = true },
        try table.find_or_insert(gpa, hashes[2], Equal{ .handle = 2 }, 2, context),
    );
    try testing.expectEqual(3, table.len);
    try check_invariants(&table, context);
}

test "handles: find_or_insert grows, and prefetch is harmless" {
    var generator = rng.test_rng();
    var hashes: [1000]u64 = undefined;
    for (&hashes) |*hash| hash.* = generator.next_u64();
    const context: Hashes = .{ .hashes = &hashes };
    const unallocated: Table = .empty;
    unallocated.prefetch(hashes[0]);
    var table: Table = .empty;
    defer table.deinit(gpa);
    for (hashes, 0..) |hash, handle| {
        table.prefetch(hash);
        const matcher: Equal = .{ .handle = handle };
        const inserted = try table.find_or_insert(gpa, hash, matcher, handle, context);
        try testing.expectEqual(Table.Found{ .handle = handle, .inserted = true }, inserted);
        const found = try table.find_or_insert(
            gpa,
            hash,
            Equal{ .handle = handle },
            std.math.maxInt(usize),
            context,
        );
        try testing.expectEqual(Table.Found{ .handle = handle, .inserted = false }, found);
    }
    try testing.expectEqual(hashes.len, table.len);
    try check_invariants(&table, context);
    for (hashes, 0..) |hash, handle| try testing.expect(has_candidate(&table, hash, handle));
}

test "handles: find_or_insert grows a full table before walking" {
    // Twelve handles fill a 16-slot table. All share a fingerprint and home slot 15, and
    // doubling the table moves the odd ones to home slot 31.
    var hashes: [13]u64 = undefined;
    for (&hashes, 0..) |*hash, handle| hash.* = 0xAB00_0000_0000_000F | ((handle % 2) << 4);
    const context: Hashes = .{ .hashes = &hashes };
    const cases = [_]struct { accept: usize, want: Table.Found }{
        .{ .accept = 1, .want = .{ .handle = 12, .inserted = true } },
        .{ .accept = 2, .want = .{ .handle = 2, .inserted = false } },
    };
    for (cases) |case| {
        var table: Table = .empty;
        defer table.deinit(gpa);
        for (hashes[0..12], 0..) |hash, handle| try table.insert(gpa, hash, handle, context);
        try testing.expectEqual(table.capacity(), table.len);

        var offered: std.ArrayList(usize) = .empty;
        defer offered.deinit(gpa);
        const recorder: Recorder = .{ .offered = &offered, .accept = case.accept };
        const found = try table.find_or_insert(gpa, hashes[12], recorder, 12, context);
        try testing.expectEqual(case.want, found);
        try testing.expectEqual(24, table.capacity());
        try testing.expect(offered.items.len > 0);
        for (offered.items) |handle| try testing.expectEqual(0, handle % 2);
        try check_invariants(&table, context);
    }
}

test "handles: find_or_insert offers the candidates of get" {
    // The first two hashes share a home slot and fingerprint, the third only the fingerprint,
    // and the fourth only the home slot. Every seeded hash is inserted again under a new
    // handle, along with 50 fresh ones.
    var generator = rng.test_rng();
    const seeded = 204;
    var hashes: [2 * seeded + 50]u64 = undefined;
    hashes[0..4].* = .{
        0xAB00_0000_0000_0005, 0xAB00_0100_0000_0005,
        0xAB00_0000_0000_0006, 0xCD00_0000_0000_0005,
    };
    for (hashes[4..seeded]) |*hash| hash.* = generator.next_u64();
    @memcpy(hashes[seeded .. 2 * seeded], hashes[0..seeded]);
    for (hashes[2 * seeded ..]) |*hash| hash.* = generator.next_u64();
    const context: Hashes = .{ .hashes = &hashes };

    var table: Table = .empty;
    defer table.deinit(gpa);
    for (hashes[0..seeded], 0..) |hash, handle| try table.insert(gpa, hash, handle, context);
    try table.reserve(gpa, hashes.len - seeded, context);

    for (hashes[seeded..], seeded..) |hash, handle| {
        const before = try candidates(&table, hash);
        defer gpa.free(before);
        var offered: std.ArrayList(usize) = .empty;
        defer offered.deinit(gpa);
        const recorder: Recorder = .{ .offered = &offered, .accept = null };
        const found = try table.find_or_insert(gpa, hash, recorder, handle, NoRehash{});
        try testing.expectEqual(Table.Found{ .handle = handle, .inserted = true }, found);
        try testing.expectEqualSlices(usize, before, offered.items);
        const after = try candidates(&table, hash);
        defer gpa.free(after);
        try testing.expectEqualSlices(usize, before, after[0 .. after.len - 1]);
        try testing.expectEqual(handle, after[after.len - 1]);
    }
    try check_invariants(&table, context);
}

test "handles: basic insert, get, and remove" {
    // Handles 0 and 1 share a hash, and handle 4 is never inserted.
    const hashes = [_]u64{ spread(1), spread(1), spread(2), spread(3), spread(4) };
    const context: Hashes = .{ .hashes = &hashes };
    var table: Table = .empty;
    defer table.deinit(gpa);
    try testing.expect(table.is_empty());
    try testing.expectEqual(0, table.metas.len);
    try testing.expectEqual(@as(?usize, null), first_candidate(&table, hashes[0]));
    try testing.expect(!table.remove(hashes[0], 0));

    for (hashes[0..4], 0..) |hash, handle| try table.insert(gpa, hash, handle, context);
    try testing.expectEqual(4, table.len);
    try expect_sorted_candidates(&table, hashes[0], &.{ 0, 1 });
    try expect_sorted_candidates(&table, hashes[2], &.{2});
    try expect_sorted_candidates(&table, hashes[3], &.{3});
    try testing.expectEqual(@as(?usize, null), first_candidate(&table, hashes[4]));

    try testing.expect(table.remove(hashes[0], 0));
    try expect_sorted_candidates(&table, hashes[0], &.{1});
    try testing.expectEqual(3, table.len);

    // Removing absent handles changes nothing.
    const before = try metas(&table);
    defer gpa.free(before);
    try testing.expect(!table.remove(hashes[0], 0));
    try testing.expect(!table.remove(hashes[4], 4));
    const after = try metas(&table);
    defer gpa.free(after);
    try testing.expectEqualSlices(u32, before, after);
    try testing.expectEqual(3, table.len);

    // The same handle may be inserted twice under one hash, and is removed once at a time.
    try table.insert(gpa, hashes[1], 1, context);
    try expect_sorted_candidates(&table, hashes[1], &.{ 1, 1 });
    try testing.expect(table.remove(hashes[1], 1));
    try expect_sorted_candidates(&table, hashes[1], &.{1});
    try check_invariants(&table, context);
}

test "handles: fingerprint false candidates" {
    const keys = [_][]const u8{ "a", "b", "c", "d" };
    const hashes = [_]u64{
        0xAB00_0000_0000_0005, 0xAB00_0100_0000_0005,
        0xAB00_0000_0000_0006, 0xCD00_0000_0000_0005,
    };
    const context: Hashes = .{ .hashes = &hashes };
    var table: Table = .empty;
    defer table.deinit(gpa);
    for (hashes, 0..) |hash, handle| try table.insert(gpa, hash, handle, context);

    try expect_sorted_candidates(&table, hashes[0], &.{ 0, 1 });
    var confirmed: usize = 0;
    var it = table.get(hashes[0]);
    while (it.next()) |handle| {
        if (std.mem.eql(u8, keys[handle], "a")) {
            try testing.expectEqual(0, handle);
            confirmed += 1;
        }
    }
    try testing.expectEqual(1, confirmed);
    try expect_sorted_candidates(&table, hashes[2], &.{2});
    try expect_sorted_candidates(&table, hashes[3], &.{3});
    try check_invariants(&table, context);
}

test "handles: growth rehashes every entry" {
    var generator = rng.test_rng();
    var hashes: [5000]u64 = undefined;
    var calls: usize = 0;
    const context: Hashes = .{ .hashes = &hashes, .calls = &calls };
    var table: Table = .empty;
    defer table.deinit(gpa);
    var growths: usize = 0;
    for (0..hashes.len) |handle| {
        hashes[handle] = generator.next_u64();
        const slots = table.metas.len;
        const len = table.len;
        const before = calls;
        try table.insert(gpa, hashes[handle], handle, context);
        try testing.expectEqual(handle + 1, table.len);
        if (table.metas.len == slots) {
            try testing.expectEqual(before, calls);
            continue;
        }
        // Growth doubles once, rehashing every existing entry exactly once.
        growths += 1;
        try testing.expectEqual(@max(slots * 2, handles.MIN_SLOTS), table.metas.len);
        try testing.expectEqual(slots * 3 / 4, len);
        try testing.expectEqual(len, calls - before);
        try check_invariants(&table, Hashes{ .hashes = hashes[0 .. handle + 1] });
        for (hashes[0 .. handle + 1], 0..) |hash, held| {
            try testing.expect(has_candidate(&table, hash, held));
        }
    }
    try testing.expectEqual(10, growths);
    try testing.expectEqual(8192, table.metas.len);
}

test "handles: shared hash run" {
    const entries = 2000;
    const context: Constant = .{ .hash = spread(1) };
    var table: Table = .empty;
    defer table.deinit(gpa);
    for (0..entries) |handle| try table.insert(gpa, spread(1), handle, context);
    try testing.expectEqual(4096, table.metas.len);
    const all = try candidates(&table, spread(1));
    defer gpa.free(all);
    try testing.expectEqual(entries, all.len);
    try check_invariants(&table, context);

    var handle: usize = 0;
    while (handle < entries) : (handle += 2) try testing.expect(table.remove(spread(1), handle));
    var odd: [entries / 2]usize = undefined;
    for (&odd, 0..) |*value, index| value.* = 2 * index + 1;
    try expect_sorted_candidates(&table, spread(1), &odd);
    try check_invariants(&table, context);
}

const model_handles = 1024;

/// The multimap model: how many times each handle is held, with `hash_of` fixed per handle.
const Model = struct {
    hash_of: [model_handles]u64,
    counts: [model_handles]u32 = @splat(0),
    calls: usize = 0,

    pub fn rehash(model: *Model, handle: usize) u64 {
        model.calls += 1;
        return model.hash_of[handle];
    }

    fn total(model: *const Model) usize {
        var sum: usize = 0;
        for (model.counts) |count| sum += count;
        return sum;
    }

    /// Candidates of `hash` in a table of `slots` slots: every held handle whose hash shares
    /// the home slot and fingerprint, sorted.
    fn expected(model: *const Model, hash: u64, slots: usize) ![]usize {
        const mask: u64 = slots -% 1;
        var result: std.ArrayList(usize) = .empty;
        errdefer result.deinit(gpa);
        for (model.hash_of, model.counts, 0..) |other, count, handle| {
            if (other >> 56 != hash >> 56 or (other ^ hash) & mask != 0) continue;
            try result.appendNTimes(gpa, handle, count);
        }
        return result.toOwnedSlice(gpa);
    }
};

/// Draws one hash pool: paired hashes share their low 24 bits and fingerprints take four
/// values, so false candidates are common.
fn model_pool(generator: *rng.TestRng, pool: []u64) void {
    for (pool, 0..) |*hash, index| {
        const fingerprint = rng.range_less_than(generator, u64, 0, 4) << 56;
        const middle = generator.next_u64() & 0x00FF_FFFF_FF00_0000;
        const low = (if (index % 2 == 1) pool[index - 1] else generator.next_u64()) & 0xFF_FFFF;
        hash.* = fingerprint | middle | low;
    }
}

test "handles: matches a multimap model" {
    const operations = 50_000;
    var generator = rng.TestRng.init(5);
    var pool: [512]u64 = undefined;
    model_pool(&generator, &pool);
    const model = try gpa.create(Model);
    defer gpa.destroy(model);
    model.* = .{ .hash_of = undefined };
    for (&model.hash_of) |*hash| hash.* = pool[rng.range_less_than(&generator, usize, 0, 512)];

    var table: Table = .empty;
    defer table.deinit(gpa);
    var removed: usize = 0;
    var false_candidates: usize = 0;
    var len_max: usize = 0;
    for (0..operations) |operation| {
        // Alternate phases that favor insertion and removal.
        const inserts: u32 = if ((operation / 5000) % 2 == 0) 6 else 3;
        const roll = rng.range_less_than(&generator, u32, 0, 10);
        const slots = table.metas.len;
        const calls = model.calls;
        const hash = if (roll < inserts) hash: {
            const handle = rng.range_less_than(&generator, usize, 0, model_handles);
            try table.insert(gpa, model.hash_of[handle], handle, model);
            model.counts[handle] += 1;
            break :hash model.hash_of[handle];
        } else if (roll < 9) hash: {
            const handle = rng.range_less_than(&generator, usize, 0, model_handles);
            const held = model.counts[handle] > 0;
            try testing.expectEqual(held, table.remove(model.hash_of[handle], handle));
            if (held) {
                model.counts[handle] -= 1;
                removed += 1;
            }
            break :hash model.hash_of[handle];
        } else if (rng.boolean(&generator))
            pool[rng.range_less_than(&generator, usize, 0, pool.len)]
        else
            generator.next_u64();
        if (table.metas.len == slots) try testing.expectEqual(calls, model.calls);
        try testing.expectEqual(model.total(), table.len);
        len_max = @max(len_max, table.len);

        const expected = try model.expected(hash, table.metas.len);
        defer gpa.free(expected);
        const actual = try candidates(&table, hash);
        defer gpa.free(actual);
        std.mem.sort(usize, actual, {}, std.sort.asc(usize));
        try testing.expectEqualSlices(usize, expected, actual);
        for (actual) |handle| false_candidates += @intFromBool(model.hash_of[handle] != hash);
        if (operation % 1000 == 0) try check_invariants(&table, Hashes{ .hashes = &model.hash_of });
    }
    try check_invariants(&table, Hashes{ .hashes = &model.hash_of });
    try testing.expect(removed > 10_000 and false_candidates > 1000 and len_max > 2000);
}

test "handles: init_capacity never rehashes" {
    var none = try Table.init_capacity(gpa, 0);
    defer none.deinit(gpa);
    try testing.expectEqual(0, none.metas.len);

    var generator = rng.test_rng();
    for ([_]usize{ 1, 12, 13, 100, 384, 385, 1000 }) |entries| {
        var table = try Table.init_capacity(gpa, entries);
        defer table.deinit(gpa);
        const slots = table.metas.len;
        try testing.expect(table.capacity() >= entries);
        try testing.expect(slots == handles.MIN_SLOTS or slots / 2 * 3 / 4 < entries);
        for (0..entries) |handle| try table.insert(gpa, generator.next_u64(), handle, NoRehash{});
        try testing.expectEqual(slots, table.metas.len);
        try testing.expectEqual(entries, table.len);
    }
}

test "handles: reserve grows once and keeps entries" {
    var generator = rng.test_rng();
    var hashes: [1000]u64 = undefined;
    for (&hashes) |*hash| hash.* = generator.next_u64();
    const context: Hashes = .{ .hashes = &hashes };
    var calls: usize = 0;
    const counted: Hashes = .{ .hashes = &hashes, .calls = &calls };

    // Reserving nothing on an empty table allocates nothing.
    var table: Table = .empty;
    defer table.deinit(gpa);
    try table.reserve(gpa, 0, context);
    try testing.expectEqual(0, table.metas.len);

    // A reserve that fits in the current capacity changes nothing.
    for (hashes[0..600], 0..) |hash, handle| try table.insert(gpa, hash, handle, context);
    var slots = table.metas.len;
    try table.reserve(gpa, 1, counted);
    try testing.expectEqual(slots, table.metas.len);
    try testing.expectEqual(0, calls);

    // A larger reserve rebuilds once, rehashing each held entry once; the reserved inserts
    // fit only if the reserve counts the held entries.
    try table.reserve(gpa, hashes.len - 600, counted);
    try testing.expect(table.capacity() >= hashes.len);
    try testing.expectEqual(600, calls);
    slots = table.metas.len;
    for (hashes[600..], 600..) |hash, handle| try table.insert(gpa, hash, handle, NoRehash{});
    try testing.expectEqual(slots, table.metas.len);
    try testing.expectEqual(hashes.len, table.len);
    try check_invariants(&table, context);
    for (hashes, 0..) |hash, handle| try testing.expect(has_candidate(&table, hash, handle));
}

test "handles: partition reads neither home nor fingerprint bits" {
    // The group of 256 comes from the byte just below the fingerprint.
    try testing.expectEqual(0xAB, handles.partition(0xAB << (handles.FINGERPRINT_SHIFT - 8), 256));

    // Flipping the fingerprint or the low 40 bits never moves a hash to another group.
    var generator = rng.test_rng();
    for (0..1000) |_| {
        const hash = generator.next_u64();
        for ([_]usize{ 1, 2, 256, 1 << 16 }) |partitions| {
            const group = handles.partition(hash, partitions);
            try testing.expect(group < partitions);
            const fingerprint_flipped = hash ^ (@as(u64, 0xFF) << handles.FINGERPRINT_SHIFT);
            try testing.expectEqual(group, handles.partition(fingerprint_flipped, partitions));
            const low_flipped = hash ^ ((@as(u64, 1) << 40) - 1);
            try testing.expectEqual(group, handles.partition(low_flipped, partitions));
        }
    }
}
