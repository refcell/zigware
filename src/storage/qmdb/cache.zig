//! A bounded `location -> key` cache for snapshot rebuilds (qmdb/cache.rs).
//!
//! Set-associative with 16 ways: a location hashes (Fibonacci hashing) to one set, and a full
//! set evicts its lowest (oldest) location. Snapshot rebuilds use it to resolve translated-key
//! collisions from memory instead of re-reading the log. Keys are owned by the cache and freed
//! (`codec.free`) when replaced, removed, or evicted. Prefetch hints are not ported.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");

const ways_max = 16;
/// Marks an empty slot; never a valid location.
const empty: u64 = std.math.maxInt(u64);

pub fn Cache(comptime K: type) type {
    return struct {
        const Self = @This();

        locations: []u64,
        keys: []K,
        sets: u64,
        ways: usize,

        /// A cache holding at most `capacity` keys (`capacity > 0`).
        pub fn init(gpa: Allocator, capacity: usize) Allocator.Error!Self {
            assert(capacity > 0);
            const ways = @min(ways_max, capacity);
            const sets = capacity / ways;
            const slots = sets * ways;
            assert(slots <= capacity and slots > 0);
            const locations = try gpa.alloc(u64, slots);
            errdefer gpa.free(locations);
            const keys = try gpa.alloc(K, slots);
            @memset(locations, empty);
            return .{ .locations = locations, .keys = keys, .sets = sets, .ways = ways };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.locations, self.keys) |location, key| {
                if (location != empty) codec.free(K, gpa, key);
            }
            gpa.free(self.locations);
            gpa.free(self.keys);
            self.* = undefined;
        }

        fn set_start(self: *const Self, location: u64) usize {
            const hash = location *% utils.GOLDEN_RATIO;
            const set: usize = @intCast((@as(u128, hash) * self.sets) >> 64);
            assert(set < self.sets);
            return set * self.ways;
        }

        fn slot(self: *const Self, location: u64) ?usize {
            const start = self.set_start(location);
            const set = self.locations[start..][0..self.ways];
            const offset = std.mem.indexOfScalar(u64, set, location) orelse return null;
            return start + offset;
        }

        /// The key cached for `location`, if any.
        pub fn get(self: *const Self, location: u64) ?*const K {
            if (location == empty) return null;
            const index = self.slot(location) orelse return null;
            return &self.keys[index];
        }

        /// Caches `key` (taking ownership) for `location`, replacing its old key, else filling an
        /// empty slot in its set, else evicting the set's lowest location.
        pub fn put(self: *Self, gpa: Allocator, location: u64, key: K) void {
            assert(location != empty); // The location is reserved for empty slots.
            const start = self.set_start(location);
            var empty_index: ?usize = null;
            var oldest_location: u64 = empty;
            var oldest_index: usize = start;
            for (start..start + self.ways) |index| {
                const resident = self.locations[index];
                if (resident == location) {
                    codec.free(K, gpa, self.keys[index]);
                    self.keys[index] = key;
                    return;
                }
                if (resident == empty) {
                    if (empty_index == null) empty_index = index;
                } else if (resident < oldest_location) {
                    oldest_location = resident;
                    oldest_index = index;
                }
            }
            const index = empty_index orelse oldest_index;
            if (self.locations[index] != empty) codec.free(K, gpa, self.keys[index]);
            self.locations[index] = location;
            self.keys[index] = key;
            assert(self.slot(location) == index);
        }

        /// Drops the key cached for `location`, if any.
        pub fn remove(self: *Self, gpa: Allocator, location: u64) void {
            if (location == empty) return;
            const index = self.slot(location) orelse return;
            codec.free(K, gpa, self.keys[index]);
            self.locations[index] = empty;
            assert(self.slot(location) == null);
        }
    };
}

const testing = std.testing;

fn present(cache: *const Cache(u64), start: u64, end: u64) usize {
    var count: usize = 0;
    for (start..end) |location| {
        if (cache.get(location) != null) count += 1;
    }
    return count;
}

// commonware `test_put_rejects_empty_marker` (`#[should_panic]`): the empty-slot marker is
// not a location.
test "put rejects the empty marker" {
    try utils.death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            var cache = try Cache(u64).init(testing.allocator, 16);
            defer cache.deinit(testing.allocator);
            cache.put(testing.allocator, std.math.maxInt(u64), 0);
        }
    }.body);
}

test "capacity is an upper bound" {
    const gpa = testing.allocator;
    for ([_]usize{ 1, 3, 15, 16, 17, 31, 32, 33, 100, 1000 }) |capacity| {
        var cache = try Cache(u64).init(gpa, capacity);
        defer cache.deinit(gpa);
        try testing.expect(cache.locations.len <= capacity);
        const inserted: u64 = 10 * capacity;
        for (0..inserted) |location| cache.put(gpa, location, location);
        try testing.expect(present(&cache, 0, inserted) <= capacity);
    }
}

test "get put remove" {
    const gpa = testing.allocator;
    var cache = try Cache([]const u8).init(gpa, 16);
    defer cache.deinit(gpa);
    try testing.expect(cache.get(7) == null);
    cache.put(gpa, 7, try gpa.dupe(u8, "a"));
    try testing.expectEqualStrings("a", cache.get(7).?.*);
    cache.put(gpa, 7, try gpa.dupe(u8, "b"));
    try testing.expectEqualStrings("b", cache.get(7).?.*);
    cache.remove(gpa, 7);
    try testing.expect(cache.get(7) == null);
    cache.remove(gpa, 7);
    try testing.expect(cache.get(7) == null);
}

test "overwrite leaves single entry" {
    const gpa = testing.allocator;
    var cache = try Cache(u64).init(gpa, 16);
    defer cache.deinit(gpa);
    for (0..16) |location| cache.put(gpa, location, location);
    cache.remove(gpa, 0);
    cache.put(gpa, 5, 500);
    try testing.expectEqual(@as(u64, 500), cache.get(5).?.*);
    cache.remove(gpa, 5);
    try testing.expect(cache.get(5) == null);
    try testing.expectEqual(@as(usize, 14), present(&cache, 0, 16));
}

test "full set evicts oldest location" {
    const gpa = testing.allocator;
    var cache = try Cache(u64).init(gpa, 16);
    defer cache.deinit(gpa);
    for (0..16) |location| cache.put(gpa, location, location);
    cache.put(gpa, 100, 100);
    try testing.expect(cache.get(0) == null);
    try testing.expectEqual(@as(usize, 15), present(&cache, 1, 16));
    try testing.expectEqual(@as(u64, 100), cache.get(100).?.*);
}

test "eviction is confined to its set" {
    const gpa = testing.allocator;
    var cache = try Cache(u64).init(gpa, 2 * ways_max);
    defer cache.deinit(gpa);
    var first: [4 * ways_max]u64 = undefined;
    var second: [4 * ways_max]u64 = undefined;
    var first_len: usize = 0;
    var second_len: usize = 0;
    for (0..4 * ways_max) |location| {
        if (cache.set_start(location) == 0) {
            first[first_len] = location;
            first_len += 1;
        } else {
            second[second_len] = location;
            second_len += 1;
        }
    }
    try testing.expect(first_len > ways_max and second_len > ways_max);
    for (first[0..ways_max]) |location| cache.put(gpa, location, location);
    for (second[0..ways_max]) |location| cache.put(gpa, location, location);
    cache.put(gpa, second[ways_max], second[ways_max]);
    try testing.expect(cache.get(second[0]) == null);
    for (first[0..ways_max]) |location| try testing.expectEqual(location, cache.get(location).?.*);
    for (second[1 .. ways_max + 1]) |location| {
        try testing.expectEqual(location, cache.get(location).?.*);
    }
}

test "empty slot is used before eviction" {
    const gpa = testing.allocator;
    var cache = try Cache(u64).init(gpa, 16);
    defer cache.deinit(gpa);
    for (0..16) |location| cache.put(gpa, location, location);
    cache.remove(gpa, 3);
    cache.put(gpa, 100, 100);
    try testing.expectEqual(@as(u64, 0), cache.get(0).?.*);
    try testing.expect(cache.get(3) == null);
    try testing.expectEqual(@as(u64, 100), cache.get(100).?.*);
}

test "small capacity holds one entry" {
    const gpa = testing.allocator;
    var cache = try Cache(u64).init(gpa, 1);
    defer cache.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), cache.locations.len);
    cache.put(gpa, 1, 1);
    cache.put(gpa, 2, 2);
    try testing.expect(cache.get(1) == null);
    try testing.expectEqual(@as(u64, 2), cache.get(2).?.*);
}
