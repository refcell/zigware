//! Tests for `cache.Cache` (commonware `utils/src/cache.rs`, its proptest model, and the
//! `utils/fuzz` cache target). Not ported: the interrupted-prefill case (Rust unwinds a
//! panicking factory; a Zig factory cannot fail mid-prefill) and the hashbrown growth checks
//! (the indexes here are allocated at full size and never grow).

const std = @import("std");
const cache_mod = @import("cache.zig");
const handles = @import("handles.zig");
const fuzz = @import("fuzz.zig");
const rng = @import("rng.zig");
const Cache = cache_mod.Cache;
const Location = cache_mod.Location;
const ResidentSlot = cache_mod.ResidentSlot;
const linked = cache_mod.linked;
const UNLINKED = cache_mod.UNLINKED;
const MASK = cache_mod.ADMISSION_GENERATION_MASK;
const CORRELATED = cache_mod.CORRELATED;
const REFERENCED = cache_mod.REFERENCED;

const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const gpa = testing.allocator;
const U64Cache = Cache(u64, u64);
const BitSet = std.DynamicBitSetUnmanaged;

// Factories and predicates (Rust closures).

fn Constant(comptime V: type) type {
    return struct {
        value: V,

        pub fn make(factory: @This()) V {
            return factory.value;
        }
    };
}

const Counting = struct {
    calls: *usize,
    value: u64 = 0,

    pub fn make(factory: Counting) u64 {
        factory.calls.* += 1;
        return factory.value;
    }
};

const Never = struct {
    pub fn make(_: Never) u64 {
        @panic("the factory must not be called");
    }
};

/// Keeps keys below `bound`.
const Below = struct {
    bound: u64,

    pub fn keep(predicate: Below, key: anytype, _: anytype) bool {
        return key < predicate.bound;
    }
};

const Even = struct {
    pub fn keep(_: Even, key: u64, _: *const u64) bool {
        return key % 2 == 0;
    }
};

/// Drops `rejected` and records each dropped key.
const Recorder = struct {
    rejected: []const u64,
    dropped: *std.ArrayList(u64),

    pub fn keep(predicate: Recorder, key: u64, _: *const u64) bool {
        if (std.mem.indexOfScalar(u64, predicate.rejected, key) == null) return true;
        predicate.dropped.append(gpa, key) catch @panic("out of memory");
        return false;
    }
};

const Drop = struct {
    pub fn keep(_: Drop, _: anytype, _: anytype) bool {
        return false;
    }
};

fn value_of(comptime V: type, value: ?*const V) ?V {
    return if (value) |pointer| pointer.* else null;
}

fn iota(comptime start: u64, comptime end: u64) [end - start]u64 {
    var result: [end - start]u64 = undefined;
    for (&result, start..) |*value, key| value.* = key;
    return result;
}

// Queue order and keys.

fn KeyOf(comptime C: type) type {
    return @FieldType(C.Entry, "key");
}

/// Small slots from newest to oldest.
fn small_order(cache: anytype) ![]usize {
    var order: std.ArrayList(usize) = .empty;
    errdefer order.deinit(gpa);
    var current = cache.small.head;
    while (current) |slot| : (current = linked(cache.topology[slot].next)) {
        try order.append(gpa, slot);
        try expect(order.items.len <= cache.capacity);
    }
    return order.toOwnedSlice(gpa);
}

/// Main slots starting at the CLOCK hand.
fn main_order(cache: anytype) ![]usize {
    var order: std.ArrayList(usize) = .empty;
    errdefer order.deinit(gpa);
    const hand = cache.main.hand orelse return order.toOwnedSlice(gpa);
    var current = hand;
    while (true) {
        try order.append(gpa, current);
        try expect(order.items.len <= cache.capacity);
        current = cache.topology[current].next;
        try expect(current != UNLINKED);
        if (current == hand) break;
    }
    return order.toOwnedSlice(gpa);
}

/// Ghost slots from newest to oldest.
fn ghost_order(ghost: anytype) ![]usize {
    var order: std.ArrayList(usize) = .empty;
    errdefer order.deinit(gpa);
    var current = ghost.head;
    while (current) |slot| : (current = linked(ghost.slots.items[slot].next)) {
        try order.append(gpa, slot);
        try expect(order.items.len <= ghost.capacity);
    }
    return order.toOwnedSlice(gpa);
}

fn resident_keys(cache: anytype, order: []const usize) ![]KeyOf(@TypeOf(cache.*)) {
    const keys = try gpa.alloc(KeyOf(@TypeOf(cache.*)), order.len);
    for (order, keys) |slot, *key| key.* = cache.slots.items[slot].key;
    return keys;
}

fn small_keys(cache: anytype) ![]KeyOf(@TypeOf(cache.*)) {
    const order = try small_order(cache);
    defer gpa.free(order);
    return resident_keys(cache, order);
}

fn main_keys(cache: anytype) ![]KeyOf(@TypeOf(cache.*)) {
    const order = try main_order(cache);
    defer gpa.free(order);
    return resident_keys(cache, order);
}

fn ghost_keys(cache: anytype) ![]KeyOf(@TypeOf(cache.*)) {
    const order = try ghost_order(&cache.ghost);
    defer gpa.free(order);
    const keys = try gpa.alloc(KeyOf(@TypeOf(cache.*)), order.len);
    for (order, keys) |slot, *key| key.* = cache.ghost.slots.items[slot].key.?;
    return keys;
}

const Queue = enum { small, main, ghost };

fn queue_keys(cache: *const U64Cache, queue: Queue) ![]u64 {
    return switch (queue) {
        .small => small_keys(cache),
        .main => main_keys(cache),
        .ghost => ghost_keys(cache),
    };
}

fn expect_queue(cache: *const U64Cache, queue: Queue, expected: []const u64) !void {
    const keys = try queue_keys(cache, queue);
    defer gpa.free(keys);
    try testing.expectEqualSlices(u64, expected, keys);
}

fn in_queue(cache: *const U64Cache, queue: Queue, key: u64) !bool {
    const keys = try queue_keys(cache, queue);
    defer gpa.free(keys);
    return std.mem.indexOfScalar(u64, keys, key) != null;
}

fn bits(cache: *const U64Cache, key: u64) u8 {
    const slot = cache.find_slot(key, cache_mod.key_hash(u64, key)).?;
    return cache.slots.items[slot].state.load();
}

fn slot_of(cache: *const U64Cache, key: u64) ?usize {
    return cache.find_slot(key, cache_mod.key_hash(u64, key));
}

// Invariants (Rust `check_invariants`).

/// Resident ownership, queue topology, and exact history agree.
fn check_invariants(cache: anytype) !void {
    const K = KeyOf(@TypeOf(cache.*));
    const capacity = cache.capacity;
    const slot_count = cache.slots.items.len;
    try expect(slot_count <= capacity);
    try expectEqual(capacity, cache.topology.len);
    try expect(cache.small.len <= cache.small.capacity);
    try expect(cache.main.len <= cache.main.capacity);
    try expectEqual(cache.small.len + cache.main.len, cache.index.len);
    try expectEqual(slot_count, cache.index.len + cache.free.items.len);

    var free = try BitSet.initEmpty(gpa, capacity);
    defer free.deinit(gpa);
    for (cache.free.items) |slot| {
        try expect(!free.isSet(slot));
        free.set(slot);
    }
    var resident = try BitSet.initEmpty(gpa, capacity);
    defer resident.deinit(gpa);
    try check_small(cache, &resident);
    try check_main(cache, &resident);

    var indexed: usize = 0;
    for (cache.index.slots) |entry| {
        if (entry.meta == handles.EMPTY) continue;
        indexed += 1;
        const slot = entry.handle;
        try expect(slot < slot_count and resident.isSet(slot));
        const key = cache.slots.items[slot].key;
        try expectEqual(@as(?usize, slot), cache.find_slot(key, cache_mod.key_hash(K, key)));
    }
    try expectEqual(cache.index.len, indexed);
    try expectEqual(indexed, resident.count());
    for (cache.topology, 0..) |topology, slot| {
        if (resident.isSet(slot)) {
            try expect(!free.isSet(slot));
            continue;
        }
        if (slot < slot_count) {
            try expect(free.isSet(slot));
            try expect(!cache.slots.items[slot].live);
        }
        try expectEqual(Location.free, topology.location());
        try expectEqual(0, topology.admitted_at());
    }
    try check_ghost(cache);
}

fn check_small(cache: anytype, resident: *BitSet) !void {
    const small = try small_order(cache);
    defer gpa.free(small);
    try expectEqual(cache.small.len, small.len);
    const young_len: usize = if (cache.small.young_tail) |tail|
        (std.mem.indexOfScalar(usize, small, tail) orelse return error.TestUnexpectedResult) + 1
    else
        0;
    try expect(cache.small.admissions <= MASK);
    try expect(young_len <= cache.small.correlation_window);
    try expect(young_len <= small.len);
    for (small, 0..) |slot, rank| {
        try expect(!resident.isSet(slot));
        resident.set(slot);
        try expect(cache.slots.items[slot].live);
        const topology = cache.topology[slot];
        try expectEqual(Location.small, topology.location());
        const state = cache.slots.items[slot].state.load();
        const young = rank < young_len;
        try expectEqual(young, state & CORRELATED != 0);
        if (young) {
            try expectEqual(CORRELATED, state);
            const age = (cache.small.admissions -% topology.admitted_at()) & MASK;
            try expect(age < cache.small.correlation_window);
        } else {
            try expectEqual(0, topology.admitted_at());
        }
        const prev: ?usize = if (rank == 0) null else small[rank - 1];
        const next: ?usize = if (rank + 1 < small.len) small[rank + 1] else null;
        try expectEqual(prev, linked(topology.prev));
        try expectEqual(next, linked(topology.next));
    }
    const head: ?usize = if (small.len > 0) small[0] else null;
    const tail: ?usize = if (small.len > 0) small[small.len - 1] else null;
    const young_tail: ?usize = if (young_len > 0) small[young_len - 1] else null;
    try expectEqual(head, cache.small.head);
    try expectEqual(tail, cache.small.tail);
    try expectEqual(young_tail, cache.small.young_tail);
}

fn check_main(cache: anytype, resident: *BitSet) !void {
    const main = try main_order(cache);
    defer gpa.free(main);
    try expectEqual(cache.main.len, main.len);
    for (main, 0..) |slot, rank| {
        try expect(!resident.isSet(slot));
        resident.set(slot);
        try expect(cache.slots.items[slot].live);
        const topology = cache.topology[slot];
        try expectEqual(Location.main, topology.location());
        try expectEqual(0, topology.admitted_at());
        try expectEqual(0, cache.slots.items[slot].state.load() & CORRELATED);
        try expectEqual(main[(rank + main.len - 1) % main.len], topology.prev);
        try expectEqual(main[(rank + 1) % main.len], topology.next);
    }
}

fn check_ghost(cache: anytype) !void {
    const K = KeyOf(@TypeOf(cache.*));
    const ghost = &cache.ghost;
    try expect(ghost.len() <= ghost.capacity);
    try expect(ghost.slots.items.len <= ghost.capacity);
    const order = try ghost_order(ghost);
    defer gpa.free(order);
    try expectEqual(ghost.len(), order.len);

    var free = try BitSet.initEmpty(gpa, ghost.capacity);
    defer free.deinit(gpa);
    var current = ghost.free_head;
    while (current) |slot| : (current = linked(ghost.slots.items[slot].next)) {
        try expect(!free.isSet(slot));
        free.set(slot);
        try expect(ghost.slots.items[slot].key == null);
        try expectEqual(UNLINKED, ghost.slots.items[slot].prev);
    }
    try expectEqual(ghost.slots.items.len, ghost.len() + free.count());

    var seen = try BitSet.initEmpty(gpa, ghost.capacity);
    defer seen.deinit(gpa);
    for (order, 0..) |slot, rank| {
        try expect(!seen.isSet(slot) and !free.isSet(slot));
        seen.set(slot);
        const key = ghost.slots.items[slot].key.?;
        try expectEqual(@as(?usize, slot), ghost.find(key, cache_mod.key_hash(K, key)));
        try expect(!cache.contains(key));
        const prev: ?usize = if (rank == 0) null else order[rank - 1];
        const next: ?usize = if (rank + 1 < order.len) order[rank + 1] else null;
        try expectEqual(prev, linked(ghost.slots.items[slot].prev));
        try expectEqual(next, linked(ghost.slots.items[slot].next));
    }
    const head: ?usize = if (order.len > 0) order[0] else null;
    const tail: ?usize = if (order.len > 0) order[order.len - 1] else null;
    try expectEqual(head, ghost.head);
    try expectEqual(tail, ghost.tail);
    for (ghost.slots.items, 0..) |entry, slot| {
        try expectEqual(seen.isSet(slot), entry.key != null);
        try expectEqual(free.isSet(slot), entry.key == null);
    }
}

// Basic operations.

test "cache: basic put, get, and peek" {
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    try expect(cache.is_empty());
    try expectEqual(2, cache.capacity);
    try expectEqual(@as(?u64, null), cache.put(1, 10));
    try expectEqual(@as(?u64, null), cache.put(2, 20));
    try expectEqual(2, cache.len());
    try expectEqual(@as(?u64, 10), value_of(u64, cache.get(1)));
    try expectEqual(@as(?u64, 20), value_of(u64, cache.peek(2)));
    try expect(cache.contains(1));
    try expect(!cache.contains(3));
    try expectEqual(@as(?u64, null), value_of(u64, cache.get(3)));
    try check_invariants(&cache);
}

test "cache: put replaces an existing value" {
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    try expectEqual(@as(?u64, null), cache.put(1, 10));
    try expectEqual(@as(?u64, 10), cache.put(1, 11));
    try expectEqual(@as(?u64, 11), value_of(u64, cache.get(1)));
    try expectEqual(1, cache.len());
    try check_invariants(&cache);
}

test "cache: capacity one reuses its only slot and behaves as CLOCK" {
    var cache = try U64Cache.init(gpa, 1);
    defer cache.deinit(gpa);
    _ = cache.put(1, 10);
    try expectEqual(@as(?u64, 10), value_of(u64, cache.get(1)));
    _ = cache.put(2, 20);
    try expect(!cache.contains(1));
    try expectEqual(@as(?u64, 20), value_of(u64, cache.get(2)));
    try expectEqual(1, cache.len());
    try expect(cache.ghost.len() == 0);
    try check_invariants(&cache);
}

test "cache: get_or_insert_with calls the factory only on a miss" {
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    var calls: usize = 0;
    const factory: Counting = .{ .calls = &calls, .value = 100 };
    try expectEqual(100, cache.get_or_insert_with(1, factory).*);
    try expectEqual(1, calls);
    try expectEqual(100, cache.get_or_insert_with(1, factory).*);
    try expectEqual(1, calls);
    try check_invariants(&cache);
}

const Failing = struct {
    pub fn make(_: Failing) error{Bad}!u64 {
        return error.Bad;
    }
};

const Succeeding = struct {
    pub fn make(_: Succeeding) error{Bad}!u64 {
        return 10;
    }
};

test "cache: try_get_or_insert_with does not cache errors" {
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    try testing.expectError(error.Bad, cache.try_get_or_insert_with(1, Failing{}));
    try expect(!cache.contains(1));
    try expectEqual(10, (try cache.try_get_or_insert_with(1, Succeeding{})).*);
    try expect(cache.contains(1));
    try check_invariants(&cache);
}

test "cache: a failed factory leaves the cache and Ghost history unchanged" {
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    for (1..4) |key| _ = cache.put(key, key);
    try expect(try in_queue(&cache, .ghost, 1));
    const queues = [_]Queue{ .small, .main, .ghost };
    var before: [3][]u64 = undefined;
    for (queues, &before) |queue, *keys| keys.* = try queue_keys(&cache, queue);
    defer for (before) |keys| gpa.free(keys);
    try testing.expectError(error.Bad, cache.try_get_or_insert_with(1, Failing{}));
    for (queues, before) |queue, keys| try expect_queue(&cache, queue, keys);
    try check_invariants(&cache);
}

test "cache: remove keeps the slot for reuse" {
    var makes: usize = 0;
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    _ = cache.get_or_insert_mut(1, Counting{ .calls = &makes, .value = 10 });
    _ = cache.get_or_insert_mut(2, Counting{ .calls = &makes, .value = 20 });
    try expectEqual(2, makes);
    try expectEqual(2, cache.slots.items.len);

    try expect(cache.remove(1));
    try expect(!cache.contains(1));
    try expectEqual(1, cache.len());
    cache.get_or_insert_mut(3, Counting{ .calls = &makes, .value = 30 }).value.* = 30;
    try expectEqual(2, makes);
    try expectEqual(2, cache.slots.items.len);
    try expectEqual(@as(?u64, 30), value_of(u64, cache.get(3)));
    try expect(!cache.remove(999));
    try check_invariants(&cache);
}

test "cache: retain frees slots for reuse" {
    var cache = try U64Cache.init(gpa, 4);
    defer cache.deinit(gpa);
    for (0..4) |key| _ = cache.put(key, key * 10);
    cache.retain(Even{});
    try expectEqual(2, cache.len());
    try expect(cache.contains(0) and cache.contains(2));
    try expect(!cache.contains(1) and !cache.contains(3));
    _ = cache.put(10, 100);
    _ = cache.put(12, 120);
    try expectEqual(4, cache.slots.items.len);
    try expectEqual(4, cache.len());
    try check_invariants(&cache);
}

test "cache: get_or_insert_mut reuses allocations" {
    var makes: usize = 0;
    var cache = try U64Cache.init(gpa, 3);
    defer cache.deinit(gpa);
    for (0..100) |key| cache.get_or_insert_mut(key, Counting{ .calls = &makes }).value.* = key;
    try expectEqual(3, makes);
    try expectEqual(3, cache.slots.items.len);
    try expectEqual(3, cache.len());
    try check_invariants(&cache);
}

test "cache: prefill allocates once and reuses" {
    var makes: usize = 0;
    var cache = try U64Cache.init(gpa, 3);
    defer cache.deinit(gpa);
    cache.prefill(Counting{ .calls = &makes });
    try expectEqual(3, makes);
    try expectEqual(3, cache.slots.items.len);
    try expect(cache.is_empty());
    try check_invariants(&cache);
    for (0..100) |key| cache.get_or_insert_mut(key, Counting{ .calls = &makes }).value.* = key;
    try expectEqual(3, makes);
    try expectEqual(3, cache.slots.items.len);
    try expectEqual(3, cache.len());
    try check_invariants(&cache);
}

const Sequence = struct {
    next: *u64,

    pub fn make(factory: Sequence) u64 {
        defer factory.next.* += 1;
        return factory.next.* + 10;
    }
};

test "cache: prefill and detached slots preserve reuse order" {
    var cache = try U64Cache.init(gpa, 6);
    defer cache.deinit(gpa);
    for (0..3) |key| {
        try expectEqual(key, cache.get_or_insert_mut(key, Constant(u64){ .value = key + 10 }).slot);
    }
    try expect(cache.remove(1));
    try expect(cache.remove(2));
    var next: u64 = 3;
    cache.prefill(Sequence{ .next = &next });
    try expectEqual(@as(?u64, 10), value_of(u64, cache.get_at(0, 0)));
    try check_invariants(&cache);

    // New slots come first, in creation order, then the detached ones, newest first.
    for ([_]u64{ 3, 4, 5, 2, 1 }) |expected| {
        const found = cache.get_or_insert_mut(expected, Never{});
        try expectEqual(expected, found.slot);
        try expectEqual(expected + 10, found.value.*);
        try check_invariants(&cache);
    }

    try expect(cache.remove(1));
    try expect(cache.remove(2));
    var detached: std.ArrayList(u64) = .empty;
    defer detached.deinit(gpa);
    try detached.appendSlice(gpa, &.{ 1, 2 });
    cache.retain(Recorder{ .rejected = &.{ 0, 3 }, .dropped = &detached });
    try check_invariants(&cache);
    std.mem.reverse(u64, detached.items);
    for (detached.items) |expected| {
        const found = cache.get_or_insert_mut(expected + 20, Never{});
        try expectEqual(expected, found.slot);
        try expectEqual(expected + 10, found.value.*);
        try check_invariants(&cache);
    }
}

test "cache: clear drops entries and allows reuse" {
    var cache = try U64Cache.init(gpa, 4);
    defer cache.deinit(gpa);
    for (0..4) |key| _ = cache.put(key, key);
    cache.clear();
    try expect(cache.is_empty());
    _ = cache.put(9, 9);
    try expectEqual(@as(?u64, 9), value_of(u64, cache.get(9)));
    try check_invariants(&cache);
}

/// Counts drops (Rust `Drop`).
const Tracked = struct {
    drops: *usize,

    pub fn discard(value: Tracked) void {
        value.drops.* += 1;
    }
};

test "cache: values are dropped on replacement and clear" {
    var drops: usize = 0;
    var cache = try Cache(u64, Tracked).init(gpa, 2);
    defer cache.deinit(gpa);
    for (0..2) |key| try expect(cache.put(key, .{ .drops = &drops }) == null);
    try expectEqual(0, drops);
    // An eviction drops the evicted value.
    try expect(cache.put(2, .{ .drops = &drops }) == null);
    try expectEqual(1, drops);
    // A replaced value is returned; dropping it is the caller's.
    Tracked.discard(cache.put(2, .{ .drops = &drops }).?);
    try expectEqual(2, drops);
    cache.clear();
    try expectEqual(4, drops);
}

test "cache: remove retains the value until reuse" {
    var drops: usize = 0;
    var cache = try Cache(u64, Tracked).init(gpa, 2);
    defer cache.deinit(gpa);
    _ = cache.put(1, .{ .drops = &drops });
    try expect(cache.remove(1));
    try expectEqual(0, drops);
    _ = cache.put(2, .{ .drops = &drops });
    try expectEqual(1, drops);
}

test "cache: get_at validates the key and rejects stale or freed slots" {
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    const first = cache.get_or_insert_mut(1, Constant(u64){ .value = 0 });
    first.value.* = 10;
    const second = cache.get_or_insert_mut(2, Constant(u64){ .value = 0 });
    second.value.* = 20;
    try expectEqual(@as(?u64, 10), value_of(u64, cache.get_at(first.slot, 1)));
    try expectEqual(@as(?u64, 20), value_of(u64, cache.get_at(second.slot, 2)));
    try expectEqual(@as(?u64, null), value_of(u64, cache.get_at(first.slot, 2)));
    try expectEqual(@as(?u64, null), value_of(u64, cache.get_at(cache.capacity, 1)));

    // A freed slot misses; reusing it resolves only the new key.
    try expect(cache.remove(1));
    try expectEqual(@as(?u64, null), value_of(u64, cache.get_at(first.slot, 1)));
    const reused = cache.get_or_insert_mut(3, Never{});
    reused.value.* = 30;
    try expectEqual(first.slot, reused.slot);
    try expectEqual(@as(?u64, null), value_of(u64, cache.get_at(first.slot, 1)));
    try expectEqual(@as(?u64, 30), value_of(u64, cache.get_at(first.slot, 3)));

    // The slot is stable on a hit.
    const hit = cache.get_or_insert_mut(3, Never{});
    try expectEqual(reused.slot, hit.slot);
    try expectEqual(30, hit.value.*);
    try check_invariants(&cache);

    // An evicted slot misses once reused for another key.
    var single = try U64Cache.init(gpa, 1);
    defer single.deinit(gpa);
    const slot = single.get_or_insert_mut(1, Constant(u64){ .value = 10 }).slot;
    const evicted = single.get_or_insert_mut(3, Never{});
    evicted.value.* = 30;
    try expectEqual(slot, evicted.slot);
    try expectEqual(@as(?u64, null), value_of(u64, single.get_at(slot, 1)));
    try expectEqual(@as(?u64, 30), value_of(u64, single.get_at(slot, 3)));
    try check_invariants(&single);
}

test "cache: get_mut updates a resident value" {
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    _ = cache.put(1, 10);
    try expect(cache.get_mut(2) == null);
    cache.get_mut(1).?.* = 11;
    try expectEqual(@as(?u64, 11), value_of(u64, cache.get(1)));
    try check_invariants(&cache);
}

// Replacement policy.

test "cache: resident metadata fits three words and preserves links" {
    try expectEqual(3 * @sizeOf(usize), @sizeOf(ResidentSlot));
    var slot: ResidentSlot = .{
        .prev = std.math.maxInt(usize) - 1,
        .next = std.math.maxInt(usize) - 2,
        .location_and_admission = Location.small.pack(MASK),
    };
    try expectEqual(Location.small, slot.location());
    try expectEqual(MASK, slot.admitted_at());
    slot.location_and_admission = Location.main.pack(0);
    try expectEqual(Location.main, slot.location());
    try expectEqual(0, slot.admitted_at());
    try expectEqual(std.math.maxInt(usize) - 1, slot.prev);
    try expectEqual(std.math.maxInt(usize) - 2, slot.next);
    slot.location_and_admission = Location.free.pack(0);
    try expectEqual(Location.free, slot.location());
}

test "cache: partitions round for tiny capacities" {
    const Expected = struct {
        capacity: usize,
        small: usize,
        main: usize,
        window: usize,
        ghost: usize,
    };
    const expected = [_]Expected{
        .{ .capacity = 1, .small = 0, .main = 1, .window = 0, .ghost = 0 },
        .{ .capacity = 2, .small = 1, .main = 1, .window = 1, .ghost = 1 },
        .{ .capacity = 10, .small = 1, .main = 9, .window = 1, .ghost = 5 },
        .{ .capacity = 11, .small = 1, .main = 10, .window = 1, .ghost = 5 },
        .{ .capacity = 20, .small = 2, .main = 18, .window = 1, .ghost = 10 },
        .{ .capacity = 40, .small = 4, .main = 36, .window = 2, .ghost = 20 },
    };
    for (expected) |row| {
        var cache = try U64Cache.init(gpa, row.capacity);
        defer cache.deinit(gpa);
        try expectEqual(row.small, cache.small.capacity);
        try expectEqual(row.main, cache.main.capacity);
        try expectEqual(row.window, cache.small.correlation_window);
        try expectEqual(row.ghost, cache.ghost.capacity);
        try check_invariants(&cache);
    }
    for (1..21) |capacity| {
        var cache = try U64Cache.init(gpa, capacity);
        defer cache.deinit(gpa);
        for (0..200) |key| {
            _ = cache.put(key, key);
            try check_invariants(&cache);
        }
    }
}

fn filled(capacity: usize, end: u64) !U64Cache {
    var cache = try U64Cache.init(gpa, capacity);
    for (0..end) |key| _ = cache.put(key, key);
    return cache;
}

test "cache: warm-up fills Small, then Main, with cold entries" {
    var cache = try filled(20, 20);
    defer cache.deinit(gpa);
    try expect_queue(&cache, .small, &.{ 1, 0 });
    try expect_queue(&cache, .main, &iota(2, 20));
    for (2..20) |key| try expectEqual(0, bits(&cache, key) & REFERENCED);
    try check_invariants(&cache);
}

test "cache: empty residents preserve precise Ghost history" {
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    for (1..4) |key| _ = cache.put(key, key);
    try expect_queue(&cache, .ghost, &.{1});
    cache.retain(Below{ .bound = 2 });
    try expectEqual(0, cache.len());
    try expect_queue(&cache, .ghost, &.{1});
    cache.retain(Drop{});
    try expectEqual(0, cache.small.len + cache.main.len);
    try expect_queue(&cache, .ghost, &.{1});
    try check_invariants(&cache);
}

test "cache: the correlation window ignores only young hits" {
    // Key 4 is inside the two-entry window: its hit is ignored, so a scan evicts it.
    var correlated = try U64Cache.init(gpa, 40);
    defer correlated.deinit(gpa);
    for (1..41) |key| _ = correlated.put(key, key);
    try expect_queue(&correlated, .small, &.{ 4, 3, 2, 1 });
    try expectEqual(@as(?u64, 4), value_of(u64, correlated.get(4)));
    try expectEqual(0, bits(&correlated, 4) & REFERENCED);
    for (41..45) |key| _ = correlated.put(key, key);
    try expect(!correlated.contains(4));
    try expect(try in_queue(&correlated, .ghost, 4));
    try check_invariants(&correlated);

    // Key 1 is outside the window: its hit promotes it on the next insertion.
    var reused = try U64Cache.init(gpa, 40);
    defer reused.deinit(gpa);
    for (1..41) |key| _ = reused.put(key, key);
    try expectEqual(@as(?u64, 1), value_of(u64, reused.get(1)));
    _ = reused.put(41, 41);
    try expect(try in_queue(&reused, .small, 41));
    try expect(try in_queue(&reused, .main, 1));
    try expectEqual(0, bits(&reused, 1) & REFERENCED);
    try expectEqual(0, reused.ghost.len());
    try check_invariants(&reused);
}

test "cache: removing a younger entry neither rewinds nor delays correlation age" {
    var rewind = try filled(20, 20);
    defer rewind.deinit(gpa);
    try expectEqual(@as(?u64, 0), value_of(u64, rewind.get(0)));
    try expect(rewind.remove(1));
    _ = rewind.put(20, 20);
    _ = rewind.put(21, 21);
    try expect(try in_queue(&rewind, .main, 0));
    try expect(!try in_queue(&rewind, .ghost, 0));
    try check_invariants(&rewind);

    var delay = try filled(40, 40);
    defer delay.deinit(gpa);
    try expect_queue(&delay, .small, &.{ 3, 2, 1, 0 });
    try expect(delay.remove(3));
    _ = delay.put(40, 40);
    try expectEqual(@as(?u64, 2), value_of(u64, delay.get(2)));
    for (41..44) |key| _ = delay.put(key, key);
    try expect(try in_queue(&delay, .main, 2));
    try expect(!try in_queue(&delay, .ghost, 2));
    try check_invariants(&delay);
}

test "cache: Ghost history is bounded and promotes reuse" {
    var cache = try filled(20, 31);
    defer cache.deinit(gpa);
    try expect_queue(&cache, .small, &.{ 30, 29 });
    try expect_queue(&cache, .main, &iota(2, 20));
    try expect_queue(&cache, .ghost, &.{ 28, 27, 26, 25, 24, 23, 22, 21, 20, 1 });

    // Key 1 is in Ghost: reuse consumes its history and enters Main directly.
    cache.get_or_insert_mut(1, Never{}).value.* = 100;
    try expectEqual(@as(?u64, 100), value_of(u64, cache.peek(1)));
    try expect(try in_queue(&cache, .main, 1));
    try expect_queue(&cache, .small, &.{ 30, 29 });
    try expect_queue(&cache, .ghost, &.{ 28, 27, 26, 25, 24, 23, 22, 21, 20 });

    // Key 0 aged out of Ghost, so it enters Small cold and evicts Small's tail.
    _ = cache.put(0, 200);
    const small = try small_keys(&cache);
    defer gpa.free(small);
    try expectEqual(0, small[0]);
    try expect(!try in_queue(&cache, .main, 0));
    const ghost = try ghost_keys(&cache);
    defer gpa.free(ghost);
    try expectEqual(29, ghost[0]);
    try check_invariants(&cache);
}

test "cache: Main evicts despite an offered vacancy" {
    var cache = try U64Cache.init(gpa, 2);
    defer cache.deinit(gpa);
    for (1..4) |key| _ = cache.put(key, key);
    try expect_queue(&cache, .main, &.{2});
    try expect(cache.remove(3));
    try expectEqual(1, cache.len());
    try expect_queue(&cache, .ghost, &.{1});
    _ = cache.put(1, 10);
    try expectEqual(1, cache.len());
    try expect_queue(&cache, .main, &.{1});
    try expect(!cache.contains(2));
    try check_invariants(&cache);
}

test "cache: promoting Small replaces from a full Main" {
    var cache = try filled(20, 20);
    defer cache.deinit(gpa);
    for (0..18) |key| try expectEqual(@as(?u64, key), value_of(u64, cache.get(key)));
    _ = cache.put(20, 20);
    try expectEqual(cache.main.capacity, cache.main.len);
    try expectEqual(2, cache.small.len);
    try expectEqual(0, bits(&cache, 0) & REFERENCED);
    // The sweep evicted key 18 and left the hand on 19; the promoted key 0 is swept last.
    try expect_queue(&cache, .main, &([_]u64{19} ++ iota(2, 18) ++ [_]u64{0}));

    const small = try small_keys(&cache);
    defer gpa.free(small);
    try expectEqual(1, small[small.len - 1]);
    try expectEqual(@as(?u64, 1), value_of(u64, cache.get(1)));
    _ = cache.put(21, 21);
    try expect_queue(&cache, .main, &(iota(2, 18) ++ [_]u64{ 0, 1 }));
    try expectEqual(0, bits(&cache, 1) & REFERENCED);
    try expect(try in_queue(&cache, .small, 21));
    try expectEqual(cache.main.capacity, cache.main.len);
    try expectEqual(2, cache.small.len);
    try check_invariants(&cache);
}

test "cache: a slot stays stable on promotion and goes stale on reuse" {
    var cache = try U64Cache.init(gpa, 40);
    defer cache.deinit(gpa);
    const slot1 = cache.get_or_insert_mut(1, Constant(u64){ .value = 10 }).slot;
    const slot2 = cache.get_or_insert_mut(2, Constant(u64){ .value = 20 }).slot;
    for (3..41) |key| _ = cache.put(key, key * 10);
    try expectEqual(@as(?u64, 10), value_of(u64, cache.get_at(slot1, 1)));
    _ = cache.put(41, 410);
    try expectEqual(@as(?u64, 10), value_of(u64, cache.get_at(slot1, 1)));
    try expect(try in_queue(&cache, .main, 1));

    try expect(cache.slots.items[slot2].live);
    try expectEqual(2, cache.slots.items[slot2].key);
    _ = cache.put(42, 420);
    try expectEqual(@as(?u64, null), value_of(u64, cache.get_at(slot2, 2)));
    try expectEqual(@as(?usize, slot2), slot_of(&cache, 42));
    try expectEqual(@as(?u64, 420), value_of(u64, cache.get_at(slot2, 42)));
    try check_invariants(&cache);
}

test "cache: a scan does not displace Main" {
    var cache = try filled(10, 10);
    defer cache.deinit(gpa);
    try expectEqual(9, cache.main.len);
    for (100..110) |key| _ = cache.put(key, key);
    for (1..10) |key| try expect(cache.peek(key) != null);
    try check_invariants(&cache);
}

test "cache: the Main sweep reaches an unreferenced resident beyond 128" {
    var cache = try filled(200, 200);
    defer cache.deinit(gpa);
    for (20..149) |key| try expectEqual(@as(?u64, key), value_of(u64, cache.get(key)));
    _ = cache.put(200, 200);
    try expect_queue(&cache, .ghost, &.{0});
    _ = cache.put(0, 0);
    try expect(cache.peek(149) == null);
    for (20..149) |key| {
        try expectEqual(@as(?u64, key), value_of(u64, cache.peek(key)));
        try expectEqual(0, bits(&cache, key));
    }
    try check_invariants(&cache);
}

test "cache: prefill reuses values through churn" {
    const Buffer = [32]u8;
    var makes: usize = 0;
    const Make = struct {
        makes: *usize,

        pub fn make(factory: @This()) Buffer {
            factory.makes.* += 1;
            return @splat(0);
        }
    };
    var cache = try Cache(u64, Buffer).init(gpa, 20);
    defer cache.deinit(gpa);
    cache.prefill(Make{ .makes = &makes });
    try expectEqual(20, makes);
    for (0..2000) |key| {
        cache.get_or_insert_mut(key, Make{ .makes = &makes }).value[0] = @truncate(key);
        try check_invariants(&cache);
    }
    try expectEqual(20, cache.slots.items.len);
    try expectEqual(20, makes);
}

test "cache: remove, retain, and clear repair resident state" {
    var cache = try filled(20, 31);
    defer cache.deinit(gpa);
    _ = cache.put(1, 1);
    try expect(cache.remove(1));
    try expect(!cache.remove(1));
    const ghost_before = try ghost_keys(&cache);
    defer gpa.free(ghost_before);
    const ghost = ghost_before[0];
    try expect(!cache.remove(ghost));
    try expect(!try in_queue(&cache, .ghost, ghost));

    // With a full cache, the forgotten Ghost key enters Small cold.
    _ = cache.put(100, 100);
    _ = cache.put(ghost, ghost);
    try expect(try in_queue(&cache, .small, ghost));
    try expect(!try in_queue(&cache, .main, ghost));

    cache.retain(Even{});
    try expect(cache.ghost.len() > 0);
    for (cache.slots.items) |entry| try expect(!entry.live or entry.key % 2 == 0);
    try check_invariants(&cache);

    cache.clear();
    try expect(cache.is_empty());
    try expectEqual(0, cache.small.len + cache.main.len);
    try expectEqual(0, cache.ghost.len());
    try check_invariants(&cache);
}

fn hammer(cache: *U64Cache, slot: usize) void {
    for (0..1000) |_| std.debug.assert(cache.get_at(slot, 1).?.* == 1);
}

test "cache: shared hits are concurrent" {
    const io = testing.io;
    var cache = try filled(40, 0);
    defer cache.deinit(gpa);
    for (1..41) |key| _ = cache.put(key, key);
    const slot = slot_of(&cache, 1).?;
    var futures: [4]std.Io.Future(void) = undefined;
    for (&futures) |*future| future.* = try io.concurrent(hammer, .{ &cache, slot });
    for (&futures) |*future| future.await(io);
    _ = cache.put(41, 41);
    try expect(try in_queue(&cache, .main, 1));
    try check_invariants(&cache);
}

test "cache: correlation age survives an admission counter wrap" {
    var wrapped = try U64Cache.init(gpa, 40);
    defer wrapped.deinit(gpa);
    wrapped.small.admissions = MASK - 1;
    var plain = try filled(40, 0);
    defer plain.deinit(gpa);
    for (1..41) |key| {
        _ = wrapped.put(key, key);
        _ = plain.put(key, key);
    }
    const wrapped_small = try small_keys(&wrapped);
    defer gpa.free(wrapped_small);
    try expect_queue(&plain, .small, wrapped_small);
    for (wrapped_small) |key| try expectEqual(bits(&plain, key), bits(&wrapped, key));

    // Key 1 left the window across the wrap. Remove both young residents and cross the
    // wrap repeatedly: young_tail, not generation equality, owns youth.
    try expectEqual(@as(?u64, 1), value_of(u64, wrapped.get(1)));
    try expect(wrapped.remove(4));
    try expect(wrapped.remove(3));
    try expectEqual(@as(?usize, null), wrapped.small.young_tail);
    for (0..8) |cycle| {
        const first = 41 + 2 * cycle;
        const second = first + 1;
        wrapped.small.admissions = MASK - 1;
        _ = wrapped.put(first, first);
        const young_tail = slot_of(&wrapped, first);
        _ = wrapped.put(second, second);
        try expectEqual(young_tail, wrapped.small.young_tail);
        try check_invariants(&wrapped);
        if (cycle < 7) {
            try expect(wrapped.remove(second));
            try expect(wrapped.remove(first));
            try expectEqual(@as(?usize, null), wrapped.small.young_tail);
        }
    }
    _ = wrapped.put(57, 57);
    try expect(try in_queue(&wrapped, .main, 1));
    try check_invariants(&wrapped);
    wrapped.clear();
    try expectEqual(0, wrapped.small.admissions);
    try check_invariants(&wrapped);
}

// Colliding keys and Ghost ownership.

/// A key whose hash always collides; live keys are counted through `owner` (Rust `Rc`).
const GhostKey = struct {
    value: u64,
    owner: *usize,

    fn init(value: u64, owner: *usize) GhostKey {
        owner.* += 1;
        return .{ .value = value, .owner = owner };
    }

    pub fn hash(_: GhostKey) u64 {
        return 0;
    }

    pub fn eql(a: GhostKey, b: GhostKey) bool {
        return a.value == b.value;
    }

    pub fn discard(key: GhostKey) void {
        std.debug.assert(key.owner.* > 0);
        key.owner.* -= 1;
    }
};

fn exercise_colliding_ghost(capacity: usize) !void {
    var owner: usize = 0;
    var ghost = try cache_mod.GhostQueue(GhostKey).init(gpa, capacity);
    var expected: std.ArrayList(u64) = .empty;
    defer expected.deinit(gpa);
    for (0..2048) |step| {
        const value: u64 = (step * 17 + step / 5) % 127;
        const position = std.mem.indexOfScalar(u64, expected.items, value);
        const requested = GhostKey.init(value, &owner);
        try expectEqual(position != null, ghost.forget(requested, requested.hash()));
        requested.discard();
        if (position) |index| _ = expected.orderedRemove(index);
        if (step % 5 != 0) {
            const historical = GhostKey.init(value, &owner);
            ghost.push(historical, historical.hash());
            if (capacity != 0) {
                try expected.insert(gpa, 0, value);
                if (expected.items.len > capacity) expected.shrinkRetainingCapacity(capacity);
            }
        }
        if (step == 777 or step == 1333) {
            ghost.clear();
            expected.clearRetainingCapacity();
        }
        try expect_ghost(&ghost, expected.items);
        // Each live historical key holds one reference.
        try expectEqual(expected.items.len, owner);
    }
    ghost.deinit(gpa);
    try expectEqual(0, owner);
}

fn expect_ghost(ghost: anytype, expected: []const u64) !void {
    const order = try ghost_order(ghost);
    defer gpa.free(order);
    try expectEqual(expected.len, order.len);
    try expectEqual(expected.len, ghost.len());
    try expect(ghost.slots.items.len <= ghost.capacity);
    var previous: ?usize = null;
    for (order, expected) |slot, value| {
        const entry = ghost.slots.items[slot];
        try expectEqual(value, entry.key.?.value);
        try expectEqual(previous, linked(entry.prev));
        try expectEqual(@as(?usize, slot), ghost.find(entry.key.?, 0));
        previous = slot;
    }
    try expectEqual(previous, ghost.tail);
    var free: usize = 0;
    var current = ghost.free_head;
    while (current) |slot| : (current = linked(ghost.slots.items[slot].next)) {
        try expect(ghost.slots.items[slot].key == null);
        free += 1;
        try expect(free <= ghost.slots.items.len);
    }
    try expectEqual(ghost.slots.items.len, order.len + free);
}

test "cache: Ghost collision churn and key ownership" {
    for ([_]usize{ 0, 1, 2, 31 }) |capacity| try exercise_colliding_ghost(capacity);
}

const CollidingKey = struct {
    value: u64,

    pub fn hash(_: CollidingKey) u64 {
        return 0;
    }
};

test "cache: colliding keys share resident and Ghost indexes" {
    var cache = try Cache(CollidingKey, u64).init(gpa, 20);
    defer cache.deinit(gpa);
    for (0..256) |key| {
        _ = cache.put(.{ .value = key }, key);
        try check_invariants(&cache);
    }
    const ghost = try ghost_keys(&cache);
    defer gpa.free(ghost);
    try expectEqual(cache.ghost.capacity, ghost.len);
    for (ghost, 0..) |key, index| {
        try expect(!cache.contains(key));
        for (ghost[index + 1 ..]) |other| try expect(key.value != other.value);
    }

    // Constant hashes still consume only the exact requested history key.
    const requested = ghost[ghost.len / 2];
    _ = cache.put(requested, std.math.maxInt(u64));
    try expectEqual(@as(?u64, std.math.maxInt(u64)), value_of(u64, cache.get(requested)));
    const after = try ghost_keys(&cache);
    defer gpa.free(after);
    for (after) |key| try expect(key.value != requested.value);
    try check_invariants(&cache);
}

test "cache: slice keys keep independent Ghost history" {
    // Rust borrows `&str` keys; here the keys are slices compared by contents.
    const names = [_][]const u8{ "first", "second", "third" };
    var cache = try Cache([]const u8, usize).init(gpa, 2);
    defer cache.deinit(gpa);
    for (names, 0..) |name, value| _ = cache.put(name, value);
    const ghost = try ghost_keys(&cache);
    defer gpa.free(ghost);
    try expectEqual(1, ghost.len);
    try testing.expectEqualStrings("first", ghost[0]);
    const copy = "first".*;
    try expect(!cache.remove(&copy));
    try expectEqual(0, cache.ghost.len());
    try expectEqual(@as(?usize, 2), value_of(usize, cache.get("third")));
    try check_invariants(&cache);
}

// Model fuzz (commonware `utils/fuzz/fuzz_targets/cache.rs`).

/// Keys confined to a small space so a small cache churns and evicts heavily.
const key_space = 64;
/// Clock2Q+ gives Small more than one slot only from capacity 20.
const capacity_max = 48;

const Model = [key_space]?u16;

const Factory = Constant(u16);

fn fuzz_step(
    generator: *rng.FuzzRng,
    cache: *Cache(u8, u16),
    model: *Model,
) !void {
    const key = rng.range_less_than(generator, u8, 0, key_space);
    const value = generator.next_u32() & 0xffff;
    const v: u16 = @intCast(value);
    switch (rng.range_less_than(generator, u8, 0, 10)) {
        0 => try expectEqual(value_of(u16, cache.peek(key)), value_of(u16, cache.get(key))),
        1 => try expectEqual(cache.contains(key), cache.peek(key) != null),
        2 => if (cache.get_mut(key)) |slot| {
            slot.* = v;
            model[key] = v;
        },
        3 => {
            _ = cache.put(key, v);
            model[key] = v;
            try expectEqual(@as(?u16, v), value_of(u16, cache.peek(key)));
        },
        4 => {
            const stored = cache.get_or_insert_with(key, Factory{ .value = v }).*;
            model[key] = stored;
            try expectEqual(@as(?u16, stored), value_of(u16, cache.peek(key)));
        },
        5 => {
            cache.get_or_insert_mut(key, Factory{ .value = v }).value.* = v;
            model[key] = v;
            try expectEqual(@as(?u16, v), value_of(u16, cache.peek(key)));
        },
        6 => {
            const had = cache.contains(key);
            try expectEqual(had, cache.remove(key));
            model[key] = null;
            try expect(!cache.contains(key));
        },
        7 => {
            cache.retain(Below{ .bound = key });
            for (model[key..]) |*entry| entry.* = null;
        },
        8 => {
            cache.clear();
            model.* = @splat(null);
            try expect(cache.is_empty());
        },
        9 => try expect(cache.len() <= cache.capacity),
        else => unreachable,
    }
}

fn fuzz_cache(_: void, generator: *rng.FuzzRng) !void {
    const capacity = rng.range_at_most(generator, usize, 1, capacity_max);
    var cache = try Cache(u8, u16).init(gpa, capacity);
    defer cache.deinit(gpa);
    if (rng.boolean(generator)) cache.prefill(Factory{ .value = 0 });
    // The last value written for each logically present key; an evicted key is absent.
    var model: Model = @splat(null);
    for (0..rng.range_at_most(generator, u32, 0, 256)) |_| {
        try fuzz_step(generator, &cache, &model);
        try expect(cache.len() <= capacity);
        var present: usize = 0;
        for (0..key_space) |index| {
            const key: u8 = @intCast(index);
            const resident = cache.peek(key);
            try expectEqual(cache.contains(key), resident != null);
            if (resident) |stored| {
                present += 1;
                try expectEqual(model[index], stored.*);
            }
        }
        try expectEqual(present, cache.len());
        try expectEqual(present == 0, cache.is_empty());
        // Like commonware's `exercise_cache`, check the structure after every operation.
        try check_invariants(&cache);
    }
}

test "fuzz cache" {
    try fuzz.run({}, fuzz_cache, 0x6361_6368, 200);
}

/// A key that counts how often the cache hashes it.
const CountingKey = struct {
    id: u32,
    hashes: *u32,

    pub fn hash(key: CountingKey) u64 {
        key.hashes.* += 1;
        return std.hash.Wyhash.hash(0, std.mem.asBytes(&key.id));
    }

    pub fn eql(a: CountingKey, b: CountingKey) bool {
        return a.id == b.id;
    }
};

test "cache: each operation hashes a key exactly once (shared_hashes_without_rehash_steps)" {
    var counts: [3]u32 = @splat(0);
    const one: CountingKey = .{ .id = 1, .hashes = &counts[0] };
    const two: CountingKey = .{ .id = 2, .hashes = &counts[1] };
    const three: CountingKey = .{ .id = 3, .hashes = &counts[2] };
    var cache = try Cache(CountingKey, usize).init(gpa, 2);
    defer cache.deinit(gpa);
    _ = cache.put(one, 1);
    _ = cache.put(two, 2);
    try expectEqual([3]u32{ 1, 1, 0 }, counts);
    // Key 3 replaces Small's key 1: the incoming key and the victim moved to Ghost each hash
    // once across their resident and Ghost operations. Ghost reuses the victim's stored hash;
    // the victim's hash comes from the eviction's safety check, so without it there is none.
    const victim: u32 = @intFromBool(std.debug.runtime_safety);
    _ = cache.put(three, 3);
    try expectEqual([3]u32{ 1 + victim, 1, 1 }, counts);
    // A nonresident removal shares the resident-miss hash with the Ghost discard.
    try expect(!cache.remove(one));
    try expectEqual(2 + victim, counts[0]);
    // Retain and clear work from slot ownership and hash nothing.
    const not_three = struct {
        pub fn keep(key: CountingKey, _: *const usize) bool {
            return key.id != 3;
        }
    };
    cache.retain(not_three);
    cache.clear();
    try expectEqual([3]u32{ 2 + victim, 1, 1 }, counts);
}

/// A key whose equality ignores `metadata` and whose hash is constant.
const MetadataKey = struct {
    id: u32,
    metadata: u32,

    pub fn hash(_: MetadataKey) u64 {
        return 0;
    }

    pub fn eql(a: MetadataKey, b: MetadataKey) bool {
        return a.id == b.id;
    }
};

test "cache: a Ghost hit stores the incoming key (non_clone_keys_keep_incoming_metadata)" {
    var cache = try Cache(MetadataKey, u32).init(gpa, 2);
    defer cache.deinit(gpa);
    const zero = Constant(u32){ .value = 0 };
    const original = cache.get_or_insert_mut(.{ .id = 0, .metadata = 10 }, zero);
    _ = cache.put(.{ .id = 1, .metadata = 11 }, 1);
    _ = cache.put(.{ .id = 2, .metadata = 12 }, 2);
    const probe: MetadataKey = .{ .id = 0, .metadata = 0 };
    try expectEqual(@as(?*const u32, null), cache.get_at(original.slot, probe));
    try check_invariants(&cache);

    // The historical key is consumed and the caller's key becomes the resident one.
    const hit = cache.get_or_insert_mut(.{ .id = 0, .metadata = 20 }, zero);
    hit.value.* = 20;
    try expectEqual(@as(?u32, 20), value_of(u32, cache.get_at(hit.slot, probe)));
    const Check = struct {
        pub fn keep(key: MetadataKey, value: *const u32) bool {
            if (key.id == 0) {
                std.debug.assert(key.metadata == 20);
                std.debug.assert(value.* == 20);
            }
            return true;
        }
    };
    cache.retain(Check);
    const resident = cache.slots.items[hit.slot].key;
    try expectEqual(@as(u32, 20), resident.metadata);
    try check_invariants(&cache);

    try expect(cache.remove(probe));
    try expectEqual(@as(?*const u32, null), cache.get_at(hit.slot, probe));
    const reused = cache.get_or_insert_mut(.{ .id = 3, .metadata = 30 }, zero);
    try expectEqual(hit.slot, reused.slot);
    try expectEqual(@as(u32, 20), reused.value.*);
    try check_invariants(&cache);
    cache.clear();
    try check_invariants(&cache);
}
