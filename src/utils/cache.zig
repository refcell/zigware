//! A fixed-capacity key-value cache using Clock2Q+ replacement (commonware
//! `utils/src/cache.rs`, https://arxiv.org/abs/2511.21958).
//!
//! Clock2Q+ separates residents into a Small probation queue and a Main CLOCK ring. New
//! entries enter Small, where hits outside a correlation window earn promotion to Main. Main
//! gives referenced entries a second chance before eviction. A bounded Ghost queue records
//! keys evicted from Small; a later request for one of these keys consumes its history and
//! enters Main directly. During warm-up, cold entries fill Small first and then Main.
//!
//! For capacity `C`, Small is `max(C / 10, 1)` when `C > 1`, Main gets the remainder, and
//! Ghost is `C / 2`. The newest half of Small, rounded up, forms the correlation window; hits
//! inside it are ignored. Admission age advances even when entries are removed. Capacity one
//! uses Main alone.
//!
//! A resident keeps its numeric slot until removal or eviction, including when it moves from
//! Small to Main; `get_at` validates liveness and the full key, so stale hints miss. Slots are
//! reused in place: `remove` and `retain` keep detached values for later insertion,
//! `get_or_insert_mut` returns a reused slot's stale value for overwriting, and `prefill`
//! allocates every value up front.
//!
//! Zig specifics: every buffer is allocated by `init`, so no operation allocates. The resident
//! and Ghost indexes are `handles.Table(usize)`s of slot IDs whose keys live in the slots.
//! Keys hash with a fixed-seed Wyhash (deterministic; use keys an adversary cannot choose, or
//! give `K` a `hash` decl) and compare with `K.eql`, `std.mem.eql` for slices, or
//! `std.meta.eql`. Rust's drops become hooks: the cache passes a key or value it drops to
//! `K.discard` / `V.discard` when declared. Hits record use in an atomic byte, so `get` and
//! `get_at` may run concurrently with each other (not with mutations).

const std = @import("std");
const handles = @import("handles.zig");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

/// Sentinel for a cache-owned slot with no neighbor.
pub const UNLINKED: usize = std.math.maxInt(usize);
/// Low bits available for the modular Small admission generation.
pub const ADMISSION_GENERATION_MASK: usize = std.math.maxInt(usize) >> 2;
/// Bit offset of the resident location tag.
const LOCATION_SHIFT: std.math.Log2Int(usize) = @bitSizeOf(usize) - 2;
/// Slot-state bit set after an eligible resident hit.
pub const REFERENCED: u8 = 1 << 0;
/// Slot-state bit set while a Small resident is in the correlation window.
pub const CORRELATED: u8 = 1 << 1;
/// Seed of the key hash.
const hash_seed: u64 = 0x636f_6d6d_6f6e_7761;

pub fn linked(slot: usize) ?usize {
    return if (slot == UNLINKED) null else slot;
}

fn has_decl(comptime T: type, comptime name: []const u8) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => @hasDecl(T, name),
        else => false,
    };
}

/// The hash of `key`: `K.hash(key)` when declared, else a seeded Wyhash of its contents.
pub fn key_hash(comptime K: type, key: K) u64 {
    if (comptime has_decl(K, "hash")) return K.hash(key);
    const info = @typeInfo(K);
    if (comptime info == .int and info.int.bits <= 64) return integer_hash(key);
    var hasher = std.hash.Wyhash.init(hash_seed);
    std.hash.autoHashStrat(&hasher, key, .Deep);
    return hasher.final();
}

/// An integer key's hash: one folded 64x64-bit multiply (foldhash's integer step). The fold
/// XORs the product's high half into its low half, so both the low bits (home slot) and the
/// top byte (fingerprint) depend on every key bit. The second multiply and rotate of ahash's
/// non-AES fallback, ported from commonware's hasher, cost a fifth of a lookup and spread
/// sequential, shifted, and strided keys no better.
fn integer_hash(key: anytype) u64 {
    const multiple: u64 = 6364136223846793005;
    const value: u64 = @as(@Int(.unsigned, @bitSizeOf(@TypeOf(key))), @bitCast(key));
    return folded_multiply(value ^ hash_seed, multiple);
}

fn folded_multiply(a: u64, b: u64) u64 {
    const product = @as(u128, a) * b;
    return @as(u64, @truncate(product)) ^ @as(u64, @truncate(product >> 64));
}

/// Key equality: `K.eql` when declared, contents for slices, else `std.meta.eql`.
pub fn key_eql(comptime K: type, a: K, b: K) bool {
    if (comptime has_decl(K, "eql")) return K.eql(a, b);
    const info = @typeInfo(K);
    if (info == .pointer and info.pointer.size == .slice) {
        return std.mem.eql(info.pointer.child, a, b);
    }
    return std.meta.eql(a, b);
}

/// Passes a dropped key or value to `T.discard`, when declared (Rust `Drop`).
fn discard(comptime T: type, value: T) void {
    if (comptime has_decl(T, "discard")) T.discard(value);
}

/// Where a resident slot participates in the replacement policy.
pub const Location = enum(u2) {
    free = 0,
    small = 1,
    main = 2,

    pub fn pack(location: Location, admission_generation: usize) usize {
        const tag: usize = @backingInt(location);
        return (tag << LOCATION_SHIFT) | (admission_generation & ADMISSION_GENERATION_MASK);
    }
};

/// Cold topology for a stable cache slot.
pub const ResidentSlot = struct {
    /// Previous entry toward the head of Small, or in Main's circular ring.
    prev: usize = UNLINKED,
    /// Next entry toward the tail of Small, or in Main's circular ring.
    next: usize = UNLINKED,
    /// Location tag in the high bits and Small admission generation in the low bits.
    location_and_admission: usize = 0,

    fn has_location(slot: ResidentSlot, expected: Location) bool {
        return slot.location_and_admission & ~ADMISSION_GENERATION_MASK == expected.pack(0);
    }

    pub fn location(slot: ResidentSlot) Location {
        const tag = slot.location_and_admission >> LOCATION_SHIFT;
        assert(tag <= 2);
        return @fromBackingInt(@intCast(tag));
    }

    pub fn admitted_at(slot: ResidentSlot) usize {
        return slot.location_and_admission & ADMISSION_GENERATION_MASK;
    }
};

comptime {
    assert(@sizeOf(ResidentSlot) == 3 * @sizeOf(usize));
    assert(Location.free.pack(0) == 0);
}

/// Resident partition selected for an incoming key.
pub const Admission = enum { small, main };

/// Storage action selected for one confirmed-miss insertion.
const InsertionPlan = union(enum) {
    /// Use unused cache capacity.
    vacant,
    /// Replace one resident.
    evict: usize,
    /// Promote a Small resident and replace a separate Main resident.
    promote_then_evict: struct { promoted: usize, victim: usize },

    fn victim(plan: InsertionPlan) ?usize {
        return switch (plan) {
            .vacant => null,
            .evict => |slot| slot,
            .promote_then_evict => |transition| transition.victim,
        };
    }
};

/// Replacement state stored inline with each slot: the correlation marker and reference bit.
/// Relaxed atomics: the bits affect only replacement decisions.
pub const SlotState = struct {
    bits: std.atomic.Value(u8) = .init(0),

    fn init(admission: Admission) SlotState {
        return .{ .bits = .init(if (admission == .small) CORRELATED else 0) };
    }

    pub fn load(state: *const SlotState) u8 {
        return state.bits.load(.monotonic);
    }

    /// Records a hit; hits inside the correlation window are ignored.
    fn record_hit(state: *SlotState) void {
        if (state.load() & (CORRELATED | REFERENCED) != 0) return;
        state.bits.store(REFERENCED, .monotonic);
    }

    fn earned_promotion(state: *const SlotState) bool {
        return state.load() & (CORRELATED | REFERENCED) == REFERENCED;
    }

    /// Consumes one Main reference bit.
    fn take_reference(state: *SlotState) bool {
        if (state.load() & REFERENCED == 0) return false;
        state.bits.store(0, .monotonic);
        return true;
    }

    fn reset(state: *SlotState) void {
        state.bits.store(0, .monotonic);
    }
};

/// State and endpoints for the Small queue.
pub const SmallQueue = struct {
    capacity: usize,
    /// Admission age at which a resident leaves the correlation window.
    correlation_window: usize,
    /// Newest Small resident.
    /// Endpoints are `UNLINKED` when absent: an optional `usize` is 16 bytes, and its padding
    /// stores blocked store-to-load forwarding on every put (5.5 blocks per put on Zen 5).
    head: usize = UNLINKED,
    /// Oldest Small resident.
    tail: usize = UNLINKED,
    /// Oldest resident still inside the correlation window.
    young_tail: usize = UNLINKED,
    /// Modular count of Small admissions, including removed entries.
    admissions: usize = 0,
    len: usize = 0,

    fn init(capacity: usize) SmallQueue {
        return .{ .capacity = capacity, .correlation_window = (capacity + 1) / 2 };
    }

    /// Attaches a free slot at the queue head; `entries[slot].state` holds its hit bits.
    fn push(small: *SmallQueue, entries: anytype, slots: []ResidentSlot, slot: usize) void {
        // Admission count, rather than queue length, preserves correlation age across removal.
        small.admissions = (small.admissions +% 1) & ADMISSION_GENERATION_MASK;
        const old_head = small.head;
        const entry = &slots[slot];
        assert(entry.has_location(.free));
        entry.prev = UNLINKED;
        entry.next = old_head;
        entry.location_and_admission = Location.small.pack(small.admissions);
        if (old_head != UNLINKED) slots[old_head].prev = slot else small.tail = slot;
        small.head = slot;
        small.len += 1;
        assert(small.len <= small.capacity);

        // Only the oldest correlated survivor can leave the window after one new admission.
        if (small.young_tail == UNLINKED) small.young_tail = slot;
        const demoted = small.young_tail;
        const age = (small.admissions -% slots[demoted].admitted_at()) & ADMISSION_GENERATION_MASK;
        if (age < small.correlation_window) return;
        const boundary = slots[demoted].prev;
        assert(boundary != UNLINKED);
        // Discard references made inside the window: only a later hit promotes.
        entries[demoted].state.reset();
        slots[demoted].location_and_admission = Location.small.pack(0);
        small.young_tail = boundary;
    }

    /// Detaches a resident and repairs the queue and correlation boundary.
    fn unlink(small: *SmallQueue, slots: []ResidentSlot, slot: usize) void {
        assert(slots[slot].has_location(.small));
        const prev = slots[slot].prev;
        const next = slots[slot].next;
        if (prev != UNLINKED) slots[prev].next = next else small.head = next;
        if (next != UNLINKED) slots[next].prev = prev else small.tail = prev;
        assert(small.len > 0);
        small.len -= 1;
        // Removing the boundary shrinks the window without making older residents young.
        if (small.young_tail == slot) small.young_tail = prev;
        slots[slot] = .{};
    }

    fn clear(small: *SmallQueue) void {
        small.* = .init(small.capacity);
    }
};

/// Circular resident topology and the CLOCK hand for Main.
pub const MainRing = struct {
    capacity: usize,
    /// Next resident considered for eviction.
    /// `UNLINKED` when Main is empty.
    hand: usize = UNLINKED,
    len: usize = 0,

    /// Sweeps the hand to the first unreferenced resident, consuming reference bits.
    fn select(main: *MainRing, entries: anytype, slots: []const ResidentSlot) usize {
        // Each referenced resident passed loses its bit, so a full turn finds a victim.
        for (0..main.len + 1) |_| {
            const slot = main.hand;
            assert(slot != UNLINKED);
            if (!entries[slot].state.take_reference()) return slot;
            main.hand = slots[slot].next;
        }
        unreachable; // The ring holds `len` residents, each passed at most once with a bit.
    }

    const main_tag = Location.main.pack(0);

    /// Attaches a free slot immediately before the hand, so the sweep reaches it last.
    fn push(main: *MainRing, slots: []ResidentSlot, slot: usize) void {
        assert(main.len < main.capacity);
        assert(slots[slot].has_location(.free));
        const hand = main.hand;
        if (hand == UNLINKED) {
            slots[slot] = .{ .prev = slot, .next = slot, .location_and_admission = main_tag };
            main.hand = slot;
            main.len = 1;
            return;
        }
        const prev = slots[hand].prev;
        assert(prev != UNLINKED);
        slots[slot] = .{ .prev = prev, .next = hand, .location_and_admission = main_tag };
        slots[prev].next = slot;
        slots[hand].prev = slot;
        main.len += 1;
    }

    /// Detaches a resident and advances the hand past it.
    fn unlink(main: *MainRing, slots: []ResidentSlot, slot: usize) void {
        assert(slots[slot].has_location(.main));
        if (main.len == 1) {
            assert(main.hand == slot);
            main.hand = UNLINKED;
            main.len = 0;
        } else {
            const prev = slots[slot].prev;
            const next = slots[slot].next;
            assert(prev != UNLINKED and next != UNLINKED);
            slots[prev].next = next;
            slots[next].prev = prev;
            if (main.hand == slot) main.hand = next;
            main.len -= 1;
        }
        slots[slot] = .{};
    }

    fn clear(main: *MainRing) void {
        main.hand = UNLINKED;
        main.len = 0;
    }
};

/// Exact bounded history of keys recently evicted from Small.
pub fn GhostQueue(comptime K: type) type {
    return struct {
        const Self = @This();

        /// Exact key membership by queue position.
        index: handles.Table(usize),
        slots: std.ArrayList(Slot),
        /// First detached position, linked through `Slot.next`.
        /// Endpoints are `UNLINKED` when absent, as `SmallQueue`'s.
        free_head: usize = UNLINKED,
        /// Newest historical entry.
        head: usize = UNLINKED,
        /// Oldest historical entry.
        tail: usize = UNLINKED,
        capacity: usize,

        pub const Slot = struct {
            /// Historical key, or null when the slot is free.
            key: ?K,
            prev: usize,
            /// Next toward the tail, or the next free slot when `key` is null.
            next: usize,
        };

        pub fn init(gpa: Allocator, capacity: usize) Allocator.Error!Self {
            // Room for twice the entries, as commonware's index: short runs keep misses cheap.
            var index = try handles.Table(usize).init_capacity(gpa, capacity * 2);
            errdefer index.deinit(gpa);
            return .{
                .index = index,
                .slots = try .initCapacity(gpa, capacity),
                .capacity = capacity,
            };
        }

        pub fn deinit(ghost: *Self, gpa: Allocator) void {
            ghost.clear();
            ghost.index.deinit(gpa);
            ghost.slots.deinit(gpa);
        }

        pub fn len(ghost: *const Self) usize {
            return ghost.index.len;
        }

        /// Adds an evicted Small key at the head, dropping the oldest when full.
        pub fn push(ghost: *Self, key: K, hash: u64) void {
            if (ghost.capacity == 0) return discard(K, key);
            var displaced: ?K = null;
            const slot = if (ghost.free_head != UNLINKED) slot: {
                const free = ghost.free_head;
                ghost.free_head = ghost.slots.items[free].next;
                break :slot free;
            } else if (ghost.slots.items.len < ghost.capacity) slot: {
                ghost.slots.appendAssumeCapacity(.{
                    .key = null,
                    .prev = UNLINKED,
                    .next = UNLINKED,
                });
                break :slot ghost.slots.items.len - 1;
            } else slot: {
                const oldest = ghost.tail;
                assert(oldest != UNLINKED);
                const historical = ghost.slots.items[oldest].key.?;
                assert(ghost.index.remove(key_hash(K, historical), oldest));
                displaced = ghost.unlink(oldest);
                break :slot oldest;
            };
            const old_head = ghost.head;
            const entry = &ghost.slots.items[slot];
            assert(entry.key == null);
            entry.* = .{ .key = key, .prev = UNLINKED, .next = old_head };
            if (old_head != UNLINKED) {
                ghost.slots.items[old_head].prev = slot;
            } else ghost.tail = slot;
            ghost.head = slot;
            ghost.index.insert_assume_capacity(hash, slot);
            if (displaced) |historical| discard(K, historical);
        }

        pub fn find(ghost: *const Self, key: K, hash: u64) ?usize {
            return ghost.index.find(hash, KeyMatcher{ .slots = ghost.slots.items, .key = key });
        }

        const KeyMatcher = struct {
            slots: []const Slot,
            key: K,

            pub fn matches(matcher: KeyMatcher, slot: usize) bool {
                return key_eql(K, matcher.slots[slot].key.?, matcher.key);
            }
        };

        /// Removes the history of `key`; returns whether it was present.
        pub fn forget(ghost: *Self, key: K, hash: u64) bool {
            const slot = ghost.find(key, hash) orelse return false;
            assert(ghost.index.remove(hash, slot));
            const historical = ghost.unlink(slot);
            ghost.slots.items[slot].next = ghost.free_head;
            ghost.free_head = slot;
            discard(K, historical);
            return true;
        }

        /// Detaches one historical entry and returns its key.
        fn unlink(ghost: *Self, slot: usize) K {
            const slots = ghost.slots.items;
            const prev = slots[slot].prev;
            const next = slots[slot].next;
            if (prev != UNLINKED) slots[prev].next = next else ghost.head = next;
            if (next != UNLINKED) slots[next].prev = prev else ghost.tail = prev;
            const key = slots[slot].key.?;
            slots[slot] = .{ .key = null, .prev = UNLINKED, .next = UNLINKED };
            return key;
        }

        pub fn clear(ghost: *Self) void {
            for (ghost.slots.items) |slot| if (slot.key) |key| discard(K, key);
            ghost.index.clear();
            ghost.slots.clearRetainingCapacity();
            ghost.free_head = UNLINKED;
            ghost.head = UNLINKED;
            ghost.tail = UNLINKED;
        }
    };
}

pub fn Cache(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        /// Resident membership: slot IDs, keyed by the hash of each slot's key.
        index: handles.Table(usize),
        /// Stable keys, reusable values, and inline hit state; grows to `capacity`.
        slots: std.ArrayList(Entry),
        /// Slots detached by remove/retain or prepared by prefill (a stack).
        free: std.ArrayList(usize),
        capacity: usize,
        /// Queue links and admission ages by slot.
        topology: []ResidentSlot,
        small: SmallQueue,
        main: MainRing,
        ghost: GhostQueue(K),

        pub const Entry = struct {
            key: K,
            value: V,
            state: SlotState,
            /// Indexed and resolvable by `get_at`.
            live: bool,
            /// `key` holds a key (false for prefilled slots never used).
            keyed: bool,
            /// The hash of `key` when it was inserted, so `retain` detaches without
            /// rehashing (commonware's table retain works from slot ownership).
            hash: u64 = 0,
        };

        /// What `get_or_insert_mut` returns: the slot and its value.
        pub const SlotValue = struct { slot: usize, value: *V };

        /// An empty cache with room for `capacity` residents; allocates everything up front.
        pub fn init(gpa: Allocator, capacity: usize) Allocator.Error!Self {
            assert(capacity > 0);
            const small_capacity = if (capacity == 1) 0 else @max(capacity / 10, 1);
            // Room for twice the residents, as commonware's index (`with_capacity(2 * capacity)`):
            // at a quarter load or less, most runs end at their home slot, so misses stay cheap.
            var index = try handles.Table(usize).init_capacity(gpa, capacity * 2);
            errdefer index.deinit(gpa);
            var slots: std.ArrayList(Entry) = try .initCapacity(gpa, capacity);
            errdefer slots.deinit(gpa);
            var free: std.ArrayList(usize) = try .initCapacity(gpa, capacity);
            errdefer free.deinit(gpa);
            const topology = try gpa.alloc(ResidentSlot, capacity);
            errdefer gpa.free(topology);
            @memset(topology, .{});
            return .{
                .index = index,
                .slots = slots,
                .free = free,
                .capacity = capacity,
                .topology = topology,
                .small = .init(small_capacity),
                .main = .{ .capacity = capacity - small_capacity },
                .ghost = try .init(gpa, capacity / 2),
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.drop_slots();
            self.ghost.deinit(gpa);
            self.index.deinit(gpa);
            self.slots.deinit(gpa);
            self.free.deinit(gpa);
            gpa.free(self.topology);
            self.* = undefined;
        }

        pub fn len(self: *const Self) usize {
            return self.index.len;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.index.len == 0;
        }

        /// Whether `key` is resident, without recording use.
        pub fn contains(self: *const Self, key: K) bool {
            return self.find_slot(key, key_hash(K, key)) != null;
        }

        /// The value for `key` without recording use.
        pub fn peek(self: *const Self, key: K) ?*const V {
            const slot = self.find_slot(key, key_hash(K, key)) orelse return null;
            return &self.slots.items[slot].value;
        }

        /// The value for `key`, recording use. Safe to call concurrently with other hits.
        pub fn get(self: *Self, key: K) ?*const V {
            return self.get_mut(key);
        }

        /// The value in `slot` if it holds `key` as a live entry, recording use. Stale,
        /// freed, and out-of-range slots miss.
        pub fn get_at(self: *Self, slot: usize, key: K) ?*const V {
            if (slot >= self.slots.items.len) return null;
            const entry = &self.slots.items[slot];
            if (!entry.live or !key_eql(K, entry.key, key)) return null;
            entry.state.record_hit();
            return &entry.value;
        }

        /// The value for `key`, recording use.
        pub fn get_mut(self: *Self, key: K) ?*V {
            const slot = self.find_slot(key, key_hash(K, key)) orelse return null;
            const entry = &self.slots.items[slot];
            entry.state.record_hit();
            return &entry.value;
        }

        /// Inserts `value` for `key`. On a hit, records use and returns the previous value
        /// (the argument key is dropped); otherwise claims vacant capacity or evicts.
        pub fn put(self: *Self, key: K, value: V) ?V {
            const hash = key_hash(K, key);
            if (self.hit(key, hash)) |slot| {
                const entry = &self.slots.items[slot];
                const previous = entry.value;
                entry.value = value;
                return previous;
            }
            _ = self.insert(key, hash, value, no_factory);
            return null;
        }

        /// The value for `key`, inserting `factory.make()` on a miss (not called on a hit).
        pub fn get_or_insert_with(self: *Self, key: K, factory: anytype) *const V {
            const hash = key_hash(K, key);
            const slot = self.hit(key, hash) orelse
                self.insert(key, hash, factory.make(), no_factory);
            return &self.slots.items[slot].value;
        }

        /// Like `get_or_insert_with` with a fallible `factory.make()`: an error inserts
        /// nothing and leaves the cache (including Ghost history) unchanged.
        pub fn try_get_or_insert_with(
            self: *Self,
            key: K,
            factory: anytype,
        ) MakeError(@TypeOf(factory))!*const V {
            const hash = key_hash(K, key);
            const slot = self.hit(key, hash) orelse slot: {
                const value = factory.make() catch |err| {
                    discard(K, key);
                    return err;
                };
                break :slot self.insert(key, hash, value, no_factory);
            };
            return &self.slots.items[slot].value;
        }

        /// The error set of `factory.make()`.
        fn MakeError(comptime Factory: type) type {
            const Maker = switch (@typeInfo(Factory)) {
                .pointer => |pointer| pointer.child,
                else => Factory,
            };
            const Return = @typeInfo(@TypeOf(Maker.make)).@"fn".return_type.?;
            return @typeInfo(Return).error_union.error_set;
        }

        /// The slot for `key` and its value. On a hit, records use; on a miss into a reused
        /// slot, the value is that slot's stale value, for the caller to overwrite. Only when
        /// the cache grows is `factory.make()` called.
        pub fn get_or_insert_mut(self: *Self, key: K, factory: anytype) SlotValue {
            const hash = key_hash(K, key);
            const slot = self.hit(key, hash) orelse self.insert(key, hash, null, factory);
            return .{ .slot = slot, .value = &self.slots.items[slot].value };
        }

        /// Removes `key`, keeping its slot and value for reuse; returns whether it was
        /// present. An absent key's Ghost history is forgotten.
        pub fn remove(self: *Self, key: K) bool {
            const hash = key_hash(K, key);
            const slot = self.find_slot(key, hash) orelse {
                _ = self.ghost.forget(key, hash);
                return false;
            };
            self.detach(slot, hash);
            return true;
        }

        /// Keeps only the residents for which `predicate.keep(key, *const V)` is true;
        /// dropped residents' slots and values are kept for reuse.
        pub fn retain(self: *Self, predicate: anytype) void {
            for (self.slots.items, 0..) |*entry, slot| {
                if (!entry.live or predicate.keep(entry.key, &entry.value)) continue;
                self.detach(slot, entry.hash);
            }
        }

        /// Removes all entries and Ghost history, dropping every key and value.
        pub fn clear(self: *Self) void {
            self.drop_slots();
            self.index.clear();
            self.free.clearRetainingCapacity();
            @memset(self.topology, .{});
            self.small.clear();
            self.main.clear();
            self.ghost.clear();
            assert(self.is_empty());
        }

        /// Allocates every remaining slot with `factory.make()` and leaves them free, so
        /// later inserts reuse them in ascending slot order.
        pub fn prefill(self: *Self, factory: anytype) void {
            const start = self.free.items.len;
            while (self.slots.items.len < self.capacity) {
                const slot = self.slots.items.len;
                self.slots.appendAssumeCapacity(.{
                    .key = undefined,
                    .value = factory.make(),
                    .state = .{},
                    .live = false,
                    .keyed = false,
                });
                self.free.appendAssumeCapacity(slot);
            }
            // The free list pops from the back: hand out new slots in ascending order.
            std.mem.reverse(usize, self.free.items[start..]);
        }

        pub fn find_slot(self: *const Self, key: K, hash: u64) ?usize {
            return self.index.find(hash, KeyMatcher{ .slots = self.slots.items, .key = key });
        }

        const KeyMatcher = struct {
            slots: []const Entry,
            key: K,

            pub fn matches(matcher: KeyMatcher, slot: usize) bool {
                return key_eql(K, matcher.slots[slot].key, matcher.key);
            }
        };

        /// On a hit, records use, drops the argument key, and returns the slot.
        fn hit(self: *Self, key: K, hash: u64) ?usize {
            const slot = self.find_slot(key, hash) orelse return null;
            self.slots.items[slot].state.record_hit();
            discard(K, key);
            return slot;
        }

        /// Detaches a resident, keeping its slot and value for reuse.
        fn detach(self: *Self, slot: usize, hash: u64) void {
            assert(self.index.remove(hash, slot));
            _ = self.unlink_resident(slot);
            self.slots.items[slot].live = false;
            self.free.appendAssumeCapacity(slot);
        }

        fn drop_slots(self: *Self) void {
            for (self.slots.items) |entry| {
                if (entry.keyed) discard(K, entry.key);
                discard(V, entry.value);
            }
            self.slots.clearRetainingCapacity();
        }

        const no_factory = struct {
            fn make() V {
                unreachable; // Callers pass a value, so no slot needs a fresh one.
            }
        };

        /// Installs an absent key with `value`, or reuses storage (`factory.make()` only
        /// when the cache grows). Returns its slot.
        fn insert(self: *Self, key: K, hash: u64, value: ?V, factory: anytype) usize {
            const ghost_hit = self.ghost.forget(key, hash);
            const has_vacancy = self.free.items.len > 0 or
                self.slots.items.len < self.capacity;
            const admission = self.choose_admission(ghost_hit, has_vacancy);
            const plan = self.plan_insertion(admission, has_vacancy);

            // Remove the victim's index entry while its key is installed. A Small victim's
            // key moves to Ghost with the same hash.
            var historical_hash: ?u64 = null;
            const slot = if (plan.victim()) |victim| slot: {
                // The slot keeps its key's hash, so the victim is not rehashed.
                const victim_hash = self.slots.items[victim].hash;
                // Rehashing costs a hash per eviction, so it runs only with safety checks.
                if (std.debug.runtime_safety) {
                    assert(victim_hash == key_hash(K, self.slots.items[victim].key));
                }
                assert(self.index.remove(victim_hash, victim));
                if (self.unlink_resident(victim) == .small) historical_hash = victim_hash;
                break :slot victim;
            } else self.free.pop() orelse self.slots.items.len;

            if (plan == .promote_then_evict) {
                const promoted = plan.promote_then_evict.promoted;
                self.small.unlink(self.topology, promoted);
                self.slots.items[promoted].state.reset();
                self.main.push(self.topology, promoted);
            }

            var displaced_key: ?K = null;
            var displaced_value: ?V = null;
            if (slot == self.slots.items.len) {
                self.slots.appendAssumeCapacity(.{
                    .key = key,
                    .value = value orelse factory.make(),
                    .state = .init(admission),
                    .live = true,
                    .keyed = true,
                    .hash = hash,
                });
            } else {
                const entry = &self.slots.items[slot];
                if (entry.keyed) displaced_key = entry.key;
                if (value != null) displaced_value = entry.value;
                entry.key = key;
                if (value) |new_value| entry.value = new_value;
                entry.state = .init(admission);
                entry.live = true;
                entry.keyed = true;
                entry.hash = hash;
            }
            switch (admission) {
                .small => self.small.push(self.slots.items, self.topology, slot),
                .main => self.main.push(self.topology, slot),
            }
            self.index.insert_assume_capacity(hash, slot);

            // Bookkeeping is complete before keys and values are dropped.
            if (historical_hash) |victim_hash| {
                self.ghost.push(displaced_key.?, victim_hash);
            } else if (displaced_key) |old_key| discard(K, old_key);
            if (displaced_value) |old_value| discard(V, old_value);
            return slot;
        }

        /// The resident partition for an incoming key.
        fn choose_admission(self: *const Self, ghost_hit: bool, has_vacancy: bool) Admission {
            // A Ghost hit bypasses Small. During warm-up, Small fills to its target before
            // more vacant slots go to Main.
            if (ghost_hit or self.small.capacity == 0 or
                (has_vacancy and self.small.len >= self.small.capacity)) return .main;
            return .small;
        }

        /// Plans the resident transition for one confirmed-miss insertion.
        fn plan_insertion(self: *Self, admission: Admission, has_vacancy: bool) InsertionPlan {
            switch (admission) {
                .small => {
                    if (has_vacancy) return .vacant;
                    const tail = self.small.tail; // A full cache has a Small tail.
                    assert(tail != UNLINKED);
                    if (!self.slots.items[tail].state.earned_promotion()) {
                        return .{ .evict = tail };
                    }
                    // A full cache with bounded partitions has a full Main: promote the tail
                    // while the incoming entry reuses a Main victim.
                    assert(self.main.len == self.main.capacity);
                    const victim = self.main.select(self.slots.items, self.topology);
                    return .{ .promote_then_evict = .{ .promoted = tail, .victim = victim } };
                },
                .main => {
                    if (self.main.len == self.main.capacity) {
                        return .{ .evict = self.main.select(self.slots.items, self.topology) };
                    }
                    // Main grows only while the cache has unused capacity.
                    assert(has_vacancy);
                    return .vacant;
                },
            }
        }

        /// Detaches a resident and returns its previous partition.
        fn unlink_resident(self: *Self, slot: usize) Location {
            const location = self.topology[slot].location();
            switch (location) {
                .small => self.small.unlink(self.topology, slot),
                .main => self.main.unlink(self.topology, slot),
                .free => unreachable, // A resident slot is in Small or Main.
            }
            return location;
        }
    };
}

test {
    _ = @import("cache_test.zig");
}
