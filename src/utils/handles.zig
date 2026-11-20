//! An open-addressing multimap from 64-bit hashes to caller-owned handles (commonware
//! `utils/src/handles.rs`).
//!
//! `Table` never stores keys. Each slot holds a handle and a `u32` of metadata: the entry's
//! probe displacement (high 24 bits) and a one-byte fingerprint of its hash (the hash's top
//! byte). The low bits of a hash select its home slot. A lookup is a candidate generator: it
//! yields every handle inserted under the hash, plus any whose different hash shares the home
//! slot and fingerprint, so callers confirm each candidate against the key it resolves to.
//! Hashes must be well distributed in both the low bits and the top byte.
//!
//! Within each run of occupied slots, entries are sorted by home slot (Robin Hood order), so
//! a lookup stops at an empty slot or at an entry closer to its own home. Removal shifts the
//! rest of the run back one slot (no tombstones). The table never shrinks.
//!
//! Each slot packs its metadata and handle together, as commonware's does, so an insert or a
//! lookup on a cold table touches one cache line. Inserts and removes load a 64-byte span of
//! packed slots as one vector, find their slot and shift the run with masks, and store it back
//! without a branch per slot; a span that would cross the end of the table, a run longer than
//! one span, or a run near the maximum displacement goes one slot at a time. Lookups walk one
//! slot at a time: runs are short, and a span's compare costs more than the loads it saves.
//!
//! Rust's closures become context parameters: a `rehash_context` declares
//! `fn rehash(self, handle: H) u64` (the hash each held handle was inserted under, called
//! only when the table grows), and a `matcher` declares `fn matches(self, handle: H) bool`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

/// The bit at which a hash's fingerprint starts.
pub const FINGERPRINT_SHIFT: u6 = 56;
/// Metadata of an unoccupied slot; its displacement exceeds `MAX_DISPLACEMENT`.
pub const EMPTY: u32 = std.math.maxInt(u32);
/// Largest displacement an entry may have.
pub const MAX_DISPLACEMENT: u32 = (1 << 24) - 2;
/// One unit of displacement in slot metadata.
pub const DISPLACEMENT_UNIT: u32 = 1 << 8;
/// Slot count after the first allocation.
pub const MIN_SLOTS: usize = 16;

/// The slot metadata of an entry for `hash` at `displacement` from its home.
pub fn slot_meta(hash: u64, displacement: u32) u32 {
    assert(displacement <= MAX_DISPLACEMENT);
    return (displacement << 8) | @as(u32, @intCast(hash >> FINGERPRINT_SHIFT));
}

/// Which of `partitions` groups `hash` falls in, from the bits just below the fingerprint,
/// which a `Table` of fewer than 2^40 slots reads for neither its home slot nor fingerprint.
/// Asserts `partitions` is a power of two no larger than 2^16.
pub fn partition(hash: u64, partitions: usize) usize {
    assert(std.math.isPowerOfTwo(partitions) and partitions <= 1 << 16);
    const shift: u6 = FINGERPRINT_SHIFT - @as(u6, @intCast(@ctz(partitions)));
    const group: usize = @intCast((hash >> shift) & (partitions - 1));
    assert(group < partitions);
    return group;
}

/// Bytes a probe or shift reads at once: one cache line of packed slots.
pub const SPAN_BYTES = 64;

/// A probe at `displacement` stops at a slot when this is at most `displacement`: one past the
/// entry's displacement, or 0 for `EMPTY`, whose metadata wraps (no entry's reaches 2^32 - 256).
/// One compare replaces the empty test and the closer-to-home test.
fn stop_key(meta: u32) u32 {
    return (meta +% DISPLACEMENT_UNIT) >> 8;
}

/// `H` is an integer of at most 8 bytes, so a slot is a few `u32` words and a span of slots
/// shifts as one vector of words.
pub fn Table(comptime H: type) type {
    comptime assert(@typeInfo(H) == .int and @sizeOf(H) <= 8);
    return struct {
        const Self = @This();

        /// A power of two of slots, or none before the first allocation.
        slots: []Slot = &.{},
        len: usize = 0,

        /// Packed to 4-byte alignment, as commonware's `#[repr(C, packed)]` slot: 12 bytes for
        /// a `u64` handle, 8 for a `u32`.
        pub const Slot = extern struct {
            /// Displacement (high 24 bits) and fingerprint (low byte), or `EMPTY`.
            meta: u32,
            /// Meaningful only when the slot is occupied.
            handle: H align(4),
        };

        /// `u32` words per slot; a slot's metadata is its first word.
        const W = @sizeOf(Slot) / 4;
        /// Words in a span: one 64-byte vector, which may end inside a slot it does not use.
        const LANES = SPAN_BYTES / 4;
        /// Whole slots in a span.
        pub const SPAN = LANES / W;
        const Words = @Vector(LANES, u32);
        /// One bit per word lane of a span, lowest first.
        const Mask = u32;
        /// The bits of the metadata lanes of a span's whole slots.
        const meta_bits: Mask = bits: {
            var bits: Mask = 0;
            for (0..SPAN) |slot| bits |= 1 << (slot * W);
            break :bits bits;
        };

        comptime {
            assert(@sizeOf(Slot) % 4 == 0 and @alignOf(Slot) == 4);
            assert(@offsetOf(Slot, "meta") == 0);
            assert(SPAN >= 4 and SPAN <= 16 and LANES <= 32);
        }

        const lane_index: Words = std.simd.iota(u32, LANES);
        /// The slot of the span each word lane belongs to.
        const lane_slot: Words = lane_index / @as(Words, @splat(W));
        /// `DISPLACEMENT_UNIT` on metadata lanes, 0 on handle lanes.
        const meta_units: Words = @select(
            u32,
            lane_index % @as(Words, @splat(W)) == @as(Words, @splat(0)),
            @as(Words, @splat(DISPLACEMENT_UNIT)),
            @as(Words, @splat(0)),
        );
        /// Each lane takes the same lane of the previous slot (slot 0 keeps its own).
        const up_lanes: @Vector(LANES, i32) = lanes: {
            var lanes: [LANES]i32 = undefined;
            for (&lanes, 0..) |*lane, i| lane.* = @intCast(if (i >= W) i - W else i);
            break :lanes lanes;
        };
        /// Each lane takes the same lane of the next slot (the last slot keeps its own).
        const down_lanes: @Vector(LANES, i32) = lanes: {
            var lanes: [LANES]i32 = undefined;
            for (&lanes, 0..) |*lane, i| lane.* = @intCast(if (i + W < LANES) i + W else i);
            break :lanes lanes;
        };

        /// The metadata lanes of whole slots where `lanes` holds: one mask move, with no
        /// gather of the metadata words.
        fn meta_mask(lanes: @Vector(LANES, bool)) Mask {
            const bits: @Int(.unsigned, LANES) = @bitCast(lanes);
            return bits & meta_bits;
        }

        /// `words` with every slot's handle lanes holding `handle`.
        fn with_handle(words: Words, handle: H) Words {
            const handle_words: [W - 1]u32 = @bitCast(@as(@Int(.unsigned, (W - 1) * 32), handle));
            const position = lane_index % @as(Words, @splat(W));
            var result = words;
            inline for (handle_words, 1..) |word, k| {
                const lanes = position == @as(Words, @splat(k));
                result = @select(u32, lanes, @as(Words, @splat(word)), result);
            }
            return result;
        }

        /// Whether the span from `start` lies within the table's words.
        fn fits(slots: []const Slot, start: usize) bool {
            return start * W + LANES <= slots.len * W;
        }

        /// The words of the span of slots from `start`, which must fit.
        fn load(slots: []const Slot, start: usize) Words {
            assert(fits(slots, start));
            const words: [*]const u32 = @ptrCast(slots.ptr);
            return words[start * W ..][0..LANES].*;
        }

        fn store(slots: []Slot, start: usize, words: Words) void {
            assert(fits(slots, start));
            const target: [*]u32 = @ptrCast(slots.ptr);
            target[start * W ..][0..LANES].* = words;
        }

        pub const empty: Self = .{};

        /// An empty table that fits `entries` entries without growing.
        pub fn init_capacity(gpa: Allocator, entries: usize) Allocator.Error!Self {
            if (entries == 0) return .empty;
            const result: Self = .{ .slots = try empty_slots(gpa, slots_for(entries)) };
            assert(result.capacity() >= entries);
            return result;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.slots);
            self.* = undefined;
        }

        /// The slot count that fits `entries` entries without growing.
        fn slots_for(entries: usize) usize {
            assert(entries > 0);
            const scaled = std.math.mul(usize, entries, 4) catch @panic("capacity overflow");
            const minimum = scaled / 3 + @intFromBool(scaled % 3 != 0);
            const slots = std.math.ceilPowerOfTwo(usize, minimum) catch
                @panic("capacity overflow");
            return @max(slots, MIN_SLOTS);
        }

        fn empty_slots(gpa: Allocator, count: usize) Allocator.Error![]Slot {
            assert(std.math.isPowerOfTwo(count) and count >= MIN_SLOTS);
            const slots = try gpa.alloc(Slot, count);
            for (slots) |*slot| slot.* = .{ .meta = EMPTY, .handle = 0 };
            return slots;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.len == 0;
        }

        /// The number of entries that fit before the next growth.
        pub fn capacity(self: *const Self) usize {
            return self.slots.len * 3 / 4;
        }

        /// Grows the table, if needed, so inserting `additional` more entries never grows it.
        pub fn reserve(
            self: *Self,
            gpa: Allocator,
            additional: usize,
            rehash_context: anytype,
        ) Allocator.Error!void {
            const entries = std.math.add(usize, self.len, additional) catch
                @panic("capacity overflow");
            if (entries > self.capacity()) {
                try self.rebuild(gpa, slots_for(entries), rehash_context);
            }
            assert(self.capacity() >= entries);
        }

        /// The handles whose home slot and fingerprint match `hash`, in probe order.
        pub fn get(self: *const Self, hash: u64) Candidates {
            return .{ .slots = self.slots, .hash = hash, .slot = home(self.slots.len, hash) };
        }

        pub const Candidates = struct {
            slots: []const Slot,
            hash: u64,
            /// The next slot to probe.
            slot: usize,
            displacement: u32 = 0,

            /// The next candidate's slot index.
            fn next_slot(it: *Candidates) ?usize {
                if (it.slots.len == 0) return null;
                const mask = it.slots.len - 1;
                // Each pass moves one slot further; the run ends within
                // `MAX_DISPLACEMENT + 1` slots.
                while (true) {
                    const meta = it.slots[it.slot].meta;
                    if (stop_key(meta) <= it.displacement) return null;
                    const current = it.slot;
                    const matched = meta == slot_meta(it.hash, it.displacement);
                    it.slot = (it.slot + 1) & mask;
                    it.displacement += 1;
                    if (matched) return current;
                }
            }

            pub fn next(it: *Candidates) ?H {
                const slot = it.next_slot() orelse return null;
                return it.slots[slot].handle;
            }
        };

        fn home(slots: usize, hash: u64) usize {
            const mask = slots -% 1;
            return @as(usize, @truncate(hash)) & mask;
        }

        /// Hints the CPU to load the home slot of `hash`.
        pub fn prefetch(self: *const Self, hash: u64) void {
            if (self.slots.len == 0) return;
            @prefetch(&self.slots[home(self.slots.len, hash)], .{});
        }

        /// Inserts `handle` under `hash`. Duplicate hashes and handles are allowed.
        /// Panics if an entry would end up more than 2^24 - 2 slots from its home.
        pub fn insert(
            self: *Self,
            gpa: Allocator,
            hash: u64,
            handle: H,
            rehash_context: anytype,
        ) Allocator.Error!void {
            if (self.len == self.capacity()) try self.grow(gpa, rehash_context);
            self.place(hash, handle);
            self.len += 1;
            assert(self.len <= self.capacity());
        }

        /// Inserts `handle` under `hash` without growing; asserts there is room.
        pub fn insert_assume_capacity(self: *Self, hash: u64, handle: H) void {
            assert(self.len < self.capacity());
            self.place(hash, handle);
            self.len += 1;
        }

        /// Removes every entry, keeping the slots.
        pub fn clear(self: *Self) void {
            for (self.slots) |*slot| slot.meta = EMPTY;
            self.len = 0;
        }

        /// The first candidate for `hash` that `matcher.matches` accepts, or null: `get`
        /// with the confirmation inlined into one walk of the run.
        pub fn find(self: *const Self, hash: u64, matcher: anytype) ?H {
            if (self.slots.len == 0) return null;
            return switch (self.walk(hash, matcher)) {
                .found => |found| found,
                .stop => null,
            };
        }

        pub const Found = struct { handle: H, inserted: bool };

        /// The first candidate for `hash` that `matcher.matches` accepts, or else `handle`,
        /// inserted under `hash`, in one walk of the run. A full table grows first, so the
        /// candidates offered are those `get` yields after any growth, in the same order.
        pub fn find_or_insert(
            self: *Self,
            gpa: Allocator,
            hash: u64,
            matcher: anytype,
            handle: H,
            rehash_context: anytype,
        ) Allocator.Error!Found {
            if (self.len == self.capacity()) try self.grow(gpa, rehash_context);
            const stop = switch (self.walk(hash, matcher)) {
                .found => |found| return .{ .handle = found, .inserted = false },
                .stop => |stop| stop,
            };
            self.place_at(stop.slot, stop.displacement, hash, handle);
            self.len += 1;
            assert(self.len <= self.capacity());
            return .{ .handle = handle, .inserted = true };
        }

        /// Removes one entry holding `handle` whose home slot and fingerprint match `hash`;
        /// returns whether one existed.
        pub fn remove(self: *Self, hash: u64, handle: H) bool {
            if (self.slots.len == 0) return false;
            switch (self.remove_in_span(hash, handle)) {
                .removed => {},
                .absent => return false,
                .found => |hole| if (!self.shift_out(hole)) self.shift_out_slots(hole),
                .unknown => {
                    const hole = self.find_slot_scalar(hash, handle) orelse return false;
                    if (!self.shift_out(hole)) self.shift_out_slots(hole);
                },
            }
            assert(self.len > 0);
            self.len -= 1;
            return true;
        }

        /// `removed`, or the slot to remove when its run continues past the span, or neither
        /// found nor ruled out (`unknown`) in the span.
        const SlotSearch = union(enum) { removed, found: usize, absent, unknown };

        /// Removes the first entry of the run from the home of `hash` holding `handle` under
        /// the home and fingerprint of `hash`, within the span from that home, in one load and
        /// one store: every word of the span is compared at once, and the rest of the run moves
        /// back one slot by masks of the same span.
        fn remove_in_span(self: *Self, hash: u64, handle: H) SlotSearch {
            const start = home(self.slots.len, hash);
            if (!fits(self.slots, start)) return .unknown;
            const words = load(self.slots, start);
            const unit: Words = @splat(DISPLACEMENT_UNIT);
            const stops = meta_mask((words +% unit) >> @splat(8) <= lane_slot);
            // Each slot's expected words: its metadata at its displacement, then the handle.
            const fingerprint: Words = @splat(@as(u32, @intCast(hash >> FINGERPRINT_SHIFT)));
            const expected = with_handle((lane_slot << @splat(8)) | fingerprint, handle);
            const equal: @Int(.unsigned, LANES) = @bitCast(words == expected);
            var whole: Mask = equal;
            inline for (1..W) |k| whole &= equal >> k;
            const matches = whole & meta_bits;
            // Robin Hood order keeps every entry from this home before the stop.
            assert(stops == 0 or matches >> @intCast(@ctz(stops)) == 0);
            if (matches == 0) return if (stops != 0) .absent else .unknown;
            // The hole's first word, and the first slot after it that stays: empty, or
            // holding an entry at its home (its metadata plus one unit is below two units).
            const hole: u32 = @ctz(matches);
            const through_hole: Mask = (@as(Mask, 2) << @intCast(hole)) - 1;
            const stays = meta_mask(words +% unit < unit + unit) & ~through_hole;
            if (stays == 0) return .{ .found = start + hole / W };
            const last: u32 = @ctz(stays) - W;
            assert(hole % W == 0 and last % W == 0 and hole <= last);
            // Slots from the hole up to the last take their successor's entry, one slot closer
            // to home, and the last empties.
            const moved = lane_index -% @as(Words, @splat(hole)) < @as(Words, @splat(last - hole));
            const down = @shuffle(u32, words, undefined, down_lanes);
            const shifted = @select(u32, moved, down -% meta_units, words);
            const vacated = lane_index == @as(Words, @splat(last));
            store(self.slots, start, @select(u32, vacated, @as(Words, @splat(EMPTY)), shifted));
            return .removed;
        }

        /// `find_slot`, one candidate at a time.
        fn find_slot_scalar(self: *const Self, hash: u64, handle: H) ?usize {
            var candidates = self.get(hash);
            while (candidates.next_slot()) |slot| {
                if (self.slots[slot].handle == handle) return slot;
            }
            return null;
        }

        /// Empties `hole` and moves the rest of its run back one slot, within one span;
        /// returns false, changing nothing, when the span does not hold the run's end.
        fn shift_out(self: *Self, hole: usize) bool {
            if (!fits(self.slots, hole)) return false;
            const words = load(self.slots, hole);
            assert(words[0] != EMPTY);
            // Slots after the hole that stay, empty or holding an entry at its home: their
            // metadata plus one unit is below two units (`EMPTY` wraps; no entry's reaches it).
            const unit: Words = @splat(DISPLACEMENT_UNIT);
            const stays = meta_mask(words +% unit < unit + unit) & ~@as(Mask, 1);
            if (stays == 0) return false;
            // The first word of the slot that empties, after the moved slots before it.
            const last: u32 = @ctz(stays) - W;
            assert(last % W == 0);
            const moved = lane_index < @as(Words, @splat(last));
            const down = @shuffle(u32, words, undefined, down_lanes);
            const shifted = @select(u32, moved, down -% meta_units, words);
            const vacated = lane_index == @as(Words, @splat(last));
            store(self.slots, hole, @select(u32, vacated, @as(Words, @splat(EMPTY)), shifted));
            return true;
        }

        /// `shift_out`, one slot at a time.
        fn shift_out_slots(self: *Self, start: usize) void {
            // Shift the rest of the run back one slot, stopping before an entry at home.
            const mask = self.slots.len - 1;
            var hole = start;
            while (true) {
                const next = (hole + 1) & mask;
                const slot = self.slots[next];
                if (slot.meta == EMPTY or slot.meta < DISPLACEMENT_UNIT) break;
                self.slots[hole] = .{
                    .meta = slot.meta - DISPLACEMENT_UNIT,
                    .handle = slot.handle,
                };
                hole = next;
            }
            self.slots[hole].meta = EMPTY;
        }

        const Walk = union(enum) {
            found: H,
            /// Where an entry for the hash goes: the first empty slot or the first entry
            /// closer to its own home.
            stop: struct { slot: usize, displacement: u32 },
        };

        /// Walks the run from the home of `hash`, offering each candidate to `matcher`, one
        /// slot at a time: runs are short, and one load and compare per slot beats a span's.
        fn walk(self: *const Self, hash: u64, matcher: anytype) Walk {
            assert(self.slots.len > 0);
            const mask = self.slots.len - 1;
            var slot = home(self.slots.len, hash);
            var displacement: u32 = 0;
            // Each pass moves one slot further; the run ends within the maximum displacement.
            while (true) {
                const entry = self.slots[slot];
                if (stop_key(entry.meta) <= displacement) {
                    return .{ .stop = .{ .slot = slot, .displacement = displacement } };
                }
                if (@TypeOf(matcher) != void and entry.meta == slot_meta(hash, displacement)) {
                    if (matcher.matches(entry.handle)) return .{ .found = entry.handle };
                }
                if (displacement >= MAX_DISPLACEMENT) {
                    @panic("the run from a home slot must end within the maximum displacement");
                }
                slot = (slot + 1) & mask;
                displacement += 1;
            }
        }

        /// Places an entry in Robin Hood order without changing `len`. Requires an empty slot.
        fn place(self: *Self, hash: u64, handle: H) void {
            if (!self.place_in_span(hash, handle)) {
                const stop = switch (self.walk(hash, {})) {
                    .found => unreachable, // A walk without a matcher accepts no candidate.
                    .stop => |stop| stop,
                };
                self.place_at(stop.slot, stop.displacement, hash, handle);
            }
        }

        /// `place` within the span from the home of `hash`, in one load and one store without
        /// a branch on the run: the stop, the empty slot ending the run after it, the shift
        /// between them, and the new entry come from masks of that span. Returns false,
        /// changing nothing, when the span does not hold the stop and that empty slot.
        fn place_in_span(self: *Self, hash: u64, handle: H) bool {
            const start = home(self.slots.len, hash);
            if (!fits(self.slots, start)) return false;
            const words = load(self.slots, start);
            const unit: Words = @splat(DISPLACEMENT_UNIT);
            const stops = meta_mask((words +% unit) >> @splat(8) <= lane_slot);
            if (stops == 0) return false;
            // The stop's first word, and the first empty slot's at or after it.
            const target: u32 = @ctz(stops);
            const before: Mask = (@as(Mask, 1) << @intCast(target)) - 1;
            const empties = meta_mask(words == @as(Words, @splat(EMPTY))) & ~before;
            if (empties == 0) return false;
            const end: u32 = @ctz(empties);
            assert(target % W == 0 and end % W == 0 and target <= end);
            const limit: Words = @splat(MAX_DISPLACEMENT);
            const too_far = meta_mask((words >> @splat(8)) >= limit);
            if (too_far & ~before & ((@as(Mask, 1) << @intCast(end)) - 1) != 0) {
                @panic("shifting a run must not move an entry past the maximum displacement");
            }
            // Slots after the stop through the empty one take their predecessor's entry, one
            // slot further from home; the stop's slot takes the new entry.
            const displacement = target / W;
            const first: Words = @splat(target + W);
            const moved = lane_index -% first < @as(Words, @splat(end - target));
            const up = @shuffle(u32, words, undefined, up_lanes);
            const shifted = @select(u32, moved, up +% meta_units, words);
            const entry = with_handle(@splat(slot_meta(hash, displacement)), handle);
            const placed = lane_slot == @as(Words, @splat(displacement));
            store(self.slots, start, @select(u32, placed, entry, shifted));
            assert(self.slots[start + displacement].meta == slot_meta(hash, displacement));
            return true;
        }

        /// Places an entry for `hash` at `target`, `displacement` from its home, shifting the
        /// rest of the run forward one slot.
        fn place_at(self: *Self, target: usize, displacement: u32, hash: u64, handle: H) void {
            assert(self.len < self.slots.len);
            const meta = slot_meta(hash, displacement);
            // Most targets are empty at three-quarters load or less: no run to shift.
            if (self.slots[target].meta == EMPTY) {
                self.slots[target] = .{ .meta = meta, .handle = handle };
            } else if (!self.shift_in(target, meta, handle)) {
                self.shift_in_slots(target, meta, handle);
            }
            assert(self.slots[target].meta == meta);
        }

        /// Moves the run from `target` forward one slot into its first empty slot and places
        /// `meta` and `handle` at `target`, within one span; returns false, changing nothing,
        /// when the span holds no empty slot.
        fn shift_in(self: *Self, target: usize, meta: u32, handle: H) bool {
            if (!fits(self.slots, target)) return false;
            const words = load(self.slots, target);
            const empties = meta_mask(words == @as(Words, @splat(EMPTY)));
            if (empties == 0) return false;
            // The first word of the run's empty slot.
            const end: u32 = @ctz(empties);
            assert(end % W == 0);
            const limit: Words = @splat(MAX_DISPLACEMENT);
            const too_far = meta_mask((words >> @splat(8)) >= limit);
            if (too_far & ((@as(Mask, 1) << @intCast(end)) - 1) != 0) {
                @panic("shifting a run must not move an entry past the maximum displacement");
            }
            // Slots 1 through the empty one take their predecessor's entry, one slot further
            // from home (slot 0's lanes wrap to the maximum and stay).
            const moved = lane_index -% @as(Words, @splat(W)) < @as(Words, @splat(end));
            const up = @shuffle(u32, words, undefined, up_lanes);
            store(self.slots, target, @select(u32, moved, up +% meta_units, words));
            self.slots[target] = .{ .meta = meta, .handle = handle };
            return true;
        }

        /// `shift_in`, one slot at a time.
        fn shift_in_slots(self: *Self, target: usize, meta: u32, handle: H) void {
            const mask = self.slots.len - 1;
            var slot = target;
            // Find the end of the run; the table has an empty slot.
            while (self.slots[slot].meta != EMPTY) : (slot = (slot + 1) & mask) {
                if (self.slots[slot].meta >> 8 >= MAX_DISPLACEMENT) {
                    @panic("shifting a run must not move an entry past the maximum displacement");
                }
            }
            while (slot != target) {
                const previous = (slot -% 1) & mask;
                const moved = self.slots[previous];
                self.slots[slot] = .{
                    .meta = moved.meta + DISPLACEMENT_UNIT,
                    .handle = moved.handle,
                };
                slot = previous;
            }
            self.slots[target] = .{ .meta = meta, .handle = handle };
        }

        /// Rebuilds with twice as many slots.
        fn grow(self: *Self, gpa: Allocator, rehash_context: anytype) Allocator.Error!void {
            try self.rebuild(gpa, @max(self.slots.len * 2, MIN_SLOTS), rehash_context);
        }

        /// Rebuilds with `count` slots, placing each entry under `rehash_context.rehash`.
        fn rebuild(
            self: *Self,
            gpa: Allocator,
            count: usize,
            rehash_context: anytype,
        ) Allocator.Error!void {
            var table: Self = .{ .slots = try empty_slots(gpa, count), .len = self.len };
            for (self.slots) |slot| {
                if (slot.meta == EMPTY) continue;
                table.place(rehash_context.rehash(slot.handle), slot.handle);
            }
            gpa.free(self.slots);
            self.* = table;
            assert(self.len <= self.capacity());
        }
    };
}

test {
    _ = @import("handles_test.zig");
}

const death = @import("death.zig");

test "handles: partition rejects a count that is not a power of two" {
    // commonware `handles.rs` `test_partition_rejects_a_count_that_is_not_a_power_of_two`
    // (#[should_panic]).
    try death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            var partitions: usize = 3;
            _ = &partitions;
            _ = partition(0, partitions);
        }
    }.body);
}
