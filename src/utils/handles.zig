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

pub fn Table(comptime H: type) type {
    return struct {
        const Self = @This();

        /// A power of two of slots, or none before the first allocation.
        slots: []Slot = &.{},
        len: usize = 0,

        pub const Slot = struct {
            /// Displacement (high 24 bits) and fingerprint (low byte), or `EMPTY`.
            meta: u32,
            /// Meaningful only when the slot is occupied.
            handle: H,
        };

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
            for (slots) |*slot| slot.* = .{ .meta = EMPTY, .handle = undefined };
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
            return .{ .slots = self.slots, .hash = hash, .slot = home(self.slots, hash) };
        }

        pub const Candidates = struct {
            slots: []const Slot,
            hash: u64,
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
                    if (meta == EMPTY or meta >> 8 < it.displacement) return null;
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

        fn home(slots: []const Slot, hash: u64) usize {
            const mask = slots.len -% 1;
            return @as(usize, @truncate(hash)) & mask;
        }

        /// Hints the CPU to load the home slot of `hash`.
        pub fn prefetch(self: *const Self, hash: u64) void {
            if (self.slots.len == 0) return;
            @prefetch(&self.slots[home(self.slots, hash)], .{});
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
            var candidates = self.get(hash);
            var hole = while (candidates.next_slot()) |slot| {
                if (std.meta.eql(self.slots[slot].handle, handle)) break slot;
            } else return false;

            // Shift the rest of the run back one slot, stopping before an entry at home.
            const mask = self.slots.len - 1;
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
            assert(self.len > 0);
            self.len -= 1;
            return true;
        }

        const Walk = union(enum) {
            found: H,
            /// Where an entry for the hash goes: the first empty slot or the first entry
            /// closer to its own home.
            stop: struct { slot: usize, displacement: u32 },
        };

        /// Walks the run from the home of `hash`, offering each candidate to `matcher`.
        fn walk(self: *const Self, hash: u64, matcher: anytype) Walk {
            assert(self.slots.len > 0);
            const mask = self.slots.len - 1;
            var slot = home(self.slots, hash);
            var displacement: u32 = 0;
            while (true) {
                const current = self.slots[slot];
                if (current.meta == EMPTY or current.meta >> 8 < displacement) {
                    return .{ .stop = .{ .slot = slot, .displacement = displacement } };
                }
                if (current.meta == slot_meta(hash, displacement)) {
                    const accepted = if (@TypeOf(matcher) == void)
                        false
                    else
                        matcher.matches(current.handle);
                    if (accepted) return .{ .found = current.handle };
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
            const stop = switch (self.walk(hash, {})) {
                .found => unreachable, // A walk without a matcher accepts no candidate.
                .stop => |stop| stop,
            };
            self.place_at(stop.slot, stop.displacement, hash, handle);
        }

        /// Places an entry for `hash` at `target`, `displacement` from its home, shifting the
        /// rest of the run forward one slot.
        fn place_at(self: *Self, target: usize, displacement: u32, hash: u64, handle: H) void {
            assert(self.len < self.slots.len);
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
            self.slots[target] = .{ .meta = slot_meta(hash, displacement), .handle = handle };
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
