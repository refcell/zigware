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
//! Metadata and handles live in separate arrays, so probes and shifts work on a `WINDOW` of 16
//! slots as one vector, without a branch per slot (as hashbrown's group probes, which
//! commonware's tables use); a window that would cross the end of the table, a run longer
//! than one window, or a run near the maximum displacement goes one slot at a time.
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

/// Slots a probe scans at once: one 64-byte vector of metadata.
pub const WINDOW = 16;
const Lanes = @Vector(WINDOW, u32);
/// One bit per slot of a window, lowest first.
const Mask = u32;
const lane_index: Lanes = std.simd.iota(u32, WINDOW);

/// Lane `i` takes lane `i - 1` (lane 0 keeps its own), for shifting a run forward one slot.
const up_lanes: @Vector(WINDOW, i32) = lanes: {
    var lanes: [WINDOW]i32 = undefined;
    for (&lanes, 0..) |*lane, i| lane.* = @max(@as(i32, @intCast(i)) - 1, 0);
    break :lanes lanes;
};
/// Lane `i` takes lane `i + 1` (the last keeps its own), for shifting a run back one slot.
const down_lanes: @Vector(WINDOW, i32) = lanes: {
    var lanes: [WINDOW]i32 = undefined;
    for (&lanes, 0..) |*lane, i| lane.* = @min(@as(i32, @intCast(i)) + 1, WINDOW - 1);
    break :lanes lanes;
};

/// Bits `[0, count)`.
fn low_mask(count: u32) Mask {
    assert(count <= WINDOW);
    return (@as(Mask, 1) << @intCast(count)) - 1;
}

fn lanes_of(mask: Mask) @Vector(WINDOW, bool) {
    assert(mask <= low_mask(WINDOW));
    return @bitCast(@as(u16, @intCast(mask)));
}

fn mask_of(lanes: @Vector(WINDOW, bool)) Mask {
    return @as(u16, @bitCast(lanes));
}

/// A probe at `displacement` stops at a slot when this is at most `displacement`: one past the
/// entry's displacement, or 0 for `EMPTY`, whose metadata wraps (no entry's reaches 2^32 - 256).
/// One compare replaces the empty test and the closer-to-home test.
fn stop_key(meta: u32) u32 {
    return (meta +% DISPLACEMENT_UNIT) >> 8;
}

fn stop_keys(window: Lanes) Lanes {
    return (window +% @as(Lanes, @splat(DISPLACEMENT_UNIT))) >> @splat(8);
}

/// One probe step from `slot` for `hash` at `displacement`: a whole window when it fits, else
/// one slot. `matches` are bits from `slot` before the run ends; `scanned` counts the slots
/// consumed, which end at the run's stop when `stopped`.
const Probe = struct { matches: Mask, stopped: bool, scanned: u32 };

fn probe(metas: []const u32, slot: usize, hash: u64, displacement: u32) Probe {
    if (slot + WINDOW <= metas.len and displacement + WINDOW <= MAX_DISPLACEMENT) {
        const window: Lanes = metas[slot..][0..WINDOW].*;
        const displacements = @as(Lanes, @splat(displacement)) + lane_index;
        const fingerprint: u32 = @intCast(hash >> FINGERPRINT_SHIFT);
        const expected = (displacements << @splat(8)) | @as(Lanes, @splat(fingerprint));
        const matches = mask_of(window == expected);
        const stops = mask_of(stop_keys(window) <= displacements);
        assert(matches & stops == 0);
        if (stops == 0) return .{ .matches = matches, .stopped = false, .scanned = WINDOW };
        const end: u32 = @ctz(stops);
        // Robin Hood order keeps every entry from this home before the stop.
        assert(matches & ~low_mask(end) == 0);
        return .{ .matches = matches, .stopped = true, .scanned = end };
    }
    const meta = metas[slot];
    if (stop_key(meta) <= displacement) {
        return .{ .matches = 0, .stopped = true, .scanned = 0 };
    }
    const matched = meta == slot_meta(hash, displacement);
    return .{ .matches = @intFromBool(matched), .stopped = false, .scanned = 1 };
}

/// `H` is an integer, so runs shift handles as vectors.
pub fn Table(comptime H: type) type {
    comptime assert(@typeInfo(H) == .int);
    return struct {
        const Self = @This();
        const Handles = @Vector(WINDOW, H);

        /// Each slot's displacement (high 24 bits) and fingerprint (low byte), or `EMPTY`: a
        /// power of two of slots, or none before the first allocation.
        metas: []u32 = &.{},
        /// Each slot's handle, meaningful only when the slot is occupied.
        handles: []H = &.{},
        len: usize = 0,

        pub const empty: Self = .{};

        /// An empty table that fits `entries` entries without growing.
        pub fn init_capacity(gpa: Allocator, entries: usize) Allocator.Error!Self {
            if (entries == 0) return .empty;
            const result = try empty_table(gpa, slots_for(entries));
            assert(result.capacity() >= entries);
            return result;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.metas);
            gpa.free(self.handles);
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

        fn empty_table(gpa: Allocator, count: usize) Allocator.Error!Self {
            assert(std.math.isPowerOfTwo(count) and count >= MIN_SLOTS);
            const metas = try gpa.alloc(u32, count);
            errdefer gpa.free(metas);
            const handles = try gpa.alloc(H, count);
            @memset(metas, EMPTY);
            return .{ .metas = metas, .handles = handles };
        }

        pub fn is_empty(self: *const Self) bool {
            return self.len == 0;
        }

        /// The number of entries that fit before the next growth.
        pub fn capacity(self: *const Self) usize {
            assert(self.metas.len == self.handles.len);
            return self.metas.len * 3 / 4;
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
            return .{
                .metas = self.metas,
                .handles = self.handles,
                .hash = hash,
                .slot = home(self.metas.len, hash),
            };
        }

        pub const Candidates = struct {
            metas: []const u32,
            handles: []const H,
            hash: u64,
            /// The next slot to probe.
            slot: usize,
            displacement: u32 = 0,
            /// Matches probed but not yet returned, as bits from `base`.
            pending: Mask = 0,
            base: usize = 0,
            /// Whether the probe reached the end of the run.
            stopped: bool = false,

            /// The next candidate's slot index.
            fn next_slot(it: *Candidates) ?usize {
                if (it.metas.len == 0) return null;
                const mask = it.metas.len - 1;
                // Each pass returns a pending match or probes further; the run ends within
                // `MAX_DISPLACEMENT + 1` slots.
                while (true) {
                    if (it.pending != 0) {
                        const bit = @ctz(it.pending);
                        it.pending &= it.pending - 1;
                        return (it.base + bit) & mask;
                    }
                    if (it.stopped) return null;
                    const step = probe(it.metas, it.slot, it.hash, it.displacement);
                    it.base = it.slot;
                    it.pending = step.matches;
                    it.stopped = step.stopped;
                    it.slot = (it.slot + step.scanned) & mask;
                    it.displacement += step.scanned;
                }
            }

            pub fn next(it: *Candidates) ?H {
                const slot = it.next_slot() orelse return null;
                return it.handles[slot];
            }
        };

        fn home(slots: usize, hash: u64) usize {
            const mask = slots -% 1;
            return @as(usize, @truncate(hash)) & mask;
        }

        /// Hints the CPU to load the home slot of `hash`.
        pub fn prefetch(self: *const Self, hash: u64) void {
            if (self.metas.len == 0) return;
            @prefetch(&self.metas[home(self.metas.len, hash)], .{});
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
            @memset(self.metas, EMPTY);
            self.len = 0;
        }

        /// The first candidate for `hash` that `matcher.matches` accepts, or null: `get`
        /// with the confirmation inlined into one walk of the run.
        pub fn find(self: *const Self, hash: u64, matcher: anytype) ?H {
            if (self.metas.len == 0) return null;
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
            var candidates = self.get(hash);
            const hole = while (candidates.next_slot()) |slot| {
                if (self.handles[slot] == handle) break slot;
            } else return false;
            if (!self.shift_out(hole)) self.shift_out_slots(hole);
            assert(self.len > 0);
            self.len -= 1;
            return true;
        }

        /// Empties `hole` and moves the rest of its run back one slot, within one window;
        /// returns false, changing nothing, when the window does not hold the run's end.
        fn shift_out(self: *Self, hole: usize) bool {
            if (hole + WINDOW > self.metas.len) return false;
            const window: Lanes = self.metas[hole..][0..WINDOW].*;
            assert(window[0] != EMPTY);
            // Slots after the hole that stay: empty, or holding an entry at its home.
            const stays = (mask_of(window == @as(Lanes, @splat(EMPTY))) |
                mask_of(window < @as(Lanes, @splat(DISPLACEMENT_UNIT)))) & ~@as(Mask, 1);
            if (stays == 0) return false;
            const end: u32 = @ctz(stays);
            const moved = lanes_of(low_mask(end - 1));
            const down = @shuffle(u32, window, undefined, down_lanes);
            const unit: Lanes = @splat(DISPLACEMENT_UNIT);
            const shifted = @select(u32, moved, down -% unit, window);
            const vacated = lanes_of(@as(Mask, 1) << @intCast(end - 1));
            const empty_lanes: Lanes = @splat(EMPTY);
            self.metas[hole..][0..WINDOW].* = @select(u32, vacated, empty_lanes, shifted);
            const handles: Handles = self.handles[hole..][0..WINDOW].*;
            const handles_down = @shuffle(H, handles, undefined, down_lanes);
            self.handles[hole..][0..WINDOW].* = @select(H, moved, handles_down, handles);
            return true;
        }

        /// `shift_out`, one slot at a time.
        fn shift_out_slots(self: *Self, start: usize) void {
            // Shift the rest of the run back one slot, stopping before an entry at home.
            const mask = self.metas.len - 1;
            var hole = start;
            while (true) {
                const next = (hole + 1) & mask;
                const meta = self.metas[next];
                if (meta == EMPTY or meta < DISPLACEMENT_UNIT) break;
                self.metas[hole] = meta - DISPLACEMENT_UNIT;
                self.handles[hole] = self.handles[next];
                hole = next;
            }
            self.metas[hole] = EMPTY;
        }

        const Walk = union(enum) {
            found: H,
            /// Where an entry for the hash goes: the first empty slot or the first entry
            /// closer to its own home.
            stop: struct { slot: usize, displacement: u32 },
        };

        /// Walks the run from the home of `hash`, offering each candidate to `matcher`.
        fn walk(self: *const Self, hash: u64, matcher: anytype) Walk {
            assert(self.metas.len > 0);
            const mask = self.metas.len - 1;
            var slot = home(self.metas.len, hash);
            var displacement: u32 = 0;
            // Each pass probes a window or a slot; the run ends within the maximum displacement.
            while (true) {
                const step = probe(self.metas, slot, hash, displacement);
                if (@TypeOf(matcher) != void) {
                    var matches = step.matches;
                    while (matches != 0) : (matches &= matches - 1) {
                        const handle = self.handles[(slot + @ctz(matches)) & mask];
                        if (matcher.matches(handle)) return .{ .found = handle };
                    }
                }
                slot = (slot + step.scanned) & mask;
                displacement += step.scanned;
                if (step.stopped) {
                    return .{ .stop = .{ .slot = slot, .displacement = displacement } };
                }
                if (displacement > MAX_DISPLACEMENT) {
                    @panic("the run from a home slot must end within the maximum displacement");
                }
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
            assert(self.len < self.metas.len);
            const meta = slot_meta(hash, displacement);
            if (!self.shift_in(target, meta, handle)) self.shift_in_slots(target, meta, handle);
            assert(self.metas[target] == meta);
        }

        /// Moves the run from `target` forward one slot into its first empty slot and places
        /// `meta` and `handle` at `target`, within one window; returns false, changing nothing,
        /// when the window holds no empty slot.
        fn shift_in(self: *Self, target: usize, meta: u32, handle: H) bool {
            if (target + WINDOW > self.metas.len) return false;
            const window: Lanes = self.metas[target..][0..WINDOW].*;
            const empties = mask_of(window == @as(Lanes, @splat(EMPTY)));
            if (empties == 0) return false;
            const end: u32 = @ctz(empties);
            const too_far = mask_of((window >> @splat(8)) >= @as(Lanes, @splat(MAX_DISPLACEMENT)));
            if (too_far & low_mask(end) != 0) {
                @panic("shifting a run must not move an entry past the maximum displacement");
            }
            // Lanes 1 through `end` take their predecessor's entry, one slot further from home.
            const moved = lanes_of(low_mask(end + 1) & ~@as(Mask, 1));
            const up = @shuffle(u32, window, undefined, up_lanes);
            const unit: Lanes = @splat(DISPLACEMENT_UNIT);
            const shifted = @select(u32, moved, up +% unit, window);
            self.metas[target..][0..WINDOW].* = shifted;
            const handles: Handles = self.handles[target..][0..WINDOW].*;
            const handles_up = @shuffle(H, handles, undefined, up_lanes);
            self.handles[target..][0..WINDOW].* = @select(H, moved, handles_up, handles);
            self.metas[target] = meta;
            self.handles[target] = handle;
            return true;
        }

        /// `shift_in`, one slot at a time.
        fn shift_in_slots(self: *Self, target: usize, meta: u32, handle: H) void {
            const mask = self.metas.len - 1;
            var slot = target;
            // Find the end of the run; the table has an empty slot.
            while (self.metas[slot] != EMPTY) : (slot = (slot + 1) & mask) {
                if (self.metas[slot] >> 8 >= MAX_DISPLACEMENT) {
                    @panic("shifting a run must not move an entry past the maximum displacement");
                }
            }
            while (slot != target) {
                const previous = (slot -% 1) & mask;
                self.metas[slot] = self.metas[previous] + DISPLACEMENT_UNIT;
                self.handles[slot] = self.handles[previous];
                slot = previous;
            }
            self.metas[target] = meta;
            self.handles[target] = handle;
        }

        /// Rebuilds with twice as many slots.
        fn grow(self: *Self, gpa: Allocator, rehash_context: anytype) Allocator.Error!void {
            try self.rebuild(gpa, @max(self.metas.len * 2, MIN_SLOTS), rehash_context);
        }

        /// Rebuilds with `count` slots, placing each entry under `rehash_context.rehash`.
        fn rebuild(
            self: *Self,
            gpa: Allocator,
            count: usize,
            rehash_context: anytype,
        ) Allocator.Error!void {
            var table = try empty_table(gpa, count);
            table.len = self.len;
            for (self.metas, self.handles) |meta, handle| {
                if (meta == EMPTY) continue;
                table.place(rehash_context.rehash(handle), handle);
            }
            gpa.free(self.metas);
            gpa.free(self.handles);
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
