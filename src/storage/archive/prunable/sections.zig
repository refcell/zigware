//! In-memory index of the prunable archive's retained sections (commonware's `Positions` and
//! `Sections` in `archive/prunable/storage.rs`).
//!
//! Each retained section holds the translated key of every record it stores, by journal
//! position, and the first journal position of every index it stores, by offset from the
//! section's start. A key handle packs a section's slot and a record's position, so the key
//! table resolves a candidate to its translated key without storing keys.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Marks an absent offset in `Positions`.
const none: u64 = std.math.maxInt(u64);

/// Bits of a key handle holding the journal position. The rest hold the section slot.
pub const position_bits: u6 = 40;

/// The most sections a handle can name (2^24).
pub const max_slots: usize = 1 << (64 - @as(u7, position_bits));

/// Packs a record's section slot and journal position into a key handle.
pub fn handle(slot: usize, position: u64) u64 {
    assert(slot < max_slots);
    assert(position >> position_bits == 0); // A section holds fewer than 2^40 records.
    return (@as(u64, slot) << position_bits) | position;
}

/// A key handle's section slot and journal position.
pub const Unpacked = struct { slot: usize, position: u64 };

/// Splits a key handle into its section slot and journal position.
pub fn unpack(packed_handle: u64) Unpacked {
    const unpacked: Unpacked = .{
        .slot = @intCast(packed_handle >> position_bits),
        .position = packed_handle & ((@as(u64, 1) << position_bits) - 1),
    };
    assert(unpacked.slot < max_slots);
    assert(handle(unpacked.slot, unpacked.position) == packed_handle);
    return unpacked;
}

/// Journal position of the first record stored at each index of a section, by offset from the
/// section's start. The vector spans every offset up to the highest one present.
pub const Positions = struct {
    positions: std.ArrayList(u64) = .empty,
    present: u64 = 0,

    pub fn deinit(self: *Positions, gpa: Allocator) void {
        self.positions.deinit(gpa);
        self.* = undefined;
    }

    /// The first position of `offset`, if present.
    pub fn get(self: *const Positions, offset: u64) ?u64 {
        assert(self.present <= self.positions.items.len);
        if (offset >= self.positions.items.len) return null;
        const position = self.positions.items[@intCast(offset)];
        return if (position == none) null else position;
    }

    /// The number of offsets present.
    pub fn len(self: *const Positions) u64 {
        assert(self.present <= self.positions.items.len);
        return self.present;
    }

    /// Records `position` as the first for `offset`, returning false if `offset` already has
    /// one.
    pub fn insert(
        self: *Positions,
        gpa: Allocator,
        offset: u64,
        position: u64,
    ) Allocator.Error!bool {
        assert(position != none);
        const at = std.math.cast(usize, offset) orelse
            @panic("section offset must not exceed the address space");
        if (at >= self.positions.items.len) {
            const old = self.positions.items.len;
            try self.positions.resize(gpa, at + 1);
            @memset(self.positions.items[old..], none);
        }
        const slot = &self.positions.items[at];
        if (slot.* != none) return false;
        slot.* = position;
        self.present += 1;
        assert(self.present <= self.positions.items.len);
        return true;
    }
};

/// Retained sections, addressed by start index or by the slot held in a key handle.
pub fn Sections(comptime Key: type) type {
    return struct {
        const Self = @This();

        /// In-memory state of one retained section.
        pub const Section = struct {
            /// First index of the section.
            start: u64,
            /// Translated key of each record, by journal position.
            keys: std.ArrayList(Key) = .empty,
            /// First journal position of each index, by offset from `start`.
            positions: Positions = .{},

            pub fn deinit(section: *Section, gpa: Allocator) void {
                section.keys.deinit(gpa);
                section.positions.deinit(gpa);
                section.* = undefined;
            }
        };

        const Start = struct { start: u64, slot: usize };

        /// Slot of each retained section, ascending by start index.
        by_start: std.ArrayList(Start) = .empty,
        /// Section state by slot. A pruned section's slot is null until a new section reuses it.
        slots: std.ArrayList(?Section) = .empty,
        /// Slots freed by pruning, reused before `slots` grows. Its capacity always covers
        /// every slot, so pruning never allocates.
        free: std.ArrayList(usize) = .empty,

        pub const Added = struct { slot: usize, first: bool };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.slots.items) |*entry| {
                if (entry.*) |*section| section.deinit(gpa);
            }
            self.slots.deinit(gpa);
            self.by_start.deinit(gpa);
            self.free.deinit(gpa);
            self.* = undefined;
        }

        /// Where `start` is (or would be inserted) in `by_start`.
        fn lower_bound(self: *const Self, start: u64) usize {
            var low: usize = 0;
            var high: usize = self.by_start.items.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                if (self.by_start.items[mid].start < start) low = mid + 1 else high = mid;
            }
            assert(low <= self.by_start.items.len);
            return low;
        }

        /// The section starting at `start`, if retained.
        pub fn get(self: *const Self, start: u64) ?*const Section {
            const at = self.lower_bound(start);
            if (at == self.by_start.items.len) return null;
            const entry = self.by_start.items[at];
            if (entry.start != start) return null;
            return self.slot(entry.slot);
        }

        /// The section held in `slot`, which a key handle guarantees is retained.
        pub fn slot(self: *const Self, slot_index: usize) *const Section {
            assert(slot_index < self.slots.items.len);
            if (self.slots.items[slot_index]) |*section| return section;
            @panic("key handle must reference a retained section");
        }

        /// The retained section in `slot_index`, or null for a free slot. Iterate slots
        /// `0..slot_count()` to visit every retained section with its slot.
        pub fn at_slot(self: *const Self, slot_index: usize) ?*const Section {
            assert(slot_index < self.slots.items.len);
            const section = if (self.slots.items[slot_index]) |*section| section else return null;
            assert(section.keys.items.len > 0);
            return section;
        }

        pub fn slot_count(self: *const Self) usize {
            assert(self.by_start.items.len + self.free.items.len == self.slots.items.len);
            return self.slots.items.len;
        }

        /// The slot of the section starting at `start`, creating the section if needed.
        fn slot_for(self: *Self, gpa: Allocator, start: u64) Allocator.Error!usize {
            const at = self.lower_bound(start);
            if (at < self.by_start.items.len and self.by_start.items[at].start == start) {
                return self.by_start.items[at].slot;
            }
            try self.by_start.ensureUnusedCapacity(gpa, 1);
            const slot_index = self.free.pop() orelse grow: {
                if (self.slots.items.len >= max_slots) @panic("too many retained sections");
                try self.free.ensureTotalCapacity(gpa, self.slots.items.len + 1);
                try self.slots.append(gpa, null);
                break :grow self.slots.items.len - 1;
            };
            assert(self.slots.items[slot_index] == null);
            self.slots.items[slot_index] = .{ .start = start };
            self.by_start.insertAssumeCapacity(at, .{ .start = start, .slot = slot_index });
            return slot_index;
        }

        /// Adds the record at `position` of the section starting at `start`, creating the
        /// section if needed. Returns the section's slot and whether this is the first record
        /// at `offset`.
        pub fn add(
            self: *Self,
            gpa: Allocator,
            start: u64,
            offset: u64,
            position: u64,
            translated: Key,
        ) Allocator.Error!Added {
            const slot_index = try self.slot_for(gpa, start);
            const section = &self.slots.items[slot_index].?;
            assert(section.start == start);
            // Records must arrive in journal order.
            assert(section.keys.items.len == position);
            try section.keys.ensureUnusedCapacity(gpa, 1);
            const first = try section.positions.insert(gpa, offset, position);
            section.keys.appendAssumeCapacity(translated);
            return .{ .slot = slot_index, .first = first };
        }

        /// A section removed by `pop_below`. The caller owns `section`.
        pub const Popped = struct { slot: usize, section: Section };

        /// Removes the oldest section if it starts below `min`, freeing its slot.
        pub fn pop_below(self: *Self, min: u64) ?Popped {
            if (self.by_start.items.len == 0) return null;
            const oldest = self.by_start.items[0];
            if (oldest.start >= min) return null;
            _ = self.by_start.orderedRemove(0);
            const section = self.slots.items[oldest.slot].?;
            self.slots.items[oldest.slot] = null;
            assert(self.free.items.len < self.free.capacity);
            self.free.appendAssumeCapacity(oldest.slot);
            assert(section.start == oldest.start);
            return .{ .slot = oldest.slot, .section = section };
        }
    };
}

test "positions match a model" {
    const gpa = std.testing.allocator;
    var positions: Positions = .{};
    defer positions.deinit(gpa);
    var model = std.AutoHashMap(u64, u64).init(gpa);
    defer model.deinit();
    const offsets = [_]u64{ 3, 0, 3, 7, 1, 0, 12, 7, 5 };
    for (offsets, 0..) |offset, position| {
        const inserted = try positions.insert(gpa, offset, position);
        const result = try model.getOrPut(offset);
        if (!result.found_existing) result.value_ptr.* = position;
        try std.testing.expectEqual(!result.found_existing, inserted);
    }
    try std.testing.expectEqual(model.count(), positions.len());
    for (0..16) |offset| {
        try std.testing.expectEqual(model.get(offset), positions.get(offset));
    }
    try std.testing.expectEqual(null, positions.get(1 << 50));
}

test "handles round-trip" {
    const cases = [_]Unpacked{
        .{ .slot = 0, .position = 0 },
        .{ .slot = max_slots - 1, .position = (1 << 40) - 1 },
        .{ .slot = 5, .position = 1234 },
    };
    for (cases) |case| {
        const unpacked = unpack(handle(case.slot, case.position));
        try std.testing.expectEqual(case, unpacked);
    }
}
