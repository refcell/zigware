//! Policies that advance a batch's inactivity floor (qmdb/floor.rs).
//!
//! After a batch's writes resolve, it asks its policy for `limits` and walks the operations in
//! location order from the floor it inherits toward the tip its writes reached. Each inactive
//! location the walk passes spends a skip; each active update it reaches goes to the policy's
//! `decide` as an `Entry`: keeping, replacing, or evicting it spends an entry and moves the
//! floor one past it, while stopping spends nothing and ends the walk with the floor at the
//! update. See commonware's module documentation for the full rules.
//!
//! A policy is any type with these declarations (commonware's `Policy` trait):
//!
//! ```zig
//! pub fn evicts(self: *const P) bool
//! pub fn limits(self: *const P, made_inactive: usize) Limits
//! pub fn decide(self: *P, comptime K: type, comptime V: type, entry: Entry(K, V)) Decision(V)
//! ```
//!
//! Rust ties a decision to its entry's lifetime; here a policy must return the decision built
//! from the entry it was given (`keep`, `stop`, `replace`, or `evict`).

const std = @import("std");
const assert = std.debug.assert;

/// How far a walk advances the floor: it decides at most `entries` active updates and passes
/// at most `skips` inactive locations.
pub const Limits = struct {
    /// The most active updates to decide.
    entries: usize,
    /// The most inactive locations to pass.
    skips: u64,
};

/// What the walk does with a decided update.
pub fn Action(comptime V: type) type {
    return union(enum) {
        /// Write the value for the update's key at the tip.
        write: V,
        /// Leave the update in place and end the walk.
        stop,
        /// Delete the update's key.
        evict,
    };
}

/// What a policy does with an `Entry`. Only the entry's methods construct one.
pub fn Decision(comptime V: type) type {
    return struct {
        action: Action(V),
        /// The entry's value when the decision does not move it anywhere (`stop`, `replace`);
        /// the walk releases it.
        released: ?V = null,
    };
}

/// An active update at the floor that a policy's `decide` receives. It borrows the update's
/// key and owns its value.
pub fn Entry(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        location: u64,
        key: *const K,
        value: V,

        /// Move the update to the tip.
        pub fn keep(self: Self) Decision(V) {
            return .{ .action = .{ .write = self.value } };
        }

        /// Decide nothing and end the walk with the floor at this update's location.
        pub fn stop(self: Self) Decision(V) {
            return .{ .action = .stop, .released = self.value };
        }

        /// Write `value` for the key at the tip; the walk releases the entry's own value.
        pub fn replace(self: Self, value: V) Decision(V) {
            return .{ .action = .{ .write = value }, .released = self.value };
        }

        /// Delete the key; the owned value is returned alongside the decision.
        pub fn evict(self: Self) struct { Decision(V), V } {
            return .{ .{ .action = .evict }, self.value };
        }
    };
}

/// A floor walk's position and remaining limits. The floor it reaches depends only on which
/// locations hold active updates, not on how they were read.
pub const Walk = struct {
    /// Every location below it is inactive or decided.
    floor: u64,
    /// The walk reads and decides nothing at or past it.
    end: u64,
    /// Active updates left to decide.
    entries: usize,
    /// Inactive locations left to pass.
    skips: u64,

    /// A walk at `floor` that ends at `tip` or where `skips` and `entries` run out.
    pub fn init(floor: u64, tip: u64, entries: usize, skips: u64) Walk {
        assert(floor <= tip);
        const limit = floor +| skips +| @as(u64, entries);
        const walk: Walk = .{
            .floor = floor,
            .end = @min(limit, tip),
            .entries = entries,
            .skips = skips,
        };
        assert(walk.floor <= walk.end);
        return walk;
    }

    /// Moves the floor to the active update at `location`, spending the inactive gap in
    /// skips. When the gap exceeds the remaining skips, the floor advances by them instead and
    /// the walk ends (returns false).
    pub fn reach(self: *Walk, location: u64) bool {
        assert(location >= self.floor);
        const gap = location - self.floor;
        if (gap > self.skips) {
            self.floor += self.skips;
            self.skips = 0;
            return false;
        }
        self.skips -= gap;
        self.floor = location;
        return true;
    }

    /// Spends an entry on the update at the floor and moves the floor past it.
    pub fn decide(self: *Walk) void {
        assert(self.entries > 0);
        self.entries -= 1;
        self.floor += 1;
    }

    /// The number of leading `candidates` (ascending locations of active updates) the walk's
    /// remaining entries and skips let it reach.
    pub fn reachable(self: *const Walk, candidates: []const u64) usize {
        var floor = self.floor;
        var skips = self.skips;
        const limit = @min(candidates.len, self.entries);
        for (candidates[0..limit], 0..) |location, index| {
            assert(location >= floor);
            const gap = location - floor;
            if (gap > skips) return index;
            skips -= gap;
            floor = location + 1;
        }
        return limit;
    }

    /// No active update remains below `end`: the floor moves there if the remaining skips
    /// reach it, and by them otherwise.
    pub fn exhaust(self: *Walk) void {
        assert(self.floor <= self.end);
        const gap = @min(self.end - self.floor, self.skips);
        self.floor += gap;
        self.skips -= gap;
    }
};

/// Advances the floor in proportion to the operations a batch makes inactive: one entry per
/// operation made inactive plus one for the previous commit, with unlimited skips. Keeps
/// every entry. Each batch then leaves the database's size at most `3n + 1` operations past
/// its floor, for `n` active keys.
pub const Proportional = struct {
    /// `decide` keeps every entry, so the walk need not hand it an owned copy.
    pub const keeps_every_entry = true;

    pub fn evicts(_: *const Proportional) bool {
        return false;
    }

    pub fn limits(_: *const Proportional, made_inactive: usize) Limits {
        return .{ .entries = made_inactive + 1, .skips = std.math.maxInt(u64) };
    }

    pub fn decide(
        _: *Proportional,
        comptime K: type,
        comptime V: type,
        entry: Entry(K, V),
    ) Decision(V) {
        return entry.keep();
    }
};

/// Holds the floor at its inherited location (or moves it to the new commit if the batch's
/// final state is empty).
pub const Hold = struct {
    pub fn evicts(_: *const Hold) bool {
        return false;
    }

    pub fn limits(_: *const Hold, _: usize) Limits {
        return .{ .entries = 0, .skips = 0 };
    }

    /// Not called with zero `entries`.
    pub fn decide(_: *Hold, comptime K: type, comptime V: type, entry: Entry(K, V)) Decision(V) {
        return entry.stop();
    }
};

/// Keeps every active update it reaches within its limits.
pub const Bounded = struct {
    /// The most active updates to keep.
    entries: usize,
    /// The most inactive locations to pass.
    skips: u64,

    pub fn evicts(_: *const Bounded) bool {
        return false;
    }

    pub fn limits(self: *const Bounded, _: usize) Limits {
        return .{ .entries = self.entries, .skips = self.skips };
    }

    pub fn decide(
        _: *Bounded,
        comptime K: type,
        comptime V: type,
        entry: Entry(K, V),
    ) Decision(V) {
        return entry.keep();
    }
};

/// Asserts at comptime that `P` is a floor policy.
/// Whether policy `P` declares that its `decide` returns `keep()` for every entry and never
/// evicts, so the walk may skip `decide` and keep each update's value as it is.
pub fn keeps_every_entry(comptime P: type) bool {
    return @hasDecl(P, "keeps_every_entry") and P.keeps_every_entry;
}

pub fn check(comptime P: type) void {
    comptime {
        assert(@hasDecl(P, "evicts"));
        assert(@hasDecl(P, "limits"));
        assert(@hasDecl(P, "decide"));
    }
}

const testing = std.testing;

test "walk window ends at tip or limits" {
    const max_usize = std.math.maxInt(usize);
    try testing.expectEqual(@as(u64, 9), Walk.init(3, 100, 2, 4).end);
    try testing.expectEqual(@as(u64, 5), Walk.init(3, 5, 2, 4).end);
    try testing.expectEqual(@as(u64, 100), Walk.init(3, 100, max_usize, std.math.maxInt(u64)).end);
    try testing.expectEqual(@as(u64, 3), Walk.init(3, 100, 0, 0).end);
}

test "walk reaches and decides" {
    var walk = Walk.init(0, 100, 2, 3);
    try testing.expect(walk.reach(2));
    try testing.expectEqual(@as(u64, 2), walk.floor);
    walk.decide();
    try testing.expectEqual(@as(u64, 3), walk.floor);
    try testing.expectEqual(@as(usize, 1), walk.entries);
    try testing.expect(walk.reach(3));
    walk.decide();
    try testing.expectEqual(@as(u64, 4), walk.floor);
    try testing.expectEqual(@as(usize, 0), walk.entries);

    walk = Walk.init(0, 100, 2, 3);
    try testing.expect(walk.reach(1));
    walk.decide();
    try testing.expect(!walk.reach(5));
    try testing.expectEqual(@as(u64, 4), walk.floor);
}

test "walk exhausts to window end" {
    var walk = Walk.init(0, 10, 5, 2);
    walk.exhaust();
    try testing.expectEqual(@as(u64, 2), walk.floor);

    walk = Walk.init(0, 3, 5, 10);
    walk.exhaust();
    try testing.expectEqual(@as(u64, 3), walk.floor);

    walk = Walk.init(4, 10, 1, std.math.maxInt(u64));
    try testing.expect(walk.reach(6));
    walk.exhaust();
    try testing.expectEqual(@as(u64, 10), walk.floor);
}

test "walk reaches leading candidates within limits" {
    try testing.expectEqual(@as(usize, 2), Walk.init(0, 100, 3, 2).reachable(&.{ 1, 2, 5, 6 }));
    try testing.expectEqual(@as(usize, 1), Walk.init(0, 100, 1, 10).reachable(&.{ 3, 4 }));
    try testing.expectEqual(@as(usize, 1), Walk.init(0, 100, 2, 0).reachable(&.{ 0, 2 }));
    try testing.expectEqual(@as(usize, 0), Walk.init(0, 100, 2, 0).reachable(&.{1}));
    try testing.expectEqual(@as(usize, 0), Walk.init(0, 100, 0, 10).reachable(&.{0}));
    try testing.expectEqual(@as(usize, 0), Walk.init(0, 100, 2, 0).reachable(&.{}));
}

test "policies" {
    check(Proportional);
    check(Hold);
    check(Bounded);
    var proportional: Proportional = .{};
    try testing.expectEqual(@as(usize, 4), proportional.limits(3).entries);
    const key: u64 = 9;
    const decision = proportional.decide(u64, u64, .{ .location = 1, .key = &key, .value = 5 });
    try testing.expectEqual(@as(u64, 5), decision.action.write);
    var hold: Hold = .{};
    try testing.expectEqual(@as(usize, 0), hold.limits(10).entries);
    try testing.expect(hold.decide(u64, u64, .{ .location = 1, .key = &key, .value = 5 })
        .action == .stop);
    const evicted, const owned = (Entry(u64, u64){ .location = 1, .key = &key, .value = 7 })
        .evict();
    try testing.expect(evicted.action == .evict);
    try testing.expectEqual(@as(u64, 7), owned);
}
