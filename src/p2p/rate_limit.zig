//! Rate limiting quotas and a keyed GCRA rate limiter (commonware `runtime::Quota` and
//! `runtime::KeyedRateLimiter`, which re-export the `governor` 0.10 crate).
//!
//! The algorithm is governor's generic cell rate algorithm, step for step:
//! `t = max(replenish_1_per, 1ns)`, `tau = t * (max_burst - 1)`, and per key a theoretical
//! arrival time `tat` in nanoseconds since the limiter started (zero means fresh). A check at
//! `t0` is rejected while `t0 < tat - tau` (the earliest possible time is `start + tat - tau`);
//! otherwise `tat` becomes `max(tat, t0) + t`. So a fresh key admits `max_burst` cells at once
//! and then one per `t`.
//!
//! Lives in p2p until the runtime lane ports it; the interface matches commonware's so the
//! move changes no callers. Keys are kept in a sorted array (binary search by `K.order`), so
//! lookups are deterministic and `retain_recent` bounds memory.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");

const SystemTime = utils.SystemTime;
const Duration = utils.Duration;

/// A rate-limiting quota: up to `max_burst` cells at once, replenished one per
/// `replenish_1_per_ns` (governor `Quota`).
pub const Quota = struct {
    max_burst: u32,
    replenish_1_per_ns: u64,

    /// `max_burst` cells per second, replenished evenly (integer nanoseconds, truncated).
    pub fn per_second(max_burst: u32) Quota {
        return per_period(max_burst, std.time.ns_per_s);
    }

    /// `max_burst` cells per minute.
    pub fn per_minute(max_burst: u32) Quota {
        return per_period(max_burst, 60 * std.time.ns_per_s);
    }

    /// `max_burst` cells per hour.
    pub fn per_hour(max_burst: u32) Quota {
        return per_period(max_burst, 3600 * std.time.ns_per_s);
    }

    fn per_period(max_burst: u32, period_ns: u64) Quota {
        assert(max_burst > 0);
        assert(period_ns > 0);
        return .{ .max_burst = max_burst, .replenish_1_per_ns = period_ns / max_burst };
    }

    /// One cell per `replenish_1_per`, burst of one; null for a zero period.
    pub fn with_period(replenish_1_per: Duration) ?Quota {
        const nanos = replenish_1_per.as_nanos();
        if (nanos == 0) return null;
        const clamped: u64 = @intCast(@min(nanos, std.math.maxInt(u64)));
        return .{ .max_burst = 1, .replenish_1_per_ns = clamped };
    }

    /// The same replenishment interval with a different burst size.
    pub fn allow_burst(quota: Quota, max_burst: u32) Quota {
        assert(max_burst > 0);
        return .{ .max_burst = max_burst, .replenish_1_per_ns = quota.replenish_1_per_ns };
    }

    pub fn burst_size(quota: Quota) u32 {
        assert(quota.max_burst > 0);
        return quota.max_burst;
    }

    pub fn replenish_interval(quota: Quota) Duration {
        return Duration.from_nanos(quota.replenish_1_per_ns);
    }
};

/// Governor's GCRA parameters.
const Gcra = struct {
    t: u64,
    tau: u64,

    fn init(quota: Quota) Gcra {
        assert(quota.max_burst > 0);
        const t = @max(quota.replenish_1_per_ns, 1);
        const tau = std.math.mul(u64, t, quota.max_burst - 1) catch std.math.maxInt(u64);
        assert(t >= 1);
        return .{ .t = t, .tau = tau };
    }
};

/// A rate limiter keyed by `K` (`K.order(a, b)`), reading time from a `std.Io` real clock.
pub fn KeyedRateLimiter(comptime K: type) type {
    return struct {
        const Self = @This();

        pub const Entry = struct { key: K, tat_ns: u64 };

        gpa: Allocator,
        io: Io,
        gcra: Gcra,
        start: SystemTime,
        /// Strictly ascending by key.
        entries: std.ArrayList(Entry) = .empty,

        pub fn init(gpa: Allocator, io: Io, quota: Quota) Self {
            const start = SystemTime.from_timestamp(Io.Clock.real.now(io));
            return init_at(gpa, io, quota, start);
        }

        /// A limiter whose clock started at `start` (for tests that drive time by hand).
        pub fn init_at(gpa: Allocator, io: Io, quota: Quota, start: SystemTime) Self {
            return .{ .gpa = gpa, .io = io, .gcra = .init(quota), .start = start };
        }

        pub fn deinit(limiter: *Self) void {
            limiter.entries.deinit(limiter.gpa);
            limiter.* = undefined;
        }

        pub fn now(limiter: *const Self) SystemTime {
            return SystemTime.from_timestamp(Io.Clock.real.now(limiter.io));
        }

        /// Admits one cell for `key` now, or returns the earliest time it would be admitted
        /// (governor `NotUntil::earliest_possible`).
        pub fn check_key(limiter: *Self, key: K) Allocator.Error!?SystemTime {
            return limiter.check_key_at(key, limiter.now());
        }

        /// `check_key` at an explicit time.
        pub fn check_key_at(limiter: *Self, key: K, at: SystemTime) Allocator.Error!?SystemTime {
            const t0 = limiter.since_start(at);
            const index = try limiter.find_or_insert(key);
            const entry = &limiter.entries.items[index];
            const tat = if (entry.tat_ns == 0) t0 else entry.tat_ns;
            const earliest_ns = tat -| limiter.gcra.tau;
            if (t0 < earliest_ns) {
                assert(entry.tat_ns != 0);
                return limiter.start.saturating_add(Duration.from_nanos(earliest_ns));
            }
            entry.tat_ns = @max(tat, t0) +| limiter.gcra.t;
            assert(entry.tat_ns > t0);
            return null;
        }

        /// Whether `key` would be admitted now, without consuming a cell.
        pub fn would_admit(limiter: *const Self, key: K, at: SystemTime) bool {
            const t0 = limiter.since_start(at);
            const index = limiter.find(key) orelse return true;
            const tat = limiter.entries.items[index].tat_ns;
            if (tat == 0) return true;
            return t0 >= tat -| limiter.gcra.tau;
        }

        /// Drops keys indistinguishable from a fresh key (governor `retain_recent`).
        pub fn retain_recent(limiter: *Self) void {
            limiter.retain_recent_at(limiter.now());
        }

        pub fn retain_recent_at(limiter: *Self, at: SystemTime) void {
            const drop_below = limiter.since_start(at) -| limiter.gcra.t;
            var kept: usize = 0;
            for (limiter.entries.items) |entry| {
                if (entry.tat_ns <= drop_below) continue;
                limiter.entries.items[kept] = entry;
                kept += 1;
            }
            assert(kept <= limiter.entries.items.len);
            limiter.entries.shrinkRetainingCapacity(kept);
        }

        /// Number of keys with state.
        pub fn len(limiter: *const Self) usize {
            return limiter.entries.items.len;
        }

        fn since_start(limiter: *const Self, at: SystemTime) u64 {
            const delta = at.nanos_since_epoch - limiter.start.nanos_since_epoch;
            if (delta <= 0) return 0;
            return std.math.cast(u64, delta) orelse std.math.maxInt(u64);
        }

        fn find(limiter: *const Self, key: K) ?usize {
            return std.sort.binarySearch(Entry, limiter.entries.items, key, compare);
        }

        fn find_or_insert(limiter: *Self, key: K) Allocator.Error!usize {
            const index = std.sort.lowerBound(Entry, limiter.entries.items, key, compare);
            const items = limiter.entries.items;
            if (index < items.len and K.order(items[index].key, key) == .eq) return index;
            try limiter.entries.insert(limiter.gpa, index, .{ .key = key, .tat_ns = 0 });
            assert(K.order(limiter.entries.items[index].key, key) == .eq);
            return index;
        }

        fn compare(key: K, entry: Entry) std.math.Order {
            return K.order(key, entry.key);
        }
    };
}

const testing = std.testing;

const Key = struct {
    id: u32,
    pub fn order(a: Key, b: Key) std.math.Order {
        return std.math.order(a.id, b.id);
    }
};

const Limiter = KeyedRateLimiter(Key);
const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

fn limiter_at_zero(quota: Quota) Limiter {
    return Limiter.init_at(testing.allocator, Io.failing, quota, at_ms(0));
}

fn at_ms(ms: u64) SystemTime {
    return .{ .nanos_since_epoch = @as(i128, ms) * std.time.ns_per_ms };
}

test "quota constructors" {
    const unlimited = Quota.per_second(std.math.maxInt(u32));
    try testing.expectEqual(@as(u64, 100 * ns_per_ms), Quota.per_second(10).replenish_1_per_ns);
    try testing.expectEqual(@as(u64, 0), unlimited.replenish_1_per_ns);
    try testing.expectEqual(@as(u64, 6 * ns_per_s), Quota.per_minute(10).replenish_1_per_ns);
    try testing.expectEqual(@as(u64, 360 * ns_per_s), Quota.per_hour(10).replenish_1_per_ns);
    try testing.expect(Quota.with_period(Duration.zero) == null);
    const quota = Quota.with_period(Duration.from_millis(5)).?.allow_burst(7);
    try testing.expectEqual(@as(u32, 7), quota.burst_size());
    try testing.expectEqual(@as(u64, 5 * ns_per_ms), quota.replenish_1_per_ns);
}

test "burst then one per interval, with governor's earliest time" {
    var limiter = limiter_at_zero(.per_second(1));
    defer limiter.deinit();
    const key: Key = .{ .id = 1 };
    try testing.expect(try limiter.check_key_at(key, at_ms(0)) == null);
    // governor's notuntil test: "rate-limited until Nanos(1s)".
    const retry = (try limiter.check_key_at(key, at_ms(0))).?;
    try testing.expect(retry.order(at_ms(1000)) == .eq);
    try testing.expect((try limiter.check_key_at(key, at_ms(999))) != null);
    try testing.expect(try limiter.check_key_at(key, at_ms(1000)) == null);
    // Other keys are independent.
    try testing.expect(try limiter.check_key_at(.{ .id = 2 }, at_ms(1000)) == null);
    try testing.expectEqual(@as(usize, 2), limiter.len());
}

test "burst of max_burst cells" {
    var limiter = limiter_at_zero(.per_second(10));
    defer limiter.deinit();
    const key: Key = .{ .id = 7 };
    for (0..10) |_| try testing.expect(try limiter.check_key_at(key, at_ms(0)) == null);
    const retry = (try limiter.check_key_at(key, at_ms(0))).?;
    try testing.expect(retry.order(at_ms(100)) == .eq);
    try testing.expect(!limiter.would_admit(key, at_ms(99)));
    try testing.expect(limiter.would_admit(key, at_ms(100)));
    try testing.expect(try limiter.check_key_at(key, at_ms(100)) == null);
    try testing.expect((try limiter.check_key_at(key, at_ms(100))) != null);
}

test "zero replenish interval never limits" {
    const quota = Quota.per_second(std.math.maxInt(u32));
    var limiter = limiter_at_zero(quota);
    defer limiter.deinit();
    for (0..10_000) |_| {
        try testing.expect(try limiter.check_key_at(.{ .id = 1 }, at_ms(0)) == null);
    }
}

test "retain_recent drops keys that look fresh" {
    var limiter = limiter_at_zero(.per_second(1));
    defer limiter.deinit();
    for (0..4) |id| _ = try limiter.check_key_at(.{ .id = @intCast(id) }, at_ms(0));
    _ = try limiter.check_key_at(.{ .id = 9 }, at_ms(1500));
    // drop_below = 2000ms - 1000ms; keys 0..3 have tat 1000ms, key 9 has 2500ms.
    limiter.retain_recent_at(at_ms(2000));
    try testing.expectEqual(@as(usize, 1), limiter.len());
    try testing.expectEqual(@as(u32, 9), limiter.entries.items[0].key.id);
}
