//! Non-blocking concurrency limits (commonware `utils/src/concurrency.rs`).
//!
//! A reservation points at its limiter (Rust shares it through an `Arc`), so a limiter must
//! outlive its reservations; `deinit` asserts none are held. `KeyedLimiter` allocates its key
//! set for `max` keys at `init` and never allocates afterwards. Keys are copied by value (a
//! slice key is borrowed) and hash like `cache` keys (`K.hash`/`K.eql` when declared).

const std = @import("std");
const cache = @import("cache.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Limits the concurrency of an operation without blocking.
pub const Limiter = struct {
    max: u32,
    current: std.atomic.Value(u32) = .init(0),

    /// A limiter that allows up to `max` (> 0) concurrent reservations.
    pub fn init(max: u32) Limiter {
        assert(max > 0);
        return .{ .max = max };
    }

    /// Asserts that no reservation is held.
    pub fn deinit(limiter: *Limiter) void {
        assert(limiter.current.load(.acquire) == 0);
        limiter.* = undefined;
    }

    /// Reserves a slot, or returns null when the limiter is saturated.
    pub fn try_acquire(limiter: *Limiter) ?Reservation {
        var current = limiter.current.load(.monotonic);
        while (current < limiter.max) {
            current = limiter.current.cmpxchgWeak(current, current + 1, .acq_rel, .monotonic) orelse
                return .{ .limiter = limiter };
        }
        assert(current == limiter.max);
        return null;
    }

    /// Slots held right now.
    pub fn len(limiter: *const Limiter) u32 {
        const current = limiter.current.load(.acquire);
        assert(current <= limiter.max);
        return current;
    }
};

/// A slot held in a `Limiter`; `deinit` releases it.
pub const Reservation = struct {
    limiter: *Limiter,

    pub fn deinit(reservation: *Reservation) void {
        const previous = reservation.limiter.current.fetchSub(1, .acq_rel);
        assert(previous > 0 and previous <= reservation.limiter.max);
        reservation.* = undefined;
    }
};

/// Limits the concurrency of a keyed operation without blocking: at most `max` keys at once,
/// and at most one reservation per key.
pub fn KeyedLimiter(comptime K: type) type {
    return struct {
        const Self = @This();

        const Context = struct {
            pub fn hash(_: Context, key: K) u64 {
                return cache.key_hash(K, key);
            }

            pub fn eql(_: Context, a: K, b: K) bool {
                return cache.key_eql(K, a, b);
            }
        };
        const load_percentage = std.hash_map.default_max_load_percentage;
        const Set = std.HashMapUnmanaged(K, void, Context, load_percentage);

        max: u32,
        io: Io,
        mutex: Io.Mutex = .init,
        current: Set,

        pub fn init(gpa: Allocator, io: Io, max: u32) Allocator.Error!Self {
            assert(max > 0);
            var current: Set = .empty;
            try current.ensureTotalCapacity(gpa, max);
            return .{ .max = max, .io = io, .current = current };
        }

        /// Asserts that no reservation is held.
        pub fn deinit(limiter: *Self, gpa: Allocator) void {
            assert(limiter.current.count() == 0);
            limiter.current.deinit(gpa);
            limiter.* = undefined;
        }

        /// Reserves `key`, or returns null when the limiter is saturated or `key` is held.
        pub fn try_acquire(limiter: *Self, key: K) ?KeyedReservation {
            limiter.mutex.lockUncancelable(limiter.io);
            defer limiter.mutex.unlock(limiter.io);
            assert(limiter.current.count() <= limiter.max);
            if (limiter.current.count() >= limiter.max) return null;
            const entry = limiter.current.getOrPutAssumeCapacity(key);
            if (entry.found_existing) return null;
            return .{ .limiter = limiter, .key = key };
        }

        /// Keys held right now.
        pub fn len(limiter: *Self) u32 {
            limiter.mutex.lockUncancelable(limiter.io);
            defer limiter.mutex.unlock(limiter.io);
            return limiter.current.count();
        }

        /// A key held in a `KeyedLimiter`; `deinit` releases it.
        pub const KeyedReservation = struct {
            limiter: *Self,
            key: K,

            pub fn deinit(reservation: *KeyedReservation) void {
                const limiter = reservation.limiter;
                limiter.mutex.lockUncancelable(limiter.io);
                defer limiter.mutex.unlock(limiter.io);
                assert(limiter.current.remove(reservation.key));
                reservation.* = undefined;
            }
        };
    };
}

const testing = std.testing;

test "concurrency: allows reservations up to max" {
    var limiter = Limiter.init(2);
    defer limiter.deinit();
    var first = limiter.try_acquire().?;
    var second = limiter.try_acquire().?;
    try testing.expectEqual(null, limiter.try_acquire());
    second.deinit();
    var third = limiter.try_acquire().?;
    try testing.expectEqual(2, limiter.len());
    third.deinit();
    first.deinit();
    try testing.expectEqual(0, limiter.len());
}

test "concurrency: allows reservations up to max for keys" {
    var limiter = try KeyedLimiter(u64).init(testing.allocator, testing.io, 2);
    defer limiter.deinit(testing.allocator);
    var first = limiter.try_acquire(0).?;
    var second = limiter.try_acquire(1).?;
    try testing.expectEqual(null, limiter.try_acquire(2));
    second.deinit();
    var third = limiter.try_acquire(2).?;
    third.deinit();
    first.deinit();
}

test "concurrency: blocks conflicting reservations for a key" {
    var limiter = try KeyedLimiter([]const u8).init(testing.allocator, testing.io, 2);
    defer limiter.deinit(testing.allocator);
    var first = limiter.try_acquire("peer").?;
    const copy = "peer".*;
    try testing.expectEqual(null, limiter.try_acquire(&copy));
    first.deinit();
    var second = limiter.try_acquire(&copy).?;
    second.deinit();
}

fn contend(limiter: *Limiter, held: *std.atomic.Value(u32), peak: *std.atomic.Value(u32)) void {
    for (0..2000) |_| {
        var reservation = limiter.try_acquire() orelse continue;
        const now = held.fetchAdd(1, .acq_rel) + 1;
        _ = peak.fetchMax(now, .acq_rel);
        _ = held.fetchSub(1, .acq_rel);
        reservation.deinit();
    }
}

test "concurrency: concurrent reservations never exceed max" {
    var limiter = Limiter.init(3);
    defer limiter.deinit();
    var held: std.atomic.Value(u32) = .init(0);
    var peak: std.atomic.Value(u32) = .init(0);
    var group: Io.Group = .init;
    for (0..8) |_| group.async(testing.io, contend, .{ &limiter, &held, &peak });
    try group.await(testing.io);
    try testing.expect(peak.load(.acquire) <= 3);
    try testing.expectEqual(0, limiter.len());
}
