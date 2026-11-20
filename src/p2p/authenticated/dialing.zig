//! Dialing results shared by the lookup and discovery trackers (commonware
//! `p2p/src/authenticated/dialing.rs`).

const std = @import("std");
const utils = @import("utils");

const SystemTime = utils.SystemTime;
const Duration = utils.Duration;

/// Merges `b` into `a`, keeping the earliest time.
pub fn earliest(a: ?SystemTime, b: SystemTime) SystemTime {
    const current = a orelse return b;
    return current.min(b);
}

/// Whether a peer is dialable.
pub const DialStatus = union(enum) {
    /// Dial the peer now.
    now,
    /// The peer becomes dialable at this time.
    after: SystemTime,
    /// The peer is not dialable.
    unavailable,
};

/// Result of reserving a peer.
pub const ReserveResult = enum {
    reserved,
    /// Not enough time has passed since the last reservation.
    rate_limited,
    /// Already reserved, ourselves, or otherwise not reservable.
    unavailable,
};

/// Rust's `Duration / u32`.
pub fn divide(duration: Duration, divisor: u32) Duration {
    std.debug.assert(divisor > 0);
    const secs = duration.secs / divisor;
    const carry = duration.secs - secs * divisor;
    const extra_nanos: u32 = @intCast(@as(u128, carry) * utils.time.NANOS_PER_SEC / divisor);
    return .init(secs, duration.nanos / divisor + extra_nanos);
}

const testing = std.testing;

test "earliest keeps the smaller time" {
    const one: SystemTime = .{ .nanos_since_epoch = 1 };
    const two: SystemTime = .{ .nanos_since_epoch = 2 };
    try testing.expectEqual(one, earliest(null, one));
    try testing.expectEqual(one, earliest(two, one));
    try testing.expectEqual(one, earliest(one, two));
}

test "divide matches Rust's Duration division" {
    try testing.expectEqual(Duration.init(0, 500_000_000), divide(.init(1, 1), 2));
    try testing.expectEqual(Duration.init(2, 250_000_000), divide(.init(4, 500_000_000), 2));
    const half_max = divide(Duration.max, 2);
    try testing.expectEqual(std.math.maxInt(u64) / 2, half_max.secs);
    try testing.expectEqual(@as(u32, 999_999_999), half_max.nanos);
}
