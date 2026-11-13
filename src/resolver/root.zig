//! resolver: Resolve data identified by a fixed-length key.
//!
//! Zig port of commonware's `commonware-resolver` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/resolver). docs/lanes/broadcast-resolver.md
//! tracks what is ported.
//!
//! The lib.rs traits are comptime interfaces, checked with the `assert_*` functions below:
//!
//! - `Consumer`: `C.Key` (a `utils.Span`), `C.Value`, `C.Subscriber`, `C.Outcome` (`Outcome`
//!   or `bool`), and `c.deliver(delivery, value) !oneshot.Receiver(C.Outcome)`.
//! - `Resolver`: `R.Key`, `R.Subscriber`, `r.fetch(Fetch) Feedback`,
//!   `r.fetch_all([]const Fetch) Feedback`, `r.retain(Predicate) Feedback`.
//! - `TargetedResolver`: a `Resolver` with `R.PublicKey`,
//!   `r.fetch_targeted(Fetch, []const PublicKey) Feedback` and
//!   `r.fetch_all_targeted([]const Targeted) Feedback`.
//!
//! Keys and subscribers compare with `order` below (codec's `Ord`, plus `void` for the unit
//! subscriber). commonware attaches a `tracing::Span` to every subscriber; zigware has no
//! tracing, so spans are not carried.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const actor = @import("actor");

pub const subscribers = @import("subscribers.zig");
pub const ingress = @import("ingress.zig");
pub const p2p = @import("p2p/mod.zig");

pub const Feedback = actor.Feedback;

/// Rust `Ord` for keys and subscribers: codec's order, with `void` (Rust `()`) always equal.
pub fn order(comptime T: type, a: T, b: T) std.math.Order {
    if (T == void) return .eq;
    return codec.order(T, a, b);
}

/// Rust `Eq` for keys and subscribers.
pub fn eql(comptime T: type, a: T, b: T) bool {
    return order(T, a, b) == .eq;
}

/// A key to fetch data for a subscriber.
pub fn Fetch(comptime K: type, comptime S: type) type {
    return struct {
        const Self = @This();

        /// The peer-visible key.
        key: K,
        /// Subscriber attached to the key.
        subscriber: S,

        /// A fetch with the default (unit) subscriber (Rust `From<K>`).
        pub fn from_key(key: K) Self {
            comptime assert(S == void);
            return .{ .key = key, .subscriber = {} };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.order(b) == .eq;
        }

        /// Key first, then subscriber.
        pub fn order(a: Self, b: Self) std.math.Order {
            const key_order = root.order(K, a.key, b.key);
            if (key_order != .eq) return key_order;
            return root.order(S, a.subscriber, b.subscriber);
        }
    };
}

const root = @This();

/// Data delivered for a resolved fetch.
pub fn Delivery(comptime K: type, comptime S: type) type {
    return struct {
        const Self = @This();

        /// The peer-visible key used to validate the response.
        key: K,
        /// Subscribers still retained when the response arrived (never empty).
        subscribers: []const S,

        pub fn eql(a: Self, b: Self) bool {
            return a.order(b) == .eq;
        }

        /// Key first, then subscribers lexicographically.
        pub fn order(a: Self, b: Self) std.math.Order {
            assert(a.subscribers.len > 0);
            assert(b.subscribers.len > 0);
            const key_order = root.order(K, a.key, b.key);
            if (key_order != .eq) return key_order;
            const common = @min(a.subscribers.len, b.subscribers.len);
            for (a.subscribers[0..common], b.subscribers[0..common]) |left, right| {
                const item_order = root.order(S, left, right);
                if (item_order != .eq) return item_order;
            }
            return std.math.order(a.subscribers.len, b.subscribers.len);
        }
    };
}

/// Completion of the delivered subscriber snapshot.
pub const Resolution = enum {
    /// No delivered subscribers remain unresolved.
    complete,
    /// Some delivered subscribers remain unresolved.
    partial,
};

/// Consumer disposition for a delivered response.
pub const Outcome = union(enum) {
    /// The response is invalid for the peer-visible key. Network resolvers may penalize the
    /// serving peer before retrying.
    invalid,
    /// The response is valid and resolves at least one delivered subscriber. `complete`
    /// retires the delivered subscribers; `partial` retries the key. Network resolvers may
    /// credit the serving peer in either case.
    resolved: Resolution,
    /// The response is valid but resolves no delivered subscriber. The resolver retries
    /// without crediting or penalizing the serving peer.
    unresolved,
    /// The consumer no longer needs the key. The resolver retires the key and all of its
    /// subscribers without retrying or attributing the response to its source.
    ignored,

    /// `true` is `resolved(complete)`, `false` is `invalid` (Rust `From<bool>`).
    pub fn from_bool(valid: bool) Outcome {
        return if (valid) .{ .resolved = .complete } else .invalid;
    }

    /// Converts a consumer's outcome type (`Outcome` or `bool`).
    pub fn from(value: anytype) Outcome {
        const T = @TypeOf(value);
        if (T == Outcome) return value;
        if (T == bool) return from_bool(value);
        @compileError("resolver: consumer outcome must be Outcome or bool, not " ++ @typeName(T));
    }

    pub fn eql(a: Outcome, b: Outcome) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .resolved => |resolution| resolution == b.resolved,
            else => true,
        };
    }
};

/// A retain predicate over `(key, subscriber)` pairs (Rust `Box<dyn Fn(&K, &S) -> bool>`).
///
/// The captured state is copied inline (at most `state_size_max` bytes), so a predicate is a
/// plain value that needs no allocation and can be queued in a mailbox.
pub fn Predicate(comptime K: type, comptime S: type) type {
    return struct {
        const Self = @This();
        pub const state_size_max = 64;

        state: [state_size_max]u8 align(16),
        function: *const fn (state: *const anyopaque, key: K, subscriber: S) bool,

        /// A predicate calling `function(captured, key, subscriber)`.
        pub fn init(
            captured: anytype,
            comptime function: fn (@TypeOf(captured), K, S) bool,
        ) Self {
            const Captured = @TypeOf(captured);
            comptime assert(@sizeOf(Captured) <= state_size_max);
            comptime assert(@alignOf(Captured) <= 16);
            const Thunk = struct {
                fn call(state: *const anyopaque, key: K, subscriber: S) bool {
                    const value: *const Captured = @ptrCast(@alignCast(state));
                    return function(value.*, key, subscriber);
                }
            };
            var self: Self = .{ .state = @splat(0), .function = Thunk.call };
            @memcpy(self.state[0..@sizeOf(Captured)], std.mem.asBytes(&captured));
            return self;
        }

        pub fn call(self: *const Self, key: K, subscriber: S) bool {
            return self.function(&self.state, key, subscriber);
        }
    };
}

/// Checks that `C` is a `Consumer`.
pub fn assert_consumer(comptime C: type) void {
    comptime {
        assert(@hasDecl(C, "Key"));
        assert(@hasDecl(C, "Value"));
        assert(@hasDecl(C, "Subscriber"));
        assert(@hasDecl(C, "Outcome"));
        assert(C.Outcome == Outcome or C.Outcome == bool);
        assert(@hasDecl(C, "deliver"));
    }
}

/// Checks that `R` is a `Resolver`.
pub fn assert_resolver(comptime R: type) void {
    comptime {
        assert(@hasDecl(R, "Key"));
        assert(@hasDecl(R, "Subscriber"));
        assert(@hasDecl(R, "fetch"));
        assert(@hasDecl(R, "fetch_all"));
        assert(@hasDecl(R, "retain"));
    }
}

/// Checks that `R` is a `TargetedResolver`.
pub fn assert_targeted_resolver(comptime R: type) void {
    comptime {
        assert_resolver(R);
        assert(@hasDecl(R, "PublicKey"));
        assert(@hasDecl(R, "fetch_targeted"));
        assert(@hasDecl(R, "fetch_all_targeted"));
    }
}

const testing = std.testing;

test "fetch orders by key then subscriber" {
    const F = Fetch(u8, u16);
    const a: F = .{ .key = 1, .subscriber = 9 };
    const b: F = .{ .key = 2, .subscriber = 0 };
    const c: F = .{ .key = 1, .subscriber = 10 };
    try testing.expectEqual(std.math.Order.lt, a.order(b));
    try testing.expectEqual(std.math.Order.lt, a.order(c));
    try testing.expect(a.eql(a));
    const unit = Fetch(u8, void).from_key(4);
    try testing.expectEqual(@as(u8, 4), unit.key);
}

test "delivery compares keys then subscribers" {
    const D = Delivery(u8, u16);
    const a: D = .{ .key = 1, .subscribers = &.{ 1, 2 } };
    const b: D = .{ .key = 1, .subscribers = &.{ 1, 2, 3 } };
    const c: D = .{ .key = 1, .subscribers = &.{2} };
    try testing.expectEqual(std.math.Order.lt, a.order(b));
    try testing.expectEqual(std.math.Order.lt, b.order(c));
    try testing.expect(a.eql(.{ .key = 1, .subscribers = &.{ 1, 2 } }));
}

test "outcome from bool" {
    try testing.expect(Outcome.from(true).eql(.{ .resolved = .complete }));
    try testing.expect(Outcome.from(false).eql(.invalid));
    try testing.expect(!Outcome.eql(.{ .resolved = .partial }, .{ .resolved = .complete }));
    try testing.expect(Outcome.from(@as(Outcome, .ignored)).eql(.ignored));
}

test "predicate captures state by value" {
    const P = Predicate(u8, u16);
    const Floor = struct { floor: u8 };
    const predicate = P.init(Floor{ .floor = 3 }, struct {
        fn keep(captured: Floor, key: u8, _: u16) bool {
            return key >= captured.floor;
        }
    }.keep);
    const copy = predicate;
    try testing.expect(copy.call(3, 0));
    try testing.expect(!copy.call(2, 0));
}

test {
    std.testing.refAllDecls(@This());
}
