//! Reporter implementations for standard shapes (commonware `consensus/src/reporter.rs`).
//!
//! - `Optional(R)`: commonware's `impl Reporter for Option<R>`; a missing reporter accepts
//!   every activity with `Feedback.ok`.
//! - `Reporters(R1, R2)`: reports to two optional reporters and returns the worst feedback.
//!
//! Activities are values: both reporters of `Reporters` receive the same value, so an
//! activity that owns memory must be shared (or copied by the reporter that keeps it).

const std = @import("std");
const assert = std.debug.assert;
const traits = @import("traits.zig");

const Feedback = traits.Feedback;

/// A reporter that may be absent.
pub fn Optional(comptime R: type) type {
    comptime traits.assert_reporter(R);
    return struct {
        const Self = @This();
        pub const Activity = R.Activity;

        inner: ?R,

        pub fn report(self: *Self, activity: Activity) Feedback {
            const reporter = if (self.inner) |*reporter| reporter else return .ok;
            return reporter.report(activity);
        }
    };
}

/// Reports to two reporters, either of which may be absent.
pub fn Reporters(comptime R1: type, comptime R2: type) type {
    comptime traits.assert_reporter(R1);
    comptime traits.assert_reporter(R2);
    comptime assert(R1.Activity == R2.Activity);
    return struct {
        const Self = @This();
        pub const Activity = R1.Activity;

        r1: ?R1,
        r2: ?R2,

        pub fn init(r1: ?R1, r2: ?R2) Self {
            return .{ .r1 = r1, .r2 = r2 };
        }

        pub fn report(self: *Self, activity: Activity) Feedback {
            var feedback: Feedback = .ok;
            if (self.r1) |*r1| feedback = combine(feedback, r1.report(activity));
            if (self.r2) |*r2| feedback = combine(feedback, r2.report(activity));
            return feedback;
        }
    };
}

/// The worst of two feedbacks: closed, then backoff, then ok.
pub fn combine(a: Feedback, b: Feedback) Feedback {
    if (a == .closed or b == .closed) return .closed;
    if (a == .backoff or b == .backoff) return .backoff;
    assert(a == .ok and b == .ok);
    return .ok;
}

const testing = std.testing;

const Counter = struct {
    pub const Activity = u32;
    total: u32 = 0,
    feedback: Feedback = .ok,

    pub fn report(self: *Counter, activity: u32) Feedback {
        self.total += activity;
        return self.feedback;
    }
};

test "optional branch reports" {
    var reporters = Reporters(Counter, Counter).init(.{}, null);
    try testing.expectEqual(Feedback.ok, reporters.report(3));
    try testing.expectEqual(3, reporters.r1.?.total);
    var both = Reporters(Counter, Counter).init(.{}, .{ .feedback = .backoff });
    try testing.expectEqual(Feedback.backoff, both.report(2));
    try testing.expectEqual(2, both.r1.?.total);
    try testing.expectEqual(2, both.r2.?.total);
    var none = Reporters(Counter, Counter).init(null, null);
    try testing.expectEqual(Feedback.ok, none.report(1));
}

test "absent reporter ignores activity" {
    var absent: Optional(Counter) = .{ .inner = null };
    try testing.expectEqual(Feedback.ok, absent.report(5));
    var present: Optional(Counter) = .{ .inner = .{ .feedback = .closed } };
    try testing.expectEqual(Feedback.closed, present.report(5));
    try testing.expectEqual(5, present.inner.?.total);
}

test "combine returns worst feedback" {
    try testing.expectEqual(Feedback.closed, combine(.closed, .backoff));
    try testing.expectEqual(Feedback.closed, combine(.ok, .closed));
    try testing.expectEqual(Feedback.backoff, combine(.backoff, .ok));
    try testing.expectEqual(Feedback.ok, combine(.ok, .ok));
}
