//! actor: Safely coordinate concurrent components.
//!
//! Zig port of commonware's `commonware-actor` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/actor): feedback from submitting
//! work to a bounded endpoint, and `mailbox`, a bounded message queue with caller-managed
//! overflow that actors use as their inbox.

const std = @import("std");
const assert = std.debug.assert;

pub const mailbox = @import("mailbox.zig");

/// Feedback from submitting work to a bounded endpoint.
pub const Feedback = enum {
    /// The work was accepted within the configured capacity.
    ok,
    /// The submission exceeded configured capacity but was handled by the overflow policy.
    backoff,
    /// The endpoint is closed.
    closed,

    /// Returns `true` when the endpoint handled the submission.
    pub fn accepted(feedback: Feedback) bool {
        return feedback == .ok or feedback == .backoff;
    }
};

/// Feedback from endpoints that may reject work under backpressure.
pub fn Unreliable(comptime T: type) type {
    return union(enum) {
        const Self = @This();

        /// Endpoint outcome from the submission attempt.
        outcome: T,
        /// The work was rejected by the endpoint.
        rejected,

        /// Wrap an outcome for an operation that may reject work.
        pub fn new(value: T) Self {
            return .{ .outcome = value };
        }

        /// Returns `true` when the operation was rejected before producing an outcome.
        pub fn is_rejected(self: Self) bool {
            return self == .rejected;
        }

        /// Returns the outcome when the operation was not rejected.
        pub fn get(self: Self) ?T {
            return switch (self) {
                .outcome => |value| value,
                .rejected => null,
            };
        }

        /// Returns `true` when the endpoint handled the submission (`Unreliable(Feedback)`).
        pub fn accepted(self: Self) bool {
            comptime assert(T == Feedback);
            return switch (self) {
                .outcome => |feedback| feedback.accepted(),
                .rejected => false,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            return switch (a) {
                .rejected => b == .rejected,
                .outcome => |value| b == .outcome and std.meta.eql(value, b.outcome),
            };
        }
    };
}

test "feedback accepted" {
    try std.testing.expect(Feedback.ok.accepted());
    try std.testing.expect(Feedback.backoff.accepted());
    try std.testing.expect(!Feedback.closed.accepted());
}

test "unreliable feedback" {
    const U = Unreliable(Feedback);
    try std.testing.expect(U.new(.ok).accepted());
    try std.testing.expect(U.new(.backoff).accepted());
    try std.testing.expect(!U.new(.closed).accepted());
    try std.testing.expect(!@as(U, .rejected).accepted());
    try std.testing.expect(@as(U, .rejected).is_rejected());
    try std.testing.expect(!U.new(.ok).is_rejected());
    try std.testing.expectEqual(@as(?Feedback, .backoff), U.new(.backoff).get());
    try std.testing.expectEqual(@as(?Feedback, null), @as(U, .rejected).get());
    try std.testing.expect(U.new(.ok).eql(U.new(.ok)));
    try std.testing.expect(!U.new(.ok).eql(U.new(.backoff)));
    try std.testing.expect(!U.new(.ok).eql(.rejected));
}

test {
    std.testing.refAllDecls(@This());
}
