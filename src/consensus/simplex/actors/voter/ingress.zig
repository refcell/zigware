//! Messages to the voter (commonware `actors/voter/ingress.rs`).
//!
//! When the mailbox is full, overflow keeps the latest finalization ahead of everything else
//! and drops messages it supersedes: anything at or below its view, a second timeout for a
//! view (unless it upgrades inactivity to a leader nullify), and repeats of a proposal or a
//! certificate kind for a view.
//!
//! Certificates own memory, so a `verified` message carries the allocator that frees it if
//! the mailbox drops the message (Rust's `Drop`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const actor = @import("actor");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const metrics = @import("../../metrics.zig");

const View = consensus_types.View;
const Round = consensus_types.Round;
const TimeoutReason = metrics.TimeoutReason;

pub fn Message(comptime S: type, comptime D: type) type {
    return union(enum) {
        const Self = @This();
        const Certificate = types.Certificate(S, D);

        /// A proposal the batcher saw from the round's leader.
        proposal: types.Proposal(D),
        /// The batcher wants the round to time out now.
        timeout: struct { round: Round, reason: TimeoutReason },
        /// A verified certificate, from the batcher or the resolver.
        verified: struct { gpa: Allocator, certificate: Certificate },

        pub const Overflow = Pending(S, D);

        pub fn view(self: Self) View {
            return switch (self) {
                .proposal => |proposal| proposal.view(),
                .timeout => |timeout| timeout.round.view,
                .verified => |verified| verified.certificate.view(),
            };
        }

        /// Releases a message the mailbox drops.
        pub fn discard(message: Self) void {
            switch (message) {
                .verified => |verified| {
                    var certificate = verified.certificate;
                    certificate.deinit(verified.gpa);
                },
                .proposal, .timeout => {},
            }
        }

        fn is_finalization(self: Self) bool {
            return self == .verified and self.verified.certificate == .finalization;
        }

        /// Whether `a` and `b` are the same kind of message for the same view (a repeat).
        fn repeats(a: Self, b: Self) bool {
            if (a.view() != b.view()) return false;
            return switch (a) {
                .proposal => b == .proposal,
                .verified => |verified| b == .verified and
                    std.meta.activeTag(verified.certificate) ==
                        std.meta.activeTag(b.verified.certificate),
                .timeout => false,
            };
        }

        /// The overflow policy (commonware `Policy::handle`).
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            const new_view = message.view();
            if (overflow.finalization) |old| {
                if (old.view().get() >= new_view.get()) return discard(message);
            }
            if (message.is_finalization()) {
                overflow.retain_above(new_view);
                if (overflow.finalization) |old| discard(old);
                overflow.finalization = message;
                return;
            }
            if (message == .timeout) {
                if (overflow.find_timeout(new_view)) |old| {
                    const upgrade = message.timeout.reason == .leader_nullify and
                        old.timeout.reason == .inactivity;
                    if (upgrade) old.* = message;
                    return;
                }
            }
            for (0..overflow.messages.len) |index| {
                if (repeats(message, overflow.messages.at(index))) return discard(message);
            }
            errdefer discard(message);
            try overflow.messages.pushBack(gpa, message);
            assert(!overflow.is_empty());
        }
    };
}

/// Messages held while the voter's mailbox is full (commonware `Pending`).
pub fn Pending(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const M = Message(S, D);

        finalization: ?M = null,
        messages: std.Deque(M) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.finalization) |message| M.discard(message);
            while (self.messages.popFront()) |message| M.discard(message);
            self.messages.deinit(gpa);
            self.* = undefined;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.finalization == null and self.messages.len == 0;
        }

        fn retain_above(self: *Self, view: View) void {
            const count = self.messages.len;
            for (0..count) |_| {
                const message = self.messages.popFront().?;
                if (message.view().get() > view.get()) {
                    self.messages.pushBackAssumeCapacity(message);
                } else {
                    M.discard(message);
                }
            }
            assert(self.messages.len <= count);
        }

        fn find_timeout(self: *Self, view: View) ?*M {
            for (0..self.messages.len) |index| {
                const message = self.messages.atPtr(index);
                if (message.* == .timeout and message.view() == view) return message;
            }
            return null;
        }

        /// Hands the finalization first, then the rest in order.
        pub fn drain(self: *Self, pusher: anytype) void {
            if (self.finalization) |finalization| {
                self.finalization = null;
                if (pusher.push(finalization)) |rejected| {
                    self.finalization = rejected;
                    return;
                }
            }
            while (self.messages.popFront()) |message| {
                if (pusher.push(message)) |rejected| {
                    self.messages.pushFrontAssumeCapacity(rejected);
                    break;
                }
            }
        }
    };
}

/// The voter's mailbox (commonware `voter::Mailbox`).
pub fn Mailbox(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const M = Message(S, D);

        sender: actor.mailbox.Sender(M),

        pub fn clone(self: Self) Self {
            return .{ .sender = self.sender.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        pub fn proposal(self: Self, value: types.Proposal(D)) Allocator.Error!void {
            _ = try self.sender.enqueue(.{ .proposal = value });
        }

        pub fn timeout(self: Self, round: Round, reason: TimeoutReason) Allocator.Error!void {
            _ = try self.sender.enqueue(.{ .timeout = .{ .round = round, .reason = reason } });
        }

        /// Hands over `certificate`, allocated with `gpa`; the voter takes ownership.
        pub fn recovered(
            self: Self,
            gpa: Allocator,
            certificate: types.Certificate(S, D),
        ) Allocator.Error!void {
            const message: M = .{ .verified = .{ .gpa = gpa, .certificate = certificate } };
            _ = try self.sender.enqueue(message);
        }
    };
}
