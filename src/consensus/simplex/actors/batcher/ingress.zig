//! Messages to the batcher (commonware `actors/batcher/ingress.rs`).
//!
//! When the mailbox is full, overflow keeps only the latest view update and drops our own
//! votes that the update makes irrelevant or that repeat a kept vote's view and kind.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const actor = @import("actor");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");

const View = consensus_types.View;
const Participant = consensus_types.Participant;

pub fn Message(comptime S: type, comptime D: type) type {
    return union(enum) {
        const Self = @This();
        const Vote = types.Vote(S, D);

        /// The voter entered `current` (led by `leader`) or finalized `finalized`.
        update: Update,
        /// A vote this participant signed.
        constructed: Vote,

        pub const Update = struct {
            current: View,
            leader: Participant,
            finalized: View,
            forwardable_proposal: ?types.Proposal(D),
        };

        pub const Overflow = Pending(S, D);

        pub fn view(self: Self) View {
            return switch (self) {
                .update => |update| update.current,
                .constructed => |vote| vote.view(),
            };
        }

        /// Whether an update to (`current`, `finalized`) makes our own `vote` irrelevant.
        fn prunes(current: View, finalized: View, vote: Vote) bool {
            const vote_view = vote.view().get();
            return switch (vote) {
                .notarize, .nullify => vote_view < current.get() or
                    vote_view <= finalized.get(),
                .finalize => vote_view <= finalized.get(),
            };
        }

        fn similar(a: Vote, b: Vote) bool {
            return a.view() == b.view() and std.meta.activeTag(a) == std.meta.activeTag(b);
        }

        /// The overflow policy (commonware `Policy::handle`).
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            switch (message) {
                .update => |update| {
                    if (overflow.update) |old| {
                        const old_key = .{ old.current.get(), old.finalized.get() };
                        const new_key = .{ update.current.get(), update.finalized.get() };
                        const newer = new_key[0] > old_key[0] or
                            (new_key[0] == old_key[0] and new_key[1] > old_key[1]);
                        if (!newer) return;
                    }
                    overflow.update = update;
                    overflow.retain_constructed(update.current, update.finalized);
                },
                .constructed => |vote| {
                    if (overflow.update) |old| {
                        if (prunes(old.current, old.finalized, vote)) return;
                    }
                    for (0..overflow.constructed.len) |index| {
                        if (similar(overflow.constructed.at(index), vote)) return;
                    }
                    try overflow.constructed.pushBack(gpa, vote);
                },
            }
        }
    };
}

/// Messages held while the batcher's mailbox is full (commonware `Pending`).
pub fn Pending(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const M = Message(S, D);

        update: ?M.Update = null,
        constructed: std.Deque(types.Vote(S, D)) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.constructed.deinit(gpa);
            self.* = undefined;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.update == null and self.constructed.len == 0;
        }

        fn retain_constructed(self: *Self, current: View, finalized: View) void {
            const count = self.constructed.len;
            for (0..count) |_| {
                const vote = self.constructed.popFront().?;
                if (M.prunes(current, finalized, vote)) continue;
                self.constructed.pushBackAssumeCapacity(vote);
            }
            assert(self.constructed.len <= count);
        }

        /// Hands the update first, then our votes, until the mailbox is full again.
        pub fn drain(self: *Self, pusher: anytype) void {
            if (self.update) |update| {
                self.update = null;
                if (pusher.push(.{ .update = update })) |rejected| {
                    self.update = rejected.update;
                    return;
                }
            }
            while (self.constructed.popFront()) |vote| {
                if (pusher.push(.{ .constructed = vote }) != null) {
                    self.constructed.pushFrontAssumeCapacity(vote);
                    break;
                }
            }
        }
    };
}

/// The batcher's mailbox (commonware `batcher::Mailbox`).
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

        pub fn update(
            self: Self,
            current: View,
            leader: Participant,
            finalized: View,
            forwardable_proposal: ?types.Proposal(D),
        ) Allocator.Error!void {
            assert(finalized.get() <= current.get() or current.is_zero());
            _ = try self.sender.enqueue(.{ .update = .{
                .current = current,
                .leader = leader,
                .finalized = finalized,
                .forwardable_proposal = forwardable_proposal,
            } });
        }

        pub fn constructed(self: Self, vote: types.Vote(S, D)) Allocator.Error!void {
            _ = try self.sender.enqueue(.{ .constructed = vote });
        }
    };
}
