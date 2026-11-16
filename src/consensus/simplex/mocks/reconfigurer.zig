//! A Byzantine participant that answers every vote by signing the same vote for the next
//! epoch (commonware `simplex/mocks/reconfigurer.rs`): honest validators block it for the
//! epoch mismatch without reporting a fault.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus_types = @import("../../types.zig");
const types = @import("../types.zig");
const conflicter = @import("conflicter.zig");

const Round = consensus_types.Round;

pub fn Reconfigurer(comptime S: type, comptime H: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;
        const Vote = types.Vote(S, D);

        gpa: Allocator,
        scheme: *const S,

        pub fn init(gpa: Allocator, scheme: *const S) Self {
            assert(scheme.me() != null);
            return .{ .gpa = gpa, .scheme = scheme };
        }

        /// Answers votes from `receiver` on `sender` until the channel closes or the task is
        /// canceled.
        pub fn run(self: *Self, sender: anytype, receiver: anytype) void {
            // Runs until the network closes or the task is canceled.
            while (true) {
                var message = receiver.recv() catch return;
                defer message.deinit();
                const vote = codec.decode(Vote, self.gpa, message.payload) catch continue;
                defer codec.free(Vote, self.gpa, vote);
                const next = self.reconfigure(vote) catch return;
                conflicter.send_vote(self.gpa, sender, next);
            }
        }

        /// `vote` signed again for the next epoch.
        fn reconfigure(self: *Self, vote: Vote) Allocator.Error!Vote {
            const next: Vote = switch (vote) {
                inline .notarize, .finalize => |received, tag| blk: {
                    var proposal = received.proposal;
                    proposal.round = next_epoch(proposal.round);
                    const Signed = @FieldType(Vote, @tagName(tag));
                    const signed = (try Signed.sign(self.gpa, self.scheme, proposal)).?;
                    break :blk @unionInit(Vote, @tagName(tag), signed);
                },
                .nullify => |received| blk: {
                    const Nullify = @FieldType(Vote, "nullify");
                    const round = next_epoch(received.round);
                    break :blk .{ .nullify = (try Nullify.sign(self.gpa, self.scheme, round)).? };
                },
            };
            assert(next.epoch().get() == vote.epoch().get() + 1);
            return next;
        }

        fn next_epoch(round: Round) Round {
            return .new(round.epoch.next(), round.view);
        }
    };
}
