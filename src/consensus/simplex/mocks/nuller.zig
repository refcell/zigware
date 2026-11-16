//! A Byzantine participant that answers every notarize with a nullify and a finalize for the
//! same round (commonware `simplex/mocks/nuller.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const types = @import("../types.zig");
const conflicter = @import("conflicter.zig");

pub fn Nuller(comptime S: type, comptime H: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;
        const Vote = types.Vote(S, D);

        gpa: Allocator,
        scheme: *const S,

        pub fn init(gpa: Allocator, scheme: *const S) Self {
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
                if (vote != .notarize) continue;
                const proposal = vote.notarize.proposal;
                const nullify = types.Nullify(S).sign(self.gpa, self.scheme, proposal.round) catch
                    return;
                conflicter.send_vote(self.gpa, sender, Vote{ .nullify = nullify.? });
                const finalize = types.Finalize(S, D).sign(self.gpa, self.scheme, proposal) catch
                    return;
                conflicter.send_vote(self.gpa, sender, Vote{ .finalize = finalize.? });
            }
        }
    };
}
