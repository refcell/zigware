//! A Byzantine participant that answers every notarize it sees with only a nullify for that
//! round (commonware `simplex/mocks/nullify_only.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const types = @import("../types.zig");
const conflicter = @import("conflicter.zig");

pub fn NullifyOnly(comptime S: type, comptime H: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;
        const Vote = types.Vote(S, D);
        const Nullify = types.Nullify(S);

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
                const notarize = switch (vote) {
                    .notarize => |value| value,
                    .nullify, .finalize => continue,
                };
                const round = notarize.proposal.round;
                const signed = Nullify.sign(self.gpa, self.scheme, round) catch return;
                const nullify = signed.?;
                assert(nullify.round == round);
                conflicter.send_vote(self.gpa, sender, Vote{ .nullify = nullify });
            }
        }
    };
}
