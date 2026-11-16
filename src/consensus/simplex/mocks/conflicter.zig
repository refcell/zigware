//! A Byzantine participant that answers every notarize and finalize with two conflicting
//! votes: one for a random payload, one for the received proposal (commonware
//! `simplex/mocks/conflicter.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const types = @import("../types.zig");

pub fn Conflicter(comptime S: type, comptime H: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;
        const Vote = types.Vote(S, D);
        const Proposal = types.Proposal(D);

        gpa: Allocator,
        io: Io,
        scheme: *const S,

        pub fn init(gpa: Allocator, io: Io, scheme: *const S) Self {
            return .{ .gpa = gpa, .io = io, .scheme = scheme };
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
                switch (vote) {
                    inline .notarize, .finalize => |received, tag| {
                        const Signed = @FieldType(Vote, @tagName(tag));
                        var payload: D = undefined;
                        self.io.random(&payload.bytes);
                        const random: Proposal = .init(
                            received.proposal.round,
                            received.proposal.parent,
                            payload,
                        );
                        self.sign_and_send(sender, Signed, tag, random);
                        self.sign_and_send(sender, Signed, tag, received.proposal);
                    },
                    .nullify => {},
                }
            }
        }

        fn sign_and_send(
            self: *Self,
            sender: anytype,
            comptime Signed: type,
            comptime tag: std.meta.Tag(Vote),
            proposal: Proposal,
        ) void {
            const signed = (Signed.sign(self.gpa, self.scheme, proposal) catch return).?;
            send_vote(self.gpa, sender, @unionInit(Vote, @tagName(tag), signed));
        }
    };
}

/// Encodes `vote` and sends it to every peer, ignoring the outcome.
pub fn send_vote(gpa: Allocator, sender: anytype, vote: anytype) void {
    const bytes = codec.encode(@TypeOf(vote), gpa, vote) catch return;
    defer gpa.free(bytes);
    const sent = sender.send(.all, &.{bytes}, true) catch return;
    gpa.free(sent);
}
