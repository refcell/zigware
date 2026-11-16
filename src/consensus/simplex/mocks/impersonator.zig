//! A Byzantine participant that re-signs every notarize and finalize it receives but claims
//! another participant's index, so the signature never verifies (commonware
//! `simplex/mocks/impersonator.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus_types = @import("../../types.zig");
const types = @import("../types.zig");
const conflicter = @import("conflicter.zig");

const Participant = consensus_types.Participant;

pub fn Impersonator(comptime S: type, comptime H: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;
        const Vote = types.Vote(S, D);

        gpa: Allocator,
        scheme: *const S,

        pub fn init(gpa: Allocator, scheme: *const S) Self {
            return .{ .gpa = gpa, .scheme = scheme };
        }

        /// Participant 1 when signing as 0, else participant 0.
        fn impersonated(signer: Participant) Participant {
            const index: u32 = if (signer.get() == 0) 1 else 0;
            assert(index != signer.get());
            return .init(index);
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
                        const sign = Signed.sign(self.gpa, self.scheme, received.proposal);
                        var signed = (sign catch return).?;
                        signed.attestation.signer = impersonated(signed.attestation.signer);
                        const forged = @unionInit(Vote, @tagName(tag), signed);
                        conflicter.send_vote(self.gpa, sender, forged);
                    },
                    .nullify => {},
                }
            }
        }
    };
}
