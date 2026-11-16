//! A Byzantine participant that answers every notarize and finalize by re-voting for the
//! proposal it saw `view_delta` views earlier (commonware `simplex/mocks/outdated.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus_types = @import("../../types.zig");
const types = @import("../types.zig");
const conflicter = @import("conflicter.zig");

const View = consensus_types.View;
const ViewDelta = consensus_types.ViewDelta;

pub fn Outdated(comptime S: type, comptime H: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;
        const Vote = types.Vote(S, D);
        const Proposal = types.Proposal(D);

        gpa: Allocator,
        scheme: *const S,
        view_delta: ViewDelta,
        /// The last proposal seen at each view (grows for the mock's lifetime, as in
        /// commonware).
        history: std.AutoHashMapUnmanaged(View, Proposal) = .empty,

        pub fn init(gpa: Allocator, scheme: *const S, view_delta: ViewDelta) Self {
            return .{ .gpa = gpa, .scheme = scheme, .view_delta = view_delta };
        }

        pub fn deinit(self: *Self) void {
            self.history.deinit(self.gpa);
            self.* = undefined;
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
                        const view = received.proposal.view();
                        self.history.put(self.gpa, view, received.proposal) catch return;
                        const old: View = .new(view.get() -| self.view_delta.get());
                        const proposal = self.history.get(old) orelse continue;
                        const Signed = @FieldType(Vote, @tagName(tag));
                        const sign = Signed.sign(self.gpa, self.scheme, proposal);
                        const signed = (sign catch return).?;
                        const stale = @unionInit(Vote, @tagName(tag), signed);
                        conflicter.send_vote(self.gpa, sender, stale);
                    },
                    .nullify => {},
                }
            }
        }
    };
}
