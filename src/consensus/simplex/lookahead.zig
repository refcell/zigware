//! Vote admission windows and the relay plan (commonware `simplex/mod.rs`: `Lookahead`,
//! `Viewport`, and `Plan`). See mod.rs's "Optimistic Validation" for why each bound is what
//! it is.

const std = @import("std");
const assert = std.debug.assert;
const consensus_types = @import("../types.zig");
const elector = @import("elector.zig");

const View = consensus_types.View;
const ViewDelta = consensus_types.ViewDelta;
const TermLength = consensus_types.TermLength;
const Round = consensus_types.Round;

/// How far ahead of the current view votes and local work may run.
pub const Lookahead = struct {
    term_length: TermLength,
    optimistic_views: ViewDelta,

    pub fn init(terms: elector.Terms) Lookahead {
        const result: Lookahead = .{
            .term_length = terms.length,
            .optimistic_views = terms.optimistic_views,
        };
        assert(result.term_length.get() > 0);
        assert(result.optimistic_views.get() == terms.optimistic_views.get());
        return result;
    }

    /// Whether `pending` is a same-term view ahead of `current`, at most
    /// `2 * optimistic_views + 1` ahead (see `admission_limit`).
    pub fn in_admission_window(self: Lookahead, current: View, pending: View) bool {
        const limit = self.admission_limit(current);
        assert(limit.get() >= current.get());
        return current.get() < pending.get() and pending.get() <= limit.get();
    }

    /// Whether to admit a peer's vote for `pending` while at `current`: the usual successors,
    /// the admission window, or the next-term lane.
    pub fn admits(self: Lookahead, current: View, pending: View) bool {
        if (current.admits(pending, self.term_length)) return true;
        if (self.in_admission_window(current, pending)) return true;
        const next_start = current.next_term_start(self.term_length);
        assert(next_start.get() > current.get());
        const lane = @min(@max(self.optimistic_views.get(), 1), self.term_length.get()) +| 1;
        return pending.get() > next_start.get() and
            pending.get() <= next_start.saturating_add(.new(lane)).get();
    }

    /// Whether this participant may do local work (vote) for `pending` while at `current`.
    pub fn admits_outbound(self: Lookahead, current: View, pending: View) bool {
        if (current.admits(pending, self.term_length)) return true;
        const bound = current.saturating_add(self.optimistic_views);
        assert(bound.get() >= current.get());
        return pending.get() <= bound.get() and self.in_admission_window(current, pending);
    }

    /// The highest view of the admission window: `current + 2 * optimistic_views + 1`,
    /// clamped to the end of `current`'s term.
    pub fn admission_limit(self: Lookahead, current: View) View {
        const window = self.optimistic_views.get() *| 2 +| 1;
        const term_end = current.term_end(self.term_length);
        const reach = current.saturating_add(.new(window));
        assert(term_end.get() >= current.get());
        return if (term_end.get() < reach.get()) term_end else reach;
    }

    /// The lowest directly notarized ancestor that may authorize an optimistic vote at
    /// `view`, or null when `view` is never issued optimistically.
    pub fn issuance_floor(self: Lookahead, view: View) ?View {
        if (self.optimistic_views.is_zero()) return null;
        if (view.is_term_start(self.term_length)) return null;
        const result = view.saturating_sub(self.optimistic_views).saturating_sub(.new(1));
        assert(result.get() < view.get());
        return result;
    }
};

/// The views the batcher and voter track: from `view_retention` below the finalized view up
/// to the lookahead past the current view.
pub const Viewport = struct {
    finalized: View,
    current: View,
    view_retention: ViewDelta,
    lookahead: Lookahead,

    pub fn floor(self: Viewport) View {
        const result = self.finalized.saturating_sub(self.view_retention);
        assert(result.get() <= self.finalized.get());
        return result;
    }

    /// Whether `view` is tracked at all (genesis never is).
    pub fn retains(self: Viewport, view: View) bool {
        return !view.is_zero() and view.get() >= self.floor().get();
    }

    pub fn admits_vote(self: Viewport, pending: View) bool {
        return self.retains(pending) and self.lookahead.admits(self.current, pending);
    }

    /// Certificates are admitted from arbitrarily far ahead.
    pub fn admits_certificate(self: Viewport, pending: View) bool {
        return self.retains(pending);
    }
};

/// What the relay should do with a payload (commonware `simplex::Plan`).
pub fn Plan(comptime P: type) type {
    return union(enum) {
        /// Prepare a pipelined handoff candidate for `round`.
        prepare: struct { round: Round },
        /// Broadcast our own proposal for `round`.
        propose: struct { round: Round },
        /// Forward a proposal to peers that have not voted for it.
        forward: struct { round: Round, recipients: @import("p2p").Recipients(P) },

        pub fn round(self: @This()) Round {
            return switch (self) {
                inline else => |plan| plan.round,
            };
        }
    };
}

const testing = std.testing;
const utils = @import("utils");

fn test_lookahead(optimistic_views: u64) Lookahead {
    return .{
        .term_length = .new(utils.NonZero(u32).init(5).?),
        .optimistic_views = .new(optimistic_views),
    };
}

test "lookahead admits" {
    const current = View.new(6);
    // The immediate successor and the next term start are always admitted.
    try testing.expect(test_lookahead(0).admits(current, current.next()));
    const next_term_start = current.next_term_start(test_lookahead(0).term_length);
    try testing.expect(test_lookahead(0).admits(current, next_term_start));
    // Bounded same-term optimistic lookahead.
    try testing.expect(test_lookahead(1).admits(current, .new(9)));
    try testing.expect(!test_lookahead(1).admits(current, .new(10)));
    try testing.expect(!test_lookahead(10).admits(current, .new(100)));
    // Local work is limited to the lookahead itself.
    try testing.expect(test_lookahead(1).admits_outbound(current, .new(7)));
    try testing.expect(!test_lookahead(1).admits_outbound(current, .new(8)));
}

test "large lookahead admission is bounded by the term" {
    const lookahead = test_lookahead(100);
    const current = View.new(9);
    try testing.expect(lookahead.admits(current, .new(10)));
    try testing.expect(lookahead.admits(current, current.next_term_start(lookahead.term_length)));
    try testing.expect(lookahead.admits(current, .new(17)));
    try testing.expect(!lookahead.admits(current, .new(18)));
}

test "admission limit" {
    const current = View.new(6);
    try testing.expectEqual(View.new(7), test_lookahead(0).admission_limit(current));
    try testing.expectEqual(View.new(9), test_lookahead(1).admission_limit(current));
    try testing.expectEqual(View.new(10), test_lookahead(100).admission_limit(current));
    try testing.expectEqual(View.new(10), test_lookahead(3).admission_limit(.new(10)));
}

test "issuance floor" {
    try testing.expectEqual(null, test_lookahead(0).issuance_floor(.new(7)));
    try testing.expectEqual(null, test_lookahead(100).issuance_floor(.new(11)));
    try testing.expectEqual(View.new(6), test_lookahead(2).issuance_floor(.new(9)).?);
    try testing.expectEqual(View.zero(), test_lookahead(2).issuance_floor(.new(2)).?);
}

test "lookahead admits the next-term lane" {
    const lookahead = test_lookahead(2);
    const current = View.new(9);
    try testing.expect(lookahead.admits(current, .new(11)));
    try testing.expect(lookahead.admits(current, .new(14)));
    try testing.expect(!lookahead.admits(current, .new(15)));
    const rotating: Lookahead = .{ .term_length = .one, .optimistic_views = .zero() };
    try testing.expect(rotating.admits(.new(6), .new(8)));
    try testing.expect(rotating.admits(.new(25), .new(28)));
    try testing.expect(!rotating.admits(.new(25), .new(29)));
}

test "viewport" {
    const viewport: Viewport = .{
        .finalized = .new(20),
        .current = .new(25),
        .view_retention = .new(10),
        .lookahead = .{
            .term_length = .new(utils.NonZero(u32).init(10).?),
            .optimistic_views = .zero(),
        },
    };
    try testing.expect(!viewport.retains(.zero()));
    try testing.expectEqual(View.new(10), viewport.floor());
    try testing.expect(!viewport.retains(.new(9)));
    try testing.expect(viewport.retains(.new(10)));
    const admitted = [_]u64{ 10, 25, 26, 31, 33 };
    for (admitted) |view| try testing.expect(viewport.admits_vote(.new(view)));
    const refused = [_]u64{ 5, 27, 34 };
    for (refused) |view| try testing.expect(!viewport.admits_vote(.new(view)));
    try testing.expect(!viewport.admits_certificate(.new(9)));
    try testing.expect(viewport.admits_certificate(.new(1000)));
}
