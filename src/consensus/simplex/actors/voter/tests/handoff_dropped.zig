//! commonware `simplex/actors/voter/mod.rs` pipelined-handoff tests on `HandoffFixture`
//! where the application leaves the handoff unanswered: a dropped response forfeits the
//! view once its parent certifies, and a stalled or closed one is replaced on the certified
//! fallback when the parent is nullified.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const Fixture = @import("handoff_fixture.zig").Fixture(h);

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = 20 * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        /// Waits up to 1 s of simulated time for a view-3 request, then expects the requests
        /// so far to name `parents`, in order.
        fn expect_requests(ctx: Ctx, fixture: *Fixture, parents: []const u64) !void {
            const automaton = &fixture.stack.automaton;
            var waited: u64 = 0;
            // Bounded by 1 s of simulated time.
            while (automaton.proposals_count < parents.len) : (waited += 1) {
                if (waited > 1_000) return error.NoRequest;
                try ctx.sleep(.fromMilliseconds(1));
            }
            try testing.expectEqual(parents.len, automaton.proposals_count);
            for (parents, 0..) |parent, index| {
                const request = automaton.request_for(3, @intCast(index)) orelse
                    return error.RequestNotForView3;
                try testing.expectEqual(parent, request.parent[0].get());
            }
        }

        // commonware test_pipelined_handoff_dropped_response_nullifies_after_parent_certification:
        // the voter nullifies the term-start view without an ordinary request on that parent.
        test "voter pipelined handoff dropped response nullifies after parent certification" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.start(ctx, .{ .drop_proposals = true, .handoff = .vote });
                    defer fixture.deinit();
                    try expect_requests(ctx, &fixture, &.{2});
                    const certified = try fixture.certify_parent(ctx);
                    fixture.stack.automaton.answer_certification(certified, true);
                    var parent_certified = false;
                    var entered_child = false;
                    var child_nullified = false;
                    var waited: u64 = 0;
                    // Before normal deadlines: bounded by 1 s of simulated time.
                    while (!parent_certified or !child_nullified) : (waited += 1) {
                        if (waited > 1_000) return error.DroppedHandoffNotNullified;
                        if (fixture.stack.resolver.try_recv()) |message| {
                            defer message.discard();
                            if (message == .certified and message.certified.success and
                                message.certified.notarization.view().get() == 2)
                            {
                                parent_certified = true;
                            }
                        } else |_| {}
                        if (fixture.stack.batcher.try_recv()) |message| switch (message) {
                            .update => |update| {
                                if (update.current.get() == 3) entered_child = true;
                            },
                            .constructed => |vote| if (vote == .nullify and
                                vote.view().get() == 3)
                            {
                                // The child is nullified only once it is current.
                                try testing.expect(entered_child);
                                child_nullified = true;
                            },
                        } else |_| {}
                        try ctx.sleep(.fromMilliseconds(1));
                    }
                    // Parent certification must not retry a dropped handoff.
                    try expect_requests(ctx, &fixture, &.{2});
                    try h.expect_handoff_metrics(
                        ctx,
                        &.{.{ "Requested", 1 }},
                        &.{.{ "ResponseClosed", 1 }},
                    );
                }
            }.body);
        }

        const Unanswered = enum { stalled, closed };

        /// commonware `reissue_handoff_after_parent_nullification`: the application leaves
        /// the handoff `unanswered`, then the captured parent is nullified while view 3 is
        /// live. The voter must request a replacement on certified view 1 before the leader
        /// timeout; after a closed response, it proposes and votes on that fallback.
        fn reissue_after_parent_nullification(ctx: Ctx, unanswered: Unanswered) !void {
            const gpa = ctx.gpa();
            const closed = unanswered == .closed;
            var fixture: Fixture = undefined;
            try fixture.start(ctx, .{ .handoff = .vote, .stall_proposals = !closed });
            defer fixture.deinit();
            try expect_requests(ctx, &fixture, &.{2});
            if (closed) {
                const automaton = &fixture.stack.automaton;
                automaton.answer_handoff(try automaton.take_handoff(ctx), null);
                // Nothing observable marks the voter consuming the closed response.
                try ctx.sleep(.fromMilliseconds(Fixture.settle_ms));
            }
            // Nullifying the captured parent enters view 3, and the abandoned request must be
            // replaced at once with one on certified view 1.
            const nullification = try h.build_peers(
                gpa,
                .nullification,
                fixture.net.schemes(),
                fixture.local,
                .new(h.default_epoch, .new(2)),
                fixture.net.quorum(),
            );
            try fixture.stack.mailbox.recovered(gpa, .{ .nullification = nullification });
            try expect_requests(ctx, &fixture, &.{ 2, 1 });
            if (closed) {
                // Bounded by the 5 s wait per message, below view 3's 10 s leader timeout.
                while (true) {
                    const next = try fixture.stack.next_batcher(ctx, 5_000);
                    const message = next orelse return error.NoFallbackVote;
                    if (message != .constructed) continue;
                    const vote = message.constructed;
                    if (vote.view().get() != 3) continue;
                    // View 3 must not time out instead of proposing on view 1.
                    if (vote == .nullify) return error.FallbackTimedOut;
                    if (vote != .notarize) continue;
                    try testing.expectEqual(1, vote.notarize.proposal.parent.get());
                    break;
                }
            }
            try h.expect_handoff_metrics(
                ctx,
                &.{.{ "Requested", 1 }},
                &.{.{ "AncestrySuperseded", 1 }},
            );
        }

        // commonware test_pipelined_handoff_reissues_stalled_proposal_after_parent_nullification.
        test "voter pipelined handoff reissues stalled proposal after parent nullification" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    try reissue_after_parent_nullification(ctx, .stalled);
                }
            }.body);
        }

        // commonware test_pipelined_handoff_reissues_closed_proposal_after_parent_nullification.
        test "voter pipelined handoff reissues closed proposal after parent nullification" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    try reissue_after_parent_nullification(ctx, .closed);
                }
            }.body);
        }
    };
}
