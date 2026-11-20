//! commonware `simplex/actors/voter/mod.rs` pipelined-handoff restart tests on
//! `HandoffFixture`: replay never restores a held candidate or re-requests a handoff the
//! journal already settled.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const Fixture = @import("handoff_fixture.zig").Fixture(h);

        fn run(comptime body: fn (Ctx) anyerror!void, timeout_s: u64) !void {
            try h.soak(timeout_s * std.time.ns_per_s, body);
        }

        /// Delivers the parent's notarization signed by every validator.
        fn notarize_parent(ctx: Ctx, fixture: *Fixture) !void {
            const gpa = ctx.gpa();
            const notarization = try h.build(
                gpa,
                .notarization,
                fixture.net.schemes(),
                fixture.parent,
                fixture.net.quorum(),
            );
            try fixture.stack.mailbox.recovered(gpa, .{ .notarization = notarization });
        }

        /// Drains the batcher until our nullify vote at `view`, failing on a notarize vote for
        /// any of `stale`.
        fn until_nullify(ctx: Ctx, fixture: *Fixture, view: u64, stale: []const h.Digest) !void {
            // Bounded by the 15 s wait per message.
            while (true) {
                const next = try fixture.stack.next_batcher(ctx, 15_000);
                const message = next orelse return error.NoNullify;
                if (message != .constructed) continue;
                switch (message.constructed) {
                    .nullify => |vote| if (vote.view().get() == view) return,
                    .notarize => |vote| for (stale) |digest| {
                        try testing.expect(!vote.proposal.payload.eql(digest));
                    },
                    else => {},
                }
            }
        }

        // commonware test_pipelined_handoff_not_reissued_after_parent_nullify_on_restart:
        // replay restores our nullify vote for the uncertified parent's view, so the restarted
        // voter requests no fresh handoff on it; parent certification yields one ordinary
        // request.
        test "voter pipelined handoff not reissued after parent nullify on restart" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    try testing.expect(try fixture.stack.nullify_within(ctx, 2, 20_000));
                    try fixture.restart(ctx, "restarted", .{});
                    const automaton = &fixture.stack.automaton;
                    // No handoff request follows replay.
                    var waited: u64 = 0;
                    while (waited < 1_000) : (waited += 1) {
                        _ = try fixture.stack.next_batcher(ctx, 0);
                        try ctx.sleep(.fromMilliseconds(1));
                    }
                    try testing.expectEqual(0, automaton.proposals_count);
                    // Certifying the parent makes the view an ordinary candidate.
                    try notarize_parent(ctx, &fixture);
                    waited = 0;
                    // Bounded by 5 s of simulated time.
                    while (automaton.proposals_count == 0) : (waited += 1) {
                        if (waited > 5_000) return error.NoOrdinaryRequest;
                        _ = try fixture.stack.next_batcher(ctx, 0);
                        try ctx.sleep(.fromMilliseconds(1));
                    }
                    try testing.expectEqual(1, automaton.proposals_count);
                    const request = automaton.request_for(3, 0).?;
                    try testing.expectEqual(2, request.parent[0].get());
                    try h.expect_handoff_metrics_in(ctx, "restarted", &.{}, &.{});
                }
            }.body, 60);
        }

        // commonware test_pipelined_handoff_held_build_is_volatile_on_restart: replay
        // re-issues the handoff request instead of restoring the held candidate, and dropping
        // that request forfeits the view once the parent certifies.
        test "voter pipelined handoff held build is volatile on restart" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    fixture.respond();
                    try h.wait_counter(
                        ctx,
                        "handoff_events",
                        "event",
                        "RelayedBeforeCertification",
                    );
                    try fixture.restart(ctx, "restarted", .{
                        .handoff = .stage,
                        .hold_handoffs = true,
                    });
                    const automaton = &fixture.stack.automaton;
                    const fresh = try automaton.take_handoff(ctx);
                    automaton.answer_handoff(fresh, null);
                    try notarize_parent(ctx, &fixture);
                    try until_nullify(ctx, &fixture, 3, &.{});
                }
            }.body, 20);
        }

        // commonware test_pipelined_handoff_restart_before_vote_votes_only_rebuilt_candidate:
        // a leader that relays a held candidate and restarts before voting builds afresh,
        // votes only the rebuilt candidate once the parent certifies, and after that vote is
        // journaled another restart does not build again.
        test "voter pipelined handoff restart before vote votes only rebuilt candidate" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    const relayed = fixture.digest();
                    fixture.respond();
                    try fixture.observe_relay(ctx);
                    try fixture.expect_silent(&.{relayed});
                    // The replacement replays a journal with no vote at view 3 and builds again.
                    try fixture.restart(ctx, "restarted", .{
                        .handoff = .stage,
                        .hold_handoffs = true,
                    });
                    const slot = try fixture.stack.automaton.take_handoff(ctx);
                    try testing.expect(slot.candidate == .stage);
                    fixture.candidate = slot;
                    const rebuilt = fixture.digest();
                    // Restart must build a fresh candidate.
                    try testing.expect(!rebuilt.eql(relayed));
                    fixture.respond();
                    try fixture.observe_relay(ctx);
                    // Certifying the parent releases the rebuilt candidate, and only it is voted.
                    try notarize_parent(ctx, &fixture);
                    try fixture.observe_vote(ctx);
                    try fixture.expect_silent(&.{relayed});
                    // The vote is journaled before it is published, so a further restart
                    // replays it and does not build for view 3 again.
                    try fixture.restart(ctx, "again", .{ .handoff = .stage });
                    const stale = [_]h.Digest{ rebuilt, relayed };
                    try until_nullify(ctx, &fixture, 3, &stale);
                    // A journaled vote must latch the view against another build.
                    try testing.expectEqual(0, fixture.stack.automaton.requests_for(3));
                    try fixture.expect_silent(&stale);
                }
            }.body, 20);
        }
    };
}
