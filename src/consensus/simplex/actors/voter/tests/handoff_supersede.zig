//! commonware `simplex/actors/voter/mod.rs` pipelined-handoff tests on `HandoffFixture`: a
//! held candidate is dropped, never voted, when a conflicting parent, a nullification, or
//! the leader timeout supersedes it, and the request contract for one view.

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

        /// The fixture's parent with another payload, notarized by peers only (the local
        /// voter already voted for the original), delivered to the voter.
        fn deliver_conflicting_parent(ctx: Ctx, fixture: *Fixture) !h.Proposal {
            const gpa = ctx.gpa();
            var conflicting = fixture.parent;
            conflicting.payload = h.Sha256.hash(&.{"conflicting parent"});
            const notarization = try h.build_peers(
                gpa,
                .notarization,
                fixture.net.schemes(),
                fixture.local,
                conflicting,
                fixture.net.quorum(),
            );
            try fixture.stack.mailbox.recovered(gpa, .{ .notarization = notarization });
            return conflicting;
        }

        /// Delivers a peers-only nullification of `view` and waits for the voter to enter a
        /// view at or above `entered`.
        fn nullify(ctx: Ctx, fixture: *Fixture, view: u64, entered: u64) !u64 {
            const gpa = ctx.gpa();
            const nullification = try h.build_peers(
                gpa,
                .nullification,
                fixture.net.schemes(),
                fixture.local,
                .new(h.default_epoch, .new(view)),
                fixture.net.quorum(),
            );
            try fixture.stack.mailbox.recovered(gpa, .{ .nullification = nullification });
            // Bounded: views only advance, and each wait is limited.
            while (true) {
                const current = (try fixture.stack.next_update(ctx, 5_000)).current.get();
                if (current >= entered) return current;
            }
        }

        /// Asserts the abandonment of a relayed-but-unvoted candidate for `reason`.
        fn expect_abandoned(ctx: Ctx, fixture: *Fixture, reason: []const u8) !void {
            try h.wait_counter(ctx, "handoff_abandoned", "reason", reason);
            try fixture.expect_silent(&.{fixture.digest()});
            try h.expect_handoff_metrics(ctx, &.{
                .{ "RelayedBeforeCertification", 1 },
                .{ "CandidateReturned", 1 },
                .{ "Requested", 1 },
            }, &.{.{ reason, 1 }});
        }

        // commonware test_pipelined_handoff_held_build_rejects_conflicting_parent: a
        // conflicting notarization at the parent view supersedes the held build and issues a
        // second handoff request on the new tip.
        test "voter pipelined handoff held build rejects conflicting parent" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    fixture.respond();
                    try fixture.observe_relay(ctx);
                    _ = try deliver_conflicting_parent(ctx, &fixture);
                    const certified = try fixture.stack.automaton.take_certification(ctx, 2);
                    try fixture.finish_certification(ctx, certified);
                    try h.wait_counter(ctx, "handoff_abandoned", "reason", "AncestrySuperseded");
                    try fixture.expect_silent(&.{fixture.digest()});
                    try h.expect_handoff_metrics(ctx, &.{
                        .{ "RelayedBeforeCertification", 1 },
                        .{ "CandidateReturned", 1 },
                        .{ "Requested", 2 },
                    }, &.{.{ "AncestrySuperseded", 1 }});
                }
            }.body);
        }

        // commonware test_pipelined_handoff_request_contract: one view gets at most two
        // prepare requests (the second only after an equivocating outgoing leader's other
        // block replaces our parent) and one ordinary request, after the second prepare
        // answers `Wait` and the replacement certifies.
        test "voter pipelined handoff request contract" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    const automaton = &fixture.stack.automaton;
                    fixture.respond();
                    try h.wait_counter(
                        ctx,
                        "handoff_events",
                        "event",
                        "RelayedBeforeCertification",
                    );
                    const conflicting = try deliver_conflicting_parent(ctx, &fixture);
                    const certified = try automaton.take_certification(ctx, 2);
                    try h.wait_counter(ctx, "handoff_abandoned", "reason", "AncestrySuperseded");
                    // The second prepare names the replacement parent. Decline it.
                    const second = try automaton.take_handoff(ctx);
                    automaton.answer_handoff(second, .wait);
                    try h.wait_counter(ctx, "handoff_events", "event", "WaitReturned");
                    try fixture.finish_certification(ctx, certified);
                    var waited: u64 = 0;
                    // Bounded by 5 s of simulated time.
                    while (fixture.child_requests() < 3) : (waited += 1) {
                        if (waited > 5_000) return error.NoOrdinaryRequest;
                        try ctx.sleep(.fromMilliseconds(1));
                    }
                    try ctx.sleep(.fromMilliseconds(Fixture.settle_ms));
                    // Two prepares and one ordinary proposal.
                    try testing.expectEqual(3, fixture.child_requests());
                    const parents = [_]h.Digest{
                        fixture.parent.payload,
                        conflicting.payload,
                        conflicting.payload,
                    };
                    for (parents, 0..) |parent, index| {
                        const request = automaton.request_for(3, @intCast(index)).?;
                        try testing.expectEqual(2, request.parent[0].get());
                        try testing.expectEqual(parent, request.parent[1]);
                    }
                    // The ordinary request must not reach the prepare path.
                    try testing.expectEqual(2, automaton.handoffs_count);
                    try h.expect_handoff_metrics(ctx, &.{
                        .{ "Requested", 2 },
                        .{ "CandidateReturned", 1 },
                        .{ "RelayedBeforeCertification", 1 },
                        .{ "WaitReturned", 1 },
                    }, &.{.{ "AncestrySuperseded", 1 }});
                }
            }.body);
        }

        // commonware test_pipelined_handoff_held_build_rejects_parent_nullification: the
        // nullified tip leaves certified ancestry, so the replacement is an ordinary request.
        test "voter pipelined handoff held build rejects parent nullification" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    fixture.respond();
                    try fixture.observe_relay(ctx);
                    const certified = try fixture.certify_parent(ctx);
                    try testing.expectEqual(3, try nullify(ctx, &fixture, 2, 3));
                    try fixture.finish_certification(ctx, certified);
                    try expect_abandoned(ctx, &fixture, "AncestrySuperseded");
                    var waited: u64 = 0;
                    // Bounded by 5 s of simulated time.
                    while (fixture.child_requests() < 2) : (waited += 1) {
                        if (waited > 5_000) return error.NoOrdinaryRequest;
                        try ctx.sleep(.fromMilliseconds(1));
                    }
                    try testing.expectEqual(1, fixture.stack.automaton.handoffs_count);
                }
            }.body);
        }

        // commonware test_pipelined_handoff_held_build_exits_view.
        test "voter pipelined handoff held build exits view" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    fixture.respond();
                    try fixture.observe_relay(ctx);
                    const certified = try fixture.certify_parent(ctx);
                    _ = try nullify(ctx, &fixture, 3, 4);
                    try fixture.finish_certification(ctx, certified);
                    try expect_abandoned(ctx, &fixture, "ViewExit");
                }
            }.body);
        }

        // commonware test_pipelined_handoff_held_build_becomes_ineligible_at_leader_timeout:
        // the leader timeout expires while the parent's certification sync is parked.
        test "voter pipelined handoff held build becomes ineligible at leader timeout" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    fixture.respond();
                    try fixture.observe_relay(ctx);
                    const certified = try fixture.certify_parent(ctx);
                    try fixture.block_certification(ctx, certified);
                    // The 10 s leader timeout, plus 1 s.
                    try ctx.sleep(.fromSeconds(11));
                    try fixture.release_certification(ctx);
                    try expect_abandoned(ctx, &fixture, "IneligibleAtRecording");
                }
            }.body);
        }
    };
}
