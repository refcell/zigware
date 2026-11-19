//! commonware `simplex/actors/voter/mod.rs` pipelined-handoff tests on `HandoffFixture`: a
//! built term-start candidate is held until its parent certifies or finalizes, then voted
//! once without a rebuild.

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

        // commonware test_pipelined_handoff_build_before_certification: a candidate built
        // before its parent certifies is relayed at once, held through the parent's journal
        // sync, and voted only after it.
        test "voter pipelined handoff build before certification" {
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
                    try fixture.expect_silent(&.{fixture.digest()});
                    try fixture.release_certification(ctx);
                    try fixture.observe_vote(ctx);
                    // The held handoff must not rebuild.
                    try testing.expectEqual(1, fixture.child_requests());
                    try h.expect_handoff_metrics(ctx, &.{
                        .{ "RelayedBeforeCertification", 1 },
                        .{ "VotedAfterCertification", 1 },
                        .{ "CandidateReturned", 1 },
                        .{ "Requested", 1 },
                    }, &.{});
                }
            }.body);
        }

        /// commonware `certification_first_reuses_build`: certification completes before the
        /// application answers; entering the child view keeps the pending build, which is
        /// relayed and voted once, after certification.
        fn certification_first_reuses_build(
            ctx: Ctx,
            decision: @FieldType(h.Options, "handoff"),
        ) !void {
            var fixture: Fixture = undefined;
            try fixture.init(ctx, decision);
            defer fixture.deinit();
            const certified = try fixture.certify_parent(ctx);
            try fixture.finish_certification(ctx, certified);
            // Parent certification must not cancel the pending build.
            try testing.expect(!fixture.candidate.?.is_closed());
            fixture.respond();
            try fixture.observe_relay_and_vote(ctx);
            try testing.expectEqual(1, fixture.child_requests());
            try h.expect_handoff_metrics(ctx, &.{
                .{ "RelayedAfterCertification", 1 },
                .{ "VotedAfterCertification", 1 },
                .{ "CandidateReturned", 1 },
                .{ "Requested", 1 },
            }, &.{});
        }

        // commonware test_pipelined_handoff_certification_first_reuses_build_stage.
        test "voter pipelined handoff certification first reuses build stage" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    try certification_first_reuses_build(ctx, .stage);
                }
            }.body);
        }

        // commonware test_pipelined_handoff_certification_first_reuses_build_vote.
        test "voter pipelined handoff certification first reuses build vote" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    try certification_first_reuses_build(ctx, .vote);
                }
            }.body);
        }

        // commonware test_pipelined_handoff_held_build_released_by_parent_finalization:
        // parent finalization releases a held build like certification does.
        test "voter pipelined handoff held build released by parent finalization" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    fixture.respond();
                    try fixture.observe_relay(ctx);
                    const finalization = try h.build_peers(
                        gpa,
                        .finalization,
                        fixture.net.schemes(),
                        fixture.local,
                        fixture.parent,
                        fixture.net.quorum(),
                    );
                    try fixture.stack.mailbox.recovered(gpa, .{ .finalization = finalization });
                    try fixture.observe_vote(ctx);
                    try testing.expectEqual(1, fixture.child_requests());
                    try h.expect_handoff_metrics(ctx, &.{
                        .{ "RelayedBeforeCertification", 1 },
                        .{ "VotedAfterCertification", 1 },
                        .{ "CandidateReturned", 1 },
                        .{ "Requested", 1 },
                    }, &.{});
                }
            }.body);
        }

        // commonware test_pipelined_handoff_waiting_build_overlaps_certification_sync: an
        // already waiting request starts its ordinary build before the parent's sync
        // completes, but that build cannot relay or vote for the child until it does.
        test "voter pipelined handoff waiting build overlaps certification sync" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    fixture.respond_wait();
                    try h.wait_counter(ctx, "handoff_events", "event", "WaitReturned");
                    const certified = try fixture.certify_parent(ctx);
                    try fixture.block_certification(ctx, certified);
                    try fixture.wait_for_replacement(ctx);
                    // The ordinary response is available after its 1 ms build latency.
                    try ctx.sleep(.fromMilliseconds(Fixture.settle_ms));
                    try testing.expectEqual(2, fixture.child_requests());
                    // The ordinary build must not relay or vote before the sync.
                    try testing.expectEqual(null, fixture.relayed.try_next());
                    try testing.expectEqual(null, try fixture.next_notarize(ctx, 3, 0));
                    try fixture.release_certification(ctx);
                    const relayed = try fixture.relayed.next(ctx, 5_000) orelse
                        return error.NoRelay;
                    const voted = try fixture.next_notarize(ctx, 3, 5_000) orelse
                        return error.NoVote;
                    try testing.expectEqual(relayed, voted);
                    try testing.expectEqual(2, fixture.child_requests());
                    try h.expect_handoff_metrics(ctx, &.{
                        .{ "WaitReturned", 1 },
                        .{ "Requested", 1 },
                    }, &.{});
                }
            }.body);
        }
    };
}
