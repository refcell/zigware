//! commonware `simplex/actors/voter/mod.rs` pipelined-handoff tests on `HandoffFixture`:
//! `Wait` responses around the parent's certification sync, and the view exits, parent
//! nullify votes, and failed certifications that cancel or keep a pending build.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const Fixture = @import("handoff_fixture.zig").Fixture(h);

        fn run(comptime body: fn (Ctx) anyerror!void, timeout_s: u64) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = timeout_s * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        // commonware test_pipelined_handoff_wait_response_during_certification_sync: a
        // `Wait` that arrives while the parent's sync is parked is consumed only once the
        // loop resumes, which then dispatches the ordinary replacement.
        test "voter pipelined handoff wait response during certification sync" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    const certified = try fixture.certify_parent(ctx);
                    try fixture.block_certification(ctx, certified);
                    fixture.respond_wait();
                    try ctx.sleep(.fromMilliseconds(Fixture.settle_ms));
                    try testing.expectEqual(1, fixture.child_requests());
                    try h.expect_handoff_metrics(ctx, &.{.{ "Requested", 1 }}, &.{});
                    try fixture.release_certification(ctx);
                    try fixture.wait_for_replacement(ctx);
                    try ctx.sleep(.fromMilliseconds(Fixture.settle_ms));
                    try testing.expectEqual(2, fixture.child_requests());
                    try h.expect_handoff_metrics(ctx, &.{
                        .{ "WaitReturned", 1 },
                        .{ "Requested", 1 },
                    }, &.{});
                }
            }.body, 20);
        }

        // commonware test_pipelined_handoff_wait_response_after_certification_sync: a late
        // `Wait` after the parent's durable certification dispatches its replacement with no
        // further parent event.
        test "voter pipelined handoff wait response after certification sync" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    const certified = try fixture.certify_parent(ctx);
                    try fixture.finish_certification(ctx, certified);
                    try testing.expectEqual(1, fixture.child_requests());
                    fixture.respond_wait();
                    try fixture.wait_for_replacement(ctx);
                    try ctx.sleep(.fromMilliseconds(Fixture.settle_ms));
                    try testing.expectEqual(2, fixture.child_requests());
                    try h.expect_handoff_metrics(ctx, &.{
                        .{ "WaitReturned", 1 },
                        .{ "Requested", 1 },
                    }, &.{});
                }
            }.body, 20);
        }

        // commonware test_pipelined_handoff_waiting_request_exits_view: a waiting handoff
        // request is abandoned when its view exits, and no ordinary request follows.
        test "voter pipelined handoff waiting request exits view" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    fixture.respond_wait();
                    try h.wait_counter(ctx, "handoff_events", "event", "WaitReturned");
                    const certified = try fixture.certify_parent(ctx);
                    const nullification = try h.build_peers(
                        gpa,
                        .nullification,
                        fixture.net.schemes(),
                        fixture.local,
                        .new(h.default_epoch, .new(3)),
                        fixture.net.quorum(),
                    );
                    try fixture.stack.mailbox.recovered(gpa, .{ .nullification = nullification });
                    // Bounded: views only advance, and each wait is limited.
                    while ((try fixture.stack.next_update(ctx, 5_000)).current.get() <= 3) {}
                    try fixture.finish_certification(ctx, certified);
                    try h.wait_counter(ctx, "handoff_abandoned", "reason", "ViewExit");
                    try testing.expectEqual(1, fixture.child_requests());
                    try h.expect_handoff_metrics(
                        ctx,
                        &.{ .{ "WaitReturned", 1 }, .{ "Requested", 1 } },
                        &.{.{ "ViewExit", 1 }},
                    );
                }
            }.body, 20);
        }

        // commonware test_pipelined_handoff_parent_nullify_cancels_pending_build: voting to
        // nullify the parent's view cancels a pending build; the request is retained, and an
        // ordinary request for the same context follows if the parent certifies after all.
        test "voter pipelined handoff parent nullify cancels pending build" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    const certified = try fixture.certify_parent(ctx);
                    // The parent's certification times out (10 s) with the build pending.
                    try testing.expect(try fixture.stack.nullify_within(ctx, 2, 20_000));
                    try h.wait_counter(ctx, "handoff_abandoned", "reason", "ParentNullify");
                    try fixture.wait_closed(ctx);
                    try testing.expectEqual(1, fixture.child_requests());
                    try fixture.finish_certification(ctx, certified);
                    try fixture.wait_for_replacement(ctx);
                    try h.expect_handoff_metrics(
                        ctx,
                        &.{.{ "Requested", 1 }},
                        &.{.{ "ParentNullify", 1 }},
                    );
                }
            }.body, 60);
        }

        // commonware test_pipelined_handoff_failed_parent_certification_cancels_pending_build:
        // a failed parent certification invalidates the captured ancestry.
        test "voter pipelined handoff failed parent certification cancels pending build" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    const certified = try fixture.certify_parent(ctx);
                    fixture.stack.automaton.answer_certification(certified, false);
                    try h.wait_counter(
                        ctx,
                        "handoff_abandoned",
                        "reason",
                        "AncestryInvalidated",
                    );
                    try fixture.wait_closed(ctx);
                    try h.expect_handoff_metrics(
                        ctx,
                        &.{.{ "Requested", 1 }},
                        &.{.{ "AncestryInvalidated", 1 }},
                    );
                }
            }.body, 20);
        }

        // commonware test_pipelined_handoff_late_parent_nullification_keeps_build: a
        // nullification of the parent's view after it certified keeps the pending build.
        test "voter pipelined handoff late parent nullification keeps build" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var fixture: Fixture = undefined;
                    try fixture.init(ctx, .stage);
                    defer fixture.deinit();
                    const certified = try fixture.certify_parent(ctx);
                    try fixture.finish_certification(ctx, certified);
                    // Signed by peers only: the quorum excludes the local voter.
                    const nullification = try h.build_peers(
                        gpa,
                        .nullification,
                        fixture.net.schemes(),
                        fixture.local,
                        .new(h.default_epoch, .new(2)),
                        fixture.net.quorum(),
                    );
                    try fixture.stack.mailbox.recovered(gpa, .{ .nullification = nullification });
                    // Let the voter record the nullification before the build answers.
                    try ctx.sleep(.fromMilliseconds(Fixture.settle_ms));
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
            }.body, 20);
        }
    };
}
