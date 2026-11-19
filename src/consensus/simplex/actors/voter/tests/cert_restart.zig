//! commonware `simplex/actors/voter/mod.rs` certification-and-timeout tests: a canceled
//! certification is not journaled as a failure, so a restart certifies the view again; a
//! validator stuck on an uncertifiable view escapes only through a finalization; and a failed
//! certification lets a validator that voted notarize vote nullify at once.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;
        const target = 3;

        fn run(comptime body: fn (Ctx) anyerror!void, timeout_s: u64) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = timeout_s * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        fn options(partition: []const u8) h.Options {
            return .{
                .leader_timeout_ms = 5_000,
                .certification_timeout_ms = 5_000,
                .timeout_retry_ms = 60 * 60 * 1_000,
                .partition = partition,
                .batcher_capacity = 8,
            };
        }

        /// Advances validator 0 to follower view 3, then relays and delivers validator 1's
        /// proposal there and its notarization.
        fn notarize_target(
            ctx: Ctx,
            net: *h.Network,
            stack: *h.VoterStack,
            label: []const u8,
        ) !h.Proposal {
            const gpa = ctx.gpa();
            _ = try stack.next_update(ctx, 5_000);
            const parent = try h.advance_to_view(stack, ctx, net, target);
            const proposal = h.proposal_at(epoch, target, label);
            h.relay_contents(net, 1, proposal.payload, proposal.round, parent, 0);
            try stack.mailbox.proposal(proposal);
            const notarization =
                try h.build(gpa, .notarization, net.schemes(), proposal, net.quorum());
            try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
            return proposal;
        }

        /// Whether an update past the target view arrives within `limit_ms`.
        fn advances_within(ctx: Ctx, stack: *h.VoterStack, limit_ms: u64) !bool {
            var waited: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited <= limit_ms) : (waited += 1) {
                if (stack.batcher.try_recv()) |message| {
                    if (message == .update and message.update.current.get() > target) return true;
                    continue;
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
            return false;
        }

        // commonware test_cancelled_certification_recertifies_after_restart: a canceled
        // certify request must not be persisted as a failure. After a restart the view
        // certifies from replayed notarization state, with no immediate nullify.
        test "voter cancelled certification recertifies after restart" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "cancelled_cert_restart_recertify");
                    defer net.deinit();
                    const partition = "cancelled_certification_recertifies_after_restart";
                    var first = options(partition);
                    first.certifier = .cancel;
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, first);
                    defer stack.stop();
                    _ = try notarize_target(ctx, &net, &stack, "restart_recertify_payload");
                    // Give the canceled certification attempt time to run.
                    try ctx.sleep(.fromMilliseconds(200));
                    // A canceled certification must not advance the view.
                    try testing.expect(!try advances_within(ctx, &stack, 200));
                    // A longer certify latency leaves a window in which a wrong immediate
                    // nullify could fire after the restart.
                    var restarted = options(partition);
                    restarted.certify_latency_ms = 2_000;
                    try stack.replace(ctx, &net, restarted);
                    _ = try stack.next_update(ctx, 5_000);
                    try expect_recertified(ctx, &stack);
                    // Let the reporter ingest late events.
                    try ctx.sleep(.fromMilliseconds(100));
                    try testing.expectEqual(0, stack.reporter.votes(.new(target)).nullify);
                    try testing.expect(!stack.reporter.nullified(.new(target)));
                }
            }.body, 20);
        }

        /// Waits up to 5 s for a successful certification at the target view, failing on our
        /// nullify vote there first.
        fn expect_recertified(ctx: Ctx, stack: *h.VoterStack) !void {
            var waited: u64 = 0;
            // Bounded by 5 s of simulated time.
            while (waited <= 5_000) : (waited += 1) {
                if (stack.resolver.try_recv()) |message| {
                    defer message.discard();
                    if (message != .certified) continue;
                    if (message.certified.notarization.view().get() != target) continue;
                    try testing.expect(message.certified.success);
                    return;
                } else |_| {}
                if (stack.batcher.try_recv()) |message| {
                    if (message == .constructed and message.constructed == .nullify and
                        message.constructed.view().get() == target)
                    {
                        return error.ImmediateNullifyAfterRestart;
                    }
                    continue;
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
            return error.NotRecertified;
        }

        /// Our next nullify vote within `limit_ms`, skipping other batcher messages.
        fn next_nullify(ctx: Ctx, stack: *h.VoterStack, limit_ms: u64) !?u64 {
            var waited: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited <= limit_ms) : (waited += 1) {
                if (stack.batcher.try_recv()) |message| {
                    if (message == .constructed and message.constructed == .nullify) {
                        return message.constructed.view().get();
                    }
                    continue;
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
            return null;
        }

        /// The highest view announced within `limit_ms`, failing on a nullify vote for any
        /// view but `stuck`, if given.
        fn highest_view_within(ctx: Ctx, stack: *h.VoterStack, stuck: ?u64, limit_ms: u64) !u64 {
            var highest: u64 = 0;
            var waited: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited <= limit_ms) : (waited += 1) {
                if (stack.batcher.try_recv()) |message| {
                    switch (message) {
                        .update => |update| highest = @max(highest, update.current.get()),
                        .constructed => |vote| if (vote == .nullify) {
                            // Only the stuck view is nullified.
                            if (stuck) |view| try testing.expectEqual(view, vote.view().get());
                        },
                    }
                    continue;
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
            return highest;
        }

        // commonware test_only_finalization_rescues_validator: a validator stuck on view 4,
        // whose certification never completes, is not rescued by a notarization of view 5
        // (it can only nullify its current view), but a finalization of view 5 rescues it.
        test "voter only finalization rescues validator" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 4, "future_notarization_no_rescue");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 2_000,
                        .certification_timeout_ms = 3_000,
                        .timeout_retry_ms = 1_000,
                        .certifier = .cancel,
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 5_000);
                    const parent = try h.advance_to_view(&stack, ctx, &net, 4);
                    const p4 = h.proposal_at(epoch, 4, "view_4_proposal");
                    h.relay_contents(&net, 1, p4.payload, p4.round, parent, 0);
                    try stack.mailbox.proposal(p4);
                    const n4 = try h.build(gpa, .notarization, net.schemes(), p4, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .notarization = n4 });
                    // The first nullify vote confirms the stuck state.
                    try testing.expectEqual(4, try next_nullify(ctx, &stack, 10_000));
                    // The validators that certified view 4 progress at view 5.
                    const p5: h.Proposal = .init(
                        .new(epoch, .new(5)),
                        .new(4),
                        h.Sha256.hash(&.{"view_5_proposal"}),
                    );
                    const n5 = try h.build(gpa, .notarization, net.schemes(), p5, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .notarization = n5 });
                    // Retries re-send the view-4 nullify every second, but nothing advances.
                    try testing.expect(try highest_view_within(ctx, &stack, 4, 5_000) <= 4);
                    // A finalization of view 5 is the only escape.
                    const f5 = try h.build(gpa, .finalization, net.schemes(), p5, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .finalization = f5 });
                    try testing.expect(try highest_view_within(ctx, &stack, null, 5_000) > 5);
                }
            }.body, 60);
        }

        // commonware test_certification_failure_allows_nullify_after_notarize: when
        // certification fails after we voted notarize, we vote nullify at once, long before
        // the 100 s timeouts, so the honest validators that notarized can still form a
        // nullification.
        test "voter certification failure allows nullify after notarize" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "cert_fail_nullify");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 100_000,
                        .certification_timeout_ms = 100_000,
                        .timeout_retry_ms = 100_000,
                        .certifier = .{ .custom = never },
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 5_000);
                    const parent = try h.advance_to_view(&stack, ctx, &net, target);
                    const proposal = h.proposal_at(epoch, target, "test_proposal");
                    h.relay_contents(&net, 1, proposal.payload, proposal.round, parent, 0);
                    try stack.mailbox.proposal(proposal);
                    // Verification passes, so we notarize first.
                    // Bounded by the 2 s wait per message.
                    while (true) {
                        const next = try stack.next_batcher(ctx, 2_000);
                        const message = next orelse return error.NoNotarize;
                        if (message != .constructed or message.constructed != .notarize) continue;
                        if (message.constructed.view().get() == target) break;
                    }
                    const notarization =
                        try h.build(gpa, .notarization, net.schemes(), proposal, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
                    try testing.expect(try stack.nullify_within(ctx, target, 5_000));
                }
            }.body, 10);
        }

        fn never(_: h.Round, _: h.Digest) bool {
            return false;
        }
    };
}
