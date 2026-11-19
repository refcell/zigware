//! commonware `simplex/actors/voter/mod.rs` certification-and-timeout tests: a canceled
//! certification is not journaled as a failure, so a restart certifies the view again.

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
    };
}
