//! commonware `simplex/actors/voter/mod.rs` replay tests: what a restarted voter redoes, and
//! does not redo, after replaying its journal.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const Sha256 = h.Sha256;
        const epoch = h.default_epoch;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = 10 * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        fn certify_calls(stack: *h.VoterStack) u32 {
            return @atomicLoad(u32, &stack.automaton.certify_calls, .acquire);
        }

        const no_recertification: h.Options = .{
            .leader_timeout_ms = 500,
            .certification_timeout_ms = 1_000_000,
            .timeout_retry_ms = 1_000_000,
            .partition = "no_recertification_after_replay",
            .batcher_capacity = 8,
        };

        /// Finalizes view 2 (no certification) and notarizes view 3 (certified once).
        fn finalize_2_and_certify_3(ctx: Ctx, net: *h.Network, stack: *h.VoterStack) !void {
            const gpa = ctx.gpa();
            const schemes = net.schemes();
            const quorum = net.quorum();
            const round_2: h.Round = .new(epoch, .new(2));
            const proposal_2: h.Proposal =
                .init(round_2, .new(1), Sha256.hash(&.{"finalized_payload"}));
            const finalization = try h.build(gpa, .finalization, schemes, proposal_2, quorum);
            try stack.mailbox.recovered(gpa, .{ .finalization = finalization });
            // Bounded: views only advance, and each wait is limited.
            while ((try stack.next_update(ctx, 5_000)).finalized.get() < 2) {}
            try testing.expectEqual(@as(u32, 0), certify_calls(stack));
            const round_3: h.Round = .new(epoch, .new(3));
            const payload_3 = Sha256.hash(&.{"payload_for_certification"});
            const proposal_3: h.Proposal = .init(round_3, .new(2), payload_3);
            h.relay_contents(net, 0, payload_3, round_3, proposal_2.payload, 0);
            try stack.mailbox.proposal(proposal_3);
            const notarization = try h.build(gpa, .notarization, schemes, proposal_3, quorum);
            try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
            // Bounded: views only advance, and each wait is limited.
            while ((try stack.next_update(ctx, 5_000)).current.get() <= 3) {}
            try testing.expectEqual(@as(u32, 1), certify_calls(stack));
        }

        // commonware test_no_recertification_after_replay
        test "voter no recertification after replay" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "no_recertification_after_replay");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, no_recertification);
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    try finalize_2_and_certify_3(ctx, &net, &stack);
                    // The restarted voter replays both views without certifying again.
                    try stack.restart(ctx, &net, no_recertification);
                    _ = try stack.next_update(ctx, 5_000);
                    try ctx.sleep(.fromMilliseconds(100));
                    try testing.expectEqual(@as(u32, 1), certify_calls(&stack));
                }
            }.body);
        }
    };
}
