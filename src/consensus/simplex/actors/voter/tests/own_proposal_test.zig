//! commonware `simplex/actors/voter/mod.rs` own-proposal tests: a voter never verifies a
//! proposal it built, nor proposes or verifies again for a view whose notarize it journaled.
//! Round robin over 5 in epoch 333 elects us (participant 0) for view 2 and participant 1 for
//! view 3.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const Sha256 = h.Sha256;
        const epoch = h.default_epoch;

        fn run(timeout_s: u64, comptime body: fn (Ctx) anyerror!void) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = timeout_s * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        /// The voter of these tests: a 500 ms leader timeout, 1 s otherwise, on `partition`.
        fn options(partition: []const u8) h.Options {
            return .{
                .leader_timeout_ms = 500,
                .certification_timeout_ms = 1_000,
                .timeout_retry_ms = 1_000,
                .partition = partition,
                .batcher_capacity = 8,
            };
        }

        /// Waits for our notarize at `view` and returns its proposal.
        fn wait_notarize(ctx: Ctx, stack: *h.VoterStack, view: u64) !h.Proposal {
            // Bounded by the per-message wait.
            while (true) {
                const message = (try stack.next_batcher(ctx, 5_000)) orelse
                    return error.NoNotarize;
                if (message != .constructed or message.constructed != .notarize) continue;
                const vote = message.constructed.notarize;
                if (vote.view().get() == view) return vote.proposal;
            }
        }

        /// Waits for our nullify at `view` (the leader timeout), failing on a notarize there.
        fn wait_nullify_only(ctx: Ctx, stack: *h.VoterStack, view: u64) !void {
            // Bounded by the per-message wait.
            while (true) {
                const message = (try stack.next_batcher(ctx, 5_000)) orelse
                    return error.NoNullify;
                if (message != .constructed or message.constructed.view().get() != view) continue;
                switch (message.constructed) {
                    .nullify => return,
                    .notarize => return error.Notarized,
                    .finalize => {},
                }
            }
        }

        /// Expects the restarted voter's first update to re-enter `view` under `leader`.
        fn expect_reentered(ctx: Ctx, stack: *h.VoterStack, view: u64, leader: u32) !void {
            const update = try stack.next_update(ctx, 5_000);
            try testing.expectEqual(view, update.current.get());
            try testing.expectEqual(leader, update.leader.get());
        }

        // commonware test_no_self_verify_when_proposing
        test "voter no self verify when proposing" {
            try h.covers(.schemes_round_robin);
            try run(10, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "no_self_verify_when_proposing");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, options("no_self_verify_when_proposing"));
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    _ = try h.advance_to_view(&stack, ctx, &net, 2);
                    // The leader timeout's nullify comes after the whole propose flow ran.
                    try testing.expect(try stack.nullify_within(ctx, 2, 5_000));
                    try testing.expect(stack.automaton.proposal_requested(2));
                    try testing.expect(!stack.automaton.verification_requested(2));
                }
            }.body);
        }

        // commonware test_no_self_propose_or_verify_after_restart
        test "voter no self propose or verify after restart" {
            try h.covers(.schemes_round_robin);
            try run(10, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "no_self_propose_or_verify_after_restart");
                    defer net.deinit();
                    const voter = options("no_self_propose_or_verify_after_restart");
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, voter);
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    _ = try h.advance_to_view(&stack, ctx, &net, 2);
                    const proposal = try wait_notarize(ctx, &stack, 2);
                    // Replaying our journaled notarize restores the view's proposal, so a
                    // re-delivered copy neither proposes nor verifies again.
                    try stack.replace(ctx, &net, voter);
                    try expect_reentered(ctx, &stack, 2, 0);
                    try stack.mailbox.proposal(proposal);
                    try testing.expect(try stack.nullify_within(ctx, 2, 5_000));
                    try testing.expect(!stack.automaton.proposal_requested(2));
                    try testing.expect(!stack.automaton.verification_requested(2));
                }
            }.body);
        }

        // commonware test_nullify_after_crash_in_propose_window
        test "voter nullify after crash in propose window" {
            try h.covers(.schemes_round_robin);
            try run(30, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "nullify_after_crash_in_propose_window");
                    defer net.deinit();
                    // Before the crash, the propose request never returns.
                    var voter = options("nullify_after_crash_in_propose_window");
                    voter.leader_timeout_ms = 600_000;
                    voter.certification_timeout_ms = 600_000;
                    voter.timeout_retry_ms = 600_000;
                    voter.stall_proposals = true;
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, voter);
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    _ = try h.advance_to_view(&stack, ctx, &net, 2);
                    try stack.wait_proposal_request(ctx, 2);
                    // Nothing was journaled, so the restarted voter proposes once, has it
                    // dropped, and nullifies instead of retrying.
                    voter.leader_timeout_ms = 500;
                    voter.stall_proposals = false;
                    voter.drop_proposals = true;
                    try stack.replace(ctx, &net, voter);
                    try expect_reentered(ctx, &stack, 2, 0);
                    try wait_nullify_only(ctx, &stack, 2);
                    try testing.expectEqual(@as(u32, 1), stack.automaton.requests_for(2));
                }
            }.body);
        }

        // commonware test_no_self_verify_after_restart
        test "voter no self verify after restart" {
            try h.covers(.schemes_round_robin);
            try run(10, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "no_self_verify_after_restart");
                    defer net.deinit();
                    const voter = options("no_self_verify_after_restart");
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, voter);
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    const parent = try h.advance_to_view(&stack, ctx, &net, 3);
                    // We verify and notarize the leader's proposal for view 3.
                    const round: h.Round = .new(epoch, .new(3));
                    const payload = Sha256.hash(&.{"follower_proposal"});
                    const proposal: h.Proposal = .init(round, .new(2), payload);
                    h.relay_contents(&net, 1, payload, round, parent, 0);
                    try stack.mailbox.proposal(proposal);
                    try testing.expect((try wait_notarize(ctx, &stack, 3)).eql(proposal));
                    // After replaying that notarize, a re-delivered copy is not verified again.
                    try stack.replace(ctx, &net, voter);
                    try expect_reentered(ctx, &stack, 3, 1);
                    try stack.mailbox.proposal(proposal);
                    try testing.expect(try stack.nullify_within(ctx, 3, 5_000));
                    try testing.expect(!stack.automaton.verification_requested(3));
                    try testing.expect(!stack.automaton.proposal_requested(3));
                }
            }.body);
        }
    };
}
