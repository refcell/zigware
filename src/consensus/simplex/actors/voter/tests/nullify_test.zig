//! commonware `simplex/actors/voter/mod.rs` nullify fast-path tests: a voter whose view can no
//! longer produce a notarize (a failed, dropped, or abandoned proposal, or the leader's own
//! nullify hint) nullifies at once instead of waiting out its 10 s timeouts.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const View = h.View;
        const Sha256 = h.Sha256;
        const epoch = h.default_epoch;

        /// commonware's fast-path configuration: timeouts far beyond the 1 s the tests wait.
        const slow_timeouts: h.Options = .{
            .leader_timeout_ms = 10_000,
            .certification_timeout_ms = 10_000,
            .timeout_retry_ms = 60 * 60 * 1000,
            .batcher_capacity = 32,
        };

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = 20 * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        const Position = struct { view: View, leader: u32 };

        /// The first update: the voter's starting view and its leader.
        fn first_update(ctx: Ctx, stack: *h.VoterStack) !Position {
            const message = (try stack.next_batcher(ctx, 1_000)) orelse return error.NoUpdate;
            if (message != .update) return error.UnexpectedMessage;
            return .{ .view = message.update.current, .leader = message.update.leader.get() };
        }

        /// Finalizes `at.view` with payload `hash(view)` and returns the next view it enters.
        fn finalize_and_advance(
            ctx: Ctx,
            net: *h.Network,
            stack: *h.VoterStack,
            at: Position,
        ) !Position {
            const gpa = ctx.gpa();
            const view = at.view.get();
            var label: [8]u8 = undefined;
            std.mem.writeInt(u64, &label, view, .big);
            const parent: View = .new(view -| 1);
            const payload = Sha256.hash(&.{&label});
            const proposal: h.Proposal = .init(.new(epoch, at.view), parent, payload);
            const schemes = net.schemes();
            const finalization =
                try h.build(gpa, .finalization, schemes, proposal, net.quorum());
            try stack.mailbox.recovered(gpa, .{ .finalization = finalization });
            // Bounded by the runner's timeout.
            while (true) {
                const message = (try stack.next_batcher(ctx, 5_000)) orelse return error.TimedOut;
                if (message != .update or message.update.current.get() <= view) continue;
                return .{ .view = message.update.current, .leader = message.update.leader.get() };
            }
        }

        /// Finalizes views until one whose leader is (`leading`) or is not (`!leading`) us.
        fn advance_until(
            ctx: Ctx,
            net: *h.Network,
            stack: *h.VoterStack,
            start: Position,
            leading: bool,
        ) !Position {
            var at = start;
            // Round-robin over 5 participants: a matching view is at most 5 views away.
            for (0..8) |_| {
                if ((at.leader == 0) == leading) return at;
                at = try finalize_and_advance(ctx, net, stack, at);
            }
            return error.NoMatchingView;
        }

        /// Broadcasts a proposal at `at` over the finalized `view - 1` (payload
        /// `hash(view - 1)`), from its leader, and hands it to the voter.
        fn propose(
            net: *h.Network,
            stack: *h.VoterStack,
            at: Position,
            label: []const u8,
            nonce: u64,
        ) !void {
            const view = at.view.get();
            const proposal = h.proposal_at(epoch, view, label);
            var parent_label: [8]u8 = undefined;
            std.mem.writeInt(u64, &parent_label, view - 1, .big);
            var buffer: [128]u8 = undefined;
            var writer: codec.Writer = .init(&buffer);
            proposal.round.write(&writer);
            codec.write(h.Digest, Sha256.hash(&.{&parent_label}), &writer);
            codec.write(u64, nonce, &writer);
            net.relay.broadcast(net.keys()[at.leader], .all, proposal.payload, writer.written());
            try stack.mailbox.proposal(proposal);
        }

        /// Waits `limit_ms` of simulated time for our nullify at `view`; true when it came.
        fn nullified_within(ctx: Ctx, stack: *h.VoterStack, view: View, limit_ms: u64) !bool {
            var waited: u64 = 0;
            while (waited <= limit_ms) {
                if (stack.batcher.try_recv()) |message| {
                    if (message != .constructed) continue;
                    const vote = message.constructed;
                    if (vote == .nullify and vote.view().get() == view.get()) return true;
                    continue;
                } else |err| switch (err) {
                    error.Empty => {},
                    else => return error.MailboxClosed,
                }
                try ctx.sleep(.fromMilliseconds(1));
                waited += 1;
            }
            return false;
        }

        /// Whether the timeouts metric counted `reason` at least once.
        fn timeout_counted(ctx: Ctx, comptime reason: []const u8) !bool {
            const gpa = ctx.gpa();
            const encoded = try ctx.scope.encode(gpa);
            defer gpa.free(encoded);
            const label = "reason=\"" ++ reason ++ "\"";
            var lines = std.mem.splitScalar(u8, encoded, '\n');
            var counted = false;
            // Bounded by the encoded metrics.
            while (lines.next()) |line| {
                if (std.mem.indexOf(u8, line, "_timeouts") == null) continue;
                if (std.mem.indexOf(u8, line, label) == null) continue;
                counted = counted or !std.mem.endsWith(u8, line, " 0");
            }
            return counted;
        }

        const Vote = @FieldType(h.BatcherMessage, "constructed");

        /// Whether our vote at `view` reaches `observer` within `limit_ms` of simulated time,
        /// draining the batcher meanwhile (commonware's `select!` over both).
        fn network_vote_within(
            ctx: Ctx,
            stack: *h.VoterStack,
            observer: *h.Observer,
            view: View,
            limit_ms: u64,
        ) !bool {
            var waited: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited < limit_ms) {
                while (stack.batcher.try_recv()) |_| {} else |_| {}
                var message = observer.receiver.try_recv() catch {
                    try ctx.sleep(.fromMilliseconds(1));
                    waited += 1;
                    continue;
                };
                defer message.deinit();
                const vote = try codec.decode(Vote, ctx.gpa(), message.payload);
                if (vote.view().get() == view.get()) return true;
            }
            return false;
        }

        fn expect_fast_nullify(ctx: Ctx, stack: *h.VoterStack, view: View) !void {
            // With 10 s timeouts, a nullify within 1 s came from the fast path.
            if (!try nullified_within(ctx, stack, view, 1_000)) return error.NoFastNullify;
        }

        // commonware test_verification_failure_emits_nullify_immediately
        test "voter verification failure emits nullify immediately" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "consensus");
                    defer net.deinit();
                    var options = slow_timeouts;
                    options.fail_verification = true;
                    options.verify_latency_ms = 10;
                    options.partition = "voter_verify_fail_test";
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, options);
                    defer stack.stop();
                    const start = try first_update(ctx, &stack);
                    const at = try advance_until(ctx, &net, &stack, start, false);
                    try propose(&net, &stack, at, "test_proposal", 0);
                    try expect_fast_nullify(ctx, &stack, at.view);
                }
            }.body);
        }

        // commonware test_leader_nullify_timeout_hint_fast_paths_nullify
        test "voter leader nullify timeout hint fast paths nullify" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "leader_nullify_timeout_hint_fast_paths_nullify");
                    defer net.deinit();
                    var options = slow_timeouts;
                    options.partition = "voter_leader_nullify_fast_path";
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, options);
                    defer stack.stop();
                    const start = try first_update(ctx, &stack);
                    // As a verifier, the leader's nullify hint nullifies at once.
                    const at = try advance_until(ctx, &net, &stack, start, false);
                    const round: h.Round = .new(epoch, at.view);
                    try stack.mailbox.timeout(round, .leader_nullify);
                    try expect_fast_nullify(ctx, &stack, at.view);
                    // A duplicate hint does not nullify again.
                    try stack.mailbox.timeout(round, .leader_nullify);
                    try testing.expect(!try nullified_within(ctx, &stack, at.view, 300));
                }
            }.body);
        }

        // commonware test_dropped_propose_emits_nullify_immediately
        test "voter dropped propose emits nullify immediately" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "dropped_propose_emits_nullify_immediately");
                    defer net.deinit();
                    var options = slow_timeouts;
                    options.drop_proposals = true;
                    options.partition = "voter_drop_propose_test";
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, options);
                    defer stack.stop();
                    const start = try first_update(ctx, &stack);
                    // As the leader, a dropped propose response nullifies at once.
                    const at = try advance_until(ctx, &net, &stack, start, true);
                    try expect_fast_nullify(ctx, &stack, at.view);
                }
            }.body);
        }

        // commonware test_dropped_verify_emits_nullify_immediately
        test "voter dropped verify emits nullify immediately" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "dropped_verify_emits_nullify_immediately");
                    defer net.deinit();
                    var options = slow_timeouts;
                    options.partition = "voter_drop_verify_test";
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, options);
                    defer stack.stop();
                    stack.application.drop_verifications = true;
                    const start = try first_update(ctx, &stack);
                    const at = try advance_until(ctx, &net, &stack, start, false);
                    try propose(&net, &stack, at, "drop_verify", 0);
                    try expect_fast_nullify(ctx, &stack, at.view);
                    // A dropped verify counts as an ignored proposal.
                    try testing.expect(try timeout_counted(ctx, "IgnoredProposal"));
                }
            }.body);
        }

        // commonware test_invalid_ancestry_emits_nullify_immediately
        test "voter invalid ancestry emits nullify immediately" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "invalid_ancestry_emits_nullify_immediately");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, slow_timeouts);
                    defer stack.stop();
                    // Advance until we verify in a view after a finalization.
                    var at = try first_update(ctx, &stack);
                    if (at.view.get() == 1) at = try finalize_and_advance(ctx, &net, &stack, at);
                    at = try advance_until(ctx, &net, &stack, at, false);
                    // A proposal whose parent is below the finalized floor.
                    const view = at.view.get();
                    const parent: View = .new((view - 1) -| 1);
                    const payload = Sha256.hash(&.{"invalid_parent_before_finalized"});
                    try stack.mailbox.proposal(.init(.new(epoch, at.view), parent, payload));
                    try expect_fast_nullify(ctx, &stack, at.view);
                    try testing.expect(try timeout_counted(ctx, "InvalidProposal"));
                }
            }.body);
        }

        // commonware test_dropped_verify_still_votes_after_prior_participation
        test "voter dropped verify still votes after prior participation" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "dropped_verify_still_votes_after_prior_participation");
                    defer net.deinit();
                    var observer: h.Observer = undefined;
                    try observer.start(&net, 1, 0);
                    defer observer.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 250,
                        .certification_timeout_ms = 250,
                        .timeout_retry_ms = 60 * 60 * 1000,
                        .partition = "voter_dropped_verify_after_participation",
                        .batcher_capacity = 64,
                    });
                    defer stack.stop();
                    stack.application.drop_verifications = true;
                    // We vote over the network in a view we lead.
                    const start = try first_update(ctx, &stack);
                    const led = try advance_until(ctx, &net, &stack, start, true);
                    const voted = try network_vote_within(ctx, &stack, &observer, led.view, 1_000);
                    try testing.expect(voted);
                    // In a later view we verify, the dropped verify still leads to a vote.
                    var at = try finalize_and_advance(ctx, &net, &stack, led);
                    at = try advance_until(ctx, &net, &stack, at, false);
                    try propose(&net, &stack, at, "drop_verify_after_ready", 11);
                    const retried = try network_vote_within(ctx, &stack, &observer, at.view, 1_000);
                    try testing.expect(retried);
                }
            }.body);
        }
    };
}
