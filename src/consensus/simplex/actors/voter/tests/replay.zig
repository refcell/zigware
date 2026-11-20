//! commonware `simplex/actors/voter/mod.rs` certification replay tests: a certification
//! verdict is journaled with the finalize vote it enables, in one section sync, and replays
//! after a restart without asking the automaton again.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;
        const target = 3;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            try h.soak(20 * std.time.ns_per_s, body);
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

        /// Advances validator 0 to follower view 3, relays and hands it validator 1's
        /// proposal there, waits for our notarize vote, and delivers the notarization.
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
            // Bounded by the 5 s wait per message.
            while (true) {
                const next = try stack.next_batcher(ctx, 5_000);
                const message = next orelse return error.NoNotarize;
                if (message != .constructed or message.constructed != .notarize) continue;
                if (message.constructed.view().get() == target) break;
            }
            const notarization =
                try h.build(gpa, .notarization, net.schemes(), proposal, net.quorum());
            try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
            return proposal;
        }

        /// The verdict of the next `certified` resolver message at the target view within
        /// `limit_ms`, or null; other messages are dropped.
        fn next_certified(ctx: Ctx, stack: *h.VoterStack, limit_ms: u64) !?bool {
            var waited: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited <= limit_ms) : (waited += 1) {
                if (stack.resolver.try_recv()) |message| {
                    defer message.discard();
                    if (message != .certified) continue;
                    const certified = message.certified;
                    if (certified.notarization.view().get() == target) return certified.success;
                    continue;
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
            return null;
        }

        /// Whether our finalize vote at the target view is queued for the batcher now.
        fn finalize_queued(stack: *h.VoterStack) bool {
            var found = false;
            // Bounded by the queued messages.
            while (stack.batcher.try_recv()) |message| {
                if (message != .constructed or message.constructed != .finalize) continue;
                found = found or message.constructed.view().get() == target;
            } else |_| {}
            return found;
        }

        /// Waits for our finalize vote at the target view on `observer` within `limit_ms`.
        fn finalize_broadcast(ctx: Ctx, observer: *h.Observer, limit_ms: u64) !bool {
            var waited: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited <= limit_ms) : (waited += 1) {
                const vote = try observer.next_vote(ctx, 0) orelse {
                    try ctx.sleep(.fromMilliseconds(1));
                    continue;
                };
                if (vote == .finalize and vote.view().get() == target) return true;
            }
            return false;
        }

        /// The first run of commonware `successful_certification_replayed_after_restart`: the
        /// certification and the finalize it enables are appended, then wait behind one
        /// section sync before anything observes them.
        fn certify_behind_sync(ctx: Ctx, net: *h.Network, observer: *h.Observer) !h.Proposal {
            var gates: runtime.storage.mocks.SyncGates = .init(ctx.io());
            var stack: h.VoterStack = undefined;
            var first = options("successful_cert_replay");
            first.sync_gates = &gates;
            first.hold_certifications = .{ .view = target };
            try stack.start(ctx, net, first);
            defer stack.stop();
            const proposal = try notarize_target(ctx, net, &stack, "cert_replay_payload");
            const slot = try stack.automaton.take_certification(ctx, target);
            // Arm the gate immediately before the certification succeeds.
            gates.arm();
            stack.automaton.answer_certification(slot, true);
            var waited: u64 = 0;
            // Bounded by 5 s of simulated time.
            while (!gates.blocked()) : (waited += 1) {
                if (waited > 5_000) return error.SyncNotBlocked;
                try ctx.sleep(.fromMilliseconds(1));
            }
            // Nothing observes the certification or the finalize before the sync completes.
            try testing.expectEqual(null, try next_certified(ctx, &stack, 0));
            try testing.expect(!stack.reporter.certified(.new(target)));
            try testing.expect(!finalize_queued(&stack));
            try testing.expectEqual(1, gates.calls());
            try testing.expect(!try finalize_broadcast(ctx, observer, 100));
            gates.release();
            // Bounded by the 5 s wait per message.
            while (true) {
                const next = try stack.next_batcher(ctx, 5_000);
                const message = next orelse return error.NoDurableFinalize;
                if (message != .constructed or message.constructed != .finalize) continue;
                if (message.constructed.view().get() == target) break;
            }
            try testing.expectEqual(true, try next_certified(ctx, &stack, 5_000));
            try expect_certified(ctx, &stack, proposal);
            try testing.expect(try finalize_broadcast(ctx, observer, 5_000));
            // The certification and the finalize share one section sync.
            try testing.expectEqual(1, gates.calls());
            return proposal;
        }

        fn expect_certified(ctx: Ctx, stack: *h.VoterStack, proposal: h.Proposal) !void {
            const gpa = ctx.gpa();
            try testing.expect(stack.reporter.certified(.new(target)));
            var reported = (try stack.reporter.notarization(.new(target))).?;
            defer reported.deinit(gpa);
            try testing.expect(reported.proposal.eql(proposal));
        }

        // commonware test_successful_certification_replayed_after_restart: the replayed
        // certification advances exactly one view without re-certifying, and the coalesced
        // finalize replays too.
        test "voter successful certification replayed after restart" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "successful_cert_replay");
                    defer net.deinit();
                    var observer: h.Observer = undefined;
                    try observer.start(&net, 1, 0);
                    defer observer.deinit();
                    const proposal = try certify_behind_sync(ctx, &net, &observer);
                    // A fresh voter, automaton, and reporter over the same journal. Holding
                    // every certification shows any request the replay makes.
                    var stack: h.VoterStack = undefined;
                    var restarted = options("successful_cert_replay");
                    restarted.hold_certifications = .all;
                    try stack.start(ctx, &net, restarted);
                    defer stack.stop();
                    try testing.expectEqual(true, try next_certified(ctx, &stack, 5_000));
                    try stack.expect_update(ctx, target + 1, target - 1);
                    // The voter must not re-certify the replayed view.
                    try testing.expect(!stack.automaton.certification_requested(target));
                    const finalizes = stack.reporter.votes(.new(target)).finalize;
                    try testing.expect(finalizes & 1 != 0);
                    try expect_certified(ctx, &stack, proposal);
                }
            }.body);
        }

        // commonware test_failed_certification_replayed_after_restart: a failed certification
        // replays as a failure, reported to the resolver but not the reporter, and the voter
        // stays at the target view.
        test "voter failed certification replayed after restart" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "failed_cert_replay");
                    defer net.deinit();
                    var first = options("failed_cert_replay");
                    first.certifier = .{ .custom = never };
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, first);
                    const label = "failed_cert_replay_payload";
                    _ = notarize_target(ctx, &net, &stack, label) catch |err| {
                        stack.stop();
                        return err;
                    };
                    const verdict = next_certified(ctx, &stack, 5_000) catch |err| {
                        stack.stop();
                        return err;
                    };
                    const failed = verdict == false and !stack.reporter.certified(.new(target));
                    // Let the journal sync.
                    ctx.sleep(.fromMilliseconds(50)) catch {};
                    stack.stop();
                    try testing.expect(failed);
                    var restarted: h.VoterStack = undefined;
                    try restarted.start(ctx, &net, options("failed_cert_replay"));
                    defer restarted.stop();
                    try testing.expectEqual(false, try next_certified(ctx, &restarted, 5_000));
                    // After replay the voter is at the target view, not past it.
                    try restarted.expect_update(ctx, target, target - 1);
                    try testing.expect(!restarted.reporter.certified(.new(target)));
                }
            }.body);
        }

        fn never(_: h.Round, _: h.Digest) bool {
            return false;
        }
    };
}
