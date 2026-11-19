//! commonware `simplex/actors/voter/mod.rs` verification tests: which proposals reach the
//! application's `verify`, and which in-flight verifications a certificate or a failed ancestor
//! makes the voter drop.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const Sha256 = h.Sha256;
        const epoch = h.default_epoch;
        const RoundRobin = @FieldType(h.Options, "elector");

        fn run(timeout_s: u64, comptime body: fn (Ctx) anyerror!void) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = timeout_s * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        /// The leader `elector` picks for `view` among `n` validators.
        fn leader(gpa: std.mem.Allocator, elector: RoundRobin, n: u32, view: u64) !usize {
            std.debug.assert(n > 0);
            var built = try elector.build(gpa, n);
            defer built.deinit(gpa);
            const elected = built.elect(.new(epoch, .new(view)), {}).get();
            std.debug.assert(elected < n);
            return elected;
        }

        /// Relays `proposal`'s contents from `sender` as the mock application encodes them:
        /// `(round, parent payload, nonce)`.
        fn relay(
            net: *h.Network,
            sender: usize,
            subject: h.Proposal,
            parent: h.Digest,
            nonce: u64,
        ) void {
            var buffer: [128]u8 = undefined;
            var writer: codec.Writer = .init(&buffer);
            subject.round.write(&writer);
            codec.write(h.Digest, parent, &writer);
            codec.write(u64, nonce, &writer);
            net.relay.broadcast(net.keys()[sender], .all, subject.payload, writer.written());
        }

        fn proposal(view: u64, parent: u64, label: []const u8) h.Proposal {
            return .init(.new(epoch, .new(view)), .new(parent), Sha256.hash(&.{label}));
        }

        /// Waits up to `limit_ms` for our vote of `kind` at `view`; false when none came.
        fn vote_within(
            ctx: Ctx,
            stack: *h.VoterStack,
            comptime kind: anytype,
            view: u64,
            limit_ms: u64,
        ) !bool {
            var waited: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited < limit_ms) {
                const message = stack.batcher.try_recv() catch |err| switch (err) {
                    error.Empty => {
                        try ctx.sleep(.fromMilliseconds(1));
                        waited += 1;
                        continue;
                    },
                    else => return error.MailboxClosed,
                };
                if (message != .constructed or message.constructed != kind) continue;
                if (message.constructed.view().get() == view) return true;
            }
            return false;
        }

        /// Waits for the batcher update announcing a view above `view`.
        fn wait_past(ctx: Ctx, stack: *h.VoterStack, view: u64) !void {
            // Bounded: views only advance, and each wait is limited.
            while (true) {
                const update = try stack.next_update(ctx, 5_000);
                if (update.current.get() > view) return;
            }
        }

        fn reject_view_1(round: h.Round, _: h.Digest) bool {
            return round.view.get() != 1;
        }

        /// Starts the voter as the follower after view 1's leader in a stable-leader term.
        fn start_failed_ancestor(
            ctx: Ctx,
            net: *h.Network,
            stack: *h.VoterStack,
            elector: RoundRobin,
        ) !usize {
            const leader_index = try leader(ctx.gpa(), elector, 5, 1);
            try stack.start(ctx, net, .{
                .leader_timeout_ms = 10_000,
                .certification_timeout_ms = 10_000,
                .timeout_retry_ms = 30_000,
                .local_index = (leader_index + 1) % 5,
                .certifier = .{ .custom = reject_view_1 },
                .elector = elector,
            });
            _ = try stack.next_update(ctx, 1_000);
            return leader_index;
        }

        // commonware test_failed_certification_blocks_direct_descendant_verify
        test "voter failed certification blocks direct descendant verify" {
            try h.covers(.ed25519);
            try run(20, struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    const namespace = "failed_certification_blocks_direct_descendant_verify";
                    try net.start(ctx, 5, namespace);
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    const elector = h.term_elector(5, 30_000, 2);
                    const leader_index = try start_failed_ancestor(ctx, &net, &stack, elector);
                    defer stack.stop();
                    // Locally notarize view 1, then view 2 optimistically above it.
                    const proposal_1 = proposal(1, 0, "failed_ancestor_view_1");
                    relay(&net, leader_index, proposal_1, h.genesis(epoch), 0);
                    try stack.mailbox.proposal(proposal_1);
                    if (!try vote_within(ctx, &stack, .notarize, 1, 5_000)) return error.NoVote;
                    const proposal_2 = proposal(2, 1, "failed_ancestor_view_2");
                    relay(&net, leader_index, proposal_2, proposal_1.payload, 1);
                    try stack.mailbox.proposal(proposal_2);
                    if (!try vote_within(ctx, &stack, .notarize, 2, 5_000)) return error.NoVote;
                    // View 1's certification is rejected, so it nullifies.
                    const schemes = net.schemes();
                    const quorum = net.quorum();
                    const n1 = try h.build(gpa, .notarization, schemes, proposal_1, quorum);
                    const n2 = try h.build(gpa, .notarization, schemes, proposal_2, quorum);
                    try stack.mailbox.recovered(gpa, .{ .notarization = n1 });
                    const nullified = try vote_within(ctx, &stack, .nullify, 1, 5_000);
                    if (!nullified) return error.NoNullify;
                    // The rejected ancestor blocks view 3 before the application verifies it.
                    try stack.mailbox.recovered(gpa, .{ .notarization = n2 });
                    const proposal_3 = proposal(3, 2, "failed_ancestor_view_3");
                    relay(&net, leader_index, proposal_3, proposal_2.payload, 2);
                    try stack.mailbox.proposal(proposal_3);
                    try testing.expect(!try vote_within(ctx, &stack, .notarize, 3, 1_000));
                    try testing.expect(!stack.automaton.verification_requested(3));
                    // Nullifying the failed ancestor abandons the term: the voter reaches view 6.
                    const round_1: h.Round = .new(epoch, .new(1));
                    const nullification =
                        try h.build(gpa, .nullification, schemes, round_1, quorum);
                    try stack.mailbox.recovered(gpa, .{ .nullification = nullification });
                    try wait_past(ctx, &stack, 5);
                }
            }.body);
        }

        // commonware test_finalization_cancels_inflight_verification
        test "voter finalization cancels inflight verification" {
            try h.covers(.ed25519);
            try run(10, struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 4, "finalization_cancels_verify");
                    defer net.deinit();
                    const leader_index = try leader(gpa, .default(), 4, 1);
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 5_000,
                        .certification_timeout_ms = 5_000,
                        .local_index = (leader_index + 1) % 4,
                        .verify_latency_ms = 1_000,
                    });
                    defer stack.stop();
                    const first = try stack.next_update(ctx, 1_000);
                    try testing.expectEqual(@as(u64, 1), first.current.get());
                    try testing.expectEqual(@as(u32, @intCast(leader_index)), first.leader.get());
                    const target = proposal(1, 0, "verification_overtaken_by_finalization");
                    relay(&net, leader_index, target, h.genesis(epoch), 7);
                    try stack.mailbox.proposal(target);
                    try ctx.sleep(.fromMilliseconds(10));
                    // Verification is in flight before the finalization arrives.
                    try testing.expect(stack.automaton.verification_requested(1));
                    const schemes = net.schemes();
                    const finalization =
                        try h.build(gpa, .finalization, schemes, target, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .finalization = finalization });
                    try wait_past(ctx, &stack, 1);
                    // The now-canceled verification never leads to a notarize vote.
                    try ctx.sleep(.fromSeconds(2));
                    try testing.expectEqual(@as(u64, 0), stack.reporter.votes(.new(1)).notarize);
                }
            }.body);
        }

        // commonware test_conflicting_notarization_cancels_inflight_verification
        test "voter conflicting notarization cancels inflight verification" {
            try h.covers(.ed25519);
            try run(10, struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 4, "conflicting_notarization_cancels_verify");
                    defer net.deinit();
                    const leader_index = try leader(gpa, .default(), 4, 1);
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 5_000,
                        .certification_timeout_ms = 5_000,
                        .local_index = (leader_index + 1) % 4,
                        // B's certification never completes, so the view does not advance.
                        .certifier = .pending,
                    });
                    defer stack.stop();
                    stack.automaton.hold_verifications = true;
                    const first = try stack.next_update(ctx, 1_000);
                    try testing.expectEqual(@as(u64, 1), first.current.get());
                    // The leader's proposal A is sent for verification.
                    try stack.mailbox.proposal(proposal(1, 0, "proposal_a"));
                    try ctx.sleep(.fromMilliseconds(10));
                    try testing.expect(stack.automaton.verification_requested(1));
                    try testing.expect(!stack.automaton.verification_dropped(1));
                    // A notarization of the conflicting proposal B drops A's verification.
                    const b = proposal(1, 0, "proposal_b");
                    const schemes = net.schemes();
                    const notarization =
                        try h.build(gpa, .notarization, schemes, b, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
                    try ctx.sleep(.fromMilliseconds(100));
                    try testing.expect(stack.automaton.verification_dropped(1));
                }
            }.body);
        }

        /// A validator leading none of views 1 to 3 among 4.
        fn follower_of_first_views(gpa: std.mem.Allocator) !usize {
            var leads: [4]bool = @splat(false);
            for (1..4) |view| leads[try leader(gpa, .default(), 4, view)] = true;
            for (leads, 0..) |led, index| {
                if (!led) return index;
            }
            return error.NoFollower;
        }

        /// Waits for our finalize vote on `expected`, failing on any notarize of its view.
        fn expect_finalize_only(ctx: Ctx, stack: *h.VoterStack, expected: h.Proposal) !void {
            const view = expected.round.view.get();
            // Bounded by the per-message wait.
            while (true) {
                const message = (try stack.next_batcher(ctx, 5_000)) orelse
                    return error.NoFinalize;
                if (message != .constructed) continue;
                switch (message.constructed) {
                    .notarize => |vote| if (vote.view().get() == view) return error.Notarized,
                    .finalize => |vote| {
                        if (vote.view().get() != view) continue;
                        try testing.expect(vote.proposal.eql(expected));
                        return;
                    },
                    .nullify => {},
                }
            }
        }

        // commonware test_certification_precludes_verification
        test "voter certification precludes verification" {
            try h.covers(.ed25519);
            try run(10, struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 4, "certification_precludes_verification");
                    defer net.deinit();
                    const local = try follower_of_first_views(gpa);
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 5_000,
                        .certification_timeout_ms = 5_000,
                        .local_index = local,
                    });
                    defer stack.stop();
                    stack.automaton.hold = .{ .view = 2 };
                    const first = try stack.next_update(ctx, 1_000);
                    try testing.expectEqual(@as(u64, 1), first.current.get());
                    // View 2's notarization arrives first, and its certification is requested.
                    // Its payload is relayed, so verifying it would succeed.
                    const proposal_1 = proposal(1, 0, "proposal_1");
                    const proposal_2 = proposal(2, 1, "proposal_2");
                    const leader_2 = try leader(gpa, .default(), 4, 2);
                    relay(&net, leader_2, proposal_2, proposal_1.payload, 0);
                    const schemes = net.schemes();
                    const quorum = net.quorum();
                    const n2 =
                        try h.build_peers(gpa, .notarization, schemes, local, proposal_2, quorum);
                    try stack.mailbox.recovered(gpa, .{ .notarization = n2 });
                    const certified_2 = try stack.automaton.take_certification(ctx, 2);
                    try testing.expect(!stack.automaton.verification_requested(1));
                    try testing.expect(!stack.automaton.verification_requested(2));
                    // View 1 notarizes and certifies, so we enter view 2.
                    const n1 =
                        try h.build_peers(gpa, .notarization, schemes, local, proposal_1, quorum);
                    try stack.mailbox.recovered(gpa, .{ .notarization = n1 });
                    // Bounded: views only advance, and each wait is limited.
                    while ((try stack.next_update(ctx, 5_000)).current.get() != 2) {}
                    // View 1 was verifiable before it certified; view 2 only after its
                    // certification was requested, so it is never verified.
                    try ctx.sleep(.fromMilliseconds(100));
                    try testing.expect(stack.automaton.verification_requested(1));
                    try testing.expect(!stack.automaton.verification_requested(2));
                    try testing.expect(!certified_2.is_closed());
                    // Certification alone carries view 2 to a finalize vote.
                    stack.automaton.answer_certification(certified_2, true);
                    try expect_finalize_only(ctx, &stack, proposal_2);
                    try testing.expect(!stack.automaton.verification_requested(2));
                }
            }.body);
        }

        /// Waits for view `view`'s certification verdict, failing on our nullify there.
        fn expect_certified_not_nullified(ctx: Ctx, stack: *h.VoterStack, view: u64) !void {
            var waited_ms: u64 = 0;
            // Bounded by 3 s of simulated time.
            while (waited_ms < 3_000) : (waited_ms += 1) {
                if (stack.batcher.try_recv()) |message| {
                    if (message == .constructed and message.constructed == .nullify and
                        message.constructed.view().get() == view) return error.Nullified;
                } else |_| {}
                if (stack.resolver.try_recv()) |message| {
                    defer message.discard();
                    if (message == .certified and
                        message.certified.notarization.view().get() == view)
                    {
                        try testing.expect(message.certified.success);
                        return;
                    }
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
            return error.NotCertified;
        }

        // commonware test_stale_same_parent_verification_failure_does_not_nullify_replacement
        test "voter stale same parent verification failure does not nullify replacement" {
            try h.covers(.ed25519);
            try run(10, struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "stale-same-parent-verification");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 5_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = 60 * 60 * 1000,
                        .verify_latency_ms = 100,
                        .certify_latency_ms = 500,
                        .fail_verification = true,
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    const parent = try h.advance_to_view(&stack, ctx, &net, 5);
                    // Proposal A goes to verification, which will fail.
                    const a = proposal(5, 4, "proposal-a");
                    relay(&net, 1, a, parent, 1);
                    try stack.mailbox.proposal(a);
                    try ctx.sleep(.fromMilliseconds(10));
                    try testing.expect(stack.automaton.verification_requested(5));
                    // B, over the same parent, is notarized before A's failure lands: the stale
                    // failure must not nullify the view B certifies.
                    const b = proposal(5, 4, "proposal-b");
                    const notarization =
                        try h.build(gpa, .notarization, net.schemes(), b, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
                    try expect_certified_not_nullified(ctx, &stack, 5);
                }
            }.body);
        }
    };
}
