//! commonware `simplex/actors/voter/mod.rs` leader- and certification-timeout tests: a hung
//! certification still nullifies on the view timeout, a verified or recovered proposal clears
//! the leader timeout so only the certification timeout nullifies, a view entered after a
//! nullification gets a fresh leader timeout, and the first view progresses without one.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;
        const target = 3;
        const retry_ms = 60 * 60 * 1_000;

        fn run(comptime body: fn (Ctx) anyerror!void, timeout_s: u64) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = timeout_s * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        const Watch = struct {
            /// The vote kind and view that ends the wait.
            want: ?Want = null,
            /// Vote kinds and views that fail the wait.
            forbid: []const Want = &.{},
            /// Ends the wait on an update at or past this view.
            update_at_least: ?u64 = null,
        };
        const Want = struct { kind: std.meta.Tag(h.Vote), view: u64 };
        const Seen = enum { want, update, quiet };

        /// Drains batcher messages for up to `limit_ms` of simulated time: returns on the
        /// wanted vote or update, fails on the forbidden vote, and reports quiet otherwise.
        fn watch(ctx: Ctx, stack: *h.VoterStack, w: Watch, limit_ms: u64) !Seen {
            var waited: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited <= limit_ms) : (waited += 1) {
                if (stack.batcher.try_recv()) |message| {
                    switch (message) {
                        .update => |update| if (w.update_at_least) |view| {
                            if (update.current.get() >= view) return .update;
                        },
                        .constructed => |vote| {
                            const view = vote.view().get();
                            for (w.forbid) |f| if (vote == f.kind and view == f.view) {
                                return error.ForbiddenVote;
                            };
                            if (w.want) |f| if (vote == f.kind and view == f.view) return .want;
                        },
                    }
                    continue;
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
            return .quiet;
        }

        /// Advances to follower view 3 and relays and delivers validator 1's proposal there,
        /// then waits up to 2 s for our notarize vote.
        fn notarize_target(
            ctx: Ctx,
            net: *h.Network,
            stack: *h.VoterStack,
            label: []const u8,
        ) !h.Proposal {
            _ = try stack.next_update(ctx, 5_000);
            const parent = try h.advance_to_view(stack, ctx, net, target);
            const proposal = h.proposal_at(epoch, target, label);
            h.relay_contents(net, 1, proposal.payload, proposal.round, parent, 0);
            try stack.mailbox.proposal(proposal);
            const notarized = try watch(ctx, stack, .{
                .want = .{ .kind = .notarize, .view = target },
            }, 2_000);
            try testing.expectEqual(.want, notarized);
            return proposal;
        }

        // commonware test_pending_certification_nullifies_on_timeout: a certification that
        // never answers still lets the view timeout nullify, and the nullify alone does not
        // advance the view.
        test "voter pending certification nullifies on timeout" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "pending_cert_nullify");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 3_000,
                        .certification_timeout_ms = 4_000,
                        .timeout_retry_ms = retry_ms,
                        .certifier = .pending,
                    });
                    defer stack.stop();
                    const proposal = try notarize_target(ctx, &net, &stack, "test_proposal");
                    const notarization =
                        try h.build(gpa, .notarization, net.schemes(), proposal, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
                    const nullified = try watch(ctx, &stack, .{
                        .want = .{ .kind = .nullify, .view = target },
                    }, 8_000);
                    try testing.expectEqual(.want, nullified);
                    // Without a nullification or finalization the view does not advance.
                    const advanced = try watch(ctx, &stack, .{
                        .update_at_least = target + 1,
                    }, 2_000);
                    try testing.expectEqual(.quiet, advanced);
                }
            }.body, 10);
        }

        // commonware test_proposal_clears_leader_timeout_before_certification_timeout: once
        // the proposal is verified, the 1 s leader timeout no longer fires; only the 5 s
        // certification timeout nullifies.
        test "voter proposal clears leader timeout before certification timeout" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "proposal_clears_leader_timeout");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 1_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = retry_ms,
                    });
                    defer stack.stop();
                    _ = try notarize_target(ctx, &net, &stack, "proposal_clears_leader_timeout");
                    try expect_late_nullify(ctx, &stack);
                }
            }.body, 15);
        }

        /// No nullify of the target view for 2 s, then one within 6 s.
        fn expect_late_nullify(ctx: Ctx, stack: *h.VoterStack) !void {
            const nullify: Want = .{ .kind = .nullify, .view = target };
            const early = try watch(ctx, stack, .{ .forbid = &.{nullify} }, 2_000);
            try testing.expectEqual(.quiet, early);
            try testing.expectEqual(.want, try watch(ctx, stack, .{ .want = nullify }, 6_000));
        }

        // commonware test_recovered_proposal_clears_leader_timeout_before_certification_timeout:
        // a proposal recovered from a notarization clears the leader timeout without a local
        // notarize vote, so only the certification timeout nullifies.
        test "voter recovered proposal clears leader timeout before certification timeout" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "recovered_proposal_clears_leader_timeout");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 1_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = retry_ms,
                        .certifier = .pending,
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 5_000);
                    _ = try h.advance_to_view(&stack, ctx, &net, target);
                    const proposal =
                        h.proposal_at(epoch, target, "recovered_proposal_clears_leader_timeout");
                    const notarization =
                        try h.build(gpa, .notarization, net.schemes(), proposal, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
                    const notarize: Want = .{ .kind = .notarize, .view = target };
                    const nullify: Want = .{ .kind = .nullify, .view = target };
                    // Neither a notarize from the certificate nor an early nullify.
                    try testing.expectEqual(.quiet, try watch(ctx, &stack, .{
                        .forbid = &.{ notarize, nullify },
                    }, 2_000));
                    try testing.expectEqual(.want, try watch(ctx, &stack, .{
                        .want = nullify,
                        .forbid = &.{notarize},
                    }, 6_000));
                }
            }.body, 15);
        }

        // commonware test_next_view_gets_fresh_timeout_after_prior_view_nullifies: view 1
        // times out and nullifies; after its nullification, view 2 gets its own leader timeout
        // instead of nullifying on entry.
        test "voter next view gets fresh timeout after prior view nullifies" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    const namespace = "next_view_gets_fresh_timeout_after_prior_view_nullifies";
                    try net.start(ctx, 5, namespace);
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 1_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = retry_ms,
                    });
                    defer stack.stop();
                    try testing.expectEqual(1, (try stack.next_update(ctx, 5_000)).current.get());
                    const nullify_1: Want = .{ .kind = .nullify, .view = 1 };
                    try testing.expectEqual(.want, try watch(ctx, &stack, .{
                        .want = nullify_1,
                    }, 2_000));
                    const nullification = try h.build(
                        gpa,
                        .nullification,
                        net.schemes(),
                        .new(epoch, .new(1)),
                        net.quorum(),
                    );
                    try stack.mailbox.recovered(gpa, .{ .nullification = nullification });
                    const nullify_2: Want = .{ .kind = .nullify, .view = 2 };
                    try testing.expectEqual(.update, try watch(ctx, &stack, .{
                        .forbid = &.{nullify_2},
                        .update_at_least = 2,
                    }, 2_000));
                    try testing.expectEqual(.quiet, try watch(ctx, &stack, .{
                        .forbid = &.{nullify_2},
                    }, 500));
                }
            }.body, 15);
        }

        // commonware test_first_view_progress_without_timeout: with prompt certificates the
        // first view notarizes, finalizes before entering view 2, and never nullifies.
        test "voter first view progress without timeout" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "first_view_progress_without_timeout");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 1_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = retry_ms,
                    });
                    defer stack.stop();
                    try stack.expect_update(ctx, 1, 0);
                    const first: h.Round = .new(epoch, .new(1));
                    const input = if (h.Elector.Input == void) {} else null;
                    const leader = stack.elector.elect(first, input).get();
                    const payload = h.Sha256.hash(&.{"first_view_progress_without_timeout"});
                    const proposal: h.Proposal = .init(first, .zero(), payload);
                    h.relay_contents(&net, leader, payload, first, h.genesis(epoch), 0);
                    try stack.mailbox.proposal(proposal);
                    const nullify: Want = .{ .kind = .nullify, .view = 1 };
                    try testing.expectEqual(.want, try watch(ctx, &stack, .{
                        .want = .{ .kind = .notarize, .view = 1 },
                        .forbid = &.{nullify},
                    }, 2_000));
                    const notarization =
                        try h.build(gpa, .notarization, net.schemes(), proposal, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
                    try expect_finalize_then_view_2(ctx, &stack);
                    // Let the reporter ingest late events.
                    try ctx.sleep(.fromMilliseconds(50));
                    try testing.expectEqual(0, stack.reporter.votes(.new(1)).nullify);
                    try testing.expect(!stack.reporter.nullified(.new(1)));
                }
            }.body, 15);
        }

        /// Our finalize of view 1 comes before view 2, and both within 3 s, with no nullify.
        fn expect_finalize_then_view_2(ctx: Ctx, stack: *h.VoterStack) !void {
            const nullify: Want = .{ .kind = .nullify, .view = 1 };
            const finalized = try watch(ctx, stack, .{
                .want = .{ .kind = .finalize, .view = 1 },
                .forbid = &.{nullify},
                .update_at_least = 2,
            }, 3_000);
            // An update to view 2 first means the view advanced before finalize.
            try testing.expectEqual(.want, finalized);
            const advanced = try watch(ctx, stack, .{
                .forbid = &.{nullify},
                .update_at_least = 2,
            }, 3_000);
            try testing.expectEqual(.update, advanced);
        }
    };
}
