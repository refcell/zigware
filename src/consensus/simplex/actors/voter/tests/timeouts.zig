//! commonware `simplex/actors/voter/mod.rs` timeout tests: nullification broadcasts and
//! retries, stall timeouts, and finalizing again after a term heals.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const harness = @import("harness.zig");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            try h.soak(10 * std.time.ns_per_s, body);
        }

        /// Waits for our vote of `kind` at `view`, skipping other batcher messages.
        fn wait_vote(ctx: Ctx, stack: *h.VoterStack, comptime kind: anytype, view: u64) !void {
            // Bounded by the per-message wait.
            while (true) {
                const message = (try stack.next_batcher(ctx, 5_000)) orelse return error.TimedOut;
                if (message != .constructed or message.constructed != kind) continue;
                if (message.constructed.view().get() == view) return;
            }
        }

        /// Waits for the batcher update announcing `view`.
        fn wait_view(ctx: Ctx, stack: *h.VoterStack, view: u64) !void {
            // Bounded: views only advance, and each wait is limited.
            while (true) {
                const update = try stack.next_update(ctx, 5_000);
                if (update.current.get() == view) return;
            }
        }

        /// Expects the observer's next certificate to encode exactly as `expected`.
        fn expect_broadcast(
            ctx: Ctx,
            net: *const h.Network,
            observer: *h.Observer,
            expected: h.Certificate,
        ) !void {
            const gpa = ctx.gpa();
            var certificate = try observer.next_certificate(gpa, net);
            defer certificate.deinit(gpa);
            const want = try codec.encode(h.Certificate, gpa, expected);
            defer gpa.free(want);
            const got = try codec.encode(h.Certificate, gpa, certificate);
            defer gpa.free(got);
            try testing.expectEqualSlices(u8, want, got);
        }

        // commonware test_nullification_notification_omits_floor_but_retry_broadcasts_entry: a
        // recovered nullification is broadcast alone (not with the finalized floor before it), and
        // a later timeout's retry rebroadcasts the nullification that entered the view.
        test "voter nullification notification omits floor but retry broadcasts entry" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "nullification_floor_broadcast");
                    defer net.deinit();
                    var observer: h.Observer = undefined;
                    try observer.start(&net, 1, 1);
                    defer observer.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(
                        ctx,
                        &net,
                        .{ .leader_timeout_ms = 5_000, .timeout_retry_ms = 100 },
                    );
                    defer stack.stop();
                    try stack.expect_update(ctx, 1, 0);
                    _ = try h.advance_to_view(&stack, ctx, &net, 2);
                    try wait_vote(ctx, &stack, .notarize, 2);
                    var floor = try observer.next_certificate(gpa, &net);
                    defer floor.deinit(gpa);
                    try testing.expect(floor == .finalization and floor.view().get() == 1);
                    const round: h.Round = .new(epoch, .new(2));
                    const quorum = net.quorum();
                    var nullification = try h.build(
                        gpa,
                        .nullification,
                        net.schemes(),
                        round,
                        quorum,
                    );
                    defer nullification.deinit(gpa);
                    try stack.mailbox.recovered(
                        gpa,
                        .{ .nullification = try nullification.clone(gpa) },
                    );
                    try expect_broadcast(ctx, &net, &observer, .{ .nullification = nullification });
                    try testing.expect(!try observer.any_within(ctx, 10));
                    try wait_view(ctx, &stack, 3);
                    try stack.mailbox.timeout(.new(epoch, .new(3)), .inactivity);
                    try wait_vote(ctx, &stack, .nullify, 3);
                    try expect_broadcast(ctx, &net, &observer, .{ .nullification = nullification });
                }
            }.body);
        }

        // commonware stall_timeout_nullifies_current_view: with two-view terms and a 5 s stall
        // timeout, the voter that enters view 2 late (certification takes 3.5 s) nullifies it on
        // the term's stall deadline, before its own 3 s leader timeout could fire.
        test "voter stall timeout nullifies current view" {
            try h.covers(.schemes_round_robin);
            try run_long(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "stall_timeout_nullifies_current_view");
                    defer net.deinit();
                    const elector = h.term_elector(2, 5_000, 0);
                    const leader = try h.leader_of(gpa, elector, 1);
                    const first: h.Round = .new(epoch, .new(1));
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 3_000,
                        .certification_timeout_ms = 4_000,
                        .timeout_retry_ms = 2_000,
                        .certify_latency_ms = 3_500.0,
                        .elector = elector,
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 5_000);
                    const payload = h.Sha256.hash(&.{"same_term_timeout_view_1"});
                    const proposal_1: h.Proposal = .init(first, .zero(), payload);
                    h.relay_contents(&net, leader, payload, first, h.genesis(epoch), 0);
                    try stack.mailbox.proposal(proposal_1);
                    const quorum = net.quorum();
                    const certificate = try h.build(
                        gpa,
                        .notarization,
                        net.schemes(),
                        proposal_1,
                        quorum,
                    );
                    try stack.mailbox.recovered(gpa, .{ .notarization = certificate });
                    try wait_view(ctx, &stack, 2);
                    // The very next batcher message must be the nullify for view 2, within 2 s.
                    const next = try stack.next_batcher(ctx, 2_000);
                    const message = next orelse return error.NoNullify;
                    try testing.expect(message == .constructed and message.constructed == .nullify);
                    try testing.expectEqual(2, message.constructed.view().get());
                }
            }.body);
        }

        fn run_long(comptime body: fn (Ctx) anyerror!void) !void {
            try h.soak(30 * std.time.ns_per_s, body);
        }

        // commonware finalize_resumes_after_same_term_heal: a leader-timeout nullify at view 1
        // blocks finalize votes for the rest of its three-view term, until view 1's finalization
        // heals the term; view 3, certified after the heal, gets our finalize vote.
        test "voter finalize resumes after same term heal" {
            try h.covers(.schemes_round_robin);
            try run_long(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "finalize_resumes_after_same_term_heal");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 1_000,
                        .certification_timeout_ms = 2_000,
                        .timeout_retry_ms = 10_000,
                        .certify_latency_ms = 0.0,
                        .elector = h.term_elector(3, 20_000, 0),
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 5_000);
                    // The term's leader never proposes, so we nullify view 1 on the leader timeout.
                    try wait_vote(ctx, &stack, .nullify, 1);
                    const quorum = net.quorum();
                    const proposal_1 = proposal(1, 0, "finalize_resume_view_1");
                    const proposal_2 = proposal(2, 1, "finalize_resume_view_2");
                    for ([_]h.Proposal{ proposal_1, proposal_2 }) |subject| {
                        const notarized = try h.build(
                            gpa,
                            .notarization,
                            net.schemes(),
                            subject,
                            quorum,
                        );
                        try stack.mailbox.recovered(gpa, .{ .notarization = notarized });
                    }
                    // Bounded: views only advance, and each wait is limited.
                    while (true) {
                        const next = try stack.next_batcher(ctx, 5_000);
                        const message = next orelse return error.TimedOut;
                        if (message == .constructed) try testing.expect(
                            message.constructed != .finalize,
                        );
                        if (message == .update and message.update.current.get() == 3) break;
                    }
                    const finalized = try h.build(
                        gpa,
                        .finalization,
                        net.schemes(),
                        proposal_1,
                        quorum,
                    );
                    try stack.mailbox.recovered(gpa, .{ .finalization = finalized });
                    const proposal_3 = proposal(3, 2, "finalize_resume_view_3");
                    const notarized = try h.build(
                        gpa,
                        .notarization,
                        net.schemes(),
                        proposal_3,
                        quorum,
                    );
                    try stack.mailbox.recovered(gpa, .{ .notarization = notarized });
                    // Bounded by the 5 s wait per message.
                    while (true) {
                        const next = try stack.next_batcher(ctx, 5_000);
                        const message = next orelse return error.TimedOut;
                        if (message != .constructed or message.constructed != .finalize) continue;
                        try testing.expectEqual(3, message.constructed.view().get());
                        return;
                    }
                }
            }.body);
        }

        /// A proposal at `view` over `parent` with payload `hash(label)`.
        fn proposal(view: u64, parent: u64, label: []const u8) h.Proposal {
            return .init(.new(epoch, .new(view)), .new(parent), h.Sha256.hash(&.{label}));
        }
    };
}
