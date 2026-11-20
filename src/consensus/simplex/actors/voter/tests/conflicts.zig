//! commonware `simplex/actors/voter/mod.rs` conflict tests: a proposal and a certificate
//! for the same view that agree or disagree, and our own proposal against a peer's vote under
//! our identity. commonware runs each over six signing schemes, as `Tests(h)`
//! does over each fixture in `harness.fixtures`.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const harness = @import("harness.zig");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const Sha256 = h.Sha256;
        const epoch = h.default_epoch;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            try h.soak(10 * std.time.ns_per_s, body);
        }

        /// A proposal at `view` over `view - 1` with payload `hash(label)`.
        fn proposal(view: u64, label: []const u8) h.Proposal {
            return .init(.new(epoch, .new(view)), .new(view - 1), Sha256.hash(&.{label}));
        }

        fn notarization(ctx: Ctx, net: *const h.Network, subject: h.Proposal) !h.Notarization {
            return h.build(ctx.gpa(), .notarization, net.schemes(), subject, net.quorum());
        }

        /// Expects the next resolver update to be a notarization of `subject`.
        fn expect_notarization_update(ctx: Ctx, stack: *h.VoterStack, subject: h.Proposal) !void {
            const message = (try stack.next_resolver(ctx, 5_000)) orelse return error.TimedOut;
            defer message.discard();
            try testing.expect(message == .updated);
            const certificate = message.updated.certificate;
            try testing.expect(certificate == .notarization);
            try testing.expect(certificate.notarization.proposal.eql(subject));
        }

        /// Waits until the reporter's notarization at `expected`'s view equals `expected`.
        fn expect_reported(ctx: Ctx, stack: *h.VoterStack, expected: *const h.Notarization) !void {
            const gpa = ctx.gpa();
            const want = try codec.encode(h.Notarization, gpa, expected.*);
            defer gpa.free(want);
            var waited: u64 = 0;
            while (waited < 500) : (waited += 1) {
                if (try stack.reporter.notarization(expected.view())) |reported| {
                    var owned = reported;
                    defer owned.deinit(gpa);
                    const got = try codec.encode(h.Notarization, gpa, owned);
                    defer gpa.free(got);
                    if (std.mem.eql(u8, want, got)) return;
                }
                try ctx.sleep(.fromMilliseconds(10));
            }
            return error.TimedOut;
        }

        /// Waits for our finalize vote, which must be for `subject`.
        fn expect_finalize(ctx: Ctx, stack: *h.VoterStack, subject: h.Proposal) !void {
            // Bounded by the per-message wait.
            while (true) {
                const message = (try stack.next_batcher(ctx, 5_000)) orelse return error.TimedOut;
                if (message != .constructed or message.constructed != .finalize) continue;
                try testing.expect(message.constructed.finalize.proposal.eql(subject));
                return;
            }
        }

        // commonware certificate_conflicts_proposal: a notarization for B after proposal A at the
        // same view is accepted and recorded, and the voter does not finalize the conflict.
        test "voter certificate conflicts proposal" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "certificate_conflicts_proposal_test");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{});
                    defer stack.stop();
                    try stack.expect_update(ctx, 1, 0);
                    try stack.mailbox.proposal(proposal(2, "proposal_a"));
                    try ctx.sleep(.fromMilliseconds(10));
                    const proposal_b = proposal(2, "proposal_b");
                    var notarization_b = try notarization(ctx, &net, proposal_b);
                    defer notarization_b.deinit(gpa);
                    try stack.mailbox.recovered(
                        gpa,
                        .{ .notarization = try notarization_b.clone(gpa) },
                    );
                    try stack.expect_replayed(ctx);
                    try expect_notarization_update(ctx, &stack, proposal_b);
                    try expect_reported(ctx, &stack, &notarization_b);
                    // No finalize vote on the conflict.
                    try ctx.sleep(.fromMilliseconds(100));
                    // Bounded by the batcher mailbox's contents.
                    while (stack.batcher.try_recv()) |message| {
                        if (message == .constructed) try testing.expect(
                            message.constructed != .finalize,
                        );
                    } else |_| {}
                }
            }.body);
        }

        // commonware proposal_conflicts_certificate: after a notarization for A, the voter
        // finalizes
        // A, and a later proposal B for the same view changes nothing.
        test "voter proposal conflicts certificate" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "proposal_conflicts_certificate_test");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{});
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 5_000);
                    const proposal_a = proposal(2, "proposal_a");
                    var notarization_a = try notarization(ctx, &net, proposal_a);
                    defer notarization_a.deinit(gpa);
                    try stack.mailbox.recovered(
                        gpa,
                        .{ .notarization = try notarization_a.clone(gpa) },
                    );
                    try stack.expect_replayed(ctx);
                    try expect_notarization_update(ctx, &stack, proposal_a);
                    try expect_reported(ctx, &stack, &notarization_a);
                    try expect_finalize(ctx, &stack, proposal_a);
                    try stack.mailbox.proposal(proposal(2, "proposal_b"));
                    try ctx.sleep(.fromMilliseconds(100));
                }
            }.body);
        }

        // commonware certificate_verifies_proposal: while the application's verification of a
        // proposal is still pending, a notarization of the same proposal verifies it, so the voter
        // finalizes it.
        test "voter certificate verifies proposal" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "certificate_conflicts_proposal_test");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .partition = "voter_certificate_verifies_proposal_test",
                        .verify_latency_ms = 100_000.0, // Very slow verification.
                        .batcher_capacity = 8,
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 5_000);
                    const same = proposal(2, "same_proposal");
                    try stack.mailbox.proposal(same);
                    try ctx.sleep(.fromMilliseconds(10));
                    var certificate = try notarization(ctx, &net, same);
                    defer certificate.deinit(gpa);
                    try stack.mailbox.recovered(
                        gpa,
                        .{ .notarization = try certificate.clone(gpa) },
                    );
                    try stack.expect_replayed(ctx);
                    try expect_notarization_update(ctx, &stack, same);
                    try expect_reported(ctx, &stack, &certificate);
                    try expect_finalize(ctx, &stack, same);
                }
            }.body);
        }

        // commonware drop_our_proposal_on_conflict: a peer sharing our identity notarizes proposal
        // A while our automaton is still building B; our B is dropped, and after A is notarized the
        // voter finalizes A.
        test "voter drop our proposal on conflict" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "drop_our_proposal_on_conflict_test");
                    defer net.deinit();
                    // Host the voter on the leader of view 2.
                    const view2: h.Round = .new(epoch, .new(2));
                    const leader = try h.leader_of(gpa, .default(), view2.view.get());
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .local_index = leader,
                        .partition = "voter_leader",
                        .propose_latency_ms = 50.0, // Lets the peer's vote arrive first.
                        .batcher_capacity = 8,
                    });
                    defer stack.stop();
                    try stack.expect_update(ctx, 1, 0);
                    const view1 = proposal(1, "view1_payload");
                    const finalized = try h.build(
                        gpa,
                        .finalization,
                        net.schemes(),
                        view1,
                        net.quorum(),
                    );
                    try stack.mailbox.recovered(gpa, .{ .finalization = finalized });
                    try stack.expect_update(ctx, 2, 1);
                    try ctx.sleep(.fromMilliseconds(5));
                    // Our identity's conflicting proposal arrives before our automaton answers.
                    const conflicting = proposal(2, "leader_proposal");
                    try stack.mailbox.proposal(conflicting);
                    // Bounded by the batcher mailbox's contents.
                    while (stack.batcher.try_recv()) |message| {
                        try testing.expect(
                            message == .constructed and message.constructed == .notarize,
                        );
                        try testing.expect(message.constructed.notarize.proposal.eql(conflicting));
                    } else |_| {}
                    try ctx.sleep(.fromMilliseconds(100));
                    const certificate = try notarization(ctx, &net, conflicting);
                    try stack.mailbox.recovered(gpa, .{ .notarization = certificate });
                    // The voter dropped its own proposal, so it finalizes the conflicting one.
                    try expect_finalize(ctx, &stack, conflicting);
                }
            }.body);
        }
    };
}
