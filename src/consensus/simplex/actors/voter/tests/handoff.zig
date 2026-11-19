//! commonware `simplex/actors/voter/mod.rs` pipelined-handoff tests: the incoming term's
//! leader builds and votes on its term-start proposal before the outgoing term's last view
//! certifies.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = 20 * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        /// Relays and hands the voter `sender`'s proposal at `view` over `view - 1`,
        /// whose payload is `parent`; returns its payload.
        fn feed(
            net: *h.Network,
            stack: *h.VoterStack,
            sender: usize,
            view: u64,
            parent: h.Digest,
            label: []const u8,
        ) !h.Digest {
            const round: h.Round = .new(epoch, .new(view));
            const payload = h.Sha256.hash(&.{label});
            h.relay_contents(net, sender, payload, round, parent, view - 1);
            try stack.mailbox.proposal(.init(round, .new(view - 1), payload));
            return payload;
        }

        // commonware test_pipelined_handoff_proposes_across_term_boundary: with two-view
        // terms, the leader of term 2 notarizes its view-3 handoff proposal, built on view 2,
        // after notarizing view 2 and before any certificate forms.
        test "voter pipelined handoff proposes across term boundary" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "pipelined_handoff_proposes_across_term_boundary");
                    defer net.deinit();
                    const elector = h.term_elector(2, 30_000, 1);
                    const outgoing = try h.leader_of(gpa, elector, 1);
                    const local = try h.leader_of(gpa, elector, 3);
                    try testing.expect(outgoing != local);
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        // No certificate is delivered, so a view-3 notarize needs a handoff.
                        .leader_timeout_ms = 10_000,
                        .certification_timeout_ms = 10_000,
                        .timeout_retry_ms = 30_000,
                        .local_index = local,
                        .propose_latency_ms = 10.0,
                        .handoff = .vote,
                        .elector = elector,
                    });
                    defer stack.stop();
                    const p1 = try feed(
                        &net,
                        &stack,
                        outgoing,
                        1,
                        h.genesis(epoch),
                        "pipelined_handoff_view_1",
                    );
                    _ = try feed(&net, &stack, outgoing, 2, p1, "pipelined_handoff_view_2");
                    var saw_2 = false;
                    // Bounded by the 8 s wait per message.
                    while (true) {
                        const next = try stack.next_batcher(ctx, 8_000);
                        const message = next orelse return error.NoHandoffNotarize;
                        if (message != .constructed or message.constructed != .notarize) continue;
                        const notarize = message.constructed.notarize;
                        if (notarize.view().get() == 2) saw_2 = true;
                        if (notarize.view().get() != 3) continue;
                        try testing.expect(saw_2);
                        try testing.expectEqual(2, notarize.proposal.parent.get());
                        break;
                    }
                    try h.expect_handoff_metrics(ctx, &.{
                        .{ "RelayedBeforeCertification", 1 },
                        .{ "VotedBeforeCertification", 1 },
                        .{ "CandidateReturned", 1 },
                        .{ "Requested", 1 },
                    }, &.{});
                }
            }.body);
        }

        // commonware test_pipelined_handoff_certifies_parent_before_child: a lone validator
        // notarizes its term-start child (view 2) before the parent (view 1) certifies, but
        // the application sees the parent's certification request first.
        test "voter pipelined handoff certifies parent before child" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 1, "pipelined_handoff_certifies_parent_before_child");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 10_000,
                        .certification_timeout_ms = 10_000,
                        .timeout_retry_ms = 30_000,
                        .hold_certifications = .all,
                        .handoff = .vote,
                    });
                    defer stack.stop();
                    var parent: ?h.Proposal = null;
                    var child: ?h.Proposal = null;
                    // Bounded by the 5 s wait per message.
                    while (parent == null or child == null) {
                        const next = try stack.next_batcher(ctx, 5_000);
                        const message = next orelse return error.NoNotarize;
                        if (message != .constructed or message.constructed != .notarize) continue;
                        const proposal = message.constructed.notarize.proposal;
                        switch (proposal.view().get()) {
                            1 => parent = proposal,
                            2 => child = proposal,
                            else => {},
                        }
                    }
                    try testing.expectEqual(1, child.?.parent.get());
                    for ([_]h.Proposal{ child.?, parent.? }) |subject| {
                        const certificate = try h.build(
                            gpa,
                            .notarization,
                            net.schemes(),
                            subject,
                            1,
                        );
                        try stack.mailbox.recovered(gpa, .{ .notarization = certificate });
                    }
                    const automaton = &stack.automaton;
                    const parent_slot = try automaton.take_certification(ctx, 1);
                    // The child's certification must not run ahead of its parent's.
                    try testing.expect(!automaton.certification_requested(2));
                    automaton.answer_certification(parent_slot, true);
                    const child_slot = try automaton.take_certification(ctx, 2);
                    automaton.answer_certification(child_slot, true);
                    // Bounded by the 5 s wait per message.
                    while (true) {
                        const next = try stack.next_batcher(ctx, 5_000);
                        const message = next orelse return error.NoFinalize;
                        if (message != .constructed or message.constructed != .finalize) continue;
                        if (message.constructed.view().get() == 2) break;
                    }
                    try testing.expect(stack.reporter.certified(.new(1)));
                    try testing.expect(stack.reporter.certified(.new(2)));
                }
            }.body);
        }
    };
}
