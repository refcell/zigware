//! commonware `simplex/actors/voter/mod.rs` `displaced_ancestor_cancels_before_timeout`: the
//! incoming leader's handoff build rests on an outgoing chain A1 to A3 it verified and voted
//! for. A conflicting notarization for B1 at the chain's first view invalidates that
//! ancestry, so the voter cancels the build before any timeout, live or after a restart
//! replays its votes.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;
        const n = 4;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = 5 * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        fn options(local: usize, scope: []const u8) h.Options {
            return .{
                .local_index = local,
                .leader_timeout_ms = 10_000,
                .certification_timeout_ms = 20_000,
                .timeout_retry_ms = 30_000,
                .handoff = .stage,
                .hold_handoffs = true,
                .hold_certifications = .{ .view = 1 },
                .elector = h.term_elector(3, 300_000, 2),
                .scope = scope,
            };
        }

        /// Relays and hands the voter the outgoing leader's A chain at views 1 to 3, and
        /// waits for our notarize vote on each, without any certificate. Returns A3's payload
        /// and writes A1's to `first`.
        fn vote_chain(stack: *h.VoterStack, net: *h.Network, ctx: Ctx, first: *h.Digest) !h.Digest {
            const outgoing = 2;
            var parent = h.genesis(epoch);
            for (1..4) |view| {
                const round: h.Round = .new(epoch, .new(view));
                var buffer: [128]u8 = undefined;
                const contents = h.mock_contents(&buffer, round, parent, view);
                const payload = h.Sha256.hash(&.{contents});
                const proposal: h.Proposal = .init(round, .new(view - 1), payload);
                net.relay.broadcast(net.keys()[outgoing], .all, proposal.payload, contents);
                try stack.mailbox.proposal(proposal);
                // Bounded by the 5 s wait per message.
                while (true) {
                    const next = try stack.next_batcher(ctx, 5_000);
                    const message = next orelse return error.NoNotarize;
                    if (message == .update) {
                        try testing.expectEqual(1, message.update.current.get());
                        continue;
                    }
                    const vote = message.constructed;
                    // The voter must not time out before preparing the handoff.
                    if (vote == .nullify) return error.TimedOutBeforeHandoff;
                    if (vote != .notarize) continue;
                    try testing.expect(vote.notarize.proposal.eql(proposal));
                    try testing.expectEqual(3, vote.notarize.attestation.signer.get());
                    break;
                }
                if (view == 1) first.* = proposal.payload;
                parent = proposal.payload;
            }
            return parent;
        }

        /// Takes the view-4 handoff candidate and expects it to be the only request, built on
        /// A3.
        fn take_candidate(stack: *h.VoterStack, ctx: Ctx, tip: h.Digest) !*h.Automaton.HeldHandoff {
            const slot = try stack.automaton.take_handoff(ctx);
            try testing.expect(slot.candidate == .stage);
            try testing.expect(!slot.is_closed());
            try testing.expectEqual(1, stack.automaton.proposals_count);
            const request = stack.automaton.request_for(4, 0) orelse return error.NoRequest;
            try testing.expectEqual(3, request.parent[0].get());
            try testing.expectEqual(tip, request.parent[1]);
            return slot;
        }

        fn displaced_ancestor_cancels_before_timeout(ctx: Ctx, restart: bool) !void {
            const gpa = ctx.gpa();
            var net: h.Network = undefined;
            try net.start(ctx, n, "pipelined_handoff_displaced_ancestor");
            defer net.deinit();
            const elector = h.term_elector(3, 300_000, 2);
            try testing.expectEqual(2, try h.leader_among(gpa, elector, n, 1));
            const local = try h.leader_among(gpa, elector, n, 4);
            try testing.expectEqual(3, local);
            var stack: h.VoterStack = undefined;
            try stack.start(ctx, &net, options(local, "voter"));
            defer stack.stop();
            var a1: h.Digest = undefined;
            const tip = try vote_chain(&stack, &net, ctx, &a1);
            var slot = try take_candidate(&stack, ctx, tip);
            for (1..4) |view| try testing.expect(!stack.reporter.notarized(.new(view)));
            const scope = if (restart) "restarted" else "voter";
            if (restart) {
                try stack.replace(ctx, &net, options(local, scope));
                // Aborting the voter closed the old build's response.
                try testing.expect(slot.is_closed());
                slot = try take_candidate(&stack, ctx, tip);
            }
            // Only the outgoing leader equivocates: validators 0, 1, and 2 notarize B1, while
            // local 3 voted A1.
            const round: h.Round = .new(epoch, .new(1));
            var buffer: [128]u8 = undefined;
            const contents = h.mock_contents(&buffer, round, h.genesis(epoch), 4);
            const conflicting: h.Proposal = .init(round, .new(0), h.Sha256.hash(&.{contents}));
            try testing.expect(!conflicting.payload.eql(a1));
            const notarization = try h.build_peers(
                gpa,
                .notarization,
                net.schemes(),
                local,
                conflicting,
                net.quorum(),
            );
            net.relay.broadcast(net.keys()[2], .all, conflicting.payload, contents);
            try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
            const certified = try stack.automaton.take_certification(ctx, 1);
            // With B1's certification held, the build must already be canceled.
            try wait_closed(ctx, slot);
            try testing.expect(!stack.reporter.certified(.new(1)));
            try h.expect_counters_in(ctx, scope, "handoff_abandoned", "reason", &.{
                .{ "AncestryInvalidated", 1 },
            });
            stack.automaton.answer_certification(certified, true);
            // Bounded by the 5 s wait per message.
            while (true) {
                const next = try stack.next_batcher(ctx, 5_000);
                const message = next orelse return error.NoUpdate;
                if (message == .update and message.update.current.get() == 2) break;
                // B1's certification must not need a timeout.
                if (message == .constructed and message.constructed == .nullify) {
                    return error.CertificationTimedOut;
                }
            }
            try testing.expect(stack.reporter.certified(.new(1)));
            var reported = (try stack.reporter.notarization(.new(1))).?;
            defer reported.deinit(gpa);
            try testing.expect(reported.proposal.payload.eql(conflicting.payload));
        }

        fn wait_closed(ctx: Ctx, slot: *h.Automaton.HeldHandoff) !void {
            var waited: u64 = 0;
            // Bounded by 1 s of simulated time.
            while (!slot.is_closed()) : (waited += 1) {
                if (waited > 1_000) return error.BuildNotCanceled;
                try ctx.sleep(.fromMilliseconds(1));
            }
        }

        // commonware test_pipelined_handoff_displaced_ancestor_cancels_before_timeout.
        test "voter pipelined handoff displaced ancestor cancels before timeout" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    try displaced_ancestor_cancels_before_timeout(ctx, false);
                }
            }.body);
        }

        // commonware test_pipelined_handoff_displaced_ancestor_cancels_after_restart.
        test "voter pipelined handoff displaced ancestor cancels after restart" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    try displaced_ancestor_cancels_before_timeout(ctx, true);
                }
            }.body);
        }
    };
}
