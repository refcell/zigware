//! commonware `simplex/actors/voter/mod.rs` pipelined-handoff tests on `OutgoingTermHandoff`
//! (a view-4 handoff build pending on the uncertified final view of a three-view outgoing
//! term, with view 2's certification held), plus a waiting request dropped after our nullify
//! vote for its view.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            try h.soak(60 * std.time.ns_per_s, body);
        }

        /// commonware `OutgoingTermHandoff`. Must not move after `start`.
        const OutgoingTermHandoff = struct {
            net: h.Network,
            stack: h.VoterStack,
            local: usize,
            proposals: [3]h.Proposal,
            /// The application's held view-4 handoff response.
            response: *h.Automaton.HeldHandoff,
            /// The application's held certification of view 2.
            certified: ?*h.Automaton.Held,

            fn start(self: *OutgoingTermHandoff, ctx: Ctx, namespace: []const u8) !void {
                const gpa = ctx.gpa();
                try self.net.start(ctx, 5, namespace);
                errdefer self.net.deinit();
                // Views 1 to 3 form the outgoing term, and our term starts at view 4.
                const elector = h.term_elector(3, 300_000, 1);
                self.local = try h.leader_of(gpa, elector, 4);
                const outgoing = try h.leader_of(gpa, elector, 1);
                try self.stack.start(ctx, &self.net, .{
                    .leader_timeout_ms = 1_000,
                    .certification_timeout_ms = 2_000,
                    .timeout_retry_ms = 300_000,
                    .local_index = self.local,
                    .handoff = .vote,
                    .hold_handoffs = true,
                    .hold_certifications = .{ .view = 2 },
                    .elector = elector,
                });
                errdefer self.stack.stop();
                // The outgoing leader relays views 1 to 3, each built on the previous one.
                var parent = h.genesis(epoch);
                for (&self.proposals, 1..) |*proposal, view| {
                    var label: [40]u8 = undefined;
                    const name = try std.fmt.bufPrint(
                        &label,
                        "pipelined_handoff_parent_term_{d}",
                        .{view},
                    );
                    const round: h.Round = .new(epoch, .new(view));
                    proposal.* = .init(round, .new(view - 1), h.Sha256.hash(&.{name}));
                    const payload = proposal.payload;
                    h.relay_contents(&self.net, outgoing, payload, round, parent, view - 1);
                    parent = proposal.payload;
                }
                try self.prepare(ctx);
            }

            /// View 1 certifies and we vote for views 2 and 3; that last vote starts the
            /// view-4 build the application holds. Then view 2 notarizes with its
            /// certification held.
            fn prepare(self: *OutgoingTermHandoff, ctx: Ctx) !void {
                const gpa = ctx.gpa();
                const first = try h.build_peers(
                    gpa,
                    .notarization,
                    self.net.schemes(),
                    self.local,
                    self.proposals[0],
                    self.net.quorum(),
                );
                try self.stack.mailbox.recovered(gpa, .{ .notarization = first });
                // Bounded: views only advance, and each wait is limited.
                while ((try self.stack.next_update(ctx, 5_000)).current.get() != 2) {}
                for (self.proposals[1..]) |proposal| {
                    try self.stack.mailbox.proposal(proposal);
                    try self.wait_notarize(ctx, proposal.view().get(), null);
                }
                self.response = try self.stack.automaton.take_handoff(ctx);
                const second = try h.build(
                    gpa,
                    .notarization,
                    self.net.schemes(),
                    self.proposals[1],
                    self.net.quorum(),
                );
                try self.stack.mailbox.recovered(gpa, .{ .notarization = second });
                self.certified = try self.stack.automaton.take_certification(ctx, 2);
            }

            fn deinit(self: *OutgoingTermHandoff) void {
                self.stack.stop();
                self.net.deinit();
                self.* = undefined;
            }

            /// Lets the application certify view 2.
            fn certify_view_2(self: *OutgoingTermHandoff) void {
                self.stack.automaton.answer_certification(self.certified.?, true);
                self.certified = null;
            }

            /// Waits up to 5 s of simulated time for the voter to cancel the held build.
            fn wait_for_cancellation(self: *OutgoingTermHandoff, ctx: Ctx) !void {
                var waited: u64 = 0;
                // Bounded by 5 s of simulated time.
                while (!self.response.is_closed()) : (waited += 1) {
                    if (waited > 5_000) return error.BuildNotCanceled;
                    _ = try self.stack.next_batcher(ctx, 0);
                    try ctx.sleep(.fromMilliseconds(1));
                }
            }

            /// Waits for our notarize vote at `view`, and checks its parent if given.
            fn wait_notarize(self: *OutgoingTermHandoff, ctx: Ctx, view: u64, parent: ?u64) !void {
                // Bounded by the 5 s wait per message.
                while (true) {
                    const next = try self.stack.next_batcher(ctx, 5_000);
                    const message = next orelse return error.NoNotarize;
                    if (message != .constructed or message.constructed != .notarize) continue;
                    const vote = message.constructed.notarize;
                    if (vote.view().get() != view) continue;
                    if (parent) |expected| {
                        try testing.expectEqual(expected, vote.proposal.parent.get());
                    }
                    return;
                }
            }

            /// Expects the view-4 requests so far to name `parents`, in order. Later views
            /// are not counted: we lead the whole term, and polling can observe the view-5
            /// request that follows our view-4 vote before commonware's assertion would.
            fn expect_requests(self: *OutgoingTermHandoff, parents: []const u64) !void {
                const automaton = &self.stack.automaton;
                try testing.expectEqual(parents.len, automaton.requests_for(4));
                for (parents, 0..) |parent, index| {
                    const request = automaton.request_for(4, @intCast(index)).?;
                    try testing.expectEqual(parent, request.parent[0].get());
                }
            }
        };

        // commonware test_pipelined_handoff_parent_term_nullification_cancels_pending_build:
        // a nullification in the parent's term before our own nullify vote also cancels the
        // build; once the fallback certifies, an ordinary request on it proposes view 4.
        test "voter pipelined handoff parent term nullification cancels pending build" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var handoff: OutgoingTermHandoff = undefined;
                    try handoff.start(ctx, "pipelined_handoff_parent_term_nullification");
                    defer handoff.deinit();
                    // The other validators nullify view 3 before our certification timeout.
                    const nullification = try h.build_peers(
                        gpa,
                        .nullification,
                        handoff.net.schemes(),
                        handoff.local,
                        .new(epoch, .new(3)),
                        handoff.net.quorum(),
                    );
                    try handoff.stack.mailbox.recovered(gpa, .{ .nullification = nullification });
                    try handoff.wait_for_cancellation(ctx);
                    try handoff.expect_requests(&.{3});
                    handoff.certify_view_2();
                    try handoff.wait_notarize(ctx, 4, 2);
                    try handoff.expect_requests(&.{ 3, 2 });
                    try h.expect_handoff_metrics(ctx, &.{.{ "Requested", 1 }}, &.{
                        .{ "AncestryInvalidated", 1 },
                        .{ "AncestrySuperseded", 1 },
                    });
                }
            }.body);
        }

        // commonware test_pipelined_handoff_nullify_below_parent_cancels_pending_build: our
        // nullify vote for view 2, below the build's uncertified parent, cancels the build;
        // once views 2 and 3 certify, the waiting request becomes an ordinary request for the
        // same context.
        test "voter pipelined handoff nullify below parent cancels pending build" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var handoff: OutgoingTermHandoff = undefined;
                    try handoff.start(ctx, "pipelined_handoff_nullify_below_parent");
                    defer handoff.deinit();
                    // View 2's certification times out (2 s), so we vote to nullify it.
                    try testing.expect(try handoff.stack.nullify_within(ctx, 2, 5_000));
                    try handoff.wait_for_cancellation(ctx);
                    try handoff.expect_requests(&.{3});
                    handoff.certify_view_2();
                    const third = try h.build(
                        gpa,
                        .notarization,
                        handoff.net.schemes(),
                        handoff.proposals[2],
                        handoff.net.quorum(),
                    );
                    try handoff.stack.mailbox.recovered(gpa, .{ .notarization = third });
                    try handoff.wait_notarize(ctx, 4, 3);
                    try handoff.expect_requests(&.{ 3, 3 });
                    try h.expect_handoff_metrics(
                        ctx,
                        &.{.{ "Requested", 1 }},
                        &.{.{ "ParentNullify", 1 }},
                    );
                }
            }.body);
        }

        // commonware test_pipelined_handoff_waiting_request_dropped_after_view_nullify: with
        // one-view terms and no certificate for view 1, the waiting view-4 request survives
        // the parent's nullification and is dropped when the parent certifies after our
        // nullify vote for view 4.
        test "voter pipelined handoff waiting request dropped after view nullify" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    try waiting_request_dropped_after_view_nullify(ctx);
                }
            }.body);
        }

        fn waiting_request_dropped_after_view_nullify(ctx: Ctx) !void {
            const gpa = ctx.gpa();
            var net: h.Network = undefined;
            try net.start(ctx, 5, "pipelined_handoff_view_nullify");
            defer net.deinit();
            const local = try h.leader_of(gpa, .default(), 4);
            var stack: h.VoterStack = undefined;
            try stack.start(ctx, &net, .{
                .leader_timeout_ms = 10_000,
                .local_index = local,
                .hold_certifications = .{ .view = 3 },
            });
            defer stack.stop();
            // Enter view 3 without a certificate for view 1.
            try recover_nullification(ctx, &net, &stack, local, 2);
            // Notarize view 3 without our share and hold its certification. The application
            // answers the view-4 handoff with `wait`.
            const proposal: h.Proposal = .init(
                .new(epoch, .new(3)),
                .new(0),
                h.Sha256.hash(&.{"pipelined_handoff_view_nullify_3"}),
            );
            const notarization = try h.build_peers(
                gpa,
                .notarization,
                net.schemes(),
                local,
                proposal,
                net.quorum(),
            );
            try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
            const certified = try stack.automaton.take_certification(ctx, 3);
            try stack.wait_proposal_request(ctx, 4);
            // Nullifying view 3 enters view 4 with the request retained, and our leader
            // timeout then nullifies view 4.
            try recover_nullification(ctx, &net, &stack, local, 3);
            try testing.expect(try stack.nullify_within(ctx, 4, 15_000));
            // View 3 certifies while view 4 is still current.
            stack.automaton.answer_certification(certified, true);
            for (0..1_000) |_| {
                _ = try stack.next_batcher(ctx, 0);
                try ctx.sleep(.fromMilliseconds(1));
            }
            // No build follows our nullify vote.
            try testing.expectEqual(1, stack.automaton.requests_for(4));
            try h.expect_handoff_metrics(
                ctx,
                &.{ .{ "WaitReturned", 1 }, .{ "Requested", 1 } },
                &.{.{ "ViewNullify", 1 }},
            );
        }

        fn recover_nullification(
            ctx: Ctx,
            net: *h.Network,
            stack: *h.VoterStack,
            local: usize,
            view: u64,
        ) !void {
            const gpa = ctx.gpa();
            const nullification = try h.build_peers(
                gpa,
                .nullification,
                net.schemes(),
                local,
                .new(epoch, .new(view)),
                net.quorum(),
            );
            try stack.mailbox.recovered(gpa, .{ .nullification = nullification });
        }
    };
}
