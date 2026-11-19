//! commonware `simplex/actors/voter/mod.rs` `HandoffFixture`: a five-validator voter that
//! leads view 3, the first view of the second two-view term, after voting for the
//! uncertified outgoing tip at view 2. The test holds the certification of view 2 and the
//! application's handoff response.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Fixture(comptime h: type) type {
    return struct {
        const Self = @This();
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;
        pub const view_parent = 2;
        pub const view_child = 3;
        /// Time for the voter to drain its mailbox after the mock application's 1 ms
        /// latencies, when no observable event marks that it has done so (commonware `SETTLE`).
        pub const settle_ms = 50;

        net: h.Network,
        stack: h.VoterStack,
        gates: runtime.storage.mocks.SyncGates,
        relayed: h.RelayObserver,
        local: usize,
        outgoing: usize,
        /// The outgoing tip at view 2, notarized locally but uncertified.
        parent: h.Proposal,
        /// The handoff candidate the mock built for view 3, once taken.
        candidate: ?*h.Automaton.HeldHandoff,

        /// commonware `HandoffFixture::start`: starts the voter with `options` and drives it to
        /// the uncertified outgoing tip. Must not move afterward.
        pub fn start(self: *Self, ctx: Ctx, options: h.Options) !void {
            const gpa = ctx.gpa();
            try self.net.start(ctx, 5, "pipelined_handoff_linear");
            errdefer self.net.deinit();
            const elector = h.term_elector(2, 30_000, 1);
            self.local = try h.leader_of(gpa, elector, view_child);
            self.outgoing = try h.leader_of(gpa, elector, 1);
            self.gates = .init(ctx.io());
            self.candidate = null;
            var merged = options;
            merged.leader_timeout_ms = 10_000;
            merged.certification_timeout_ms = 10_000;
            merged.timeout_retry_ms = 30_000;
            merged.local_index = self.local;
            merged.elector = elector;
            merged.hold_certifications = .{ .view = view_parent };
            merged.hold_handoffs = true;
            merged.sync_gates = &self.gates;
            try self.stack.start(ctx, &self.net, merged);
            errdefer self.stack.stop();
            self.parent = try self.prepare_tip(ctx);
            // commonware's `observer()`: the next participant listens to later relays.
            try self.relayed.start(&self.net, (self.local + 1) % 5);
        }

        /// commonware `HandoffFixture::new`: `start` under `decision`, then takes the candidate
        /// the application built for the view-3 handoff request.
        pub fn init(self: *Self, ctx: Ctx, decision: @FieldType(h.Options, "handoff")) !void {
            try self.start(ctx, .{ .handoff = decision });
            errdefer self.deinit();
            const slot = try self.stack.automaton.take_handoff(ctx);
            try testing.expectEqual(view_child, slot.view.get());
            try testing.expectEqual(decision, std.meta.activeTag(slot.candidate));
            self.candidate = slot;
        }

        pub fn deinit(self: *Self) void {
            self.relayed.deinit();
            self.stack.stop();
            self.net.deinit();
            self.* = undefined;
        }

        /// commonware `HandoffFixture::restart`: aborts the voter and starts its replacement
        /// over the same journal, under metrics scope `scope` with the fixture's validator,
        /// elector, and timeouts and the rest of `options`. Drops the taken candidate and
        /// earlier relays, as the replacement's new relay observer would not see them.
        pub fn restart(self: *Self, ctx: Ctx, scope: []const u8, options: h.Options) !void {
            var merged = options;
            merged.leader_timeout_ms = 10_000;
            merged.certification_timeout_ms = 10_000;
            merged.timeout_retry_ms = 30_000;
            merged.local_index = self.local;
            merged.elector = h.term_elector(2, 30_000, 1);
            merged.scope = scope;
            self.candidate = null;
            try self.stack.replace(ctx, &self.net, merged);
            while (self.relayed.try_next()) |_| {}
        }

        /// The taken candidate's payload.
        pub fn digest(self: *const Self) h.Digest {
            return self.candidate.?.digest();
        }

        /// Waits up to 1 s of simulated time for the voter to cancel the held build. The
        /// voter counts the abandonment before its cancel joins the build's task.
        pub fn wait_closed(self: *Self, ctx: Ctx) !void {
            var waited: u64 = 0;
            // Bounded by 1 s of simulated time.
            while (!self.candidate.?.is_closed()) : (waited += 1) {
                if (waited > 1_000) return error.BuildNotCanceled;
                try ctx.sleep(.fromMilliseconds(1));
            }
        }

        /// Answers the pending handoff with the built candidate.
        pub fn respond(self: *Self) void {
            const slot = self.candidate.?;
            self.stack.automaton.answer_handoff(slot, slot.candidate);
        }

        /// Answers the pending handoff with `wait`.
        pub fn respond_wait(self: *Self) void {
            self.stack.automaton.answer_handoff(self.candidate.?, .wait);
        }

        /// commonware `prepare_pipelined_handoff_tip`: certifies view 1 and drives the voter
        /// through its notarize vote for view 2.
        fn prepare_tip(self: *Self, ctx: Ctx) !h.Proposal {
            const gpa = ctx.gpa();
            _ = try self.stack.next_update(ctx, 5_000);
            const genesis = h.genesis(epoch);
            const p1 = h.proposal_at(epoch, 1, "pipelined_test_view_1");
            h.relay_contents(&self.net, self.outgoing, p1.payload, p1.round, genesis, 0);
            const notarization = try h.build_peers(
                gpa,
                .notarization,
                self.net.schemes(),
                self.local,
                p1,
                self.net.quorum(),
            );
            try self.stack.mailbox.recovered(gpa, .{ .notarization = notarization });
            try self.wait_certified_view_1(ctx);
            const p2 = h.proposal_at(epoch, view_parent, "pipelined_test_view_2");
            h.relay_contents(&self.net, self.outgoing, p2.payload, p2.round, p1.payload, 1);
            try self.stack.mailbox.proposal(p2);
            try self.wait_notarize(ctx, view_parent);
            return p2;
        }

        /// Waits until view 1 certifies and the voter enters view 2.
        fn wait_certified_view_1(self: *Self, ctx: Ctx) !void {
            var certified = false;
            var entered = false;
            var waited: u64 = 0;
            // Bounded by 5 s of simulated time.
            while (!certified or !entered) : (waited += 1) {
                if (waited > 5_000) return error.TipNotReached;
                if (self.stack.batcher.try_recv()) |message| {
                    if (message == .update and message.update.current.get() == 2) entered = true;
                } else |_| {}
                if (self.stack.resolver.try_recv()) |message| {
                    defer message.discard();
                    if (message == .certified and message.certified.success and
                        message.certified.notarization.view().get() == 1) certified = true;
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
        }

        /// Waits up to 5 s of simulated time for our notarize vote at `view`.
        pub fn wait_notarize(self: *Self, ctx: Ctx, view: u64) !void {
            _ = try self.next_notarize(ctx, view, 5_000) orelse return error.NoNotarize;
        }

        /// Our next notarize vote's payload at `view` within `limit_ms`, skipping other
        /// batcher messages.
        pub fn next_notarize(self: *Self, ctx: Ctx, view: u64, limit_ms: u64) !?h.Digest {
            var waited: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited <= limit_ms) {
                const message = self.stack.batcher.try_recv() catch {
                    try ctx.sleep(.fromMilliseconds(1));
                    waited += 1;
                    continue;
                };
                if (message != .constructed or message.constructed != .notarize) continue;
                const notarize = message.constructed.notarize;
                if (notarize.view().get() == view) return notarize.proposal.payload;
            }
            return null;
        }

        /// Proposal and handoff requests the application received for view 3.
        pub fn child_requests(self: *Self) u32 {
            return self.stack.automaton.requests_for(view_child);
        }

        /// Delivers the parent's notarization and returns its held certification request.
        pub fn certify_parent(self: *Self, ctx: Ctx) !*h.Automaton.Held {
            const gpa = ctx.gpa();
            const notarization = try h.build(
                gpa,
                .notarization,
                self.net.schemes(),
                self.parent,
                self.net.quorum(),
            );
            try self.stack.mailbox.recovered(gpa, .{ .notarization = notarization });
            return self.stack.automaton.take_certification(ctx, view_parent);
        }

        /// Answers the parent's certification request and waits until its journal sync parks.
        pub fn block_certification(self: *Self, ctx: Ctx, slot: *h.Automaton.Held) !void {
            self.gates.arm();
            self.stack.automaton.answer_certification(slot, true);
            var waited: u64 = 0;
            // Bounded by 5 s of simulated time.
            while (!self.gates.blocked()) : (waited += 1) {
                if (waited > 5_000) return error.SyncNotBlocked;
                try ctx.sleep(.fromMilliseconds(1));
            }
        }

        /// Releases the parked sync and waits until the voter reports the parent certified.
        pub fn release_certification(self: *Self, ctx: Ctx) !void {
            self.gates.release();
            // Bounded by the 5 s wait per message.
            while (true) {
                const next = try self.stack.next_resolver(ctx, 5_000);
                const message = next orelse return error.ParentNotCertified;
                defer message.discard();
                if (message != .certified or !message.certified.success) continue;
                if (message.certified.notarization.view().get() == view_parent) return;
            }
        }

        /// Answers the parent's certification request and waits until the voter processed it.
        pub fn finish_certification(self: *Self, ctx: Ctx, slot: *h.Automaton.Held) !void {
            try self.block_certification(ctx, slot);
            try self.release_certification(ctx);
        }

        /// Waits for exactly one ordinary replacement request with the captured context.
        pub fn wait_for_replacement(self: *Self, ctx: Ctx) !void {
            var waited: u64 = 0;
            // Bounded by 5 s of simulated time.
            while (self.child_requests() < 2) : (waited += 1) {
                if (waited > 5_000) return error.NoReplacement;
                try ctx.sleep(.fromMilliseconds(1));
            }
            try testing.expectEqual(2, self.child_requests());
            const automaton = &self.stack.automaton;
            const first = automaton.request_for(view_child, 0).?;
            const second = automaton.request_for(view_child, 1).?;
            // The ordinary request must reuse the captured context.
            try testing.expectEqualDeep(first, second);
            try testing.expectEqual(view_parent, second.parent[0].get());
            try testing.expectEqual(self.parent.payload, second.parent[1]);
        }

        /// Asserts no relay and no notarize vote for any of `stale` (commonware
        /// `assert_handoff_silent`).
        pub fn expect_silent(self: *Self, stale: []const h.Digest) !void {
            while (self.relayed.try_next()) |payload| {
                try expect_not_in(payload, stale);
            }
            // Bounded by the queued messages.
            while (self.stack.batcher.try_recv()) |message| {
                if (message != .constructed or message.constructed != .notarize) continue;
                try expect_not_in(message.constructed.notarize.proposal.payload, stale);
            } else |_| {}
        }

        fn expect_not_in(payload: h.Digest, stale: []const h.Digest) !void {
            for (stale) |candidate| {
                if (std.mem.eql(u8, &payload.bytes, &candidate.bytes)) {
                    return error.StaleHandoffObserved;
                }
            }
        }

        /// Waits for the relay of the held candidate (commonware `observe_handoff_relay`).
        pub fn observe_relay(self: *Self, ctx: Ctx) !void {
            const payload = try self.relayed.next(ctx, 5_000) orelse return error.NoRelay;
            try testing.expectEqual(self.digest(), payload);
        }

        /// Waits for the view-3 vote that releases the held candidate; it was relayed when
        /// held, so no second relay may arrive (commonware `observe_handoff_vote`).
        pub fn observe_vote(self: *Self, ctx: Ctx) !void {
            const voted = try self.next_notarize(ctx, view_child, 5_000) orelse
                return error.NoHandoffVote;
            try testing.expectEqual(self.digest(), voted);
            while (self.relayed.try_next()) |payload| {
                if (payload.eql(self.digest())) return error.RelayedTwice;
            }
        }

        /// Waits for both the relay and the view-3 vote of the candidate (commonware
        /// `observe_handoff_relay_and_vote`).
        pub fn observe_relay_and_vote(self: *Self, ctx: Ctx) !void {
            const voted = try self.next_notarize(ctx, view_child, 5_000) orelse
                return error.NoHandoffVote;
            try testing.expectEqual(self.digest(), voted);
            try self.observe_relay(ctx);
        }
    };
}
