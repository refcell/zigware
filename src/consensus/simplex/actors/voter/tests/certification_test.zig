//! commonware `simplex/actors/voter/mod.rs` certificate and certification tests: recovered
//! certificates the voter applies and reports, and how certification outcomes gate votes.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            return run_for(10, body);
        }

        fn run_for(timeout_s: u64, comptime body: fn (Ctx) anyerror!void) !void {
            try h.soak(timeout_s * std.time.ns_per_s, body);
        }

        // commonware test_recovered_finalization_is_reported
        test "voter recovered finalization is reported" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "recovered_finalization_is_reported");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{});
                    defer stack.stop();
                    const first = (try stack.next_batcher(ctx, 1_000)) orelse return error.NoUpdate;
                    try testing.expect(first == .update);
                    try testing.expectEqual(@as(u64, 1), first.update.current.get());
                    try testing.expectEqual(@as(u64, 0), first.update.finalized.get());
                    // A finalization one view above the current view is applied and reported.
                    const proposal = h.proposal_at(epoch, 2, "recovered_finalization_is_reported");
                    var finalization =
                        try h.build(gpa, .finalization, net.schemes(), proposal, net.quorum());
                    defer finalization.deinit(gpa);
                    const copy = try finalization.clone(gpa);
                    try stack.mailbox.recovered(gpa, .{ .finalization = copy });
                    // Bounded by the runner's timeout.
                    while (true) {
                        const message = (try stack.next_batcher(ctx, 5_000)) orelse
                            return error.NotFinalized;
                        if (message == .update and message.update.finalized.get() == 2) break;
                    }
                    var recorded = (try stack.reporter.finalization(.new(2))) orelse
                        return error.NotReported;
                    defer recorded.deinit(gpa);
                    try testing.expect(recorded.eql(finalization));
                }
            }.body);
        }

        /// Proposal `view` over `parent` with payload `hash(be64(view))`.
        fn chained(view: u64, parent: u64) h.Proposal {
            var be: [8]u8 = undefined;
            std.mem.writeInt(u64, &be, view, .big);
            const round: h.Round = .new(epoch, .new(view));
            return .init(round, .new(parent), h.Sha256.hash(&.{&be}));
        }

        fn recover_notarization(ctx: Ctx, net: *h.Network, stack: *h.VoterStack, view: u64) !void {
            const gpa = ctx.gpa();
            const subject = chained(view, view - 1);
            const notarization =
                try h.build(gpa, .notarization, net.schemes(), subject, net.quorum());
            try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
        }

        fn drain_resolver(stack: *h.VoterStack) void {
            // Bounded by the mailbox capacity.
            while (stack.resolver.try_recv()) |message| message.discard() else |_| {}
        }

        /// Waits for the voter's request for the notarization of view 2, proposed under view 3.
        fn expect_resolve(ctx: Ctx, stack: *h.VoterStack) !void {
            // Bounded by the per-message wait.
            while (true) {
                const message = (try stack.next_resolver(ctx, 20_000)) orelse
                    return error.NeverRequested;
                defer message.discard();
                if (message != .resolve) continue;
                try testing.expectEqual(@as(u64, 3), message.resolve.proposal.get());
                try testing.expectEqual(@as(u64, 2), message.resolve.view.get());
                try testing.expect(message.resolve.kind == .notarization);
                try testing.expect(message.resolve.target == null);
                return;
            }
        }

        const Recovery = struct { certified: [2]u64 = .{ 0, 0 }, certified_count: u32 = 0 };

        /// Records a certification verdict for view 2 or 3.
        fn record_certified(recovery: *Recovery, message: h.ResolverMessage) !void {
            defer message.discard();
            if (message != .certified) return;
            const view = message.certified.notarization.view().get();
            if (view != 2 and view != 3) return;
            try testing.expect(message.certified.success);
            if (recovery.certified_count >= recovery.certified.len) return error.Recertified;
            recovery.certified[recovery.certified_count] = view;
            recovery.certified_count += 1;
        }

        /// Waits until views 2 and 3 certify in order and we vote to finalize view 3.
        fn expect_recovery(ctx: Ctx, stack: *h.VoterStack) !void {
            var recovery: Recovery = .{};
            var finalized_3 = false;
            var waited_ms: u64 = 0;
            // Bounded by 20 s of simulated time.
            while (waited_ms < 20_000) : (waited_ms += 1) {
                if (stack.resolver.try_recv()) |message| {
                    try record_certified(&recovery, message);
                } else |_| {}
                if (stack.batcher.try_recv()) |message| {
                    if (message == .constructed and message.constructed == .finalize) {
                        finalized_3 = finalized_3 or message.constructed.view().get() == 3;
                    }
                } else |_| {}
                if (recovery.certified_count == 2 and finalized_3) {
                    try testing.expectEqualSlices(u64, &.{ 2, 3 }, &recovery.certified);
                    return;
                }
                try ctx.sleep(.fromMilliseconds(1));
            }
            return error.RecoveryStalled;
        }

        // commonware test_missed_notarization_is_fetched
        test "voter missed notarization is fetched" {
            try h.covers(.ed25519);
            try run_for(30, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 4, "missed_notarization_is_fetched");
                    defer net.deinit();
                    // A stable leader with optimistic validation; we follow in term 1.
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{ .elector = h.term_elector(5, 30_000, 2) });
                    defer stack.stop();
                    try recover_notarization(ctx, &net, &stack, 1);
                    // Bounded: views only advance, and each wait is limited.
                    while ((try stack.next_update(ctx, 5_000)).current.get() != 2) {}
                    drain_resolver(&stack);
                    // Certifying view 3 needs view 2's exact notarization, which we missed.
                    try recover_notarization(ctx, &net, &stack, 3);
                    try stack.expect_updated(ctx, .notarization, 3);
                    try expect_resolve(ctx, &stack);
                    // The fetched parent certifies before its child, and finalize voting resumes.
                    // Bounded by the mailbox capacity.
                    while (stack.batcher.try_recv()) |_| {} else |_| {}
                    try recover_notarization(ctx, &net, &stack, 2);
                    try expect_recovery(ctx, &stack);
                }
            }.body);
        }

        /// Expects the resolver's finalization update for `view` before any certification
        /// verdict, then no verdict for 4 s.
        fn expect_no_certified(ctx: Ctx, stack: *h.VoterStack, view: u64) !void {
            // Bounded by the per-message wait.
            while (true) {
                const message = (try stack.next_resolver(ctx, 5_000)) orelse
                    return error.NoFinalizationUpdate;
                defer message.discard();
                if (message == .certified) return error.Certified;
                if (message != .updated or message.updated.certificate != .finalization) continue;
                try testing.expectEqual(view, message.updated.certificate.view().get());
                break;
            }
            var waited_ms: u64 = 0;
            // Bounded by 4 s of simulated time.
            while (waited_ms < 4_000) : (waited_ms += 1) {
                if (stack.resolver.try_recv()) |message| {
                    defer message.discard();
                    if (message == .certified) return error.Certified;
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
        }

        // commonware test_certification_cancelled_on_finalization
        test "voter certification cancelled on finalization" {
            try h.covers(.schemes);
            try run_for(30, struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "consensus");
                    defer net.deinit();
                    // Certification takes 2 s, so the finalization overtakes it.
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 5_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = 60 * 60 * 1000,
                        .certify_latency_ms = 2_000,
                        .partition = "cert_cancel_test",
                        .batcher_capacity = 1024,
                        .resolver_capacity = 10,
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    const round: h.Round = .new(epoch, .new(5));
                    const payload = h.Sha256.hash(&.{"payload_to_certify"});
                    const proposal: h.Proposal = .init(round, .new(0), payload);
                    h.relay_contents(&net, 0, payload, round, h.Sha256.hash(&.{"genesis"}), 42);
                    try stack.mailbox.proposal(proposal);
                    const schemes = net.schemes();
                    const quorum = net.quorum();
                    const notarization =
                        try h.build(gpa, .notarization, schemes, proposal, quorum);
                    try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
                    try ctx.sleep(.fromMilliseconds(100));
                    const finalization =
                        try h.build(gpa, .finalization, schemes, proposal, quorum);
                    try stack.mailbox.recovered(gpa, .{ .finalization = finalization });
                    // Bounded: views only advance, and each wait is limited.
                    while ((try stack.next_update(ctx, 5_000)).finalized.get() < 5) {}
                    try expect_no_certified(ctx, &stack, 5);
                }
            }.body);
        }

        /// Waits up to 6 s for the certification verdict of `view`, draining the batcher.
        fn certified_verdict(ctx: Ctx, stack: *h.VoterStack, view: u64) !?bool {
            var waited_ms: u64 = 0;
            // Bounded by 6 s of simulated time.
            while (waited_ms < 6_000) : (waited_ms += 1) {
                while (stack.batcher.try_recv()) |_| {} else |_| {}
                if (stack.resolver.try_recv()) |message| {
                    defer message.discard();
                    if (message == .certified and
                        message.certified.notarization.view().get() == view)
                    {
                        return message.certified.success;
                    }
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
            return null;
        }

        /// Whether an update announces a view above `view` within 5 s.
        fn advances_past(ctx: Ctx, stack: *h.VoterStack, view: u64) !bool {
            var waited_ms: u64 = 0;
            // Bounded by 5 s of simulated time.
            while (waited_ms < 5_000) : (waited_ms += 1) {
                const message = stack.batcher.try_recv() catch {
                    try ctx.sleep(.fromMilliseconds(1));
                    continue;
                };
                if (message == .update and message.update.current.get() > view) return true;
            }
            return false;
        }

        /// Waits up to `limit_ms` for our vote of `kind` at `view`.
        fn expect_vote(
            ctx: Ctx,
            stack: *h.VoterStack,
            comptime kind: anytype,
            view: u64,
            limit_ms: u64,
        ) !void {
            var waited_ms: u64 = 0;
            // Bounded by `limit_ms` of simulated time.
            while (waited_ms < limit_ms) {
                const message = stack.batcher.try_recv() catch {
                    try ctx.sleep(.fromMilliseconds(1));
                    waited_ms += 1;
                    continue;
                };
                if (message != .constructed or message.constructed != kind) continue;
                if (message.constructed.view().get() == view) return;
            }
            return error.NoVote;
        }

        fn recover(
            ctx: Ctx,
            net: *h.Network,
            stack: *h.VoterStack,
            comptime kind: std.meta.Tag(h.Certificate),
            subject: if (kind == .nullification) h.Round else h.Proposal,
        ) !void {
            const gpa = ctx.gpa();
            const certificate = try h.build(gpa, kind, net.schemes(), subject, net.quorum());
            const recovered = @unionInit(h.Certificate, @tagName(kind), certificate);
            try stack.mailbox.recovered(gpa, recovered);
        }

        /// commonware's certification-after-timeout voter: 10 s timeouts, a 100 s retry.
        const ten_second_timeouts: h.Options = .{
            .leader_timeout_ms = 10_000,
            .certification_timeout_ms = 10_000,
            .timeout_retry_ms = 100_000,
        };

        // commonware test_certification_still_reports_to_resolver_after_nullification
        test "voter certification still reports to resolver after nullification" {
            try h.covers(.schemes);
            try run_for(30, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "consensus");
                    defer net.deinit();
                    // Certification takes 2 s, so the nullification arrives while it runs.
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 5_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = 60 * 60 * 1000,
                        .certify_latency_ms = 2_000,
                        .partition = "cert_after_nullification_test",
                        .batcher_capacity = 1024,
                        .resolver_capacity = 10,
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    const round: h.Round = .new(epoch, .new(5));
                    const payload = h.Sha256.hash(&.{"payload_to_certify"});
                    const proposal: h.Proposal = .init(round, .new(0), payload);
                    h.relay_contents(&net, 0, payload, round, h.Sha256.hash(&.{"genesis"}), 42);
                    try stack.mailbox.proposal(proposal);
                    try recover(ctx, &net, &stack, .notarization, proposal);
                    try ctx.sleep(.fromMilliseconds(100));
                    try recover(ctx, &net, &stack, .nullification, round);
                    // The late verdict still reaches the resolver.
                    const verdict = try certified_verdict(ctx, &stack, 5);
                    try testing.expectEqual(@as(?bool, true), verdict);
                }
            }.body);
        }

        // commonware test_late_notarization_after_nullification_still_certifies
        test "voter late notarization after nullification still certifies" {
            try h.covers(.schemes_round_robin);
            try run_for(30, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "late_notarization_after_nullification");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 5_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = 5_000,
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    _ = try h.advance_to_view(&stack, ctx, &net, 3);
                    // View 3 is nullified, then its notarization arrives and still certifies.
                    try recover(ctx, &net, &stack, .nullification, .new(epoch, .new(3)));
                    const late = h.proposal_at(epoch, 3, "late_notarization_after_nullification");
                    try recover(ctx, &net, &stack, .notarization, late);
                    const verdict = try certified_verdict(ctx, &stack, 3);
                    try testing.expectEqual(@as(?bool, true), verdict);
                }
            }.body);
        }

        // commonware test_certification_after_timeout
        test "voter certification after timeout" {
            try h.covers(.schemes_round_robin);
            try run_for(60, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "certification_after_timeout");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, ten_second_timeouts);
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    // Round robin elects participant 1 for view 3: we follow, and get no
                    // proposal, so we time out before any notarize.
                    _ = try h.advance_to_view(&stack, ctx, &net, 3);
                    try expect_vote(ctx, &stack, .nullify, 3, 15_000);
                    // A delayed notarization still certifies and advances the view.
                    const proposal = h.proposal_at(epoch, 3, "timeout_test");
                    try recover(ctx, &net, &stack, .notarization, proposal);
                    try testing.expect(try advances_past(ctx, &stack, 3));
                }
            }.body);
        }

        // commonware test_certification_after_notarize_timeout_as_follower
        test "voter certification after notarize timeout as follower" {
            try h.covers(.schemes_round_robin);
            try run_for(60, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "certification_after_notarize_timeout_as_follower");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, ten_second_timeouts);
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    const parent = try h.advance_to_view(&stack, ctx, &net, 3);
                    // We notarize participant 1's proposal, then time out waiting for its
                    // notarization.
                    const proposal = h.proposal_at(epoch, 3, "follower_test");
                    h.relay_contents(&net, 1, proposal.payload, proposal.round, parent, 0);
                    try stack.mailbox.proposal(proposal);
                    try expect_vote(ctx, &stack, .notarize, 3, 5_000);
                    try ctx.sleep(.fromSeconds(11));
                    try expect_vote(ctx, &stack, .nullify, 3, 1_000);
                    // The late notarization still certifies and advances the view.
                    try recover(ctx, &net, &stack, .notarization, proposal);
                    try testing.expect(try advances_past(ctx, &stack, 3));
                }
            }.body);
        }

        /// Waits for our notarize at `view` and returns its proposal.
        fn notarized_proposal(ctx: Ctx, stack: *h.VoterStack, view: u64) !h.Proposal {
            // Bounded by the per-message wait.
            while (true) {
                const message = (try stack.next_batcher(ctx, 5_000)) orelse
                    return error.NoNotarize;
                if (message != .constructed or message.constructed != .notarize) continue;
                const vote = message.constructed.notarize;
                if (vote.view().get() == view) return vote.proposal;
            }
        }

        // commonware test_certification_after_notarize_timeout_as_leader
        test "voter certification after notarize timeout as leader" {
            try h.covers(.schemes_round_robin);
            try run_for(60, struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "certification_after_notarize_timeout_as_leader");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, ten_second_timeouts);
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    // Round robin elects us for view 2: we propose and notarize, then time out
                    // waiting for its notarization.
                    _ = try h.advance_to_view(&stack, ctx, &net, 2);
                    const proposal = try notarized_proposal(ctx, &stack, 2);
                    try ctx.sleep(.fromSeconds(11));
                    try expect_vote(ctx, &stack, .nullify, 2, 1_000);
                    // The late notarization still certifies and advances the view.
                    try recover(ctx, &net, &stack, .notarization, proposal);
                    try testing.expect(try advances_past(ctx, &stack, 2));
                }
            }.body);
        }

        /// Whether `event` is the debug "failed to certify proposal" for `round` (formatted the
        /// way the voter's tracer writes it).
        fn failed_to_certify(
            round: h.Round,
            event: runtime.telemetry.traces.collector.RecordedEvent,
        ) bool {
            if (!std.mem.eql(u8, event.metadata.content, "failed to certify proposal")) {
                return false;
            }
            var buffer: [64]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&buffer);
            runtime.telemetry.traces.write_field_value(&writer, round) catch return false;
            for (event.metadata.fields) |field| {
                if (!std.mem.eql(u8, field.name, "round")) continue;
                if (std.mem.eql(u8, field.value, writer.buffered())) return true;
            }
            return false;
        }

        // commonware test_cancelled_certification_does_not_hang
        test "voter cancelled certification does not hang" {
            try h.covers(.schemes_round_robin);
            try run_for(10, struct {
                fn body(ctx: Ctx) anyerror!void {
                    const traces = runtime.telemetry.traces;
                    var collector = traces.Collector.init(ctx.gpa(), .{});
                    defer collector.deinit();
                    var subscriber = collector.subscriber();
                    subscriber.level = .debug;
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "consensus");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .certification_timeout_ms = 500,
                        .timeout_retry_ms = 60 * 60 * 1000,
                        .certifier = .cancel,
                        .tracer = .init(subscriber, "commonware_consensus::simplex::voter"),
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 1_000);
                    const parent = try h.advance_to_view(&stack, ctx, &net, 3);
                    const proposal = h.proposal_at(epoch, 3, "test_proposal");
                    h.relay_contents(&net, 1, proposal.payload, proposal.round, parent, 0);
                    try stack.mailbox.proposal(proposal);
                    try recover(ctx, &net, &stack, .notarization, proposal);
                    // The certifier drops the request, so the view times out to a nullify.
                    try expect_vote(ctx, &stack, .nullify, 3, 5_000);
                    const debug = collector.get_by_level(.debug);
                    try debug.expect_event(proposal.round, failed_to_certify);
                }
            }.body);
        }
    };
}
