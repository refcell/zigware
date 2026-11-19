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
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = timeout_s * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
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
    };
}
