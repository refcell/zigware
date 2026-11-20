//! commonware `simplex/actors/voter/mod.rs` timeout tests: a timeout's nullify vote and the
//! nullification that follows replay after a restart, and a batcher timeout hint on a view
//! update nullifies that view at once.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;
        const target = 3;

        fn run(comptime body: fn (Ctx) anyerror!void, timeout_s: u64) !void {
            try h.soak(timeout_s * std.time.ns_per_s, body);
        }

        fn options(partition: []const u8) h.Options {
            return .{
                .leader_timeout_ms = 5_000,
                .certification_timeout_ms = 5_000,
                .timeout_retry_ms = 60 * 60 * 1_000,
                .partition = partition,
                .batcher_capacity = 8,
            };
        }

        /// Whether our nullify vote at the target view is queued for the batcher now.
        fn nullify_queued(stack: *h.VoterStack) bool {
            var found = false;
            // Bounded by the queued messages.
            while (stack.batcher.try_recv()) |message| {
                if (message != .constructed or message.constructed != .nullify) continue;
                found = found or message.constructed.view().get() == target;
            } else |_| {}
            return found;
        }

        /// Waits for an update past the target view.
        fn wait_past_target(ctx: Ctx, stack: *h.VoterStack) !void {
            // Bounded: views only advance, and each wait is limited.
            while ((try stack.next_update(ctx, 5_000)).current.get() <= target) {}
        }

        /// The first run: a timeout's nullify vote waits behind its section sync, then the
        /// nullification moves the voter past the target view.
        fn nullify_behind_sync(ctx: Ctx, net: *h.Network) !void {
            const gpa = ctx.gpa();
            var gates: runtime.storage.mocks.SyncGates = .init(ctx.io());
            var first = options("nullify_nullification_replay");
            first.sync_gates = &gates;
            var stack: h.VoterStack = undefined;
            try stack.start(ctx, net, first);
            defer stack.stop();
            _ = try stack.next_update(ctx, 5_000);
            _ = try h.advance_to_view(&stack, ctx, net, target);
            gates.arm();
            try stack.mailbox.timeout(.new(epoch, .new(target)), .leader_timeout);
            var waited: u64 = 0;
            // Bounded by 5 s of simulated time.
            while (!gates.blocked()) : (waited += 1) {
                if (waited > 5_000) return error.SyncNotBlocked;
                try ctx.sleep(.fromMilliseconds(1));
            }
            // The nullify does not reach the batcher before its section sync completes.
            try testing.expect(!nullify_queued(&stack));
            gates.release();
            try testing.expect(try stack.nullify_within(ctx, target, 5_000));
            const nullification = try h.build(
                gpa,
                .nullification,
                net.schemes(),
                .new(epoch, .new(target)),
                net.quorum(),
            );
            try stack.mailbox.recovered(gpa, .{ .nullification = nullification });
            try wait_past_target(ctx, &stack);
            // Let the journal sync.
            try ctx.sleep(.fromMilliseconds(50));
        }

        // commonware test_nullify_and_nullification_replayed_after_restart: replay hands the
        // resolver the nullification and moves past the nullified view.
        test "voter nullify and nullification replayed after restart" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "nullify_nullification_replay");
                    defer net.deinit();
                    try nullify_behind_sync(ctx, &net);
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, options("nullify_nullification_replay"));
                    defer stack.stop();
                    var replayed = false;
                    // Bounded by the 5 s wait per message.
                    while (!replayed) {
                        const next = try stack.next_resolver(ctx, 5_000);
                        const message = next orelse return error.NoReplayedNullification;
                        defer message.discard();
                        if (message != .updated) continue;
                        const certificate = message.updated.certificate;
                        replayed = certificate == .nullification and
                            certificate.view().get() == target;
                    }
                    try wait_past_target(ctx, &stack);
                }
            }.body, 20);
        }

        // commonware test_batcher_update_triggers_timeout: when the batcher answers a view
        // update with a timeout reason, the voter nullifies that view at once, not after its
        // 100 s leader timeout.
        test "voter batcher update triggers timeout" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "batcher_update_timeout");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 100_000,
                        .certification_timeout_ms = 100_000,
                        .timeout_retry_ms = 60 * 60 * 1_000,
                        .partition = "batcher_timeout_test",
                    });
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 5_000);
                    _ = try h.advance_to_view(&stack, ctx, &net, target);
                    // Certify view 3 to advance to view 4.
                    const proposal = h.proposal_at(epoch, target, "batcher_timeout_view3");
                    const genesis = h.Sha256.hash(&.{"genesis"});
                    h.relay_contents(&net, 1, proposal.payload, proposal.round, genesis, 0);
                    try stack.mailbox.proposal(proposal);
                    const notarization =
                        try h.build(gpa, .notarization, net.schemes(), proposal, net.quorum());
                    try stack.mailbox.recovered(gpa, .{ .notarization = notarization });
                    // On the update past view 3, signal leader inactivity like the batcher.
                    var current: u64 = 0;
                    // Bounded: views only advance, and each wait is limited.
                    while (current <= target) {
                        current = (try stack.next_update(ctx, 5_000)).current.get();
                    }
                    try stack.mailbox.timeout(.new(epoch, .new(current)), .inactivity);
                    try testing.expect(try stack.nullify_within(ctx, target + 1, 5_000));
                }
            }.body, 30);
        }
    };
}
