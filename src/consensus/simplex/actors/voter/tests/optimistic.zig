//! commonware `simplex/actors/voter/mod.rs` optimistic-proposal tests: proposal requests
//! for future views of a term, and how they interleave with timeouts and journal syncs.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const harness = @import("harness.zig");

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

        // commonware test_optimistic_future_proposal_survives_interleaved_timeout: the leader of a
        // five-view term asks for view 2's proposal optimistically with view 1's notarize; view 1's
        // certification timeout fires while that request is in flight, and must not drop it.
        test "voter optimistic future proposal survives interleaved timeout" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(
                        ctx,
                        5,
                        "optimistic_future_proposal_survives_interleaved_timeout",
                    );
                    defer net.deinit();
                    const elector = h.term_elector(5, 30_000, 2);
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 2_000,
                        // Fires between the view-2 request (one propose latency in) and its answer.
                        .certification_timeout_ms = 300,
                        .timeout_retry_ms = 10_000,
                        .local_index = try h.leader_of(ctx.gpa(), elector, 1),
                        .propose_latency_ms = 200.0,
                        .elector = elector,
                    });
                    defer stack.stop();
                    var saw_notarize_1 = false;
                    var saw_nullify_1 = false;
                    // Bounded by the 8 s wait per message.
                    while (true) {
                        const message = (try stack.next_batcher(ctx, 8_000)) orelse
                            return error.NoOptimisticNotarize;
                        if (message != .constructed) continue;
                        const view = message.constructed.view().get();
                        switch (message.constructed) {
                            .notarize => {
                                if (view == 1) saw_notarize_1 = true;
                                if (view == 2) {
                                    try testing.expect(saw_notarize_1);
                                    try testing.expect(saw_nullify_1); // The timeout interleaved.
                                    return;
                                }
                            },
                            .nullify => if (view == 1) {
                                saw_nullify_1 = true;
                            },
                            .finalize => {},
                        }
                    }
                }
            }.body);
        }

        // commonware test_next_propose_dispatches_before_sync: while the journal sync of
        // view 1's notarize is held, the view 2 proposal request still reaches the
        // application, and the view 1 notarize is published only after the sync.
        test "voter next propose dispatches before sync" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "next_propose_dispatches_before_sync");
                    defer net.deinit();
                    const elector = h.term_elector(5, 30_000, 2);
                    var gates: runtime.storage.mocks.SyncGates = .init(ctx.io());
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .local_index = try h.leader_of(ctx.gpa(), elector, 1),
                        .propose_latency_ms = 200.0,
                        .elector = elector,
                        .sync_gates = &gates,
                    });
                    defer stack.stop();
                    try stack.wait_proposal_request(ctx, 1);
                    gates.arm();
                    // The voter appends view 1's notarize and blocks on the gated sync.
                    var waited: u64 = 0;
                    while (!gates.blocked()) : (waited += 1) {
                        if (waited >= 1_000) return error.SyncNotGated;
                        try ctx.sleep(.fromMilliseconds(1));
                    }
                    try stack.wait_proposal_request(ctx, 2);
                    // Nothing for view 1 reaches the batcher before its sync.
                    // Bounded by the batcher mailbox's contents.
                    while (stack.batcher.try_recv()) |message| {
                        if (message != .constructed or message.constructed != .notarize) continue;
                        try testing.expect(message.constructed.view().get() != 1);
                    } else |_| {}
                    try testing.expectEqual(@as(u64, 1), gates.calls());
                    gates.release();
                    // Bounded by the 5 s wait per message.
                    while (true) {
                        const next = try stack.next_batcher(ctx, 5_000);
                        const message = next orelse return error.NoNotarize;
                        if (message != .constructed or message.constructed != .notarize) continue;
                        if (message.constructed.view().get() == 1) return;
                    }
                }
            }.body);
        }
    };
}
