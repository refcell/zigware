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
    };
}
