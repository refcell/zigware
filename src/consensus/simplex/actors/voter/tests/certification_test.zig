//! commonware `simplex/actors/voter/mod.rs` certificate and certification tests: recovered
//! certificates the voter applies and reports, and how certification outcomes gate votes.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const h = @import("harness.zig");

const Ctx = h.Ctx;
const epoch = h.default_epoch;

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

// commonware test_recovered_finalization_is_reported
test "voter recovered finalization is reported" {
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
            try stack.mailbox.recovered(gpa, .{ .finalization = try finalization.clone(gpa) });
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
