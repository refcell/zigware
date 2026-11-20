//! commonware `simplex/actors/voter/mod.rs` backfill tests: certificates for views behind
//! the voter's finalized view or its journal floor. commonware runs each over six signing
//! schemes, as `Tests(h)` does over each fixture in `harness.fixtures`.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const harness = @import("harness.zig");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const Sha256 = h.Sha256;
        const epoch = h.default_epoch;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            try h.soak(30 * std.time.ns_per_s, body);
        }

        /// A proposal at `view` over `parent` with payload `hash(label)`.
        fn proposal(view: u64, parent: u64, label: []const u8) h.Proposal {
            return .init(.new(epoch, .new(view)), .new(parent), Sha256.hash(&.{label}));
        }

        /// Hands the voter a quorum certificate of `kind` over `proposal(view, parent, label)`.
        fn recover(
            ctx: Ctx,
            net: *const h.Network,
            stack: *h.VoterStack,
            comptime kind: std.meta.Tag(h.Certificate),
            view: u64,
            parent: u64,
            label: []const u8,
        ) !void {
            const gpa = ctx.gpa();
            const subject = proposal(view, parent, label);
            const signed = try h.build(gpa, kind, net.schemes(), subject, net.quorum());
            try stack.mailbox.recovered(gpa, @unionInit(h.Certificate, @tagName(kind), signed));
        }

        // commonware stale_backfill: after jumping to finalized view 100, an old notarization (view
        // 50) from the resolver is ignored, and a later finalization (view 300) still applies.
        test "voter stale backfill" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "consensus");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .partition = "test",
                        .leader_timeout_ms = 5_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = 60 * 60 * 1_000,
                        .propose_latency_ms = 10.0,
                        .verify_latency_ms = 10.0,
                        .certify_latency_ms = 10.0,
                        .batcher_capacity = 1024,
                        .resolver_capacity = 10,
                    });
                    defer stack.stop();
                    try stack.expect_update(ctx, 1, 0);
                    try recover(ctx, &net, &stack, .finalization, 100, 50, "test");
                    try stack.expect_update(ctx, 101, 100);
                    try stack.expect_replayed(ctx);
                    try stack.expect_updated(ctx, .finalization, 100);
                    // An old notarization the voter must ignore, then a newer finalization.
                    try recover(ctx, &net, &stack, .notarization, 50, 49, "test2");
                    try recover(ctx, &net, &stack, .finalization, 300, 100, "test3");
                    try stack.expect_update(ctx, 301, 300);
                    try stack.expect_updated(ctx, .finalization, 300);
                }
            }.body);
        }

        // commonware append_old_interesting_view: after pruning sets the journal floor near view
        // 45,
        // a notarization below it (view 42) that is still above the finalized view minus retention
        // is processed without the journal rejecting the old section.
        test "voter append old interesting view" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "test_prune_panic");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .certification_timeout_ms = 1_000,
                        .timeout_retry_ms = 1_000,
                        .batcher_capacity = 10,
                    });
                    defer stack.stop();
                    try stack.expect_update(ctx, 1, 0);
                    try recover(ctx, &net, &stack, .finalization, 50, 49, "test");
                    try stack.expect_update(ctx, 51, 50);
                    try stack.expect_replayed(ctx);
                    try stack.expect_updated(ctx, .finalization, 50);
                    // The journal floor target: 50 - retention (10) + 5.
                    try recover(ctx, &net, &stack, .notarization, 45, 44, "test2");
                    try stack.expect_updated(ctx, .notarization, 45);
                    try recover(ctx, &net, &stack, .notarization, 42, 41, "test3");
                    try stack.expect_updated(ctx, .notarization, 42);
                    try recover(ctx, &net, &stack, .finalization, 100, 99, "test4");
                    try stack.expect_update(ctx, 101, 100);
                    try stack.expect_updated(ctx, .finalization, 100);
                }
            }.body);
        }

        // commonware finalization_without_notarization_certificate: a finalization alone finalizes
        // its view and is reported, without any notarization being reported.
        test "voter finalization without notarization certificate" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "consensus");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{});
                    defer stack.stop();
                    try stack.expect_update(ctx, 1, 0);
                    const subject = proposal(2, 1, "finalize_without_notarization");
                    var expected = try h.build(
                        gpa,
                        .finalization,
                        net.schemes(),
                        subject,
                        net.quorum(),
                    );
                    defer expected.deinit(gpa);
                    try stack.mailbox.recovered(gpa, .{ .finalization = try expected.clone(gpa) });
                    try expect_finalization_update(ctx, &stack, 2);
                    try expect_reported(ctx, &stack, &expected);
                    stack.reporter.mutex.lockUncancelable(ctx.io());
                    defer stack.reporter.mutex.unlock(ctx.io());
                    try testing.expectEqual(0, stack.reporter.notarizations.count());
                }
            }.body);
        }

        /// Skips resolver messages until a finalization update, which must be at `view`.
        fn expect_finalization_update(ctx: Ctx, stack: *h.VoterStack, view: u64) !void {
            // Bounded by the per-message wait.
            while (true) {
                const message = (try stack.next_resolver(ctx, 5_000)) orelse return error.TimedOut;
                defer message.discard();
                if (message != .updated or message.updated.certificate != .finalization) continue;
                try testing.expectEqual(view, message.updated.certificate.view().get());
                return;
            }
        }

        /// Waits until the reporter holds a finalization at `expected`'s view equal to `expected`.
        fn expect_reported(ctx: Ctx, stack: *h.VoterStack, expected: *const h.Finalization) !void {
            const gpa = ctx.gpa();
            const want = try codec.encode(h.Finalization, gpa, expected.*);
            defer gpa.free(want);
            var waited: u64 = 0;
            while (waited < 500) : (waited += 1) {
                if (try stack.reporter.finalization(expected.view())) |reported| {
                    var owned = reported;
                    defer owned.deinit(gpa);
                    const got = try codec.encode(h.Finalization, gpa, owned);
                    defer gpa.free(got);
                    try testing.expectEqualSlices(u8, want, got);
                    return;
                }
                try ctx.sleep(.fromMilliseconds(10));
            }
            return error.TimedOut;
        }
    };
}
