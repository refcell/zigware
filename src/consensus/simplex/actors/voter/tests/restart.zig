//! commonware `simplex/actors/voter/mod.rs` restart-floor tests: how a configured finalized
//! floor and the replayed journal combine when a voter restarts.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const harness = @import("harness.zig");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const View = h.View;
        const Sha256 = h.Sha256;
        const epoch = h.default_epoch;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
                .timeout_ns = 20 * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{});
        }

        /// A proposal at `view` over `view - 1` with payload `hash(label)`.
        fn proposal(view: u64, label: []const u8) h.Proposal {
            return .init(.new(epoch, .new(view)), .new(view - 1), Sha256.hash(&.{label}));
        }

        /// A quorum finalization of `proposal(view, label)`.
        fn finalization(
            ctx: Ctx,
            net: *const h.Network,
            view: u64,
            label: []const u8,
        ) !h.Finalization {
            return h.build(
                ctx.gpa(),
                .finalization,
                net.schemes(),
                proposal(view, label),
                net.quorum(),
            );
        }

        fn seed_finalization(
            ctx: Ctx,
            net: *const h.Network,
            partition: []const u8,
            view: u64,
        ) !void {
            var stale = try finalization(ctx, net, view, "journal-finalization");
            defer stale.deinit(ctx.gpa());
            const artifact: h.Artifact = .{ .finalization = stale };
            try h.seed_journal(ctx, partition, &net.schemes()[0], .new(view), &.{artifact});
        }

        fn finalization_count(reporter: *h.Reporter, io: std.Io, view: u64) u32 {
            reporter.mutex.lockUncancelable(io);
            defer reporter.mutex.unlock(io);
            const entry = reporter.finalizations.get(.new(view)) orelse return 0;
            return entry.count;
        }

        // commonware test_voter_restart_newer_floor_skips_stale_journal
        test "voter restart newer floor skips stale journal" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "voter_restart_newer_floor");
                    defer net.deinit();
                    const partition = "voter_restart_newer_floor";
                    // A stale finalization the configured floor must hide from replay.
                    try seed_finalization(ctx, &net, partition, 3);
                    var stack: h.VoterStack = undefined;
                    const floor = try finalization(ctx, &net, 8, "newer-floor-finalization");
                    try stack.start(
                        ctx,
                        &net,
                        h.floor_start(partition, floor, std.math.maxInt(u64)),
                    );
                    defer stack.stop();
                    try h.expect_at_floor(&stack, ctx, .new(8));
                    try testing.expect(finalization_count(&stack.reporter, ctx.io(), 8) > 0);
                    try testing.expectEqual(0, finalization_count(&stack.reporter, ctx.io(), 3));
                }
            }.body);
        }

        // commonware test_voter_restart_floor_finalization_not_resent
        test "voter restart floor finalization not resent" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "voter_restart_floor_not_resent");
                    defer net.deinit();
                    // Observe the certificates the voter broadcasts.
                    const observer = net.keys()[1];
                    var channel = try net.oracle().control(observer).register(1, h.test_quota);
                    defer channel.sender.deinit();
                    defer channel.receiver.deinit();
                    try net.oracle().add_link(net.keys()[0], observer, .{
                        .latency = .from_millis(0),
                        .jitter = .from_millis(0),
                        .success_rate = 1.0,
                    });
                    var floor = try finalization(ctx, &net, 8, "floor");
                    defer floor.deinit(gpa);
                    var stack: h.VoterStack = undefined;
                    const partition = "voter_restart_floor_not_resent";
                    const options = h.floor_start(
                        partition,
                        try floor.clone(gpa),
                        std.math.maxInt(u64),
                    );
                    try stack.start(ctx, &net, options);
                    defer stack.stop();
                    try h.expect_at_floor(&stack, ctx, .new(8));
                    // A peer forwards the floor finalization again, then a new one ending the
                    // watch.
                    try stack.mailbox.recovered(gpa, .{ .finalization = try floor.clone(gpa) });
                    const next = try finalization(ctx, &net, 9, "next");
                    try stack.mailbox.recovered(gpa, .{ .finalization = next });
                    try expect_broadcasts_skip(ctx, &net, &channel.receiver, 8, 9);
                    try testing.expectEqual(1, finalization_count(&stack.reporter, ctx.io(), 8));
                    try testing.expectEqual(1, finalization_count(&stack.reporter, ctx.io(), 9));
                    try expect_updates_skip(ctx, &stack, 8, 9);
                }
            }.body);
        }

        /// Receives certificates on `receiver` until one at `until`; none may be at `skipped`.
        fn expect_broadcasts_skip(
            ctx: Ctx,
            net: *const h.Network,
            receiver: *h.Net.Receiver,
            skipped: u64,
            until: u64,
        ) !void {
            const cfg = net.schemes()[0].certificate_codec_config();
            // Bounded by the runner's timeout.
            while (true) {
                var message = try receiver.recv();
                defer message.deinit();
                var certificate = try codec.decode_cfg(
                    h.Certificate,
                    ctx.gpa(),
                    message.payload,
                    cfg,
                );
                defer certificate.deinit(ctx.gpa());
                const view = certificate.view().get();
                try testing.expect(view != skipped); // Floor finalization broadcast again.
                if (view == until) return;
            }
        }

        /// Receives resolver updates until one at `until`; none may be at `skipped`.
        fn expect_updates_skip(ctx: Ctx, stack: *h.VoterStack, skipped: u64, until: u64) !void {
            // Bounded by the runner's timeout.
            while (true) {
                const message = (try stack.next_resolver(ctx, 5_000)) orelse return error.TimedOut;
                defer message.discard();
                if (message != .updated) continue;
                const view = message.updated.certificate.view().get();
                try testing.expect(view != skipped); // Floor finalization reported again.
                if (view == until) return;
            }
        }

        // commonware test_voter_restart_older_floor_ignored_for_newer_journal
        test "voter restart older floor ignored for newer journal" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "voter_restart_older_floor");
                    defer net.deinit();
                    const partition = "voter_restart_older_floor";
                    // A newer journaled finalization lets replay advance past the configured floor.
                    try seed_finalization(ctx, &net, partition, 8);
                    var stack: h.VoterStack = undefined;
                    const floor = try finalization(ctx, &net, 3, "older-floor-finalization");
                    try stack.start(
                        ctx,
                        &net,
                        h.floor_start(partition, floor, std.math.maxInt(u64)),
                    );
                    defer stack.stop();
                    try h.expect_at_floor(&stack, ctx, .new(8));
                    try testing.expect(finalization_count(&stack.reporter, ctx.io(), 8) > 0);
                    // The configured floor is reported before replay supersedes it.
                    try testing.expect(finalization_count(&stack.reporter, ctx.io(), 3) > 0);
                }
            }.body);
        }

        // commonware test_voter_replay_floor_does_not_move_during_replay
        test "voter replay floor does not move during replay" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "voter_replay_floor_static");
                    defer net.deinit();
                    const partition = "voter_replay_floor_static";
                    // Two above-floor artifacts in one section: the finalization advances the last
                    // finalized view, but the finalize vote after it must still replay.
                    const journaled = proposal(8, "same-section-finalize");
                    const quorum = net.quorum();
                    var certificate = try h.build(
                        gpa,
                        .finalization,
                        net.schemes(),
                        journaled,
                        quorum,
                    );
                    defer certificate.deinit(gpa);
                    const vote = (try h.Finalize.sign(gpa, &net.schemes()[0], journaled)).?;
                    try h.seed_journal(ctx, partition, &net.schemes()[0], .new(8), &.{
                        .{ .finalization = certificate },
                        .{ .finalize = vote },
                    });
                    var stack: h.VoterStack = undefined;
                    const floor = try finalization(ctx, &net, 3, "static-replay-floor");
                    try stack.start(
                        ctx,
                        &net,
                        h.floor_start(partition, floor, std.math.maxInt(u64)),
                    );
                    defer stack.stop();
                    try h.expect_at_floor(&stack, ctx, .new(8));
                    const signers = stack.reporter.votes(.new(8)).finalize;
                    try testing.expect(signers & 1 != 0); // The above-floor finalize vote replayed.
                    const payload = stack.reporter.vote_payloads.get(.{
                        .view = .new(8),
                        .signer = 0,
                        .finalize = true,
                    }) orelse return error.NotReplayed;
                    try testing.expectEqualDeep(journaled.payload, payload);
                }
            }.body);
        }

        /// Expects the next resolver update to be the finalization `expected`, byte for byte.
        fn expect_finalization(
            ctx: Ctx,
            stack: *h.VoterStack,
            expected: *const h.Finalization,
        ) !void {
            const gpa = ctx.gpa();
            const message = (try stack.next_resolver(ctx, 5_000)) orelse return error.TimedOut;
            defer message.discard();
            try testing.expect(message == .updated);
            try testing.expect(message.updated.certificate == .finalization);
            const want = try codec.encode(h.Finalization, gpa, expected.*);
            defer gpa.free(want);
            const got = try codec.encode(
                h.Finalization,
                gpa,
                message.updated.certificate.finalization,
            );
            defer gpa.free(got);
            try testing.expectEqualSlices(u8, want, got);
        }

        // commonware populate_resolver_on_restart: a finalization the voter journaled is handed to
        // the resolver again after a restart, and the voter resumes past it.
        test "voter populate resolver on restart" {
            try h.covers(.schemes);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "populate_resolver_on_restart_test");
                    defer net.deinit();
                    const options: h.Options = .{
                        .partition = "voter_populate_resolver_on_restart_test",
                        .batcher_capacity = 8,
                    };
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, options);
                    defer stack.stop();
                    try stack.expect_update(ctx, 1, 0);
                    try stack.expect_replayed(ctx);
                    const subject = proposal(2, "finalize_without_notarization");
                    var expected = try h.build(
                        gpa,
                        .finalization,
                        net.schemes(),
                        subject,
                        net.quorum(),
                    );
                    defer expected.deinit(gpa);
                    try stack.mailbox.recovered(gpa, .{ .finalization = try expected.clone(gpa) });
                    try expect_finalization(ctx, &stack, &expected);
                    try stack.restart(ctx, &net, options);
                    try stack.expect_update(ctx, 3, 2);
                    try expect_finalization(ctx, &stack, &expected);
                }
            }.body);
        }

        // commonware startup_update_timeout_hint_nullifies_recovered_view: a leader-nullify timeout
        // hint sent right after the restarted voter's first update makes it nullify the recovered
        // view at once, although every timer is 10 s or more.
        test "voter startup update timeout hint nullifies recovered view" {
            try h.covers(.schemes_round_robin);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "startup_update_timeout_hint");
                    defer net.deinit();
                    const options: h.Options = .{
                        .partition = "voter_startup_update_timeout_hint_nullify",
                        // Long deadlines prove the nullify comes from the hint, not a timer.
                        .leader_timeout_ms = 10_000,
                        .certification_timeout_ms = 10_000,
                        .timeout_retry_ms = 60 * 60 * 1_000,
                        .batcher_capacity = 32,
                    };
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, options);
                    defer stack.stop();
                    _ = try stack.next_update(ctx, 5_000);
                    _ = try h.advance_to_view(&stack, ctx, &net, 3);
                    try stack.restart(ctx, &net, options);
                    const first = (try stack.next_batcher(ctx, 5_000)) orelse return error.TimedOut;
                    try testing.expect(first == .update);
                    try testing.expectEqual(3, first.update.current.get());
                    try testing.expectEqual(2, first.update.finalized.get());
                    try stack.mailbox.timeout(.new(epoch, .new(3)), .leader_nullify);
                    // Each wait is bounded by 1 s (commonware's whole-loop deadline) and the
                    // batcher
                    // sees only a handful of messages before the nullify.
                    var received: u32 = 0;
                    while (received < 64) : (received += 1) {
                        const message = (try stack.next_batcher(ctx, 1_000)) orelse break;
                        if (message != .constructed or message.constructed != .nullify) continue;
                        if (message.constructed.nullify.view().get() == 3) return;
                    }
                    return error.NoImmediateNullify;
                }
            }.body);
        }

        // commonware test_replay_preserves_exhausted_skip_budget: replaying a skipped term keeps
        // its
        // budget spent, so a leader-nullify hint waits; finalizing the skipped view then makes the
        // pending hint fire before the leader deadline.
        test "voter replay preserves exhausted skip budget" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "voter_replay_skip_budget");
                    defer net.deinit();
                    const partition = "voter_replay_skip_budget";
                    // The artifacts of skipping view 1: replaying the nullification enters view 2
                    // without moving the finalized floor.
                    const skipped: h.Round = .new(epoch, .new(1));
                    const quorum = net.quorum();
                    var nullification = try h.build(
                        gpa,
                        .nullification,
                        net.schemes(),
                        skipped,
                        quorum,
                    );
                    defer nullification.deinit(gpa);
                    const local = (try h.Nullify.sign(gpa, &net.schemes()[0], skipped)).?;
                    try h.seed_journal(ctx, partition, &net.schemes()[0], .new(1), &.{
                        .{ .nullify = local },
                        .{ .nullification = nullification },
                    });
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, h.floor_start(partition, null, 1));
                    defer stack.stop();
                    try stack.expect_update(ctx, 2, 0);
                    // The replayed term spent budget 1, so this hint must stay pending.
                    try stack.mailbox.timeout(.new(epoch, .new(2)), .leader_nullify);
                    try testing.expect(!try stack.nullify_within(ctx, 2, 1_000));
                    // Finalizing view 1 makes the retained hint eligible before the 5 s deadline.
                    const payload = Sha256.hash(&.{"restore-skip-budget"});
                    const subject: h.Proposal = .init(skipped, .zero(), payload);
                    const restore = try h.build(gpa, .finalization, net.schemes(), subject, quorum);
                    try stack.mailbox.recovered(gpa, .{ .finalization = restore });
                    try testing.expect(try stack.nullify_within(ctx, 2, 1_000));
                }
            }.body);
        }
    };
}
