//! commonware `simplex/actors/voter/mod.rs` floor-journaling tests: a voter started from a
//! finalized floor journals it once, so a restart (from an older floor, the same floor, or
//! over a journal of our own votes) resumes at it.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const storage = @import("storage");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;
        const floor_view = 5;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            try h.soak(20 * std.time.ns_per_s, body);
        }

        /// A quorum finalization at the floor view with payload `hash(label)`.
        fn floor_finalization(ctx: Ctx, net: *const h.Network, label: []const u8) !h.Finalization {
            const proposal = h.proposal_at(epoch, floor_view, label);
            return h.build(ctx.gpa(), .finalization, net.schemes(), proposal, net.quorum());
        }

        /// commonware `restart_resumes_at_floor`: starts a voter from finalized `floor` over
        /// `partition` until it applies the floor, then restarts a fresh voter over the same
        /// partition from `restart` (null for genesis) and expects the journaled floor to be
        /// the active floor, reported anew.
        fn restart_resumes_at_floor(
            ctx: Ctx,
            net: *h.Network,
            partition: []const u8,
            floor: h.Finalization,
            restart: ?h.Finalization,
        ) !void {
            var first: h.VoterStack = undefined;
            try first.start(ctx, net, h.floor_start(partition, floor, std.math.maxInt(u64)));
            h.expect_at_floor(&first, ctx, .new(floor_view)) catch |err| {
                first.stop();
                return err;
            };
            first.stop();
            var restarted: h.VoterStack = undefined;
            const options = h.floor_start(partition, restart, std.math.maxInt(u64));
            try restarted.start(ctx, net, options);
            defer restarted.stop();
            try h.expect_at_floor(&restarted, ctx, .new(floor_view));
            try testing.expect(restarted.reporter.finalized(.new(floor_view)) != null);
        }

        /// commonware `journaled_finalizations`: the finalizations at `view` in `partition`.
        fn journaled_finalizations(
            ctx: Ctx,
            net: *const h.Network,
            partition: []const u8,
            view: u64,
        ) !u32 {
            const gpa = ctx.gpa();
            var page_cache: runtime.buffer.paged.CacheRef =
                try .init(gpa, h.page_size, h.page_cache_size);
            defer page_cache.deinit();
            const Journal = storage.journal.segmented.variable.Journal(h.Artifact);
            var replay = try Journal.init(gpa, ctx.storage, .{
                .partition = partition,
                .codec_config = net.schemes()[0].certificate_codec_config(),
                .cache_ref = &page_cache,
                .write_buffer = 1024 * 1024,
                .replay_buffer = 1024 * 1024,
            });
            errdefer replay.deinit();
            var count: u32 = 0;
            // Bounded by the journal's contents.
            while (try replay.next()) |entry| {
                var artifact = entry.item;
                defer artifact.deinit(gpa);
                if (artifact == .finalization and artifact.view().get() == view) count += 1;
            }
            var journal = try replay.finish();
            journal.deinit();
            return count;
        }

        // commonware test_voter_restart_lower_floor_keeps_journaled_floor: a restart from
        // genesis, below the journaled floor, resumes at the journaled floor.
        test "voter restart lower floor keeps journaled floor" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "voter_restart_lower_floor");
                    defer net.deinit();
                    const floor = try floor_finalization(ctx, &net, "journaled-floor-finalization");
                    const partition = "voter_restart_lower_floor";
                    try restart_resumes_at_floor(ctx, &net, partition, floor, null);
                }
            }.body);
        }

        // commonware test_voter_restart_same_floor_journals_once: restarting from the floor
        // already journaled does not journal it again.
        test "voter restart same floor journals once" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "voter_restart_same_floor");
                    defer net.deinit();
                    const partition = "voter_restart_same_floor";
                    const floor = try floor_finalization(ctx, &net, "same-floor-finalization");
                    const again = try floor.clone(gpa);
                    try restart_resumes_at_floor(ctx, &net, partition, floor, again);
                    const count = try journaled_finalizations(ctx, &net, partition, floor_view);
                    try testing.expectEqual(1, count);
                }
            }.body);
        }

        // commonware test_voter_floor_journaled_despite_journaled_votes: a journal holding
        // only our own vote above the floor does not make the floor durable, so the floor is
        // still journaled.
        test "voter floor journaled despite journaled votes" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    const gpa = ctx.gpa();
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "voter_floor_journaled_votes");
                    defer net.deinit();
                    const partition = "voter_floor_journaled_votes";
                    const voted = h.proposal_at(epoch, 7, "vote-above-floor");
                    var notarize = (try h.Notarize.sign(gpa, &net.schemes()[0], voted)).?;
                    var artifact: h.Artifact = .{ .notarize = notarize };
                    defer artifact.deinit(gpa);
                    try h.seed_journal(ctx, partition, &net.schemes()[0], .new(7), &.{artifact});
                    _ = &notarize;
                    const floor = try floor_finalization(ctx, &net, "floor-below-vote");
                    try restart_resumes_at_floor(ctx, &net, partition, floor, null);
                }
            }.body);
        }
    };
}
