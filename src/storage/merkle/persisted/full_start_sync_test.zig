//! In-flight `start_sync` tests of `full.zig`, ported from commonware's
//! `storage/src/merkle/persisted/full.rs`, with `runtime.storage.mocks.DelayedSync` holding
//! started syncs (`DelayedSyncContext`). Opening syncs with blocking syncs, which the mock
//! passes, so no open needs `drive_pending_syncs`.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../mod.zig");
const support = @import("full_test.zig");

const gpa = support.gpa;
const Context = runtime.deterministic.Context;
const Merkle = support.Merkle(merkle.mmr.Family);

const Fixture = struct {
    inner: runtime.storage.memory.Storage,
    pending: runtime.storage.mocks.DelayedSync,
    delayed: runtime.storage.mocks.DelayedSynced,
    cache_ref: runtime.buffer.paged.CacheRef,

    fn init(self: *Fixture, ctx: Context) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
        self.cache_ref = try .init(gpa, 111, 5);
    }

    fn deinit(self: *Fixture) void {
        self.cache_ref.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    fn open(self: *Fixture) !Merkle {
        return self.open_family(merkle.mmr.Family, self.delayed.storage());
    }

    fn open_family(
        self: *Fixture,
        comptime F: type,
        storage: runtime.storage.Storage,
    ) !support.Merkle(F) {
        return support.Merkle(F).init(gpa, storage, &support.hasher, .{
            .journal_partition = "journal-partition",
            .metadata_partition = "metadata-partition",
            .items_per_blob = 7,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &self.cache_ref,
        });
    }

    /// Release parked syncs until `completion` completes (commonware `drive_pending_syncs`).
    fn drive(self: *Fixture, completion: runtime.storage.Completion) !void {
        while (completion.is_pending()) self.pending.release_all();
        try completion.wait_release();
    }
};

fn observes_clean_start_sync_failure(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    {
        var structure = try f.open();
        defer structure.deinit();
        // Complete the data sync after the checkpoint has sampled its durable boundary.
        try support.add_digests(merkle.mmr.Family, &structure, 0, 1);
        const completion = try structure.start_sync();
        try testing.expect(f.pending.parked() > 0);
        try f.drive(completion);
    }
    var structure = try f.open();
    defer structure.deinit();
    // The reopened tree has no new nodes, but a started sync can still fail.
    try testing.expect(!structure.journal_dirty);
    const completion = try structure.start_sync();
    try testing.expect(f.pending.parked() > 0);
    f.pending.fail_all();
    completion.release();
    // Full sync must report a failure from an unobserved completion.
    try testing.expectError(error.Io, structure.sync());
}

test "full sync observes a clean start_sync failure" {
    // commonware `test_full_sync_observes_clean_start_sync_failure`.
    try soak_body(observes_clean_start_sync_failure);
}

fn DestroyObservesFailedSync(comptime F: type) type {
    return struct {
        fn pruning(ctx: Context, structure: *support.Merkle(F), done: *bool) anyerror!void {
            _ = ctx;
            defer done.* = true;
            try support.add_digests(F, structure, 0, 100);
            try structure.prune(60);
        }

        fn body(ctx: Context) !void {
            var f: Fixture = undefined;
            try f.init(ctx);
            defer f.deinit();
            // Prune a tree of 100 leaves to 60, so the metadata holds the boundary and the pins
            // for nodes the journal has pruned.
            var structure = try f.open_family(F, f.delayed.storage());
            var destroyed = false;
            defer if (!destroyed) structure.deinit();
            // Rollovers wait on parked syncs, so release them until the prune is done
            // (commonware `drive_pending_syncs`).
            var done = false;
            const prune = try ctx.child("prune").spawn(pruning, .{ &structure, &done });
            while (!done) {
                f.pending.release_all();
                try ctx.sleep(.fromMilliseconds(1));
            }
            try try prune.join();
            const root = try structure.root(&support.hasher, 0);
            // Start a sync of one more leaf, drop its handle, and fail it.
            try support.add_digests(F, &structure, 100, 101);
            const completion = try structure.start_sync();
            completion.release();
            try testing.expect(f.pending.parked() > 0);
            f.pending.fail_all();
            f.pending.unblock();
            // Destroy returns the failure and the synced tree survives it.
            destroyed = true;
            try testing.expectError(error.Io, structure.destroy());
            var reopened = try f.open_family(F, f.inner.storage());
            defer reopened.destroy() catch unreachable; // Memory storage removes infallibly.
            try testing.expectEqual(@as(u64, 100), reopened.leaves());
            try testing.expect(root.eql(try reopened.root(&support.hasher, 0)));
        }
    };
}

test "issue 5668: destroy observes a failed sync before removal (mmr)" {
    // commonware `issue_5668_regression_destroy_observes_failed_sync_before_removal_mmr`.
    try soak_body(DestroyObservesFailedSync(merkle.mmr.Family).body);
}

test "issue 5668: destroy observes a failed sync before removal (mmb)" {
    // commonware `issue_5668_regression_destroy_observes_failed_sync_before_removal_mmb`.
    try soak_body(DestroyObservesFailedSync(merkle.mmb.Family).body);
}

/// Runs `body` on `-Dfuzz-soak` deterministic runners (one, the default seed, in a plain
/// `zig build test`) through `runtime.deterministic.soak`, which names a failing seed.
fn soak_body(comptime body: fn (Context) anyerror!void) !void {
    try runtime.deterministic.soak(gpa, .{}, {}, struct {
        fn run(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start_context(body, .{}));
        }
    }.run);
}
