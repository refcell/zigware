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
        return Merkle.init(gpa, self.delayed.storage(), &support.hasher, .{
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
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(observes_clean_start_sync_failure, .{}));
}
