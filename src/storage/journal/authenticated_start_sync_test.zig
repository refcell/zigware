//! commonware's `journal/authenticated.rs` in-flight `start_sync` tests, with
//! `runtime.storage.mocks.DelayedSync` holding started syncs (`DelayedSyncContext`). Opening
//! a journal syncs with blocking syncs here, which the mock passes, so no open needs
//! `drive_pending_syncs`.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const merkle = @import("../merkle/mod.zig");
const fixed = @import("contiguous/fixed.zig");
const authenticated_journal = @import("authenticated_journal.zig");

const gpa = testing.allocator;
const Context = runtime.deterministic.Context;
const CacheRef = runtime.buffer.paged.CacheRef;
const Op = struct { u8, [32]u8, [32]u8 };
const Journal = authenticated_journal.Journal(
    merkle.mmr.Family,
    fixed.Journal(Op),
    cryptography.Sha256,
);

fn create_operation(index: u8) Op {
    return .{ 0, @splat(index), @splat(index +% 1) };
}

fn is_commit(op: Op) bool {
    return op[0] == 1;
}

const Fixture = struct {
    inner: runtime.storage.memory.Storage,
    pending: runtime.storage.mocks.DelayedSync,
    delayed: runtime.storage.mocks.DelayedSynced,
    journal_cache: CacheRef,
    merkle_cache: CacheRef,

    fn init(self: *Fixture, ctx: Context) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
        self.journal_cache = try CacheRef.init(gpa, 101, 11);
        errdefer self.journal_cache.deinit();
        self.merkle_cache = try CacheRef.init(gpa, 101, 11);
    }

    fn deinit(self: *Fixture) void {
        self.merkle_cache.deinit();
        self.journal_cache.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    fn open(self: *Fixture) !Journal {
        return self.open_on(self.delayed.storage());
    }

    fn open_on(self: *Fixture, storage: runtime.storage.Storage) !Journal {
        const merkle_cfg = self.merkle_config();
        const journal_cfg = self.journal_config();
        return Journal.init(gpa, storage, merkle_cfg, journal_cfg, is_commit, .forward_fold);
    }

    fn merkle_config(self: *Fixture) merkle.full.Config {
        return .{
            .journal_partition = "mmr-journal",
            .metadata_partition = "mmr-metadata",
            .items_per_blob = 11,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &self.merkle_cache,
        };
    }

    fn journal_config(self: *Fixture) fixed.Config {
        return .{
            .partition = "journal",
            .items_per_blob = 7,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &self.journal_cache,
        };
    }
};

fn waiting(ctx: Context, completion: runtime.storage.Completion) anyerror!void {
    _ = ctx;
    try completion.wait_release();
}

/// A sync completion must not block journal use while the backend sync is pending.
fn overlaps_work(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var journal = try f.open();
    for (0..4) |i| _ = try journal.append(create_operation(@intCast(i)));
    const starts_before = f.pending.starts();
    const completion = try journal.start_sync();
    try testing.expect(f.pending.starts() > starts_before);
    try testing.expectEqual(@as(u64, 0), f.pending.completions());
    const waiter = try ctx.child("await_sync").spawn(waiting, .{completion});
    while (f.pending.entered() == 0) try ctx.sleep(.fromMilliseconds(1));
    // Appends and reads complete before the sync does.
    _ = try journal.append(create_operation(4));
    try testing.expectEqual(create_operation(0), try journal.read(0));
    try testing.expectEqual(@as(u64, 0), f.pending.completions());
    f.pending.unblock();
    try try waiter.join();
    // The mid-sync append is durable after the next sync.
    _ = try journal.append(.{ 1, @splat(0), @splat(0) });
    try (try journal.start_sync()).wait_release();
    const root = try journal.root(0);
    journal.deinit();
    var reopened = try f.open();
    defer reopened.deinit();
    try testing.expectEqual(@as(u64, 6), reopened.size());
    try testing.expectEqual(root, try reopened.root(0));
}

test "authenticated start_sync overlaps work (test_start_sync_overlaps_work)" {
    try soak_context(overlaps_work, .{});
}

/// A failed in-flight sync surfaces through its completion and the next durability op.
fn failure_propagates(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    f.pending.unblock(); // Pass syncs through so opening does not park.
    var journal = try f.open();
    defer journal.deinit();
    for (0..4) |i| _ = try journal.append(create_operation(@intCast(i)));
    f.pending.arm_fail();
    const completion = try journal.start_sync();
    try testing.expectError(error.Io, completion.wait_release());
    const starts_before = f.pending.starts();
    try testing.expectError(error.Io, journal.commit());
    // The surfaced error is the retained failure, not a fresh sync's.
    try testing.expectEqual(starts_before, f.pending.starts());
}

test "authenticated start_sync failure propagates (test_start_sync_failure_propagates)" {
    try soak_context(failure_propagates, .{});
}

/// Release parked syncs until `completion` completes (commonware `drive_pending_syncs`), then
/// return its result.
fn drive(f: *Fixture, completion: runtime.storage.Completion) !void {
    while (completion.is_pending()) f.pending.release_all();
    try completion.wait_release();
}

/// A Merkle-only sync failure fails the joined completion although the items' sync succeeded.
fn merkle_failure_fails_handle(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var journal = try f.open();
    defer journal.deinit();
    for (0..4) |i| _ = try journal.append(create_operation(@intCast(i)));
    // Prove the appends durable, then dirty only the Merkle journal: commit syncs the items
    // but merely flushes Merkle nodes.
    try drive(&f, try journal.start_sync());
    for (4..6) |i| _ = try journal.append(create_operation(@intCast(i)));
    try journal.commit();
    // The items are durable, so their only parked sync is the watermark advance: release it,
    // then fail the Merkle journal's syncs.
    const completion = try journal.start_sync();
    f.pending.next().release({});
    f.pending.fail_all();
    try testing.expectError(error.Io, completion.wait_release());
    // The Merkle journal retained the failure: the next sync resurfaces it.
    try testing.expectError(error.Io, journal.sync());
}

test "authenticated Merkle-only sync failure fails the joined completion" {
    // commonware `test_start_sync_merkle_failure_fails_handle`.
    try soak_context(merkle_failure_fails_handle, .{});
}

/// The Merkle journal's recovery watermark persisted in `f`'s backing storage.
fn merkle_watermark(f: *Fixture) !?u64 {
    const Nodes = fixed.Journal(cryptography.Sha256.Digest);
    return Nodes.persisted_watermark(gpa, f.inner.storage(), "mmr-journal");
}

/// Reopening recovers the Merkle journal bounded, so publication persists its recovery
/// watermark even when no node is flushed.
fn reopen_persists_merkle_watermark(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    // Persist operations while the Merkle recovery watermark still describes genesis.
    var journal = try f.open();
    for (0..5) |i| _ = try journal.append(create_operation(@intCast(i)));
    _ = try journal.append(.{ 1, @splat(0), @splat(0) });
    try drive(&f, try journal.start_sync());
    const size = journal.merkle.size();
    journal.deinit();
    // Confirm the first publication left the Merkle watermark at genesis.
    try testing.expectEqual(@as(?u64, 0), try merkle_watermark(&f));
    // Reopening publishes the recovered Merkle prefix even without new node writes.
    var reopened = try f.open_on(f.inner.storage());
    try testing.expectEqual(size, reopened.merkle.size());
    reopened.deinit();
    try testing.expectEqual(@as(?u64, size), try merkle_watermark(&f));
}

test "authenticated reopen persists the Merkle watermark" {
    // commonware `test_reopen_persists_merkle_watermark`.
    try soak_context(reopen_persists_merkle_watermark, .{});
}

const commit_op: Op = .{ 1, @splat(0), @splat(0) };

/// Commits 30 operations and prunes to 20, so the Merkle metadata holds a boundary and pins.
/// With `recommit`, commits 6 more, which syncs the operation log but merely flushes Merkle
/// nodes; without it, syncs again.
fn setup(ctx: Context, journal: *Journal, recommit: bool, done: *bool) anyerror!void {
    _ = ctx;
    defer done.* = true;
    for (0..30) |i| _ = try journal.append(create_operation(@intCast(i)));
    _ = try journal.append(commit_op);
    try journal.sync();
    _ = try journal.prune(20);
    if (!recommit) return journal.sync();
    for (30..36) |i| _ = try journal.append(create_operation(@intCast(i)));
    _ = try journal.append(commit_op);
    try journal.commit();
}

/// Runs `setup` while releasing every sync it parks (commonware `drive_pending_syncs`).
fn drive_setup(ctx: Context, f: *Fixture, journal: *Journal, recommit: bool) !void {
    var done = false;
    const task = try ctx.child("setup").spawn(setup, .{ journal, recommit, &done });
    while (!done) {
        f.pending.release_all();
        try ctx.sleep(.fromMilliseconds(1));
    }
    try (try task.join());
    f.pending.release_all();
}

/// A failed Merkle sync nobody observed surfaces at destroy before anything is removed, so the
/// journal reopens at its last commit (commonware issue 5668).
fn destroy_observes_failed_merkle_sync(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var journal = try f.open();
    try drive_setup(ctx, &f, &journal, true);
    const bounds = journal.get_bounds();
    const root = try journal.root(0);
    try testing.expect(bounds.start > 0);
    // Start a sync and drop its completion. The operation log's only parked sync is its
    // watermark advance: it lands, and every Merkle journal sync fails.
    (try journal.start_sync()).release();
    try testing.expect(f.pending.parked() > 1);
    f.pending.next().release({});
    f.pending.fail_all();
    f.pending.unblock();
    // Destroy returns the failure, and the last commit survives it.
    try testing.expectError(error.Io, journal.destroy());
    var reopened = try f.open();
    try testing.expectEqual(bounds, reopened.get_bounds());
    try testing.expectEqual(root, try reopened.root(0));
    try reopened.destroy();
}

test "authenticated destroy observes a failed Merkle sync before removal" {
    // commonware `issue_5668_regression_destroy_observes_failed_merkle_sync_before_removal`.
    try soak_context(destroy_observes_failed_merkle_sync, .{});
}

fn destroying(ctx: Context, journal: *Journal, done: *bool) anyerror!void {
    _ = ctx;
    defer done.* = true;
    try journal.destroy();
}

/// A destroy dropped while the operation journal's clear is still being staged has removed
/// nothing, so the pruned journal reopens at its last commit (commonware issue 5668).
fn destroy_stages_journal_clear(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var journal = try f.open();
    try drive_setup(ctx, &f, &journal, false);
    const bounds = journal.get_bounds();
    const root = try journal.root(0);
    try testing.expect(bounds.start > 0);
    // Park destroy's first durability operation, then drop the destroy there.
    try f.pending.arm();
    var done = false;
    const task = try ctx.child("destroy").spawn(destroying, .{ &journal, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done);
    try testing.expectEqual(@as(u64, 1), f.pending.calls());
    const ended = task.abort();
    if (ended) |result| result catch {} else |_| {}
    f.pending.unblock();
    // The unfinished clear is not durable, so the last commit reopens.
    var reopened = try f.open();
    try testing.expectEqual(bounds, reopened.get_bounds());
    try testing.expectEqual(root, try reopened.root(0));
    try reopened.destroy();
}

test "authenticated destroy stages the journal clear before removal" {
    // commonware `issue_5668_regression_destroy_stages_journal_clear_before_removal`.
    try soak_context(destroy_stages_journal_clear, .{});
}

fn finishing(ctx: Context, recovery: *Journal.Recovery, out: *?Journal) anyerror!void {
    _ = ctx;
    out.* = try recovery.finish();
}

/// Seeds the Merkle structure with one leaf and the operation journal with one operation.
fn seed_sync_order(f: *Fixture, merkle_storage: runtime.storage.Storage) !void {
    const hasher = Journal.Hasher.init(.forward_fold);
    var structure = try Journal.Merkle.init(gpa, merkle_storage, &hasher, f.merkle_config());
    defer structure.deinit();
    var batch = try structure.new_batch();
    const leaf: [32]u8 = @splat(1);
    batch.add(gpa, &hasher, &leaf) catch |err| {
        batch.deinit(gpa);
        return err;
    };
    const merkleized = try batch.merkleize(&structure, &hasher);
    defer merkleized.release(gpa);
    try structure.apply_batch(merkleized);
    try structure.sync();
    var items = try fixed.Journal(Op).init(gpa, f.delayed.storage(), f.journal_config());
    defer items.deinit();
    _ = try items.append(create_operation(1));
    try items.sync();
}

/// Finishing recovery syncs the operations before any Merkle sync.
fn initialization_sync_order(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    // Control operation and Merkle durability independently.
    var merkle_pending: runtime.storage.mocks.DelayedSync = .init(gpa, ctx.io());
    defer merkle_pending.deinit();
    var merkle_delayed: runtime.storage.mocks.DelayedSynced =
        .init(gpa, f.inner.storage(), &merkle_pending);
    try seed_sync_order(&f, merkle_delayed.storage());
    // Keep no Merkle leaf, so finishing repairs the structure from the one operation.
    const hasher = Journal.Hasher.init(.forward_fold);
    var structure = try Journal.Merkle.Recovery.prepare(
        gpa,
        merkle_delayed.storage(),
        &hasher,
        f.merkle_config(),
        .{ .at_most = 0 },
    );
    const Items = fixed.Journal(Op);
    const items = Items.recover(gpa, f.delayed.storage(), f.journal_config(), null) catch |err| {
        structure.deinit();
        return err;
    };
    var recovery: Journal.Recovery = .{
        .gpa = gpa,
        .journal = items,
        .merkle = structure,
        .hasher = hasher,
        .selected_end = 1,
    };
    try f.pending.arm();
    try merkle_pending.arm();
    var out: ?Journal = null;
    const task = try ctx.child("finish").spawn(finishing, .{ &recovery, &out });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(out == null);
    try testing.expectEqual(@as(u64, 1), f.pending.calls());
    try testing.expectEqual(@as(u64, 0), merkle_pending.calls());
    // Complete both syncs and check the published operation prefix.
    f.pending.unblock();
    merkle_pending.unblock();
    try (try task.join());
    var journal = out.?;
    try testing.expectEqual(@as(u64, 0), journal.get_bounds().start);
    try testing.expectEqual(@as(u64, 1), journal.get_bounds().end);
    try journal.destroy();
}

test "authenticated initialization syncs operations before Merkle repair" {
    // commonware `test_initialization_syncs_operations_before_merkle_repair`.
    try soak_context(initialization_sync_order, .{});
}

/// Runs `function` with `args` on a deterministic runner once per `-Dfuzz-soak` round, from the
/// runner's default seed (`runtime.deterministic.soak`).
fn soak_context(comptime function: anytype, args: anytype) !void {
    const Args = @TypeOf(args);
    try runtime.deterministic.soak(gpa, .{}, args, struct {
        fn run(context: Args, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start_context(function, context));
        }
    }.run);
}
