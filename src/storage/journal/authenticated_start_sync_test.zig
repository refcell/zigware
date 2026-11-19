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
        const merkle_config: merkle.full.Config = .{
            .journal_partition = "mmr-journal",
            .metadata_partition = "mmr-metadata",
            .items_per_blob = 11,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &self.merkle_cache,
        };
        const journal_config: fixed.Config = .{
            .partition = "journal",
            .items_per_blob = 7,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &self.journal_cache,
        };
        const storage = self.delayed.storage();
        return Journal.init(gpa, storage, merkle_config, journal_config, is_commit, .forward_fold);
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
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(overlaps_work, .{}));
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
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(failure_propagates, .{}));
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
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(merkle_failure_fails_handle, .{}));
}
