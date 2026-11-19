//! commonware `qmdb/keyless/fixed.rs`'s in-flight `start_sync` tests, with
//! `runtime.storage.mocks.DelayedSync` holding started syncs (`DelayedSyncContext`). An
//! operation commonware polls with `now_or_never` runs here as a task on the deterministic
//! runtime, which the test checks has not finished before it releases the parked syncs.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const value = @import("../value.zig");
const keyless = @import("mod.zig");
const verify = @import("../verify.zig");

const gpa = testing.allocator;
const Context = runtime.deterministic.Context;
const CacheRef = runtime.buffer.paged.CacheRef;
const metrics = runtime.telemetry.metrics;
const U64 = utils.sequence.U64;
const F = merkle.mmr.Family;
const Encoding = value.Fixed(U64);
const Journal = fixed.Journal(keyless.Operation(F, Encoding));
const Db = keyless.Db(F, Encoding, Journal, cryptography.Sha256);

const Fixture = struct {
    inner: runtime.storage.memory.Storage,
    pending: runtime.storage.mocks.DelayedSync,
    delayed: runtime.storage.mocks.DelayedSynced,
    cache: CacheRef,
    registry: metrics.Registry,

    fn init(self: *Fixture, ctx: Context) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
        self.cache = try CacheRef.init(gpa, 1024, 8);
        self.registry = metrics.Registry.init(gpa);
    }

    fn deinit(self: *Fixture) void {
        self.registry.deinit();
        self.cache.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    fn open(self: *Fixture) !Db {
        return self.open_with(.{ .items_per_blob = 1000, .page_size = 1024 }, null);
    }

    const Layout = struct { items_per_blob: u64, page_size: u16 };

    fn open_with(self: *Fixture, layout: Layout, max_size: ?u64) !Db {
        if (self.cache.page_size != layout.page_size) {
            self.cache.deinit();
            self.cache = try CacheRef.init(gpa, layout.page_size, 8);
        }
        self.registry.deinit();
        self.registry = metrics.Registry.init(gpa);
        const scope = metrics.Scope.init(&self.registry).child("db");
        const cfg: Db.Cfg = .{
            .merkle = .{
                .journal_partition = "merkle-journal",
                .metadata_partition = "merkle-metadata",
                .items_per_blob = 1000,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &self.cache,
            },
            .log = .{
                .partition = "log-journal",
                .items_per_blob = layout.items_per_blob,
                .cache_ref = &self.cache,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
        };
        return Db.init(gpa, self.delayed.storage(), scope, cfg, max_size);
    }
};

/// Appends `item` in one batch declaring `floor` (null inherits it); returns its location.
fn append(db: *Db, item: U64, floor: ?u64) !u64 {
    const location = db.bounds().end;
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        try batch.append(item);
        if (floor) |loc| batch.with_inactivity_floor(loc);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
    return location;
}

fn waiting(ctx: Context, completion: runtime.storage.Completion) anyerror!void {
    _ = ctx;
    try completion.wait_release();
}

fn pruning(ctx: Context, db: *Db, location: u64, done: *bool) anyerror!void {
    _ = ctx;
    try db.prune(location);
    done.* = true;
}

fn run(comptime body: fn (Context) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start_context(body, .{}));
}

/// A started sync must not block reads and applies while it is in flight.
fn overlaps_work(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open();
    const first = try append(&db, U64.init(1), null);
    const completions_before = f.pending.completions();
    const entered_before = f.pending.entered();
    const completion = try db.start_sync();
    try testing.expect(completion.is_pending());
    const waiter = try ctx.child("await_sync").spawn(waiting, .{completion});
    while (f.pending.entered() == entered_before) try ctx.sleep(.fromMilliseconds(1));
    // Reads and applies complete before the sync does.
    try testing.expectEqual(@as(?U64, U64.init(1)), try db.get(first));
    const second = try append(&db, U64.init(2), null);
    try testing.expectEqual(completions_before, f.pending.completions());
    f.pending.unblock();
    try try waiter.join();
    // The mid-sync batch is durable after the next sync.
    try (try db.start_sync()).wait_release();
    const root = db.root();
    db.deinit();
    var reopened = try f.open();
    defer reopened.deinit();
    try testing.expect(reopened.root().eql(root));
    try testing.expectEqual(@as(?U64, U64.init(2)), try reopened.get(second));
}

test "keyless start_sync overlaps work (test_keyless_fixed_start_sync_overlaps_work)" {
    try run(overlaps_work);
}

/// A failed in-flight sync surfaces through its completion and the next durability op.
fn failure_propagates(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    f.pending.unblock(); // Pass syncs through so opening does not park.
    var db = try f.open();
    defer db.deinit();
    _ = try append(&db, U64.init(1), null);
    f.pending.arm_fail();
    const completion = try db.start_sync();
    try testing.expectError(error.Io, completion.wait_release());
    const starts_before = f.pending.starts();
    try testing.expectError(error.Io, db.commit());
    // The surfaced error is the retained failure, not a fresh sync's.
    try testing.expectEqual(starts_before, f.pending.starts());
}

test "keyless start_sync failure propagates (test_keyless_fixed_start_sync_failure_propagates)" {
    try run(failure_propagates);
}

/// State made durable by an awaited start_sync completion is recovered on reopen.
fn recovery(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    f.pending.unblock();
    var db = try f.open();
    const location = try append(&db, U64.init(1), db.inactivity_floor());
    try (try db.start_sync()).wait_release();
    const root = db.root();
    db.deinit();
    f.inner.crash();
    var reopened = try f.open();
    defer reopened.deinit();
    try testing.expect(reopened.root().eql(root));
    try testing.expectEqual(@as(?U64, U64.init(1)), try reopened.get(location));
}

test "keyless start_sync recovery (test_keyless_fixed_start_sync_recovery)" {
    try run(recovery);
}

/// Pruning drains the in-flight sync before mutating storage.
fn prune_waits(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open();
    defer db.deinit();
    // The second batch declares floor 2, so the prune below is non-trivial.
    _ = try append(&db, U64.init(1), 0);
    _ = try append(&db, U64.init(2), 2);
    const starts_before = f.pending.starts();
    const completion = try db.start_sync();
    try testing.expect(f.pending.starts() > starts_before);
    const floor = db.inactivity_floor();
    try testing.expect(floor > 0);
    var done = false;
    const prune = try ctx.child("prune").spawn(pruning, .{ &db, floor, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done); // Prune proceeded while the started sync was pending.
    f.pending.unblock();
    try try prune.join();
    try completion.wait_release();
    try testing.expect(db.bounds().start <= floor);
}

test "keyless start_sync prune waits (test_keyless_fixed_start_sync_prune_waits)" {
    try run(prune_waits);
}

/// Seven operations per log blob, one per 18-byte page, so selecting the genesis commit
/// discards two whole pages of the first branch.
const rebranch_layout: Fixture.Layout = .{ .items_per_blob = 7, .page_size = 18 };

/// Builds branch A, reopens bounded at the genesis commit to build branch B, starts its sync,
/// completes only the operation (or only the merkle) journal's half, and crashes. Recovery
/// publishes branch B only when its operations became durable first; otherwise both journals
/// stay at genesis. Returns the size and root recovery must find.
fn rebranch_sync_crash(ctx: Context, merkle_first: bool) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open_with(rebranch_layout, null);
    const root_genesis = db.root();
    _ = try append(&db, U64.init(11), db.inactivity_floor());
    try db.sync();
    const root_a = db.root();
    try testing.expectEqual(@as(u64, 3), db.bounds().end);
    db.deinit();

    db = try f.open_with(rebranch_layout, 1);
    try testing.expectEqual(@as(u64, 1), db.bounds().end);
    try testing.expect(db.root().eql(root_genesis));
    try testing.expectEqual(@as(u64, 1), try append(&db, U64.init(22), db.inactivity_floor()));
    try testing.expectEqual(@as(u64, 3), db.bounds().end);
    const root_b = db.root();
    try testing.expect(!root_a.eql(root_b));

    // Complete only one side of the paired operation/merkle sync, then crash.
    const starts = f.pending.starts();
    const completions = f.pending.completions();
    const completion = try db.start_sync();
    try testing.expectEqual(@as(u64, 2), f.pending.starts() - starts);
    const operation_data = f.pending.next();
    const merkle_data = f.pending.next();
    const completed, const parked = if (merkle_first)
        .{ merkle_data, operation_data }
    else
        .{ operation_data, merkle_data };
    completed.release({});
    try testing.expectEqual(completions + 1, f.pending.completions());
    f.inner.crash();
    parked.release(error.Io); // The crash lost it.
    completion.release();
    db.deinit();

    var reopened = try f.open_with(rebranch_layout, null);
    defer reopened.deinit();
    const size: u64 = if (merkle_first) 1 else 3;
    const root = if (merkle_first) root_genesis else root_b;
    try testing.expectEqual(size, reopened.bounds().end);
    try testing.expect(reopened.root().eql(root));
    if (!merkle_first) try testing.expectEqual(@as(?U64, U64.init(22)), try reopened.get(1));
    var proof = try reopened.proof(0, size);
    defer proof.deinit(gpa);
    const H = cryptography.Sha256;
    const ok = try verify.verify(F, H, Db.Operation, gpa, &proof.proof, 0, proof.items, &root);
    try testing.expect(ok);
}

fn rebranch_operation_first(ctx: Context) !void {
    try rebranch_sync_crash(ctx, false);
}

fn rebranch_merkle_first(ctx: Context) !void {
    try rebranch_sync_crash(ctx, true);
}

test "keyless rebranch sync crash recovers one history (test_keyless_fixed_rebranch_sync_crash)" {
    try run(rebranch_operation_first);
    try run(rebranch_merkle_first);
}
