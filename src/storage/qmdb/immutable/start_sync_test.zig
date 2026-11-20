//! commonware `qmdb/immutable/fixed.rs`'s in-flight `start_sync` tests, with
//! `runtime.storage.mocks.DelayedSync` holding started syncs (`DelayedSyncContext`). An
//! operation commonware polls with `now_or_never` runs here as a task on the deterministic
//! runtime, which the test checks has not finished before it releases the parked syncs.
//! `test_fixed_start_sync_recovery` is in recovery_test.zig.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Context = runtime.deterministic.Context;
const metrics = runtime.telemetry.metrics;
const Db = support.Fixed(merkle.mmr.Family);
const Digest = support.Digest;
const fill = support.fill;

const Fixture = struct {
    harness: support.Harness,
    inner: runtime.storage.memory.Storage,
    pending: runtime.storage.mocks.DelayedSync,
    delayed: runtime.storage.mocks.DelayedSynced,

    fn init(self: *Fixture, ctx: Context) !void {
        self.harness = try support.Harness.init(gpa);
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
    }

    fn deinit(self: *Fixture) void {
        self.pending.deinit();
        self.inner.deinit();
        self.harness.deinit();
    }

    fn open(self: *Fixture) !Db {
        const h = &self.harness;
        h.registry.deinit();
        h.registry = metrics.Registry.init(gpa);
        const scope = metrics.Scope.init(&h.registry).child("db");
        // One blob per journal (commonware's `open_delayed_db`), so no write rolls a blob
        // over and waits on a parked sync.
        var cfg = h.cfg(Db);
        cfg.merkle.items_per_blob = 1000;
        cfg.log.items_per_blob = 1000;
        return Db.init(gpa, self.delayed.storage(), scope, cfg, null);
    }
};

/// Commonware's `apply_set`: one set in a batch declaring `floor`.
fn apply_set(db: *Db, key: Digest, value: Digest, floor: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        try batch.set(key, value);
        batch.with_inactivity_floor(floor);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn expect_value(db: *const Db, key: Digest, expected: Digest) !void {
    const actual = (try db.get(&key)) orelse return error.TestExpectedValue;
    try testing.expect(actual.eql(expected));
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

/// Runs `body` on a deterministic runner, once per `-Dfuzz-soak` seed.
fn run(comptime body: fn (Context) anyerror!void) !void {
    try runtime.deterministic.soak(gpa, .{}, {}, struct {
        fn round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start_context(body, .{}));
        }
    }.round);
}

/// A started sync must not block reads and applies while it is in flight.
fn overlaps_work(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open();
    try apply_set(&db, fill(1), fill(2), db.inactivity_floor());
    const starts_before = f.pending.starts();
    const entered_before = f.pending.entered();
    const completions_before = f.pending.completions();
    const completion = try db.start_sync();
    try testing.expect(f.pending.starts() > starts_before);
    try testing.expectEqual(completions_before, f.pending.completions());
    const waiter = try ctx.child("await_sync").spawn(waiting, .{completion});
    while (f.pending.entered() == entered_before) try ctx.sleep(.fromMilliseconds(1));
    // Reads and applies complete before the sync does.
    try expect_value(&db, fill(1), fill(2));
    try apply_set(&db, fill(3), fill(4), db.inactivity_floor());
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
    try expect_value(&reopened, fill(3), fill(4));
}

test "immutable start_sync overlaps work (test_fixed_start_sync_overlaps_work)" {
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
    try apply_set(&db, fill(1), fill(2), db.inactivity_floor());
    f.pending.arm_fail();
    const completion = try db.start_sync();
    try testing.expectError(error.Io, completion.wait_release());
    const starts_before = f.pending.starts();
    try testing.expectError(error.Io, db.commit());
    // The surfaced error is the retained failure, not a fresh sync's.
    try testing.expectEqual(starts_before, f.pending.starts());
}

test "immutable start_sync failure propagates (test_fixed_start_sync_failure_propagates)" {
    try run(failure_propagates);
}

/// Pruning drains the in-flight sync before mutating storage.
fn prune_waits(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open();
    defer db.deinit();
    // The second batch declares floor 2, so the prune below is non-trivial.
    try apply_set(&db, fill(1), fill(2), 0);
    try apply_set(&db, fill(3), fill(4), 2);
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

test "immutable start_sync prune waits (test_fixed_start_sync_prune_waits)" {
    try run(prune_waits);
}

fn applying(ctx: Context, db: *Db, batch: *Db.MerkleizedBatch, done: *bool) anyerror!void {
    _ = ctx;
    try db.apply_batch(batch);
    done.* = true;
}

/// An apply whose append waits on the in-flight sync indexes its sets meanwhile; the database
/// publishes the batch only once both are done.
fn apply_indexes_while_journal_waits(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open();
    defer db.deinit();
    try apply_set(&db, fill(1), fill(101), 0);
    const completion = try db.start_sync();
    // Exceed the write buffer, so the append must wait for the outstanding sync.
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (2..34) |i| try batch.set(fill(@intCast(i)), fill(@intCast(i + 100)));
        break :merkleized try batch.merkleize(&db);
    };
    defer merkleized.release();
    const root = merkleized.root();
    const completions_before = f.pending.completions();
    var done = false;
    const apply = try ctx.child("apply").spawn(applying, .{ &db, merkleized, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done); // The append waits on the parked sync.
    // Indexing finished while the journal is parked; publication waits for both.
    try testing.expectEqual(@as(u64, 33), db.snapshot.len());
    try testing.expectEqual(@as(u64, 3), db.bounds().end);
    try testing.expectEqual(completions_before, f.pending.completions());
    f.pending.unblock();
    try try apply.join();
    try completion.wait_release();
    try testing.expect(db.root().eql(root));
    try testing.expectEqual(@as(u64, 36), db.bounds().end);
    try db.sync();
    db.deinit();
    db = try f.open();
    try testing.expect(db.root().eql(root));
    for (1..34) |i| try expect_value(&db, fill(@intCast(i)), fill(@intCast(i + 100)));
}

// fixed.rs `test_fixed_apply_indexes_while_journal_waits`.
test "immutable apply indexes while the journal waits" {
    try run(apply_indexes_while_journal_waits);
}
