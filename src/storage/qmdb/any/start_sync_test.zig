//! commonware `qmdb/any/unordered/fixed.rs`'s in-flight `start_sync` tests, with
//! `runtime.storage.mocks.DelayedSync` holding started syncs (`DelayedSyncContext`). An
//! operation commonware polls with `now_or_never` runs here as a task on the deterministic
//! runtime, which the test checks has not finished before it releases the parked syncs.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Context = runtime.deterministic.Context;
const metrics = runtime.telemetry.metrics;
const Db = support.UnorderedFixed(merkle.mmr.Family);
const Digest = support.Digest;
const key = support.to_digest;
const val = support.to_val;

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

fn write(db: *Db, index: u64) !void {
    try support.apply_writes(Db, db, &.{.{ .key = key(index), .value = val(index, 0) }});
}

fn expect_value(db: *const Db, k: Digest, expected: Digest) !void {
    const actual = (try db.get(&k)) orelse return error.TestExpectedValue;
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
    try write(&db, 0);
    const starts_before = f.pending.starts();
    const entered_before = f.pending.entered();
    const completions_before = f.pending.completions();
    const completion = try db.start_sync();
    try testing.expect(f.pending.starts() > starts_before);
    try testing.expectEqual(completions_before, f.pending.completions());
    const waiter = try ctx.child("await_sync").spawn(waiting, .{completion});
    while (f.pending.entered() == entered_before) try ctx.sleep(.fromMilliseconds(1));
    // Reads and applies complete before the sync does.
    try expect_value(&db, key(0), val(0, 0));
    try write(&db, 1);
    try testing.expectEqual(completions_before, f.pending.completions());
    f.pending.unblock();
    try try waiter.join();
    // The mid-sync batch is durable after the next sync.
    try (try db.start_sync()).wait_release();
    const root = db.root();
    const size = db.bounds().end;
    db.deinit();
    var reopened = try f.open();
    defer reopened.deinit();
    try testing.expect(reopened.root().eql(root));
    try testing.expectEqual(size, reopened.bounds().end);
    try expect_value(&reopened, key(1), val(1, 0));
}

test "any start_sync overlaps work (test_start_sync_overlaps_work)" {
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
    try write(&db, 0);
    f.pending.arm_fail();
    const completion = try db.start_sync();
    try testing.expectError(error.Io, completion.wait_release());
    const starts_before = f.pending.starts();
    try testing.expectError(error.Io, db.commit());
    // The surfaced error is the retained failure, not a fresh sync's.
    try testing.expectEqual(starts_before, f.pending.starts());
}

test "any start_sync failure propagates (test_start_sync_failure_propagates)" {
    try run(failure_propagates);
}

/// Pruning drains the in-flight commit sync before mutating the log, even once the merkle
/// sync it started itself completes.
fn prune_waits(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open();
    defer db.deinit();
    try write(&db, 0);
    const starts_before = f.pending.starts();
    const completion = try db.start_sync();
    try testing.expect(f.pending.starts() > starts_before);
    const started = f.pending.starts();
    // A non-trivial prune: the floor advanced past the seed commit.
    const floor = db.inactivity_floor();
    try testing.expect(floor > 0);
    var done = false;
    const prune = try ctx.child("prune").spawn(pruning, .{ &db, floor, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done); // Prune proceeded while the commit sync was pending.
    if (f.pending.starts() > started) {
        // Release only the merkle sync prune started (parked last): it still waits.
        f.pending.last().release({});
        try ctx.sleep(.fromMilliseconds(10));
        try testing.expect(!done);
    }
    f.pending.unblock();
    try try prune.join();
    try completion.wait_release();
}

test "any start_sync prune waits (test_start_sync_prune_waits)" {
    try run(prune_waits);
}
