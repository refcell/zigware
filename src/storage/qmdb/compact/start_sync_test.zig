//! commonware `qmdb/compact/db.rs`'s in-flight `start_sync` tests (`compact_db_tests!`), with
//! `runtime.storage.mocks.DelayedSync` holding started syncs (`DelayedSyncContext`). Each
//! scenario runs over the keyless and immutable fixed dbs of both families. An operation
//! commonware polls with `now_or_never` runs here as a task on the deterministic runtime,
//! which the test checks has not finished before it releases the parked syncs; commonware's
//! `drive_pending_syncs` is a task releasing every parked sync until the operation returns.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Context = runtime.deterministic.Context;
const Completion = runtime.storage.Completion;
const DelayedSync = runtime.storage.mocks.DelayedSync;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;
const all_dbs = .{
    support.KeylessFixed(Mmr),
    support.KeylessFixed(Mmb),
    support.ImmutableFixed(Mmr),
    support.ImmutableFixed(Mmb),
};

const Fixture = struct {
    inner: runtime.buffer.mocks.Storage,
    pending: DelayedSync,
    delayed: runtime.storage.mocks.DelayedSynced,
    cache_ref: runtime.buffer.paged.CacheRef,

    /// `self` must not move afterwards.
    fn init(self: *Fixture, ctx: Context) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.interface(), &self.pending);
        self.cache_ref = try .init(gpa, 101, 11);
    }

    /// Every db must be closed first; parked syncs are released.
    fn deinit(self: *Fixture) void {
        self.pending.unblock();
        self.cache_ref.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    fn cfg(self: *Fixture, comptime Db: type) Db.Cfg {
        return .{
            .witness = .{
                .partition = "compact-start-sync-witness",
                .items_per_section = 64,
                .codec_config = {},
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .codec_config = support.codec_config(Db),
        };
    }

    fn open(self: *Fixture, comptime Db: type) !Db {
        return Db.init(gpa, self.delayed.storage(), self.cfg(Db), null);
    }

    /// Opens while a task releases the parked syncs (the open persists the genesis witness).
    fn open_driven(self: *Fixture, ctx: Context, comptime Db: type) !Db {
        var driver = try Driver.start(ctx, &self.pending);
        defer driver.finish();
        return self.open(Db);
    }
};

/// Releases every parked sync until finished (commonware's `drive_pending_syncs`).
const Driver = struct {
    stop: std.atomic.Value(bool) = .init(false),
    io: std.Io,
    task: ?runtime.context.Handle(anyerror!void) = null,

    fn start(ctx: Context, pending: *DelayedSync) !*Driver {
        const driver = try gpa.create(Driver);
        errdefer gpa.destroy(driver);
        driver.* = .{ .io = ctx.io() };
        const releasing = ctx.child("drive");
        driver.task = try releasing.spawn(release_until_stopped, .{ pending, &driver.stop });
        return driver;
    }

    fn release_until_stopped(
        ctx: Context,
        pending: *DelayedSync,
        stop: *const std.atomic.Value(bool),
    ) anyerror!void {
        // Each pass releases what parked since the last; the driven operation is bounded.
        while (!stop.load(.acquire)) {
            if (pending.parked() > 0) pending.release_all();
            try ctx.sleep(.fromMilliseconds(1));
        }
        std.debug.assert(stop.load(.acquire));
    }

    fn finish(driver: *Driver) void {
        driver.stop.store(true, .release);
        // A canceled join would leave the task running over the freed driver, so the join
        // is uncancelable; a pending cancel stays pending for the caller's next wait.
        const io = driver.io;
        const protection = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(protection);
        if (driver.task.?.join()) |outcome| outcome catch {} else |_| {}
        gpa.destroy(driver);
    }
};

/// Applies the one mutation for `seed`, with `seed`'s value as metadata.
fn apply(comptime Db: type, db: *Db, seed: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        try support.mutate(Db, &batch, seed);
        batch.with_metadata(support.metadata_value(Db, seed));
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn fails(result: anytype) bool {
    _ = result catch return true;
    return false;
}

/// Waits on `completion` while a task releases the parked syncs.
fn wait_driven(ctx: Context, pending: *DelayedSync, completion: Completion) !void {
    var driver = try Driver.start(ctx, pending);
    defer driver.finish();
    try completion.wait_release();
}

/// Leaves a failed recovery-watermark sync retained after dropping its completion.
fn fail_dropped_watermark_sync(comptime Db: type, ctx: Context, f: *Fixture, db: *Db) !void {
    // Prove the data durable so the next call only advances recovery metadata.
    try wait_driven(ctx, &f.pending, try db.start_sync());
    const dropped = try db.start_sync();
    try testing.expectEqual(1, f.pending.parked()); // Only the recovery-watermark sync.
    f.pending.fail_all();
    dropped.release();
}

fn waiting(ctx: Context, completion: Completion) anyerror!void {
    _ = ctx;
    try completion.wait_release();
}

/// Runs `db`'s `operation` ("sync" or "commit") and records that it returned.
fn Durably(comptime Db: type, comptime operation: []const u8) type {
    return struct {
        fn run(ctx: Context, db: *Db, done: *bool) anyerror!void {
            _ = ctx;
            defer done.* = true;
            try @field(Db, operation)(db);
        }
    };
}

fn run(comptime body: fn (Context) anyerror!void) !void {
    try runtime.deterministic.soak(gpa, .{}, {}, struct {
        fn round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start_context(body, .{}));
        }
    }.round);
}

/// Applying a successor does not wait for the witness sync already in flight.
fn apply_overlaps_start_sync(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open_driven(ctx, Db);
    try apply(Db, &db, 1);
    const starts_before = f.pending.starts();
    const entered_before = f.pending.entered();
    const completions_before = f.pending.completions();
    const completion = try db.start_sync();
    try testing.expect(f.pending.starts() > starts_before);
    try testing.expectEqual(completions_before, f.pending.completions());
    const first_target = db.target();
    const waiter = try ctx.child("await_sync").spawn(waiting, .{completion});
    while (f.pending.entered() == entered_before) try ctx.sleep(.fromMilliseconds(1));

    try apply(Db, &db, 2);
    try testing.expect(!db.root().eql(first_target.root));
    const second_target = db.target();
    try testing.expect(!second_target.eql(first_target));
    // The database made progress while the sync was still in flight.
    try testing.expectEqual(completions_before, f.pending.completions());
    f.pending.unblock();
    try try waiter.join();

    // The successor becomes durable once the next start_sync completes.
    try (try db.start_sync()).wait_release();
    db.deinit();
    db = try f.open(Db);
    try testing.expect(db.target().eql(second_target));
    try testing.expectEqual(support.metadata_value(Db, 2), (try db.get_metadata()).?);
    try db.destroy();
}

test "compact apply overlaps start_sync (test_compact_apply_overlaps_start_sync)" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try apply_overlaps_start_sync(Db, ctx);
        }
    }.body);
}

/// State persisted by an awaited start_sync is recovered on reopen.
fn start_sync_recovery(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    f.pending.unblock();
    var db = try f.open(Db);
    try apply(Db, &db, 1);
    try (try db.start_sync()).wait_release();
    const root = db.root();
    db.deinit();
    db = try f.open(Db);
    try testing.expect(db.root().eql(root));
    try testing.expectEqual(support.metadata_value(Db, 1), (try db.get_metadata()).?);
    try db.destroy();
}

test "compact start_sync recovery (test_compact_start_sync_recovery)" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try start_sync_recovery(Db, ctx);
        }
    }.body);
}

/// A start_sync that fails in flight surfaces through its completion and the next durability
/// operation, even one with nothing new to persist.
fn start_sync_failure_propagates(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    f.pending.unblock();
    var db = try f.open(Db);
    defer db.deinit();
    try apply(Db, &db, 1);
    f.pending.arm_fail(); // Every later sync resolves to an injected error.
    try testing.expect(fails((try db.start_sync()).wait_release()));
    const starts_before = f.pending.starts();
    // The witness was already journaled, so this commit has nothing to journal; it must still
    // observe the retained failure rather than no-op.
    try testing.expect(fails(db.commit()));
    // The surfaced error is the retained failure, not a fresh sync's.
    try testing.expectEqual(starts_before, f.pending.starts());
}

test "compact start_sync failure propagates (test_compact_start_sync_failure_propagates)" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try start_sync_failure_propagates(Db, ctx);
        }
    }.body);
}

/// A sync with nothing new to persist still drains (and proves) a prior start_sync.
fn start_sync_then_noop_sync_drains(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open_driven(ctx, Db);
    try apply(Db, &db, 1);
    const starts_before = f.pending.starts();
    const completions_before = f.pending.completions();
    const completion = try db.start_sync();
    try testing.expect(f.pending.starts() > starts_before);
    try testing.expectEqual(completions_before, f.pending.completions());
    const root = db.root();
    var done = false;
    const syncing = try ctx.child("sync").spawn(Durably(Db, "sync").run, .{ &db, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done); // The sync waits for the started one.
    f.pending.unblock();
    try try syncing.join();
    try completion.wait_release();
    try testing.expect(f.pending.completions() > completions_before);
    db.deinit();
    db = try f.open(Db);
    try testing.expect(db.root().eql(root));
    try db.destroy();
}

test "compact start_sync then a no-op sync drains (test_compact_start_sync_then_noop_sync_drains)" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try start_sync_then_noop_sync_drains(Db, ctx);
        }
    }.body);
}

/// A cancel taken while start_sync waits on the prior sync propagates as `error.Canceled`
/// rather than returning a ready completion holding it, which a caller would carry on past.
fn start_sync_canceled_while_waiting(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open_driven(ctx, Db);
    defer db.deinit();
    try apply(Db, &db, 1);
    const held = try db.start_sync(); // Parked until released below.
    var outcome: CancelOutcome = .{};
    const task = try ctx.child("cancel").spawn(CancelOutcome.start_sync(Db), .{ &db, &outcome });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!outcome.returned); // Waiting on the held sync.
    if (task.abort()) |result| result catch {} else |_| {}
    try testing.expect(outcome.returned);
    try testing.expect(outcome.start_sync_canceled);
    f.pending.unblock();
    try held.wait_release();
}

const CancelOutcome = struct {
    returned: bool = false,
    start_sync_canceled: bool = false,

    fn start_sync(comptime Db: type) fn (Context, *Db, *CancelOutcome) anyerror!void {
        return struct {
            fn run(ctx: Context, db: *Db, outcome: *CancelOutcome) anyerror!void {
                _ = ctx;
                defer outcome.returned = true;
                const completion = db.start_sync() catch |err| {
                    outcome.start_sync_canceled = err == error.Canceled;
                    return err;
                };
                completion.release();
            }
        }.run;
    }
};

test "compact start_sync canceled while waiting on the prior sync propagates" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try start_sync_canceled_while_waiting(Db, ctx);
        }
    }.body);
}

/// A no-op sync returns a retained metadata failure before starting new journal work.
fn noop_sync_fails_without_new_work(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open_driven(ctx, Db);
    defer db.deinit();
    try apply(Db, &db, 1);
    try fail_dropped_watermark_sync(Db, ctx, &f, &db);
    const starts_before = f.pending.starts();
    var driver = try Driver.start(ctx, &f.pending);
    const outcome = db.sync();
    driver.finish();
    try testing.expect(fails(outcome)); // The sync must not absorb the retained failure.
    try testing.expectEqual(starts_before, f.pending.starts());
}

// commonware `test_compact_start_sync_then_noop_sync_fails_without_new_work`.
test "compact start_sync then a no-op sync fails without new work" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try noop_sync_fails_without_new_work(Db, ctx);
        }
    }.body);
}

/// A commit with nothing new to persist still waits for a prior start_sync, and starts no
/// journal work once it succeeds.
fn start_sync_then_noop_commit_waits(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open_driven(ctx, Db);
    try apply(Db, &db, 1);
    const completion = try db.start_sync();
    const starts_before = f.pending.starts();
    var done = false;
    const committing = try ctx.child("commit").spawn(Durably(Db, "commit").run, .{ &db, &done });
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!done); // The commit waits for the started sync.
    f.pending.unblock();
    try try committing.join();
    try completion.wait_release();
    // A successful pipelined sync triggers no journal work.
    try testing.expectEqual(starts_before, f.pending.starts());
    try db.destroy();
}

// commonware `test_compact_start_sync_then_noop_commit_waits`.
test "compact start_sync then a no-op commit waits" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try start_sync_then_noop_commit_waits(Db, ctx);
        }
    }.body);
}

/// A start_sync with nothing new to persist returns a working completion and journals no
/// duplicate witness.
fn start_sync_noop_second_call(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open_driven(ctx, Db);
    try apply(Db, &db, 1);
    const first = try db.start_sync();
    // A second start_sync waits for the first before starting, so release it first.
    f.pending.unblock();
    try first.wait_release();
    try (try db.start_sync()).wait_release();
    const root = db.root();
    db.deinit();

    // The journal holds exactly the bootstrap witness and the one durable witness.
    var journal = try Db.WitnessJournal.init(gpa, f.delayed.storage(), f.cfg(Db).witness);
    try testing.expectEqual(2, journal.size());
    journal.deinit();
    db = try f.open(Db);
    try testing.expect(db.root().eql(root));
    try db.destroy();
}

test "compact start_sync no-op second call (test_compact_start_sync_noop_second_call)" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try start_sync_noop_second_call(Db, ctx);
        }
    }.body);
}

/// A metadata sync failure from start_sync resurfaces on the next commit, even one with new
/// state to persist.
fn metadata_failure_resurfaces_on_commit(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open_driven(ctx, Db);
    defer db.deinit();
    try apply(Db, &db, 1);
    const completion = try db.start_sync();
    // start_sync parks the data sync, then the offsets sync: complete the data sync and fail
    // the offsets sync.
    try testing.expectEqual(2, f.pending.parked());
    const offsets = f.pending.last();
    const data = f.pending.next();
    data.release({});
    offsets.release(error.Io);
    try testing.expect(fails(completion.wait_release()));
    // Later syncs pass; only the retained offsets failure remains.
    f.pending.unblock();
    // A new batch proves the commit checks the prior sync before persisting a new witness.
    try apply(Db, &db, 2);
    try testing.expect(fails(db.commit()));
}

// commonware `test_compact_start_sync_metadata_failure_resurfaces_on_commit`.
test "compact start_sync metadata failure resurfaces on commit" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try metadata_failure_resurfaces_on_commit(Db, ctx);
        }
    }.body);
}

/// A later start_sync cannot replace an unobserved failure from the prior completion.
fn retains_dropped_metadata_failure(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open_driven(ctx, Db);
    defer db.deinit();
    try apply(Db, &db, 1);
    try fail_dropped_watermark_sync(Db, ctx, &f, &db);
    // The call succeeds, but its completion carries the retained failure.
    const next = try db.start_sync();
    try testing.expect(fails(wait_driven(ctx, &f.pending, next)));
}

// commonware `test_compact_start_sync_retains_dropped_metadata_failure`.
test "compact start_sync retains a dropped metadata failure" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try retains_dropped_metadata_failure(Db, ctx);
        }
    }.body);
}

/// Once a start_sync completes successfully, a commit touches no storage.
fn start_sync_proven_skips_journal(comptime Db: type, ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    f.pending.unblock();
    var db = try f.open(Db);
    try apply(Db, &db, 1);
    try (try db.start_sync()).wait_release();
    const starts_before = f.pending.starts();
    try db.commit();
    try testing.expectEqual(starts_before, f.pending.starts());
    try db.destroy();
}

test "compact start_sync proven skips the journal (test_compact_start_sync_proven_skips_journal)" {
    inline for (all_dbs) |Db| try run(struct {
        fn body(ctx: Context) !void {
            try start_sync_proven_skips_journal(Db, ctx);
        }
    }.body);
}
