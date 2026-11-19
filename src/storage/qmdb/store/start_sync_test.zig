//! commonware `qmdb/store/db.rs`'s in-flight `start_sync` tests, with
//! `runtime.storage.mocks.DelayedSync` holding started syncs (`DelayedSyncContext`). An
//! operation commonware polls with `now_or_never` runs here as a task on the deterministic
//! runtime, which the test checks has not finished before it releases the parked syncs.
//! `test_store_start_sync_recovery` is in db_test.zig.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const translator = @import("../../translator.zig");
const value = @import("../value.zig");
const test_support = @import("../test_support.zig");
const store = @import("mod.zig");
const Sequential = @import("parallel").Sequential;

const gpa = testing.allocator;
const Context = runtime.deterministic.Context;
const Digest = cryptography.Blake3.Digest;
const Bytes = []const u8;
const Db = store.Db(Digest, value.Variable(Bytes), translator.TwoCap, Sequential);
const CodecCfg = @FieldType(Db.Journal.Cfg, "codec_config");

fn key(i: u64) Digest {
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, i, .big);
    return cryptography.Blake3.hash(&.{&be});
}

const Fixture = struct {
    inner: runtime.storage.memory.Storage,
    pending: runtime.storage.mocks.DelayedSync,
    delayed: runtime.storage.mocks.DelayedSynced,
    cache: runtime.buffer.paged.CacheRef,

    fn init(self: *Fixture, ctx: Context) !void {
        self.inner = .init(gpa);
        self.pending = .init(gpa, ctx.io());
        self.delayed = .init(gpa, self.inner.storage(), &self.pending);
        self.cache = try .init(gpa, 1024, 8);
    }

    fn deinit(self: *Fixture) void {
        self.cache.deinit();
        self.pending.deinit();
        self.inner.deinit();
    }

    /// Commonware's `open_delayed_store`: large pages and sections, so a mid-sync apply
    /// neither fills the write buffer nor rolls a section over and waits on a parked sync.
    fn open(self: *Fixture) !Db {
        const cfg: Db.Cfg = .{
            .log = .{
                .partition = "journal",
                .items_per_section = 1000,
                .codec_config = test_support.codec_config(CodecCfg),
                .cache_ref = &self.cache,
                .write_buffer = 64 * 1024,
                .replay_buffer = 64 * 1024,
            },
            .translator = .{},
            .init_cache = 1024,
            .strategy = .{},
        };
        return Db.init(gpa, self.delayed.storage(), cfg, null);
    }
};

/// Commonware's `apply_write`: one write of `key -> bytes` in its own batch.
fn apply_write(db: *Db, k: Digest, bytes: Bytes) !void {
    const writes = [_]Db.Write{.{ .key = k, .value = bytes }};
    var changeset = try Db.Changeset.init(gpa, &writes);
    try db.apply_batch(&changeset);
}

fn expect_value(db: *Db, k: Digest, want: Bytes) !void {
    const got = try db.get(&k);
    defer codec.free(?Bytes, gpa, got);
    try testing.expectEqualSlices(u8, want, got orelse return error.TestExpectedValue);
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
    const value0: [8]u8 = @splat(1);
    try apply_write(&db, key(0), &value0);
    const starts_before = f.pending.starts();
    const entered_before = f.pending.entered();
    const completions_before = f.pending.completions();
    const completion = try db.start_sync();
    try testing.expect(f.pending.starts() > starts_before);
    try testing.expectEqual(completions_before, f.pending.completions());
    const waiter = try ctx.child("await_sync").spawn(waiting, .{completion});
    while (f.pending.entered() == entered_before) try ctx.sleep(.fromMilliseconds(1));
    // Reads and applies complete before the sync does.
    try expect_value(&db, key(0), &value0);
    const value1: [8]u8 = @splat(2);
    try apply_write(&db, key(1), &value1);
    try testing.expectEqual(completions_before, f.pending.completions());
    f.pending.unblock();
    try try waiter.join();
    // The mid-sync batch is durable after the next sync.
    try (try db.start_sync()).wait_release();
    const size = db.bounds().end;
    db.deinit();
    var reopened = try f.open();
    defer reopened.deinit();
    try testing.expectEqual(size, reopened.bounds().end);
    try expect_value(&reopened, key(1), &value1);
}

test "store start_sync overlaps work (test_store_start_sync_overlaps_work)" {
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
    const ones: [8]u8 = @splat(1);
    try apply_write(&db, key(0), &ones);
    f.pending.arm_fail();
    const completion = try db.start_sync();
    try testing.expectError(error.Io, completion.wait_release());
    const starts_before = f.pending.starts();
    try testing.expectError(error.Io, db.commit());
    // The surfaced error is the retained failure, not a fresh sync's.
    try testing.expectEqual(starts_before, f.pending.starts());
}

test "store start_sync failure propagates (test_store_start_sync_failure_propagates)" {
    try run(failure_propagates);
}

/// Pruning drains the in-flight sync before mutating storage.
fn prune_waits(ctx: Context) !void {
    var f: Fixture = undefined;
    try f.init(ctx);
    defer f.deinit();
    var db = try f.open();
    defer db.deinit();
    // Two batches, so the floor walks leave a non-trivial prune target.
    const ones: [8]u8 = @splat(1);
    const twos: [8]u8 = @splat(2);
    try apply_write(&db, key(0), &ones);
    try apply_write(&db, key(1), &twos);
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
}

test "store start_sync prune waits (test_store_start_sync_prune_waits)" {
    try run(prune_waits);
}
