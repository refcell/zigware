//! commonware `glue/src/stateful/db/mod.rs`'s tuple locking and concurrency tests,
//! `tuple_apply_does_not_hold_ready_writer_while_waiting_for_reader`,
//! `tuple_apply_cancellation_leaves_completed_and_untouched_members`,
//! `tuple_new_batches_queues_reads_concurrently`, and `tuple_apply_runs_databases_in_parallel`,
//! on the deterministic runtime so an apply that never finishes fails instead of hanging.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const db = @import("mod.zig");

const gpa = testing.allocator;

const TestEnv = struct {
    gpa: std.mem.Allocator,
    io: Io,

    pub fn child(env: TestEnv, _: []const u8) TestEnv {
        return env;
    }
};

const TestUnmerkleized = struct {
    pub fn merkleize(_: *TestUnmerkleized) !TestMerkleized {
        return .{};
    }
    pub fn deinit(_: *TestUnmerkleized) void {}
};

const TestMerkleized = struct {
    pub fn root(_: *const TestMerkleized) u64 {
        return 0;
    }
    pub fn new_batch(_: *const TestMerkleized) !TestUnmerkleized {
        return .{};
    }
    pub fn clone(self: *const TestMerkleized) TestMerkleized {
        return self.*;
    }
    pub fn deinit(_: *TestMerkleized) void {}
};

/// Counts the batches applied to it (commonware's `ObservedDb` `applied`).
const AppliedDb = struct {
    applied: *u64,

    pub const Config = *u64;
    pub const SyncTarget = void;
    pub const Unmerkleized = TestUnmerkleized;
    pub const Merkleized = TestMerkleized;

    pub fn init(_: TestEnv, applied: *u64, _: ?void) !AppliedDb {
        return .{ .applied = applied };
    }
    pub fn initial_sync_target() void {}
    pub fn sync_target(_: *const AppliedDb) void {}
    pub fn new_batch(_: db.BatchContext(AppliedDb)) !TestUnmerkleized {
        return .{};
    }
    pub fn matches_sync_target(_: *const TestMerkleized, _: *const void) bool {
        return true;
    }
    pub fn apply(self: *AppliedDb, _: *const TestMerkleized) !void {
        self.applied.* += 1;
    }
    pub fn finalize(_: *AppliedDb) !void {}
    pub fn deinit(_: *AppliedDb) void {}
};

const Set = db.Tuple(.{ AppliedDb, AppliedDb });

fn apply_both(set: *const Set) anyerror!void {
    const batches: Set.Merkleized = .{ .{}, .{} };
    try set.apply(&batches);
}

/// Runs `body` on a deterministic runtime that fails after 5 simulated seconds.
fn run(comptime body: fn (Io) anyerror!void) !void {
    const timeout_ns = 5 * std.time.ns_per_s;
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .timeout_ns = timeout_ns });
    defer runner.deinit();
    try try runner.start(body, .{runner.io()});
}

fn holds_no_member_while_waiting(io: Io) anyerror!void {
    var applied: [2]u64 = .{ 0, 0 };
    var set = try Set.open(TestEnv{ .gpa = gpa, .io = io }, .{ &applied[0], &applied[1] }, null);
    defer set.deinit();
    var reader_first = try set.members[0].read();
    var apply = try io.concurrent(apply_both, .{&set});
    try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expectEqual(@as(u64, 0), applied[0]);
    // The apply waits behind the first member's reader; the second stays readable.
    var reader_second = try set.members[1].read();
    reader_second.deinit();
    reader_first.deinit();
    try apply.await(io);
    try testing.expectEqual([2]u64{ 1, 1 }, applied);
}

fn cancellation_keeps_members(io: Io) anyerror!void {
    var applied: [2]u64 = .{ 0, 0 };
    var set = try Set.open(TestEnv{ .gpa = gpa, .io = io }, .{ &applied[0], &applied[1] }, null);
    defer set.deinit();
    var reader_second = try set.members[1].read();
    // The first member applies while the second waits for `reader_second`.
    var apply = try io.concurrent(apply_both, .{&set});
    try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expectEqual([2]u64{ 1, 0 }, applied);
    // Cancel the apply, then release the reader it was waiting behind.
    try testing.expectError(error.Canceled, apply.cancel(io));
    reader_second.deinit();
    // Neither member was lost, yet only the first applied its batch.
    try testing.expect(!set.members[0].is_lost() and !set.members[1].is_lost());
    var guard_first = try set.members[0].read();
    guard_first.deinit();
    var guard_second = try set.members[1].read();
    guard_second.deinit();
    try testing.expectEqual([2]u64{ 1, 0 }, applied);
}

test "stateful db tuple: an apply holds no member while it waits for another's reader" {
    try run(holds_no_member_while_waiting);
}

test "stateful db tuple: a canceled apply keeps its completed and untouched members" {
    try run(cancellation_keeps_members);
}

/// Counts batches built and applies started, and holds each apply while `hold` is set
/// (commonware's `BlockingApplyDb`).
const BlockingDb = struct {
    counts: *Counts,

    const Counts = struct { io: Io, built: u64 = 0, started: u64 = 0, hold: bool = true };

    pub const Config = *Counts;
    pub const SyncTarget = void;
    pub const Unmerkleized = TestUnmerkleized;
    pub const Merkleized = TestMerkleized;

    pub fn init(_: TestEnv, counts: *Counts, _: ?void) !BlockingDb {
        return .{ .counts = counts };
    }
    pub fn initial_sync_target() void {}
    pub fn sync_target(_: *const BlockingDb) void {}
    pub fn new_batch(context: db.BatchContext(BlockingDb)) !TestUnmerkleized {
        context.database.counts.built += 1;
        return .{};
    }
    pub fn matches_sync_target(_: *const TestMerkleized, _: *const void) bool {
        return true;
    }
    pub fn apply(self: *BlockingDb, _: *const TestMerkleized) !void {
        self.counts.started += 1;
        while (self.counts.hold) try self.counts.io.sleep(.fromMilliseconds(1), .awake);
    }
    pub fn finalize(_: *BlockingDb) !void {}
    pub fn deinit(_: *BlockingDb) void {}
};

const BlockingSet = db.Tuple(.{ BlockingDb, BlockingDb });

fn build_both(set: *const BlockingSet) anyerror!void {
    var batches = try set.new_batches();
    inline for (0..2) |i| batches[i].deinit();
}

fn apply_blocking(set: *const BlockingSet) anyerror!void {
    const batches: BlockingSet.Merkleized = .{ .{}, .{} };
    try set.apply(&batches);
}

fn new_batches_reads_concurrently(io: Io) anyerror!void {
    var counts: [2]BlockingDb.Counts = .{ .{ .io = io }, .{ .io = io } };
    const env: TestEnv = .{ .gpa = gpa, .io = io };
    var set = try BlockingSet.open(env, .{ &counts[0], &counts[1] }, null);
    defer set.deinit();
    var slot_first = try set.members[0].write();
    var slot_second = try set.members[1].write();
    var build = try io.concurrent(build_both, .{&set});
    var first_held = true;
    // A failed check still lets the build finish before the set closes.
    errdefer {
        if (first_held) slot_first.put();
        build.await(io) catch {};
    }
    try io.sleep(.fromMilliseconds(10), .awake);
    // Releasing the second member lets its batch build while the first is still held.
    slot_second.put();
    try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expectEqual(@as(u64, 0), counts[0].built);
    try testing.expectEqual(@as(u64, 1), counts[1].built);
    slot_first.put();
    first_held = false;
    try build.await(io);
    try testing.expectEqual(@as(u64, 1), counts[0].built);
}

fn apply_runs_in_parallel(io: Io) anyerror!void {
    var counts: [2]BlockingDb.Counts = .{ .{ .io = io }, .{ .io = io } };
    const env: TestEnv = .{ .gpa = gpa, .io = io };
    var set = try BlockingSet.open(env, .{ &counts[0], &counts[1] }, null);
    defer set.deinit();
    var apply = try io.concurrent(apply_blocking, .{&set});
    // A failed check still lets the apply finish before the set closes.
    errdefer {
        counts[0].hold = false;
        counts[1].hold = false;
        apply.await(io) catch {};
    }
    try io.sleep(.fromMilliseconds(10), .awake);
    // Both members started while the first is still held.
    try testing.expectEqual(@as(u64, 1), counts[0].started);
    try testing.expectEqual(@as(u64, 1), counts[1].started);
    counts[0].hold = false;
    counts[1].hold = false;
    try apply.await(io);
}

test "stateful db tuple: new_batches queues reads on every member at once" {
    try run(new_batches_reads_concurrently);
}

test "stateful db tuple: apply runs every member at once" {
    try run(apply_runs_in_parallel);
}
