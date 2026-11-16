//! commonware `glue/src/stateful/db/mod.rs` tests of database sets, with its mock databases.
//!
//! commonware's tests of panics (`*_panic_identifies_failing_database`) check returned errors
//! and lost databases here, since sets return errors. Its cancellation and concurrency tests
//! (tuple apply in parallel, cancelled applies) have no counterpart while sets mutate their
//! members one at a time.

const std = @import("std");
const testing = std.testing;
const db = @import("mod.zig");

/// The environment mocks receive; only `gpa`, `io`, and `child` are used.
const TestEnv = struct {
    gpa: std.mem.Allocator = testing.allocator,
    io: std.Io = testing.io,

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

/// The batch, apply, and finalize declarations every mock shares.
fn Mock(comptime Self: type) type {
    return struct {
        pub const Unmerkleized = TestUnmerkleized;
        pub const Merkleized = TestMerkleized;

        pub fn new_batch(_: db.BatchContext(Self)) !TestUnmerkleized {
            return .{};
        }
        pub fn matches_sync_target(_: *const TestMerkleized, _: *const Self.SyncTarget) bool {
            return true;
        }
        pub fn apply(_: *Self, _: *const TestMerkleized) !void {}
        pub fn finalize(_: *Self) !void {}
        pub fn deinit(_: *Self) void {}
    };
}

/// Opens at the expected target, which must not be ahead of the configured one (commonware
/// `InitializationDb`).
const InitializationDb = struct {
    current_target: u64,

    pub const Config = u64;
    pub const SyncTarget = u64;
    const M = Mock(InitializationDb);
    pub const Unmerkleized = M.Unmerkleized;
    pub const Merkleized = M.Merkleized;
    pub const new_batch = M.new_batch;
    pub const matches_sync_target = M.matches_sync_target;
    pub const apply = M.apply;
    pub const finalize = M.finalize;
    pub const deinit = M.deinit;

    pub fn init(_: TestEnv, config: u64, expected: ?u64) !InitializationDb {
        const target = expected orelse config;
        if (target > config) return error.DatabaseBehind;
        return .{ .current_target = target };
    }
    pub fn initial_sync_target() u64 {
        return 0;
    }
    pub fn sync_target(self: *const InitializationDb) u64 {
        return self.current_target;
    }
};

/// Records its selected restart target durably, then may fail (commonware
/// `RecoverableStartupDb`).
const RecoverableStartupDb = struct {
    target: u64,

    pub const Config = struct { state: *u64, fail: bool };
    pub const SyncTarget = u64;
    const M = Mock(RecoverableStartupDb);
    pub const Unmerkleized = M.Unmerkleized;
    pub const Merkleized = M.Merkleized;
    pub const new_batch = M.new_batch;
    pub const matches_sync_target = M.matches_sync_target;
    pub const apply = M.apply;
    pub const finalize = M.finalize;
    pub const deinit = M.deinit;

    pub fn init(_: TestEnv, config: Config, expected: ?u64) !RecoverableStartupDb {
        const retained = config.state.*;
        const selected = expected orelse retained;
        if (selected > retained) return error.DatabaseBehind;
        config.state.* = selected;
        if (config.fail) return error.InitializationInterrupted;
        return .{ .target = selected };
    }
    pub fn initial_sync_target() u64 {
        return 0;
    }
    pub fn sync_target(self: *const RecoverableStartupDb) u64 {
        return self.target;
    }
};

/// Counts its prunes and finalizations, and fails its applies when asked.
const CountingDb = struct {
    counts: *Counts,

    pub const Counts = struct {
        prunes: u64 = 0,
        finalizes: u64 = 0,
        closes: u64 = 0,
        fail_apply: bool = false,
        fail_finalize: bool = false,
    };
    pub const Config = *Counts;
    pub const SyncTarget = void;
    pub const Unmerkleized = TestUnmerkleized;
    pub const Merkleized = TestMerkleized;
    const M = Mock(CountingDb);
    pub const new_batch = M.new_batch;
    pub const matches_sync_target = M.matches_sync_target;

    pub fn init(_: TestEnv, counts: *Counts, _: ?void) !CountingDb {
        return .{ .counts = counts };
    }
    pub fn initial_sync_target() void {}
    pub fn sync_target(_: *const CountingDb) void {}
    pub fn apply(self: *CountingDb, _: *const TestMerkleized) !void {
        if (self.counts.fail_apply) return error.TestApplyFailed;
    }
    pub fn finalize(self: *CountingDb) !void {
        if (self.counts.fail_finalize) return error.TestSyncFailed;
        self.counts.finalizes += 1;
    }
    pub fn prune(self: *CountingDb, _: *const void) !void {
        self.counts.prunes += 1;
    }
    pub fn deinit(self: *CountingDb) void {
        self.counts.closes += 1;
    }
};

test "stateful db: tuple initialization retries a partial failure and rejects behind" {
    const Set = db.Tuple(.{ RecoverableStartupDb, RecoverableStartupDb });
    var left: u64 = 3;
    var right: u64 = 2;
    const interrupted = Set.open(TestEnv{}, .{
        .{ .state = &left, .fail = false },
        .{ .state = &right, .fail = true },
    }, .{ 1, 1 });
    try testing.expectError(error.InitializationInterrupted, interrupted);
    try testing.expectEqual(1, left);
    try testing.expectEqual(1, right);

    var recovered = try Set.open(TestEnv{}, .{
        .{ .state = &left, .fail = false },
        .{ .state = &right, .fail = false },
    }, .{ 1, 1 });
    try testing.expectEqual(.{ 1, 1 }, try recovered.committed_targets());
    recovered.deinit();

    const behind = Set.open(TestEnv{}, .{
        .{ .state = &left, .fail = false },
        .{ .state = &right, .fail = false },
    }, .{ 1, 2 });
    try testing.expectError(error.DatabaseBehind, behind);
}

test "stateful db: tuple initialization validates ahead and aligned databases" {
    const Set = db.Tuple(.{ InitializationDb, InitializationDb });
    var set = try Set.open(TestEnv{}, .{ 2, 1 }, .{ 1, 1 });
    defer set.deinit();
    inline for (0..2) |i| {
        var guard = try set.members[i].read();
        defer guard.deinit();
        try testing.expectEqual(1, guard.get().current_target);
    }
    try testing.expectEqual(.{ 0, 0 }, Set.initial_sync_targets());
}

test "stateful db: a failed tuple open closes the members it opened" {
    const Set = db.Tuple(.{ CountingDb, InitializationDb });
    var counts: CountingDb.Counts = .{};
    const opened = Set.open(TestEnv{}, .{ &counts, 1 }, .{ {}, 2 });
    try testing.expectError(error.DatabaseBehind, opened);
    try testing.expectEqual(1, counts.closes);
}

test "stateful db: database set prune calls managed db prune" {
    var counts: CountingDb.Counts = .{};
    const shared = try db.Shared(CountingDb).open(TestEnv{}, &counts, null);
    defer shared.deinit();
    try shared.prune(&{});
    try testing.expectEqual(1, counts.prunes);
}

test "stateful db: new batches release the read lock before returning" {
    var counts: CountingDb.Counts = .{};
    const Set = db.Tuple(.{ CountingDb, CountingDb });
    var set = try Set.open(TestEnv{}, .{ &counts, &counts }, null);
    defer set.deinit();
    var batches = try set.new_batches();
    inline for (0..2) |i| batches[i].deinit();
    inline for (0..2) |i| {
        var slot = try set.members[i].write(); // Would block if a read lock were still held.
        slot.put();
    }
    var single = try set.members[0].new_batches();
    single.deinit();
}

test "stateful db: a failed apply loses only that member and reports it" {
    var good: CountingDb.Counts = .{};
    var bad: CountingDb.Counts = .{ .fail_apply = true };
    const Set = db.Tuple(.{ CountingDb, CountingDb });
    var set = try Set.open(TestEnv{}, .{ &good, &bad }, null);
    defer set.deinit();
    const batches: Set.Merkleized = .{ .{}, .{} };
    try testing.expectError(error.TestApplyFailed, set.apply(&batches));
    try testing.expect(!set.members[0].is_lost());
    try testing.expect(set.members[1].is_lost());
    try testing.expectEqual(1, bad.closes); // A lost member is closed at once.
}

test "stateful db: barriers report every member's sync" {
    var good: CountingDb.Counts = .{};
    var bad: CountingDb.Counts = .{ .fail_finalize = true };
    const Set = db.Tuple(.{ CountingDb, CountingDb, CountingDb });
    var set = try Set.open(TestEnv{}, .{ &good, &bad, &good }, null);
    defer set.deinit();
    const barrier = try set.finalize();
    try testing.expectError(error.DatabaseSyncFailed, barrier.durable());
    const failure = barrier.first_failure().?;
    try testing.expectEqual(1, failure.index.?);
    try testing.expectEqual(error.TestSyncFailed, failure.err);
    try testing.expectEqual(2, good.finalizes); // The later member still ran.

    const empty: db.Barrier = .{};
    try empty.durable();
}

test "stateful db: matching sync targets requires every member" {
    const Set = db.Tuple(.{ InitializationDb, InitializationDb });
    const batches: Set.Merkleized = .{ .{}, .{} };
    try testing.expect(Set.matches_sync_targets(&batches, &.{ 1, 2 }));
    var forked = try Set.fork_batches(&batches);
    inline for (0..2) |i| forked[i].deinit();
}
