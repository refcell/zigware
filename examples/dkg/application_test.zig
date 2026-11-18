//! The application's state against commonware's: the roots and ranges its QMDB reaches, printed
//! by a scratch test over commonware's own `Database` and `db_config` (heights 1 through 4,
//! each batch forked from the last, with height 2 applied and finalized on the way).

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const types = @import("types.zig");
const application = @import("application.zig");

const runtime = zigware.runtime;
const metrics = runtime.telemetry.metrics;
const ed25519 = zigware.cryptography.ed25519;
const App = application.App;
const Database = application.Database;

const initial_root = "1bb24ad3198bc9f4190c3b359a13234591ca8600ad83230a95d649f7f2279a55";

/// Root and `[start, end)` after each height.
const expected = [_]struct { []const u8, u64, u64 }{
    .{ "fa2a08a308a38fe26011a77fc056f400617a8eddb753adf731d949688c7f04be", 2, 4 },
    .{ "3edbbb969f37d5168ee270ce1995cca2a482dfd47b95a1209b1fe1aba6b2efc9", 5, 7 },
    .{ "a1bb63ad049c721ec6ec929914dc70d6e34baffaf9cd9903f746ef15570d82c2", 8, 10 },
    .{ "3e7eae57bc2136599523a9a72f7be4e174c58e1740c1c93d74e28f034efa1863", 11, 13 },
};

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,
    arena: std.heap.ArenaAllocator,

    fn init(harness: *Harness) !void {
        harness.* = .{
            .storage = .init(testing.allocator),
            .cache_ref = try .init(testing.allocator, types.page_size, types.page_cache_size),
            .registry = metrics.Registry.init(testing.allocator),
            .arena = .init(testing.allocator),
        };
    }

    fn deinit(harness: *Harness) void {
        harness.arena.deinit();
        harness.registry.deinit();
        harness.cache_ref.deinit();
        harness.storage.deinit();
    }

    fn open(harness: *Harness) !Database {
        const arena = harness.arena.allocator();
        const config = try application.db_config(arena, "v", &harness.cache_ref);
        return Database.open(.{
            .gpa = testing.allocator,
            .io = testing.io,
            .storage = harness.storage.interface(),
            .scope = metrics.Scope.init(&harness.registry).child("db"),
        }, config, null);
    }
};

fn expect_target(target: types.Target, root_hex: []const u8, start: u64, end: u64) !void {
    var root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&root, root_hex);
    try testing.expectEqualSlices(u8, &root, &target.root.bytes);
    try testing.expectEqual(start, target.start);
    try testing.expectEqual(end, target.end);
}

test "dkg: the application reaches commonware's state roots" {
    try expect_target(Database.initial_sync_targets(), initial_root, 0, 1);
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const database = try harness.open();
    defer database.deinit();

    var batch = try database.new_batches();
    for (expected, 1..) |row, height| {
        var merkleized = try App.execute(.new(height), &batch);
        defer merkleized.deinit();
        try expect_target(application.target_of(&merkleized), row[0], row[1], row[2]);
        batch = try Database.fork_batches(&merkleized);
        if (height == 2) {
            try database.apply(&merkleized);
            const barrier = try database.finalize();
            try barrier.durable();
            try expect_target(try database.committed_targets(), row[0], row[1], row[2]);
        }
    }
    batch.deinit();
}

test "dkg: propose builds the parent's child over the state it reaches" {
    const gpa = testing.allocator;
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const database = try harness.open();
    defer database.deinit();

    const leader = ed25519.PrivateKey.from_seed(0).public_key();
    const context: types.Context = .{
        .round = .new(.zero(), .new(1)),
        .leader = leader,
        .parent = .{ .zero(), .empty },
    };
    const initial = Database.initial_sync_targets();
    var parent = try types.Block.init(gpa, context, .empty, .zero(), initial, null);
    defer parent.deinit(gpa);

    var batch = try database.new_batches();
    var proposed = try App.propose(gpa, context, &parent, &batch, null);
    defer proposed.block.deinit(gpa);
    defer proposed.merkleized.deinit();
    try testing.expectEqual(1, proposed.block.height().get());
    try testing.expect(proposed.block.parent().eql(parent.digest()));
    const first = expected[0];
    try expect_target(App.sync_targets(&proposed.block), first[0], first[1], first[2]);

    // Processing the proposal on another fork reaches the same state.
    var other = try database.new_batches();
    var processed = try App.process(proposed.block.height(), &other);
    defer processed.deinit();
    try testing.expect(processed.root().eql(proposed.block.target.root));
}
