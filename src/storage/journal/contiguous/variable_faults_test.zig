//! commonware's `journal/contiguous/variable.rs` tests of storage faults during syncs: a failed
//! flush inside `start_sync`, and init syncing adopted data before rebuilt offsets become
//! durable (checked with a sync fault scoped to the data partition, commonware's
//! `SyncFaultContext`).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const paged = runtime.buffer.paged;
const variable = @import("variable.zig");

const gpa = testing.allocator;
const Faulty = runtime.storage.faulty.Storage(utils.rng.TestRng);

test "variable: a failed flush inside start_sync returns an error" {
    var inner: runtime.storage.memory.Storage = .init(gpa);
    defer inner.deinit();
    var rng: utils.rng.TestRng = .init(0);
    var storage: Faulty = .init(gpa, &inner, &rng, .{});
    defer storage.deinit();
    var cache_ref = try paged.CacheRef.init(gpa, 101, 2);
    defer cache_ref.deinit();
    var journal = try variable.Journal(u64).init(gpa, storage.storage(), .{
        .partition = "variable-start-sync-flush-failure",
        .items_per_section = 3,
        .codec_config = {},
        .cache_ref = &cache_ref,
        .write_buffer = 2048,
        .replay_buffer = 2048,
    });
    defer journal.deinit();

    // Buffer an item so start_sync must flush it, then fail every write.
    try testing.expectEqual(0, try journal.append(0));
    storage.config = .{
        .write_rate = .{ .failure_rate = .one, .retention_rate = .zero, .mode = .prefix },
    };
    try testing.expectError(error.Io, journal.start_sync());
}

test "variable: init syncs adopted data before advancing rebuilt offsets" {
    const Journal = variable.Journal([32]u8);
    const partition = "init-adopted-variable";
    var inner: runtime.storage.memory.Storage = .init(gpa);
    defer inner.deinit();
    var cache_ref = try paged.CacheRef.init(gpa, 512, 2);
    defer cache_ref.deinit();
    const cfg: variable.Config([32]u8) = .{
        .partition = partition,
        .items_per_section = 10,
        .codec_config = {},
        .cache_ref = &cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
    {
        var journal = try Journal.init(gpa, inner.storage(), cfg);
        defer journal.deinit();
        try testing.expectEqual(0, try journal.append(@splat(1)));
        try testing.expectEqual(1, try journal.append(@splat(2)));
        try journal.sync();
        // The state of a crash after item 2's data became visible to recovery, but before
        // the offsets journal's recovery watermark advanced past item 1.
        try journal.test_set_offsets_recovery_watermark(1);
    }

    // init must sync the adopted data before the rebuilt offsets become durable, so a sync
    // fault scoped to the data partition fails the reopen.
    var faults: runtime.storage.mocks.SyncFaults = .{
        .partition = partition ++ variable.data_suffix,
    };
    var wrapper: runtime.storage.mocks.SyncFault = .init(gpa, inner.storage(), &faults);
    try testing.expectError(error.Io, Journal.init(gpa, wrapper.storage(), cfg));

    // Without the fault the same storage reopens with both items.
    var journal = try Journal.init(gpa, inner.storage(), cfg);
    defer journal.deinit();
    try testing.expectEqual(2, journal.size());
    try testing.expectEqual(@as([32]u8, @splat(2)), try journal.read(1));
}
