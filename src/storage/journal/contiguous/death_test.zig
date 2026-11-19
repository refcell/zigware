//! commonware's `#[should_panic]` tests of the contiguous journals, as death tests
//! (`utils.death`): `read_many` with unsorted or duplicate positions ("positions must be
//! strictly increasing") on both journals, and `init_sync` with a reversed range. Snapshot
//! readers are not ported, so `read_many` runs on the journal directly.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const death = @import("utils").death;
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const variable = @import("variable.zig");
const contiguous = @import("mod.zig");
const authenticated = @import("../authenticated.zig");

const gpa = testing.allocator;
const strictly_increasing = "reached unreachable code";

/// Read `positions` from a fixed journal of five items (commonware's `test_cfg(10)`).
fn fixed_read_many(positions: []const u64) !void {
    var storage: runtime.storage.memory.Storage = .init(gpa);
    defer storage.deinit();
    var cache = try paged.CacheRef.init(gpa, 44, 3);
    defer cache.deinit();
    var journal = try fixed.Journal(u64).init(gpa, storage.storage(), .{
        .partition = "test-partition",
        .items_per_blob = 10,
        .cache_ref = &cache,
        .write_buffer = 2048,
        .replay_buffer = 2048,
    });
    defer journal.deinit();
    for (0..5) |i| _ = try journal.append(i);
    var out: [2]u64 = undefined;
    try journal.read_many(positions, out[0..positions.len]);
}

fn variable_cfg(cache: *paged.CacheRef, partition: []const u8) variable.Config(u64) {
    return .{
        .partition = partition,
        .items_per_section = 5,
        .codec_config = {},
        .cache_ref = cache,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
}

/// Read `positions` from a synced variable journal of five items.
fn variable_read_many(positions: []const u64) !void {
    var storage: runtime.storage.memory.Storage = .init(gpa);
    defer storage.deinit();
    var cache = try paged.CacheRef.init(gpa, 64, 2);
    defer cache.deinit();
    const cfg = variable_cfg(&cache, "read-many");
    var journal = try variable.Journal(u64).init(gpa, storage.storage(), cfg);
    defer journal.deinit();
    for (0..5) |i| _ = try journal.append(i * 100);
    try journal.sync();
    var out: [2]u64 = undefined;
    try journal.read_many(positions, out[0..positions.len]);
}

// commonware `fixed::test_read_many_rejects_unsorted_positions`.
test "fixed read_many panics on unsorted positions" {
    try death.expect_panic(@src(), strictly_increasing, struct {
        fn body() !void {
            try fixed_read_many(&.{ 2, 1 });
        }
    }.body);
}

// commonware `fixed::test_read_many_rejects_duplicate_positions`.
test "fixed read_many panics on duplicate positions" {
    try death.expect_panic(@src(), strictly_increasing, struct {
        fn body() !void {
            try fixed_read_many(&.{ 1, 1 });
        }
    }.body);
}

// commonware `variable::test_variable_read_many_rejects_unsorted_positions`.
test "variable read_many panics on unsorted positions" {
    try death.expect_panic(@src(), strictly_increasing, struct {
        fn body() !void {
            try variable_read_many(&.{ 2, 1 });
        }
    }.body);
}

// commonware `variable::test_variable_read_many_rejects_duplicate_positions`.
test "variable read_many panics on duplicate positions" {
    try death.expect_panic(@src(), strictly_increasing, struct {
        fn body() !void {
            try variable_read_many(&.{ 1, 1 });
        }
    }.body);
}

// commonware `variable::test_init_sync_invalid_parameters`: a range whose start is past its
// end.
test "variable init_sync panics on a reversed range" {
    try death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            var storage: runtime.storage.memory.Storage = .init(gpa);
            defer storage.deinit();
            var cache = try paged.CacheRef.init(gpa, 64, 2);
            defer cache.deinit();
            const cfg = variable_cfg(&cache, "test-invalid");
            const range: contiguous.Bounds = .{ .start = 10, .end = 5 };
            const J = variable.Journal(u64);
            var journal = try authenticated.init_sync(J, gpa, storage.storage(), cfg, range);
            journal.deinit();
        }
    }.body);
}
