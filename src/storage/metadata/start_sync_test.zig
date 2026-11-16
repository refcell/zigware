//! commonware's `start_sync` metadata tests (`storage/src/metadata/mod.rs`), on
//! `runtime.storage.faulty` where commonware injects faults.
//!
//! Syncs complete synchronously here: a started sync has finished (or failed) when
//! `start_sync` returns, so a parked sync is one whose blob sync fails, and a dropped handle
//! changes nothing. A failure consumes the store at the call that hits it (only `deinit` may
//! follow) instead of at the next sync.

const std = @import("std");
const testing = std.testing;
const metadata = @import("mod.zig");
const Faults = @import("../archive/faults.zig").Faults;

const gpa = testing.allocator;
const Store = metadata.Metadata(u64, []const u8);
const config: metadata.Config([]const u8) = .{
    .partition = "test",
    .codec_config = .{ .range = .full(), .item = {} },
};

fn put(store: *Store, key: u64, byte: u8, len: usize) !void {
    const value = try gpa.alloc(u8, len);
    errdefer gpa.free(value);
    @memset(value, byte);
    if (try store.put(key, value)) |previous| gpa.free(previous);
}

fn expect_value(store: *const Store, key: u64, byte: u8, len: usize) !void {
    const value = store.get(key) orelse return error.TestExpectedValue;
    try testing.expectEqual(len, value.len);
    for (value.*) |actual| try testing.expectEqual(byte, actual);
}

fn open(faults: *Faults) !Store {
    return Store.init(gpa, faults.interface(), config);
}

test "start_sync: pipelined syncs then destroy leave nothing" {
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    var store = try open(&faults);
    try put(&store, 1, 3, 1);
    try store.start_sync();
    try put(&store, 1, 4, 1);
    try store.start_sync();
    try store.destroy();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try testing.expect(reopened.get(1) == null);
}

test "start_sync: the newest copy wins on reopen" {
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    {
        var store = try open(&faults);
        defer store.deinit();
        try put(&store, 1, 3, 1);
        try store.start_sync();
        try put(&store, 1, 4, 1);
        try store.start_sync();
    }
    try faults.crash();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try expect_value(&reopened, 1, 4, 1);
}

test "start_sync: a dropped handle does not cancel the sync" {
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    {
        var store = try open(&faults);
        defer store.deinit();
        try put(&store, 1, 3, 1);
        try store.start_sync();
        try store.sync();
    }
    try faults.crash();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try expect_value(&reopened, 1, 3, 1);
}

test "start_sync: a failed sync consumes the store and keeps the durable copy" {
    // Covers commonware's failure-fails-next-sync, dropped-handle-fails-next-sync, and
    // destroy-after-failed-sync tests: the failure surfaces on the call, and a reopen finds
    // the last acknowledged generation.
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    {
        var store = try open(&faults);
        defer store.deinit();
        for (1..4) |generation| {
            try put(&store, 0, @intCast(generation), 8);
            try store.sync();
        }
        try put(&store, 0, 4, 8);
        faults.layer.config = .{ .sync_rate = .one };
        defer faults.disarm();
        try testing.expectError(error.Io, store.start_sync());
        try testing.expect(store.failed);
    }
    try faults.crash();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try expect_value(&reopened, 0, 3, 8);
}

test "start_sync: a write failure consumes the store" {
    var faults: Faults = undefined;
    faults.init(gpa, 0);
    defer faults.deinit();
    {
        var store = try open(&faults);
        defer store.deinit();
        // Equal-size values settle the key order, so later syncs take the overwrite path,
        // which mutates the target copy's state before writing.
        try put(&store, 1, 1, 8);
        try store.sync();
        try put(&store, 1, 2, 8);
        try store.sync();
        try put(&store, 1, 3, 8);
        faults.layer.config = .{ .write_rate = .{
            .failure_rate = .one,
            .retention_rate = .zero,
            .mode = .prefix,
        } };
        defer faults.disarm();
        try testing.expectError(error.Io, store.start_sync());
        try testing.expect(store.failed);
    }
    try faults.crash();
    var reopened = try open(&faults);
    defer reopened.deinit();
    try expect_value(&reopened, 1, 2, 8);
}
