//! Tests of metered storage (commonware `storage::metered::tests`). No counterpart:
//! `test_shared_blob_owners_share_metrics` (a Zig handle has one owner; Rust shares it in an
//! `Arc`).

const std = @import("std");
const testing = std.testing;
const iface = @import("../storage.zig");
const memory = @import("memory.zig");
const metered = @import("metered.zig");
const audited = @import("audited.zig");
const suite = @import("tests.zig");
const deterministic = @import("../deterministic.zig");
const metrics = @import("../telemetry/metrics/mod.zig");

const gpa = testing.allocator;

/// Memory storage metered into its own registry, under `storage`.
const Harness = struct {
    registry: metrics.Registry,
    inner: memory.Storage,
    storage: metered.Storage,

    fn init(h: *Harness) !void {
        h.registry = .init(gpa);
        errdefer h.registry.deinit();
        h.inner = .init(gpa);
        errdefer h.inner.deinit();
        const scope = metrics.Scope.init(&h.registry).sub_registry("storage");
        h.storage = try .init(gpa, h.inner.storage(), &scope);
    }

    fn deinit(h: *Harness) void {
        h.storage.deinit();
        h.inner.deinit();
        h.registry.deinit();
    }

    fn get(h: *Harness, comptime field: []const u8) i64 {
        return @intCast(@field(h.storage.metrics, field).metric().get());
    }
};

test "metered storage passes the storage suite (test_metered_storage)" {
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    try (try runner.start(suite.run_storage_tests, .{ runner.io(), gpa, h.storage.storage() }));
    try testing.expectEqual(@as(i64, 0), h.get("open_blobs"));
    try testing.expect(h.get("storage_writes") > 0);
}

test "metered blob metrics (test_metered_blob_metrics)" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const blob = (try h.storage.storage().open("partition", "test_blob")).blob;
    try testing.expectEqual(@as(i64, 1), h.get("open_blobs"));
    try blob.write_at(0, "hello world", .{});
    try testing.expectEqual(@as(i64, 1), h.get("storage_writes"));
    try testing.expectEqual(@as(i64, 11), h.get("storage_write_bytes"));
    var buffer: [11]u8 = undefined;
    try blob.read_at(0, &buffer);
    try testing.expectEqualStrings("hello world", &buffer);
    try testing.expectEqual(@as(i64, 1), h.get("storage_reads"));
    try testing.expectEqual(@as(i64, 11), h.get("storage_read_bytes"));
    try blob.sync();
    try testing.expectEqual(@as(i64, 1), h.get("storage_syncs"));
    // A write with `sync` counts a write and a sync.
    try blob.write_at_vectored(11, &.{ " ag", "ain" }, .{ .sync = true });
    try testing.expectEqual(@as(i64, 2), h.get("storage_writes"));
    try testing.expectEqual(@as(i64, 17), h.get("storage_write_bytes"));
    try testing.expectEqual(@as(i64, 2), h.get("storage_syncs"));
    try blob.resize(11);
    try testing.expectEqual(@as(i64, 1), h.get("storage_resizes"));
    blob.close();
    try testing.expectEqual(@as(i64, 0), h.get("open_blobs"));
}

test "start_sync counts a sync, as sync does (test_metered_start_sync_increments_metric)" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const blob = (try h.storage.storage().open("partition", "test_blob")).blob;
    defer blob.close();
    try blob.write_at(0, "hello world", .{});
    try testing.expectEqual(@as(i64, 0), h.get("storage_syncs"));
    try (try blob.start_sync()).wait_release();
    try testing.expectEqual(@as(i64, 1), h.get("storage_syncs"));
}

test "metered reads forward their options and count (test_metered_blob_forwards_read_options)" {
    // The audited storage below hashes the read options, so its state shows what arrived.
    var states: [2][8]u8 = undefined;
    for ([_]iface.ReadOptions{ .{}, .{ .dont_cache = true } }, &states) |options, *state| {
        var registry: metrics.Registry = .init(gpa);
        defer registry.deinit();
        var inner: memory.Storage = .init(gpa);
        defer inner.deinit();
        var auditor: deterministic.Auditor = .{};
        var audit: audited.Storage = .init(gpa, inner.storage(), &auditor);
        defer audit.deinit();
        const scope = metrics.Scope.init(&registry).sub_registry("storage");
        var storage: metered.Storage = try .init(gpa, audit.storage(), &scope);
        defer storage.deinit();
        const blob = (try storage.storage().open("partition", "blob")).blob;
        try blob.write_at(0, "data", .{});
        var buffer: [4]u8 = undefined;
        try blob.read_at_options(0, &buffer, options);
        try blob.read_at_options(0, &buffer, options);
        try testing.expectEqual(@as(u64, 2), storage.metrics.storage_reads.metric().get());
        try testing.expectEqual(@as(u64, 8), storage.metrics.storage_read_bytes.metric().get());
        state.* = auditor.state();
    }
    try testing.expect(!std.mem.eql(u8, &states[0], &states[1]));
}

test "a failed open does not count an open blob (test_failed_open_does_not_count_open_blob)" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const blob = (try h.storage.storage().open("partition", "test_blob")).blob;
    try blob.sync();
    blob.close();
    try testing.expectEqual(@as(i64, 0), h.get("open_blobs"));
    const result = h.storage.storage().open_versioned("partition", "test_blob", .only(7));
    try testing.expectError(error.BlobVersionMismatch, result);
    try testing.expectEqual(@as(i64, 0), h.get("open_blobs"));
}

test "open blobs count each handle (test_metered_blob_multiple_blobs)" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const first = (try h.storage.storage().open("partition", "blob1")).blob;
    const second = (try h.storage.storage().open("partition", "blob2")).blob;
    try testing.expectEqual(@as(i64, 2), h.get("open_blobs"));
    try first.sync();
    first.close();
    try testing.expectEqual(@as(i64, 1), h.get("open_blobs"));
    try second.sync();
    second.close();
    try testing.expectEqual(@as(i64, 0), h.get("open_blobs"));
}

test "metered storage registers commonware's metric names" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const blob = (try h.storage.storage().open("partition", "blob")).blob;
    defer blob.close();
    const text = try h.registry.encode(gpa);
    defer gpa.free(text);
    const expected = [_][]const u8{
        "# HELP storage_open_blobs Number of open blobs.\n# TYPE storage_open_blobs gauge\n" ++
            "storage_open_blobs 1\n",
        "storage_storage_reads_total 0\n",
        "storage_storage_read_bytes_total 0\n",
        "storage_storage_writes_total 0\n",
        "storage_storage_write_bytes_total 0\n",
        "storage_storage_syncs_total 0\n",
        "storage_storage_resizes_total 0\n",
    };
    for (expected) |line| {
        if (std.mem.indexOf(u8, text, line) == null) {
            std.debug.print("missing {s} in:\n{s}\n", .{ line, text });
            return error.TestExpectedEqual;
        }
    }
}
