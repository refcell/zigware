//! Metrics of the contiguous journals (commonware's `journal/contiguous/metrics.rs`).
//!
//! Fixed and variable journals register the same set. The duration histograms are not ported:
//! journals take no clock (time comes from the runtime context, which they do not hold).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const metrics = @import("runtime").telemetry.metrics;

pub const Metrics = struct {
    /// Logical end position.
    size: metrics.Gauge,
    /// Oldest readable item position.
    pruning_boundary: metrics.Gauge,
    /// Readable items retained.
    retained: metrics.Gauge,
    /// Items in the blob containing the newest retained item.
    tail_items: metrics.Gauge,
    append_calls: metrics.Counter,
    append_many_calls: metrics.Counter,
    append_prepared_calls: metrics.Counter,
    read_calls: metrics.Counter,
    read_many_calls: metrics.Counter,
    /// Items read without a blob read.
    cache_hits: metrics.Counter,
    /// Items that fell back to a blob read in `read` and `read_many`.
    cache_misses: metrics.Counter,
    /// Items returned by `read`, `read_many`, and the sync probes.
    items_read: metrics.Counter,
    start_sync_calls: metrics.Counter,
    commit_calls: metrics.Counter,
    sync_calls: metrics.Counter,

    const gauges = .{
        .{ "size", "Logical end position of the journal" },
        .{ "pruning_boundary", "Oldest readable item position" },
        .{ "retained", "Number of readable items retained" },
        .{ "tail_items", "Items in the blob containing the newest retained item" },
    };
    const counters = .{
        .{ "append_calls", "Number of single-item append calls" },
        .{ "append_many_calls", "Number of append-many calls" },
        .{ "append_prepared_calls", "Number of pre-encoded batch append calls" },
        .{ "read_calls", "Number of single-item read calls" },
        .{ "read_many_calls", "Number of non-empty batch read calls" },
        .{ "cache_hits", "Number of items served without a blob read" },
        .{ "cache_misses", "Number of items requiring a blob read" },
        .{
            "items_read",
            "Number of items returned by point reads, batch reads, and sync probes",
        },
        .{ "start_sync_calls", "Number of start_sync calls" },
        .{ "commit_calls", "Number of commit calls" },
        .{ "sync_calls", "Number of sync calls" },
    };

    /// Registers the set under `scope`, or records it unregistered without one.
    pub fn init(gpa: Allocator, scope: ?metrics.Scope) Allocator.Error!Metrics {
        var result: Metrics = undefined;
        var registered: usize = 0;
        errdefer {
            inline for (gauges ++ counters, 0..) |entry, index| {
                if (index < registered) @field(result, entry[0]).deinit();
            }
        }
        inline for (gauges) |entry| {
            @field(result, entry[0]) = if (scope) |s|
                try s.gauge(entry[0], entry[1])
            else
                try metrics.Gauge.detached(gpa, .{});
            registered += 1;
        }
        inline for (counters) |entry| {
            @field(result, entry[0]) = if (scope) |s|
                try s.counter(entry[0], entry[1])
            else
                try metrics.Counter.detached(gpa, .{});
            registered += 1;
        }
        assert(registered == gauges.len + counters.len);
        return result;
    }

    pub fn deinit(self: *Metrics) void {
        inline for (gauges ++ counters) |entry| @field(self, entry[0]).deinit();
        self.* = undefined;
    }

    /// Updates the state gauges from the current bounds. Like commonware's `try_set`, a value
    /// past `i64::MAX` (a journal reset near `u64::MAX`) leaves its gauge unchanged.
    pub fn update(self: *Metrics, size: u64, boundary: u64, items_per_blob: u64) void {
        assert(boundary <= size);
        assert(items_per_blob > 0);
        _ = self.size.metric().try_set(size) catch {};
        _ = self.pruning_boundary.metric().try_set(boundary) catch {};
        _ = self.retained.metric().try_set(size - boundary) catch {};
        const tail_items = if (size == boundary) 0 else blk: {
            const tail_start = (size - 1) / items_per_blob * items_per_blob;
            break :blk size - @max(boundary, tail_start);
        };
        _ = self.tail_items.metric().try_set(tail_items) catch {};
    }
};

test "tail_items counts the newest blob's readable items" {
    var set = try Metrics.init(std.testing.allocator, null);
    defer set.deinit();
    set.update(25, 0, 10);
    try std.testing.expectEqual(5, set.tail_items.metric().get());
    try std.testing.expectEqual(25, set.retained.metric().get());
    // A full tail blob counts all its items; a boundary inside it caps them.
    set.update(30, 23, 10);
    try std.testing.expectEqual(7, set.tail_items.metric().get());
    set.update(30, 30, 10);
    try std.testing.expectEqual(0, set.tail_items.metric().get());
}

test "variable journal metrics register with the offsets journal under its child" {
    const gpa = std.testing.allocator;
    const runtime = @import("runtime");
    const variable = @import("variable.zig");
    const Bytes = []const u8;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var memory = runtime.storage.memory.Storage.init(gpa);
    defer memory.deinit();
    var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 64, 4);
    defer cache_ref.deinit();
    var journal = try variable.Journal(Bytes).init(gpa, memory.storage(), .{
        .partition = "metrics",
        .items_per_section = 4,
        .codec_config = .{ .range = .full(), .item = {} },
        .cache_ref = &cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
        .metrics = metrics.Scope.init(&registry).child("journal"),
    });
    defer journal.deinit();
    for (0..10) |_| _ = try journal.append("item");
    try journal.sync();
    _ = try journal.prune(5);
    const item = try journal.read(6);
    gpa.free(item);
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    const expect = std.testing.expect;
    try expect(metrics.has_metric_value(text, "journal_size", "10"));
    try expect(metrics.has_metric_value(text, "journal_pruning_boundary", "4"));
    try expect(metrics.has_metric_value(text, "journal_retained", "6"));
    try expect(metrics.has_metric_value(text, "journal_tail_items", "2"));
    try expect(metrics.has_metric_value(text, "journal_append_calls_total", "10"));
    try expect(metrics.has_metric_value(text, "journal_read_calls_total", "1"));
    try expect(metrics.has_metric_value(text, "journal_items_read_total", "1"));
    try expect(metrics.has_metric_value(text, "journal_sync_calls_total", "1"));
    try expect(metrics.has_metric_value(text, "journal_offsets_size", "10"));
    // Data blobs [1, 2] remain after pruning blob 0; offsets blobs too.
    try expect(metrics.has_metric_value(text, "journal_data_tracked", "2"));
    try expect(metrics.has_metric_value(text, "journal_data_pruned_total", "1"));
    try expect(metrics.has_metric_value(text, "journal_offsets_blobs_tracked", "2"));
}
