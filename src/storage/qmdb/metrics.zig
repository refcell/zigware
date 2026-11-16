//! Metrics for QMDB variants (qmdb/metrics.rs).
//!
//! Every variant registers the same set under its scope. Durations are histograms over
//! `Buckets.local`; time them with `timer(io)` and `finish(io)` (commonware's drop-observing
//! `ScopedTimer`), using the database's `std.Io` clock.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");

const telemetry = runtime.telemetry.metrics;
const Scope = telemetry.Scope;
const Counter = telemetry.Counter;
const Gauge = telemetry.Gauge;
const Timed = telemetry.histogram.Timed;

pub const Metrics = struct {
    /// Logical operation end.
    size: Gauge,
    /// Oldest retained operation location.
    pruning_boundary: Gauge,
    /// Retained operation count.
    retained: Gauge,
    /// Application-declared pruning floor location.
    inactivity_floor: Gauge,
    /// Most recent commit operation location.
    last_commit: Gauge,
    apply_batch_calls: Counter,
    apply_batch_duration: Timed,
    /// Operations written by completed batch applications.
    operations_applied: Counter,
    get_calls: Counter,
    get_duration: Timed,
    /// Non-empty get-many calls.
    get_many_calls: Counter,
    get_many_duration: Timed,
    /// Lookups requested by read paths, found or not.
    lookups_requested: Counter,
    commit_calls: Counter,
    commit_duration: Timed,
    /// Pipelined syncs begun via `start_sync`.
    start_sync_calls: Counter,
    sync_calls: Counter,
    sync_duration: Timed,
    prune_calls: Counter,
    prune_duration: Timed,

    const gauges = .{
        .{ "size", "Logical operation end" },
        .{ "pruning_boundary", "Oldest retained operation location" },
        .{ "retained", "Number of retained operations" },
        .{ "inactivity_floor", "Application-declared pruning floor location" },
        .{ "last_commit", "Most recent commit operation location" },
    };
    const counters = .{
        .{ "apply_batch_calls", "Number of apply-batch calls" },
        .{
            "operations_applied",
            "Number of operations written by completed batch applications",
        },
        .{ "get_calls", "Number of get calls" },
        .{ "get_many_calls", "Number of non-empty get-many calls" },
        .{
            "lookups_requested",
            "Number of lookups requested by get/get-many calls, including misses",
        },
        .{ "commit_calls", "Number of commit calls" },
        .{ "start_sync_calls", "Number of start_sync calls" },
        .{ "sync_calls", "Number of sync calls" },
        .{ "prune_calls", "Number of prune calls" },
    };
    const timers = .{
        .{ "apply_batch_duration", "Duration of apply-batch calls" },
        .{ "get_duration", "Duration of get calls" },
        .{ "get_many_duration", "Duration of non-empty get-many calls" },
        .{ "commit_duration", "Duration of commit calls" },
        .{ "sync_duration", "Duration of sync calls" },
        .{ "prune_duration", "Duration of prune calls" },
    };

    /// Registers the full metric set under `scope`.
    pub fn init(scope: Scope) Allocator.Error!Metrics {
        var self: Metrics = undefined;
        const fields = @typeInfo(Metrics).@"struct".field_names.len;
        comptime assert(gauges.len + counters.len + timers.len == fields);
        var registered: usize = 0;
        errdefer inline for (gauges ++ counters ++ timers, 0..) |entry, index| {
            if (index < registered) @field(self, entry[0]).deinit();
        };
        inline for (gauges) |entry| {
            @field(self, entry[0]) = try scope.gauge(entry[0], entry[1]);
            registered += 1;
        }
        inline for (counters) |entry| {
            @field(self, entry[0]) = try scope.counter(entry[0], entry[1]);
            registered += 1;
        }
        inline for (timers) |entry| {
            @field(self, entry[0]) = try Timed.register(&scope, entry[0], entry[1]);
            registered += 1;
        }
        return self;
    }

    pub fn deinit(self: *Metrics) void {
        inline for (gauges ++ counters ++ timers) |entry| @field(self, entry[0]).deinit();
        self.* = undefined;
    }

    /// Updates the state gauges.
    pub fn update(
        self: *Metrics,
        size: u64,
        pruning_boundary: u64,
        inactivity_floor: u64,
        last_commit: u64,
    ) void {
        assert(pruning_boundary <= size or size == 0);
        // Values above i64's range leave a gauge unchanged, as commonware's `try_set` does.
        _ = self.size.metric().try_set(size) catch {};
        _ = self.pruning_boundary.metric().try_set(pruning_boundary) catch {};
        _ = self.retained.metric().try_set(size -| pruning_boundary) catch {};
        _ = self.inactivity_floor.metric().try_set(inactivity_floor) catch {};
        _ = self.last_commit.metric().try_set(last_commit) catch {};
    }
};

const testing = std.testing;

test "metrics register and update" {
    const gpa = testing.allocator;
    var registry = telemetry.Registry.init(gpa);
    defer registry.deinit();
    var metrics = try Metrics.init(Scope.init(&registry).child("db"));
    defer metrics.deinit();
    metrics.update(10, 3, 4, 9);
    metrics.get_calls.metric().inc();
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    try testing.expect(telemetry.has_metric_value(text, "db_size", "10"));
    try testing.expect(telemetry.has_metric_value(text, "db_pruning_boundary", "3"));
    try testing.expect(telemetry.has_metric_value(text, "db_retained", "7"));
    try testing.expect(telemetry.has_metric_value(text, "db_inactivity_floor", "4"));
    try testing.expect(telemetry.has_metric_value(text, "db_last_commit", "9"));
    try testing.expect(telemetry.has_metric_value(text, "db_get_calls_total", "1"));
    try testing.expect(std.mem.indexOf(u8, text, "db_prune_duration_bucket") != null);
}
