//! Sync progress gauges (commonware's `qmdb/sync/metrics.rs`): the synced size against the
//! size of the current target. The gauges match once the flow has synced the latest target.

const std = @import("std");
const assert = std.debug.assert;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;

pub const Metrics = struct {
    /// Size of the current sync target.
    target_size: metrics.Gauge,
    /// Database size reached by sync.
    size: metrics.Gauge,

    /// Register the gauges under `scope`.
    pub fn init(scope: metrics.Scope) std.mem.Allocator.Error!Metrics {
        var target_size = try scope.gauge("target_size", "Size of the current sync target");
        errdefer target_size.deinit();
        const size = try scope.gauge(
            "size",
            "Database size reached by sync, equal to target_size when sync completes",
        );
        return .{ .target_size = target_size, .size = size };
    }

    pub fn deinit(self: *Metrics) void {
        self.target_size.deinit();
        self.size.deinit();
        self.* = undefined;
    }

    /// Record the size of the current sync target.
    pub fn record_target(self: *const Metrics, size: u64) void {
        assert(size <= std.math.maxInt(i64));
        _ = self.target_size.metric().set(@intCast(size));
    }

    /// Record the database size reached by sync so far.
    pub fn record_synced(self: *const Metrics, size: u64) void {
        assert(size <= std.math.maxInt(i64));
        _ = self.size.metric().set(@intCast(size));
    }
};

test "metrics record target and synced sizes" {
    const gpa = std.testing.allocator;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var sync_metrics = try Metrics.init(metrics.Scope.init(&registry).child("sync"));
    defer sync_metrics.deinit();
    sync_metrics.record_target(42);
    sync_metrics.record_synced(17);
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    try std.testing.expect(metrics.has_metric_value(text, "sync_target_size", 42));
    try std.testing.expect(metrics.has_metric_value(text, "sync_size", 17));
}
