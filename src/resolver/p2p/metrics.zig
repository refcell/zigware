//! Metrics of the p2p resolver engine (commonware `resolver/src/p2p/metrics.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const metrics = @import("runtime").telemetry.metrics;

const status = metrics.status;
const Timed = metrics.Timed;

pub const Metrics = struct {
    /// Current number of pending fetch requests.
    fetch_pending: metrics.Gauge,
    /// Current number of active fetch requests.
    fetch_active: metrics.Gauge,
    /// Current number of serves in flight.
    serve_processing: metrics.Gauge,
    /// Fetch outcome events by status. Complete and partial resolutions count as `Success`;
    /// responses judged valid but resolving no subscribers count as `Ambiguous`. Redelivering
    /// an accepted response adds neither count.
    fetch: status.Counter,
    /// Canceled fetches by status.
    cancel: status.Counter,
    /// Serves by status.
    serve: status.Counter,
    /// Durations of successful serves.
    serve_duration: Timed,
    /// Time from starting a fetch until all subscribers in a delivery are resolved.
    fetch_duration: Timed,

    /// Registers every metric under `scope`.
    pub fn init(scope: *const metrics.Scope) Allocator.Error!Metrics {
        var fetch_pending = try scope.gauge(
            "fetch_pending",
            "Current number of pending fetch requests",
        );
        errdefer fetch_pending.deinit();
        var fetch_active = try scope.gauge(
            "fetch_active",
            "Current number of active fetch requests",
        );
        errdefer fetch_active.deinit();
        var serve_processing = try scope.gauge(
            "serve_processing",
            "Current number of serves currently processing",
        );
        errdefer serve_processing.deinit();
        var fetch = try status.Counter.register(scope, "fetch", "Number of fetches by status");
        errdefer fetch.deinit();
        var cancel = try status.Counter.register(
            scope,
            "cancel",
            "Number of canceled fetches by status",
        );
        errdefer cancel.deinit();
        var serve = try status.Counter.register(scope, "serve", "Number of serves by status");
        errdefer serve.deinit();
        var serve_duration = try scope.histogram(
            "serve_duration",
            "Histogram of successful serves",
            &metrics.Buckets.local,
        );
        errdefer serve_duration.deinit();
        const fetch_duration = try scope.histogram(
            "fetch_duration",
            "Time from starting a fetch until all subscribers in a delivery are resolved",
            &metrics.Buckets.network,
        );
        return .{
            .fetch_pending = fetch_pending,
            .fetch_active = fetch_active,
            .serve_processing = serve_processing,
            .fetch = fetch,
            .cancel = cancel,
            .serve = serve,
            .serve_duration = .init(serve_duration),
            .fetch_duration = .init(fetch_duration),
        };
    }

    pub fn deinit(self: *Metrics) void {
        self.fetch_pending.deinit();
        self.fetch_active.deinit();
        self.serve_processing.deinit();
        self.fetch.deinit();
        self.cancel.deinit();
        self.serve.deinit();
        self.serve_duration.deinit();
        self.fetch_duration.deinit();
        self.* = undefined;
    }

    /// Sets a gauge to a count, ignoring counts beyond `i64` (commonware `try_set`).
    pub fn set_count(gauge: metrics.Gauge, count: usize) void {
        assert(@sizeOf(usize) <= @sizeOf(u64));
        _ = gauge.metric().try_set(count) catch {};
    }
};
