//! Metrics for the P2P resolver `Actor` (commonware `glue/src/stateful/db/p2p/metrics.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const metrics = @import("runtime").telemetry.metrics;

const status = metrics.status;

/// Metrics for the QMDB P2P resolver actor.
pub const Metrics = struct {
    /// Fetch requests whose caller still holds its reply receiver.
    pending_requests: metrics.Gauge,
    /// Total fetch requests dispatched to the P2P engine.
    fetch_requests: metrics.Counter,
    /// Candidate deliveries by routing outcome.
    deliveries: status.Counter,
    /// Incoming serve requests by outcome.
    serve_requests: status.Counter,
    /// Whether a database is currently attached (1) or not (0).
    has_database: metrics.Gauge,

    /// Registers the resolver metrics under `scope`.
    pub fn init(scope: *const metrics.Scope) Allocator.Error!Metrics {
        var pending_requests = try scope.gauge("pending_requests", "Pending sync requests");
        errdefer pending_requests.deinit();
        var fetch_requests = try scope.counter(
            "fetch_requests",
            "Total fetch requests dispatched to the P2P engine",
        );
        errdefer fetch_requests.deinit();
        var deliveries = try status.Counter.register(
            scope,
            "deliveries",
            "Candidate deliveries by routing outcome",
        );
        errdefer deliveries.deinit();
        var serve_requests = try status.Counter.register(
            scope,
            "serve_requests",
            "Incoming serve requests by outcome",
        );
        errdefer serve_requests.deinit();
        const has_database = try scope.gauge(
            "has_database",
            "Whether a database is currently attached",
        );
        assert(pending_requests.metric().get() == 0);
        assert(has_database.metric().get() == 0);
        return .{
            .pending_requests = pending_requests,
            .fetch_requests = fetch_requests,
            .deliveries = deliveries,
            .serve_requests = serve_requests,
            .has_database = has_database,
        };
    }

    /// Handles sharing these metrics (commonware's `Clone`).
    pub fn clone(self: *const Metrics) Metrics {
        return .{
            .pending_requests = self.pending_requests.clone(),
            .fetch_requests = self.fetch_requests.clone(),
            .deliveries = self.deliveries.clone(),
            .serve_requests = self.serve_requests.clone(),
            .has_database = self.has_database.clone(),
        };
    }

    pub fn deinit(self: *Metrics) void {
        self.pending_requests.deinit();
        self.fetch_requests.deinit();
        self.deliveries.deinit();
        self.serve_requests.deinit();
        self.has_database.deinit();
        self.* = undefined;
    }
};

test "stateful p2p metrics register under the actor's scope" {
    const testing = std.testing;
    var registry = metrics.Registry.init(testing.allocator);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("resolver");
    var registered = try Metrics.init(&scope);
    defer registered.deinit();
    var shared = registered.clone();
    defer shared.deinit();
    shared.pending_requests.metric().inc();
    _ = shared.has_database.metric().set(1);
    try testing.expectEqual(@as(i64, 1), registered.pending_requests.metric().get());
    try testing.expectEqual(@as(i64, 1), registered.has_database.metric().get());
    const encoded = try scope.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expect(std.mem.indexOf(u8, encoded, "resolver_pending_requests 1") != null);
    try testing.expect(std.mem.indexOf(u8, encoded, "resolver_has_database 1") != null);
}
