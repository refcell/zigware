//! Metrics for the aggregation engine (commonware `aggregation/metrics.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const metrics = @import("runtime").telemetry.metrics;

pub const Metrics = struct {
    /// Lowest height without a certificate.
    tip: metrics.Gauge,
    /// Digests returned by the automaton, by status.
    digest: metrics.status.Counter,
    /// Acks processed, by status.
    acks: metrics.status.Counter,
    /// Certificates produced.
    certificates: metrics.Counter,
    /// Durations of application digest requests.
    digest_duration: metrics.Timed,

    /// Registers every metric under `scope`.
    pub fn init(scope: *const metrics.Scope) Allocator.Error!Metrics {
        var tip = try scope.gauge("tip", "Lowest height without a certificate");
        errdefer tip.deinit();
        const digest_help = "Number of digests returned by the automaton by status";
        var digest = try metrics.status.Counter.register(scope, "digest", digest_help);
        errdefer digest.deinit();
        const acks_help = "Number of Ack messages processed by status";
        var acks = try metrics.status.Counter.register(scope, "acks", acks_help);
        errdefer acks.deinit();
        const certificates_help = "Number of certificates produced";
        var certificates = try scope.counter("certificates", certificates_help);
        errdefer certificates.deinit();
        const duration = try scope.histogram(
            "digest_duration",
            "Histogram of application digest durations",
            &metrics.Buckets.local,
        );
        const result: Metrics = .{
            .tip = tip,
            .digest = digest,
            .acks = acks,
            .certificates = certificates,
            .digest_duration = .init(duration),
        };
        assert(result.tip.metric().get() == 0);
        return result;
    }

    pub fn deinit(self: *Metrics) void {
        self.tip.deinit();
        self.digest.deinit();
        self.acks.deinit();
        self.certificates.deinit();
        self.digest_duration.deinit();
        self.* = undefined;
    }
};

test "metrics register under the scope" {
    const gpa = std.testing.allocator;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("engine");
    var registered = try Metrics.init(&scope);
    defer registered.deinit();
    _ = registered.tip.metric().set(7);
    try registered.acks.inc(.success);
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    try std.testing.expect(metrics.has_metric_value(text, "engine_tip", 7));
    try std.testing.expect(metrics.has_metric_value(text, "engine_acks_total", 1));
}
