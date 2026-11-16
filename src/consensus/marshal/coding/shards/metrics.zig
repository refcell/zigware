//! Metrics for the shard engine (commonware `marshal/coding/shards/metrics.rs`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const metrics = @import("runtime").telemetry.metrics;

/// Metrics for the shard engine, registered under one scope.
pub fn ShardMetrics(comptime P: type) type {
    return struct {
        const Self = @This();

        /// Per-peer label.
        pub const Peer = struct { peer: P };
        pub const PeerFamily = metrics.raw.Family(Peer, metrics.raw.Counter);

        /// Histogram of successful block reconstruction duration in seconds.
        reconstruction_duration: metrics.Registered(metrics.raw.Histogram),
        /// Number of blocks in the reconstructed blocks cache.
        reconstructed_blocks_cache_count: metrics.Gauge,
        /// Number of active reconstruction states.
        reconstruction_states_count: metrics.Gauge,
        /// Number of shards received per peer.
        shards_received: metrics.Registered(PeerFamily),
        /// Total number of blocks successfully reconstructed.
        blocks_reconstructed_total: metrics.Counter,
        /// Total number of block reconstruction failures.
        reconstruction_failures_total: metrics.Counter,

        pub fn init(scope: *const metrics.Scope) Allocator.Error!Self {
            var duration = try scope.histogram(
                "reconstruction_duration",
                "Histogram of successful block reconstruction duration in seconds",
                &metrics.Buckets.local,
            );
            errdefer duration.deinit();
            var cached = try scope.gauge(
                "reconstructed_blocks_cache_count",
                "Number of blocks in the reconstructed blocks cache",
            );
            errdefer cached.deinit();
            var states = try scope.gauge(
                "reconstruction_states_count",
                "Number of active reconstruction states",
            );
            errdefer states.deinit();
            var received = try scope.family(
                Peer,
                metrics.raw.Counter,
                "shards_received",
                "Number of shards received per peer",
            );
            errdefer received.deinit();
            var reconstructed = try scope.counter(
                "blocks_reconstructed_total",
                "Total number of blocks successfully reconstructed",
            );
            errdefer reconstructed.deinit();
            const failures = try scope.counter(
                "reconstruction_failures_total",
                "Total number of block reconstruction failures",
            );
            return .{
                .reconstruction_duration = duration,
                .reconstructed_blocks_cache_count = cached,
                .reconstruction_states_count = states,
                .shards_received = received,
                .blocks_reconstructed_total = reconstructed,
                .reconstruction_failures_total = failures,
            };
        }

        pub fn deinit(self: *Self) void {
            self.reconstruction_duration.deinit();
            self.reconstructed_blocks_cache_count.deinit();
            self.reconstruction_states_count.deinit();
            self.shards_received.deinit();
            self.blocks_reconstructed_total.deinit();
            self.reconstruction_failures_total.deinit();
            self.* = undefined;
        }

        /// Counts a shard from `peer`. Best effort: a failed allocation skips the sample.
        pub fn shard_received(self: *Self, peer: P) void {
            const counter = self.shards_received.metric().get_or_create(.{ .peer = peer }) catch
                return;
            counter.inc();
        }
    };
}

comptime {
    std.debug.assert(@sizeOf(ShardMetrics(u64)) > 0);
}
