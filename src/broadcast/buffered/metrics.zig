//! Metrics for the engine (commonware `broadcast/src/buffered/metrics.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const metrics = @import("runtime").telemetry.metrics;

const status = metrics.status;

/// Metrics for the `Engine`, registered under one scope.
pub fn Metrics(comptime P: type) type {
    return struct {
        const Self = @This();

        /// Per-sequencer label.
        pub const Sequencer = struct { sequencer: P };
        pub const PeerFamily = metrics.raw.Family(Sequencer, metrics.raw.Counter);

        /// Number of broadcasts received by peer.
        peer: metrics.Registered(PeerFamily),
        /// Number of received messages by status.
        receive: status.Counter,
        /// Number of `subscribe` requests by status.
        subscribe: status.Counter,
        /// Number of `get` requests by status.
        get: status.Counter,
        /// Number of digests being awaited. May be less than the number of waiters since
        /// there may be multiple waiters for the same digest.
        waiters: metrics.Gauge,

        pub fn init(scope: *const metrics.Scope) Allocator.Error!Self {
            var peer = try scope.family(
                Sequencer,
                metrics.raw.Counter,
                "peer",
                "Number of broadcasts received by peer",
            );
            errdefer peer.deinit();
            var receive = try status.Counter.register(
                scope,
                "receive",
                "Number of received messages by status",
            );
            errdefer receive.deinit();
            var subscribe = try status.Counter.register(
                scope,
                "subscribe",
                "Number of `subscribe` requests by status",
            );
            errdefer subscribe.deinit();
            const get_help = "Number of `get` requests by status";
            var get = try status.Counter.register(scope, "get", get_help);
            errdefer get.deinit();
            const waiters = try scope.gauge("waiters", "Number of digests being awaited");
            return .{
                .peer = peer,
                .receive = receive,
                .subscribe = subscribe,
                .get = get,
                .waiters = waiters,
            };
        }

        pub fn deinit(self: *Self) void {
            self.peer.deinit();
            self.receive.deinit();
            self.subscribe.deinit();
            self.get.deinit();
            self.waiters.deinit();
            self.* = undefined;
        }
    };
}

/// Records one sample. Metrics are best effort: a status seen for the first time allocates
/// its series, and a failed allocation skips that one sample.
pub fn record(counter: status.Counter, value: status.Status) void {
    counter.inc(value) catch {};
}

test "metrics register and unregister" {
    const testing = std.testing;
    const Key = @import("cryptography").ed25519.PublicKey;
    var registry: metrics.Registry = .init(testing.allocator);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry);
    var engine_metrics = try Metrics(Key).init(&scope);
    try testing.expectEqual(@as(usize, 5), registry.count());
    engine_metrics.deinit();
    try testing.expectEqual(@as(usize, 0), registry.count());
    assert(registry.count() == 0);
}
