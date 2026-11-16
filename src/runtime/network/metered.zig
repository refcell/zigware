//! Network metrics (commonware `runtime/src/network/metered.rs`): connections made by dialing
//! us and by dialing others, and bytes received and sent. Counts are taken after the operation
//! succeeds, and are not tracked per connection.
//!
//! The deterministic network counts into a `Metrics` when `Network.metrics` is set (the
//! deterministic runner registers one under `runtime`), so its types stay the same.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const metrics = @import("../telemetry/metrics/mod.zig");

const Counter = metrics.Registered(metrics.raw.Counter);

pub const Metrics = struct {
    /// Number of connections created by dialing us.
    inbound_connections: Counter,
    /// Number of connections created by dialing others.
    outbound_connections: Counter,
    /// Bandwidth used by receiving data from others.
    inbound_bandwidth: Counter,
    /// Bandwidth used by sending data to others.
    outbound_bandwidth: Counter,

    /// Registers every metric in `scope`.
    pub fn init(scope: *const metrics.Scope) Allocator.Error!Metrics {
        var inbound_connections = try scope.counter(
            "inbound_connections",
            "Number of connections created by dialing us",
        );
        errdefer inbound_connections.deinit();
        var outbound_connections = try scope.counter(
            "outbound_connections",
            "Number of connections created by dialing others",
        );
        errdefer outbound_connections.deinit();
        var inbound_bandwidth = try scope.counter(
            "inbound_bandwidth",
            "Bandwidth used by receiving data from others",
        );
        errdefer inbound_bandwidth.deinit();
        const outbound_bandwidth = try scope.counter(
            "outbound_bandwidth",
            "Bandwidth used by sending data to others",
        );
        return .{
            .inbound_connections = inbound_connections,
            .outbound_connections = outbound_connections,
            .inbound_bandwidth = inbound_bandwidth,
            .outbound_bandwidth = outbound_bandwidth,
        };
    }

    pub fn deinit(self: *Metrics) void {
        inline for (@typeInfo(Metrics).@"struct".field_names) |name| @field(self, name).deinit();
        self.* = undefined;
    }

    /// Counts one sent message of `bufs`.
    pub fn sent(self: *const Metrics, bufs: []const []const u8) void {
        var total: u64 = 0;
        for (bufs) |buf| total += buf.len;
        const before = self.outbound_bandwidth.metric().get();
        self.outbound_bandwidth.metric().inc_by(total);
        assert(self.outbound_bandwidth.metric().get() >= before);
    }

    /// Counts `length` received bytes.
    pub fn received(self: *const Metrics, length: usize) void {
        const before = self.inbound_bandwidth.metric().get();
        self.inbound_bandwidth.metric().inc_by(length);
        assert(self.inbound_bandwidth.metric().get() >= before);
    }
};
