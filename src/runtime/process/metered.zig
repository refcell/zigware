//! Process metrics (commonware `runtime/src/process/metered.rs`): the resident set size and
//! virtual memory size of the current process, in bytes. commonware reads them through
//! `sysinfo`; zigware reads `/proc/self/statm` through `std.Io`, so they update on Linux only
//! and stay 0 elsewhere. The production runner refreshes them every `tick_interval_ns`.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const metrics = @import("../telemetry/metrics/mod.zig");

const Gauge = metrics.Registered(metrics.raw.Gauge);

/// How often `collect` refreshes the gauges (commonware `TICK_INTERVAL`).
pub const tick_interval_ns: u64 = 10 * std.time.ns_per_s;

/// Whether this platform reports process memory.
pub const supported = builtin.os.tag == .linux;

pub const Metrics = struct {
    /// Resident set size in bytes.
    rss: Gauge,
    /// Virtual memory size in bytes.
    virtual_memory: Gauge,

    /// Registers both gauges in `scope` as `process_rss` and `process_virtual_memory`.
    pub fn init(scope: *const metrics.Scope) Allocator.Error!Metrics {
        var rss = try scope.gauge("process_rss", "Resident set size of the current process");
        errdefer rss.deinit();
        const virtual_memory = try scope.gauge(
            "process_virtual_memory",
            "Virtual memory size of the current process",
        );
        return .{ .rss = rss, .virtual_memory = virtual_memory };
    }

    pub fn deinit(self: *Metrics) void {
        self.rss.deinit();
        self.virtual_memory.deinit();
        self.* = undefined;
    }

    /// Refreshes both gauges; a read that fails leaves them unchanged, as commonware's
    /// `update` does when the process is not found. Only cancellation is reported: swallowing
    /// it would consume the request and leave `collect` running.
    pub fn update(self: *Metrics, io: Io) Io.Cancelable!void {
        if (!supported) return;
        const usage = read_statm(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        assert(usage.rss_bytes <= usage.virtual_bytes);
        _ = self.rss.metric().set(@intCast(usage.rss_bytes));
        _ = self.virtual_memory.metric().set(@intCast(usage.virtual_bytes));
    }

    /// Refreshes the gauges every `tick_interval_ns` until canceled (commonware `collect`).
    pub fn collect(self: *Metrics, io: Io) Io.Cancelable!void {
        while (true) {
            try self.update(io);
            try io.sleep(.fromNanoseconds(tick_interval_ns), .awake);
        }
    }
};

const Usage = struct { virtual_bytes: u64, rss_bytes: u64 };

fn read_statm(io: Io) !Usage {
    const file = try Io.Dir.openFileAbsolute(io, "/proc/self/statm", .{});
    defer file.close(io);
    var buffer: [256]u8 = undefined;
    const len = try file.readPositional(io, &.{&buffer}, 0);
    return parse_statm(buffer[0..len], std.heap.pageSize());
}

/// The first two fields of statm: total program size and resident set, in pages.
fn parse_statm(text: []const u8, page_size: usize) error{InvalidStatm}!Usage {
    assert(page_size > 0);
    var fields = std.mem.tokenizeAny(u8, text, " \n");
    const size = fields.next() orelse return error.InvalidStatm;
    const resident = fields.next() orelse return error.InvalidStatm;
    const pages = std.fmt.parseInt(u64, size, 10) catch return error.InvalidStatm;
    const rss_pages = std.fmt.parseInt(u64, resident, 10) catch return error.InvalidStatm;
    if (rss_pages > pages) return error.InvalidStatm;
    const virtual_bytes = std.math.mul(u64, pages, page_size) catch return error.InvalidStatm;
    if (virtual_bytes > std.math.maxInt(i64)) return error.InvalidStatm;
    return .{ .virtual_bytes = virtual_bytes, .rss_bytes = rss_pages * page_size };
}

const testing = std.testing;

test "statm parsing" {
    const usage = try parse_statm("1000 250 30 4 0 120 0\n", 4096);
    try testing.expectEqual(@as(u64, 1000 * 4096), usage.virtual_bytes);
    try testing.expectEqual(@as(u64, 250 * 4096), usage.rss_bytes);
    for ([_][]const u8{ "", "12", "x 1", "1 2", "5 a" }) |bad| {
        try testing.expectError(error.InvalidStatm, parse_statm(bad, 4096));
    }
}

test "process metrics report RSS above 1 MiB and virtual memory at least RSS" {
    // commonware `test_process_metrics_init`.
    if (!supported) return error.SkipZigTest;
    var registry: metrics.Registry = .init(testing.allocator);
    defer registry.deinit();
    const scope: metrics.Scope = .init(&registry);
    var process: Metrics = try .init(&scope);
    defer process.deinit();
    for (0..2) |_| {
        try process.update(testing.io);
        const rss = process.rss.metric().get();
        try testing.expect(rss > 1024 * 1024);
        try testing.expect(process.virtual_memory.metric().get() >= rss);
    }
}
