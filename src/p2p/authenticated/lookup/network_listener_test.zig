//! Tests of the lookup network's listener (commonware `lookup/actors/listener.rs` tests): the
//! handshake rate limits per IP and per subnet, and the checks on unregistered and private
//! source IPs, read from the listener's counters after raw connections.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const rate_limit = @import("../../rate_limit.zig");
const network_mod = @import("network.zig");
const harness = @import("network_test.zig");

const Net = harness.Net;
const Transport = harness.Transport;
const gpa = testing.allocator;

/// commonware's listener address.
const port: u16 = 30_101;

const Options = struct {
    per_ip: rate_limit.Quota = .per_hour(100),
    per_subnet: rate_limit.Quota = .per_hour(100),
    allow_private_ips: bool = true,
    bypass_ip_check: bool = false,
    /// Whether a tracked peer registers our loopback IP with the listener.
    register: bool = true,
};

/// Starts a listening node configured by `options`, as commonware's listener test setup.
fn start_listener(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    options: Options,
) !harness.Node {
    var config = harness.test_config(harness.PrivateKey.from_seed(1), port, 1024);
    config.allowed_handshake_rate_per_ip = options.per_ip;
    config.allowed_handshake_rate_per_subnet = options.per_subnet;
    config.allow_private_ips = options.allow_private_ips;
    config.bypass_ip_check = options.bypass_ip_check;
    config.handshake_timeout = .from_millis(5);
    config.max_concurrent_handshakes = 8;
    // A peer at 127.0.0.1 registers the IP our raw connections come from.
    const registered: [1]harness.Entry = .{.{
        .key = harness.PrivateKey.from_seed(2).public_key(),
        .value = .{ .symmetric = harness.local_socket(4_000) },
    }};
    const entries: []const harness.Entry = if (options.register) &registered else &.{};
    const tracked: Net.Tracker.Tracked = .init_primary(.init(entries));
    return harness.start_network(io, transport, scope, config, 0, tracked, .per_second(100));
}

/// Connects to the listener (retrying until it is bound), waits for a byte or the close,
/// and drops the connection.
fn connect_once(io: Io, transport: *Transport) !void {
    const address = network_mod.to_address(harness.local_socket(port));
    var attempts: u32 = 0;
    var connection = while (true) : (attempts += 1) {
        try testing.expect(attempts < 1_000);
        break transport.dial(address) catch |err| {
            if (err != error.ConnectionFailed) return err;
            try io.sleep(.fromMilliseconds(1), .awake);
            continue;
        };
    };
    defer {
        connection.sink.deinit();
        connection.stream.deinit();
    }
    var byte: [1]u8 = undefined;
    connection.stream.recv(&byte) catch {};
}

fn expect_metric(scope: metrics.Scope, needle: []const u8) !void {
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    if (std.mem.indexOf(u8, text, needle) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ needle, text });
        return error.MissingMetric;
    }
}

/// commonware `check_rate_limits`: one connection, then three more, each rate limited
/// by `options`.
fn rate_limits(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    options: Options,
    expected: []const []const u8,
) !void {
    var node = try start_listener(io, transport, scope, options);
    defer harness.stop_node(io, &node);
    for (0..4) |_| try connect_once(io, transport);
    for (expected) |needle| try expect_metric(scope, needle);
}

test "the listener rate limits handshakes per IP" {
    // commonware `rate_limits_ip`.
    try run(rate_limits, .{ Options{ .per_ip = .per_hour(1) }, &[_][]const u8{
        "handshake_ip_rate_limited_total 3",
        "handshake_subnet_rate_limited_total 0",
        "handshakes_blocked_total 0",
    } });
}

test "the listener rate limits handshakes per subnet" {
    // commonware `rate_limits_subnet`.
    try run(rate_limits, .{ Options{ .per_subnet = .per_hour(1) }, &[_][]const u8{
        "handshake_subnet_rate_limited_total 3",
        "handshake_ip_rate_limited_total 0",
        "handshakes_blocked_total 0",
    } });
}

test "the listener charges both rate limits" {
    // commonware `rate_limits_both`.
    const options: Options = .{ .per_ip = .per_hour(1), .per_subnet = .per_hour(1) };
    try run(rate_limits, .{ options, &[_][]const u8{
        "handshake_ip_rate_limited_total 3",
        "handshake_subnet_rate_limited_total 3",
        "handshakes_blocked_total 0",
    } });
}

/// One connection with `options`; then the blocked counter reads `blocked`.
fn single_connection(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    options: Options,
    blocked: []const u8,
) !void {
    var node = try start_listener(io, transport, scope, options);
    defer harness.stop_node(io, &node);
    try connect_once(io, transport);
    try expect_metric(scope, blocked);
}

test "the listener blocks unregistered IPs" {
    // commonware `blocks_unregistered_ips`.
    const options: Options = .{ .register = false };
    try run(single_connection, .{ options, "handshakes_blocked_total 1" });
}

test "the listener allows unregistered IPs when the IP check is bypassed" {
    // commonware `allows_unregistered_ips`.
    const options: Options = .{ .register = false, .bypass_ip_check = true };
    try run(single_connection, .{ options, "handshakes_blocked_total 0" });
}

test "the listener blocks private IPs unless allowed" {
    // commonware `blocks_private_ips`: registered and bypassed, yet loopback is private.
    const options: Options = .{ .allow_private_ips = false, .bypass_ip_check = true };
    try run(single_connection, .{ options, "handshakes_blocked_total 1" });
}

fn run(comptime function: anytype, args: anytype) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 10 * std.time.ns_per_s };
    const Args = @TypeOf(args);
    try runtime.deterministic.soak(gpa, config, args, struct {
        fn run(context: Args, runner: *runtime.deterministic.Runner) anyerror!void {
            const args_all = .{ runner.io(), runner.network(), runner.metrics() } ++ context;
            try (try runner.start(function, args_all));
        }
    }.run);
}
