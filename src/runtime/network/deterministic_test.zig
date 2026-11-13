//! Tests of the deterministic network (commonware `network::deterministic::tests`), run on the
//! deterministic runtime.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const build_options = @import("build_options");
const network = @import("../network.zig");
const runtime_deterministic = @import("../deterministic.zig");
const Network = network.deterministic.Network;
const port_min = network.deterministic.ephemeral_port_min;
const port_end = network.deterministic.ephemeral_port_end;

fn new_network(io: Io) Network {
    return .init(testing.allocator, io);
}

fn suite(io: Io) !void {
    try network.tests.run_network_tests(io, Network, new_network);
}

fn stress(io: Io) !void {
    try network.tests.run_network_stress_tests(io, Network, new_network);
}

test "deterministic network passes the network suite" {
    var runner = try runtime_deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(suite, .{runner.io()}));
}

test "deterministic network stress (slow)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    var runner = try runtime_deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(stress, .{runner.io()}));
}

test "binding an ephemeral loopback port fails" {
    var net = new_network(testing.io);
    defer net.deinit();
    const ephemeral: network.Address = .{ .ip4 = .loopback(port_min) };
    try testing.expectError(error.BindFailed, net.bind(ephemeral));
    const last: network.Address = .{ .ip4 = .loopback(port_end - 1) };
    try testing.expectError(error.BindFailed, net.bind(last));
    // The same port on another address, and the first port past the range, bind.
    const other = try net.bind(.{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 40000 } });
    other.deinit();
    const past = try net.bind(.{ .ip4 = .loopback(port_end) });
    past.deinit();
}

test "dialers get ephemeral ports in order, and a closed listener stays bound" {
    const Root = struct {
        fn run(io: Io) !void {
            var net = new_network(io);
            defer net.deinit();
            const address: network.Address = .{ .ip4 = .loopback(8080) };
            const listener = try net.bind(address);
            for (0..3) |i| {
                var connection = try net.dial(address);
                connection.deinit();
                var accepted = try listener.accept();
                defer accepted.deinit();
                const port = port_min + i;
                try testing.expectEqual(@as(u16, @intCast(port)), accepted.address.ip4.port);
            }
            listener.deinit();
            try testing.expectError(error.ConnectionFailed, net.dial(address));
            try testing.expectError(error.BindFailed, net.bind(address));
        }
    };
    var runner = try runtime_deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(Root.run, .{runner.io()}));
}
