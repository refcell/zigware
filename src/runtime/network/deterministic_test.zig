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

/// Two networks, each audited by its own auditor (commonware `network::audited::tests`).
const AuditedPair = struct {
    auditors: [2]runtime_deterministic.Auditor = .{ .{}, .{} },
    networks: [2]Network = undefined,

    fn init(pair: *AuditedPair, io: Io) void {
        for (&pair.networks, &pair.auditors) |*net, *auditor| {
            net.* = new_network(io);
            net.auditor = auditor;
        }
    }

    fn deinit(pair: *AuditedPair) void {
        for (&pair.networks) |*net| net.deinit();
    }

    fn expect_same(pair: *const AuditedPair) !void {
        try testing.expectEqualSlices(u8, &pair.auditors[0].state(), &pair.auditors[1].state());
    }
};

fn exchange(net: *Network, listener: *Network.Listener, address: network.Address) !void {
    var client = try net.dial(address);
    defer client.deinit();
    var server = try listener.accept();
    defer server.deinit();
    var buffer: [6]u8 = undefined;
    try client.sink.send(&.{"client"});
    try server.stream.recv(&buffer);
    try testing.expectEqualStrings("client", &buffer);
    try server.sink.send(&.{"server"});
    try client.stream.recv(&buffer);
    try testing.expectEqualStrings("server", &buffer);
}

test "audited networks running the same operations reach the same audit state" {
    const Root = struct {
        fn run(io: Io) !void {
            var pair: AuditedPair = .{};
            pair.init(io);
            defer pair.deinit();
            const address: network.Address = .{ .ip4 = .loopback(1234) };
            var listeners: [2]*Network.Listener = undefined;
            for (&listeners, &pair.networks) |*listener, *net| listener.* = try net.bind(address);
            defer for (listeners) |listener| listener.deinit();
            try pair.expect_same();
            const initial = pair.auditors[0].state();
            for (listeners, &pair.networks) |listener, *net| try exchange(net, listener, address);
            try pair.expect_same();
            try testing.expect(!std.mem.eql(u8, &initial, &pair.auditors[0].state()));
            for (&pair.networks) |*net| {
                try testing.expectError(error.BindFailed, net.bind(address));
            }
            try pair.expect_same();
            const missing: network.Address = .{ .ip4 = .loopback(9999) };
            for (&pair.networks) |*net| {
                try testing.expectError(error.ConnectionFailed, net.dial(missing));
            }
            try pair.expect_same();
        }
    };
    var runner = try runtime_deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(Root.run, .{runner.io()}));
}

test "audited sends keep their chunks and audit the same as one buffer" {
    const Root = struct {
        fn run(io: Io) !void {
            var pair: AuditedPair = .{};
            pair.init(io);
            defer pair.deinit();
            const address: network.Address = .{ .ip4 = .loopback(1234) };
            const sends = [2][]const []const u8{ &.{ "a", "b", "c", "d" }, &.{"abcd"} };
            for (&pair.networks, sends) |*net, bufs| {
                const listener = try net.bind(address);
                defer listener.deinit();
                var client = try net.dial(address);
                defer client.deinit();
                var server = try listener.accept();
                defer server.deinit();
                try client.sink.send(bufs);
                var buffer: [4]u8 = undefined;
                try server.stream.recv(&buffer);
                try testing.expectEqualStrings("abcd", &buffer);
            }
            try pair.expect_same();
        }
    };
    var runner = try runtime_deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(Root.run, .{runner.io()}));
}

test "the runner's network is audited" {
    const Root = struct {
        fn run(runner: *runtime_deterministic.Runner) !void {
            const before = runner.auditor.state();
            const listener = try runner.network().bind(.{ .ip4 = .loopback(1234) });
            listener.deinit();
            try testing.expect(!std.mem.eql(u8, &before, &runner.auditor.state()));
        }
    };
    var runner = try runtime_deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(Root.run, .{&runner}));
}
