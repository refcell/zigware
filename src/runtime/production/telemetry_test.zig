//! The metrics HTTP server, scraped over loopback TCP.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const testing = std.testing;
const telemetry = @import("../telemetry/mod.zig");
const server_mod = @import("telemetry.zig");

const tcp = @import("network.zig");
const io = testing.io;
const gpa = testing.allocator;

/// Sends `request` and returns the whole response (the server closes the connection).
fn fetch(address: net.IpAddress, request: []const u8) ![]u8 {
    const stream = try tcp.connect(io, address, .fromSeconds(10));
    defer stream.close(io);
    var out_buffer: [256]u8 = undefined;
    var writer = stream.writer(io, &out_buffer);
    try writer.interface.writeAll(request);
    try writer.interface.flush();
    var in_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &in_buffer);
    return reader.interface.allocRemaining(gpa, .limited(1 << 20));
}

test "GET /metrics serves the exposition, other paths are not found" {
    var registry: telemetry.metrics.Registry = .init(gpa);
    defer registry.deinit();
    const scope: telemetry.metrics.Scope = .init(&registry);
    var votes = try scope.child("node").counter("votes", "Votes cast");
    defer votes.deinit();
    votes.metric().inc_by(3);

    const any_port: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try any_port.listen(io, .{});
    defer server.deinit(io);
    var serving = try io.concurrent(server_mod.serve, .{ io, gpa, &scope, &server });
    defer serving.cancel(io) catch {};

    const ok = try fetch(server.socket.address, "GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n");
    defer gpa.free(ok);
    const expected_body =
        \\# HELP node_votes Votes cast.
        \\# TYPE node_votes counter
        \\node_votes_total 3
        \\# EOF
        \\
    ;
    try testing.expect(std.mem.startsWith(u8, ok, "HTTP/1.1 200 OK\r\n"));
    const content_type = "content-type: " ++ server_mod.content_type ++ "\r\n";
    try testing.expect(std.mem.indexOf(u8, ok, content_type) != null);
    try testing.expect(std.mem.endsWith(u8, ok, "\r\n\r\n" ++ expected_body));

    // The server keeps serving after each connection, and later values show up.
    votes.metric().inc();
    const again = try fetch(server.socket.address, "GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n");
    defer gpa.free(again);
    try testing.expect(std.mem.indexOf(u8, again, "node_votes_total 4\n") != null);

    const missing = try fetch(server.socket.address, "GET /other HTTP/1.1\r\nHost: test\r\n\r\n");
    defer gpa.free(missing);
    try testing.expect(std.mem.startsWith(u8, missing, "HTTP/1.1 404 Not Found\r\n"));

    // A malformed request is dropped (with a warning) without stopping the server.
    const quiet = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = quiet;
    const garbage = try fetch(server.socket.address, "nonsense\r\n\r\n");
    defer gpa.free(garbage);
    const after = try fetch(server.socket.address, "GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n");
    defer gpa.free(after);
    try testing.expect(std.mem.startsWith(u8, after, "HTTP/1.1 200 OK\r\n"));
}
