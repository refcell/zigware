//! Metrics over HTTP for the production runtime (commonware `runtime::tokio::telemetry`):
//! `GET /metrics` answers with the registry's Prometheus text exposition.
//!
//! The server takes one connection at a time and answers one request per connection
//! (`Connection: close`), so its work is bounded without spawning a task per scrape; a
//! Prometheus scrape is one short request. Like commonware, it listens on its own socket rather
//! than the runtime network, so scrapes are not metered or bound by p2p timeouts.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = Io.net;
const http = std.http;
const telemetry = @import("../telemetry/mod.zig");

const Scope = telemetry.metrics.Scope;
const log = std.log.scoped(.runtime_telemetry);

/// commonware's content type for the exposition.
pub const content_type = "text/plain; version=0.0.4";

/// The longest request head the server reads.
pub const request_head_size_max = 8 * 1024;

/// Serves `scope`'s registry on `server` until canceled. A failed connection is logged and
/// dropped; only cancellation ends the loop.
pub fn serve(io: Io, gpa: Allocator, scope: *const Scope, server: *net.Server) Io.Cancelable!void {
    var served: u64 = 0;
    while (true) : (served +%= 1) {
        const stream = server.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                log.warn("metrics accept failed: {t}", .{err});
                continue;
            },
        };
        defer stream.close(io);
        respond(io, gpa, scope, stream) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => log.warn("metrics request failed: {t}", .{err}),
        };
    }
}

/// Answers one request on `stream`.
fn respond(io: Io, gpa: Allocator, scope: *const Scope, stream: net.Stream) !void {
    var in_buffer: [request_head_size_max]u8 = undefined;
    var out_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &in_buffer);
    var writer = stream.writer(io, &out_buffer);
    var http_server: http.Server = .init(&reader.interface, &writer.interface);
    var request = http_server.receiveHead() catch |err| switch (err) {
        error.ReadFailed => return reader.err orelse error.ReadFailed,
        else => return err,
    };
    const found = request.head.method == .GET and std.mem.eql(u8, request.head.target, "/metrics");
    if (!found) {
        try request.respond("Not Found\n", .{ .status = .not_found, .keep_alive = false });
        return;
    }
    const body = try scope.encode(gpa);
    defer gpa.free(body);
    assert(std.mem.endsWith(u8, body, "# EOF\n"));
    try request.respond(body, .{
        .keep_alive = false,
        .extra_headers = &.{.{ .name = "content-type", .value = content_type }},
    });
}

test {
    _ = @import("telemetry_test.zig");
}
