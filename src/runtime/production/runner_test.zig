//! The production runner end to end: storage that survives a restart, TCP, and metrics.

const std = @import("std");
const testing = std.testing;
const production = @import("runner.zig");

const Runner = production.Runner;
const Network = @import("network.zig").Network;

fn storage_directory(buffer: []u8, tmp: *const testing.TmpDir) []const u8 {
    return std.fmt.bufPrint(buffer, ".zig-cache/tmp/{s}/runner", .{tmp.sub_path}) catch
        unreachable; // The buffer fits the fixed-length temporary path.
}

fn echo(listener: *Network.Listener) !Network.Accepted {
    var accepted = try listener.accept();
    errdefer accepted.deinit();
    var message: [4]u8 = undefined;
    try accepted.stream.recv(&message);
    try accepted.sink.send(&.{&message});
    return accepted;
}

/// Writes a synced blob, echoes over TCP, and counts the echo.
fn first_run(runner: *Runner) !void {
    const io = runner.io();
    const opened = try runner.storage().open("partition", "blob");
    defer opened.blob.close();
    try testing.expectEqual(@as(u64, 0), opened.len);
    try opened.blob.write_at(0, "durable", .{ .sync = true });

    const net = runner.network();
    const listener = try net.bind(.{ .ip4 = .loopback(0) });
    defer listener.deinit();
    var server = try io.concurrent(echo, .{listener});
    var connection = try net.dial(listener.local_addr());
    defer connection.deinit();
    try connection.sink.send(&.{"ping"});
    var reply: [4]u8 = undefined;
    try connection.stream.recv(&reply);
    var accepted = try server.await(io);
    defer accepted.deinit();
    try testing.expectEqualStrings("ping", &reply);

    var echoes = try runner.metrics().child("node").counter("echoes", "Echoes served");
    defer echoes.deinit();
    echoes.metric().inc();
    const encoded = try runner.metrics().encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings(
        \\# HELP node_echoes Echoes served.
        \\# TYPE node_echoes counter
        \\node_echoes_total 1
        \\# EOF
        \\
    , encoded);
}

fn second_run(runner: *Runner) !void {
    const opened = try runner.storage().open("partition", "blob");
    defer opened.blob.close();
    try testing.expectEqual(@as(u64, 7), opened.len);
    var contents: [7]u8 = undefined;
    try opened.blob.read_at(0, &contents);
    try testing.expectEqualStrings("durable", &contents);
}

fn run_twice(io_uring: ?@import("ring.zig").Config) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [64]u8 = undefined;
    const path = storage_directory(&path_buffer, &tmp);
    var runner: Runner = undefined;
    try runner.init(testing.allocator, .{
        .storage_directory = path,
        .worker_threads = 4,
        .io_uring = io_uring,
    });
    try runner.start(first_run, .{&runner});
    runner.deinit();

    try runner.init(testing.allocator, .{ .storage_directory = path, .io_uring = io_uring });
    defer runner.deinit();
    try runner.start(second_run, .{&runner});
}

test "the production runner serves storage, tcp, and metrics, and storage survives restart" {
    try run_twice(null);
}

test "the production runner does the same over io_uring" {
    // Skip where the kernel cannot give a ring (the runner reports that as `error.Io`).
    var probe: @import("ring.zig").Ring = undefined;
    try @import("ring_test.zig").init_or_skip(&probe, .{ .entries = 64 });
    probe.deinit();
    try run_twice(.{ .entries = 64 });
}
