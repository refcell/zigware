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
    // The runner's own `runtime_process_*` gauges are encoded too.
    const echoes_family =
        \\# HELP node_echoes Echoes served.
        \\# TYPE node_echoes counter
        \\node_echoes_total 1
        \\
    ;
    try testing.expect(std.mem.startsWith(u8, encoded, echoes_family));
    try testing.expect(std.mem.endsWith(u8, encoded, "# EOF\n"));
    try testing.expect(std.mem.indexOf(u8, encoded, "\nruntime_process_rss ") != null);
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
    try run_twice(.{});
}

test "a file as storage root fails runner init (test_acquire_fails_on_unusable_root)" {
    // commonware's `Hold::acquire` fails on such a root; here `Runner.init` creates the root
    // before the storage takes its hold, and both steps fail on a file.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [64]u8 = undefined;
    const path = storage_directory(&path_buffer, &tmp);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "runner", .data = "not a directory" });
    var runner: Runner = undefined;
    try testing.expectError(
        error.Io,
        runner.init(testing.allocator, .{ .storage_directory = path }),
    );
}

const Context = production.Context;

fn store(ctx: Context, name: []const u8) anyerror!u64 {
    const opened = try ctx.storage.open("tasks", name);
    defer opened.blob.close();
    try opened.blob.write_at(0, name, .{ .sync = true });
    var stored = try ctx.scope.counter("stored", "Blobs stored");
    defer stored.deinit();
    stored.metric().inc();
    // The child label prefixes the task's metrics.
    const encoded = try ctx.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expect(std.mem.indexOf(u8, encoded, "writer_stored_total 1\n") != null);
    return name.len;
}

fn wait_forever(ctx: Context, started: *std.Io.Event) anyerror!void {
    started.set(ctx.io());
    try ctx.sleep(.fromSeconds(3600));
}

fn context_root(ctx: Context, started: *std.Io.Event) anyerror!void {
    const handle = try ctx.child("writer").spawn(store, .{"blob"});
    try testing.expectEqual(@as(u64, 4), try (try handle.join()));
    // Left running: the root's return aborts it.
    const pending = try ctx.child("pending").spawn(wait_forever, .{started});
    pending.detach();
    try started.wait(ctx.io());
}

test "the production runner runs a supervised Context root (start_context)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [64]u8 = undefined;
    const path = storage_directory(&path_buffer, &tmp);
    var runner: Runner = undefined;
    try runner.init(testing.allocator, .{ .storage_directory = path });
    defer runner.deinit();
    var started: std.Io.Event = .unset;
    try (try runner.start_context(context_root, .{&started}));
}

fn seven(_: Context) anyerror!u64 {
    return 7;
}

fn nested_root(ctx: Context, path: []const u8) anyerror!void {
    // A second runner on the held directory is refused before it starts or waits.
    var nested: Runner = undefined;
    try testing.expectError(
        error.Io,
        nested.init(testing.allocator, .{ .storage_directory = path }),
    );
    // The outer runner and its storage stay usable.
    const handle = try ctx.child("after_rejection").spawn(seven, .{});
    try testing.expectEqual(@as(u64, 7), try (try handle.join()));
    const opened = try ctx.storage.open("partition", "blob");
    opened.blob.close();
    try ctx.sleep(.fromMilliseconds(1));
}

// commonware's `test_nested_same_directory_rejected_before_closure_and_outer_remains_usable`.
test "a nested runner on a held directory fails and the outer one stays usable" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [64]u8 = undefined;
    const path = storage_directory(&path_buffer, &tmp);
    var runner: Runner = undefined;
    try runner.init(testing.allocator, .{ .storage_directory = path });
    defer runner.deinit();
    try (try runner.start_context(nested_root, .{path}));
    // Once the first runner is gone, the directory can be held again.
    runner.deinit();
    try runner.init(testing.allocator, .{ .storage_directory = path });
}

const iface = @import("../storage.zig");
const header = @import("../storage/header.zig");

/// Opens a runner over `path` whose storage accepts and creates only `layouts`.
fn layout_runner(runner: *Runner, path: []const u8, layout: ?iface.BlobLayout) !void {
    const storage: @import("storage.zig").Config = if (layout) |only|
        .{ .layouts = .only(only), .layout = only }
    else
        .{};
    try runner.init(testing.allocator, .{ .storage_directory = path, .storage = storage });
}

fn read_file(tmp: *testing.TmpDir, path: []const u8) ![]u8 {
    return tmp.dir.readFileAlloc(testing.io, path, testing.allocator, .unlimited);
}

test "the runner's storage layout policy (test_storage_blob_layout_restriction)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [64]u8 = undefined;
    const path = storage_directory(&path_buffer, &tmp);
    const v0_bytes = try header.blob_bytes(testing.allocator, .v0, 0, "payload");
    defer testing.allocator.free(v0_bytes);
    // hex("v0"), hex("v1"), hex("rollback").
    const v0_path = "runner/layout_restriction/7630";
    const v1_path = "runner/layout_restriction/7631";
    const rollback_path = "runner/layout_restriction/726f6c6c6261636b";
    try tmp.dir.createDirPath(testing.io, "runner/layout_restriction");
    try tmp.dir.writeFile(testing.io, .{ .sub_path = v0_path, .data = v0_bytes });
    var runner: Runner = undefined;

    // The default policy reads legacy V0 blobs.
    try layout_runner(&runner, path, null);
    {
        defer runner.deinit();
        const opened = try runner.storage().open("layout_restriction", "v0");
        defer opened.blob.close();
        try testing.expectEqual(@as(u64, 7), opened.len);
        try iface.tests.expect_read(opened.blob, 0, "payload");
    }

    // A V1-only policy rejects V0 untouched and creates new blobs as V1.
    try layout_runner(&runner, path, .v1);
    {
        defer runner.deinit();
        const v0 = runner.storage().open("layout_restriction", "v0");
        try testing.expectError(error.BlobLayoutMismatch, v0);
        (try runner.storage().open("layout_restriction", "v1")).blob.close();
    }
    const v0_after = try read_file(&tmp, v0_path);
    defer testing.allocator.free(v0_after);
    try testing.expectEqualSlices(u8, v0_bytes, v0_after);
    const v1 = try read_file(&tmp, v1_path);
    defer testing.allocator.free(v1);
    try testing.expectEqualSlices(u8, &header.magic(.v1), v1[0..header.magic_length]);

    // A V0-only policy rejects the header-only V1 blob without healing it and creates V0.
    try layout_runner(&runner, path, .v0);
    {
        defer runner.deinit();
        const v1_open = runner.storage().open("layout_restriction", "v1");
        try testing.expectError(error.BlobLayoutMismatch, v1_open);
        const created = try runner.storage().open("layout_restriction", "rollback");
        try testing.expectEqual(@as(u64, 0), created.len);
        try created.blob.write_at(0, "rollback!", .{ .sync = true });
        created.blob.close();
        const reopened = try runner.storage().open("layout_restriction", "rollback");
        defer reopened.blob.close();
        try testing.expectEqual(@as(u64, 9), reopened.len);
        try iface.tests.expect_read(reopened.blob, 0, "rollback!");
    }
    const v1_after = try read_file(&tmp, v1_path);
    defer testing.allocator.free(v1_after);
    try testing.expectEqualSlices(u8, v1, v1_after);
    const rollback = try read_file(&tmp, rollback_path);
    defer testing.allocator.free(rollback);
    try testing.expectEqualSlices(u8, &header.magic(.v0), rollback[0..header.magic_length]);
    try testing.expectEqualStrings("rollback!", rollback[header.prelude_size..]);
}

fn expect_rss_published(runner: *Runner) !void {
    const text = try runner.metrics_registry.encode(testing.allocator);
    defer testing.allocator.free(text);
    // The sample line, not its `# HELP` or `# TYPE` line.
    const prefix = "\nruntime_process_rss ";
    const start = std.mem.indexOf(u8, text, prefix) orelse return error.TestUnexpectedResult;
    const rest = text[start + prefix.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
    try testing.expect(try std.fmt.parseInt(i64, rest[0..end], 10) > 0);
}

fn rss_root(ctx: Context, runner: *Runner) anyerror!void {
    _ = ctx;
    try expect_rss_published(runner);
}

test "the production runner publishes runtime_process_rss (test_process_rss_metric)" {
    if (!@import("../process/metered.zig").supported) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [64]u8 = undefined;
    const path = storage_directory(&path_buffer, &tmp);
    var runner: Runner = undefined;
    try runner.init(testing.allocator, .{ .storage_directory = path });
    defer runner.deinit();
    try runner.start(expect_rss_published, .{&runner});
    try (try runner.start_context(rss_root, .{&runner}));
}
