//! Benchmarks of the production runtime's I/O backends: `std.Io.Threaded` system calls
//! against our io_uring workers (`production/ring.zig`), on the loads that decide which one
//! Linux uses by default (docs/lanes/runtime-telemetry.md). commonware has no runtime
//! benches; the names follow its `runtime::<module>` convention.
//!
//! - `runtime::network::echo`: concurrent TCP connections over loopback, each sending
//!   fixed-size messages that the server echoes back, one at a time.
//! - `runtime::storage`: concurrent blobs, each written page by page, synced, and read back.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const bench = @import("bench");
const runtime = @import("runtime");

const production = runtime.production;
const Network = production.network.Network;
const Storage = production.storage.Storage;
const Ring = production.ring.Ring;

const Backend = enum { threaded, io_uring };

/// Concurrent connections or blobs: futures live in fixed arrays of this size.
const tasks_max = 64;
const message_size = 4096;
const page_size = 4096;

pub fn run(runner: *bench.Runner) !void {
    inline for (.{ Backend.threaded, Backend.io_uring }) |backend| {
        var ring: Ring = undefined;
        const ring_ready = backend == .threaded or ring_init(&ring, runner.io);
        if (ring_ready) {
            defer if (backend == .io_uring) ring.deinit();
            const ring_ptr: ?*Ring = if (backend == .io_uring) &ring else null;
            try run_echo(runner, backend, ring_ptr);
            try run_storage(runner, backend, ring_ptr);
        }
    }
}

/// Whether the kernel gives a ring: io_uring may be missing, disabled, or out of memory.
fn ring_init(ring: *Ring, io: Io) bool {
    ring.init(io, .{}) catch |err| {
        std.log.warn("runtime benches: io_uring unavailable ({t}); skipped", .{err});
        return false;
    };
    return true;
}

fn run_echo(runner: *bench.Runner, backend: Backend, ring: ?*Ring) !void {
    const connections = runner.inputs.pick(u32, 2, 16, 64);
    const messages = runner.inputs.pick(u32, 4, 1_000, 4_000);
    const benchmark = bench.Benchmark.init("runtime::network::echo")
        .with_param("backend", @tagName(backend))
        .with_param("connections", connections)
        .with_param("messages", messages)
        .with_param("size", message_size);
    if (!runner.matches(benchmark.name())) return;
    var workload: Echo = .{
        .gpa = runner.allocator,
        .io = runner.io,
        .ring = ring,
        .connections = connections,
        .messages = messages,
    };
    try runner.run(benchmark, &workload);
}

/// One iteration connects every client, echoes every message, and closes.
const Echo = struct {
    gpa: Allocator,
    io: Io,
    ring: ?*Ring,
    connections: u32,
    messages: u32,

    pub fn iter(echo: *Echo) !void {
        assert(echo.connections > 0 and echo.connections <= tasks_max);
        assert(echo.messages > 0);
        var tcp: Network = .init(echo.gpa, echo.io, .{ .ring = echo.ring });
        defer tcp.deinit();
        const listener = try tcp.bind(.{ .ip4 = .loopback(0) });
        defer listener.deinit();
        var server = try echo.io.concurrent(echo_serve, .{ echo, listener });
        defer server.cancel(echo.io) catch {};
        var clients: [tasks_max]Io.Future(anyerror!void) = undefined;
        var started: u32 = 0;
        defer for (clients[0..started]) |*client| client.cancel(echo.io) catch {};
        while (started < echo.connections) : (started += 1) {
            clients[started] = try echo.io.concurrent(echo_client, .{ echo, &tcp, listener });
        }
        for (clients[0..started]) |*client| try client.await(echo.io);
        started = 0;
        try server.await(echo.io);
    }
};

/// Accepts every connection and echoes each on its own task.
fn echo_serve(echo: *const Echo, listener: *Network.Listener) anyerror!void {
    var accepted: [tasks_max]Network.Accepted = undefined;
    var handlers: [tasks_max]Io.Future(anyerror!void) = undefined;
    var count: u32 = 0;
    defer for (accepted[0..count], handlers[0..count]) |*connection, *handler| {
        handler.cancel(echo.io) catch {};
        connection.deinit();
    };
    while (count < echo.connections) : (count += 1) {
        accepted[count] = try listener.accept();
        handlers[count] = echo.io.concurrent(echo_handle, .{ echo, &accepted[count] }) catch |err| {
            accepted[count].deinit();
            return err;
        };
    }
    for (handlers[0..count]) |*handler| try handler.await(echo.io);
    assert(count == echo.connections);
}

fn echo_handle(echo: *const Echo, connection: *Network.Accepted) anyerror!void {
    var message: [message_size]u8 = undefined;
    for (0..echo.messages) |_| {
        try connection.stream.recv(&message);
        try connection.sink.send(&.{&message});
    }
    assert(connection.stream.peek(1).len == 0);
}

fn echo_client(echo: *const Echo, tcp: *Network, listener: *Network.Listener) anyerror!void {
    var connection = try tcp.dial(listener.local_addr());
    defer connection.deinit();
    var sent: [message_size]u8 = undefined;
    var received: [message_size]u8 = undefined;
    for (0..echo.messages) |index| {
        @memset(&sent, @truncate(index));
        try connection.sink.send(&.{&sent});
        try connection.stream.recv(&received);
        if (received[message_size - 1] != sent[0]) return error.EchoMismatch;
    }
    assert(connection.stream.peek(1).len == 0);
}

fn run_storage(runner: *bench.Runner, backend: Backend, ring: ?*Ring) !void {
    const blobs = runner.inputs.pick(u32, 2, 8, 16);
    const pages = runner.inputs.pick(u32, 4, 256, 1_024);
    const benchmark = bench.Benchmark.init("runtime::storage")
        .with_param("backend", @tagName(backend))
        .with_param("blobs", blobs)
        .with_param("pages", pages)
        .with_param("size", page_size);
    if (!runner.matches(benchmark.name())) return;
    var workload: StorageLoad = .{
        .gpa = runner.allocator,
        .io = runner.io,
        .ring = ring,
        .blobs = blobs,
        .pages = pages,
    };
    try runner.run(benchmark, &workload);
}

/// One iteration writes, syncs, and reads back every blob, then removes the partition.
const StorageLoad = struct {
    gpa: Allocator,
    io: Io,
    ring: ?*Ring,
    blobs: u32,
    pages: u32,
    directory: [64]u8 = undefined,
    directory_len: usize = 0,
    storage: Storage = undefined,

    pub fn setup(load: *StorageLoad) !void {
        assert(load.blobs > 0 and load.blobs <= tasks_max);
        var nonce: [8]u8 = undefined;
        load.io.random(&nonce);
        const name = try std.fmt.bufPrint(&load.directory, ".zig-cache/tmp/runtime-bench-{x}", .{
            std.mem.readInt(u64, &nonce, .little),
        });
        load.directory_len = name.len;
        const root = try Io.Dir.cwd().createDirPathOpen(load.io, name, .{});
        load.storage = try .init(load.io, load.gpa, root, .{ .ring = load.ring });
        assert(load.directory_len > 0);
    }

    pub fn iter(load: *StorageLoad) !void {
        var writers: [tasks_max]Io.Future(anyerror!void) = undefined;
        var started: u32 = 0;
        defer for (writers[0..started]) |*writer| writer.cancel(load.io) catch {};
        while (started < load.blobs) : (started += 1) {
            writers[started] = try load.io.concurrent(storage_blob, .{ load, started });
        }
        for (writers[0..started]) |*writer| try writer.await(load.io);
        started = 0;
        try load.storage.storage().remove("bench", null);
    }

    pub fn teardown(load: *StorageLoad) void {
        load.storage.deinit();
        const name = load.directory[0..load.directory_len];
        Io.Dir.cwd().deleteTree(load.io, name) catch |err|
            std.log.warn("runtime benches: could not remove {s}: {t}", .{ name, err });
    }
};

fn storage_blob(load: *StorageLoad, index: u32) anyerror!void {
    var name_buffer: [16]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buffer, "blob-{d}", .{index});
    const opened = try load.storage.storage().open("bench", name);
    defer opened.blob.close();
    assert(opened.len == 0);
    var page: [page_size]u8 = undefined;
    for (0..load.pages) |number| {
        @memset(&page, @truncate(number));
        try opened.blob.write_at(number * page_size, &page, .{});
    }
    try opened.blob.sync();
    for (0..load.pages) |number| {
        try opened.blob.read_at(number * page_size, &page);
        if (page[page_size - 1] != @as(u8, @truncate(number))) return error.ReadMismatch;
    }
}
