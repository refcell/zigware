//! Benchmarks of the runtime package.
//!
//! - `buffer_paged::{append,read,sync}`: commonware's page-cache benches
//!   (`runtime/src/utils/buffer/benches`), in `buffer/benches.zig`.
//! - `iobuf::iobuf::decode_fixed`: commonware's `IoBuf` overhead bench
//!   (`runtime/src/iobuf/benches`), in `iobuf_benches.zig`.
//!
//! The rest have no commonware counterpart: they measure the production runtime's I/O
//! backends, `std.Io.Threaded` system calls against our io_uring workers
//! (`production/ring.zig`), on the loads that decide which one Linux uses by default
//! (docs/lanes/runtime-telemetry.md). Their names follow commonware's `runtime::<module>`
//! convention.
//!
//! - `runtime::network::echo`: concurrent TCP connections over loopback, each sending
//!   fixed-size messages that the server echoes back, one at a time.
//! - `runtime::storage`: concurrent blobs, each written page by page, synced, and read back.
//! - `runtime::storage::<workload>`: commonware's filesystem workload bench
//!   (`runtime/src/storage/benches`, ported in `storage/benches/`): fixed-size sequential and
//!   random reads and overwrites, appends, durable writes, and an append with concurrent
//!   readers, each timed for a fixed duration with sampled latency percentiles.

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
    try @import("buffer/benches.zig").run(runner);
    try @import("iobuf_benches.zig").run(runner);
    inline for (.{ Backend.threaded, Backend.io_uring }) |backend| {
        var ring: Ring = undefined;
        const ring_ready = backend == .threaded or ring_init(&ring, runner.io);
        if (ring_ready) {
            defer if (backend == .io_uring) ring.deinit();
            const ring_ptr: ?*Ring = if (backend == .io_uring) &ring else null;
            try run_echo(runner, backend, ring_ptr);
            try run_storage(runner, backend, ring_ptr);
            try run_filesystem(runner, backend, ring_ptr);
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

const fs_config = @import("storage/benches/config.zig");
const fs_workload = @import("storage/benches/workload.zig");
const fs_report = @import("storage/benches/report.zig");

/// commonware's filesystem workloads with the flags each needs: smoke inputs time 10 ms on a
/// 64 KiB file, standard ones 50 ms on 4 MiB.
fn run_filesystem(runner: *bench.Runner, backend: Backend, ring: ?*Ring) !void {
    const duration_ms = runner.inputs.pick(u64, 10, 50, 1_000);
    const file_size = runner.inputs.pick(u64, 64 << 10, 4 << 20, 64 << 20);
    const io_size = 4096;
    const names = comptime @typeInfo(fs_config.Workload).@"enum".field_names;
    inline for (names) |name| {
        const workload = comptime std.meta.stringToEnum(fs_config.Workload, name).?;
        var cfg = try filesystem_config(workload, backend, file_size);
        cfg.duration_ns = duration_ms * std.time.ns_per_ms;
        if (cfg.validate()) |message| std.debug.panic("bench config: {s}", .{message});
        const benchmark = bench.Benchmark.init("runtime::storage::" ++ name)
            .with_param("backend", @tagName(backend))
            .with_param("inflight", cfg.inflight)
            .with_param("io_size", io_size);
        if (runner.matches(benchmark.name())) {
            var load: FilesystemLoad = .{
                .gpa = runner.allocator,
                .io = runner.io,
                .ring = ring,
                .cfg = &cfg,
            };
            try runner.run(benchmark, &load);
        }
    }
}

/// The configuration commonware's CLI flags give `workload`, through `fs_config.parse`.
fn filesystem_config(
    comptime workload: fs_config.Workload,
    backend: Backend,
    file_size: u64,
) !fs_config.Config {
    var size_text: [24]u8 = undefined;
    const size = try std.fmt.bufPrint(&size_text, "{d}", .{file_size});
    const backend_name = if (backend == .io_uring) "iouring" else "tokio";
    const common = [_][]const u8{
        "--bench",    "--backend", backend_name, "--workload", @tagName(workload),
        "--duration", "1",         "--io-size",  "4K",
    };
    const extra: []const []const u8 = switch (workload) {
        .write_append => &.{ "--sync-every", "8", "--write-shape", "vectored" },
        .write_seq => &.{ "--inflight", "4", "--file-size", size, "--sync-every", "8" },
        .write_rand => &.{ "--inflight", "4", "--file-size", size, "--write-shape", "vectored" },
        .write_sync => &.{
            "--inflight",    "4",              "--file-size", size,
            "--sync-method", "write_and_sync",
        },
        .read_seq, .read_rand, .read_write_append => &.{
            "--inflight", "4",    "--file-size", size,
            "--cache",    "warm", "--output",    "json",
        },
    };
    var args: [common.len + 8][]const u8 = undefined;
    @memcpy(args[0..common.len], &common);
    @memcpy(args[common.len..][0..extra.len], extra);
    return switch (fs_config.parse(args[0 .. common.len + extra.len])) {
        .config => |config| config,
        .invalid => |message| std.debug.panic("bench config: {s}", .{message}),
    };
}

/// One iteration runs one timed workload (commonware's `run_benchmark`) on a fresh root and
/// keeps its report for the metrics.
const FilesystemLoad = struct {
    gpa: Allocator,
    io: Io,
    ring: ?*Ring,
    cfg: *fs_config.Config,
    root_path: []u8 = &.{},
    report: ?fs_report.Report = null,

    pub fn setup(load: *FilesystemLoad) !void {
        try Io.Dir.cwd().createDirPath(load.io, ".zig-cache/tmp");
        load.root_path = try @import("storage/benches/filesystem.zig").prepare_root(
            load.gpa,
            load.io,
            ".zig-cache/tmp",
        );
        load.cfg.root = load.root_path;
    }

    pub fn iter(load: *FilesystemLoad) !void {
        const root = try Io.Dir.cwd().openDir(load.io, load.root_path, .{});
        var storage: Storage = try .init(load.io, load.gpa, root, .{ .ring = load.ring });
        defer storage.deinit();
        const reopened = try Io.Dir.cwd().openDir(load.io, load.root_path, .{});
        defer reopened.close(load.io);
        const env: fs_workload.Env = .{
            .gpa = load.gpa,
            .io = load.io,
            .storage = storage.storage(),
            .root = reopened,
        };
        const report = try fs_workload.run_benchmark(&env, load.cfg);
        assert(report.read != null or report.write != null);
        if (report.write) |write| assert(write.ops > 0);
        if (report.read) |read| assert(read.ops > 0);
        if (load.cfg.workload == .write_append) {
            assert(report.final_file_size == report.write.?.bytes);
        }
        // Both report formats render (commonware's `print_human` and `print_json`).
        var text: [4096]u8 = undefined;
        var writer: Io.Writer = .fixed(&text);
        try report.print_human(&writer, load.cfg);
        try report.print_json(&writer, load.cfg);
        assert(std.mem.indexOf(u8, writer.buffered(), "final_file_size") != null);
        load.report = report;
    }

    pub fn teardown(load: *FilesystemLoad) void {
        @import("storage/benches/filesystem.zig").cleanup_root(load.io, load.root_path) catch |err|
            std.log.warn("runtime benches: could not remove {s}: {t}", .{ load.root_path, err });
        load.gpa.free(load.root_path);
    }

    pub fn metrics(load: *const FilesystemLoad, buffer: []bench.Metric) []const bench.Metric {
        const report = load.report orelse return buffer[0..0];
        var count: usize = 0;
        if (report.read) |read| {
            buffer[count] = .init("read_ops", read.ops);
            buffer[count + 1] = .init("read_p99_latency_ns", read.p99_latency_ns);
            count += 2;
        }
        if (report.write) |write| {
            buffer[count] = .init("write_ops", write.ops);
            buffer[count + 1] = .init("write_p99_latency_ns", write.p99_latency_ns);
            count += 2;
        }
        buffer[count] = .init("final_file_size", report.final_file_size);
        return buffer[0 .. count + 1];
    }
};
