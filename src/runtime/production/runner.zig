//! The production runner (commonware `runtime::tokio::Runner`): the same surface as
//! `deterministic.Runner` (`io`, `storage`, `network`, `metrics`, `start`) over a real
//! `std.Io.Threaded`, file storage under a held directory, and TCP.
//!
//! `std.Io.Uring` does not compile in Zig 0.17.1, so the runner uses `std.Io.Threaded` on
//! every platform; on Linux, `Config.io_uring` moves blob and socket I/O onto our own ring
//! (commonware's `iouring-storage` and `iouring-network` features). See the runtime-telemetry
//! lane file.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const iface = @import("../storage.zig");
const telemetry = @import("../telemetry/mod.zig");
const file_storage = @import("storage.zig");
const tcp_network = @import("network.zig");
const ring_mod = @import("ring.zig");

pub const Error = iface.Error;

/// commonware `tokio::Config`.
pub const Config = struct {
    /// Base directory of all storage, created if missing and held for the run.
    storage_directory: []const u8,
    storage: file_storage.Config = .{},
    network: tcp_network.Config = .{},
    /// Runs storage and network I/O through io_uring (Linux only); null keeps it on `std.Io`.
    io_uring: ?ring_mod.Config = null,
    /// Threads running tasks besides the caller's; null uses one per logical CPU, less one.
    worker_threads: ?u32 = null,
    thread_stack_size_bytes: usize = std.Thread.SpawnConfig.default_stack_size,

    pub fn validate(config: Config) void {
        assert(config.storage_directory.len > 0);
        assert(config.thread_stack_size_bytes > 0);
        assert(config.storage.layouts.contains(config.storage.layout));
        // The runner supplies the ring itself.
        assert(config.storage.ring == null and config.network.ring == null);
    }
};

pub const Runner = struct {
    threaded: Io.Threaded,
    /// Initialized only with `Config.io_uring`.
    ring: ring_mod.Ring,
    ring_active: bool,
    file_storage: file_storage.Storage,
    tcp: tcp_network.Network,
    /// The metrics registry. Release every handle before `deinit`.
    metrics_registry: telemetry.metrics.Registry,

    /// Initializes in place: the storage and network hold the runner's `Io`, so the runner
    /// must not move. Holds `storage_directory` until `deinit`.
    pub fn init(runner: *Runner, gpa: Allocator, config: Config) Error!void {
        config.validate();
        runner.threaded = .init(gpa, .{
            .stack_size = config.thread_stack_size_bytes,
            .async_limit = if (config.worker_threads) |count| .limited(count) else null,
        });
        errdefer runner.threaded.deinit();
        const runner_io = runner.threaded.io();
        var storage_config = config.storage;
        var network_config = config.network;
        runner.ring_active = config.io_uring != null;
        if (config.io_uring) |ring_config| {
            runner.ring.init(runner_io, ring_config) catch return error.Io;
            storage_config.ring = &runner.ring;
            network_config.ring = &runner.ring;
        }
        errdefer if (runner.ring_active) runner.ring.deinit();
        const root = Io.Dir.cwd().createDirPathOpen(runner_io, config.storage_directory, .{}) catch
            return error.Io;
        errdefer root.close(runner_io);
        runner.file_storage = try .init(runner_io, gpa, root, storage_config);
        runner.tcp = .init(gpa, runner_io, network_config);
        runner.metrics_registry = .init(gpa);
        assert(runner.tcp.io.userdata == runner.file_storage.io.userdata);
    }

    /// Every blob, listener, and connection must be closed first.
    pub fn deinit(runner: *Runner) void {
        runner.metrics_registry.deinit();
        runner.tcp.deinit();
        runner.file_storage.deinit();
        if (runner.ring_active) runner.ring.deinit();
        runner.threaded.deinit();
        runner.* = undefined;
    }

    /// Real time, OS randomness, and threads.
    pub fn io(runner: *Runner) Io {
        return runner.threaded.io();
    }

    /// File storage under `storage_directory`.
    pub fn storage(runner: *Runner) iface.Storage {
        return runner.file_storage.storage();
    }

    /// The TCP network.
    pub fn network(runner: *Runner) *tcp_network.Network {
        return &runner.tcp;
    }

    /// The root metrics scope: empty label, no attributes.
    pub fn metrics(runner: *Runner) telemetry.metrics.Scope {
        return .init(&runner.metrics_registry);
    }

    /// Runs `function(args...)` on the calling thread until it returns. Tasks it starts run
    /// on the runner's threads; it awaits or cancels them before returning.
    pub fn start(
        runner: *Runner,
        comptime function: anytype,
        args: std.meta.ArgsTuple(@TypeOf(function)),
    ) @typeInfo(@TypeOf(function)).@"fn".return_type.? {
        // The runner has not moved since `init`.
        assert(runner.tcp.io.userdata == @as(?*anyopaque, &runner.threaded));
        return @call(.auto, function, args);
    }
};
