//! The production runner (commonware `runtime::tokio::Runner`): the same surface as
//! `deterministic.Runner` (`io`, `storage`, `network`, `metrics`, `start`, `start_context`)
//! over a real `std.Io.Threaded`, file storage under a held directory, and TCP.
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
const system_resolver_mod = @import("resolver.zig");
const context_mod = @import("../context.zig");
const process = @import("../process/metered.zig");

pub const Error = iface.Error;

/// The production runtime's context (see `context.zig`).
pub const Context = context_mod.Context(tcp_network.Network);

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
    /// Capacity of the supervision tree: contexts alive at once.
    max_contexts: u32 = context_mod.default_max_contexts,
    thread_stack_size_bytes: usize = std.Thread.SpawnConfig.default_stack_size,
    /// Receives the events of `Context.tracer` (tracing's installed subscriber); none drops
    /// them unformatted.
    subscriber: ?telemetry.traces.Subscriber = null,

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
    /// `runtime_process_rss` and `runtime_process_virtual_memory`, refreshed while `start` or
    /// `start_context` runs (commonware spawns the collector for the runtime's life).
    process_metrics: process.Metrics,
    /// What every `Context` shares, created by the first `start_context`.
    context_runtime: ?context_mod.Runtime,
    max_contexts: u32,
    subscriber: ?telemetry.traces.Subscriber,
    /// The system resolver behind `Context.resolve`.
    system_resolver: system_resolver_mod.Resolver,
    gpa: Allocator,

    /// Initializes in place: the storage and network hold the runner's `Io`, so the runner
    /// must not move. Holds `storage_directory` until `deinit`.
    pub fn init(runner: *Runner, gpa: Allocator, config: Config) Error!void {
        config.validate();
        runner.threaded = .init(gpa, .{
            .stack_size = config.thread_stack_size_bytes,
            .async_limit = if (config.worker_threads) |count| .limited(count) else null,
        });
        errdefer runner.threaded.deinit();
        runner.metrics_registry = .init(gpa);
        errdefer runner.metrics_registry.deinit();
        runner.process_metrics = try .init(&runner.metrics().sub_registry("runtime"));
        errdefer runner.process_metrics.deinit();
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
        const cwd = Io.Dir.cwd();
        const root = cwd.createDirPathOpen(runner_io, config.storage_directory, .{}) catch |err|
            return if (err == error.Canceled) error.Canceled else error.Io;
        errdefer root.close(runner_io);
        runner.file_storage = try .init(runner_io, gpa, root, storage_config);
        runner.tcp = .init(gpa, runner_io, network_config);
        runner.context_runtime = null;
        runner.max_contexts = config.max_contexts;
        runner.subscriber = config.subscriber;
        runner.system_resolver = .{ .io = runner_io };
        runner.gpa = gpa;
        assert(runner.tcp.io.userdata == runner.file_storage.io.userdata);
    }

    /// Every blob, listener, and connection must be closed first.
    pub fn deinit(runner: *Runner) void {
        if (runner.context_runtime) |*runtime| runtime.deinit();
        runner.process_metrics.deinit();
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
        var collector = runner.collector_start();
        defer runner.collector_stop(&collector);
        return @call(.auto, function, args);
    }

    const Collector = ?Io.Future(Io.Cancelable!void);

    /// Refreshes the process metrics now, then every tick on a task of their own (none when
    /// no thread is free: they then hold the first reading).
    fn collector_start(runner: *Runner) Collector {
        const io_ = runner.io();
        // A cancel arriving here belongs to the caller: re-arm it for the body to see.
        runner.process_metrics.update(io_) catch io_.recancel();
        return io_.concurrent(process.Metrics.collect, .{ &runner.process_metrics, io_ }) catch
            null;
    }

    fn collector_stop(runner: *Runner, collector: *Collector) void {
        const future = &(collector.* orelse return);
        future.cancel(runner.io()) catch |err| assert(err == error.Canceled);
        collector.* = null;
    }

    /// Runs `function(ctx, args...)` on the calling thread with a root `Context` over this
    /// runner's io, storage, network, and metrics. When it returns, every task it spawned is
    /// aborted.
    pub fn start_context(
        runner: *Runner,
        comptime function: anytype,
        args: anytype,
    ) Allocator.Error!context_mod.Return(function) {
        assert(runner.tcp.io.userdata == @as(?*anyopaque, &runner.threaded));
        if (runner.context_runtime == null) {
            const io_ = runner.io();
            const max = runner.max_contexts;
            runner.context_runtime = try .init(runner.gpa, io_, max, null, runner.metrics());
            runner.context_runtime.?.subscriber = runner.subscriber;
            runner.context_runtime.?.resolver = runner.system_resolver.resolver();
        }
        const runtime = &runner.context_runtime.?;
        const ctx: Context = .root(runtime, runner.storage(), runner.network(), runner.metrics());
        var collector = runner.collector_start();
        defer runner.collector_stop(&collector);
        return ctx.run_root(function, args);
    }
};
