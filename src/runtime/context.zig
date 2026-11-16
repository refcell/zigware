//! The runtime context (commonware's `Supervisor`, `Spawner`, `Clock`, `Metrics`, `Storage`,
//! and `Network` traits on one value): what a task is given to spawn, sleep, store, connect,
//! and register metrics.
//!
//! `Context(Network)` is a plain value, generic over the backend's network type, so the same
//! code runs on `deterministic.Runner` and `production.Runner`:
//!
//! ```zig
//! fn run(ctx: Context, ...) !void {
//!     const handle = try ctx.child("worker").spawn(worker, .{42});
//!     try ctx.sleep(.fromMilliseconds(10));
//!     const value = try handle.join(); // error.Closed if the worker was aborted
//! }
//! ```
//!
//! Supervision follows commonware (`supervision.zig`): `spawn` consumes the context, and when
//! a task returns or is aborted, every task spawned below its context is aborted. Spawn several
//! tasks from `ctx.child(label)`; spawning twice from one context panics.
//!
//! A `Handle` must be joined, aborted, or detached exactly once (Rust drops it). A detached
//! task keeps running under supervision.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const storage_mod = @import("storage.zig");
const signal = @import("signal.zig");
const supervision = @import("supervision.zig");
const telemetry = @import("telemetry/mod.zig");
const Auditor = @import("deterministic.zig").Auditor;

const Scope = telemetry.metrics.Scope;
const NodeRef = supervision.NodeRef;
const raw = telemetry.metrics.raw;
const TaskLabel = telemetry.metrics.task.Label;
pub const Execution = telemetry.metrics.task.Execution;
const parallel = @import("parallel");
const Registered = telemetry.metrics.Registered;
const traces = telemetry.traces;
const resolver_mod = @import("resolver.zig");
const IpAddr = resolver_mod.IpAddr;

/// Default capacity of the supervision tree: live contexts at once.
pub const default_max_contexts = 16 * 1024;

/// The latest deadline `sleep_until` waits for (commonware `SystemTime::limit` stand-in).
pub const deadline_max: Io.Timestamp = .fromNanoseconds(std.math.maxInt(i64));

/// State every context of one runner shares.
pub const Runtime = struct {
    gpa: Allocator,
    io: Io,
    tree: supervision.Tree,
    stopper: signal.Stopper,
    /// The deterministic runtime's auditor, if any.
    auditor: ?*Auditor,
    /// `runtime_tasks_spawned` and `runtime_tasks_running` (commonware's executor metrics),
    /// keyed by the spawning context's label. Attributes never reach the key, so spawning
    /// with a varying attribute does not grow them.
    tasks_spawned: Registered(raw.Family(TaskLabel, raw.Counter)),
    tasks_running: Registered(raw.Family(TaskLabel, raw.Gauge)),
    /// Names the fiber a spawn is about to start, for runtimes that track task labels
    /// themselves (the deterministic runner's `runtime_task_polls` and audit).
    label_hook: ?LabelHook = null,
    /// Where events from `Context.tracer` go (the runner's `Config.subscriber`), if anywhere.
    subscriber: ?traces.Subscriber = null,
    /// What `Context.resolve` asks (the runner's resolver).
    resolver: ?resolver_mod.Resolver = null,
    /// The deterministic runner's DNS records, which `Context.resolver_register` edits; null on
    /// production.
    dns: ?*resolver_mod.Dns = null,
    /// Whether `Context.strategy` runs parallel work inline on the calling task (the
    /// deterministic runner: one OS thread, so results never depend on thread timing).
    strategy_inline: bool = false,

    pub const LabelHook = struct {
        userdata: *anyopaque,
        /// Called with the task's label right before its fiber starts, and with null if the
        /// start failed.
        label_next: *const fn (userdata: *anyopaque, name: ?[]const u8) void,
    };

    /// `scope` is the runner's root scope; the task metrics register below `runtime`.
    pub fn init(
        gpa: Allocator,
        io: Io,
        max_contexts: u32,
        auditor: ?*Auditor,
        scope: Scope,
    ) !Runtime {
        assert(scope.prefix().len == 0);
        var tree: supervision.Tree = try .init(gpa, io, max_contexts);
        errdefer tree.deinit(gpa);
        const runtime_scope = scope.sub_registry("runtime");
        var spawned = try runtime_scope.family(
            TaskLabel,
            raw.Counter,
            "tasks_spawned",
            "Total number of tasks spawned",
        );
        errdefer spawned.deinit();
        const running = try runtime_scope.family(
            TaskLabel,
            raw.Gauge,
            "tasks_running",
            "Number of tasks currently running",
        );
        return .{
            .gpa = gpa,
            .io = io,
            .tree = tree,
            .stopper = .init(io),
            .auditor = auditor,
            .tasks_spawned = spawned,
            .tasks_running = running,
        };
    }

    pub fn deinit(runtime: *Runtime) void {
        runtime.tasks_running.deinit();
        runtime.tasks_spawned.deinit();
        runtime.tree.deinit(runtime.gpa);
        runtime.* = undefined;
    }

    /// Counts a task spawned under `name` and returns its running gauge, which the task
    /// decrements when it ends.
    fn task_started(
        runtime: *Runtime,
        name: []const u8,
        execution: Execution,
    ) Allocator.Error!*raw.Gauge {
        const label: TaskLabel = .task(name, execution);
        const spawned = try runtime.tasks_spawned.metric().get_or_create(label);
        const running = try runtime.tasks_running.metric().get_or_create(label);
        spawned.inc();
        running.inc();
        assert(running.get() > 0);
        return running;
    }

    fn audit(runtime: *Runtime, label: []const u8, fields: []const []const u8) void {
        if (runtime.auditor) |auditor| auditor.event(label, fields);
    }
};

pub const JoinError = error{Closed} || Io.Cancelable;

/// The return type of a task function.
pub fn Return(comptime function: anytype) type {
    return @typeInfo(@TypeOf(function)).@"fn".return_type.?;
}

/// The most handles one `select` waits on.
pub const select_max = 64;

/// Waits for the first of `handles` to finish, aborts the rest, and returns the first one's
/// result (commonware `Handle::select`). Consumes every handle. `error.Closed` if `handles` is
/// empty. Returns only once every task has ended, even when the caller is canceled.
pub fn select(
    comptime T: type,
    io: Io,
    handles: []const Handle(T),
) (JoinError || Io.ConcurrentError)!T {
    if (handles.len == 0) return error.Closed;
    assert(handles.len <= select_max);
    const Done = struct { index: usize, result: JoinError!T };
    const Race = union(enum) { done: Done };
    const Waiter = struct {
        fn wait(handle: Handle(T), index: usize) Done {
            return .{ .index = index, .result = handle.join() };
        }
    };
    // A joined handle may free its task state, so abort through copies of the nodes: a
    // retired node's generation makes a stale copy a no-op.
    var nodes: [select_max]NodeRef = undefined;
    for (handles, nodes[0..handles.len]) |handle, *node| {
        node.* = if (handle.header) |header| header.node else .aborted;
    }
    const tree = handles[0].tree;
    var buffer: [select_max]Race = undefined;
    var race: Io.Select(Race) = .init(io, buffer[0..handles.len]);
    var started: usize = 0;
    while (started < handles.len) : (started += 1) {
        race.concurrent(.done, Waiter.wait, .{ handles[started], started }) catch |err| {
            for (handles[started..]) |handle| {
                if (handle.abort()) |_| {} else |_| {}
            }
            abort_all(tree, nodes[0..started]);
            drain(Race, &race, started);
            return err;
        };
    }
    const first = race.await() catch |err| {
        abort_all(tree, nodes[0..handles.len]);
        drain(Race, &race, handles.len);
        return err;
    };
    abort_all(tree, nodes[0..handles.len]);
    drain(Race, &race, handles.len - 1);
    assert(first.done.index < handles.len);
    return first.done.result;
}

/// Aborts the subtree of every node in `nodes`.
fn abort_all(tree: *supervision.Tree, nodes: []const NodeRef) void {
    assert(nodes.len <= select_max);
    for (nodes) |node| tree.abort(node, null);
}

/// Collects `count` results the caller will not use, then releases the select.
fn drain(comptime Race: type, race: *Io.Select(Race), count: usize) void {
    for (0..count) |_| {
        _ = race.queue.getOneUncancelable(race.io) catch unreachable; // Never closed here.
    }
    race.cancelDiscard();
}

/// A spawned task's result (commonware `Handle`). Join, abort, or detach it exactly once.
pub fn Handle(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Null for a task that never started because its context was already aborted.
        header: ?*supervision.Header,
        tree: *supervision.Tree,
        result: *const T,

        /// Waits for the task's result. `error.Closed` if it was aborted before it returned.
        /// A canceled join leaves the task running detached, as dropping commonware's
        /// `Handle` future does.
        pub fn join(handle: Self) JoinError!T {
            const header = handle.header orelse return error.Closed;
            const tree = handle.tree;
            // Claim only once the task ended: claiming earlier would await the future
            // uncancelably, and an aborting ancestor could no longer cancel the task.
            header.finished.wait(tree.io) catch |err| {
                tree.detach(header);
                return err;
            };
            assert(header.ended);
            if (tree.claim(header, false)) {
                tree.finish(header, false);
            } else {
                // The claimer's await returns at once: the task already ended.
                header.done.waitUncancelable(tree.io);
            }
            assert(header.claimed);
            const closed = header.closed;
            const result = handle.result.*;
            tree.release(header);
            return if (closed) error.Closed else result;
        }

        /// Aborts the task and everything spawned below its context, then waits for them
        /// (commonware `Handle::abort` followed by awaiting the handle).
        pub fn abort(handle: Self) JoinError!T {
            const header = handle.header orelse return error.Closed;
            handle.tree.abort(header.node, null);
            return handle.join();
        }

        /// Releases the handle; the task keeps running under supervision.
        pub fn detach(handle: Self) void {
            const header = handle.header orelse return;
            handle.tree.detach(header);
        }
    };
}

pub const ThreadPoolError = parallel.ThreadPool.Error;

/// A parallel strategy from `Context.strategy`, owning its thread pool.
pub const Strategy = struct {
    rayon: parallel.Rayon,

    /// Stops the pool's workers. No operation may be in progress.
    pub fn deinit(strategy: *Strategy) void {
        strategy.rayon.pool.destroy();
        strategy.* = undefined;
    }
};

pub fn Context(comptime Network: type) type {
    return struct {
        const Self = @This();

        runtime: *Runtime,
        node: NodeRef,
        storage: storage_mod.Storage,
        network: *Network,
        scope: Scope,
        /// How the next `spawn` runs its task; reset for every new context.
        execution: Execution = .shared,

        /// The root context of a run; `run_root` gives it its supervision node.
        pub fn root(
            runtime: *Runtime,
            storage: storage_mod.Storage,
            network: *Network,
            scope: Scope,
        ) Self {
            return .{
                .runtime = runtime,
                .node = .aborted,
                .storage = storage,
                .network = network,
                .scope = scope,
            };
        }

        pub fn io(ctx: *const Self) Io {
            return ctx.runtime.io;
        }

        pub fn gpa(ctx: *const Self) Allocator {
            return ctx.runtime.gpa;
        }

        /// Runs `function(ctx, args...)` as the root of a supervision tree: when it returns,
        /// every task it spawned is aborted.
        pub fn run_root(ctx: Self, comptime function: anytype, args: anytype) Return(function) {
            const tree = &ctx.runtime.tree;
            var root_ctx = ctx;
            root_ctx.node = tree.root();
            defer {
                tree.abort(root_ctx.node, null);
                // Await tasks that returned but had not reported `ended`, and detached ones.
                tree.drain();
            }
            return @call(.auto, function, .{root_ctx} ++ args);
        }

        /// A child context labeled `label` (commonware `Supervisor::child`): metrics are named
        /// `<prefix>_<label>_...`, and it gets its own supervision node.
        pub fn child(ctx: Self, label: []const u8) Self {
            var result = ctx;
            result.scope = ctx.scope.child(label);
            result.node = ctx.runtime.tree.child(ctx.node);
            result.execution = .shared;
            return result;
        }

        /// The next `spawn` runs its task on a dedicated thread (commonware
        /// `Spawner::dedicated`). `std.Io` already runs each concurrent task on its own fiber
        /// (deterministic) or pool thread (production), so this changes only the task's
        /// `execution` metric label.
        pub fn dedicated(ctx: Self) Self {
            var result = ctx;
            result.execution = .dedicated;
            return result;
        }

        /// The next `spawn` runs its task on the shared runtime, which `blocking` marks as
        /// allowed to block (commonware `Spawner::shared`). Like `dedicated`, only the metric
        /// label changes.
        pub fn shared(ctx: Self, blocking: bool) Self {
            var result = ctx;
            result.execution = if (blocking) .shared_blocking else .shared;
            return result;
        }

        /// A parallel strategy planning for `parallelism` threads (commonware
        /// `Strategizer::strategy`). The deterministic runner runs its work inline on the
        /// calling task, as commonware's single registered Rayon thread does; the production
        /// runner starts `parallelism - 1` workers, and the caller runs jobs too. Release
        /// with `Strategy.deinit`.
        pub fn strategy(ctx: *const Self, parallelism: u32) ThreadPoolError!Strategy {
            assert(parallelism >= 1);
            const threads = if (ctx.runtime.strategy_inline) 0 else parallelism - 1;
            const pool = try parallel.ThreadPool.create(ctx.gpa(), ctx.io(), .{
                .threads = threads,
            });
            const rayon = parallel.Rayon.init(pool).with_parallelism(parallelism);
            assert(rayon.parallelism() == parallelism);
            return .{ .rayon = rayon };
        }

        /// The addresses `host` resolves to (commonware `Resolver::resolve`); free them with
        /// `ctx.gpa()`. `error.ResolveFailed` if it resolves to none.
        pub fn resolve(ctx: *const Self, host: []const u8) resolver_mod.Error![]IpAddr {
            const resolver = ctx.runtime.resolver orelse return error.ResolveFailed;
            return resolver.resolve(ctx.gpa(), host);
        }

        /// Maps `host` to `addresses`, or removes its mapping when null (commonware
        /// `deterministic::Context::resolver_register`). Deterministic runner only.
        pub fn resolver_register(
            ctx: *const Self,
            host: []const u8,
            addresses: ?[]const IpAddr,
        ) Allocator.Error!void {
            const dns = ctx.runtime.dns orelse @panic("resolver_register is deterministic only");
            try dns.register(host, addresses);
        }

        /// A tracer emitting under `target` (a module path, as tracing's `target:`) to the
        /// runner's subscriber; with none, its events cost nothing.
        pub fn tracer(ctx: *const Self, target: []const u8) traces.Tracer {
            assert(target.len > 0);
            return .init(ctx.runtime.subscriber, target);
        }

        /// Adds `key="value"` to every metric registered below (commonware
        /// `Supervisor::with_attribute`).
        pub fn with_attribute(ctx: Self, key: []const u8, value: anytype) Self {
            var result = ctx;
            result.scope = ctx.scope.with_attribute(key, value);
            return result;
        }

        pub const SpawnError = Allocator.Error || Io.ConcurrentError;

        /// Spawns `function(task_ctx, args...)` (commonware `Spawner::spawn`), consuming
        /// `ctx`. The task runs at once; its handle returns its result.
        pub fn spawn(
            ctx: Self,
            comptime function: anytype,
            args: anytype,
        ) SpawnError!Handle(Return(function)) {
            const State = TaskState(Self, function, @TypeOf(args));
            const tree = &ctx.runtime.tree;
            tree.reap();
            const task_node = tree.child(ctx.node);
            if (task_node.index == NodeRef.aborted.index) {
                return .{ .header = null, .tree = tree, .result = undefined };
            }
            const state = ctx.gpa().create(State) catch |err| {
                tree.abort(task_node, null);
                return err;
            };
            const name = ctx.scope.prefix();
            const running = ctx.runtime.task_started(name, ctx.execution) catch |err| {
                tree.abort(task_node, null);
                ctx.gpa().destroy(state);
                return err;
            };
            state.* = .{ .context = ctx, .args = args, .running = running };
            state.context.node = task_node;
            state.context.execution = .shared;
            state.header.node = ctx.node;
            tree.starting();
            const hook = ctx.runtime.label_hook;
            // The label lives in the task's state, which outlives its fiber.
            if (hook) |h| h.label_next(h.userdata, state.context.scope.prefix());
            state.future = ctx.io().concurrent(State.run, .{state}) catch |err| {
                if (hook) |h| h.label_next(h.userdata, null);
                tree.start_failed();
                running.dec();
                tree.abort(task_node, null);
                ctx.gpa().destroy(state);
                return err;
            };
            if (!tree.attach(&state.header)) {
                // The context's node was aborted while the task started: cancel the task
                // unless it already returned.
                const claimed = tree.claim(&state.header, true);
                assert(claimed);
                tree.finish(&state.header, true);
            }
            return .{ .header = &state.header, .tree = tree, .result = &state.result };
        }

        /// The current wall-clock time (commonware `Clock::current`).
        pub fn current(ctx: *const Self) Io.Timestamp {
            return Io.Clock.real.now(ctx.io());
        }

        pub fn sleep(ctx: *const Self, duration: Io.Duration) Io.Cancelable!void {
            return ctx.io().sleep(duration, .awake);
        }

        /// Sleeps until the wall clock reaches `deadline`. Deadlines past `deadline_max` (in
        /// 2262) sleep until it, since `std.Io.Threaded` cannot represent later ones.
        pub fn sleep_until(ctx: *const Self, deadline: Io.Timestamp) Io.Cancelable!void {
            const clamped = if (deadline.nanoseconds > deadline_max.nanoseconds)
                deadline_max
            else
                deadline;
            assert(clamped.nanoseconds <= deadline_max.nanoseconds);
            const limit: Io.Timeout = .{ .deadline = .{ .raw = clamped, .clock = .real } };
            return limit.sleep(ctx.io());
        }

        pub const TimeoutError = error{Timeout} || Io.Cancelable || Io.ConcurrentError;

        /// Runs `function(args...)` and returns its result, or `error.Timeout` (canceling it)
        /// if it takes longer than `duration` (commonware `Clock::timeout`).
        pub fn timeout(
            ctx: *const Self,
            duration: Io.Duration,
            comptime function: anytype,
            args: anytype,
        ) TimeoutError!Return(function) {
            const T = Return(function);
            const Race = union(enum) { value: T, expired: Io.Cancelable!void };
            var buffer: [2]Race = undefined;
            var race: Io.Select(Race) = .init(ctx.io(), &buffer);
            defer race.cancelDiscard();
            try race.concurrent(.value, function, args);
            try race.concurrent(.expired, sleep_for, .{ ctx.io(), duration });
            return switch (try race.await()) {
                .value => |value| value,
                .expired => |expired| {
                    try expired;
                    return error.Timeout;
                },
            };
        }

        fn sleep_for(task_io: Io, duration: Io.Duration) Io.Cancelable!void {
            return task_io.sleep(duration, .awake);
        }

        /// Resolves every `stopped` signal with `value` (the first `stop` wins) and waits until
        /// they are all released, or `error.Timeout` after `timeout` (commonware `stop`).
        pub fn stop(
            ctx: *const Self,
            value: i32,
            timeout_duration: ?Io.Duration,
        ) signal.StopError!void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(i32, &bytes, value, .big);
            ctx.runtime.audit("stop", &.{&bytes});
            const limit: Io.Timeout = if (timeout_duration) |duration|
                .{ .duration = .{ .raw = duration, .clock = .awake } }
            else
                .none;
            return ctx.runtime.stopper.stop(value, limit);
        }

        /// A signal resolved by the first `stop` (commonware `stopped`). Release it with
        /// `deinit` once shutdown work is done.
        pub fn stopped(ctx: *const Self) signal.Signal {
            ctx.runtime.audit("stopped", &.{});
            return ctx.runtime.stopper.stopped();
        }

        /// Registers `metric` as `<prefix>_<name>` (commonware `Metrics::register`).
        pub fn register(
            ctx: *const Self,
            name: []const u8,
            help: []const u8,
            metric: anytype,
        ) Allocator.Error!telemetry.metrics.Registered(@TypeOf(metric)) {
            if (ctx.runtime.auditor != null) ctx.audit_register(name, help);
            return ctx.scope.register(name, help, metric);
        }

        fn audit_register(ctx: *const Self, name: []const u8, help: []const u8) void {
            var fields: [2 + 2 * telemetry.metrics.scope.attribute_count_max][]const u8 = undefined;
            fields[0] = name;
            fields[1] = help;
            var count: usize = 2;
            for (0..ctx.scope.attribute_count) |index| {
                const attribute = ctx.scope.attribute(index);
                fields[count] = attribute.key;
                fields[count + 1] = attribute.value;
                count += 2;
            }
            ctx.runtime.audit("register", fields[0..count]);
        }

        /// The text exposition of every registered metric (commonware `Metrics::encode`).
        pub fn encode(ctx: *const Self, allocator: Allocator) Allocator.Error![]u8 {
            ctx.runtime.audit("encode", &.{});
            return ctx.scope.encode(allocator);
        }
    };
}

/// The heap state of one spawned task.
fn TaskState(comptime Ctx: type, comptime function: anytype, comptime Args: type) type {
    const T = Return(function);
    return struct {
        const State = @This();

        header: supervision.Header = .{ .vtable = &vtable },
        future: Io.Future(T) = undefined,
        result: T = undefined,
        context: Ctx,
        args: Args,
        /// This task's `runtime_tasks_running` entry, decremented when it ends.
        running: *raw.Gauge,

        const vtable: supervision.Header.VTable = .{ .finish = finish, .destroy = destroy };

        fn run(state: *State) T {
            const tree = &state.context.runtime.tree;
            const result = @call(.auto, function, .{state.context} ++ state.args);
            assert(state.running.get() > 0);
            state.running.dec();
            // Abort everything spawned below this task's context, then report it ended.
            tree.abort(state.header.node, &state.header);
            tree.ended(&state.header);
            return result;
        }

        fn finish(header: *supervision.Header, task_io: Io, cancel: bool) void {
            const state: *State = @alignCast(@fieldParentPtr("header", header));
            const future = &state.future;
            state.result = if (cancel) future.cancel(task_io) else future.await(task_io);
        }

        fn destroy(header: *supervision.Header) void {
            const state: *State = @alignCast(@fieldParentPtr("header", header));
            const allocator = state.context.runtime.gpa;
            allocator.destroy(state);
        }
    };
}

test {
    _ = @import("context_test.zig");
}
