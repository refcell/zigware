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

/// Default capacity of the supervision tree: live contexts at once.
pub const default_max_contexts = 16 * 1024;

/// State every context of one runner shares.
pub const Runtime = struct {
    gpa: Allocator,
    io: Io,
    tree: supervision.Tree,
    stopper: signal.Stopper,
    /// The deterministic runtime's auditor, if any.
    auditor: ?*Auditor,

    pub fn init(gpa: Allocator, io: Io, max_contexts: u32, auditor: ?*Auditor) !Runtime {
        return .{
            .gpa = gpa,
            .io = io,
            .tree = try .init(gpa, io, max_contexts),
            .stopper = .init(io),
            .auditor = auditor,
        };
    }

    pub fn deinit(runtime: *Runtime) void {
        runtime.tree.deinit(runtime.gpa);
        runtime.* = undefined;
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

/// A spawned task's result (commonware `Handle`). Join, abort, or detach it exactly once.
pub fn Handle(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Null for a task that never started because its context was already aborted.
        header: ?*supervision.Header,
        tree: *supervision.Tree,
        result: *const T,

        /// Waits for the task's result. `error.Closed` if it was aborted before it returned.
        pub fn join(handle: Self) JoinError!T {
            const header = handle.header orelse return error.Closed;
            if (handle.tree.claim(header, false)) {
                handle.tree.finish(header, false);
            } else {
                try header.done.wait(handle.tree.io);
            }
            const closed = header.closed;
            const result = handle.result.*;
            handle.tree.release(header);
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

pub fn Context(comptime Network: type) type {
    return struct {
        const Self = @This();

        runtime: *Runtime,
        node: NodeRef,
        storage: storage_mod.Storage,
        network: *Network,
        scope: Scope,

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
                tree.reap();
            }
            return @call(.auto, function, .{root_ctx} ++ args);
        }

        /// A child context labeled `label` (commonware `Supervisor::child`): metrics are named
        /// `<prefix>_<label>_...`, and it gets its own supervision node.
        pub fn child(ctx: Self, label: []const u8) Self {
            var result = ctx;
            result.scope = ctx.scope.child(label);
            result.node = ctx.runtime.tree.child(ctx.node);
            return result;
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
            state.* = .{ .context = ctx, .args = args };
            state.context.node = task_node;
            state.header.node = ctx.node;
            state.future = ctx.io().concurrent(State.run, .{state}) catch |err| {
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

        /// Sleeps until the wall clock reaches `deadline`.
        pub fn sleep_until(ctx: *const Self, deadline: Io.Timestamp) Io.Cancelable!void {
            const limit: Io.Timeout = .{ .deadline = .{ .raw = deadline, .clock = .real } };
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
            var select: Io.Select(Race) = .init(ctx.io(), &buffer);
            defer select.cancelDiscard();
            try select.concurrent(.value, function, args);
            try select.concurrent(.expired, sleep_for, .{ ctx.io(), duration });
            return switch (try select.await()) {
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

        const vtable: supervision.Header.VTable = .{ .finish = finish, .destroy = destroy };

        fn run(state: *State) T {
            const tree = &state.context.runtime.tree;
            const result = @call(.auto, function, .{state.context} ++ state.args);
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
