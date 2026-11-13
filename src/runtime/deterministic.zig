//! A deterministic runtime that randomly selects tasks to run based on a seed
//! (commonware `runtime/src/deterministic.rs`).
//!
//! Tasks are stackful fibers on one OS thread. Each iteration of the event loop drains the
//! ready tasks, shuffles them with the seeded RNG (rand 0.10's shuffle over commonware's
//! `StdRng`), and runs each until it blocks. Then simulated time advances by one `cycle`; when
//! nothing is ready it jumps straight to the next timer. A run with the same seed and the same
//! code replays exactly, and the `Auditor` hashes every scheduling decision so two runs can be
//! compared.
//!
//! The executor implements `std.Io` (`Runner.io`): async/concurrent tasks, groups, futexes,
//! sleep, clocks, and randomness, with file and network operations failing. Every `std.Io`
//! primitive built on those (Mutex, Condition, Event, Queue, Select) is therefore
//! deterministic too, and library code written against `std.Io` runs unmodified.
//!
//! Differences from commonware, by necessity:
//! - Zig has no unwinding, so a task cannot be dropped mid-await. Aborting a task is a
//!   `std.Io` cancelation request: its next cancelation point returns `error.Canceled`. When
//!   the root task finishes, every other task is canceled and drained the same way; tasks
//!   still blocked after that (uncancelable waits) are discarded without running their defers.
//! - Panics abort the process (no `catch_panics`); a stall or timeout is returned as
//!   `error.Stalled` / `error.Timeout` from `Runner.start` instead of a panic.
//! - The auditor hashes the same kinds of events with the same hasher, but fibers block at
//!   different points than polled futures, so its digests are not comparable with Rust's.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const utils = @import("utils");
const cryptography = @import("cryptography");

const fiber = @import("fiber.zig");
const rng_helpers = @import("rng.zig");

const Rng = utils.rng.TestRng;

/// Configuration for the deterministic runtime.
pub const Config = struct {
    /// Seed of the runtime RNG (commonware's default is 42).
    seed: u64 = 42,
    /// Simulated time added after every iteration of the event loop.
    cycle_ns: u64 = std.time.ns_per_ms,
    /// Simulated time the runtime starts at, in nanoseconds since the Unix epoch.
    start_time_ns: u64 = 0,
    /// If the runtime is still executing this long after `start_time_ns`, `start` returns
    /// `error.Timeout`.
    timeout_ns: ?u64 = null,
    /// Upper bound on live tasks, including the root.
    max_tasks: u32 = 4096,
    /// Bytes of stack mapped for each task (only touched pages are backed by memory).
    stack_size_bytes: usize = 8 * 1024 * 1024,

    pub fn validate(config: Config) void {
        assert(config.cycle_ns > 0 or config.timeout_ns == null);
        assert(config.max_tasks >= 1);
        assert(config.stack_size_bytes >= 64 * 1024);
        if (config.timeout_ns) |timeout_ns| {
            assert(config.start_time_ns +| timeout_ns > config.start_time_ns);
        }
    }
};

pub const Error = error{
    /// No task can make progress and no timer is pending.
    Stalled,
    /// Simulated time reached `start_time_ns + timeout_ns`.
    Timeout,
    OutOfMemory,
};

/// Hashes an unambiguous sequence of length-prefixed fields (commonware `AuditHasher`).
pub const AuditHasher = struct {
    crc: cryptography.Crc32 = cryptography.Crc32.init(),

    pub fn update(hasher: *AuditHasher, value: []const u8) void {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, value.len, .big);
        hasher.crc.update(&length);
        hasher.crc.update(value);
    }

    pub fn update_int(hasher: *AuditHasher, comptime T: type, value: T) void {
        var bytes: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &bytes, value, .big);
        hasher.update(&bytes);
    }

    pub fn finalize(hasher: *AuditHasher) [4]u8 {
        return hasher.crc.finalize().bytes;
    }
};

/// Tracks the state of the runtime for determinism auditing (commonware `Auditor`).
pub const Auditor = struct {
    digest: [4]u8 = @splat(0),

    /// Record an event: the new digest hashes the old digest, `label`, and `fields`.
    pub fn event(auditor: *Auditor, label: []const u8, fields: []const []const u8) void {
        var hasher: AuditHasher = .{};
        hasher.update(&auditor.digest);
        hasher.update(label);
        for (fields) |field| hasher.update(field);
        auditor.digest = hasher.finalize();
    }

    /// Hex encoding of the current digest (commonware `Auditor::state`).
    pub fn state(auditor: *const Auditor) [8]u8 {
        return std.fmt.bytesToHex(auditor.digest, .lower);
    }
};

const max_closure_bytes = 1024;
const max_result_bytes = 1024;
const max_alignment: std.mem.Alignment = .@"16";

const Task = struct {
    id: u64,
    label: []const u8,
    context: Io.fiber.Context,
    stack: ?fiber.Stack,
    state: enum { ready, running, blocked, finished },
    kind: union(enum) {
        root,
        future: struct { awaiter: ?*Task },
        group: *Group,
    },
    start: union(enum) {
        with_result: *const fn (context: *const anyopaque, result: *anyopaque) void,
        without_result: *const fn (context: *const anyopaque) void,
    },
    closure: [max_closure_bytes]u8 align(max_alignment.toByteUnits()),
    result: [max_result_bytes]u8 align(max_alignment.toByteUnits()),

    /// A cancelation was requested; it fires at the next unblocked cancelation point.
    cancel_requested: bool,
    /// `error.Canceled` was returned and not re-armed with `recancel`.
    cancel_acknowledged: bool,
    cancel_protection: Io.CancelProtection,

    /// Whether the current block may be interrupted by a cancelation request.
    wait_cancelable: bool,
    /// Bumped on every wake, so timers armed for an earlier wait are ignored.
    wait_generation: u64,
    wake_reason: enum { notified, timeout, canceled },
    futex_address: usize,
    futex_node: std.DoublyLinkedList.Node,
    group_node: std.DoublyLinkedList.Node,
    all_node: std.DoublyLinkedList.Node,

    fn cancel_point_open(task: *const Task) bool {
        return task.cancel_protection == .unblocked and !task.cancel_acknowledged;
    }
};

const Group = struct {
    members: std.DoublyLinkedList = .{},
    count: u32 = 0,
    awaiter: ?*Task = null,
    /// In `Runner.groups`, so groups never awaited are freed when `start` returns.
    node: std.DoublyLinkedList.Node = .{},
};

const Alarm = struct {
    deadline_ns: u64,
    sequence: u64,
    task: *Task,
    generation: u64,

    fn order(_: void, a: Alarm, b: Alarm) std.math.Order {
        const by_time = std.math.order(a.deadline_ns, b.deadline_ns);
        return if (by_time != .eq) by_time else std.math.order(a.sequence, b.sequence);
    }
};

/// Implementation of the deterministic runtime. One `Runner` may `start` several root tasks in
/// sequence: simulated time, the RNG, and the auditor carry over, like recovering from
/// commonware's `Checkpoint`.
pub const Runner = struct {
    allocator: std.mem.Allocator,
    config: Config,
    rng: Rng,
    auditor: Auditor = .{},
    time_ns: u64,
    deadline_ns: ?u64,
    iterations: u64 = 0,
    next_task_id: u64 = 0,
    next_alarm_sequence: u64 = 0,

    scheduler_context: Io.fiber.Context = undefined,
    current: ?*Task = null,
    root_finished: bool = false,
    tasks: std.DoublyLinkedList = .{},
    task_count: u32 = 0,
    ready: std.ArrayList(*Task),
    batch: std.ArrayList(*Task),
    alarms: std.PriorityQueue(Alarm, void, Alarm.order) = .empty,
    futex_waiters: std.DoublyLinkedList = .{},
    groups: std.DoublyLinkedList = .{},
    stack_pool: std.ArrayList(fiber.Stack),

    pub fn init(allocator: std.mem.Allocator, config: Config) Error!Runner {
        config.validate();
        comptime assert(fiber.supported);
        var ready: std.ArrayList(*Task) = try .initCapacity(allocator, config.max_tasks);
        errdefer ready.deinit(allocator);
        var batch: std.ArrayList(*Task) = try .initCapacity(allocator, config.max_tasks);
        errdefer batch.deinit(allocator);
        const stack_pool: std.ArrayList(fiber.Stack) = try .initCapacity(allocator, 16);
        const deadline_ns = if (config.timeout_ns) |t| config.start_time_ns + t else null;
        return .{
            .allocator = allocator,
            .config = config,
            .rng = Rng.init(config.seed),
            .time_ns = config.start_time_ns,
            .deadline_ns = deadline_ns,
            .ready = ready,
            .batch = batch,
            .stack_pool = stack_pool,
        };
    }

    pub fn deinit(runner: *Runner) void {
        assert(runner.current == null);
        assert(runner.task_count == 0);
        for (runner.stack_pool.items) |stack| stack.unmap();
        runner.stack_pool.deinit(runner.allocator);
        runner.ready.deinit(runner.allocator);
        runner.batch.deinit(runner.allocator);
        runner.alarms.deinit(runner.allocator);
        runner.* = undefined;
    }

    /// The `std.Io` backed by this runtime: simulated clock, seeded randomness, and tasks.
    pub fn io(runner: *Runner) Io {
        return .{ .userdata = runner, .vtable = &vtable };
    }

    /// Simulated time, in nanoseconds since the Unix epoch.
    pub fn now_ns(runner: *const Runner) u64 {
        return runner.time_ns;
    }

    /// Run `function(args...)` as the root task until it returns, then cancel and drain every
    /// task it left behind. Returns the root's result.
    pub fn start(
        runner: *Runner,
        comptime function: anytype,
        args: std.meta.ArgsTuple(@TypeOf(function)),
    ) Error!@typeInfo(@TypeOf(function)).@"fn".return_type.? {
        const Result = @typeInfo(@TypeOf(function)).@"fn".return_type.?;
        const Args = @TypeOf(args);
        const Closure = struct {
            fn call(context: *const anyopaque, result: *anyopaque) void {
                const call_args: *const Args = @ptrCast(@alignCast(context));
                const result_ptr: *Result = @ptrCast(@alignCast(result));
                result_ptr.* = @call(.auto, function, call_args.*);
            }
        };
        assert(runner.current == null);
        assert(runner.task_count == 0);
        const root = try runner.spawn_task(
            std.mem.asBytes(&args),
            .of(Args),
            @sizeOf(Result),
            .of(Result),
            .{ .with_result = Closure.call },
            .root,
        );
        runner.root_finished = false;
        const outcome = runner.run_until_root();
        runner.shutdown();
        outcome catch |err| {
            runner.destroy_task(root);
            return err;
        };
        const result_ptr: *const Result = @ptrCast(@alignCast(&root.result));
        const result = result_ptr.*;
        runner.destroy_task(root);
        assert(runner.task_count == 0);
        return result;
    }

    fn spawn_task(
        runner: *Runner,
        closure: []const u8,
        closure_alignment: std.mem.Alignment,
        result_len: usize,
        result_alignment: std.mem.Alignment,
        start_fn: @FieldType(Task, "start"),
        kind: @FieldType(Task, "kind"),
    ) error{OutOfMemory}!*Task {
        assert(closure.len <= max_closure_bytes);
        assert(result_len <= max_result_bytes);
        assert(closure_alignment.compare(.lte, max_alignment));
        assert(result_alignment.compare(.lte, max_alignment));
        if (runner.task_count >= runner.config.max_tasks) return error.OutOfMemory;
        const stack = try runner.acquire_stack();
        errdefer runner.release_stack(stack);
        const task = try runner.allocator.create(Task);
        task.* = .{
            .id = runner.next_task_id,
            .label = "",
            .context = undefined,
            .stack = stack,
            .state = .ready,
            .kind = kind,
            .start = start_fn,
            .closure = undefined,
            .result = undefined,
            .cancel_requested = false,
            .cancel_acknowledged = false,
            .cancel_protection = .unblocked,
            .wait_cancelable = false,
            .wait_generation = 0,
            .wake_reason = .notified,
            .futex_address = 0,
            .futex_node = .{},
            .group_node = .{},
            .all_node = .{},
        };
        @memcpy(task.closure[0..closure.len], closure);
        task.context = fiber.prepare(stack, task_entry, task);
        runner.next_task_id += 1;
        runner.task_count += 1;
        runner.tasks.append(&task.all_node);
        runner.ready.appendAssumeCapacity(task);
        return task;
    }

    fn destroy_task(runner: *Runner, task: *Task) void {
        assert(task.state == .finished or runner.current == null);
        assert(runner.task_count > 0);
        if (task.stack) |stack| runner.release_stack(stack);
        runner.tasks.remove(&task.all_node);
        runner.task_count -= 1;
        runner.allocator.destroy(task);
    }

    fn acquire_stack(runner: *Runner) error{OutOfMemory}!fiber.Stack {
        if (runner.stack_pool.pop()) |stack| return stack;
        return fiber.Stack.map(runner.config.stack_size_bytes);
    }

    fn release_stack(runner: *Runner, stack: fiber.Stack) void {
        runner.stack_pool.append(runner.allocator, stack) catch stack.unmap();
    }

    fn task_entry(argument: *anyopaque) callconv(.c) noreturn {
        const task: *Task = @ptrCast(@alignCast(argument));
        assert(task.state == .running);
        switch (task.start) {
            .with_result => |start_fn| start_fn(&task.closure, &task.result),
            .without_result => |start_fn| start_fn(&task.closure),
        }
        const runner = runner_of(task);
        runner.finish(task);
        fiber.switch_to(&task.context, &runner.scheduler_context);
        unreachable; // A finished task is never resumed.
    }

    fn runner_of(task: *Task) *Runner {
        _ = task;
        return active_runner.?;
    }

    /// The runner whose event loop is on this thread's stack (fibers reach it here).
    threadlocal var active_runner: ?*Runner = null;

    fn finish(runner: *Runner, task: *Task) void {
        assert(runner.current == task);
        task.state = .finished;
        switch (task.kind) {
            .root => runner.root_finished = true,
            .future => |future| if (future.awaiter) |awaiter| runner.wake(awaiter, .notified),
            .group => |group| {
                group.members.remove(&task.group_node);
                group.count -= 1;
                if (group.count == 0) {
                    if (group.awaiter) |awaiter| runner.wake(awaiter, .notified);
                }
            },
        }
    }

    /// Switch from the scheduler to `task` until it blocks or finishes.
    fn resume_task(runner: *Runner, task: *Task) void {
        assert(runner.current == null);
        assert(task.state == .ready);
        task.state = .running;
        runner.current = task;
        fiber.switch_to(&runner.scheduler_context, &task.context);
        assert(runner.current == task);
        runner.current = null;
        assert(task.state != .running);
        if (task.state != .finished) return;
        // Off the task's stack now, so it can be reused.
        if (task.stack) |stack| runner.release_stack(stack);
        task.stack = null;
        // Group members are owned by nobody once finished; futures wait for their awaiter
        // and the root for `start`.
        if (task.kind == .group) runner.destroy_task(task);
    }

    /// Block the current task until `wake`. Returns why it woke.
    fn block(runner: *Runner, cancelable: bool) @FieldType(Task, "wake_reason") {
        const task = runner.current.?;
        assert(task.state == .running);
        task.state = .blocked;
        task.wait_cancelable = cancelable;
        fiber.switch_to(&task.context, &runner.scheduler_context);
        assert(runner.current == task);
        assert(task.state == .running);
        return task.wake_reason;
    }

    fn wake(runner: *Runner, task: *Task, reason: @FieldType(Task, "wake_reason")) void {
        assert(task.state == .blocked);
        if (task.futex_address != 0) {
            runner.futex_waiters.remove(&task.futex_node);
            task.futex_address = 0;
        }
        task.state = .ready;
        task.wake_reason = reason;
        task.wait_generation += 1;
        runner.ready.appendAssumeCapacity(task);
    }

    fn request_cancel(runner: *Runner, task: *Task) void {
        task.cancel_requested = true;
        if (task.state == .blocked and task.wait_cancelable and task.cancel_point_open()) {
            runner.wake(task, .canceled);
        }
    }

    /// A cancelation point for the current task.
    fn check_cancel(runner: *Runner) Io.Cancelable!void {
        const task = runner.current.?;
        if (task.cancel_requested and task.cancel_point_open()) {
            task.cancel_acknowledged = true;
            return error.Canceled;
        }
    }

    fn arm_alarm(runner: *Runner, task: *Task, deadline_ns: u64) void {
        const alarm: Alarm = .{
            .deadline_ns = deadline_ns,
            .sequence = runner.next_alarm_sequence,
            .task = task,
            .generation = task.wait_generation,
        };
        runner.next_alarm_sequence += 1;
        runner.alarms.push(runner.allocator, alarm) catch @panic("deterministic: out of memory");
    }

    fn run_until_root(runner: *Runner) Error!void {
        const previous = active_runner;
        active_runner = runner;
        defer active_runner = previous;
        while (true) {
            try runner.check_deadline();
            runner.run_batch(true);
            if (runner.root_finished) return;
            runner.time_ns = std.math.add(u64, runner.time_ns, runner.config.cycle_ns) catch
                @panic("deterministic: executor time overflowed");
            try runner.wake_until_progress();
            runner.iterations += 1;
        }
    }

    /// Run every task that is ready now, in seeded random order.
    fn run_batch(runner: *Runner, stop_at_root: bool) void {
        assert(runner.batch.items.len == 0);
        std.mem.swap(std.ArrayList(*Task), &runner.ready, &runner.batch);
        defer runner.batch.clearRetainingCapacity();
        if (runner.batch.items.len > 1) {
            rng_helpers.shuffle(&runner.rng, *Task, runner.batch.items);
        }
        for (runner.batch.items) |task| {
            assert(task.state == .ready);
            var id: [16]u8 = undefined;
            std.mem.writeInt(u128, &id, task.id, .big);
            runner.auditor.event("process_task", &.{ &id, task.label });
            runner.resume_task(task);
            if (stop_at_root and runner.root_finished) {
                // Tasks not reached this iteration stay ready for the drain.
                const index = std.mem.indexOfScalar(*Task, runner.batch.items, task).?;
                for (runner.batch.items[index + 1 ..]) |rest| {
                    runner.ready.appendAssumeCapacity(rest);
                }
                return;
            }
        }
    }

    fn check_deadline(runner: *const Runner) Error!void {
        if (runner.deadline_ns) |deadline_ns| {
            if (runner.time_ns >= deadline_ns) return error.Timeout;
        }
    }

    /// Fire timers until some task is ready, jumping over idle time.
    fn wake_until_progress(runner: *Runner) Error!void {
        while (true) {
            if (runner.ready.items.len == 0) {
                if (runner.alarms.peek()) |next| {
                    if (next.deadline_ns > runner.time_ns) runner.time_ns = next.deadline_ns;
                }
            }
            try runner.check_deadline();
            runner.fire_alarms();
            if (runner.ready.items.len != 0) return;
            if (runner.alarms.items.len == 0) return error.Stalled;
        }
    }

    fn fire_alarms(runner: *Runner) void {
        while (runner.alarms.peek()) |next| {
            if (next.deadline_ns > runner.time_ns) return;
            const alarm = runner.alarms.pop().?;
            const task = alarm.task;
            // A stale alarm (its wait already ended) wakes nobody, as in commonware.
            if (task.state == .blocked and task.wait_generation == alarm.generation) {
                runner.wake(task, .timeout);
            }
        }
    }

    /// After the root returns (or the run fails): cancel every other task and run what is
    /// ready, without advancing time, until nothing more can run. Then discard the rest.
    fn shutdown(runner: *Runner) void {
        const previous = active_runner;
        active_runner = runner;
        defer active_runner = previous;
        var rounds: u32 = 0;
        while (rounds < runner.config.max_tasks * 4) : (rounds += 1) {
            var node = runner.tasks.first;
            while (node) |n| : (node = n.next) {
                const task: *Task = @alignCast(@fieldParentPtr("all_node", n));
                if (task.state != .finished) runner.request_cancel(task);
            }
            if (runner.ready.items.len == 0) break;
            runner.run_batch(false);
        }
        runner.discard_remaining();
    }

    fn discard_remaining(runner: *Runner) void {
        runner.ready.clearRetainingCapacity();
        runner.alarms.items.len = 0;
        runner.futex_waiters = .{};
        var node = runner.tasks.first;
        while (node) |n| {
            node = n.next;
            const task: *Task = @alignCast(@fieldParentPtr("all_node", n));
            if (task.kind != .root) runner.destroy_task(task);
        }
        // Groups left behind can no longer be awaited; free them here.
        while (runner.groups.popFirst()) |group_node| {
            const group: *Group = @alignCast(@fieldParentPtr("node", group_node));
            runner.allocator.destroy(group);
        }
    }

    fn create_group(runner: *Runner) error{OutOfMemory}!*Group {
        const group = try runner.allocator.create(Group);
        group.* = .{};
        runner.groups.append(&group.node);
        return group;
    }

    fn destroy_group(runner: *Runner, group: *Group) void {
        assert(group.count == 0);
        assert(group.members.first == null);
        runner.groups.remove(&group.node);
        runner.allocator.destroy(group);
    }

    // std.Io implementation.

    const vtable: Io.VTable = blk: {
        var table = Io.failing.vtable.*;
        table.async = io_async;
        table.concurrent = io_concurrent;
        table.await = io_await;
        table.cancel = io_cancel;
        table.groupAsync = io_group_async;
        table.groupConcurrent = io_group_concurrent;
        table.groupAwait = io_group_await;
        table.groupCancel = io_group_cancel;
        table.recancel = io_recancel;
        table.swapCancelProtection = io_swap_cancel_protection;
        table.checkCancel = io_check_cancel;
        table.futexWait = io_futex_wait;
        table.futexWaitUncancelable = io_futex_wait_uncancelable;
        table.futexWake = io_futex_wake;
        table.now = io_now;
        table.clockResolution = io_clock_resolution;
        table.sleep = io_sleep;
        table.random = io_random;
        table.randomSecure = io_random_secure;
        break :blk table;
    };

    fn from(userdata: ?*anyopaque) *Runner {
        return @ptrCast(@alignCast(userdata.?));
    }

    fn io_async(
        userdata: ?*anyopaque,
        result: []u8,
        result_alignment: std.mem.Alignment,
        context: []const u8,
        context_alignment: std.mem.Alignment,
        start_fn: *const fn (context: *const anyopaque, result: *anyopaque) void,
    ) ?*Io.AnyFuture {
        return io_concurrent(
            userdata,
            result.len,
            result_alignment,
            context,
            context_alignment,
            start_fn,
        ) catch {
            start_fn(context.ptr, result.ptr);
            return null;
        };
    }

    fn io_concurrent(
        userdata: ?*anyopaque,
        result_len: usize,
        result_alignment: std.mem.Alignment,
        context: []const u8,
        context_alignment: std.mem.Alignment,
        start_fn: *const fn (context: *const anyopaque, result: *anyopaque) void,
    ) Io.ConcurrentError!*Io.AnyFuture {
        const runner = from(userdata);
        const task = runner.spawn_task(
            context,
            context_alignment,
            result_len,
            result_alignment,
            .{ .with_result = start_fn },
            .{ .future = .{ .awaiter = null } },
        ) catch return error.ConcurrencyUnavailable;
        return @ptrCast(task);
    }

    fn io_await(
        userdata: ?*anyopaque,
        any_future: *Io.AnyFuture,
        result: []u8,
        result_alignment: std.mem.Alignment,
    ) void {
        _ = result_alignment;
        const runner = from(userdata);
        const task: *Task = @ptrCast(@alignCast(any_future));
        assert(task.kind == .future);
        if (task.state != .finished) {
            assert(task.kind.future.awaiter == null);
            task.kind.future.awaiter = runner.current.?;
            _ = runner.block(false);
            assert(task.state == .finished);
        }
        @memcpy(result, task.result[0..result.len]);
        runner.destroy_task(task);
    }

    fn io_cancel(
        userdata: ?*anyopaque,
        any_future: *Io.AnyFuture,
        result: []u8,
        result_alignment: std.mem.Alignment,
    ) void {
        const runner = from(userdata);
        const task: *Task = @ptrCast(@alignCast(any_future));
        if (task.state != .finished) runner.request_cancel(task);
        io_await(userdata, any_future, result, result_alignment);
    }

    fn io_group_async(
        userdata: ?*anyopaque,
        group: *Io.Group,
        context: []const u8,
        context_alignment: std.mem.Alignment,
        start_fn: *const fn (context: *const anyopaque) void,
    ) void {
        io_group_concurrent(userdata, group, context, context_alignment, start_fn) catch {
            start_fn(context.ptr);
        };
    }

    fn io_group_concurrent(
        userdata: ?*anyopaque,
        io_group: *Io.Group,
        context: []const u8,
        context_alignment: std.mem.Alignment,
        start_fn: *const fn (context: *const anyopaque) void,
    ) Io.ConcurrentError!void {
        const runner = from(userdata);
        const group: *Group = if (io_group.token.raw) |token|
            @ptrCast(@alignCast(token))
        else
            runner.create_group() catch return error.ConcurrencyUnavailable;
        errdefer if (group.count == 0) runner.destroy_group(group);
        const task = runner.spawn_task(
            context,
            context_alignment,
            0,
            .@"1",
            .{ .without_result = start_fn },
            .{ .group = group },
        ) catch return error.ConcurrencyUnavailable;
        group.members.append(&task.group_node);
        group.count += 1;
        io_group.token.raw = group;
    }

    fn io_group_await(
        userdata: ?*anyopaque,
        io_group: *Io.Group,
        token: *anyopaque,
    ) Io.Cancelable!void {
        const runner = from(userdata);
        const group: *Group = @ptrCast(@alignCast(token));
        var canceled = false;
        if (group.count > 0) {
            assert(group.awaiter == null);
            group.awaiter = runner.current.?;
            if (runner.check_cancel()) |_| {
                if (runner.block(true) == .canceled) {
                    runner.current.?.cancel_acknowledged = true;
                    canceled = true;
                }
            } else |_| canceled = true;
            if (canceled) runner.wait_group_canceled(group);
        }
        runner.destroy_group(group);
        io_group.token.raw = null;
        if (canceled) return error.Canceled;
    }

    fn io_group_cancel(userdata: ?*anyopaque, io_group: *Io.Group, token: *anyopaque) void {
        const runner = from(userdata);
        const group: *Group = @ptrCast(@alignCast(token));
        if (group.count > 0) {
            assert(group.awaiter == null);
            group.awaiter = runner.current.?;
            runner.wait_group_canceled(group);
        }
        runner.destroy_group(group);
        io_group.token.raw = null;
    }

    /// Cancel every member of `group` and wait, uncancelably, for all of them to finish.
    fn wait_group_canceled(runner: *Runner, group: *Group) void {
        assert(group.awaiter == runner.current.?);
        var node = group.members.first;
        while (node) |n| : (node = n.next) {
            runner.request_cancel(@alignCast(@fieldParentPtr("group_node", n)));
        }
        while (group.count > 0) _ = runner.block(false);
        group.awaiter = null;
    }

    fn io_recancel(userdata: ?*anyopaque) void {
        const task = from(userdata).current.?;
        assert(task.cancel_acknowledged);
        task.cancel_acknowledged = false;
    }

    fn io_swap_cancel_protection(
        userdata: ?*anyopaque,
        new: Io.CancelProtection,
    ) Io.CancelProtection {
        const task = from(userdata).current.?;
        defer task.cancel_protection = new;
        return task.cancel_protection;
    }

    fn io_check_cancel(userdata: ?*anyopaque) Io.Cancelable!void {
        return from(userdata).check_cancel();
    }

    fn io_futex_wait(
        userdata: ?*anyopaque,
        ptr: *const u32,
        expected: u32,
        timeout: Io.Timeout,
    ) Io.Cancelable!void {
        const runner = from(userdata);
        try runner.check_cancel();
        if (@atomicLoad(u32, ptr, .acquire) != expected) return;
        const task = runner.current.?;
        task.futex_address = @intFromPtr(ptr);
        runner.futex_waiters.append(&task.futex_node);
        if (runner.deadline_of(timeout)) |deadline_ns| runner.arm_alarm(task, deadline_ns);
        if (runner.block(true) == .canceled) {
            task.cancel_acknowledged = true;
            return error.Canceled;
        }
    }

    fn io_futex_wait_uncancelable(userdata: ?*anyopaque, ptr: *const u32, expected: u32) void {
        const runner = from(userdata);
        if (@atomicLoad(u32, ptr, .acquire) != expected) return;
        const task = runner.current.?;
        task.futex_address = @intFromPtr(ptr);
        runner.futex_waiters.append(&task.futex_node);
        const reason = runner.block(false);
        assert(reason == .notified);
    }

    fn io_futex_wake(userdata: ?*anyopaque, ptr: *const u32, max_waiters: u32) void {
        const runner = from(userdata);
        var woken: u32 = 0;
        var node = runner.futex_waiters.first;
        while (node) |n| {
            if (woken == max_waiters) break;
            node = n.next;
            const task: *Task = @alignCast(@fieldParentPtr("futex_node", n));
            if (task.futex_address != @intFromPtr(ptr)) continue;
            runner.wake(task, .notified);
            woken += 1;
        }
        assert(woken <= max_waiters);
    }

    /// Absolute simulated deadline of `timeout`, or null for none.
    fn deadline_of(runner: *const Runner, timeout: Io.Timeout) ?u64 {
        return switch (timeout) {
            .none => null,
            .duration => |duration| runner.time_ns +| clamp_ns(duration.raw.nanoseconds),
            .deadline => |deadline| clamp_ns(deadline.raw.nanoseconds),
        };
    }

    fn clamp_ns(nanoseconds: i96) u64 {
        if (nanoseconds <= 0) return 0;
        return std.math.cast(u64, nanoseconds) orelse std.math.maxInt(u64);
    }

    fn io_sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Cancelable!void {
        const runner = from(userdata);
        try runner.check_cancel();
        const deadline_ns = runner.deadline_of(timeout) orelse {
            // Sleeping forever: only a cancelation ends it.
            _ = runner.block(true);
            runner.current.?.cancel_acknowledged = true;
            return error.Canceled;
        };
        if (deadline_ns <= runner.time_ns) return;
        runner.arm_alarm(runner.current.?, deadline_ns);
        if (runner.block(true) == .canceled) {
            runner.current.?.cancel_acknowledged = true;
            return error.Canceled;
        }
    }

    fn io_now(userdata: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
        _ = clock;
        return .fromNanoseconds(from(userdata).time_ns);
    }

    fn io_clock_resolution(
        userdata: ?*anyopaque,
        clock: Io.Clock,
    ) Io.Clock.ResolutionError!Io.Duration {
        _ = userdata;
        _ = clock;
        return .fromNanoseconds(1);
    }

    fn io_random(userdata: ?*anyopaque, buffer: []u8) void {
        from(userdata).rng.fill_bytes(buffer);
    }

    fn io_random_secure(userdata: ?*anyopaque, buffer: []u8) Io.RandomSecureError!void {
        from(userdata).rng.fill_bytes(buffer);
    }
};

const testing = std.testing;

fn test_runner(config: Config) !Runner {
    return Runner.init(testing.allocator, config);
}

test "root result is returned" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn run(value: u32) u32 {
            return value * 2;
        }
    };
    try testing.expectEqual(@as(u32, 42), try runner.start(Root.run, .{21}));
}

test "error results pass through (test_error_future)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn run() error{Oops}!void {
            return error.Oops;
        }
    };
    try testing.expectError(error.Oops, try runner.start(Root.run, .{}));
}

test "sleep advances simulated time (test_clock_sleep)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn run(io: Io) !i96 {
            const start_ns = Io.Clock.awake.now(io).nanoseconds;
            try io.sleep(.fromMilliseconds(10), .awake);
            return Io.Clock.awake.now(io).nanoseconds - start_ns;
        }
    };
    const elapsed = try (try runner.start(Root.run, .{runner.io()}));
    try testing.expect(elapsed >= 10 * std.time.ns_per_ms);
}

test "idle time is skipped, not cycled through (test_simulated_skip)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn run(io: Io) !void {
            try io.sleep(.fromSeconds(3600), .awake);
        }
    };
    try (try runner.start(Root.run, .{runner.io()}));
    try testing.expect(runner.now_ns() >= 3600 * std.time.ns_per_s);
    try testing.expect(runner.iterations < 5);
}

test "timeout fires (test_timeout)" {
    var runner = try test_runner(.{ .timeout_ns = 10 * std.time.ns_per_s });
    defer runner.deinit();
    const Root = struct {
        fn run(io: Io) !void {
            while (true) try io.sleep(.fromSeconds(1), .awake);
        }
    };
    try testing.expectError(error.Timeout, runner.start(Root.run, .{runner.io()}));
}

test "stall is detected (test_stall)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn run(io: Io) void {
            var event: Io.Event = .unset;
            event.waitUncancelable(io);
        }
    };
    try testing.expectError(error.Stalled, runner.start(Root.run, .{runner.io()}));
}

test "concurrent tasks, futures, and a queue" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn producer(io: Io, queue: *Io.Queue(u32), count: u32) !void {
            for (0..count) |i| {
                try queue.putOne(io, @intCast(i));
                try io.sleep(.fromMilliseconds(1), .awake);
            }
        }
        fn run(io: Io) !u64 {
            var buffer: [4]u32 = undefined;
            var queue: Io.Queue(u32) = .init(&buffer);
            var future = try io.concurrent(producer, .{ io, &queue, 100 });
            var sum: u64 = 0;
            for (0..100) |_| sum += try queue.getOne(io);
            try future.await(io);
            return sum;
        }
    };
    try testing.expectEqual(@as(u64, 4950), try (try runner.start(Root.run, .{runner.io()})));
}

test "cancel interrupts a sleeping task (test_spawn_abort)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn forever(io: Io) Io.Cancelable!void {
            while (true) try io.sleep(.fromSeconds(1), .awake);
        }
        fn run(io: Io) !void {
            var future = try io.concurrent(forever, .{io});
            try io.sleep(.fromSeconds(5), .awake);
            try testing.expectError(error.Canceled, future.cancel(io));
        }
    };
    try (try runner.start(Root.run, .{runner.io()}));
}

test "leftover tasks are canceled when the root finishes (test_root_finishes)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn spin(io: Io) Io.Cancelable!void {
            while (true) try io.sleep(.fromNanoseconds(0), .awake);
        }
        fn run(io: Io, group: *Io.Group) void {
            group.async(io, spin, .{io});
        }
    };
    var group: Io.Group = .init;
    runner.start(Root.run, .{ runner.io(), &group }) catch unreachable;
    try testing.expectEqual(@as(u32, 0), runner.task_count);
}

test "groups await all members and propagate cancelation" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn work(io: Io, total: *u32, delay_ms: i64) Io.Cancelable!void {
            try io.sleep(.fromMilliseconds(delay_ms), .awake);
            total.* += 1;
        }
        fn run(io: Io) !u32 {
            var total: u32 = 0;
            var group: Io.Group = .init;
            for (0..8) |i| group.async(io, work, .{ io, &total, @as(i64, @intCast(i)) * 10 });
            try group.await(io);
            var slow: Io.Group = .init;
            for (0..4) |_| slow.async(io, work, .{ io, &total, 1_000 });
            slow.cancel(io);
            return total;
        }
    };
    try testing.expectEqual(@as(u32, 8), try (try runner.start(Root.run, .{runner.io()})));
}

fn order_run(seed: u64) !struct { [8]u8, [16]u8 } {
    var runner = try test_runner(.{ .seed = seed });
    defer runner.deinit();
    const Root = struct {
        fn task(io: Io, order: *std.ArrayList(u8), index: u8) Io.Cancelable!void {
            try io.sleep(.fromNanoseconds(0), .awake);
            order.appendAssumeCapacity(index);
        }
        fn run(io: Io, order: *std.ArrayList(u8)) !void {
            var group: Io.Group = .init;
            for (0..16) |i| group.async(io, task, .{ io, order, @as(u8, @intCast(i)) });
            try group.await(io);
        }
    };
    var storage: [16]u8 = undefined;
    var order: std.ArrayList(u8) = .initBuffer(&storage);
    try (try runner.start(Root.run, .{ runner.io(), &order }));
    return .{ runner.auditor.state(), storage };
}

test "same seed, same order; different seed, different order (test_same_seed_same_order)" {
    const first = try order_run(1);
    const again = try order_run(1);
    const other = try order_run(2);
    try testing.expectEqualSlices(u8, &first[0], &again[0]);
    try testing.expectEqualSlices(u8, &first[1], &again[1]);
    try testing.expect(!std.mem.eql(u8, &first[0], &other[0]));
    try testing.expect(!std.mem.eql(u8, &first[1], &other[1]));
}

test "auditor separates events (test_auditor_separates_events)" {
    var a: Auditor = .{};
    a.event("ab", &.{"c"});
    var b: Auditor = .{};
    b.event("a", &.{"bc"});
    try testing.expect(!std.mem.eql(u8, &a.digest, &b.digest));
    var c: Auditor = .{};
    c.event("ab", &.{"c"});
    try testing.expectEqualSlices(u8, &a.digest, &c.digest);
}

test "state carries over between starts (test_recover_time_persists)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn run(io: Io) !void {
            try io.sleep(.fromSeconds(10), .awake);
        }
    };
    try (try runner.start(Root.run, .{runner.io()}));
    const after_first = runner.now_ns();
    const audit_first = runner.auditor.state();
    try (try runner.start(Root.run, .{runner.io()}));
    try testing.expect(runner.now_ns() >= after_first + 10 * std.time.ns_per_s);
    try testing.expect(!std.mem.eql(u8, &audit_first, &runner.auditor.state()));
}
