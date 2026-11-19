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
const build_options = @import("build_options");
const assert = std.debug.assert;
const Io = std.Io;
const utils = @import("utils");
const cryptography = @import("cryptography");

const fiber = @import("fiber.zig");
const storage_mod = @import("storage.zig");
const network_mod = @import("network.zig");
const context_mod = @import("context.zig");
const telemetry = @import("telemetry/mod.zig");
const resolver_mod = @import("resolver.zig");
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
    /// Capacity of the supervision tree: contexts alive at once.
    max_contexts: u32 = context_mod.default_max_contexts,
    /// Storage fault injection (commonware `with_storage_fault_config`); none by default.
    storage_faults: storage_mod.faulty.Config = .{},
    /// Receives the events of `Context.tracer` (tracing's installed subscriber); none drops
    /// them unformatted.
    subscriber: ?telemetry.traces.Subscriber = null,

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

    /// Adds `chunks` as one length-prefixed field: their boundaries are not hashed
    /// (commonware `AuditHasher::update_bufs`).
    pub fn update_chunks(hasher: *AuditHasher, chunks: []const []const u8) void {
        var total: u64 = 0;
        for (chunks) |chunk| total += chunk.len;
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, total, .big);
        hasher.crc.update(&length);
        for (chunks) |chunk| hasher.crc.update(chunk);
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

    /// Like `event`, with `chunks` hashed as one field between `before` and `after`.
    pub fn event_chunked(
        auditor: *Auditor,
        label: []const u8,
        before: []const []const u8,
        chunks: []const []const u8,
        after: []const []const u8,
    ) void {
        var hasher: AuditHasher = .{};
        hasher.update(&auditor.digest);
        hasher.update(label);
        for (before) |field| hasher.update(field);
        hasher.update_chunks(chunks);
        for (after) |field| hasher.update(field);
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

const TaskLabel = telemetry.metrics.task.Label;
const PollCounter = telemetry.metrics.raw.Counter;
const PollFamily = telemetry.metrics.raw.Family(TaskLabel, PollCounter);
const label_size_max = telemetry.metrics.scope.prefix_size_max;

const Task = struct {
    id: u64,
    /// The task's name (commonware `Label::name`): the spawning `Context`'s label, the
    /// spawning task's name for a plain `io.concurrent` fiber, empty for the root. Copied, so
    /// it outlives whatever named it.
    label_buffer: [label_size_max]u8,
    label_len: u8,
    label_kind: telemetry.metrics.task.Kind,
    /// This task's `runtime_task_polls` entry.
    polls: *PollCounter,
    context: fiber.Context,
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
    /// Alarms in `Runner.alarms` that point at this task, stale ones included.
    alarms_queued: u32,
    wake_reason: enum { notified, timeout, canceled },
    futex_address: usize,
    futex_node: std.DoublyLinkedList.Node,
    group_node: std.DoublyLinkedList.Node,
    all_node: std.DoublyLinkedList.Node,

    fn label(task: *const Task) []const u8 {
        return task.label_buffer[0..task.label_len];
    }

    fn task_label(task: *const Task) TaskLabel {
        return .{ .name = task.label(), .kind = task.label_kind, .execution = .shared };
    }

    /// With `-Dcancel-audit`, panics when the task reaches a cancelation point while holding a
    /// cancel it already acknowledged and never re-armed: it caught `error.Canceled` without
    /// propagating it or calling `io.recancel()`, so this point cannot deliver the cancel and a
    /// cancelable wait here is never woken by it. Deliberate work after a cancel opts out by
    /// blocking cancelation (`io.swapCancelProtection(.blocked)`).
    fn audit_cancel(task: *const Task) void {
        if (!build_options.cancel_audit) return;
        if (!task.cancel_requested or !task.cancel_acknowledged) return;
        if (task.cancel_protection != .unblocked) return;
        std.debug.panic(
            "deterministic: task '{s}' caught error.Canceled without propagating it or " ++
                "calling io.recancel(), then reached another cancelation point",
            .{task.label()},
        );
    }

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

/// The deterministic runtime's context (see `context.zig`).
pub const Context = context_mod.Context(network_mod.deterministic.Network);

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

    scheduler_context: fiber.Context = .{},
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
    /// In-memory storage; durable contents carry over between starts.
    memory_storage: storage_mod.memory.Storage,
    /// Fault injection over `memory_storage`, drawing from the runtime RNG; created on first
    /// use.
    faulty_storage: ?storage_mod.faulty.Storage(Rng) = null,
    /// Audits every storage operation, over `faulty_storage`; created on first use.
    audited_storage: ?storage_mod.audited.Storage = null,
    /// Counts storage operations in the `runtime` metrics, over `audited_storage`.
    metered_storage: ?storage_mod.metered.Storage = null,
    /// Counts `simulated_network`'s connections and bytes in the `runtime` metrics.
    network_metrics: ?network_mod.metered.Metrics = null,
    /// The simulated network, created on first use; it carries over between starts.
    simulated_network: ?network_mod.deterministic.Network = null,
    /// What every `Context` shares, created by the first `start_context`.
    context_runtime: ?context_mod.Runtime = null,
    /// The metrics registry; it carries over between starts. Release every handle before
    /// `deinit`.
    metrics_registry: telemetry.metrics.Registry,
    /// `runtime_iterations` (commonware's executor metric): scheduler cycles run. Registered
    /// by the first `start`, once the runner no longer moves (a handle points at its registry).
    iterations_counter: ?telemetry.metrics.Registered(telemetry.metrics.raw.Counter) = null,
    /// `runtime_task_polls`: fiber resumes per task label, registered with the counter above.
    task_polls: ?telemetry.metrics.Registered(PollFamily) = null,
    /// The name `Context.spawn` gave the fiber it is about to start (`label_next`).
    next_label: ?[]const u8 = null,
    /// DNS records (`Context.resolver_register`); they carry over between starts.
    dns: resolver_mod.Dns,

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
            .memory_storage = .init(allocator),
            .metrics_registry = .init(allocator),
            .dns = .init(allocator),
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
        if (runner.metered_storage) |*metered| metered.deinit();
        if (runner.audited_storage) |*audited| audited.deinit();
        if (runner.faulty_storage) |*faults| faults.deinit();
        runner.memory_storage.deinit();
        if (runner.context_runtime) |*runtime| runtime.deinit();
        if (runner.simulated_network) |*net| net.deinit();
        if (runner.network_metrics) |*counts| counts.deinit();
        if (runner.iterations_counter) |*counter| counter.deinit();
        if (runner.task_polls) |*polls| polls.deinit();
        runner.dns.deinit();
        runner.metrics_registry.deinit();
        runner.* = undefined;
    }

    /// The `std.Io` backed by this runtime: simulated clock, seeded randomness, and tasks.
    pub fn io(runner: *Runner) Io {
        return .{ .userdata = runner, .vtable = &vtable };
    }

    /// The runtime's in-memory storage, with `Config.storage_faults` injected, every operation
    /// audited, and counted in the `runtime_storage_*` and `runtime_open_blobs` metrics
    /// (commonware's `Metered(Audited(Faulty(Memory)))`). The runner must not move once it is
    /// used. Panics if registering the metrics runs out of memory.
    pub fn storage(runner: *Runner) storage_mod.Storage {
        if (runner.metered_storage == null) {
            assert(runner.audited_storage == null);
            const inner = runner.storage_faulty().storage();
            runner.audited_storage = .init(runner.allocator, inner, &runner.auditor);
            const audited = runner.audited_storage.?.storage();
            const scope = runner.metrics().sub_registry(telemetry.metrics.metrics_prefix);
            runner.metered_storage = storage_mod.metered.Storage.init(
                runner.allocator,
                audited,
                &scope,
            ) catch @panic("deterministic: registering storage metrics: out of memory");
        }
        return runner.metered_storage.?.storage();
    }

    /// The live fault configuration (commonware `storage_fault_config`): changes take effect
    /// at the next storage operation and carry over between starts.
    pub fn storage_fault_config(runner: *Runner) *storage_mod.faulty.Config {
        return &runner.storage_faulty().config;
    }

    fn storage_faulty(runner: *Runner) *storage_mod.faulty.Storage(Rng) {
        if (runner.faulty_storage == null) {
            const faults = runner.config.storage_faults;
            const memory = &runner.memory_storage;
            runner.faulty_storage = .init(runner.allocator, memory, &runner.rng, faults);
        }
        assert(runner.faulty_storage.?.inner == &runner.memory_storage);
        return &runner.faulty_storage.?;
    }

    /// Crash storage as a run ends (commonware `Runner::run`): unsynced writes and resizes
    /// survive as the fault configuration selected, only durable contents remain, and the
    /// run's handles can no longer publish.
    fn crash_storage(runner: *Runner) void {
        if (runner.faulty_storage) |*faults| {
            faults.crash() catch @panic("deterministic: replaying storage crash failed");
        }
        runner.memory_storage.crash();
    }

    /// The runtime's deterministic network, audited and counted in the `runtime_*_connections`
    /// and `runtime_*_bandwidth` metrics (commonware's `Metered(Audited(Deterministic))`). The
    /// runner must not move once it is used. Panics if registering the metrics runs out of
    /// memory.
    pub fn network(runner: *Runner) *network_mod.deterministic.Network {
        if (runner.simulated_network == null) {
            assert(runner.network_metrics == null);
            const scope = runner.metrics().sub_registry(telemetry.metrics.metrics_prefix);
            runner.network_metrics = network_mod.metered.Metrics.init(&scope) catch
                @panic("deterministic: registering network metrics: out of memory");
            runner.simulated_network = .init(runner.allocator, runner.io());
            runner.simulated_network.?.auditor = &runner.auditor;
            runner.simulated_network.?.metrics = &runner.network_metrics.?;
        }
        return &runner.simulated_network.?;
    }

    /// The root metrics scope (commonware's `Metrics` on the root context): empty label, no
    /// attributes. The runner must not move once it is used.
    pub fn metrics(runner: *Runner) telemetry.metrics.Scope {
        return .init(&runner.metrics_registry);
    }

    /// CRC32C digest of all durable blob contents (commonware `storage_audit`).
    pub fn storage_audit(runner: *Runner) [4]u8 {
        return runner.memory_storage.audit();
    }

    /// Simulated time, in nanoseconds since the Unix epoch.
    pub fn now_ns(runner: *const Runner) u64 {
        return runner.time_ns;
    }

    /// Run `function(ctx, args...)` as the root task with a root `Context`: storage, the
    /// network, metrics, and supervision (commonware `Runner::start`). Tasks it spawns are
    /// aborted when it returns.
    pub fn start_context(
        runner: *Runner,
        comptime function: anytype,
        args: anytype,
    ) Error!context_mod.Return(function) {
        const Result = context_mod.Return(function);
        const Args = @TypeOf(args);
        if (runner.context_runtime == null) {
            const auditor = &runner.auditor;
            const max = runner.config.max_contexts;
            const scope = runner.metrics();
            runner.context_runtime = try .init(runner.allocator, runner.io(), max, auditor, scope);
            runner.context_runtime.?.label_hook = .{ .userdata = runner, .label_next = label_next };
            runner.context_runtime.?.subscriber = runner.config.subscriber;
            runner.context_runtime.?.strategy_inline = true;
        }
        const runtime = &runner.context_runtime.?;
        // The runner may have moved since the last start: point at it again.
        runner.dns.auditor = &runner.auditor;
        runtime.dns = &runner.dns;
        runtime.resolver = runner.dns.resolver();
        const ctx: Context = .root(runtime, runner.storage(), runner.network(), runner.metrics());
        const Root = struct {
            fn call(root_ctx: *const Context, root_args: *const Args) Result {
                return root_ctx.run_root(function, root_args.*);
            }
        };
        return runner.start(Root.call, .{ &ctx, &args });
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
        if (runner.iterations_counter == null) {
            const scope = runner.metrics().sub_registry("runtime");
            const help = "Total number of iterations";
            runner.iterations_counter = try scope.counter("iterations", help);
            const polls_help = "Total number of task polls";
            runner.task_polls = try scope.family(TaskLabel, PollCounter, "task_polls", polls_help);
        }
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
        // A restart recovers like commonware's checkpoint: only what survived the crash.
        runner.crash_storage();
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
        // A name set for this spawn applies to it alone, even if the spawn fails.
        const named = runner.next_label;
        runner.next_label = null;
        var label_buffer: [label_size_max]u8 = undefined;
        const task_label = runner.spawn_label(kind, named, &label_buffer);
        const polls = try runner.task_polls.?.metric().get_or_create(task_label);
        const stack = try runner.acquire_stack();
        errdefer runner.release_stack(stack);
        const task = try runner.allocator.create(Task);
        task.* = .{
            .id = runner.next_task_id,
            .label_buffer = label_buffer,
            .label_len = @intCast(task_label.name.len),
            .label_kind = task_label.kind,
            .polls = polls,
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
            .alarms_queued = 0,
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
        runner.drop_alarms(task);
        runner.tasks.remove(&task.all_node);
        runner.task_count -= 1;
        runner.allocator.destroy(task);
    }

    /// Removes the stale alarms of a task being destroyed: a wait that ended before its
    /// timeout leaves its alarm queued, and firing it later would read the freed task.
    fn drop_alarms(runner: *Runner, task: *Task) void {
        var index: usize = 0;
        while (task.alarms_queued > 0 and index < runner.alarms.items.len) {
            if (runner.alarms.items[index].task != task) {
                index += 1;
                continue;
            }
            assert(task.state == .finished or runner.current == null);
            _ = runner.alarms.popIndex(index);
            task.alarms_queued -= 1;
            // Removal reorders the heap, so scan again from the start.
            index = 0;
        }
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
        if (cancelable) task.audit_cancel();
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
        task.audit_cancel();
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
        task.alarms_queued += 1;
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
            runner.iterations_counter.?.metric().inc();
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
            runner.auditor.event("process_task", &.{ &id, task.label() });
            task.polls.inc();
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
            assert(task.alarms_queued > 0);
            task.alarms_queued -= 1;
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

    /// The label of a task about to be spawned, its name copied into `buffer`.
    fn spawn_label(
        runner: *const Runner,
        kind: @FieldType(Task, "kind"),
        named: ?[]const u8,
        buffer: *[label_size_max]u8,
    ) TaskLabel {
        if (kind == .root) {
            assert(named == null);
            return .root();
        }
        if (named) |name| {
            assert(name.len <= label_size_max);
            @memcpy(buffer[0..name.len], name);
            return .task(buffer[0..name.len], .shared);
        }
        // A plain fiber is part of the task that started it, as commonware polls a task's
        // inner futures within the task.
        const parent = runner.current orelse return .root();
        const name = parent.label();
        @memcpy(buffer[0..name.len], name);
        return .{ .name = buffer[0..name.len], .kind = parent.label_kind, .execution = .shared };
    }

    /// Names the next fiber this runner spawns (a `Context` task), or clears the name.
    fn label_next(userdata: *anyopaque, name: ?[]const u8) void {
        const runner: *Runner = @ptrCast(@alignCast(userdata));
        assert(name == null or runner.next_label == null);
        runner.next_label = name;
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

    /// Randomness from the runtime RNG, audited as commonware's `Context::fill_bytes`.
    fn io_random(userdata: ?*anyopaque, buffer: []u8) void {
        const runner = from(userdata);
        runner.auditor.event("rand", &.{"fill_bytes"});
        runner.rng.fill_bytes(buffer);
    }

    fn io_random_secure(userdata: ?*anyopaque, buffer: []u8) Io.RandomSecureError!void {
        io_random(userdata, buffer);
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
    // commonware reads the count from the exposition.
    const encoded = try runner.metrics().encode(testing.allocator);
    defer testing.allocator.free(encoded);
    const prefix = "runtime_iterations_total ";
    const at = std.mem.indexOf(u8, encoded, prefix).?;
    const rest = encoded[at + prefix.len ..];
    const value = try std.fmt.parseInt(u64, rest[0..std.mem.indexOfScalar(u8, rest, '\n').?], 10);
    try testing.expectEqual(runner.iterations, value);
    try testing.expect(value < 10);
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

test "recancel re-arms a caught cancel for the next wait" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        /// Catches the cancel, re-arms it, and returns what a later 1 s sleep reports.
        fn swallow(io: Io, started_ns: *i96) anyerror!void {
            io.sleep(.fromSeconds(60), .awake) catch |err| {
                assert(err == error.Canceled);
                io.recancel();
            };
            started_ns.* = Io.Clock.awake.now(io).nanoseconds;
            return io.sleep(.fromSeconds(1), .awake);
        }
        fn run(io: Io) !void {
            var started_ns: i96 = 0;
            var future = try io.concurrent(swallow, .{ io, &started_ns });
            try io.sleep(.fromSeconds(1), .awake);
            // The second sleep fails at once instead of sleeping its full second.
            try testing.expectError(error.Canceled, future.cancel(io));
            const elapsed_ns = Io.Clock.awake.now(io).nanoseconds - started_ns;
            try testing.expect(elapsed_ns < std.time.ns_per_s);
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

test "storage survives a restart with only synced contents (test_recover_storage)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn write(store: storage_mod.Storage) !void {
            const blob = (try store.open("partition", "blob")).blob;
            defer blob.close();
            try blob.write_at(0, "synced", .{});
            try blob.sync();
            try blob.write_at(6, " lost", .{});
        }
        fn read(store: storage_mod.Storage) !u64 {
            const opened = try store.open("partition", "blob");
            defer opened.blob.close();
            var buffer: [6]u8 = undefined;
            try opened.blob.read_at(0, &buffer);
            try testing.expectEqualSlices(u8, "synced", &buffer);
            return opened.len;
        }
    };
    try (try runner.start(Root.write, .{runner.storage()}));
    const audit = runner.storage_audit();
    try testing.expectEqual(@as(u64, 6), try (try runner.start(Root.read, .{runner.storage()})));
    try testing.expectEqualSlices(u8, &audit, &runner.storage_audit());
}

test "storage faults are injected and recovered from (test_storage_fault_injection_and_recovery)" {
    var runner = try test_runner(.{ .storage_faults = .{ .sync_rate = .one } });
    defer runner.deinit();
    const Root = struct {
        fn fail(store: storage_mod.Storage) !void {
            const blob = (try store.open("test_fault", "blob")).blob;
            defer blob.close();
            try blob.write_at(0, "data", .{});
            try testing.expectError(error.Io, blob.sync());
        }
        fn recover(store: storage_mod.Storage) !void {
            const opened = try store.open("test_fault", "blob");
            defer opened.blob.close();
            try testing.expectEqual(@as(u64, 0), opened.len); // Unsynced data is lost.
            try opened.blob.write_at(0, "recovered", .{});
            try opened.blob.sync();
            var buffer: [9]u8 = undefined;
            try opened.blob.read_at(0, &buffer);
            try testing.expectEqualStrings("recovered", &buffer);
        }
    };
    try (try runner.start(Root.fail, .{runner.storage()}));
    runner.storage_fault_config().* = .{};
    try (try runner.start(Root.recover, .{runner.storage()}));
}

test "storage fault config changes take effect at once (test_storage_fault_dynamic_config)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn body(owner: *Runner) !void {
            const blob = (try owner.storage().open("test_dynamic", "blob")).blob;
            defer blob.close();
            try blob.write_at(0, "initial", .{});
            try blob.sync();
            owner.storage_fault_config().sync_rate = .one;
            try blob.write_at(0, "updated", .{});
            try testing.expectError(error.Io, blob.sync());
            owner.storage_fault_config().sync_rate = .zero;
            try blob.sync();
        }
    };
    try (try runner.start(Root.body, .{&runner}));
}

test "a restart replays the unsynced writes the fault config retains" {
    const retain_all: storage_mod.faulty.WriteConfig =
        .{ .failure_rate = .zero, .retention_rate = .one, .mode = .prefix };
    var runner = try test_runner(.{ .storage_faults = .{ .write_rate = retain_all } });
    defer runner.deinit();
    const Root = struct {
        fn write(store: storage_mod.Storage) !void {
            const blob = (try store.open("partition", "blob")).blob;
            defer blob.close();
            try blob.write_at(0, "........", .{ .sync = true });
            try blob.write_at(0, "AB", .{});
        }
        fn read(store: storage_mod.Storage) ![8]u8 {
            const opened = try store.open("partition", "blob");
            defer opened.blob.close();
            var buffer: [8]u8 = undefined;
            try opened.blob.read_at(0, &buffer);
            return buffer;
        }
    };
    try (try runner.start(Root.write, .{runner.storage()}));
    const contents = try (try runner.start(Root.read, .{runner.storage()}));
    try testing.expectEqualStrings("AB......", &contents);
}

fn storage_fault_opens(seed: u64) ![20]bool {
    const faults: storage_mod.faulty.Config = .{ .open_rate = .literal(0.5) };
    var runner = try test_runner(.{ .seed = seed, .storage_faults = faults });
    defer runner.deinit();
    const Root = struct {
        fn body(store: storage_mod.Storage) ![20]bool {
            var results: [20]bool = undefined;
            for (&results, 0..) |*result, index| {
                var name_buffer: [8]u8 = undefined;
                const name = try std.fmt.bufPrint(&name_buffer, "blob{d}", .{index});
                const opened = store.open("test_determinism", name);
                result.* = if (opened) |ok| blk: {
                    ok.blob.close();
                    break :blk true;
                } else |_| false;
            }
            return results;
        }
    };
    return try runner.start(Root.body, .{runner.storage()});
}

test "storage faults replay with the seed (test_storage_fault_determinism)" {
    const first = try storage_fault_opens(12345);
    try testing.expectEqual(first, try storage_fault_opens(12345));
    try testing.expect(!std.mem.eql(bool, &first, &try storage_fault_opens(99999)));
}

fn storage_fault_tasks(seed: u64) ![5]u32 {
    const faults: storage_mod.faulty.Config = .{
        .open_rate = .literal(0.5),
        .write_rate = .{
            .failure_rate = .literal(0.3),
            .retention_rate = .zero,
            .mode = .prefix,
        },
        .sync_rate = .literal(0.2),
    };
    var runner = try test_runner(.{ .seed = seed, .storage_faults = faults });
    defer runner.deinit();
    const Root = struct {
        fn task(ctx: Context, task_index: usize) anyerror!u32 {
            var successes: u32 = 0;
            for (0..4) |blob_index| {
                var name_buffer: [32]u8 = undefined;
                const name = try std.fmt.bufPrint(
                    &name_buffer,
                    "task{d}_blob{d}",
                    .{ task_index, blob_index },
                );
                const opened = ctx.storage.open("partition", name) catch continue;
                defer opened.blob.close();
                successes += 1;
                if (opened.blob.write_at(0, "data", .{})) |_| successes += 1 else |_| {}
                if (opened.blob.sync()) |_| successes += 1 else |_| {}
            }
            return successes;
        }

        fn body(ctx: Context) ![5]u32 {
            var handles: [5]context_mod.Handle(anyerror!u32) = undefined;
            for (&handles, 0..) |*handle, index| {
                handle.* = try ctx.child("task").spawn(task, .{index});
            }
            var results: [5]u32 = undefined;
            for (handles, &results) |handle, *result| result.* = try (try handle.join());
            return results;
        }
    };
    return try runner.start_context(Root.body, .{});
}

test "storage faults and task order replay together (test_storage_fault_determinism_multi_task)" {
    const first = try storage_fault_tasks(42);
    try testing.expectEqual(first, try storage_fault_tasks(42));
    try testing.expect(!std.mem.eql(u32, &first, &try storage_fault_tasks(99999)));
}

test "reading the auditor state keeps its history (test_auditor_state_preserves_history)" {
    var observed: Auditor = .{};
    var uninterrupted: Auditor = .{};
    try testing.expectEqualStrings("00000000", &observed.state());
    observed.event("a", &.{"x"});
    const before = observed.state();
    try testing.expectEqual(before, observed.state());
    observed.event("b", &.{"y"});
    uninterrupted.event("a", &.{"x"});
    uninterrupted.event("b", &.{"y"});
    try testing.expect(!std.mem.eql(u8, &before, &observed.state()));
    try testing.expectEqual(observed.state(), uninterrupted.state());
}

test "the auditor ignores buffer chunking (test_auditor_ignores_buffer_chunking)" {
    var contiguous: Auditor = .{};
    contiguous.event("send", &.{"abcd"});
    var chunked: Auditor = .{};
    chunked.event_chunked("send", &.{}, &.{ "a", "bc", "d" }, &.{});
    try testing.expectEqual(contiguous.state(), chunked.state());
    var different: Auditor = .{};
    different.event_chunked("send", &.{}, &.{ "a", "bc", "e" }, &.{});
    try testing.expect(!std.mem.eql(u8, &contiguous.state(), &different.state()));
}

/// Draws `draws` random bytes, then writes and syncs `data` to a blob; returns the audit state.
fn audit_with_effects(draws: u8, data: []const u8) ![8]u8 {
    var runner = try test_runner(.{ .seed = 7 });
    defer runner.deinit();
    const Root = struct {
        fn body(r: *Runner, count: u8, payload: []const u8) !void {
            var buffer: [8]u8 = undefined;
            for (0..count) |_| r.io().random(&buffer);
            const opened = try r.storage().open("partition", "blob");
            defer opened.blob.close();
            try opened.blob.write_at(0, payload, .{});
            try opened.blob.sync();
        }
    };
    try (try runner.start(Root.body, .{ &runner, draws, data }));
    return runner.auditor.state();
}

test "random draws and storage operations are audited" {
    const base = try audit_with_effects(1, "data");
    try testing.expectEqual(base, try audit_with_effects(1, "data"));
    try testing.expect(!std.mem.eql(u8, &base, &try audit_with_effects(2, "data")));
    try testing.expect(!std.mem.eql(u8, &base, &try audit_with_effects(1, "date")));
}

fn audit_with_metric(name: []const u8, help: []const u8) ![8]u8 {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn body(ctx: Context, metric_name: []const u8, metric_help: []const u8) !void {
            const counter: telemetry.metrics.raw.Counter = .{};
            var registered = try ctx.register(metric_name, metric_help, counter);
            registered.deinit();
        }
    };
    try (try runner.start_context(Root.body, .{ name, help }));
    return runner.auditor.state();
}

test "the auditor separates metric fields (test_auditor_separates_metric_fields)" {
    const a = try audit_with_metric("a", "bc");
    try testing.expect(!std.mem.eql(u8, &a, &try audit_with_metric("ab", "c")));
}

test "the clock starts at the configured time (test_default_time_zero, test_start_time)" {
    for ([_]u64{ 0, 100 * std.time.ns_per_s }) |start_ns| {
        var runner = try test_runner(.{ .start_time_ns = start_ns });
        defer runner.deinit();
        const Root = struct {
            fn body(ctx: Context, expected_ns: u64) !void {
                try testing.expectEqual(@as(i96, expected_ns), ctx.current().nanoseconds);
            }
        };
        try (try runner.start_context(Root.body, .{start_ns}));
    }
}

test "an aborted sleeper does not block a later alarm (test_dropped_sleeper_before_live_deadline)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn sleeper(ctx: Context, started: *Io.Event) anyerror!void {
            started.set(ctx.io());
            try ctx.sleep(.fromMilliseconds(1000));
        }

        fn body(ctx: Context) !void {
            var started: Io.Event = .unset;
            const handle = try ctx.child("sleeper").spawn(sleeper, .{&started});
            try started.wait(ctx.io());
            try testing.expectError(error.Closed, handle.abort());
            const start = ctx.current();
            try ctx.sleep(.fromMilliseconds(2000));
            try testing.expect(start.durationTo(ctx.current()).toMilliseconds() >= 2000);
        }
    };
    try (try runner.start_context(Root.body, .{}));
}

// commonware test_dropped_sleeper_beyond_timeout. commonware reports a timeout because a
// dropped Rust sleep leaves its alarm in the heap; zigware frees an aborted task's alarms with
// it, so nothing remains to wait for and the run stalls instead.
test "an aborted sleeper's alarm beyond the timeout is dropped" {
    var runner = try test_runner(.{ .timeout_ns = 10 * std.time.ns_per_s });
    defer runner.deinit();
    const Root = struct {
        fn sleeper(ctx: Context, started: *Io.Event) anyerror!void {
            started.set(ctx.io());
            try ctx.sleep(.fromMilliseconds(20_000));
        }

        fn body(ctx: Context) !void {
            var started: Io.Event = .unset;
            const handle = try ctx.child("sleeper").spawn(sleeper, .{&started});
            try started.wait(ctx.io());
            try testing.expectError(error.Closed, handle.abort());
            var never: Io.Event = .unset;
            try never.wait(ctx.io());
        }
    };
    try testing.expectError(error.Stalled, runner.start_context(Root.body, .{}));
    try testing.expect(runner.now_ns() < 10 * std.time.ns_per_s);
}

test "a repeated attribute key keeps the last value (test_metrics_duplicate_attribute_overwrites)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn body(ctx: Context) !void {
            const scoped = ctx.child("test")
                .with_attribute("epoch", "old")
                .with_attribute("epoch", "new");
            try testing.expectEqual(@as(u8, 1), scoped.scope.attribute_count);
            const attribute = scoped.scope.attribute(0);
            try testing.expectEqualStrings("epoch", attribute.key);
            try testing.expectEqualStrings("new", attribute.value);
        }
    };
    try (try runner.start_context(Root.body, .{}));
}

// commonware test_removed_blob_reopens_while_handle_alive.
test "a removed blob reopens while its old handle is alive" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn body(store: storage_mod.Storage) !void {
            const old = (try store.open("partition", "blob")).blob;
            try old.write_at(0, "old", .{});
            try store.remove("partition", null);
            const current = try store.open("partition", "blob");
            defer current.blob.close();
            try testing.expectEqual(@as(u64, 0), current.len);
            // Closing the removed handle must not affect its replacement.
            old.close();
            try current.blob.write_at(0, "new", .{});
            try current.blob.sync();
            var buffer: [3]u8 = undefined;
            try current.blob.read_at(0, &buffer);
            try testing.expectEqualStrings("new", &buffer);
        }
    };
    try (try runner.start(Root.body, .{runner.storage()}));
}

test "the fault configuration carries over a restart (test_recover_snapshots_fault_configuration)" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn set(owner: *Runner) void {
            owner.storage_fault_config().open_rate = .one;
        }

        fn open(store: storage_mod.Storage) !void {
            try testing.expectError(error.Io, store.open("fault_config", "blob"));
        }
    };
    try runner.start(Root.set, .{&runner});
    try (try runner.start(Root.open, .{runner.storage()}));
}

const crash_epoch_stable_len = 32;
const crash_epoch_pending_len = 256;
const CrashEpoch = struct {
    bytes: [crash_epoch_stable_len + crash_epoch_pending_len]u8,
    audit: [4]u8,
};

/// Syncs a stable prefix, leaves a random subset of a pending suffix to survive the restart,
/// and returns what the next run reads.
fn crash_epoch(seed: u64) !CrashEpoch {
    const faults: storage_mod.faulty.Config = .{ .write_rate = .{
        .failure_rate = .zero,
        .retention_rate = .literal(0.5),
        .mode = .subset,
    } };
    var runner = try test_runner(.{ .seed = seed, .storage_faults = faults });
    defer runner.deinit();
    const Root = struct {
        fn write(store: storage_mod.Storage) !void {
            const blob = (try store.open("crash_epoch", "blob")).blob;
            defer blob.close();
            const stable: [crash_epoch_stable_len]u8 = @splat(0xA5);
            const pending: [crash_epoch_pending_len]u8 = @splat(0x5A);
            try blob.write_at(0, &stable, .{});
            try blob.sync();
            try blob.write_at(stable.len, &pending, .{});
        }

        fn read(store: storage_mod.Storage, bytes: []u8) !void {
            const opened = try store.open("crash_epoch", "blob");
            defer opened.blob.close();
            @memset(bytes, 0);
            try opened.blob.read_at(0, bytes[0..@intCast(opened.len)]);
        }
    };
    var result: CrashEpoch = undefined;
    try (try runner.start(Root.write, .{runner.storage()}));
    try (try runner.start(Root.read, .{ runner.storage(), &result.bytes }));
    result.audit = runner.storage_audit();
    return result;
}

// commonware test_recover_random_crash_writes_is_seeded_and_epoch_scoped.
test "crash writes are seeded and scoped to their run" {
    const first = try crash_epoch(12345);
    try testing.expectEqual(first, try crash_epoch(12345));
    const different = try crash_epoch(54321);
    try testing.expect(!std.mem.eql(u8, &first.bytes, &different.bytes));
    for (first.bytes[0..crash_epoch_stable_len]) |byte| try testing.expectEqual(0xA5, byte);
    const pending = first.bytes[crash_epoch_stable_len..];
    try testing.expect(std.mem.indexOfScalar(u8, pending, 0) != null);
    try testing.expect(std.mem.indexOfScalar(u8, pending, 0x5A) != null);
}

test "the runner's network connects tasks" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Network = network_mod.deterministic.Network;
    const Root = struct {
        fn serve(listener: *Network.Listener) !void {
            var accepted = try listener.accept();
            defer accepted.deinit();
            var buffer: [4]u8 = undefined;
            try accepted.stream.recv(&buffer);
            try accepted.sink.send(&.{&buffer});
        }
        fn run(io: Io, net: *Network) !void {
            const address: network_mod.Address = .{ .ip4 = .loopback(9000) };
            const listener = try net.bind(address);
            defer listener.deinit();
            var server = try io.concurrent(serve, .{listener});
            var connection = try net.dial(address);
            defer connection.deinit();
            try connection.sink.send(&.{"ping"});
            var buffer: [4]u8 = undefined;
            try connection.stream.recv(&buffer);
            try testing.expectEqualStrings("ping", &buffer);
            try server.await(io);
        }
    };
    try (try runner.start(Root.run, .{ runner.io(), runner.network() }));
}

// Regression (15fe6e5): a timed wait woken early leaves its alarm queued; destroying the task
// must drop it, or firing it later reads the freed task.
test "a finished task's stale alarms are dropped with it" {
    var runner = try test_runner(.{});
    defer runner.deinit();
    const Root = struct {
        fn waiter(io: Io, word: *u32) !void {
            const timeout: Io.Timeout = .{ .duration = .{
                .raw = .fromSeconds(10),
                .clock = .awake,
            } };
            try io.futexWaitTimeout(u32, word, 0, timeout);
            try testing.expectEqual(@as(u32, 1), word.*);
        }
        fn run(io: Io, r: *Runner) !void {
            var word: u32 = 0;
            var future = try io.concurrent(waiter, .{ io, &word });
            // Several cycles, so the waiter has run and armed its alarm.
            try io.sleep(.fromMilliseconds(10), .awake);
            try testing.expectEqual(@as(usize, 1), r.alarms.items.len);
            word = 1;
            io.futexWake(u32, &word, 1);
            try future.await(io);
            // The waiter is freed; its alarm went with it.
            try testing.expectEqual(@as(usize, 0), r.alarms.items.len);
            try io.sleep(.fromSeconds(20), .awake);
        }
    };
    try (try runner.start(Root.run, .{ runner.io(), &runner }));
}

/// Overwrites a synced blob without syncing, syncs one byte of it, reopens, and (with
/// `fresh`) supersedes it with a synced write; returns what the next run reads.
fn logical_open(fresh: bool) ![5]u8 {
    const retain_all: storage_mod.faulty.WriteConfig =
        .{ .failure_rate = .zero, .retention_rate = .one, .mode = .prefix };
    var runner = try test_runner(.{ .storage_faults = .{ .write_rate = retain_all } });
    defer runner.deinit();
    const Root = struct {
        fn write(r: *Runner, sync: bool) !void {
            const store = r.storage();
            const blob = (try store.open("partition", "blob")).blob;
            try blob.write_at(0, "saved", .{ .sync = true });
            try blob.write_at(0, "stale", .{});
            try blob.write_at(2, "X", .{ .sync = true });
            blob.close();
            // The reopen sees only the durable snapshot, not the retained fragments.
            const reopened = try store.open("partition", "blob");
            defer reopened.blob.close();
            try testing.expectEqual(@as(u64, 5), reopened.len);
            try storage_mod.tests.expect_read(reopened.blob, 0, "saXed");
            // Duplicate opens are audited too.
            const before = r.auditor.state();
            try testing.expectError(error.BlobAlreadyOpen, store.open("partition", "blob"));
            try testing.expect(!std.mem.eql(u8, &before, &r.auditor.state()));
            if (sync) {
                try reopened.blob.write_at(0, "fresh", .{});
                try reopened.blob.sync();
            }
        }
        fn read(store: storage_mod.Storage) ![5]u8 {
            const opened = try store.open("partition", "blob");
            defer opened.blob.close();
            try testing.expectEqual(@as(u64, 5), opened.len);
            var buffer: [5]u8 = undefined;
            try opened.blob.read_at(0, &buffer);
            return buffer;
        }
    };
    try (try runner.start(Root.write, .{ &runner, fresh }));
    return try (try runner.start(Root.read, .{runner.storage()}));
}

// commonware test_logical_open_releases_retained_mutations, both cases.
test "a reopen drops the retained fragments of a closed open" {
    // Crash replay must not restore fragments the successful reopen excluded.
    try testing.expectEqualStrings("saXed", &try logical_open(false));
    try testing.expectEqualStrings("fresh", &try logical_open(true));
}
