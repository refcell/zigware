//! Tests of `plan.zig` (commonware `simulate/plan.rs` tests), with two stub engines that report
//! finalizations straight to the plan instead of running consensus.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const simulate = @import("mod.zig");

const Key = cryptography.ed25519.PublicKey;
const PrivateKey = cryptography.ed25519.PrivateKey;
const Context = simulate.engine.Context;
const Handle = simulate.engine.Handle;
const Duration = utils.time.Duration;
const Probability = utils.Probability;
const Round = consensus.Round;
const Height = consensus.Height;
const Tracker = simulate.ProgressTracker(Key);
const Schedule = simulate.Schedule(Key);
const gpa = testing.allocator;

fn key(seed: u64) Key {
    return PrivateKey.from_seed(seed).public_key();
}

fn round(view: u64) Round {
    return Round.new(consensus.Epoch.zero(), consensus.View.new(view));
}

fn keys(comptime count: usize) [count]Key {
    var result: [count]Key = undefined;
    for (&result, 0..) |*pk, seed| pk.* = key(seed);
    return result;
}

fn sleep(ctx: Context, duration: Duration) error{Canceled}!void {
    if (duration.is_zero()) return;
    const nanos: i96 = @intCast(duration.as_nanos());
    try ctx.sleep(.fromNanoseconds(nanos));
}

/// A report `FinalizingEngine`'s first node emits before its ordinary finalizations.
const Scripted = struct { pk: Key, view: u64, digest: u8 };

/// Participant indices in delayed initialization order.
const Starts = struct {
    indices: [8]usize = undefined,
    count: usize = 0,

    fn slice(starts: *const Starts) []const usize {
        return starts.indices[0..starts.count];
    }
};

/// Reports `finalizations` views, one per `period`, after `finalize_after`.
const FinalizingEngine = struct {
    pub const PublicKey = Key;
    pub const State = void;
    pub const Engine = Node;

    keys: []const Key,
    /// Delay before a node emits any report.
    finalize_after: Duration,
    /// Ordinary finalizations each node reports, one per view.
    finalizations: u64,
    /// Delay after each ordinary finalization; zero emits a burst.
    period: Duration = .zero,
    script: []const Scripted = &.{},
    starts: ?*Starts = null,

    pub const Node = struct {
        context: Context,
        monitor: simulate.Monitor(Key),
        pk: Key,
        finalize_after: Duration,
        finalizations: u64,
        period: Duration,
        script: []const Scripted,
    };

    pub fn participants(self: *const FinalizingEngine) []const Key {
        return self.keys;
    }

    pub fn channels(_: *const FinalizingEngine) []const simulate.ChannelSpec {
        return &.{};
    }

    pub fn max_message_size(_: *const FinalizingEngine) u32 {
        return p2p.max_message_size(&.{});
    }

    pub fn init(self: *const FinalizingEngine, ctx: simulate.InitContext(Key)) !struct {
        Node,
        void,
    } {
        if (ctx.delayed) if (self.starts) |starts| {
            starts.indices[starts.count] = ctx.index;
            starts.count += 1;
        };
        // Only the first node emits the script so its reports stay ordered.
        const script = if (ctx.index == 0) self.script else &.{};
        return .{ .{
            .context = ctx.context,
            .monitor = ctx.monitor,
            .pk = ctx.public_key,
            .finalize_after = self.finalize_after,
            .finalizations = self.finalizations,
            .period = self.period,
            .script = script,
        }, {} };
    }

    pub fn start(node: Node) !Handle {
        return node.context.spawn(report, .{node});
    }

    fn report(ctx: Context, node: Node) void {
        // The initial delay lets scheduled actions run before reports arrive.
        sleep(ctx, node.finalize_after) catch return;
        // Sends without yielding queue the whole script before the plan sees any of it.
        for (node.script) |scripted| {
            const sent = node.monitor.send(.{
                .pk = scripted.pk,
                .round = round(scripted.view),
                .height = Height.new(scripted.view),
                .block_digest = &.{scripted.digest},
            });
            assert(sent);
        }
        var view: u64 = 1;
        while (view <= node.finalizations) : (view += 1) {
            _ = node.monitor.send(.{
                .pk = node.pk,
                .round = round(view),
                .height = Height.new(view),
                .block_digest = &.{@truncate(view)},
            });
            sleep(ctx, node.period) catch return;
            if (view == std.math.maxInt(u64)) return;
        }
    }
};

/// Records whether the storage fault was configured when the engine initialized.
const FaultObservingEngine = struct {
    pub const PublicKey = Key;
    pub const State = bool;
    pub const Engine = Node;

    keys: []const Key,

    pub const Node = struct {
        context: Context,
        monitor: simulate.Monitor(Key),
        pk: Key,
    };

    pub fn participants(self: *const FaultObservingEngine) []const Key {
        return self.keys;
    }

    pub fn channels(_: *const FaultObservingEngine) []const simulate.ChannelSpec {
        return &.{};
    }

    pub fn max_message_size(_: *const FaultObservingEngine) u32 {
        return p2p.max_message_size(&.{});
    }

    pub fn init(_: *const FaultObservingEngine, ctx: simulate.InitContext(Key)) !struct {
        Node,
        bool,
    } {
        const open_rate = ctx.storage_faults.open_rate;
        const saw_fault = open_rate != null and std.meta.eql(open_rate.?, Probability.one);
        const node: Node = .{
            .context = ctx.context,
            .monitor = ctx.monitor,
            .pk = ctx.public_key,
        };
        return .{ node, saw_fault };
    }

    pub fn start(node: Node) !Handle {
        return node.context.spawn(report, .{node});
    }

    fn report(ctx: Context, node: Node) void {
        sleep(ctx, .from_millis(10)) catch return;
        _ = node.monitor.send(.{
            .pk = node.pk,
            .round = round(1),
            .height = Height.new(1),
            .block_digest = &.{1},
        });
    }
};

const AtLeastTrackedValidators = struct {
    pub const name = "at_least_tracked_validators";

    min: usize,

    pub fn reached(
        self: *const AtLeastTrackedValidators,
        tracker: *const Tracker,
        _: anytype,
        _: usize,
    ) !bool {
        return tracker.tracked_count() >= self.min;
    }
};

const AllStatesSawFault = struct {
    pub const name = "all_states_saw_fault";

    pub fn check(
        _: *const AllStatesSawFault,
        _: *const Tracker,
        states: []const *const bool,
    ) !void {
        for (states) |state| if (!state.*) return error.FaultNotVisibleDuringInit;
    }
};

/// Fails when checked more than once.
const SingleUseProperty = struct {
    pub const name = "single_use_property";

    calls: *usize,

    pub fn check(self: *const SingleUseProperty, _: *const Tracker, _: []const *const void) !void {
        self.calls.* += 1;
        if (self.calls.* > 1) return error.PropertyReused;
    }
};

/// A finalization check that suspends, so reports queue while it runs.
const SlowCheck = struct {
    pub const name = "slow_check";

    context: Context,
    calls: *u64,

    pub fn check(self: *const SlowCheck, _: []const *const void) !void {
        self.calls.* += 1;
        try sleep(self.context, .from_millis(5));
    }
};

const FinalizingPlan = simulate.Plan(FinalizingEngine);

fn run_one(plan: *const FinalizingPlan) !void {
    var result = try plan.run(gpa);
    result.deinit();
}

const QuietReporter = struct {
    fn run(ctx: Context, runner: *runtime.deterministic.Runner) !void {
        // Emit reports every millisecond while each check takes five.
        const participants = keys(1);
        const engine: FinalizingEngine = .{
            .keys = &participants,
            .finalize_after = .zero,
            .finalizations = std.math.maxInt(u64),
            .period = .from_millis(1),
        };
        var calls: u64 = 0;
        const slow: SlowCheck = .{ .context = ctx.child("check"), .calls = &calls };
        const plan: FinalizingPlan = .{
            .engine = &engine,
            .required_finalizations = 1,
            .finalization_properties = &.{.from(&slow)},
        };
        var result = try FinalizingPlan.run_in_context(ctx, &plan, runner);
        defer result.deinit();
        // Every accepted report is checked, including those queued during a check.
        try testing.expect(calls > 1);
        try testing.expectEqual(calls, result.tracker.min_view());
    }
};

test "plan: completion does not require a quiet reporter" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .timeout_ns = std.time.ns_per_s });
    defer runner.deinit();
    try try runner.start_context(QuietReporter.run, .{&runner});
}

test "plan: queued fork must fail simulation" {
    // Reports from both validators meet the exit condition before the final report conflicts
    // with an earlier digest at the same height.
    const participants = keys(2);
    const a = participants[0];
    const b = participants[1];
    const engine: FinalizingEngine = .{
        .keys = &participants,
        .finalize_after = .zero,
        .finalizations = 0,
        .script = &.{
            .{ .pk = b, .view = 2, .digest = 2 },
            .{ .pk = a, .view = 3, .digest = 3 },
            .{ .pk = b, .view = 3, .digest = 4 },
        },
    };
    const plan: FinalizingPlan = .{
        .engine = &engine,
        .required_finalizations = 2,
        .timeout = .from_secs(2),
    };
    // Every accepted report must be checked before the simulation succeeds.
    try testing.expectError(error.ForkAtHeight, run_one(&plan));
}

test "plan: delayed start does not follow completion" {
    // The active node queues three reports at once. Completion holds after the first, while
    // the delay round is only reached by the queued third.
    const participants = keys(2);
    const active = participants[0];
    const engine: FinalizingEngine = .{
        .keys = &participants,
        .finalize_after = .zero,
        .finalizations = 0,
        .script = &.{
            .{ .pk = active, .view = 1, .digest = 1 },
            .{ .pk = active, .view = 2, .digest = 2 },
            .{ .pk = active, .view = 3, .digest = 3 },
        },
    };
    const plan: FinalizingPlan = .{
        .engine = &engine,
        .required_finalizations = 1,
        .timeout = .from_secs(2),
        .crashes = &.{.{ .delay_round = .{
            .participants = participants[1..],
            .round = round(3),
        } }},
    };
    // The plan keeps its team fixed after completion.
    try testing.expectError(error.DelayedNeverStarted, run_one(&plan));
}

test "plan: multi delayed start is deterministic" {
    // Repeat the same seeded run and compare the delayed initialization order.
    const participants = keys(4);
    var first: ?Starts = null;
    for (0..24) |_| {
        // Two participants start after the active nodes reach view one.
        var starts: Starts = .{};
        const engine: FinalizingEngine = .{
            .keys = &participants,
            .finalize_after = .from_millis(100),
            .finalizations = 2,
            .starts = &starts,
        };
        const plan: FinalizingPlan = .{
            .engine = &engine,
            .seed = 7,
            .required_finalizations = 2,
            .timeout = .from_secs(2),
            .crashes = &.{.{ .delay_round = .{
                .participants = participants[0..2],
                .round = round(1),
            } }},
        };
        try run_one(&plan);
        // Both delayed nodes start, in the same order on every run.
        try testing.expectEqual(2, starts.count);
        if (first) |expected| {
            try testing.expectEqualSlices(usize, expected.slice(), starts.slice());
        } else first = starts;
    }
}

const still_link: p2p.simulated.Link = .{
    .latency = .from_millis(10),
    .jitter = .zero,
    .success_rate = 1.0,
};

test "plan: schedule action applied before completion is counted" {
    const participants = keys(1);
    const engine: FinalizingEngine = .{
        .keys = &participants,
        .finalize_after = .from_millis(100),
        .finalizations = 1,
    };
    var schedule: Schedule = .empty;
    defer schedule.deinit(gpa);
    try schedule.add(gpa, .from_millis(1), .{ .heal = still_link });
    try schedule.add(gpa, .from_secs(5), .{ .heal = still_link });
    const plan: FinalizingPlan = .{
        .engine = &engine,
        .required_finalizations = 1,
        .timeout = .from_secs(2),
        .crashes = &.{.{ .schedule = &schedule }},
    };
    var result = try plan.run(gpa);
    defer result.deinit();
    try testing.expectEqual(1, result.scheduled_actions);
}

test "plan: delay and schedule actions compose" {
    const participants = keys(2);
    const engine: FinalizingEngine = .{
        .keys = &participants,
        .finalize_after = .from_millis(100),
        .finalizations = 2,
    };
    var schedule: Schedule = .empty;
    defer schedule.deinit(gpa);
    try schedule.add(gpa, .from_millis(1), .{ .heal = still_link });
    const plan: FinalizingPlan = .{
        .engine = &engine,
        .required_finalizations = 2,
        .timeout = .from_secs(2),
        .crashes = &.{
            .{ .delay_round = .{ .participants = participants[0..1], .round = round(1) } },
            .{ .schedule = &schedule },
        },
    };
    var result = try plan.run(gpa);
    defer result.deinit();
    try testing.expect(result.delayed_started);
    try testing.expectEqual(1, result.scheduled_actions);
}

test "plan: schedule double crash before restart counts one crash" {
    const participants = keys(1);
    const pk = participants[0];
    const engine: FinalizingEngine = .{
        .keys = &participants,
        .finalize_after = .from_millis(50),
        .finalizations = 1,
    };
    var schedule: Schedule = .empty;
    defer schedule.deinit(gpa);
    try schedule.add(gpa, .from_millis(1), .{ .crash = pk });
    try schedule.add(gpa, .from_millis(2), .{ .crash = pk });
    try schedule.add(gpa, .from_millis(3), .{ .restart = pk });
    const plan: FinalizingPlan = .{
        .engine = &engine,
        .required_finalizations = 1,
        .timeout = .from_secs(2),
        .crashes = &.{.{ .schedule = &schedule }},
    };
    var result = try plan.run(gpa);
    defer result.deinit();
    // The second crash before the restart is a no-op.
    try testing.expectEqual(1, result.crashes);
    try testing.expectEqual(3, result.scheduled_actions);
}

test "plan: custom exit condition overrides required finalizations" {
    const participants = keys(2);
    const engine: FinalizingEngine = .{
        .keys = &participants,
        .finalize_after = .from_millis(10),
        .finalizations = 1,
    };
    const condition: AtLeastTrackedValidators = .{ .min = 2 };
    const plan: FinalizingPlan = .{
        .engine = &engine,
        .required_finalizations = 100,
        .exit_condition = .from(&condition),
        .timeout = .from_secs(2),
    };
    var result = try plan.run(gpa);
    defer result.deinit();
    try testing.expectEqual(2, result.tracker.tracked_count());
}

test "plan: each seed's run checks its own properties" {
    // Properties are borrowed, so each seed's run gets its own; a reused one fails.
    const participants = keys(1);
    const engine: FinalizingEngine = .{
        .keys = &participants,
        .finalize_after = .from_millis(10),
        .finalizations = 1,
    };
    var states: [2]usize = .{ 0, 0 };
    for (&states, 0..) |*calls, seed| {
        const single: SingleUseProperty = .{ .calls = calls };
        const plan: FinalizingPlan = .{
            .engine = &engine,
            .required_finalizations = 1,
            .timeout = .from_secs(1),
            .properties = &.{.from(&single)},
        };
        var result = try plan.run_with_seed(gpa, seed);
        result.deinit();
        try testing.expectEqual(1, calls.*);
        try testing.expectError(error.PropertyViolation, plan.run_with_seed(gpa, seed));
    }
}

test "plan: storage fault is visible during engine init" {
    const participants = keys(1);
    const engine: FaultObservingEngine = .{ .keys = &participants };
    const saw_fault: AllStatesSawFault = .{};
    const plan: simulate.Plan(FaultObservingEngine) = .{
        .engine = &engine,
        .storage_fault = .{ .open_rate = .one },
        .timeout = .from_secs(1),
        .required_finalizations = 1,
        .properties = &.{.from(&saw_fault)},
    };
    var result = try plan.run(gpa);
    defer result.deinit();
}

test "plan: only one delay strategy may be configured" {
    const participants = keys(2);
    const engine: FinalizingEngine = .{
        .keys = &participants,
        .finalize_after = .zero,
        .finalizations = 1,
    };
    const delay: simulate.Crash(Key) = .{ .delay_round = .{
        .participants = participants[0..1],
        .round = round(1),
    } };
    const plan: FinalizingPlan = .{ .engine = &engine, .crashes = &.{ delay, delay } };
    try testing.expectError(error.DuplicateCrashStrategy, run_one(&plan));
}
