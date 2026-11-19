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

/// Validators that each process and report one height per period (commonware's
/// `ProcessingEngine`).
const ProcessingEngine = struct {
    pub const PublicKey = Key;
    pub const State = Processed;
    pub const Engine = Node;

    keys: []const Key,
    /// Time each validator takes to process a height, in participant order.
    periods: []const Duration,
    /// Height each validator has processed, kept across restarts.
    processed: []std.atomic.Value(u64),
    /// Every validator start, in order.
    starts: *Log,

    /// A validator start: its index, and the height each validator had processed by then.
    const Start = struct { index: usize, heights: [3]u64 };

    const Log = struct {
        items: [16]Start = undefined,
        count: usize = 0,

        fn slice(starts: *const Log) []const Start {
            return starts.items[0..starts.count];
        }
    };

    /// The height a validator has processed.
    pub const Processed = struct {
        value: *std.atomic.Value(u64),

        pub fn processed_height(self: *const Processed) u64 {
            return self.value.load(.monotonic);
        }
    };

    pub const Node = struct {
        context: Context,
        monitor: simulate.Monitor(Key),
        pk: Key,
        period: Duration,
        processed: *std.atomic.Value(u64),
    };

    pub fn participants(self: *const ProcessingEngine) []const Key {
        return self.keys;
    }

    pub fn channels(_: *const ProcessingEngine) []const simulate.ChannelSpec {
        return &.{};
    }

    pub fn max_message_size(_: *const ProcessingEngine) u32 {
        return p2p.max_message_size(&.{});
    }

    pub fn init(self: *const ProcessingEngine, ctx: simulate.InitContext(Key)) !struct {
        Node,
        Processed,
    } {
        assert(self.processed.len <= 3 and self.starts.count < self.starts.items.len);
        var record: Start = .{ .index = ctx.index, .heights = @splat(0) };
        for (self.processed, 0..) |*height, index| record.heights[index] = height.load(.monotonic);
        self.starts.items[self.starts.count] = record;
        self.starts.count += 1;
        const processed = &self.processed[ctx.index];
        return .{ .{
            .context = ctx.context,
            .monitor = ctx.monitor,
            .pk = ctx.public_key,
            .period = self.periods[ctx.index],
            .processed = processed,
        }, .{ .value = processed } };
    }

    pub fn start(node: Node) !Handle {
        return node.context.spawn(process, .{node});
    }

    fn process(ctx: Context, node: Node) void {
        while (true) {
            sleep(ctx, node.period) catch return;
            const height = node.processed.fetchAdd(1, .monotonic) + 1;
            const sent = node.monitor.send(.{
                .pk = node.pk,
                .round = round(height),
                .height = Height.new(height),
                .block_digest = &.{@truncate(height)},
            });
            if (!sent) return;
        }
    }
};

const ProcessingPlan = simulate.Plan(ProcessingEngine);

/// Runs one validator against `crash` while its reports outpace the plan's checks, and
/// returns the number of crashes the plan applied.
const OutpacedChecks = struct {
    fn run(
        ctx: Context,
        runner: *runtime.deterministic.Runner,
        crash: simulate.Crash(Key),
    ) !u64 {
        // Emit reports every millisecond while each check takes five, so reports stay queued
        // behind the check in progress.
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
            .required_finalizations = 20,
            .finalization_properties = &.{.from(&slow)},
            .crashes = &.{crash},
        };
        var result = try FinalizingPlan.run_in_context(ctx, &plan, runner);
        defer result.deinit();
        return result.crashes;
    }

    fn crashes(crash: simulate.Crash(Key)) !u64 {
        var runner = try runtime.deterministic.Runner.init(gpa, .{
            .timeout_ns = 2 * std.time.ns_per_s,
        });
        defer runner.deinit();
        return try runner.start_context(run, .{ &runner, crash });
    }

    /// The crash count of a schedule that crashes the validator at `crash_ms` and restarts
    /// it ten milliseconds later.
    fn scheduled(crash_ms: u64) !u64 {
        const pk = keys(1)[0];
        var schedule: Schedule = .empty;
        defer schedule.deinit(gpa);
        try schedule.add(gpa, .from_millis(crash_ms), .{ .crash = pk });
        try schedule.add(gpa, .from_millis(crash_ms + 10), .{ .restart = pk });
        return crashes(.{ .schedule = &schedule });
    }
};

test "plan: scheduled crash applies while reports outpace checks" {
    try testing.expectEqual(1, try OutpacedChecks.scheduled(10));
}

test "plan: a scheduled crash due behind queued reports applies before completion" {
    // By 80ms the plan has checked about 16 reports, and reports up to 80 are queued. Taken in
    // arrival order, the crash would wait behind the 20th report, which completes the run.
    try testing.expectEqual(1, try OutpacedChecks.scheduled(80));
}

test "plan: random crash applies while reports outpace checks" {
    const crashes = try OutpacedChecks.crashes(.{ .random = .{
        .frequency = .from_millis(30),
        .downtime = .from_millis(5),
        .count = 1,
    } });
    try testing.expect(crashes > 0);
}

test "plan: processed height crash stops participants together" {
    // The fast validators enter the shared window after about 50ms. The slow validator first
    // stops alone at height 2 for 200ms, so it enters the window after about 350ms. It sits
    // between the fast validators in participant order, so neither the first nor the last
    // participant decides alone when the shared crash is due.
    const slow = 1;
    const fast = [_]usize{ 0, 2 };
    const participants = keys(3);
    var processed: [3]std.atomic.Value(u64) = @splat(.init(0));
    var starts: ProcessingEngine.Log = .{};
    const engine: ProcessingEngine = .{
        .keys = &participants,
        .periods = &.{ .from_millis(10), .from_millis(30), .from_millis(10) },
        .processed = &processed,
        .starts = &starts,
    };
    const condition: simulate.exit.ProcessedHeightAtLeast = .{ .required = 8 };
    const plan: ProcessingPlan = .{
        .engine = &engine,
        .crashes = &.{
            .{ .processed_height = .{
                .participants = participants[slow .. slow + 1],
                .heights = .{ .min = 2, .max = 2 },
                .downtime = .from_millis(200),
            } },
            .{ .processed_height = .{
                .participants = &participants,
                .heights = .{ .min = 5, .max = 45 },
                .downtime = .from_millis(100),
            } },
        },
        .exit_condition = .from(&condition),
        .timeout = .from_secs(2),
    };
    var result = try plan.run(gpa);
    defer result.deinit();
    // The slow validator stops twice and each fast validator once.
    try testing.expectEqual(4, result.crashes);

    // After every validator starts, the slow one restarts alone, once the fast ones have
    // processed 20 heights or more. The last three restarts then record the same heights, so
    // no validator ran while another was stopped. The slow validator stopped as it entered the
    // window, when the fast ones were already inside it.
    const all = starts.slice();
    try testing.expect(all.len >= 4);
    const alone = all[3];
    try testing.expectEqual(slow, alone.index);
    for (fast) |index| try testing.expect(alone.heights[index] >= 20);
    const together = all[4..];
    try testing.expectEqual(3, together.len);
    var restarted: [3]bool = @splat(false);
    for (together) |start| restarted[start.index] = true;
    try testing.expectEqual([3]bool{ true, true, true }, restarted);
    const heights = together[0].heights;
    for (together) |start| try testing.expectEqual(heights, start.heights);
    try testing.expectEqual(5, heights[slow]);
    for (fast) |index| try testing.expect(heights[index] > 5);
}

test "plan: processed height crash requires every participant inside window" {
    // The fast validator processes height 10, past the window, after about 100ms. The slow
    // validator has then processed only height 3 and has yet to enter the window.
    const participants = keys(2);
    var processed: [2]std.atomic.Value(u64) = @splat(.init(0));
    var starts: ProcessingEngine.Log = .{};
    const engine: ProcessingEngine = .{
        .keys = &participants,
        .periods = &.{ .from_millis(10), .from_millis(30) },
        .processed = &processed,
        .starts = &starts,
    };
    const condition: simulate.exit.ProcessedHeightAtLeast = .{ .required = 8 };
    const plan: ProcessingPlan = .{
        .engine = &engine,
        .crashes = &.{.{ .processed_height = .{
            .participants = &participants,
            .heights = .{ .min = 5, .max = 9 },
            .downtime = .from_millis(100),
        } }},
        .exit_condition = .from(&condition),
        .timeout = .from_secs(2),
    };
    try testing.expectError(error.SkippedProcessedHeightWindow, plan.run(gpa));
}

test "plan: processed height crash needs a participant" {
    const participants = keys(1);
    var processed: [1]std.atomic.Value(u64) = @splat(.init(0));
    var starts: ProcessingEngine.Log = .{};
    const engine: ProcessingEngine = .{
        .keys = &participants,
        .periods = &.{.from_millis(10)},
        .processed = &processed,
        .starts = &starts,
    };
    const plan: ProcessingPlan = .{
        .engine = &engine,
        .crashes = &.{.{ .processed_height = .{
            .participants = &.{},
            .heights = .{ .min = 1, .max = 1 },
            .downtime = .zero,
        } }},
    };
    try testing.expectError(error.EmptyCrashParticipants, plan.run(gpa));
}

/// Runs one validator that processes a height every 10ms against `crash` until it has
/// processed `exit_height` heights. Returns the number of crashes the plan applied and the
/// heights the validator had processed at its starts, in `heights`.
fn crashes_and_start_heights(
    crash: simulate.Crash(Key),
    exit_height: u64,
    heights: *std.ArrayList(u64),
) !u64 {
    const participants = keys(1);
    var processed: [1]std.atomic.Value(u64) = @splat(.init(0));
    var starts: ProcessingEngine.Log = .{};
    const engine: ProcessingEngine = .{
        .keys = &participants,
        .periods = &.{.from_millis(10)},
        .processed = &processed,
        .starts = &starts,
    };
    var with_participant = crash;
    if (with_participant == .processed_height) {
        with_participant.processed_height.participants = &participants;
    }
    const condition: simulate.exit.ProcessedHeightAtLeast = .{ .required = exit_height };
    const plan: ProcessingPlan = .{
        .engine = &engine,
        .crashes = &.{with_participant},
        .exit_condition = .from(&condition),
        .timeout = .from_secs(2),
    };
    var result = try plan.run(gpa);
    defer result.deinit();
    for (starts.slice()) |start| try heights.append(gpa, start.heights[0]);
    return result.crashes;
}

test "plan: processed height crash restarts without downtime" {
    var heights: std.ArrayList(u64) = .empty;
    defer heights.deinit(gpa);
    // `crashes_and_start_heights` fills in the validator.
    const crashes = try crashes_and_start_heights(.{ .processed_height = .{
        .participants = &.{},
        .heights = .{ .min = 2, .max = 2 },
        .downtime = .zero,
    } }, 4, &heights);
    try testing.expectEqual(1, crashes);
    // The validator restarts at the height it stopped at.
    try testing.expectEqualSlices(u64, &.{ 0, 2 }, heights.items);
}

test "plan: random crash restarts without downtime" {
    var heights: std.ArrayList(u64) = .empty;
    defer heights.deinit(gpa);
    // A crash is due every 25ms. With immediate restarts the validator processes five heights
    // in about 66ms, so it stops exactly twice. commonware exits at six heights. Measured on
    // both runtimes, a crash at 27ms restarts the validator at 29ms there and 31ms here: an
    // abort here waits for the canceled task to reach its cancelation point and then resumes
    // the aborter, one 1ms cycle each, where commonware drops the future at once. Two restarts
    // put the sixth height at 76ms, just after the third crash at 75ms (73ms in commonware).
    const crashes = try crashes_and_start_heights(.{ .random = .{
        .frequency = .from_millis(25),
        .downtime = .zero,
        .count = 1,
    } }, 5, &heights);
    try testing.expectEqual(2, crashes);
    try testing.expectEqualSlices(u64, &.{ 0, 2, 4 }, heights.items);
}
