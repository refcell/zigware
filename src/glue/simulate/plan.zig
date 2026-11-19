//! Simulation plan: declarative test configuration and the loop that drives it (commonware
//! `glue/src/simulate/plan.rs`).
//!
//! A plan runs every participant's engine in the deterministic runtime over a simulated
//! network, injects its crashes and scheduled actions, checks agreement and its properties
//! on every finalization report, and stops once its exit condition holds. Commonware's
//! `select_loop!` becomes one event queue (`events.zig`) that every source feeds; the plan
//! wakes at least every `exit_poll` to evaluate polling exit conditions.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const action = @import("action.zig");
const tracker_module = @import("tracker.zig");
const events_module = @import("events.zig");
const engine_module = @import("engine.zig");
const team_module = @import("team.zig");
const exit = @import("exit.zig");
const property = @import("property.zig");

const log = std.log.scoped(.simulator);
const Duration = utils.time.Duration;
const Link = p2p.simulated.Link;
const Context = engine_module.Context;
const Handle = engine_module.Handle;
const Runner = runtime.deterministic.Runner;

/// How often the plan evaluates an exit condition that requires polling.
pub const exit_poll = Io.Duration.fromMilliseconds(25);

/// The default link: 10ms latency, 5ms jitter, every message delivered.
pub const default_link: Link = .{
    .latency = Duration.from_millis(10),
    .jitter = Duration.from_millis(5),
    .success_rate = 1.0,
};

/// Why a plan fails, beyond the errors of the engine, the network, and the runtime. Commonware
/// panics on the `...NotExercised`, `DelayedNeverStarted`, and `SkippedProcessedHeightWindow`
/// cases; here they are errors so their tests port.
pub const Error = error{
    /// A finalization property failed (the log names it).
    FinalizationPropertyViolation,
    /// A post-run property failed (the log names it).
    PropertyViolation,
    /// The exit condition failed to evaluate (the log names it).
    ExitConditionFailed,
    /// `Crash.random` was configured but no validator crashed.
    RandomCrashesNotExercised,
    /// A schedule had events but none was applied before completion.
    ScheduleNotExercised,
    /// A delay was configured but the delayed validators never started.
    DelayedNeverStarted,
    /// A participant of a `Crash.processed_height` reported a height past its window before
    /// the crash fired (commonware: "reported processed height must not be past the crash
    /// window").
    SkippedProcessedHeightWindow,
    /// Not every `Crash.processed_height` window was reached.
    ProcessedHeightCrashNotReached,
    /// A crash names a key that is not a participant.
    UnknownParticipant,
    /// More than one `Crash.random` or `Crash.delay_round` is configured.
    DuplicateCrashStrategy,
    /// A `Crash.processed_height` lists no participants (commonware's `NonEmptyVec`).
    EmptyCrashParticipants,
};

/// A declarative simulation of engine definition `D` (commonware `Plan<D>`; its builder's
/// defaults are the field defaults). Everything it points to must outlive `run`.
pub fn Plan(comptime D: type) type {
    engine_module.assert_engine(D);
    return struct {
        const Self = @This();
        pub const P = D.PublicKey;
        pub const S = D.State;
        pub const Tracker = tracker_module.ProgressTracker(P);
        pub const Exit = exit.ExitCondition(P, S);
        pub const FinalizationProperty = property.FinalizationProperty(S);
        pub const Property = property.Property(P, S);
        const Network = p2p.simulated.Network(P);
        const Events = events_module.Events(P);
        const Team = team_module.Team(D);

        /// The engine every validator runs.
        engine: *const D,
        /// Deterministic seed: the same seed produces the same execution.
        seed: u64 = 0,
        /// The link between every pair of validators.
        link: Link = default_link,
        /// Crash strategies, applied together.
        crashes: []const action.Crash(P) = &.{},
        /// Views every validator must finalize under the default exit condition.
        required_finalizations: u64 = 10,
        /// When to stop; null is `MinimumFinalizations{ required_finalizations }`.
        exit_condition: ?Exit = null,
        /// Simulated time after which the run fails with `error.Timeout`.
        timeout: ?Duration = null,
        /// Storage fault injection from the start.
        storage_fault: ?action.FaultConfig = null,
        /// Checked after every finalization report.
        finalization_properties: []const FinalizationProperty = &.{},
        /// Checked once, after the exit condition holds.
        properties: []const Property = &.{},

        /// The outcome of a run (commonware `PlanResult<D>`).
        pub const Result = struct {
            /// The deterministic runtime's audit state at the end of the run.
            state: [8]u8,
            /// The final progress tracker; owned.
            tracker: Tracker,
            /// Validator crashes during the run.
            crashes: u64,
            /// Scheduled actions applied.
            scheduled_actions: u64,
            /// Whether delayed validators were started.
            delayed_started: bool,

            pub fn deinit(self: *Result) void {
                self.tracker.deinit();
                self.* = undefined;
            }
        };

        /// Runs the plan with its seed.
        pub fn run(self: *const Self, gpa: Allocator) !Result {
            return self.run_with_seed(gpa, self.seed);
        }

        /// Runs the plan with `seed` in a fresh deterministic runtime.
        pub fn run_with_seed(self: *const Self, gpa: Allocator, seed: u64) !Result {
            try self.validate();
            const timeout_ns: ?u64 = if (self.timeout) |timeout|
                std.math.cast(u64, timeout.as_nanos()) orelse std.math.maxInt(u64)
            else
                null;
            var runner = try Runner.init(gpa, .{ .seed = seed, .timeout_ns = timeout_ns });
            defer runner.deinit();
            return try runner.start_context(run_in_context, .{ self, &runner });
        }

        /// At most one random crash strategy and one delay may be configured, and every
        /// processed-height crash names a participant.
        pub fn validate(self: *const Self) Error!void {
            var random: usize = 0;
            var delays: usize = 0;
            for (self.crashes) |crash| switch (crash) {
                .random => random += 1,
                .delay_round => delays += 1,
                .processed_height => |window| if (window.participants.len == 0) {
                    return error.EmptyCrashParticipants;
                },
                .schedule => {},
            };
            if (random > 1 or delays > 1) return error.DuplicateCrashStrategy;
            assert(random <= 1 and delays <= 1);
        }

        /// Runs `plan` inside an already running deterministic runtime (commonware's
        /// `run_inner`), for tests that share the runtime with the plan.
        pub fn run_in_context(ctx: Context, plan: *const Self, runner: *Runner) anyerror!Result {
            const gpa = ctx.gpa();
            try plan.validate();
            if (plan.storage_fault) |faults| {
                runner.storage_fault_config().* = faults;
                log.info("enabled storage fault injection", .{});
            }
            const participants = plan.engine.participants();
            const network = try Network.init(gpa, ctx.io(), .{
                .max_size = plan.engine.max_message_size(),
                .max_peers_per_set = participants.len,
                .disconnect_on_block = true,
                .tracked_peer_sets = 1,
            });
            defer network.deinit();
            const network_task = try ctx.child("network").spawn(run_network, .{network});
            defer {
                network.close();
                network_task.join() catch {};
            }
            try track(gpa, network, participants);
            const state = try Run.create(ctx, plan, runner, network);
            defer state.destroy();
            return state.execute();
        }

        fn run_network(_: Context, network: *Network) void {
            network.run() catch {};
        }

        /// Seeds the participants as peer set 0 so subscriptions reconcile immediately.
        fn track(gpa: Allocator, network: *Network, participants: []const P) !void {
            const sorted = try gpa.dupe(P, participants);
            defer gpa.free(sorted);
            const Tracked = p2p.TrackedPeers(P);
            Tracked.PeerSet.sort(sorted);
            const feedback = network.oracle().manager().track(0, .init_primary(.init(sorted)));
            assert(feedback == .ok);
        }

        /// The state of one run; heap-allocated, since its spawned helpers point into it.
        const Run = struct {
            plan: *const Self,
            ctx: Context,
            runner: *Runner,
            gpa: Allocator,
            oracle: Network.Oracle,
            events: Events,
            team: Team,
            tracker: Tracker,
            default_exit: exit.MinimumFinalizations,
            /// Whether each participant starts delayed.
            delayed: []bool,
            delayed_count: usize,
            delayed_started: bool = false,
            /// Whether each `Crash.processed_height` (by crash index) has triggered.
            triggered: []bool,
            crashes: u64 = 0,
            scheduled_actions: std.atomic.Value(u64) = .init(0),
            /// Helper tasks: the crash ticker, schedulers, and restart delays.
            helpers: std.ArrayList(Handle) = .empty,
            /// Scratch for listing states and indices.
            states: []*const S,
            indices: []usize,

            fn create(ctx: Context, plan: *const Self, runner: *Runner, network: *Network) !*Run {
                const gpa = ctx.gpa();
                const n = plan.engine.participants().len;
                const sim = try gpa.create(Run);
                errdefer gpa.destroy(sim);
                var team = try Team.init(gpa, plan.engine);
                errdefer team.deinit();
                const delayed = try gpa.alloc(bool, n);
                errdefer gpa.free(delayed);
                const triggered = try gpa.alloc(bool, plan.crashes.len);
                errdefer gpa.free(triggered);
                @memset(triggered, false);
                const states = try gpa.alloc(*const S, n);
                errdefer gpa.free(states);
                const indices = try gpa.alloc(usize, n);
                sim.* = .{
                    .plan = plan,
                    .ctx = ctx,
                    .runner = runner,
                    .gpa = gpa,
                    .oracle = network.oracle(),
                    .events = .init(gpa, ctx.io()),
                    .team = team,
                    .tracker = .init(gpa),
                    .default_exit = .{ .required = plan.required_finalizations },
                    .delayed = delayed,
                    .delayed_count = 0,
                    .triggered = triggered,
                    .states = states,
                    .indices = indices,
                };
                try sim.mark_delayed();
                return sim;
            }

            /// Stops every helper and validator, then frees the run.
            fn destroy(sim: *Run) void {
                const gpa = sim.gpa;
                sim.events.close();
                for (sim.helpers.items) |helper| helper.abort() catch {};
                sim.helpers.deinit(gpa);
                sim.team.deinit();
                sim.tracker.deinit();
                sim.events.deinit();
                gpa.free(sim.indices);
                gpa.free(sim.states);
                gpa.free(sim.triggered);
                gpa.free(sim.delayed);
                gpa.destroy(sim);
            }

            /// Marks the participants of the first `Crash.delay_round` as delayed.
            fn mark_delayed(sim: *Run) !void {
                @memset(sim.delayed, false);
                for (sim.plan.crashes) |crash| {
                    const delay = switch (crash) {
                        .delay_round => |delay| delay,
                        else => continue,
                    };
                    for (delay.participants) |pk| {
                        const index = sim.team.index_of(pk) orelse return error.UnknownParticipant;
                        if (!sim.delayed[index]) sim.delayed_count += 1;
                        sim.delayed[index] = true;
                    }
                    return;
                }
            }

            fn exit_condition(sim: *const Run) Exit {
                return sim.plan.exit_condition orelse .from(&sim.default_exit);
            }

            fn monitor(sim: *Run) events_module.Monitor(P) {
                return .{ .events = &sim.events };
            }

            fn faults(sim: *Run) *const action.FaultConfig {
                return sim.runner.storage_fault_config();
            }

            fn start_validator(sim: *Run, index: usize, delayed: bool) !void {
                const reporter = sim.monitor();
                try sim.team.start_one(sim.ctx, sim.oracle, index, reporter, delayed, sim.faults());
            }

            fn execute(sim: *Run) anyerror!Result {
                const plan = sim.plan;
                try sim.team.start(
                    sim.ctx,
                    sim.oracle,
                    plan.link,
                    sim.monitor(),
                    sim.delayed,
                    sim.faults(),
                );
                try sim.spawn_helpers();
                while (true) {
                    const event = try sim.events.next(exit_poll) orelse {
                        if (sim.exit_condition().requires_polling and try sim.exit_reached()) break;
                        continue;
                    };
                    defer sim.events.release(event);
                    if (try sim.handle_event(event)) break;
                }
                return sim.complete();
            }

            /// Handles one event; returns whether the exit condition now holds.
            fn handle_event(sim: *Run, event: Events.Event) !bool {
                switch (event) {
                    .report => |report| {
                        try sim.tracker.observe(report.update());
                        try sim.trigger_processed_height_crashes();
                        try sim.check_finalization();
                        if (try sim.exit_reached()) return true;
                        try sim.start_delayed_if_reached();
                    },
                    .restart => |pk| try sim.restart(pk),
                    .crash => |pk| {
                        const index = sim.team.index_of(pk) orelse return error.UnknownParticipant;
                        if (sim.team.crash(index)) sim.crashes += 1;
                    },
                    .crash_tick => try sim.crash_random(),
                }
                return false;
            }

            fn restart(sim: *Run, pk: P) !void {
                const index = sim.team.index_of(pk) orelse return error.UnknownParticipant;
                const delayed = sim.delayed[index];
                log.info("restarting validator {d}", .{index});
                try sim.start_validator(index, delayed);
            }

            /// Whether the exit condition holds for the validators that must satisfy it now.
            fn exit_reached(sim: *Run) !bool {
                const n = sim.delayed.len;
                const target = if (sim.delayed_started) n else n - sim.delayed_count;
                const states = sim.team.active_states(sim.states);
                const condition = sim.exit_condition();
                return condition.reached(&sim.tracker, states, target) catch |err| {
                    log.info("exit condition {s} failed: {t}", .{ condition.name, err });
                    return error.ExitConditionFailed;
                };
            }

            fn check_finalization(sim: *Run) !void {
                const states = sim.team.active_states(sim.states);
                for (sim.plan.finalization_properties) |check| {
                    check.check(states) catch |err| {
                        log.info("finalization property {s} failed: {t}", .{ check.name, err });
                        return error.FinalizationPropertyViolation;
                    };
                }
            }

            /// Stops accepting reports, checks those already queued, then the post-run
            /// properties and that every configured fault was exercised.
            fn complete(sim: *Run) !Result {
                sim.events.close();
                while (try sim.events.next(.fromNanoseconds(0))) |event| {
                    defer sim.events.release(event);
                    const report = switch (event) {
                        .report => |report| report,
                        else => continue,
                    };
                    try sim.tracker.observe(report.update());
                    try sim.check_finalization();
                }
                const states = sim.team.active_states(sim.states);
                for (sim.plan.properties) |check| {
                    check.check(&sim.tracker, states) catch |err| {
                        log.info("post-run property {s} failed: {t}", .{ check.name, err });
                        return error.PropertyViolation;
                    };
                }
                try sim.check_exercised();
                const result: Result = .{
                    .state = sim.runner.auditor.state(),
                    .tracker = sim.tracker,
                    .crashes = sim.crashes,
                    .scheduled_actions = sim.scheduled_actions.load(.monotonic),
                    .delayed_started = sim.delayed_started,
                };
                sim.tracker = .init(sim.gpa);
                return result;
            }

            /// Fails if a configured crash strategy never took effect.
            fn check_exercised(sim: *const Run) Error!void {
                var scheduled: usize = 0;
                var random = false;
                var delayed = false;
                for (sim.plan.crashes, sim.triggered) |crash, triggered| switch (crash) {
                    .random => random = true,
                    .schedule => |schedule| scheduled += schedule.events.items.len,
                    .delay_round => delayed = true,
                    .processed_height => if (!triggered) {
                        return error.ProcessedHeightCrashNotReached;
                    },
                };
                if (random and sim.crashes == 0) return error.RandomCrashesNotExercised;
                const applied = sim.scheduled_actions.load(.monotonic);
                if (scheduled > 0 and applied == 0) return error.ScheduleNotExercised;
                if (delayed and !sim.delayed_started) return error.DelayedNeverStarted;
            }

            /// Crashes the participants of each processed-height window together once all of
            /// them run and report a height inside it.
            fn trigger_processed_height_crashes(sim: *Run) !void {
                for (sim.plan.crashes, sim.triggered) |crash, *triggered| {
                    const window = switch (crash) {
                        .processed_height => |window| window,
                        else => continue,
                    };
                    if (triggered.*) continue;
                    if (!try sim.processed_height_due(window.participants, window.heights)) {
                        continue;
                    }
                    triggered.* = true;
                    for (window.participants) |pk| {
                        const index = sim.team.index_of(pk) orelse unreachable; // Checked above.
                        if (!sim.team.crash(index)) continue;
                        sim.crashes += 1;
                        try sim.restart_after(pk, window.downtime);
                    }
                }
            }

            /// Whether every participant runs and reports a height inside `heights`. Checks
            /// every participant, so a running one past the window fails the run even while
            /// another is stopped or behind.
            fn processed_height_due(
                sim: *const Run,
                participants: []const P,
                heights: action.HeightRange,
            ) Error!bool {
                assert(participants.len > 0);
                var due = true;
                for (participants) |pk| {
                    const index = sim.team.index_of(pk) orelse return error.UnknownParticipant;
                    const height = sim.team.processed_height(index) orelse {
                        due = false;
                        continue;
                    };
                    if (height > heights.max) return error.SkippedProcessedHeightWindow;
                    if (height < heights.min) due = false;
                }
                return due;
            }

            /// Starts the delayed validators, in random order, once a delay round is reached.
            fn start_delayed_if_reached(sim: *Run) !void {
                if (sim.delayed_started or sim.delayed_count == 0 or !sim.delay_reached()) return;
                log.info("starting delayed participants", .{});
                var count: usize = 0;
                for (sim.team.order) |index| {
                    if (!sim.delayed[index]) continue;
                    sim.indices[count] = index;
                    count += 1;
                }
                const order = sim.indices[0..count];
                shuffle(sim.ctx.io(), order, order.len);
                for (order) |index| {
                    try sim.start_validator(index, true);
                }
                sim.delayed_started = true;
            }

            fn delay_reached(sim: *const Run) bool {
                const max = sim.tracker.max_round() orelse return false;
                for (sim.plan.crashes) |crash| switch (crash) {
                    .delay_round => |delay| if (max.order(delay.round) != .lt) return true,
                    else => {},
                };
                return false;
            }

            /// Crashes up to `count` random running validators, restarting each after the
            /// downtime (`Crash.random`).
            fn crash_random(sim: *Run) !void {
                const config = sim.random_crash() orelse return;
                const active = sim.team.active_indices(sim.indices);
                const count = @min(config.count, active.len);
                shuffle(sim.ctx.io(), active, count);
                for (active[0..count]) |index| {
                    if (!sim.team.crash(index)) continue;
                    sim.crashes += 1;
                    try sim.restart_after(sim.team.participants[index], config.downtime);
                }
            }

            fn random_crash(sim: *const Run) ?@FieldType(action.Crash(P), "random") {
                for (sim.plan.crashes) |crash| switch (crash) {
                    .random => |config| return config,
                    else => {},
                };
                return null;
            }

            fn spawn_helpers(sim: *Run) !void {
                try sim.helpers.ensureUnusedCapacity(sim.gpa, sim.plan.crashes.len);
                if (sim.random_crash()) |config| {
                    const ticker = try sim.ctx.child("crash_ticker")
                        .spawn(crash_ticker, .{ &sim.events, config.frequency });
                    sim.helpers.appendAssumeCapacity(ticker);
                }
                for (sim.plan.crashes) |crash| {
                    const schedule = switch (crash) {
                        .schedule => |schedule| schedule,
                        else => continue,
                    };
                    const scheduler_ctx = sim.ctx.child("scheduler");
                    const handle = try scheduler_ctx.spawn(scheduler, .{ sim, schedule });
                    sim.helpers.appendAssumeCapacity(handle);
                }
            }

            fn restart_after(sim: *Run, pk: P, downtime: Duration) !void {
                try sim.helpers.ensureUnusedCapacity(sim.gpa, 1);
                const handle = try sim.ctx.child("restart_delay")
                    .spawn(restart_task, .{ &sim.events, pk, downtime });
                sim.helpers.appendAssumeCapacity(handle);
            }

            fn restart_task(ctx: Context, queue: *Events, pk: P, downtime: Duration) void {
                if (downtime.as_nanos() > 0) ctx.sleep(io_duration(downtime)) catch return;
                _ = queue.push(.{ .restart = pk });
            }

            fn crash_ticker(ctx: Context, queue: *Events, frequency: Duration) void {
                while (true) {
                    ctx.sleep(io_duration(frequency)) catch return;
                    if (!queue.push(.crash_tick)) return;
                }
            }

            /// Sleeps until each scheduled time and applies its action: network and storage
            /// actions directly, crashes and restarts through the event queue.
            fn scheduler(ctx: Context, sim: *Run, schedule: *const action.Schedule(P)) void {
                const start = ctx.current().nanoseconds;
                for (schedule.events.items) |event| {
                    const elapsed = ctx.current().nanoseconds - start;
                    const at: i96 = @intCast(event.at.as_nanos());
                    if (at > elapsed) ctx.sleep(.fromNanoseconds(at - elapsed)) catch return;
                    if (!sim.apply(event.action)) return;
                    _ = sim.scheduled_actions.fetchAdd(1, .monotonic);
                }
            }

            /// Applies a scheduled action; false once the plan stopped accepting events.
            fn apply(sim: *Run, scheduled: action.Action(P)) bool {
                switch (scheduled) {
                    .set_storage_fault => |config| sim.runner.storage_fault_config().* = config,
                    .heal => |link| {
                        for (sim.team.participants) |from| {
                            for (sim.team.participants) |to| {
                                if (from.order(to) == .eq) continue;
                                sim.relink(from, to, link);
                            }
                        }
                    },
                    .update_link => |update| sim.relink(update.from, update.to, update.link),
                    .crash => |pk| return sim.events.push(.{ .crash = pk }),
                    .restart => |pk| return sim.events.push(.{ .restart = pk }),
                }
                return true;
            }

            fn relink(sim: *Run, from: P, to: P, link: Link) void {
                sim.oracle.remove_link(from, to) catch {};
                sim.oracle.add_link(from, to, link) catch {};
            }
        };
    };
}

fn io_duration(duration: Duration) Io.Duration {
    const nanos = std.math.cast(i96, duration.as_nanos()) orelse std.math.maxInt(i96);
    return .fromNanoseconds(nanos);
}

/// Moves `count` uniformly chosen items of `items` to its front (a partial Fisher-Yates
/// shuffle on the runtime's RNG).
fn shuffle(io: Io, items: []usize, count: usize) void {
    assert(count <= items.len);
    for (0..count) |i| {
        var bytes: [8]u8 = undefined;
        io.random(&bytes);
        const span = items.len - i;
        const j = i + @as(usize, @intCast(std.mem.readInt(u64, &bytes, .little) % span));
        std.mem.swap(usize, &items[i], &items[j]);
    }
}
