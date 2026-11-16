//! Adaptive execution policies for collection operations and spawned jobs (commonware's
//! `parallel/src/policy.rs`).
//!
//! Entries are keyed by call site, input-size bucket, work-size bucket, and planning parallelism
//! so a decision learned for one workload does not leak into another. Each entry keeps
//! wall-clock estimates of its paths and prefers the faster, with ties going to serial (equal
//! wall time for fewer busy workers).
//!
//! A `Cadence` probes the losing path on an interval that grows with how badly it lost. A stale
//! loser estimate never suppresses its probes, so an estimate skewed by transient conditions,
//! such as pool contention at startup, can recover.
//!
//! Serial budget: wall time decides which path is faster, and busy time decides whether serial
//! is affordable. A parallel run's busy time is the time its threads spend executing it and
//! approximates the cost of the same run on one thread, so serial is seeded or probed only while
//! the parallel busy-time estimate fits under `serial_sample_budget_ns`, and preferred only
//! while the serial estimate fits too. Queueing lengthens a parallel run's wall time but not its
//! busy time, so contention steers callers toward serial while it stays affordable.
//!
//! Placement: each run entry learns a `Placement` (the whole pool or one group of workers) as a
//! `Choice`, with its own serial-versus-parallel cadence per placement. A confined caller
//! compares serial against its own placement, and a caller with a choice against the preferred
//! one. zigware's pool is one group, so `Rayon` confines its callers to `wide`; the choice is
//! ported so a grouped pool can use it.
//!
//! Spawned jobs compare a job's estimated wall time against the overhead of offloading it.
//! Callers outside the pool share one hand-off overhead estimate and cadence; workers keep their
//! own.
//!
//! Fallible operations record samples only on success: an early error's short wall time would
//! drag an estimate down. Both paths produce identical results, so a misjudged call costs only
//! throughput.
//!
//! zigware differences: a call site is the caller's return address (Zig has no
//! `#[track_caller]`), and the entry tables are bounded (`run_entries_max`,
//! `spawn_entries_max`): a key that finds its table full runs parallel or offloaded, untimed.
//! A return address is a machine call site, not a source one: in optimized builds a caller that
//! is inlined, or a loop that is unrolled, splits one source call into several entries, each
//! learning (and taking table space) on its own, so learning takes longer than in Debug.
//! Keying by source location would need an `@src()` argument on every operation.

const std = @import("std");
const assert = std.debug.assert;

/// Calls between samples of the preferred path, so its estimate does not go stale.
pub const preferred_sample_interval: u32 = 10;
/// Calls between probes of the losing path when its estimate is within 2x of the winner's and
/// the ordering has no confirmations.
pub const resample_interval: u32 = 100;
/// The most doublings of `resample_interval` between probes (100 << 5 = 3,200 calls). Each
/// additional multiple of the winner's wall time and each confirmation of the ordering adds one.
pub const max_resample_shift: u32 = 5;
/// The estimated busy time of a parallel run, in nanoseconds, under which serial is seeded or
/// probed. Preferring serial also requires the serial wall-time estimate to fit.
pub const serial_sample_budget_ns: u64 = 10_000_000;
/// The estimated job time, in nanoseconds, within which a spawned job may run inline.
pub const spawn_inline_budget_ns: u64 = 1_000_000;
/// Weight of the previous estimate in each EWMA update.
const ewma_previous_weight: u64 = 4;
/// Weight of a new sample in each EWMA update.
const ewma_next_weight: u64 = 1;
const ewma_weight: u64 = ewma_previous_weight + ewma_next_weight;

/// The most run keys a policy learns.
pub const run_entries_max = 256;
/// The most spawn keys a policy learns.
pub const spawn_entries_max = 64;

/// The path the policy chose for a call: the strategy runs the matching serial or parallel body.
pub const RunExecution = enum { serial, parallel };

/// How the spawn policy runs a job: inline on the calling task, or handed off to a pool.
pub const SpawnExecution = enum { inlined, offload };

/// Where a parallel run's placed work runs.
pub const Placement = enum(u1) {
    /// Any worker of the strategy's pool.
    wide,
    /// The workers of one group.
    local,

    fn other(placement: Placement) Placement {
        return if (placement == .wide) .local else .wide;
    }
};

/// The placements a run's caller may use.
pub const Pools = union(enum) {
    /// Only this placement takes part in the decision.
    fixed: Placement,
    /// Wide or Local.
    either,
};

/// A population of spawning callers with its own execution cadence and overhead estimate.
pub const Spawner = enum(u1) {
    /// A worker of the strategy's pool; its round trip is not a hand-off.
    worker,
    /// A caller outside the pool, whose round trip feeds the hand-off overhead.
    outside,
};

/// A path chosen by an arbitration and whether the caller should time it.
pub fn Decision(comptime P: type) type {
    return struct { path: P, measure: bool };
}

/// The decisions for one run and whether the caller should time it.
pub const RunPlan = struct {
    execution: RunExecution,
    /// The placement a parallel run uses. A serial run always carries `wide`.
    placement: Placement,
    /// Whether the run is timed and recorded with `Policy.record_run`.
    measure: bool,
};

/// The timing of a measured run.
pub const RunSample = struct {
    wall_ns: u64,
    /// The time the run's threads spent executing it. A serial run's busy time is its wall time.
    busy_ns: u64,
};

/// The decisions for one spawned job and whether the caller should time it.
pub const SpawnPlan = struct {
    execution: SpawnExecution,
    /// The population whose overhead estimate receives an offloaded job's round-trip sample.
    spawner: Spawner = .outside,
    /// The descendant placement of an admitted external root on a grouped pool, if chosen.
    placement: ?Placement = null,
    measure: bool = false,

    /// An untimed plan to run the job on `execution`, with no learned placement choice.
    pub fn fixed(execution: SpawnExecution) SpawnPlan {
        return .{ .execution = execution };
    }
};

/// An empty, seeded, or live time estimate in nanoseconds.
pub const Estimate = union(enum) {
    empty,
    seed: u64,
    live: u64,

    pub fn get(estimate: Estimate) ?u64 {
        return switch (estimate) {
            .empty => null,
            .seed, .live => |value| value,
        };
    }

    /// Seeds from the first sample and replaces that seed if the second sample is lower. Other
    /// samples blend into the EWMA, moving the estimate by at most a fifth of the gap.
    pub fn record(estimate: *Estimate, sample_ns: u64) void {
        estimate.* = switch (estimate.*) {
            .empty => .{ .seed = sample_ns },
            .seed => |current| if (sample_ns < current)
                .{ .live = sample_ns }
            else
                .{ .live = update_ewma(current, sample_ns) },
            .live => |current| .{ .live = update_ewma(current, sample_ns) },
        };
        assert(estimate.* != .empty);
    }
};

/// Paces measurement and probing for one policy entry.
///
/// Between boundaries the preferred path is measured every `preferred_sample_interval` calls so
/// its estimate stays live. The boundary recurs every `resample_interval << shift` calls; the
/// shift sums the gap (one once the loser takes twice the winner's wall time, one more per
/// further multiple) and the confirmations (boundaries that kept the same preferred path with no
/// smaller gap), capped at `max_resample_shift`. Any call that finds the other path preferred,
/// or the gap smaller than at the latest boundary, clears the confirmations. A boundary whose
/// probe is disallowed still measures the preferred path and confirms the ordering.
pub fn Cadence(comptime P: type) type {
    return struct {
        const Self = @This();
        const Boundary = struct { path: P, shift: u32 };

        /// Calls since the latest boundary.
        since_probe: u32 = 0,
        /// The preferred path and the gap's count at the latest boundary, if any.
        boundary: ?Boundary = null,
        /// Consecutive boundaries that confirmed the ordering, at most `max_resample_shift`.
        confirmations: u32 = 0,

        /// Makes the next call a probe boundary.
        pub fn saturate(cadence: *Self) void {
            cadence.since_probe = std.math.maxInt(u32);
        }

        /// Arbitrates one call between a `preferred` and a `loser` path. The loser runs at an
        /// allowed probe boundary, and a disallowed boundary still measures the preferred path.
        pub fn arbitrate(
            cadence: *Self,
            preferred: P,
            loser: P,
            winner_ns: u64,
            loser_ns: u64,
            probe_allowed: bool,
        ) Decision(P) {
            assert(preferred != loser);
            const slowdown = loser_ns / @max(winner_ns, 1);
            const gap_shift: u32 = @intCast(@min(slowdown -| 1, max_resample_shift));
            const confirmed = if (cadence.boundary) |boundary|
                boundary.path == preferred and gap_shift >= boundary.shift
            else
                false;
            if (!confirmed) cadence.confirmations = 0;
            const shift = @min(gap_shift + cadence.confirmations, max_resample_shift);
            const interval = resample_interval << @intCast(shift);
            cadence.since_probe +|= 1;
            if (cadence.since_probe >= interval) {
                cadence.since_probe = 0;
                cadence.boundary = .{ .path = preferred, .shift = gap_shift };
                if (confirmed) {
                    cadence.confirmations = @min(cadence.confirmations + 1, max_resample_shift);
                }
                return .{ .path = if (probe_allowed) loser else preferred, .measure = true };
            }
            assert(cadence.confirmations <= max_resample_shift);
            return .{
                .path = preferred,
                .measure = cadence.since_probe % preferred_sample_interval == 0,
            };
        }
    };
}

/// A learned choice between the Wide and Local placements.
pub const Choice = struct {
    wide_ns: Estimate = .empty,
    local_ns: Estimate = .empty,
    /// The schedule for probing the slower placement.
    cadence: Cadence(Placement) = .{},

    /// The faster placement once both are measured, and Wide until then or on a tie.
    pub fn preferred(choice: *const Choice) Placement {
        const wide_ns = choice.wide_ns.get() orelse return .wide;
        const local_ns = choice.local_ns.get() orelse return .wide;
        return if (local_ns < wide_ns) .local else .wide;
    }

    pub fn estimate(choice: *const Choice, placement: Placement) ?u64 {
        return choice.estimate_ptr_const(placement).get();
    }

    fn estimate_ptr_const(choice: *const Choice, placement: Placement) *const Estimate {
        return if (placement == .wide) &choice.wide_ns else &choice.local_ns;
    }

    fn estimate_ptr(choice: *Choice, placement: Placement) *Estimate {
        return if (placement == .wide) &choice.wide_ns else &choice.local_ns;
    }

    /// Returns the placement to use and whether to measure it. A placement without an estimate
    /// is timed first, Wide before Local; then the faster is preferred and the other probed on
    /// this choice's cadence, paced against the faster of the preferred placement and
    /// `rival_ns` (another path the caller could take).
    pub fn choose(choice: *Choice, rival_ns: ?u64) Decision(Placement) {
        const wide_ns = choice.wide_ns.get();
        const local_ns = choice.local_ns.get();
        if (wide_ns == null or local_ns == null) {
            // Saturating keeps the choice due for a boundary while it seeds.
            choice.cadence.saturate();
            return .{ .path = if (wide_ns == null) .wide else .local, .measure = true };
        }
        const preferred_placement = choice.preferred();
        const loser = preferred_placement.other();
        var winner = choice.estimate(preferred_placement).?;
        if (rival_ns) |rival| winner = @min(winner, rival);
        const loser_ns = choice.estimate(loser).?;
        return choice.cadence.arbitrate(preferred_placement, loser, winner, loser_ns, true);
    }

    /// Folds `sample_ns` into the estimate of `placement`.
    pub fn record(choice: *Choice, placement: Placement, sample_ns: u64) void {
        choice.estimate_ptr(placement).record(sample_ns);
    }

    /// Records a spawned root's descendant-placement sample. Lower samples of the losing
    /// placement take effect at once so its infrequent probes do not retain old delays.
    pub fn record_spawn(choice: *Choice, placement: Placement, sample_ns: u64) void {
        const loser = placement != choice.preferred();
        const target = choice.estimate_ptr(placement);
        if (target.get()) |current| {
            if (loser and sample_ns < current) {
                target.* = .{ .live = sample_ns };
                return;
            }
        }
        target.record(sample_ns);
    }
};

/// Timing state for one run key.
pub const RunEntry = struct {
    /// The serial wall time, shared by every caller.
    serial_ns: Estimate = .empty,
    /// The parallel wall time of each placement.
    placement: Choice = .{},
    /// The busy-time estimate of parallel runs on each placement, indexed by placement.
    busy_ns: [2]Estimate = @splat(.empty),
    /// The cadences on which serial is arbitrated against each placement.
    cadences: [2]Cadence(RunExecution) = @splat(.{}),

    /// The preferred placement's wall time, or null until it is measured.
    pub fn parallel_ns(entry: *const RunEntry) ?u64 {
        return entry.placement.estimate(entry.placement.preferred());
    }

    const Estimates = struct { parallel_ns: u64, busy_ns: u64 };

    /// The wall-time and busy-time estimates of `placement`, or null until both are measured.
    fn estimates(entry: *const RunEntry, placement: Placement) ?Estimates {
        const wall = entry.placement.estimate(placement) orelse return null;
        const busy = entry.busy_ns[@backingInt(placement)].get() orelse return null;
        return .{ .parallel_ns = wall, .busy_ns = busy };
    }

    /// Prefers the path with the lower wall-time estimate, allowing serial only when its
    /// estimate and the parallel busy-time estimate fit under the budget. Ties favor serial.
    pub fn preferred(serial: u64, parallel: u64, busy: u64) RunExecution {
        if (busy >= serial_sample_budget_ns) return .parallel;
        if (serial >= serial_sample_budget_ns) return .parallel;
        return if (parallel < serial) .parallel else .serial;
    }

    /// The serial wall-time estimate while serial is preferred over `placement`, else null.
    pub fn serial_rival_ns(entry: *const RunEntry, placement: Placement) ?u64 {
        const serial_ns = entry.serial_ns.get() orelse return null;
        const both = entry.estimates(placement) orelse return null;
        if (preferred(serial_ns, both.parallel_ns, both.busy_ns) != .serial) return null;
        return serial_ns;
    }

    /// Returns the path to run, serial or `placement`, on that placement's cadence.
    pub fn choose(entry: *RunEntry, placement: Placement) Decision(RunExecution) {
        const serial_ns = entry.serial_ns.get();
        const cadence = &entry.cadences[@backingInt(placement)];
        // Seed the placement with its first call; until serial is measured, saturating keeps
        // the cadence due so the next call offers the serial seed.
        const both = entry.estimates(placement) orelse {
            if (serial_ns == null) cadence.saturate();
            return .{ .path = .parallel, .measure = true };
        };
        // Serial is eligible only while the parallel busy time is below the budget.
        const can_sample_serial = both.busy_ns < serial_sample_budget_ns;
        // Until serial is sampled, parallel is preferred and each boundary is the seed slot.
        const serial = serial_ns orelse {
            return cadence.arbitrate(
                .parallel,
                .serial,
                both.parallel_ns,
                both.parallel_ns,
                can_sample_serial,
            );
        };
        if (preferred(serial, both.parallel_ns, both.busy_ns) == .serial) {
            return cadence.arbitrate(.serial, .parallel, serial, both.parallel_ns, true);
        }
        return cadence.arbitrate(.parallel, .serial, both.parallel_ns, serial, can_sample_serial);
    }

    /// Records a parallel run on `placement`.
    pub fn record_parallel(
        entry: *RunEntry,
        placement: Placement,
        wall_ns: u64,
        busy_ns: u64,
    ) void {
        entry.placement.record(placement, wall_ns);
        entry.busy_ns[@backingInt(placement)].record(busy_ns);
    }
};

/// Timing state for one spawn key. Inline is preferred only when the job's estimated wall
/// time is no greater than both the caller's round-trip overhead and `spawn_inline_budget_ns`.
/// The decision uses the inline wall-time estimate once one exists; while offload is preferred,
/// its probe boundary runs inline whenever the worker wall-time estimate fits the budget.
pub const SpawnEntry = struct {
    /// Descendant placement, trained only by admitted external roots on grouped pools.
    placement: Choice = .{},
    /// The hand-off overhead of a job offloaded from outside the pool.
    overhead_ns: Estimate = .empty,
    /// The job's own wall time on a pool worker.
    job_ns: Estimate = .empty,
    /// The job's own wall time inline on the calling task.
    inline_ns: Estimate = .empty,
    /// The round-trip overhead of jobs that workers keep in their own pools.
    own_overhead_ns: Estimate = .empty,
    /// The cadence of each `Spawner`.
    cadences: [2]Cadence(SpawnExecution) = @splat(.{}),

    /// Decides, on `spawner`'s cadence, whether its call runs inline or offloaded. `budget`
    /// caps the job wall eligible for inlining.
    pub fn choose(entry: *SpawnEntry, spawner: Spawner, budget: u64) Decision(SpawnExecution) {
        const overhead = switch (spawner) {
            .worker => entry.own_overhead_ns,
            .outside => entry.overhead_ns,
        };
        const cadence = &entry.cadences[@backingInt(spawner)];
        // Seed both offload estimates before ever inlining.
        const overhead_ns = overhead.get();
        const job_ns = entry.job_ns.get();
        if (overhead_ns == null or job_ns == null) {
            cadence.saturate();
            return .{ .path = .offload, .measure = true };
        }
        // Ties favor inline. Inline probes check the budget against the worker's wall time, so
        // an old, high inline estimate can recover; offload probes are always allowed.
        const bound = entry.inline_ns.get() orelse job_ns.?;
        const threshold = @min(overhead_ns.?, budget);
        if (bound > threshold) {
            return cadence.arbitrate(.offload, .inlined, threshold, bound, job_ns.? < budget);
        }
        return cadence.arbitrate(.inlined, .offload, bound, threshold, true);
    }
};

/// Identifies a stream of similar calls.
pub const Key = struct {
    site: usize,
    len_bucket: u8,
    work_bucket: u8,
    parallelism: usize,

    pub fn init(site: usize, len: usize, work: usize, parallelism: usize) Key {
        return .{
            .site = site,
            .len_bucket = len_bucket(len),
            .work_bucket = len_bucket(work),
            .parallelism = parallelism,
        };
    }
};

fn Table(comptime Entry: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();
        keys: [capacity]Key = undefined,
        entries: [capacity]Entry = undefined,
        len: usize = 0,

        fn get(table: *Self, key: Key) ?*Entry {
            for (table.keys[0..table.len], 0..) |existing, index| {
                if (std.meta.eql(existing, key)) return &table.entries[index];
            }
            return null;
        }

        /// The entry for `key`, created if absent, or null when the table is full.
        fn get_or_put(table: *Self, key: Key) ?*Entry {
            if (table.get(key)) |entry| return entry;
            if (table.len == capacity) return null;
            table.keys[table.len] = key;
            table.entries[table.len] = .{};
            table.len += 1;
            assert(table.len <= capacity);
            return &table.entries[table.len - 1];
        }
    };
}

/// Adaptive execution decisions (serial vs parallel for collection operations, inline vs
/// offload for spawned jobs), shared by the strategies that point at it. One lock serializes
/// updates; no lock is held while work runs.
pub const Policy = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    run_entries: Table(RunEntry, run_entries_max) = .{},
    spawn_entries: Table(SpawnEntry, spawn_entries_max) = .{},

    pub fn init(io: std.Io) Policy {
        return .{ .io = io };
    }

    fn lock(policy: *Policy) void {
        policy.mutex.lockUncancelable(policy.io);
    }

    fn unlock(policy: *Policy) void {
        policy.mutex.unlock(policy.io);
    }

    /// Run keys learned so far.
    pub fn len(policy: *Policy) usize {
        policy.lock();
        defer policy.unlock();
        return policy.run_entries.len;
    }

    /// Spawn keys learned so far.
    pub fn spawn_len(policy: *Policy) usize {
        policy.lock();
        defer policy.unlock();
        return policy.spawn_entries.len;
    }

    /// Chooses the execution path for this call site and, for a parallel run, the placement.
    pub fn choose_run(
        policy: *Policy,
        site: usize,
        len_items: usize,
        work: usize,
        parallelism: usize,
        pools: Pools,
    ) RunPlan {
        var plan: RunPlan = .{ .execution = .serial, .placement = .wide, .measure = false };
        // A strategy configured for serial execution never spends a measurement on it.
        if (parallelism <= 1) return plan;
        policy.lock();
        defer policy.unlock();
        const key = Key.init(site, len_items, work, parallelism);
        const entry = policy.run_entries.get_or_put(key) orelse {
            plan.execution = .parallel;
            plan.placement = if (pools == .fixed) pools.fixed else .wide;
            return plan;
        };
        switch (pools) {
            .fixed => |placement| {
                const decision = entry.choose(placement);
                plan.execution = decision.path;
                plan.measure = decision.measure;
                if (decision.path == .parallel) plan.placement = placement;
                return plan;
            },
            .either => return choose_either(entry),
        }
    }

    /// A caller with a choice consults the placement first. A placement seed or probe takes the
    /// call as a timed parallel run without arbitrating either execution cadence.
    fn choose_either(entry: *RunEntry) RunPlan {
        const preferred = entry.placement.preferred();
        const serial_ns = entry.serial_ns.get();
        const rival_ns = entry.serial_rival_ns(preferred);
        const placement = entry.placement.choose(rival_ns).path;
        if (placement == preferred) {
            const decision = entry.choose(preferred);
            // A serial run always carries `wide`.
            const used: Placement = if (decision.path == .parallel) placement else .wide;
            return .{ .execution = decision.path, .placement = used, .measure = decision.measure };
        }
        // Until serial is measured, a placement's first sample leaves its serial comparison due.
        if (serial_ns == null and entry.placement.estimate(placement) == null) {
            entry.cadences[@backingInt(placement)].saturate();
        }
        return .{ .execution = .parallel, .placement = placement, .measure = true };
    }

    /// Records a run that followed `plan`. A serial run records only its wall time.
    pub fn record_run(
        policy: *Policy,
        site: usize,
        len_items: usize,
        work: usize,
        parallelism: usize,
        plan: RunPlan,
        sample: RunSample,
    ) void {
        if (parallelism <= 1) return;
        policy.lock();
        defer policy.unlock();
        const key = Key.init(site, len_items, work, parallelism);
        const entry = policy.run_entries.get_or_put(key) orelse return;
        switch (plan.execution) {
            .serial => entry.serial_ns.record(sample.wall_ns),
            .parallel => entry.record_parallel(plan.placement, sample.wall_ns, sample.busy_ns),
        }
    }

    /// Plans a spawned job, including whether the caller should time it.
    pub fn choose_spawn(
        policy: *Policy,
        site: usize,
        len_items: usize,
        parallelism: usize,
        spawner: Spawner,
    ) SpawnPlan {
        // A single worker cannot overlap a hand-off, so always inline.
        var plan: SpawnPlan = .fixed(.inlined);
        if (parallelism <= 1) return plan;
        policy.lock();
        defer policy.unlock();
        plan.spawner = spawner;
        const key = Key.init(site, len_items, len_items, parallelism);
        const entry = policy.spawn_entries.get_or_put(key) orelse {
            plan.execution = .offload;
            return plan;
        };
        const decision = entry.choose(spawner, spawn_inline_budget_ns);
        plan.execution = decision.path;
        plan.measure = decision.measure;
        return plan;
    }

    /// Chooses descendants' placement after a group admits an external root.
    pub fn choose_spawn_placement(
        policy: *Policy,
        site: usize,
        len_items: usize,
        parallelism: usize,
        plan: SpawnPlan,
    ) SpawnPlan {
        assert(plan.execution == .offload and plan.spawner == .outside);
        assert(plan.placement == null);
        policy.lock();
        defer policy.unlock();
        var placed = plan;
        const key = Key.init(site, len_items, len_items, parallelism);
        const entry = policy.spawn_entries.get_or_put(key) orelse {
            placed.placement = .wide;
            return placed;
        };
        const decision = entry.placement.choose(null);
        placed.placement = decision.path;
        placed.measure = placed.measure or decision.measure;
        return placed;
    }

    /// Records the wall time of a spawned job that ran inline on the calling task.
    pub fn record_spawn_inline(
        policy: *Policy,
        site: usize,
        len_items: usize,
        parallelism: usize,
        job_ns: u64,
    ) void {
        const entry = policy.lock_spawn(site, len_items, parallelism) orelse return;
        defer policy.unlock();
        entry.inline_ns.record(job_ns);
    }

    /// Records the wall time of a spawned job that ran on a pool worker.
    pub fn record_spawn_job(
        policy: *Policy,
        site: usize,
        len_items: usize,
        parallelism: usize,
        plan: SpawnPlan,
        job_ns: u64,
    ) void {
        const entry = policy.lock_spawn(site, len_items, parallelism) orelse return;
        defer policy.unlock();
        entry.job_ns.record(job_ns);
        if (plan.placement) |placement| entry.placement.record_spawn(placement, job_ns);
    }

    /// Records one offloaded spawn's round trip under `plan`: the round trip minus the job feeds
    /// the hand-off overhead, or the overhead kept for workers.
    pub fn record_spawn_round_trip(
        policy: *Policy,
        site: usize,
        len_items: usize,
        parallelism: usize,
        plan: SpawnPlan,
        round_trip_ns: u64,
        job_ns: u64,
    ) void {
        const entry = policy.lock_spawn(site, len_items, parallelism) orelse return;
        defer policy.unlock();
        const overhead = round_trip_ns -| job_ns;
        switch (plan.spawner) {
            .worker => entry.own_overhead_ns.record(overhead),
            .outside => entry.overhead_ns.record(overhead),
        }
    }

    /// Locks the policy and returns the spawn entry for this call site, or returns null with
    /// the policy unlocked.
    fn lock_spawn(policy: *Policy, site: usize, len_items: usize, parallelism: usize) ?*SpawnEntry {
        if (parallelism <= 1) return null;
        policy.lock();
        const key = Key.init(site, len_items, len_items, parallelism);
        return policy.spawn_entries.get_or_put(key) orelse {
            policy.unlock();
            return null;
        };
    }

    /// The run entry for this call site, if learned. Tests read its estimates.
    pub fn run_entry(
        policy: *Policy,
        site: usize,
        len_items: usize,
        work: usize,
        parallelism: usize,
    ) ?RunEntry {
        policy.lock();
        defer policy.unlock();
        const key = Key.init(site, len_items, work, parallelism);
        const entry = policy.run_entries.get(key) orelse return null;
        return entry.*;
    }

    /// The spawn entry for this call site, if learned. Tests read its estimates.
    pub fn spawn_entry(
        policy: *Policy,
        site: usize,
        len_items: usize,
        parallelism: usize,
    ) ?SpawnEntry {
        policy.lock();
        defer policy.unlock();
        const key = Key.init(site, len_items, len_items, parallelism);
        const entry = policy.spawn_entries.get(key) orelse return null;
        return entry.*;
    }
};

fn update_ewma(current: u64, next: u64) u64 {
    const weighted = @as(u128, current) * ewma_previous_weight + @as(u128, next) * ewma_next_weight;
    return std.math.cast(u64, weighted / ewma_weight) orelse std.math.maxInt(u64);
}

/// The power-of-two bucket of `len`, which bounds policy growth and avoids overfitting to tiny
/// input differences.
pub fn len_bucket(len: usize) u8 {
    if (len == 0) return 0;
    return @intCast(@bitSizeOf(usize) - @clz(len));
}

test {
    _ = @import("policy_tests.zig");
}
