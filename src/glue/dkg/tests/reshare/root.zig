//! commonware `glue::dkg::tests::reshare` (mod.rs): reshare ceremonies end to end over many
//! epochs, each on the discovery and the lookup network; see docs/lanes/glue.md.
//! Commonware's `slow` group runs only with -Dslow-tests; the single-participant test always
//! runs.

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const assert = std.debug.assert;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const simulate = @import("../../../simulate/mod.zig");
const harness = @import("harness.zig");
const properties = @import("properties.zig");

const gpa = testing.allocator;
const SharingMode = cryptography.bls12381.primitives.sharing.Mode;
const S = harness.ValidatorState;
const Network = harness.lookup.Network;

/// commonware's `case::discovery` and `case::lookup`.
const networks = [_]Network{ .discovery, .lookup };

/// The most epochs a plan checks `SchemesRegistered` for.
const max_scheme_epochs = 8;

fn skip_slow() error{SkipZigTest}!void {
    if (!build_options.slow_tests) return error.SkipZigTest;
}

/// One plan's shape (commonware's `*_plan` builders in mod.rs).
const Options = struct {
    final_epoch: u64,
    seed: u64 = 0,
    timeout_secs: u64 = 60,
    /// `BoundaryEpochInfos::with_min_successes`; null requires every boundary to succeed.
    min_successes: ?u64 = null,
    no_reveals: bool = true,
    /// `failed_carry_over_plan`: a `FailedCeremonyCarryOver` per epoch.
    failed: []const u64 = &.{},
    /// `with_scheme_properties`: `SchemesRegistered` for epochs 1 through `final_epoch + 1`.
    schemes: bool = true,
    link: p2p.simulated.Link = harness.good_link,
    crashes: []const simulate.action.Crash(harness.Key) = &.{},
    /// `crash_storm_plan`: exit once every participant is active at the final height, and
    /// check `AllNodesRecovered`.
    recovery: bool = false,
    /// `BoundaryOutputMode` for epoch zero.
    output_mode: ?SharingMode = null,
};

/// Runs a plan to `options.final_epoch`'s last block with `SignerRegistered`,
/// `BoundaryEpochInfos`, and `EpochInfoContinuity` (`reshare_plan_with_boundary`), plus the
/// properties `options` adds.
/// Returns the runtime's audit state.
fn run_reshare(engine: *harness.ReshareEngine, options: Options) ![8]u8 {
    const final_epoch = options.final_epoch;
    const epochs: usize = @intCast(final_epoch + 1);
    assert(epochs <= max_scheme_epochs);
    assert(options.failed.len <= max_scheme_epochs);
    const height = properties.final_height(final_epoch);
    const exit: simulate.exit.ProcessedHeightAtLeast = .{ .required = height };
    const all_active: properties.AllActiveProcessedHeight = .{
        .required = height,
        .participants = engine.participants().len,
    };
    const recovered: properties.AllNodesRecovered(S) = .{ .public_keys = engine.participants() };
    const signer: properties.SignerRegistered(S) = .{};
    var boundary = properties.BoundaryEpochInfos(S).init(gpa, final_epoch + 1);
    boundary.no_reveals = options.no_reveals;
    if (options.min_successes) |min| boundary.min_successes = min;
    const continuity: properties.EpochInfoContinuity(S) = .{
        .gpa = gpa,
        .epochs = final_epoch + 1,
        .schedule = engine.schedule(),
    };
    var checks: [5 + 2 * max_scheme_epochs]harness.Plan.Property = undefined;
    checks[0] = .from(&signer);
    checks[1] = .from(&boundary);
    checks[2] = .from(&continuity);
    var count: usize = 3;
    if (options.recovery) {
        checks[count] = .from(&recovered);
        count += 1;
    }
    var output_mode: properties.BoundaryOutputMode(S) = undefined;
    if (options.output_mode) |mode| {
        output_mode = .{ .gpa = gpa, .epoch = 0, .mode = @backingInt(mode) };
        checks[count] = .from(&output_mode);
        count += 1;
    }
    var schemes: [max_scheme_epochs]properties.SchemesRegistered(S) = undefined;
    if (options.schemes) {
        for (schemes[0..epochs], 1..) |*scheme, epoch| {
            scheme.* = .{ .gpa = gpa, .public_keys = engine.participants(), .epoch = epoch };
            checks[count] = .from(scheme);
            count += 1;
        }
    }
    var carried: [max_scheme_epochs]properties.FailedCeremonyCarryOver(S) = undefined;
    for (carried[0..options.failed.len], options.failed) |*carry, epoch| {
        carry.* = .{ .gpa = gpa, .epoch = epoch, .schedule = engine.schedule() };
        checks[count] = .from(carry);
        count += 1;
    }
    const plan: harness.Plan = .{
        .engine = engine,
        .seed = options.seed,
        .link = options.link,
        .crashes = options.crashes,
        .required_finalizations = 0,
        .exit_condition = if (options.recovery) .from(&all_active) else .from(&exit),
        .timeout = .from_secs(options.timeout_secs),
        .properties = checks[0..count],
    };
    var result = try plan.run(gpa);
    defer result.deinit();
    return result.state;
}

/// commonware `reshare_e2e_deterministic`: two runs of one seed end in the same state.
fn expect_deterministic(transport: Network, seed: u64) !void {
    var states: [2][8]u8 = undefined;
    for (&states) |*state| {
        var engine = try harness.ReshareEngine.create_on(gpa, transport);
        defer engine.deinit();
        state.* = try run_reshare(&engine, .{ .final_epoch = 1, .seed = seed, .schemes = false });
    }
    try testing.expectEqual(states[0], states[1]);
}

// commonware `reshare_e2e_deterministic`.
test "reshare e2e deterministic" {
    try skip_slow();
    for (networks) |transport| {
        try expect_deterministic(transport, 0);
    }
}

// commonware `reshare_e2e_deterministic_multiple_seeds`.
test "reshare e2e deterministic multiple seeds" {
    try skip_slow();
    for (networks) |transport| {
        for (0..3) |seed| try expect_deterministic(transport, seed);
    }
}

// commonware `reshare_e2e_single_participant_two_epochs`.
test "reshare e2e single participant two epochs" {
    for (networks) |transport| {
        var engine = try harness.ReshareEngine.with_network(gpa, transport, 1, &.{1}, 1);
        defer engine.deinit();
        _ = try run_reshare(&engine, .{ .final_epoch = 1 });
    }
}

// commonware `reshare_e2e_rotates_participants`: five validators, four players per epoch.
test "reshare e2e rotates participants" {
    try skip_slow();
    for (networks) |transport| {
        var engine = try harness.ReshareEngine.create_on(gpa, transport);
        defer engine.deinit();
        _ = try run_reshare(&engine, .{ .final_epoch = 0 });
    }
}

// commonware `reshare_e2e_multiple_epochs`.
test "reshare e2e multiple epochs" {
    try skip_slow();
    for (networks) |transport| {
        var engine = try harness.ReshareEngine.create_on(gpa, transport);
        defer engine.deinit();
        _ = try run_reshare(&engine, .{ .final_epoch = 4 });
    }
}

// commonware `reshare_e2e_four_epochs_changing_size`.
test "reshare e2e four epochs changing size" {
    try skip_slow();
    for (networks) |transport| {
        const sizes = &.{ 4, 5, 6, 7, 4 };
        var engine = try harness.ReshareEngine.with_network(gpa, transport, 8, sizes, 1);
        defer engine.deinit();
        _ = try run_reshare(&engine, .{ .final_epoch = 4 });
    }
}

// commonware `reshare_e2e_failed_ceremony_carries_committee`.
test "reshare e2e failed ceremony carries committee" {
    try skip_slow();
    for (networks) |transport| {
        var engine = try harness.ReshareEngine.create_on(gpa, transport);
        defer engine.deinit();
        engine.failures = &.{0};
        _ = try run_reshare(&engine, .{
            .final_epoch = 0,
            .min_successes = 0,
            .no_reveals = false,
            .failed = &.{0},
            .schemes = false,
        });
    }
}

// commonware `reshare_e2e_consecutive_failed_ceremonies_carry_state`.
test "reshare e2e consecutive failed ceremonies carry state" {
    try skip_slow();
    for (networks) |transport| {
        var engine = try harness.ReshareEngine.create_on(gpa, transport);
        defer engine.deinit();
        engine.failures = &.{ 0, 1 };
        _ = try run_reshare(&engine, .{
            .final_epoch = 2,
            .timeout_secs = 90,
            .min_successes = 1,
            .failed = &.{ 0, 1 },
            .schemes = false,
        });
    }
}

// commonware `reshare_e2e_many_failed_ceremonies_carry_state`.
test "reshare e2e many failed ceremonies carry state" {
    try skip_slow();
    for (networks) |transport| {
        var engine = try harness.ReshareEngine.with_network(gpa, transport, 8, &.{ 4, 5 }, 1);
        defer engine.deinit();
        engine.failures = &.{ 0, 2, 3 };
        _ = try run_reshare(&engine, .{
            .final_epoch = 4,
            .timeout_secs = 120,
            .min_successes = 2,
            .failed = &.{ 0, 2, 3 },
            .schemes = false,
        });
    }
}

/// commonware `crash_storm_plan`: every boundary must succeed despite the crashes.
fn run_crash_storm(
    transport: Network,
    final_epoch: u64,
    crash: simulate.action.Crash(harness.Key),
    seed: u64,
    timeout_secs: u64,
) !void {
    var engine = try harness.ReshareEngine.create_on(gpa, transport);
    defer engine.deinit();
    _ = try run_reshare(&engine, .{
        .final_epoch = final_epoch,
        .seed = seed,
        .timeout_secs = timeout_secs,
        .no_reveals = false,
        .crashes = &.{crash},
        .recovery = true,
    });
}

// commonware `reshare_e2e_multiple_epochs_with_random_crashes`.
test "reshare e2e multiple epochs with random crashes" {
    try skip_slow();
    for (networks) |transport| {
        const crash: simulate.action.Crash(harness.Key) = .{ .random = .{
            .frequency = .from_secs(2),
            .downtime = .from_millis(750),
            .count = 1,
        } };
        for (0..3) |seed| try run_crash_storm(transport, 4, crash, seed, 180);
    }
}

// commonware `reshare_e2e_multiple_epochs_with_many_random_crashes`.
test "reshare e2e multiple epochs with many random crashes" {
    try skip_slow();
    for (networks) |transport| {
        const crash: simulate.action.Crash(harness.Key) = .{ .random = .{
            .frequency = .from_secs(2),
            .downtime = .from_millis(750),
            .count = 3,
        } };
        try run_crash_storm(transport, 4, crash, 0, 360);
    }
}

// commonware `reshare_e2e_multiple_epochs_with_total_shutdown`: more uninterrupted uptime
// than `certification_timeout`, so recovery progresses before the next total shutdown.
test "reshare e2e multiple epochs with total shutdown" {
    try skip_slow();
    for (networks) |transport| {
        const crash: simulate.action.Crash(harness.Key) = .{ .random = .{
            .frequency = .from_secs(4),
            .downtime = .from_secs(1),
            .count = 5,
        } };
        try run_crash_storm(transport, 3, crash, 0, 180);
    }
}

// commonware `reshare_e2e_rotating_subset`.
test "reshare e2e rotating subset" {
    try skip_slow();
    for (networks) |transport| {
        var engine = try harness.ReshareEngine.with_network(gpa, transport, 7, &.{4}, 1);
        defer engine.deinit();
        _ = try run_reshare(&engine, .{ .final_epoch = 0 });
    }
}

// commonware `reshare_e2e_lossy_network`.
test "reshare e2e lossy network" {
    try skip_slow();
    for (networks) |transport| {
        var engine = try harness.ReshareEngine.create_on(gpa, transport);
        defer engine.deinit();
        _ = try run_reshare(&engine, .{
            .final_epoch = 4,
            .timeout_secs = 720,
            .min_successes = 1,
            .schemes = false,
            .link = .{
                .latency = .from_millis(100),
                .jitter = .from_millis(50),
                .success_rate = 0.7,
            },
        });
    }
}

// commonware `reshare_e2e_roots_of_unity_output`.
test "reshare e2e roots of unity output" {
    try skip_slow();
    for (networks) |transport| {
        var engine = try harness.ReshareEngine.create_on(gpa, transport);
        defer engine.deinit();
        engine.sharing_mode = .roots_of_unity;
        _ = try run_reshare(&engine, .{ .final_epoch = 0, .output_mode = .roots_of_unity });
    }
}

const epocher: consensus.types.FixedEpocher = .{ .length = properties.epoch_length };

/// Runs `crashes` until `active` validators process `height`, with no other properties.
fn run_until_active(
    engine: *harness.ReshareEngine,
    seed: u64,
    crashes: []const simulate.action.Crash(harness.Key),
    height: u64,
    active: usize,
) !void {
    const exit: properties.AllActiveProcessedHeight = .{
        .required = height,
        .participants = active,
    };
    const plan: harness.Plan = .{
        .engine = engine,
        .seed = seed,
        .link = harness.good_link,
        .crashes = crashes,
        .required_finalizations = 0,
        .exit_condition = .from(&exit),
        .timeout = .from_secs(60),
    };
    var result = try plan.run(gpa);
    result.deinit();
}

// commonware `reshare_e2e_boundary_lagging_validator`: a validator that crashed early in
// epoch 1 restarts while the rest wait on the final block. Another stops at the block before
// it, so the restarted validator completes the only possible quorum.
test "reshare e2e boundary lagging validator" {
    try skip_slow();
    for (networks) |transport| {
        const epoch: consensus.Epoch = .new(1);
        const first = epocher.first(epoch).?.get();
        const midpoint = epocher.midpoint(epoch).?.get();
        const last = properties.final_height(epoch.get());
        const stopped_at = last - 1;
        for (0..3) |seed| {
            var engine = try harness.ReshareEngine.with_network(gpa, transport, 4, &.{4}, 1);
            defer engine.deinit();
            const keys = engine.participants();
            const stopped = keys[2];
            engine.ledger.hold = .{ .key = stopped, .height = stopped_at };
            const crashes = [_]simulate.action.Crash(harness.Key){
                .{ .processed_height = .{
                    .participants = keys[3..4],
                    .heights = .{ .min = first + 1, .max = midpoint - 8 },
                    .downtime = .from_secs(10),
                } },
                // Down for the rest of the run.
                .{ .processed_height = .{
                    .participants = keys[2..3],
                    .heights = .{ .min = stopped_at, .max = stopped_at },
                    .downtime = .from_secs(3600),
                } },
            };
            try run_until_active(&engine, seed, &crashes, last, 3);
        }
    }
}

// commonware `reshare_registers_shareless_player_as_member`: a player whose epoch-zero share
// is gone before it starts registers a member scheme at its committee position, and the other
// signers finish the epoch without it.
test "reshare e2e shareless player registers as member" {
    try skip_slow();
    var engine = try harness.ReshareEngine.with_committees(gpa, 4, &.{4}, 1);
    defer engine.deinit();
    const key = engine.participants()[1];
    const index = for (engine.initial.output.players.items, 0..) |player, at| {
        if (player.eql(key)) break at;
    } else unreachable; // Every participant is an epoch-zero player here.
    try engine.stores[1].prune(.new(1));
    _ = try run_reshare(&engine, .{ .final_epoch = 0, .schemes = false });
    const expected: properties.Registration = .{
        .epoch = .zero(),
        .membership = .{ .member = .init(@intCast(index)) },
    };
    for (engine.ledger.registrations_of(key)) |registration| {
        if (registration.eql(expected)) break;
    } else return error.SharelessPlayerNotMember;
}

test {
    _ = @import("harness_test.zig");
    _ = @import("properties_test.zig");
    _ = @import("state_sync_test.zig");
}
