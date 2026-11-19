//! commonware `glue::dkg::tests::reshare` (mod.rs): the ceremonies where a delayed validator
//! joins through peer state sync, on the discovery network. Every validator runs the
//! state-sync variant (`state_sync_validator.zig`). The multi-epoch runs are in commonware's
//! `slow` group and run only with -Dslow-tests.

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const assert = std.debug.assert;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const simulate = @import("../../../simulate/mod.zig");
const harness = @import("harness.zig");
const properties = @import("properties.zig");
const support = @import("support.zig");
const block_mod = @import("state_sync_block.zig");
const app_mod = @import("state_sync_app.zig");
const ssv = @import("state_sync_validator.zig");

const gpa = testing.allocator;
const Engine = ssv.StateSyncEngine;
const S = ssv.ValidatorState;
const Key = harness.Key;
const Crash = simulate.action.Crash(Key);
const Duration = @import("utils").time.Duration;
const epoch_length = properties.epoch_length;

const RoundRobin = ssv.Validator.ElectorConfig;
const Prop = ssv.Plan.Property;

/// commonware's `#[values(RoundRobin::default(), stable_leaders())]`.
const electors = [_]RoundRobin{ .default(), stable_leaders() };
/// Each ceremony runs with both electors on both networks (commonware's `case::discovery` and
/// `case::lookup`).
const cases = blk: {
    var list: [electors.len * 2]struct { RoundRobin, harness.lookup.Network } = undefined;
    for (electors, 0..) |elector, at| {
        list[2 * at] = .{ elector, .discovery };
        list[2 * at + 1] = .{ elector, .lookup };
    }
    break :blk list;
};

/// commonware `stable_leaders`: terms of two views, a 5 s stall timeout, and two optimistic
/// views, so every dealer of the largest committee gets a term in an epoch's dealing window.
fn stable_leaders() RoundRobin {
    const length = @import("utils").NonZero(u32).init(2).?;
    return RoundRobin.default().with_term(.new(length), .from_secs(5), .new(2));
}

/// commonware's fast link for the processed-hold tests: two fetch round trips fit in a block.
const fast_link: p2p.simulated.Link = .{
    .latency = .from_millis(4),
    .jitter = .from_millis(1),
    .success_rate = 1.0,
};

fn skip_slow() error{SkipZigTest}!void {
    if (!build_options.slow_tests) return error.SkipZigTest;
}

fn first_height(epoch: u64) u64 {
    return epoch * epoch_length;
}

fn midpoint(epoch: u64) u64 {
    return epoch * epoch_length + epoch_length / 2;
}

/// commonware `height_round`: the round whose view is `height`'s offset in its epoch.
fn height_round(height: u64) consensus.Round {
    return .new(.new(height / epoch_length), .new(height % epoch_length));
}

/// One plan's shape (commonware `reshare_plan_with_boundary` plus the test's own additions).
const Options = struct {
    final_epoch: u64,
    /// `BoundaryEpochInfos::new(boundary_epochs)`; null drops the base properties (commonware's
    /// bare `PlanBuilder`).
    boundary_epochs: ?u64,
    expected_failures: []const u64 = &.{},
    no_reveals: bool = false,
    seed: u64 = 0,
    timeout_secs: u64 = 120,
    link: p2p.simulated.Link = harness.good_link,
    /// Borrowed.
    crashes: []const Crash,
    /// Borrowed; checked after the base properties.
    extra: []const Prop = &.{},
    /// Exit once every active validator processed the final height (commonware
    /// `AllActiveProcessedHeight`), rather than once any did.
    active: ?usize = null,
};

fn run(engine: *Engine, options: Options) !ssv.Plan.Result {
    const height = properties.final_height(options.final_epoch);
    const exit: simulate.exit.ProcessedHeightAtLeast = .{ .required = height };
    const all_active: properties.AllActiveProcessedHeight = .{
        .required = height,
        .participants = options.active orelse 0,
    };
    const signer: properties.SignerRegistered(S) = .{};
    var boundary = properties.BoundaryEpochInfos(S).init(gpa, options.boundary_epochs orelse 1);
    boundary.no_reveals = options.no_reveals;
    boundary.expected_failures = options.expected_failures;
    const continuity: properties.EpochInfoContinuity(S) = .{
        .gpa = gpa,
        .epochs = options.final_epoch + 1,
        .schedule = engine.schedule(),
    };
    var checks: [12]Prop = undefined;
    var count: usize = 0;
    if (options.boundary_epochs != null) {
        checks[0..3].* = .{ .from(&signer), .from(&boundary), .from(&continuity) };
        count = 3;
    }
    assert(count + options.extra.len <= checks.len);
    @memcpy(checks[count..][0..options.extra.len], options.extra);
    count += options.extra.len;
    const plan: ssv.Plan = .{
        .engine = engine,
        .seed = options.seed,
        .link = options.link,
        .crashes = options.crashes,
        .required_finalizations = 0,
        .exit_condition = if (options.active != null) .from(&all_active) else .from(&exit),
        .timeout = .from_secs(options.timeout_secs),
        .properties = checks[0..count],
    };
    return plan.run(gpa);
}

fn delay(keys: *const [1]Key, height: u64) Crash {
    return .{ .delay_round = .{ .participants = keys, .round = height_round(height) } };
}

/// `keys` is borrowed by the returned crash and must outlive the plan.
fn crash_at(keys: []const Key, min: u64, max: u64, downtime: Duration) Crash {
    assert(keys.len > 0);
    return .{ .processed_height = .{
        .participants = keys,
        .heights = .{ .min = min, .max = max },
        .downtime = downtime,
    } };
}

fn synced_at(engine: *const Engine, key: Key, min: u64, max: u64) properties.StateSyncedAtHeight(
    S,
    support.Ledger,
) {
    return .{ .public_key = key, .min_height = min, .max_height = max, .ledger = engine.ledger() };
}

/// commonware `state_sync_next_player_plan_starting_at`: the delayed validator waits for
/// `start_height`'s round, then must be a newcomer at `next_player_epoch`, sync within the
/// floor window, and sign from `signer_epoch`.
const NextPlayer = struct {
    final_epoch: u64,
    delayed_index: usize,
    start_height: u64,
    next_player_epoch: u64,
    signer_epoch: u64,
    boundary_epochs: u64,
    expected_failures: []const u64 = &.{},
    no_reveals: bool = false,
    timeout_secs: u64 = 120,
    link: p2p.simulated.Link = harness.good_link,
    /// Crashes after the delay (borrowed).
    crashes: []const Crash = &.{},
    /// Borrowed.
    extra: []const Prop = &.{},
};

fn run_next_player(engine: *Engine, options: NextPlayer) !ssv.Plan.Result {
    const delayed = engine.participants()[options.delayed_index];
    const configured = engine.state_sync_floor;
    // Entering the delayed round does not prove the preceding height is finalized.
    const sync_floor = configured orelse first_height(options.next_player_epoch);
    const max_floor = configured orelse properties.final_height(options.next_player_epoch);
    const membership: properties.StateSyncMembership(S) = .{
        .gpa = gpa,
        .schedule = engine.schedule(),
        .public_key = delayed,
        .next_player_epoch = options.next_player_epoch,
    };
    const at_height = synced_at(engine, delayed, sync_floor, max_floor);
    const synced_signer: properties.StateSyncedSigner(S, support.Ledger) = .{
        .public_key = delayed,
        .min_epoch = options.signer_epoch,
        .ledger = engine.ledger(),
    };
    var extra: [6]Prop = undefined;
    extra[0..3].* = .{ .from(&membership), .from(&at_height), .from(&synced_signer) };
    assert(options.extra.len <= extra.len - 3);
    @memcpy(extra[3..][0..options.extra.len], options.extra);
    const keys = [_]Key{delayed};
    var crashes: [4]Crash = undefined;
    assert(options.crashes.len < crashes.len);
    crashes[0] = delay(&keys, options.start_height);
    @memcpy(crashes[1..][0..options.crashes.len], options.crashes);
    return run(engine, .{
        .final_epoch = options.final_epoch,
        .boundary_epochs = options.boundary_epochs,
        .expected_failures = options.expected_failures,
        .no_reveals = options.no_reveals,
        .timeout_secs = options.timeout_secs,
        .link = options.link,
        .crashes = crashes[0 .. 1 + options.crashes.len],
        .extra = extra[0 .. 3 + options.extra.len],
    });
}

test "reshare state sync: block encoding round trips and bounds its size" {
    const Block = ssv.Validator.Block;
    var engine = try harness.ReshareEngine.with_committees(gpa, 4, &.{4}, 1);
    defer engine.deinit();
    const info = try engine.initial.clone(gpa);
    const target = app_mod.Any.initial_sync_target();
    var genesis = try Block.genesis(gpa, engine.keys[0], info, target);
    defer genesis.deinit(gpa);
    const bytes = try codec.encode(Block, gpa, genesis);
    defer gpa.free(bytes);
    const cfg: Block.Cfg = .{
        .max_participants = ssv.max_participants,
        .max_supported_mode = @import("../mocks.zig").max_supported_mode,
    };
    try testing.expect(bytes.len <= Block.max_encode_size_for(cfg));
    var decoded = try codec.decode_cfg(Block, gpa, bytes, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(genesis));
    try testing.expect(decoded.target.eql(target));
    try testing.expect(decoded.digest().eql(cryptography.Sha256.hash(&.{bytes})));
}

// commonware `reshare_e2e_state_sync_epoch_first_next_player`: the delayed validator syncs to
// epoch 1's first height and plays from epoch 2.
test "reshare state sync: epoch-first next player" {
    try skip_slow();
    for (cases) |case| {
        const elector, const transport = case;
        var engine = try Engine.with_committee(gpa, transport, 6, 4);
        defer engine.deinit();
        engine.elector = elector;
        engine.state_sync_floor = first_height(1);
        var result = try run_next_player(&engine, .{
            .final_epoch = 3,
            .delayed_index = 5,
            .start_height = midpoint(1),
            .next_player_epoch = 1,
            .signer_epoch = 2,
            .boundary_epochs = 4,
        });
        result.deinit();
    }
}

// commonware `reshare_e2e_state_sync_restart_before_epoch_boundary`: the delayed validator is
// held at mid-epoch 1, crashed there, and restarts from its completed sync without syncing
// again.
test "reshare state sync: restart before epoch boundary" {
    try skip_slow();
    for (cases) |case| {
        const elector, const transport = case;
        var engine = try Engine.with_committee(gpa, transport, 6, 4);
        defer engine.deinit();
        engine.elector = elector;
        const floor = first_height(1);
        engine.state_sync_floor = floor;
        const window_start = floor + epoch_length / 2;
        const delayed = engine.participants()[5];
        engine.with_processed_hold(delayed, window_start);
        const window_end = first_height(2);
        const keys = [_]Key{delayed};
        const crashes = [_]Crash{crash_at(&keys, window_start, window_end, .from_millis(250))};
        var result = try run_next_player(&engine, .{
            .final_epoch = 3,
            .delayed_index = 5,
            .start_height = floor,
            .next_player_epoch = 1,
            .signer_epoch = 2,
            .boundary_epochs = 4,
            .link = fast_link,
            .crashes = &crashes,
        });
        defer result.deinit();
        try testing.expectEqual(1, result.crashes);
        try testing.expectEqual(1, engine.ledger().state_sync_starts_of(delayed));
    }
}

// commonware `reshare_e2e_state_sync_restart_with_stale_bootstrap`: restarted before sync
// completes, the delayed validator syncs again from its persisted floor in epoch 1, although
// every bootstrap member's first latest reply on restart is an epoch-0 finalization.
test "reshare state sync: restart with stale bootstrap" {
    try skip_slow();
    for (cases) |case| {
        const elector, const transport = case;
        var engine = try Engine.with_committee(gpa, transport, 6, 4);
        defer engine.deinit();
        engine.elector = elector;
        engine.stale = properties.final_height(0);
        const delayed = engine.participants()[5];
        const keys = [_]Key{delayed};
        const crashes = [_]Crash{
            delay(&keys, midpoint(1)),
            crash_at(&keys, 0, 0, .from_millis(250)),
        };
        var result = try run(&engine, .{
            .final_epoch = 3,
            .boundary_epochs = 4,
            .crashes = &crashes,
        });
        defer result.deinit();
        try testing.expectEqual(1, result.crashes);
        try testing.expectEqual(2, engine.ledger().state_sync_starts_of(delayed));
    }
}

// commonware `reshare_e2e_state_sync_active_player_late_restart`: epoch 0 fails, so the delayed
// validator joins epoch 1 as an active dealer and player, then is crashed late in it.
test "reshare state sync: active player late restart" {
    try skip_slow();
    for (cases) |case| {
        const elector, const transport = case;
        var engine = try Engine.with_committee(gpa, transport, 4, 4);
        defer engine.deinit();
        engine.elector = elector;
        engine.base.failures = &.{0};
        const floor = first_height(1);
        engine.state_sync_floor = floor;
        const late = midpoint(1) + 1;
        const delayed = engine.participants()[3];
        engine.with_processed_hold(delayed, late);
        const keys = [_]Key{delayed};
        const crashes = [_]Crash{
            delay(&keys, floor),
            crash_at(&keys, late, properties.final_height(1), .from_millis(250)),
        };
        const at_height = synced_at(&engine, delayed, floor, floor);
        const schemes: properties.SchemesRegistered(S) = .{
            .gpa = gpa,
            .public_keys = &keys,
            .epoch = 2,
        };
        const extra = [_]Prop{ .from(&at_height), .from(&schemes) };
        var result = try run(&engine, .{
            .final_epoch = 2,
            .boundary_epochs = 3,
            .expected_failures = &.{0},
            .link = fast_link,
            .crashes = &crashes,
            .extra = &extra,
        });
        defer result.deinit();
        try testing.expectEqual(1, result.crashes);
        try testing.expectEqual(1, engine.ledger().state_sync_starts_of(delayed));
    }
}

// commonware `reshare_e2e_late_state_sync_carries_share_across_failure`: epochs 0 and 1 fail,
// so the genesis share carries into epoch 2 for a validator synced mid-epoch 1.
test "reshare state sync: late sync carries share across failure" {
    try skip_slow();
    for (cases) |case| {
        const elector, const transport = case;
        var engine = try Engine.with_committee(gpa, transport, 4, 4);
        defer engine.deinit();
        engine.elector = elector;
        engine.base.failures = &.{ 0, 1 };
        const floor = midpoint(1) + 1;
        engine.state_sync_floor = floor;
        const delayed = engine.participants()[3];
        const keys = [_]Key{delayed};
        const crashes = [_]Crash{delay(&keys, properties.final_height(1) - 1)};
        const at_height = synced_at(&engine, delayed, floor, floor);
        const schemes: properties.SchemesRegistered(S) = .{
            .gpa = gpa,
            .public_keys = &keys,
            .epoch = 2,
        };
        const extra = [_]Prop{ .from(&at_height), .from(&schemes) };
        var result = try run(&engine, .{
            .final_epoch = 2,
            .boundary_epochs = 3,
            .expected_failures = &.{ 0, 1 },
            .link = fast_link,
            .crashes = &crashes,
            .extra = &extra,
        });
        result.deinit();
        try testing.expectEqual(1, engine.ledger().state_sync_starts_of(delayed));
    }
}

// commonware `reshare_e2e_state_sync_epoch_crosses_during_sync`: the network finishes epoch 1
// while the delayed validator still syncs to its epoch-1 floor; it catches up through marshal
// and signs for epoch 4.
test "reshare state sync: epoch crosses during sync" {
    try skip_slow();
    for (cases) |case| {
        const elector, const transport = case;
        var engine = try Engine.with_committee(gpa, transport, 6, 4);
        defer engine.deinit();
        engine.elector = elector;
        engine.epoch_cross_during_sync = true;
        const delayed = engine.participants()[5];
        const keys = [_]Key{delayed};
        const crashes = [_]Crash{delay(&keys, midpoint(1))};
        const at_height = synced_at(&engine, delayed, first_height(1), properties.final_height(1));
        const synced_signer: properties.StateSyncedSigner(S, support.Ledger) = .{
            .public_key = delayed,
            .min_epoch = 4,
            .ledger = engine.ledger(),
        };
        const extra = [_]Prop{ .from(&at_height), .from(&synced_signer) };
        var result = try run(&engine, .{
            .final_epoch = 4,
            .boundary_epochs = 5,
            .timeout_secs = 180,
            .crashes = &crashes,
            .extra = &extra,
        });
        result.deinit();
        try testing.expectEqual(1, engine.ledger().state_sync_starts_of(delayed));
    }
}

// commonware `reshare_e2e_state_sync_epoch_zero_next_player`.
test "reshare state sync: epoch-zero next player" {
    try skip_slow();
    for (cases) |case| {
        const elector, const transport = case;
        var base = try harness.ReshareEngine.create_on(gpa, transport);
        errdefer base.deinit();
        var engine = try Engine.from_base(base);
        defer engine.deinit();
        engine.elector = elector;
        var result = try run_next_player(&engine, .{
            .final_epoch = 2,
            .delayed_index = 4,
            .start_height = midpoint(0),
            .next_player_epoch = 0,
            .signer_epoch = 1,
            .boundary_epochs = 3,
            .no_reveals = true,
        });
        result.deinit();
    }
}

// commonware `reshare_e2e_state_sync_next_player_after_failed_ceremony`.
test "reshare state sync: next player after failed ceremony" {
    try skip_slow();
    for (cases) |case| {
        const elector, const transport = case;
        var engine = try Engine.with_committee(gpa, transport, 6, 4);
        defer engine.deinit();
        engine.elector = elector;
        engine.base.failures = &.{1};
        const carry: properties.FailedCeremonyCarryOver(S) = .{
            .gpa = gpa,
            .epoch = 1,
            .schedule = engine.schedule(),
        };
        const extra = [_]Prop{.from(&carry)};
        var result = try run_next_player(&engine, .{
            .final_epoch = 3,
            .delayed_index = 5,
            .start_height = midpoint(1),
            .next_player_epoch = 1,
            .signer_epoch = 3,
            .boundary_epochs = 4,
            .expected_failures = &.{1},
            .no_reveals = true,
            .timeout_secs = 180,
            .extra = &extra,
        });
        result.deinit();
    }
}

// commonware `reshare_e2e_state_sync_existing_player_after_failed_ceremony`.
test "reshare state sync: existing player after failed ceremony" {
    try skip_slow();
    for (cases) |case| {
        const elector, const transport = case;
        var base = try harness.ReshareEngine.create_on(gpa, transport);
        errdefer base.deinit();
        var engine = try Engine.from_base(base);
        defer engine.deinit();
        engine.elector = elector;
        engine.base.failures = &.{0};
        const delayed = engine.participants()[1];
        const keys = [_]Key{delayed};
        const crashes = [_]Crash{delay(&keys, midpoint(0))};
        const schemes: properties.SchemesRegistered(S) = .{
            .gpa = gpa,
            .public_keys = &keys,
            .epoch = 1,
        };
        const extra = [_]Prop{.from(&schemes)};
        var result = try run(&engine, .{
            .final_epoch = 1,
            .boundary_epochs = 2,
            .expected_failures = &.{0},
            .timeout_secs = 180,
            .crashes = &crashes,
            .extra = &extra,
        });
        result.deinit();
    }
}

// commonware `reshare_e2e_boundary_participating_synced_validator`: one validator stops for
// good two blocks before epoch 1's boundary, so the others reach it only with the synced
// validator's votes.
test "reshare state sync: boundary participating synced validator" {
    try skip_slow();
    const last = properties.final_height(1);
    const stopped_at = last - 2;
    const floor = first_height(1) + 2;
    for (cases) |case| {
        const elector, const transport = case;
        for (0..6) |seed| {
            var engine = try Engine.with_committee(gpa, transport, 4, 4);
            defer engine.deinit();
            engine.elector = elector;
            engine.base.failures = &.{0};
            engine.state_sync_floor = floor;
            const stopped = engine.participants()[2];
            const synced = engine.participants()[3];
            engine.with_processed_hold(stopped, stopped_at);
            const keys = [_]Key{synced};
            const stopped_keys = [_]Key{stopped};
            const crashes = [_]Crash{
                delay(&keys, stopped_at - 1),
                crash_at(&stopped_keys, stopped_at, stopped_at, .from_secs(3600)),
            };
            const at_height = synced_at(&engine, synced, floor, floor);
            const extra = [_]Prop{.from(&at_height)};
            var result = try run(&engine, .{
                .final_epoch = 1,
                .boundary_epochs = null,
                .seed = seed,
                .timeout_secs = 60,
                .crashes = &crashes,
                .extra = &extra,
                .active = engine.participants().len - 1,
            });
            result.deinit();
        }
    }
}
