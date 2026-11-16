//! Multi-node tests of the simplex engine (commonware `simplex/mod.rs` tests): honest
//! validators on `p2p.simulated` under the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const config_mod = @import("config.zig");
const elector_mod = @import("elector.zig");
const engine_mod = @import("engine.zig");
const ed25519 = @import("scheme/ed25519.zig");
const application_mod = @import("mocks/application.zig");
const relay_mod = @import("mocks/relay.zig");
const reporter_mod = @import("mocks/reporter.zig");
const conflicter_mod = @import("mocks/conflicter.zig");
const nuller_mod = @import("mocks/nuller.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Key = cryptography.ed25519.PublicKey;
const wrapped = @import("mocks/wrapped.zig");
/// Every engine signs through the wrapper; only `Role.invalid` makes validator 0 misbehave.
const Scheme = wrapped.Scheme(ed25519.Scheme(Digest));
const Net = p2p.simulated.Network(Key);
const Context = runtime.deterministic.Context;
const Application = application_mod.Application(Sha256, Key);
const Relay = relay_mod.Relay(Digest, Key);
const Reporter = reporter_mod.Reporter(Scheme, Digest);
const Attributable = @import("scheme/reporter.zig").AttributableReporter(
    Scheme,
    Digest,
    IoRng,
    parallel.Sequential,
    *Reporter,
);
const Conflicter = conflicter_mod.Conflicter(Scheme, Sha256);
const Nuller = nuller_mod.Nuller(Scheme, Sha256);
const Impersonator = @import("mocks/impersonator.zig").Impersonator(Scheme, Sha256);
const Outdated = @import("mocks/outdated.zig").Outdated(Scheme, Sha256);
const Elector = elector_mod.RoundRobinElector;
const Equivocator = @import("mocks/equivocator.zig").Equivocator(Scheme, Sha256, Key, Elector);
const IoRng = @import("actors/context.zig").IoRng;
const Reconfigurer = @import("mocks/reconfigurer.zig").Reconfigurer(Scheme, Sha256);
const Duration = utils.Duration;
const Link = p2p.simulated.Link;
const View = consensus_types.View;
const Epoch = consensus_types.Epoch;

const Params = struct {
    pub const Context = runtime.deterministic.Context;
    pub const Scheme = wrapped.Scheme(ed25519.Scheme(Sha256.Digest));
    pub const Elector = elector_mod.RoundRobinElector;
    pub const Blocker = Net.Control;
    pub const Digest = Sha256.Digest;
    pub const Automaton = *Application;
    pub const Relay = *Application;
    pub const Reporter = *Attributable;
    pub const Strategy = parallel.Sequential;
    pub const Sender = Net.Sender;
    pub const Receiver = Net.Receiver;
};
const Engine = engine_mod.Engine(Params);
const Channel = engine_mod.Channel(Params);

const test_quota = p2p.Quota.per_second(1024);
const epoch: Epoch = .new(333);
const page_size = 1024;
const page_cache_size = 10;

/// What validator 0 runs: the engine, or one of the Byzantine mocks.
/// `absent` leaves validator 0 offline until the test starts it; `slow` runs the engine with
/// an application that takes 10 s to propose, verify, and certify; `invalid` runs the engine
/// with every signature corrupted.
const Role = enum {
    honest,
    absent,
    slow,
    invalid,
    conflicter,
    nuller,
    impersonator,
    outdated,
    equivocator,
    reconfigurer,

    /// Whether validator 0 runs a Byzantine mock instead of the engine.
    fn is_byzantine(role: Role) bool {
        return switch (role) {
            .honest, .absent, .slow, .invalid => false,
            .conflicter,
            .nuller,
            .impersonator,
            .outdated,
            .equivocator,
            .reconfigurer,
            => true,
        };
    }
};

/// A Byzantine mock on the vote channel; the other channels stay registered and unused.
const Byzantine = struct {
    role: Role,
    conflicter: Conflicter,
    nuller: Nuller,
    impersonator: Impersonator,
    outdated: Outdated,
    elector: Elector,
    equivocator: Equivocator,
    reconfigurer: Reconfigurer,
    channels: [3]Channel,
    handle: runtime.context.Handle(void),

    fn run(ctx: Context, byzantine: *Byzantine) void {
        _ = ctx;
        const votes = &byzantine.channels[0];
        switch (byzantine.role) {
            // Proof: only Byzantine roles start this task.
            .honest, .absent, .slow, .invalid => unreachable,
            .conflicter => byzantine.conflicter.run(&votes.sender, &votes.receiver),
            .nuller => byzantine.nuller.run(&votes.sender, &votes.receiver),
            .impersonator => byzantine.impersonator.run(&votes.sender, &votes.receiver),
            .outdated => byzantine.outdated.run(&votes.sender, &votes.receiver),
            .reconfigurer => byzantine.reconfigurer.run(&votes.sender, &votes.receiver),
            .equivocator => {
                const certificates = &byzantine.channels[1].receiver;
                byzantine.equivocator.run(&votes.sender, certificates);
            },
        }
    }

    fn stop(byzantine: *Byzantine) void {
        byzantine.handle.abort() catch {};
        byzantine.outdated.deinit();
        byzantine.equivocator.deinit();
        byzantine.elector.deinit(gpa);
        for (&byzantine.channels) |*channel| {
            channel.sender.deinit();
            channel.receiver.deinit();
        }
    }
};

/// One validator's engine and mocks. Must not move once started.
const Validator = struct {
    state: enum { absent, honest, byzantine },
    byzantine: *Byzantine,
    application: Application,
    reporter: Reporter,
    /// Wraps `reporter` for the engine; it verifies peer activity only when the harness's
    /// `verify_reports` is set (otherwise ed25519 activity passes through unchanged).
    attributable: Attributable,
    page_cache: runtime.buffer.paged.CacheRef,
    elector: Elector,
    engine: Engine,
    partition: [32]u8,
    handle: ?runtime.context.Handle(Engine.RunResult) = null,
};

/// One simulated network of validators. Must not move once started.
const Harness = struct {
    ctx: Context,
    fixture: Fixture,
    /// The fixture's signing schemes, wrapped (validator 0's per `role`).
    schemes: []Scheme,
    /// The fixture's verifier, wrapped honestly.
    verifier: Scheme,
    network: *Net,
    network_task: std.Io.Future((std.Io.Cancelable || Allocator.Error)!void),
    relay: Relay,
    validators: []Validator,
    /// Whether honest validators keep votes of finalized views (commonware's Byzantine
    /// tests set it).
    track_historical_votes: bool = false,
    timeouts: Timeouts,
    role: Role,
    /// Engine mailbox size and whether applications stall proposals, for engines started
    /// from now on.
    mailbox_size: u32 = 1024,
    stall_proposals: bool = false,
    verify_reports: bool = false,

    const Timeouts = struct {
        leader_ms: u64 = 1000,
        certification_ms: u64 = 2000,
        retry_ms: u64 = 10_000,
    };

    const Fixture = cryptography.certificate.mocks.Fixture(ed25519.Scheme(Digest));

    fn keys(harness: *const Harness) []const Key {
        return harness.fixture.participants;
    }

    fn oracle(harness: *const Harness) Net.Oracle {
        return harness.network.oracle();
    }

    /// Starts `n` validators, every pair linked by `link` (when given); validator 0 plays
    /// `role`.
    fn start(harness: *Harness, ctx: Context, n: u32, link: ?Link, role: Role) !void {
        try harness.start_timed(ctx, n, link, role, .{});
    }

    /// `start` with the engines' leader, certification, and retry timeouts.
    fn start_timed(
        harness: *Harness,
        ctx: Context,
        n: u32,
        link: ?Link,
        role: Role,
        timeouts: Timeouts,
    ) !void {
        try harness.start_network(ctx, n, link, role, timeouts);
        for (harness.validators, harness.keys(), 0..) |*validator, key, index| {
            if (index == 0 and role == .absent) continue;
            if (index == 0 and role.is_byzantine()) {
                try harness.start_byzantine(validator, key, role);
            } else {
                try harness.start_validator(index);
            }
        }
    }

    /// Everything `start_timed` does except starting validators: all start absent.
    fn start_network(
        harness: *Harness,
        ctx: Context,
        n: u32,
        link: ?Link,
        role: Role,
        timeouts: Timeouts,
    ) !void {
        assert(timeouts.leader_ms <= timeouts.certification_ms);
        const io = ctx.io();
        var rng = utils.rng.test_rng();
        harness.* = undefined;
        harness.ctx = ctx;
        harness.timeouts = timeouts;
        harness.role = role;
        harness.fixture = try ed25519.fixture(Digest, gpa, &rng, "consensus", n);
        errdefer harness.fixture.deinit(gpa);
        harness.schemes = try gpa.alloc(Scheme, n);
        errdefer gpa.free(harness.schemes);
        for (harness.schemes, harness.fixture.schemes, 0..) |*scheme, inner, index| {
            const corrupt = index == 0 and role == .invalid;
            scheme.* = .init(inner, if (corrupt) .corrupt_signature else .honest);
        }
        harness.verifier = .init(harness.fixture.verifier, .honest);
        harness.network = try Net.init(gpa, io, .{
            .max_size = 1024 * 1024,
            .max_peers_per_set = n + 1,
            .disconnect_on_block = true,
            .tracked_peer_sets = 1,
        });
        harness.network_task = try io.concurrent(Net.run, .{harness.network});
        harness.relay = .init(gpa, io);
        harness.validators = try gpa.alloc(Validator, n);
        for (harness.validators) |*validator| validator.state = .absent;
        const peers = harness.keys();
        _ = harness.oracle().manager().track(0, .init_primary(.init(peers)));
        if (link) |value| try harness.link_all(value, null);
        // commonware's equivocator and reconfigurer tests keep the default; its other
        // Byzantine tests set it.
        harness.track_historical_votes = role.is_byzantine() and
            role != .equivocator and role != .reconfigurer;
        harness.mailbox_size = 1024;
        harness.stall_proposals = false;
        harness.verify_reports = false;
    }

    fn start_byzantine(harness: *Harness, validator: *Validator, key: Key, role: Role) !void {
        const io = harness.ctx.io();
        const byzantine = try gpa.create(Byzantine);
        errdefer gpa.destroy(byzantine);
        const scheme = &harness.schemes[0];
        const n: u32 = @intCast(harness.validators.len);
        var elector = try elector_mod.RoundRobin(Sha256).default().build(gpa, n);
        errdefer elector.deinit(gpa);
        byzantine.* = .{
            .role = role,
            .conflicter = .init(gpa, io, scheme),
            .nuller = .init(gpa, scheme),
            .impersonator = .init(gpa, scheme),
            // Four times the view retention, as in commonware's `outdated` test.
            .outdated = .init(gpa, scheme, .new(40)),
            .elector = elector,
            .equivocator = .init(gpa, io, scheme, elector, epoch, &harness.relay),
            .reconfigurer = .init(gpa, scheme),
            .channels = try register(harness.oracle(), key),
            .handle = undefined,
        };
        byzantine.handle = try harness.ctx.child("byzantine").spawn(Byzantine.run, .{byzantine});
        validator.* = undefined;
        validator.byzantine = byzantine;
        validator.state = .byzantine;
    }

    /// The validator at `index` when it runs the engine.
    fn honest(harness: *Harness, index: usize) ?*Validator {
        const validator = &harness.validators[index];
        return if (validator.state == .honest) validator else null;
    }

    fn deinit(harness: *Harness) void {
        const validators = harness.validators;
        for (validators) |*validator| {
            if (validator.state == .byzantine) validator.byzantine.stop();
        }
        harness.crash_all();
        for (validators) |*validator| {
            if (validator.state == .byzantine) gpa.destroy(validator.byzantine);
        }
        gpa.free(harness.validators);
        harness.relay.deinit();
        harness.network.close();
        harness.network_task.await(harness.ctx.io()) catch {};
        harness.network.deinit();
        gpa.free(harness.schemes);
        harness.fixture.deinit(gpa);
        harness.* = undefined;
    }

    /// Aborts validator `index`'s engine and frees its mocks; its journal stays in storage
    /// for `start_validator` to recover.
    fn crash(harness: *Harness, index: usize) void {
        const validator = harness.honest(index).?;
        abort(validator);
        // No broadcast reaches the application once deregistered, so it can be freed.
        harness.relay.deregister(harness.keys()[index]);
        stop_actors(validator);
        validator.state = .absent;
        assert(harness.honest(index) == null);
    }

    /// Aborts every engine and frees its mocks; the validators become absent, and their
    /// journals stay in storage for `start_validator` to recover.
    fn crash_all(harness: *Harness) void {
        const validators = harness.validators;
        // Abort every engine before freeing any mock: live voters relay to all applications.
        for (validators) |*validator| {
            if (validator.state == .honest) abort(validator);
        }
        harness.relay.deregister_all();
        for (validators) |*validator| {
            if (validator.state != .honest) continue;
            stop_actors(validator);
            validator.state = .absent;
        }
        for (validators) |*validator| assert(validator.state != .honest);
    }

    /// Replaces the link of every ordered pair `restrict` admits (commonware `Update`).
    fn relink_all(harness: *Harness, link: Link, restrict: ?*const Restrict) !void {
        try harness.link_all(null, restrict);
        try harness.link_all(link, restrict);
    }

    /// Links (or, with `link == null`, unlinks) every ordered pair `restrict` admits.
    fn link_all(harness: *Harness, link: ?Link, restrict: ?*const Restrict) !void {
        const peers = harness.keys();
        for (peers, 0..) |from, a| for (peers, 0..) |to, b| {
            if (a == b) continue;
            if (restrict) |admits| if (!admits(peers.len, a, b)) continue;
            if (link) |value| {
                try harness.oracle().add_link(from, to, value);
            } else {
                try harness.oracle().remove_link(from, to);
            }
        };
    }

    /// Starts the engine of validator `index`.
    fn start_validator(harness: *Harness, index: usize) !void {
        const channels = try register(harness.oracle(), harness.keys()[index]);
        try harness.start_validator_on(index, channels);
    }

    /// Starts validator `index`'s engine on `channels`, registered for it beforehand.
    fn start_validator_on(harness: *Harness, index: usize, channels: [3]Channel) !void {
        const io = harness.ctx.io();
        const validator = &harness.validators[index];
        const key = harness.keys()[index];
        assert(validator.state == .absent);
        validator.* = undefined;
        validator.handle = null;
        const slow = index == 0 and harness.role == .slow;
        const normal: application_mod.Latency = .{ .mean = 10, .std_dev = 5 };
        validator.application = try .init(gpa, io, .{
            .relay = &harness.relay,
            .me = key,
            .propose_latency = if (slow) .{ .mean = 10_000, .std_dev = 0 } else normal,
            .verify_latency = if (slow) .{ .mean = 10_000, .std_dev = 5 } else normal,
            .certify_latency = if (slow) .{ .mean = 10_000, .std_dev = 5 } else normal,
        });
        validator.application.stall_proposals = harness.stall_proposals;
        try validator.application.register();
        validator.reporter = .init(gpa, io, &harness.verifier);
        const rng: IoRng = .{ .io = io };
        const verify = harness.verify_reports;
        const scheme = harness.schemes[index];
        validator.attributable =
            .init(gpa, io, rng, scheme, &validator.reporter, parallel.sequential, verify);
        validator.page_cache = try .init(gpa, page_size, page_cache_size);
        const n: u32 = @intCast(harness.validators.len);
        validator.elector = try elector_mod.RoundRobin(Sha256).default().build(gpa, n);
        validator.partition = @splat(0);
        _ = try std.fmt.bufPrint(&validator.partition, "validator-{d}", .{index});
        const control = harness.oracle().control(key);
        var cfg = engine_config(validator, harness.schemes[index], control);
        cfg.track_historical_votes = harness.track_historical_votes;
        cfg.mailbox_size = harness.mailbox_size;
        cfg.leader_timeout = .from_millis(harness.timeouts.leader_ms);
        cfg.certification_timeout = .from_millis(harness.timeouts.certification_ms);
        cfg.timeout_retry = .from_millis(harness.timeouts.retry_ms);
        try validator.engine.init(harness.ctx, cfg);
        validator.handle = try harness.ctx.child("engine").spawn(Engine.run, .{
            &validator.engine, channels[0], channels[1], channels[2],
        });
        validator.state = .honest;
    }

    /// Waits until every validator finalized `view`.
    fn wait_all(harness: *Harness, view: u64) !void {
        for (0..harness.validators.len) |index| {
            const validator = harness.honest(index) orelse continue;
            try validator.reporter.wait_for_finalized(.new(view));
        }
    }

    /// The lowest finalized view across honest validators.
    fn min_finalized(harness: *Harness) u64 {
        var lowest: u64 = std.math.maxInt(u64);
        for (0..harness.validators.len) |index| {
            const validator = harness.honest(index) orelse continue;
            lowest = @min(lowest, validator.reporter.latest_finalized().get());
        }
        assert(lowest != std.math.maxInt(u64));
        return lowest;
    }

    /// The highest finalized view across validators.
    fn max_finalized(harness: *Harness) u64 {
        var highest: u64 = 0;
        for (0..harness.validators.len) |index| {
            const validator = harness.honest(index) orelse continue;
            highest = @max(highest, validator.reporter.latest_finalized().get());
        }
        return highest;
    }

    /// No faults, no invalid activity, one payload per finalized view, and no blocks.
    fn check(harness: *Harness, through: u64) !void {
        for (harness.validators) |*validator| {
            validator.reporter.assert_no_faults();
        }
        try harness.check_agreement(through);
        const blocked = try harness.oracle().blocked(gpa);
        defer gpa.free(blocked);
        try testing.expectEqual(0, blocked.len);
    }

    /// No invalid activity, and every honest validator finalized the same payload at each
    /// view at or below `through`.
    fn check_agreement(harness: *Harness, through: u64) !void {
        for (0..harness.validators.len) |index| {
            const validator = harness.honest(index) orelse continue;
            validator.reporter.assert_no_invalid();
        }
        for (1..through + 1) |view| {
            var expected: ?Digest = null;
            for (0..harness.validators.len) |index| {
                const validator = harness.honest(index) orelse continue;
                const payload = validator.reporter.finalized(.new(view)) orelse continue;
                if (expected) |digest| try testing.expect(digest.order(payload) == .eq);
                expected = payload;
            }
        }
    }

    /// Only validator 0 committed faults, of the `allowed` kinds, at least once (none when
    /// `allowed` is empty); only honest validators blocked, and only validator 0.
    fn check_byzantine(harness: *Harness, allowed: []const std.meta.Tag(Reporter.Activity)) !void {
        var count: usize = 0;
        for (0..harness.validators.len) |index| {
            const validator = harness.honest(index) orelse continue;
            for (validator.reporter.fault_list()) |fault| {
                try testing.expectEqual(0, fault.signer.get());
                const Kind = @TypeOf(fault.kind);
                try testing.expect(std.mem.indexOfScalar(Kind, allowed, fault.kind) != null);
                count += 1;
            }
        }
        try testing.expectEqual(allowed.len > 0, count > 0);
        try harness.check_blocked_only_byzantine();
    }

    fn check_blocked_only_byzantine(harness: *Harness) !void {
        const byzantine = harness.keys()[0];
        const blocked = try harness.oracle().blocked(gpa);
        defer gpa.free(blocked);
        try testing.expect(blocked.len > 0);
        for (blocked) |pair| {
            try testing.expect(pair.origin.order(byzantine) != .eq);
            try testing.expect(pair.recipient.order(byzantine) == .eq);
        }
    }
};

const Restrict = fn (n: usize, a: usize, b: usize) bool;

fn link_ms(latency_ms: u64, jitter_ms: u64, success_rate: f64) Link {
    return .{
        .latency = Duration.from_millis(latency_ms),
        .jitter = Duration.from_millis(jitter_ms),
        .success_rate = success_rate,
    };
}

fn register(oracle: Net.Oracle, key: Key) ![3]Channel {
    var channels: [3]Channel = undefined;
    for (&channels, 0..) |*channel, index| {
        const registered = try oracle.control(key).register(index, test_quota);
        channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
    }
    return channels;
}

fn engine_config(validator: *Validator, scheme: Scheme, blocker: Net.Control) Engine.Config {
    return .{
        .scheme = scheme,
        .elector = validator.elector,
        .blocker = blocker,
        .automaton = &validator.application,
        .relay = &validator.application,
        .reporter = &validator.attributable,
        .track_historical_votes = false,
        .strategy = parallel.sequential,
        .partition = std.mem.sliceTo(&validator.partition, 0),
        .mailbox_size = 1024,
        .epoch = epoch,
        .floor = .{ .genesis = application_mod.genesis(Sha256, epoch) },
        .replay_buffer = 1024 * 1024,
        .write_buffer = 1024 * 1024,
        .page_cache = &validator.page_cache,
        .leader_timeout = .from_secs(1),
        .certification_timeout = .from_secs(2),
        .timeout_retry = .from_secs(10),
        .view_retention = .new(10),
        .skip = .{ .enabled = .{ .timeout = .from_secs(11) } },
        .fetch_timeout = .from_secs(1),
        .fetch_retry_delay = .from_millis(100),
        .forward = .disabled,
    };
}

fn abort(validator: *Validator) void {
    const handle = validator.handle orelse return;
    validator.handle = null;
    const result = handle.abort() catch return; // Aborted before it returned.
    result catch |err| std.debug.panic("engine failed: {t}", .{err});
}

fn stop_actors(validator: *Validator) void {
    validator.engine.deinit();
    validator.elector.deinit(gpa);
    validator.page_cache.deinit();
    validator.reporter.deinit();
    validator.application.deinit();
}

/// Runs `scenario(ctx, args...)` on a fresh runner seeded with `seed`; returns the auditor
/// state (commonware `context.auditor().state()`).
fn run_seeded(seed: u64, comptime scenario: anytype, args: anytype) ![8]u8 {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = seed });
    defer runner.deinit();
    try (try runner.start_context(scenario, args));
    return runner.auditor.state();
}

/// commonware `all_online` (ed25519, round robin; 50 views rather than 100 in Debug).
fn all_online(ctx: Context, n: u32, required: u64) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, n, link_ms(200, 1, 1.0), .honest);
    defer harness.deinit();
    try harness.wait_all(required);
    try harness.check(required);
}

test "four honest validators finalize" {
    _ = try run_seeded(0, all_online, .{ 4, 10 });
}

test "all online" {
    _ = try run_seeded(0, all_online, .{ 5, 50 });
}

/// commonware `slow_and_lossy_links_seeded`: half the messages drop.
fn slow_and_lossy_links(ctx: Context) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, 5, link_ms(200, 150, 0.5), .honest);
    defer harness.deinit();
    const required = 20;
    try harness.wait_all(required);
    try harness.check(required);
}

test "slow and lossy links" {
    _ = try run_seeded(6, slow_and_lossy_links, .{});
}

test "determinism: the same seed replays the same run" {
    var states: [2][8]u8 = undefined;
    for (&states, 0..) |*state, seed| {
        state.* = try run_seeded(seed, slow_and_lossy_links, .{});
        const again = try run_seeded(seed, slow_and_lossy_links, .{});
        try testing.expectEqualSlices(u8, state, &again);
    }
    // A different seed takes a different path.
    try testing.expect(!std.mem.eql(u8, &states[0], &states[1]));
}

fn separated(n: usize, a: usize, b: usize) bool {
    const m = n / 2;
    return (a < m and b >= m) or (a >= m and b < m);
}

/// commonware `partition`: cut the validators in half, check nothing finalizes, then heal.
fn partition(ctx: Context) !void {
    var harness: Harness = undefined;
    const link = link_ms(10, 1, 1.0);
    try harness.start(ctx, 10, link, .honest);
    defer harness.deinit();
    const required = 20;
    try harness.wait_all(required);
    try harness.link_all(null, &separated);
    // Let in-progress notarizations and finalizations finish.
    try ctx.sleep(.fromSeconds(10));
    const before = harness.max_finalized();
    try ctx.sleep(.fromSeconds(60));
    try testing.expectEqual(before, harness.max_finalized()); // Nothing finalizes while split.
    try harness.link_all(link, &separated);
    try harness.wait_all(before + required);
    try harness.check(before + required);
}

test "partition heals" {
    _ = try run_seeded(0, partition, .{});
}

/// commonware `conflicter`/`nuller`: validator 0 is Byzantine; the honest three still
/// finalize, report its faults, and block it.
fn byzantine_scenario(
    ctx: Context,
    role: Role,
    allowed: []const std.meta.Tag(Reporter.Activity),
) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, 4, link_ms(10, 1, 1.0), role);
    defer harness.deinit();
    const required = 20;
    try harness.wait_all(required);
    try harness.check_agreement(required);
    try harness.check_byzantine(allowed);
}

test "conflicter is reported and blocked" {
    for (0..2) |seed| {
        const allowed = &.{ .conflicting_notarize, .conflicting_finalize };
        _ = try run_seeded(seed, byzantine_scenario, .{ Role.conflicter, allowed });
    }
}

test "nuller is reported and blocked" {
    for (0..2) |seed| {
        _ = try run_seeded(seed, byzantine_scenario, .{ Role.nuller, &.{.nullify_finalize} });
    }
}

test "reconfigurer is blocked without faults" {
    // Votes for the next epoch are not faults; validator 0 is blocked for the mismatch.
    for (0..2) |seed| _ = try run_seeded(seed, byzantine_scenario, .{ Role.reconfigurer, &.{} });
}

test "impersonator is blocked without faults" {
    for (0..2) |seed| _ = try run_seeded(seed, byzantine_scenario, .{ Role.impersonator, &.{} });
}

/// commonware `outdated`: re-votes for proposals 40 views old are ignored, without faults
/// or blocks.
fn outdated_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, 4, link_ms(10, 1, 1.0), .outdated);
    defer harness.deinit();
    const required = 60;
    try harness.wait_all(required);
    try harness.check_agreement(required);
    for (0..harness.validators.len) |index| {
        const validator = harness.honest(index) orelse continue;
        validator.reporter.assert_no_faults();
    }
    const blocked = try harness.oracle().blocked(gpa);
    defer gpa.free(blocked);
    try testing.expectEqual(0, blocked.len);
}

test "outdated votes are ignored" {
    _ = try run_seeded(0, outdated_scenario, .{});
}

fn not_zero(_: usize, a: usize, b: usize) bool {
    return a != 0 and b != 0;
}

fn one_not_zero(_: usize, a: usize, b: usize) bool {
    return (a == 1 or b == 1) and a != 0 and b != 0;
}

fn zero_not_one(_: usize, a: usize, b: usize) bool {
    return (a == 0 or b == 0) and a != 1 and b != 1;
}

fn not_one(_: usize, a: usize, b: usize) bool {
    return a != 1 and b != 1;
}

/// commonware `backfill`: validator 0 joins late, after the others accrued nullifications
/// over slow links, and catches up through the resolver while validator 1 is cut off.
fn backfill_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, 4, null, .absent);
    defer harness.deinit();
    try harness.link_all(link_ms(10, 1, 1.0), &not_zero);
    const required = 50;
    try harness.wait_all(required);
    // Degrade the online links and let nullifications accrue.
    const slow = link_ms(3000, 0, 1.0);
    try harness.relink_all(slow, &not_zero);
    try ctx.sleep(.fromSeconds(60));
    // Cut validator 1 off, and link validator 0 to the rest.
    try harness.link_all(null, &one_not_zero);
    try harness.link_all(slow, &zero_not_one);
    try harness.relink_all(link_ms(10, 3, 1.0), &not_one);
    try harness.start_validator(0);
    try harness.validators[0].reporter.wait_for_finalized(.new(required));
    const blocked = try harness.oracle().blocked(gpa);
    defer gpa.free(blocked);
    try testing.expectEqual(0, blocked.len);
}

test "backfill: a late validator catches up through the resolver" {
    _ = try run_seeded(0, backfill_scenario, .{});
}

/// commonware `one_offline`: validator 0 never starts; the other four finalize, it never
/// appears in their activity, and the views it leads are nullified (up to 10 exceptions).
/// (Its leader-labelled timeout metrics follow with the actor metrics.)
fn one_offline_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    const n = 5;
    try harness.start(ctx, n, null, .absent);
    defer harness.deinit();
    try harness.link_all(link_ms(10, 1, 1.0), &not_zero);
    const required = 100;
    try harness.wait_all(required);
    for (0..n) |index| {
        const validator = harness.honest(index) orelse continue;
        validator.reporter.assert_no_faults();
        validator.reporter.assert_no_invalid();
        try testing.expect(try offline_exceptions(validator, required) <= 10);
    }
    const blocked = try harness.oracle().blocked(gpa);
    defer gpa.free(blocked);
    try testing.expectEqual(0, blocked.len);
}

/// Checks validator 0 never voted in `validator`'s view, and counts the views it led (after
/// a certified view, as commonware's reporter elects them) without a quorum of nullifies or
/// a nullification.
fn offline_exceptions(validator: *Validator, through: u64) !u32 {
    const quorum = utils.N3f1.quorum(@as(u32, 5));
    const offline: Reporter.Signers = 1;
    var offline_views: u32 = 0;
    var exceptions: u32 = 0;
    for (1..through + 1) |value| {
        const view: View = .new(value);
        const votes = validator.reporter.votes(view);
        try testing.expectEqual(0, (votes.notarize | votes.nullify | votes.finalize) & offline);
        const previous: View = .new(value - 1);
        const certified = validator.reporter.notarized(previous) or
            validator.reporter.nullified(previous);
        if (!certified) continue;
        const leader = validator.elector.elect(.new(epoch, view), {});
        if (leader.get() != 0) continue;
        offline_views += 1;
        if (@popCount(votes.nullify) < quorum) exceptions += 1;
        if (!validator.reporter.nullified(view)) exceptions += 1;
    }
    try testing.expect(offline_views > 0);
    return exceptions;
}

test "one offline: the others finalize and nullify its views" {
    _ = try run_seeded(0, one_offline_scenario, .{});
}

/// commonware `slow_validator`: validator 0 proposes, verifies, and certifies 10 s late, so
/// it never notarizes or finalizes; everyone still finalizes 50 views.
fn slow_validator_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, 5, link_ms(10, 1, 1.0), .slow);
    defer harness.deinit();
    const required = 50;
    try harness.wait_all(required); // The slow validator learns finalizations from the rest.
    for (harness.validators) |*validator| {
        validator.reporter.assert_no_faults();
        validator.reporter.assert_no_invalid();
        for (1..validator.reporter.latest_finalized().get() + 1) |value| {
            const votes = validator.reporter.votes(.new(value));
            try testing.expectEqual(0, (votes.notarize | votes.finalize) & 1);
        }
    }
    const blocked = try harness.oracle().blocked(gpa);
    defer gpa.free(blocked);
    try testing.expectEqual(0, blocked.len);
}

test "slow validator: the others finalize without its votes" {
    _ = try run_seeded(0, slow_validator_scenario, .{});
}

/// commonware `all_recovery`: over 3 s links no view finishes for a minute; after a minute
/// fully cut off and relinking at 10 ms, the views right after the highest nullified one are
/// nearly all notarized (the skip timeout recovers quickly).
fn all_recovery_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    const n = 5;
    try harness.start(ctx, n, link_ms(3000, 0, 1.0), .honest);
    defer harness.deinit();
    try ctx.sleep(.fromSeconds(60));
    try testing.expectEqual(0, harness.max_finalized()); // Nothing finalizes over slow links.
    try harness.link_all(null, null);
    try ctx.sleep(.fromSeconds(60));
    var latest: u64 = 0;
    for (harness.validators) |*validator| {
        latest = @max(latest, validator.reporter.max_vote_view(.nullify).get());
    }
    try testing.expect(latest > 0);
    try harness.link_all(link_ms(10, 1, 1.0), null);
    const required = 100;
    try harness.wait_all(required);
    const view_retention = 10;
    const tolerated_missing = 3;
    for (harness.validators) |*validator| {
        validator.reporter.assert_no_faults();
        validator.reporter.assert_no_invalid();
        var found: u32 = 0;
        for (latest..latest + view_retention) |view| {
            if (validator.reporter.notarized(.new(view))) found += 1;
        }
        try testing.expect(found >= view_retention - tolerated_missing);
    }
    const blocked = try harness.oracle().blocked(gpa);
    defer gpa.free(blocked);
    try testing.expectEqual(0, blocked.len);
}

test "all recovery: the cluster recovers quickly after relinking" {
    _ = try run_seeded(0, all_recovery_scenario, .{});
}

/// commonware `all_crash_after_nullify`: validator 0 never starts and nothing is linked, so
/// the rest only nullify view 1; they crash before a nullification can form, and once
/// restarted from their journals and linked, they rebuild it and finalize.
fn all_crash_after_nullify_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, 4, null, .absent);
    defer harness.deinit();
    // Wait for every online validator to have its nullify for view 1 reported.
    const stalled: View = .new(1);
    for (1..harness.validators.len) |index| {
        const own: Reporter.Signers = @as(Reporter.Signers, 1) << @intCast(index);
        const reporter = &harness.validators[index].reporter;
        while (reporter.votes(stalled).nullify & own == 0) try ctx.sleep(.fromMilliseconds(100));
    }
    // The batcher reports a vote before the voter's journal syncs it; let it sync.
    try ctx.sleep(.fromSeconds(1));
    try testing.expectEqual(0, harness.max_finalized());
    harness.crash_all();
    try harness.link_all(link_ms(10, 1, 1.0), &not_zero);
    for (1..harness.validators.len) |index| try harness.start_validator(index);
    // Validator 0 never votes, so every restarted vote is needed for a quorum.
    try harness.wait_all(10);
}

test "all crash after nullify: restarted validators rebuild the nullification" {
    _ = try run_seeded(0, all_crash_after_nullify_scenario, .{});
}

/// One run of commonware `equivocator_seeded`: validator 0 leads with two proposals, one for
/// a random victim and one for the rest. The honest six finalize through a crash and
/// restart of one of them; returns whether anyone blocked the equivocator (only it may be
/// blocked).
fn equivocator_run(ctx: Context) !bool {
    var harness: Harness = undefined;
    try harness.start(ctx, 7, link_ms(10, 1, 1.0), .equivocator);
    defer harness.deinit();
    const required = 50;
    try harness.wait_all(required);
    const rng: IoRng = .{ .io = ctx.io() };
    const index = 1 + rng.next_u64() % (harness.validators.len - 1);
    harness.crash(index);
    try harness.wait_all(required * 2);
    try harness.start_validator(index);
    try harness.wait_all(required * 3);
    try harness.check_agreement(required * 3);
    const byzantine = harness.keys()[0];
    const blocked = try harness.oracle().blocked(gpa);
    defer gpa.free(blocked);
    for (blocked) |pair| {
        try testing.expect(pair.origin.order(byzantine) != .eq);
        try testing.expect(pair.recipient.order(byzantine) == .eq);
    }
    return blocked.len > 0;
}

test "equivocator is blocked for at least one seed" {
    const detected = for (0..5) |seed| {
        var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = seed });
        defer runner.deinit();
        if (try (try runner.start_context(equivocator_run, .{}))) break true;
    } else false;
    try testing.expect(detected);
}

/// commonware `invalid`: validator 0 signs every vote with a corrupted signature. The honest
/// three finalize and block it without faults. Every reporter sees invalid votes, but only
/// validator 0's sees invalid certificates (assembled from its own votes); honest engines
/// reject those before reporting.
fn invalid_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, 4, link_ms(10, 1, 1.0), .invalid);
    defer harness.deinit();
    const required = 50;
    // Validator 0 never finalizes: its certificates carry its own invalid signature.
    for (1..harness.validators.len) |index| {
        try harness.validators[index].reporter.wait_for_finalized(.new(required));
    }
    for (harness.validators, 0..) |*validator, index| {
        validator.reporter.assert_no_faults();
        const invalid = validator.reporter.invalid();
        try testing.expect(invalid.votes > 0);
        try testing.expectEqual(index == 0, invalid.certificates > 0);
    }
    const byzantine = harness.keys()[0];
    const blocked = try harness.oracle().blocked(gpa);
    defer gpa.free(blocked);
    // Validator 0 may block itself too.
    try testing.expect(blocked.len >= harness.validators.len - 1);
    for (blocked) |pair| try testing.expect(pair.recipient.order(byzantine) == .eq);
}

test "invalid signatures are reported and blocked" {
    for (0..2) |seed| _ = try run_seeded(seed, invalid_scenario, .{});
}

fn zero_only_to_one(_: usize, a: usize, b: usize) bool {
    if (a == 0 or b == 0) return a == 1 or b == 1;
    return true;
}

/// commonware `received_certificates_are_reported`: validator 0 links only to validator 1, so
/// it cannot form certificates itself, yet reports nearly all those relayed to it.
fn received_certificates_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, 4, null, .honest);
    defer harness.deinit();
    try harness.link_all(link_ms(100, 1, 1.0), &zero_only_to_one);
    const required = 10;
    const honest = &harness.validators[1].reporter;
    try honest.wait_for_finalized(.new(required));
    // Let certificates in flight reach validator 0.
    try ctx.sleep(.fromSeconds(1));
    const excluded = &harness.validators[0].reporter;
    var notarized: [2]u32 = @splat(0);
    var finalized: [2]u32 = @splat(0);
    for (1..required + 1) |value| {
        const view: View = .new(value);
        for ([_]*Reporter{ honest, excluded }, 0..) |reporter, index| {
            if (reporter.notarized(view)) notarized[index] += 1;
            if (reporter.finalized(view) != null) finalized[index] += 1;
        }
    }
    // Early views may pass before validator 0 is connected.
    try testing.expect(notarized[1] >= notarized[0] -| 2);
    try testing.expect(finalized[1] >= finalized[0] -| 2);
    try testing.expect(finalized[0] > 0);
}

test "received certificates are reported" {
    _ = try run_seeded(0, received_certificates_scenario, .{});
}

const Notarize = @import("types.zig").Notarize(Scheme, Digest);
const Finalize = @import("types.zig").Finalize(Scheme, Digest);
const Certificate = @import("types.zig").Certificate(Scheme, Digest);

/// A certificate of `kind` (`.notarization` or `.finalization`) from a quorum of the
/// harness's signers, over `payload`'s hash at `view` on `parent`.
fn quorum_certificate(
    harness: *Harness,
    comptime kind: std.meta.Tag(Certificate),
    view: u64,
    parent: u64,
    payload: []const u8,
) !Certificate {
    const Vote = if (kind == .notarization) Notarize else Finalize;
    const proposal: @import("types.zig").Proposal(Digest) =
        .init(.new(epoch, .new(view)), .new(parent), Sha256.hash(&.{payload}));
    var votes: [4]Vote = undefined;
    const quorum = utils.N3f1.quorum(@as(u32, @intCast(harness.schemes.len)));
    assert(quorum <= votes.len);
    for (votes[0..quorum], harness.schemes[0..quorum]) |*vote, *scheme| {
        vote.* = (try Vote.sign(gpa, scheme, proposal)).?;
    }
    const Signed = @FieldType(Certificate, @tagName(kind));
    const scheme = &harness.schemes[0];
    const signed = try Signed.from_votes(gpa, scheme, votes[0..quorum], parallel.sequential);
    return @unionInit(Certificate, @tagName(kind), signed);
}

/// commonware `survives_burst`: before validator 0's engine (mailbox size 1, proposals
/// stalled) starts, an outside peer queues notarizations of views 1 to 3 and a finalization
/// of view 3; the engine works through the burst and reports view 3 finalized.
fn survives_burst_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    try harness.start_network(ctx, 4, null, .absent, .{});
    defer harness.deinit();
    const me = harness.keys()[0];
    const channels = try register(harness.oracle(), me);
    const injector = cryptography.ed25519.PrivateKey.from_seed(9_000_000).public_key();
    var injected = try harness.oracle().control(injector).register(1, test_quota);
    defer injected.sender.deinit();
    defer injected.receiver.deinit();
    try harness.oracle().add_link(injector, me, link_ms(0, 0, 1.0));
    const tracked: p2p.TrackedPeers(Key) = .{
        .primary = .init(&.{me}),
        .secondary = .init(&.{injector}),
    };
    _ = harness.oracle().manager().track(1, tracked);
    try ctx.sleep(.fromMilliseconds(1));
    const certificates = [_]Certificate{
        try quorum_certificate(&harness, .notarization, 1, 0, "payload-1"),
        try quorum_certificate(&harness, .notarization, 2, 1, "payload-2"),
        try quorum_certificate(&harness, .notarization, 3, 2, "payload-3"),
        try quorum_certificate(&harness, .finalization, 3, 2, "payload-3"),
    };
    defer for (certificates) |certificate| codec.free(Certificate, gpa, certificate);
    for (certificates) |certificate| {
        const bytes = try codec.encode(Certificate, gpa, certificate);
        defer gpa.free(bytes);
        gpa.free(try injected.sender.send(.{ .one = me }, &.{bytes}, true));
    }
    harness.mailbox_size = 1;
    harness.stall_proposals = true;
    try harness.start_validator_on(0, channels);
    try harness.validators[0].reporter.wait_for_finalized(.new(3));
}

test "survives burst: a mailbox of one drains a certificate burst" {
    _ = try run_seeded(0, survives_burst_scenario, .{});
}

/// commonware `engine_shutdown`: a lone validator finalizes on its own; after a graceful
/// `stop` or an abort its engine ends, and nothing finalizes afterwards. (commonware counts
/// running engine tasks; that waits on the runtime's task metrics.)
fn engine_shutdown_scenario(ctx: Context, graceful: bool) !void {
    var harness: Harness = undefined;
    try harness.start(ctx, 1, null, .honest);
    defer harness.deinit();
    try ctx.sleep(.fromMilliseconds(1000));
    const early = harness.max_finalized();
    try ctx.sleep(.fromMilliseconds(1500));
    try testing.expect(harness.max_finalized() > early); // The engine is still running.
    const validator = harness.honest(0).?;
    const handle = validator.handle.?;
    validator.handle = null;
    if (graceful) {
        try ctx.child("stop").stop(0, .fromSeconds(5));
        try validator.engine.wait_stopped();
        try (try handle.join()); // The engine returned on its own.
    } else if (handle.abort()) |result| {
        try result;
    } else |_| {} // Aborted before it returned.
    const ended = harness.max_finalized();
    try ctx.sleep(.fromMilliseconds(1000));
    try testing.expectEqual(ended, harness.max_finalized());
}

test "engine shutdown: an aborted engine stops its actors" {
    for (0..3) |seed| _ = try run_seeded(seed, engine_shutdown_scenario, .{false});
}

test "engine shutdown: a graceful stop ends the engine" {
    for (0..3) |seed| _ = try run_seeded(seed, engine_shutdown_scenario, .{true});
}

/// commonware `attributable_reporter_filtering`: every engine reports through the
/// attributable wrapper with verification on. ed25519 is attributable, so each validator
/// still sees its peers' notarize (except at the last view) and finalize votes.
fn attributable_reporter_scenario(ctx: Context) !void {
    var harness: Harness = undefined;
    try harness.start_network(ctx, 3, link_ms(10, 1, 1.0), .honest, .{});
    defer harness.deinit();
    harness.verify_reports = true;
    for (0..harness.validators.len) |index| try harness.start_validator(index);
    const required = 10;
    try harness.wait_all(required);
    try harness.check(required);
    for (harness.validators) |*validator| {
        const reporter = &validator.reporter;
        try testing.expect(reporter.notarized(.new(1)) or reporter.finalized(.new(1)) != null);
        const last = reporter.max_vote_view(.notarize).get();
        try testing.expect(last > 1); // Peer votes were reported at all.
        const through = @max(last, reporter.max_vote_view(.finalize).get());
        for (1..through + 1) |view| {
            const votes = reporter.votes(.new(view));
            if (votes.notarize != 0 and view != last) {
                try testing.expect(@popCount(votes.notarize) > 1);
            }
            if (votes.finalize != 0) try testing.expect(@popCount(votes.finalize) > 1);
        }
    }
}

test "attributable reporter: peer votes reach the reporter verified" {
    _ = try run_seeded(0, attributable_reporter_scenario, .{});
}

/// One run of commonware `unclean_shutdown`: start every validator from its journal, stop
/// them all at a random point within 2 s, and report whether all reached `required`. Short
/// timeouts let a restarted cluster time out of views it cannot finish, as in commonware.
fn unclean_run(ctx: Context, required: u64) !bool {
    var harness: Harness = undefined;
    const timeouts: Harness.Timeouts = .{
        .leader_ms = 500,
        .certification_ms = 1000,
        .retry_ms = 500,
    };
    try harness.start_timed(ctx, 5, link_ms(50, 50, 1.0), .honest, timeouts);
    defer harness.deinit();
    const rng: IoRng = .{ .io = ctx.io() };
    const wait_ms = 100 + rng.next_u64() % 1900;
    try ctx.sleep(.fromMilliseconds(@intCast(wait_ms)));
    for (harness.validators) |*validator| validator.reporter.assert_no_faults();
    const blocked = try harness.oracle().blocked(gpa);
    defer gpa.free(blocked);
    try testing.expectEqual(0, blocked.len);
    return harness.min_finalized() >= required;
}

test "unclean shutdown: repeated crashes recover from the journal" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = 0 });
    defer runner.deinit();
    const restarts_max = 200;
    // Each start after the first crashes storage, keeping only synced journal contents.
    const restarts = for (0..restarts_max) |restart| {
        if (try (try runner.start_context(unclean_run, .{100}))) break restart;
    } else return error.TestUnexpectedResult;
    try testing.expect(restarts > 0);
}
