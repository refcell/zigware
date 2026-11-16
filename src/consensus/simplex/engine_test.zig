//! Multi-node tests of the simplex engine (commonware `simplex/mod.rs` tests): honest
//! validators on `p2p.simulated` under the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
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
const Scheme = ed25519.Scheme(Digest);
const Net = p2p.simulated.Network(Key);
const Context = runtime.deterministic.Context;
const Application = application_mod.Application(Sha256, Key);
const Relay = relay_mod.Relay(Digest, Key);
const Reporter = reporter_mod.Reporter(Scheme, Digest);
const Conflicter = conflicter_mod.Conflicter(Scheme, Sha256);
const Nuller = nuller_mod.Nuller(Scheme, Sha256);
const Elector = elector_mod.RoundRobinElector;
const Duration = utils.Duration;
const Link = p2p.simulated.Link;
const View = consensus_types.View;
const Epoch = consensus_types.Epoch;

const Params = struct {
    pub const Context = runtime.deterministic.Context;
    pub const Scheme = ed25519.Scheme(Sha256.Digest);
    pub const Elector = elector_mod.RoundRobinElector;
    pub const Blocker = Net.Control;
    pub const Digest = Sha256.Digest;
    pub const Automaton = *Application;
    pub const Relay = *Application;
    pub const Reporter = *reporter_mod.Reporter(ed25519.Scheme(Sha256.Digest), Sha256.Digest);
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
const Role = enum { honest, conflicter, nuller };

/// A Byzantine mock on the vote channel; the other channels stay registered and unused.
const Byzantine = struct {
    role: Role,
    conflicter: Conflicter,
    nuller: Nuller,
    channels: [3]Channel,
    handle: runtime.context.Handle(void),

    fn run(ctx: Context, byzantine: *Byzantine) void {
        _ = ctx;
        const votes = &byzantine.channels[0];
        switch (byzantine.role) {
            .honest => unreachable, // Proof: only Byzantine roles start this task.
            .conflicter => byzantine.conflicter.run(&votes.sender, &votes.receiver),
            .nuller => byzantine.nuller.run(&votes.sender, &votes.receiver),
        }
    }

    fn stop(byzantine: *Byzantine) void {
        byzantine.handle.abort() catch {};
        for (&byzantine.channels) |*channel| {
            channel.sender.deinit();
            channel.receiver.deinit();
        }
    }
};

/// One validator's engine and mocks. Must not move once started.
const Validator = struct {
    byzantine: ?*Byzantine = null,
    application: Application,
    reporter: Reporter,
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
    network: *Net,
    network_task: std.Io.Future((std.Io.Cancelable || Allocator.Error)!void),
    relay: Relay,
    validators: []Validator,
    started: usize = 0,
    /// Whether honest validators keep votes of finalized views (commonware's Byzantine
    /// tests set it).
    track_historical_votes: bool = false,

    const Fixture = cryptography.certificate.mocks.Fixture(Scheme);

    fn keys(harness: *const Harness) []const Key {
        return harness.fixture.participants;
    }

    fn oracle(harness: *const Harness) Net.Oracle {
        return harness.network.oracle();
    }

    /// Starts `n` validators, every pair linked by `link`; validator 0 plays `role`.
    fn start(harness: *Harness, ctx: Context, n: u32, link: Link, role: Role) !void {
        const io = ctx.io();
        var rng = utils.rng.test_rng();
        harness.* = undefined;
        harness.ctx = ctx;
        harness.fixture = try ed25519.fixture(Digest, gpa, &rng, "consensus", n);
        errdefer harness.fixture.deinit(gpa);
        harness.network = try Net.init(gpa, io, .{
            .max_size = 1024 * 1024,
            .max_peers_per_set = n + 1,
            .disconnect_on_block = true,
            .tracked_peer_sets = 1,
        });
        harness.network_task = try io.concurrent(Net.run, .{harness.network});
        harness.relay = .init(gpa, io);
        harness.validators = try gpa.alloc(Validator, n);
        harness.started = 0;
        const peers = harness.keys();
        _ = harness.oracle().manager().track(0, .init_primary(.init(peers)));
        try harness.link_all(link, null);
        harness.track_historical_votes = role != .honest;
        for (harness.validators, peers, 0..) |*validator, key, index| {
            if (index == 0 and role != .honest) {
                try harness.start_byzantine(validator, key, role);
            } else {
                try harness.start_validator(validator, key, index);
            }
            harness.started += 1;
        }
    }

    fn start_byzantine(harness: *Harness, validator: *Validator, key: Key, role: Role) !void {
        const io = harness.ctx.io();
        const byzantine = try gpa.create(Byzantine);
        errdefer gpa.destroy(byzantine);
        const scheme = &harness.fixture.schemes[0];
        byzantine.* = .{
            .role = role,
            .conflicter = .init(gpa, io, scheme),
            .nuller = .init(gpa, scheme),
            .channels = try register(harness.oracle(), key),
            .handle = undefined,
        };
        byzantine.handle = try harness.ctx.child("byzantine").spawn(Byzantine.run, .{byzantine});
        validator.* = undefined;
        validator.byzantine = byzantine;
    }

    /// The validators running the engine.
    fn honest(harness: *Harness, index: usize) ?*Validator {
        const validator = &harness.validators[index];
        return if (validator.byzantine == null) validator else null;
    }

    fn deinit(harness: *Harness) void {
        // Abort every engine before freeing any mock: live voters relay to all applications.
        const validators = harness.validators[0..harness.started];
        for (validators) |*validator| {
            if (validator.byzantine) |byzantine| byzantine.stop() else abort(validator);
        }
        harness.relay.deregister_all();
        for (validators) |*validator| {
            if (validator.byzantine) |byzantine| gpa.destroy(byzantine) else stop_actors(validator);
        }
        gpa.free(harness.validators);
        harness.relay.deinit();
        harness.network.close();
        harness.network_task.await(harness.ctx.io()) catch {};
        harness.network.deinit();
        harness.fixture.deinit(gpa);
        harness.* = undefined;
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

    fn start_validator(harness: *Harness, validator: *Validator, key: Key, index: usize) !void {
        const io = harness.ctx.io();
        validator.* = undefined;
        validator.byzantine = null;
        validator.handle = null;
        validator.application = try .init(gpa, io, .{
            .relay = &harness.relay,
            .me = key,
            .propose_latency = .{ .mean = 10, .std_dev = 5 },
            .verify_latency = .{ .mean = 10, .std_dev = 5 },
            .certify_latency = .{ .mean = 10, .std_dev = 5 },
        });
        try validator.application.register();
        validator.reporter = .init(gpa, io, &harness.fixture.verifier);
        validator.page_cache = try .init(gpa, page_size, page_cache_size);
        const n: u32 = @intCast(harness.validators.len);
        validator.elector = try elector_mod.RoundRobin(Sha256).default().build(gpa, n);
        validator.partition = @splat(0);
        _ = try std.fmt.bufPrint(&validator.partition, "validator-{d}", .{index});
        const control = harness.oracle().control(key);
        var cfg = engine_config(validator, harness.fixture.schemes[index], control);
        cfg.track_historical_votes = harness.track_historical_votes;
        try validator.engine.init(harness.ctx, cfg);
        const channels = try register(harness.oracle(), key);
        validator.handle = try harness.ctx.child("engine").spawn(Engine.run, .{
            &validator.engine, channels[0], channels[1], channels[2],
        });
    }

    /// Waits until every validator finalized `view`.
    fn wait_all(harness: *Harness, view: u64) !void {
        for (0..harness.validators.len) |index| {
            const validator = harness.honest(index) orelse continue;
            try validator.reporter.wait_for_finalized(.new(view));
        }
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

    /// Only validator 0 committed faults, of the `allowed` kinds, at least once; only
    /// honest validators blocked, and only validator 0.
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
        try testing.expect(count > 0);
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
        .reporter = &validator.reporter,
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
