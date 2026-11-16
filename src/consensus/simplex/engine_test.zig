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
const Elector = elector_mod.RoundRobinElector;
const Duration = utils.Duration;
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

/// One validator's engine and mocks. Must not move once started.
const Validator = struct {
    application: Application,
    reporter: Reporter,
    page_cache: runtime.buffer.paged.CacheRef,
    elector: Elector,
    engine: Engine,
    partition: [32]u8,
    handle: ?runtime.context.Handle(Engine.RunResult) = null,
};

const Options = struct {
    n: u32,
    required: u64,
    latency_ms: u64 = 10,
};

fn link_all(oracle: Net.Oracle, keys: []const Key, latency_ms: u64) !void {
    for (keys) |from| for (keys) |to| {
        if (from.order(to) == .eq) continue;
        try oracle.add_link(from, to, .{
            .latency = Duration.from_millis(latency_ms),
            .jitter = Duration.from_millis(1),
            .success_rate = 1.0,
        });
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
        .skip = .disabled,
        .fetch_timeout = .from_secs(1),
        .fetch_retry_delay = .from_millis(100),
        .forward = .disabled,
    };
}

fn all_online(ctx: Context, options: Options) !void {
    const io = ctx.io();
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "consensus", options.n);
    defer fixture.deinit(gpa);
    const keys = fixture.participants;
    const network = try Net.init(gpa, io, .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = options.n + 1,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    });
    defer network.deinit();
    var network_task = try io.concurrent(Net.run, .{network});
    defer {
        network.close();
        network_task.await(io) catch {};
    }
    const oracle = network.oracle();
    _ = oracle.manager().track(0, .init_primary(.init(keys)));
    try link_all(oracle, keys, options.latency_ms);

    var relay: Relay = .init(gpa, io);
    defer relay.deinit();
    const validators = try gpa.alloc(Validator, options.n);
    defer gpa.free(validators);
    var started: usize = 0;
    defer for (validators[0..started]) |*validator| stop(validator);
    for (validators, keys, 0..) |*validator, key, index| {
        try start(ctx, validator, &relay, &fixture, oracle, key, index);
        started += 1;
    }
    for (validators) |*validator| try validator.reporter.wait_for_finalized(.new(options.required));
    for (validators) |*validator| {
        validator.reporter.assert_no_faults();
        validator.reporter.assert_no_invalid();
    }
    // Every validator finalized the same payload at each view both saw finalized.
    for (1..options.required + 1) |view| {
        var expected: ?Digest = null;
        for (validators) |*validator| {
            const payload = validator.reporter.finalized(.new(view)) orelse continue;
            if (expected) |digest| try testing.expect(digest.order(payload) == .eq);
            expected = payload;
        }
    }
}

fn start(
    ctx: Context,
    validator: *Validator,
    relay: *Relay,
    fixture: anytype,
    oracle: Net.Oracle,
    key: Key,
    index: usize,
) !void {
    const io = ctx.io();
    validator.* = undefined;
    validator.handle = null;
    validator.application = try .init(gpa, io, .{
        .relay = relay,
        .me = key,
        .propose_latency = .{ .mean = 10, .std_dev = 5 },
        .verify_latency = .{ .mean = 10, .std_dev = 5 },
        .certify_latency = .{ .mean = 10, .std_dev = 5 },
    });
    try validator.application.register();
    validator.reporter = .init(gpa, io, &fixture.verifier);
    validator.page_cache = try .init(gpa, page_size, page_cache_size);
    const n: u32 = @intCast(fixture.schemes.len);
    validator.elector = try elector_mod.RoundRobin(Sha256).default().build(gpa, n);
    validator.partition = @splat(0);
    _ = try std.fmt.bufPrint(&validator.partition, "validator-{d}", .{index});
    const control = oracle.control(key);
    const cfg = engine_config(validator, fixture.schemes[index], control);
    try validator.engine.init(ctx, cfg);
    const channels = try register(oracle, key);
    validator.handle = try ctx.child("engine").spawn(Engine.run, .{
        &validator.engine, channels[0], channels[1], channels[2],
    });
}

fn stop(validator: *Validator) void {
    if (validator.handle) |handle| {
        const result = handle.abort() catch return stop_actors(validator);
        result catch |err| std.debug.panic("engine failed: {t}", .{err});
    }
    stop_actors(validator);
}

fn stop_actors(validator: *Validator) void {
    validator.engine.deinit();
    validator.elector.deinit(gpa);
    validator.page_cache.deinit();
    validator.reporter.deinit();
    validator.application.deinit();
}

fn run_all_online(seed: u64, options: Options) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = seed });
    defer runner.deinit();
    try (try runner.start_context(all_online, .{options}));
}

test "four honest validators finalize" {
    try run_all_online(0, .{ .n = 4, .required = 10 });
}
