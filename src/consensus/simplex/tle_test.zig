//! commonware's `tle` DST (`simplex/mod.rs`): four validators run the threshold VRF scheme
//! with the Random elector, a message is encrypted to round (333, 10) before it exists, and
//! the seed of that round's notarization decrypts it. Skipped in Debug without
//! `-Dslow-tests`.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const consensus_types = @import("../types.zig");
const elector_mod = @import("elector.zig");
const engine_mod = @import("engine.zig");
const application_mod = @import("mocks/application.zig");
const relay_mod = @import("mocks/relay.zig");
const reporter_mod = @import("mocks/reporter.zig");
const vrf = @import("scheme/bls12381_threshold/vrf.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const Key = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Context = runtime.deterministic.Context;
const Application = application_mod.Application(Sha256, Key);
const Relay = relay_mod.Relay(Sha256.Digest, Key);
const IoRng = @import("actors/context.zig").IoRng;
const Round = consensus_types.Round;
const Epoch = consensus_types.Epoch;
const tle = cryptography.bls12381.tle;
const primitives = cryptography.bls12381.primitives;

const epoch: Epoch = .new(333);
const n = 4;
const test_quota = p2p.Quota.per_second(1024);

fn Params(comptime V: type) type {
    return struct {
        pub const Context = runtime.deterministic.Context;
        pub const Scheme = vrf.Scheme(Sha256.Digest, Key, V);
        pub const Elector = elector_mod.RandomElector(Sha256, V);
        pub const Blocker = Net.Control;
        pub const Digest = Sha256.Digest;
        pub const Automaton = *Application;
        pub const Relay = *Application;
        pub const Reporter = *reporter_mod.Reporter(Scheme, Sha256.Digest);
        pub const Strategy = parallel.Sequential;
        pub const Sender = Net.Sender;
        pub const Receiver = Net.Receiver;
    };
}

/// One validator's engine and mocks. Must not move once started.
fn Validator(comptime V: type) type {
    const P = Params(V);
    return struct {
        const Self = @This();
        const Engine = engine_mod.Engine(P);

        application: Application,
        reporter: reporter_mod.Reporter(P.Scheme, Sha256.Digest),
        page_cache: runtime.buffer.paged.CacheRef,
        engine: Engine,
        partition: [16]u8,
        handle: ?runtime.context.Handle(Engine.RunResult),

        fn config(self: *Self, scheme: P.Scheme, blocker: Net.Control) Engine.Config {
            return .{
                .scheme = scheme,
                .elector = elector_mod.Random(Sha256).init(.v1).build(V, n),
                .blocker = blocker,
                .automaton = &self.application,
                .relay = &self.application,
                .reporter = &self.reporter,
                .track_historical_votes = false,
                .strategy = parallel.sequential,
                .partition = std.mem.sliceTo(&self.partition, 0),
                .mailbox_size = 1024,
                .epoch = epoch,
                .floor = .{ .genesis = application_mod.genesis(Sha256, epoch) },
                .replay_buffer = 1024 * 1024,
                .write_buffer = 1024 * 1024,
                .page_cache = &self.page_cache,
                .leader_timeout = .from_millis(100),
                .certification_timeout = .from_millis(200),
                .timeout_retry = .from_millis(500),
                .view_retention = .new(100),
                .skip = .{ .enabled = .{ .timeout = .from_secs(50) } },
                .fetch_timeout = .from_millis(100),
                .fetch_retry_delay = .from_millis(100),
                .forward = .disabled,
            };
        }

        fn start(
            self: *Self,
            ctx: Context,
            relay: *Relay,
            fixture: anytype,
            index: usize,
            oracle: Net.Oracle,
        ) !void {
            const io = ctx.io();
            const key = fixture.participants[index];
            const normal: application_mod.Latency = .{ .mean = 10, .std_dev = 5 };
            self.handle = null;
            self.application = try .init(gpa, io, .{
                .relay = relay,
                .me = key,
                .propose_latency = normal,
                .verify_latency = normal,
                .certify_latency = normal,
            });
            try self.application.register();
            self.reporter = .init(gpa, io, &fixture.verifier);
            self.page_cache = try .init(gpa, 1024, 10);
            self.partition = @splat(0);
            _ = try std.fmt.bufPrint(&self.partition, "validator-{d}", .{index});
            var channels: [3]engine_mod.Channel(P) = undefined;
            for (&channels, 0..) |*channel, kind| {
                const registered = try oracle.control(key).register(kind, test_quota);
                channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
            }
            const scheme = fixture.schemes[index];
            try self.engine.init(ctx, self.config(scheme, oracle.control(key)));
            self.handle = try ctx.child("engine").spawn(Engine.run, .{
                &self.engine, channels[0], channels[1], channels[2],
            });
        }

        fn abort(self: *Self) void {
            const handle = self.handle orelse return;
            self.handle = null;
            const result = handle.abort() catch return; // Aborted before it returned.
            result catch |err| std.debug.panic("engine failed: {t}", .{err});
        }

        fn deinit(self: *Self) void {
            assert(self.handle == null);
            self.engine.deinit();
            self.page_cache.deinit();
            self.reporter.deinit();
            self.application.deinit();
            self.* = undefined;
        }
    };
}

/// Waits (up to 30 simulated seconds, commonware's timed runner) until validator 0 reports
/// the target round's notarization, then decrypts the ciphertext with its seed.
fn decrypt_at_target(
    comptime V: type,
    ctx: Context,
    validator: *Validator(V),
    target: Round,
    ciphertext: tle.Ciphertext(V),
) !tle.Block {
    const polls_max = 300;
    for (0..polls_max) |_| {
        try ctx.sleep(.fromMilliseconds(100));
        var notarization = try validator.reporter.notarization(target.view) orelse continue;
        defer notarization.deinit(gpa);
        const seed = vrf.seed(V, &notarization);
        assert(seed.round == target);
        return seed.decrypt(ciphertext) orelse error.DecryptionFailed;
    }
    return error.TargetNotNotarized;
}

fn run(comptime V: type, ctx: Context) !void {
    const io = ctx.io();
    var rng: IoRng = .{ .io = io };
    const S = Params(V).Scheme;
    var fixture = try vrf.fixture(S, gpa, &rng, "consensus", n);
    defer fixture.deinit(gpa);
    const network = try Net.init(gpa, io, .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = n + 1,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    });
    defer network.deinit();
    var network_task = try io.concurrent(Net.run, .{network});
    defer network_task.await(io) catch {};
    defer network.close();
    const oracle = network.oracle();
    _ = oracle.manager().track(0, .init_primary(.init(fixture.participants)));
    const link: p2p.simulated.Link = .{
        .latency = .from_millis(10),
        .jitter = .from_millis(5),
        .success_rate = 1.0,
    };
    for (fixture.participants, 0..) |from, a| for (fixture.participants, 0..) |to, b| {
        if (a != b) try oracle.add_link(from, to, link);
    };
    var relay: Relay = .init(gpa, io);
    defer relay.deinit();
    var validators: [n]Validator(V) = undefined;
    var started: usize = 0;
    defer {
        // Abort every engine before freeing any mock: live voters relay to all applications.
        for (validators[0..started]) |*validator| validator.abort();
        relay.deregister_all();
        for (validators[0..started]) |*validator| validator.deinit();
    }
    for (&validators, 0..) |*validator, index| {
        try validator.start(ctx, &relay, &fixture, index, oracle);
        started += 1;
    }
    const target: Round = .new(epoch, .new(10));
    const message: tle.Block = "Secret message for future view10".*;
    const ciphertext = try fixture.schemes[0].encrypt(&rng, target, &message);
    const decrypted = try decrypt_at_target(V, ctx, &validators[0], target, ciphertext);
    try testing.expectEqualSlices(u8, &message, &decrypted);
}

fn run_variant(comptime V: type) !void {
    const scenario = struct {
        fn call(ctx: Context) !void {
            return run(V, ctx);
        }
    }.call;
    const SoakRound = struct {
        fn run(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start_context(scenario, .{}));
        }
    };
    try runtime.deterministic.soak(gpa, .{ .seed = 0 }, {}, SoakRound.run);
}

test "tle: the target round's seed decrypts a message encrypted before it" {
    // BLS signing and recovery take minutes in Debug; ReleaseSafe CI runs it.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    try run_variant(primitives.MinPk);
    try run_variant(primitives.MinSig);
}
