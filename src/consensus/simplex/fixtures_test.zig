//! commonware's `test_for_all_fixtures` DSTs (`simplex/mod.rs`): the honest-path scenarios
//! run on every canonical (scheme, elector) fixture: threshold VRF with the Random elector
//! (MinPk, MinSig), threshold standard, multisig (MinPk, MinSig), ed25519, and secp256r1
//! with round robin. commonware puts these in its slow group; here they run in ReleaseSafe
//! and with `-Dslow-tests` (BLS signing takes minutes in Debug). engine_test.zig runs the
//! ed25519 variants in every build.

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
const ed25519 = @import("scheme/ed25519.zig");
const secp256r1 = @import("scheme/secp256r1.zig");
const multisig = @import("scheme/bls12381_multisig.zig");
const standard = @import("scheme/bls12381_threshold/standard.zig");
const vrf = @import("scheme/bls12381_threshold/vrf.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Key = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Link = p2p.simulated.Link;
const Context = runtime.deterministic.Context;
const Application = application_mod.Application(Sha256, Key);
const Relay = relay_mod.Relay(Digest, Key);
const IoRng = @import("actors/context.zig").IoRng;
const Epoch = consensus_types.Epoch;
const primitives = cryptography.bls12381.primitives;

const epoch: Epoch = .new(333);
const test_quota = p2p.Quota.per_second(1024);

/// One canonical fixture: the scheme, its elector, and how to build both.
fn RoundRobinFixture(comptime S: type, comptime make: anytype) type {
    return struct {
        pub const Scheme = S;
        pub const Elector = elector_mod.RoundRobinElector;

        pub fn fixture(rng: anytype, n: u32) !cryptography.certificate.mocks.Fixture(S) {
            return make(gpa, rng, "consensus", n);
        }

        pub fn elector(n: u32) !Elector {
            return elector_mod.RoundRobin(Sha256).default().build(gpa, n);
        }

        pub fn deinit_elector(value: *Elector) void {
            value.deinit(gpa);
        }
    };
}

fn VrfFixture(comptime V: type) type {
    return struct {
        pub const Scheme = vrf.Scheme(Digest, Key, V);
        pub const Elector = elector_mod.RandomElector(Sha256, V);

        pub fn fixture(rng: anytype, n: u32) !cryptography.certificate.mocks.Fixture(Scheme) {
            return vrf.fixture(Scheme, gpa, rng, "consensus", n);
        }

        pub fn elector(n: u32) !Elector {
            return elector_mod.Random(Sha256).init(.v1).build(V, n);
        }

        pub fn deinit_elector(_: *Elector) void {}
    };
}

fn make_ed25519(allocator: Allocator, rng: anytype, namespace: []const u8, n: u32) !Ed25519 {
    return ed25519.fixture(Digest, allocator, rng, namespace, n);
}
const Ed25519 = cryptography.certificate.mocks.Fixture(ed25519.Scheme(Digest));

fn Maker(comptime S: type, comptime module: type) type {
    return struct {
        fn make(
            allocator: Allocator,
            rng: anytype,
            namespace: []const u8,
            n: u32,
        ) !cryptography.certificate.mocks.Fixture(S) {
            return module.fixture(S, allocator, rng, namespace, n);
        }
    };
}

const Secp = secp256r1.Scheme(Digest, Key);
fn Multisig(comptime V: type) type {
    return multisig.Scheme(Digest, Key, V);
}
fn Standard(comptime V: type) type {
    return standard.Scheme(Digest, Key, V);
}

fn BlsFixture(comptime Of: fn (type) type, comptime module: type, comptime V: type) type {
    return RoundRobinFixture(Of(V), Maker(Of(V), module).make);
}

/// commonware `for_each_fixture`, in its order.
const fixtures = .{
    VrfFixture(primitives.MinPk),
    VrfFixture(primitives.MinSig),
    BlsFixture(Standard, standard, primitives.MinPk),
    BlsFixture(Standard, standard, primitives.MinSig),
    BlsFixture(Multisig, multisig, primitives.MinPk),
    BlsFixture(Multisig, multisig, primitives.MinSig),
    RoundRobinFixture(ed25519.Scheme(Digest), make_ed25519),
    RoundRobinFixture(Secp, Maker(Secp, secp256r1).make),
};

fn Params(comptime F: type) type {
    return struct {
        pub const Context = runtime.deterministic.Context;
        pub const Scheme = F.Scheme;
        pub const Elector = F.Elector;
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
fn Validator(comptime F: type) type {
    const P = Params(F);
    return struct {
        const Self = @This();
        const Engine = engine_mod.Engine(P);

        application: Application,
        reporter: reporter_mod.Reporter(P.Scheme, Digest),
        page_cache: runtime.buffer.paged.CacheRef,
        elector: F.Elector,
        engine: Engine,
        partition: [16]u8,
        handle: ?runtime.context.Handle(Engine.RunResult),

        /// commonware's engine configuration for the honest-path DSTs.
        fn config(self: *Self, scheme: P.Scheme, blocker: Net.Control) Engine.Config {
            return .{
                .scheme = scheme,
                .elector = self.elector,
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
            self.elector = try F.elector(@intCast(fixture.participants.len));
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
            F.deinit_elector(&self.elector);
            self.page_cache.deinit();
            self.reporter.deinit();
            self.application.deinit();
            self.* = undefined;
        }
    };
}

/// commonware `all_online`: five validators over 200 ms links finalize `required` views,
/// with no faults, invalid activity, disagreement, or blocks.
fn all_online(comptime F: type, ctx: Context, required: u64) !void {
    const n = 5;
    const io = ctx.io();
    var rng: IoRng = .{ .io = io };
    var fixture = try F.fixture(&rng, n);
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
    const link: Link = .{
        .latency = .from_millis(200),
        .jitter = .from_millis(1),
        .success_rate = 1.0,
    };
    for (fixture.participants, 0..) |from, a| for (fixture.participants, 0..) |to, b| {
        if (a != b) try oracle.add_link(from, to, link);
    };
    var relay: Relay = .init(gpa, io);
    defer relay.deinit();
    var validators: [n]Validator(F) = undefined;
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
    for (&validators) |*validator| try validator.reporter.wait_for_finalized(.new(required));
    try check_agreement(F, &validators, required);
    const blocked = try oracle.blocked(gpa);
    defer gpa.free(blocked);
    try testing.expectEqual(0, blocked.len);
}

/// No faults or invalid activity, and every validator finalized the same payload at each
/// view at or below `through`.
fn check_agreement(comptime F: type, validators: []Validator(F), through: u64) !void {
    for (validators) |*validator| {
        validator.reporter.assert_no_faults();
        validator.reporter.assert_no_invalid();
    }
    for (1..through + 1) |view| {
        var expected: ?Digest = null;
        for (validators) |*validator| {
            const payload = validator.reporter.finalized(.new(view)) orelse continue;
            if (expected) |digest| try testing.expect(digest.order(payload) == .eq);
            expected = payload;
        }
    }
}

fn run_all(comptime scenario: anytype, args: anytype) !void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    inline for (fixtures) |F| {
        const Bound = struct {
            fn call(ctx: Context, inner: @TypeOf(args)) !void {
                return @call(.auto, scenario, .{ F, ctx } ++ inner);
            }
        };
        var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = 0 });
        defer runner.deinit();
        try (try runner.start_context(Bound.call, .{args}));
    }
}

test "all fixtures: all online" {
    try run_all(all_online, .{@as(u64, 100)});
}
