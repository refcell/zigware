//! commonware's `test_for_all_fixtures` DSTs (`simplex/mod.rs`): the honest-path scenarios
//! run on every canonical (scheme, elector) fixture: threshold VRF with the Random elector
//! (MinPk, MinSig), threshold standard, multisig (MinPk, MinSig), ed25519, and secp256r1
//! with round robin. commonware puts these in its slow group; here slow builds run them at
//! full size and ReleaseSafe runs a quick slice (BLS signing takes minutes in Debug).
//! engine_test.zig runs the ed25519 variants in every build.

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
const engine_test = @import("engine_test.zig");
const twins_campaign_test = @import("twins_campaign_test.zig");
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
/// ReleaseSafe without `-Dslow-tests` runs a quick slice (fewer views, shorter waits, one
/// twins case per fixture) so per-push CI still catches regressions; slow builds (nightly)
/// run commonware's sizes.
const full = build_options.slow_tests;
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

/// A network of `F` validators, each started on demand. Must not move once started.
fn Cluster(comptime F: type, comptime n: u32) type {
    return struct {
        const Self = @This();
        const Restrict = fn (count: usize, a: usize, b: usize) bool;

        ctx: Context,
        fixture: cryptography.certificate.mocks.Fixture(F.Scheme),
        network: *Net,
        network_task: std.Io.Future(@typeInfo(@TypeOf(Net.run)).@"fn".return_type.?),
        relay: Relay,
        validators: [n]Validator(F),
        running: [n]bool,

        fn start(self: *Self, ctx: Context) !void {
            const io = ctx.io();
            var rng: IoRng = .{ .io = io };
            self.ctx = ctx;
            self.fixture = try F.fixture(&rng, n);
            errdefer self.fixture.deinit(gpa);
            self.network = try Net.init(gpa, io, .{
                .max_size = 1024 * 1024,
                .max_peers_per_set = n + 1,
                .disconnect_on_block = true,
                .tracked_peer_sets = 1,
            });
            self.network_task = try io.concurrent(Net.run, .{self.network});
            _ = self.oracle().manager().track(0, .init_primary(.init(self.fixture.participants)));
            self.relay = .init(gpa, io);
            self.running = @splat(false);
        }

        fn deinit(self: *Self) void {
            const io = self.ctx.io();
            // Abort every engine before freeing any mock: live voters relay to all of them.
            for (&self.validators, self.running) |*validator, running| {
                if (running) validator.abort();
            }
            self.relay.deregister_all();
            for (&self.validators, self.running) |*validator, running| {
                if (running) validator.deinit();
            }
            self.relay.deinit();
            self.network.close();
            self.network_task.await(io) catch {};
            self.network.deinit();
            self.fixture.deinit(gpa);
            self.* = undefined;
        }

        fn oracle(self: *const Self) Net.Oracle {
            return self.network.oracle();
        }

        fn start_validator(self: *Self, index: usize) !void {
            assert(!self.running[index]);
            // Per-validator metrics, as commonware's `child("validator").with_attribute(..)`.
            var validator_ctx = self.ctx;
            const scope = self.ctx.scope.child("validator");
            const key = self.fixture.participants[index];
            validator_ctx.scope = scope.with_attribute("public_key", key);
            const validator = &self.validators[index];
            try validator.start(validator_ctx, &self.relay, &self.fixture, index, self.oracle());
            self.running[index] = true;
        }

        fn start_all_but(self: *Self, skipped: ?usize) !void {
            for (0..n) |index| {
                if (skipped == index) continue;
                try self.start_validator(index);
            }
        }

        /// Links (or, with `link == null`, unlinks) every ordered pair `restrict` admits.
        fn link_all(self: *Self, link: ?Link, restrict: ?*const Restrict) !void {
            const peers = self.fixture.participants;
            for (peers, 0..) |from, a| for (peers, 0..) |to, b| {
                if (a == b) continue;
                if (restrict) |admits| if (!admits(peers.len, a, b)) continue;
                if (link) |value| {
                    try self.oracle().add_link(from, to, value);
                } else {
                    try self.oracle().remove_link(from, to);
                }
            };
        }

        /// Replaces the link of every ordered pair `restrict` admits.
        fn relink_all(self: *Self, link: Link, restrict: ?*const Restrict) !void {
            try self.link_all(null, restrict);
            try self.link_all(link, restrict);
        }

        fn wait_all(self: *Self, view: u64) !void {
            for (&self.validators, self.running) |*validator, running| {
                if (running) try validator.reporter.wait_for_finalized(.new(view));
            }
        }

        fn max_finalized(self: *Self) u64 {
            var highest: u64 = 0;
            for (&self.validators, self.running) |*validator, running| {
                if (!running) continue;
                highest = @max(highest, validator.reporter.latest_finalized().get());
            }
            return highest;
        }

        /// No faults, invalid activity, disagreement among running validators, or blocks.
        fn check(self: *Self, through: u64) !void {
            for (&self.validators, self.running) |*validator, running| {
                if (!running) continue;
                validator.reporter.assert_no_faults();
                validator.reporter.assert_no_invalid();
            }
            for (1..through + 1) |view| {
                var expected: ?Digest = null;
                for (&self.validators, self.running) |*validator, running| {
                    if (!running) continue;
                    const payload = validator.reporter.finalized(.new(view)) orelse continue;
                    if (expected) |digest| try testing.expect(digest.order(payload) == .eq);
                    expected = payload;
                }
            }
            const blocked = try self.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
        }
    };
}

fn link_ms(latency_ms: u64, jitter_ms: u64, success_rate: f64) Link {
    return .{
        .latency = .from_millis(latency_ms),
        .jitter = .from_millis(jitter_ms),
        .success_rate = success_rate,
    };
}

/// commonware `all_online`: five validators over 200 ms links finalize `required` views,
/// with no faults, invalid activity, disagreement, or blocks.
fn all_online(comptime F: type, ctx: Context, required: u64) !void {
    var cluster: Cluster(F, 5) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    try cluster.link_all(link_ms(200, 1, 1.0), null);
    try cluster.start_all_but(null);
    try cluster.wait_all(required);
    try cluster.check(required);
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

fn separated(count: usize, a: usize, b: usize) bool {
    const half = count / 2;
    return (a < half and b >= half) or (a >= half and b < half);
}

/// commonware `one_offline`: validator 0 never starts; the rest finalize 100 views, and
/// every online validator records timeouts and nullifications for the offline leader.
fn one_offline(comptime F: type, ctx: Context) !void {
    const n = 5;
    var cluster: Cluster(F, n) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    try cluster.link_all(link_ms(10, 1, 1.0), &not_zero);
    try cluster.start_all_but(0);
    const required: u64 = if (full) 100 else 30;
    try cluster.wait_all(required);
    try cluster.check(required);
    const encoded = try ctx.scope.encode(gpa);
    defer gpa.free(encoded);
    var buffer: [128]u8 = undefined;
    const offline = cluster.fixture.participants[0];
    const label = try std.fmt.bufPrint(&buffer, "leader=\"{f}\"", .{offline});
    const count = engine_test.count_nonzero_metric_lines;
    try testing.expect(count(encoded, &.{ "_timeouts", label }) >= n - 1);
    try testing.expectEqual(n - 1, count(encoded, &.{ "_nullifications", label }));
}

/// commonware `partition`: ten validators split in half finalize nothing, then heal.
fn partition(comptime F: type, ctx: Context) !void {
    var cluster: Cluster(F, 10) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    const link = link_ms(10, 1, 1.0);
    try cluster.link_all(link, null);
    try cluster.start_all_but(null);
    const required: u64 = if (full) 20 else 10;
    try cluster.wait_all(required);
    try cluster.link_all(null, &separated);
    // Let in-progress notarizations and finalizations finish.
    try ctx.sleep(.fromSeconds(10));
    const before = cluster.max_finalized();
    try ctx.sleep(.fromSeconds(if (full) 60 else 20));
    try testing.expectEqual(before, cluster.max_finalized()); // Nothing finalizes while split.
    try cluster.link_all(link, &separated);
    try cluster.wait_all(before + required);
    try cluster.check(before + required);
}

/// commonware `slow_and_lossy_links`: half the messages drop over 200 ms links.
fn slow_and_lossy_links(comptime F: type, ctx: Context) !void {
    var cluster: Cluster(F, 5) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    try cluster.link_all(link_ms(200, 150, 0.5), null);
    try cluster.start_all_but(null);
    const required: u64 = if (full) 20 else 10;
    try cluster.wait_all(required);
    try cluster.check(required);
}

/// commonware `backfill`: validator 0 joins late, cut off from validator 1, and catches up
/// through the others' certificates over degraded links.
fn backfill(comptime F: type, ctx: Context) !void {
    var cluster: Cluster(F, 4) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    try cluster.link_all(link_ms(10, 1, 1.0), &not_zero);
    try cluster.start_all_but(0);
    const required: u64 = if (full) 100 else 30;
    try cluster.wait_all(required);
    // Degrade the online links and let nullifications accrue.
    const slow = link_ms(3000, 0, 1.0);
    try cluster.relink_all(slow, &not_zero);
    try ctx.sleep(.fromSeconds(60));
    // Cut validator 1 off, and link validator 0 to the rest.
    try cluster.link_all(null, &one_not_zero);
    try cluster.link_all(slow, &zero_not_one);
    try cluster.relink_all(link_ms(10, 3, 1.0), &not_one);
    try cluster.start_validator(0);
    try cluster.validators[0].reporter.wait_for_finalized(.new(required));
    try cluster.check(required);
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
    try run_all(all_online, .{@as(u64, if (full) 100 else 30)});
}

test "all fixtures: one offline" {
    try run_all(one_offline, .{});
}

test "all fixtures: partition heals" {
    try run_all(partition, .{});
}

test "all fixtures: slow and lossy links" {
    try run_all(slow_and_lossy_links, .{});
}

test "all fixtures: backfill" {
    try run_all(backfill, .{});
}

// commonware `twins`: `twins_campaign` on `TWINS_CAMPAIGN` over `TWINS_LINK`, with each
// fixture's scheme and elector. Slow builds run all 20 cases per fixture; ReleaseSafe runs
// one case per fixture.
test "all fixtures: twins" {
    if (builtin.mode == .debug and !full) return error.SkipZigTest;
    const campaigns = twins_campaign_test;
    var campaign = campaigns.twins_campaign;
    if (!full) campaign.max_cases = 1;
    inline for (fixtures) |F| {
        try campaigns.Suite(F).run_campaign(campaign, campaigns.twins_link);
    }
}
