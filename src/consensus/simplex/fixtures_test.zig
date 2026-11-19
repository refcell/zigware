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
const utils = @import("utils");
const runtime = @import("runtime");
const consensus_types = @import("../types.zig");
const elector_mod = @import("elector.zig");
const engine_mod = @import("engine.zig");
const engine_test = @import("engine_test.zig");
const twins_campaign_test = @import("twins_campaign_test.zig");
const application_mod = @import("mocks/application.zig");
const relay_mod = @import("mocks/relay.zig");
const reporter_mod = @import("mocks/reporter.zig");
const conflicter_mod = @import("mocks/conflicter.zig");
const nuller_mod = @import("mocks/nuller.zig");
const impersonator_mod = @import("mocks/impersonator.zig");
const reconfigurer_mod = @import("mocks/reconfigurer.zig");
const outdated_mod = @import("mocks/outdated.zig");
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
    engine_test.Ed25519Fixture,
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

/// How a validator differs from commonware's honest-path defaults.
const Options = struct {
    /// Its application takes 10 s per step (commonware `slow_validator`).
    slow: bool = false,
    /// commonware `unclean_shutdown`'s short progress timeouts and retry, so a restarted
    /// cluster times out of views it cannot finish.
    short_timeouts: bool = false,
};

const Role = enum { conflicter, nuller, impersonator, reconfigurer, outdated };

/// A Byzantine mock on the vote channel; the other channels stay registered and unused.
fn Byzantine(comptime F: type) type {
    const S = F.Scheme;
    return struct {
        const Self = @This();

        role: Role,
        conflicter: conflicter_mod.Conflicter(S, Sha256),
        nuller: nuller_mod.Nuller(S, Sha256),
        impersonator: impersonator_mod.Impersonator(S, Sha256),
        reconfigurer: reconfigurer_mod.Reconfigurer(S, Sha256),
        outdated: outdated_mod.Outdated(S, Sha256),
        channels: [3]engine_mod.Channel(Params(F)),
        handle: runtime.context.Handle(void),

        /// Registers `key`'s channels and starts the mock. Must not move once started.
        fn start(
            self: *Self,
            ctx: Context,
            role: Role,
            scheme: *const S,
            control: Net.Control,
        ) !void {
            const io = ctx.io();
            self.* = .{
                .role = role,
                .conflicter = .init(gpa, io, scheme),
                .nuller = .init(gpa, scheme),
                .impersonator = .init(gpa, scheme),
                .reconfigurer = .init(gpa, scheme),
                // Four times the view retention, as in commonware's `outdated` test.
                .outdated = .init(gpa, scheme, .new(40)),
                .channels = undefined,
                .handle = undefined,
            };
            for (&self.channels, 0..) |*channel, kind| {
                const registered = try control.register(kind, test_quota);
                channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
            }
            self.handle = try ctx.child("byzantine").spawn(Self.run, .{self});
            assert(scheme.me() != null);
        }

        fn run(_: Context, self: *Self) void {
            const votes = &self.channels[0];
            switch (self.role) {
                .conflicter => self.conflicter.run(&votes.sender, &votes.receiver),
                .nuller => self.nuller.run(&votes.sender, &votes.receiver),
                .impersonator => self.impersonator.run(&votes.sender, &votes.receiver),
                .reconfigurer => self.reconfigurer.run(&votes.sender, &votes.receiver),
                .outdated => self.outdated.run(&votes.sender, &votes.receiver),
            }
        }

        fn stop(self: *Self) void {
            self.handle.abort() catch {};
            self.outdated.deinit();
            for (&self.channels) |*channel| {
                channel.sender.deinit();
                channel.receiver.deinit();
            }
        }
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
        fn config(
            self: *Self,
            scheme: P.Scheme,
            blocker: Net.Control,
            options: Options,
        ) Engine.Config {
            const short = options.short_timeouts;
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
                .leader_timeout = if (short) .from_millis(500) else .from_secs(1),
                .certification_timeout = if (short) .from_secs(1) else .from_secs(2),
                .timeout_retry = if (short) .from_millis(500) else .from_secs(10),
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
            options: Options,
        ) !void {
            const slow = options.slow;
            const io = ctx.io();
            const key = fixture.participants[index];
            const normal: application_mod.Latency = .{ .mean = 10, .std_dev = 5 };
            // commonware `slow_validator`'s application: 10 s per step.
            const stalled: application_mod.Latency = .{ .mean = 10_000, .std_dev = 5 };
            self.handle = null;
            self.application = try .init(gpa, io, .{
                .relay = relay,
                .me = key,
                .propose_latency = if (slow) .{ .mean = 10_000, .std_dev = 0 } else normal,
                .verify_latency = if (slow) stalled else normal,
                .certify_latency = if (slow) stalled else normal,
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
            try self.engine.init(ctx, self.config(scheme, oracle.control(key), options));
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
        /// The validator whose application takes 10 s per step, if any.
        slow: ?usize,
        /// Validator 0's Byzantine mock, when it runs one instead of the engine.
        byzantine: ?*Byzantine(F),
        short_timeouts: bool,

        fn start(self: *Self, ctx: Context) !void {
            var rng: IoRng = .{ .io = ctx.io() };
            return self.start_with(ctx, &rng);
        }

        /// `start`, drawing the fixture from `rng`; a fixed rng keeps the same keys across
        /// restarts (commonware `unclean_shutdown`).
        fn start_with(self: *Self, ctx: Context, rng: anytype) !void {
            const io = ctx.io();
            self.ctx = ctx;
            self.fixture = try F.fixture(rng, n);
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
            self.slow = null;
            self.byzantine = null;
            self.short_timeouts = false;
        }

        fn deinit(self: *Self) void {
            const io = self.ctx.io();
            if (self.byzantine) |byzantine| {
                byzantine.stop();
                gpa.destroy(byzantine);
            }
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
            const options: Options = .{
                .slow = self.slow == index,
                .short_timeouts = self.short_timeouts,
            };
            const fixture = &self.fixture;
            try validator.start(validator_ctx, &self.relay, fixture, index, self.oracle(), options);
            self.running[index] = true;
        }

        /// Crashes every running validator; each restarts from its journal on `start_validator`.
        fn crash_all(self: *Self) void {
            // Abort every engine before freeing any mock: live voters relay to all of them.
            for (&self.validators, self.running) |*validator, running| {
                if (running) validator.abort();
            }
            self.relay.deregister_all();
            for (&self.validators, &self.running) |*validator, *running| {
                if (running.*) validator.deinit();
                running.* = false;
            }
            assert(std.mem.indexOfScalar(bool, &self.running, true) == null);
        }

        /// Starts validator 0 as the Byzantine mock `role`.
        fn start_byzantine(self: *Self, role: Role) !void {
            assert(self.byzantine == null);
            assert(!self.running[0]);
            const byzantine = try gpa.create(Byzantine(F));
            errdefer gpa.destroy(byzantine);
            const control = self.oracle().control(self.fixture.participants[0]);
            try byzantine.start(self.ctx, role, &self.fixture.schemes[0], control);
            self.byzantine = byzantine;
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

        fn min_finalized(self: *Self) u64 {
            var lowest: u64 = std.math.maxInt(u64);
            for (&self.validators, self.running) |*validator, running| {
                if (!running) continue;
                lowest = @min(lowest, validator.reporter.latest_finalized().get());
            }
            assert(lowest != std.math.maxInt(u64)); // Some validator is running.
            return lowest;
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
                if (running) validator.reporter.assert_no_faults();
            }
            try self.check_agreement(through);
            const blocked = try self.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
        }

        /// Only validator 0 committed faults, each of an `allowed` kind, at least once (none
        /// when `allowed` is empty); only running validators blocked, and only validator 0.
        fn check_byzantine(self: *Self, comptime allowed: anytype) !void {
            var count: usize = 0;
            for (&self.validators, self.running) |*validator, running| {
                if (!running) continue;
                for (validator.reporter.fault_list()) |fault| {
                    try testing.expectEqual(0, fault.signer.get());
                    const known = inline for (allowed) |kind| {
                        if (fault.kind == kind) break true;
                    } else false;
                    try testing.expect(known);
                    count += 1;
                }
            }
            try testing.expectEqual(allowed.len > 0, count > 0);
            const byzantine = self.fixture.participants[0];
            const blocked = try self.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expect(blocked.len > 0);
            for (blocked) |pair| {
                try testing.expect(pair.origin.order(byzantine) != .eq);
                try testing.expect(pair.recipient.order(byzantine) == .eq);
            }
        }

        /// No invalid activity, and running validators agree on every finalized view.
        fn check_agreement(self: *Self, through: u64) !void {
            for (&self.validators, self.running) |*validator, running| {
                if (running) validator.reporter.assert_no_invalid();
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
fn slow_and_lossy_links(comptime F: type, ctx: Context, required: u64) !void {
    var cluster: Cluster(F, 5) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    try cluster.link_all(link_ms(200, 150, 0.5), null);
    try cluster.start_all_but(null);
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

/// commonware `slow_validator`: validator 0's application takes 10 s per step; the rest
/// finalize without its notarize or finalize votes.
fn slow_validator(comptime F: type, ctx: Context) !void {
    var cluster: Cluster(F, 5) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    cluster.slow = 0;
    try cluster.link_all(link_ms(10, 1, 1.0), null);
    try cluster.start_all_but(null);
    const required: u64 = if (full) 50 else 20;
    try cluster.wait_all(required); // The slow validator learns finalizations from the rest.
    try cluster.check(required);
    for (&cluster.validators) |*validator| {
        for (1..validator.reporter.latest_finalized().get() + 1) |value| {
            const votes = validator.reporter.votes(.new(value));
            try testing.expectEqual(0, (votes.notarize | votes.finalize) & 1);
        }
    }
}

/// commonware `all_recovery`: over 3 s links no view finishes for a minute; after a minute
/// cut off and relinking at 10 ms, the views right after the highest nullified one are
/// nearly all notarized (the skip timeout recovers quickly).
fn all_recovery(comptime F: type, ctx: Context) !void {
    var cluster: Cluster(F, 5) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    try cluster.link_all(link_ms(3000, 0, 1.0), null);
    try cluster.start_all_but(null);
    try ctx.sleep(.fromSeconds(60));
    try testing.expectEqual(0, cluster.max_finalized()); // Nothing finalizes over slow links.
    try cluster.link_all(null, null);
    try ctx.sleep(.fromSeconds(60));
    var latest: u64 = 0;
    for (&cluster.validators) |*validator| {
        latest = @max(latest, validator.reporter.max_vote_view(.nullify).get());
    }
    try testing.expect(latest > 0);
    try cluster.link_all(link_ms(10, 1, 1.0), null);
    const view_retention = 10;
    // Quick runs wait only until the checked views are past retention.
    const required: u64 = if (full) 100 else latest + 2 * view_retention;
    try cluster.wait_all(required);
    try cluster.check(required);
    const tolerated_missing = 3;
    for (&cluster.validators) |*validator| {
        var found: u32 = 0;
        for (latest..latest + view_retention) |view| {
            if (validator.reporter.notarized(.new(view))) found += 1;
        }
        try testing.expect(found >= view_retention - tolerated_missing);
    }
}

/// commonware `all_crash_after_nullify`: validator 0 never starts and nothing is linked, so
/// the rest only nullify view 1; they crash before a nullification can form, and once
/// restarted from their journals and linked, they rebuild it and finalize.
fn all_crash_after_nullify(comptime F: type, ctx: Context) !void {
    var cluster: Cluster(F, 4) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    try cluster.start_all_but(0);
    // Wait for every online validator to have its nullify for view 1 reported.
    const stalled: consensus_types.View = .new(1);
    const Signers = reporter_mod.Reporter(F.Scheme, Digest).Signers;
    for (1..cluster.validators.len) |index| {
        const own: Signers = @as(Signers, 1) << @intCast(index);
        const reporter = &cluster.validators[index].reporter;
        while (reporter.votes(stalled).nullify & own == 0) try ctx.sleep(.fromMilliseconds(100));
    }
    // The batcher reports a vote before the voter's journal syncs it; let it sync.
    try ctx.sleep(.fromSeconds(1));
    try testing.expectEqual(0, cluster.max_finalized());
    cluster.crash_all();
    try cluster.link_all(link_ms(10, 1, 1.0), &not_zero);
    try cluster.start_all_but(0);
    // Validator 0 never votes, so every restarted vote is needed for a quorum.
    try cluster.wait_all(10);
    try cluster.check(10);
}

/// One run of commonware `unclean_shutdown`: start every validator from its journal, stop
/// them all at a random point within 2 s, and report whether all reached `required`.
fn UncleanRun(comptime F: type) type {
    return struct {
        fn run(ctx: Context, required: u64) !bool {
            return unclean_run(F, ctx, required);
        }
    };
}

fn unclean_run(comptime F: type, ctx: Context, required: u64) !bool {
    var cluster: Cluster(F, 5) = undefined;
    var rng = utils.rng.test_rng();
    try cluster.start_with(ctx, &rng);
    defer cluster.deinit();
    cluster.short_timeouts = true;
    try cluster.link_all(link_ms(50, 50, 1.0), null);
    try cluster.start_all_but(null);
    const random: IoRng = .{ .io = ctx.io() };
    const wait_ms = 100 + random.next_u64() % 1900;
    try ctx.sleep(.fromMilliseconds(@intCast(wait_ms)));
    for (&cluster.validators) |*validator| validator.reporter.assert_no_faults();
    const blocked = try cluster.oracle().blocked(gpa);
    defer gpa.free(blocked);
    try testing.expectEqual(0, blocked.len);
    return cluster.min_finalized() >= required;
}

/// commonware `unclean_shutdown`: crash every validator repeatedly (each start after the
/// first crashes storage, keeping only synced journal contents) until one run finalizes
/// `required` views on all of them.
fn unclean_shutdown(comptime F: type) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = 0 });
    defer runner.deinit();
    const restarts_max = 200;
    const required: u64 = if (full) 100 else 15;
    const restarts = for (0..restarts_max) |restart| {
        if (try (try runner.start_context(UncleanRun(F).run, .{required}))) break restart;
    } else return error.TestUnexpectedResult;
    try testing.expect(restarts > 0);
}

/// commonware `slow_and_lossy_links_seeded`: the run's auditor state.
fn lossy_state(comptime F: type, seed: u64, required: u64) ![8]u8 {
    const Bound = struct {
        fn call(ctx: Context, views: u64) !void {
            return slow_and_lossy_links(F, ctx, views);
        }
    };
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = seed });
    defer runner.deinit();
    try (try runner.start_context(Bound.call, .{required}));
    return runner.auditor.state();
}

/// commonware `conflicter`, `nuller`, `impersonator`, and `reconfigurer`: validator 0 is
/// Byzantine; the honest three still finalize, report its `allowed` faults, and block it.
fn byzantine_scenario(comptime F: type, ctx: Context, role: Role, comptime allowed: anytype) !void {
    var cluster: Cluster(F, 4) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    try cluster.link_all(link_ms(10, 1, 1.0), null);
    try cluster.start_byzantine(role);
    try cluster.start_all_but(0);
    const required: u64 = if (full) 50 else 10;
    try cluster.wait_all(required);
    try cluster.check_agreement(required);
    try cluster.check_byzantine(allowed);
}

/// commonware `outdated`: re-votes for proposals 40 views old are ignored, without faults
/// or blocks.
fn outdated(comptime F: type, ctx: Context) !void {
    var cluster: Cluster(F, 4) = undefined;
    try cluster.start(ctx);
    defer cluster.deinit();
    try cluster.link_all(link_ms(10, 1, 1.0), null);
    try cluster.start_byzantine(.outdated);
    try cluster.start_all_but(0);
    const required: u64 = 60; // Past the mock's 40-view-old re-votes.
    try cluster.wait_all(required);
    try cluster.check(required);
}

/// The quick slice's fixtures: one per scheme family (VRF MinPk, standard MinSig, multisig
/// MinPk, secp256r1); engine_test.zig covers ed25519 in every build.
const quick_fixtures = [fixtures.len]bool{ true, false, false, true, true, false, false, true };

fn run_all(comptime scenario: anytype, args: anytype) !void {
    if (builtin.mode == .debug and !full) return error.SkipZigTest;
    inline for (fixtures, quick_fixtures) |F, quick| {
        if (!full and !quick) continue;
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
    // The other fixture DSTs cover the honest path per push; this one runs nightly.
    if (!full) return error.SkipZigTest;
    try run_all(all_online, .{@as(u64, 100)});
}

test "all fixtures: one offline" {
    try run_all(one_offline, .{});
}

test "all fixtures: partition heals" {
    try run_all(partition, .{});
}

test "all fixtures: slow and lossy links" {
    try run_all(slow_and_lossy_links, .{@as(u64, if (full) 20 else 10)});
}

test "all fixtures: backfill" {
    try run_all(backfill, .{});
}

test "all fixtures: slow validator" {
    try run_all(slow_validator, .{});
}

test "all fixtures: all recovery" {
    try run_all(all_recovery, .{});
}

test "all fixtures: all crash after nullify" {
    try run_all(all_crash_after_nullify, .{});
}

// commonware `determinism`: the same seed replays the same run (its most complex DST).
test "all fixtures: determinism" {
    if (builtin.mode == .debug and !full) return error.SkipZigTest;
    const seeds: u64 = if (full) 5 else 1;
    const required: u64 = if (full) 20 else 5;
    inline for (fixtures, quick_fixtures) |F, quick| {
        if (full or quick) for (0..seeds) |seed| {
            const state = try lossy_state(F, seed, required);
            try testing.expectEqualSlices(u8, &state, &try lossy_state(F, seed, required));
        };
    }
}

// commonware `test_distinct_states`: each fixture takes a different path on the same seed.
test "all fixtures: distinct states" {
    if (!full) return error.SkipZigTest;
    var states: [fixtures.len][8]u8 = undefined;
    inline for (fixtures, &states) |F, *state| state.* = try lossy_state(F, 7, 20);
    for (states[0 .. states.len - 1], states[1..]) |a, b| {
        try testing.expect(!std.mem.eql(u8, &a, &b));
    }
}

test "all fixtures: conflicter is reported and blocked" {
    const allowed = .{ .conflicting_notarize, .conflicting_finalize };
    try run_all(byzantine_scenario, .{ Role.conflicter, allowed });
}

test "all fixtures: nuller is reported and blocked" {
    try run_all(byzantine_scenario, .{ Role.nuller, .{.nullify_finalize} });
}

test "all fixtures: impersonator is blocked without faults" {
    try run_all(byzantine_scenario, .{ Role.impersonator, .{} });
}

test "all fixtures: reconfigurer is blocked without faults" {
    // Votes for the next epoch are not faults; validator 0 is blocked for the mismatch.
    try run_all(byzantine_scenario, .{ Role.reconfigurer, .{} });
}

test "all fixtures: outdated votes are ignored" {
    try run_all(outdated, .{});
}

test "all fixtures: unclean shutdown" {
    if (builtin.mode == .debug and !full) return error.SkipZigTest;
    inline for (fixtures, quick_fixtures) |F, quick| {
        if (full or quick) try unclean_shutdown(F);
    }
}

// commonware `twins`: `twins_campaign` on `TWINS_CAMPAIGN` over `TWINS_LINK`, with each
// fixture's scheme and elector. Slow builds run all 20 cases per fixture; ReleaseSafe runs
// one case per fixture.
test "all fixtures: twins" {
    if (builtin.mode == .debug and !full) return error.SkipZigTest;
    const campaigns = twins_campaign_test;
    var campaign = campaigns.twins_campaign;
    if (!full) campaign.max_cases = 1;
    inline for (fixtures, quick_fixtures) |F, quick| {
        if (!full and !quick) continue;
        try campaigns.Suite(F).run_campaign(campaign, campaigns.twins_link);
    }
}

// engine_test.zig's remaining `test_for_all_fixtures` DSTs on the other fixtures. Per push,
// ReleaseSafe runs them on the threshold VRF MinPk fixture alone (the non-attributable path
// and the Random elector); slow builds run all seven.
test {
    inline for (fixtures, 0..) |F, index| {
        if (F != engine_test.Ed25519Fixture) _ = engine_test.Suite(F, index == 0);
    }
}
