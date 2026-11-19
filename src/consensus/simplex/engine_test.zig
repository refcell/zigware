//! Multi-node tests of the simplex engine (commonware `simplex/mod.rs` tests): honest
//! validators on `p2p.simulated` under the deterministic runtime.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
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

/// The ed25519 fixture with round robin: every test runs on it in every build.
pub const Ed25519Fixture = struct {
    pub const Scheme = ed25519.Scheme(cryptography.Sha256.Digest);
    pub const Elector = elector_mod.RoundRobinElector;

    pub fn fixture(rng: anytype, n: u32) !cryptography.certificate.mocks.Fixture(Scheme) {
        return ed25519.fixture(cryptography.Sha256.Digest, testing.allocator, rng, "consensus", n);
    }

    pub fn elector(n: u32) !Elector {
        return elector_mod.RoundRobin(cryptography.Sha256).default().build(testing.allocator, n);
    }

    pub fn deinit_elector(value: *Elector) void {
        value.deinit(testing.allocator);
    }
};

/// The engine DSTs over fixture `F` (`Scheme`, `Elector`, `fixture`, `elector`,
/// `deinit_elector`). The ed25519 fixture runs every test in every build; other fixtures run
/// commonware's `test_for_all_fixtures` ones that fixtures_test.zig lacks, in slow builds.
pub fn Suite(comptime F: type) type {
    return struct {
        const primary = F == Ed25519Fixture;
        const full = build_options.slow_tests;
        const fixture_enabled = primary or full;
        pub const gpa = testing.allocator;
        const Sha256 = cryptography.Sha256;
        const Digest = Sha256.Digest;
        const Key = cryptography.ed25519.PublicKey;
        const wrapped = @import("mocks/wrapped.zig");
        /// Every engine signs through the wrapper; only `Role.invalid` makes validator 0 misbehave.
        const Scheme = wrapped.Scheme(F.Scheme);
        const Net = p2p.simulated.Network(Key);
        pub const Context = runtime.deterministic.Context;
        const Application = application_mod.Application(Sha256, Key);
        const Relay = relay_mod.Relay(Digest, Key);
        pub const Reporter = reporter_mod.Reporter(Scheme, Digest);
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
        const Elector = F.Elector;
        pub const RoundRobin = elector_mod.RoundRobin(Sha256);
        pub const HandoffKind = std.meta.Tag(@import("../traits.zig").Handoff(Digest));
        const equivocator_mod = @import("mocks/equivocator.zig");
        const Equivocator = equivocator_mod.Equivocator(Scheme, Sha256, Key, Elector);
        const IoRng = @import("actors/context.zig").IoRng;
        const Reconfigurer = @import("mocks/reconfigurer.zig").Reconfigurer(Scheme, Sha256);
        const NullifyOnly = @import("mocks/nullify_only.zig").NullifyOnly(Scheme, Sha256);
        pub const Duration = utils.Duration;
        pub const Link = p2p.simulated.Link;
        const View = consensus_types.View;
        const Epoch = consensus_types.Epoch;

        const Params = struct {
            pub const Context = runtime.deterministic.Context;
            pub const Scheme = wrapped.Scheme(F.Scheme);
            pub const Elector = F.Elector;
            pub const Blocker = Net.Control;
            pub const Digest = Sha256.Digest;
            pub const Automaton = *Application;
            pub const Relay = *Application;
            pub const Reporter = *Routed;
            pub const Strategy = parallel.Sequential;
            pub const Sender = Net.Sender;
            pub const Receiver = Net.Receiver;
        };
        const Engine = engine_mod.Engine(Params);
        const Channel = engine_mod.Channel(Params);

        const test_quota = p2p.Quota.per_second(1024);
        /// Debug runs without `-Dslow-tests` shrink the DSTs (fewer views and seeds) to keep the
        /// suite fast; ReleaseSafe runs them at full size.
        pub const quick = if (primary)
            builtin.mode == .debug and !build_options.slow_tests
        else
            !full;
        pub const epoch: Epoch = .new(333);
        const page_size = 1024;
        const page_cache_size = 10;

        /// What validator 0 runs: the engine, or one of the Byzantine mocks.
        /// `absent` leaves validator 0 offline until the test starts it; `slow` runs the engine
        /// with an application that takes 10 s to propose, verify, and certify; `invalid` runs the
        /// engine with every signature corrupted.
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
            nullify_only,

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
                    .nullify_only,
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
            nullify_only: NullifyOnly,
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
                    .nullify_only => byzantine.nullify_only.run(&votes.sender, &votes.receiver),
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
                F.deinit_elector(&byzantine.elector);
                for (&byzantine.channels) |*channel| {
                    channel.sender.deinit();
                    channel.receiver.deinit();
                }
            }
        };

        /// The engine's reporter: the attributable wrapper when `filter`, else the mock itself
        /// (commonware wraps it only in `attributable_reporter_filtering`).
        const Routed = struct {
            validator: *Validator,
            filter: bool,

            pub fn report(self: *Routed, activity: Reporter.Activity) @import("actor").Feedback {
                if (self.filter) return self.validator.attributable.report(activity);
                return self.validator.reporter.report(activity);
            }
        };

        /// One validator's engine and mocks. Must not move once started.
        const Validator = struct {
            state: enum { absent, honest, byzantine },
            byzantine: *Byzantine,
            application: Application,
            reporter: Reporter,
            /// Wraps `reporter` with peer-activity verification and non-attributable filtering;
            /// the engine reports through it only when the harness's `verify_reports` is set.
            attributable: Attributable,
            routed: Routed,
            page_cache: runtime.buffer.paged.CacheRef,
            elector: Elector,
            engine: Engine,
            partition: [32]u8,
            handle: ?runtime.context.Handle(Engine.RunResult) = null,
        };

        /// One simulated network of validators. Must not move once started.
        pub const Harness = struct {
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
            /// The elector configuration, the applications' handoff decision, and their verify and
            /// certify latencies (the defaults when null), for validators started from now on.
            round_robin: RoundRobin = .default(),
            handoff: HandoffKind = .wait,
            propose_latency: ?application_mod.Latency = null,
            verify_latency: ?application_mod.Latency = null,
            certify_latency: ?*const fn (index: usize) application_mod.Latency = null,
            /// A finalization the next validator started takes as its floor (genesis when null);
            /// the engine takes ownership.
            floor: ?Reporter.Finalization = null,
            /// How applications started from now on answer certification requests.
            should_certify: application_mod.Certifier(Digest) = .always,

            pub const Timeouts = struct {
                leader_ms: u64 = 1000,
                certification_ms: u64 = 2000,
                retry_ms: u64 = 10_000,
                skip_ms: u64 = 11_000,
            };

            const Fixture = cryptography.certificate.mocks.Fixture(F.Scheme);

            /// The fixture's elector; round robin ones take the harness's term configuration.
            pub fn build_elector(harness: *const Harness, n: u32) !Elector {
                const round_robin = Elector == elector_mod.RoundRobinElector;
                if (round_robin) return harness.round_robin.build(gpa, n);
                return F.elector(n);
            }

            pub fn keys(harness: *const Harness) []const Key {
                return harness.fixture.participants;
            }

            pub fn oracle(harness: *const Harness) Net.Oracle {
                return harness.network.oracle();
            }

            /// Starts `n` validators, every pair linked by `link` (when given); validator 0 plays
            /// `role`.
            pub fn start(harness: *Harness, ctx: Context, n: u32, link: ?Link, role: Role) !void {
                try harness.start_timed(ctx, n, link, role, .{});
            }

            /// `start` with the engines' leader, certification, and retry timeouts.
            pub fn start_timed(
                harness: *Harness,
                ctx: Context,
                n: u32,
                link: ?Link,
                role: Role,
                timeouts: Timeouts,
            ) !void {
                try harness.start_network(ctx, n, link, role, timeouts);
                for (0..harness.validators.len) |index| {
                    if (index == 0 and role == .absent) continue;
                    if (index == 0 and role.is_byzantine()) {
                        try harness.start_byzantine(index, role);
                    } else {
                        try harness.start_validator(index);
                    }
                }
            }

            /// Everything `start_timed` does except starting validators: all start absent.
            pub fn start_network(
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
                harness.fixture = try F.fixture(&rng, n);
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
                harness.round_robin = .default();
                harness.handoff = .wait;
                harness.propose_latency = null;
                harness.verify_latency = null;
                harness.certify_latency = null;
                harness.floor = null;
                harness.should_certify = .always;
            }

            /// Starts validator `index` as the Byzantine mock `role`.
            pub fn start_byzantine(harness: *Harness, index: usize, role: Role) !void {
                assert(role.is_byzantine());
                const io = harness.ctx.io();
                const validator = &harness.validators[index];
                const key = harness.keys()[index];
                assert(validator.state == .absent);
                const byzantine = try gpa.create(Byzantine);
                errdefer gpa.destroy(byzantine);
                const scheme = &harness.schemes[index];
                const n: u32 = @intCast(harness.validators.len);
                var elector = try F.elector(n);
                errdefer F.deinit_elector(&elector);
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
                    .nullify_only = .init(gpa, scheme),
                    .channels = try register(harness.oracle(), key),
                    .handle = undefined,
                };
                const task = harness.ctx.child("byzantine");
                byzantine.handle = try task.spawn(Byzantine.run, .{byzantine});
                validator.* = undefined;
                validator.byzantine = byzantine;
                validator.state = .byzantine;
            }

            /// The validator at `index` when it runs the engine.
            pub fn honest(harness: *Harness, index: usize) ?*Validator {
                const validator = &harness.validators[index];
                return if (validator.state == .honest) validator else null;
            }

            pub fn deinit(harness: *Harness) void {
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
            pub fn crash(harness: *Harness, index: usize) void {
                harness.shutdown(index);
                harness.validators[index].reporter.deinit();
            }

            /// `crash`, but the reporter lives on for `restart` (commonware hands the restarted
            /// engine the same reporter, so its checks span both runs).
            pub fn shutdown(harness: *Harness, index: usize) void {
                const validator = harness.honest(index).?;
                abort(validator);
                // No broadcast reaches the application once deregistered, so it can be freed.
                harness.relay.deregister(harness.keys()[index]);
                stop_actors(validator);
                validator.state = .absent;
                assert(harness.honest(index) == null);
            }

            /// Starts validator `index`, shut down with `shutdown`, from its journal on new
            /// channels, reporting to the reporter it kept.
            pub fn restart(harness: *Harness, index: usize) !void {
                const channels = try register(harness.oracle(), harness.keys()[index]);
                try harness.start_engine(index, channels, .keep);
            }

            /// Aborts every engine and frees its mocks; the validators become absent, and their
            /// journals stay in storage for `start_validator` to recover.
            pub fn crash_all(harness: *Harness) void {
                const validators = harness.validators;
                // Abort every engine before freeing any mock: live voters relay to all
                // applications.
                for (validators) |*validator| {
                    if (validator.state == .honest) abort(validator);
                }
                harness.relay.deregister_all();
                for (validators) |*validator| {
                    if (validator.state != .honest) continue;
                    stop_actors(validator);
                    validator.reporter.deinit();
                    validator.state = .absent;
                }
                for (validators) |*validator| assert(validator.state != .honest);
            }

            /// Replaces the link of every ordered pair `restrict` admits (commonware `Update`).
            pub fn relink_all(harness: *Harness, link: Link, restrict: ?*const Restrict) !void {
                try harness.link_all(null, restrict);
                try harness.link_all(link, restrict);
            }

            /// Links (or, with `link == null`, unlinks) every ordered pair `restrict` admits.
            pub fn link_all(harness: *Harness, link: ?Link, restrict: ?*const Restrict) !void {
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
            pub fn start_validator(harness: *Harness, index: usize) !void {
                const channels = try register(harness.oracle(), harness.keys()[index]);
                try harness.start_validator_on(index, channels);
            }

            /// Starts validator `index`'s engine on `channels`, registered for it beforehand.
            pub fn start_validator_on(harness: *Harness, index: usize, channels: [3]Channel) !void {
                try harness.start_engine(index, channels, .new);
            }

            /// Starts validator `index`'s engine on `channels` with a new reporter, or the one it
            /// kept through `shutdown`.
            pub fn start_engine(
                harness: *Harness,
                index: usize,
                channels: [3]Channel,
                reporter: enum { new, keep },
            ) !void {
                const io = harness.ctx.io();
                const validator = &harness.validators[index];
                const key = harness.keys()[index];
                assert(validator.state == .absent);
                const kept = validator.reporter;
                validator.* = undefined;
                validator.handle = null;
                const slow = index == 0 and harness.role == .slow;
                const normal: application_mod.Latency = .{ .mean = 10, .std_dev = 5 };
                // commonware `slow_validator`'s application: 10 s per step.
                const stalled: application_mod.Latency = .{ .mean = 10_000, .std_dev = 5 };
                const stalled_propose: application_mod.Latency = .{ .mean = 10_000, .std_dev = 0 };
                const propose_time = harness.propose_latency orelse normal;
                const verify_time = harness.verify_latency orelse normal;
                const certify_time =
                    if (harness.certify_latency) |latency| latency(index) else normal;
                validator.application = try .init(gpa, io, .{
                    .relay = &harness.relay,
                    .me = key,
                    .propose_latency = if (slow) stalled_propose else propose_time,
                    .verify_latency = if (slow) stalled else verify_time,
                    .certify_latency = if (slow) stalled else certify_time,
                    .should_certify = harness.should_certify,
                });
                validator.application.stall_proposals = harness.stall_proposals;
                validator.application.handoff = harness.handoff;
                try validator.application.register();
                validator.reporter =
                    if (reporter == .keep) kept else .init(gpa, io, &harness.verifier);
                const rng: IoRng = .{ .io = io };
                const verify = harness.verify_reports;
                const scheme = harness.schemes[index];
                validator.attributable =
                    .init(gpa, io, rng, scheme, &validator.reporter, parallel.sequential, verify);
                validator.routed = .{ .validator = validator, .filter = verify };
                validator.page_cache = try .init(gpa, page_size, page_cache_size);
                const n: u32 = @intCast(harness.validators.len);
                validator.elector = try harness.build_elector(n);
                validator.partition = @splat(0);
                _ = try std.fmt.bufPrint(&validator.partition, "validator-{d}", .{index});
                const control = harness.oracle().control(key);
                var cfg = engine_config(validator, harness.schemes[index], control);
                cfg.track_historical_votes = harness.track_historical_votes;
                cfg.mailbox_size = harness.mailbox_size;
                cfg.leader_timeout = .from_millis(harness.timeouts.leader_ms);
                cfg.certification_timeout = .from_millis(harness.timeouts.certification_ms);
                cfg.timeout_retry = .from_millis(harness.timeouts.retry_ms);
                cfg.skip = .{ .enabled = .{ .timeout = .from_millis(harness.timeouts.skip_ms) } };
                if (harness.floor) |floor| cfg.floor = .{ .finalized = floor };
                harness.floor = null;
                // Per-validator metrics, as commonware's `child("validator").with_attribute(..)`.
                var validator_ctx = harness.ctx;
                const validator_scope = harness.ctx.scope.child("validator");
                validator_ctx.scope = validator_scope.with_attribute("public_key", key);
                try validator.engine.init(validator_ctx, cfg);
                validator.handle = try validator_ctx.child("engine").spawn(Engine.run, .{
                    &validator.engine, channels[0], channels[1], channels[2],
                });
                validator.state = .honest;
            }

            /// Waits until every validator finalized `view`.
            pub fn wait_all(harness: *Harness, view: u64) !void {
                for (0..harness.validators.len) |index| {
                    const validator = harness.honest(index) orelse continue;
                    try validator.reporter.wait_for_finalized(.new(view));
                }
            }

            /// The lowest finalized view across honest validators.
            pub fn min_finalized(harness: *Harness) u64 {
                var lowest: u64 = std.math.maxInt(u64);
                for (0..harness.validators.len) |index| {
                    const validator = harness.honest(index) orelse continue;
                    lowest = @min(lowest, validator.reporter.latest_finalized().get());
                }
                assert(lowest != std.math.maxInt(u64));
                return lowest;
            }

            /// The highest finalized view across validators.
            pub fn max_finalized(harness: *Harness) u64 {
                var highest: u64 = 0;
                for (0..harness.validators.len) |index| {
                    const validator = harness.honest(index) orelse continue;
                    highest = @max(highest, validator.reporter.latest_finalized().get());
                }
                return highest;
            }

            /// No faults, no invalid activity, one payload per finalized view, and no blocks.
            pub fn check(harness: *Harness, through: u64) !void {
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
            pub fn check_agreement(harness: *Harness, through: u64) !void {
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
            pub fn check_byzantine(
                harness: *Harness,
                allowed: []const std.meta.Tag(Reporter.Activity),
            ) !void {
                var count: usize = 0;
                for (0..harness.validators.len) |index| {
                    const validator = harness.honest(index) orelse continue;
                    for (validator.reporter.fault_list()) |fault| {
                        try testing.expectEqual(0, fault.signer.get());
                        const Kind = @TypeOf(fault.kind);
                        const known = std.mem.indexOfScalar(Kind, allowed, fault.kind) != null;
                        try testing.expect(known);
                        count += 1;
                    }
                }
                try testing.expectEqual(allowed.len > 0, count > 0);
                try harness.check_blocked_only_byzantine();
            }

            pub fn check_blocked_only_byzantine(harness: *Harness) !void {
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

        pub fn link_ms(latency_ms: u64, jitter_ms: u64, success_rate: f64) Link {
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

        fn engine_config(
            validator: *Validator,
            scheme: Scheme,
            blocker: Net.Control,
        ) Engine.Config {
            return .{
                .scheme = scheme,
                .elector = validator.elector,
                .blocker = blocker,
                .automaton = &validator.application,
                .relay = &validator.application,
                .reporter = &validator.routed,
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
            F.deinit_elector(&validator.elector);
            validator.page_cache.deinit();
            validator.application.deinit();
        }

        /// Runs `scenario(ctx, args...)` on a fresh runner seeded with `seed`; returns the auditor
        /// state (commonware `context.auditor().state()`).
        pub fn run_seeded(seed: u64, comptime scenario: anytype, args: anytype) ![8]u8 {
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
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, all_online, .{ 4, 10 });
        }

        test "all online" {
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, all_online, .{ 5, if (quick) 20 else 50 });
        }

        test "the voter and batcher trace at commonware's targets and spans" {
            if (comptime !primary) return error.SkipZigTest;
            const traces = runtime.telemetry.traces;
            var collector = traces.Collector.init(gpa, .{});
            defer collector.deinit();
            var subscriber = collector.subscriber();
            subscriber.level = .debug;
            const config: runtime.deterministic.Config = .{ .seed = 0, .subscriber = subscriber };
            var runner = try runtime.deterministic.Runner.init(gpa, config);
            defer runner.deinit();
            try (try runner.start_context(all_online, .{ 4, 5 }));
            try collector.get_by_level(.info).expect_message_exact("consensus initialized");
            try collector.get_by_level(.debug).expect_message_exact("broadcasting finalization");
            try collector.get_by_level(.debug).expect_message_exact("broadcasting notarize");
            const at_voter = struct {
                fn check(_: void, event: traces.collector.RecordedEvent) bool {
                    const voter_target = "commonware_consensus::simplex::actors::voter";
                    return std.mem.eql(u8, event.target, voter_target) and
                        std.mem.eql(u8, event.metadata.content, "consensus initialized");
                }
            }.check;
            try collector.get_all().expect_event({}, at_voter);
            // Votes broadcast inside the notify span, and automaton requests inside the propose and
            // verify spans, each under its view's root span.
            const in_span = struct {
                fn notify(_: void, event: traces.collector.RecordedEvent) bool {
                    return spanned(event, "broadcasting notarize", "simplex.voter.notify");
                }
                fn propose(_: void, event: traces.collector.RecordedEvent) bool {
                    const message = "requested proposal from automaton";
                    return spanned(event, message, "simplex.voter.propose");
                }
                fn verify(_: void, event: traces.collector.RecordedEvent) bool {
                    const message = "requested proposal verification";
                    return spanned(event, message, "simplex.voter.verify");
                }
                /// The batcher builds certificates in the voter's view span it adopted.
                fn recovered(_: void, event: traces.collector.RecordedEvent) bool {
                    const message = "recovered certificate, forwarding to voter";
                    if (!std.mem.eql(u8, event.metadata.content, message)) return false;
                    if (event.spans.len != 1) return false;
                    return std.mem.eql(u8, event.spans[0].content, "simplex.voter.view");
                }
                fn spanned(
                    event: traces.collector.RecordedEvent,
                    message: []const u8,
                    span: []const u8,
                ) bool {
                    if (!std.mem.eql(u8, event.metadata.content, message)) return false;
                    if (event.spans.len != 2) return false;
                    const root = event.spans[1].content;
                    if (!std.mem.eql(u8, root, "simplex.voter.view")) return false;
                    return std.mem.eql(u8, event.spans[0].content, span);
                }
            };
            try collector.get_all().expect_event({}, in_span.notify);
            try collector.get_all().expect_event({}, in_span.propose);
            try collector.get_all().expect_event({}, in_span.verify);
            try collector.get_all().expect_event({}, in_span.recovered);
            try testing.expect(collector.get_by_level(.warn).is_empty());
        }

        /// commonware `slow_and_lossy_links_seeded`: half the messages drop.
        fn slow_and_lossy_links(ctx: Context, required: u64) !void {
            var harness: Harness = undefined;
            try harness.start(ctx, 5, link_ms(200, 150, 0.5), .honest);
            defer harness.deinit();
            try harness.wait_all(required);
            try harness.check(required);
        }

        test "slow and lossy links" {
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(6, slow_and_lossy_links, .{if (quick) 10 else 20});
        }

        test "determinism: the same seed replays the same run" {
            if (comptime !primary) return error.SkipZigTest;
            const required: u64 = if (quick) 5 else 20;
            var states: [2][8]u8 = undefined;
            for (&states, 0..) |*state, seed| {
                state.* = try run_seeded(seed, slow_and_lossy_links, .{required});
                const again = try run_seeded(seed, slow_and_lossy_links, .{required});
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
            const required: u64 = if (quick) 5 else 20;
            try harness.wait_all(required);
            try harness.link_all(null, &separated);
            // Let in-progress notarizations and finalizations finish.
            try ctx.sleep(.fromSeconds(10));
            const before = harness.max_finalized();
            try ctx.sleep(.fromSeconds(if (quick) 20 else 60));
            // Nothing finalizes while split.
            try testing.expectEqual(before, harness.max_finalized());
            try harness.link_all(link, &separated);
            try harness.wait_all(before + required);
            try harness.check(before + required);
        }

        test "partition heals" {
            if (comptime !primary) return error.SkipZigTest;
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
            if (comptime !primary) return error.SkipZigTest;
            for (0..2) |seed| {
                const allowed = &.{ .conflicting_notarize, .conflicting_finalize };
                _ = try run_seeded(seed, byzantine_scenario, .{ Role.conflicter, allowed });
            }
        }

        test "nuller is reported and blocked" {
            if (comptime !primary) return error.SkipZigTest;
            for (0..2) |seed| {
                const allowed = &.{.nullify_finalize};
                _ = try run_seeded(seed, byzantine_scenario, .{ Role.nuller, allowed });
            }
        }

        test "reconfigurer is blocked without faults" {
            if (comptime !primary) return error.SkipZigTest;
            // Votes for the next epoch are not faults; validator 0 is blocked for the mismatch.
            const args = .{ Role.reconfigurer, &.{} };
            for (0..2) |seed| _ = try run_seeded(seed, byzantine_scenario, args);
        }

        test "impersonator is blocked without faults" {
            if (comptime !primary) return error.SkipZigTest;
            const args = .{ Role.impersonator, &.{} };
            for (0..2) |seed| _ = try run_seeded(seed, byzantine_scenario, args);
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
            if (comptime !primary) return error.SkipZigTest;
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
            if (comptime !primary) return error.SkipZigTest;
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
            const required: u64 = if (quick) 30 else 100;
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
            // The online validators record timeouts and nullifications for the offline leader.
            const encoded = try ctx.scope.encode(gpa);
            defer gpa.free(encoded);
            var label_buffer: [128]u8 = undefined;
            const offline_key = harness.keys()[0];
            const label = try std.fmt.bufPrint(&label_buffer, "leader=\"{f}\"", .{offline_key});
            try testing.expect(nonzero_metric_lines(encoded, &.{ "_timeouts", label }) >= n - 1);
            try testing.expectEqual(n - 1, nonzero_metric_lines(encoded, &.{
                "_nullifications",
                label,
            }));
        }

        /// Counts lines of `encoded` containing every pattern whose trailing value is nonzero.
        pub fn nonzero_metric_lines(encoded: []const u8, patterns: []const []const u8) u32 {
            assert(patterns.len > 0);
            var count: u32 = 0;
            var lines = std.mem.splitScalar(u8, encoded, '\n');
            while (lines.next()) |line| {
                const matched = for (patterns) |pattern| {
                    if (std.mem.indexOf(u8, line, pattern) == null) break false;
                } else true;
                if (!matched) continue;
                const space = std.mem.lastIndexOfScalar(u8, line, ' ') orelse continue;
                const value = std.fmt.parseInt(u64, line[space + 1 ..], 10) catch continue;
                if (value > 0) count += 1;
            }
            assert(count <= encoded.len);
            return count;
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
                const signers = votes.notarize | votes.nullify | votes.finalize;
                try testing.expectEqual(0, signers & offline);
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
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, one_offline_scenario, .{});
        }

        /// commonware `slow_validator`: validator 0 proposes, verifies, and certifies 10 s late, so
        /// it never notarizes or finalizes; everyone still finalizes 50 views.
        fn slow_validator_scenario(ctx: Context) !void {
            var harness: Harness = undefined;
            try harness.start(ctx, 5, link_ms(10, 1, 1.0), .slow);
            defer harness.deinit();
            const required: u64 = if (quick) 20 else 50;
            // The slow validator learns finalizations from the rest.
            try harness.wait_all(required);
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
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, slow_validator_scenario, .{});
        }

        /// commonware `all_recovery`: over 3 s links no view finishes for a minute; after a minute
        /// fully cut off and relinking at 10 ms, the views right after the highest nullified one
        /// are nearly all notarized (the skip timeout recovers quickly).
        fn all_recovery_scenario(ctx: Context) !void {
            var harness: Harness = undefined;
            const n = 5;
            try harness.start(ctx, n, link_ms(3000, 0, 1.0), .honest);
            defer harness.deinit();
            try ctx.sleep(.fromSeconds(60));
            // Nothing finalizes over slow links.
            try testing.expectEqual(0, harness.max_finalized());
            try harness.link_all(null, null);
            try ctx.sleep(.fromSeconds(60));
            var latest: u64 = 0;
            for (harness.validators) |*validator| {
                latest = @max(latest, validator.reporter.max_vote_view(.nullify).get());
            }
            try testing.expect(latest > 0);
            try harness.link_all(link_ms(10, 1, 1.0), null);
            const view_retention = 10;
            // Quick runs wait only until the checked views are past retention.
            const required: u64 = if (quick) latest + 2 * view_retention else 100;
            try harness.wait_all(required);
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
            if (comptime !primary) return error.SkipZigTest;
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
                while (reporter.votes(stalled).nullify & own == 0) {
                    try ctx.sleep(.fromMilliseconds(100));
                }
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
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, all_crash_after_nullify_scenario, .{});
        }

        /// One run of commonware `equivocator_seeded`: validator 0 leads with two proposals, one
        /// for a random victim and one for the rest. The honest six finalize through a crash and
        /// restart of one of them; returns whether anyone blocked the equivocator (only it may be
        /// blocked).
        fn equivocator_run(ctx: Context) !bool {
            var harness: Harness = undefined;
            try harness.start(ctx, 7, link_ms(10, 1, 1.0), .equivocator);
            defer harness.deinit();
            const required: u64 = if (quick) 10 else 50;
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
            if (comptime !fixture_enabled) return error.SkipZigTest;
            const detected = for (0..5) |seed| {
                var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = seed });
                defer runner.deinit();
                if (try (try runner.start_context(equivocator_run, .{}))) break true;
            } else false;
            try testing.expect(detected);
        }

        /// commonware `invalid`: validator 0 signs every vote with a corrupted signature. The
        /// honest three finalize and block it without faults. Every reporter sees invalid votes,
        /// but only validator 0's sees invalid certificates (assembled from its own votes); honest
        /// engines reject those before reporting.
        fn invalid_scenario(ctx: Context) !void {
            var harness: Harness = undefined;
            try harness.start(ctx, 4, link_ms(10, 1, 1.0), .invalid);
            defer harness.deinit();
            const required: u64 = if (quick) 20 else 50;
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
            if (comptime !fixture_enabled) return error.SkipZigTest;
            const seeds: u64 = if (quick) 1 else 2;
            for (0..seeds) |seed| _ = try run_seeded(seed, invalid_scenario, .{});
        }

        fn zero_only_to_one(_: usize, a: usize, b: usize) bool {
            if (a == 0 or b == 0) return a == 1 or b == 1;
            return true;
        }

        /// commonware `received_certificates_are_reported`: validator 0 links only to validator 1,
        /// so it cannot form certificates itself, yet reports nearly all those relayed to it.
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
            if (comptime !fixture_enabled) return error.SkipZigTest;
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
            const all = [_]usize{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
            const quorum = utils.N3f1.quorum(@as(u32, @intCast(harness.schemes.len)));
            assert(quorum <= all.len);
            return signed_certificate(harness, kind, view, parent, payload, all[0..quorum]);
        }

        /// A certificate of `kind` for `view` signed by the validators at `signers`; notarizations
        /// and finalizations name `parent` and the hash of `payload`, nullifications ignore both.
        fn signed_certificate(
            harness: *Harness,
            comptime kind: std.meta.Tag(Certificate),
            view: u64,
            parent: u64,
            payload: []const u8,
            signers: []const usize,
        ) !Certificate {
            const Vote = switch (kind) {
                .notarization => Notarize,
                .finalization => Finalize,
                .nullification => @import("types.zig").Nullify(Scheme),
            };
            const round: consensus_types.Round = .new(epoch, .new(view));
            const proposal: @import("types.zig").Proposal(Digest) =
                .init(round, .new(parent), Sha256.hash(&.{payload}));
            var votes: [16]Vote = undefined;
            assert(signers.len <= votes.len);
            assert(signers.len >= utils.N3f1.quorum(@as(u32, @intCast(harness.schemes.len))));
            for (votes[0..signers.len], signers) |*vote, signer| {
                const scheme = &harness.schemes[signer];
                const subject = if (kind == .nullification) round else proposal;
                vote.* = (try Vote.sign(gpa, scheme, subject)).?;
            }
            const Signed = @FieldType(Certificate, @tagName(kind));
            const scheme = &harness.schemes[0];
            const strategy = parallel.sequential;
            const signed = try Signed.from_votes(gpa, scheme, votes[0..signers.len], strategy);
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
            if (comptime !fixture_enabled) return error.SkipZigTest;
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
            if (comptime !fixture_enabled) return error.SkipZigTest;
            for (0..3) |seed| _ = try run_seeded(seed, engine_shutdown_scenario, .{false});
        }

        test "engine shutdown: a graceful stop ends the engine" {
            if (comptime !fixture_enabled) return error.SkipZigTest;
            for (0..3) |seed| _ = try run_seeded(seed, engine_shutdown_scenario, .{true});
        }

        /// commonware `attributable_reporter_filtering`: every engine reports through the
        /// attributable wrapper with verification on. On an attributable scheme each validator
        /// still sees its peers' notarize (except at the last view) and finalize votes; on a
        /// non-attributable one it sees no votes at all.
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
                const finalized = reporter.finalized(.new(1)) != null;
                const certified = reporter.notarized(.new(1)) or finalized;
                try testing.expect(certified);
                const last = reporter.max_vote_view(.notarize).get();
                if (!Scheme.is_attributable()) {
                    try testing.expectEqual(0, last);
                    try testing.expectEqual(0, reporter.max_vote_view(.finalize).get());
                    continue;
                }
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
            if (comptime !fixture_enabled) return error.SkipZigTest;
            _ = try run_seeded(0, attributable_reporter_scenario, .{});
        }

        /// A peer outside the committee with a one-way `link` to every validator (commonware
        /// `start_certificate_injector`); it sends on the certificate channel. Release both halves.
        fn start_injector(harness: *Harness, link: Link) !Net.Registered {
            const injector = cryptography.ed25519.PrivateKey.from_seed(1_000_000).public_key();
            const registered = try harness.oracle().control(injector).register(1, test_quota);
            for (harness.keys()) |key| try harness.oracle().add_link(injector, key, link);
            const tracked: p2p.TrackedPeers(Key) = .{
                .primary = .init(harness.keys()),
                .secondary = .init(&.{injector}),
            };
            _ = harness.oracle().manager().track(1, tracked);
            try harness.ctx.sleep(.fromMilliseconds(10));
            return registered;
        }

        fn inject(sender: *Net.Sender, recipient: ?Key, certificate: Certificate) !void {
            const bytes = try codec.encode(Certificate, gpa, certificate);
            defer gpa.free(bytes);
            const recipients: p2p.Recipients(Key) = if (recipient) |key| .{ .one = key } else .all;
            gpa.free(try sender.send(recipients, &.{bytes}, true));
        }

        /// The split-views groups: who saw a notarization of view 2 (`group1`) or view 3
        /// (`group2`); everyone else saw nullifications.
        const SplitGroup = enum { group1, group2, ignorant, byzantine };

        fn split_group(index: usize) SplitGroup {
            return switch (index) {
                0...2 => .group1,
                3...5 => .group2,
                6 => .ignorant,
                else => .byzantine,
            };
        }

        /// commonware `split_views_no_lockup`: before any engine starts, every validator learns
        /// that view 1 finalized, then sees either a notarization or a nullification of view 2 and
        /// of view 3, so the honest seven split. Validators 7 to 9 only nullify. Once linked, the
        /// honest validators must still finalize past view 3.
        fn split_views_scenario(ctx: Context) !void {
            var harness: Harness = undefined;
            const timeouts: Harness.Timeouts = .{
                .leader_ms = 10_000,
                .certification_ms = 11_000,
                .retry_ms = 10_000,
                .skip_ms = 12_000,
            };
            try harness.start_network(ctx, 10, null, .absent, timeouts);
            defer harness.deinit();
            const link = link_ms(10, 0, 1.0);
            var injector = try start_injector(&harness, link);
            defer injector.deinit();
            try inject_split(&harness, &injector.sender);
            for (0..harness.validators.len) |index| {
                if (split_group(index) == .byzantine) {
                    try harness.start_byzantine(index, .nullify_only);
                } else {
                    try harness.start_validator(index);
                }
            }
            // Let the engines consume the preloaded certificates.
            try ctx.sleep(.fromSeconds(2));
            try check_split(&harness);
            try harness.link_all(link, null);
            for (0..7) |index| try harness.validators[index].reporter.wait_for_finalized(.new(4));
            for (0..7) |index| {
                harness.validators[index].reporter.assert_no_faults();
                harness.validators[index].reporter.assert_no_invalid();
            }
            const blocked = try harness.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
        }

        /// Sends view 1's notarization and finalization to all, then each group's view of views 2
        /// and 3.
        fn inject_split(harness: *Harness, sender: *Net.Sender) !void {
            var certificates: [7]Certificate = .{
                try quorum_certificate(harness, .notarization, 1, 0, "B_F"),
                try quorum_certificate(harness, .finalization, 1, 0, "B_F"),
                try quorum_certificate(harness, .notarization, 2, 1, "B_G1"),
                try quorum_certificate(harness, .nullification, 2, 0, ""),
                try quorum_certificate(harness, .notarization, 3, 1, "B_G2"),
                try quorum_certificate(harness, .nullification, 3, 0, ""),
                undefined,
            };
            defer for (certificates[0..6]) |certificate| codec.free(Certificate, gpa, certificate);
            try inject(sender, null, certificates[0]);
            try inject(sender, null, certificates[1]);
            for ([_]SplitGroup{ .group1, .group2 }, 0..) |notarized, offset| {
                for (harness.keys(), 0..) |key, index| {
                    const first: u64 = if (split_group(index) == notarized) 2 else 3;
                    const seen = first + 2 * offset;
                    try inject(sender, key, certificates[seen]);
                }
            }
        }

        /// A certificate from the first quorum of validators (commonware signs with one more,
        /// `0..=quorum`; any quorum certifies the same).
        /// Each honest validator holds exactly its group's certificates of views 2 and 3, and none
        /// voted to nullify view 4 yet.
        fn check_split(harness: *Harness) !void {
            for (0..7) |index| {
                const reporter = &harness.validators[index].reporter;
                try testing.expect(reporter.finalized(.new(1)) != null);
                for ([_]SplitGroup{ .group1, .group2 }, 2..) |notarized, view| {
                    const holds = split_group(index) == notarized;
                    try testing.expect(reporter.finalized(.new(view)) == null);
                    try testing.expectEqual(holds, reporter.notarized(.new(view)));
                    try testing.expectEqual(!holds, reporter.nullified(.new(view)));
                }
                try testing.expectEqual(0, reporter.votes(.new(4)).nullify);
            }
        }

        test "split views: honest validators split across views 2 and 3 do not lock up" {
            if (comptime !fixture_enabled) return error.SkipZigTest;
            _ = try run_seeded(0, split_views_scenario, .{});
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
            if (comptime !primary) return error.SkipZigTest;
            var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = 0 });
            defer runner.deinit();
            const restarts_max = 200;
            // Each start after the first crashes storage, keeping only synced journal contents.
            const restarts = for (0..restarts_max) |restart| {
                const required: u64 = if (quick) 15 else 100;
                if (try (try runner.start_context(unclean_run, .{required}))) break restart;
            } else return error.TestUnexpectedResult;
            try testing.expect(restarts > 0);
        }

        /// commonware `slow_certifiers_finalize_without_nullification`: the last two of five
        /// validators certify eight times slower, so every quorum holds a slow certifier, yet no
        /// view is nullified and at least 200 views finalize in 30 virtual seconds.
        fn slow_certifiers_scenario(
            ctx: Context,
            round_robin: RoundRobin,
            handoff: HandoffKind,
        ) !void {
            // Each run finalizes over 200 views; Debug takes about a minute per run.
            if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
            var harness: Harness = undefined;
            try harness.start_network(ctx, 5, link_ms(10, 1, 1.0), .honest, .{
                .leader_ms = 1500,
                .certification_ms = 3500,
                .retry_ms = 10_000,
                .skip_ms = 12_000,
            });
            defer harness.deinit();
            harness.round_robin = round_robin;
            harness.handoff = handoff;
            harness.verify_latency = .{ .mean = 1, .std_dev = 0 };
            harness.certify_latency = struct {
                fn latency(index: usize) application_mod.Latency {
                    const mean: f64 = if (index >= 3) 80 else 10;
                    return .{ .mean = mean, .std_dev = 5 };
                }
            }.latency;
            for (0..5) |index| try harness.start_validator(index);
            try ctx.sleep(.fromSeconds(30));
            for (harness.validators) |*validator| {
                validator.reporter.assert_no_invalid();
                validator.reporter.assert_no_faults();
                try testing.expectEqual(0, validator.reporter.nullifications.count());
                try testing.expect(validator.reporter.finalizations.count() >= 200);
            }
            const blocked = try harness.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
        }

        fn stable_terms(length: u32, optimistic_views: u64) RoundRobin {
            const term: consensus_types.TermLength = .new(utils.NonZero(u32).init(length).?);
            return RoundRobin.default().with_term(term, .from_secs(30), .new(optimistic_views));
        }

        test "stable leader optimistic tolerates slow certifiers" {
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, slow_certifiers_scenario, .{ stable_terms(50, 2), .wait });
        }

        test "stable leader handoff vote tolerates slow certifiers" {
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, slow_certifiers_scenario, .{ stable_terms(7, 2), .vote });
        }

        test "rotating handoff vote tolerates slow certifiers" {
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, slow_certifiers_scenario, .{ RoundRobin.default(), .vote });
        }

        test "short term handoff vote tolerates slow certifiers" {
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, slow_certifiers_scenario, .{ stable_terms(3, 2), .vote });
        }

        fn leader_of(schedule: Elector, view: u64) usize {
            return schedule.elect(.new(epoch, .new(view)), {}).get();
        }

        /// Which honest validator leads first after the silent one in a certified-split DST.
        const SplitLeader = enum { group, lone };

        /// The certified-split roles: the silent validator leads view 10; with `.group` first the
        /// group leads views 11 and 12 and the lone holder view 13, with `.lone` first the lone
        /// holder leads view 11 and the group views 12 and 13.
        const SplitRoles = struct { silent: usize, lone: usize, group: [2]usize };

        fn split_roles(first: SplitLeader) !SplitRoles {
            var schedule = try RoundRobin.default().build(gpa, 4);
            defer schedule.deinit(gpa);
            const roles: SplitRoles = switch (first) {
                .group => .{
                    .silent = leader_of(schedule, 10),
                    .group = .{ leader_of(schedule, 11), leader_of(schedule, 12) },
                    .lone = leader_of(schedule, 13),
                },
                .lone => .{
                    .silent = leader_of(schedule, 10),
                    .lone = leader_of(schedule, 11),
                    .group = .{ leader_of(schedule, 12), leader_of(schedule, 13) },
                },
            };
            for (roles.group) |member| {
                assert(member != roles.silent and member != roles.lone);
            }
            assert(roles.silent != roles.lone);
            return roles;
        }

        /// A certified-split DST: who leads first after the silent validator, and the view the lone
        /// holder certified (its parent is view 2; the group holds nullifications of views 3
        /// through it).
        const SplitCase = struct { first: SplitLeader, certified: u64 };

        /// Shares view 2's notarization and finalization with every validator, the certified view's
        /// notarization with the lone holder only, the nullifications of views 3 through the
        /// certified view with the group only, and those of the views after it up to 9 with all.
        fn inject_certified_split(
            harness: *Harness,
            sender: *Net.Sender,
            roles: SplitRoles,
            case: SplitCase,
        ) !void {
            const keys = harness.keys();
            var payload: [8]u8 = undefined;
            const name = try std.fmt.bufPrint(&payload, "B_{d}", .{case.certified});
            const shared: [3]Certificate = .{
                try quorum_certificate(harness, .notarization, 2, 1, "B_2"),
                try quorum_certificate(harness, .finalization, 2, 1, "B_2"),
                try quorum_certificate(harness, .notarization, case.certified, 2, name),
            };
            defer for (shared) |certificate| codec.free(Certificate, gpa, certificate);
            try inject(sender, null, shared[0]);
            try inject(sender, null, shared[1]);
            try inject(sender, keys[roles.lone], shared[2]);
            for (3..10) |view| {
                const nullification = try quorum_certificate(harness, .nullification, view, 0, "");
                defer codec.free(Certificate, gpa, nullification);
                if (view > case.certified) {
                    try inject(sender, null, nullification);
                } else for (roles.group) |member| try inject(sender, keys[member], nullification);
            }
        }

        /// Before the partition ends, the lone holder certified its view and nullified none of
        /// views 3 through it, and the group nullified all of them.
        fn check_certified_split(harness: *Harness, roles: SplitRoles, case: SplitCase) !void {
            for (0..4) |index| {
                const validator = harness.honest(index) orelse continue;
                const reporter = &validator.reporter;
                try testing.expect(reporter.finalized(.new(2)) != null);
                const lone = index == roles.lone;
                try testing.expectEqual(lone, reporter.notarized(.new(case.certified)));
                if (lone) try testing.expect(reporter.certified(.new(case.certified)));
                for (3..case.certified + 1) |view| {
                    try testing.expectEqual(!lone, reporter.nullified(.new(view)));
                }
            }
        }

        /// After healing: with the group leading first, the lone holder fetched the group's
        /// nullifications; with the lone holder first, the group fetched and certified its
        /// notarization. Background repair considers those views complete, so this proves targeted
        /// delivery.
        fn check_targeted_repair(harness: *Harness, roles: SplitRoles, case: SplitCase) !void {
            switch (case.first) {
                .group => {
                    const lone = &harness.validators[roles.lone].reporter;
                    for (3..case.certified + 1) |view| {
                        try testing.expect(lone.nullified(.new(view)));
                    }
                },
                .lone => for (roles.group) |member| {
                    const reporter = &harness.validators[member].reporter;
                    try testing.expect(reporter.notarized(.new(case.certified)));
                    try testing.expect(reporter.certified(.new(case.certified)));
                },
            }
        }

        /// commonware's certified-split DSTs (`certified_split_heals_in_group_led_view`,
        /// `_when_lone_holder_leads_first`, and `_with_displaced_certified_view`): one of four
        /// validators certified a notarization the two others nullified, and the fourth stays
        /// silent. Once linked, targeted repair heals the split: with the group leading first,
        /// view 11 is the first new finalization; with the lone holder first, the certified view.
        fn certified_split_scenario(ctx: Context, case: SplitCase) !void {
            const roles = try split_roles(case.first);
            var harness: Harness = undefined;
            try harness.start_network(ctx, 4, null, .absent, .{
                .leader_ms = 10_000,
                .certification_ms = 11_000,
                .retry_ms = 10_000,
                .skip_ms = 12_000,
            });
            defer harness.deinit();
            // Proposals wait so the engines process the preloaded certificates first.
            harness.propose_latency = .{ .mean = 250, .std_dev = 50 };
            const link = link_ms(10, 0, 1.0);
            var injector = try start_injector(&harness, link);
            defer injector.deinit();
            try inject_certified_split(&harness, &injector.sender, roles, case);
            // Engines start before the partition ends, so their preload rebroadcasts are lost.
            for (0..4) |index| {
                if (index != roles.silent) try harness.start_validator(index);
            }
            try ctx.sleep(.fromSeconds(2));
            try check_certified_split(&harness, roles, case);
            try harness.link_all(link, null);
            try harness.wait_all(3);
            const expected: u64 = if (case.first == .group) 11 else case.certified;
            for (0..4) |index| {
                const reporter = &(harness.honest(index) orelse continue).reporter;
                try testing.expectEqual(expected, reporter.first_finalized_above(.new(2)).?.get());
                reporter.assert_no_faults();
                reporter.assert_no_invalid();
            }
            try check_targeted_repair(&harness, roles, case);
            const blocked = try harness.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
        }

        test "certified split heals in a group-led view" {
            if (comptime !primary) return error.SkipZigTest;
            const case: SplitCase = .{ .first = .group, .certified = 3 };
            _ = try run_seeded(0, certified_split_scenario, .{case});
        }

        test "certified split heals when the lone holder leads first" {
            if (comptime !primary) return error.SkipZigTest;
            const case: SplitCase = .{ .first = .lone, .certified = 3 };
            _ = try run_seeded(0, certified_split_scenario, .{case});
        }

        test "certified split heals with a displaced certified view" {
            if (comptime !primary) return error.SkipZigTest;
            const case: SplitCase = .{ .first = .group, .certified = 5 };
            _ = try run_seeded(0, certified_split_scenario, .{case});
        }

        /// The cross-term certified-split roles (terms of 5 views): `offline` leads terms 1, 5, and
        /// 9; `a`, `b`, and `c` lead terms 2, 3, and 4, then 6, 7, and 8.
        const CrossTermRoles = struct { offline: usize, a: usize, b: usize, c: usize };

        fn cross_term_schedule() RoundRobin {
            const term: consensus_types.TermLength = .new(utils.NonZero(u32).init(5).?);
            return RoundRobin.default().with_term(term, .from_secs(12), .new(0));
        }

        /// commonware picks epoch 2 so that its sorted honest indices lead terms 2, 3, and 4. This
        /// harness runs epoch 333, so naming each honest validator by the term it leads keeps
        /// commonware's schedule.
        fn cross_term_roles() !CrossTermRoles {
            var schedule = try cross_term_schedule().build(gpa, 4);
            defer schedule.deinit(gpa);
            const roles: CrossTermRoles = .{
                .offline = leader_of(schedule, 1),
                .a = leader_of(schedule, 6),
                .b = leader_of(schedule, 11),
                .c = leader_of(schedule, 16),
            };
            // The offline validator leads terms 1 and 5, and every other term start is honest.
            try testing.expectEqual(roles.offline, leader_of(schedule, 21));
            for ([_]u64{ 6, 11, 16, 26, 31, 36 }) |view| {
                try testing.expect(leader_of(schedule, view) != roles.offline);
            }
            // The view-26 leader must hold view 22's certification.
            try testing.expect(leader_of(schedule, 26) != roles.c);
            // The halt detector ends when term 9 returns to the offline validator.
            try testing.expectEqual(roles.offline, leader_of(schedule, 41));
            assert(roles.a != roles.b and roles.b != roles.c and roles.a != roles.c);
            return roles;
        }

        /// Sends `certificate` to each validator in `targets`, then frees it.
        fn inject_to(
            harness: *Harness,
            sender: *Net.Sender,
            certificate: Certificate,
            targets: []const usize,
        ) !void {
            defer codec.free(Certificate, gpa, certificate);
            assert(targets.len > 0);
            for (targets) |target| try inject(sender, harness.keys()[target], certificate);
        }

        /// Term 1's chain (views 1 and 2) reaches `b` and `c`; `a` only learns the term was
        /// abandoned (at view 1 when backfill is suppressed, else at view 3). Everyone nullifies
        /// terms 2 to 4 at their starts.
        fn inject_term_one(
            harness: *Harness,
            sender: *Net.Sender,
            roles: CrossTermRoles,
            suppress_backfill: bool,
        ) !void {
            const r = roles;
            const followers = [_]usize{ r.b, r.c };
            const signers = [_]usize{ r.b, r.c, r.offline };
            const a_skip: u64 = if (suppress_backfill) 1 else 3;
            const v1 = try signed_certificate(harness, .notarization, 1, 0, "V1", &signers);
            try inject_to(harness, sender, v1, &followers);
            const v2 = try signed_certificate(harness, .notarization, 2, 1, "V2", &signers);
            try inject_to(harness, sender, v2, &followers);
            const v3 = try signed_certificate(harness, .nullification, 3, 0, "", &signers);
            try inject_to(harness, sender, v3, &followers);
            const a_signers = [_]usize{ r.a, r.c, r.offline };
            const skip = try signed_certificate(harness, .nullification, a_skip, 0, "", &a_signers);
            try inject_to(harness, sender, skip, &.{ r.a, r.b });
            const honest = [_]usize{ r.a, r.b, r.c };
            for ([_]u64{ 6, 11, 16 }) |view| {
                const abandoned =
                    try signed_certificate(harness, .nullification, view, 0, "", &honest);
                try inject_to(harness, sender, abandoned, &honest);
            }
        }

        /// Term 5's chain (views 21 and 22; view 21 names genesis, so `a` can vote without term 1)
        /// reaches `a` and `b`; `c` only learns the term was abandoned (at view 21 when backfill is
        /// suppressed, else at view 23).
        fn inject_term_five(
            harness: *Harness,
            sender: *Net.Sender,
            roles: CrossTermRoles,
            suppress_backfill: bool,
        ) !void {
            const r = roles;
            const followers = [_]usize{ r.a, r.b };
            const signers = [_]usize{ r.a, r.b, r.offline };
            const c_skip: u64 = if (suppress_backfill) 21 else 23;
            const v21 = try signed_certificate(harness, .notarization, 21, 0, "V21", &signers);
            try inject_to(harness, sender, v21, &followers);
            const v22 = try signed_certificate(harness, .notarization, 22, 21, "V22", &signers);
            try inject_to(harness, sender, v22, &followers);
            const c_signers = [_]usize{ r.a, r.c, r.offline };
            const skip = try signed_certificate(harness, .nullification, c_skip, 0, "", &c_signers);
            try inject_to(harness, sender, skip, &.{r.c});
            const v23 = try signed_certificate(harness, .nullification, 23, 0, "", &signers);
            try inject_to(harness, sender, v23, &followers);
        }

        /// Before the partition ends: `a` certified only view 22, `c` only view 2, `b` both, and
        /// nobody finalized.
        fn check_cross_term_split(harness: *Harness, roles: CrossTermRoles) !void {
            for (0..4) |index| {
                const reporter = &(harness.honest(index) orelse continue).reporter;
                try testing.expectEqual(index != roles.a, reporter.certified(.new(2)));
                try testing.expectEqual(index != roles.c, reporter.certified(.new(22)));
                try testing.expectEqual(0, reporter.latest_finalized().get());
            }
        }

        /// Polls each second until every honest validator finalizes view 26 (true) or nullifies a
        /// view of term 9, which proves each led a full term without finalizing (false).
        fn wait_cross_term(harness: *Harness) !bool {
            // commonware's timed runner allows 300 s.
            for (0..300) |_| {
                var finalized = true;
                var halted = true;
                for (0..4) |index| {
                    const reporter = &(harness.honest(index) orelse continue).reporter;
                    finalized = finalized and reporter.latest_finalized().get() >= 26;
                    halted = halted and reporter.latest_nullified().get() >= 41;
                }
                if (finalized) return true;
                if (halted) return false;
                try harness.ctx.sleep(.fromSeconds(1));
            }
            return error.Timeout;
        }

        /// On a halt, each deprived validator fetched its proposal parent from an honest proposer
        /// but lacks the notarization before it, so it cannot certify the parent.
        fn check_cross_term_halt(harness: *Harness, roles: CrossTermRoles) !void {
            const a = &harness.validators[roles.a].reporter;
            try testing.expect(a.notarized(.new(2)));
            try testing.expect(!a.notarized(.new(1)));
            try testing.expect(!a.certified(.new(2)));
            const c = &harness.validators[roles.c].reporter;
            try testing.expect(c.notarized(.new(22)));
            try testing.expect(!c.notarized(.new(21)));
            try testing.expect(!c.certified(.new(22)));
        }

        /// commonware `stable_leader_cross_term_certified_split`: with terms of 5 views, the
        /// offline validator leads terms 1 and 5, and each honest validator misses one of the two
        /// certified chains. Once linked, recursive parent repair must let every honest validator
        /// finalize view 26 before term 9 returns to the offline leader.
        fn cross_term_split_scenario(ctx: Context, suppress_backfill: bool) !void {
            const roles = try cross_term_roles();
            var harness: Harness = undefined;
            try harness.start_network(ctx, 4, null, .absent, .{
                .leader_ms = 10_000,
                .certification_ms = 11_000,
                .retry_ms = 10_000,
                .skip_ms = 12_000,
            });
            defer harness.deinit();
            harness.round_robin = cross_term_schedule();
            // Proposals wait so the engines process the preloaded certificates first.
            harness.propose_latency = .{ .mean = 250, .std_dev = 50 };
            const link = link_ms(10, 0, 1.0);
            var injector = try start_injector(&harness, link);
            defer injector.deinit();
            try inject_term_one(&harness, &injector.sender, roles, suppress_backfill);
            try inject_term_five(&harness, &injector.sender, roles, suppress_backfill);
            // Engines start before the partition ends, so their preload rebroadcasts are lost.
            for (0..4) |index| {
                if (index != roles.offline) try harness.start_validator(index);
            }
            try ctx.sleep(.fromSeconds(2));
            try check_cross_term_split(&harness, roles);
            try harness.link_all(link, null);
            const finalized = try wait_cross_term(&harness);
            for (0..4) |index| {
                const reporter = &(harness.honest(index) orelse continue).reporter;
                reporter.assert_no_faults();
                reporter.assert_no_invalid();
            }
            const blocked = try harness.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
            if (!finalized) {
                try check_cross_term_halt(&harness, roles);
                return error.TestUnexpectedResult; // Every honest leader exhausted a term.
            }
            for (0..4) |index| {
                const reporter = &(harness.honest(index) orelse continue).reporter;
                try testing.expect(reporter.latest_finalized().get() >= 26);
            }
            const c = &harness.validators[roles.c].reporter;
            try testing.expect(c.certified(.new(21)) and c.certified(.new(22)));
        }

        test "stable leader cross-term certified split recovers" {
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, cross_term_split_scenario, .{true});
        }

        test "stable leader cross-term certified split is backfillable" {
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, cross_term_split_scenario, .{false});
        }

        /// commonware `run_hailstorm`: five validators; each round, once all finalized the next 15
        /// views, a random validator shuts down, the rest finalize 15 more, and it restarts from
        /// its journal with the reporter it kept; then all finalize 15 more. No reporter may see a
        /// fork below the last target minus the view retention.
        fn hailstorm_scenario(ctx: Context, round_robin: RoundRobin, shutdowns: u32) !void {
            var harness: Harness = undefined;
            try harness.start_network(ctx, 5, link_ms(10, 1, 1.0), .honest, .{});
            defer harness.deinit();
            harness.round_robin = round_robin;
            for (0..5) |index| try harness.start_validator(index);
            const interval = 15;
            const rng: IoRng = .{ .io = ctx.io() };
            var target: u64 = 0;
            for (0..shutdowns) |_| {
                target += interval;
                try harness.wait_all(target);
                target += interval;
                const index: usize = @intCast(rng.next_u64() % 5);
                harness.shutdown(index);
                try harness.wait_all(target);
                target += interval;
                try harness.restart(index);
                try harness.wait_all(target);
            }
            // Views within the retention of the last target may still lack activity.
            const view_retention = 10;
            assert(target > view_retention);
            for (harness.validators) |*validator| {
                validator.reporter.assert_no_faults();
                validator.reporter.assert_no_invalid();
                try validator.reporter.check_no_forks(.new(target - view_retention));
            }
            const blocked = try harness.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
        }

        /// Two hailstorm runs of 10 shutdowns with one seed reach the same auditor state.
        fn hailstorm(round_robin: RoundRobin) !void {
            // Two shutdowns take about 30 s in Debug; ReleaseSafe runs all 10.
            if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
            const first = try run_seeded(0, hailstorm_scenario, .{ round_robin, 10 });
            const second = try run_seeded(0, hailstorm_scenario, .{ round_robin, 10 });
            try testing.expectEqualSlices(u8, &first, &second);
        }

        test "hailstorm: restarts under load replay deterministically" {
            if (comptime !fixture_enabled) return error.SkipZigTest;
            try hailstorm(RoundRobin.default());
        }

        test "hailstorm with a stable leader" {
            if (comptime !primary) return error.SkipZigTest;
            const term: consensus_types.TermLength = .new(utils.NonZero(u32).init(3).?);
            try hailstorm(RoundRobin.default().with_term(term, .from_secs(12), .new(0)));
        }

        /// commonware `observer`: a sixth peer outside the committee is registered, tracked as
        /// secondary, and linked with all five validators. commonware's loop starts engines only
        /// for the participants, so the observer never runs one; the five still finalize without
        /// faults, invalid activity, or blocks.
        fn observer_scenario(ctx: Context, required: u64) !void {
            var harness: Harness = undefined;
            const link = link_ms(10, 1, 1.0);
            try harness.start_network(ctx, 5, link, .honest, .{ .skip_ms = 12_000 });
            defer harness.deinit();
            const observer = cryptography.ed25519.PrivateKey.from_seed(5).public_key();
            for (harness.keys()) |key| assert(key.order(observer) != .eq);
            var channels = try register(harness.oracle(), observer);
            defer for (&channels) |*channel| {
                channel.sender.deinit();
                channel.receiver.deinit();
            };
            for (harness.keys()) |key| {
                try harness.oracle().add_link(observer, key, link);
                try harness.oracle().add_link(key, observer, link);
            }
            const tracked: p2p.TrackedPeers(Key) = .{
                .primary = .init(harness.keys()),
                .secondary = .init(&.{observer}),
            };
            _ = harness.oracle().manager().track(1, tracked);
            for (0..5) |index| try harness.start_validator(index);
            try harness.wait_all(required);
            try harness.check(required);
        }

        test "observer: a linked peer outside the committee changes nothing" {
            if (comptime !fixture_enabled) return error.SkipZigTest;
            _ = try run_seeded(0, observer_scenario, .{if (quick) 20 else 100});
        }

        fn among_active(_: usize, a: usize, b: usize) bool {
            return a < 4 and b < 4;
        }

        /// The lowest finalized view in (0, `tip`) that `reporter` holds and that is not a term
        /// start (the lowest finalized one when every view starts a term).
        fn mid_term_floor(reporter: *Reporter, round_robin: RoundRobin, tip: u64) ?u64 {
            var first: ?u64 = null;
            for (1..tip) |view| {
                if (reporter.finalized(.new(view)) == null) continue;
                if (first == null) first = view;
                if (!View.new(view).is_term_start(round_robin.terms.length)) return view;
            }
            return first;
        }

        /// commonware `non_genesis_floor_joiner_catches_tip`: four of five validators finalize
        /// past view 15; the fifth then links in and starts from a mid-term finalization below
        /// that tip as its floor, catches up to the tip, and finalizes 5 views past it.
        fn floor_joiner_scenario(ctx: Context, round_robin: RoundRobin) !void {
            var harness: Harness = undefined;
            const timeouts: Harness.Timeouts = .{ .retry_ms = 1000, .skip_ms = 5000 };
            try harness.start_network(ctx, 5, null, .honest, timeouts);
            defer harness.deinit();
            harness.round_robin = round_robin;
            const link = link_ms(10, 1, 1.0);
            try harness.link_all(link, &among_active);
            for (0..4) |index| try harness.start_validator(index);
            try harness.wait_all(15);
            const tip = harness.min_finalized();
            const reporter = &harness.validators[0].reporter;
            const floor = mid_term_floor(reporter, round_robin, tip).?;
            assert(floor > 0 and floor < tip);
            if (round_robin.terms.length.get() > 1) {
                try testing.expect(!View.new(floor).is_term_start(round_robin.terms.length));
            }
            const joiner = harness.keys()[4];
            for (harness.keys()[0..4]) |key| {
                try harness.oracle().add_link(joiner, key, link);
                try harness.oracle().add_link(key, joiner, link);
            }
            harness.floor = (try reporter.finalization(.new(floor))).?;
            try harness.start_validator(4);
            try harness.validators[4].reporter.wait_for_finalized(.new(tip));
            try harness.validators[4].reporter.wait_for_finalized(.new(tip + 5));
            for (harness.validators) |*validator| {
                validator.reporter.assert_no_faults();
                validator.reporter.assert_no_invalid();
            }
            const blocked = try harness.oracle().blocked(gpa);
            defer gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
        }

        test "non-genesis floor: a joiner from a finalization catches the tip" {
            if (comptime !fixture_enabled) return error.SkipZigTest;
            _ = try run_seeded(0, floor_joiner_scenario, .{RoundRobin.default()});
        }

        test "non-genesis floor: a stable-leader joiner starts mid-term" {
            if (comptime !primary) return error.SkipZigTest;
            const term: consensus_types.TermLength = .new(utils.NonZero(u32).init(3).?);
            const round_robin = RoundRobin.default().with_term(term, .from_secs(12), .new(0));
            _ = try run_seeded(0, floor_joiner_scenario, .{round_robin});
        }

        /// Whether the default round robin over five validators elects someone other than
        /// validator 0 in `round`.
        fn led_honestly(round: consensus_types.Round, _: Digest) bool {
            var schedule = RoundRobin.default().build(gpa, 5) catch @panic("out of memory");
            defer schedule.deinit(gpa);
            return schedule.elect(round, {}).get() != 0;
        }

        /// commonware `dishonest_leader_certification_rejected`: every application refuses to
        /// certify the views validator 0 leads; the five still finalize 50 views without faults or
        /// invalid activity.
        fn dishonest_leader_scenario(ctx: Context, required: u64) !void {
            var harness: Harness = undefined;
            try harness.start_network(ctx, 5, link_ms(10, 1, 1.0), .honest, .{ .skip_ms = 12_000 });
            defer harness.deinit();
            harness.should_certify = .{ .custom = &led_honestly };
            for (0..5) |index| try harness.start_validator(index);
            try harness.wait_all(required);
            for (harness.validators) |*validator| {
                validator.reporter.assert_no_faults();
                validator.reporter.assert_no_invalid();
                // Views validator 0 led never certify.
                for (1..required + 1) |view| {
                    const round: consensus_types.Round = .new(epoch, .new(view));
                    if (!led_honestly(round, undefined)) {
                        try testing.expect(!validator.reporter.certified(.new(view)));
                    }
                }
            }
        }

        test "dishonest leader: views it leads never certify" {
            if (comptime !primary) return error.SkipZigTest;
            _ = try run_seeded(0, dishonest_leader_scenario, .{if (quick) 20 else 50});
        }
    };
}

const Primary = Suite(Ed25519Fixture);
const PrimaryOptimistic = @import("engine_optimistic_test.zig").Suite(Ed25519Fixture);
pub const count_nonzero_metric_lines = Primary.nonzero_metric_lines;

test {
    _ = Primary;
    _ = PrimaryOptimistic;
}
