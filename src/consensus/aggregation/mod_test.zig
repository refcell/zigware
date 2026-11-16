//! Multi-node tests of the aggregation engine (commonware `aggregation/mod.rs` tests): every
//! validator runs an engine on p2p's simulated network in the deterministic runtime, with each
//! certificate scheme.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const build_options = @import("build_options");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const scheme = @import("scheme.zig");
const limits = @import("limits.zig");
const engine_mod = @import("engine.zig");
const mocks = @import("mocks/root.zig");

const Epoch = consensus_types.Epoch;
const Height = consensus_types.Height;
const PublicKey = cryptography.ed25519.PublicKey;
const D = cryptography.Sha256.Digest;
const Net = p2p.simulated.Network(PublicKey);
const Tracked = p2p.TrackedPeers(PublicKey);
const MinPk = cryptography.bls12381.primitives.MinPk;
const MinSig = cryptography.bls12381.primitives.MinSig;
const Duration = utils.Duration;
const gpa = testing.allocator;

const namespace = "my testing namespace";
const test_quota = p2p.Quota.per_second(std.math.maxInt(u32));
const epoch_default: Epoch = .new(111);

const reliable_link: p2p.simulated.Link = .{
    .latency = Duration.from_millis(10),
    .jitter = Duration.from_millis(1),
    .success_rate = 1.0,
};

fn skip_slow() error{SkipZigTest}!void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
}

/// The engine's parameter type for scheme `S`.
fn Parameters(comptime S: type) type {
    return struct {
        pub const Scheme = S;
        pub const Provider = *mocks.Provider(S);
        pub const Digest = D;
        pub const Automaton = mocks.Application;
        pub const Reporter = mocks.ReporterMailbox(S, D);
        pub const Monitor = *mocks.Monitor;
        pub const Blocker = Net.Control;
        pub const Strategy = parallel.Sequential;
    };
}

/// One validator: its engine, the state the engine borrows, and its reporter actor.
fn Validator(comptime S: type) type {
    return struct {
        const Self = @This();
        const Engine = engine_mod.Engine(Parameters(S));
        const Reporter = mocks.Reporter(S, D);

        provider: mocks.Provider(S),
        monitor: *mocks.Monitor,
        cache: runtime.buffer.paged.CacheRef,
        partition: [80]u8,
        partition_len: usize,
        /// The validator's own reporter, absent when it reports to a shared one.
        reporter: ?*Reporter = null,
        reporter_task: ?Io.Future(anyerror!void) = null,
        mailbox: mocks.ReporterMailbox(S, D),
        engine: ?*Engine = null,
        engine_task: ?Io.Future(Engine.RunError!void) = null,

        /// Cancels the engine and waits for it to stop.
        fn stop_engine(self: *Self, io: Io) void {
            var task = self.engine_task orelse return;
            self.engine_task = null;
            task.cancel(io) catch {};
            self.engine.?.destroy();
            self.engine = null;
        }

        fn deinit(self: *Self, io: Io) void {
            self.stop_engine(io);
            // The engine's mailbox clone is gone; this releases the last sender.
            self.mailbox.deinit();
            if (self.reporter) |reporter| stop_reporter(io, reporter, &self.reporter_task.?);
            self.cache.deinit();
            self.provider.deinit();
            self.monitor.destroy();
        }
    };
}

fn stop_reporter(io: Io, reporter: anytype, task: anytype) void {
    task.await(io) catch |err| switch (err) {
        error.Canceled => {},
        else => std.debug.panic("reporter: {t}", .{err}),
    };
    reporter.deinit();
    gpa.destroy(reporter);
}

/// How each engine is configured (commonware's `Config` values the tests vary).
const EngineOptions = struct {
    rebroadcast: Duration = Duration.from_secs(5),
    window: u64 = 10,
    activity_timeout: u64 = 100,
    /// Journal partitions are `<prefix>-<index>`.
    partition: []const u8 = "aggregation",
};

test "1k" {
    try skip_slow();
    const S = mocks.scheme.Scheme(D);
    _ = try Run(S, mocks.scheme.fixture, .{
        .timeout_s = 3600,
        .committee = 10,
        .link = .{
            .latency = Duration.from_millis(80),
            .jitter = Duration.from_millis(10),
            .success_rate = 0.98,
        },
        .target = .new(1_000),
    }).run();
}

/// Where a simulation's identities come from: the runtime RNG (commonware's fixtures drawn
/// from the context, so each scheme shifts the schedule), or a fixed test RNG that gives
/// the same identities on every restart.
const Keys = enum { runtime, fixed };

/// A run of validators on a simulated network. The fixture holds a committee of
/// `committee`; the first `networked` participants join the network, and `spawn` starts the
/// first validators of those.
fn Simulation(comptime S: type) type {
    return struct {
        const Self = @This();
        const V = Validator(S);
        const Fixture = cryptography.certificate.mocks.Fixture(S);

        io: Io,
        storage: runtime.storage.Storage,
        scope: runtime.telemetry.metrics.Scope,
        fixture: Fixture,
        /// The networked participants (a prefix of the fixture's).
        participants: []const PublicKey,
        network: *Net,
        network_task: Io.Future((Io.Cancelable || Allocator.Error)!void),
        validators: []V,
        spawned: usize = 0,
        /// Which validators have an engine (`spawn` starts a prefix, `start` any one).
        started: []bool,
        /// The reporter every validator reports to, when shared.
        shared: ?struct {
            reporter: *V.Reporter,
            task: Io.Future(anyerror!void),
            mailbox: mocks.ReporterMailbox(S, D),
        } = null,
        registered: []?Net.Registered,

        fn init(
            io: Io,
            storage: runtime.storage.Storage,
            scope: runtime.telemetry.metrics.Scope,
            comptime fixture: anytype,
            keys: Keys,
            committee: u32,
            networked: u32,
        ) !*Self {
            assert(networked <= committee);
            var test_rng = utils.rng.TestRng.init(0);
            const runtime_rng: engine_mod.IoRng = .{ .io = io };
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.* = .{
                .io = io,
                .storage = storage,
                .scope = scope,
                .fixture = switch (keys) {
                    .fixed => try fixture(S, gpa, &test_rng, namespace, committee),
                    .runtime => try fixture(S, gpa, &runtime_rng, namespace, committee),
                },
                .participants = undefined,
                .network = undefined,
                .network_task = undefined,
                .validators = undefined,
                .registered = undefined,
                .started = undefined,
            };
            self.participants = self.fixture.participants[0..networked];
            const max_size = p2p.sizing.max_message_size(&.{limits.max_payload_size(S, D)});
            const peers = try gpa.dupe(PublicKey, self.participants);
            defer gpa.free(peers);
            self.network = try Net.init_with_peers(gpa, io, .{
                .max_size = @intCast(max_size),
                .max_peers_per_set = networked,
                .disconnect_on_block = true,
                .tracked_peer_sets = 1,
            }, .init_primary(.init(peers)));
            self.network_task = try io.concurrent(Net.run, .{self.network});
            const oracle = self.network.oracle();
            self.registered = try gpa.alloc(?Net.Registered, networked);
            for (self.participants, self.registered) |participant, *slot| {
                slot.* = try oracle.control(participant).register(0, test_quota);
            }
            self.validators = try gpa.alloc(V, networked);
            self.started = try gpa.alloc(bool, networked);
            @memset(self.started, false);
            return self;
        }

        /// Adds (`link` set) or removes (null) every link between networked participants.
        fn link_all(self: *Self, link: ?p2p.simulated.Link) !void {
            const oracle = self.network.oracle();
            for (self.participants) |from| {
                for (self.participants) |to| {
                    if (from.order(to) == .eq) continue;
                    if (link) |value| {
                        try oracle.add_link(from, to, value);
                    } else {
                        try oracle.remove_link(from, to);
                    }
                }
            }
        }

        /// Starts the reporter and engine of the first `count` validators; validators in
        /// `incorrect` propose conflicting digests.
        fn spawn(
            self: *Self,
            count: usize,
            epoch: Epoch,
            options: EngineOptions,
            incorrect: []const usize,
        ) !void {
            for (0..count) |index| {
                const strategy: mocks.Strategy = for (incorrect) |bad| {
                    if (bad == index) break .incorrect;
                } else .correct;
                try self.spawn_next(epoch, options, strategy);
            }
        }

        /// Makes every validator spawned from now on report to one shared reporter.
        fn share_reporter(self: *Self) !void {
            assert(self.shared == null and self.spawned == 0);
            const reporter = try gpa.create(V.Reporter);
            errdefer gpa.destroy(reporter);
            const verifier = try self.fixture.verifier.clone(gpa);
            reporter.*, const mailbox = try V.Reporter.init(gpa, self.io, verifier, 0);
            const task = try self.io.concurrent(run_reporter, .{reporter});
            self.shared = .{ .reporter = reporter, .task = task, .mailbox = mailbox };
        }

        /// Starts the next validator's engine with `strategy`.
        fn spawn_next(
            self: *Self,
            epoch: Epoch,
            options: EngineOptions,
            strategy: mocks.Strategy,
        ) !void {
            assert(self.spawned < self.validators.len);
            const index = self.spawned;
            var provider: mocks.Provider(S) = .init(gpa);
            const signer = try self.fixture.schemes[index].clone(gpa);
            assert(try provider.register(epoch, signer));
            try self.start(index, options, .{
                .provider = provider,
                .monitor = try mocks.Monitor.create(gpa, self.io, epoch),
                .verifier = try self.fixture.verifier.clone(gpa),
                .strategy = strategy,
            });
            self.spawned += 1;
        }

        /// What a validator runs with: its schemes by epoch, its epoch monitor, the scheme
        /// its own reporter verifies with, and its proposal strategy. The validator takes
        /// ownership of all of them.
        const Setup = struct {
            provider: mocks.Provider(S),
            monitor: *mocks.Monitor,
            verifier: S,
            strategy: mocks.Strategy,
        };

        /// Starts the reporter and engine of validator `index`.
        fn start(self: *Self, index: usize, options: EngineOptions, setup: Setup) !void {
            assert(!self.started[index]);
            const validator = &self.validators[index];
            const participant = self.fixture.participants[index];
            validator.provider = setup.provider;
            validator.monitor = setup.monitor;
            validator.cache = try .init(gpa, 1024, 10);
            try self.attach_reporter(validator, index, setup.verifier);
            self.started[index] = true;
            const name = try std.fmt.bufPrint(
                &validator.partition,
                "{s}-{d}",
                .{ options.partition, index },
            );
            validator.partition_len = name.len;
            var label_buffer: [32]u8 = undefined;
            const label = try std.fmt.bufPrint(&label_buffer, "validator_{d}", .{index});
            const scope = self.scope.child(label);
            const registered = self.registered[index].?;
            self.registered[index] = null;
            const engine = try V.Engine.create(gpa, self.io, self.storage, &scope, .{
                .monitor = validator.monitor,
                .provider = &validator.provider,
                .automaton = .init(setup.strategy),
                .reporter = validator.mailbox.clone(),
                .blocker = self.network.oracle().control(participant),
                .priority_acks = false,
                .rebroadcast_timeout = options.rebroadcast,
                .epoch_bounds = .{ .new(1), .new(1) },
                .window = options.window,
                .activity_timeout = .new(options.activity_timeout),
                .journal_partition = validator.partition[0..validator.partition_len],
                .journal_write_buffer = 4096,
                .journal_replay_buffer = 4096,
                .journal_heights_per_section = 6,
                .journal_compression = 3,
                .journal_page_cache = &validator.cache,
                .strategy = parallel.sequential,
            });
            validator.engine = engine;
            validator.engine_task = try engine.start(registered.sender, registered.receiver);
        }

        /// Gives `validator` its own reporter verifying with `verifier`, or a mailbox to the
        /// shared one.
        fn attach_reporter(self: *Self, validator: *V, index: usize, verifier: S) !void {
            validator.engine = null;
            validator.engine_task = null;
            validator.reporter = null;
            validator.reporter_task = null;
            if (self.shared) |shared| {
                var unused = verifier;
                unused.deinit(gpa);
                validator.mailbox = shared.mailbox.clone();
                return;
            }
            const reporter = try gpa.create(V.Reporter);
            errdefer gpa.destroy(reporter);
            reporter.*, validator.mailbox = try V.Reporter.init(gpa, self.io, verifier, index);
            validator.reporter = reporter;
            validator.reporter_task = try self.io.concurrent(run_reporter, .{reporter});
        }

        fn run_reporter(reporter: *V.Reporter) anyerror!void {
            return reporter.run();
        }

        /// Waits until every reporter's tip reaches `height` in at least `epoch`.
        fn await_reporters(self: *Self, height: Height, epoch: Epoch) !void {
            for (self.validators, self.started) |*validator, started| {
                if (!started) continue;
                while (true) {
                    const tip = try validator.mailbox.get_tip() orelse Tip.zero;
                    if (tip.height.get() >= height.get() and tip.epoch.get() >= epoch.get()) break;
                    try self.io.sleep(.fromMilliseconds(100), .awake);
                }
            }
        }

        const Tip = struct {
            const zero: mocks.reporter.Tip = .{ .height = .zero(), .epoch = .zero() };
        };

        fn deinit(self: *Self) void {
            // Stop every engine before the reporters see their last sender go.
            for (self.validators, self.started) |*validator, started| {
                if (started) validator.stop_engine(self.io);
            }
            for (self.validators, self.started) |*validator, started| {
                if (started) validator.deinit(self.io);
            }
            gpa.free(self.validators);
            gpa.free(self.started);
            if (self.shared) |*shared| {
                shared.mailbox.deinit();
                stop_reporter(self.io, shared.reporter, &shared.task);
            }
            for (self.registered) |*slot| if (slot.*) |*registered| registered.deinit();
            gpa.free(self.registered);
            self.network.close();
            self.network_task.await(self.io) catch |err| switch (err) {
                error.Canceled => {},
                else => std.debug.panic("network: {t}", .{err}),
            };
            self.network.deinit();
            self.fixture.deinit(gpa);
            gpa.destroy(self);
        }
    };
}

/// One multi-node run: which validators run, over which links, and what must happen.
const Scenario = struct {
    seed: u64 = 0,
    timeout_s: u64 = 30,
    /// The committee size and how many of it are on the network.
    committee: u32 = 4,
    networked: ?u32 = null,
    /// Validators with engines (a prefix of the networked ones).
    online: ?u32 = null,
    link: p2p.simulated.Link = reliable_link,
    rebroadcast: Duration = Duration.from_secs(5),
    incorrect: []const usize = &.{},
    /// Remove every link for this long after spawning, then restore `link`.
    partition: ?Duration = null,
    /// Every online reporter reaches this height, or (null) none certifies anything within
    /// `quiet`.
    target: ?Height = .new(100),
    quiet: Duration = Duration.from_secs(12),
};

fn Run(comptime S: type, comptime fixture: anytype, comptime scenario: Scenario) type {
    return struct {
        fn body(
            io: Io,
            storage: runtime.storage.Storage,
            scope: runtime.telemetry.metrics.Scope,
        ) anyerror!void {
            const networked = scenario.networked orelse scenario.committee;
            const online = scenario.online orelse networked;
            const simulation = try Simulation(S).init(
                io,
                storage,
                scope,
                fixture,
                .runtime,
                scenario.committee,
                networked,
            );
            defer simulation.deinit();
            try simulation.link_all(scenario.link);
            const options: EngineOptions = .{ .rebroadcast = scenario.rebroadcast };
            try simulation.spawn(online, epoch_default, options, scenario.incorrect);
            if (scenario.partition) |duration| {
                try simulation.link_all(null);
                try io.sleep(.fromNanoseconds(@intCast(duration.as_nanos())), .awake);
                try simulation.link_all(scenario.link);
            }
            const target = scenario.target orelse {
                try io.sleep(.fromNanoseconds(@intCast(scenario.quiet.as_nanos())), .awake);
                for (simulation.validators[0..simulation.spawned]) |*validator| {
                    try testing.expectEqual(null, try validator.mailbox.get_tip());
                }
                return;
            };
            try simulation.await_reporters(target, epoch_default);
        }

        /// Runs the scenario and returns the runtime's audit state.
        fn run() ![8]u8 {
            var runner = try runtime.deterministic.Runner.init(gpa, .{
                .seed = scenario.seed,
                .timeout_ns = scenario.timeout_s * std.time.ns_per_s,
            });
            defer runner.deinit();
            try (try runner.start(body, .{ runner.io(), runner.storage(), runner.metrics() }));
            return runner.auditor.state();
        }
    };
}

/// Every scheme fixture; the flag marks the ones fast enough for Debug builds (only ed25519:
/// unoptimized P-256 and BLS arithmetic take tens of seconds per run).
const fixtures = .{
    .{ scheme.ed25519.Scheme(D), scheme.ed25519.fixture, true },
    .{ scheme.secp256r1.Scheme(D, PublicKey), scheme.secp256r1.fixture, false },
    .{
        scheme.bls12381_multisig.Scheme(D, PublicKey, MinPk),
        scheme.bls12381_multisig.fixture,
        false,
    },
    .{
        scheme.bls12381_multisig.Scheme(D, PublicKey, MinSig),
        scheme.bls12381_multisig.fixture,
        false,
    },
    .{
        scheme.bls12381_threshold.Scheme(D, PublicKey, MinPk),
        scheme.bls12381_threshold.fixture,
        false,
    },
    .{
        scheme.bls12381_threshold.Scheme(D, PublicKey, MinSig),
        scheme.bls12381_threshold.fixture,
        false,
    },
};

/// Runs `scenario` with every scheme fixture. In Debug builds without `-Dslow-tests`, `slow`
/// scenarios (commonware's slow group) skip and the rest run with ed25519 only.
fn for_all_fixtures(comptime scenario: Scenario, comptime slow: bool) !void {
    const fast = builtin.mode == .debug and !build_options.slow_tests;
    if (slow and fast) return error.SkipZigTest;
    inline for (fixtures) |entry| {
        if (entry[2] or !fast) _ = try Run(entry[0], entry[1], scenario).run();
    }
}

test "all online" {
    try for_all_fixtures(.{}, false);
}

test "byzantine proposer" {
    try for_all_fixtures(.{ .incorrect = &.{0} }, false);
}

test "slow and lossy links" {
    try for_all_fixtures(lossy(0), true);
}

fn lossy(seed: u64) Scenario {
    return .{
        .seed = seed,
        .timeout_s = 120,
        .link = .{
            .latency = Duration.from_millis(200),
            .jitter = Duration.from_millis(150),
            .success_rate = 0.5,
        },
        .rebroadcast = Duration.from_secs(2),
    };
}

test "determinism" {
    try skip_slow();
    inline for (fixtures) |entry| {
        inline for (1..6) |seed| {
            const R = Run(entry[0], entry[1], lossy(seed));
            try testing.expectEqual(try R.run(), try R.run());
        }
    }
}

test "distinct states" {
    try skip_slow();
    var states: [fixtures.len][8]u8 = undefined;
    inline for (fixtures, 0..) |entry, index| {
        states[index] = try Run(entry[0], entry[1], lossy(7)).run();
    }
    for (0..states.len - 1) |index| {
        try testing.expect(!std.mem.eql(u8, &states[index], &states[index + 1]));
    }
}

test "one offline" {
    try for_all_fixtures(.{ .committee = 5, .networked = 4 }, true);
}

test "network partition" {
    try for_all_fixtures(.{ .timeout_s = 60, .partition = Duration.from_secs(20) }, false);
}

test "insufficient validators" {
    try for_all_fixtures(.{
        .timeout_s = 15,
        .committee = 5,
        .online = 2,
        .rebroadcast = Duration.from_secs(3),
        .target = null,
    }, false);
}

const AdmittedSigner = struct {
    const S = scheme.ed25519.Scheme(D);
    const epoch: Epoch = epoch_default;
    const next_epoch: Epoch = .new(112);
    const options: EngineOptions = .{
        .rebroadcast = Duration.from_millis(50),
        // Fill a two-height window before admission, so progress requires signing both
        // existing digests under the new committee.
        .window = 2,
        .activity_timeout = 10,
        .partition = "admission",
    };

    /// Rotates one member of a four-validator committee: the fifth participant verifies
    /// epoch 111 without signing authority and joins the signers in epoch 112. One current
    /// member stays offline, so all three running validators must ack to reach quorum.
    fn body(
        io: Io,
        storage: runtime.storage.Storage,
        scope: runtime.telemetry.metrics.Scope,
    ) anyerror!void {
        const simulation = try Simulation(S).init(
            io,
            storage,
            scope,
            scheme.ed25519.fixture,
            .fixed,
            5,
            5,
        );
        defer simulation.deinit();
        try simulation.link_all(reliable_link);
        const participants = simulation.fixture.participants;
        // Start the joining validator first.
        for ([_]usize{ 4, 1, 2 }) |index| {
            var provider: mocks.Provider(S) = .init(gpa);
            if (index == 4) {
                const former = try S.Participants.init(gpa, participants[0..4]);
                assert(try provider.register(epoch, try S.verifier(gpa, namespace, former)));
            }
            const current = try S.Participants.init(gpa, participants[1..]);
            const private_key = simulation.fixture.private_keys[index];
            const signer = (try S.signer(gpa, namespace, current, private_key)).?;
            assert(try provider.register(next_epoch, signer));
            const current_verifier = try S.Participants.init(gpa, participants[1..]);
            const initial = if (index == 4) epoch else next_epoch;
            const monitor = try mocks.Monitor.create(gpa, io, initial);
            try simulation.start(index, options, .{
                .provider = provider,
                .monitor = monitor,
                .verifier = try S.verifier(gpa, namespace, current_verifier),
                .strategy = .correct,
            });
            if (index != 4) continue;
            // Wait for both digests to be verified without signing authority before
            // changing epochs or starting peers that could send acks.
            while (!try digests_verified(scope, 2)) try io.sleep(.fromMilliseconds(10), .awake);
            monitor.update(next_epoch);
        }
        // Both pending heights certify at the joining validator, which counts its own newly
        // signed acks as well as its peers'.
        const mailbox = &simulation.validators[4].mailbox;
        for ([_]Height{ .zero(), .new(1) }) |height| {
            while (try mailbox.get(height) == null) try io.sleep(.fromMilliseconds(10), .awake);
        }
    }

    /// Whether a `digest_duration_count` metric has reached `count`.
    fn digests_verified(scope: runtime.telemetry.metrics.Scope, count: u32) !bool {
        const encoded = try scope.encode(gpa);
        defer gpa.free(encoded);
        var expected_buffer: [16]u8 = undefined;
        const expected = try std.fmt.bufPrint(&expected_buffer, " {d}", .{count});
        var lines = std.mem.splitScalar(u8, encoded, '\n');
        while (lines.next()) |line| {
            if (std.mem.indexOf(u8, line, "digest_duration_count") == null) continue;
            if (std.mem.endsWith(u8, line, expected)) return true;
        }
        return false;
    }

    fn run() !void {
        var runner = try runtime.deterministic.Runner.init(gpa, .{
            .timeout_ns = 10 * std.time.ns_per_s,
        });
        defer runner.deinit();
        try (try runner.start(body, .{ runner.io(), runner.storage(), runner.metrics() }));
    }
};

test "admitted signer certifies pending heights" {
    try AdmittedSigner.run();
}

/// Starts all four validators with a shared reporter, with `strategy_of(index)`.
fn spawn_shared(
    comptime S: type,
    simulation: *Simulation(S),
    options: EngineOptions,
    comptime strategy_of: fn (usize) mocks.Strategy,
) !void {
    try simulation.link_all(reliable_link);
    try simulation.share_reporter();
    for (0..simulation.validators.len) |index| {
        try simulation.spawn_next(epoch_default, options, strategy_of(index));
    }
}

/// Waits until the shared reporter's contiguous tip reaches `target`, or (when `deadline`
/// is set) until that much time passed. Returns whether it reached the target.
fn await_contiguous(
    comptime S: type,
    simulation: *Simulation(S),
    target: Height,
    deadline: ?Duration,
) !bool {
    const io = simulation.io;
    const start = Io.Timestamp.now(io, .awake).nanoseconds;
    const mailbox = &simulation.shared.?.mailbox;
    while (true) {
        const contiguous = try mailbox.get_contiguous_tip();
        if (contiguous) |tip| if (tip.get() >= target.get()) return true;
        if (deadline) |limit| {
            const elapsed = Io.Timestamp.now(io, .awake).nanoseconds - start;
            if (elapsed >= limit.as_nanos()) return false;
        }
        try io.sleep(.fromMilliseconds(50), .awake);
    }
}

fn UncleanByzantineShutdown(comptime S: type, comptime fixture: anytype) type {
    return struct {
        const target: Height = .new(200);
        const options: EngineOptions = .{
            .rebroadcast = Duration.from_millis(20),
            // Large enough that no certificate is dropped.
            .activity_timeout = 1024,
            .partition = "unclean_shutdown_test",
        };

        fn strategy_of(index: usize) mocks.Strategy {
            return if (index == 0) .incorrect else .correct;
        }

        /// One run until the shared reporter is complete or a random unclean shutdown.
        fn body(
            io: Io,
            storage: runtime.storage.Storage,
            scope: runtime.telemetry.metrics.Scope,
        ) anyerror!bool {
            const simulation = try Simulation(S).init(io, storage, scope, fixture, .fixed, 4, 4);
            // Canceling the engines models a crash: unsynced journal writes are lost on the
            // next start.
            defer simulation.deinit();
            try spawn_shared(S, simulation, options, strategy_of);
            var draw: [8]u8 = undefined;
            io.random(&draw);
            const wait_ms = 100 + std.mem.readInt(u64, &draw, .little) % 900;
            return await_contiguous(S, simulation, target, Duration.from_millis(wait_ms));
        }

        fn run() !void {
            var runner = try runtime.deterministic.Runner.init(gpa, .{
                .timeout_ns = 45 * std.time.ns_per_s,
            });
            defer runner.deinit();
            const min_shutdowns = 4;
            const max_shutdowns = 10;
            var shutdowns: u32 = 0;
            while (shutdowns < max_shutdowns) : (shutdowns += 1) {
                const args = .{ runner.io(), runner.storage(), runner.metrics() };
                const complete = try (try runner.start(body, args));
                if (complete and shutdowns >= min_shutdowns) return;
            }
            return error.TargetNotReached;
        }
    };
}

test "unclean byzantine shutdown" {
    try skip_slow();
    inline for (fixtures) |entry| try UncleanByzantineShutdown(entry[0], entry[1]).run();
}

fn UncleanShutdownWithUnsignedHeight(comptime S: type, comptime fixture: anytype) type {
    return struct {
        const skip_height: Height = .new(50);
        const window = 10;
        const options: EngineOptions = .{
            .rebroadcast = Duration.from_millis(100),
            .window = window,
            .partition = "unsigned_height_test",
        };

        fn skip(_: usize) mocks.Strategy {
            return .{ .skip = skip_height };
        }

        fn correct(_: usize) mocks.Strategy {
            return .correct;
        }

        /// Every validator declines to propose at `skip_height`: run until the window
        /// above it is full (as far as anyone gets without certifying it).
        fn first(
            io: Io,
            storage: runtime.storage.Storage,
            scope: runtime.telemetry.metrics.Scope,
        ) anyerror!void {
            const simulation = try Simulation(S).init(io, storage, scope, fixture, .fixed, 4, 4);
            defer simulation.deinit();
            try spawn_shared(S, simulation, options, skip);
            const mailbox = &simulation.shared.?.mailbox;
            const furthest = skip_height.get() + window - 1;
            while (true) {
                const reported = try mailbox.get_tip();
                if (reported) |tip| if (tip.height.get() >= furthest) return;
                try io.sleep(.fromMilliseconds(50), .awake);
            }
        }

        /// After a restart, replay requests the missing digest and the height certifies.
        fn second(
            io: Io,
            storage: runtime.storage.Storage,
            scope: runtime.telemetry.metrics.Scope,
        ) anyerror!void {
            const simulation = try Simulation(S).init(io, storage, scope, fixture, .fixed, 4, 4);
            defer simulation.deinit();
            try spawn_shared(S, simulation, options, correct);
            assert(try await_contiguous(S, simulation, .new(100), null));
        }

        fn run() !void {
            var runner = try runtime.deterministic.Runner.init(gpa, .{
                .timeout_ns = 60 * std.time.ns_per_s,
            });
            defer runner.deinit();
            try (try runner.start(first, .{ runner.io(), runner.storage(), runner.metrics() }));
            try (try runner.start(second, .{ runner.io(), runner.storage(), runner.metrics() }));
        }
    };
}

test "unclean shutdown with an unsigned height" {
    try skip_slow();
    inline for (fixtures) |entry| try UncleanShutdownWithUnsignedHeight(entry[0], entry[1]).run();
}
