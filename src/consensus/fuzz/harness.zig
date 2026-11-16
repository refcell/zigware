//! One fuzzed simplex run (commonware `consensus/fuzz/src/lib.rs` `run` and `simplex.rs`):
//! four validators on `p2p.simulated` under the deterministic runtime, the Byzantine ones
//! running disrupters, the honest ones running the engine with mock applications. Once
//! every honest validator finalized the required view (connected networks that can
//! finalize) or after 15 s of simulated time, the run checks the safety invariants over the
//! certificates each honest validator reported.
//!
//! Deviations from commonware: the runtime is seeded by a `u64` drawn after the other
//! fields (commonware feeds the remaining raw bytes to a `FuzzRng`), the fixture draws from
//! `TestRng` of that seed, and a run that has not finished after `run_timeout_ns` of
//! simulated time fails with `error.Timeout` (commonware hangs until the fuzzer's timeout).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const traits = @import("../traits.zig");
const simplex = @import("../simplex/root.zig");
const fuzz_types = @import("types.zig");
const strategy_mod = @import("strategy.zig");
const invariants = @import("invariants.zig");
const recorder_mod = @import("recorder.zig");
const disrupter_mod = @import("disrupter.zig");
const twin_mod = @import("twin.zig");

const Digest = fuzz_types.Digest;
const Configuration = fuzz_types.Configuration;
const Strategy = strategy_mod.Strategy;
const TermLength = consensus_types.TermLength;
const Unstructured = @import("invariants").minifuzz.Unstructured;
const Sha256 = cryptography.Sha256;
const Key = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Link = p2p.simulated.Link;
const Context = runtime.deterministic.Context;
const Application = simplex.mocks.application.Application(Sha256, Key);
const Relay = simplex.mocks.relay.Relay(Digest, Key);
const Elector = simplex.elector.RoundRobinElector;
const Duration = utils.Duration;
const Decision = std.meta.Tag(traits.Handoff(Digest));

const namespace = "consensus_fuzz";
const fault_injection_ratio = 5;
const min_number_of_faults = 2;
const min_required_containers = 5;
const max_required_containers = 50;
const max_sleep_ms = 15_000;
const quota = p2p.Quota.per_second(1024);
const page_size = 1024;
const page_cache_size = 10;
/// Simulated time a run may take before it counts as a liveness failure.
pub const run_timeout_ns: u64 = 600 * std.time.ns_per_s;

/// Honest handoff decisions: wait for parent certification, relay early but hold the vote,
/// or vote early (commonware `HANDOFF_DECISIONS`).
pub const handoff_decisions = [_]Decision{ .wait, .stage, .vote };

/// Network partitions (commonware `Partition`).
pub const Partition = enum {
    /// Every validator linked to every other.
    connected,
    /// Two halves that only the Byzantine node 0 bridges.
    two_partitions_with_byzantine,
    /// Every honest node linked only to the Byzantine node 0.
    many_partitions_with_byzantine,
    /// No links.
    isolated,
    /// Node i linked to i - 1 and i + 1, wrapping.
    ring,

    /// Whether `i` links to `j` among `n` nodes.
    pub fn admits(partition: Partition, n: usize, i: usize, j: usize) bool {
        assert(i != j);
        return switch (partition) {
            .connected => true,
            .isolated => false,
            .two_partitions_with_byzantine => i == 0 or j == 0 or
                ((i <= n / 2) == (j <= n / 2)),
            .many_partitions_with_byzantine => i == 0 or j == 0,
            .ring => @max(i, j) - @min(i, j) == 1 or @max(i, j) - @min(i, j) == n - 1,
        };
    }
};

/// commonware's `FuzzInput`.
pub const Input = struct {
    seed: u64,
    required_containers: u64,
    term_length: TermLength,
    optimistic_views: u64,
    heterogeneous_optimism: bool,
    handoff: Decision,
    degraded_network: bool,
    configuration: Configuration,
    partition: Partition,
    strategy: Strategy,

    /// commonware's `Arbitrary for FuzzInput`, in its draw order.
    pub fn draw(u: *Unstructured) !Input {
        const partition: Partition = switch (u.int_in_range(u8, 0, 99)) {
            0...79 => .connected,
            80...84 => .isolated,
            85...89 => .two_partitions_with_byzantine,
            90...94 => .many_partitions_with_byzantine,
            else => .ring,
        };
        const configuration = if (u.int_in_range(u8, 1, 100) <= 95)
            fuzz_types.n4f1c3
        else
            fuzz_types.n4f3c1;
        const degraded_network = partition == .connected and
            std.meta.eql(configuration, fuzz_types.n4f1c3) and u.int_in_range(u8, 0, 99) == 1;
        const required = u.int_in_range(u64, min_required_containers, max_required_containers);
        const term_length: TermLength = .{ .length = u.int_in_range(u32, 1, 5) };
        const optimistic = u.int_in_range(u64, 0, max_optimistic_views(term_length));
        const heterogeneous_optimism = try u.arbitrary(bool);
        const handoff = try u.choose(Decision, &handoff_decisions);
        const fault_rounds_bound = u.int_in_range(u64, 1, required);
        const max_faults = fault_rounds_bound / fault_injection_ratio;
        const min_faults = @min(min_number_of_faults, fault_rounds_bound);
        const fault_rounds = @max(u.int_in_range(u64, 0, max_faults), min_faults);
        const bounds: strategy_mod.FaultBounds =
            .{ .fault_rounds = fault_rounds, .fault_rounds_bound = fault_rounds_bound };
        const strategy: Strategy = switch (u.int_in_range(u8, 0, 9)) {
            0 => .any_scope,
            1 => .{ .future_scope = bounds },
            else => .{ .small_scope = bounds },
        };
        return .{
            .seed = try u.arbitrary(u64),
            .required_containers = required,
            .term_length = term_length,
            .optimistic_views = optimistic,
            .heterogeneous_optimism = heterogeneous_optimism,
            .handoff = handoff,
            .degraded_network = degraded_network,
            .configuration = configuration,
            .partition = partition,
            .strategy = strategy,
        };
    }

    /// The optimistic-view budget of validator `index`: the base value, or (heterogeneous
    /// runs) a per-validator value in `[0, term_length + 2]`.
    fn optimistic_views_of(input: Input, index: usize) u64 {
        if (!input.heterogeneous_optimism) return input.optimistic_views;
        const span = max_optimistic_views(input.term_length) + 1;
        return (input.optimistic_views + index) % span;
    }
};

/// `[0, term_length + 2]` covers disabled optimism, the term boundary, and values beyond it.
fn max_optimistic_views(term_length: TermLength) u64 {
    return term_length.get() + 2;
}

fn link_ms(latency_ms: u64, jitter_ms: u64, success_rate: f64) Link {
    return .{
        .latency = Duration.from_millis(latency_ms),
        .jitter = Duration.from_millis(jitter_ms),
        .success_rate = success_rate,
    };
}

/// One scheme under test (commonware's `Simplex` implementations), every one with a
/// round-robin elector over ed25519 identities.
pub const targets = struct {
    pub const Ed25519 = struct {
        pub const Scheme = simplex.scheme.ed25519.Scheme(Digest);
        pub fn fixture(gpa: Allocator, rng: anytype, n: u32) !Fixture(Scheme) {
            return simplex.scheme.ed25519.fixture(Digest, gpa, rng, namespace, n);
        }
    };

    pub const Secp256r1 = struct {
        pub const Scheme = simplex.scheme.secp256r1.Scheme(Digest, Key);
        pub fn fixture(gpa: Allocator, rng: anytype, n: u32) !Fixture(Scheme) {
            return simplex.scheme.secp256r1.fixture(Scheme, gpa, rng, namespace, n);
        }
    };

    pub fn Multisig(comptime V: type) type {
        return struct {
            pub const Scheme = simplex.scheme.bls12381_multisig.Scheme(Digest, Key, V);
            pub fn fixture(gpa: Allocator, rng: anytype, n: u32) !Fixture(Scheme) {
                return simplex.scheme.bls12381_multisig.fixture(Scheme, gpa, rng, namespace, n);
            }
        };
    }

    pub fn Threshold(comptime V: type) type {
        return struct {
            const vrf = simplex.scheme.bls12381_threshold.vrf;
            pub const Scheme = vrf.Scheme(Digest, Key, V);
            pub fn fixture(gpa: Allocator, rng: anytype, n: u32) !Fixture(Scheme) {
                return vrf.fixture(Scheme, gpa, rng, namespace, n);
            }
        };
    }
};

fn Fixture(comptime S: type) type {
    return cryptography.certificate.mocks.Fixture(S);
}

/// How Byzantine validators behave (commonware `FuzzMode`): `standard` runs a disrupter;
/// `twin` runs a twin whose primary half is an honest engine and whose secondary half is a
/// disrupter, the network split between them per view (`twin.zig`).
pub const Mode = enum { standard, twin };

/// Runs `input` against target `T` on a fresh deterministic runtime; fails on an invariant
/// violation or when the run outlives `run_timeout_ns`.
pub fn run(comptime T: type, comptime mode: Mode, gpa: Allocator, input: Input) !void {
    const config: runtime.deterministic.Config = .{
        .seed = input.seed,
        .timeout_ns = run_timeout_ns,
    };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try (try runner.start_context(Run(T, mode).scenario, .{ gpa, input }));
}

pub fn Run(comptime T: type, comptime mode: Mode) type {
    return struct {
        const Self = @This();
        const S = T.Scheme;
        const Recorder = recorder_mod.Recorder(S);
        const Disrupter = disrupter_mod.Disrupter(S);
        const Params = struct {
            pub const Context = runtime.deterministic.Context;
            pub const Scheme = S;
            pub const Elector = simplex.elector.RoundRobinElector;
            pub const Blocker = Net.Control;
            pub const Digest = Sha256.Digest;
            pub const Automaton = *Application;
            pub const Relay = *Application;
            pub const Reporter = *Recorder;
            pub const Strategy = parallel.Sequential;
            pub const Sender = Net.Sender;
            pub const Receiver = Net.Receiver;
        };
        const Splitter = twin_mod.Splitter(S);
        const TwinSender = Net.SplitSender(Splitter.Forwarder);
        /// The twin's primary half: the honest engine over split senders.
        const TwinParams = struct {
            pub const Context = Params.Context;
            pub const Scheme = S;
            pub const Elector = Params.Elector;
            pub const Blocker = Params.Blocker;
            pub const Digest = Params.Digest;
            pub const Automaton = Params.Automaton;
            pub const Relay = Params.Relay;
            pub const Reporter = Params.Reporter;
            pub const Strategy = Params.Strategy;
            pub const Sender = TwinSender;
            pub const Receiver = Net.Receiver;
        };
        const Channel = simplex.engine.Channel(Params);
        const twin = mode == .twin;
        /// The disrupter's channels: whole, or the secondary halves of a twin's.
        const DisrupterChannel = if (twin) simplex.engine.Channel(TwinParams) else Channel;
        const Honest = Node(Params);
        const certification_timeout_ms: u64 = if (twin) 1500 else 2000;

        /// An engine and its mocks. Must not move once started.
        fn Node(comptime P: type) type {
            return struct {
                const Engine = simplex.engine.Engine(P);

                started: bool = false,
                application: Application,
                recorder: Recorder,
                page_cache: runtime.buffer.paged.CacheRef,
                elector: Elector,
                engine: Engine,
                partition: [32]u8,
                handle: ?runtime.context.Handle(Engine.RunResult),
            };
        }

        /// A Byzantine validator: a disrupter, and in twin mode a primary engine. Must not
        /// move once started.
        const Byzantine = struct {
            started: bool = false,
            disrupter: Disrupter,
            channels: [3]DisrupterChannel,
            handle: ?runtime.context.Handle(void),
            primary: if (twin) Node(TwinParams) else void,

            fn run_task(ctx: Context, node: *Byzantine) void {
                _ = ctx;
                const channels = &node.channels;
                node.disrupter.run(&channels[0], &channels[1], &channels[2]);
            }
        };

        gpa: Allocator,
        ctx: Context,
        input: Input,
        fixture: Fixture(S),
        network: *Net,
        network_task: std.Io.Future((std.Io.Cancelable || Allocator.Error)!void),
        relay: Relay,
        splitter: Splitter,
        /// Validators `0..faults` are Byzantine, the rest honest (in participant order).
        byzantine: []Byzantine,
        honest: []Honest,

        fn scenario(ctx: Context, gpa: Allocator, input: Input) !void {
            var harness: Self = undefined;
            try harness.init(ctx, gpa, input);
            defer harness.deinit();
            try harness.start_nodes();
            try harness.wait();
            try harness.check();
        }

        fn keys(self: *const Self) []const Key {
            return self.fixture.participants;
        }

        fn oracle(self: *const Self) Net.Oracle {
            return self.network.oracle();
        }

        fn init(self: *Self, ctx: Context, gpa: Allocator, input: Input) !void {
            const io = ctx.io();
            const configuration = input.configuration;
            const n = configuration.n;
            assert(configuration.faults + configuration.correct == n);
            var rng = utils.rng.TestRng.init(input.seed);
            self.* = undefined;
            self.gpa = gpa;
            self.ctx = ctx;
            self.input = input;
            self.fixture = try T.fixture(gpa, &rng, n);
            errdefer self.fixture.deinit(gpa);
            self.byzantine = try gpa.alloc(Byzantine, configuration.faults);
            errdefer gpa.free(self.byzantine);
            for (self.byzantine) |*node| {
                node.started = false;
                if (twin) node.primary.started = false;
            }
            self.honest = try gpa.alloc(Honest, configuration.correct);
            errdefer gpa.free(self.honest);
            for (self.honest) |*node| node.started = false;
            self.network = try Net.init(gpa, io, .{
                .max_size = 1024 * 1024,
                .max_peers_per_set = n,
                .disconnect_on_block = false,
                .tracked_peer_sets = 1,
            });
            self.network_task = try io.concurrent(Net.run, .{self.network});
            self.relay = .init(gpa, io);
            _ = self.oracle().manager().track(0, .init_primary(.init(self.keys())));
            self.splitter = .{
                .gpa = gpa,
                .keys = self.keys(),
                .term_length = input.term_length,
                .certificate_cfg = self.fixture.verifier.certificate_codec_config(),
            };
            try self.link_all(link_ms(10, 1, 1.0), false);
            const standard = std.meta.eql(configuration, fuzz_types.n4f1c3);
            if (input.partition == .connected and standard and input.degraded_network) {
                try self.degrade_last();
            }
            // Twins run on slow links, so the halves' views drift apart.
            if (twin) try self.link_all(link_ms(500, 500, 1.0), true);
        }

        fn deinit(self: *Self) void {
            // Abort every engine before freeing any mock: live voters relay to every
            // application.
            for (self.honest) |*node| if (node.started) abort_engine(node);
            if (twin) for (self.byzantine) |*node| {
                if (node.primary.started) abort_engine(&node.primary);
            };
            self.relay.deregister_all();
            for (self.byzantine) |*node| if (node.started) {
                if (node.handle) |handle| handle.abort() catch {};
                for (&node.channels) |*channel| {
                    channel.sender.deinit();
                    channel.receiver.deinit();
                }
            };
            for (self.honest) |*node| if (node.started) self.stop_node(node);
            if (twin) for (self.byzantine) |*node| {
                if (node.primary.started) self.stop_node(&node.primary);
            };
            self.gpa.free(self.honest);
            self.gpa.free(self.byzantine);
            self.relay.deinit();
            self.network.close();
            self.network_task.await(self.ctx.io()) catch {};
            self.network.deinit();
            self.fixture.deinit(self.gpa);
            self.* = undefined;
        }

        /// Releases a node's engine (and the channels it owns) and mocks.
        fn stop_node(self: *Self, node: anytype) void {
            node.engine.deinit();
            node.elector.deinit(self.gpa);
            node.page_cache.deinit();
            node.recorder.deinit();
            node.application.deinit();
            node.started = false;
        }

        fn abort_engine(node: anytype) void {
            const handle = node.handle orelse return;
            node.handle = null;
            const result = handle.abort() catch return; // Aborted before it returned.
            result catch |err| std.debug.panic("engine failed: {t}", .{err});
        }

        /// Links every ordered pair the partition admits; `update` replaces existing links.
        fn link_all(self: *Self, link: Link, update: bool) !void {
            const peers = self.keys();
            for (peers, 0..) |from, a| for (peers, 0..) |to, b| {
                if (a == b) continue;
                if (!self.input.partition.admits(peers.len, a, b)) continue;
                if (update) self.oracle().remove_link(from, to) catch {};
                try self.oracle().add_link(from, to, link);
            };
        }

        /// Replaces the last validator's links with slow, lossy ones (commonware
        /// `setup_degraded_network`).
        fn degrade_last(self: *Self) !void {
            const peers = self.keys();
            const victim = peers[peers.len - 1];
            const degraded = link_ms(50, 50, 0.6);
            for (peers[0 .. peers.len - 1]) |peer| {
                self.oracle().remove_link(victim, peer) catch {};
                self.oracle().remove_link(peer, victim) catch {};
                try self.oracle().add_link(victim, peer, degraded);
                try self.oracle().add_link(peer, victim, degraded);
            }
        }

        fn register(self: *Self, key: Key) ![3]Channel {
            var channels: [3]Channel = undefined;
            for (&channels, 0..) |*channel, index| {
                const registered = try self.oracle().control(key).register(index, quota);
                channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
            }
            return channels;
        }

        fn start_nodes(self: *Self) !void {
            for (self.byzantine, 0..) |*node, index| {
                const channels = try self.register(self.keys()[index]);
                if (twin) {
                    const primary = try self.split(channels, &node.channels);
                    try self.start_engine(TwinParams, &node.primary, index, primary, "twin");
                } else {
                    node.channels = channels;
                }
                const scheme = &self.fixture.schemes[index];
                const strategy = self.input.strategy;
                node.disrupter = .init(self.gpa, self.ctx.io(), scheme, strategy);
                node.handle = null;
                node.started = true;
                const child = self.ctx.child("disrupter");
                node.handle = try child.spawn(Byzantine.run_task, .{node});
            }
            const faults = self.byzantine.len;
            for (self.honest, faults..) |*node, index| {
                const channels = try self.register(self.keys()[index]);
                try self.start_engine(Params, node, index, channels, "validator");
            }
        }

        /// Splits a twin's channels: returns the primary halves and writes the secondary
        /// halves to `secondary`.
        fn split(
            self: *Self,
            channels: [3]Channel,
            secondary: *[3]DisrupterChannel,
        ) ![3]simplex.engine.Channel(TwinParams) {
            comptime assert(twin);
            const kinds = [3]twin_mod.Kind{ .votes, .certificates, .resolver };
            var primary: [3]simplex.engine.Channel(TwinParams) = undefined;
            for (channels, kinds, 0..) |channel, kind, index| {
                const senders = channel.sender.split_with(self.splitter.forwarder(kind));
                const router = self.splitter.router(kind);
                const io = self.ctx.io();
                const receivers = try channel.receiver.split_with(self.gpa, io, router);
                primary[index] = .{ .sender = senders.primary, .receiver = receivers.primary };
                const half: DisrupterChannel = .{
                    .sender = senders.secondary,
                    .receiver = receivers.secondary,
                };
                secondary[index] = half;
            }
            return primary;
        }

        /// Starts validator `index`'s engine (an honest one, or a twin's primary half) on
        /// `channels`, which it owns from then on.
        fn start_engine(
            self: *Self,
            comptime P: type,
            node: *Node(P),
            index: usize,
            channels: [3]simplex.engine.Channel(P),
            comptime label: []const u8,
        ) !void {
            const io = self.ctx.io();
            const gpa = self.gpa;
            const key = self.keys()[index];
            const n: u32 = @intCast(self.keys().len);
            const latency: simplex.mocks.application.Latency = .{ .mean = 10, .std_dev = 5 };
            node.application = try .init(gpa, io, .{
                .relay = &self.relay,
                .me = key,
                .propose_latency = latency,
                .verify_latency = latency,
                .certify_latency = latency,
            });
            node.application.handoff = self.input.handoff;
            node.application.reject_mismatches = true;
            try node.application.register();
            node.recorder = .init(gpa, io, &self.fixture.verifier, n);
            node.page_cache = try .init(gpa, page_size, page_cache_size);
            node.elector = try self.elector_config(index).build(gpa, n);
            node.partition = @splat(0);
            _ = try std.fmt.bufPrint(&node.partition, label ++ "-{d}", .{index});
            node.handle = null;
            node.started = true;
            const control = self.oracle().control(key);
            const cfg = engine_config(P, node, self.fixture.schemes[index], control);
            try node.engine.init(self.ctx, cfg);
            node.handle = try self.ctx.child("engine").spawn(Node(P).Engine.run, .{
                &node.engine, channels[0], channels[1], channels[2],
            });
        }

        /// commonware's `round_robin`: the term length and lookahead apply only to multi-view
        /// terms.
        fn elector_config(self: *const Self, index: usize) simplex.elector.RoundRobin(Sha256) {
            const config = simplex.elector.RoundRobin(Sha256).default();
            const term_length = self.input.term_length;
            if (term_length.length == 1) return config;
            const optimistic: consensus_types.ViewDelta =
                .new(self.input.optimistic_views_of(index));
            return config.with_term(term_length, Duration.from_secs(12), optimistic);
        }

        fn engine_config(
            comptime P: type,
            node: *Node(P),
            scheme: S,
            blocker: Net.Control,
        ) Node(P).Engine.Config {
            const genesis = simplex.mocks.application.genesis(Sha256, fuzz_types.epoch);
            return .{
                .scheme = scheme,
                .elector = node.elector,
                .blocker = blocker,
                .automaton = &node.application,
                .relay = &node.application,
                .reporter = &node.recorder,
                .track_historical_votes = false,
                .strategy = parallel.sequential,
                .partition = std.mem.sliceTo(&node.partition, 0),
                .mailbox_size = 1024,
                .epoch = fuzz_types.epoch,
                .floor = .{ .genesis = genesis },
                .replay_buffer = 1024 * 1024,
                .write_buffer = 1024 * 1024,
                .page_cache = &node.page_cache,
                .leader_timeout = .from_secs(1),
                .certification_timeout = .from_millis(certification_timeout_ms),
                .timeout_retry = .from_secs(10),
                .view_retention = .new(10),
                .skip = .{ .enabled = .{ .timeout = .from_secs(11) } },
                .fetch_timeout = .from_secs(1),
                .fetch_retry_delay = .from_millis(100),
                .forward = .disabled,
            };
        }

        /// Waits until every honest validator finalized the required view (a connected
        /// network that can finalize), else sleeps 15 s.
        fn wait(self: *Self) !void {
            const live = self.input.configuration.can_finalize();
            if (self.input.partition == .connected and live) {
                for (self.honest) |*node| {
                    try node.recorder.wait_for_finalized(self.input.required_containers);
                }
            } else {
                try self.ctx.io().sleep(.fromMilliseconds(max_sleep_ms), .awake);
            }
        }

        fn check(self: *Self) !void {
            var arena: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena.deinit();
            const replicas = try arena.allocator().alloc(fuzz_types.Replica, self.honest.len);
            for (replicas, self.honest) |*replica, *node| {
                replica.* = try node.recorder.replica(arena.allocator());
            }
            const input = self.input;
            const attributable = S.is_attributable();
            const configuration = input.configuration;
            const term_length = input.term_length;
            try invariants.check(self.gpa, attributable, configuration, term_length, replicas);
        }
    };
}
