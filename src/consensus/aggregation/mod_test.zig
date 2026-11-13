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
        reporter: Reporter,
        reporter_task: Io.Future(anyerror!void),
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
            self.reporter_task.await(io) catch |err| switch (err) {
                error.Canceled => {},
                else => std.debug.panic("reporter: {t}", .{err}),
            };
            self.reporter.deinit();
            self.cache.deinit();
            self.provider.deinit();
            self.monitor.destroy();
        }
    };
}

/// A run of `n` validators on a simulated network.
fn Simulation(comptime S: type) type {
    return struct {
        const Self = @This();
        const V = Validator(S);
        const Fixture = cryptography.certificate.mocks.Fixture(S);

        io: Io,
        storage: runtime.storage.Storage,
        scope: runtime.telemetry.metrics.Scope,
        fixture: Fixture,
        network: *Net,
        network_task: Io.Future((Io.Cancelable || Allocator.Error)!void),
        validators: []V,
        registered: []?Net.Registered,

        fn init(
            io: Io,
            storage: runtime.storage.Storage,
            scope: runtime.telemetry.metrics.Scope,
            comptime fixture: anytype,
            n: u32,
        ) !*Self {
            var rng = utils.rng.TestRng.init(0);
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.io = io;
            self.storage = storage;
            self.scope = scope;
            self.fixture = try fixture(S, gpa, &rng, namespace, n);
            const max_size = p2p.sizing.max_message_size(&.{limits.max_payload_size(S, D)});
            const peers = try gpa.dupe(PublicKey, self.fixture.participants);
            defer gpa.free(peers);
            self.network = try Net.init_with_peers(gpa, io, .{
                .max_size = @intCast(max_size),
                .max_peers_per_set = n,
                .disconnect_on_block = true,
                .tracked_peer_sets = 1,
            }, .init_primary(.init(peers)));
            self.network_task = try io.concurrent(Net.run, .{self.network});
            const oracle = self.network.oracle();
            self.registered = try gpa.alloc(?Net.Registered, n);
            for (self.fixture.participants, self.registered) |participant, *slot| {
                slot.* = try oracle.control(participant).register(0, test_quota);
            }
            self.validators = try gpa.alloc(V, n);
            return self;
        }

        fn link_all(self: *Self, link: p2p.simulated.Link) !void {
            const oracle = self.network.oracle();
            for (self.fixture.participants) |from| {
                for (self.fixture.participants) |to| {
                    if (from.order(to) == .eq) continue;
                    try oracle.add_link(from, to, link);
                }
            }
        }

        /// Starts every validator's reporter and engine; validators in `incorrect` propose
        /// conflicting digests.
        fn spawn(self: *Self, epoch: Epoch, rebroadcast: Duration, incorrect: []const usize) !void {
            for (self.validators, 0..) |*validator, index| {
                const strategy: mocks.Strategy = for (incorrect) |bad| {
                    if (bad == index) break .incorrect;
                } else .correct;
                try self.spawn_one(validator, index, epoch, rebroadcast, strategy);
            }
        }

        fn spawn_one(
            self: *Self,
            validator: *V,
            index: usize,
            epoch: Epoch,
            rebroadcast: Duration,
            strategy: mocks.Strategy,
        ) !void {
            const participant = self.fixture.participants[index];
            validator.provider = .init(gpa);
            const signer = try self.fixture.schemes[index].clone(gpa);
            assert(try validator.provider.register(epoch, signer));
            validator.monitor = try mocks.Monitor.create(gpa, self.io, epoch);
            validator.cache = try .init(gpa, 1024, 10);
            const verifier = try self.fixture.verifier.clone(gpa);
            const reporter = try V.Reporter.init(gpa, self.io, verifier, index);
            validator.reporter, validator.mailbox = reporter;
            validator.reporter_task = try self.io.concurrent(run_reporter, .{&validator.reporter});
            const name = try std.fmt.bufPrint(&validator.partition, "aggregation-{d}", .{index});
            validator.partition_len = name.len;
            validator.engine = null;
            validator.engine_task = null;
            var label_buffer: [32]u8 = undefined;
            const label = try std.fmt.bufPrint(&label_buffer, "validator_{d}", .{index});
            const scope = self.scope.child(label);
            const registered = self.registered[index].?;
            self.registered[index] = null;
            const engine = try V.Engine.create(gpa, self.io, self.storage, &scope, .{
                .monitor = validator.monitor,
                .provider = &validator.provider,
                .automaton = .init(strategy),
                .reporter = validator.mailbox.clone(),
                .blocker = self.network.oracle().control(participant),
                .priority_acks = false,
                .rebroadcast_timeout = rebroadcast,
                .epoch_bounds = .{ .new(1), .new(1) },
                .window = 10,
                .activity_timeout = .new(100),
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

        fn run_reporter(reporter: *V.Reporter) anyerror!void {
            return reporter.run();
        }

        /// Waits until every reporter's tip reaches `height` in at least `epoch`.
        fn await_reporters(self: *Self, height: Height, epoch: Epoch) !void {
            for (self.validators) |*validator| {
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
            for (self.validators) |*validator| validator.stop_engine(self.io);
            for (self.validators) |*validator| validator.deinit(self.io);
            gpa.free(self.validators);
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

fn run_deterministic(seed: u64, comptime body: anytype, args: anytype) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .seed = seed,
        .timeout_ns = 120 * std.time.ns_per_s,
    });
    defer runner.deinit();
    const full = .{ runner.io(), runner.storage(), runner.metrics() } ++ args;
    try (try runner.start(body, full));
}

fn AllOnline(comptime S: type, comptime fixture: anytype) type {
    return struct {
        fn body(
            io: Io,
            storage: runtime.storage.Storage,
            scope: runtime.telemetry.metrics.Scope,
        ) anyerror!void {
            const simulation = try Simulation(S).init(io, storage, scope, fixture, 4);
            defer simulation.deinit();
            try simulation.link_all(reliable_link);
            try simulation.spawn(epoch_default, Duration.from_secs(5), &.{});
            try simulation.await_reporters(.new(100), epoch_default);
        }
    };
}

test "all online with ed25519" {
    try run_deterministic(0, AllOnline(scheme.ed25519.Scheme(D), scheme.ed25519.fixture).body, .{});
}
