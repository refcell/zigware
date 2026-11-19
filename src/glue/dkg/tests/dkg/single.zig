//! Single-participant DKG tests outside a plan (commonware `glue::dkg::tests::dkg`'s
//! `run_activation_failure_completes_empty`, `run_restart_*`, and
//! `run_share_without_final_block`). Each run boots the bootstrap engine on a fresh simulated
//! network; a restart runs another root task on the same deterministic runner, which keeps
//! storage and simulated time (commonware's `Checkpoint`). An "unclean shutdown" aborts the
//! engine without draining it.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const network = @import("../../network.zig");
const bootstrap = @import("../../bootstrap/mod.zig");
const mocks = @import("../mocks.zig");
const harness = @import("harness.zig");

const gpa = testing.allocator;
const Ctx = runtime.deterministic.Context;
const Epoch = consensus.Epoch;
const ed25519 = cryptography.ed25519;
const Key = ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Set = utils.ordered.Set(Key);
const Unit = utils.sequence.Unit;
const MinPk = cryptography.bls12381.primitives.MinPk;
const prefix = "dkg-single";
const quota = p2p.Quota.per_second(1024);

fn Types(comptime M: type) type {
    return struct {
        pub const Variant = MinPk;
        pub const Directory = Unit;
        pub const Manager = M;
        pub const PeerProvider = Net.Manager;
        pub const Blocker = Net.Control;
        pub const SecretStore = mocks.MemorySecretStore;
        pub const Network = Net;
    };
}

const KeyOnly = network.KeyOnlyManager(Net.Manager);
const Failing = mocks.FailingManager(Net.Manager);

/// What one run of the single participant owns.
fn Run(comptime M: type) type {
    return struct {
        const Self = @This();
        const Engine = bootstrap.Engine(Types(M));

        io: std.Io,
        net: *Net,
        network_task: std.Io.Future((std.Io.Cancelable || Allocator.Error)!void),
        manager: M,
        participants: Set,
        started: Engine.Started,

        /// Boots the participant over `store` (borrowed) on a fresh network.
        fn boot(self: *Self, ctx: Ctx, store: *mocks.MemorySecretStore) !void {
            const io = ctx.io();
            const signer = ed25519.PrivateKey.from_seed(0);
            self.io = io;
            self.net = try Net.init(gpa, io, .{
                .max_size = 1024 * 1024,
                .max_peers_per_set = 1,
                .disconnect_on_block = true,
                .tracked_peer_sets = 1,
            });
            self.network_task = try io.concurrent(Net.run, .{self.net});
            self.manager = M.init(self.net.oracle().manager());
            self.participants = try Set.from_dedup(gpa, &.{signer.public_key()});
            const channels = try self.register(signer.public_key());
            const config: bootstrap.Config(Types(M)) = .{
                .signer = signer,
                .manager = &self.manager,
                .peer_provider = self.net.oracle().manager(),
                .blocker = self.net.oracle().control(signer.public_key()),
                .secret_store = store,
                .namespace = "_COMMONWARE_GLUE_DKG_INITIAL_E2E",
                .sharing_mode = .non_zero_counter,
                .reveal = .v1,
                .max_supported_mode = mocks.max_supported_mode,
                .partition_prefix = prefix,
                .write_buffer = 2048,
                .replay_buffer = 2048,
                .mailbox_size = 100,
                .fetch_timeout = .from_secs(2),
                .fetch_retry_delay = .from_millis(100),
                .items_per_section = 10,
                .participants = self.participants,
                .directory = .{},
                .blocks_per_epoch = harness.epoch_length,
            };
            self.started = try Engine.start(ctx.child("dkg"), config, channels);
        }

        fn register(self: *Self, key: Key) !Engine.Channels {
            var channels: [6]Engine.Channel = undefined;
            for (&channels, 0..) |*channel, index| {
                const registered = try self.net.oracle().control(key).register(index, quota);
                channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
            }
            return .{
                .votes = channels[0],
                .certificates = channels[1],
                .resolver = channels[2],
                .backfill = channels[3],
                .broadcast = channels[4],
                .dkg = channels[5],
            };
        }

        /// The completion, or null when none arrives within `ms` of simulated time.
        fn completion(self: *Self, ms: u64) !?Engine.Completion {
            var waited: u64 = 0;
            while (waited < ms) : (waited += 10) {
                if (self.started.completion.try_recv()) |value| return value else |err| {
                    if (err != error.Empty) return err;
                }
                try self.io.sleep(.fromMilliseconds(10), .awake);
            }
            return null;
        }

        /// Whether peer set zero is tracked on this run's network.
        fn tracked(self: *Self) !bool {
            const peers = try self.net.oracle().manager().peer_set(gpa, 0) orelse return false;
            peers.free(gpa);
            return true;
        }

        /// Aborts the engine (an unclean shutdown) and returns its result, then stops the
        /// network.
        fn close(self: *Self) anyerror!void {
            const ended = self.started.handle.abort();
            self.started.completion.deinit();
            self.participants.deinit(gpa);
            self.net.close();
            self.network_task.await(self.io) catch {};
            self.net.deinit();
            if (ended) |result| return result else |_| {}
        }
    };
}

/// The processed height marshal reports under the engine's `dkg` scope.
fn processed_height(ctx: Ctx) !u64 {
    const text = try ctx.encode(gpa);
    defer gpa.free(text);
    var lines = std.mem.splitScalar(u8, text, '\n');
    const name = "dkg_marshal_processed_height ";
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, name)) {
            return std.fmt.parseInt(u64, line[name.len..], 10);
        }
    }
    return error.MissingProcessedHeight;
}

const State = struct {
    store: mocks.MemorySecretStore,
    /// Owned.
    info: ?harness.Info = null,
    restarted: ?harness.Info = null,
    has_info: bool = false,
    tracked: bool = false,

    fn deinit(self: *State) void {
        if (self.info) |*info| info.deinit(gpa);
        if (self.restarted) |*info| info.deinit(gpa);
        self.store.deinit();
    }
};

fn activation_failure_body(ctx: Ctx, state: *State) anyerror!void {
    var run: Run(Failing) = undefined;
    try run.boot(ctx, &state.store);
    var outcome = try run.completion(1000) orelse return error.ExpectedCompletion;
    defer outcome.deinit();
    try testing.expect(outcome.info == null);
    // The actor cannot derive the final block's payload, so the chain advances to the
    // height before the final block and stops there.
    try ctx.io().sleep(.fromSeconds(30), .awake);
    try testing.expectEqual(@as(u64, harness.epoch_length - 2), try processed_height(ctx));
    try run.close();
}

fn runner() !runtime.deterministic.Runner {
    return runtime.deterministic.Runner.init(gpa, .{ .timeout_ns = 600 * std.time.ns_per_s });
}

test "dkg e2e activation failure completes empty" {
    var state: State = .{ .store = .init(gpa) };
    defer state.deinit();
    var deterministic = try runner();
    defer deterministic.deinit();
    try try deterministic.start_context(activation_failure_body, .{&state});
}

/// Completes the ceremony with manager `M`, idles for `idle_s`, and shuts down uncleanly,
/// keeping the reported info in `state.info`.
fn complete_body(comptime M: type) fn (Ctx, *State, u64) anyerror!void {
    return struct {
        fn body(ctx: Ctx, state: *State, idle_s: u64) anyerror!void {
            var run: Run(M) = undefined;
            try run.boot(ctx, &state.store);
            var outcome = try run.completion(120_000) orelse return error.ExpectedCompletion;
            state.has_info = outcome.info != null;
            state.info = outcome.info;
            outcome.info = null;
            outcome.deinit();
            try ctx.io().sleep(.fromSeconds(@intCast(idle_s)), .awake);
            run.close() catch {};
        }
    }.body;
}

/// Restarts with manager `M`: records the report in `state.restarted` and whether peer set
/// zero is tracked, and fails if the engine stops within a second of reporting.
fn restart_body(comptime M: type) fn (Ctx, *State) anyerror!void {
    return struct {
        fn body(ctx: Ctx, state: *State) anyerror!void {
            var run: Run(M) = undefined;
            try run.boot(ctx, &state.store);
            var outcome = try run.completion(30_000) orelse {
                run.close() catch {};
                return error.ExpectedCompletion;
            };
            if (state.restarted) |*old| old.deinit(gpa);
            state.restarted = outcome.info;
            outcome.info = null;
            outcome.deinit();
            try ctx.io().sleep(.fromSeconds(1), .awake);
            state.tracked = try run.tracked();
            try run.close();
        }
    }.body;
}

// A participant without a share restarted after processing the final block reports the
// finalized artifact and re-activates the peer set.
test "dkg e2e restart without share" {
    var state: State = .{ .store = .init(gpa) };
    defer state.deinit();
    var deterministic = try runner();
    defer deterministic.deinit();
    try try deterministic.start_context(complete_body(KeyOnly), .{ &state, 5 });
    try testing.expect(state.has_info);
    // Model a participant that completed without a share.
    state.store.deinit();
    state.store = .init(gpa);
    try try deterministic.start_context(restart_body(KeyOnly), .{&state});
    const restarted = state.restarted orelse return error.ExpectedInfo;
    try testing.expect(restarted.eql(state.info.?));
    try testing.expect(state.tracked);
}

// A restart after a failed ceremony reports the failure.
test "dkg e2e restart after failure" {
    var state: State = .{ .store = .init(gpa) };
    defer state.deinit();
    var deterministic = try runner();
    defer deterministic.deinit();
    // Activation fails, so the ceremony reports no artifact, and the chain stops below the
    // final block while the actor idles.
    try try deterministic.start_context(complete_body(Failing), .{ &state, 60 });
    try testing.expect(!state.has_info);
    // The first restart joins after the dealing window, so the ceremony fails and the chain
    // finalizes a final block without an artifact. The second reports that outcome.
    for (0..2) |_| {
        try try deterministic.start_context(restart_body(KeyOnly), .{&state});
        try testing.expect(state.restarted == null);
        try testing.expect(state.tracked);
    }
}

fn share_without_final_block_body(ctx: Ctx, state: *State) anyerror!void {
    var run: Run(KeyOnly) = undefined;
    try run.boot(ctx, &state.store);
    // The engine stops on its own: wait for it before closing.
    const ended = run.started.handle.join();
    run.started.handle = undefined;
    run.started.completion.deinit();
    run.participants.deinit(gpa);
    run.net.close();
    run.network_task.await(run.io) catch {};
    run.net.deinit();
    const result = ended catch |err| return err;
    try testing.expectError(error.MissingFinalDkgBlock, result);
}

// A persisted share without the stored final block means bootstrap storage does not match
// the secret store (commonware's `should_panic`).
test "dkg e2e share without final block fails" {
    var state: State = .{ .store = .init(gpa) };
    defer state.deinit();
    var rng = utils.rng.TestRng.init(0);
    const Group = cryptography.bls12381.primitives.group;
    const share = Group.Share.init(.from_usize(0), Group.Private.random(&rng));
    try state.store.put_share(Epoch.zero(), share);
    var deterministic = try runner();
    defer deterministic.deinit();
    try try deterministic.start_context(share_without_final_block_body, .{&state});
}
