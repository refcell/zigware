//! Tests of the bootstrap `Engine`: commonware's `rejects_unsupported_sharing_mode`, and a
//! singleton ceremony run end to end on the simulated network (the dkg harness in
//! `tests/dkg/` covers multi-participant plans).

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const network = @import("../network.zig");
const mocks = @import("../tests/mocks.zig");
const engine_api = @import("engine.zig");

const gpa = testing.allocator;
const Ctx = runtime.deterministic.Context;
const Key = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Set = utils.ordered.Set(Key);
const Unit = utils.sequence.Unit;

const Types = struct {
    pub const Variant = cryptography.bls12381.primitives.MinPk;
    pub const Directory = Unit;
    pub const Manager = network.KeyOnlyManager(Net.Manager);
    pub const PeerProvider = Net.Manager;
    pub const Blocker = Net.Control;
    pub const SecretStore = mocks.MemorySecretStore;
    pub const Context = runtime.deterministic.Context;
    pub const Network = Net;
};
const Engine = engine_api.Engine(Types);
const namespace = "_COMMONWARE_GLUE_DKG_INITIAL_E2E";
const quota = p2p.Quota.per_second(1024);

fn config(
    net: *Net,
    signer: cryptography.ed25519.PrivateKey,
    manager: *Types.Manager,
    store: *mocks.MemorySecretStore,
    participants: Set,
) engine_api.Config(Types) {
    return .{
        .signer = signer,
        .manager = manager,
        .peer_provider = net.oracle().manager(),
        .blocker = net.oracle().control(signer.public_key()),
        .secret_store = store,
        .namespace = namespace,
        .sharing_mode = .non_zero_counter,
        .reveal = .v1,
        .max_supported_mode = mocks.max_supported_mode,
        .partition_prefix = "dkg-single",
        .write_buffer = 2048,
        .replay_buffer = 2048,
        .mailbox_size = 100,
        .fetch_timeout = .from_secs(2),
        .fetch_retry_delay = .from_millis(100),
        .items_per_section = 10,
        .participants = participants,
        .directory = .{},
        .blocks_per_epoch = 32,
    };
}

test "bootstrap engine compiles on the production runtime context" {
    // The dkg example's `bootstrap` binary runs the engine on `production.Runner`. Analyzing
    // `start` (and every task it spawns) keeps that instantiation compiling without running it.
    const Production = struct {
        pub const Variant = Types.Variant;
        pub const Directory = Types.Directory;
        pub const Manager = Types.Manager;
        pub const PeerProvider = Types.PeerProvider;
        pub const Blocker = Types.Blocker;
        pub const SecretStore = Types.SecretStore;
        pub const Context = runtime.production.runner.Context;
        pub const Network = Types.Network;
    };
    const ProductionEngine = engine_api.Engine(Production);
    comptime std.debug.assert(@TypeOf(&ProductionEngine.start) != @TypeOf(&Engine.start));
    _ = &ProductionEngine.start;
}

// commonware `rejects_unsupported_sharing_mode`.
test "bootstrap engine rejects an unsupported sharing mode" {
    var settings: engine_api.Config(Types) = undefined;
    settings.sharing_mode = .roots_of_unity;
    settings.max_supported_mode = .v0;
    try testing.expectError(error.UnsupportedSharingMode, Engine.check(&settings));
    settings.max_supported_mode = .v1;
    try Engine.check(&settings);
}

fn register(net: *Net, key: Key) !Engine.Channels {
    var channels: [6]Engine.Channel = undefined;
    for (&channels, 0..) |*channel, index| {
        const registered = try net.oracle().control(key).register(index, quota);
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

fn singleton_body(ctx: Ctx) anyerror!void {
    const io = ctx.io();
    const signer = cryptography.ed25519.PrivateKey.from_seed(0);
    const key = signer.public_key();
    const net = try Net.init(gpa, io, .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = 1,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    });
    defer net.deinit();
    var network_task = try io.concurrent(Net.run, .{net});
    defer {
        net.close();
        network_task.await(io) catch {};
    }
    var participants = try Set.from_dedup(gpa, &.{key});
    defer participants.deinit(gpa);
    var store = mocks.MemorySecretStore.init(gpa);
    defer store.deinit();
    var manager = Types.Manager.init(net.oracle().manager());
    const channels = try register(net, key);
    const settings = config(net, signer, &manager, &store, participants);
    var started = try Engine.start(ctx.child("dkg"), settings, channels);
    defer started.completion.deinit();
    var completion = try started.completion.recv();
    defer completion.deinit();
    const ended = started.handle.abort();
    if (ended) |result| try result else |_| {}
    const info = completion.info orelse return error.ExpectedDkgOutput;
    try testing.expectEqual(@as(u64, 0), info.epoch.get());
    try testing.expectEqual(.success, info.outcome);
    try testing.expect(info.players.eql(participants));
    try testing.expect(store.has_share(consensus.Epoch.zero()));
}

test "bootstrap engine completes a singleton ceremony" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .timeout_ns = 120 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(singleton_body, .{});
}
