//! commonware `examples/dkg/src/bootstrap.rs` tests.

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const config = @import("config.zig");
const types = @import("types.zig");
const bootstrap = @import("bootstrap.zig");

const ed25519 = zigware.cryptography.ed25519;
const fd = zigware.cryptography.bls12381.dkg.feldman_desmedt;
const gpa = testing.allocator;
const io = testing.io;

fn epoch_info(players: []const types.PublicKey, next: []const types.PublicKey) !types.EpochInfo {
    var rng = zigware.utils.rng.TestRng.init(2);
    const set = try types.Set(types.PublicKey).from_dedup(gpa, players);
    const N3f1 = zigware.utils.N3f1;
    const mode = types.sharing_mode;
    var dealt = try fd.deal(types.MinSig, types.PublicKey, N3f1, gpa, &rng, mode, set);
    errdefer dealt.output.deinit(gpa);
    dealt.shares.deinit(gpa);
    var info_players = try dealt.output.players.clone(gpa);
    errdefer info_players.deinit(gpa);
    return .{
        .outcome = .success,
        .epoch = .zero(),
        .output = dealt.output,
        .players = info_players,
        .next_players = try types.Set(types.PublicKey).from_dedup(gpa, next),
        .directory = .{},
    };
}

test "dkg: bootstrap writes genesis to its own and non-player validators" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var keys: [4]types.PublicKey = undefined;
    var signers: [4]ed25519.PrivateKey = undefined;
    var peers: [4]config.PeerConfig = undefined;
    for (&signers, &keys, &peers, 0..) |*signer, *key, *peer, i| {
        signer.* = .from_seed(10 + i);
        key.* = signer.public_key();
        peer.* = .{ .public_key = key.*, .dial = .localhost(@intCast(4300 + i)) };
    }
    const network: config.NetworkConfig = .{
        .participants = &keys,
        .committee_size = 2,
        .peers = &peers,
    };
    try tmp.dir.createDirPath(io, "nodes");
    for (signers, 0..) |signer, i| {
        var name_buffer: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "nodes/validator-{d}", .{i});
        try tmp.dir.createDirPath(io, name);
        var dir = try tmp.dir.openDir(io, name, .{});
        defer dir.close(io);
        const node: config.NodeConfig = .localhost(signer, @intCast(4300 + i));
        try config.write_json(io, dir, "node.json", &node);
        try config.write_json(io, dir, "network.json", &network);
    }
    // A stray directory without a node config, and a node outside the network, are skipped.
    try tmp.dir.createDirPath(io, "nodes/other");
    try tmp.dir.createDirPath(io, "nodes/outsider");
    {
        var dir = try tmp.dir.openDir(io, "nodes/outsider", .{});
        defer dir.close(io);
        const node: config.NodeConfig = .localhost(.from_seed(99), 4399);
        try config.write_json(io, dir, "node.json", &node);
    }

    var genesis = try epoch_info(keys[0..2], keys[1..3]);
    defer genesis.deinit(gpa);
    const written = try bootstrap.write_genesis_to_sibling_validators(
        io,
        gpa,
        tmp.dir,
        "nodes/validator-0",
        keys[0],
        &network,
        genesis,
    );

    // Player 0 writes its own directory and every non-player's, but not player 1's.
    try testing.expectEqual(3, written);
    var player = try tmp.dir.openDir(io, "nodes/validator-1", .{});
    defer player.close(io);
    try testing.expectError(error.FileNotFound, player.access(io, types.genesis_file, .{}));
    var outsider = try tmp.dir.openDir(io, "nodes/outsider", .{});
    defer outsider.close(io);
    try testing.expectError(error.FileNotFound, outsider.access(io, types.genesis_file, .{}));
    for ([_][]const u8{ "nodes/validator-0", "nodes/validator-2", "nodes/validator-3" }) |name| {
        var dir = try tmp.dir.openDir(io, name, .{});
        defer dir.close(io);
        var read = try types.read_genesis(io, gpa, dir);
        defer read.deinit(gpa);
        try testing.expect(read.eql(genesis));
    }
}

test "dkg: bootstrap writes genesis to its own directory when no sibling matches" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const local = ed25519.PrivateKey.from_seed(1).public_key();
    const network: config.NetworkConfig = .{
        .participants = &.{local},
        .committee_size = 1,
        .peers = &.{},
    };
    try tmp.dir.createDirPath(io, "nodes/solo");
    var genesis = try epoch_info(&.{local}, &.{local});
    defer genesis.deinit(gpa);
    const written = try bootstrap.write_genesis_to_sibling_validators(
        io,
        gpa,
        tmp.dir,
        "nodes/solo",
        local,
        &network,
        genesis,
    );
    try testing.expectEqual(1, written);
    var dir = try tmp.dir.openDir(io, "nodes/solo", .{});
    defer dir.close(io);
    var read = try types.read_genesis(io, gpa, dir);
    defer read.deinit(gpa);
    try testing.expect(read.eql(genesis));
}

const glue_dkg = zigware.glue.dkg;
const p2p = zigware.p2p;
const runtime = zigware.runtime;
const Net = p2p.simulated.Network(types.PublicKey);

const EngineTypes = struct {
    pub const Variant = types.MinSig;
    pub const Directory = types.Unit;
    pub const Manager = glue_dkg.network.KeyOnlyManager(Net.Manager);
    pub const PeerProvider = Net.Manager;
    pub const Blocker = Net.Control;
    pub const SecretStore = types.Secrets;
    pub const Context = runtime.deterministic.Context;
    pub const Network = Net;
};
const Engine = glue_dkg.bootstrap.Engine(EngineTypes);

fn register_channels(net: *Net, key: types.PublicKey) !Engine.Channels {
    const quota = p2p.Quota.per_second(types.message_rate_per_second);
    const ids = [_]u64{
        types.vote_channel,     types.certificate_channel, types.resolver_channel,
        types.backfill_channel, types.broadcast_channel,   types.dkg_channel,
    };
    var channels: [ids.len]Engine.Channel = undefined;
    for (&channels, ids) |*channel, id| {
        const registered = try net.oracle().control(key).register(id, quota);
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

fn engine_config(
    net: *Net,
    signer: ed25519.PrivateKey,
    manager: *EngineTypes.Manager,
    store: *types.Secrets,
    committee: types.Set(types.PublicKey),
) glue_dkg.bootstrap.Config(EngineTypes) {
    return .{
        .signer = signer,
        .manager = manager,
        .peer_provider = net.oracle().manager(),
        .blocker = net.oracle().control(signer.public_key()),
        .secret_store = store,
        .namespace = types.namespace,
        .sharing_mode = types.sharing_mode,
        .reveal = types.reveal,
        .max_supported_mode = types.max_supported_mode,
        .partition_prefix = "bootstrap",
        .write_buffer = types.io_buffer_size,
        .replay_buffer = types.io_buffer_size,
        .mailbox_size = types.mailbox_size,
        .fetch_timeout = .from_secs(2),
        .fetch_retry_delay = .from_millis(100),
        .items_per_section = types.items_per_section,
        .participants = committee,
        .directory = .{},
        .blocks_per_epoch = types.blocks_per_epoch,
    };
}

/// A singleton committee's bootstrap: the ceremony completes, the share moves to the validator
/// store, and the genesis lands in the node's directory with the next epoch's players.
fn singleton_bootstrap(ctx: runtime.deterministic.Context, base: std.Io.Dir) anyerror!void {
    const signer = ed25519.PrivateKey.from_seed(0);
    const key = signer.public_key();
    const network: config.NetworkConfig = .{
        .participants = &.{key},
        .committee_size = 1,
        .peers = &.{},
    };
    {
        var dir = try base.openDir(io, "nodes/validator-0", .{});
        defer dir.close(io);
        const node: config.NodeConfig = .localhost(signer, 4300);
        try config.write_json(io, dir, "node.json", &node);
    }
    var participants: types.Participants = try .init(gpa, &network);
    defer participants.deinit(gpa);

    const net = try Net.init(gpa, ctx.io(), .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = 1,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    });
    defer net.deinit();
    var network_task = try ctx.io().concurrent(Net.run, .{net});
    defer {
        net.close();
        network_task.await(ctx.io()) catch {};
    }
    var store: types.Secrets = try .init(ctx.io(), gpa, ctx.storage, bootstrap.partition);
    defer store.deinit();
    var manager = EngineTypes.Manager.init(net.oracle().manager());
    var committee = try participants.get(gpa, .zero());
    defer committee.deinit(gpa);
    const settings = engine_config(net, signer, &manager, &store, committee);
    const channels = try register_channels(net, key);
    var started = try Engine.start(ctx.child("bootstrap"), settings, channels);
    defer started.completion.deinit();
    const written = try bootstrap.complete(io, gpa, &started.completion, &store, ctx.storage, .{
        .base = base,
        .node_dir = "nodes/validator-0",
        .local = key,
        .network = &network,
        .participants = &participants,
    });
    const ended = started.handle.abort();
    if (ended) |result| try result else |_| {}
    try testing.expectEqual(1, written);

    try expect_handoff(ctx, base, &participants, committee, &store);
}

/// The genesis in validator-0's directory, and the share alone in the validator store.
fn expect_handoff(
    ctx: runtime.deterministic.Context,
    base: std.Io.Dir,
    participants: *const types.Participants,
    committee: types.Set(types.PublicKey),
    store: *types.Secrets,
) !void {
    var dir = try base.openDir(io, "nodes/validator-0", .{});
    defer dir.close(io);
    var genesis = try types.read_genesis(io, gpa, dir);
    defer genesis.deinit(gpa);
    try testing.expectEqual(0, genesis.epoch.get());
    try testing.expectEqual(.success, genesis.outcome);
    try testing.expect(genesis.players.eql(committee));
    var next = try participants.get(gpa, .new(1));
    defer next.deinit(gpa);
    try testing.expect(genesis.next_players.eql(next));
    // Only the share moved to the validator store.
    var handed: types.Secrets = try .init(ctx.io(), gpa, ctx.storage, .validator);
    defer handed.deinit();
    const share = (try handed.get_share(.zero())) orelse return error.TestMissingShare;
    try testing.expect(share.eql((try store.get_share(.zero())).?));
    try testing.expectEqual(null, try handed.get_seed(.zero()));
}

test "dkg: bootstrap completes a singleton ceremony and hands off genesis" {
    const runner_config: runtime.deterministic.Config = .{ .timeout_ns = 120 * std.time.ns_per_s };
    try runtime.deterministic.soak(gpa, runner_config, {}, struct {
        // Each seed bootstraps into a fresh directory.
        fn round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            var tmp = testing.tmpDir(.{});
            defer tmp.cleanup();
            try tmp.dir.createDirPath(io, "nodes/validator-0");
            try try runner.start_context(singleton_bootstrap, .{tmp.dir});
        }
    }.round);
}

/// A completion receiver whose ceremony never ends: `recv` waits until canceled.
const NeverCompletes = struct {
    pub const Outcome = struct {
        info: ?types.EpochInfo = null,

        pub fn deinit(_: *Outcome) void {}
    };

    pub fn recv(_: *NeverCompletes) error{ Canceled, Closed }!Outcome {
        try io.sleep(.fromSeconds(3600), .awake);
        unreachable; // The test cancels the wait.
    }
};

fn complete_never() anyerror!usize {
    var completion: NeverCompletes = .{};
    // `complete` fails in `recv` before it reads the store, the storage, or the handoff.
    var store: types.Secrets = undefined;
    return bootstrap.complete(io, gpa, &completion, &store, undefined, undefined);
}

test "dkg: bootstrap's wait for its ceremony passes a cancel on" {
    var waiting = try io.concurrent(complete_never, .{});
    try testing.expectError(error.Canceled, waiting.cancel(io));
}
