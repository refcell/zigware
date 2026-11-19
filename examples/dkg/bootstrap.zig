//! `bootstrap` subcommand: one-shot glue DKG for the epoch-0 committee (commonware
//! `examples/dkg/src/bootstrap.rs`).
//!
//! After the ceremony, the bootstrap hands its epoch-0 share to the validator's store and
//! writes the resulting genesis into every validator directory that may use it. The ceremony
//! runs glue's bootstrap engine on the discovery network; `complete` finishes it, and the node
//! then keeps serving peers that have not completed until stopped.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const config = @import("config.zig");
const types = @import("types.zig");
const net_mod = @import("network.zig");

const glue_dkg = zigware.glue.dkg;
const production = zigware.runtime.production;
const Net = net_mod.Net;
/// commonware's tracing target for this module.
const target = "commonware_dkg::bootstrap";

/// The runtime storage partition of the bootstrap's `Secrets` store.
pub const partition: types.Partition = .bootstrap;

/// Where `complete` writes the genesis: `node_dir` (relative to `base`) and its siblings in
/// `network`, from `local`'s view, with next players from `participants`.
pub const Handoff = struct {
    base: Io.Dir,
    node_dir: []const u8,
    local: types.PublicKey,
    network: *const config.NetworkConfig,
    participants: *const types.Participants,
};

/// Awaits the ceremony on `completion` (the bootstrap engine's receiver), hands only epoch
/// zero's share from `store` to the validator's store on `backend`, and writes the genesis
/// into the sibling validators. The bootstrap store also holds the ceremony's seed and
/// dealings, which the validator's first reshare must not reuse. Returns how many directories
/// it wrote.
pub fn complete(
    io: Io,
    gpa: Allocator,
    completion: anytype,
    store: *types.Secrets,
    backend: zigware.runtime.storage.Storage,
    handoff: Handoff,
) !usize {
    var outcome = completion.recv() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.BootstrapCompletionDropped,
    };
    defer outcome.deinit();
    const info = outcome.info orelse return error.BootstrapDkgFailed;
    assert(info.epoch.is_zero());
    if (try store.get_share(.zero())) |share| {
        var validator_store: types.Secrets = try .init(io, gpa, backend, .validator);
        defer validator_store.deinit();
        try validator_store.put_share(.zero(), share);
    }
    var genesis = try info.clone(gpa);
    defer genesis.deinit(gpa);
    genesis.outcome = .success;
    const next_players = try handoff.participants.get(gpa, genesis.epoch.next());
    genesis.next_players.deinit(gpa);
    genesis.next_players = next_players;
    const written = try write_genesis_to_sibling_validators(
        io,
        gpa,
        handoff.base,
        handoff.node_dir,
        handoff.local,
        handoff.network,
        genesis,
    );
    assert(written > 0);
    return written;
}

/// Writes `genesis` into every sibling validator directory of `node_dir` (relative to `base`)
/// that belongs to `network`, except those of players other than `local`, or into `node_dir`
/// alone when none are found. Returns how many directories it wrote.
pub fn write_genesis_to_sibling_validators(
    io: Io,
    gpa: Allocator,
    base: Io.Dir,
    node_dir: []const u8,
    local: types.PublicKey,
    network: *const config.NetworkConfig,
    genesis: types.EpochInfo,
) !usize {
    assert(node_dir.len > 0);
    const root_path = std.fs.path.dirname(node_dir) orelse
        return write_own(io, gpa, base, node_dir, genesis);
    var root = try base.openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);
    var written: usize = 0;
    var entries = root.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        var candidate = root.openDir(io, entry.name, .{}) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => continue,
        };
        defer candidate.close(io);
        const node = config.NodeConfig.load(io, gpa, candidate) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => return err,
            else => continue,
        };
        const public_key = node.public_key();
        if (!contains(network.participants, public_key)) continue;
        const is_local = public_key.eql(local);
        if (!is_local and genesis.players.position(public_key) != null) continue;
        try types.write_genesis(io, gpa, candidate, genesis);
        written += 1;
    }
    if (written == 0) return write_own(io, gpa, base, node_dir, genesis);
    assert(written <= network.participants.len);
    return written;
}

fn write_own(
    io: Io,
    gpa: Allocator,
    base: Io.Dir,
    node_dir: []const u8,
    genesis: types.EpochInfo,
) !usize {
    var dir = try base.openDir(io, node_dir, .{});
    defer dir.close(io);
    try types.write_genesis(io, gpa, dir, genesis);
    return 1;
}

fn contains(keys: []const types.PublicKey, key: types.PublicKey) bool {
    for (keys) |each| {
        if (each.eql(key)) return true;
    }
    return false;
}

/// The bootstrap engine's types on the production runtime and the discovery network.
pub const EngineTypes = struct {
    pub const Context = production.runner.Context;
    pub const Variant = types.MinSig;
    pub const Directory = types.Unit;
    pub const Manager = glue_dkg.network.KeyOnlyManager(Net.Oracle);
    pub const PeerProvider = Net.Oracle;
    pub const Blocker = Net.Oracle;
    pub const SecretStore = types.Secrets;
    pub const Network = Net;
};
const Engine = glue_dkg.bootstrap.Engine(EngineTypes);

/// commonware's bootstrap `Config` for `signer` over `committee` (borrowed by the engine).
pub fn engine_config(
    signer: types.ed25519.PrivateKey,
    oracle: Net.Oracle,
    manager: *EngineTypes.Manager,
    store: *types.Secrets,
    committee: types.Set(types.PublicKey),
) glue_dkg.bootstrap.Config(EngineTypes) {
    assert(committee.len() > 0);
    return .{
        .signer = signer,
        .manager = manager,
        .peer_provider = oracle,
        .blocker = oracle,
        .secret_store = store,
        .namespace = types.namespace,
        .sharing_mode = types.sharing_mode,
        .reveal = types.reveal,
        .max_supported_mode = types.max_supported_mode,
        .partition_prefix = "bootstrap",
        .page_size = types.page_size,
        .page_cache_size = types.page_cache_size,
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

fn channels(net: *Net) !Engine.Channels {
    const ids = [_]u64{
        types.vote_channel,     types.certificate_channel, types.resolver_channel,
        types.backfill_channel, types.broadcast_channel,   types.dkg_channel,
    };
    var out: [ids.len]Engine.Channel = undefined;
    for (&out, ids) |*channel, id| {
        const registered = try net_mod.register(net, id);
        channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
    }
    return .{
        .votes = out[0],
        .certificates = out[1],
        .resolver = out[2],
        .backfill = out[3],
        .broadcast = out[4],
        .dkg = out[5],
    };
}

fn run_network(net: *Net) Io.Cancelable!void {
    net.run() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => std.debug.panic("network failed: {t}", .{err}),
    };
}

/// Runs the one-shot DKG for the epoch-0 committee from `node_dir`'s config, writes the
/// genesis, and keeps serving until stopped (commonware `bootstrap::run`).
pub fn run(ctx: production.runner.Context, arena: Allocator, node_dir: []const u8) !void {
    const gpa = ctx.gpa();
    const io = ctx.io();
    var dir = try Io.Dir.cwd().openDir(io, node_dir, .{});
    defer dir.close(io);
    const node = try config.NodeConfig.load(io, arena, dir);
    const network = try config.NetworkConfig.load(io, arena, dir);
    try network.validate();
    var participants: types.Participants = try .init(gpa, &network);
    defer participants.deinit(gpa);
    var committee = try participants.get(gpa, .zero());
    defer committee.deinit(gpa);
    const committee_size: u32 = @intCast(committee.len());
    const payload = glue_dkg.bootstrap.max_payload_size(
        types.MinSig,
        types.Unit,
        committee_size,
        types.max_supported_mode,
    );
    var net_config = try net_mod.network_config(arena, &node, &network, payload);
    net_config.tracer = ctx.tracer("commonware_p2p");
    const net = try Net.create(gpa, io, ctx.network, ctx.scope.child("network"), net_config);
    defer net.destroy();
    const engine_channels = try channels(net);
    var network_task = try io.concurrent(run_network, .{net});
    defer network_task.cancel(io) catch {};

    var store: types.Secrets = try .init(io, gpa, ctx.storage, partition);
    defer store.deinit();
    var manager = EngineTypes.Manager.init(net.oracle());
    const settings = engine_config(node.signer, net.oracle(), &manager, &store, committee);
    var started = try Engine.start(ctx.child("bootstrap"), settings, engine_channels);
    defer started.completion.deinit();
    const written = try complete(io, gpa, &started.completion, &store, ctx.storage, .{
        .base = Io.Dir.cwd(),
        .node_dir = node_dir,
        .local = node.public_key(),
        .network = &network,
        .participants = &participants,
    });
    var next_players = try participants.get(gpa, .new(1));
    defer next_players.deinit(gpa);
    ctx.tracer(target).event(.info, "bootstrap complete, serving peers until stopped", .{
        .epoch = @as(u64, 0),
        .players = committee.len(),
        .next_players = next_players.len(),
        .directories = written,
    });
    // Keep serving the one-shot chain so participants that have not completed can catch up.
    if (started.handle.join()) |result| {
        result catch |err| {
            ctx.tracer(target).event(.@"error", "bootstrap task failed", .{ .err = err });
        };
    } else |err| return err;
}
