//! `setup` subcommand: generate validator directories and network config (commonware
//! `examples/dkg/src/setup.rs`).
//!
//! Writes `validator-<i>/node.json` and `validator-<i>/network.json` for every peer, then
//! prints the `mprocs` commands that run the epoch-0 bootstrap players and the validators.
//! The commands run this port (`zig build run-dkg -- ...`) where commonware's run
//! `cargo run --bin commonware-dkg -- ...`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const config = @import("config.zig");
const types = @import("types.zig");

const ed25519 = zigware.cryptography.ed25519;
const IpAddr = zigware.deployer.IpAddr;

/// The command that runs this example, where commonware's is `cargo run --bin commonware-dkg`.
pub const run_command = "zig build run-dkg";

pub const Options = struct {
    /// Directory where validator subdirectories are generated.
    node_dir: []const u8 = "./data",
    /// Total number of validators to generate.
    peers: u64 = 6,
    /// Number of validators in each epoch committee.
    committee_size: u64 = 4,
    /// First local P2P port, assigned to validator-0.
    base_port: u16 = 3000,
    /// IP address used for generated listen and dial addresses.
    host: IpAddr = .{ .v4 = .{ 127, 0, 0, 1 } },
};

pub const Error = error{
    ZeroPeers,
    TooManyPeers,
    ZeroCommitteeSize,
    CommitteeExceedsPeers,
    NotEnoughDealerLogSlots,
    PortOverflow,
    NonEmptyDirectory,
};

/// The options from `--node-dir`, `--peers`, `--committee-size`, `--base-port`, and `--host`
/// (each `--name value` or `--name=value`, at most once), or null when they do not parse.
pub fn parse_options(args: []const []const u8) ?Options {
    const names = [_][]const u8{ "node-dir", "peers", "committee-size", "base-port", "host" };
    var values: [names.len]?[]const u8 = @splat(null);
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (!std.mem.startsWith(u8, arg, "--")) return null;
        const equals = std.mem.indexOfScalar(u8, arg, '=');
        const name = arg[2 .. equals orelse arg.len];
        const slot = for (names, 0..) |candidate, position| {
            if (std.mem.eql(u8, candidate, name)) break position;
        } else return null;
        if (values[slot] != null) return null;
        values[slot] = if (equals) |at| arg[at + 1 ..] else blk: {
            index += 1;
            if (index == args.len) return null;
            break :blk args[index];
        };
    }
    var options: Options = .{};
    if (values[0]) |text| options.node_dir = text;
    if (values[1]) |text| options.peers = std.fmt.parseInt(u64, text, 10) catch return null;
    if (values[2]) |text| {
        options.committee_size = std.fmt.parseInt(u64, text, 10) catch return null;
    }
    if (values[3]) |text| options.base_port = std.fmt.parseInt(u16, text, 10) catch return null;
    if (values[4]) |text| options.host = IpAddr.parse(text) catch return null;
    return options;
}

/// Checks the peer count, the committee size, the dealer log slots, and the port range.
pub fn validate(options: *const Options) Error!void {
    if (options.peers == 0) return error.ZeroPeers;
    if (options.peers > types.max_participants) return error.TooManyPeers;
    if (options.committee_size == 0) return error.ZeroCommitteeSize;
    if (options.committee_size > options.peers) return error.CommitteeExceedsPeers;
    if (zigware.utils.N3f1.quorum(options.committee_size) > dealer_log_slots()) {
        return error.NotEnoughDealerLogSlots;
    }
    _ = try port(options, options.peers - 1);
}

/// Blocks after an epoch's midpoint and before its final block, each of which can carry one
/// dealer log.
pub fn dealer_log_slots() u64 {
    const blocks = types.blocks_per_epoch;
    return blocks -| (blocks / 2 + 1);
}

/// The port of validator `index`.
pub fn port(options: *const Options, index: u64) Error!u16 {
    const offset = std.math.cast(u16, index) orelse return error.PortOverflow;
    return std.math.add(u16, options.base_port, offset) catch error.PortOverflow;
}

/// Every signer, and the network config they share (its slices allocated from `arena`).
pub const Generated = struct {
    signers: []const ed25519.PrivateKey,
    network: config.NetworkConfig,
};

/// Draws one signer per peer from `rng` (`fill_bytes`) and builds the network config.
pub fn generate(arena: Allocator, rng: anytype, options: *const Options) !Generated {
    try validate(options);
    const count: usize = @intCast(options.peers);
    const signers = try arena.alloc(ed25519.PrivateKey, count);
    const participants = try arena.alloc(ed25519.PublicKey, count);
    const peers = try arena.alloc(config.PeerConfig, count);
    for (signers, participants, peers, 0..) |*signer, *participant, *peer, index| {
        signer.* = .random(rng);
        participant.* = signer.public_key();
        peer.* = .{
            .public_key = participant.*,
            .dial = .{ .ip = options.host, .port = try port(options, index) },
        };
    }
    return .{ .signers = signers, .network = .{
        .participants = participants,
        .committee_size = options.committee_size,
        .peers = peers,
    } };
}

/// Writes every validator directory under `options.node_dir` (relative to `base`), refusing a
/// non-empty one.
pub fn write(
    io: Io,
    arena: Allocator,
    base: Io.Dir,
    options: *const Options,
    generated: *const Generated,
) !void {
    assert(generated.signers.len == options.peers);
    try base.createDirPath(io, options.node_dir);
    var root = try base.openDir(io, options.node_dir, .{ .iterate = true });
    defer root.close(io);
    var entries = root.iterate();
    if (try entries.next(io) != null) return error.NonEmptyDirectory;
    for (generated.signers, 0..) |signer, index| {
        const name = try std.fmt.allocPrint(arena, "validator-{d}", .{index});
        try root.createDir(io, name, .default_dir);
        var node_dir = try root.openDir(io, name, .{});
        defer node_dir.close(io);
        const address: config.SocketAddr = .{
            .ip = options.host,
            .port = try port(options, index),
        };
        const node: config.NodeConfig = .{ .signer = signer, .listen = address, .dial = address };
        try config.write_json(io, node_dir, "node.json", &node);
        try config.write_json(io, node_dir, "network.json", &generated.network);
    }
}

/// The indexes of the epoch-0 players in the participant list. Caller owns the slice.
pub fn bootstrap_indexes(gpa: Allocator, network: *const config.NetworkConfig) ![]u64 {
    var participants: types.Participants = try .init(gpa, network);
    defer participants.deinit(gpa);
    var players = try participants.get(gpa, .zero());
    defer players.deinit(gpa);
    var indexes: std.ArrayList(u64) = .empty;
    errdefer indexes.deinit(gpa);
    for (network.participants, 0..) |participant, index| {
        if (players.position(participant) != null) try indexes.append(gpa, index);
    }
    assert(indexes.items.len == players.len());
    return indexes.toOwnedSlice(gpa);
}

/// Writes one quoted `<run_command> -- <command> --node-dir <dir>/validator-<i>` per index,
/// separated by spaces.
pub fn write_commands(
    writer: *Io.Writer,
    options: *const Options,
    command: []const u8,
    indexes: []const u64,
) Io.Writer.Error!void {
    const dir = options.node_dir;
    const separator = if (std.mem.endsWith(u8, dir, "/")) "" else "/";
    for (indexes, 0..) |index, position| {
        if (position > 0) try writer.writeByte(' ');
        try writer.print("\"{s} -- {s} --node-dir {s}{s}validator-{d}\"", .{
            run_command, command, dir, separator, index,
        });
    }
}

/// Prints the commands to run the bootstrap, then the validators.
pub fn print_commands(
    gpa: Allocator,
    writer: *Io.Writer,
    options: *const Options,
    network: *const config.NetworkConfig,
) !void {
    const players = try bootstrap_indexes(gpa, network);
    defer gpa.free(players);
    const all = try gpa.alloc(u64, network.participants.len);
    defer gpa.free(all);
    for (all, 0..) |*index, position| index.* = position;
    try writer.writeAll("Run bootstrap with:\nmprocs ");
    try write_commands(writer, options, "bootstrap", players);
    try writer.writeAll("\nOnce every bootstrap logs \"bootstrap complete\", stop them all and " ++
        "run the cluster with:\nmprocs ");
    try write_commands(writer, options, "validator", all);
    try writer.writeByte('\n');
}

/// Generates the validator directories and prints the commands to run next.
pub fn run(io: Io, arena: Allocator, options: *const Options, stdout: *Io.Writer) !void {
    var key: [32]u8 = undefined;
    io.random(&key);
    var rng = zigware.utils.rng.ChaChaRng(12).init_key(key);
    const generated = try generate(arena, &rng, options);
    try write(io, arena, .cwd(), options, &generated);
    try print_commands(arena, stdout, options, &generated.network);
}
