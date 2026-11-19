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
