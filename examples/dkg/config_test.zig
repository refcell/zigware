//! Tests for `config.zig`, ported from commonware's `examples/dkg/src/config.rs`, plus the
//! exact `serde_json::to_string_pretty` output commonware writes (testdata/, printed by
//! commonware's own types).

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const config = @import("config.zig");

const ed25519 = zigware.cryptography.ed25519;
const gpa = testing.allocator;

fn render(value: anytype) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try value.write(&out.writer);
    return out.toOwnedSlice();
}

fn address(text: []const u8) config.SocketAddr {
    return config.SocketAddr.parse(text) catch unreachable; // Test literals parse.
}

test "dkg: config roundtrip" {
    var rng = zigware.utils.rng.TestRng.init(0);
    const signer: ed25519.PrivateKey = .random(&rng);
    const public_key = signer.public_key();
    const node: config.NodeConfig = .localhost(signer, 3000);
    const network: config.NetworkConfig = .{
        .participants = &.{public_key},
        .committee_size = 1,
        .peers = &.{.{ .public_key = public_key, .dial = node.dial }},
    };

    const node_encoded = try render(&node);
    defer gpa.free(node_encoded);
    const node_decoded = try config.NodeConfig.parse(gpa, node_encoded);
    try testing.expect(node_decoded.public_key().eql(node.public_key()));
    try testing.expect(node_decoded.listen.eql(node.listen));

    const network_encoded = try render(&network);
    defer gpa.free(network_encoded);
    var network_decoded = try config.NetworkConfig.parse(gpa, network_encoded);
    defer network_decoded.deinit(gpa);
    try testing.expectEqual(1, network_decoded.participants.len);
    try testing.expect(network_decoded.participants[0].eql(public_key));
    try testing.expectEqual(network.committee_size, network_decoded.committee_size);
    try testing.expect(network_decoded.peers[0].dial.eql(node.dial));
}

test "dkg: node.json is byte-identical to commonware's" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*byte, index| byte.* = @intCast(index);
    const node: config.NodeConfig = .{
        .signer = .from_bytes(seed),
        .listen = address("127.0.0.1:3000"),
        .dial = address("[2001:db8::1]:3001"),
    };
    const expected = @embedFile("testdata/node.json");
    const encoded = try render(&node);
    defer gpa.free(encoded);
    try testing.expectEqualStrings(expected, encoded);

    const decoded = try config.NodeConfig.parse(gpa, expected);
    try testing.expect(decoded.signer.eql(&node.signer));
    try testing.expect(decoded.dial.eql(node.dial));
}

test "dkg: network.json is byte-identical to commonware's" {
    const a = ed25519.PrivateKey.from_seed(1).public_key();
    const b = ed25519.PrivateKey.from_seed(2).public_key();
    const network: config.NetworkConfig = .{
        .participants = &.{ a, b },
        .committee_size = 1,
        .peers = &.{
            .{ .public_key = a, .dial = address("10.0.0.1:4000") },
            .{ .public_key = b, .dial = address("[::1]:4001") },
        },
    };
    const no_peers: config.NetworkConfig = .{
        .participants = &.{a},
        .committee_size = 1,
        .peers = &.{},
    };
    const cases = .{
        .{ network, @embedFile("testdata/network.json") },
        .{ no_peers, @embedFile("testdata/network_no_peers.json") },
    };
    inline for (cases) |case| {
        const encoded = try render(&case[0]);
        defer gpa.free(encoded);
        try testing.expectEqualStrings(case[1], encoded);

        var decoded = try config.NetworkConfig.parse(gpa, case[1]);
        defer decoded.deinit(gpa);
        const again = try render(&decoded);
        defer gpa.free(again);
        try testing.expectEqualStrings(case[1], again);
    }
}

test "dkg: parsing follows serde: unknown fields ignored, missing and duplicate fields refused" {
    const key = "478b8e507e0bb2b18c0f9e0824769e8562d10df9abe2e774896f82b4b4405266";
    const extra = "{\"participants\":[\"" ++ key ++ "\"],\"committee_size\":1,\"peers\":[]," ++
        "\"other\":{\"nested\":[1,2]}}";
    var parsed = try config.NetworkConfig.parse(gpa, extra);
    parsed.deinit(gpa);

    const refused = [_][]const u8{
        "{\"participants\":[],\"peers\":[]}",
        "{\"participants\":[],\"committee_size\":1,\"committee_size\":1,\"peers\":[]}",
        "{\"participants\":[],\"committee_size\":-1,\"peers\":[]}",
        "{\"participants\":[\"zz\"],\"committee_size\":1,\"peers\":[]}",
        "{\"participants\":[\"" ++ key[0..62] ++ "\"],\"committee_size\":1,\"peers\":[]}",
        "{\"participants\":[],\"committee_size\":1,\"peers\":[{\"public_key\":\"" ++ key ++
            "\",\"dial\":\"10.0.0.1\"}]}",
        "[]",
        "",
    };
    for (refused) |text| {
        try testing.expect(std.meta.isError(config.NetworkConfig.parse(gpa, text)));
    }
}

test "dkg: socket addresses parse and display as Rust's SocketAddr" {
    const cases = [_][2][]const u8{
        .{ "127.0.0.1:3000", "127.0.0.1:3000" },
        .{ "[::1]:0", "[::1]:0" },
        .{ "[2001:0db8:0000:0000:0000:0000:0000:0001]:65535", "[2001:db8::1]:65535" },
        .{ "[::ffff:10.0.0.1]:80", "[::ffff:10.0.0.1]:80" },
        .{ "10.0.0.1:080", "10.0.0.1:80" },
    };
    for (cases) |case| {
        var buffer: [64]u8 = undefined;
        const shown = try std.fmt.bufPrint(&buffer, "{f}", .{try config.SocketAddr.parse(case[0])});
        try testing.expectEqualStrings(case[1], shown);
    }
    const refused = [_][]const u8{
        "127.0.0.1", "127.0.0.1:", "127.0.0.1:65536", "::1:80",        "[127.0.0.1]:80",
        "[::1]80",   "host:80",    ":80",             "127.0.0.1:+80",
    };
    for (refused) |text| {
        try testing.expectError(error.InvalidAddress, config.SocketAddr.parse(text));
    }
}

test "dkg: validate checks participants and committee size" {
    const a = ed25519.PrivateKey.from_seed(1).public_key();
    const b = ed25519.PrivateKey.from_seed(2).public_key();
    var network: config.NetworkConfig = .{
        .participants = &.{ a, b },
        .committee_size = 2,
        .peers = &.{},
    };
    try network.validate();
    network.committee_size = 3;
    try testing.expectError(error.CommitteeExceedsParticipants, network.validate());
    network.committee_size = 0;
    try testing.expectError(error.ZeroCommitteeSize, network.validate());
    network.participants = &.{};
    network.committee_size = 1;
    try testing.expectError(error.EmptyParticipants, network.validate());
}

test "dkg: bootstrappers are every peer but the local one, in order" {
    const keys = [_]ed25519.PublicKey{
        ed25519.PrivateKey.from_seed(3).public_key(),
        ed25519.PrivateKey.from_seed(1).public_key(),
        ed25519.PrivateKey.from_seed(2).public_key(),
    };
    var peers: [3]config.PeerConfig = undefined;
    for (&peers, keys, 0..) |*peer, key, index| {
        peer.* = .{ .public_key = key, .dial = .localhost(@intCast(4000 + index)) };
    }
    const network: config.NetworkConfig = .{
        .participants = &keys,
        .committee_size = 1,
        .peers = &peers,
    };
    const others = try network.bootstrappers(gpa, keys[1]);
    defer gpa.free(others);
    try testing.expectEqual(2, others.len);
    try testing.expect(others[0].public_key.eql(keys[0]));
    try testing.expectEqual(4000, others[0].dial.port);
    try testing.expect(others[1].public_key.eql(keys[2]));
    try testing.expectEqual(4002, others[1].dial.port);
}
