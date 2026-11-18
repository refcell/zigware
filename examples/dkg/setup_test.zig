//! Tests for `setup.zig`, ported from commonware's `examples/dkg/src/setup.rs`.

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const config = @import("config.zig");
const setup = @import("setup.zig");

const ed25519 = zigware.cryptography.ed25519;
const gpa = testing.allocator;
const io = testing.io;

fn keys(comptime n: usize) [n]ed25519.PublicKey {
    var rng = zigware.utils.rng.TestRng.init(0);
    var out: [n]ed25519.PublicKey = undefined;
    for (&out) |*key| key.* = ed25519.PrivateKey.random(&rng).public_key();
    return out;
}

test "dkg: setup writes only node and network configs" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const options: setup.Options = .{
        .node_dir = "nodes",
        .peers = 3,
        .committee_size = 2,
        .base_port = 4100,
    };
    var rng = zigware.utils.rng.TestRng.init(7);
    const generated = try setup.generate(arena.allocator(), &rng, &options);
    try setup.write(io, arena.allocator(), tmp.dir, &options, &generated);

    var first = try tmp.dir.openDir(io, "nodes/validator-0", .{ .iterate = true });
    defer first.close(io);
    const node = try config.NodeConfig.load(io, gpa, first);
    var network = try config.NetworkConfig.load(io, gpa, first);
    defer network.deinit(gpa);
    try testing.expectEqual(3, network.participants.len);
    try testing.expectEqual(2, network.committee_size);
    try testing.expectEqual(4100, node.listen.port);
    try testing.expect(node.public_key().eql(network.participants[0]));

    // Genesis and secret material come only from `bootstrap`.
    var names: [2][]const u8 = undefined;
    var count: usize = 0;
    var entries = first.iterate();
    while (try entries.next(io)) |entry| : (count += 1) {
        try testing.expect(count < names.len);
        names[count] = try arena.allocator().dupe(u8, entry.name);
    }
    try testing.expectEqual(2, count);
    std.mem.sort([]const u8, &names, {}, less_than);
    try testing.expectEqualStrings("network.json", names[0]);
    try testing.expectEqualStrings("node.json", names[1]);

    // The last validator listens on the last port with its own key, and shares the config.
    var last = try tmp.dir.openDir(io, "nodes/validator-2", .{});
    defer last.close(io);
    const last_node = try config.NodeConfig.load(io, gpa, last);
    try testing.expectEqual(4102, last_node.dial.port);
    try testing.expect(last_node.public_key().eql(network.participants[2]));
    try testing.expectEqual(4102, network.peers[2].dial.port);
}

fn less_than(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

test "dkg: setup rejects bad committee size" {
    const options: setup.Options = .{ .node_dir = "unused", .peers = 2, .committee_size = 3 };
    try testing.expectError(error.CommitteeExceedsPeers, setup.validate(&options));
}

test "dkg: setup rejects committee without enough dealer log slots" {
    try testing.expectEqual(31, setup.dealer_log_slots());
    // A 46-member committee needs a quorum of 31, the last that fits.
    try setup.validate(&.{ .node_dir = "unused", .peers = 47, .committee_size = 46 });
    try testing.expectError(
        error.NotEnoughDealerLogSlots,
        setup.validate(&.{ .node_dir = "unused", .peers = 47, .committee_size = 47 }),
    );
}

test "dkg: setup rejects zero and oversized counts and port overflow" {
    try testing.expectError(error.ZeroPeers, setup.validate(&.{ .peers = 0 }));
    try testing.expectError(error.TooManyPeers, setup.validate(&.{ .peers = 65 }));
    try testing.expectError(error.ZeroCommitteeSize, setup.validate(&.{ .committee_size = 0 }));
    try setup.validate(&.{ .peers = 2, .committee_size = 1, .base_port = 65534 });
    try testing.expectError(
        error.PortOverflow,
        setup.validate(&.{ .peers = 2, .committee_size = 1, .base_port = 65535 }),
    );
}

test "dkg: bootstrap commands only include epoch zero players" {
    const participants = keys(4);
    const network: config.NetworkConfig = .{
        .participants = &participants,
        .committee_size = 2,
        .peers = &.{},
    };
    const indexes = try setup.bootstrap_indexes(gpa, &network);
    defer gpa.free(indexes);
    try testing.expectEqualSlices(u64, &.{ 0, 1 }, indexes);
}

test "dkg: printed commands run the epoch zero players, then every validator" {
    const participants = keys(3);
    const network: config.NetworkConfig = .{
        .participants = &participants,
        .committee_size = 2,
        .peers = &.{},
    };
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try setup.print_commands(gpa, &out.writer, &.{ .node_dir = "./data/" }, &network);
    const run = "\"zig build run-dkg -- ";
    try testing.expectEqualStrings(
        "Run bootstrap with:\nmprocs " ++
            run ++ "bootstrap --node-dir ./data/validator-0\" " ++
            run ++ "bootstrap --node-dir ./data/validator-1\"\n" ++
            "Once every bootstrap logs \"bootstrap complete\", stop them all and run the " ++
            "cluster with:\nmprocs " ++
            run ++ "validator --node-dir ./data/validator-0\" " ++
            run ++ "validator --node-dir ./data/validator-1\" " ++
            run ++ "validator --node-dir ./data/validator-2\"\n",
        out.written(),
    );
}

test "dkg: setup rejects non-empty directory" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "nodes");
    try tmp.dir.writeFile(io, .{ .sub_path = "nodes/sentinel", .data = "keep" });
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const options: setup.Options = .{ .node_dir = "nodes", .peers = 1, .committee_size = 1 };
    var rng = zigware.utils.rng.TestRng.init(1);
    const generated = try setup.generate(arena.allocator(), &rng, &options);
    try testing.expectError(
        error.NonEmptyDirectory,
        setup.write(io, arena.allocator(), tmp.dir, &options, &generated),
    );
    try tmp.dir.access(io, "nodes/sentinel", .{});
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "nodes/validator-0", .{}));
}

test "dkg: parse options takes clap's forms and defaults" {
    const defaults = setup.parse_options(&.{}).?;
    try testing.expectEqualStrings("./data", defaults.node_dir);
    try testing.expectEqual(6, defaults.peers);
    try testing.expectEqual(4, defaults.committee_size);
    try testing.expectEqual(3000, defaults.base_port);

    const parsed = setup.parse_options(&.{
        "--node-dir", "out", "--peers=5", "--committee-size", "3", "--base-port=4000",
        "--host",     "::1",
    }).?;
    try testing.expectEqualStrings("out", parsed.node_dir);
    try testing.expectEqual(5, parsed.peers);
    try testing.expectEqual(3, parsed.committee_size);
    try testing.expectEqual(4000, parsed.base_port);
    try testing.expect(parsed.host == .v6);

    const refused = [_][]const []const u8{
        &.{"--peers"},
        &.{ "--peers", "x" },
        &.{ "--peers", "1", "--peers", "2" },
        &.{ "--base-port", "70000" },
        &.{ "--host", "localhost" },
        &.{"positional"},
        &.{ "--unknown", "1" },
    };
    for (refused) |args| try testing.expect(setup.parse_options(args) == null);
}
