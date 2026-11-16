//! flood's `setup`: a seeded run's files against serde_yaml's layout of commonware's types
//! (written out here, field by field, as `setup.rs` serializes them), plus its refusals.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const zigware = @import("zigware");
const lib = @import("lib.zig");
const setup = @import("setup.zig");

const aws = zigware.deployer.aws;
const ed25519 = zigware.cryptography.ed25519;
const TestRng = zigware.utils.rng.TestRng;

const tag = "ffa638a0-991c-442c-8ec4-aa4e418213a5";

fn options(output: []const u8, dashboard: []const u8) setup.Options {
    return .{
        .peers = 3,
        .bootstrappers = 1,
        .regions = &.{ "us-west-2", "eu-west-1" },
        .instance_type = "c7g.xlarge",
        .storage_size = 10,
        .storage_class = "gp3",
        .worker_threads = 4,
        .message_size = 1024,
        .message_rate = 16384,
        .mailbox_size = 16384,
        .dashboard = dashboard,
        .instrument = false,
        .output = output,
    };
}

/// serde_yaml's `config.yaml` for `setup.rs`'s `aws::Config` (unset options are skipped).
fn expected_config(arena: std.mem.Allocator, names: []const []const u8) ![]const u8 {
    var out: Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeAll("tag: " ++ tag ++ "\nmonitoring:\n  instance_type: c7g.xlarge\n" ++
        "  storage_size: 10\n  storage_class: gp3\n  dashboard: dashboard.json\ninstances:\n");
    const regions = [_][]const u8{ "us-west-2", "eu-west-1", "us-west-2" };
    for (names, regions) |name, region| {
        try w.print("- name: {s}\n  region: {s}\n  instance_type: c7g.xlarge\n" ++
            "  storage_size: 10\n  storage_class: gp3\n  binary: flood\n" ++
            "  config: {s}.yaml\n  profiling: false\n", .{ name, region, name });
    }
    try w.writeAll("ports:\n- protocol: tcp\n  port: 4545\n  cidr: 0.0.0.0/0\n");
    return out.written();
}

/// serde_yaml's `{public key}.yaml` for `commonware_flood::Config`.
fn expected_peer(
    arena: std.mem.Allocator,
    private_key: []const u8,
    names: []const []const u8,
    bootstrapper: []const u8,
) ![]const u8 {
    var out: Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.print("private_key: {s}\nport: 4545\nallowed_peers:\n", .{private_key});
    for (names) |name| try w.print("- {s}\n", .{name});
    try w.print("bootstrappers:\n- {s}\nworker_threads: 4\nmessage_size: 1024\n" ++
        "message_rate: 16384\nmailbox_size: 16384\ninstrument: false\n", .{bootstrapper});
    return out.written();
}

fn read(arena: std.mem.Allocator, dir: Io.Dir, path: []const u8) ![]const u8 {
    return dir.readFileAlloc(testing.io, path, arena, .limited(1 << 16));
}

test "setup: writes commonware's config and peer files" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "dash.json", .data = "{\"flood\":1}" });
    const output = try std.fmt.allocPrint(arena, "{s}/assets", .{home});
    const dashboard = try std.fmt.allocPrint(arena, "{s}/dash.json", .{home});
    const chosen = options(output, dashboard);
    var rng = TestRng.init(7);
    const generated = try setup.generate(arena, &rng, tag, &chosen);
    try setup.write_files(testing.io, arena, &generated, dashboard, output);

    // Each peer is named by the public key of its private key.
    var names: [3][]const u8 = undefined;
    for (generated.peers, &names) |peer, *name| {
        var seed: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&seed, peer.config.private_key);
        const key = ed25519.PrivateKey.from_bytes(seed);
        name.* = try std.fmt.allocPrint(arena, "{f}", .{key.public_key()});
        try testing.expectEqual(@as(usize, 64), name.len);
    }
    const bootstrapper = generated.peers[0].config.bootstrappers[0];
    try testing.expect(for (names) |name| {
        if (std.mem.eql(u8, name, bootstrapper)) break true;
    } else false);

    try testing.expectEqualStrings(
        try expected_config(arena, &names),
        try read(arena, tmp.dir, "assets/config.yaml"),
    );
    for (generated.peers, names) |peer, name| {
        const path = try std.fmt.allocPrint(arena, "assets/{s}.yaml", .{name});
        const text = try read(arena, tmp.dir, path);
        const want = try expected_peer(arena, peer.config.private_key, &names, bootstrapper);
        try testing.expectEqualStrings(want, text);
        // flood reads its file back.
        const parsed = try lib.Config.parse(arena, text);
        try testing.expectEqualStrings(peer.config.private_key, parsed.private_key);
    }
    const copied = try read(arena, tmp.dir, "assets/dashboard.json");
    try testing.expectEqualStrings("{\"flood\":1}", copied);
    // The deployer accepts the configuration.
    const config = try aws.Config.parse(arena, try read(arena, tmp.dir, "assets/config.yaml"));
    try testing.expect(aws.create.validate_names(&config) == null);
    try testing.expect(aws.create.validate_storage_config(&config) == null);
    // The output directory is never reused.
    try testing.expectError(
        error.OutputDirectoryAlreadyExists,
        setup.write_files(testing.io, arena, &generated, dashboard, output),
    );
}

test "setup: refuses more bootstrappers or regions than peers" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var rng = TestRng.init(1);
    var chosen = options("out", "dash.json");
    chosen.bootstrappers = 4;
    try testing.expectError(
        error.BootstrappersMustBeLessThanPeers,
        setup.generate(arena, &rng, tag, &chosen),
    );
    chosen.bootstrappers = 3;
    chosen.regions = &.{ "a", "b", "c", "d" };
    try testing.expectError(
        error.MustBeAtLeastOnePeerPerRegion,
        setup.generate(arena, &rng, tag, &chosen),
    );
    // Every peer may bootstrap; the sample then keeps their order.
    chosen.regions = &.{"a"};
    const generated = try setup.generate(arena, &rng, tag, &chosen);
    const bootstrappers = generated.peers[0].config.bootstrappers;
    try testing.expectEqual(@as(usize, 3), bootstrappers.len);
    for (bootstrappers, generated.config.instances) |bootstrapper, instance| {
        try testing.expectEqualStrings(instance.name, bootstrapper);
    }
}

test "setup: reservoir sampling keeps uniform draws distinct" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const items = [_][]const u8{ "a", "b", "c", "d", "e", "f" };
    var counts: [items.len]u32 = @splat(0);
    var rng = TestRng.init(3);
    for (0..600) |_| {
        const chosen = try setup.sample(arena, &rng, &items, 2);
        try testing.expect(!std.mem.eql(u8, chosen[0], chosen[1]));
        for (chosen) |item| counts[item[0] - 'a'] += 1;
    }
    // Each item is chosen with probability 1/3: about 200 times in 600 draws.
    for (counts) |count| try testing.expect(count > 140 and count < 260);
}

test "setup: parses clap's option forms" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // zig fmt: off
    const args = [_][]const u8{
        "--peers", "3", "--bootstrappers=1", "--regions", "us-west-2,eu-west-1",
        "--instance-type", "c7g.xlarge", "--storage-size", "10", "--storage-class", "gp3",
        "--storage-iops=3000", "--worker-threads", "4", "--message-size", "1024",
        "--message-rate", "16384", "--mailbox-size", "16384", "--dashboard", "dashboard.json",
        "--instrument", "true", "--output", "assets",
    };
    // zig fmt: on
    const parsed = (try setup.parse_options(arena, &args)).?;
    try testing.expectEqual(@as(u64, 3), parsed.peers);
    try testing.expectEqual(@as(usize, 2), parsed.regions.len);
    try testing.expectEqualStrings("eu-west-1", parsed.regions[1]);
    try testing.expectEqual(@as(?i32, 3000), parsed.storage_iops);
    try testing.expectEqual(@as(?i32, null), parsed.storage_throughput);
    try testing.expect(parsed.instrument);
    // A missing option, a repeated one, a zero rate, and a bad bool are refused.
    try testing.expect(try setup.parse_options(arena, args[0 .. args.len - 2]) == null);
    const repeated = args ++ [_][]const u8{"--peers=4"};
    try testing.expect(try setup.parse_options(arena, &repeated) == null);
    var zero = args;
    zero[17] = "0";
    try testing.expectEqualStrings("--message-rate", zero[16]);
    try testing.expect(try setup.parse_options(arena, &zero) == null);
    var bad = args;
    bad[23] = "yes";
    try testing.expect(try setup.parse_options(arena, &bad) == null);
}

test "setup: flood reads the hosts file the deployer writes" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const IpAddr = zigware.deployer.IpAddr;
    const hosts_list = [_]aws.Host{
        .{ .name = "aa", .region = "us-west-2", .ip = try IpAddr.parse("1.2.3.4") },
        .{ .name = "bb", .region = "eu-west-1", .ip = try IpAddr.parse("2001:db8::1") },
    };
    const hosts: aws.Hosts = .{
        .monitoring = .{
            .public = try IpAddr.parse("5.6.7.8"),
            .private = try IpAddr.parse("10.0.0.9"),
        },
        .hosts = &hosts_list,
    };
    var text: Io.Writer.Allocating = .init(arena);
    try hosts.write(&text.writer);
    const parsed = try lib.Hosts.parse(arena, text.written());
    try testing.expectEqual(@as(usize, 2), parsed.hosts.len);
    try testing.expectEqualStrings("bb", parsed.hosts[1].name);
    try testing.expectEqualStrings("eu-west-1", parsed.hosts[1].region);
    var buffer: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try writer.print("{f} {f}", .{ parsed.monitoring_private, parsed.hosts[1].ip });
    try testing.expectEqualStrings("10.0.0.9:0 [2001:db8::1]:0", writer.buffered());
}
