//! Flood tests: `SmallRng` against rand 0.10, YAML against serde_yaml 0.9, and the sender and
//! receiver tasks flooding each other on p2p's simulated network.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const build_options = @import("build_options");
const lib = @import("lib.zig");
const yaml = lib.yaml;

const p2p = zigware.p2p;
const metrics = zigware.runtime.telemetry.metrics;
const ed25519 = zigware.cryptography.ed25519;
const Key = ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);

test "SmallRng matches rand 0.10" {
    // `SmallRng::seed_from_u64(0)`: fill 21 bytes, fill 16 bytes, then `next_u64`.
    var rng = lib.SmallRng.seed_from_u64(0);
    var first: [21]u8 = undefined;
    rng.fill_bytes(&first);
    try testing.expectEqualSlices(u8, &.{
        0xdf, 0x23, 0x0b, 0x49, 0x61, 0x5d, 0x17, 0x53, 0x07, 0xd5, 0x80,
        0xc3, 0x3d, 0x6f, 0xda, 0x61, 0xfc, 0x7b, 0x9a, 0xec, 0x91,
    }, &first);
    var second: [16]u8 = undefined;
    rng.fill_bytes(&second);
    try testing.expectEqualSlices(u8, &.{
        0x1a, 0x5e, 0xbe, 0x3b, 0x8c, 0xbf, 0xee, 0x02,
        0xea, 0x5e, 0x4a, 0xaf, 0xeb, 0x04, 0xca, 0x7e,
    }, &second);
    try testing.expectEqual(@as(u64, 379361710973160858), rng.next_u64());
}

test "xoshiro256++ reference vectors" {
    // rand's test against the reference C implementation, seeded with [1, 2, 3, 4].
    var rng: lib.SmallRng = .{ .state = .{ 1, 2, 3, 4 } };
    const expected = [_]u64{
        41943041,             58720359,             3588806011781223,
        3591011842654386,     9228616714210784205,  9973669472204895162,
        14011001112246962877, 12406186145184390807, 15849039046786891736,
        10450023813501588000,
    };
    for (expected) |value| try testing.expectEqual(value, rng.next_u64());
}

test "events print as tracing-subscriber's JSON, strings escaped as serde_json does" {
    var buffer: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try lib.write_json_event(&writer, 1_500_000, .warn, "flood", "say \"hi\"\n\x01", .{
        .count = 3,
        .ok = true,
        .peer = "a\\b\t\x1f",
    });
    const expected = "{\"timestamp\":\"1970-01-01T00:00:00.001500Z\"," ++
        "\"level\":\"WARN\",\"fields\":{\"message\":\"say \\\"hi\\\"\\n\\u0001\"," ++
        "\"count\":3,\"ok\":true,\"peer\":\"a\\\\b\\t\\u001f\"},\"target\":\"flood\"}\n";
    try testing.expectEqualStrings(expected, writer.buffered());
}

test "message carries its send time" {
    var rng = lib.SmallRng.seed_from_u64(0);
    var message: [24]u8 = undefined;
    lib.fill_message(&message, 0x0102030405060708, &rng);
    try testing.expectEqualSlices(u8, &.{ 8, 7, 6, 5, 4, 3, 2, 1, 0xdf, 0x23 }, message[0..10]);
    try testing.expectEqual(@as(?u64, 0x0102030405060708), lib.sent_ns(&message));
    try testing.expectEqual(@as(?u64, null), lib.sent_ns(message[0..7]));
}

/// serde_yaml 0.9.34's `to_string` of the Rust `Config` with these values.
const config_yaml =
    \\private_key: 0123456789abcdef
    \\port: 4545
    \\allowed_peers:
    \\- 1e5a
    \\- abcd
    \\- '0012'
    \\- 'true'
    \\- 'null'
    \\- e5
    \\- '7'
    \\bootstrappers: []
    \\worker_threads: 4
    \\message_size: 1024
    \\message_rate: 16384
    \\mailbox_size: 16384
    \\instrument: false
    \\
;

test "config round-trips through serde_yaml's format" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const config = try lib.Config.parse(arena.allocator(), config_yaml);
    try testing.expectEqualStrings("0123456789abcdef", config.private_key);
    try testing.expectEqual(@as(u16, 4545), config.port);
    try testing.expectEqual(@as(usize, 7), config.allowed_peers.len);
    try testing.expectEqualStrings("0012", config.allowed_peers[2]);
    try testing.expectEqualStrings("true", config.allowed_peers[3]);
    try testing.expectEqual(@as(usize, 0), config.bootstrappers.len);
    try testing.expectEqual(@as(u32, 16384), config.message_rate);
    try testing.expect(!config.instrument);
    var buffer: [1024]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try config.write(&writer);
    try testing.expectEqualStrings(config_yaml, writer.buffered());
}

test "hosts file parses" {
    // serde_yaml 0.9.34's `to_string` of a deployer `Hosts`.
    const text =
        \\monitoring:
        \\  public: 1.2.3.4
        \\  private: 10.0.0.1
        \\hosts:
        \\- name: ab
        \\  region: us-east-1
        \\  ip: 127.0.0.1
        \\- name: cd
        \\  region: eu-west-1
        \\  ip: ::1
        \\
    ;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const hosts = try lib.Hosts.parse(arena.allocator(), text);
    try testing.expectEqual(@as(usize, 2), hosts.hosts.len);
    try testing.expectEqualStrings("cd", hosts.hosts[1].name);
    try testing.expectEqualStrings("eu-west-1", hosts.hosts[1].region);
    try testing.expect(hosts.hosts[1].ip == .ip6);
    try testing.expect(hosts.monitoring_private.eql(&(try Io.net.IpAddress.parse("10.0.0.1", 0))));
}

test "needs_quotes follows serde_yaml" {
    const quoted = [_][]const u8{
        "",     "0012", "7", "-3",   "+5",   "1.5",  "1e5", "0x1f", "0o17", "0b101",
        "true", "NULL", "~", ".inf", ".NaN", "a: b", "#x",  "-x",   "x:",   " x",
    };
    for (quoted) |text| {
        if (!yaml.needs_quotes(text)) std.debug.print("{s}\n", .{text});
        try testing.expect(yaml.needs_quotes(text));
    }
    const plain = [_][]const u8{ "1e5a", "e5", "abcd", "us-east-1", "inf", "nan", "0xzz", "a:b" };
    for (plain) |text| {
        if (yaml.needs_quotes(text)) std.debug.print("{s}\n", .{text});
        try testing.expect(!yaml.needs_quotes(text));
    }
}

test "yaml rejects what it does not support" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const invalid = [_][]const u8{
        "a: &anchor 1", "a: [1, 2]", "a: 'x''y'", "a:\n  - b\n c: d", "a: 1\n---\nb: 2",
        "-\n  - x",     "\ta: 1",
    };
    for (invalid) |text| {
        const result = yaml.Document.parse(arena.allocator(), text);
        if (result) |_| std.debug.print("accepted: {s}\n", .{text}) else |_| {}
        try testing.expectError(error.InvalidYaml, result);
    }
}

/// Parses `input` as YAML; accepted documents must survive navigation without errors other
/// than the typed accessor ones.
fn fuzz_one(input: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const document = yaml.Document.parse(arena.allocator(), input) catch |err| switch (err) {
        error.InvalidYaml => return,
        else => |other| return other,
    };
    _ = lib.Config.parse(arena.allocator(), input) catch |err| switch (err) {
        error.MissingKey, error.InvalidValue => {},
        else => |other| return other,
    };
    _ = document;
}

test "fuzz yaml (seeded)" {
    const alphabet = "abc019:-' \n#[]{}~.\"";
    var rng = zigware.utils.TestRng.init(0x7a41 ^ build_options.fuzz_seed);
    var input: [96]u8 = undefined;
    for (0..2000 * @as(u64, build_options.fuzz_soak)) |_| {
        const len = zigware.utils.rng.range_at_most(&rng, usize, 0, input.len);
        for (input[0..len]) |*byte| {
            byte.* = alphabet[zigware.utils.rng.range_less_than(&rng, usize, 0, alphabet.len)];
        }
        try fuzz_one(input[0..len]);
    }
}

test "fuzz yaml" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [4096]u8 = undefined;
            try fuzz_one(bytes[0..smith.slice(&bytes)]);
        }
    }.run, .{});
}

const peers = 3;
const per_sender = 50;

fn flood_root(io: Io) !void {
    const gpa = testing.allocator;
    var keys: [peers]Key = undefined;
    for (&keys, 0..) |*key, index| key.* = ed25519.PrivateKey.from_seed(index).public_key();
    var sorted = keys;
    std.sort.pdq(Key, &sorted, {}, Key.less_than);
    const network = try Net.init_with_peers(gpa, io, .{
        .max_size = 1024,
        .max_peers_per_set = peers,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    }, .init_primary(.init(&sorted)));
    defer network.deinit();
    var run = try io.concurrent(Net.run, .{network});
    defer {
        network.close();
        run.await(io) catch {};
    }
    const oracle = network.oracle();
    for (keys) |a| for (keys) |b| {
        if (Key.order(a, b) == .eq) continue;
        try oracle.add_link(a, b, .{
            .latency = .from_millis(20),
            .jitter = .from_millis(2),
            .success_rate = 1.0,
        });
    };
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry);
    var channels: [peers]Net.Registered = undefined;
    for (&channels, keys) |*channel, key| {
        channel.* = try oracle.control(key).register(0, p2p.Quota.per_second(1000));
    }
    defer for (&channels) |*channel| {
        channel.sender.deinit();
        channel.receiver.deinit();
    };
    var messages = try scope.counter("messages", "Sent messages");
    defer messages.deinit();
    const help = "Message latency in seconds";
    var latency = try scope.histogram("latency", help, &lib.latency_buckets);
    defer latency.deinit();
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (&channels) |*channel| {
        try group.concurrent(io, flood_sender, .{ io, &channel.sender, messages.metric() });
        try group.concurrent(io, flood_receiver, .{ io, &channel.receiver, latency.metric() });
    }
    try group.await(io);
    // Each peer sends `per_sender` messages to both others; every one arrives.
    try testing.expectEqual(@as(u64, peers * per_sender), messages.metric().get());
    const delivered: u64 = peers * per_sender * (peers - 1);
    try testing.expectEqual(delivered, latency.metric().get_count());
    const mean = latency.metric().get_sum() / @as(f64, @floatFromInt(latency.metric().get_count()));
    try testing.expect(mean > 0.010 and mean < 0.030);
}

fn flood_sender(io: Io, sender: *Net.Sender, messages: *metrics.raw.Counter) Io.Cancelable!void {
    const gpa = testing.allocator;
    lib.run_sender(gpa, io, sender, 64, messages, per_sender) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => std.debug.panic("sender: {t}", .{err}),
    };
}

fn flood_receiver(
    io: Io,
    receiver: *Net.Receiver,
    latency: *metrics.raw.Histogram,
) Io.Cancelable!void {
    try lib.run_receiver(io, receiver, latency, per_sender * (peers - 1));
}

test "peers flood each other on the simulated network" {
    var runner = try zigware.runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(flood_root, .{runner.io()}));
}
