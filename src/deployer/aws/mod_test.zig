//! Tests for the aws configuration types: commonware's `mod.rs` test and serde_yaml 0.9.34
//! golden files for `Config`, `Hosts`, and `Metadata`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const aws = @import("mod.zig");
const yaml = @import("../yaml.zig");
const IpAddr = @import("../ip.zig").IpAddr;

test "bandwidth_weighting uses aws names and defaults when absent" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const Case = struct { []const u8, ?aws.BandwidthWeighting };
    for ([_]Case{
        // Configs use the AWS identifiers so they read the same as the console and CLI.
        .{ "bandwidth_weighting: vpc-1\n", .vpc_1 },
        .{ "bandwidth_weighting: ebs-1\n", .ebs_1 },
        .{ "bandwidth_weighting: 'vpc-1'\n", .vpc_1 },
        .{ "bandwidth_weighting: Vpc1\n", null },
        .{ "bandwidth_weighting: ~\n", null },
        // Existing configs omit the field and keep the instance type's standard split.
        .{ "{}\n", .default },
    }) |case| {
        const map = try (try yaml.Document.parse(allocator, case[0])).root.as_map();
        if (case[1]) |expected| {
            try testing.expectEqual(expected, try aws.BandwidthWeighting.from_map(map));
        } else {
            try testing.expectError(error.InvalidValue, aws.BandwidthWeighting.from_map(map));
        }
    }
    // Writing a config back omits the standard split, so round trips do not add the field.
    const config: aws.Config = .{
        .tag = "t",
        .monitoring = .{
            .instance_type = "x",
            .storage_size = 1,
            .storage_class = "gp2",
            .bandwidth_weighting = .default,
            .dashboard = "d",
        },
        .instances = &.{},
        .ports = &.{},
    };
    var buffer: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try config.write(&writer);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "bandwidth") == null);
}

/// `serde_yaml::to_string` of a `Config` with every optional field set on one instance and
/// unset on the other, generated with serde_yaml 0.9.34.
const config_golden =
    \\tag: ffa638a0-991c-442c-8ec4-aa4e418213a5
    \\monitoring:
    \\  instance_type: t4g.small
    \\  storage_size: 10
    \\  storage_class: gp3
    \\  storage_throughput: 125
    \\  bandwidth_weighting: ebs-1
    \\  dashboard: dashboard.json
    \\instances:
    \\- name: node1
    \\  region: us-east-1
    \\  availability_zone_group: g1
    \\  instance_type: t4g.small
    \\  storage_size: 10
    \\  storage_class: io2
    \\  storage_iops: 3000
    \\  storage_throughput: -1
    \\  bandwidth_weighting: vpc-1
    \\  binary: /path/to/binary-arm64
    \\  config: /path/to/config.conf
    \\  profiling: true
    \\- name: '007'
    \\  region: us-west-2
    \\  instance_type: t3.small
    \\  storage_size: -2147483648
    \\  storage_class: gp2
    \\  binary: ''
    \\  config: 'it''s: x'
    \\  profiling: false
    \\ports:
    \\- protocol: tcp
    \\  port: 65535
    \\  cidr: 0.0.0.0/0
    \\
;

const golden_config: aws.Config = .{
    .tag = "ffa638a0-991c-442c-8ec4-aa4e418213a5",
    .monitoring = .{
        .instance_type = "t4g.small",
        .storage_size = 10,
        .storage_class = "gp3",
        .storage_throughput = 125,
        .bandwidth_weighting = .ebs_1,
        .dashboard = "dashboard.json",
    },
    .instances = &.{
        .{
            .name = "node1",
            .region = "us-east-1",
            .availability_zone_group = "g1",
            .instance_type = "t4g.small",
            .storage_size = 10,
            .storage_class = "io2",
            .storage_iops = 3000,
            .storage_throughput = -1,
            .bandwidth_weighting = .vpc_1,
            .binary = "/path/to/binary-arm64",
            .config = "/path/to/config.conf",
            .profiling = true,
        },
        .{
            .name = "007",
            .region = "us-west-2",
            .instance_type = "t3.small",
            .storage_size = -2147483648,
            .storage_class = "gp2",
            .binary = "",
            .config = "it's: x",
            .profiling = false,
        },
    },
    .ports = &.{.{ .protocol = "tcp", .port = 65535, .cidr = "0.0.0.0/0" }},
};

fn expect_instance(expected: aws.InstanceConfig, actual: aws.InstanceConfig) !void {
    try testing.expectEqualStrings(expected.name, actual.name);
    try testing.expectEqualStrings(expected.region, actual.region);
    try testing.expectEqualDeep(expected.availability_zone_group, actual.availability_zone_group);
    try testing.expectEqualStrings(expected.instance_type, actual.instance_type);
    try testing.expectEqual(expected.storage_size, actual.storage_size);
    try testing.expectEqualStrings(expected.storage_class, actual.storage_class);
    try testing.expectEqual(expected.storage_iops, actual.storage_iops);
    try testing.expectEqual(expected.storage_throughput, actual.storage_throughput);
    try testing.expectEqual(expected.bandwidth_weighting, actual.bandwidth_weighting);
    try testing.expectEqualStrings(expected.binary, actual.binary);
    try testing.expectEqualStrings(expected.config, actual.config);
    try testing.expectEqual(expected.profiling, actual.profiling);
}

test "config writes and reads as serde_yaml does" {
    var buffer: [2048]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try golden_config.write(&writer);
    try testing.expectEqualStrings(config_golden, writer.buffered());

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const parsed = try aws.Config.parse(arena.allocator(), config_golden);
    try testing.expectEqualStrings(golden_config.tag, parsed.tag);
    try testing.expectEqualDeep(golden_config.monitoring, parsed.monitoring);
    try testing.expectEqual(@as(usize, 2), parsed.instances.len);
    for (golden_config.instances, parsed.instances) |expected, actual| {
        try expect_instance(expected, actual);
    }
    try testing.expectEqualDeep(golden_config.ports, parsed.ports);
}

test "empty config collections write as flow sequences" {
    const config: aws.Config = .{
        .tag = "t",
        .monitoring = .{
            .instance_type = "x",
            .storage_size = 1,
            .storage_class = "gp2",
            .dashboard = "d",
        },
        .instances = &.{},
        .ports = &.{},
    };
    var buffer: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try config.write(&writer);
    try testing.expectEqualStrings(
        \\tag: t
        \\monitoring:
        \\  instance_type: x
        \\  storage_size: 1
        \\  storage_class: gp2
        \\  dashboard: d
        \\instances: []
        \\ports: []
        \\
    , writer.buffered());
}

/// A config with `monitoring.<line>` replaced, read with serde_yaml 0.9.34.
fn monitoring_with(comptime lines: []const u8) []const u8 {
    return "tag: t\nmonitoring:\n  instance_type: x\n" ++ lines ++
        "  storage_class: gp2\n  dashboard: d\ninstances: []\nports: []\n";
}

test "config reading follows serde's derive" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    // Hex integers and null optionals read; unknown keys are ignored.
    const hex = try aws.Config.parse(allocator, monitoring_with(
        \\  storage_size: 0x10
        \\  storage_iops: ~
        \\  extra: 1
        \\
    ));
    try testing.expectEqual(@as(i32, 16), hex.monitoring.storage_size);
    try testing.expectEqual(@as(?i32, null), hex.monitoring.storage_iops);
    // Quoted integers are strings, which serde refuses for an i32.
    const quoted = monitoring_with("  storage_size: '1'\n");
    try testing.expectError(error.InvalidValue, aws.Config.parse(allocator, quoted));
    const quoted_iops = monitoring_with("  storage_size: 1\n  storage_iops: '5'\n");
    try testing.expectError(error.InvalidValue, aws.Config.parse(allocator, quoted_iops));
    // Strings accept any scalar: a number, a null word, or nothing.
    const replaced = [_]struct { []const u8, []const u8 }{
        .{ "tag: 5\n", "5" }, .{ "tag: ~\n", "~" }, .{ "tag:\n", "" },
    };
    for (replaced) |case| {
        const text = try std.mem.concat(allocator, u8, &.{ case[0], monitoring_with(
            "  storage_size: 1\n",
        )["tag: t\n".len..] });
        try testing.expectEqualStrings(case[1], (try aws.Config.parse(allocator, text)).tag);
    }
    // A required sequence may not be null.
    const null_instances = "tag: t\nmonitoring:\n  instance_type: x\n  storage_size: 1\n" ++
        "  storage_class: gp2\n  dashboard: d\ninstances: ~\nports: []\n";
    try testing.expectError(error.InvalidValue, aws.Config.parse(allocator, null_instances));
    const missing = "tag: t\ninstances: []\nports: []\n";
    try testing.expectError(error.MissingKey, aws.Config.parse(allocator, missing));
}

const hosts_golden =
    \\monitoring:
    \\  public: 1.2.3.4
    \\  private: 10.0.0.1
    \\hosts:
    \\- name: ab
    \\  region: us-east-1
    \\  ip: 127.0.0.1
    \\- name: 'true'
    \\  region: eu-west-1
    \\  ip: 2001:db8::1
    \\
;

test "hosts write and read as serde_yaml does" {
    const hosts: aws.Hosts = .{
        .monitoring = .{
            .public = try IpAddr.parse("1.2.3.4"),
            .private = try IpAddr.parse("10.0.0.1"),
        },
        .hosts = &.{
            .{ .name = "ab", .region = "us-east-1", .ip = try IpAddr.parse("127.0.0.1") },
            .{ .name = "true", .region = "eu-west-1", .ip = try IpAddr.parse("2001:db8::1") },
        },
    };
    var buffer: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try hosts.write(&writer);
    try testing.expectEqualStrings(hosts_golden, writer.buffered());

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const parsed = try aws.Hosts.parse(arena.allocator(), hosts_golden);
    try testing.expectEqual(@as(usize, 2), parsed.hosts.len);
    try testing.expectEqualStrings("true", parsed.hosts[1].name);
    try testing.expect(parsed.hosts[1].ip.eql(hosts.hosts[1].ip));
    try testing.expect(parsed.monitoring.private.eql(hosts.monitoring.private));
}

test "ips read from any string scalar, as Rust parses them" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const valid = "monitoring:\n  public: '1.2.3.4'\n  private: ::ffff:1.2.3.4\nhosts: []\n";
    const parsed = try aws.Hosts.parse(allocator, valid);
    var buffer: [64]u8 = undefined;
    const shown = try std.fmt.bufPrint(&buffer, "{f}", .{parsed.monitoring.private});
    try testing.expectEqualStrings("::ffff:1.2.3.4", shown);
    const leading_zero = "monitoring:\n  public: 01.2.3.4\n  private: ::1\nhosts: []\n";
    try testing.expectError(error.InvalidValue, aws.Hosts.parse(allocator, leading_zero));
}

test "metadata writes and reads as serde_yaml does" {
    const metadata: aws.Metadata = .{
        .tag = "t",
        .created_at = std.math.maxInt(u64),
        .regions = &.{ "us-east-1", "null" },
        .instance_count = 3,
    };
    const golden =
        \\tag: t
        \\created_at: 18446744073709551615
        \\regions:
        \\- us-east-1
        \\- 'null'
        \\instance_count: 3
        \\
    ;
    var buffer: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try metadata.write(&writer);
    try testing.expectEqualStrings(golden, writer.buffered());

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const parsed = try aws.Metadata.parse(arena.allocator(), golden);
    try testing.expectEqualDeep(metadata, parsed);

    const empty: aws.Metadata = .{
        .tag = "t",
        .created_at = 0,
        .regions = &.{},
        .instance_count = 0,
    };
    writer = .fixed(&buffer);
    try empty.write(&writer);
    try testing.expectEqualStrings(
        "tag: t\ncreated_at: 0\nregions: []\ninstance_count: 0\n",
        writer.buffered(),
    );
}

test "architecture strings" {
    try testing.expectEqualStrings("arm64", aws.Architecture.arm64.as_str());
    try testing.expectEqualStrings("amd64", aws.Architecture.x86_64.as_str());
    var buffer: [8]u8 = undefined;
    try testing.expectEqualStrings("amd64", try std.fmt.bufPrint(&buffer, "{f}", .{
        aws.Architecture.x86_64,
    }));
}
