//! AWS EC2 deployer (commonware `deployer::aws`): the configuration, hosts, and metadata
//! files and the constants shared by every command.
//!
//! The YAML these types read and write is byte-identical to serde_yaml 0.9's for commonware's
//! types: fields in declaration order, `availability_zone_group`, `storage_iops`, and
//! `storage_throughput` omitted when absent, and `bandwidth_weighting` omitted when `default`.
//! Reading follows serde's derive: unknown keys are ignored, strings accept any scalar, integers
//! and booleans must be plain scalars, and an absent or null optional is `null`.
//!
//! Parsed values borrow from the parse arena and the input text.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const yaml = @import("../yaml.zig");
const IpAddr = @import("../ip.zig").IpAddr;

pub const utils = @import("utils.zig");
pub const s3 = @import("s3.zig");
pub const services = @import("services.zig");
pub const ec2 = @import("ec2.zig");
pub const create = @import("create.zig");
pub const deployments = @import("deployments.zig");
pub const sigv4 = @import("sigv4.zig");
pub const query = @import("query.zig");
pub const client = @import("client.zig");
pub const Failure = @import("failure.zig").Failure;

pub const Error = yaml.Error;
pub const WriteError = yaml.Emitter.WriteError;

/// Port on binary where metrics are exposed.
pub const metrics_port: u16 = 9090;
/// Port on instance where system metrics are exposed.
pub const system_port: u16 = 9100;
/// Port on monitoring where logs are pushed.
pub const logs_port: u16 = 3100;
/// Port on monitoring where profiles are pushed.
pub const profiles_port: u16 = 4040;
/// Port on monitoring where traces are pushed.
pub const traces_port: u16 = 4318;

/// Name of the monitoring instance.
pub const monitoring_name = "monitoring";
/// AWS region where monitoring instances are deployed.
pub const monitoring_region = "us-east-1";
/// File name that indicates the deployment completed.
pub const created_file_name = "created";
/// File name that indicates the deployment was destroyed.
pub const destroyed_file_name = "destroyed";
/// File name for deployment metadata.
pub const metadata_file_name = "metadata.yaml";

/// Maximum instances to manipulate at one time (the CLI's default `--concurrency`).
pub const default_concurrency = "128";

/// Subcommand names.
pub const cmd = "aws";
pub const create_cmd = "create";
pub const update_cmd = "update";
pub const authorize_cmd = "authorize";
pub const destroy_cmd = "destroy";
pub const clean_cmd = "clean";
pub const profile_cmd = "profile";
pub const attach_cmd = "attach";
pub const list_cmd = "list";

/// CPU architecture for EC2 instances.
pub const Architecture = enum {
    arm64,
    x86_64,

    /// The architecture string used in AMI names, download URLs, and labels.
    pub fn as_str(architecture: Architecture) []const u8 {
        return switch (architecture) {
            .arm64 => "arm64",
            .x86_64 => "amd64",
        };
    }

    pub fn format(architecture: Architecture, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.writeAll(architecture.as_str());
    }
};

/// How a Nitro instance splits its fixed card bandwidth between networking and EBS. The
/// combined budget does not change, so favoring one side lowers the other side's baseline.
pub const BandwidthWeighting = enum {
    /// The instance type's standard split; serializes as absent.
    default,
    /// More networking baseline, less EBS baseline.
    vpc_1,
    /// More EBS baseline, less networking baseline.
    ebs_1,

    /// The AWS identifier, which configs use.
    pub fn name(weighting: BandwidthWeighting) []const u8 {
        return switch (weighting) {
            .default => "default",
            .vpc_1 => "vpc-1",
            .ebs_1 => "ebs-1",
        };
    }

    pub fn is_default(weighting: BandwidthWeighting) bool {
        return weighting == .default;
    }

    /// The `bandwidth_weighting` field of `map`: absent is `default`; otherwise the value must
    /// name a variant (a null is an unknown variant, as in serde).
    pub fn from_map(map: yaml.Map) Error!BandwidthWeighting {
        const node = try map.find("bandwidth_weighting") orelse return .default;
        const text = try node.string();
        inline for (comptime std.enums.values(BandwidthWeighting)) |weighting| {
            if (std.mem.eql(u8, text, weighting.name())) return weighting;
        }
        return error.InvalidValue;
    }

    fn write(weighting: BandwidthWeighting, e: *yaml.Emitter) WriteError!void {
        if (weighting.is_default()) return;
        try e.string_field("bandwidth_weighting", weighting.name());
    }
};

/// Host deployment information.
pub const Host = struct {
    name: []const u8,
    region: []const u8,
    /// Public IP address of the host.
    ip: IpAddr,
};

/// Instance IP addresses.
pub const Ips = struct {
    public: IpAddr,
    private: IpAddr,
};

/// The hosts file every binary instance receives (`hosts.yaml`).
pub const Hosts = struct {
    /// Public and private IP addresses of the monitoring instance.
    monitoring: Ips,
    /// Hosts deployed across all regions.
    hosts: []const Host,

    pub fn parse(arena: Allocator, text: []const u8) Error!Hosts {
        const root = try (try yaml.Document.parse(arena, text)).root.as_map();
        const monitoring = try (try root.get("monitoring")).as_map();
        const nodes = try (try root.get("hosts")).as_list();
        const hosts = try arena.alloc(Host, nodes.len);
        for (nodes, hosts) |node, *host| {
            const map = try node.as_map();
            host.* = .{
                .name = try string(map, "name"),
                .region = try string(map, "region"),
                .ip = try ip(map, "ip"),
            };
        }
        assert(hosts.len == nodes.len);
        return .{
            .monitoring = .{
                .public = try ip(monitoring, "public"),
                .private = try ip(monitoring, "private"),
            },
            .hosts = hosts,
        };
    }

    pub fn write(hosts: *const Hosts, writer: *Io.Writer) WriteError!void {
        var e: yaml.Emitter = .{ .writer = writer };
        try e.begin_map("monitoring");
        try ip_field(&e, "public", hosts.monitoring.public);
        try ip_field(&e, "private", hosts.monitoring.private);
        e.end();
        try e.begin_list("hosts", hosts.hosts.len);
        for (hosts.hosts) |host| {
            e.begin_item();
            try e.string_field("name", host.name);
            try e.string_field("region", host.region);
            try ip_field(&e, "ip", host.ip);
            e.end();
        }
        e.end();
        assert(e.depth == 0);
    }
};

/// Port configuration.
pub const PortConfig = struct {
    /// Protocol (e.g. "tcp").
    protocol: []const u8,
    port: u16,
    /// CIDR block.
    cidr: []const u8,
};

/// Instance configuration.
pub const InstanceConfig = struct {
    /// Unique ignoring case, not `monitoring`, and matching `[A-Za-z0-9_-]+`.
    name: []const u8,
    region: []const u8,
    /// Instances in the same region and group launch in the same availability zone.
    availability_zone_group: ?[]const u8 = null,
    /// Instance type (e.g. `t4g.small` for ARM64, `t3.small` for x86_64).
    instance_type: []const u8,
    /// Storage size in GB.
    storage_size: i32,
    /// Storage class (e.g. "gp2").
    storage_class: []const u8,
    storage_iops: ?i32 = null,
    /// Provisioned throughput in MiB/s.
    storage_throughput: ?i32 = null,
    bandwidth_weighting: BandwidthWeighting = .default,
    /// Path to the binary to deploy.
    binary: []const u8,
    /// Path to the binary configuration file.
    config: []const u8,
    profiling: bool,

    fn parse(map: yaml.Map) Error!InstanceConfig {
        return .{
            .name = try string(map, "name"),
            .region = try string(map, "region"),
            .availability_zone_group = try optional_string(map, "availability_zone_group"),
            .instance_type = try string(map, "instance_type"),
            .storage_size = try (try map.get("storage_size")).integer(i32),
            .storage_class = try string(map, "storage_class"),
            .storage_iops = try map.optional_integer("storage_iops", i32),
            .storage_throughput = try map.optional_integer("storage_throughput", i32),
            .bandwidth_weighting = try BandwidthWeighting.from_map(map),
            .binary = try string(map, "binary"),
            .config = try string(map, "config"),
            .profiling = try (try map.get("profiling")).boolean(),
        };
    }

    fn write(instance: *const InstanceConfig, e: *yaml.Emitter) WriteError!void {
        assert(e.dash);
        try e.string_field("name", instance.name);
        try e.string_field("region", instance.region);
        if (instance.availability_zone_group) |group| {
            try e.string_field("availability_zone_group", group);
        }
        try e.string_field("instance_type", instance.instance_type);
        try write_storage(e, instance.storage_size, instance.storage_class, instance.storage_iops);
        if (instance.storage_throughput) |throughput| {
            try e.int_field("storage_throughput", throughput);
        }
        try instance.bandwidth_weighting.write(e);
        try e.string_field("binary", instance.binary);
        try e.string_field("config", instance.config);
        try e.bool_field("profiling", instance.profiling);
        assert(!e.dash);
    }
};

/// Monitoring configuration.
pub const MonitoringConfig = struct {
    instance_type: []const u8,
    storage_size: i32,
    storage_class: []const u8,
    storage_iops: ?i32 = null,
    storage_throughput: ?i32 = null,
    bandwidth_weighting: BandwidthWeighting = .default,
    /// Path to a custom dashboard file that is uploaded to Grafana.
    dashboard: []const u8,

    fn parse(map: yaml.Map) Error!MonitoringConfig {
        return .{
            .instance_type = try string(map, "instance_type"),
            .storage_size = try (try map.get("storage_size")).integer(i32),
            .storage_class = try string(map, "storage_class"),
            .storage_iops = try map.optional_integer("storage_iops", i32),
            .storage_throughput = try map.optional_integer("storage_throughput", i32),
            .bandwidth_weighting = try BandwidthWeighting.from_map(map),
            .dashboard = try string(map, "dashboard"),
        };
    }

    fn write(monitoring: *const MonitoringConfig, e: *yaml.Emitter) WriteError!void {
        try e.begin_map("monitoring");
        const depth = e.depth;
        try e.string_field("instance_type", monitoring.instance_type);
        try write_storage(
            e,
            monitoring.storage_size,
            monitoring.storage_class,
            monitoring.storage_iops,
        );
        if (monitoring.storage_throughput) |throughput| {
            try e.int_field("storage_throughput", throughput);
        }
        try monitoring.bandwidth_weighting.write(e);
        try e.string_field("dashboard", monitoring.dashboard);
        assert(e.depth == depth);
        e.end();
    }
};

/// Deployer configuration (`deployer aws create --config`).
pub const Config = struct {
    /// Unique tag for the deployment, matching `[A-Za-z0-9_-]+`.
    tag: []const u8,
    monitoring: MonitoringConfig,
    instances: []const InstanceConfig,
    /// Ports open on all instances.
    ports: []const PortConfig,

    pub fn parse(arena: Allocator, text: []const u8) Error!Config {
        const root = try (try yaml.Document.parse(arena, text)).root.as_map();
        const monitoring = try (try root.get("monitoring")).as_map();
        const instance_nodes = try (try root.get("instances")).as_list();
        const instances = try arena.alloc(InstanceConfig, instance_nodes.len);
        for (instance_nodes, instances) |node, *instance| {
            instance.* = try InstanceConfig.parse(try node.as_map());
        }
        const port_nodes = try (try root.get("ports")).as_list();
        const ports = try arena.alloc(PortConfig, port_nodes.len);
        for (port_nodes, ports) |node, *port| {
            const map = try node.as_map();
            port.* = .{
                .protocol = try string(map, "protocol"),
                .port = try (try map.get("port")).integer(u16),
                .cidr = try string(map, "cidr"),
            };
        }
        assert(instances.len == instance_nodes.len and ports.len == port_nodes.len);
        return .{
            .tag = try string(root, "tag"),
            .monitoring = try MonitoringConfig.parse(monitoring),
            .instances = instances,
            .ports = ports,
        };
    }

    pub fn write(config: *const Config, writer: *Io.Writer) WriteError!void {
        var e: yaml.Emitter = .{ .writer = writer };
        try e.string_field("tag", config.tag);
        try config.monitoring.write(&e);
        try e.begin_list("instances", config.instances.len);
        for (config.instances) |*instance| {
            e.begin_item();
            try instance.write(&e);
            e.end();
        }
        e.end();
        try e.begin_list("ports", config.ports.len);
        for (config.ports) |port| {
            e.begin_item();
            try e.string_field("protocol", port.protocol);
            try e.int_field("port", port.port);
            try e.string_field("cidr", port.cidr);
            e.end();
        }
        e.end();
        assert(e.depth == 0);
    }
};

/// Metadata persisted during deployment creation (`metadata.yaml`).
pub const Metadata = struct {
    tag: []const u8,
    /// Seconds since the Unix epoch.
    created_at: u64,
    regions: []const []const u8,
    instance_count: u64,

    pub fn parse(arena: Allocator, text: []const u8) Error!Metadata {
        const root = try (try yaml.Document.parse(arena, text)).root.as_map();
        const nodes = try (try root.get("regions")).as_list();
        const regions = try arena.alloc([]const u8, nodes.len);
        for (nodes, regions) |node, *region| region.* = try node.string();
        assert(regions.len == nodes.len);
        return .{
            .tag = try string(root, "tag"),
            .created_at = try (try root.get("created_at")).integer(u64),
            .regions = regions,
            .instance_count = try (try root.get("instance_count")).integer(u64),
        };
    }

    pub fn write(metadata: *const Metadata, writer: *Io.Writer) WriteError!void {
        var e: yaml.Emitter = .{ .writer = writer };
        try e.string_field("tag", metadata.tag);
        try e.int_field("created_at", metadata.created_at);
        try e.begin_list("regions", metadata.regions.len);
        for (metadata.regions) |region| try e.string_item(region);
        e.end();
        try e.int_field("instance_count", metadata.instance_count);
        assert(e.depth == 0);
    }
};

fn string(map: yaml.Map, key: []const u8) Error![]const u8 {
    return (try map.get(key)).string();
}

/// An `Option<String>` with serde `default`: absent or null is `null`.
fn optional_string(map: yaml.Map, key: []const u8) Error!?[]const u8 {
    const node = try map.find(key) orelse return null;
    if (node.is_null()) return null;
    return try node.string();
}

/// An `IpAddr`, which serde reads from any string scalar.
fn ip(map: yaml.Map, key: []const u8) Error!IpAddr {
    return IpAddr.parse(try string(map, key)) catch error.InvalidValue;
}

fn ip_field(e: *yaml.Emitter, key: []const u8, value: IpAddr) WriteError!void {
    var buffer: [64]u8 = undefined;
    var text: Io.Writer = .fixed(&buffer);
    // An IPv6 address prints at most 39 bytes.
    value.format(&text) catch unreachable;
    assert(text.buffered().len > 0);
    try e.string_field(key, text.buffered());
}

fn write_storage(e: *yaml.Emitter, size: i32, class: []const u8, iops: ?i32) WriteError!void {
    try e.int_field("storage_size", size);
    try e.string_field("storage_class", class);
    if (iops) |value| try e.int_field("storage_iops", value);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("mod_test.zig");
}
