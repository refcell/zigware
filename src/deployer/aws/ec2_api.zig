//! The EC2 calls of commonware's `deployer::aws::ec2` (all but `RunInstances`, which lives in
//! `ec2.zig`), as EC2 Query requests over the signed client with the SDK's standard retries.
//!
//! A call that AWS refuses returns `error.AwsEc2`, and `Ec2.failure` holds the `ApiError`
//! (commonware's `Ec2Error`). Like commonware, describe calls read one page, and the wait loops
//! poll every `retry_interval_ms` until the condition holds or the task is canceled.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const aws = @import("mod.zig");
const aws_utils = @import("utils.zig");
const client_module = @import("client.zig");
const create = @import("create.zig");
const query = @import("query.zig");
const sigv4 = @import("sigv4.zig");

const Client = client_module.Client;
const ApiError = client_module.ApiError;
const Pair = sigv4.Pair;

const log = std.log.scoped(.deployer);

/// How often the wait loops poll (zero in tests, like commonware's launch retries).
pub const poll_interval_ms: u64 = if (builtin.is_test) 0 else aws_utils.retry_interval_ms;
/// How often `wait_for_vpc_peering_connection` polls.
pub const peering_poll_interval_ms: u64 = if (builtin.is_test) 0 else 2_000;

/// Canonical's AWS account, which publishes the Ubuntu images.
pub const canonical_owner = "099720109477";

pub const Error = error{
    /// AWS refused the call; `Ec2.failure` says why.
    AwsEc2,
    /// A response lacked a field the call needs.
    MalformedResponse,
    /// `describe_instance_type` found no such instance type.
    InstanceTypeNotFound,
    /// The instance type lists neither arm64 nor x86_64.
    NoSupportedArchitecture,
    /// No Ubuntu 24.04 image matched.
    NoMatchingAmi,
    /// No availability zone offers any of the instance types.
    NoAvailabilityZone,
    MalformedXml,
    OutOfMemory,
    Canceled,
};

/// An EC2 client for one region. Results are allocated from `arena`.
pub const Ec2 = struct {
    client: *const Client,
    arena: Allocator,
    /// Why the last `error.AwsEc2` happened.
    failure: ?ApiError = null,

    /// Sends `action` with `params` and returns the response body.
    pub fn run(ec2: *Ec2, action: []const u8, params: []const Pair) Error![]const u8 {
        assert(action.len > 0);
        // An allocating writer fails only when allocation does.
        var body = query.Body.init(ec2.arena, action, query.ec2_version) catch
            return error.OutOfMemory;
        for (params) |param| body.add(param.name, param.value) catch return error.OutOfMemory;
        const result = ec2.client.call(ec2.arena, .{
            .service = "ec2",
            .method = "POST",
            .host = try ec2.client.ec2_host(ec2.arena),
            .headers = &.{.{ .name = "content-type", .value = query.content_type }},
            .body = body.written(),
        }, .ec2_query) catch |err| return switch (err) {
            error.OutOfMemory, error.Canceled => |e| e,
            // Proof: signing fails only on allocation, and the body is well-formed.
            else => unreachable,
        };
        switch (result) {
            .ok => |response| return response.body,
            .failed => |err| {
                ec2.failure = err;
                log.debug("{s} failed: {f}", .{ action, err });
                return error.AwsEc2;
            },
        }
    }

    fn text(ec2: *Ec2, xml: []const u8, path: []const []const u8) Error![]const u8 {
        return try query.decoded_text(ec2.arena, xml, path) orelse error.MalformedResponse;
    }

    fn sleep(ec2: *Ec2, duration_ms: u64) Error!void {
        try ec2.client.io.sleep(.fromMilliseconds(@intCast(duration_ms)), .awake);
    }
};

/// Builds Query parameters: indexed names (`Filter.1.Value.2`) allocated from an arena.
pub const Params = struct {
    arena: Allocator,
    list: std.ArrayList(Pair) = .empty,

    pub fn add(params: *Params, name: []const u8, value: []const u8) !void {
        assert(name.len > 0);
        try params.list.append(params.arena, .{ .name = name, .value = value });
    }

    pub fn addf(
        params: *Params,
        comptime name: []const u8,
        args: anytype,
        value: []const u8,
    ) !void {
        try params.add(try std.fmt.allocPrint(params.arena, name, args), value);
    }

    pub fn add_int(params: *Params, name: []const u8, value: i64) !void {
        try params.add(name, try std.fmt.allocPrint(params.arena, "{d}", .{value}));
    }

    /// `TagSpecification.1`: `deployer={tag}` on a new resource of `resource_type`.
    pub fn tag_spec(params: *Params, resource_type: []const u8, tag: []const u8) !void {
        try params.add("TagSpecification.1.ResourceType", resource_type);
        try params.add("TagSpecification.1.Tag.1.Key", "deployer");
        try params.add("TagSpecification.1.Tag.1.Value", tag);
    }

    /// `Filter.{index}` matching any of `values`.
    pub fn filter(params: *Params, index: u32, name: []const u8, values: []const []const u8) !void {
        assert(index > 0);
        try params.addf("Filter.{d}.Name", .{index}, name);
        for (values, 1..) |value, position| {
            try params.addf("Filter.{d}.Value.{d}", .{ index, position }, value);
        }
    }

    /// `{prefix}.1`, `{prefix}.2`, ... for `values`.
    pub fn list_of(params: *Params, comptime prefix: []const u8, values: []const []const u8) !void {
        for (values, 1..) |value, position| try params.addf(prefix ++ ".{d}", .{position}, value);
    }

    /// One ingress rule, `IpPermissions.{index}`.
    pub fn ip_permission(
        params: *Params,
        index: u32,
        protocol: []const u8,
        from_port: i32,
        to_port: i32,
        cidr: []const u8,
    ) !void {
        assert(index > 0);
        try params.addf("IpPermissions.{d}.IpProtocol", .{index}, protocol);
        const from = try std.fmt.allocPrint(params.arena, "{d}", .{from_port});
        try params.addf("IpPermissions.{d}.FromPort", .{index}, from);
        const to = try std.fmt.allocPrint(params.arena, "{d}", .{to_port});
        try params.addf("IpPermissions.{d}.ToPort", .{index}, to);
        try params.addf("IpPermissions.{d}.IpRanges.1.CidrIp", .{index}, cidr);
    }
};

fn params_of(ec2: *Ec2) Params {
    return .{ .arena = ec2.arena };
}

/// The instance (or other resource) IDs at `path`, in order.
fn ids_at(ec2: *Ec2, xml: []const u8, path: []const []const u8) Error![]const []const u8 {
    return query.texts(ec2.arena, xml, path);
}

// --- Key pairs and instance types --------------------------------------------------------------

/// Imports an SSH public key (commonware `import_key_pair`).
pub fn import_key_pair(ec2: *Ec2, key_name: []const u8, public_key: []const u8) Error!void {
    var params = params_of(ec2);
    try params.add("KeyName", key_name);
    const encoded = try ec2.arena.alloc(u8, std.base64.standard.Encoder.calcSize(public_key.len));
    _ = std.base64.standard.Encoder.encode(encoded, public_key);
    try params.add("PublicKeyMaterial", encoded);
    _ = try ec2.run("ImportKeyPair", params.list.items);
}

/// Deletes an SSH key pair (commonware `delete_key_pair`).
pub fn delete_key_pair(ec2: *Ec2, key_name: []const u8) Error!void {
    _ = try ec2.run("DeleteKeyPair", &.{.{ .name = "KeyName", .value = key_name }});
}

fn describe_instance_type(ec2: *Ec2, instance_type: []const u8) Error![]const u8 {
    const xml = try ec2.run("DescribeInstanceTypes", &.{
        .{ .name = "InstanceType.1", .value = instance_type },
    });
    const items = try query.elements(ec2.arena, xml, &.{
        "DescribeInstanceTypesResponse", "instanceTypeSet", "item",
    });
    if (items.len == 0) return error.InstanceTypeNotFound;
    return items[0];
}

/// The architecture of an instance type (commonware `detect_architecture`).
pub fn detect_architecture(ec2: *Ec2, instance_type: []const u8) Error!aws.Architecture {
    const info = try describe_instance_type(ec2, instance_type);
    const architectures = try query.texts(ec2.arena, info, &.{
        "processorInfo", "supportedArchitectures", "item",
    });
    // Instance types support one architecture, so the order of these checks is moot.
    for (architectures) |name| if (std.mem.eql(u8, name, "arm64")) return .arm64;
    for (architectures) |name| if (std.mem.eql(u8, name, "x86_64")) return .x86_64;
    return error.NoSupportedArchitecture;
}

/// Whether an instance type exposes NVMe instance-store devices (commonware
/// `supports_nvme_instance_storage`).
pub fn supports_nvme_instance_storage(ec2: *Ec2, instance_type: []const u8) Error!bool {
    const info = try describe_instance_type(ec2, instance_type);
    const supported = try query.first_text(info, &.{"instanceStorageSupported"}) orelse "false";
    const nvme = try query.first_text(info, &.{ "instanceStorageInfo", "nvmeSupport" }) orelse "";
    return std.mem.eql(u8, supported, "true") and
        (std.mem.eql(u8, nvme, "required") or std.mem.eql(u8, nvme, "supported"));
}

/// The newest Ubuntu 24.04 image for `architecture` (commonware `find_latest_ami`).
pub fn find_latest_ami(ec2: *Ec2, architecture: aws.Architecture) Error![]const u8 {
    var params = params_of(ec2);
    const name = try std.fmt.allocPrint(
        ec2.arena,
        "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-{s}-server-*",
        .{architecture.as_str()},
    );
    try params.filter(1, "name", &.{name});
    try params.filter(2, "root-device-type", &.{"ebs"});
    try params.add("Owner.1", canonical_owner);
    const xml = try ec2.run("DescribeImages", params.list.items);
    const path = [_][]const u8{ "DescribeImagesResponse", "imagesSet", "item" };
    const images = try query.elements(ec2.arena, xml, &path);
    if (images.len == 0) return error.NoMatchingAmi;
    var latest_id: ?[]const u8 = null;
    var latest_date: []const u8 = "";
    for (images) |image| {
        // ISO 8601 creation dates order as strings; an image without one sorts last.
        const date = try query.first_text(image, &.{"creationDate"}) orelse "";
        if (latest_id != null and std.mem.order(u8, date, latest_date) != .gt) continue;
        latest_id = try ec2.text(image, &.{"imageId"});
        latest_date = date;
    }
    return latest_id.?;
}

// --- Networking --------------------------------------------------------------------------------

/// Creates a tagged VPC (commonware `create_vpc`).
pub fn create_vpc(ec2: *Ec2, cidr_block: []const u8, tag: []const u8) Error![]const u8 {
    var params = params_of(ec2);
    try params.add("CidrBlock", cidr_block);
    try params.tag_spec("vpc", tag);
    const xml = try ec2.run("CreateVpc", params.list.items);
    return ec2.text(xml, &.{ "CreateVpcResponse", "vpc", "vpcId" });
}

/// Creates an Internet Gateway and attaches it to `vpc_id` (commonware
/// `create_and_attach_igw`).
pub fn create_and_attach_igw(ec2: *Ec2, vpc_id: []const u8, tag: []const u8) Error![]const u8 {
    var params = params_of(ec2);
    try params.tag_spec("internet-gateway", tag);
    const xml = try ec2.run("CreateInternetGateway", params.list.items);
    const igw_id = try ec2.text(xml, &.{
        "CreateInternetGatewayResponse", "internetGateway", "internetGatewayId",
    });
    _ = try ec2.run("AttachInternetGateway", &.{
        .{ .name = "InternetGatewayId", .value = igw_id },
        .{ .name = "VpcId", .value = vpc_id },
    });
    return igw_id;
}

/// Creates a route table with a default route through the Internet Gateway (commonware
/// `create_route_table`).
pub fn create_route_table(
    ec2: *Ec2,
    vpc_id: []const u8,
    igw_id: []const u8,
    tag: []const u8,
) Error![]const u8 {
    var params = params_of(ec2);
    try params.add("VpcId", vpc_id);
    try params.tag_spec("route-table", tag);
    const xml = try ec2.run("CreateRouteTable", params.list.items);
    const route_table_id = try ec2.text(xml, &.{
        "CreateRouteTableResponse", "routeTable", "routeTableId",
    });
    _ = try ec2.run("CreateRoute", &.{
        .{ .name = "RouteTableId", .value = route_table_id },
        .{ .name = "DestinationCidrBlock", .value = "0.0.0.0/0" },
        .{ .name = "GatewayId", .value = igw_id },
    });
    return route_table_id;
}

/// Creates a subnet and associates it with the route table (commonware `create_subnet`).
pub fn create_subnet(
    ec2: *Ec2,
    vpc_id: []const u8,
    route_table_id: []const u8,
    subnet_cidr: []const u8,
    availability_zone: []const u8,
    tag: []const u8,
) Error![]const u8 {
    var params = params_of(ec2);
    try params.add("VpcId", vpc_id);
    try params.add("CidrBlock", subnet_cidr);
    try params.add("AvailabilityZone", availability_zone);
    try params.tag_spec("subnet", tag);
    const xml = try ec2.run("CreateSubnet", params.list.items);
    const subnet_id = try ec2.text(xml, &.{ "CreateSubnetResponse", "subnet", "subnetId" });
    _ = try ec2.run("AssociateRouteTable", &.{
        .{ .name = "RouteTableId", .value = route_table_id },
        .{ .name = "SubnetId", .value = subnet_id },
    });
    return subnet_id;
}

fn create_security_group(
    ec2: *Ec2,
    group_name: []const u8,
    description: []const u8,
    vpc_id: []const u8,
    tag: []const u8,
) Error![]const u8 {
    var params = params_of(ec2);
    try params.add("GroupName", group_name);
    try params.add("GroupDescription", description);
    try params.add("VpcId", vpc_id);
    try params.tag_spec("security-group", tag);
    const xml = try ec2.run("CreateSecurityGroup", params.list.items);
    return ec2.text(xml, &.{ "CreateSecurityGroupResponse", "groupId" });
}

fn deployer_permission(params: *Params, deployer_ip: []const u8) !void {
    var buffer: [64]u8 = undefined;
    const cidr = aws_utils.exact_cidr(&buffer, deployer_ip) catch return error.MalformedResponse;
    try params.ip_permission(
        1,
        aws_utils.deployer_protocol,
        aws_utils.deployer_min_port,
        aws_utils.deployer_max_port,
        try params.arena.dupe(u8, cidr),
    );
}

/// Creates the monitoring instance's security group, open to the deployer's IP (commonware
/// `create_security_group_monitoring`).
pub fn create_security_group_monitoring(
    ec2: *Ec2,
    vpc_id: []const u8,
    deployer_ip: []const u8,
    tag: []const u8,
) Error![]const u8 {
    const description = "Security group for monitoring instance";
    const group_id = try create_security_group(ec2, tag, description, vpc_id, tag);
    var params = params_of(ec2);
    try params.add("GroupId", group_id);
    try deployer_permission(&params, deployer_ip);
    _ = try ec2.run("AuthorizeSecurityGroupIngress", params.list.items);
    return group_id;
}

/// Creates the binary instances' security group, open to the deployer's IP and the configured
/// ports (commonware `create_security_group_binary`). Monitoring's rules come later, through
/// `add_monitoring_ingress`.
pub fn create_security_group_binary(
    ec2: *Ec2,
    vpc_id: []const u8,
    deployer_ip: []const u8,
    tag: []const u8,
    ports: []const aws.PortConfig,
) Error![]const u8 {
    const name = try std.fmt.allocPrint(ec2.arena, "{s}-binary", .{tag});
    const description = "Security group for binary instances";
    const group_id = try create_security_group(ec2, name, description, vpc_id, tag);
    var params = params_of(ec2);
    try params.add("GroupId", group_id);
    try deployer_permission(&params, deployer_ip);
    for (ports, 2..) |port, index| {
        const value: i32 = port.port;
        try params.ip_permission(@intCast(index), port.protocol, value, value, port.cidr);
    }
    _ = try ec2.run("AuthorizeSecurityGroupIngress", params.list.items);
    return group_id;
}

/// Opens every TCP port to `cidr` (commonware `authorize`'s ingress rule).
pub fn authorize_deployer_ingress(ec2: *Ec2, sg_id: []const u8, cidr: []const u8) Error!void {
    var params = params_of(ec2);
    try params.add("GroupId", sg_id);
    try params.ip_permission(
        1,
        aws_utils.deployer_protocol,
        aws_utils.deployer_min_port,
        aws_utils.deployer_max_port,
        cidr,
    );
    _ = try ec2.run("AuthorizeSecurityGroupIngress", params.list.items);
}

/// Revokes `group_id`'s TCP `port` rule for traffic from `source_group_id` (commonware
/// `destroy`'s logs, profiles, and traces rules).
pub fn revoke_group_ingress(
    ec2: *Ec2,
    group_id: []const u8,
    port: u16,
    source_group_id: []const u8,
) Error!void {
    var params = params_of(ec2);
    try params.add("GroupId", group_id);
    try params.add("IpPermissions.1.IpProtocol", "tcp");
    try params.add_int("IpPermissions.1.FromPort", port);
    try params.add_int("IpPermissions.1.ToPort", port);
    try params.add("IpPermissions.1.Groups.1.GroupId", source_group_id);
    _ = try ec2.run("RevokeSecurityGroupIngress", params.list.items);
}

/// Opens the metrics and system ports to the monitoring instance (commonware
/// `add_monitoring_ingress`).
pub fn add_monitoring_ingress(ec2: *Ec2, sg_id: []const u8, monitoring_ip: []const u8) Error!void {
    var buffer: [64]u8 = undefined;
    const cidr = aws_utils.exact_cidr(&buffer, monitoring_ip) catch return error.MalformedResponse;
    var params = params_of(ec2);
    try params.add("GroupId", sg_id);
    try params.ip_permission(1, "tcp", aws.metrics_port, aws.metrics_port, cidr);
    try params.ip_permission(2, "tcp", aws.system_port, aws.system_port, cidr);
    _ = try ec2.run("AuthorizeSecurityGroupIngress", params.list.items);
}

// --- Instances ---------------------------------------------------------------------------------

fn instance_items(ec2: *Ec2, xml: []const u8) Error![]const []const u8 {
    return query.elements(ec2.arena, xml, &.{
        "DescribeInstancesResponse", "reservationSet", "item", "instancesSet", "item",
    });
}

fn describe_instances(ec2: *Ec2, instance_ids: []const []const u8) Error![]const []const u8 {
    var params = params_of(ec2);
    try params.list_of("InstanceId", instance_ids);
    return instance_items(ec2, try ec2.run("DescribeInstances", params.list.items));
}

fn instance_state(instance: []const u8) Error![]const u8 {
    return try query.first_text(instance, &.{ "instanceState", "name" }) orelse "";
}

/// Waits until every instance runs with a public IP and returns the IPs in input order
/// (commonware `wait_for_instances_running`). Running instances are not asked about again,
/// and failed describes are retried.
pub fn wait_for_instances_running(
    ec2: *Ec2,
    instance_ids: []const []const u8,
) Error![]const []const u8 {
    assert(instance_ids.len > 0);
    const ips = try ec2.arena.alloc(?[]const u8, instance_ids.len);
    @memset(ips, null);
    var pending: std.ArrayList([]const u8) = .empty;
    var attempt: u32 = 0;
    while (true) {
        pending.clearRetainingCapacity();
        for (instance_ids, ips) |id, ip| if (ip == null) try pending.append(ec2.arena, id);
        if (pending.items.len == 0) break;
        const instances = describe_instances(ec2, pending.items) catch |err| switch (err) {
            error.AwsEc2 => {
                attempt +|= 1;
                log.debug("describe_instances failed, retrying: pending={d} attempt={d}", .{
                    pending.items.len, attempt,
                });
                try ec2.sleep(poll_interval_ms);
                continue;
            },
            else => |e| return e,
        };
        attempt = 0;
        for (instances) |instance| {
            const id = try query.first_text(instance, &.{"instanceId"}) orelse continue;
            if (!std.mem.eql(u8, try instance_state(instance), "running")) continue;
            const ip = try query.first_text(instance, &.{"ipAddress"}) orelse continue;
            for (instance_ids, ips) |wanted, *slot| {
                if (std.mem.eql(u8, wanted, id)) slot.* = try ec2.arena.dupe(u8, ip);
            }
        }
        const missing = for (ips) |ip| {
            if (ip == null) break true;
        } else false;
        if (!missing) break;
        try ec2.sleep(poll_interval_ms);
    }
    const out = try ec2.arena.alloc([]const u8, ips.len);
    for (out, ips) |*slot, ip| slot.* = ip.?;
    return out;
}

/// Waits until every instance runs and passes its system and instance status checks
/// (commonware `wait_for_instances_ready`).
pub fn wait_for_instances_ready(ec2: *Ec2, instance_ids: []const []const u8) Error!void {
    assert(instance_ids.len > 0);
    var params = params_of(ec2);
    try params.list_of("InstanceId", instance_ids);
    try params.add("IncludeAllInstances", "true");
    while (true) {
        const xml = ec2.run("DescribeInstanceStatus", params.list.items) catch |err| switch (err) {
            error.AwsEc2 => {
                try ec2.sleep(poll_interval_ms);
                continue;
            },
            else => |e| return e,
        };
        const statuses = try query.elements(ec2.arena, xml, &.{
            "DescribeInstanceStatusResponse", "instanceStatusSet", "item",
        });
        const ready = for (statuses) |status| {
            const state = try query.first_text(status, &.{ "instanceState", "name" }) orelse "";
            const system = try query.first_text(status, &.{ "systemStatus", "status" }) orelse "";
            const own = try query.first_text(status, &.{ "instanceStatus", "status" }) orelse "";
            const ok = std.mem.eql(u8, state, "running") and std.mem.eql(u8, system, "ok") and
                std.mem.eql(u8, own, "ok");
            if (!ok) break false;
        } else true;
        if (ready) return;
        try ec2.sleep(poll_interval_ms);
    }
}

/// The private IP of an instance (commonware `get_private_ip`).
pub fn get_private_ip(ec2: *Ec2, instance_id: []const u8) Error![]const u8 {
    const instances = try describe_instances(ec2, &.{instance_id});
    if (instances.len == 0) return error.MalformedResponse;
    return ec2.text(instances[0], &.{"privateIpAddress"});
}

/// The instances tagged `deployer={tag}` (commonware `find_instances_by_tag`).
pub fn find_instances_by_tag(ec2: *Ec2, tag: []const u8) Error![]const []const u8 {
    var params = params_of(ec2);
    try params.filter(1, "tag:deployer", &.{tag});
    const xml = try ec2.run("DescribeInstances", params.list.items);
    return ids_at(ec2, xml, &.{
        "DescribeInstancesResponse", "reservationSet", "item", "instancesSet", "item",
        "instanceId",
    });
}

/// Terminates instances; none is a no-op (commonware `terminate_instances`).
pub fn terminate_instances(ec2: *Ec2, instance_ids: []const []const u8) Error!void {
    if (instance_ids.len == 0) return;
    var params = params_of(ec2);
    try params.list_of("InstanceId", instance_ids);
    _ = try ec2.run("TerminateInstances", params.list.items);
}

/// Waits until every instance is terminated (commonware `wait_for_instances_terminated`).
pub fn wait_for_instances_terminated(ec2: *Ec2, instance_ids: []const []const u8) Error!void {
    while (true) {
        const instances = try describe_instances(ec2, instance_ids);
        const done = for (instances) |instance| {
            if (!std.mem.eql(u8, try instance_state(instance), "terminated")) break false;
        } else true;
        if (done) return;
        try ec2.sleep(poll_interval_ms);
    }
}

// --- VPC peering -------------------------------------------------------------------------------

/// Requests a peering from `requester_vpc_id` to `peer_vpc_id` in `peer_region` (commonware
/// `create_vpc_peering_connection`).
pub fn create_vpc_peering_connection(
    ec2: *Ec2,
    requester_vpc_id: []const u8,
    peer_vpc_id: []const u8,
    peer_region: []const u8,
    tag: []const u8,
) Error![]const u8 {
    var params = params_of(ec2);
    try params.add("VpcId", requester_vpc_id);
    try params.add("PeerVpcId", peer_vpc_id);
    try params.add("PeerRegion", peer_region);
    try params.tag_spec("vpc-peering-connection", tag);
    const xml = try ec2.run("CreateVpcPeeringConnection", params.list.items);
    return ec2.text(xml, &.{
        "CreateVpcPeeringConnectionResponse", "vpcPeeringConnection", "vpcPeeringConnectionId",
    });
}

/// The status code of a peering connection, or null when AWS no longer lists it.
fn peering_status(ec2: *Ec2, peer_id: []const u8) Error!?[]const u8 {
    const xml = try ec2.run("DescribeVpcPeeringConnections", &.{
        .{ .name = "VpcPeeringConnectionId.1", .value = peer_id },
    });
    const connections = try query.elements(ec2.arena, xml, &.{
        "DescribeVpcPeeringConnectionsResponse", "vpcPeeringConnectionSet", "item",
    });
    if (connections.len == 0) return null;
    return try query.first_text(connections[0], &.{ "status", "code" }) orelse "";
}

/// Polls every 2 s until the peering awaits acceptance; failed describes are retried
/// (commonware `wait_for_vpc_peering_connection`).
pub fn wait_for_vpc_peering_connection(ec2: *Ec2, peer_id: []const u8) Error!void {
    while (true) {
        const status = peering_status(ec2, peer_id) catch |err| switch (err) {
            error.AwsEc2 => null,
            else => |e| return e,
        };
        if (status) |code| if (std.mem.eql(u8, code, "pending-acceptance")) return;
        try ec2.sleep(peering_poll_interval_ms);
    }
}

/// Accepts a peering in the peer region (commonware `accept_vpc_peering_connection`).
pub fn accept_vpc_peering_connection(ec2: *Ec2, peer_id: []const u8) Error!void {
    _ = try ec2.run("AcceptVpcPeeringConnection", &.{
        .{ .name = "VpcPeeringConnectionId", .value = peer_id },
    });
}

/// Routes `destination_cidr` through a peering (commonware `add_route`).
pub fn add_route(
    ec2: *Ec2,
    route_table_id: []const u8,
    destination_cidr: []const u8,
    peer_id: []const u8,
) Error!void {
    _ = try ec2.run("CreateRoute", &.{
        .{ .name = "RouteTableId", .value = route_table_id },
        .{ .name = "DestinationCidrBlock", .value = destination_cidr },
        .{ .name = "VpcPeeringConnectionId", .value = peer_id },
    });
}

/// The peerings tagged `deployer={tag}` (commonware `find_vpc_peering_by_tag`).
pub fn find_vpc_peering_by_tag(ec2: *Ec2, tag: []const u8) Error![]const []const u8 {
    var params = params_of(ec2);
    try params.filter(1, "tag:deployer", &.{tag});
    const xml = try ec2.run("DescribeVpcPeeringConnections", params.list.items);
    return ids_at(ec2, xml, &.{
        "DescribeVpcPeeringConnectionsResponse", "vpcPeeringConnectionSet", "item",
        "vpcPeeringConnectionId",
    });
}

/// Deletes a peering (commonware `delete_vpc_peering`).
pub fn delete_vpc_peering(ec2: *Ec2, peering_id: []const u8) Error!void {
    _ = try ec2.run("DeleteVpcPeeringConnection", &.{
        .{ .name = "VpcPeeringConnectionId", .value = peering_id },
    });
}

/// Waits until a peering is deleted or no longer listed (commonware
/// `wait_for_vpc_peering_deletion`).
pub fn wait_for_vpc_peering_deletion(ec2: *Ec2, peer_id: []const u8) Error!void {
    while (true) {
        const status = try peering_status(ec2, peer_id) orelse return;
        if (std.mem.eql(u8, status, "deleted")) return;
        try ec2.sleep(poll_interval_ms);
    }
}

// --- Discovery and teardown --------------------------------------------------------------------

/// An ingress rule of a security group.
pub const IpPermission = struct {
    protocol: []const u8,
    from_port: ?i32,
    to_port: ?i32,
    cidrs: []const []const u8,
};

pub const SecurityGroup = struct {
    id: []const u8,
    name: []const u8,
    ip_permissions: []const IpPermission,
};

/// The security groups tagged `deployer={tag}` (commonware `find_security_groups_by_tag`).
pub fn find_security_groups_by_tag(ec2: *Ec2, tag: []const u8) Error![]const SecurityGroup {
    var params = params_of(ec2);
    try params.filter(1, "tag:deployer", &.{tag});
    const xml = try ec2.run("DescribeSecurityGroups", params.list.items);
    const items = try query.elements(ec2.arena, xml, &.{
        "DescribeSecurityGroupsResponse", "securityGroupInfo", "item",
    });
    const groups = try ec2.arena.alloc(SecurityGroup, items.len);
    for (groups, items) |*group, item| {
        const rules = try query.elements(ec2.arena, item, &.{ "ipPermissions", "item" });
        const permissions = try ec2.arena.alloc(IpPermission, rules.len);
        for (permissions, rules) |*permission, rule| permission.* = .{
            .protocol = try query.decoded_text(ec2.arena, rule, &.{"ipProtocol"}) orelse "",
            .from_port = try port_at(rule, "fromPort"),
            .to_port = try port_at(rule, "toPort"),
            .cidrs = try query.texts(ec2.arena, rule, &.{ "ipRanges", "item", "cidrIp" }),
        };
        group.* = .{
            .id = try ec2.text(item, &.{"groupId"}),
            .name = try query.decoded_text(ec2.arena, item, &.{"groupName"}) orelse "",
            .ip_permissions = permissions,
        };
    }
    return groups;
}

fn port_at(rule: []const u8, comptime name: []const u8) Error!?i32 {
    const text = try query.first_text(rule, &.{name}) orelse return null;
    return std.fmt.parseInt(i32, text, 10) catch error.MalformedResponse;
}

/// Deletes a security group (commonware `delete_security_group`).
pub fn delete_security_group(ec2: *Ec2, sg_id: []const u8) Error!void {
    _ = try ec2.run("DeleteSecurityGroup", &.{.{ .name = "GroupId", .value = sg_id }});
}

fn find_by_tag(
    ec2: *Ec2,
    tag: []const u8,
    comptime action: []const u8,
    comptime set: []const u8,
    comptime id: []const u8,
) Error![]const []const u8 {
    var params = params_of(ec2);
    try params.filter(1, "tag:deployer", &.{tag});
    const xml = try ec2.run(action, params.list.items);
    return ids_at(ec2, xml, &.{ action ++ "Response", set, "item", id });
}

/// The route tables tagged `deployer={tag}` (commonware `find_route_tables_by_tag`).
pub fn find_route_tables_by_tag(ec2: *Ec2, tag: []const u8) Error![]const []const u8 {
    return find_by_tag(ec2, tag, "DescribeRouteTables", "routeTableSet", "routeTableId");
}

/// Deletes a route table (commonware `delete_route_table`).
pub fn delete_route_table(ec2: *Ec2, route_table_id: []const u8) Error!void {
    _ = try ec2.run("DeleteRouteTable", &.{.{ .name = "RouteTableId", .value = route_table_id }});
}

/// The Internet Gateways tagged `deployer={tag}` (commonware `find_igws_by_tag`).
pub fn find_igws_by_tag(ec2: *Ec2, tag: []const u8) Error![]const []const u8 {
    return find_by_tag(
        ec2,
        tag,
        "DescribeInternetGateways",
        "internetGatewaySet",
        "internetGatewayId",
    );
}

/// The VPC an Internet Gateway is attached to, if any (commonware `find_vpc_by_igw`).
pub fn find_vpc_by_igw(ec2: *Ec2, igw_id: []const u8) Error!?[]const u8 {
    const xml = try ec2.run("DescribeInternetGateways", &.{
        .{ .name = "InternetGatewayId.1", .value = igw_id },
    });
    const vpcs = try query.texts(ec2.arena, xml, &.{
        "DescribeInternetGatewaysResponse", "internetGatewaySet", "item", "attachmentSet",
        "item",                             "vpcId",
    });
    return if (vpcs.len == 0) null else vpcs[0];
}

/// The regions enabled for the account (commonware `get_enabled_regions`), sorted.
pub fn get_enabled_regions(ec2: *Ec2) Error![]const []const u8 {
    var params = params_of(ec2);
    try params.add("AllRegions", "true");
    try params.filter(1, "opt-in-status", &.{ "opt-in-not-required", "opted-in" });
    const xml = try ec2.run("DescribeRegions", params.list.items);
    const regions = try query.texts(ec2.arena, xml, &.{
        "DescribeRegionsResponse", "regionInfo", "item", "regionName",
    });
    const sorted = try ec2.arena.dupe([]const u8, regions);
    std.sort.pdq([]const u8, sorted, {}, less_than_string);
    return sorted;
}

fn less_than_string(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// Detaches an Internet Gateway from a VPC (commonware `detach_igw`).
pub fn detach_igw(ec2: *Ec2, igw_id: []const u8, vpc_id: []const u8) Error!void {
    _ = try ec2.run("DetachInternetGateway", &.{
        .{ .name = "InternetGatewayId", .value = igw_id },
        .{ .name = "VpcId", .value = vpc_id },
    });
}

/// Deletes an Internet Gateway (commonware `delete_igw`).
pub fn delete_igw(ec2: *Ec2, igw_id: []const u8) Error!void {
    _ = try ec2.run("DeleteInternetGateway", &.{.{ .name = "InternetGatewayId", .value = igw_id }});
}

/// The subnets tagged `deployer={tag}` (commonware `find_subnets_by_tag`).
pub fn find_subnets_by_tag(ec2: *Ec2, tag: []const u8) Error![]const []const u8 {
    return find_by_tag(ec2, tag, "DescribeSubnets", "subnetSet", "subnetId");
}

/// Deletes a subnet (commonware `delete_subnet`).
pub fn delete_subnet(ec2: *Ec2, subnet_id: []const u8) Error!void {
    _ = try ec2.run("DeleteSubnet", &.{.{ .name = "SubnetId", .value = subnet_id }});
}

/// The VPCs tagged `deployer={tag}` (commonware `find_vpcs_by_tag`).
pub fn find_vpcs_by_tag(ec2: *Ec2, tag: []const u8) Error![]const []const u8 {
    return find_by_tag(ec2, tag, "DescribeVpcs", "vpcSet", "vpcId");
}

/// Deletes a VPC (commonware `delete_vpc`).
pub fn delete_vpc(ec2: *Ec2, vpc_id: []const u8) Error!void {
    _ = try ec2.run("DeleteVpc", &.{.{ .name = "VpcId", .value = vpc_id }});
}

/// For each availability zone offering any of `instance_types`, which of them it offers,
/// both sorted (commonware `find_az_instance_support`'s `BTreeMap<_, BTreeSet<_>>`).
pub fn find_az_instance_support(
    ec2: *Ec2,
    instance_types: []const []const u8,
) Error![]const create.AzSupport {
    var params = params_of(ec2);
    try params.add("LocationType", "availability-zone");
    try params.filter(1, "instance-type", instance_types);
    const xml = try ec2.run("DescribeInstanceTypeOfferings", params.list.items);
    const offerings = try query.elements(ec2.arena, xml, &.{
        "DescribeInstanceTypeOfferingsResponse", "instanceTypeOfferingSet", "item",
    });
    var support: std.ArrayList(create.AzSupport) = .empty;
    for (offerings) |offering| {
        const az = try query.decoded_text(ec2.arena, offering, &.{"location"}) orelse continue;
        const instance_type =
            try query.decoded_text(ec2.arena, offering, &.{"instanceType"}) orelse continue;
        const entry = for (support.items) |*entry| {
            if (std.mem.eql(u8, entry.az, az)) break entry;
        } else blk: {
            try support.append(ec2.arena, .{ .az = az, .instance_types = &.{} });
            break :blk &support.items[support.items.len - 1];
        };
        if (contains(entry.instance_types, instance_type)) continue;
        const types = try ec2.arena.alloc([]const u8, entry.instance_types.len + 1);
        @memcpy(types[0..entry.instance_types.len], entry.instance_types);
        types[entry.instance_types.len] = instance_type;
        std.sort.pdq([]const u8, types, {}, less_than_string);
        entry.instance_types = types;
    }
    if (support.items.len == 0) return error.NoAvailabilityZone;
    std.sort.pdq(create.AzSupport, support.items, {}, struct {
        fn less(_: void, a: create.AzSupport, b: create.AzSupport) bool {
            return less_than_string({}, a.az, b.az);
        }
    }.less);
    return support.items;
}

fn contains(items: []const []const u8, wanted: []const u8) bool {
    for (items) |item| if (std.mem.eql(u8, item, wanted)) return true;
    return false;
}

/// Waits until no network interface uses the security group (commonware
/// `wait_for_enis_deleted`).
pub fn wait_for_enis_deleted(ec2: *Ec2, sg_id: []const u8) Error!void {
    var params = params_of(ec2);
    try params.filter(1, "group-id", &.{sg_id});
    while (true) {
        const xml = try ec2.run("DescribeNetworkInterfaces", params.list.items);
        const interfaces = try query.elements(ec2.arena, xml, &.{
            "DescribeNetworkInterfacesResponse", "networkInterfaceSet", "item",
        });
        if (interfaces.len == 0) return;
        try ec2.sleep(poll_interval_ms);
    }
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("ec2_api_test.zig");
}
