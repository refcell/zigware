//! The EC2 calls against scripted EC2 Query responses (never AWS): the parameters each call
//! sends and how each reads its response.

const std = @import("std");
const testing = std.testing;
const client_module = @import("client.zig");
const api = @import("ec2_api.zig");

const Outcome = client_module.Outcome;

fn ok(body: []const u8) Outcome {
    return .{ .response = .{ .status = 200, .body = body } };
}

fn ec2_error(status: u16, comptime code: []const u8) Outcome {
    return .{ .response = .{
        .status = status,
        .body = "<Response><Errors><Error><Code>" ++ code ++
            "</Code><Message>m</Message></Error></Errors></Response>",
    } };
}

const Harness = struct {
    arena_state: std.heap.ArenaAllocator,
    requests: [16]client_module.Request = undefined,
    replay: client_module.Replay,
    client: client_module.Client,
    ec2: api.Ec2,

    fn init(harness: *Harness, outcomes: []const Outcome) void {
        harness.arena_state = .init(testing.allocator);
        const arena = harness.arena_state.allocator();
        harness.replay = .{
            .outcomes = outcomes,
            .requests = &harness.requests,
            .allocator = arena,
        };
        harness.client = .{
            .io = testing.io,
            .transport = harness.replay.transport(),
            .credentials = .{ .access_key_id = "access-key", .secret_access_key = "secret-key" },
            .region = "us-east-1",
        };
        harness.ec2 = .{ .client = &harness.client, .arena = arena };
    }

    fn deinit(harness: *Harness) void {
        harness.arena_state.deinit();
    }

    /// The body of request `index`, which must have been sent.
    fn body(harness: *const Harness, index: usize) []const u8 {
        return harness.replay.recorded()[index].body;
    }
};

fn expect_contains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

test "ec2 api: key pairs send the base64 public key" {
    var harness: Harness = undefined;
    harness.init(&.{ ok("<ImportKeyPairResponse/>"), ok("<DeleteKeyPairResponse/>") });
    defer harness.deinit();
    try api.import_key_pair(&harness.ec2, "deployer-t", "ssh-ed25519 AAAA");
    try testing.expectEqualStrings(
        "Action=ImportKeyPair&Version=2016-11-15&KeyName=deployer-t" ++
            "&PublicKeyMaterial=c3NoLWVkMjU1MTkgQUFBQQ%3D%3D",
        harness.body(0),
    );
    try api.delete_key_pair(&harness.ec2, "deployer-t");
    try expect_contains(harness.body(1), "Action=DeleteKeyPair");
}

fn storage(comptime supported: []const u8, comptime nvme: []const u8) []const u8 {
    return "<item><instanceStorageSupported>" ++ supported ++ "</instanceStorageSupported>" ++
        "<instanceStorageInfo><nvmeSupport>" ++ nvme ++ "</nvmeSupport>" ++
        "</instanceStorageInfo></item>";
}

fn instance_type_response(comptime item: []const u8) []const u8 {
    return "<DescribeInstanceTypesResponse><instanceTypeSet>" ++ item ++
        "</instanceTypeSet></DescribeInstanceTypesResponse>";
}

test "ec2 api: instance type architecture and NVMe storage" {
    var harness: Harness = undefined;
    harness.init(&.{
        ok(instance_type_response("<item><processorInfo><supportedArchitectures>" ++
            "<item>arm64</item></supportedArchitectures></processorInfo></item>")),
        ok(instance_type_response(
            \\<item><processorInfo><supportedArchitectures>
            \\<item>i386</item><item>x86_64</item></supportedArchitectures></processorInfo></item>
        )),
        ok(instance_type_response("")),
        ok(instance_type_response("<item><processorInfo/></item>")),
        ok(instance_type_response(storage("true", "required"))),
        ok(instance_type_response(storage("false", "required"))),
        ok(instance_type_response(storage("true", "unsupported"))),
    });
    defer harness.deinit();
    const ec2 = &harness.ec2;
    try testing.expectEqual(.arm64, try api.detect_architecture(ec2, "c7g.large"));
    try testing.expectEqualStrings(
        "Action=DescribeInstanceTypes&Version=2016-11-15&InstanceType.1=c7g.large",
        harness.body(0),
    );
    try testing.expectEqual(.x86_64, try api.detect_architecture(ec2, "c7i.large"));
    try testing.expectError(error.InstanceTypeNotFound, api.detect_architecture(ec2, "x"));
    try testing.expectError(error.NoSupportedArchitecture, api.detect_architecture(ec2, "x"));
    try testing.expect(try api.supports_nvme_instance_storage(ec2, "i4i.large"));
    try testing.expect(!try api.supports_nvme_instance_storage(ec2, "c7i.large"));
    try testing.expect(!try api.supports_nvme_instance_storage(ec2, "c7i.large"));
}

test "ec2 api: find_latest_ami picks the newest Ubuntu image" {
    var harness: Harness = undefined;
    harness.init(&.{
        ok(
            \\<DescribeImagesResponse><imagesSet>
            \\<item><imageId>ami-old</imageId><creationDate>2024-05-01T00:00:00.000Z</creationDate></item>
            \\<item><imageId>ami-new</imageId><creationDate>2025-01-02T00:00:00.000Z</creationDate></item>
            \\<item><imageId>ami-mid</imageId><creationDate>2024-12-31T23:59:59.000Z</creationDate></item>
            \\</imagesSet></DescribeImagesResponse>
        ),
        ok("<DescribeImagesResponse><imagesSet/></DescribeImagesResponse>"),
    });
    defer harness.deinit();
    try testing.expectEqualStrings("ami-new", try api.find_latest_ami(&harness.ec2, .arm64));
    try testing.expectEqualStrings(
        "Action=DescribeImages&Version=2016-11-15&Filter.1.Name=name" ++
            "&Filter.1.Value.1=ubuntu%2Fimages%2Fhvm-ssd-gp3" ++
            "%2Fubuntu-noble-24.04-arm64-server-%2A" ++
            "&Filter.2.Name=root-device-type&Filter.2.Value.1=ebs&Owner.1=099720109477",
        harness.body(0),
    );
    try testing.expectError(error.NoMatchingAmi, api.find_latest_ami(&harness.ec2, .x86_64));
}

test "ec2 api: networking resources are created, tagged, and wired" {
    var harness: Harness = undefined;
    harness.init(&.{
        ok("<CreateVpcResponse><vpc><vpcId>vpc-1</vpcId></vpc></CreateVpcResponse>"),
        ok("<CreateInternetGatewayResponse><internetGateway><internetGatewayId>igw-1" ++
            "</internetGatewayId></internetGateway></CreateInternetGatewayResponse>"),
        ok("<AttachInternetGatewayResponse/>"),
        ok("<CreateRouteTableResponse><routeTable><routeTableId>rtb-1</routeTableId>" ++
            "</routeTable></CreateRouteTableResponse>"),
        ok("<CreateRouteResponse/>"),
        ok("<CreateSubnetResponse><subnet><subnetId>subnet-1</subnetId></subnet>" ++
            "</CreateSubnetResponse>"),
        ok("<AssociateRouteTableResponse/>"),
    });
    defer harness.deinit();
    const ec2 = &harness.ec2;
    try testing.expectEqualStrings("vpc-1", try api.create_vpc(ec2, "10.0.0.0/16", "t"));
    try testing.expectEqualStrings(
        "Action=CreateVpc&Version=2016-11-15&CidrBlock=10.0.0.0%2F16" ++
            "&TagSpecification.1.ResourceType=vpc&TagSpecification.1.Tag.1.Key=deployer" ++
            "&TagSpecification.1.Tag.1.Value=t",
        harness.body(0),
    );
    try testing.expectEqualStrings("igw-1", try api.create_and_attach_igw(ec2, "vpc-1", "t"));
    try testing.expectEqualStrings(
        "Action=AttachInternetGateway&Version=2016-11-15&InternetGatewayId=igw-1&VpcId=vpc-1",
        harness.body(2),
    );
    try testing.expectEqualStrings("rtb-1", try api.create_route_table(ec2, "vpc-1", "igw-1", "t"));
    try testing.expectEqualStrings(
        "Action=CreateRoute&Version=2016-11-15&RouteTableId=rtb-1" ++
            "&DestinationCidrBlock=0.0.0.0%2F0&GatewayId=igw-1",
        harness.body(4),
    );
    const subnet = try api.create_subnet(ec2, "vpc-1", "rtb-1", "10.0.1.0/24", "us-east-1a", "t");
    try testing.expectEqualStrings("subnet-1", subnet);
    try expect_contains(harness.body(5), "&AvailabilityZone=us-east-1a&");
    try testing.expectEqualStrings(
        "Action=AssociateRouteTable&Version=2016-11-15&RouteTableId=rtb-1&SubnetId=subnet-1",
        harness.body(6),
    );
}

test "ec2 api: security groups open the deployer, configured, and monitoring ports" {
    const created = ok("<CreateSecurityGroupResponse><return>true</return>" ++
        "<groupId>sg-1</groupId></CreateSecurityGroupResponse>");
    const authorized = ok("<AuthorizeSecurityGroupIngressResponse/>");
    var harness: Harness = undefined;
    harness.init(&.{ created, authorized, created, authorized, authorized });
    defer harness.deinit();
    const ec2 = &harness.ec2;
    try testing.expectEqualStrings(
        "sg-1",
        try api.create_security_group_monitoring(ec2, "vpc-1", "1.2.3.4", "t"),
    );
    try testing.expectEqualStrings(
        "Action=CreateSecurityGroup&Version=2016-11-15&GroupName=t" ++
            "&GroupDescription=Security%20group%20for%20monitoring%20instance&VpcId=vpc-1" ++
            "&TagSpecification.1.ResourceType=security-group" ++
            "&TagSpecification.1.Tag.1.Key=deployer&TagSpecification.1.Tag.1.Value=t",
        harness.body(0),
    );
    try testing.expectEqualStrings(
        "Action=AuthorizeSecurityGroupIngress&Version=2016-11-15&GroupId=sg-1" ++
            "&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=0" ++
            "&IpPermissions.1.ToPort=65535&IpPermissions.1.IpRanges.1.CidrIp=1.2.3.4%2F32",
        harness.body(1),
    );
    const ports = [_]@import("mod.zig").PortConfig{
        .{ .protocol = "udp", .port = 4545, .cidr = "0.0.0.0/0" },
    };
    _ = try api.create_security_group_binary(ec2, "vpc-1", "1.2.3.4", "t", &ports);
    try expect_contains(harness.body(2), "&GroupName=t-binary&");
    try expect_contains(harness.body(3), "&IpPermissions.2.IpProtocol=udp" ++
        "&IpPermissions.2.FromPort=4545&IpPermissions.2.ToPort=4545" ++
        "&IpPermissions.2.IpRanges.1.CidrIp=0.0.0.0%2F0");
    try api.add_monitoring_ingress(ec2, "sg-2", "10.0.0.5");
    try testing.expectEqualStrings(
        "Action=AuthorizeSecurityGroupIngress&Version=2016-11-15&GroupId=sg-2" ++
            "&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=9090" ++
            "&IpPermissions.1.ToPort=9090&IpPermissions.1.IpRanges.1.CidrIp=10.0.0.5%2F32" ++
            "&IpPermissions.2.IpProtocol=tcp&IpPermissions.2.FromPort=9100" ++
            "&IpPermissions.2.ToPort=9100&IpPermissions.2.IpRanges.1.CidrIp=10.0.0.5%2F32",
        harness.body(4),
    );
}

fn instances_response(comptime instances: []const u8) []const u8 {
    return "<DescribeInstancesResponse><reservationSet><item><instancesSet>" ++ instances ++
        "</instancesSet></item></reservationSet></DescribeInstancesResponse>";
}

fn instance(
    comptime id: []const u8,
    comptime state: []const u8,
    comptime ip: []const u8,
) []const u8 {
    return "<item><instanceId>" ++ id ++ "</instanceId><instanceState><code>0</code><name>" ++
        state ++ "</name></instanceState><privateIpAddress>10.0.0.9</privateIpAddress>" ++ ip ++
        "</item>";
}

test "ec2 api: wait_for_instances_running asks only about pending instances" {
    var harness: Harness = undefined;
    harness.init(&.{
        ok(instances_response(instance("i-1", "pending", "") ++
            instance("i-2", "running", "<ipAddress>5.6.7.8</ipAddress>"))),
        ec2_error(400, "InvalidInstanceID.NotFound"), // Retried after the poll interval.
        ok(instances_response(instance("i-1", "running", ""))), // No public IP yet.
        ok(instances_response(instance("i-1", "running", "<ipAddress>1.2.3.4</ipAddress>"))),
    });
    defer harness.deinit();
    const ips = try api.wait_for_instances_running(&harness.ec2, &.{ "i-1", "i-2" });
    try testing.expectEqual(@as(usize, 2), ips.len);
    try testing.expectEqualStrings("1.2.3.4", ips[0]);
    try testing.expectEqualStrings("5.6.7.8", ips[1]);
    try testing.expectEqualStrings(
        "Action=DescribeInstances&Version=2016-11-15&InstanceId.1=i-1&InstanceId.2=i-2",
        harness.body(0),
    );
    try testing.expectEqualStrings(
        "Action=DescribeInstances&Version=2016-11-15&InstanceId.1=i-1",
        harness.body(3),
    );
}

test "ec2 api: instance status, private IP, termination, and lookup by tag" {
    const status = "<DescribeInstanceStatusResponse><instanceStatusSet><item>" ++
        "<instanceState><name>running</name></instanceState>" ++
        "<systemStatus><status>ok</status></systemStatus>" ++
        "<instanceStatus><status>{s}</status></instanceStatus>" ++
        "</item></instanceStatusSet></DescribeInstanceStatusResponse>";
    var harness: Harness = undefined;
    harness.init(&.{
        ok(comptime std.fmt.comptimePrint(status, .{"initializing"})),
        ok(comptime std.fmt.comptimePrint(status, .{"ok"})),
        ok(instances_response(instance("i-1", "running", ""))),
        ok("<TerminateInstancesResponse/>"),
        ok(instances_response(instance("i-1", "shutting-down", ""))),
        ok(instances_response(instance("i-1", "terminated", ""))),
        ok(instances_response(instance("i-1", "running", "") ++ instance("i-2", "stopped", ""))),
    });
    defer harness.deinit();
    const ec2 = &harness.ec2;
    try api.wait_for_instances_ready(ec2, &.{"i-1"});
    try testing.expectEqualStrings(
        "Action=DescribeInstanceStatus&Version=2016-11-15&InstanceId.1=i-1" ++
            "&IncludeAllInstances=true",
        harness.body(1),
    );
    try testing.expectEqualStrings("10.0.0.9", try api.get_private_ip(ec2, "i-1"));
    try api.terminate_instances(ec2, &.{}); // Nothing to terminate: no request.
    try api.terminate_instances(ec2, &.{"i-1"});
    try api.wait_for_instances_terminated(ec2, &.{"i-1"});
    const found = try api.find_instances_by_tag(ec2, "t");
    try testing.expectEqual(@as(usize, 2), found.len);
    try testing.expectEqualStrings("i-2", found[1]);
    try testing.expectEqualStrings(
        "Action=DescribeInstances&Version=2016-11-15&Filter.1.Name=tag%3Adeployer" ++
            "&Filter.1.Value.1=t",
        harness.body(6),
    );
    try testing.expectEqual(@as(usize, 7), harness.replay.count);
}

fn peering(comptime code: []const u8) Outcome {
    return ok("<DescribeVpcPeeringConnectionsResponse><vpcPeeringConnectionSet><item>" ++
        "<vpcPeeringConnectionId>pcx-1</vpcPeeringConnectionId><status><code>" ++ code ++
        "</code></status></item></vpcPeeringConnectionSet>" ++
        "</DescribeVpcPeeringConnectionsResponse>");
}

test "ec2 api: VPC peering waits on its status" {
    var harness: Harness = undefined;
    harness.init(&.{
        ok("<CreateVpcPeeringConnectionResponse><vpcPeeringConnection><vpcPeeringConnectionId>" ++
            "pcx-1</vpcPeeringConnectionId></vpcPeeringConnection>" ++
            "</CreateVpcPeeringConnectionResponse>"),
        peering("initiating-request"),
        ec2_error(400, "InvalidVpcPeeringConnectionID.NotFound"), // Not visible yet: retried.
        peering("pending-acceptance"),
        peering("deleting"),
        peering("deleted"),
        ok("<DescribeVpcPeeringConnectionsResponse><vpcPeeringConnectionSet/>" ++
            "</DescribeVpcPeeringConnectionsResponse>"),
    });
    defer harness.deinit();
    const ec2 = &harness.ec2;
    const peer = try api.create_vpc_peering_connection(ec2, "vpc-1", "vpc-2", "eu-west-1", "t");
    try testing.expectEqualStrings("pcx-1", peer);
    try expect_contains(harness.body(0), "&VpcId=vpc-1&PeerVpcId=vpc-2&PeerRegion=eu-west-1&");
    try api.wait_for_vpc_peering_connection(ec2, peer);
    try testing.expectEqual(@as(usize, 4), harness.replay.count);
    try api.wait_for_vpc_peering_deletion(ec2, peer);
    try testing.expectEqual(@as(usize, 6), harness.replay.count);
    try api.wait_for_vpc_peering_deletion(ec2, peer); // No longer listed.
}

test "ec2 api: security groups read their ingress rules" {
    var harness: Harness = undefined;
    harness.init(&.{ok("<DescribeSecurityGroupsResponse><securityGroupInfo><item>" ++
        "<groupId>sg-1</groupId><groupName>t</groupName><ipPermissions>" ++
        "<item><ipProtocol>tcp</ipProtocol><fromPort>0</fromPort><toPort>65535</toPort>" ++
        "<ipRanges><item><cidrIp>1.2.3.4/32</cidrIp></item><item><cidrIp>5.6.7.8/32</cidrIp>" ++
        "</item></ipRanges></item><item><ipProtocol>-1</ipProtocol><ipRanges/></item>" ++
        "</ipPermissions></item></securityGroupInfo></DescribeSecurityGroupsResponse>")});
    defer harness.deinit();
    const groups = try api.find_security_groups_by_tag(&harness.ec2, "t");
    try testing.expectEqual(@as(usize, 1), groups.len);
    try testing.expectEqualStrings("sg-1", groups[0].id);
    const rules = groups[0].ip_permissions;
    try testing.expectEqual(@as(usize, 2), rules.len);
    try testing.expectEqual(@as(?i32, 65535), rules[0].to_port);
    try testing.expectEqualStrings("5.6.7.8/32", rules[0].cidrs[1]);
    try testing.expectEqualStrings("-1", rules[1].protocol);
    try testing.expectEqual(@as(?i32, null), rules[1].from_port);
}

test "ec2 api: AZ support, enabled regions, and gateway attachments" {
    var harness: Harness = undefined;
    harness.init(&.{
        ok("<DescribeInstanceTypeOfferingsResponse><instanceTypeOfferingSet>" ++
            "<item><instanceType>c7i.large</instanceType><location>us-east-1b</location></item>" ++
            "<item><instanceType>c7g.large</instanceType><location>us-east-1a</location></item>" ++
            "<item><instanceType>c7i.large</instanceType><location>us-east-1a</location></item>" ++
            "<item><instanceType>c7i.large</instanceType><location>us-east-1a</location></item>" ++
            "</instanceTypeOfferingSet></DescribeInstanceTypeOfferingsResponse>"),
        ok("<DescribeInstanceTypeOfferingsResponse><instanceTypeOfferingSet/>" ++
            "</DescribeInstanceTypeOfferingsResponse>"),
        ok(
            \\<DescribeRegionsResponse><regionInfo><item><regionName>us-west-2</regionName></item>
            \\<item><regionName>eu-west-1</regionName></item></regionInfo></DescribeRegionsResponse>
        ),
        ok("<DescribeInternetGatewaysResponse><internetGatewaySet><item><attachmentSet/></item>" ++
            "</internetGatewaySet></DescribeInternetGatewaysResponse>"),
        ok("<DescribeInternetGatewaysResponse><internetGatewaySet><item><attachmentSet><item>" ++
            "<vpcId>vpc-9</vpcId><state>available</state></item></attachmentSet></item>" ++
            "</internetGatewaySet></DescribeInternetGatewaysResponse>"),
    });
    defer harness.deinit();
    const ec2 = &harness.ec2;
    const support = try api.find_az_instance_support(ec2, &.{ "c7i.large", "c7g.large" });
    try testing.expectEqualStrings(
        "Action=DescribeInstanceTypeOfferings&Version=2016-11-15" ++
            "&LocationType=availability-zone&Filter.1.Name=instance-type" ++
            "&Filter.1.Value.1=c7i.large&Filter.1.Value.2=c7g.large",
        harness.body(0),
    );
    try testing.expectEqual(@as(usize, 2), support.len);
    try testing.expectEqualStrings("us-east-1a", support[0].az);
    try testing.expectEqual(@as(usize, 2), support[0].instance_types.len);
    try testing.expectEqualStrings("c7g.large", support[0].instance_types[0]);
    try testing.expectEqualStrings("c7i.large", support[0].instance_types[1]);
    try testing.expectEqualStrings("us-east-1b", support[1].az);
    try testing.expectError(error.NoAvailabilityZone, api.find_az_instance_support(ec2, &.{"x"}));
    const regions = try api.get_enabled_regions(ec2);
    try testing.expectEqualStrings("eu-west-1", regions[0]);
    try testing.expectEqualStrings("us-west-2", regions[1]);
    try expect_contains(harness.body(2), "&AllRegions=true&Filter.1.Name=opt-in-status" ++
        "&Filter.1.Value.1=opt-in-not-required&Filter.1.Value.2=opted-in");
    try testing.expectEqual(null, try api.find_vpc_by_igw(ec2, "igw-1"));
    try testing.expectEqualStrings("vpc-9", (try api.find_vpc_by_igw(ec2, "igw-1")).?);
}

test "ec2 api: refused calls keep their failure and are not retried" {
    var harness: Harness = undefined;
    harness.init(&.{ ec2_error(403, "UnauthorizedOperation"), ec2_error(503, "Unavailable") });
    defer harness.deinit();
    try testing.expectError(error.AwsEc2, api.delete_vpc(&harness.ec2, "vpc-1"));
    try testing.expectEqualStrings("UnauthorizedOperation", harness.ec2.failure.?.service_code().?);
    try testing.expectEqual(@as(usize, 1), harness.replay.count);
    // A 503 is retried; the script then runs out, which is final.
    try testing.expectError(error.AwsEc2, api.delete_subnet(&harness.ec2, "subnet-1"));
    try testing.expectEqual(@as(usize, 3), harness.replay.count);
    try testing.expect(harness.ec2.failure.? == .dispatch);
}

test "ec2 api: teardown calls name their resources" {
    var harness: Harness = undefined;
    const done = ok("<Response/>");
    harness.init(&.{ done, done, done, done, done, done, done, done });
    defer harness.deinit();
    const ec2 = &harness.ec2;
    try api.delete_security_group(ec2, "sg-1");
    try api.delete_route_table(ec2, "rtb-1");
    try api.detach_igw(ec2, "igw-1", "vpc-1");
    try api.delete_igw(ec2, "igw-1");
    try api.delete_vpc_peering(ec2, "pcx-1");
    try api.accept_vpc_peering_connection(ec2, "pcx-1");
    try api.add_route(ec2, "rtb-1", "10.1.0.0/16", "pcx-1");
    try api.wait_for_enis_deleted(ec2, "sg-1");
    const expected = [_][]const u8{
        "Action=DeleteSecurityGroup&Version=2016-11-15&GroupId=sg-1",
        "Action=DeleteRouteTable&Version=2016-11-15&RouteTableId=rtb-1",
        "Action=DetachInternetGateway&Version=2016-11-15&InternetGatewayId=igw-1&VpcId=vpc-1",
        "Action=DeleteInternetGateway&Version=2016-11-15&InternetGatewayId=igw-1",
        "Action=DeleteVpcPeeringConnection&Version=2016-11-15&VpcPeeringConnectionId=pcx-1",
        "Action=AcceptVpcPeeringConnection&Version=2016-11-15&VpcPeeringConnectionId=pcx-1",
        "Action=CreateRoute&Version=2016-11-15&RouteTableId=rtb-1" ++
            "&DestinationCidrBlock=10.1.0.0%2F16&VpcPeeringConnectionId=pcx-1",
        "Action=DescribeNetworkInterfaces&Version=2016-11-15&Filter.1.Name=group-id" ++
            "&Filter.1.Value.1=sg-1",
    };
    for (expected, 0..) |body, index| try testing.expectEqualStrings(body, harness.body(index));
}

test "ec2 api: resources are found by their deployer tag" {
    var harness: Harness = undefined;
    harness.init(&.{
        ok("<DescribeVpcPeeringConnectionsResponse><vpcPeeringConnectionSet><item>" ++
            "<vpcPeeringConnectionId>pcx-1</vpcPeeringConnectionId></item>" ++
            "</vpcPeeringConnectionSet></DescribeVpcPeeringConnectionsResponse>"),
        ok("<DescribeRouteTablesResponse><routeTableSet><item><routeTableId>rtb-1</routeTableId>" ++
            "<routeSet><item><gatewayId>local</gatewayId></item></routeSet></item>" ++
            "</routeTableSet></DescribeRouteTablesResponse>"),
        ok("<DescribeInternetGatewaysResponse><internetGatewaySet><item><internetGatewayId>" ++
            "igw-1</internetGatewayId></item></internetGatewaySet>" ++
            "</DescribeInternetGatewaysResponse>"),
        ok("<DescribeSubnetsResponse><subnetSet><item><subnetId>subnet-1</subnetId></item>" ++
            "<item><subnetId>subnet-2</subnetId></item></subnetSet></DescribeSubnetsResponse>"),
        ok("<DescribeVpcsResponse><vpcSet/></DescribeVpcsResponse>"),
    });
    defer harness.deinit();
    const ec2 = &harness.ec2;
    try testing.expectEqualStrings("pcx-1", (try api.find_vpc_peering_by_tag(ec2, "t"))[0]);
    try testing.expectEqualStrings("rtb-1", (try api.find_route_tables_by_tag(ec2, "t"))[0]);
    try testing.expectEqualStrings("igw-1", (try api.find_igws_by_tag(ec2, "t"))[0]);
    try testing.expectEqual(@as(usize, 2), (try api.find_subnets_by_tag(ec2, "t")).len);
    try testing.expectEqual(@as(usize, 0), (try api.find_vpcs_by_tag(ec2, "t")).len);
    try testing.expectEqualStrings(
        "Action=DescribeRouteTables&Version=2016-11-15&Filter.1.Name=tag%3Adeployer" ++
            "&Filter.1.Value.1=t",
        harness.body(1),
    );
}
