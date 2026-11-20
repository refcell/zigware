//! commonware's `destroy` against a temporary home and scripted responses per endpoint (the
//! regions run concurrently), never against AWS.

const std = @import("std");
const testing = std.testing;
const client_module = @import("client.zig");
const destroy = @import("destroy.zig");
const Session = @import("session.zig").Session;

const Home = @import("commands_test.zig").Home;
const Outcome = client_module.Outcome;
const Route = client_module.RoutedReplay.Route;

fn ok(body: []const u8) Outcome {
    return .{ .response = .{ .status = 200, .body = body } };
}

const done = ok("<Response/>");

fn none(comptime action: []const u8, comptime set: []const u8) Outcome {
    return ok("<" ++ action ++ "Response><" ++ set ++ "/></" ++ action ++ "Response>");
}

const Harness = struct {
    home: Home,
    replay: client_module.RoutedReplay,
    session: Session,

    fn init(harness: *Harness, routes: []Route) !void {
        harness.home = .init(true); // Skipped cleanups and failed revokes log warnings.
        const arena = harness.home.arena();
        harness.replay = .{ .routes = routes, .allocator = arena };
        harness.session = try harness.home.session(harness.replay.transport());
    }

    fn deinit(harness: *Harness) void {
        harness.home.deinit();
    }
};

const config_yaml =
    \\tag: t
    \\monitoring:
    \\  instance_type: c7g.medium
    \\  storage_size: 10
    \\  storage_class: gp3
    \\  dashboard: dashboard.json
    \\instances:
    \\- name: node0
    \\  region: us-west-2
    \\  instance_type: c7g.medium
    \\  storage_size: 10
    \\  storage_class: gp3
    \\  binary: bin
    \\  config: conf
    \\  profiling: false
    \\ports: []
    \\
;

const instances_set = "<DescribeInstancesResponse><reservationSet><item><instancesSet><item>" ++
    "<instanceId>i-1</instanceId><instanceState><name>{s}</name></instanceState></item>" ++
    "</instancesSet></item></reservationSet></DescribeInstancesResponse>";
const groups_set = "<DescribeSecurityGroupsResponse><securityGroupInfo>" ++
    "<item><groupId>sg-m</groupId><groupName>t</groupName></item>" ++
    "<item><groupId>sg-b</groupId><groupName>t-binary</groupName></item>" ++
    "</securityGroupInfo></DescribeSecurityGroupsResponse>";

const monitoring_script = [_]Outcome{
    ok(std.fmt.comptimePrint(instances_set, .{"running"})),
    done, // TerminateInstances
    ok(std.fmt.comptimePrint(instances_set, .{"terminated"})),
    ok(groups_set),
    done, // Revoke logs
    .{ .response = .{ .status = 400, .body = "<Response><Errors><Error><Code>" ++
        "InvalidPermission.NotFound</Code></Error></Errors></Response>" } }, // Revoke profiles
    done, // Revoke traces
    ok(groups_set),
    none("DescribeNetworkInterfaces", "networkInterfaceSet"),
    done, // DeleteSecurityGroup sg-m
    none("DescribeNetworkInterfaces", "networkInterfaceSet"),
    done, // DeleteSecurityGroup sg-b
    ok("<DescribeSubnetsResponse><subnetSet><item><subnetId>subnet-1</subnetId></item>" ++
        "</subnetSet></DescribeSubnetsResponse>"),
    done, // DeleteSubnet
    none("DescribeRouteTables", "routeTableSet"),
    none("DescribeVpcPeeringConnections", "vpcPeeringConnectionSet"),
    ok("<DescribeInternetGatewaysResponse><internetGatewaySet><item><internetGatewayId>igw-1" ++
        "</internetGatewayId></item></internetGatewaySet></DescribeInternetGatewaysResponse>"),
    ok("<DescribeInternetGatewaysResponse><internetGatewaySet><item><attachmentSet><item>" ++
        "<vpcId>vpc-1</vpcId></item></attachmentSet></item></internetGatewaySet>" ++
        "</DescribeInternetGatewaysResponse>"),
    done, // DetachInternetGateway
    done, // DeleteInternetGateway
    done, // DeleteKeyPair
    ok("<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-1</vpcId></item></vpcSet>" ++
        "</DescribeVpcsResponse>"),
    done, // DeleteVpc
};

const quiet_script = [_]Outcome{
    none("DescribeInstances", "reservationSet"),
    none("DescribeSecurityGroups", "securityGroupInfo"),
    none("DescribeSecurityGroups", "securityGroupInfo"),
    none("DescribeSubnets", "subnetSet"),
    none("DescribeRouteTables", "routeTableSet"),
    none("DescribeVpcPeeringConnections", "vpcPeeringConnectionSet"),
    none("DescribeInternetGateways", "internetGatewaySet"),
    done, // DeleteKeyPair
    none("DescribeVpcs", "vpcSet"),
};

fn action_of(request: client_module.Request) []const u8 {
    const start = "Action=".len;
    const end = std.mem.indexOfScalarPos(u8, request.body, start, '&').?;
    return request.body[start..end];
}

test "destroy: tears down every region, then marks the deployment destroyed" {
    var east: [32]client_module.Request = undefined;
    var west: [16]client_module.Request = undefined;
    var bucket: [4]client_module.Request = undefined;
    var routes = [_]Route{
        .{
            .host = "ec2.us-east-1.amazonaws.com",
            .outcomes = &monitoring_script,
            .requests = &east,
        },
        .{ .host = "ec2.us-west-2.amazonaws.com", .outcomes = &quiet_script, .requests = &west },
        .{
            .host = "b.s3.us-east-1.amazonaws.com",
            .outcomes = &.{ok("<ListBucketResult/>")},
            .requests = &bucket,
        },
    };
    var harness: Harness = undefined;
    try harness.init(&routes);
    defer harness.deinit();
    try harness.home.write("t.yaml", config_yaml);
    try harness.home.write(".commonware_deployer/t/created", "");
    try harness.home.write(".commonware_deployer/bucket", "b");
    try destroy.destroy(&harness.session, .{ .config = try harness.home.path("t.yaml") });
    try testing.expect(harness.home.exists(".commonware_deployer/t/destroyed"));

    const sent = routes[0].recorded();
    try testing.expectEqual(monitoring_script.len, sent.len);
    try testing.expectEqualStrings(
        "Action=RevokeSecurityGroupIngress&Version=2016-11-15&GroupId=sg-m" ++
            "&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=3100" ++
            "&IpPermissions.1.ToPort=3100&IpPermissions.1.Groups.1.GroupId=sg-b",
        sent[4].body,
    );
    try testing.expectEqualStrings("DeleteKeyPair", action_of(sent[20]));
    try testing.expect(std.mem.endsWith(u8, sent[20].body, "&KeyName=deployer-t"));
    try testing.expectEqualStrings("DeleteVpc", action_of(sent[22]));
    try testing.expectEqual(quiet_script.len, routes[1].recorded().len);
    const listed = routes[2].recorded()[0].path;
    try testing.expectEqualStrings("/?list-type=2&prefix=deployments%2Ft%2F", listed);
}

test "destroy: by tag reads the regions from the metadata" {
    var west: [16]client_module.Request = undefined;
    var routes = [_]Route{
        .{ .host = "ec2.us-west-2.amazonaws.com", .outcomes = &quiet_script, .requests = &west },
    };
    var harness: Harness = undefined;
    try harness.init(&routes);
    defer harness.deinit();
    try testing.expectError(error.Failed, destroy.destroy(&harness.session, .{ .tag = "t" }));
    try testing.expectEqualStrings("t", harness.session.failure.?.metadata_not_found);
    try harness.home.write(
        ".commonware_deployer/t/metadata.yaml",
        "tag: t\ncreated_at: 1\nregions:\n- us-west-2\ninstance_count: 1\n",
    );
    try destroy.destroy(&harness.session, .{ .tag = "t" });
    try testing.expectEqual(quiet_script.len, routes[0].recorded().len);
    // Already destroyed: nothing is asked of AWS again.
    try destroy.destroy(&harness.session, .{ .tag = "t" });
    try testing.expectEqual(quiet_script.len, routes[0].count.load(.acquire));
}

test "destroy: a refused region fails the command and leaves no destroyed marker" {
    var east: [32]client_module.Request = undefined;
    var west: [16]client_module.Request = undefined;
    var routes = [_]Route{
        .{ .host = "ec2.us-east-1.amazonaws.com", .outcomes = &quiet_script, .requests = &east },
        .{
            .host = "ec2.us-west-2.amazonaws.com",
            .outcomes = &.{.{ .response = .{ .status = 403, .body = "<Response><Errors><Error>" ++
                "<Code>UnauthorizedOperation</Code></Error></Errors></Response>" } }},
            .requests = &west,
        },
    };
    var harness: Harness = undefined;
    try harness.init(&routes);
    defer harness.deinit();
    try harness.home.write("t.yaml", config_yaml);
    try harness.home.write(".commonware_deployer/t/created", "");
    const target: destroy.Target = .{ .config = try harness.home.path("t.yaml") };
    try testing.expectError(error.Failed, destroy.destroy(&harness.session, target));
    const failure = harness.session.failure.?.aws_ec2;
    try testing.expectEqualStrings("UnauthorizedOperation", failure.service_code().?);
    try testing.expect(!harness.home.exists(".commonware_deployer/t/destroyed"));
}
