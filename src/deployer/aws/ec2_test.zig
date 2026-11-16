//! commonware `deployer::aws::ec2`'s launch tests: `launch_instances` against scripted EC2
//! responses (commonware's `ReplayConnector`), never against AWS.

const std = @import("std");
const testing = std.testing;
const ec2 = @import("ec2.zig");
const client_module = @import("client.zig");
const create = @import("create.zig");
const aws = @import("mod.zig");

const capacity_error =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<Response><Errors><Error><Code>InsufficientInstanceCapacity</Code><Message>capacity unavailable</Message></Error></Errors><RequestID>request-id</RequestID></Response>
;
const subnet_error =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<Response><Errors><Error><Code>InsufficientFreeAddressesInSubnet</Code><Message>subnet unavailable</Message></Error></Errors><RequestID>request-id</RequestID></Response>
;
const transient_error =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<Response><Errors><Error><Code>InternalError</Code><Message>transient failure</Message></Error></Errors><RequestID>request-id</RequestID></Response>
;
const throttled_error =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<Response><Errors><Error><Code>RequestLimitExceeded</Code><Message>request limit exceeded</Message></Error></Errors><RequestID>request-id</RequestID></Response>
;
const unauthorized_error =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>not authorized</Message></Error></Errors><RequestID>request-id</RequestID></Response>
;
const opt_in_required_error =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<Response><Errors><Error><Code>OptInRequired</Code><Message>region is not enabled</Message></Error></Errors><RequestID>request-id</RequestID></Response>
;
const vcpu_limit_error =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<Response><Errors><Error><Code>VcpuLimitExceeded</Code><Message>quota exceeded</Message></Error></Errors><RequestID>request-id</RequestID></Response>
;
const launch_success =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<RunInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><instancesSet><item><instanceId>i-test</instanceId></item></instancesSet></RunInstancesResponse>
;

const Outcome = client_module.Outcome;

fn replay_response(status: u16, body: []const u8) Outcome {
    return .{ .response = .{ .status = status, .body = body } };
}

/// One scripted launch: the replay, the arena results live in, and the outcome.
const Harness = struct {
    arena_state: std.heap.ArenaAllocator,
    requests: [32]client_module.Request = undefined,
    bodies: [32][]const u8 = undefined,
    replay: client_module.Replay,

    fn init(harness: *Harness, outcomes: []const Outcome) void {
        std.debug.assert(outcomes.len <= harness.bodies.len);
        harness.arena_state = .init(testing.allocator);
        harness.replay = .{
            .outcomes = outcomes,
            .requests = &harness.requests,
            .allocator = harness.arena_state.allocator(),
        };
    }

    fn deinit(harness: *Harness) void {
        harness.arena_state.deinit();
    }

    fn launch(harness: *Harness, bandwidth_weighting: aws.BandwidthWeighting) !ec2.LaunchResult {
        const client: client_module.Client = .{
            .io = testing.io,
            .transport = harness.replay.transport(),
            .credentials = .{ .access_key_id = "access-key", .secret_access_key = "secret-key" },
            .region = "us-east-1",
        };
        const subnets = [_]create.Subnet{
            .{ .az = "us-east-1a", .id = "subnet-a" },
            .{ .az = "us-east-1b", .id = "subnet-b" },
        };
        const instance_type = "c8a.8xlarge";
        const az_support = [_]create.AzSupport{
            .{ .az = "us-east-1a", .instance_types = &.{instance_type} },
            .{ .az = "us-east-1b", .instance_types = &.{instance_type} },
        };
        const request: ec2.LaunchRequest = .{
            .ami_id = "ami-test",
            .instance_type = instance_type,
            .storage_size = 10,
            .storage_class = .gp3,
            .bandwidth_weighting = bandwidth_weighting,
            .key_name = "key-test",
            .sg_id = "sg-test",
            .count = 1,
            .name = "instance-test",
            .tag = "tag-test",
        };
        const quiet = testing.log_level;
        testing.log_level = .err; // Capacity failures log a warning.
        defer testing.log_level = quiet;
        return ec2.launch_instances(
            &client,
            testing.allocator,
            harness.arena_state.allocator(),
            &request,
            &subnets,
            &az_support,
            0,
        );
    }

    fn request_bodies(harness: *Harness) []const []const u8 {
        const requests = harness.replay.recorded();
        for (requests, 0..) |request, index| harness.bodies[index] = request.body;
        return harness.bodies[0..requests.len];
    }
};

fn client_token(request_body: []const u8) []const u8 {
    var fields = std.mem.splitScalar(u8, request_body, '&');
    while (fields.next()) |field| {
        if (std.mem.startsWith(u8, field, "ClientToken=")) return field["ClientToken=".len..];
    }
    @panic("RunInstances should carry a client token");
}

fn expect_launched(result: ec2.LaunchResult, az: []const u8) !void {
    const launched = switch (result) {
        .ok => |launched| launched,
        .failure => |failure| {
            std.debug.print("unexpected failure: {f}\n", .{failure});
            return error.TestUnexpectedResult;
        },
    };
    try testing.expectEqual(@as(usize, 1), launched.instance_ids.len);
    try testing.expectEqualStrings("i-test", launched.instance_ids[0]);
    try testing.expectEqualStrings(az, launched.az);
}

test "ec2: capacity retry revisits eligible subnets" {
    var harness: Harness = undefined;
    harness.init(&.{
        replay_response(400, capacity_error),
        replay_response(400, capacity_error),
        replay_response(200, launch_success),
    });
    defer harness.deinit();
    try expect_launched(try harness.launch(.default), "us-east-1a");
    try testing.expectEqual(@as(usize, 3), harness.replay.count);
}

test "ec2: default weighting leaves network performance options unset" {
    var harness: Harness = undefined;
    harness.init(&.{replay_response(200, launch_success)});
    defer harness.deinit();
    try expect_launched(try harness.launch(.default), "us-east-1a");
    // Instance types without configurable weighting reject the option, so the standard split
    // must be expressed by omitting it rather than by sending "default".
    const bodies = harness.request_bodies();
    try testing.expectEqual(@as(usize, 1), bodies.len);
    try testing.expect(std.mem.indexOf(u8, bodies[0], "BandwidthWeighting") == null);
}

test "ec2: vpc-1 weighting is sent as a network performance option" {
    var harness: Harness = undefined;
    harness.init(&.{replay_response(200, launch_success)});
    defer harness.deinit();
    try expect_launched(try harness.launch(.vpc_1), "us-east-1a");
    // The option travels in the RunInstances query body under its AWS name.
    const bodies = harness.request_bodies();
    try testing.expectEqual(@as(usize, 1), bodies.len);
    const option = "NetworkPerformanceOptions.BandwidthWeighting=vpc-1";
    try testing.expect(std.mem.indexOf(u8, bodies[0], option) != null);
}

test "ec2: the capacity scan owns RunInstances retries" {
    var harness: Harness = undefined;
    harness.init(&.{ replay_response(500, capacity_error), replay_response(200, launch_success) });
    defer harness.deinit();
    try expect_launched(try harness.launch(.default), "us-east-1b");
    try testing.expectEqual(@as(usize, 2), harness.replay.count);
    const bodies = harness.request_bodies();
    try testing.expect(!std.mem.eql(u8, client_token(bodies[0]), client_token(bodies[1])));
}

test "ec2: same-subnet retries reuse the client token" {
    var harness: Harness = undefined;
    harness.init(&.{ .io_failure, replay_response(200, launch_success) });
    defer harness.deinit();
    try expect_launched(try harness.launch(.default), "us-east-1a");
    const bodies = harness.request_bodies();
    try testing.expectEqual(@as(usize, 2), bodies.len);
    try testing.expectEqualStrings(client_token(bodies[0]), client_token(bodies[1]));
    try testing.expectEqual(@as(usize, 36), client_token(bodies[0]).len);
}

test "ec2: a transient connector failure retries the same request" {
    var harness: Harness = undefined;
    harness.init(&.{ .{ .other = .{ .transient = true } }, replay_response(200, launch_success) });
    defer harness.deinit();
    try expect_launched(try harness.launch(.default), "us-east-1a");
    const bodies = harness.request_bodies();
    try testing.expectEqual(@as(usize, 2), bodies.len);
    try testing.expectEqualStrings(client_token(bodies[0]), client_token(bodies[1]));
}

fn expect_fails_after_one_request(outcome: Outcome) !void {
    var harness: Harness = undefined;
    harness.init(&.{outcome});
    defer harness.deinit();
    const result = try harness.launch(.default);
    try testing.expect(result == .failure);
    try testing.expect(result.failure == .aws_ec2);
    try testing.expectEqual(@as(usize, 1), harness.replay.count);
}

test "ec2: permanent service errors are not retried" {
    try expect_fails_after_one_request(replay_response(400, unauthorized_error));
    try expect_fails_after_one_request(replay_response(400, opt_in_required_error));
}

test "ec2: a fatal service code overrides a retryable status" {
    for ([_][]const u8{ unauthorized_error, opt_in_required_error, vcpu_limit_error }) |body| {
        try expect_fails_after_one_request(replay_response(500, body));
    }
}

test "ec2: transient service errors retry the same request" {
    for ([_]Outcome{
        replay_response(500, transient_error),
        replay_response(400, throttled_error),
    }) |first| {
        var harness: Harness = undefined;
        harness.init(&.{ first, replay_response(200, launch_success) });
        defer harness.deinit();
        try expect_launched(try harness.launch(.default), "us-east-1a");
        const bodies = harness.request_bodies();
        try testing.expectEqual(@as(usize, 2), bodies.len);
        try testing.expectEqualStrings(client_token(bodies[0]), client_token(bodies[1]));
    }
}

test "ec2: a full subnet is not retried" {
    var harness: Harness = undefined;
    harness.init(&.{
        replay_response(400, subnet_error),
        replay_response(400, capacity_error),
        replay_response(200, launch_success),
    });
    defer harness.deinit();
    try expect_launched(try harness.launch(.default), "us-east-1b");
    try testing.expectEqual(@as(usize, 3), harness.replay.count);
}

test "ec2: capacity retries until capacity returns" {
    const failures = 20;
    var outcomes: [failures + 1]Outcome = @splat(replay_response(400, capacity_error));
    outcomes[failures] = replay_response(200, launch_success);
    var harness: Harness = undefined;
    harness.init(&outcomes);
    defer harness.deinit();
    try expect_launched(try harness.launch(.default), "us-east-1a");
    try testing.expectEqual(@as(usize, failures + 1), harness.replay.count);
}

test "ec2: an unscripted dispatch failure and an unreadable success are classified" {
    // A dispatch failure without a transient classification is final (commonware's request
    // construction and credential failures); an unreadable 200 retries like a response error.
    try expect_fails_after_one_request(.{ .other = .{ .transient = false } });
    var harness: Harness = undefined;
    harness.init(&.{ replay_response(200, "<Run"), replay_response(200, launch_success) });
    defer harness.deinit();
    try expect_launched(try harness.launch(.default), "us-east-1a");
    try testing.expectEqual(@as(usize, 2), harness.replay.count);
}

test "ec2: the RunInstances body carries every launch parameter" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const request: ec2.LaunchRequest = .{
        .ami_id = "ami-1",
        .instance_type = "c7g.large",
        .storage_size = 100,
        .storage_class = .gp3,
        .storage_iops = 4_000,
        .storage_throughput = 500,
        .bandwidth_weighting = .ebs_1,
        .key_name = "deployer-t",
        .sg_id = "sg-1",
        .count = 2,
        .name = "node 0",
        .tag = "t",
    };
    const body = try ec2.run_instances_body(arena_state.allocator(), &request, "subnet-1", "tok");
    try testing.expectEqualStrings("Action=RunInstances&Version=2016-11-15" ++
        "&BlockDeviceMapping.1.DeviceName=%2Fdev%2Fsda1" ++
        "&BlockDeviceMapping.1.Ebs.DeleteOnTermination=true" ++
        "&BlockDeviceMapping.1.Ebs.Iops=4000&BlockDeviceMapping.1.Ebs.Throughput=500" ++
        "&BlockDeviceMapping.1.Ebs.VolumeSize=100&BlockDeviceMapping.1.Ebs.VolumeType=gp3" ++
        "&ImageId=ami-1&InstanceType=c7g.large&KeyName=deployer-t&MaxCount=2&MinCount=2" ++
        "&TagSpecification.1.ResourceType=instance" ++
        "&TagSpecification.1.Tag.1.Key=deployer&TagSpecification.1.Tag.1.Value=t" ++
        "&TagSpecification.1.Tag.2.Key=name&TagSpecification.1.Tag.2.Value=node%200" ++
        "&ClientToken=tok&NetworkInterface.1.AssociatePublicIpAddress=true" ++
        "&NetworkInterface.1.DeviceIndex=0&NetworkInterface.1.SecurityGroupId.1=sg-1" ++
        "&NetworkInterface.1.SubnetId=subnet-1" ++
        "&NetworkPerformanceOptions.BandwidthWeighting=ebs-1", body);
}

test "ec2: an instance type no subnet offers and invalid storage fail before any request" {
    var harness: Harness = undefined;
    harness.init(&.{});
    defer harness.deinit();
    const client: client_module.Client = .{
        .io = testing.io,
        .transport = harness.replay.transport(),
        .credentials = .{ .access_key_id = "a", .secret_access_key = "s" },
        .region = "us-east-1",
    };
    var request: ec2.LaunchRequest = .{
        .ami_id = "ami",
        .instance_type = "m7i.large",
        .storage_size = 10,
        .storage_class = .gp3,
        .key_name = "k",
        .sg_id = "sg",
        .count = 1,
        .name = "n",
        .tag = "t",
    };
    const subnets = [_]create.Subnet{.{ .az = "a", .id = "s" }};
    const support = [_]create.AzSupport{.{ .az = "a", .instance_types = &.{"c7g.large"} }};
    const arena = harness.arena_state.allocator();
    const gpa = testing.allocator;
    const unsupported =
        try ec2.launch_instances(&client, gpa, arena, &request, &subnets, &support, 0);
    try testing.expectEqualStrings("m7i.large", unsupported.failure.unsupported_instance_type);
    request.storage_class = .io2;
    const storage = try ec2.launch_instances(&client, gpa, arena, &request, &subnets, &support, 0);
    try testing.expect(storage.failure == .missing_storage_iops);
    try testing.expectEqual(@as(usize, 0), harness.replay.count);
}

test "ec2: client tokens are version 4 UUIDs" {
    const token = ec2.new_client_token(testing.io);
    try testing.expectEqual('-', token[8]);
    try testing.expectEqual('-', token[23]);
    try testing.expectEqual('4', token[14]);
    try testing.expect(std.mem.indexOfScalar(u8, "89ab", token[19]) != null);
    const other = ec2.new_client_token(testing.io);
    try testing.expect(!std.mem.eql(u8, &token, &other));
}
