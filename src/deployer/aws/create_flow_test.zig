//! commonware's `create` against a temporary home, scripted responses per endpoint, a recorded
//! `ssh-keygen`/`docker`/`gzip`, and recorded SSH commands (never AWS, registries, or SSH).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const aws = @import("mod.zig");
const client_module = @import("client.zig");
const create_flow = @import("create_flow.zig");
const images = @import("images.zig");
const services = @import("services.zig");
const session_module = @import("session.zig");
const Recorder = @import("update_test.zig").Recorder;

const Outcome = client_module.Outcome;
const Route = client_module.RoutedReplay.Route;

fn ok(body: []const u8) Outcome {
    return .{ .response = .{ .status = 200, .body = body } };
}

fn respond(status: u16, body: []const u8) Outcome {
    return .{ .response = .{ .status = status, .body = body } };
}

const done = ok("<Response/>");
const ec2_host = "ec2.us-east-1.amazonaws.com";
const s3_host = "b.s3.us-east-1.amazonaws.com";

/// Local commands: `ssh-keygen` writes a key pair; others are recorded and succeed unless
/// `fail_on` names their program.
const Local = struct {
    lines: [16][]const u8 = undefined,
    count: usize = 0,
    fail_on: ?[]const u8 = null,

    fn local(recorder: *Local) session_module.Local {
        return .{ .context = recorder, .run_fn = run };
    }

    fn run(
        context: *anyopaque,
        arena: std.mem.Allocator,
        argv: []const []const u8,
    ) anyerror!?[]const u8 {
        const recorder: *Local = @ptrCast(@alignCast(context));
        recorder.lines[recorder.count] = try std.mem.join(arena, " ", argv);
        recorder.count += 1;
        if (recorder.fail_on) |program| {
            if (std.mem.eql(u8, argv[0], program)) return "no space left\nstdout";
        }
        const cwd = Io.Dir.cwd();
        if (std.mem.eql(u8, argv[0], "ssh-keygen")) {
            const public = try std.fmt.allocPrint(arena, "{s}.pub", .{argv[6]});
            try cwd.writeFile(testing.io, .{ .sub_path = argv[6], .data = "private" });
            try cwd.writeFile(testing.io, .{ .sub_path = public, .data = "ssh-rsa AAAA t\n" });
        } else if (std.mem.eql(u8, argv[0], "gzip")) {
            const gz = try std.fmt.allocPrint(arena, "{s}.gz", .{argv[2]});
            try cwd.writeFile(testing.io, .{ .sub_path = gz, .data = "tarball" });
        }
        return null;
    }
};

const Harness = struct {
    tmp: testing.TmpDir,
    arena_state: std.heap.ArenaAllocator,
    replay: client_module.RoutedReplay,
    recorder: Recorder,
    local: Local = .{},
    session: session_module.Session,
    quiet: std.log.Level,

    fn init(harness: *Harness, routes: []Route) !void {
        harness.quiet = testing.log_level;
        testing.log_level = .err; // Failure paths log warnings.
        harness.tmp = testing.tmpDir(.{});
        harness.arena_state = .init(testing.allocator);
        const arena = harness.arena_state.allocator();
        harness.replay = .{ .routes = routes, .allocator = arena };
        harness.recorder = .{ .allocator = arena };
        harness.local = .{};
        harness.session = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .arena = arena,
            .home = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{harness.tmp.sub_path}),
            .credentials = .{ .access_key_id = "access-key", .secret_access_key = "secret-key" },
            .transport = harness.replay.transport(),
            .remote = harness.recorder.remote(),
            .local = harness.local.local(),
        };
        try harness.write(".commonware_deployer/bucket", "b");
        try harness.write("bin", "binary");
        try harness.write("conf", "config");
        try harness.write("dashboard.json", "{}");
    }

    fn deinit(harness: *Harness) void {
        harness.arena_state.deinit();
        harness.tmp.cleanup();
        testing.log_level = harness.quiet;
    }

    fn write(harness: *Harness, relative: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(relative)) |parent| {
            try harness.tmp.dir.createDirPath(testing.io, parent);
        }
        try harness.tmp.dir.writeFile(testing.io, .{ .sub_path = relative, .data = data });
    }

    fn read(harness: *Harness, relative: []const u8) ![]const u8 {
        const arena = harness.arena_state.allocator();
        return harness.tmp.dir.readFileAlloc(testing.io, relative, arena, .limited(1 << 20));
    }

    /// A configuration with one binary instance in `region`, its files in the home.
    fn config(harness: *Harness, tag: []const u8, region: []const u8) ![]const u8 {
        const home = harness.session.home;
        const text = try std.fmt.allocPrint(harness.arena_state.allocator(),
            \\tag: {s}
            \\monitoring:
            \\  instance_type: c7g.medium
            \\  storage_size: 10
            \\  storage_class: gp3
            \\  dashboard: {s}/dashboard.json
            \\instances:
            \\- name: node0
            \\  region: {s}
            \\  instance_type: c7g.medium
            \\  storage_size: 10
            \\  storage_class: gp3
            \\  binary: {s}/bin
            \\  config: {s}/conf
            \\  profiling: false
            \\ports: []
            \\
        , .{ tag, home, region, home, home });
        try harness.write("config.yaml", text);
        return std.fmt.allocPrint(harness.arena_state.allocator(), "{s}/config.yaml", .{home});
    }

    fn expect_failure(harness: *Harness, expected: []const u8) !void {
        var buffer: [256]u8 = undefined;
        var writer: Io.Writer = .fixed(&buffer);
        try writer.print("{f}", .{harness.session.failure.?});
        try testing.expectEqualStrings(expected, writer.buffered());
        harness.session.failure = null;
        harness.session.failed = .init(false);
    }
};

const regions_response = ok("<DescribeRegionsResponse><regionInfo><item><regionName>us-east-1" ++
    "</regionName></item></regionInfo></DescribeRegionsResponse>");
const arm64 = ok("<DescribeInstanceTypesResponse><instanceTypeSet><item>" ++
    "<instanceType>c7g.medium</instanceType><processorInfo><supportedArchitectures>" ++
    "<item>arm64</item></supportedArchitectures></processorInfo></item>" ++
    "</instanceTypeSet></DescribeInstanceTypesResponse>");

fn running(comptime id: []const u8, comptime ip: []const u8) Outcome {
    return ok("<DescribeInstancesResponse><reservationSet><item><instancesSet><item>" ++
        "<instanceId>" ++ id ++ "</instanceId><instanceState><name>running</name>" ++
        "</instanceState><privateIpAddress>10.0.0.9</privateIpAddress><ipAddress>" ++ ip ++
        "</ipAddress></item></instancesSet></item></reservationSet></DescribeInstancesResponse>");
}

fn launched(comptime id: []const u8) Outcome {
    return ok("<RunInstancesResponse><instancesSet><item><instanceId>" ++ id ++
        "</instanceId></item></instancesSet></RunInstancesResponse>");
}

const ready = ok("<DescribeInstanceStatusResponse><instanceStatusSet><item>" ++
    "<instanceState><name>running</name></instanceState>" ++
    "<systemStatus><status>ok</status></systemStatus>" ++
    "<instanceStatus><status>ok</status></instanceStatus>" ++
    "</item></instanceStatusSet></DescribeInstanceStatusResponse>");

/// Every EC2 call of a one-region deployment, in order.
const ec2_script = [_]Outcome{
    regions_response,
    arm64, // detect_architecture
    arm64, // supports_nvme_instance_storage: no instance storage
    ok("<DescribeInstanceTypeOfferingsResponse><instanceTypeOfferingSet><item>" ++
        "<instanceType>c7g.medium</instanceType><location>us-east-1a</location></item>" ++
        "</instanceTypeOfferingSet></DescribeInstanceTypeOfferingsResponse>"),
    ok("<CreateVpcResponse><vpc><vpcId>vpc-1</vpcId></vpc></CreateVpcResponse>"),
    ok("<CreateInternetGatewayResponse><internetGateway><internetGatewayId>igw-1" ++
        "</internetGatewayId></internetGateway></CreateInternetGatewayResponse>"),
    done, // AttachInternetGateway
    ok("<CreateRouteTableResponse><routeTable><routeTableId>rtb-1</routeTableId>" ++
        "</routeTable></CreateRouteTableResponse>"),
    done, // CreateRoute
    ok("<CreateSubnetResponse><subnet><subnetId>subnet-1</subnetId></subnet>" ++
        "</CreateSubnetResponse>"),
    done, // AssociateRouteTable
    ok("<CreateSecurityGroupResponse><groupId>sg-m</groupId></CreateSecurityGroupResponse>"),
    done, // monitoring ingress for the deployer
    done, // ImportKeyPair
    ok("<CreateSecurityGroupResponse><groupId>sg-b</groupId></CreateSecurityGroupResponse>"),
    done, // binary ingress for the deployer
    ok("<DescribeImagesResponse><imagesSet><item><imageId>ami-1</imageId>" ++
        "<creationDate>2025-01-02T00:00:00.000Z</creationDate></item></imagesSet>" ++
        "</DescribeImagesResponse>"),
    launched("i-m"),
    launched("i-b"),
    running("i-m", "3.3.3.3"),
    running("i-b", "4.4.4.4"),
    running("i-m", "3.3.3.3"), // get_private_ip
    done, // add_monitoring_ingress
    ready, // monitoring and the binary instance, in either order
    ready,
    done, // monitoring's logs, profiles, and traces ports
};

/// Every S3 object is already cached, so each upload is a HEAD.
const cached: [64]Outcome = @splat(ok(""));

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

test "create: deploys one region end to end with every object cached" {
    var ec2_requests: [ec2_script.len]client_module.Request = undefined;
    var s3_requests: [cached.len]client_module.Request = undefined;
    var ip_requests: [1]client_module.Request = undefined;
    var routes = [_]Route{
        .{ .host = ec2_host, .outcomes = &ec2_script, .requests = &ec2_requests },
        .{ .host = s3_host, .outcomes = &cached, .requests = &s3_requests },
        .{
            .host = "ipv4.icanhazip.com",
            .outcomes = &.{ok("1.2.3.4\n")},
            .requests = &ip_requests,
        },
    };
    var harness: Harness = undefined;
    try harness.init(&routes);
    defer harness.deinit();
    const config = try harness.config("t", "us-east-1");
    try create_flow.create_deployment(&harness.session, config, 2);

    const sent = routes[0].recorded();
    try testing.expectEqual(ec2_script.len, sent.len);
    try testing.expect(contains(sent[4].body, "Action=CreateVpc&") and
        contains(sent[4].body, "CidrBlock=10.0.0.0%2F16"));
    try testing.expect(contains(sent[9].body, "CidrBlock=10.0.0.0%2F24") and
        contains(sent[9].body, "AvailabilityZone=us-east-1a"));
    // ssh-keygen's public key, base64-encoded.
    try testing.expect(contains(sent[13].body, "PublicKeyMaterial=c3NoLXJzYSBBQUFBIHQK"));
    try testing.expect(contains(sent[15].body, "CidrIp=1.2.3.4%2F32"));
    try testing.expect(contains(sent[17].body, "Action=RunInstances&") and
        contains(sent[17].body, "ImageId=ami-1"));
    try testing.expect(contains(sent[22].body, "GroupId=sg-b") and
        contains(sent[22].body, "CidrIp=3.3.3.3%2F32"));
    try testing.expectEqualStrings("Action=AuthorizeSecurityGroupIngress&Version=2016-11-15" ++
        "&GroupId=sg-m&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=3100" ++
        "&IpPermissions.1.ToPort=3100&IpPermissions.1.Groups.1.GroupId=sg-b" ++
        "&IpPermissions.2.IpProtocol=tcp&IpPermissions.2.FromPort=4040" ++
        "&IpPermissions.2.ToPort=4040&IpPermissions.2.Groups.1.GroupId=sg-b" ++
        "&IpPermissions.3.IpProtocol=tcp&IpPermissions.3.FromPort=4318" ++
        "&IpPermissions.3.ToPort=4318&IpPermissions.3.Groups.1.GroupId=sg-b", sent[25].body);
    for (routes[1].recorded()) |request| try testing.expectEqualStrings("HEAD", request.method);

    try testing.expectEqualStrings("", try harness.read(".commonware_deployer/t/created"));
    const hosts = try aws.Hosts.parse(
        harness.arena_state.allocator(),
        try harness.read(".commonware_deployer/t/hosts.yaml"),
    );
    var buffer: [64]u8 = undefined;
    const private = try std.fmt.bufPrint(&buffer, "{f}", .{hosts.monitoring.private});
    try testing.expectEqualStrings("10.0.0.9", private);
    try testing.expectEqual(@as(usize, 1), hosts.hosts.len);
    try testing.expectEqualStrings("node0", hosts.hosts[0].name);
    const metadata = try aws.Metadata.parse(
        harness.arena_state.allocator(),
        try harness.read(".commonware_deployer/t/metadata.yaml"),
    );
    try testing.expectEqual(@as(u64, 1), metadata.instance_count);
    _ = try harness.read(".commonware_deployer/t/promtail_node0.yml");
    _ = try harness.read(".commonware_deployer/t/pyroscope-agent_node0.sh");
    const prometheus = try harness.read(".commonware_deployer/t/prometheus.yml");
    try testing.expect(contains(prometheus, "4.4.4.4"));

    // Both instances were set up and every service polled.
    var monitoring_polls: usize = 0;
    var binary_polled = false;
    for (harness.recorder.recorded()) |line| {
        if (std.mem.startsWith(u8, line, "3.3.3.3 poll ")) monitoring_polls += 1;
        if (std.mem.eql(u8, line, "4.4.4.4 poll binary active")) binary_polled = true;
    }
    try testing.expectEqual(services.monitoring_image_service_names.len, monitoring_polls);
    try testing.expect(binary_polled);
    try testing.expectEqual(@as(usize, 1), harness.local.count);
}

test "create: refuses invalid, disabled, attempted, and keyless deployments" {
    const script = [_]Outcome{ regions_response, regions_response, regions_response };
    var ec2_requests: [script.len]client_module.Request = undefined;
    var ip_requests: [1]client_module.Request = undefined;
    var routes = [_]Route{
        .{ .host = ec2_host, .outcomes = &script, .requests = &ec2_requests },
        .{ .host = "ipv4.icanhazip.com", .outcomes = &.{ok("1.2.3.4")}, .requests = &ip_requests },
    };
    var harness: Harness = undefined;
    try harness.init(&routes);
    defer harness.deinit();
    const session = &harness.session;
    const invalid = try harness.config("a b", "us-east-1");
    try testing.expectError(error.Failed, create_flow.create_deployment(session, invalid, 1));
    try harness.expect_failure("invalid tag (must match [A-Za-z0-9_-]+): a b");
    // us-west-2 is not enabled; nothing is written.
    const west = try harness.config("t", "us-west-2");
    try testing.expectError(error.Failed, create_flow.create_deployment(session, west, 1));
    try harness.expect_failure("regions not enabled: [\"us-west-2\"]");
    const directory = harness.tmp.dir.access(testing.io, ".commonware_deployer/t", .{});
    try testing.expectError(error.FileNotFound, directory);
    // ssh-keygen fails after the directory exists, so the tag cannot be retried.
    harness.local.fail_on = "ssh-keygen";
    const config = try harness.config("t", "us-east-1");
    try testing.expectError(error.Failed, create_flow.create_deployment(session, config, 1));
    try harness.expect_failure("keygen failed");
    try testing.expectError(error.Failed, create_flow.create_deployment(session, config, 1));
    try harness.expect_failure("creation already attempted");
    try testing.expectEqual(script.len, routes[0].recorded().len);
}

test "images: a missing image is pulled, saved, compressed, and uploaded" {
    const script = [_]Outcome{ respond(404, ""), respond(404, ""), ok(""), respond(404, "") };
    var requests: [script.len]client_module.Request = undefined;
    var routes = [_]Route{.{ .host = s3_host, .outcomes = &script, .requests = &requests }};
    var harness: Harness = undefined;
    try harness.init(&routes);
    defer harness.deinit();
    const session = &harness.session;
    const client = try session.s3();
    const image = "prom/prometheus:v3.2.0";
    const url = try images.cache_image(session, client, "b", session.home, image, .arm64);
    try testing.expect(contains(url, "/tools/binaries/images/prom_prometheus_v3.2.0/linux-arm64/"));
    const home = session.home;
    const lines = harness.local.lines[0..harness.local.count];
    try testing.expectEqual(@as(usize, 3), lines.len);
    try testing.expectEqualStrings("docker pull --platform linux/arm64 " ++ image, lines[0]);
    const tar = try std.fmt.allocPrint(
        harness.arena_state.allocator(),
        "{s}/prom_prometheus_v3.2.0-arm64.tar",
        .{home},
    );
    const save = try std.fmt.allocPrint(harness.arena_state.allocator(), "docker save " ++
        "--platform linux/arm64 " ++ image ++ " -o {s}", .{tar});
    try testing.expectEqualStrings(save, lines[1]);
    try testing.expect(std.mem.startsWith(u8, lines[2], "gzip -f "));
    const sent = routes[0].recorded();
    try testing.expectEqualStrings("PUT", sent[2].method);
    try testing.expectEqualStrings("tarball", sent[2].body);
    // The compressed scratch file is removed after the upload.
    try testing.expectError(error.FileNotFound, harness.tmp.dir.access(
        testing.io,
        "prom_prometheus_v3.2.0-arm64.tar.gz",
        .{},
    ));
    // A failing command reports its command line and output, as commonware's CommandFailed.
    harness.local.fail_on = "docker";
    const failed = images.cache_image(session, client, "b", home, image, .x86_64);
    try testing.expectError(error.Failed, failed);
    try harness.expect_failure("command failed: docker pull --platform linux/amd64 " ++ image ++
        ": no space left\nstdout");
}
