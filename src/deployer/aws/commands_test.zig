//! commonware's `clean` and `authorize` commands against a temporary home directory and
//! scripted AWS responses (never AWS).

const std = @import("std");
const testing = std.testing;
const client_module = @import("client.zig");
const commands = @import("commands.zig");
const Session = @import("session.zig").Session;

const Outcome = client_module.Outcome;

fn ok(body: []const u8) Outcome {
    return .{ .response = .{ .status = 200, .body = body } };
}

/// A session over a temporary home directory and a scripted transport.
pub const Harness = struct {
    tmp: testing.TmpDir,
    arena_state: std.heap.ArenaAllocator,
    requests: [32]client_module.Request = undefined,
    replay: client_module.Replay,
    session: Session,

    pub fn init(harness: *Harness, outcomes: []const Outcome) !void {
        harness.tmp = testing.tmpDir(.{});
        harness.arena_state = .init(testing.allocator);
        const arena = harness.arena_state.allocator();
        harness.replay = .{
            .outcomes = outcomes,
            .requests = &harness.requests,
            .allocator = arena,
        };
        harness.session = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .arena = arena,
            .home = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{harness.tmp.sub_path}),
            .credentials = .{ .access_key_id = "access-key", .secret_access_key = "secret-key" },
            .transport = harness.replay.transport(),
        };
    }

    pub fn deinit(harness: *Harness) void {
        harness.arena_state.deinit();
        harness.tmp.cleanup();
    }

    pub fn write(harness: *Harness, relative: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(relative)) |parent| {
            try harness.tmp.dir.createDirPath(testing.io, parent);
        }
        try harness.tmp.dir.writeFile(testing.io, .{ .sub_path = relative, .data = data });
    }

    pub fn exists(harness: *Harness, relative: []const u8) bool {
        harness.tmp.dir.access(testing.io, relative, .{}) catch return false;
        return true;
    }

    /// `relative` inside the temporary home, as the session sees it.
    pub fn home_path(harness: *Harness, relative: []const u8) ![]const u8 {
        return std.fmt.allocPrint(harness.arena_state.allocator(), "{s}/{s}", .{
            harness.session.home, relative,
        });
    }

    pub fn sent(harness: *const Harness) []const client_module.Request {
        return harness.replay.recorded();
    }

    pub fn expect_failure(harness: *Harness, expected: []const u8) !void {
        var buffer: [256]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try writer.print("{f}", .{harness.session.failure.?});
        try testing.expectEqualStrings(expected, writer.buffered());
        // Ready for the next command.
        harness.session.failure = null;
        harness.session.failed = .init(false);
    }
};

test "clean: nothing to do without a bucket config" {
    var harness: Harness = undefined;
    try harness.init(&.{});
    defer harness.deinit();
    try commands.clean(&harness.session);
    try testing.expectEqual(@as(usize, 0), harness.replay.count);
}

test "clean: deletes the bucket's objects, the bucket, and the config" {
    var harness: Harness = undefined;
    try harness.init(&.{
        ok("<ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult>"),
        ok(""),
        .{ .response = .{ .status = 204, .body = "" } },
    });
    defer harness.deinit();
    try harness.write(".commonware_deployer/bucket", "commonware-deployer-0123\n");
    try commands.clean(&harness.session);
    const sent = harness.sent();
    try testing.expectEqual(@as(usize, 3), sent.len);
    const host = "commonware-deployer-0123.s3.us-east-1.amazonaws.com";
    try testing.expectEqualStrings(host, sent[0].host);
    try testing.expectEqualStrings("DELETE", sent[2].method);
    try testing.expect(!harness.exists(".commonware_deployer/bucket"));
}

test "clean: a missing bucket still drops the config; other failures keep it" {
    const no_bucket = "<Error><Code>NoSuchBucket</Code></Error>";
    var harness: Harness = undefined;
    try harness.init(&.{
        .{ .response = .{ .status = 404, .body = no_bucket } },
        .{ .response = .{ .status = 403, .body = "<Error><Code>AccessDenied</Code></Error>" } },
    });
    defer harness.deinit();
    try harness.write(".commonware_deployer/bucket", "b");
    try commands.clean(&harness.session);
    try testing.expect(!harness.exists(".commonware_deployer/bucket"));
    try harness.write(".commonware_deployer/bucket", "b");
    try testing.expectError(error.Failed, commands.clean(&harness.session));
    try harness.expect_failure("S3 operation failed: ListObjects on bucket 'b'");
    try testing.expect(harness.exists(".commonware_deployer/bucket"));
}

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

fn groups(comptime body: []const u8) Outcome {
    return ok("<DescribeSecurityGroupsResponse><securityGroupInfo>" ++ body ++
        "</securityGroupInfo></DescribeSecurityGroupsResponse>");
}

const allowed_rule = "<ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>0</fromPort>" ++
    "<toPort>65535</toPort><ipRanges><item><cidrIp>1.2.3.4/32</cidrIp></item></ipRanges>" ++
    "</item></ipPermissions>";
const narrower_rule = "<ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort>" ++
    "<toPort>22</toPort><ipRanges><item><cidrIp>1.2.3.4/32</cidrIp></item></ipRanges>" ++
    "</item></ipPermissions>";

test "authorize: adds the IP to groups that lack the exact rule, in every region" {
    var harness: Harness = undefined;
    try harness.init(&.{
        // us-east-1 (monitoring) first, then us-west-2.
        groups("<item><groupId>sg-m</groupId>" ++ allowed_rule ++ "</item>"),
        groups("<item><groupId>sg-b</groupId>" ++ narrower_rule ++ "</item>"),
        ok("<AuthorizeSecurityGroupIngressResponse/>"),
    });
    defer harness.deinit();
    try harness.write("t.yaml", config_yaml);
    try harness.write(".commonware_deployer/t/created", "");
    const config = try harness.home_path("t.yaml");
    const changes = try commands.authorize(&harness.session, config, "1.2.3.4");
    try testing.expectEqual(@as(usize, 1), changes.len);
    try testing.expectEqualStrings("sg-b", changes[0]);
    const sent = harness.sent();
    try testing.expectEqualStrings("ec2.us-east-1.amazonaws.com", sent[0].host);
    try testing.expectEqualStrings("ec2.us-west-2.amazonaws.com", sent[1].host);
    try testing.expectEqualStrings(
        "Action=AuthorizeSecurityGroupIngress&Version=2016-11-15&GroupId=sg-b" ++
            "&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=0" ++
            "&IpPermissions.1.ToPort=65535&IpPermissions.1.IpRanges.1.CidrIp=1.2.3.4%2F32",
        sent[2].body,
    );
}

test "authorize: asks for the public IP when none is given" {
    var harness: Harness = undefined;
    try harness.init(&.{ ok("5.6.7.8\n"), groups(""), groups("") });
    defer harness.deinit();
    try harness.write("t.yaml", config_yaml);
    try harness.write(".commonware_deployer/t/created", "");
    _ = try commands.authorize(&harness.session, try harness.home_path("t.yaml"), null);
    try testing.expectEqualStrings("ipv4.icanhazip.com", harness.sent()[0].host);
}

test "authorize: refuses missing, incomplete, and destroyed deployments and bad IPs" {
    var harness: Harness = undefined;
    try harness.init(&.{});
    defer harness.deinit();
    const session = &harness.session;
    try harness.write("t.yaml", config_yaml);
    const config = try harness.home_path("t.yaml");
    try testing.expectError(error.Failed, commands.authorize(session, config, "1.2.3.4"));
    try harness.expect_failure("deployment does not exist: t");
    try harness.write(".commonware_deployer/t/metadata.yaml", "");
    try testing.expectError(error.Failed, commands.authorize(session, config, "1.2.3.4"));
    try harness.expect_failure("deployment is not complete: t");
    try harness.write(".commonware_deployer/t/created", "");
    try testing.expectError(error.Failed, commands.authorize(session, config, "::1"));
    try harness.expect_failure("IP address is not IPv4: ::1");
    try testing.expectError(error.Failed, commands.authorize(session, config, "1.2.3"));
    try harness.expect_failure("invalid IP address: invalid IP address syntax");
    try harness.write(".commonware_deployer/t/destroyed", "");
    try testing.expectError(error.Failed, commands.authorize(session, config, "1.2.3.4"));
    try harness.expect_failure("deployment already destroyed: t");
    try testing.expectError(error.Failed, commands.authorize(session, "missing.yaml", null));
    try harness.expect_failure("IO error: missing.yaml: FileNotFound");
    try testing.expectEqual(@as(usize, 0), harness.replay.count);
}
