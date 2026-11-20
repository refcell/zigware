//! commonware's `clean`, `authorize`, `list`, and `attach` commands against a temporary home
//! directory and scripted AWS responses (never AWS).

const std = @import("std");
const testing = std.testing;
const client_module = @import("client.zig");
const aws = @import("mod.zig");
const commands = @import("commands.zig");
const Recorder = @import("update_test.zig").Recorder;
const Session = @import("session.zig").Session;

const Outcome = client_module.Outcome;

fn ok(body: []const u8) Outcome {
    return .{ .response = .{ .status = 200, .body = body } };
}

/// A temporary home directory, and the arena a test's session allocates from.
pub const Home = struct {
    tmp: testing.TmpDir,
    arena_state: std.heap.ArenaAllocator,
    log_level: std.log.Level,

    /// With `quiet`, only errors log until `deinit` (failure paths log warnings).
    pub fn init(quiet: bool) Home {
        const log_level = testing.log_level;
        if (quiet) testing.log_level = .err;
        return .{
            .tmp = testing.tmpDir(.{}),
            .arena_state = .init(testing.allocator),
            .log_level = log_level,
        };
    }

    pub fn deinit(home: *Home) void {
        home.arena_state.deinit();
        home.tmp.cleanup();
        testing.log_level = home.log_level;
    }

    pub fn arena(home: *Home) std.mem.Allocator {
        return home.arena_state.allocator();
    }

    /// A session in this home with test credentials, sending through `transport`.
    pub fn session(home: *Home, transport: client_module.Transport) !Session {
        const path_home = try std.fmt.allocPrint(home.arena(), ".zig-cache/tmp/{s}", .{
            home.tmp.sub_path,
        });
        return .{
            .io = testing.io,
            .gpa = testing.allocator,
            .arena = home.arena(),
            .home = path_home,
            .credentials = .{ .access_key_id = "access-key", .secret_access_key = "secret-key" },
            .transport = transport,
        };
    }

    pub fn write(home: *Home, relative: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(relative)) |parent| {
            try home.tmp.dir.createDirPath(testing.io, parent);
        }
        try home.tmp.dir.writeFile(testing.io, .{ .sub_path = relative, .data = data });
    }

    pub fn exists(home: *Home, relative: []const u8) bool {
        home.tmp.dir.access(testing.io, relative, .{}) catch return false;
        return true;
    }

    pub fn read(home: *Home, relative: []const u8) ![]const u8 {
        return home.tmp.dir.readFileAlloc(testing.io, relative, home.arena(), .limited(1 << 20));
    }

    /// `relative` inside the home, as a session in it sees it.
    pub fn path(home: *Home, relative: []const u8) ![]const u8 {
        return std.fmt.allocPrint(home.arena(), ".zig-cache/tmp/{s}/{s}", .{
            home.tmp.sub_path, relative,
        });
    }
};

/// Expects `session` to have failed with `expected`, then clears the failure for the next
/// command.
pub fn expect_failure(session: *Session, expected: []const u8) !void {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writer.print("{f}", .{session.failure.?});
    try testing.expectEqualStrings(expected, writer.buffered());
    session.failure = null;
    session.failed = .init(false);
}

/// A session over a temporary home directory and a scripted transport.
pub const Harness = struct {
    home: Home,
    requests: [32]client_module.Request = undefined,
    replay: client_module.Replay,
    session: Session,

    pub fn init(harness: *Harness, outcomes: []const Outcome) !void {
        harness.home = .init(false);
        harness.replay = .{
            .outcomes = outcomes,
            .requests = &harness.requests,
            .allocator = harness.home.arena(),
        };
        harness.session = try harness.home.session(harness.replay.transport());
    }

    pub fn deinit(harness: *Harness) void {
        harness.home.deinit();
    }

    pub fn sent(harness: *const Harness) []const client_module.Request {
        return harness.replay.recorded();
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
    try harness.home.write(".commonware_deployer/bucket", "commonware-deployer-0123\n");
    try commands.clean(&harness.session);
    const sent = harness.sent();
    try testing.expectEqual(@as(usize, 3), sent.len);
    const host = "commonware-deployer-0123.s3.us-east-1.amazonaws.com";
    try testing.expectEqualStrings(host, sent[0].host);
    try testing.expectEqualStrings("DELETE", sent[2].method);
    try testing.expect(!harness.home.exists(".commonware_deployer/bucket"));
}

test "clean: a missing bucket still drops the config; other failures keep it" {
    const no_bucket = "<Error><Code>NoSuchBucket</Code></Error>";
    var harness: Harness = undefined;
    try harness.init(&.{
        .{ .response = .{ .status = 404, .body = no_bucket } },
        .{ .response = .{ .status = 403, .body = "<Error><Code>AccessDenied</Code></Error>" } },
    });
    defer harness.deinit();
    try harness.home.write(".commonware_deployer/bucket", "b");
    try commands.clean(&harness.session);
    try testing.expect(!harness.home.exists(".commonware_deployer/bucket"));
    try harness.home.write(".commonware_deployer/bucket", "b");
    try testing.expectError(error.Failed, commands.clean(&harness.session));
    try expect_failure(&harness.session, "S3 operation failed: ListObjects on bucket 'b'");
    try testing.expect(harness.home.exists(".commonware_deployer/bucket"));
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
    try harness.home.write("t.yaml", config_yaml);
    try harness.home.write(".commonware_deployer/t/created", "");
    const config = try harness.home.path("t.yaml");
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
    try harness.home.write("t.yaml", config_yaml);
    try harness.home.write(".commonware_deployer/t/created", "");
    _ = try commands.authorize(&harness.session, try harness.home.path("t.yaml"), null);
    try testing.expectEqualStrings("ipv4.icanhazip.com", harness.sent()[0].host);
}

test "authorize: refuses missing, incomplete, and destroyed deployments and bad IPs" {
    var harness: Harness = undefined;
    try harness.init(&.{});
    defer harness.deinit();
    const session = &harness.session;
    try harness.home.write("t.yaml", config_yaml);
    const config = try harness.home.path("t.yaml");
    try testing.expectError(error.Failed, commands.authorize(session, config, "1.2.3.4"));
    try expect_failure(&harness.session, "deployment does not exist: t");
    try harness.home.write(".commonware_deployer/t/metadata.yaml", "");
    try testing.expectError(error.Failed, commands.authorize(session, config, "1.2.3.4"));
    try expect_failure(&harness.session, "deployment is not complete: t");
    try harness.home.write(".commonware_deployer/t/created", "");
    try testing.expectError(error.Failed, commands.authorize(session, config, "::1"));
    try expect_failure(&harness.session, "IP address is not IPv4: ::1");
    try testing.expectError(error.Failed, commands.authorize(session, config, "1.2.3"));
    try expect_failure(&harness.session, "invalid IP address: invalid IP address syntax");
    try harness.home.write(".commonware_deployer/t/destroyed", "");
    try testing.expectError(error.Failed, commands.authorize(session, config, "1.2.3.4"));
    try expect_failure(&harness.session, "deployment already destroyed: t");
    try testing.expectError(error.Failed, commands.authorize(session, "missing.yaml", null));
    try expect_failure(&harness.session, "IO error: missing.yaml: FileNotFound");
    try testing.expectEqual(@as(usize, 0), harness.replay.count);
}

fn metadata_yaml(harness: *Harness, tag: []const u8, created_at: u64) !void {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const metadata: aws.Metadata = .{
        .tag = tag,
        .created_at = created_at,
        .regions = &.{ "us-east-1", "eu-west-1" },
        .instance_count = 2,
    };
    try metadata.write(&writer);
    const path = try std.fmt.allocPrint(harness.home.arena(), deployer ++ "{s}/{s}", .{
        tag, aws.metadata_file_name,
    });
    try harness.home.write(path, writer.buffered());
}

const deployer = ".commonware_deployer/";

test "list: no directory, no deployments, and newest first without destroyed ones" {
    var harness: Harness = undefined;
    try harness.init(&.{});
    defer harness.deinit();
    try testing.expectEqual(@as(usize, 0), (try commands.list(&harness.session)).len);
    try harness.home.write(deployer ++ "stray", "");
    try testing.expectEqual(@as(usize, 0), (try commands.list(&harness.session)).len);
    try metadata_yaml(&harness, "old", 10);
    try metadata_yaml(&harness, "new", 30);
    try metadata_yaml(&harness, "gone", 40);
    try harness.home.write(deployer ++ "gone/" ++ aws.destroyed_file_name, "");
    // A deployment still being created is listed too (only `attach` needs `created`).
    try metadata_yaml(&harness, "mid", 20);
    const listed = try commands.list(&harness.session);
    try testing.expectEqual(@as(usize, 3), listed.len);
    try testing.expectEqualStrings("new", listed[0].tag);
    try testing.expectEqualStrings("mid", listed[1].tag);
    try testing.expectEqualStrings("old", listed[2].tag);
}

fn hosts_yaml(harness: *Harness, tag: []const u8, host_ip: []const u8) !void {
    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const host: aws.Host = .{ .name = "node", .region = "eu-west-1", .ip = try .parse(host_ip) };
    const hosts: aws.Hosts = .{
        .monitoring = .{ .public = try .parse("2.2.2.2"), .private = try .parse("10.0.0.1") },
        .hosts = &.{host},
    };
    try hosts.write(&writer);
    const path = try std.fmt.allocPrint(harness.home.arena(), deployer ++ "{s}/{s}", .{
        tag, "hosts.yaml",
    });
    try harness.home.write(path, writer.buffered());
}

test "attach: finds the instance's deployment and attaches with its key" {
    var harness: Harness = undefined;
    try harness.init(&.{});
    defer harness.deinit();
    var recorder: Recorder = .{ .allocator = harness.home.arena() };
    harness.session.remote = recorder.remote();
    const session = &harness.session;
    try testing.expectError(error.Failed, commands.attach(session, "1.2.3"));
    try expect_failure(&harness.session, "invalid IP address: invalid IP address syntax");
    try testing.expectError(error.Failed, commands.attach(session, "1.1.1.1"));
    try expect_failure(&harness.session, "instance not found: 1.1.1.1");
    // `a` is destroyed and `b` is not created, so only `t` matches.
    for ([_][]const u8{ "a", "b", "t" }) |tag| {
        try metadata_yaml(&harness, tag, 1);
        try hosts_yaml(&harness, tag, "2001:db8::1");
    }
    try harness.home.write(deployer ++ "a/" ++ aws.created_file_name, "");
    try harness.home.write(deployer ++ "a/" ++ aws.destroyed_file_name, "");
    try harness.home.write(deployer ++ "t/" ++ aws.created_file_name, "");
    try testing.expectError(error.Failed, commands.attach(session, "2001:db8:0::1"));
    try expect_failure(&harness.session, "private key not found");
    try harness.home.write(deployer ++ "t/id_rsa_t", "key");
    try commands.attach(session, "2001:db8:0::1");
    try commands.attach(session, "2.2.2.2"); // The monitoring instance.
    try testing.expectError(error.Failed, commands.attach(session, "10.0.0.1"));
    try expect_failure(&harness.session, "instance not found: 10.0.0.1");
    const lines = recorder.recorded();
    try testing.expectEqual(@as(usize, 2), lines.len);
    try testing.expectEqualStrings("2001:db8::1 attach id_rsa_t", lines[0]);
    try testing.expectEqualStrings("2.2.2.2 attach id_rsa_t", lines[1]);
}

test "run: dispatches parsed commands" {
    var harness: Harness = undefined;
    try harness.init(&.{});
    defer harness.deinit();
    const cli = @import("../cli.zig");
    const parsed = cli.parse(&.{ "aws", "list" }).ok.command.aws;
    try testing.expect(!commands.needs_credentials(parsed));
    try commands.run(&harness.session, parsed);
    const attach = cli.parse(&.{ "aws", "attach", "1.1.1.1" }).ok.command.aws;
    try testing.expectError(error.Failed, commands.run(&harness.session, attach));
    try expect_failure(&harness.session, "instance not found: 1.1.1.1");
    const message = commands.failure_message(attach);
    try testing.expectEqualStrings("failed to attach to instance", message);
    // `clean` without a bucket config calls nothing, but needs credentials in general.
    const clean = cli.parse(&.{ "aws", "clean" }).ok.command.aws;
    try testing.expect(commands.needs_credentials(clean));
    try commands.run(&harness.session, clean);
    try testing.expectEqual(@as(usize, 0), harness.sent().len);
}
