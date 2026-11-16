//! commonware's `update` against a temporary home, scripted AWS responses, and recorded
//! remote commands (never AWS or SSH).

const std = @import("std");
const testing = std.testing;
const client_module = @import("client.zig");
const services = @import("services.zig");
const session_module = @import("session.zig");
const update = @import("update.zig");

const Outcome = client_module.Outcome;
const Route = client_module.RoutedReplay.Route;

fn ok(body: []const u8) Outcome {
    return .{ .response = .{ .status = 200, .body = body } };
}

/// Records remote commands as `{ip} {command}` (and `{ip} poll {service} {state}`); fails a
/// command containing `fail_on`.
pub const Recorder = struct {
    lines: [64][]const u8 = undefined,
    count: std.atomic.Value(usize) = .init(0),
    allocator: std.mem.Allocator,
    fail_on: ?[]const u8 = null,

    pub fn remote(recorder: *Recorder) session_module.Remote {
        return .{ .context = recorder, .vtable = &.{
            .execute = execute,
            .poll = poll,
            .download = download,
            .attach = attach,
        } };
    }

    fn record(recorder: *Recorder, comptime format: []const u8, args: anytype) !void {
        const line = try std.fmt.allocPrint(recorder.allocator, format, args);
        recorder.lines[recorder.count.fetchAdd(1, .acq_rel)] = line;
    }

    fn execute(
        context: *anyopaque,
        key: []const u8,
        ip: []const u8,
        command: []const u8,
    ) anyerror!void {
        const recorder: *Recorder = @ptrCast(@alignCast(context));
        std.debug.assert(std.mem.endsWith(u8, key, "id_rsa_t"));
        try recorder.record("{s} {s}", .{ ip, command });
        if (recorder.fail_on) |needle| {
            if (std.mem.indexOf(u8, command, needle) != null) return error.SshFailed;
        }
    }

    fn poll(
        context: *anyopaque,
        _: []const u8,
        ip: []const u8,
        service: []const u8,
        wanted: @import("utils.zig").ServiceState,
    ) anyerror!void {
        const recorder: *Recorder = @ptrCast(@alignCast(context));
        try recorder.record("{s} poll {s} {t}", .{ ip, service, wanted });
    }

    fn download(
        context: *anyopaque,
        _: []const u8,
        ip: []const u8,
        remote_path: []const u8,
        local_path: []const u8,
    ) anyerror!void {
        const recorder: *Recorder = @ptrCast(@alignCast(context));
        try recorder.record("{s} scp {s} {s}", .{ ip, remote_path, local_path });
    }

    fn attach(context: *anyopaque, key: []const u8, ip: []const u8) anyerror!void {
        const recorder: *Recorder = @ptrCast(@alignCast(context));
        try recorder.record("{s} attach {s}", .{ ip, std.fs.path.basename(key) });
    }

    pub fn recorded(recorder: *const Recorder) []const []const u8 {
        return recorder.lines[0..recorder.count.load(.acquire)];
    }
};

const Harness = struct {
    tmp: testing.TmpDir,
    arena_state: std.heap.ArenaAllocator,
    replay: client_module.RoutedReplay,
    recorder: Recorder,
    session: session_module.Session,
    quiet: std.log.Level,

    fn init(harness: *Harness, routes: []Route) !void {
        harness.quiet = testing.log_level;
        testing.log_level = .err; // The unknown instance logs a warning.
        harness.tmp = testing.tmpDir(.{});
        harness.arena_state = .init(testing.allocator);
        const arena = harness.arena_state.allocator();
        harness.replay = .{ .routes = routes, .allocator = arena };
        harness.recorder = .{ .allocator = arena };
        harness.session = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .arena = arena,
            .home = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{harness.tmp.sub_path}),
            .credentials = .{ .access_key_id = "access-key", .secret_access_key = "secret-key" },
            .transport = harness.replay.transport(),
            .remote = harness.recorder.remote(),
        };
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

    fn home_path(harness: *Harness, relative: []const u8) ![]const u8 {
        return std.fmt.allocPrint(harness.arena_state.allocator(), "{s}/{s}", .{
            harness.session.home, relative,
        });
    }

    /// A deployment `t` with instances `node0` and `node1` in us-west-2 sharing a binary.
    fn deploy(harness: *Harness) ![]const u8 {
        try harness.write("bin", "binary");
        try harness.write("conf0", "a");
        try harness.write("conf1", "b");
        const home = harness.session.home;
        const config = try std.fmt.allocPrint(harness.arena_state.allocator(),
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
            \\  binary: {0s}/bin
            \\  config: {0s}/conf0
            \\  profiling: false
            \\- name: node1
            \\  region: us-west-2
            \\  instance_type: c7g.medium
            \\  storage_size: 10
            \\  storage_class: gp3
            \\  binary: {0s}/bin
            \\  config: {0s}/conf1
            \\  profiling: false
            \\ports: []
            \\
        , .{home});
        try harness.write("t.yaml", config);
        try harness.write(".commonware_deployer/t/created", "");
        try harness.write(".commonware_deployer/t/id_rsa_t", "key");
        try harness.write(".commonware_deployer/bucket", "b");
        return harness.home_path("t.yaml");
    }
};

const uploads = [_]Outcome{
    .{ .response = .{ .status = 404, .body = "" } }, ok(""), // The shared binary.
    .{ .response = .{ .status = 404, .body = "" } }, ok(""), // conf0
    .{ .response = .{ .status = 404, .body = "" } }, ok(""), // conf1
};

fn tagged(comptime name: []const u8, comptime ip: []const u8) []const u8 {
    return "<item><instanceId>i-" ++ name ++ "</instanceId><tagSet><item><key>deployer</key>" ++
        "<value>t</value></item><item><key>name</key><value>" ++ name ++ "</value></item>" ++
        "</tagSet>" ++ ip ++ "</item>";
}

fn instances(comptime items: []const u8) Outcome {
    return ok("<DescribeInstancesResponse><reservationSet><item><instancesSet>" ++ items ++
        "</instancesSet></item></reservationSet></DescribeInstancesResponse>");
}

const monitoring_only = instances(tagged("monitoring", "<ipAddress>9.9.9.9</ipAddress>"));
const binaries = instances(tagged("node0", "<ipAddress>1.1.1.1</ipAddress>") ++
    tagged("node1", "<ipAddress>2.2.2.2</ipAddress>") ++
    tagged("stranger", "<ipAddress>3.3.3.3</ipAddress>") ++ tagged("node2", ""));

test "update: replaces each known instance's binary and config in place" {
    var s3_requests: [8]client_module.Request = undefined;
    var east: [2]client_module.Request = undefined;
    var west: [2]client_module.Request = undefined;
    var routes = [_]Route{
        .{ .host = "b.s3.us-east-1.amazonaws.com", .outcomes = &uploads, .requests = &s3_requests },
        .{
            .host = "ec2.us-east-1.amazonaws.com",
            .outcomes = &.{monitoring_only},
            .requests = &east,
        },
        .{ .host = "ec2.us-west-2.amazonaws.com", .outcomes = &.{binaries}, .requests = &west },
    };
    var harness: Harness = undefined;
    try harness.init(&routes);
    defer harness.deinit();
    const config = try harness.deploy();
    try update.update(&harness.session, config, 1);
    const lines = harness.recorder.recorded();
    try testing.expectEqual(@as(usize, 14), lines.len);
    const home = services.home_directory;
    const expected_head = [_][]const u8{
        "1.1.1.1 sudo systemctl stop binary",
        "1.1.1.1 poll binary inactive",
        "1.1.1.1 rm -f " ++ home ++ "/binary",
        "1.1.1.1 rm -f " ++ home ++ "/config.conf",
    };
    for (expected_head, lines[0..4]) |expected, line| {
        try testing.expectEqualStrings(expected, line);
    }
    const download = lines[4];
    const wget = "wget -q --tries=10 --retry-connrefused " ++
        "--retry-on-http-error=404,408,429,500,502,503,504 --waitretry=5";
    try testing.expect(std.mem.startsWith(u8, download, "1.1.1.1 " ++ wget ++ " -O " ++ home ++
        "/binary 'https://b.s3.us-east-1.amazonaws.com/deployments/t/binaries/"));
    try testing.expect(std.mem.endsWith(u8, download, "chmod +x " ++ home ++ "/binary"));
    try testing.expectEqualStrings("1.1.1.1 sudo systemctl start binary", lines[5]);
    try testing.expectEqualStrings("1.1.1.1 poll binary active", lines[6]);
    try testing.expectEqualStrings("2.2.2.2 sudo systemctl stop binary", lines[7]);
    // node1 downloads the shared binary and its own config.
    try testing.expect(std.mem.indexOf(u8, lines[11], "/deployments/t/configs/") != null);
    try testing.expectEqual(@as(usize, 6), routes[0].recorded().len);
}

test "update: the download command matches commonware's" {
    // commonware's `format!` string with WGET and the home directory written out.
    const w = @import("s3.zig").wget;
    const h = services.home_directory;
    const expected = w ++ " -O " ++ h ++ "/binary 'B' &\n" ++
        w ++ " -O " ++ h ++ "/config.conf 'C' &\n" ++
        "wait\n\n# Verify all downloads succeeded\nfor f in binary config.conf; do\n" ++
        "    if [ ! -f \"" ++ h ++ "/$f\" ]; then\n" ++
        "        echo \"ERROR: Failed to download $f\" >&2\n" ++
        "        exit 1\n    fi\ndone\n\n# Ensure the binary is executable\n" ++
        "chmod +x " ++ h ++ "/binary";
    var buffer: [2048]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&buffer, update.download_template, .{ "B", "C" });
    try testing.expectEqualStrings(expected, rendered);
}

test "update: refuses incomplete deployments and reports SSH failures" {
    var s3_requests: [8]client_module.Request = undefined;
    var east: [2]client_module.Request = undefined;
    var west: [2]client_module.Request = undefined;
    var routes = [_]Route{
        .{ .host = "b.s3.us-east-1.amazonaws.com", .outcomes = &uploads, .requests = &s3_requests },
        .{
            .host = "ec2.us-east-1.amazonaws.com",
            .outcomes = &.{monitoring_only},
            .requests = &east,
        },
        .{ .host = "ec2.us-west-2.amazonaws.com", .outcomes = &.{binaries}, .requests = &west },
    };
    var harness: Harness = undefined;
    try harness.init(&routes);
    defer harness.deinit();
    const config = try harness.deploy();
    try harness.tmp.dir.deleteFile(testing.io, ".commonware_deployer/t/id_rsa_t");
    try testing.expectError(error.Failed, update.update(&harness.session, config, 4));
    try testing.expect(harness.session.failure.? == .private_key_not_found);
    harness.session.failed = .init(false);
    try harness.write(".commonware_deployer/t/id_rsa_t", "key");
    harness.recorder.fail_on = "rm -f";
    try testing.expectError(error.Failed, update.update(&harness.session, config, 4));
    try testing.expect(harness.session.failure.? == .ssh_failed);
}
