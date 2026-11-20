//! commonware's `profile` command against a temporary home directory, scripted AWS and
//! download responses, and recorded remote commands (never AWS, GitHub, or SSH).

const std = @import("std");
const testing = std.testing;
const aws = @import("mod.zig");
const client_module = @import("client.zig");
const profile = @import("profile.zig");
const services = @import("services.zig");
const Harness = @import("commands_test.zig").Harness;
const expect_failure = @import("commands_test.zig").expect_failure;
const Recorder = @import("update_test.zig").Recorder;

const Outcome = client_module.Outcome;

fn respond(status: u16, body: []const u8) Outcome {
    return .{ .response = .{ .status = status, .body = body } };
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
    \\  binary: binary
    \\  config: config.conf
    \\  profiling: true
    \\ports: []
    \\
;

const running = respond(200, "<DescribeInstancesResponse><reservationSet><item><instancesSet>" ++
    "<item><instanceId>i-1</instanceId><ipAddress>1.2.3.4</ipAddress></item>" ++
    "</instancesSet></item></reservationSet></DescribeInstancesResponse>");
const arm64 = respond(200, "<DescribeInstanceTypesResponse><instanceTypeSet><item>" ++
    "<instanceType>c7g.medium</instanceType><processorInfo><supportedArchitectures>" ++
    "<item>arm64</item></supportedArchitectures></processorInfo></item>" ++
    "</instanceTypeSet></DescribeInstanceTypesResponse>");

/// A created deployment `t` with its key, and a debug binary at `bin`.
fn deployment(harness: *Harness, recorder: *Recorder) !void {
    recorder.* = .{ .allocator = harness.home.arena() };
    harness.session.remote = recorder.remote();
    harness.session.temp = harness.session.home;
    try harness.home.write("t.yaml", config_yaml);
    try harness.home.write("bin", "debug binary");
    try harness.home.write(".commonware_deployer/t/created", "");
    try harness.home.write(".commonware_deployer/t/id_rsa_t", "key");
}

test "profile: the script matches commonware's" {
    const script = try std.fmt.allocPrint(testing.allocator, profile.script_template, .{
        "https://u", @as(u64, 30), @as(u64, 30),
    });
    defer testing.allocator.free(script);
    // commonware's `format!` text, with WGET and the home directory written out.
    try testing.expectEqualStrings(services.expand(
        \\set -e
        \\
        \\# Download and extract samply if not present
        \\if [ ! -f <home>/samply ]; then
        \\    wget -q --tries=10 --retry-connrefused --retry-on-http-error=404,408,429,500,502,503,504 --waitretry=5 -O /tmp/samply.tar.xz 'https://u'
        \\    tar -xJf /tmp/samply.tar.xz -C <home> --strip-components=1
        \\    chmod +x <home>/samply
        \\    rm /tmp/samply.tar.xz
        \\fi
        \\
        \\# Get binary PID
        \\PID=$(systemctl show --property MainPID binary.service | cut -d= -f2)
        \\if [ -z "$PID" ] || [ "$PID" -eq 0 ]; then
        \\    echo "ERROR: binary.service not running" >&2
        \\    exit 1
        \\fi
        \\
        \\echo "Profiling PID $PID for 30 seconds..."
        \\
        \\# Record profile (use timeout with SIGINT so samply saves the profile)
        \\rm -f /tmp/profile.json
        \\sudo timeout -s INT 30s <home>/samply record -p $PID -s -o /tmp/profile.json || true
        \\sudo chown ubuntu:ubuntu /tmp/profile.json
        \\
        \\echo "Profile captured successfully"
        \\
    ), script);
}

test "profile: captures with samply already cached in S3" {
    var harness: Harness = undefined;
    // DescribeInstances, DescribeInstanceTypes, HeadBucket, HeadObject.
    try harness.init(&.{ running, arm64, respond(200, ""), respond(200, "") });
    defer harness.deinit();
    var recorder: Recorder = undefined;
    try deployment(&harness, &recorder);
    const config = try harness.home.path("t.yaml");
    const binary = try harness.home.path("bin");
    const captured = try profile.capture(&harness.session, config, "node0", 30, binary);

    const sent = harness.sent();
    try testing.expectEqual(@as(usize, 4), sent.len);
    try testing.expectEqualStrings("ec2.us-west-2.amazonaws.com", sent[0].host);
    try testing.expect(std.mem.indexOf(u8, sent[0].body, "Filter.1.Name=tag%3Adeployer" ++
        "&Filter.1.Value.1=t&Filter.2.Name=tag%3Aname&Filter.2.Value.1=node0" ++
        "&Filter.3.Name=instance-state-name&Filter.3.Value.1=running") != null);
    try testing.expectEqualStrings("HEAD", sent[3].method);
    try testing.expect(std.mem.endsWith(u8, sent[3].path, "/tools/binaries/samply/0.13.1/" ++
        "linux-aarch64/samply-aarch64-unknown-linux-gnu.tar.xz"));

    const lines = recorder.recorded();
    try testing.expectEqual(@as(usize, 2), lines.len);
    try testing.expect(std.mem.startsWith(u8, lines[0], "1.2.3.4 set -e\n"));
    try testing.expect(std.mem.indexOf(u8, lines[0], "X-Amz-Signature=") != null);
    const scp = try std.fmt.allocPrint(harness.home.arena(), "1.2.3.4 scp {s} {s}", .{
        profile.remote_profile_path, captured.profile_path,
    });
    try testing.expectEqualStrings(scp, lines[1]);
    const prefix = try harness.home.path("profile-node0-");
    try testing.expect(std.mem.startsWith(u8, captured.profile_path, prefix));
    try testing.expect(std.mem.endsWith(u8, captured.profile_path, ".json"));
    const copy = try std.fs.path.join(harness.home.arena(), &.{
        captured.symbol_dir, "binary",
    });
    const limit: std.Io.Limit = .limited(64);
    const copied = try std.Io.Dir.cwd().readFileAlloc(testing.io, copy, testing.allocator, limit);
    defer testing.allocator.free(copied);
    try testing.expectEqualStrings("debug binary", copied);
}

test "profile: downloads samply through redirects and caches it when S3 lacks it" {
    var harness: Harness = undefined;
    const redirect: Outcome = .{ .response = .{ .status = 302, .body = "", .headers = &.{
        .{ .name = "location", .value = "https://objects.example/archive?sig=1" },
    } } };
    try harness.init(&.{
        running, arm64,
        respond(200, ""), // HeadBucket
        respond(404, ""), // HeadObject: not cached
        redirect,
        respond(200, "samply archive"),
        respond(404, ""), // cache_and_presign's HeadObject
        respond(200, ""), // PutObject
    });
    defer harness.deinit();
    var recorder: Recorder = undefined;
    try deployment(&harness, &recorder);
    const config = try harness.home.path("t.yaml");
    _ = try profile.capture(&harness.session, config, "node0", 5, try harness.home.path("bin"));
    const sent = harness.sent();
    try testing.expectEqual(@as(usize, 8), sent.len);
    try testing.expectEqualStrings("github.com", sent[4].host);
    try testing.expectEqualStrings("/mstange/samply/releases/download/samply-v0.13.1/" ++
        "samply-aarch64-unknown-linux-gnu.tar.xz", sent[4].path);
    try testing.expectEqualStrings("objects.example", sent[5].host);
    try testing.expectEqualStrings("/archive?sig=1", sent[5].path);
    try testing.expectEqualStrings("PUT", sent[7].method);
    try testing.expectEqualStrings("samply archive", sent[7].body);
    try testing.expectEqual(@as(usize, 2), recorder.recorded().len);
}

test "profile: refuses unknown, incomplete, destroyed, and keyless deployments" {
    var harness: Harness = undefined;
    // The last check finds no running instance.
    try harness.init(&.{respond(200, "<DescribeInstancesResponse><reservationSet/>" ++
        "</DescribeInstancesResponse>")});
    defer harness.deinit();
    const session = &harness.session;
    try harness.home.write("t.yaml", config_yaml);
    try harness.home.write("bin", "debug binary");
    const config = try harness.home.path("t.yaml");
    const binary = try harness.home.path("bin");
    try testing.expectError(error.Failed, profile.capture(session, config, "x", 1, binary));
    try expect_failure(&harness.session, "instance not found: x");
    try testing.expectError(error.Failed, profile.capture(session, config, "node0", 1, binary));
    try expect_failure(&harness.session, "deployment is not complete: t");
    try harness.home.write(".commonware_deployer/t/created", "");
    try harness.home.write(".commonware_deployer/t/destroyed", "");
    try testing.expectError(error.Failed, profile.capture(session, config, "node0", 1, binary));
    try expect_failure(&harness.session, "deployment already destroyed: t");
    try harness.home.tmp.dir.deleteFile(testing.io, ".commonware_deployer/t/destroyed");
    try testing.expectError(error.Failed, profile.capture(session, config, "node0", 1, binary));
    try expect_failure(&harness.session, "private key not found");
    try harness.home.write(".commonware_deployer/t/id_rsa_t", "key");
    try testing.expectError(error.Failed, profile.capture(session, config, "node0", 1, binary));
    try expect_failure(&harness.session, "instance not found: node0");
    try testing.expectEqual(@as(usize, 1), harness.sent().len);
}

test "download: retries failed attempts, then fails the command" {
    const quiet = testing.log_level;
    testing.log_level = .err; // Failed attempts log warnings.
    defer testing.log_level = quiet;
    var outcomes: [aws.utils.max_download_attempts]Outcome = undefined;
    for (&outcomes) |*outcome| outcome.* = respond(404, "");
    var harness: Harness = undefined;
    try harness.init(&outcomes);
    defer harness.deinit();
    const url = "https://example.com/file";
    const arena = harness.home.arena();
    try testing.expectError(error.Failed, harness.session.download(arena, url));
    try expect_failure(&harness.session, "download failed: " ++ url);
    try testing.expectEqual(outcomes.len, harness.sent().len);
}

test "download: a relative redirect stays on the host; a body arrives after a failure" {
    const quiet = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = quiet;
    var harness: Harness = undefined;
    const redirect: Outcome = .{ .response = .{ .status = 301, .body = "", .headers = &.{
        .{ .name = "location", .value = "/moved" },
    } } };
    try harness.init(&.{ .io_failure, redirect, respond(200, "data") });
    defer harness.deinit();
    const arena = harness.home.arena();
    const body = try harness.session.download(arena, "https://h.example");
    try testing.expectEqualStrings("data", body);
    const sent = harness.sent();
    try testing.expectEqualStrings("/", sent[0].path);
    try testing.expectEqualStrings("h.example", sent[2].host);
    try testing.expectEqualStrings("/moved", sent[2].path);
}
