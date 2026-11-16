//! commonware `deployer::aws::s3`'s calls against scripted S3 responses (never AWS), and the
//! local bucket config and file digests against a temporary directory.

const std = @import("std");
const testing = std.testing;
const client_module = @import("client.zig");
const s3 = @import("s3.zig");
const Failure = @import("failure.zig").Failure;

const Outcome = client_module.Outcome;

fn respond(status: u16, body: []const u8) Outcome {
    return .{ .response = .{ .status = status, .body = body } };
}

fn s3_error(comptime code: []const u8) []const u8 {
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>" ++ code ++
        "</Code><Message>m</Message><RequestId>r</RequestId></Error>";
}

const Harness = struct {
    arena_state: std.heap.ArenaAllocator,
    requests: [16]client_module.Request = undefined,
    replay: client_module.Replay,
    client: client_module.Client,

    fn init(harness: *Harness, region: []const u8, outcomes: []const Outcome) void {
        harness.arena_state = .init(testing.allocator);
        harness.replay = .{
            .outcomes = outcomes,
            .requests = &harness.requests,
            .allocator = harness.arena_state.allocator(),
        };
        harness.client = .{
            .io = testing.io,
            .transport = harness.replay.transport(),
            .credentials = .{ .access_key_id = "access-key", .secret_access_key = "secret-key" },
            .region = region,
        };
    }

    fn deinit(harness: *Harness) void {
        harness.arena_state.deinit();
    }

    fn arena(harness: *Harness) std.mem.Allocator {
        return harness.arena_state.allocator();
    }

    fn ensure(harness: *Harness, bucket: []const u8) !?Failure {
        return s3.ensure_bucket_exists(&harness.client, harness.arena(), bucket);
    }

    fn exists(harness: *Harness, key: []const u8) !s3.Exists {
        return s3.object_exists(&harness.client, harness.arena(), "b", key);
    }

    fn sent(harness: *const Harness) []const client_module.Request {
        return harness.replay.recorded();
    }
};

fn expect_display(failure: Failure, expected: []const u8) !void {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writer.print("{f}", .{failure});
    try testing.expectEqualStrings(expected, writer.buffered());
}

test "s3: an existing bucket is used as is" {
    var harness: Harness = undefined;
    harness.init("us-east-1", &.{respond(200, "")});
    defer harness.deinit();
    try testing.expectEqual(null, try harness.ensure("b"));
    const sent = harness.sent();
    try testing.expectEqual(@as(usize, 1), sent.len);
    try testing.expectEqualStrings("HEAD", sent[0].method);
    try testing.expectEqualStrings("b.s3.us-east-1.amazonaws.com", sent[0].host);
}

test "s3: a missing bucket is created with its region's location constraint" {
    var harness: Harness = undefined;
    harness.init("eu-west-1", &.{ respond(404, ""), respond(200, "") });
    defer harness.deinit();
    try testing.expectEqual(null, try harness.ensure("b"));
    const sent = harness.sent();
    try testing.expectEqual(@as(usize, 2), sent.len);
    try testing.expectEqualStrings("PUT", sent[1].method);
    try testing.expectEqualStrings("/", sent[1].path);
    try testing.expectEqualStrings(
        "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" ++
            "<LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>",
        sent[1].body,
    );
    // us-east-1 must not carry a location constraint.
    try testing.expectEqualStrings("", try s3.create_bucket_body(harness.arena(), "us-east-1"));
}

test "s3: HeadBucket refusals: another region, access denied, and creation races" {
    {
        var harness: Harness = undefined;
        const moved: Outcome = .{ .response = .{
            .status = 301,
            .body = "",
            .headers = &.{.{ .name = "x-amz-bucket-region", .value = "eu-central-1" }},
        } };
        harness.init("us-east-1", &.{moved});
        defer harness.deinit();
        try testing.expectEqual(null, try harness.ensure("b"));
        try testing.expectEqual(@as(usize, 1), harness.replay.count);
    }
    {
        var harness: Harness = undefined;
        harness.init("us-east-1", &.{respond(403, "")});
        defer harness.deinit();
        const failure = (try harness.ensure("b")).?;
        try expect_display(
            failure,
            "S3 bucket 'b' forbidden: access denied (check IAM permissions or bucket ownership)",
        );
    }
    const races = [_][]const u8{
        s3_error("BucketAlreadyOwnedByYou"),
        s3_error("BucketAlreadyExists"),
    };
    for (races) |body| {
        var harness: Harness = undefined;
        harness.init("us-east-1", &.{ respond(404, ""), respond(409, body) });
        defer harness.deinit();
        try testing.expectEqual(null, try harness.ensure("b"));
    }
    {
        var harness: Harness = undefined;
        const invalid = s3_error("InvalidBucketName");
        harness.init("us-east-1", &.{ respond(404, ""), respond(400, invalid) });
        defer harness.deinit();
        const failure = (try harness.ensure("b")).?;
        try expect_display(failure, "S3 operation failed: CreateBucket on bucket 'b'");
        try testing.expectEqualStrings("InvalidBucketName", failure.aws_s3.err.service_code().?);
    }
}

test "s3: transient failures are retried, others are not" {
    var harness: Harness = undefined;
    harness.init("us-east-1", &.{
        respond(503, s3_error("SlowDown")),
        .io_failure,
        respond(200, ""),
        respond(400, s3_error("SlowDown")), // A throttling code retries whatever the status.
        respond(404, ""),
    });
    defer harness.deinit();
    try testing.expectEqual(true, (try harness.exists("k")).ok);
    try testing.expectEqual(false, (try harness.exists("k")).ok);
    try testing.expectEqual(@as(usize, 5), harness.replay.count);
}

test "s3: object_exists reports other errors as HeadObject failures" {
    var harness: Harness = undefined;
    harness.init("us-east-1", &.{respond(403, "")});
    defer harness.deinit();
    const result = try s3.object_exists(&harness.client, harness.arena(), "b", "a b/c");
    try expect_display(result.failure, "S3 operation failed: HeadObject on bucket 'b'");
    try testing.expectEqualStrings("/a%20b/c", harness.sent()[0].path);
    try testing.expectEqual(@as(usize, 1), harness.replay.count);
}

test "s3: cache_and_presign uploads only missing objects and presigns the key" {
    var harness: Harness = undefined;
    harness.init("us-east-1", &.{
        respond(404, ""),
        respond(500, s3_error("InternalError")), // The upload retries until it lands.
        respond(400, s3_error("BadDigest")),
        respond(200, ""),
        respond(200, ""),
    });
    defer harness.deinit();
    const client = &harness.client;
    const arena = harness.arena();
    const expires_s = s3.presign_duration_s;
    const source: s3.UploadSource = .{ .static = "data" };
    const first = try s3.cache_and_presign(client, arena, "b", "k/x", source, expires_s);
    const prefix = "https://b.s3.us-east-1.amazonaws.com/k/x?X-Amz-Algorithm=AWS4-HMAC-SHA256" ++
        "&X-Amz-Credential=access-key%2F";
    try testing.expect(std.mem.startsWith(u8, first.ok, prefix));
    try testing.expect(std.mem.indexOf(u8, first.ok, "&X-Amz-Expires=21600&") != null);
    const sent = harness.sent();
    try testing.expectEqual(@as(usize, 4), sent.len);
    for (sent[1..4]) |request| {
        try testing.expectEqualStrings("PUT", request.method);
        try testing.expectEqualStrings("data", request.body);
    }
    // Already cached: no upload.
    _ = try s3.cache_and_presign(client, arena, "b", "k/x", source, expires_s);
    try testing.expectEqual(@as(usize, 5), harness.replay.count);
}

test "s3: delete_prefix deletes every listed page" {
    const page_one =
        \\<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name>
        \\<Contents><Key>p/a&amp;b</Key><Size>1</Size></Contents><Contents><Key>p/c</Key></Contents>
        \\<IsTruncated>true</IsTruncated><NextContinuationToken>t&amp;1</NextContinuationToken>
        \\</ListBucketResult>
    ;
    const page_two =
        \\<ListBucketResult><Contents><Key>p/d</Key></Contents><IsTruncated>false</IsTruncated>
        \\</ListBucketResult>
    ;
    var harness: Harness = undefined;
    harness.init("us-east-1", &.{
        respond(200, page_one), respond(200, ""), respond(200, page_two), respond(200, ""),
    });
    defer harness.deinit();
    const failure = try s3.delete_prefix(&harness.client, harness.arena(), "b", "p/");
    try testing.expectEqual(null, failure);
    const sent = harness.sent();
    try testing.expectEqual(@as(usize, 4), sent.len);
    try testing.expectEqualStrings("/?list-type=2&prefix=p%2F", sent[0].path);
    try testing.expectEqualStrings("/?delete=", sent[1].path);
    try testing.expectEqualStrings(
        "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Object><Key>p/a&amp;b</Key>" ++
            "</Object><Object><Key>p/c</Key></Object></Delete>",
        sent[1].body,
    );
    // Content-MD5 is the base64 MD5 of the body.
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(sent[1].body, &digest, .{});
    var expected: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&expected, &digest);
    const md5 = for (sent[1].headers) |header| {
        if (std.mem.eql(u8, header.name, "content-md5")) break header.value;
    } else return error.TestUnexpectedResult;
    try testing.expectEqualStrings(&expected, md5);
    try testing.expectEqualStrings(
        "/?continuation-token=t%261&list-type=2&prefix=p%2F",
        sent[2].path,
    );
    try testing.expect(std.mem.indexOf(u8, sent[3].body, "<Key>p/d</Key>") != null);
}

test "s3: a listing failure and NoSuchBucket are reported" {
    var harness: Harness = undefined;
    harness.init("us-east-1", &.{respond(404, s3_error("NoSuchBucket"))});
    defer harness.deinit();
    const failure = (try s3.delete_bucket_and_contents(&harness.client, harness.arena(), "b")).?;
    try expect_display(failure, "S3 operation failed: ListObjects on bucket 'b'");
    try testing.expect(s3.is_no_such_bucket_error(failure));
    try testing.expect(!s3.is_no_such_bucket_error(.no_subnets_available));
}

test "s3: the bucket name is generated once and persisted" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    const home = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try testing.expectEqual(null, try s3.get_bucket_name_if_exists(io, arena, home));
    const name = try s3.get_bucket_name(io, arena, home);
    try testing.expect(std.mem.startsWith(u8, name, "commonware-deployer-"));
    const suffix = name["commonware-deployer-".len..];
    try testing.expectEqual(@as(usize, 16), suffix.len);
    for (suffix) |byte| try testing.expect(std.ascii.isHex(byte) and !std.ascii.isUpper(byte));
    try testing.expectEqualStrings(name, try s3.get_bucket_name(io, arena, home));
    // Surrounding whitespace is trimmed; an empty file counts as missing.
    try tmp.dir.writeFile(io, .{ .sub_path = ".commonware_deployer/bucket", .data = " x\n" });
    try testing.expectEqualStrings("x", (try s3.get_bucket_name_if_exists(io, arena, home)).?);
    try tmp.dir.writeFile(io, .{ .sub_path = ".commonware_deployer/bucket", .data = "\n" });
    try testing.expectEqual(null, try s3.get_bucket_name_if_exists(io, arena, home));
    try s3.delete_bucket_config(io, home);
    try s3.delete_bucket_config(io, home);
    try testing.expectEqual(null, try s3.get_bucket_name_if_exists(io, arena, home));
}

test "s3: hash_file is the SHA-256 of the whole file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "hello", .data = "hello" });
    const hello = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/hello", .{tmp.sub_path});
    try testing.expectEqualStrings(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        &(try s3.hash_file(io, hello)),
    );
    // Larger than the read buffer.
    const big = try arena.alloc(u8, 200_003);
    for (big, 0..) |*byte, index| byte.* = @truncate(index *% 31);
    try tmp.dir.writeFile(io, .{ .sub_path = "big", .data = big });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(big, &digest, .{});
    const path = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/big", .{tmp.sub_path});
    const hex = std.fmt.bytesToHex(digest, .lower);
    try testing.expectEqualStrings(&hex, &(try s3.hash_file(io, path)));
}

test "s3: list pages read keys, truncation, and tokens" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const empty = try s3.parse_list_page(arena_state.allocator(), "<ListBucketResult/>");
    try testing.expectEqual(@as(usize, 0), empty.keys.len);
    try testing.expect(!empty.truncated);
    try testing.expectError(error.MalformedXml, s3.parse_list_page(arena_state.allocator(), "<a>"));
}

test "s3: instance files upload once per distinct content" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "bin-a", .data = "same" });
    try tmp.dir.writeFile(io, .{ .sub_path = "bin-b", .data = "same" });
    try tmp.dir.writeFile(io, .{ .sub_path = "conf-a", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = "conf-b", .data = "b" });
    var harness: Harness = undefined;
    // HEAD (missing) and PUT for the shared binary and each config.
    harness.init("us-east-1", &.{
        respond(404, ""), respond(200, ""), respond(404, ""), respond(200, ""),
        respond(404, ""), respond(200, ""),
    });
    defer harness.deinit();
    const arena = harness.arena();
    const base = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/", .{tmp.sub_path});
    var instances: [2]@import("mod.zig").InstanceConfig = undefined;
    for (&instances, [_][]const u8{ "a", "b" }) |*instance, name| {
        instance.* = std.mem.zeroInit(@import("mod.zig").InstanceConfig, .{
            .name = name,
            .binary = try std.mem.concat(arena, u8, &.{ base, "bin-", name }),
            .config = try std.mem.concat(arena, u8, &.{ base, "conf-", name }),
        });
    }
    const urls = (try s3.upload_instance_files(&harness.client, arena, "b", "t", &instances)).ok;
    try testing.expectEqual(@as(usize, 6), harness.replay.count);
    try testing.expectEqualStrings(urls[0].binary_url, urls[1].binary_url);
    try testing.expect(!std.mem.eql(u8, urls[0].config_url, urls[1].config_url));
    // The key names the deployment, the kind, and the content digest.
    const same = "0967115f2813a3541eaef77de9d9d5773f1c0c04314b0bbfe4ff3b3b1c55b5d5";
    try testing.expectEqualStrings("/deployments/t/binaries/" ++ same, harness.sent()[1].path);
    try testing.expectEqualStrings("same", harness.sent()[1].body);
    try testing.expectEqualStrings("PUT", harness.sent()[3].method);
}
