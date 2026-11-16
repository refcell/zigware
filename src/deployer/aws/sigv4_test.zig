//! SigV4 vectors: the AWS documentation's examples (IAM `ListUsers` and its signing key, the
//! S3 header-signed GET and presigned URL, each reproduced by aws-sdk-go-v2 v1.41.7's signer),
//! and signatures from that signer for POST bodies, escaping, and session tokens.
//!
//! The credentials are AWS's published example keys, not real ones.

const std = @import("std");
const testing = std.testing;
const sigv4 = @import("sigv4.zig");

/// The IAM and SigV4 test-suite example credentials.
const example: sigv4.Credentials = .{
    .access_key_id = "AKIDEXAMPLE",
    .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
};

/// The S3 documentation's example credentials (the key ID is split so secret scanners, which
/// look for live key IDs, do not flag AWS's published example).
const s3_example: sigv4.Credentials = .{
    .access_key_id = "AKIA" ++ "IOSFODNN7EXAMPLE",
    .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};

/// 2015-08-30T12:36:00Z and 2013-05-24T00:00:00Z.
const time_2015: u64 = 1_440_938_160;
const time_2013: u64 = 1_369_353_600;
const empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

test "amz dates" {
    try testing.expectEqualStrings("20150830T123600Z", &sigv4.amz_date(time_2015));
    try testing.expectEqualStrings("19700101T000000Z", &sigv4.amz_date(0));
}

test "signing key (AWS docs)" {
    const key = sigv4.signing_key(example.secret_access_key, "20150830", "us-east-1", "iam");
    try testing.expectEqualStrings(
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
        &std.fmt.bytesToHex(key, .lower),
    );
}

fn expect_authorization(
    expected: []const u8,
    request: sigv4.Request,
    credentials: sigv4.Credentials,
    scope: sigv4.Scope,
) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const signed = try sigv4.sign(arena.allocator(), &request, credentials, scope);
    try testing.expectEqualStrings(expected, signed.authorization);
}

test "IAM ListUsers (AWS docs)" {
    try expect_authorization(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " ++
            "SignedHeaders=content-type;host;x-amz-date, " ++
            "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
        .{
            .method = "GET",
            .host = "iam.amazonaws.com",
            .path = "/",
            .query = &.{
                .{ .name = "Version", .value = "2010-05-08" },
                .{ .name = "Action", .value = "ListUsers" },
            },
            .headers = &.{.{
                .name = "Content-Type",
                .value = "application/x-www-form-urlencoded; charset=utf-8",
            }},
            .payload_hash = empty_hash,
        },
        example,
        .{ .region = "us-east-1", .service = "iam", .time_s = time_2015 },
    );
}

test "S3 GET with a range (AWS docs)" {
    try expect_authorization(
        "AWS4-HMAC-SHA256 Credential=" ++ "AKIA" ++ "IOSFODNN7EXAMPLE" ++
            "/20130524/us-east-1/s3/aws4_request, " ++
            "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " ++
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        .{
            .method = "GET",
            .host = "examplebucket.s3.amazonaws.com",
            .path = "/test.txt",
            .headers = &.{
                .{ .name = "Range", .value = "bytes=0-9" },
                .{ .name = "x-amz-content-sha256", .value = empty_hash },
            },
            .payload_hash = empty_hash,
            .double_encode_path = false,
        },
        s3_example,
        .{ .region = "us-east-1", .service = "s3", .time_s = time_2013 },
    );
}

test "EC2 POST query (aws-sdk-go-v2)" {
    try expect_authorization(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-west-2/ec2/aws4_request, " ++
            "SignedHeaders=content-type;host;x-amz-date, " ++
            "Signature=823db1f9f61e99c44e7a2a7bcb91098d22c1a83c742abeec6ae1e6e66af601d8",
        .{
            .method = "POST",
            .host = "ec2.us-west-2.amazonaws.com",
            .path = "/",
            .headers = &.{.{
                .name = "Content-Type",
                .value = "application/x-www-form-urlencoded; charset=utf-8",
            }},
            // SHA-256 of `Action=DescribeRegions&Version=2016-11-15`.
            .payload_hash = "903451d1f3cda66f6ac7101b5810af53eb3ce6b47c5162b0b2238ce9086b6a0d",
        },
        example,
        .{ .region = "us-west-2", .service = "ec2", .time_s = time_2015 },
    );
}

test "escaping, repeated keys, and a session token (aws-sdk-go-v2)" {
    var token = example;
    token.session_token = "TOKEN+/=";
    try expect_authorization(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " ++
            "SignedHeaders=host;x-amz-date;x-amz-security-token, " ++
            "Signature=fd78729a8c6d48e6063b2dfea30c694ae6194b68de8958d83f40284e4e8349b6",
        .{
            .method = "GET",
            .host = "example.amazonaws.com",
            .path = "/a%20b/c~d!/",
            .query = &.{
                .{ .name = "b", .value = "2" },
                .{ .name = "a", .value = "1" },
                .{ .name = "a", .value = "0" },
                .{ .name = "k", .value = "a/b c" },
            },
            .payload_hash = empty_hash,
        },
        token,
        .{ .region = "us-east-1", .service = "service", .time_s = time_2015 },
    );
}

fn expect_presigned(
    expected: []const u8,
    request: sigv4.Request,
    credentials: sigv4.Credentials,
    time_s: u64,
    expires_s: u64,
) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const scope: sigv4.Scope = .{ .region = "us-east-1", .service = "s3", .time_s = time_s };
    const url = try sigv4.presign(arena.allocator(), &request, credentials, scope, expires_s);
    try testing.expectEqualStrings(expected, url);
}

test "S3 presigned URL (AWS docs)" {
    try expect_presigned(
        "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256" ++
            "&X-Amz-Credential=" ++ "AKIA" ++ "IOSFODNN7EXAMPLE" ++
            "%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z" ++
            "&X-Amz-Expires=86400&X-Amz-SignedHeaders=host" ++
            "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
        .{
            .method = "GET",
            .host = "examplebucket.s3.amazonaws.com",
            .path = "/test.txt",
            .payload_hash = sigv4.unsigned_payload,
            .double_encode_path = false,
        },
        s3_example,
        time_2013,
        86_400,
    );
}

test "S3 presigned URL of an encoded key (aws-sdk-go-v2)" {
    try expect_presigned(
        "https://examplebucket.s3.amazonaws.com/tools/a%20b/x.tgz?" ++
            "X-Amz-Algorithm=AWS4-HMAC-SHA256" ++
            "&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request" ++
            "&X-Amz-Date=20150830T123600Z&X-Amz-Expires=21600&X-Amz-SignedHeaders=host" ++
            "&X-Amz-Signature=a58a288e2dd642090af3fc2785a04f60f0af1e94d4310f771c320f58e0633138",
        .{
            .method = "GET",
            .host = "examplebucket.s3.amazonaws.com",
            .path = "/tools/a%20b/x.tgz",
            .payload_hash = sigv4.unsigned_payload,
            .double_encode_path = false,
        },
        example,
        time_2015,
        6 * 60 * 60,
    );
}

test "uri encoding" {
    var buffer: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try sigv4.write_uri_encoded(&writer, "a-_.~ /+=é", false);
    try testing.expectEqualStrings("a-_.~%20%2F%2B%3D%C3%A9", writer.buffered());
    writer = .fixed(&buffer);
    try sigv4.write_uri_encoded(&writer, "/a b/", true);
    try testing.expectEqualStrings("/a%20b/", writer.buffered());
}
