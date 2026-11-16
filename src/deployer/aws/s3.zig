//! commonware `deployer::aws::s3`: the S3 layout shared by the deployer's commands (key
//! prefixes, presigning duration, and the `wget` instances download with), the local bucket
//! config, file digests, and the S3 calls over the signed client.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const client_module = @import("client.zig");
const Client = client_module.Client;
const ApiError = client_module.ApiError;
const deployments = @import("deployments.zig");
const ec2 = @import("ec2.zig");
const query = @import("query.zig");
const sigv4 = @import("sigv4.zig");
const Failure = @import("failure.zig").Failure;
const aws = @import("mod.zig");
const services = @import("services.zig");

const log = std.log.scoped(.deployer);

/// File in the deployer directory that holds the shared bucket's name.
pub const bucket_config_file = "bucket";

/// Prefix for cached tool binaries and images.
pub const tools_binaries_prefix = "tools/binaries";
/// Prefix for cached static configs and service files.
pub const tools_configs_prefix = "tools/configs";
/// Prefix for per-deployment files.
pub const deployments_prefix = "deployments";

/// Largest buffer used when hashing a file for its content digest.
pub const max_hash_buffer_size: usize = 32 * 1024 * 1024;
/// Most files hashed at once.
pub const max_concurrent_hashes: usize = 8;
/// How long presigned URLs stay valid.
pub const presign_duration_s: u64 = 6 * 60 * 60;

/// `wget` with retries on connection failures and on HTTP 404 (S3 eventual consistency),
/// 408, 429, 500, 502, 503, and 504.
pub const wget = "wget -q --tries=10 --retry-connrefused " ++
    "--retry-on-http-error=404,408,429,500,502,503,504 --waitretry=5";

// --- Local bucket config -----------------------------------------------------------------------

/// The persisted bucket name, without generating one (commonware `get_bucket_name_if_exists`):
/// the trimmed contents of `{home}/.commonware_deployer/bucket`, or null when it is missing or
/// empty. Cleanup paths use this so a missing config never mints a name for no real bucket.
pub fn get_bucket_name_if_exists(io: Io, arena: Allocator, home: []const u8) !?[]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try bucket_config_path(&buffer, home);
    const text = Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(4096)) catch |err| {
        return switch (err) {
            error.Canceled, error.OutOfMemory => |e| e,
            else => null,
        };
    };
    const name = std.mem.trim(u8, text, " \t\r\n");
    return if (name.len == 0) null else name;
}

/// The bucket name, generating and persisting `commonware-deployer-{16 hex digits}` when none
/// exists yet (commonware `get_bucket_name`).
pub fn get_bucket_name(io: Io, arena: Allocator, home: []const u8) ![]const u8 {
    if (try get_bucket_name_if_exists(io, arena, home)) |name| return name;
    // `Uuid::new_v4().simple()`'s first 16 hex digits.
    const token = ec2.new_client_token(io);
    const name = try std.fmt.allocPrint(arena, "commonware-deployer-{s}{s}{s}", .{
        token[0..8], token[9..13], token[14..18],
    });
    assert(name.len == "commonware-deployer-".len + 16);
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try bucket_config_path(&buffer, home);
    try Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = name });
    return name;
}

/// Deletes the bucket config so the next use generates a new name. A missing file is fine
/// (`clean` may run out of order).
pub fn delete_bucket_config(io: Io, home: []const u8) !void {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try bucket_config_path(&buffer, home);
    Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {},
    };
}

fn bucket_config_path(buffer: []u8, home: []const u8) error{NoSpaceLeft}![]const u8 {
    assert(home.len > 0);
    const directory = try deployments.deployer_directory(buffer, home, null);
    const rest = try std.fmt.bufPrint(buffer[directory.len..], "/" ++ bucket_config_file, .{});
    return buffer[0 .. directory.len + rest.len];
}

/// The lowercase hex SHA-256 of the file at `path` (commonware `hash_file`).
pub fn hash_file(io: Io, path: []const u8) ![64]u8 {
    assert(path.len > 0);
    var file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    var hasher: Sha256 = .init(.{});
    var hashed: u64 = 0;
    while (true) {
        const chunk = reader.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => return reader.err.?,
        };
        hasher.update(chunk);
        hashed += chunk.len;
        reader.interface.toss(chunk.len);
    }
    assert(hashed == reader.logicalPos());
    return std.fmt.bytesToHex(hasher.finalResult(), .lower);
}

// --- S3 calls ----------------------------------------------------------------------------------

/// The S3 operations commonware names in its errors.
pub const Operation = enum {
    create_bucket,
    delete_bucket,
    head_object,
    list_objects,
    delete_objects,

    pub fn format(operation: Operation, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.writeAll(switch (operation) {
            .create_bucket => "CreateBucket",
            .delete_bucket => "DeleteBucket",
            .head_object => "HeadObject",
            .list_objects => "ListObjects",
            .delete_objects => "DeleteObjects",
        });
    }
};

/// The virtual-hosted endpoint of `bucket` in `region`.
pub fn bucket_host(arena: Allocator, bucket: []const u8, region: []const u8) ![]const u8 {
    assert(bucket.len > 0);
    return std.fmt.allocPrint(arena, "{s}.s3.{s}.amazonaws.com", .{ bucket, region });
}

/// `/{key}`, percent-encoded with `/` kept.
pub fn object_path(arena: Allocator, key: []const u8) ![]const u8 {
    var out: Io.Writer.Allocating = .init(arena);
    try out.writer.writeByte('/');
    try sigv4.write_uri_encoded(&out.writer, key, true);
    return out.written();
}

fn s3_failure(bucket: []const u8, operation: Operation, err: ApiError) Failure {
    return .{ .aws_s3 = .{ .bucket = bucket, .operation = operation, .err = err } };
}

/// A request to a bucket's endpoint.
pub const BucketRequest = struct {
    method: []const u8,
    /// Already percent-encoded.
    path: []const u8 = "/",
    query: []const sigv4.Pair = &.{},
    headers: []const sigv4.Pair = &.{},
    body: []const u8 = "",
};

/// Sends `request` to `bucket` in `client.region` with the SDK's retries.
pub fn bucket_call(
    client: *const Client,
    arena: Allocator,
    bucket: []const u8,
    request: BucketRequest,
) !client_module.Result {
    assert(request.method.len > 0);
    return client.call(arena, .{
        .service = "s3",
        .method = request.method,
        .host = try bucket_host(arena, bucket, client.region),
        .path = request.path,
        .query = request.query,
        .headers = request.headers,
        .body = request.body,
        .s3 = true,
    }, .s3_rest);
}

/// Ensures `bucket` exists, creating it in `client.region` when HeadBucket says it does not
/// (commonware `ensure_bucket_exists`). A bucket that answers with its region lives elsewhere
/// and is used as is; any other refusal is access denied.
pub fn ensure_bucket_exists(client: *const Client, arena: Allocator, bucket: []const u8) !?Failure {
    switch (try bucket_call(client, arena, bucket, .{ .method = "HEAD" })) {
        .ok => {
            log.info("bucket already exists: bucket={s}", .{bucket});
            return null;
        },
        .failed => |err| {
            const not_found = switch (err) {
                .service => |service| service.status == 404,
                else => false,
            };
            if (not_found) {
                log.debug("bucket not found, will create: bucket={s}", .{bucket});
            } else if (header(err, "x-amz-bucket-region")) |bucket_region| {
                log.info("bucket exists in different region, using cross-region access: " ++
                    "bucket={s} bucket_region={s} client_region={s}", .{
                    bucket, bucket_region, client.region,
                });
                return null;
            } else {
                return .{ .s3_bucket_forbidden = .{ .bucket = bucket, .reason = .access_denied } };
            }
        },
    }
    return create_bucket(client, arena, bucket);
}

fn header(err: ApiError, name: []const u8) ?[]const u8 {
    const service = switch (err) {
        .service => |service| service,
        else => return null,
    };
    for (service.headers) |pair| if (std.mem.eql(u8, pair.name, name)) return pair.value;
    return null;
}

/// The `CreateBucket` body: none in us-east-1, which must not have a location constraint.
pub fn create_bucket_body(arena: Allocator, region: []const u8) ![]const u8 {
    assert(region.len > 0);
    if (std.mem.eql(u8, region, "us-east-1")) return "";
    return std.fmt.allocPrint(arena, "<CreateBucketConfiguration xmlns=\"{s}\">" ++
        "<LocationConstraint>{s}</LocationConstraint></CreateBucketConfiguration>", .{
        xml_namespace, region,
    });
}

const xml_namespace = "http://s3.amazonaws.com/doc/2006-03-01/";

fn create_bucket(client: *const Client, arena: Allocator, bucket: []const u8) !?Failure {
    const body = try create_bucket_body(arena, client.region);
    const result = try bucket_call(client, arena, bucket, .{ .method = "PUT", .body = body });
    const err = switch (result) {
        .ok => {
            log.info("created bucket: bucket={s} region={s}", .{ bucket, client.region });
            return null;
        },
        .failed => |err| err,
    };
    const code = err.service_code() orelse "";
    const exists = std.mem.eql(u8, code, "BucketAlreadyExists") or
        std.mem.eql(u8, code, "BucketAlreadyOwnedByYou");
    if (!exists) return s3_failure(bucket, .create_bucket, try err.dupe(arena));
    log.info("bucket already exists: bucket={s}", .{bucket});
    return null;
}

pub const Exists = union(enum) { ok: bool, failure: Failure };

/// Whether `key` exists in `bucket` (commonware `object_exists`).
pub fn object_exists(
    client: *const Client,
    arena: Allocator,
    bucket: []const u8,
    key: []const u8,
) !Exists {
    const path = try object_path(arena, key);
    const head = try bucket_call(client, arena, bucket, .{ .method = "HEAD", .path = path });
    const err = switch (head) {
        .ok => return .{ .ok = true },
        .failed => |err| err,
    };
    switch (err) {
        .service => |service| if (service.status == 404) return .{ .ok = false },
        else => {},
    }
    return .{ .failure = s3_failure(bucket, .head_object, try err.dupe(arena)) };
}

/// Uploads `body` to `key`, retrying every failure without limit with backoff doubling from
/// 500 ms up to 512 s (commonware `upload_with_retry`; zero in tests). A canceled sleep ends it.
pub fn put_object(
    client: *const Client,
    arena: Allocator,
    bucket: []const u8,
    key: []const u8,
    body: []const u8,
) !void {
    const path = try object_path(arena, key);
    var attempt: u32 = 0;
    while (true) {
        const result = try bucket_call(client, arena, bucket, .{
            .method = "PUT",
            .path = path,
            .body = body,
        });
        const err = switch (result) {
            .ok => {
                log.debug("uploaded to S3: bucket={s} key={s}", .{ bucket, key });
                return;
            },
            .failed => |err| err,
        };
        log.debug("upload failed, retrying: bucket={s} key={s} attempt={d} error={f}", .{
            bucket, key, attempt + 1, err,
        });
        attempt +|= 1;
        const doubling: u6 = @intCast(@min(attempt, 10));
        const backoff_ms: u64 = if (builtin.is_test) 0 else @as(u64, 500) << doubling;
        try client.io.sleep(.fromMilliseconds(@intCast(backoff_ms)), .awake);
    }
}

/// A presigned GET URL for `key`, valid for `expires_s` (commonware `presign_url`).
pub fn presign_url(
    client: *const Client,
    arena: Allocator,
    bucket: []const u8,
    key: []const u8,
    expires_s: u64,
) ![]const u8 {
    const request: sigv4.Request = .{
        .method = "GET",
        .host = try bucket_host(arena, bucket, client.region),
        .path = try object_path(arena, key),
        .payload_hash = sigv4.unsigned_payload,
        .double_encode_path = false,
    };
    const now = Io.Clock.real.now(client.io);
    const time_s: u64 = @intCast(@max(0, now.toSeconds()));
    const scope: sigv4.Scope = .{ .region = client.region, .service = "s3", .time_s = time_s };
    return sigv4.presign(arena, &request, client.credentials, scope, expires_s);
}

/// What `cache_and_presign` uploads when the object is missing.
pub const UploadSource = union(enum) { file: []const u8, static: []const u8 };

/// Largest file uploaded in one PUT (S3's single-request limit).
pub const upload_size_max: u64 = 5 * 1024 * 1024 * 1024;

pub const Presigned = union(enum) { ok: []const u8, failure: Failure };

/// Uploads `source` to `key` unless it is already there, then presigns it (commonware
/// `cache_and_presign`).
pub fn cache_and_presign(
    client: *const Client,
    arena: Allocator,
    bucket: []const u8,
    key: []const u8,
    source: UploadSource,
    expires_s: u64,
) !Presigned {
    switch (try object_exists(client, arena, bucket, key)) {
        .failure => |failure| return .{ .failure = failure },
        .ok => |exists| if (!exists) {
            log.debug("not in S3, uploading: key={s}", .{key});
            const body = switch (source) {
                .static => |bytes| bytes,
                .file => |path| try Io.Dir.cwd().readFileAlloc(
                    client.io,
                    path,
                    arena,
                    .limited(upload_size_max),
                ),
            };
            try put_object(client, arena, bucket, key, body);
        },
    }
    return .{ .ok = try presign_url(client, arena, bucket, key, expires_s) };
}

/// The `DeleteObjects` body for `keys` (XML-escaped).
pub fn delete_objects_body(arena: Allocator, keys: []const []const u8) ![]const u8 {
    assert(keys.len > 0 and keys.len <= delete_batch_max);
    var out: Io.Writer.Allocating = .init(arena);
    try out.writer.print("<Delete xmlns=\"{s}\">", .{xml_namespace});
    for (keys) |key| {
        try out.writer.writeAll("<Object><Key>");
        try query.write_escaped(&out.writer, key);
        try out.writer.writeAll("</Key></Object>");
    }
    try out.writer.writeAll("</Delete>");
    return out.written();
}

/// Most keys one `ListObjectsV2` page or `DeleteObjects` call holds.
pub const delete_batch_max = 1000;

/// Deletes every object under `prefix`, one listed page at a time (commonware `delete_prefix`).
pub fn delete_prefix(
    client: *const Client,
    arena: Allocator,
    bucket: []const u8,
    prefix: []const u8,
) !?Failure {
    var token: ?[]const u8 = null;
    var deleted: u64 = 0;
    while (true) {
        var parameters: [3]sigv4.Pair = undefined;
        parameters[0] = .{ .name = "list-type", .value = "2" };
        parameters[1] = .{ .name = "prefix", .value = prefix };
        if (token) |value| parameters[2] = .{ .name = "continuation-token", .value = value };
        const count: usize = if (token == null) 2 else 3;
        const listed = try bucket_call(client, arena, bucket, .{
            .method = "GET",
            .query = parameters[0..count],
        });
        const page = switch (listed) {
            .ok => |response| try parse_list_page(arena, response.body),
            .failed => |err| return s3_failure(bucket, .list_objects, try err.dupe(arena)),
        };
        if (page.keys.len > 0) {
            if (try delete_objects(client, arena, bucket, page.keys)) |failure| return failure;
            deleted += page.keys.len;
        }
        token = if (page.truncated) page.next_token else null;
        if (token == null) break;
    }
    log.info("deleted objects from S3: bucket={s} prefix={s} count={d}", .{
        bucket, prefix, deleted,
    });
    return null;
}

fn delete_objects(
    client: *const Client,
    arena: Allocator,
    bucket: []const u8,
    keys: []const []const u8,
) !?Failure {
    const body = try delete_objects_body(arena, keys);
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(body, &digest, .{});
    var md5: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&md5, &digest);
    const headers = [_]sigv4.Pair{
        .{ .name = "content-md5", .value = try arena.dupe(u8, &md5) },
        .{ .name = "content-type", .value = "application/xml" },
    };
    const result = try bucket_call(client, arena, bucket, .{
        .method = "POST",
        .query = &.{.{ .name = "delete", .value = "" }},
        .headers = &headers,
        .body = body,
    });
    return switch (result) {
        .ok => null,
        .failed => |err| s3_failure(bucket, .delete_objects, try err.dupe(arena)),
    };
}

pub const ListPage = struct {
    keys: []const []const u8,
    truncated: bool,
    next_token: ?[]const u8,
};

/// Reads a `ListObjectsV2` result (allocates from `arena`). A page without the result
/// element reads as empty and complete.
pub fn parse_list_page(arena: Allocator, xml: []const u8) !ListPage {
    var keys: std.ArrayList([]const u8) = .empty;
    const Collector = struct { list: *std.ArrayList([]const u8), arena: Allocator, failed: bool };
    var collector: Collector = .{ .list = &keys, .arena = arena, .failed = false };
    try query.scan(xml, &.{ "ListBucketResult", "Contents", "Key" }, &collector, struct {
        fn visit(c: *Collector, text: []const u8) bool {
            const key = query.decode_text(c.arena, text) catch {
                c.failed = true;
                return false;
            };
            c.list.append(c.arena, key) catch {
                c.failed = true;
                return false;
            };
            return true;
        }
    }.visit);
    if (collector.failed) return error.MalformedXml;
    const truncated = try query.first_text(xml, &.{ "ListBucketResult", "IsTruncated" });
    const next = try query.first_text(xml, &.{ "ListBucketResult", "NextContinuationToken" });
    return .{
        .keys = keys.items,
        .truncated = if (truncated) |text| std.mem.eql(u8, text, "true") else false,
        .next_token = if (next) |text| try query.decode_text(arena, text) else null,
    };
}

/// Deletes an empty bucket (commonware `delete_bucket`).
pub fn delete_bucket(client: *const Client, arena: Allocator, bucket: []const u8) !?Failure {
    switch (try bucket_call(client, arena, bucket, .{ .method = "DELETE" })) {
        .ok => {
            log.info("deleted bucket: bucket={s}", .{bucket});
            return null;
        },
        .failed => |err| return s3_failure(bucket, .delete_bucket, try err.dupe(arena)),
    }
}

/// Deletes every object in `bucket`, then the bucket (commonware
/// `delete_bucket_and_contents`).
pub fn delete_bucket_and_contents(
    client: *const Client,
    arena: Allocator,
    bucket: []const u8,
) !?Failure {
    if (try delete_prefix(client, arena, bucket, "")) |failure| return failure;
    return delete_bucket(client, arena, bucket);
}

/// Whether `failure` says the bucket does not exist (commonware `is_no_such_bucket_error`).
pub fn is_no_such_bucket_error(failure: Failure) bool {
    const s3 = switch (failure) {
        .aws_s3 => |s3| s3,
        else => return false,
    };
    const code = s3.err.service_code() orelse return false;
    return std.mem.eql(u8, code, "NoSuchBucket");
}

/// An instance's presigned download URLs.
pub const InstanceUrls = struct {
    name: []const u8,
    binary_url: []const u8,
    config_url: []const u8,
};

pub const InstanceFiles = union(enum) { ok: []const InstanceUrls, failure: Failure };

/// Uploads each distinct binary and config once, deduplicated by SHA-256 digest, and presigns
/// them per instance (commonware `upload_instance_files`). Files are hashed and uploaded one at
/// a time; commonware overlaps them.
pub fn upload_instance_files(
    client: *const Client,
    arena: Allocator,
    bucket: []const u8,
    tag: []const u8,
    instances: []const aws.InstanceConfig,
) !InstanceFiles {
    assert(tag.len > 0);
    var digests: std.ArrayList(Digest) = .empty;
    for (instances) |instance| {
        for ([_][]const u8{ instance.binary, instance.config }) |path| {
            if (find_digest(digests.items, path) == null) {
                try digests.append(arena, .{ .path = path, .hex = try hash_file(client.io, path) });
            }
        }
    }
    log.info("computed file digests: count={d}", .{digests.items.len});
    var urls: std.ArrayList(Presign) = .empty;
    const out = try arena.alloc(InstanceUrls, instances.len);
    for (instances, out) |instance, *slot| {
        var pair: [2][]const u8 = undefined;
        const kinds = [_]services.DeploymentFile{ .binaries, .configs };
        for ([_][]const u8{ instance.binary, instance.config }, kinds, &pair) |path, kind, *found| {
            const hex = &find_digest(digests.items, path).?.hex;
            found.* = for (urls.items) |known| {
                if (known.kind == kind and std.mem.eql(u8, &known.hex, hex)) break known.url;
            } else blk: {
                var key: Io.Writer.Allocating = .init(arena);
                try services.write_deployment_s3_key(&key.writer, tag, kind, hex);
                const source: UploadSource = .{ .file = path };
                const presigned = try cache_and_presign(
                    client,
                    arena,
                    bucket,
                    key.written(),
                    source,
                    presign_duration_s,
                );
                const url = switch (presigned) {
                    .ok => |url| url,
                    .failure => |failure| return .{ .failure = failure },
                };
                try urls.append(arena, .{ .kind = kind, .hex = hex.*, .url = url });
                break :blk url;
            };
        }
        slot.* = .{ .name = instance.name, .binary_url = pair[0], .config_url = pair[1] };
    }
    return .{ .ok = out };
}

const Digest = struct { path: []const u8, hex: [64]u8 };
const Presign = struct { kind: services.DeploymentFile, hex: [64]u8, url: []const u8 };

fn find_digest(digests: []Digest, path: []const u8) ?*Digest {
    for (digests) |*digest| if (std.mem.eql(u8, digest.path, path)) return digest;
    return null;
}

test {
    _ = @import("s3_test.zig");
}
