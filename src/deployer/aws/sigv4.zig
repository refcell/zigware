//! AWS Signature Version 4 (docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-
//! signed-request.html): request signing for the EC2 and S3 calls, and S3 presigned URLs.
//!
//! Checked against the AWS documentation's examples (the IAM `ListUsers` request and signing
//! key, and the S3 header-signed GET and presigned URL) and against signatures from the
//! official aws-sdk-go-v2 signer for escaping, repeated query keys, POST bodies, and session
//! tokens. Credentials are passed in by the caller; nothing here reads the environment.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const algorithm = "AWS4-HMAC-SHA256";
/// The payload hash S3 presigned URLs sign.
pub const unsigned_payload = "UNSIGNED-PAYLOAD";
/// Longest validity of a presigned URL (seven days).
pub const presign_expires_max_s: u64 = 7 * 24 * 60 * 60;

pub const Credentials = struct {
    access_key_id: []const u8,
    secret_access_key: []const u8,
    session_token: ?[]const u8 = null,
};

/// A query parameter or header, unencoded.
pub const Pair = struct { name: []const u8, value: []const u8 };

pub const Request = struct {
    method: []const u8,
    host: []const u8,
    /// The path as sent, already percent-encoded (`/a%20b`).
    path: []const u8,
    query: []const Pair = &.{},
    /// Headers to sign besides `host`, `x-amz-date`, and `x-amz-security-token`.
    headers: []const Pair = &.{},
    /// Lowercase hex SHA-256 of the body, or `unsigned_payload`.
    payload_hash: []const u8,
    /// Every service but S3 encodes the (already encoded) path a second time.
    double_encode_path: bool = true,
};

/// Where and when a request is signed.
pub const Scope = struct {
    region: []const u8,
    service: []const u8,
    /// Seconds since the Unix epoch.
    time_s: u64,
};

/// `seconds` as `YYYYMMDDTHHMMSSZ`.
pub fn amz_date(seconds: u64) [16]u8 {
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day = epoch.getDaySeconds();
    var out: [16]u8 = undefined;
    // Proof: four-digit years and two-digit fields fill exactly 16 bytes until year 10000.
    _ = std.fmt.bufPrint(&out, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        @as(u32, month_day.day_index) + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
    }) catch unreachable;
    assert(out[8] == 'T' and out[15] == 'Z');
    return out;
}

fn hmac(key: []const u8, message: []const u8) [HmacSha256.mac_length]u8 {
    var out: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&out, message, key);
    return out;
}

/// The signing key for `date` (`YYYYMMDD`), region, and service.
pub fn signing_key(
    secret: []const u8,
    date: []const u8,
    region: []const u8,
    service: []const u8,
) [32]u8 {
    assert(date.len == 8);
    var secret_key: [256]u8 = undefined;
    assert(secret.len + 4 <= secret_key.len);
    @memcpy(secret_key[0..4], "AWS4");
    @memcpy(secret_key[4..][0..secret.len], secret);
    const date_key = hmac(secret_key[0 .. 4 + secret.len], date);
    const region_key = hmac(&date_key, region);
    const service_key = hmac(&region_key, service);
    return hmac(&service_key, "aws4_request");
}

fn is_unreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.' or
        byte == '~';
}

/// RFC 3986 encoding as SigV4 specifies it: unreserved bytes stay, `/` stays when `keep_slash`,
/// and every other byte becomes `%XX` (uppercase).
pub fn write_uri_encoded(
    writer: *Io.Writer,
    text: []const u8,
    keep_slash: bool,
) Io.Writer.Error!void {
    for (text) |byte| {
        if (is_unreserved(byte) or (keep_slash and byte == '/')) {
            try writer.writeByte(byte);
        } else {
            try writer.print("%{X:0>2}", .{byte});
        }
    }
}

fn pair_less(_: void, a: Pair, b: Pair) bool {
    return switch (std.mem.order(u8, a.name, b.name)) {
        .lt => true,
        .gt => false,
        .eq => std.mem.order(u8, a.value, b.value) == .lt,
    };
}

/// Query parameters sorted by encoded name, then value, joined as `a=1&b=2`.
pub fn write_canonical_query(arena: Allocator, writer: *Io.Writer, query: []const Pair) !void {
    // Sorting encoded strings: encoding preserves the order of unreserved bytes but not of
    // others, so encode first.
    const encoded = try arena.alloc(Pair, query.len);
    for (query, encoded) |pair, *out| {
        out.* = .{
            .name = try encode_alloc(arena, pair.name, false),
            .value = try encode_alloc(arena, pair.value, false),
        };
    }
    std.sort.pdq(Pair, encoded, {}, pair_less);
    for (encoded, 0..) |pair, index| {
        if (index > 0) try writer.writeByte('&');
        try writer.print("{s}={s}", .{ pair.name, pair.value });
    }
}

fn encode_alloc(arena: Allocator, text: []const u8, keep_slash: bool) ![]const u8 {
    var out: Io.Writer.Allocating = .init(arena);
    try write_uri_encoded(&out.writer, text, keep_slash);
    return out.written();
}

/// Lowercased names with trimmed values (inner runs of spaces collapsed), sorted by name.
fn canonical_headers(arena: Allocator, headers: []const Pair) ![]Pair {
    const out = try arena.alloc(Pair, headers.len);
    for (headers, out) |header, *canonical| {
        const name = try std.ascii.allocLowerString(arena, header.name);
        var value: std.ArrayList(u8) = .empty;
        var tokens = std.mem.tokenizeScalar(u8, header.value, ' ');
        while (tokens.next()) |token| {
            if (value.items.len > 0) try value.append(arena, ' ');
            try value.appendSlice(arena, token);
        }
        canonical.* = .{ .name = name, .value = value.items };
    }
    std.sort.pdq(Pair, out, {}, pair_less);
    return out;
}

/// Writes `name;name;...`.
fn write_signed_headers(writer: *Io.Writer, headers: []const Pair) Io.Writer.Error!void {
    for (headers, 0..) |header, index| {
        if (index > 0) try writer.writeByte(';');
        try writer.writeAll(header.name);
    }
}

/// The canonical request, with the canonical headers already chosen.
fn canonical_request(arena: Allocator, request: *const Request, headers: []const Pair) ![]const u8 {
    var out: Io.Writer.Allocating = .init(arena);
    const writer = &out.writer;
    try writer.print("{s}\n", .{request.method});
    const path = if (request.path.len == 0) "/" else request.path;
    if (request.double_encode_path) {
        try write_uri_encoded(writer, path, true);
    } else {
        try writer.writeAll(path);
    }
    try writer.writeByte('\n');
    try write_canonical_query(arena, writer, request.query);
    try writer.writeByte('\n');
    for (headers) |header| try writer.print("{s}:{s}\n", .{ header.name, header.value });
    try writer.writeByte('\n');
    try write_signed_headers(writer, headers);
    try writer.print("\n{s}", .{request.payload_hash});
    return out.written();
}

/// `date/region/service/aws4_request`.
fn credential_scope(arena: Allocator, date: *const [16]u8, scope: Scope) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}/{s}/aws4_request", .{
        date[0..8], scope.region, scope.service,
    });
}

/// The hex signature of `canonical` for `scope` at `date`.
fn signature(
    secret: []const u8,
    date: *const [16]u8,
    credential: []const u8,
    scope: Scope,
    canonical: []const u8,
) [64]u8 {
    var request_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(canonical, &request_hash, .{});
    var buffer: [512]u8 = undefined;
    // Proof: the string to sign is the algorithm, a date, a scope of bounded names, and a hash.
    const string_to_sign = std.fmt.bufPrint(&buffer, algorithm ++ "\n{s}\n{s}\n{s}", .{
        date, credential, std.fmt.bytesToHex(request_hash, .lower),
    }) catch unreachable;
    const key = signing_key(secret, date[0..8], scope.region, scope.service);
    return std.fmt.bytesToHex(hmac(&key, string_to_sign), .lower);
}

/// The headers a signed request carries, in addition to its own.
pub const Signed = struct {
    authorization: []const u8,
    amz_date: [16]u8,
    /// `x-amz-security-token`, when the credentials hold a session token.
    security_token: ?[]const u8,
};

/// Signs `request` with an `Authorization` header (allocates from `arena`).
pub fn sign(
    arena: Allocator,
    request: *const Request,
    credentials: Credentials,
    scope: Scope,
) !Signed {
    assert(request.host.len > 0);
    const date = amz_date(scope.time_s);
    var all: std.ArrayList(Pair) = .empty;
    try all.appendSlice(arena, request.headers);
    try all.append(arena, .{ .name = "host", .value = request.host });
    try all.append(arena, .{ .name = "x-amz-date", .value = &date });
    if (credentials.session_token) |token| {
        try all.append(arena, .{ .name = "x-amz-security-token", .value = token });
    }
    const headers = try canonical_headers(arena, all.items);
    const canonical = try canonical_request(arena, request, headers);
    const credential = try credential_scope(arena, &date, scope);
    const hex = signature(credentials.secret_access_key, &date, credential, scope, canonical);
    var out: Io.Writer.Allocating = .init(arena);
    try out.writer.print(algorithm ++ " Credential={s}/{s}, SignedHeaders=", .{
        credentials.access_key_id, credential,
    });
    try write_signed_headers(&out.writer, headers);
    try out.writer.print(", Signature={s}", .{hex});
    return .{
        .authorization = out.written(),
        .amz_date = date,
        .security_token = credentials.session_token,
    };
}

/// A presigned `https` URL for `request`, valid for `expires_s` seconds; only `host` is signed
/// (allocates from `arena`).
pub fn presign(
    arena: Allocator,
    request: *const Request,
    credentials: Credentials,
    scope: Scope,
    expires_s: u64,
) ![]const u8 {
    assert(request.headers.len == 0);
    assert(expires_s > 0 and expires_s <= presign_expires_max_s);
    const date = amz_date(scope.time_s);
    const credential = try credential_scope(arena, &date, scope);
    const key_id = credentials.access_key_id;
    const access = try std.fmt.allocPrint(arena, "{s}/{s}", .{ key_id, credential });
    var query: std.ArrayList(Pair) = .empty;
    try query.appendSlice(arena, request.query);
    try query.appendSlice(arena, &.{
        .{ .name = "X-Amz-Algorithm", .value = algorithm },
        .{ .name = "X-Amz-Credential", .value = access },
        .{ .name = "X-Amz-Date", .value = try arena.dupe(u8, &date) },
        .{ .name = "X-Amz-Expires", .value = try std.fmt.allocPrint(arena, "{d}", .{expires_s}) },
        .{ .name = "X-Amz-SignedHeaders", .value = "host" },
    });
    if (credentials.session_token) |token| {
        try query.append(arena, .{ .name = "X-Amz-Security-Token", .value = token });
    }
    var signed = request.*;
    signed.query = query.items;
    const host: []const Pair = &.{.{ .name = "host", .value = request.host }};
    const canonical = try canonical_request(arena, &signed, host);
    const hex = signature(credentials.secret_access_key, &date, credential, scope, canonical);
    var out: Io.Writer.Allocating = .init(arena);
    try out.writer.print("https://{s}{s}?", .{ request.host, request.path });
    try write_canonical_query(arena, &out.writer, query.items);
    try out.writer.print("&X-Amz-Signature={s}", .{hex});
    return out.written();
}

test {
    _ = @import("sigv4_test.zig");
}
