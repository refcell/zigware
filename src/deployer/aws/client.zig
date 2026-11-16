//! A signed AWS API client over an injectable HTTP transport. `Client.ec2_query` signs an EC2
//! Query request with SigV4 and sends it; the transport is `std.http` in production
//! (`http.zig`) and a scripted replay in tests, so tests never reach AWS (commonware's tests
//! swap the SDK's HTTP connector the same way).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const sigv4 = @import("sigv4.zig");
const query = @import("query.zig");

const log = std.log.scoped(.deployer);

pub const Request = struct {
    method: []const u8,
    host: []const u8,
    /// Already percent-encoded.
    path: []const u8,
    headers: []const sigv4.Pair,
    body: []const u8,
};

/// How sending a request ended, mirroring the SDK's connector outcomes.
pub const Outcome = union(enum) {
    /// A complete HTTP response; `body` lives in the arena passed to `send`.
    response: struct { status: u16, body: []const u8 },
    /// The connection failed (I/O error): retryable.
    io_failure,
    /// The request timed out: retryable.
    timeout,
    /// Another dispatch failure, retryable only when the transport classified it transient
    /// (an incomplete response); otherwise, such as missing credentials, it is not.
    other: struct { transient: bool },
};

pub const Transport = struct {
    context: *anyopaque,
    send_fn: *const fn (
        context: *anyopaque,
        arena: Allocator,
        request: *const Request,
    ) Io.Cancelable!Outcome,

    pub fn send(
        transport: Transport,
        arena: Allocator,
        request: *const Request,
    ) Io.Cancelable!Outcome {
        assert(request.host.len > 0);
        assert(request.path.len > 0 and request.path[0] == '/');
        return transport.send_fn(transport.context, arena, request);
    }
};

pub const Client = struct {
    io: Io,
    transport: Transport,
    credentials: sigv4.Credentials,
    region: []const u8,

    /// `ec2.<region>.amazonaws.com` (allocates from `arena`).
    pub fn ec2_host(client: *const Client, arena: Allocator) ![]const u8 {
        assert(client.region.len > 0);
        return std.fmt.allocPrint(arena, "ec2.{s}.amazonaws.com", .{client.region});
    }

    /// Signs and POSTs an EC2 Query `body` (allocates from `arena`).
    pub fn ec2_query(client: *const Client, arena: Allocator, body: []const u8) !Outcome {
        assert(std.mem.startsWith(u8, body, "Action="));
        const host = try client.ec2_host(arena);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(body, &hash, .{});
        const hex = std.fmt.bytesToHex(hash, .lower);
        const content: []const sigv4.Pair = &.{.{
            .name = "content-type",
            .value = query.content_type,
        }};
        const unsigned: sigv4.Request = .{
            .method = "POST",
            .host = host,
            .path = "/",
            .headers = content,
            .payload_hash = &hex,
        };
        const now = Io.Clock.real.now(client.io);
        const time_s: u64 = @intCast(@max(0, now.toSeconds()));
        const scope: sigv4.Scope = .{ .region = client.region, .service = "ec2", .time_s = time_s };
        const signed = try sigv4.sign(arena, &unsigned, client.credentials, scope);
        var headers: std.ArrayList(sigv4.Pair) = try .initCapacity(arena, 4);
        headers.appendAssumeCapacity(content[0]);
        const date = try arena.dupe(u8, &signed.amz_date);
        headers.appendAssumeCapacity(.{ .name = "x-amz-date", .value = date });
        headers.appendAssumeCapacity(.{ .name = "authorization", .value = signed.authorization });
        if (signed.security_token) |token| {
            headers.appendAssumeCapacity(.{ .name = "x-amz-security-token", .value = token });
        }
        const request: Request = .{
            .method = "POST",
            .host = host,
            .path = "/",
            .headers = headers.items,
            .body = body,
        };
        return client.transport.send(arena, &request);
    }
};

/// The production transport: HTTPS through `std.http.Client`. Every failure to complete the
/// exchange counts as an I/O failure (retryable); cancellation propagates.
pub const HttpTransport = struct {
    http: std.http.Client,

    pub fn init(gpa: Allocator, io: Io) HttpTransport {
        return .{ .http = .{ .allocator = gpa, .io = io } };
    }

    pub fn deinit(self: *HttpTransport) void {
        self.http.deinit();
        self.* = undefined;
    }

    pub fn transport(self: *HttpTransport) Transport {
        return .{ .context = self, .send_fn = send };
    }

    fn send(
        context: *anyopaque,
        arena: Allocator,
        request: *const Request,
    ) Io.Cancelable!Outcome {
        const self: *HttpTransport = @ptrCast(@alignCast(context));
        const location = .{ request.host, request.path };
        const url = std.fmt.allocPrint(arena, "https://{s}{s}", location) catch return .io_failure;
        var content_type: ?[]const u8 = null;
        var extra: std.ArrayList(std.http.Header) = .empty;
        for (request.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
                content_type = header.value;
            } else {
                extra.append(arena, .{ .name = header.name, .value = header.value }) catch
                    return .io_failure;
            }
        }
        var body: Io.Writer.Allocating = .init(arena);
        const method = std.meta.stringToEnum(std.http.Method, request.method) orelse
            return .{ .other = .{ .transient = false } };
        const result = self.http.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = if (request.body.len > 0) request.body else null,
            .headers = .{
                .content_type = if (content_type) |value| .{ .override = value } else .default,
            },
            .extra_headers = extra.items,
            .response_writer = &body.writer,
        }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                log.debug("{s} {s} failed: {t}", .{ request.method, url, err });
                return .io_failure;
            },
        };
        assert(url.len > request.host.len);
        return .{ .response = .{ .status = @backingInt(result.status), .body = body.written() } };
    }
};

/// A transport that replays scripted outcomes and records each request body, like
/// commonware's `ReplayConnector`. Requests past the script fail as an unclassified dispatch
/// failure ("no scripted EC2 response remains").
pub const Replay = struct {
    outcomes: []const Outcome,
    bodies: [][]const u8,
    /// Holds the recorded bodies: the arena `send` gets is the caller's per-attempt scratch.
    allocator: Allocator,
    count: usize = 0,

    pub fn transport(replay: *Replay) Transport {
        return .{ .context = replay, .send_fn = send };
    }

    fn send(context: *anyopaque, _: Allocator, request: *const Request) Io.Cancelable!Outcome {
        const replay: *Replay = @ptrCast(@alignCast(context));
        assert(replay.bodies.len >= replay.outcomes.len);
        const index = replay.count;
        replay.count += 1;
        if (index >= replay.outcomes.len) return .{ .other = .{ .transient = false } };
        replay.bodies[index] = replay.allocator.dupe(u8, request.body) catch return .io_failure;
        return replay.outcomes[index];
    }

    pub fn recorded(replay: *const Replay) []const []const u8 {
        return replay.bodies[0..@min(replay.count, replay.outcomes.len)];
    }
};

const testing = std.testing;

/// Records the signed request instead of sending it.
const Capture = struct {
    headers: [4]sigv4.Pair = undefined,
    count: usize = 0,
    host: []const u8 = "",

    fn send(context: *anyopaque, _: Allocator, request: *const Request) Io.Cancelable!Outcome {
        const capture: *Capture = @ptrCast(@alignCast(context));
        capture.count = request.headers.len;
        for (request.headers, 0..) |header, index| capture.headers[index] = header;
        capture.host = request.host;
        assert(std.mem.eql(u8, request.method, "POST"));
        return .{ .response = .{ .status = 200, .body = "" } };
    }
};

test "client: EC2 queries are signed for the region's ec2 endpoint" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var capture: Capture = .{};
    const client: Client = .{
        .io = testing.io,
        .transport = .{ .context = &capture, .send_fn = Capture.send },
        .credentials = .{
            .access_key_id = "access-key",
            .secret_access_key = "secret-key",
            .session_token = "session",
        },
        .region = "eu-west-2",
    };
    const body = "Action=DescribeRegions&Version=2016-11-15";
    _ = try client.ec2_query(arena_state.allocator(), body);
    try testing.expectEqualStrings("ec2.eu-west-2.amazonaws.com", capture.host);
    try testing.expectEqual(@as(usize, 4), capture.count);
    try testing.expectEqualStrings("content-type", capture.headers[0].name);
    try testing.expectEqualStrings(query.content_type, capture.headers[0].value);
    const date = capture.headers[1].value;
    try testing.expectEqual(@as(usize, 16), date.len);
    const authorization = capture.headers[2].value;
    const expected = try std.fmt.allocPrint(
        arena_state.allocator(),
        "AWS4-HMAC-SHA256 Credential=access-key/{s}/eu-west-2/ec2/aws4_request, " ++
            "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=",
        .{date[0..8]},
    );
    try testing.expect(std.mem.startsWith(u8, authorization, expected));
    try testing.expectEqual(expected.len + 64, authorization.len);
    try testing.expectEqualStrings("session", capture.headers[3].value);
}

test "client: the HTTP transport builds without sending" {
    var http: HttpTransport = .init(testing.allocator, testing.io);
    defer http.deinit();
    const transport = http.transport();
    try testing.expect(transport.context == @as(*anyopaque, &http));
}
