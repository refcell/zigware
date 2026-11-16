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
const aws_utils = @import("utils.zig");
const builtin = @import("builtin");

const log = std.log.scoped(.deployer);

pub const Request = struct {
    method: []const u8,
    /// `https`, or `http` for the plain downloads commonware makes (Ubuntu's package archive).
    scheme: []const u8 = "https",
    host: []const u8,
    /// Already percent-encoded.
    path: []const u8,
    headers: []const sigv4.Pair,
    body: []const u8,
};

/// How an AWS call failed: a service error with its code and HTTP status, or a transport
/// failure (timeout, I/O, or an unparseable response), which may resolve on retry.
pub const ApiError = union(enum) {
    service: struct {
        code: ?[]const u8,
        status: u16,
        message: ?[]const u8 = null,
        /// The error response's headers (lowercase names); not kept by `dupe`.
        headers: []const sigv4.Pair = &.{},
    },
    transport,
    /// Request construction failed; retrying the same request cannot help.
    construction,
    /// A dispatch failure the transport did not classify as transient (such as failing to
    /// resolve credentials); retrying cannot help.
    dispatch,

    /// The SDK's error text differs; this names the same facts.
    pub fn format(err: ApiError, writer: *Io.Writer) Io.Writer.Error!void {
        switch (err) {
            .service => |service| {
                try writer.print("service error (status {d})", .{service.status});
                if (service.code) |code| try writer.print(": {s}", .{code});
                if (service.message) |message| try writer.print(": {s}", .{message});
            },
            .transport => try writer.writeAll("transport failure"),
            .construction => try writer.writeAll("request construction failure"),
            .dispatch => try writer.writeAll("dispatch failure"),
        }
    }

    /// The service error code, if any.
    pub fn service_code(err: ApiError) ?[]const u8 {
        return switch (err) {
            .service => |service| service.code,
            else => null,
        };
    }

    /// Copies the service error's strings into `arena`.
    pub fn dupe(err: ApiError, arena: Allocator) Allocator.Error!ApiError {
        const service = switch (err) {
            .service => |service| service,
            else => return err,
        };
        return .{ .service = .{
            .code = if (service.code) |text| try arena.dupe(u8, text) else null,
            .status = service.status,
            .message = if (service.message) |text| try arena.dupe(u8, text) else null,
        } };
    }
};

/// The SDK's standard transient error codes.
const transient_error_codes = [_][]const u8{
    "Throttling",                     "ThrottlingException",
    "ThrottledException",             "RequestThrottledException",
    "TooManyRequestsException",       "ProvisionedThroughputExceededException",
    "TransactionInProgressException", "RequestLimitExceeded",
    "BandwidthLimitExceeded",         "LimitExceededException",
    "RequestThrottled",               "SlowDown",
    "PriorRequestNotComplete",        "EC2ThrottledException",
    "RequestTimeout",                 "RequestTimeoutException",
};

const transient_status_codes = [_]u16{ 500, 502, 503, 504 };

/// The SDK's standard retry classification: transport failures, throttling and timeout codes,
/// and 500, 502, 503, and 504 responses.
pub fn is_transient(err: ApiError) bool {
    const service = switch (err) {
        .transport => return true,
        .construction, .dispatch => return false,
        .service => |service| service,
    };
    if (service.code) |code| {
        for (transient_error_codes) |transient| {
            if (std.mem.eql(u8, code, transient)) return true;
        }
    }
    return std.mem.indexOfScalar(u16, &transient_status_codes, service.status) != null;
}

/// Where a protocol's error responses keep their code and message.
pub const Protocol = enum {
    /// `<Response><Errors><Error><Code>`.
    ec2_query,
    /// `<Error><Code>` (REST-XML).
    s3_rest,
};

pub const Result = union(enum) { ok: Response, failed: ApiError };

/// A 2xx response, or the failure `outcome` describes (allocates from `arena`).
pub fn classify(arena: Allocator, outcome: Outcome, protocol: Protocol) Allocator.Error!Result {
    const response = switch (outcome) {
        .io_failure, .timeout => return .{ .failed = .transport },
        .other => |other| return .{ .failed = if (other.transient) .transport else .dispatch },
        .response => |response| response,
    };
    if (response.status >= 200 and response.status < 300) return .{ .ok = response };
    // An unreadable error body is still a service error, classified by its status.
    const parsed = switch (protocol) {
        .ec2_query => query.service_error(arena, response.body),
        .s3_rest => query.rest_error(arena, response.body),
    } catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MalformedXml => query.ServiceError{ .code = null, .message = null },
    };
    assert(response.status < 200 or response.status >= 300);
    return .{ .failed = .{ .service = .{
        .code = parsed.code,
        .status = response.status,
        .message = parsed.message,
        .headers = response.headers,
    } } };
}

pub const Response = struct {
    status: u16,
    body: []const u8,
    headers: []const sigv4.Pair = &.{},

    /// The value of header `name` (lowercase), if present.
    pub fn header(response: *const Response, name: []const u8) ?[]const u8 {
        for (response.headers) |pair| {
            if (std.mem.eql(u8, pair.name, name)) return pair.value;
        }
        return null;
    }
};

/// How sending a request ended, mirroring the SDK's connector outcomes.
pub const Outcome = union(enum) {
    /// A complete HTTP response; `body` and `headers` (lowercase names) live in the arena
    /// passed to `send`.
    response: Response,
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
        return client.send(arena, .{
            .service = "ec2",
            .method = "POST",
            .host = try client.ec2_host(arena),
            .headers = &.{.{ .name = "content-type", .value = query.content_type }},
            .body = body,
        });
    }

    /// Sends `call`, retrying transient failures as the SDK's standard retry does with
    /// commonware's settings: up to `max_sdk_attempts` attempts, with jittered backoff doubling
    /// from `sdk_initial_backoff_ms` to `sdk_max_backoff_ms` (allocates from `arena`).
    pub fn call(
        client: *const Client,
        arena: Allocator,
        request: Call,
        protocol: Protocol,
    ) !Result {
        var attempt: u32 = 0;
        while (true) {
            assert(attempt < aws_utils.max_sdk_attempts);
            const result = try classify(arena, try client.send(arena, request), protocol);
            const err = switch (result) {
                .ok => return result,
                .failed => |err| err,
            };
            attempt += 1;
            if (!is_transient(err) or attempt == aws_utils.max_sdk_attempts) return result;
            log.debug("{s} {s} failed, retrying: attempt={d} error={f}", .{
                request.method, request.host, attempt, err,
            });
            const delay_ms = backoff_ms(client.io, attempt);
            try client.io.sleep(.fromMilliseconds(@intCast(delay_ms)), .awake);
        }
    }

    /// Signs `call` with SigV4 for `client.region` and sends it once (allocates from `arena`).
    pub fn send(client: *const Client, arena: Allocator, spec: Call) !Outcome {
        assert(spec.service.len > 0);
        assert(spec.path.len > 0 and spec.path[0] == '/');
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(spec.body, &hash, .{});
        const hex = try arena.dupe(u8, &std.fmt.bytesToHex(hash, .lower));
        var signed_headers: std.ArrayList(sigv4.Pair) =
            try .initCapacity(arena, spec.headers.len + 1);
        signed_headers.appendSliceAssumeCapacity(spec.headers);
        // S3 requires the payload hash as a signed header.
        if (spec.s3) signed_headers.appendAssumeCapacity(.{
            .name = "x-amz-content-sha256",
            .value = hex,
        });
        const unsigned: sigv4.Request = .{
            .method = spec.method,
            .host = spec.host,
            .path = spec.path,
            .query = spec.query,
            .headers = signed_headers.items,
            .payload_hash = hex,
            .double_encode_path = !spec.s3,
        };
        const now = Io.Clock.real.now(client.io);
        const time_s: u64 = @intCast(@max(0, now.toSeconds()));
        const scope: sigv4.Scope = .{
            .region = client.region,
            .service = spec.service,
            .time_s = time_s,
        };
        const signed = try sigv4.sign(arena, &unsigned, client.credentials, scope);
        var headers: std.ArrayList(sigv4.Pair) =
            try .initCapacity(arena, signed_headers.items.len + 3);
        headers.appendSliceAssumeCapacity(signed_headers.items);
        const date = try arena.dupe(u8, &signed.amz_date);
        headers.appendAssumeCapacity(.{ .name = "x-amz-date", .value = date });
        headers.appendAssumeCapacity(.{ .name = "authorization", .value = signed.authorization });
        if (signed.security_token) |token| {
            headers.appendAssumeCapacity(.{ .name = "x-amz-security-token", .value = token });
        }
        var target: Io.Writer.Allocating = .init(arena);
        try target.writer.writeAll(spec.path);
        if (spec.query.len > 0) {
            try target.writer.writeByte('?');
            try sigv4.write_canonical_query(arena, &target.writer, spec.query);
        }
        const request: Request = .{
            .method = spec.method,
            .host = spec.host,
            .path = target.written(),
            .headers = headers.items,
            .body = spec.body,
        };
        return client.transport.send(arena, &request);
    }
};

/// A uniformly random delay up to `sdk_initial_backoff_ms * 2^(attempt - 1)`, capped at
/// `sdk_max_backoff_ms` (the SDK's exponential backoff with full jitter); zero in tests.
fn backoff_ms(io: Io, attempt: u32) u64 {
    assert(attempt > 0);
    if (builtin.is_test) return 0;
    const exponent: u6 = @intCast(@min(attempt - 1, 16));
    const doubled = aws_utils.sdk_initial_backoff_ms << exponent;
    const ceiling = @min(aws_utils.sdk_max_backoff_ms, doubled);
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    const delay = std.mem.readInt(u64, &bytes, .little) % (ceiling + 1);
    assert(delay <= aws_utils.sdk_max_backoff_ms);
    return delay;
}

/// One AWS API request before signing.
pub const Call = struct {
    service: []const u8,
    method: []const u8,
    host: []const u8,
    /// Already percent-encoded.
    path: []const u8 = "/",
    /// Unencoded; sent and signed in canonical order.
    query: []const sigv4.Pair = &.{},
    /// Headers to sign besides `host` and `x-amz-*`, with lowercase names.
    headers: []const sigv4.Pair = &.{},
    body: []const u8 = "",
    /// S3 signs `x-amz-content-sha256` and does not encode the path a second time.
    s3: bool = false,
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
        const method = std.meta.stringToEnum(std.http.Method, request.method) orelse
            return .{ .other = .{ .transient = false } };
        const response = self.exchange(arena, method, request) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                log.debug("{s} {s}{s} failed: {t}", .{
                    request.method, request.host, request.path, err,
                });
                return .io_failure;
            },
        };
        assert(response.status >= 100);
        return .{ .response = response };
    }

    fn exchange(
        self: *HttpTransport,
        arena: Allocator,
        method: std.http.Method,
        request: *const Request,
    ) !Response {
        const location = .{ request.scheme, request.host, request.path };
        const url = try std.fmt.allocPrint(arena, "{s}://{s}{s}", location);
        var content_type: std.http.Client.Request.Headers.Value = .default;
        var extra: std.ArrayList(std.http.Header) = .empty;
        for (request.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
                content_type = .{ .override = header.value };
            } else {
                try extra.append(arena, .{ .name = header.name, .value = header.value });
            }
        }
        var http_request = try self.http.request(method, try std.Uri.parse(url), .{
            .redirect_behavior = .unhandled,
            .headers = .{ .content_type = content_type, .accept_encoding = .omit },
            .extra_headers = extra.items,
        });
        defer http_request.deinit();
        if (method.requestHasBody()) {
            http_request.transfer_encoding = .{ .content_length = request.body.len };
            var body = try http_request.sendBodyUnflushed(&.{});
            try body.writer.writeAll(request.body);
            try body.end();
            try http_request.connection.?.flush();
        } else {
            assert(request.body.len == 0);
            try http_request.sendBodiless();
        }
        var response = try http_request.receiveHead(&.{});
        // Header bytes live in the connection's buffer, which the body read reuses.
        var headers: std.ArrayList(sigv4.Pair) = .empty;
        var iterator = response.head.iterateHeaders();
        while (iterator.next()) |header| {
            const name = try std.ascii.allocLowerString(arena, header.name);
            try headers.append(arena, .{ .name = name, .value = try arena.dupe(u8, header.value) });
        }
        const status = @backingInt(response.head.status);
        var body: Io.Writer.Allocating = .init(arena);
        var transfer_buffer: [64]u8 = undefined;
        const reader = response.reader(&transfer_buffer);
        _ = reader.streamRemaining(&body.writer) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
        return .{ .status = status, .body = body.written(), .headers = headers.items };
    }
};

/// A transport that replays scripted outcomes and records each request, like commonware's
/// `ReplayConnector`. Requests past the script fail as an unclassified dispatch failure ("no
/// scripted EC2 response remains").
pub const Replay = struct {
    outcomes: []const Outcome,
    requests: []Request,
    /// Holds the recorded requests: the arena `send` gets may be the caller's scratch.
    allocator: Allocator,
    count: usize = 0,

    pub fn transport(replay: *Replay) Transport {
        return .{ .context = replay, .send_fn = send };
    }

    fn send(context: *anyopaque, _: Allocator, request: *const Request) Io.Cancelable!Outcome {
        const replay: *Replay = @ptrCast(@alignCast(context));
        assert(replay.requests.len >= replay.outcomes.len);
        const index = replay.count;
        replay.count += 1;
        if (index >= replay.outcomes.len) return .{ .other = .{ .transient = false } };
        replay.requests[index] = replay.copy(request) catch return .io_failure;
        return replay.outcomes[index];
    }

    fn copy(replay: *Replay, request: *const Request) Allocator.Error!Request {
        const gpa = replay.allocator;
        const headers = try gpa.alloc(sigv4.Pair, request.headers.len);
        for (headers, request.headers) |*out, header| {
            out.* = .{
                .name = try gpa.dupe(u8, header.name),
                .value = try gpa.dupe(u8, header.value),
            };
        }
        return .{
            .method = try gpa.dupe(u8, request.method),
            .scheme = try gpa.dupe(u8, request.scheme),
            .host = try gpa.dupe(u8, request.host),
            .path = try gpa.dupe(u8, request.path),
            .headers = headers,
            .body = try gpa.dupe(u8, request.body),
        };
    }

    pub fn recorded(replay: *const Replay) []const Request {
        return replay.requests[0..@min(replay.count, replay.outcomes.len)];
    }
};

/// A transport that replays a separate script per host, for commands whose regions run
/// concurrently. Each route records its own requests; a request to an unknown host, or past
/// its route's script, fails as an unclassified dispatch failure. Safe across threads when
/// `allocator` is.
pub const RoutedReplay = struct {
    routes: []Route,
    allocator: Allocator,

    pub const Route = struct {
        host: []const u8,
        outcomes: []const Outcome,
        requests: []Request,
        count: std.atomic.Value(usize) = .init(0),

        pub fn recorded(self: *const Route) []const Request {
            const count = self.count.load(.acquire);
            return self.requests[0..@min(count, self.outcomes.len)];
        }
    };

    pub fn transport(replay: *RoutedReplay) Transport {
        return .{ .context = replay, .send_fn = send };
    }

    fn send(context: *anyopaque, _: Allocator, request: *const Request) Io.Cancelable!Outcome {
        const replay: *RoutedReplay = @ptrCast(@alignCast(context));
        const found = for (replay.routes) |*candidate| {
            if (std.mem.eql(u8, candidate.host, request.host)) break candidate;
        } else return .{ .other = .{ .transient = false } };
        assert(found.requests.len >= found.outcomes.len);
        const index = found.count.fetchAdd(1, .acq_rel);
        if (index >= found.outcomes.len) return .{ .other = .{ .transient = false } };
        var copier: Replay = .{ .outcomes = &.{}, .requests = &.{}, .allocator = replay.allocator };
        found.requests[index] = copier.copy(request) catch return .io_failure;
        return found.outcomes[index];
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
