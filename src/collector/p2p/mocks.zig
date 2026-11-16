//! Mock implementations for testing the collector (commonware `collector/src/p2p/mocks`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");

const Sha256 = cryptography.Sha256;
const Unbounded = p2p.simulated.channel.Unbounded;
const oneshot = utils.channel.oneshot;
const Key = cryptography.ed25519.PublicKey;

fn be_bytes(value: anytype) [@sizeOf(@TypeOf(value))]u8 {
    return std.mem.toBytes(std.mem.nativeToBig(@TypeOf(value), value));
}

/// The mock request and response types (commonware `mocks::types`).
pub const types = struct {
    /// A mock request for testing.
    pub const Request = struct {
        id: u64,
        data: u32,

        pub const fixed_size: usize = 8 + 4;
        pub const Commitment = Sha256.Digest;
        pub const Digest = Sha256.Digest;

        pub fn write(request: Request, writer: *codec.Writer) void {
            writer.write_int(u64, request.id);
            writer.write_int(u32, request.data);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: void) codec.Error!Request {
            _ = gpa;
            _ = cfg;
            const id = try reader.read_int(u64);
            const data = try reader.read_int(u32);
            return .{ .id = id, .data = data };
        }

        pub fn commitment(request: *const Request) Commitment {
            return Sha256.hash(&.{&be_bytes(request.id)});
        }

        pub fn digest(request: *const Request) Digest {
            return Sha256.hash(&.{ &be_bytes(request.id), &be_bytes(request.data) });
        }
    };

    /// A mock response for testing (a different size, so it never parses as a `Request`).
    pub const Response = struct {
        id: u64,
        result: u64,

        pub const fixed_size: usize = 8 + 8;
        pub const Commitment = Sha256.Digest;
        pub const Digest = Sha256.Digest;

        pub fn write(response: Response, writer: *codec.Writer) void {
            writer.write_int(u64, response.id);
            writer.write_int(u64, response.result);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: void) codec.Error!Response {
            _ = gpa;
            _ = cfg;
            const id = try reader.read_int(u64);
            const result = try reader.read_int(u64);
            return .{ .id = id, .result = result };
        }

        pub fn commitment(response: *const Response) Commitment {
            return Sha256.hash(&.{&be_bytes(response.id)});
        }

        pub fn digest(response: *const Response) Digest {
            return Sha256.hash(&.{ &be_bytes(response.id), &be_bytes(response.result) });
        }
    };
};

const MockRequest = types.Request;
const MockResponse = types.Response;

/// A mock handler received a request.
pub const Processed = struct {
    origin: Key,
    request: MockRequest,
    responded: bool,
};

/// A mock `Handler`: reports each request and answers with a configured response, or with
/// `data * 2` when `respond_by_default` is set.
pub const Handler = struct {
    pub const PublicKey = Key;
    pub const Request = types.Request;
    pub const Response = types.Response;

    sender: ?Unbounded(Processed).Sender,
    /// Configured responses by request id (borrowed).
    responses: []const MockResponse = &.{},
    respond_by_default: bool,

    pub const Events = Unbounded(Processed).Receiver;

    /// A handler and the receiver of its `Processed` events.
    pub fn init(gpa: Allocator, io: Io, respond_by_default: bool) !struct {
        handler: Handler,
        events: Events,
    } {
        const pair = try Unbounded(Processed).init(gpa, io);
        assert(!pair.sender.is_closed());
        return .{
            .handler = .{ .sender = pair.sender, .respond_by_default = respond_by_default },
            .events = pair.receiver,
        };
    }

    /// A handler that responds by default and reports nothing.
    pub fn dummy() Handler {
        return .{ .sender = null, .respond_by_default = true };
    }

    pub fn deinit(handler: *Handler) void {
        if (handler.sender) |*sender| sender.deinit();
        handler.* = undefined;
    }

    fn configured(handler: *const Handler, id: u64) ?MockResponse {
        for (handler.responses) |response| {
            if (response.id == id) return response;
        }
        return null;
    }

    pub fn process(
        handler: *Handler,
        origin: Key,
        request: MockRequest,
        responder: oneshot.Sender(MockResponse),
    ) !void {
        const configured_response = handler.configured(request.id);
        const respond = configured_response != null or handler.respond_by_default;
        if (handler.sender) |sender| {
            const processed: Processed = .{
                .origin = origin,
                .request = request,
                .responded = respond,
            };
            _ = try sender.send(processed);
        }
        var owned = responder;
        const response = configured_response orelse if (handler.respond_by_default) MockResponse{
            .id = request.id,
            .result = @as(u64, request.data *% 2),
        } else {
            owned.deinit();
            return;
        };
        owned.send(response) catch {}; // send_lossy: the engine may be gone.
    }
};

/// A mock monitor collected a response.
pub const Collected = struct {
    handler: Key,
    response: MockResponse,
    count: usize,
};

/// A mock `Monitor`: reports every collected response.
pub const Monitor = struct {
    pub const PublicKey = Key;
    pub const Response = types.Response;

    sender: ?Unbounded(Collected).Sender,

    pub const Events = Unbounded(Collected).Receiver;

    pub fn init(gpa: Allocator, io: Io) !struct { monitor: Monitor, events: Events } {
        const pair = try Unbounded(Collected).init(gpa, io);
        assert(!pair.sender.is_closed());
        return .{ .monitor = .{ .sender = pair.sender }, .events = pair.receiver };
    }

    /// A monitor that reports nothing.
    pub fn dummy() Monitor {
        return .{ .sender = null };
    }

    pub fn deinit(monitor: *Monitor) void {
        if (monitor.sender) |*sender| sender.deinit();
        monitor.* = undefined;
    }

    pub fn collected(monitor: *Monitor, handler: Key, response: MockResponse, count: usize) !void {
        const sender = monitor.sender orelse return;
        _ = try sender.send(.{ .handler = handler, .response = response, .count = count });
    }
};

/// A sender whose sends always fail as closed: it reaches no recipients.
pub const Failing = struct {
    gpa: Allocator,

    pub fn send(
        failing: *Failing,
        recipients: p2p.Recipients(Key),
        parts: []const []const u8,
        priority: bool,
    ) ![]Key {
        _ = recipients;
        _ = parts;
        _ = priority;
        return failing.gpa.alloc(Key, 0);
    }

    pub fn deinit(failing: *Failing) void {
        failing.* = undefined;
    }
};

test "mock request and response encode as commonware's" {
    const testing = std.testing;
    const request: MockRequest = .{ .id = 1, .data = 2 };
    const encoded = codec.encode_fixed(MockRequest, request);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2 }, &encoded);
    const response: MockResponse = .{ .id = 1, .result = 2 };
    try testing.expect(request.commitment().eql(response.commitment()));
    try testing.expect(!request.digest().eql(response.digest()));
    try testing.expectError(
        error.EndOfBuffer,
        codec.decode(MockResponse, testing.allocator, &encoded),
    );
}
