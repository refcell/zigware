//! The `collector` fuzz target of commonware's `collector/fuzz`: fuzzed sends, cancels, handler
//! calls, monitor calls, and engine (re)starts against collector engines on mock channels.
//!
//! As in commonware, the mock senders reach nobody and the mock receivers are closed, so each
//! engine stops once it first runs; its mailbox then refuses commands. Handlers and monitors
//! exist only for index 2 of the three peers (commonware keys them 2..5), and requests sent to
//! a handler directly must be answered with their own id.
//!
//! Inputs come from `invariants.minifuzz.Unstructured` in the order of commonware's
//! `FuzzInput::arbitrary`, and every random choice draws from `utils.rng.TestRng` like
//! `rand` 0.10 does, so an input replays commonware's run.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const build_options = @import("build_options");
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;

const collector = @import("root.zig");

const Unstructured = minifuzz.Unstructured;
const TestRng = utils.rng.TestRng;
const metrics = runtime.telemetry.metrics;
const oneshot = utils.channel.oneshot;
const Sha256 = cryptography.Sha256;
const Key = cryptography.ed25519.PublicKey;
const Recipients = p2p.Recipients(Key);

const max_len = 1_000_000;
const operations_max = 256;
/// Longest fuzzed byte string (`Vec<u8>`); the input runs out long before.
const bytes_max = 4096;
const min_buffer_size: u16 = 1;
/// commonware creates peers for `i in 2..5`.
const peer_count = 3;
/// The one peer index with a handler and a monitor: commonware keys them by `i` in 2..5,
/// so only index 2 finds one, holding the first peer's handler.
const handled_index = 2;

fn be_bytes(value: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return bytes;
}

/// SHA-256 of the encoding of `id` then `data` (a length-prefixed byte vector).
fn digest_encoding(id: u64, data: []const u8) Sha256.Digest {
    assert(data.len <= std.math.maxInt(u32));
    var prefix: [5]u8 = undefined;
    var writer = codec.Writer.init(&prefix);
    codec.write(usize, data.len, &writer);
    assert(writer.written().len > 0);
    return Sha256.hash(&.{ &be_bytes(id), writer.written(), data });
}

/// A request: an id and some data, committed to by its id.
pub const FuzzRequest = struct {
    id: u64,
    data: []const u8,

    pub const Commitment = Sha256.Digest;
    pub const Digest = Sha256.Digest;
    pub const Cfg = codec.RangeCfg(usize);

    pub fn write(request: FuzzRequest, writer: *codec.Writer) void {
        writer.write_int(u64, request.id);
        codec.write([]const u8, request.data, writer);
    }

    pub fn encode_size(request: FuzzRequest) usize {
        return 8 + codec.encode_size([]const u8, request.data);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, range: Cfg) codec.Error!FuzzRequest {
        const id = try reader.read_int(u64);
        return .{ .id = id, .data = try codec.read_range([]const u8, gpa, reader, range) };
    }

    pub fn deinit(request: *FuzzRequest, gpa: Allocator) void {
        gpa.free(request.data);
        request.* = undefined;
    }

    pub fn commitment(request: *const FuzzRequest) Commitment {
        return Sha256.hash(&.{&be_bytes(request.id)});
    }

    pub fn digest(request: *const FuzzRequest) Digest {
        return digest_encoding(request.id, request.data);
    }

    fn arbitrary(gpa: Allocator, u: *Unstructured) !FuzzRequest {
        const id = try u.arbitrary(u64);
        return .{ .id = id, .data = try u.arbitrary_bytes(gpa, bytes_max) };
    }
};

/// A response: an id and a result, committed to by its id. It keeps its allocator so the
/// oneshot channel can free one that is never received (`discard`).
pub const FuzzResponse = struct {
    id: u64,
    result: []const u8,
    gpa: Allocator,

    pub const Commitment = Sha256.Digest;
    pub const Digest = Sha256.Digest;
    pub const Cfg = codec.RangeCfg(usize);

    pub fn write(response: FuzzResponse, writer: *codec.Writer) void {
        writer.write_int(u64, response.id);
        codec.write([]const u8, response.result, writer);
    }

    pub fn encode_size(response: FuzzResponse) usize {
        return 8 + codec.encode_size([]const u8, response.result);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, range: Cfg) codec.Error!FuzzResponse {
        const id = try reader.read_int(u64);
        const result = try codec.read_range([]const u8, gpa, reader, range);
        return .{ .id = id, .result = result, .gpa = gpa };
    }

    pub fn deinit(response: *FuzzResponse, gpa: Allocator) void {
        assert(gpa.ptr == response.gpa.ptr);
        gpa.free(response.result);
        response.* = undefined;
    }

    pub fn discard(response: FuzzResponse) void {
        var owned = response;
        owned.deinit(response.gpa);
    }

    pub fn commitment(response: *const FuzzResponse) Commitment {
        return Sha256.hash(&.{&be_bytes(response.id)});
    }

    pub fn digest(response: *const FuzzResponse) Digest {
        return digest_encoding(response.id, response.result);
    }

    fn arbitrary(gpa: Allocator, u: *Unstructured) !FuzzResponse {
        const id = try u.arbitrary(u64);
        return .{ .id = id, .result = try u.arbitrary_bytes(gpa, bytes_max), .gpa = gpa };
    }
};

/// Answers each request with its configured response, or echoes its data, when `respond`.
const FuzzHandler = struct {
    pub const PublicKey = Key;
    pub const Request = FuzzRequest;
    pub const Response = FuzzResponse;

    gpa: Allocator,
    respond: bool,
    /// commonware's `HashMap<u64, FuzzResponse>`: a later insert of an id replaces the
    /// earlier one, so lookups search from the back.
    responses: [responses_max]Configured = undefined,
    response_count: usize = 0,

    const responses_max = 9;
    const Configured = struct { id: u64, result: []u8 };

    fn init(gpa: Allocator, respond: bool, seed: u64) !FuzzHandler {
        var rng = TestRng.init(seed);
        var handler: FuzzHandler = .{ .gpa = gpa, .respond = respond };
        errdefer handler.deinit();
        const count = utils.rng.range_less_than(&rng, u32, 0, 10);
        assert(count <= responses_max);
        for (0..count) |_| {
            const id = rng.next_u64();
            const result_len = utils.rng.range_less_than(&rng, usize, 0, 100);
            const result = try gpa.alloc(u8, result_len);
            rng.fill_bytes(result);
            handler.responses[handler.response_count] = .{ .id = id, .result = result };
            handler.response_count += 1;
        }
        return handler;
    }

    fn clone(handler: *const FuzzHandler) !FuzzHandler {
        var copy: FuzzHandler = .{ .gpa = handler.gpa, .respond = handler.respond };
        errdefer copy.deinit();
        for (handler.responses[0..handler.response_count]) |configured| {
            const result = try handler.gpa.dupe(u8, configured.result);
            copy.responses[copy.response_count] = .{ .id = configured.id, .result = result };
            copy.response_count += 1;
        }
        assert(copy.response_count == handler.response_count);
        return copy;
    }

    pub fn deinit(handler: *FuzzHandler) void {
        for (handler.responses[0..handler.response_count]) |configured| {
            handler.gpa.free(configured.result);
        }
        handler.* = undefined;
    }

    fn configured_result(handler: *const FuzzHandler, id: u64) ?[]const u8 {
        var index = handler.response_count;
        while (index > 0) {
            index -= 1;
            if (handler.responses[index].id == id) return handler.responses[index].result;
        }
        return null;
    }

    pub fn process(
        handler: *FuzzHandler,
        origin: Key,
        request: FuzzRequest,
        responder: oneshot.Sender(FuzzResponse),
    ) !void {
        _ = origin;
        var owned_request = request;
        defer owned_request.deinit(handler.gpa);
        var owned = responder;
        if (!handler.respond) return owned.deinit();
        const result = handler.configured_result(request.id) orelse request.data;
        const response: FuzzResponse = .{
            .id = request.id,
            .result = try handler.gpa.dupe(u8, result),
            .gpa = handler.gpa,
        };
        owned.send(response) catch response.discard(); // The receiver may be gone.
    }
};

/// Counts collected responses.
const FuzzMonitor = struct {
    pub const PublicKey = Key;
    pub const Response = FuzzResponse;

    collected_count: usize = 0,

    pub fn collected(
        monitor: *FuzzMonitor,
        handler: Key,
        response: FuzzResponse,
        count: usize,
    ) void {
        _ = handler;
        _ = count;
        response.discard();
        monitor.collected_count += 1;
        assert(monitor.collected_count > 0);
    }
};

/// Blocks nobody.
const FuzzBlocker = struct {
    pub const PublicKey = Key;

    const Subscription = struct {
        pub fn recv(_: *Subscription, _: Allocator) Allocator.Error!?[]Key {
            return null;
        }
    };

    pub fn block(_: FuzzBlocker, _: Key) collector.Feedback {
        return .ok;
    }

    pub fn blocked(_: FuzzBlocker) Allocator.Error!Subscription {
        return .{};
    }
};

/// commonware's `MockSender`, `MockCheckedSender`, and closed `MockReceiver`.
const MockNet = struct {
    pub const Sender = struct {
        gpa: Allocator,

        /// Accepted, reaching no recipients.
        pub fn send(
            sender: *Sender,
            recipients: Recipients,
            parts: []const []const u8,
            priority: bool,
        ) ![]Key {
            _ = priority;
            assert(recipients != .some or recipients.some.len <= peer_count);
            assert(parts.len > 0);
            return sender.gpa.alloc(Key, 0);
        }

        pub fn deinit(sender: *Sender) void {
            sender.* = undefined;
        }
    };

    /// Its sender is dropped before the engine first runs, so `recv` fails at once.
    pub const Receiver = struct {
        pub const PublicKey = Key;

        pub fn recv(_: *Receiver) error{ Closed, Canceled }!p2p.Message(Key) {
            return error.Closed;
        }

        pub fn capacity(_: *const Receiver) usize {
            return 1024;
        }

        pub fn deinit(receiver: *Receiver) void {
            receiver.* = undefined;
        }
    };
};

const Engine = collector.p2p.Engine(FuzzHandler, FuzzMonitor, FuzzBlocker, MockNet);

const RecipientsType = enum { all, one, some };

const Operation = union(enum) {
    send_request: struct { peer_index: u8, request: FuzzRequest, recipients_type: RecipientsType },
    cancel_request: struct { request_id: u64 },
    process_handler: struct {
        peer_index: u8,
        origin_index: u8,
        request: FuzzRequest,
        should_respond: bool,
    },
    monitor_collected: struct { peer_index: u8, response: FuzzResponse, count: u64 },
    create_engine: struct {
        peer_index: u8,
        mailbox_size: u16,
        priority_request: bool,
        priority_response: bool,
    },

    fn arbitrary(gpa: Allocator, u: *Unstructured) !Operation {
        return switch (try u.variant_index(5)) {
            0 => .{ .send_request = .{
                .peer_index = try u.arbitrary(u8),
                .request = try FuzzRequest.arbitrary(gpa, u),
                .recipients_type = try u.arbitrary(RecipientsType),
            } },
            1 => .{ .cancel_request = .{ .request_id = try u.arbitrary(u64) } },
            2 => .{ .process_handler = .{
                .peer_index = try u.arbitrary(u8),
                .origin_index = try u.arbitrary(u8),
                .request = try FuzzRequest.arbitrary(gpa, u),
                .should_respond = try u.arbitrary(bool),
            } },
            3 => .{ .monitor_collected = .{
                .peer_index = try u.arbitrary(u8),
                .response = try FuzzResponse.arbitrary(gpa, u),
                .count = try u.arbitrary(u64),
            } },
            else => .{ .create_engine = try u.arbitrary(@FieldType(Operation, "create_engine")) },
        };
    }

    /// Frees what the operation still owns.
    fn deinit(operation: *Operation, gpa: Allocator) void {
        switch (operation.*) {
            .send_request => |*send| send.request.deinit(gpa),
            .process_handler => |*process| process.request.deinit(gpa),
            .monitor_collected => |*monitor| monitor.response.deinit(gpa),
            .cancel_request, .create_engine => {},
        }
        operation.* = .{ .cancel_request = .{ .request_id = 0 } };
    }
};

/// commonware's `FuzzInput`.
const Input = struct {
    seed: u64,
    operations: std.ArrayList(Operation) = .empty,

    fn arbitrary(gpa: Allocator, u: *Unstructured) !Input {
        var input: Input = .{ .seed = try u.arbitrary(u64) };
        errdefer input.deinit(gpa);
        const count = u.int_in_range(usize, 1, operations_max);
        try input.operations.ensureTotalCapacityPrecise(gpa, count);
        for (0..count) |_| {
            input.operations.appendAssumeCapacity(try Operation.arbitrary(gpa, u));
        }
        assert(input.operations.items.len == count);
        return input;
    }

    fn deinit(input: *Input, gpa: Allocator) void {
        for (input.operations.items) |*operation| operation.deinit(gpa);
        input.operations.deinit(gpa);
    }
};

/// The peers, handler, monitor, and engines of one case.
const Harness = struct {
    gpa: Allocator,
    io: Io,
    rng: TestRng,
    registry: metrics.Registry,
    peers: [peer_count]cryptography.ed25519.PrivateKey = undefined,
    handler: FuzzHandler = undefined,
    monitor: FuzzMonitor = .{},
    mailboxes: [peer_count]?Engine.Mailbox = @splat(null),
    engines: std.ArrayList(Io.Future(Engine.Error!void)) = .empty,
    restarts: u64 = 0,

    /// commonware draws a seed and a `respond` bit per peer and builds each peer's handler
    /// from its seed; only the first (key 2) is ever reached.
    fn init(harness: *Harness) !void {
        for (&harness.peers, 0..) |*peer, index| {
            const seed = harness.rng.next_u64();
            peer.* = .from_seed(seed);
            const respond = utils.rng.boolean(&harness.rng);
            if (index == 0) harness.handler = try FuzzHandler.init(harness.gpa, respond, seed);
        }
        assert(harness.peers.len == peer_count);
    }

    fn public_key(harness: *const Harness, index: usize) Key {
        return harness.peers[index].public_key();
    }

    fn act(harness: *Harness, operation: *Operation) !void {
        switch (operation.*) {
            .send_request => |send| {
                const index = send.peer_index % peer_count;
                const mailbox = harness.mailboxes[index] orelse return;
                var some: [peer_count]Key = undefined;
                const recipients: Recipients = switch (send.recipients_type) {
                    .all => .all,
                    .one => .{ .one = harness.public_key(
                        utils.rng.range_less_than(&harness.rng, usize, 0, peer_count),
                    ) },
                    .some => .{ .some = harness.select(index, &some) },
                };
                operation.* = .{ .cancel_request = .{ .request_id = 0 } }; // Moved to `send`.
                _ = try mailbox.send(recipients, send.request);
            },
            .cancel_request => |cancel| {
                const request: FuzzRequest = .{ .id = cancel.request_id, .data = &.{} };
                for (harness.mailboxes) |entry| {
                    if (entry) |mailbox| _ = try mailbox.cancel(request.commitment());
                }
            },
            .process_handler => |call| {
                const origin = harness.public_key(call.origin_index % peer_count);
                if (call.peer_index % peer_count != handled_index) return;
                const request = call.request;
                operation.* = .{ .cancel_request = .{ .request_id = 0 } }; // Moved below.
                try harness.process(origin, request, call.should_respond);
            },
            .monitor_collected => |collected| {
                if (collected.peer_index % peer_count != handled_index) return;
                operation.* = .{ .cancel_request = .{ .request_id = 0 } }; // Moved to `collected`.
                const handler = harness.public_key(handled_index);
                harness.monitor.collected(handler, collected.response, collected.count);
            },
            .create_engine => |create| try harness.create_engine(create),
        }
    }

    /// Every peer other than `index`, each with probability one half.
    fn select(harness: *Harness, index: usize, out: *[peer_count]Key) []const Key {
        var count: usize = 0;
        for (0..peer_count) |other| {
            if (other != index and utils.rng.bernoulli(&harness.rng, 0.5)) {
                out[count] = harness.public_key(other);
                count += 1;
            }
        }
        assert(count < peer_count);
        return out[0..count];
    }

    /// Calls the handler directly; a reply it sends must carry the request's id.
    fn process(harness: *Harness, origin: Key, request: FuzzRequest, should_respond: bool) !void {
        const id = request.id;
        const pair = oneshot.channel(FuzzResponse, harness.gpa, harness.io) catch |err| {
            var owned = request;
            owned.deinit(harness.gpa);
            return err;
        };
        var receiver = pair.receiver;
        defer receiver.deinit();
        try harness.handler.process(origin, request, pair.sender);
        if (!should_respond) return;
        var response = receiver.recv() catch |err| switch (err) {
            error.Closed => return,
            error.Canceled => return error.Canceled,
        };
        defer response.deinit(harness.gpa);
        try testing.expectEqual(id, response.id);
    }

    fn create_engine(harness: *Harness, create: @FieldType(Operation, "create_engine")) !void {
        const gpa = harness.gpa;
        const index = create.peer_index % peer_count;
        const handler = if (index == handled_index)
            try harness.handler.clone()
        else
            try FuzzHandler.init(gpa, true, harness.rng.next_u64());
        const monitor = if (index == handled_index) harness.monitor else FuzzMonitor{};
        const scope = metrics.Scope.init(&harness.registry).child("engine")
            .with_attribute("instance", harness.restarts);
        const created = Engine.init(gpa, harness.io, &scope, .{
            .blocker = .{},
            .monitor = monitor,
            .handler = handler,
            .mailbox_size = @max(create.mailbox_size, min_buffer_size),
            .priority_request = create.priority_request,
            .request_codec = .to_inclusive(max_len),
            .priority_response = create.priority_response,
            .response_codec = .to_inclusive(max_len),
        }) catch |err| {
            var owned = handler;
            owned.deinit();
            return err;
        };
        harness.restarts += 1;
        if (harness.mailboxes[index]) |*old| old.deinit();
        harness.mailboxes[index] = created.mailbox;
        try harness.engines.ensureUnusedCapacity(gpa, 1);
        const future = try created.engine.start(.{ .gpa = gpa }, .{}, .{ .gpa = gpa }, .{});
        harness.engines.appendAssumeCapacity(future);
    }

    fn deinit(harness: *Harness) void {
        for (&harness.mailboxes) |*entry| {
            if (entry.*) |*mailbox| mailbox.deinit();
        }
        for (harness.engines.items) |*future| {
            future.cancel(harness.io) catch |err| std.debug.panic("engine: {t}", .{err});
        }
        harness.engines.deinit(harness.gpa);
        harness.handler.deinit();
        harness.registry.deinit();
    }
};

fn run_case(gpa: Allocator, io: Io, input: *Input) !void {
    var harness: Harness = .{
        .gpa = gpa,
        .io = io,
        .rng = TestRng.init(input.seed),
        .registry = .init(gpa),
    };
    harness.init() catch |err| {
        harness.registry.deinit();
        return err;
    };
    defer harness.deinit();
    for (input.operations.items) |*operation| {
        try harness.act(operation);
        try io.sleep(.fromMilliseconds(100), .awake);
    }
}

/// Runs one input on a fresh deterministic runtime seeded like commonware's.
pub fn run(gpa: Allocator, u: *Unstructured) !void {
    var input = try Input.arbitrary(gpa, u);
    defer input.deinit(gpa);
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = input.seed });
    defer runner.deinit();
    try (try runner.start(run_case, .{ gpa, runner.io(), &input }));
}

/// Runs `bytes` as one input, as the coverage-guided target does.
pub fn run_input(gpa: Allocator, bytes: []const u8) !void {
    var u = Unstructured.init(bytes);
    run(gpa, &u) catch |err| switch (err) {
        error.NotEnoughData, error.IncorrectFormat => {},
        else => return err,
    };
}

fn body(_: void, u: *Unstructured) !void {
    return run(testing.allocator, u);
}

test "fuzz collector (minifuzz)" {
    const limit = 16 * @as(u64, build_options.fuzz_soak);
    try (minifuzz.Builder{}).with_seed(build_options.fuzz_seed).with_search_limit(limit)
        .run(testing.allocator, {}, body);
}

// minifuzz grows its inputs only when one runs out, which these generators never report, so
// random inputs reach the deeper actions.
test "fuzz collector (random inputs)" {
    const cases = 16 * @as(u64, build_options.fuzz_soak);
    for (0..cases) |case| {
        var rng = utils.rng.TestRng.init(build_options.fuzz_seed +% case);
        var bytes: [2048]u8 = undefined;
        rng.fill_bytes(&bytes);
        try run_input(testing.allocator, &bytes);
    }
}

test "fuzz collector (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn fuzz(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [4096]u8 = undefined;
            const length = smith.slice(&bytes);
            try run_input(testing.allocator, bytes[0..length]);
        }
    }.fuzz, .{});
}

test "fuzz request and response digest their encoding" {
    const gpa = testing.allocator;
    const request: FuzzRequest = .{ .id = 7, .data = "data" };
    const encoded = try codec.encode(FuzzRequest, gpa, request);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 7, 4, 'd', 'a', 't', 'a' }, encoded);
    try testing.expect(request.digest().eql(Sha256.hash(&.{encoded})));
    const response: FuzzResponse = .{ .id = 7, .result = "data", .gpa = gpa };
    try testing.expect(response.digest().eql(request.digest()));
    try testing.expect(response.commitment().eql(Sha256.hash(&.{&be_bytes(7)})));
}
