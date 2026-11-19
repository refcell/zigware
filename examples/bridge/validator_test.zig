//! The validator's CLI against commonware's `validator` binary
//! (`testdata/validator_clap_cases.txt`, printed by it for the same arguments), and the
//! panics its `main` raises for malformed arguments, as that binary prints them, and the
//! indexer connection over loopback.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const ui = @import("ui");
const validator = @import("validator.zig");
const bridge_test = @import("bridge_test.zig");

fn run_cli(gpa: std.mem.Allocator, args: []const []const u8, out: *Io.Writer) !u8 {
    _ = gpa;
    return switch (try validator.parse(args, "validator", out, out)) {
        .exit => |status| status,
        .run => unreachable, // Proof: every recorded case exits in clap.
    };
}

test "bridge: the validator's CLI prints clap's help and errors" {
    const cases = @embedFile("testdata/validator_clap_cases.txt");
    try bridge_test.expect_clap_cases(cases, 5, run_cli);
}

fn field(comptime file: []const u8, comptime prefix: []const u8) []const u8 {
    const text = @embedFile("testdata/" ++ file);
    const start = std.mem.indexOf(u8, text, prefix).? + prefix.len;
    const end = std.mem.indexOfScalarPos(u8, text, start, '\n').?;
    return text[start..end];
}

const polynomial = field("dealer_seed_1.txt", "polynomial: ");
const share = field("dealer_seed_1.txt", "validator=1): ");
const other = field("dealer_seed_2.txt", "public: ");

/// Runs setup on a valid command line with one argument replaced; returns the panic.
fn expect_panic(name: []const u8, value: []const u8, expected: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var args = [_][]const u8{
        "--me",           "1@3001",      "--participants", "1,2,3,4",
        "--storage-dir",  "/tmp/unused", "--indexer",      "0@127.0.0.1:3000",
        "--identity",     polynomial,    "--share",        share,
        "--other-public", other,
    };
    var index: usize = 0;
    while (!std.mem.eql(u8, args[index], name)) index += 2;
    args[index + 1] = value;
    var sink: Io.Writer.Discarding = .init(&.{});
    const values = switch (try validator.parse(&args, "validator", &sink.writer, &sink.writer)) {
        .run => |values| values,
        .exit => return error.TestUnexpectedResult,
    };
    var panic: ui.rust.Panic = .{};
    const result = validator.setup(arena.allocator(), values, .none, &panic);
    if (expected.len == 0) {
        _ = try result;
        return;
    }
    try testing.expectError(error.Panic, result);
    try testing.expectEqualStrings(expected, panic.message());
}

test "bridge: the validator panics as commonware's main does" {
    try expect_panic("--me", "1@3001", "");
    try expect_panic("--identity", "zz", "Identity not well-formed");
    try expect_panic("--identity", "ab", "Identity not well-formed: InvalidEnum(171)");
    try expect_panic("--share", "ab", "Share not well-formed: EndOfBuffer");
    try expect_panic(
        "--indexer",
        "0x@1",
        "Indexer key not well-formed: ParseIntError { kind: InvalidDigit }",
    );
    try expect_panic("--indexer", "0", "index out of bounds: the len is 1 but the index is 1");
    try expect_panic(
        "--indexer",
        "0@nope",
        "Indexer address not well-formed: AddrParseError(Socket)",
    );
    try expect_panic("--other-public", "ab", "Other identity not well-formed: EndOfBuffer");
    try expect_panic(
        "--participants",
        "1,2,3",
        "Identity not well-formed: Invalid(\"Sharing\", \"total not in range\")",
    );
}

const zigware = @import("zigware");
const indexer = @import("indexer.zig");
const lib = @import("lib.zig");
const store_mod = @import("store.zig");
const store_test = @import("store_test.zig");
const types = @import("types.zig");
const ed25519 = zigware.cryptography.ed25519;
const production = zigware.runtime.production;

const Response = Io.Cancelable!types.Outbound;

fn request_task(connection: *validator.Indexer, io: Io, inbound: types.Inbound) Response {
    return connection.request(io, inbound);
}

fn cancel_task(future: *Io.Future(Response), io: Io) Response {
    return future.cancel(io);
}

/// Dials the indexer listening on `listener` as validator 1 and authenticates both sides.
fn connect(
    io: Io,
    network: *production.network.Network,
    server: *indexer.Server,
    listener: *production.network.Network.Listener,
    connections: *Io.Group,
) !validator.Indexer {
    const gpa = testing.allocator;
    const indexer_key = ed25519.PrivateKey.from_seed(0);
    const validator_key = ed25519.PrivateKey.from_seed(1);
    const config = .{ .synchrony_bound_ms = 1_000, .max_handshake_age_ms = 60_000, .version = .v1 };
    const accept_upgrader: indexer.Upgrader = .init(.init(.{
        .signer = indexer_key,
        .synchrony_bound_ms = config.synchrony_bound_ms,
        .max_handshake_age_ms = config.max_handshake_age_ms,
        .version = config.version,
    }, .v1), .fromSeconds(5));
    var accepting = try io.concurrent(indexer.Server.accept, .{
        server, listener, accept_upgrader, connections,
    });
    var dialed = try network.dial(listener.local_addr());
    const dial_upgrader: zigware.stream.utils.Timeout(validator.Cups) = .init(.init(.{
        .signer = validator_key,
        .synchrony_bound_ms = config.synchrony_bound_ms,
        .max_handshake_age_ms = config.max_handshake_age_ms,
        .version = config.version,
    }, .v1), .fromSeconds(5));
    const upgraded = dial_upgrader.dial(
        gpa,
        io,
        lib.indexer_namespace,
        lib.max_message_size,
        indexer_key.public_key(),
        dialed.stream,
        dialed.sink,
    ) catch |err| {
        dialed.deinit();
        return err;
    };
    try accepting.await(io);
    return .{ .gpa = gpa, .connection = upgraded };
}

/// A request canceled while the indexer holds its answer, then the next request on the same
/// connection, over loopback on the production runtime.
fn canceled_request(io: Io, network: *production.network.Network) !void {
    const gpa = testing.allocator;
    var fixture = try store_test.network_fixture(gpa, 1, 4);
    defer fixture.deinit(gpa);
    const public = fixture.verifier.identity();
    var store: store_mod.Store = try .init(gpa, &.{public}, .none);
    defer store.deinit(gpa);
    var server: indexer.Server = .{
        .gpa = gpa,
        .io = io,
        .store = &store,
        .tracer = .none,
        .validators = &.{ed25519.PrivateKey.from_seed(1).public_key()},
    };
    const listener = try network.bind(.{ .ip4 = .loopback(0) });
    defer listener.deinit();
    var connections: Io.Group = .init;
    defer connections.cancel(io);
    var connection = try connect(io, network, &server, listener, &connections);
    defer connection.connection.deinit(gpa);

    // Hold the store so the indexer cannot answer, and send a put: it succeeds once answered.
    try server.mutex.lock(io);
    const put: types.Inbound = .{ .put_block = .{ .network = public, .block = .{ .random = 7 } } };
    var pending = try io.concurrent(request_task, .{ &connection, io, put });
    // The indexer has received the put once it waits for the store.
    while (server.mutex.state.load(.monotonic) != .contended) {
        try io.sleep(.fromMilliseconds(1), .real);
    }
    // Cancel the request between its send and its receive, then let the indexer answer.
    var canceling = try io.concurrent(cancel_task, .{ &pending, io });
    try io.sleep(.fromMilliseconds(50), .real);
    server.mutex.unlock(io);
    try testing.expectError(error.Canceled, canceling.await(io));

    // The next request reads its own response: no block has this digest.
    const get: types.Inbound = .{ .get_block = .{
        .network = public,
        .digest = store_mod.block_digest(.{ .random = 8 }),
    } };
    const response = try connection.request(io, get);
    try testing.expect(!response.success);
}

test "bridge: a canceled indexer request leaves the connection in step" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [128]u8 = undefined;
    const directory = try std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/runner", .{tmp.sub_path});
    var runner: production.Runner = undefined;
    try runner.init(testing.allocator, .{ .storage_directory = directory });
    defer runner.deinit();
    try runner.start(canceled_request, .{ runner.io(), runner.network() });
}
