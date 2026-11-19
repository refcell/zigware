//! Collect blocks and finality certificates (commonware `examples/bridge`'s `indexer`).
//!
//! ```sh
//! zig build run-bridge-indexer -- --me 0@3000 --participants 1,2,3,4,5,6,7,8 \
//!     --networks <network 1 public>,<network 2 public>
//! ```
//!
//! Listens on 127.0.0.1:<port> for validators in `--participants`, authenticates each over an
//! encrypted stream, and answers their requests from one store of blocks and finalizations for
//! each network in `--networks` (each a hex BLS12-381 MinSig public key, the `public` printed
//! by `bridge-dealer`). Logs as `tracing_subscriber::fmt()` at debug and above.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const ui = @import("ui");
const lib = @import("lib.zig");
const types = @import("types.zig");
const store_mod = @import("store.zig");

const codec = zigware.codec;
const rust = ui.rust;
const ed25519 = zigware.cryptography.ed25519;
const PublicKey = ed25519.PublicKey;
const production = zigware.runtime.production;
const traces = zigware.runtime.telemetry.traces;
const Store = store_mod.Store;
pub const Cups = zigware.stream.SakeCups(ed25519.PrivateKey, zigware.cryptography.ChaCha20Poly1305);
pub const Upgrader = zigware.stream.utils.Timeout(Cups);

/// The log target of the indexer's events (the binary's module path).
pub const target = "indexer";

/// Rust's panic exit status, used for commonware's panics.
const panic_status: u8 = 101;

pub const about = "collect blocks and finality certificates";

pub const Clap = ui.clap.Parser(.{ .about = about, .args = &.{
    .{ .long = "me", .required = true },
    .{
        .long = "participants",
        .required = true,
        .delimited = true,
        .value = .u64,
        .help = "All participants",
    },
    .{ .long = "networks", .required = true, .delimited = true, .help = "All networks" },
} });

/// Parses `args` (without argv[0]) as clap does: help goes to `stdout` (exit 0), usage
/// errors to `stderr` (exit 2).
pub fn parse(
    args: []const []const u8,
    bin_name: []const u8,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) Io.Writer.Error!union(enum) { run: Clap.Values, exit: u8 } {
    return switch (try Clap.parse(args, bin_name, stderr)) {
        .help => {
            try Clap.write_help(stdout, bin_name);
            return .{ .exit = 0 };
        },
        .usage_error => .{ .exit = 2 },
        .run => |values| .{ .run = values },
    };
}

/// What commonware's `main` derives from the arguments.
pub const Setup = struct {
    signer: ed25519.PrivateKey,
    port: u16,
    /// The validators allowed to connect.
    validators: []const PublicKey,
    /// The networks served, as given (hex), decoded once the runtime starts.
    networks: []const []const u8,
};

/// Checks the arguments as commonware's `main` does, logging as it goes.
pub fn setup(
    arena: Allocator,
    values: Clap.Values,
    tracer: traces.Tracer,
    panic: *rust.Panic,
) (Allocator.Error || error{Panic})!Setup {
    const me = values[0].?;
    var parts = std.mem.splitScalar(u8, me, '@');
    const key_text = parts.first();
    const port_text = parts.next() orelse return panic.fail("Identity not well-formed", .{});
    if (parts.next() != null) return panic.fail("Identity not well-formed", .{});
    const key = rust.parse_unsigned(u64, key_text) catch |failure|
        return panic.fail("Key not well-formed: {s}", .{rust.int_error_debug(failure)});
    const signer = ed25519.PrivateKey.from_seed(key);
    tracer.event(.info, "loaded signer", .{ .key = signer.public_key() });
    const port = rust.parse_unsigned(u16, port_text) catch |failure|
        return panic.fail("Port not well-formed: {s}", .{rust.int_error_debug(failure)});
    tracer.event(.info, "loaded port", .{ .port = port });

    var validators: std.ArrayList(PublicKey) = .empty;
    var pieces = std.mem.splitScalar(u8, values[1].?, ',');
    while (pieces.next()) |piece| {
        // Proof: clap checked every piece.
        const participant = rust.parse_unsigned(u64, piece) catch unreachable;
        const verifier = ed25519.PrivateKey.from_seed(participant).public_key();
        tracer.event(.info, "registered authorized key", .{ .key = verifier });
        for (validators.items) |earlier| {
            if (earlier.eql(verifier)) return panic.fail(duplicate_key, .{});
        }
        try validators.append(arena, verifier);
    }
    assert(validators.items.len > 0);
    var networks: std.ArrayList([]const u8) = .empty;
    var entries = std.mem.splitScalar(u8, values[2].?, ',');
    while (entries.next()) |entry| try networks.append(arena, entry);
    assert(networks.items.len > 0);
    return .{
        .signer = signer,
        .port = port,
        .validators = validators.items,
        .networks = networks.items,
    };
}

const duplicate_key = "public keys are unique: DuplicateKey";

/// Decodes each network's identity as commonware does once its runtime starts.
pub fn decode_networks(
    arena: Allocator,
    networks: []const []const u8,
    panic: *rust.Panic,
) (Allocator.Error || error{Panic})![]const types.Public {
    const publics = try arena.alloc(types.Public, networks.len);
    for (publics, networks) |*public, network| {
        const bytes = try zigware.formatting.from_hex(arena, network) orelse
            return panic.fail("Network not well-formed", .{});
        public.* = codec.decode(types.Public, arena, bytes) catch |err|
            return panic.fail("Network not well-formed: {t}", .{err});
    }
    return publics;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(io, &stderr_buffer);
    const stderr = &stderr_writer.interface;
    defer stdout.flush() catch {};
    defer stderr.flush() catch {};
    const bin_name = if (args.len > 0) std.fs.path.basename(args[0]) else "indexer";
    const values = switch (try parse(args[@min(args.len, 1)..], bin_name, stdout, stderr)) {
        .exit => |status| return status,
        .run => |values| values,
    };
    var fmt: ui.fmt.Fmt = .{
        .io = io,
        .out = stdout,
        .ansi = ui.fmt.ansi_enabled(init.environ_map.get("NO_COLOR")),
        .level = .debug,
    };
    const tracer: traces.Tracer = .init(fmt.subscriber(), target);
    var panic: rust.Panic = .{};
    const configured = setup(arena, values, tracer, &panic) catch |err| switch (err) {
        error.Panic => return report_panic(stderr, &panic),
        else => |other| return other,
    };
    // tokio's default runner stores under a fresh temporary directory; the indexer stores nothing.
    var suffix: [8]u8 = undefined;
    io.random(&suffix);
    const storage_directory = try std.fmt.allocPrint(arena, "/tmp/commonware_tokio_runtime_{d}", .{
        std.mem.readInt(u64, &suffix, .little),
    });
    var runner: production.Runner = undefined;
    try runner.init(init.gpa, .{
        .storage_directory = storage_directory,
        .subscriber = fmt.subscriber(),
    });
    defer runner.deinit();
    try (try runner.start_context(run, .{ configured, &panic }));
    if (panic.len > 0) return report_panic(stderr, &panic);
    return 0;
}

fn report_panic(stderr: *Io.Writer, panic: *const rust.Panic) !u8 {
    try stderr.print("error: {s}\n", .{panic.message()});
    return panic_status;
}

/// Serves validators until the process ends.
fn run(
    ctx: production.runner.Context,
    configured: Setup,
    panic: *rust.Panic,
) !void {
    const gpa = ctx.gpa();
    const io = ctx.io();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const publics = decode_networks(arena, configured.networks, panic) catch |err| switch (err) {
        error.Panic => return,
        else => |other| return other,
    };
    var store: Store = try .init(gpa, publics, ctx.tracer(target));
    defer store.deinit(gpa);
    var server: Server = .{
        .gpa = gpa,
        .io = io,
        .store = &store,
        .tracer = ctx.tracer(target),
        .validators = configured.validators,
    };
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(configured.port) };
    const listener = ctx.network.bind(address) catch |err|
        std.debug.panic("failed to bind listener: {t}", .{err});
    defer listener.deinit();
    const upgrader: Upgrader = .init(.init(.{
        .signer = configured.signer,
        .synchrony_bound_ms = 1_000,
        .max_handshake_age_ms = 60_000,
        .version = .v1,
    }, .v1), .fromSeconds(5));
    var connections: Io.Group = .init;
    defer connections.cancel(io);
    while (true) try server.accept(listener, upgrader, &connections);
}

const Connection = Cups.Accepted(production.network.Stream, production.network.Sink);

/// Accepts validators and answers their requests from the store.
pub const Server = struct {
    gpa: Allocator,
    io: Io,
    store: *Store,
    /// Held while the store answers a request.
    mutex: Io.Mutex = .init,
    tracer: traces.Tracer,
    validators: []const PublicKey,

    /// Admits only the validators in `--participants`.
    pub fn admit(server: *Server, peer: PublicKey) !bool {
        for (server.validators) |validator| {
            if (validator.eql(peer)) return true;
        }
        return false;
    }

    /// Accepts and authenticates one connection, then serves it in `connections`.
    pub fn accept(
        server: *Server,
        listener: *production.network.Network.Listener,
        upgrader: Upgrader,
        connections: *Io.Group,
    ) Io.Cancelable!void {
        const accepted = listener.accept() catch |err| {
            if (err == error.Canceled) return error.Canceled;
            server.tracer.event(.debug, "failed to accept connection", .{});
            return;
        };
        const io = server.io;
        const upgraded = upgrader.listen(
            server.gpa,
            io,
            lib.indexer_namespace,
            lib.max_message_size,
            server,
            accepted.stream,
            accepted.sink,
        ) catch |err| {
            if (err == error.Canceled) return error.Canceled;
            server.tracer.event(.debug, "failed to upgrade connection", .{ .@"error" = err });
            return;
        };
        server.tracer.event(.info, "upgraded connection", .{ .peer = upgraded.peer });
        connections.concurrent(io, serve, .{ server, upgraded }) catch {
            var dropped = upgraded;
            dropped.deinit(server.gpa);
        };
    }

    /// Answers requests on one connection until it fails or sends an undecodable message.
    fn serve(server: *Server, accepted: Connection) Io.Cancelable!void {
        var upgraded = accepted;
        defer upgraded.deinit(server.gpa);
        const peer = upgraded.peer;
        var response: [types.outbound_size_max]u8 = undefined;
        while (true) {
            const message = upgraded.connection.receiver.recv() catch |err| {
                if (err == error.Canceled) return error.Canceled;
                return;
            };
            const inbound = codec.decode(types.Inbound, server.gpa, message) catch |err| {
                const fields = .{ .err = err, .peer = peer };
                server.tracer.event(.debug, "failed to decode message", fields);
                return;
            };
            const outbound = try server.answer(inbound);
            const encoded = codec.encode_to(types.Outbound, outbound, &response);
            upgraded.connection.sender.send(encoded) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                server.tracer.event(.debug, "failed to send message", .{ .peer = peer });
                return;
            };
        }
    }

    fn answer(server: *Server, inbound: types.Inbound) Io.Cancelable!types.Outbound {
        try server.mutex.lock(server.io);
        defer server.mutex.unlock(server.io);
        var seed: [8]u8 = undefined;
        server.io.random(&seed);
        var rng = zigware.utils.TestRng.init(std.mem.readInt(u64, &seed, .little));
        return server.store.handle(server.gpa, &rng, inbound) catch @panic("out of memory");
    }
};

test {
    _ = @import("indexer_test.zig");
}
