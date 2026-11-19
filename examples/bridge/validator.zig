//! Produce finality certificates and verify external finality certificates (commonware
//! `examples/bridge`'s `validator`).
//!
//! ```sh
//! zig build run-bridge-validator -- --me 1@3001 --participants 1,2,3,4 \
//!     --storage-dir /tmp/zigware-bridge/1 --indexer 0@127.0.0.1:3000 \
//!     --identity <polynomial> --share <share> --other-public <other network's public>
//! ```
//!
//! Connects to the indexer over an encrypted stream, finds the other validators of its
//! network through p2p's authenticated discovery on 127.0.0.1, and runs simplex with the
//! network's BLS12-381 threshold scheme (`--identity` and `--share`, from `bridge-dealer`).
//! Blocks carry random data or the other network's finalizations, verified against
//! `--other-public`. Logs as `tracing_subscriber::fmt()` at debug and above.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const ui = @import("ui");
const lib = @import("lib.zig");
const types = @import("types.zig");
const application = @import("application.zig");

const codec = zigware.codec;
const rust = ui.rust;
const ed25519 = zigware.cryptography.ed25519;
const PublicKey = ed25519.PublicKey;
const primitives = zigware.cryptography.bls12381.primitives;
const Sharing = primitives.sharing.Sharing(lib.Variant);
const Share = primitives.group.Share;
const Sha256 = zigware.cryptography.Sha256;
const simplex = zigware.consensus.simplex;
const traces = zigware.runtime.telemetry.traces;
const production = zigware.runtime.production;
const discovery = zigware.p2p.authenticated.discovery;
pub const Cups = zigware.stream.SakeCups(ed25519.PrivateKey, zigware.cryptography.ChaCha20Poly1305);
const Net = discovery.Network(Cups, production.network.Network);

/// The log target of the validator's own events (the binary's module path).
pub const target = "validator";
/// Messages per second each peer may send on each consensus channel.
pub const message_rate_per_second = 10;

/// Rust's panic exit status, used for commonware's panics.
const panic_status: u8 = 101;

pub const about = "produce finality certificates and verify external finality certificates";

pub const Clap = ui.clap.Parser(.{ .about = about, .args = &.{
    .{ .long = "bootstrappers", .delimited = true },
    .{ .long = "me", .required = true },
    .{
        .long = "participants",
        .required = true,
        .delimited = true,
        .integer = true,
        .help = "All participants",
    },
    .{ .long = "storage-dir", .required = true },
    .{ .long = "indexer", .required = true },
    .{ .long = "identity", .required = true },
    .{ .long = "share", .required = true },
    .{ .long = "other-public", .required = true },
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
    /// The validators of this network, sorted.
    validators: []PublicKey,
    bootstrappers: []const discovery.Bootstrapper(PublicKey),
    max_peers_per_set: usize,
    storage_directory: []const u8,
    /// The network's public polynomial (owned by `arena`).
    identity: Sharing,
    share: Share,
    indexer: PublicKey,
    indexer_address: Io.net.IpAddress,
    other_public: types.Public,
};

const Panic = rust.Panic;

/// Checks the arguments as commonware's `main` does, in its order, logging as it goes.
pub fn setup(
    arena: Allocator,
    values: Clap.Values,
    tracer: traces.Tracer,
    panic: *Panic,
) (Allocator.Error || error{Panic})!Setup {
    var parts = std.mem.splitScalar(u8, values[1].?, '@');
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
    const validators = try participants(arena, values[2].?, tracer, panic);
    const local = signer.public_key();
    const max_peers_per_set = zigware.p2p.sizing.peer_set_limit(PublicKey, validators, local);
    const given = try rust.parse_bootstrappers(arena, values[0], panic);
    const bootstrappers = try discovery_bootstrappers(arena, given);
    const n: u32 = @intCast(validators.len);
    const identity = try decode_hex(Sharing, arena, values[5].?, .{
        .max_participants = n,
        .max_supported_mode = .v0,
    }, "Identity not well-formed", panic);
    const share = try decode_hex(Share, arena, values[6].?, {}, "Share not well-formed", panic);
    const indexer = try parse_indexer(values[4].?, panic);
    const other_public = try decode_hex(
        types.Public,
        arena,
        values[7].?,
        {},
        "Other identity not well-formed",
        panic,
    );
    assert(validators.len > 0);
    return .{
        .signer = signer,
        .port = port,
        .validators = validators,
        .bootstrappers = bootstrappers,
        .max_peers_per_set = max_peers_per_set,
        .storage_directory = values[3].?,
        .identity = identity,
        .share = share,
        .indexer = ed25519.PrivateKey.from_seed(indexer.key).public_key(),
        .indexer_address = indexer.address,
        .other_public = other_public,
    };
}

/// The participants' public keys, logged as registered and sorted; duplicates panic.
fn participants(
    arena: Allocator,
    text: []const u8,
    tracer: traces.Tracer,
    panic: *Panic,
) (Allocator.Error || error{Panic})![]PublicKey {
    var validators: std.ArrayList(PublicKey) = .empty;
    var pieces = std.mem.splitScalar(u8, text, ',');
    while (pieces.next()) |piece| {
        // Proof: clap checked every piece.
        const participant = rust.parse_unsigned(u64, piece) catch unreachable;
        const verifier = ed25519.PrivateKey.from_seed(participant).public_key();
        tracer.event(.info, "registered authorized key", .{ .key = verifier });
        try validators.append(arena, verifier);
    }
    std.sort.pdq(PublicKey, validators.items, {}, PublicKey.less_than);
    for (validators.items[1..], validators.items[0 .. validators.items.len - 1]) |key, prior| {
        if (key.eql(prior)) return panic.fail("public keys are unique: DuplicateKey", .{});
    }
    assert(validators.items.len > 0);
    return validators.items;
}

fn discovery_bootstrappers(
    arena: Allocator,
    given: []const rust.Bootstrapper,
) Allocator.Error![]const discovery.Bootstrapper(PublicKey) {
    const Bootstrapper = discovery.Bootstrapper(PublicKey);
    const bootstrappers = try arena.alloc(Bootstrapper, given.len);
    for (bootstrappers, given) |*bootstrapper, entry| {
        const address: codec.SocketAddr = .{
            .ip = discovery.network.to_ip(entry.address),
            .port = entry.address.getPort(),
        };
        bootstrapper.* = .{
            .peer = ed25519.PrivateKey.from_seed(entry.key).public_key(),
            .ingress = .{ .socket = address },
        };
    }
    assert(bootstrappers.len == given.len);
    return bootstrappers;
}

/// `--indexer <key>@<ip>:<port>`.
fn parse_indexer(text: []const u8, panic: *Panic) error{Panic}!rust.Bootstrapper {
    var parts = std.mem.splitScalar(u8, text, '@');
    const key = rust.parse_unsigned(u64, parts.first()) catch |failure| {
        const debug = rust.int_error_debug(failure);
        return panic.fail("Indexer key not well-formed: {s}", .{debug});
    };
    const address_text = parts.next() orelse return panic.fail(rust.out_of_bounds, .{});
    const address = rust.parse_socket_address(address_text) orelse
        return panic.fail("Indexer address not well-formed: AddrParseError(Socket)", .{});
    return .{ .key = key, .address = address };
}

/// Decodes hex `text` as `T`, panicking with `message` as commonware's `expect` does.
fn decode_hex(
    comptime T: type,
    arena: Allocator,
    text: []const u8,
    cfg: codec.Cfg(T),
    comptime message: []const u8,
    panic: *Panic,
) (Allocator.Error || error{Panic})!T {
    const bytes = try zigware.formatting.from_hex(arena, text) orelse
        return panic.fail(message, .{});
    var reader = codec.Reader.init(bytes);
    return codec.decode_reader(T, arena, &reader, cfg) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => panic.fail(message ++ ": {f}", .{ErrorDebug{
            .err = err,
            .diagnostic = reader.diagnostic,
        }}),
    };
}

/// A codec error as commonware's `Error` derives `Debug`.
pub const ErrorDebug = struct {
    err: codec.Error,
    diagnostic: codec.Diagnostic,

    pub fn format(self: ErrorDebug, writer: *Io.Writer) Io.Writer.Error!void {
        const d = self.diagnostic;
        switch (self.err) {
            error.ExtraData, error.InvalidVarint, error.InvalidEnum, error.InvalidLength => {
                try writer.print("{t}({d})", .{ self.err, d.value });
            },
            error.Invalid => try writer.print("Invalid(\"{s}\", \"{s}\")", .{
                d.context,
                d.message,
            }),
            error.Wrapped => try writer.print("Wrapped(\"{s}\", {s})", .{
                d.context,
                d.message,
            }),
            else => try writer.print("{t}", .{self.err}),
        }
    }
};

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
    const bin_name = if (args.len > 0) std.fs.path.basename(args[0]) else "validator";
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
    var panic: Panic = .{};
    const tracer: traces.Tracer = .init(fmt.subscriber(), target);
    const configured = setup(arena, values, tracer, &panic) catch |err| switch (err) {
        error.Panic => return report_panic(stderr, &panic),
        else => |other| return other,
    };
    var runner: production.Runner = undefined;
    try runner.init(init.gpa, .{
        .storage_directory = configured.storage_directory,
        .subscriber = fmt.subscriber(),
    });
    defer runner.deinit();
    try (try runner.start_context(run, .{configured}));
    return 0;
}

fn report_panic(stderr: *Io.Writer, panic: *const Panic) !u8 {
    try stderr.print("error: {s}\n", .{panic.message()});
    return panic_status;
}

const Stream = production.network.Stream;
const Sink = production.network.Sink;

/// The indexer connection: one request, then its response.
pub const Indexer = struct {
    gpa: Allocator,
    connection: Cups.Connection(Stream, Sink),

    /// The largest `Inbound`: a tag, a network, and a block carrying a finalization.
    const inbound_size_max = types.outbound_size_max + codec.fixed_size(types.Public).?;

    /// Sends `inbound` and returns the indexer's response. The exchange is uncancelable, as
    /// commonware's application actor finishes every request: a cancel between the send and
    /// the receive would leave the response unread (or a frame half written), and every later
    /// request on the connection would read the wrong response or find it closed.
    pub fn request(self: *Indexer, io: Io, inbound: types.Inbound) Io.Cancelable!types.Outbound {
        const protection = io.swapCancelProtection(.blocked);
        const outbound = self.exchange(inbound);
        _ = io.swapCancelProtection(protection);
        try io.checkCancel();
        return outbound;
    }

    fn exchange(self: *Indexer, inbound: types.Inbound) types.Outbound {
        var buffer: [inbound_size_max]u8 = undefined;
        const encoded = codec.encode_to(types.Inbound, inbound, &buffer);
        assert(encoded.len <= inbound_size_max);
        self.connection.sender.send(encoded) catch |err| switch (err) {
            error.Canceled => unreachable, // Cancel protection is blocked.
            else => std.debug.panic("failed to send to indexer: {t}", .{err}),
        };
        const message = self.connection.receiver.recv() catch |err| switch (err) {
            error.Canceled => unreachable, // Cancel protection is blocked.
            else => std.debug.panic("failed to receive from indexer: {t}", .{err}),
        };
        return codec.decode(types.Outbound, self.gpa, message) catch |err|
            std.debug.panic("failed to decode result: {t}", .{err});
    }
};

const App = application.Application(Indexer);

pub const Params = struct {
    pub const Context = production.runner.Context;
    pub const Scheme = lib.Scheme;
    pub const Elector = simplex.elector.RoundRobinElector;
    pub const Blocker = Net.Oracle;
    pub const Digest = lib.Digest;
    pub const Automaton = *App;
    pub const Relay = *App;
    pub const Reporter = *App;
    pub const Strategy = zigware.parallel.Sequential;
    pub const Sender = Net.Sender;
    pub const Receiver = Net.Receiver;
};
const Engine = simplex.Engine(Params);
const Channel = simplex.engine.Channel(Params);

/// Connects to the indexer as commonware's validator does, or panics.
fn connect_indexer(
    ctx: production.runner.Context,
    configured: Setup,
) !Indexer {
    const gpa = ctx.gpa();
    const dialed = ctx.network.dial(configured.indexer_address) catch |err|
        std.debug.panic("Failed to dial indexer: {t}", .{err});
    const upgrader: zigware.stream.utils.Timeout(Cups) = .init(.init(.{
        .signer = configured.signer,
        .synchrony_bound_ms = 1_000,
        .max_handshake_age_ms = 60_000,
        .version = .v1,
    }, .v1), .fromSeconds(5));
    const connection = upgrader.dial(
        gpa,
        ctx.io(),
        lib.indexer_namespace,
        lib.max_message_size,
        configured.indexer,
        dialed.stream,
        dialed.sink,
    ) catch |err| std.debug.panic("Failed to upgrade connection with indexer: {t}", .{err});
    return .{ .gpa = gpa, .connection = connection };
}

/// Discovery on 127.0.0.1:`port`, sized for consensus messages.
fn network_config(configured: Setup) Net.Config {
    const local: codec.SocketAddr = .{
        .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) },
        .port = configured.port,
    };
    const participants_count: u32 = @intCast(configured.validators.len);
    const payload = simplex.limits.max_payload_size(lib.Scheme, lib.Digest, participants_count);
    return Net.Config.local(.{
        .upgrader = .init(.{
            .signer = configured.signer,
            .synchrony_bound_ms = 5_000,
            .max_handshake_age_ms = 10_000,
            .version = .v1,
        }, .v1),
        .namespace = lib.application_namespace ++ lib.p2p_suffix,
        .listen = discovery.network.to_address(local),
        .dialable = .{ .socket = local },
        .bootstrappers = configured.bootstrappers,
        .max_peers_per_set = configured.max_peers_per_set,
        .max_message_size = zigware.p2p.sizing.max_message_size(&.{payload}),
        .mailbox_size = lib.mailbox_size,
    });
}

fn run(ctx: production.runner.Context, configured: Setup) !void {
    const gpa = ctx.gpa();
    const io = ctx.io();
    var indexer = try connect_indexer(ctx, configured);
    defer indexer.connection.deinit(gpa);
    var config = network_config(configured);
    config.tracer = ctx.tracer("commonware_p2p");
    const network = try Net.create(gpa, io, ctx.network, ctx.scope.child("network"), config);
    defer network.destroy();
    _ = network.oracle().track(0, .init_primary(.init(configured.validators)));
    var channels: [3]Channel = undefined;
    for (&channels, 0..) |*channel, index| {
        const registered = try network.register(index, .per_second(message_rate_per_second));
        channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
    }
    var network_task = try io.concurrent(run_network, .{network});
    defer network_task.cancel(io) catch {};

    const namespace = lib.application_namespace ++ lib.consensus_suffix;
    var other = try lib.Scheme.certificate_verifier(gpa, namespace, configured.other_public);
    defer other.deinit(gpa);
    const identity = try configured.identity.clone(gpa);
    var set: zigware.utils.ordered.Set(PublicKey) = try .init(gpa, configured.validators);
    var scheme = try lib.Scheme.signer(gpa, namespace, set, identity, configured.share) orelse
        @panic("share must be in participants");
    set = undefined; // Owned by the scheme, with `identity`.
    defer scheme.deinit(gpa);
    const tracer = ctx.tracer(application.target);
    var app: App = try .init(gpa, io, &indexer, scheme.identity(), &other, tracer, 1024);
    defer app.deinit();
    try run_consensus(ctx, scheme, network, channels, &app);
}

/// Runs simplex over `channels` and posts finalizations until the process ends.
fn run_consensus(
    ctx: production.runner.Context,
    scheme: lib.Scheme,
    network: *Net,
    channels: [3]Channel,
    app: *App,
) !void {
    const gpa = ctx.gpa();
    var page_cache: zigware.runtime.buffer.paged.CacheRef = try .init(gpa, 16_384, 10_000);
    defer page_cache.deinit();
    const n: u32 = @intCast(scheme.participants().len());
    var elector = try simplex.elector.RoundRobin(Sha256).default().build(gpa, n);
    defer elector.deinit(gpa);
    const engine_ctx = ctx.child("engine");
    var engine: Engine = undefined;
    try engine.init(engine_ctx, engine_config(scheme, elector, network.oracle(), app, &page_cache));
    defer engine.deinit();
    const engine_task = try engine_ctx.spawn(Engine.run, .{
        &engine, channels[0], channels[1], channels[2],
    });
    defer if (engine_task.abort()) |result| {
        result catch |err| std.debug.panic("engine failed: {t}", .{err});
    } else |_| {};
    try app.run(ctx.io());
}

/// commonware's `simplex::Config` for the bridge validator.
fn engine_config(
    scheme: lib.Scheme,
    elector: simplex.elector.RoundRobinElector,
    blocker: Net.Oracle,
    app: *App,
    page_cache: *zigware.runtime.buffer.paged.CacheRef,
) Engine.Config {
    return .{
        .scheme = scheme,
        .elector = elector,
        .blocker = blocker,
        .automaton = app,
        .relay = app,
        .reporter = app,
        .partition = "log",
        .mailbox_size = 1024,
        .epoch = .zero(),
        .floor = .{ .genesis = application.genesis() },
        .replay_buffer = 1024 * 1024,
        .write_buffer = 1024 * 1024,
        .leader_timeout = .from_secs(1),
        .certification_timeout = .from_secs(2),
        .timeout_retry = .from_secs(10),
        .fetch_timeout = .from_secs(1),
        .fetch_retry_delay = .from_millis(100),
        .view_retention = .new(10),
        .skip = .{ .enabled = .{ .timeout = .from_secs(11), .budget = .participants } },
        .page_cache = page_cache,
        .strategy = zigware.parallel.sequential,
        .forward = .disabled,
        .track_historical_votes = false,
    };
}

/// Runs the network until canceled; a network failure ends the process, as commonware's
/// listener panics.
fn run_network(network: *Net) Io.Cancelable!void {
    network.run() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => std.debug.panic("network failed: {t}", .{err}),
    };
}

test {
    _ = @import("validator_test.zig");
}
