//! Commit to a secret log and agree to its hash (commonware `examples/log`).
//!
//! Whenever it is a participant's turn to build a block, it generates a random 16-byte secret
//! message and proposes its hash; participants use simplex consensus to agree on the same hash
//! in the same view. Consensus data is persisted in `--storage-dir`, so a restarted participant
//! resumes where it left off. Run at least 3 of 4 to make progress:
//!
//! ```sh
//! zig build run-log -- --me 0@3000 --participants 0,1,2,3 --storage-dir /tmp/zigware-log/0
//! zig build run-log -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 \
//!     --participants 0,1,2,3 --storage-dir /tmp/zigware-log/1
//! ```
//!
//! Peers find each other through p2p's authenticated discovery network on 127.0.0.1, on the
//! production runtime, and the UI (`gui.zig`) runs in the terminal with plain ANSI escapes.
//! As in commonware, `main`'s own events come before the GUI installs its log writer, so they
//! are not shown.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const ui = @import("ui");
const cli = @import("cli.zig");
const application = @import("application.zig");
const gui = @import("gui.zig");

const ed25519 = zigware.cryptography.ed25519;
const Sha256 = zigware.cryptography.Sha256;
const Digest = Sha256.Digest;
const PublicKey = ed25519.PublicKey;
const simplex = zigware.consensus.simplex;
const traces = zigware.runtime.telemetry.traces;
const production = zigware.runtime.production;
const discovery = zigware.p2p.authenticated.discovery;
const Upgrader = zigware.stream.SakeCups(ed25519.PrivateKey, zigware.cryptography.ChaCha20Poly1305);
const Net = discovery.Network(Upgrader, production.network.Network);
const Scheme = application.Scheme(Digest);
const Application = application.Application(Sha256);
const Reporter = application.Reporter(Digest);

/// Unique namespace to avoid message replay attacks.
pub const namespace = "_COMMONWARE_EXAMPLES_LOG";
/// Capacity of the network's internal actor mailboxes.
pub const mailbox_size = 1_000;
/// Messages per second each peer may send on each consensus channel.
pub const message_rate_per_second = 10;

/// Rust's panic exit status, used for commonware's panics.
const panic_status: u8 = 101;

pub const Params = struct {
    pub const Context = production.runner.Context;
    pub const Scheme = application.Scheme(Sha256.Digest);
    pub const Elector = simplex.elector.RoundRobinElector;
    pub const Blocker = Net.Oracle;
    pub const Digest = Sha256.Digest;
    pub const Automaton = *Application;
    pub const Relay = *Application;
    pub const Reporter = *application.Reporter(Sha256.Digest);
    pub const Strategy = zigware.parallel.Sequential;
    pub const Sender = Net.Sender;
    pub const Receiver = Net.Receiver;
};
const Engine = simplex.Engine(Params);
const Channel = simplex.engine.Channel(Params);

/// The configuration commonware's `main` builds before starting the runtime.
pub const Setup = struct {
    signer: ed25519.PrivateKey,
    port: u16,
    /// The validators, sorted.
    validators: []PublicKey,
    bootstrappers: []const discovery.Bootstrapper(PublicKey),
    max_peers_per_set: usize,
};

/// Derives the keys and bootstrappers from `arguments`.
pub fn setup(arena: Allocator, arguments: cli.Arguments) Allocator.Error!Setup {
    assert(arguments.participants.len > 0);
    const signer = ed25519.PrivateKey.from_seed(arguments.key);
    const validators = try arena.alloc(PublicKey, arguments.participants.len);
    for (validators, arguments.participants) |*validator, participant| {
        validator.* = ed25519.PrivateKey.from_seed(participant).public_key();
    }
    std.sort.pdq(PublicKey, validators, {}, PublicKey.less_than);
    const Bootstrapper = discovery.Bootstrapper(PublicKey);
    const bootstrappers = try arena.alloc(Bootstrapper, arguments.bootstrappers.len);
    for (bootstrappers, arguments.bootstrappers) |*bootstrapper, given| {
        const address: zigware.codec.SocketAddr = .{
            .ip = discovery.network.to_ip(given.address),
            .port = given.address.getPort(),
        };
        bootstrapper.* = .{
            .peer = ed25519.PrivateKey.from_seed(given.key).public_key(),
            .ingress = .{ .socket = address },
        };
    }
    const local = signer.public_key();
    const max_peers_per_set = zigware.p2p.sizing.peer_set_limit(PublicKey, validators, local);
    assert(max_peers_per_set >= validators.len);
    return .{
        .signer = signer,
        .port = arguments.port,
        .validators = validators,
        .bootstrappers = bootstrappers,
        .max_peers_per_set = max_peers_per_set,
    };
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
    const bin_name = if (args.len > 0) std.fs.path.basename(args[0]) else "log";

    var panic: cli.Panic = .{};
    const given = args[@min(args.len, 1)..];
    const outcome = cli.parse(arena, given, bin_name, stderr, &panic) catch |err| switch (err) {
        error.Panic => {
            try stderr.print("error: {s}\n", .{panic.message()});
            return panic_status;
        },
        else => |other| return other,
    };
    const arguments = switch (outcome) {
        .help => {
            try cli.write_help(stdout, bin_name);
            return 0;
        },
        .usage_error => return 2,
        .run => |arguments| arguments,
    };
    const configured = try setup(arena, arguments);
    var collector: traces.Collector = .init(init.gpa, .{});
    defer collector.deinit();
    var zone = ui.clock.Zone.load(init.gpa, io, init.environ_map.get("TZ"));
    defer zone.deinit();
    var runner: production.Runner = undefined;
    try runner.init(init.gpa, .{ .storage_directory = arguments.storage_directory });
    defer runner.deinit();
    try (try runner.start_context(run, .{ &collector, &zone, configured }));
    return 0;
}

/// Discovery on 127.0.0.1:`port`, sized for consensus messages, as commonware's `main` does.
fn network_config(configured: Setup) Net.Config {
    const local: zigware.codec.SocketAddr = .{
        .ip = .{ .v4 = zigware.codec.Ipv4.init(127, 0, 0, 1) },
        .port = configured.port,
    };
    const participants: u32 = @intCast(configured.validators.len);
    const payload = simplex.limits.max_payload_size(Scheme, Digest, participants);
    return Net.Config.local(.{
        .upgrader = .init(.{
            .signer = configured.signer,
            .synchrony_bound_ms = 5_000,
            .max_handshake_age_ms = 10_000,
            .version = .v1,
        }, .v1),
        .namespace = namespace ++ "_P2P",
        .listen = discovery.network.to_address(local),
        .dialable = .{ .socket = local },
        .bootstrappers = configured.bootstrappers,
        .max_peers_per_set = configured.max_peers_per_set,
        .max_message_size = zigware.p2p.sizing.max_message_size(&.{payload}),
        .mailbox_size = mailbox_size,
    });
}

fn run(
    ctx: production.runner.Context,
    collector: *traces.Collector,
    zone: *const ui.clock.Zone,
    configured: Setup,
) !void {
    const gpa = ctx.gpa();
    const io = ctx.io();
    const scope = ctx.scope.child("network");
    const network = try Net.create(gpa, io, ctx.network, scope, network_config(configured));
    defer network.destroy();
    // In a real-world scenario, this would be updated as new peer sets are created (like when
    // the composition of a validator set changes).
    _ = network.oracle().track(0, .init_primary(.init(configured.validators)));
    var channels: [3]Channel = undefined;
    for (&channels, 0..) |*channel, index| {
        const registered = try network.register(index, .per_second(message_rate_per_second));
        channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
    }
    var network_task = try io.concurrent(run_network, .{network});
    defer network_task.cancel(io) catch {};

    var app: Application = .init(collector.tracer(application.target));
    var reporter: Reporter = .init(collector.tracer(application.target));
    var validators: zigware.utils.ordered.Set(PublicKey) = try .init(gpa, configured.validators);
    const consensus_namespace = namespace ++ "_CONSENSUS";
    var scheme = try Scheme.signer(gpa, consensus_namespace, validators, configured.signer) orelse
        @panic("private key must be in participants");
    validators = undefined; // Owned by the scheme.
    defer scheme.deinit(gpa);
    var page_cache: zigware.runtime.buffer.paged.CacheRef = try .init(gpa, 16_384, 10_000);
    defer page_cache.deinit();
    const participants: u32 = @intCast(configured.validators.len);
    var elector = try simplex.elector.RoundRobin(Sha256).default().build(gpa, participants);
    defer elector.deinit(gpa);
    const engine_ctx = ctx.child("engine");
    var engine: Engine = undefined;
    try engine.init(engine_ctx, engine_config(scheme, elector, network.oracle(), .{
        .app = &app,
        .reporter = &reporter,
        .page_cache = &page_cache,
    }));
    defer engine.deinit();
    const engine_task = try engine_ctx.spawn(Engine.run, .{
        &engine, channels[0], channels[1], channels[2],
    });
    defer if (engine_task.abort()) |result| {
        result catch |err| std.debug.panic("engine failed: {t}", .{err});
    } else |_| {};
    try run_gui(gpa, io, collector, zone);
}

const Borrowed = struct {
    app: *Application,
    reporter: *Reporter,
    page_cache: *zigware.runtime.buffer.paged.CacheRef,
};

/// commonware's `simplex::Config` for log.
fn engine_config(
    scheme: Scheme,
    elector: simplex.elector.RoundRobinElector,
    blocker: Net.Oracle,
    borrowed: Borrowed,
) Engine.Config {
    return .{
        .scheme = scheme,
        .elector = elector,
        .blocker = blocker,
        .automaton = borrowed.app,
        .relay = borrowed.app,
        .reporter = borrowed.reporter,
        .partition = "log",
        .mailbox_size = 1024,
        .epoch = .zero(),
        .floor = .{ .genesis = application.genesis(Sha256) },
        .replay_buffer = 1024 * 1024,
        .write_buffer = 1024 * 1024,
        .leader_timeout = .from_secs(1),
        .certification_timeout = .from_secs(2),
        .timeout_retry = .from_secs(10),
        .fetch_timeout = .from_secs(1),
        .fetch_retry_delay = .from_millis(100),
        .view_retention = .new(10),
        .skip = .{ .enabled = .{ .timeout = .from_secs(11), .budget = .participants } },
        .page_cache = borrowed.page_cache,
        .strategy = zigware.parallel.sequential,
        .forward = .disabled,
        .track_historical_votes = false,
    };
}

/// Blocks on the GUI until ESC.
fn run_gui(
    gpa: Allocator,
    io: Io,
    collector: *traces.Collector,
    zone: *const ui.clock.Zone,
) !void {
    var out_buffer: [64 * 1024]u8 = undefined;
    var out_writer = Io.File.stdout().writer(io, &out_buffer);
    const out = &out_writer.interface;
    var terminal = try ui.terminal.Terminal.enter(io, out);
    defer terminal.leave(out);
    var state: gui.State = .init(gpa);
    defer state.deinit();
    try gui.run(.{
        .gpa = gpa,
        .io = io,
        .state = &state,
        .collector = collector,
        .zone = zone,
        .device = terminal.device(out),
    });
}

fn run_network(network: *Net) anyerror!void {
    return network.run();
}

test {
    _ = @import("log_test.zig");
}
