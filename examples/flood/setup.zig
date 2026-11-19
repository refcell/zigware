//! Generates flood's deployment (commonware `examples/flood/src/bin/setup.rs`): one ed25519
//! key and config file per peer, a random subset of them as bootstrappers, and the deployer's
//! `config.yaml` with one instance per peer, spread over the regions in turn.
//!
//!     zig build run-flood-setup -- --peers 3 --bootstrappers 1 \
//!         --regions us-west-2,us-east-1,eu-west-1 --instance-type c7g.xlarge \
//!         --storage-size 10 --storage-class gp3 --worker-threads 4 --message-size 1024 \
//!         --message-rate 16384 --mailbox-size 16384 --dashboard dashboard.json \
//!         --instrument false --output assets
//!
//! Then `cd assets && deployer aws create --config config.yaml`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const ui = @import("ui");
const lib = @import("lib.zig");

const aws = zigware.deployer.aws;
const ed25519 = zigware.cryptography.ed25519;
const rng_module = zigware.utils.rng;

const log = std.log.scoped(.setup);

/// The binary each instance runs.
pub const binary_name = "flood";
/// The port peers listen on, open to everyone.
pub const port: u16 = 4545;

pub const Options = struct {
    peers: u64,
    bootstrappers: u64,
    regions: []const []const u8,
    instance_type: []const u8,
    storage_size: i32,
    storage_class: []const u8,
    storage_iops: ?i32 = null,
    storage_throughput: ?i32 = null,
    worker_threads: u64,
    message_size: u32,
    /// Offered messages per second per peer; non-zero.
    message_rate: u32,
    /// Non-zero.
    mailbox_size: u64,
    /// Copied into the output as `dashboard.json`.
    dashboard: []const u8,
    instrument: bool,
    /// Created; must not exist yet.
    output: []const u8,
};

/// A peer's config and the file it goes in (`{public key}.yaml`).
pub const PeerFile = struct { file_name: []const u8, config: lib.Config };

pub const Generated = struct { config: aws.Config, peers: []const PeerFile };

/// Draws the keys and bootstrappers and builds every config. `rng` provides `fill_bytes`,
/// `next_u32`, and `next_u64`. Allocates from `arena`.
pub fn generate(
    arena: Allocator,
    rng: anytype,
    tag: []const u8,
    options: *const Options,
) !Generated {
    // commonware asserts these; the messages are its assertion texts.
    if (options.bootstrappers > options.peers) return error.BootstrappersMustBeLessThanPeers;
    if (options.regions.len == 0 or options.regions.len > options.peers) {
        return error.MustBeAtLeastOnePeerPerRegion;
    }
    const peers: usize = @intCast(options.peers);
    const seeds = try arena.alloc([32]u8, peers);
    const allowed = try arena.alloc([]const u8, peers);
    for (seeds, allowed) |*seed, *name| {
        rng.fill_bytes(seed);
        const key = ed25519.PrivateKey.from_bytes(seed.*);
        name.* = try std.fmt.allocPrint(arena, "{f}", .{key.public_key()});
    }
    const bootstrappers = try sample(arena, rng, allowed, @intCast(options.bootstrappers));
    const files = try arena.alloc(PeerFile, peers);
    const instances = try arena.alloc(aws.InstanceConfig, peers);
    for (seeds, allowed, files, instances, 0..) |*seed, name, *file, *instance, index| {
        const file_name = try std.fmt.allocPrint(arena, "{s}.yaml", .{name});
        file.* = .{
            .file_name = file_name,
            .config = .{
                // The key's encoding is its 32-byte seed.
                .private_key = try arena.dupe(u8, &std.fmt.bytesToHex(seed.*, .lower)),
                .port = port,
                .allowed_peers = allowed,
                .bootstrappers = bootstrappers,
                .worker_threads = options.worker_threads,
                .message_size = options.message_size,
                .message_rate = options.message_rate,
                .mailbox_size = options.mailbox_size,
                .instrument = options.instrument,
            },
        };
        instance.* = .{
            .name = name,
            .region = options.regions[index % options.regions.len],
            .instance_type = options.instance_type,
            .storage_size = options.storage_size,
            .storage_class = options.storage_class,
            .storage_iops = options.storage_iops,
            .storage_throughput = options.storage_throughput,
            .binary = binary_name,
            .config = file_name,
            .profiling = options.instrument,
        };
    }
    return .{ .config = monitoring_config(tag, options, instances), .peers = files };
}

fn monitoring_config(
    tag: []const u8,
    options: *const Options,
    instances: []const aws.InstanceConfig,
) aws.Config {
    assert(tag.len > 0);
    return .{
        .tag = tag,
        .instances = instances,
        .monitoring = .{
            .instance_type = options.instance_type,
            .storage_size = options.storage_size,
            .storage_class = options.storage_class,
            .storage_iops = options.storage_iops,
            .storage_throughput = options.storage_throughput,
            .dashboard = "dashboard.json",
        },
        .ports = &.{.{ .protocol = "tcp", .port = port, .cidr = "0.0.0.0/0" }},
    };
}

/// `amount` of `items` chosen uniformly, in reservoir order (rand 0.10's
/// `IteratorRandom::sample`).
pub fn sample(
    arena: Allocator,
    rng: anytype,
    items: []const []const u8,
    amount: usize,
) ![]const []const u8 {
    assert(amount <= items.len);
    const reservoir = try arena.dupe([]const u8, items[0..amount]);
    for (items[amount..], 0..) |item, index| {
        const slot = rng_module.range_less_than(rng, usize, 0, index + 1 + amount);
        if (slot < amount) reservoir[slot] = item;
    }
    return reservoir;
}

/// commonware's `examples/flood/dashboard.json`, shipped beside this file.
pub const default_dashboard = @embedFile("dashboard.json");

/// Writes the generated files into `output` (which must not exist), with `dashboard` copied
/// in as `dashboard.json`. A missing `dashboard.json` (the name commonware's README passes)
/// falls back to the embedded copy, so the README's command runs from the repository root
/// as well as from `examples/flood`.
pub fn write_files(
    io: Io,
    arena: Allocator,
    generated: *const Generated,
    dashboard: []const u8,
    output: []const u8,
) !void {
    const cwd = Io.Dir.cwd();
    if (cwd.access(io, output, .{})) |_| return error.OutputDirectoryAlreadyExists else |_| {}
    try cwd.createDirPath(io, output);
    const copy = try std.fs.path.join(arena, &.{ output, "dashboard.json" });
    cwd.copyFile(dashboard, cwd, copy, io, .{}) catch |err| {
        if (err != error.FileNotFound) return err;
        if (!std.mem.eql(u8, dashboard, "dashboard.json")) return err;
        try cwd.writeFile(io, .{ .sub_path = copy, .data = default_dashboard });
    };
    assert(default_dashboard.len > 0);
    for (generated.peers) |file| {
        var text: Io.Writer.Allocating = .init(arena);
        try file.config.write(&text.writer);
        const path = try std.fs.path.join(arena, &.{ output, file.file_name });
        try cwd.writeFile(io, .{ .sub_path = path, .data = text.written() });
    }
    var text: Io.Writer.Allocating = .init(arena);
    try generated.config.write(&text.writer);
    const path = try std.fs.path.join(arena, &.{ output, "config.yaml" });
    try cwd.writeFile(io, .{ .sub_path = path, .data = text.written() });
    log.info("wrote configuration files: path={s}", .{path});
}

// --- Command line ------------------------------------------------------------------------------

pub const about = "generate configuration files";

/// commonware's `Command::new("setup")`, in its order, with its ids and value parsers.
pub const Clap = ui.clap.Parser(.{ .about = about, .args = &.{
    .{ .long = "peers", .required = true, .value = .u64 },
    .{ .long = "bootstrappers", .required = true, .value = .u64 },
    .{ .long = "regions", .required = true, .delimited = true },
    .{ .long = "instance-type", .id = "instance_type", .required = true },
    .{ .long = "storage-size", .id = "storage_size", .required = true, .value = .i32 },
    .{ .long = "storage-class", .id = "storage_class", .required = true },
    .{ .long = "storage-iops", .id = "storage_iops", .value = .i32 },
    .{ .long = "storage-throughput", .id = "storage_throughput", .value = .i32 },
    .{ .long = "worker-threads", .required = true, .value = .u64 },
    .{ .long = "message-size", .required = true, .value = .u32 },
    .{
        .long = "message-rate",
        .required = true,
        .help = "Offered messages per second per peer (sizes the derived channel mailboxes)",
        .value = .non_zero_u32,
    },
    .{ .long = "mailbox-size", .required = true, .value = .non_zero_u64 },
    .{ .long = "dashboard", .required = true },
    .{ .long = "instrument", .required = true, .value = .bool },
    .{ .long = "output", .required = true },
} });

/// Parses `args` (without argv[0]) as clap does: help goes to `stdout` (exit 0), usage
/// errors to `stderr` (exit 2). Allocates the regions from `arena`.
pub fn parse(
    arena: Allocator,
    args: []const []const u8,
    bin_name: []const u8,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !union(enum) { run: Options, exit: u8 } {
    const values = switch (try Clap.parse(args, bin_name, stderr)) {
        .help => {
            try Clap.write_help(stdout, bin_name);
            return .{ .exit = 0 };
        },
        .usage_error => return .{ .exit = 2 },
        .run => |values| values,
    };
    return .{ .run = try options_from(arena, &values) };
}

/// The options clap accepted; every value already passed its parser.
fn options_from(arena: Allocator, values: *const Clap.Values) Allocator.Error!Options {
    var regions: std.ArrayList([]const u8) = .empty;
    var parts = std.mem.splitScalar(u8, values[2].?, ',');
    while (parts.next()) |region| try regions.append(arena, region);
    const options: Options = .{
        .peers = integer(u64, values[0].?),
        .bootstrappers = integer(u64, values[1].?),
        .regions = regions.items,
        .instance_type = values[3].?,
        .storage_size = integer(i32, values[4].?),
        .storage_class = values[5].?,
        .storage_iops = if (values[6]) |text| integer(i32, text) else null,
        .storage_throughput = if (values[7]) |text| integer(i32, text) else null,
        .worker_threads = integer(u64, values[8].?),
        .message_size = integer(u32, values[9].?),
        .message_rate = integer(u32, values[10].?),
        .mailbox_size = integer(u64, values[11].?),
        .dashboard = values[12].?,
        .instrument = std.mem.eql(u8, values[13].?, "true"),
        .output = values[14].?,
    };
    assert(options.message_rate > 0 and options.mailbox_size > 0);
    return options;
}

/// A value clap's parser accepted: decimal digits with an optional sign.
fn integer(comptime T: type, text: []const u8) T {
    return std.fmt.parseInt(T, text, 10) catch unreachable; // Proof: clap checked it.
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(io, &stderr_buffer);
    defer stdout_writer.interface.flush() catch {};
    defer stderr_writer.interface.flush() catch {};
    const bin_name = if (args.len > 0) std.fs.path.basename(args[0]) else "setup";
    const rest = args[@min(args.len, 1)..];
    const stdout = &stdout_writer.interface;
    const options = switch (try parse(arena, rest, bin_name, stdout, &stderr_writer.interface)) {
        .exit => |status| return status,
        .run => |options| options,
    };
    const tag = aws.ec2.new_client_token(io); // `Uuid::new_v4()`.
    log.info("generated deployment tag: tag={s}", .{&tag});
    var key: [32]u8 = undefined;
    io.random(&key);
    var rng = rng_module.ChaChaRng(20).init_key(key);
    const generated = generate(arena, &rng, &tag, &options) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            log.err("{t}", .{err});
            return 1;
        },
    };
    write_files(io, arena, &generated, options.dashboard, options.output) catch |err| {
        log.err("failed to write configuration files: {t}", .{err});
        return 1;
    };
    return 0;
}

test {
    _ = @import("setup_test.zig");
}
