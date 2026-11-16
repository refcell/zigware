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

/// Writes the generated files into `output` (which must not exist), with `dashboard` copied
/// in as `dashboard.json`.
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
    try cwd.copyFile(dashboard, cwd, copy, io, .{});
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

const usage =
    \\Usage: setup --peers <N> --bootstrappers <N> --regions <R1,R2,...> --instance-type <T>
    \\             --storage-size <GB> --storage-class <C> [--storage-iops <N>]
    \\             [--storage-throughput <N>] --worker-threads <N> --message-size <BYTES>
    \\             --message-rate <N> --mailbox-size <N> --dashboard <PATH>
    \\             --instrument <true|false> --output <DIR>
    \\
;

const names = [_][]const u8{
    "peers",         "bootstrappers", "regions",            "instance-type",  "storage-size",
    "storage-class", "storage-iops",  "storage-throughput", "worker-threads", "message-size",
    "message-rate",  "mailbox-size",  "dashboard",          "instrument",     "output",
};

/// Parses `--name value` or `--name=value` options (clap's forms); null on any mistake.
pub fn parse_options(arena: Allocator, args: []const []const u8) !?Options {
    var values: [names.len]?[]const u8 = @splat(null);
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (!std.mem.startsWith(u8, arg, "--")) return null;
        const equals = std.mem.indexOfScalar(u8, arg, '=');
        const name = arg[2 .. equals orelse arg.len];
        const slot = for (names, 0..) |candidate, position| {
            if (std.mem.eql(u8, candidate, name)) break position;
        } else return null;
        if (values[slot] != null) return null;
        values[slot] = if (equals) |at| arg[at + 1 ..] else blk: {
            index += 1;
            if (index == args.len) return null;
            break :blk args[index];
        };
    }
    return options_from(arena, &values) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

fn value(values: *const [names.len]?[]const u8, comptime name: []const u8) ?[]const u8 {
    inline for (names, 0..) |candidate, index| {
        if (comptime std.mem.eql(u8, candidate, name)) return values[index];
    }
    @compileError("unknown option " ++ name);
}

fn required(values: *const [names.len]?[]const u8, comptime name: []const u8) ![]const u8 {
    return value(values, name) orelse error.MissingOption;
}

fn integer(comptime T: type, text: []const u8) !T {
    return std.fmt.parseInt(T, text, 10);
}

fn options_from(arena: Allocator, values: *const [names.len]?[]const u8) !Options {
    var regions: std.ArrayList([]const u8) = .empty;
    var parts = std.mem.splitScalar(u8, try required(values, "regions"), ',');
    while (parts.next()) |region| try regions.append(arena, region);
    const iops = value(values, "storage-iops");
    const throughput = value(values, "storage-throughput");
    const options: Options = .{
        .peers = try integer(u64, try required(values, "peers")),
        .bootstrappers = try integer(u64, try required(values, "bootstrappers")),
        .regions = regions.items,
        .instance_type = try required(values, "instance-type"),
        .storage_size = try integer(i32, try required(values, "storage-size")),
        .storage_class = try required(values, "storage-class"),
        .storage_iops = if (iops) |text| try integer(i32, text) else null,
        .storage_throughput = if (throughput) |text| try integer(i32, text) else null,
        .worker_threads = try integer(u64, try required(values, "worker-threads")),
        .message_size = try integer(u32, try required(values, "message-size")),
        .message_rate = try integer(u32, try required(values, "message-rate")),
        .mailbox_size = try integer(u64, try required(values, "mailbox-size")),
        .dashboard = try required(values, "dashboard"),
        .instrument = try boolean(try required(values, "instrument")),
        .output = try required(values, "output"),
    };
    if (options.message_rate == 0 or options.mailbox_size == 0) return error.ZeroValue;
    return options;
}

/// clap's `bool` parser: `true` or `false`.
fn boolean(text: []const u8) !bool {
    if (std.mem.eql(u8, text, "true")) return true;
    if (std.mem.eql(u8, text, "false")) return false;
    return error.InvalidBool;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var buffer: [1024]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &buffer);
    const options = try parse_options(arena, args[1..]) orelse {
        try stderr.interface.writeAll(usage);
        try stderr.interface.flush();
        return 2;
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
