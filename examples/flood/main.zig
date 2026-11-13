//! Spam peers with random messages (commonware `examples/flood`, `bin/flood.rs`).
//!
//! ```sh
//! zig build run-flood -- --hosts hosts.yaml --config <public key>.yaml
//! ```
//!
//! Reads the deployer's hosts file and this peer's config, then floods every connected peer
//! over p2p's authenticated discovery network, recording the `messages` counter and `latency`
//! histogram. The flood tasks are in `lib.zig`; the authenticated network is still being
//! ported by the p2p lane, so the binary stops after loading its configuration until it lands.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const zigware = @import("zigware");
const lib = @import("lib.zig");

const ed25519 = zigware.cryptography.ed25519;

const usage = "Usage: flood --hosts <hosts> --config <config>\n";

const Arguments = struct { hosts: []const u8, config: []const u8 };

fn parse_arguments(args: []const []const u8, stderr: *Io.Writer) !?Arguments {
    var hosts: ?[]const u8 = null;
    var config: ?[]const u8 = null;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stderr.print("Spam peers with random messages.\n\n{s}", .{usage});
            return null;
        }
        const slot = if (std.mem.eql(u8, arg, "--hosts"))
            &hosts
        else if (std.mem.eql(u8, arg, "--config"))
            &config
        else {
            try stderr.print("error: unexpected argument '{s}' found\n\n{s}", .{ arg, usage });
            return error.Usage;
        };
        index += 1;
        if (index == args.len) {
            try stderr.print("error: a value is required for '{s}'\n\n{s}", .{ arg, usage });
            return error.Usage;
        }
        slot.* = args[index];
    }
    if (hosts == null or config == null) {
        try stderr.print("error: --hosts and --config are required\n\n{s}", .{usage});
        return error.Usage;
    }
    return .{ .hosts = hosts.?, .config = config.? };
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(io, &stderr_buffer);
    const stderr = &stderr_writer.interface;
    defer stderr.flush() catch {};
    const arguments = parse_arguments(args[@min(args.len, 1)..], stderr) catch {
        try stderr.flush();
        std.process.exit(2);
    } orelse return;

    const limit: Io.Limit = .limited(1 << 20);
    const hosts_text = try Io.Dir.cwd().readFileAlloc(io, arguments.hosts, arena, limit);
    const hosts = try lib.Hosts.parse(arena, hosts_text);
    const config_text = try Io.Dir.cwd().readFileAlloc(io, arguments.config, arena, limit);
    const config = try lib.Config.parse(arena, config_text);
    const key_bytes = (try zigware.formatting.from_hex(arena, config.private_key)) orelse
        return error.InvalidPrivateKey;
    if (key_bytes.len != ed25519.PrivateKey.fixed_size) return error.InvalidPrivateKey;
    const signer = ed25519.PrivateKey.from_bytes(key_bytes[0..32].*);
    const public_key = signer.public_key();
    var self_ip: ?Io.net.IpAddress = null;
    for (hosts.hosts) |host| {
        const bytes = (try zigware.formatting.from_hex(arena, host.name)) orelse continue;
        if (bytes.len == 32 and std.mem.eql(u8, bytes, &public_key.key.bytes)) self_ip = host.ip;
    }
    const ip = self_ip orelse return error.SelfNotInHosts;
    try stderr.print(
        "loaded config: peers={d} ip={f} port={d} message_size={d}\n",
        .{ hosts.hosts.len, ip, config.port, @max(config.message_size, lib.message_size_min) },
    );
    try stderr.writeAll("error: p2p's authenticated network is not ported yet\n");
    try stderr.flush();
    std.process.exit(1);
}

test {
    _ = lib;
}
