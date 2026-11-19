//! `bootstrap` subcommand: one-shot glue DKG for the epoch-0 committee (commonware
//! `examples/dkg/src/bootstrap.rs`).
//!
//! After the ceremony, the bootstrap hands its epoch-0 share to the validator's store and
//! writes the resulting genesis into every validator directory that may use it. The ceremony
//! itself runs glue's bootstrap engine (p2p lane); until it lands, `run` is not wired and only
//! the genesis hand-off is ported.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const config = @import("config.zig");
const types = @import("types.zig");

/// The runtime storage partition of the bootstrap's `Secrets` store.
pub const partition: types.Partition = .bootstrap;

/// Writes `genesis` into every sibling validator directory of `node_dir` (relative to `base`)
/// that belongs to `network`, except those of players other than `local`, or into `node_dir`
/// alone when none are found. Returns how many directories it wrote.
pub fn write_genesis_to_sibling_validators(
    io: Io,
    gpa: Allocator,
    base: Io.Dir,
    node_dir: []const u8,
    local: types.PublicKey,
    network: *const config.NetworkConfig,
    genesis: types.EpochInfo,
) !usize {
    assert(node_dir.len > 0);
    const root_path = std.fs.path.dirname(node_dir) orelse
        return write_own(io, gpa, base, node_dir, genesis);
    var root = try base.openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);
    var written: usize = 0;
    var entries = root.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        var candidate = root.openDir(io, entry.name, .{}) catch continue;
        defer candidate.close(io);
        const node = config.NodeConfig.load(io, gpa, candidate) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => continue,
        };
        const public_key = node.public_key();
        if (!contains(network.participants, public_key)) continue;
        const is_local = public_key.eql(local);
        if (!is_local and genesis.players.position(public_key) != null) continue;
        try types.write_genesis(io, gpa, candidate, genesis);
        written += 1;
    }
    if (written == 0) return write_own(io, gpa, base, node_dir, genesis);
    assert(written <= network.participants.len);
    return written;
}

fn write_own(
    io: Io,
    gpa: Allocator,
    base: Io.Dir,
    node_dir: []const u8,
    genesis: types.EpochInfo,
) !usize {
    var dir = try base.openDir(io, node_dir, .{});
    defer dir.close(io);
    try types.write_genesis(io, gpa, dir, genesis);
    return 1;
}

fn contains(keys: []const types.PublicKey, key: types.PublicKey) bool {
    for (keys) |each| {
        if (each.eql(key)) return true;
    }
    return false;
}
