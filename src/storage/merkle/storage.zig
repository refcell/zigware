//! Read access to a Merkle structure's nodes (commonware's `storage/src/merkle/storage.rs`).
//!
//! Commonware's async `Storage` trait becomes a comptime interface: a source has
//! `size() u64` and `get_node(position)` returning `?Digest` (in-memory) or `!?Digest`
//! (journaled). A source may also declare `get_nodes(positions, out)` to serve a batch of
//! reads at once; `get_nodes` here falls back to one `get_node` per position otherwise.

const std = @import("std");
const assert = std.debug.assert;

/// The type behind `source`, which may be passed by value or by pointer.
fn Source(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .pointer => |pointer| pointer.child,
        else => T,
    };
}

/// The node at `position`, or null if it is pruned or past the end.
pub fn get_node(source: anytype, position: u64) !Node(@TypeOf(source)) {
    const node = source.get_node(position);
    if (@typeInfo(@TypeOf(node)) == .error_union) return try node;
    return node;
}

/// `?Digest` for a source whose `get_node` returns `?Digest` or `!?Digest`.
fn Node(comptime T: type) type {
    const Return = @typeInfo(@TypeOf(Source(T).get_node)).@"fn".return_type.?;
    return switch (@typeInfo(Return)) {
        .error_union => |error_union| error_union.payload,
        else => Return,
    };
}

/// Reads the node at each of `positions` (strictly increasing) into `out[i]`. Fails with
/// `ElementPruned` at the first position the source lacks.
pub fn get_nodes(source: anytype, positions: []const u64, out: anytype) !void {
    assert(positions.len == out.len);
    if (positions.len > 1) {
        for (positions[1..], positions[0 .. positions.len - 1]) |position, previous| {
            assert(previous < position); // Positions must be strictly increasing.
        }
    }
    if (@hasDecl(Source(@TypeOf(source)), "get_nodes")) {
        return source.get_nodes(positions, out);
    }
    for (positions, out) |position, *digest| {
        digest.* = (try get_node(source, position)) orelse return error.ElementPruned;
    }
}

const testing = std.testing;
const cryptography = @import("cryptography");
const merkle = @import("mod.zig");

// Commonware's `test_default_get_nodes_rejects_pruned`: the default `get_nodes` serves
// retained positions in slot order and rejects a pruned one, alone or among retained ones.
test "default get_nodes rejects pruned positions" {
    const gpa = testing.allocator;
    const Sha256 = cryptography.Sha256;
    const hasher = merkle.hasher.Standard(Sha256).init(.forward_fold);
    var mem: merkle.mem.Mem(merkle.mmr.Family, Sha256.Digest) = .empty;
    defer mem.deinit(gpa);
    for (0..64) |i| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, i, .big);
        try mem.add(gpa, &hasher, &hasher.digest(&bytes).bytes);
    }
    try mem.prune(20);

    var available: std.ArrayList(u64) = .empty;
    defer available.deinit(gpa);
    var absent: ?u64 = null;
    for (0..mem.size()) |position| {
        if (mem.get_node(position) != null) {
            try available.append(gpa, position);
        } else if (absent == null) {
            absent = position;
        }
    }
    try testing.expect(absent != null);
    try testing.expect(available.items.len > 0);

    const nodes = try gpa.alloc(Sha256.Digest, available.items.len);
    defer gpa.free(nodes);
    try get_nodes(&mem, available.items, nodes);
    for (available.items, nodes) |position, node| {
        try testing.expect(node.eql(mem.get_node(position).?));
    }

    var one: [1]Sha256.Digest = undefined;
    try testing.expectError(error.ElementPruned, get_nodes(&mem, &.{absent.?}, &one));
    var two: [2]Sha256.Digest = undefined;
    const last = available.items[available.items.len - 1];
    try testing.expectError(error.ElementPruned, get_nodes(&mem, &.{ absent.?, last }, &two));
}
