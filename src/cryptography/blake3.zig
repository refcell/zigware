//! BLAKE3 implementation of the hasher interface (commonware `cryptography/src/blake3`).
//!
//! Backed by `std.crypto.hash.Blake3` for streaming; one-shot messages hash in
//! `blake3_tree.zig`'s kernel. `hash_across` splits a message of at least 128 KiB along the
//! BLAKE3 tree and hashes the subtrees across the given strategy (`blake3_tree.zig`); the
//! digest is identical either way.

const std = @import("std");
const parallel = @import("parallel");
const assert = std.debug.assert;
const hasher = @import("hasher.zig");
const digest = @import("digest.zig");
const tree = @import("blake3_tree.zig");

pub const Core = std.crypto.hash.Blake3;

const digest_length = 32;

/// Digest of a BLAKE3 hashing operation.
pub const Digest = digest.Digest(digest_length, "blake3");

const Streaming = hasher.Streaming(Core, Digest);

/// BLAKE3 hasher: `Streaming` over `Core`, with a `hash_across` that splits long messages.
pub const Blake3 = struct {
    streaming: Streaming,

    pub const Digest = Streaming.Digest;
    const Value = Streaming.Digest;

    pub fn init() Blake3 {
        return .{ .streaming = .init() };
    }

    pub fn update(self: *Blake3, bytes: []const u8) void {
        self.streaming.update(bytes);
    }

    pub fn finalize(self: *Blake3) Value {
        return self.streaming.finalize();
    }

    /// The digest of the concatenation of `parts`. A message of more than one chunk
    /// compresses its chunks side by side in `blake3_tree`'s kernel, which beats `Core` at
    /// every length: `Core` compresses a batch of fewer than four chunks one at a time (2 KiB:
    /// 3.4 µs against 1.6), and its wide batches gather their message words one at a time (1
    /// MiB: 137 µs against 111).
    pub fn hash(parts: []const []const u8) Value {
        var len: usize = 0;
        for (parts) |part| {
            len = std.math.add(usize, len, part.len) catch return Streaming.hash(parts);
        }
        // One chunk compresses its root once (std's setup and finalize cost more than that).
        if (len <= tree.chunk_len) return .{ .bytes = tree.hash(parts) };
        return .{ .bytes = tree.hash_subtrees(parts, len, parallel.sequential) };
    }

    /// `hash(parts)`, with a message of at least `tree.split_len_min` bytes hashed as
    /// subtrees across `strategy` when it runs the call in parallel. A total that overflows
    /// `usize` (possible only when parts alias) hashes serially.
    pub fn hash_across(parts: []const []const u8, strategy: anytype) Value {
        const resolved = hasher.resolve_strategy(strategy);
        var len: usize = 0;
        for (parts) |part| {
            len = std.math.add(usize, len, part.len) catch return hash(parts);
        }
        if (len < tree.split_len_min) return hash(parts);
        const Split = struct {
            parts: []const []const u8,
            len: usize,
            strategy: @TypeOf(resolved),

            pub fn serial(op: @This()) Value {
                return hash(op.parts);
            }

            pub fn parallel(op: @This()) Value {
                return .{ .bytes = tree.hash_subtrees(op.parts, op.len, op.strategy) };
            }
        };
        return resolved.run(len, Split{ .parts = parts, .len = len, .strategy = resolved });
    }

    /// The digests of `left` and `right`, each hashed with `hash_across`.
    pub fn hash_pair(
        left: []const []const u8,
        right: []const []const u8,
        strategy: anytype,
    ) [2]Value {
        return .{ hash_across(left, strategy), hash_across(right, strategy) };
    }

    /// Hashes each message alone into `digests`, which must be as long as `messages`.
    pub fn hash_many(messages: []const []const u8, digests: []Value, strategy: anytype) void {
        hasher.hash_batches(Blake3, messages, digests, strategy);
    }
};

comptime {
    assert(Core.digest_length == digest_length);
    hasher.assert_hasher(Blake3);
}

const testing = std.testing;
const fuzz = @import("fuzz.zig");

fn hex_digest(comptime text: []const u8) Digest {
    var out: Digest = undefined;
    _ = std.fmt.hexToBytes(&out.bytes, text) catch unreachable; // Proof: comptime test vector.
    return out;
}

const hello_digest = hex_digest("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");

test "blake3 hello world through streaming and one-shot" {
    var h = Blake3.init();
    h.update("hello world");
    try testing.expect(h.finalize().eql(hello_digest));
    h.update("hello world");
    try testing.expect(h.finalize().eql(hello_digest));
    try testing.expect(Blake3.hash(&.{"hello world"}).eql(hello_digest));
    try testing.expect(Blake3.hash(&.{ "hello", " world" }).eql(hello_digest));
}

test "blake3 official vectors" {
    const vectors = [_]struct { usize, Digest }{
        .{ 16384, hex_digest("f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4") },
        .{ 31744, hex_digest("62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47") },
        .{ 102400, hex_digest("bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085") },
    };
    const input = try testing.allocator.alloc(u8, 102400);
    defer testing.allocator.free(input);
    // The official input repeats the bytes 0 through 250.
    for (input, 0..) |*byte, i| byte.* = @intCast(i % 251);
    for (vectors) |vector| {
        var h = Blake3.init();
        h.update(input[0..vector[0]]);
        try testing.expect(h.finalize().eql(vector[1]));
    }
}

test "blake3 fuzz hasher entrypoints" {
    try fuzz.fuzz_hash_many(Blake3, 0xb1a4e3);
    // Last: in fuzz mode the coverage-guided half does not return.
    try fuzz.fuzz_hasher(Blake3, 0xb1a4e3);
}

test {
    _ = @import("blake3_tree_tests.zig");
}
