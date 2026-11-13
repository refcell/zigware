//! BLAKE3 implementation of the hasher interface (commonware `cryptography/src/blake3`).
//!
//! Backed by `std.crypto.hash.Blake3`, which hashes chunks with SIMD. Commonware splits long
//! messages into subtrees across a `parallel` strategy; the digest is identical either way,
//! so until the parallel package lands `hash_across` hashes on the calling thread.

const std = @import("std");
const parallel = @import("parallel");
const assert = std.debug.assert;
const hasher = @import("hasher.zig");
const digest = @import("digest.zig");

pub const Core = std.crypto.hash.Blake3;

const digest_length = 32;

/// Digest of a BLAKE3 hashing operation.
pub const Digest = digest.Digest(digest_length, "blake3");

/// BLAKE3 hasher.
pub const Blake3 = hasher.Streaming(Core, Digest);

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

test "blake3 long messages split into parts" {
    const chunk_length = 1024;
    const subtree_length = 16 * chunk_length;
    const split_length = 8 * subtree_length;
    const total = (1 << 20) + 5000;
    const data = try testing.allocator.alloc(u8, total);
    defer testing.allocator.free(data);
    var random = std.Random.DefaultPrng.init(0);
    random.random().bytes(data);
    const lengths = [_]usize{
        0,                    1,                  chunk_length,   chunk_length + 1,
        3 * chunk_length + 7, subtree_length - 1, subtree_length, subtree_length + 1,
        2 * subtree_length,   split_length - 1,   split_length,   3 * split_length + 17,
        total,
    };
    for (lengths) |length| {
        const message = data[0..length];
        var expected: Digest = undefined;
        Core.hash(message, &expected.bytes, .{});
        const a = length / 3;
        const b = a + @min(subtree_length, length - a);
        try testing.expect(Blake3.hash(&.{message}).eql(expected));
        const parts = [_][]const u8{ message[0..a], message[a..b], message[b..] };
        try testing.expect(Blake3.hash(&parts).eql(expected));
        const across = Blake3.hash_across(&.{ "", message, "" }, parallel.sequential);
        try testing.expect(across.eql(expected));
    }
}

test "blake3 fuzz hasher entrypoints" {
    try fuzz.fuzz_hasher(Blake3, 0xb1a4e3);
    try fuzz.fuzz_hash_many(Blake3, 0xb1a4e3);
}
