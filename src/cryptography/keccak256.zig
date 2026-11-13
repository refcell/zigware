//! Keccak-256 implementation of the hasher interface (commonware `cryptography/src/keccak256`).
//!
//! The original Keccak padding (0x01) used by Ethereum, not SHA3-256. Backed by
//! `std.crypto.hash.sha3.Keccak256`.

const std = @import("std");
const codec = @import("codec");
const assert = std.debug.assert;
const hasher = @import("hasher.zig");
const digest = @import("digest.zig");

pub const Core = std.crypto.hash.sha3.Keccak256;

const digest_length = 32;

/// Digest of a Keccak-256 hashing operation.
pub const Digest = digest.Digest(digest_length, "keccak256");

/// Keccak-256 hasher.
pub const Keccak256 = hasher.Streaming(Core, Digest);

comptime {
    assert(Core.digest_length == digest_length);
    hasher.assert_hasher(Keccak256);
}

const testing = std.testing;
const fuzz = @import("fuzz.zig");

fn hex_digest(comptime text: []const u8) Digest {
    var out: Digest = undefined;
    _ = std.fmt.hexToBytes(&out.bytes, text) catch unreachable; // Proof: comptime test vector.
    return out;
}

const empty_digest = hex_digest("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
const abc_digest = hex_digest("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

test "keccak256 known answers and reset" {
    try testing.expect(Keccak256.hash(&.{}).eql(empty_digest));
    try testing.expect(Keccak256.hash(&.{"abc"}).eql(abc_digest));
    try testing.expect(Keccak256.hash(&.{ "a", "", "bc" }).eql(abc_digest));
    const pair = Keccak256.hash_pair(&.{}, &.{ "a", "bc" }, {});
    try testing.expect(pair[0].eql(empty_digest));
    try testing.expect(pair[1].eql(abc_digest));

    var h = Keccak256.init();
    for ([_][]const u8{ "abc", "", "abc", "" }) |message| {
        for (message) |byte| h.update(&.{byte});
        const expected = if (message.len == 0) empty_digest else abc_digest;
        try testing.expect(h.finalize().eql(expected));
    }
}

test "keccak256 rate boundaries" {
    var data: [1024]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i);
    for ([_]usize{ 0, 1, 135, 136, 137, 271, 272, 273, 1024 }) |length| {
        var expected: Digest = undefined;
        Core.hash(data[0..length], &expected.bytes, .{});
        for (0..length + 1) |split| {
            const parts = [_][]const u8{ data[0..split], "", data[split..length] };
            try testing.expect(Keccak256.hash(&parts).eql(expected));
            try fuzz.run_plan(Keccak256, &parts, &.{"abc"});
        }
    }
}

test "keccak256 codec and zeroize" {
    var d = Keccak256.hash(&.{"abc"});
    const encoded = codec.encode_fixed(Digest, d);
    try testing.expectEqualSlices(u8, &abc_digest.bytes, &encoded);
    try testing.expect((try codec.decode(Digest, testing.allocator, &encoded)).eql(d));
    const short = codec.decode(Digest, testing.allocator, abc_digest.bytes[0..31]);
    try testing.expectError(error.EndOfBuffer, short);
    d.zeroize();
    try testing.expect(d.eql(Digest.empty));
}

test "keccak256 fuzz hasher entrypoints" {
    try fuzz.fuzz_hasher(Keccak256, 0x6ecca);
}
