//! SHA-512 implementation of the hasher interface (commonware `cryptography/src/sha512.rs`).
//!
//! Streams through `std.crypto.hash.sha2.Sha512` with whole blocks compressed by
//! `sha512_blocks.zig`, and `hash_many` hashes eight messages at once on AVX-512F
//! (`sha512_x8.zig`), as commonware does. Digests encode as their 64 raw bytes.

const std = @import("std");
const parallel = @import("parallel");
const codec = @import("codec");
const assert = std.debug.assert;
const hasher = @import("hasher.zig");
const digest = @import("digest.zig");

const StdSha512 = std.crypto.hash.sha2.Sha512;
const blocks = @import("sha512_blocks.zig");

/// std's streaming SHA-512 state, with whole blocks compressed four schedules at a time and a
/// one-part message hashed without the streaming buffer.
pub const Core = struct {
    inner: StdSha512,

    pub const digest_length = StdSha512.digest_length;
    pub const block_length = StdSha512.block_length;
    pub const Options = StdSha512.Options;

    comptime {
        assert(block_length == blocks.block_length);
    }

    pub fn init(options: Options) Core {
        return .{ .inner = StdSha512.init(options) };
    }

    pub fn update(self: *Core, bytes: []const u8) void {
        var rest = bytes;
        if (self.inner.buf_len != 0) {
            // Top up the buffered block; std compresses it once it is full.
            const take = @min(block_length - self.inner.buf_len, rest.len);
            self.inner.update(rest[0..take]);
            rest = rest[take..];
        }
        const whole = rest.len - rest.len % block_length;
        if (whole > 0) {
            assert(self.inner.buf_len == 0);
            blocks.compress(&self.inner.s, rest[0..whole]);
            self.inner.total_len += whole;
            rest = rest[whole..];
        }
        assert(rest.len < block_length);
        self.inner.update(rest);
    }

    pub fn final(self: *Core, out: *[StdSha512.digest_length]u8) void {
        self.inner.final(out);
    }

    /// Hashes the concatenation of `parts` into `out`; one part skips the streaming state.
    pub fn hash_parts(parts: []const []const u8, out: *[StdSha512.digest_length]u8) void {
        if (parts.len == 1) return blocks.digest_message(parts[0], out);
        var core = init(.{});
        for (parts) |part| core.update(part);
        core.final(out);
    }
};

const digest_length = 64;

/// Digest of a SHA-512 hashing operation.
pub const Digest = digest.Digest(digest_length, "sha512");

/// The eight-message kernel `Sha512.hash_many` runs on, where the target has AVX-512F.
pub const x8 = @import("sha512_x8.zig");

/// SHA-512 hasher.
pub const Sha512 = hasher.StreamingWith(Core, Digest, if (x8.supported) x8 else void);

comptime {
    assert(Core.digest_length == digest_length);
    hasher.assert_hasher(Sha512);
}

const testing = std.testing;
const fuzz = @import("fuzz.zig");

fn hex_digest(comptime text: []const u8) Digest {
    var out: Digest = undefined;
    _ = std.fmt.hexToBytes(&out.bytes, text) catch unreachable; // Proof: comptime test vector.
    return out;
}

const empty_digest = hex_digest(
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" ++
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
);
const abc_digest = hex_digest(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
);

test "sha512 known answers and reset" {
    try testing.expect(Sha512.hash(&.{}).eql(empty_digest));
    try testing.expect(Sha512.hash(&.{"abc"}).eql(abc_digest));
    try testing.expect(Sha512.hash(&.{ "a", "", "bc" }).eql(abc_digest));
    const pair = Sha512.hash_pair(&.{}, &.{ "a", "bc" }, parallel.sequential);
    try testing.expect(pair[0].eql(empty_digest));
    try testing.expect(pair[1].eql(abc_digest));
    var digests: [2]Digest = undefined;
    Sha512.hash_many(&.{ "", "abc" }, &digests, parallel.sequential);
    try testing.expect(digests[0].eql(empty_digest));
    try testing.expect(digests[1].eql(abc_digest));

    // Stream a byte at a time; every digest after the first matches only if finalize reset.
    var h = Sha512.init();
    for ([_][]const u8{ "abc", "", "abc", "" }) |message| {
        for (message) |byte| h.update(&.{byte});
        const expected = if (message.len == 0) empty_digest else abc_digest;
        try testing.expect(h.finalize().eql(expected));
    }
}

test "sha512 one-shot and streaming match std across block groups" {
    // Every length through five blocks (the padding boundaries and the four-block groups), then
    // longer ones, as one aligned part, one unaligned part, and three parts.
    var data: [4200]u8 = undefined;
    message_bytes(&data, 7);
    var prng = std.Random.DefaultPrng.init(0x5ad512);
    for (0..700) |i| {
        const len = if (i < 641) i else prng.random().uintAtMost(usize, data.len - 1);
        var expected: [digest_length]u8 = undefined;
        StdSha512.hash(data[0..len], &expected, .{});
        try testing.expectEqualSlices(u8, &expected, &Sha512.hash(&.{data[0..len]}).bytes);
        var shifted: [digest_length]u8 = undefined;
        StdSha512.hash(data[1..][0..len], &shifted, .{});
        try testing.expectEqualSlices(u8, &shifted, &Sha512.hash(&.{data[1..][0..len]}).bytes);
        const a = prng.random().uintAtMost(usize, len);
        const b = a + prng.random().uintAtMost(usize, len - a);
        const parts = [_][]const u8{ data[0..a], data[a..b], data[b..len] };
        try testing.expectEqualSlices(u8, &expected, &Sha512.hash(&parts).bytes);
    }
}

/// A `length`-byte message whose bytes depend on `seed`.
fn message_bytes(out: []u8, seed: usize) void {
    for (out, 0..) |*byte, i| byte.* = @truncate((i *% 31) ^ (seed *% 0x9e37));
}

test "sha512 hash_many with equal and mixed lengths" {
    var storage: [20][301]u8 = undefined;
    var messages: [20][]const u8 = undefined;
    var digests: [20]Digest = undefined;
    for (0..301) |length| {
        for (0..20) |lane| {
            const other = (length * 7 + lane * 37) % 301;
            const own = if (lane == length % 20) length else other;
            message_bytes(storage[lane][0..own], lane);
            messages[lane] = storage[lane][0..own];
        }
        for (0..21) |count| {
            Sha512.hash_many(messages[0..count], digests[0..count], parallel.sequential);
            for (messages[0..count], digests[0..count]) |message, d| {
                var reference: Digest = undefined;
                StdSha512.hash(message, &reference.bytes, .{});
                try testing.expect(d.eql(reference));
            }
        }
    }
}

test "sha512 digest codec" {
    const d = Sha512.hash(&.{"abc"});
    const encoded = codec.encode_fixed(Digest, d);
    try testing.expectEqualSlices(u8, &abc_digest.bytes, &encoded);
    try testing.expect((try codec.decode(Digest, testing.allocator, &encoded)).eql(d));
    const short = codec.decode(Digest, testing.allocator, encoded[0..63]);
    try testing.expectError(error.EndOfBuffer, short);
}

test "sha512 fuzz hasher entrypoints" {
    try fuzz.fuzz_hash_many(Sha512, 0x5ad512);
    // Last: in fuzz mode the coverage-guided half does not return.
    try fuzz.fuzz_hasher(Sha512, 0x5ad512);
}

test "sha512 hash_many on overlapping and aliased messages" {
    // commonware `test_hash_many_overlapping_messages`: message `lane` starts at byte `lane`
    // and spans `100 + 12 * lane` bytes; nine aliases of one buffer spill past a lane group.
    var backing: [400]u8 = undefined;
    message_bytes(&backing, 0);
    var messages: [20][]const u8 = undefined;
    for (&messages, 0..) |*message, lane| message.* = backing[lane .. lane * 13 + 100];
    try fuzz.check_hash_many(Sha512, &messages);
    const aliased: [9][]const u8 = @splat(&backing);
    try fuzz.check_hash_many(Sha512, &aliased);
}

// commonware `padding.rs` `test_blocks_pad_messages`: compressing a message's padded blocks
// from the IV gives its digest, for every length across the first three blocks' boundaries.
test "sha512 padded blocks give the digest" {
    var data: [400]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i * 7);
    for (0..data.len + 1) |len| {
        var state = StdSha512.init(.{});
        for (0..x8.block_count(len)) |index| {
            var bytes: [StdSha512.block_length]u8 = undefined;
            x8.block(data[0..len], index, &bytes);
            state.update(&bytes);
        }
        var got: [digest_length]u8 = undefined;
        for (state.s, 0..) |word, j| std.mem.writeInt(u64, got[j * 8 ..][0..8], word, .big);
        var expected: [digest_length]u8 = undefined;
        StdSha512.hash(data[0..len], &expected, .{});
        try testing.expectEqualSlices(u8, &expected, &got);
    }
}

test "sha512 hash_many with one long lane among short ones" {
    // The longest lane finishes alone: from a block inside its message (std's compressor) or
    // from its padding (lockstep with one lane active), next to lanes of every block count.
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5a512);
    const random = prng.random();
    const data = try gpa.alloc(u8, 1 << 13);
    defer gpa.free(data);
    random.bytes(data);
    var messages: [19][]const u8 = undefined;
    var digests: [19]Digest = undefined;
    for (0..200) |round| {
        for (&messages, 0..) |*message, index| {
            const len = if (index % 8 == round % 8)
                random.uintAtMost(usize, 3000)
            else
                random.uintAtMost(usize, if (round % 2 == 0) 260 else 1100);
            message.* = data[random.uintAtMost(usize, data.len - len)..][0..len];
        }
        Sha512.hash_many(&messages, &digests, parallel.sequential);
        for (messages, digests) |message, d| {
            var expected: Digest = undefined;
            StdSha512.hash(message, &expected.bytes, .{});
            try testing.expect(d.eql(expected));
        }
    }
}

test {
    _ = x8;
}
