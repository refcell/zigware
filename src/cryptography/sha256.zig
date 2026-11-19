//! SHA-256 implementation of the hasher interface (commonware `cryptography/src/sha256`).
//!
//! Backed by `std.crypto.hash.sha2.Sha256`, except that runs of whole blocks compress on
//! SHA-NI or ARMv8 SHA2 with the state held in registers (`sha256_blocks.zig`), where the
//! target has them, and `hash_many` hashes equal-length runs sixteen at a time on AVX-512
//! (`sha256_x16.zig`), as commonware does. Digests encode as their 32 raw bytes.

const std = @import("std");
const parallel = @import("parallel");
const codec = @import("codec");
const assert = std.debug.assert;
const hasher = @import("hasher.zig");
const digest = @import("digest.zig");
const blocks = @import("sha256_blocks.zig");

const StdSha256 = std.crypto.hash.sha2.Sha256;

/// `std.crypto.hash.sha2.Sha256` whose `update` hands whole blocks to `sha256_blocks`.
pub const Core = struct {
    inner: StdSha256,

    pub const digest_length = StdSha256.digest_length;
    pub const block_length = StdSha256.block_length;
    pub const Options = StdSha256.Options;

    pub fn init(options: Options) Core {
        return .{ .inner = StdSha256.init(options) };
    }

    pub fn update(self: *Core, bytes: []const u8) void {
        if (comptime !blocks.available) return self.inner.update(bytes);
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

    pub fn final(self: *Core, out: *[StdSha256.digest_length]u8) void {
        self.inner.final(out);
    }

    /// The longest message `hash_parts` pads on the stack: two blocks less the 0x80 byte and
    /// the 8-byte length (Merkle leaves and nodes are 36 to 72 bytes).
    const short_max = 2 * block_length - 9;

    /// Hashes the concatenation of `parts` into `out`; a short message skips the streaming
    /// state (commonware's `hash_single` kernels serve the same Merkle shapes).
    pub fn hash_parts(parts: []const []const u8, out: *[StdSha256.digest_length]u8) void {
        var total: usize = 0;
        for (parts) |part| total +|= part.len;
        if (comptime !blocks.available) return stream(parts, out);
        if (total > short_max) return stream(parts, out);
        var padded: [2 * block_length]u8 align(16) = @splat(0);
        const len = pad_short(parts, total, &padded);
        var state = iv;
        blocks.compress(&state, padded[0..len]);
        write_state(state, out);
    }

    const iv = StdSha256.init(.{}).s;

    /// `parts` padded into `padded` as one or two final blocks; returns the padded length.
    fn pad_short(parts: []const []const u8, total: usize, padded: *[2 * block_length]u8) usize {
        assert(total <= short_max);
        var offset: usize = 0;
        for (parts) |part| {
            @memcpy(padded[offset..][0..part.len], part);
            offset += part.len;
        }
        assert(offset == total);
        padded[total] = 0x80;
        const len: usize = if (total + 9 <= block_length) block_length else 2 * block_length;
        std.mem.writeInt(u64, padded[len - 8 ..][0..8], @as(u64, total) * 8, .big);
        return len;
    }

    fn write_state(state: [8]u32, out: *[StdSha256.digest_length]u8) void {
        for (state, 0..) |word, index| std.mem.writeInt(u32, out[index * 4 ..][0..4], word, .big);
    }

    /// The digests of `left` and `right`; two short messages of the same padded length
    /// compress interleaved (commonware's `hash_pair` kernels serve the Merkle node shapes).
    pub fn hash_pair_parts(
        left: []const []const u8,
        right: []const []const u8,
        out: *[2][StdSha256.digest_length]u8,
    ) void {
        var totals: [2]usize = .{ 0, 0 };
        for (left) |part| totals[0] +|= part.len;
        for (right) |part| totals[1] +|= part.len;
        const short = totals[0] <= short_max and totals[1] <= short_max;
        if (comptime !blocks.available) return separate(left, right, out);
        if (!short) return separate(left, right, out);
        var padded: [2][2 * block_length]u8 align(16) = @splat(@splat(0));
        const len_left = pad_short(left, totals[0], &padded[0]);
        const len_right = pad_short(right, totals[1], &padded[1]);
        if (len_left != len_right) return separate(left, right, out);
        var states: [2][8]u32 = .{ iv, iv };
        var pointers: [2]*[8]u32 = .{ &states[0], &states[1] };
        blocks.compress_pair(&pointers, padded[0][0..len_left], padded[1][0..len_right]);
        write_state(states[0], &out[0]);
        write_state(states[1], &out[1]);
    }

    fn separate(
        left: []const []const u8,
        right: []const []const u8,
        out: *[2][StdSha256.digest_length]u8,
    ) void {
        hash_parts(left, &out[0]);
        hash_parts(right, &out[1]);
    }

    fn stream(parts: []const []const u8, out: *[StdSha256.digest_length]u8) void {
        var core = init(.{});
        for (parts) |part| core.update(part);
        core.final(out);
    }
};

const digest_length = 32;

/// Digest of a SHA-256 hashing operation.
pub const Digest = digest.Digest(digest_length, "sha256");

/// The sixteen-message kernel `Sha256.hash_many` runs equal-length runs on, where the target
/// has it (AVX-512).
pub const x16 = @import("sha256_x16.zig");

/// SHA-256 hasher.
pub const Sha256 = hasher.StreamingWith(Core, Digest, if (x16.supported) x16 else void);

comptime {
    assert(Core.digest_length == digest_length);
    hasher.assert_hasher(Sha256);
}

const testing = std.testing;
const fuzz = @import("fuzz.zig");

fn hex_digest(comptime text: []const u8) Digest {
    var out: Digest = undefined;
    _ = std.fmt.hexToBytes(&out.bytes, text) catch unreachable; // Proof: comptime test vector.
    return out;
}

const hello_digest = hex_digest("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

fn streamed(parts: []const []const u8) Digest {
    var h = Sha256.init();
    for (parts) |part| h.update(part);
    return h.finalize();
}

test "sha256 hello world through streaming and one-shot" {
    var h = Sha256.init();
    h.update("hello world");
    const d = h.finalize();
    try testing.expect(d.eql(hello_digest));
    _ = try codec.decode(Digest, testing.allocator, &d.bytes);
    try testing.expect(Sha256.hash(&.{"hello world"}).eql(hello_digest));
    try testing.expect(Sha256.hash(&.{ "hello", " world" }).eql(hello_digest));
    // The reset hasher returned by finalize hashes again from scratch.
    h.update("hello world");
    try testing.expect(h.finalize().eql(hello_digest));
}

test "sha256 block runs match std across lengths and split points" {
    const gpa = testing.allocator;
    const data = try gpa.alloc(u8, 1 << 16);
    defer gpa.free(data);
    var prng = std.Random.DefaultPrng.init(0x5ba256);
    prng.random().bytes(data);
    // Every length through two blocks (the stack-padded path), then longer ones.
    var lengths: [192]usize = undefined;
    for (&lengths, 0..) |*len, i| len.* = if (i <= 130) i else if (i < 170) i * 37 else prng
        .random().uintAtMost(usize, data.len);
    lengths[191] = data.len;
    for (lengths) |len| {
        var expected: [32]u8 = undefined;
        StdSha256.hash(data[0..len], &expected, .{});
        // Unaligned starts, splits inside and on block boundaries, and empty parts.
        const a = prng.random().uintAtMost(usize, len);
        const b = a + prng.random().uintAtMost(usize, len - a);
        const splits = [_][2]usize{ .{ 0, 0 }, .{ a, b }, .{ len / 64 * 64, len } };
        for (splits) |cut| {
            const parts = [_][]const u8{ data[0..cut[0]], data[cut[0]..cut[1]], data[cut[1]..len] };
            try testing.expectEqualSlices(u8, &expected, &Sha256.hash(&parts).bytes);
        }
    }
}

test "sha256 one-shot matches streaming across padding boundaries" {
    var data: [300]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i);
    for (0..data.len + 1) |total| {
        const mid = total / 3;
        const parts = [_][]const u8{ data[0..mid], data[mid .. 2 * mid], data[2 * mid .. total] };
        try testing.expect(Sha256.hash(&parts).eql(streamed(&parts)));
    }
}

test "sha256 merkle node shapes match streaming" {
    var data: [72]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i);
    const shapes = [_][]const []const u8{
        &.{ data[0..8], data[8..40], data[40..72] },
        &.{ data[0..32], data[32..64] },
        &.{ data[0..8], data[8..40] },
        &.{ data[0..4], data[4..36] },
    };
    for (shapes) |parts| try testing.expect(Sha256.hash(parts).eql(streamed(parts)));

    // The MMR node shape (position || left || right).
    var left_position: [8]u8 = undefined;
    var right_position: [8]u8 = undefined;
    std.mem.writeInt(u64, &left_position, 42, .big);
    std.mem.writeInt(u64, &right_position, 43, .big);
    const a: [32]u8 = @splat(0x11);
    const b: [32]u8 = @splat(0x12);
    const c: [32]u8 = @splat(0x33);
    const d: [32]u8 = @splat(0x34);
    try fuzz.run_plan(Sha256, &.{ &left_position, &a, &b }, &.{ &right_position, &c, &d });
}

/// Splits `message` into consecutive parts of `lengths` (at most four).
fn split(message: []const u8, lengths: []const usize, parts: *[4][]const u8) []const []const u8 {
    assert(lengths.len <= parts.len);
    var offset: usize = 0;
    for (lengths, 0..) |length, index| {
        parts[index] = message[offset..][0..length];
        offset += length;
    }
    assert(offset == message.len);
    return parts[0..lengths.len];
}

test "sha256 single-message shapes and near misses match streaming" {
    // commonware `test_hash_single_shape_matches_streaming`: the MMR node, BMT node, MMR leaf,
    // and BMT leaf shapes over uniform, counting, and unaligned messages.
    const shapes = [_][]const usize{ &.{ 8, 32, 32 }, &.{ 32, 32 }, &.{ 8, 32 }, &.{ 4, 32 } };
    var backing: [5][73]u8 = undefined;
    for (0..73) |i| {
        backing[0][i] = 0;
        backing[1][i] = 0xff;
        backing[2][i] = @truncate(i);
        backing[3][i] = 0xff -% @as(u8, @truncate(i));
        backing[4][i] = @as(u8, @truncate(i)) *% 31;
    }
    var parts: [4][]const u8 = undefined;
    for (shapes) |lengths| {
        var total: usize = 0;
        for (lengths) |length| total += length;
        for (&backing, 0..) |*message, index| {
            // The last message starts one byte into its buffer, for unaligned loads.
            const start: usize = if (index == 4) 1 else 0;
            const split_parts = split(message[start..][0..total], lengths, &parts);
            try testing.expect(Sha256.hash(split_parts).eql(streamed(split_parts)));
        }
    }

    // commonware `test_hash_single_near_miss_matches_streaming`: shapes a byte or a split away
    // from those above.
    const near_misses = [_][]const usize{
        &.{ 7, 32 },  &.{ 9, 32 },     &.{ 3, 32 },        &.{ 5, 32 }, &.{ 8, 31 },
        &.{ 32, 33 }, &.{ 8, 32, 31 }, &.{ 8, 32, 32, 1 }, &.{72},      &.{40},
    };
    var counting: [73]u8 = undefined;
    for (&counting, 0..) |*byte, i| byte.* = @truncate(i);
    for (near_misses) |lengths| {
        var total: usize = 0;
        for (lengths) |length| total += length;
        const split_parts = split(counting[0..total], lengths, &parts);
        try testing.expect(Sha256.hash(split_parts).eql(streamed(split_parts)));
    }
}

test "sha256 hash_pair matches hash for BMT node shapes" {
    const zero: [32]u8 = @splat(0);
    const ff: [32]u8 = @splat(0xff);
    var ascending: [32]u8 = undefined;
    var descending: [32]u8 = undefined;
    for (0..32) |i| {
        ascending[i] = @truncate(i);
        descending[i] = @truncate(0xff - i);
    }
    var backing: [96]u8 = undefined;
    for (&backing, 0..) |*byte, i| byte.* = @truncate(i);
    try fuzz.run_plan(Sha256, &.{ &zero, &zero }, &.{ &zero, &zero });
    try fuzz.run_plan(Sha256, &.{ &ff, &ff }, &.{ &ff, &ff });
    try fuzz.run_plan(Sha256, &.{ &ascending, &descending }, &.{ &ff, &zero });
    try fuzz.run_plan(
        Sha256,
        &.{ backing[1..33], backing[17..49] },
        &.{ backing[2..34], backing[18..50] },
    );
}

test "sha256 hash_pair matches std across length pairs and parts" {
    var prng = std.Random.DefaultPrng.init(0xa1256);
    const random = prng.random();
    var data: [400]u8 = undefined;
    random.bytes(&data);
    // Every pair of lengths in steps of 3 through 132 (one and two padded blocks, and the
    // stream fallback past 119), each split into a random two-part shape.
    var left_len: usize = 0;
    while (left_len <= 132) : (left_len += 3) {
        var right_len: usize = 0;
        while (right_len <= 132) : (right_len += 3) {
            const a = random.uintAtMost(usize, left_len);
            const b = random.uintAtMost(usize, right_len);
            const left = [_][]const u8{ data[0..a], data[a..left_len] };
            const right = [_][]const u8{ data[200..][0..b], data[200 + b ..][0 .. right_len - b] };
            const pair = Sha256.hash_pair(&left, &right, parallel.sequential);
            var expected: [2][32]u8 = undefined;
            StdSha256.hash(data[0..left_len], &expected[0], .{});
            StdSha256.hash(data[200..][0..right_len], &expected[1], .{});
            try testing.expectEqualSlices(u8, &expected[0], &pair[0].bytes);
            try testing.expectEqualSlices(u8, &expected[1], &pair[1].bytes);
        }
    }
}

test "sha256 hash_many matches individual hashes" {
    const lengths = [_]usize{ 0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 129, 255, 256, 1024 };
    var storage: [33][1024]u8 = undefined;
    var messages: [33][]const u8 = undefined;
    var digests: [33]Digest = undefined;
    for (lengths) |length| {
        for (0..33) |lane| {
            for (0..length) |i| storage[lane][i] = @truncate(i +% lane);
            messages[lane] = storage[lane][0..length];
        }
        for ([_]usize{ 0, 1, 2, 6, 7, 15, 16, 17, 31, 32, 33 }) |count| {
            Sha256.hash_many(messages[0..count], digests[0..count], parallel.sequential);
            for (messages[0..count], digests[0..count]) |message, d| {
                try testing.expect(d.eql(Sha256.hash(&.{message})));
            }
        }
    }
}

/// `hash_many` of 40 messages under an explorer's batch split: runs of equal lengths that span
/// batch boundaries, so a batch range that is not whole kernel units shows.
const ManyAcross = struct {
    messages: []const []const u8,

    pub fn run(op: ManyAcross, explorer: parallel.mocks.Explorer) [40]Digest {
        var digests: [40]Digest = undefined;
        Sha256.hash_many(op.messages, &digests, explorer);
        return digests;
    }
};

test "sha256 hash_many matches individual hashes across batch splits" {
    var storage: [40][300]u8 = undefined;
    var messages: [40][]const u8 = undefined;
    for (&storage, &messages, 0..) |*bytes, *message, index| {
        for (bytes, 0..) |*byte, i| byte.* = @truncate(i *% 7 +% index);
        // 20 of 300 bytes, 12 of 64, then 8 of 299: runs longer and shorter than 16 lanes.
        const len: usize = if (index < 20) 300 else if (index < 32) 64 else 299;
        message.* = bytes[0..len];
    }
    const op: ManyAcross = .{ .messages = &messages };
    const digests = try parallel.mocks.explore(testing.allocator, testing.io, op);
    for (messages, digests) |message, d| try testing.expect(d.eql(Sha256.hash(&.{message})));
}

test "sha256 hash_many over equal-length runs matches std" {
    // Runs of 1 to 40 equal lengths (x16 chunks, short tails, and lone messages), across
    // padding boundaries; every digest checked against std.
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x16a256);
    const random = prng.random();
    const data = try gpa.alloc(u8, 1 << 14);
    defer gpa.free(data);
    random.bytes(data);
    var messages: [160][]const u8 = undefined;
    var digests: [160]Digest = undefined;
    for (0..24) |_| {
        var count: usize = 0;
        while (count < messages.len) {
            const run = @min(1 + random.uintLessThan(usize, 40), messages.len - count);
            const len = random.uintAtMost(usize, 300);
            for (messages[count..][0..run]) |*message| {
                const start = random.uintAtMost(usize, data.len - len);
                message.* = data[start..][0..len];
            }
            count += run;
        }
        Sha256.hash_many(&messages, &digests, parallel.sequential);
        for (messages, digests) |message, d| {
            var expected: [32]u8 = undefined;
            StdSha256.hash(message, &expected, .{});
            try testing.expectEqualSlices(u8, &expected, &d.bytes);
        }
    }
}

test "sha256 digest codec and size" {
    const d = Sha256.hash(&.{"hello world"});
    const encoded = codec.encode_fixed(Digest, d);
    try testing.expectEqualSlices(u8, &d.bytes, &encoded);
    try testing.expect((try codec.decode(Digest, testing.allocator, &encoded)).eql(d));
    try testing.expectEqual(@as(usize, 32), Digest.fixed_size);
    try testing.expect(Sha256.hash(&.{}).eql(streamed(&.{})));
}

test "sha256 fuzz hasher entrypoints" {
    try fuzz.fuzz_hash_many(Sha256, 0x5ad256);
    // Last: in fuzz mode the coverage-guided half does not return.
    try fuzz.fuzz_hasher(Sha256, 0x5ad256);
}

test "sha256 hash_many on aliased and unaligned inputs" {
    // commonware `test_hash_many_aliased_unaligned_inputs_match_individual_hashes`.
    var backing: [160]u8 = undefined;
    for (&backing, 0..) |*byte, i| byte.* = @truncate(i);
    var messages: [16][]const u8 = undefined;
    for (&messages, 0..) |*message, lane| message.* = backing[lane .. lane + 129];
    for (1..messages.len + 1) |count| try fuzz.check_hash_many(Sha256, messages[0..count]);
    const aliased: [16][]const u8 = @splat(backing[1..130]);
    try fuzz.check_hash_many(Sha256, &aliased);
}

test {
    _ = x16;
}
