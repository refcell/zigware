//! Sixteen-lane software SHA-256 (commonware `sha256/simd/x86_64/sha256_x16.asm`): hashes 16
//! equal-length messages at once, one message per 32-bit lane of a `@Vector(16, u32)`, which
//! lowers to AVX-512 on x86-64. `Sha256.hash_many` uses it where the target has AVX-512, as
//! commonware does: SHA-NI hashes one message at a time, and from 7 equal-length messages up the
//! kernel is faster (2 without SHA-NI).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

/// Messages hashed by one kernel call.
pub const lanes = 16;
const block_bytes = 64;
const digest_bytes = 32;
const Lane = @Vector(lanes, u32);

/// Whether the target has the vector width the kernel is written for (AVX-512 on x86-64).
pub const supported = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f);
const sha_ni = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .sha);
/// The fewest equal-length messages the kernel hashes; shorter runs hash one at a time.
pub const minimum_batch_len: usize = if (sha_ni) 7 else 2;

comptime {
    assert(minimum_batch_len >= 2 and minimum_batch_len <= lanes);
    assert(@sizeOf(Lane) == lanes * 4);
}

const round_constants = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
const initial_state = [8]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/// The SHA-256 digests of 16 messages of one length, in input order.
pub fn hash(messages: [lanes][]const u8) [lanes][digest_bytes]u8 {
    const len = messages[0].len;
    for (messages) |message| assert(message.len == len);
    var state: [8]Lane = undefined;
    for (&state, initial_state) |*word, value| word.* = @splat(value);
    var offset: usize = 0;
    while (offset + block_bytes <= len) : (offset += block_bytes) {
        compress(&state, load_block(messages, offset));
    }
    assert(len - offset < block_bytes);
    // Every lane has the same length, so every lane pads into the same one or two blocks.
    const tail_len = len - offset;
    const tail_blocks: usize = if (tail_len + 9 <= block_bytes) 1 else 2;
    var tails: [lanes][2 * block_bytes]u8 = undefined;
    var tail_messages: [lanes][]const u8 = undefined;
    for (&tails, &tail_messages, messages) |*tail, *tail_message, message| {
        @memset(tail, 0);
        @memcpy(tail[0..tail_len], message[offset..]);
        tail[tail_len] = 0x80;
        const end = tail_blocks * block_bytes;
        std.mem.writeInt(u64, tail[end - 8 ..][0..8], @as(u64, len) *% 8, .big);
        tail_message.* = tail[0..end];
    }
    for (0..tail_blocks) |block| compress(&state, load_block(tail_messages, block * block_bytes));
    return store_digests(state);
}

fn store_digests(state: [8]Lane) [lanes][digest_bytes]u8 {
    var digests: [lanes][digest_bytes]u8 = undefined;
    for (state, 0..) |word, index| {
        const values: [lanes]u32 = word;
        for (&digests, values) |*digest, value| {
            std.mem.writeInt(u32, digest[index * 4 ..][0..4], value, .big);
        }
    }
    assert(digests.len == lanes);
    return digests;
}

/// The message schedule's first 16 words of the block at `offset`, one lane per message: each
/// lane's 64 bytes load as one vector, then a 16 by 16 transpose turns rows into words.
fn load_block(messages: [lanes][]const u8, offset: usize) [16]Lane {
    assert(messages[0].len >= offset + block_bytes);
    var rows: [lanes]Lane = undefined;
    for (&rows, messages) |*row, message| {
        const bytes: @Vector(block_bytes, u8) = message[offset..][0..block_bytes].*;
        row.* = @byteSwap(@as(Lane, @bitCast(bytes)));
    }
    // Transpose by swapping each bit of the row index with the same bit of the column index.
    inline for ([_]u32{ 8, 4, 2, 1 }) |bit| {
        const masks = comptime transpose_masks(bit);
        inline for (0..lanes) |row| {
            if (row & bit == 0) {
                const low = rows[row];
                const high = rows[row | bit];
                rows[row] = @shuffle(u32, low, high, masks[0]);
                rows[row | bit] = @shuffle(u32, low, high, masks[1]);
            }
        }
    }
    return rows;
}

/// Shuffle masks for one transpose step: the low row keeps its columns without `bit` and takes
/// the high row's columns with `bit` cleared; the high row the reverse.
fn transpose_masks(comptime bit: u32) [2]@Vector(lanes, i32) {
    comptime assert(bit > 0 and bit < lanes and std.math.isPowerOfTwo(bit));
    var low: [lanes]i32 = undefined;
    var high: [lanes]i32 = undefined;
    for (0..lanes) |column| {
        const index: i32 = @intCast(column);
        const flipped: i32 = @intCast(column ^ bit);
        if (column & bit == 0) {
            low[column] = index;
            high[column] = flipped;
        } else {
            low[column] = ~flipped;
            high[column] = ~index;
        }
    }
    return .{ low, high };
}

inline fn rotr(value: Lane, comptime bits: u5) Lane {
    return std.math.rotr(Lane, value, bits);
}

/// One SHA-256 compression of a block per lane (FIPS 180-4, section 6.2.2).
fn compress(state: *[8]Lane, block: [16]Lane) void {
    var schedule = block;
    var work = state.*;
    inline for (0..64) |round| {
        if (round >= 16) {
            const w15 = schedule[(round - 15) % 16];
            const w2 = schedule[(round - 2) % 16];
            const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >> @splat(3));
            const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >> @splat(10));
            schedule[round % 16] +%= s0 +% schedule[(round - 7) % 16] +% s1;
        }
        const e = work[4];
        const a = work[0];
        const sum1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const choose = (e & work[5]) ^ (~e & work[6]);
        const constant: Lane = @splat(round_constants[round]);
        const t1 = work[7] +% sum1 +% choose +% constant +% schedule[round % 16];
        const sum0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const majority = (a & work[1]) ^ (a & work[2]) ^ (work[1] & work[2]);
        // A temporary first: assigning the literal to `work` would write lanes it still reads.
        const next: [8]Lane = .{
            t1 +% sum0 +% majority, a, work[1], work[2], work[3] +% t1, e, work[5], work[6],
        };
        work = next;
    }
    for (state, work) |*word, value| word.* +%= value;
}

const testing = std.testing;
const Std = std.crypto.hash.sha2.Sha256;

fn expect_matches_std(messages: [lanes][]const u8) !void {
    const digests = hash(messages);
    for (messages, digests) |message, digest| {
        var expected: [digest_bytes]u8 = undefined;
        Std.hash(message, &expected, .{});
        try testing.expectEqualSlices(u8, &expected, &digest);
    }
}

test "sha256 x16 matches std at every padding boundary" {
    // Lengths around one and two padding blocks, and several full blocks: the planted bugs this
    // catches are a wrong tail block count and a length written in bytes instead of bits.
    var buffer: [lanes * 300]u8 = undefined;
    for (&buffer, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% index / 7);
    var len: usize = 0;
    while (len <= 300) : (len += 1) {
        var messages: [lanes][]const u8 = undefined;
        for (&messages, 0..) |*message, lane| message.* = buffer[lane * 300 ..][0..len];
        try expect_matches_std(messages);
    }
}

test "sha256 x16 keeps each lane's digest in its place" {
    // Distinct messages per lane, so a transpose that mixes lanes or columns fails.
    var buffer: [lanes * 1000]u8 = undefined;
    for (&buffer, 0..) |*byte, index| byte.* = @truncate((index *% 2654435761) >> 13);
    var messages: [lanes][]const u8 = undefined;
    for (&messages, 0..) |*message, lane| message.* = buffer[lane * 1000 ..][0..1000];
    try expect_matches_std(messages);
    // Aliased lanes, as `hash_many` fills spare lanes with its first message.
    for (messages[3..]) |*message| message.* = messages[0];
    try expect_matches_std(messages);
}
