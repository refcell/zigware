//! SHA-512 compression of one message's consecutive blocks, a group of four at a time.
//!
//! The message schedules of four blocks run together in `@Vector(4, u64)` lanes, one block per
//! lane, so the schedule leaves the scalar ports to the rounds; the rounds then read each
//! block's W+K from the table. A round adds `h + W + K` and `Ch` first and `Σ1(e)` last, so only
//! `Σ1` and two additions sit on the `e` dependency chain (std's order puts four there). The
//! same work as std's `Sha512.round`, so digests are identical.

const std = @import("std");
const assert = std.debug.assert;
const K = @import("sha512_x8.zig").K;

pub const block_length = 128;
const group = 4;
const V = @Vector(group, u64);

/// The FIPS 180-4 initial state.
const iv = std.crypto.hash.sha2.Sha512.init(.{}).s;

/// Compresses the whole blocks of `blocks` into `state`, in order.
pub fn compress(state: *[8]u64, blocks: []const u8) void {
    // The unrolled groups' inline loops pass the default comptime branch quota.
    @setEvalBranchQuota(10_000);
    assert(blocks.len % block_length == 0);
    var rest = blocks;
    while (rest.len >= group * block_length) : (rest = rest[group * block_length ..]) {
        compress_group(group, state, rest[0 .. group * block_length]);
    }
    // A runtime count of rounds per group kept the state out of registers (1.5x slower), so
    // each count gets its own unrolled copy.
    switch (rest.len / block_length) {
        0 => {},
        inline 1...group - 1 => |count| {
            compress_group(count, state, rest[0 .. count * block_length]);
        },
        else => unreachable, // Proof: the loop leaves fewer than `group` blocks.
    }
}

/// Compresses `count` blocks (one to four) into `state`, their schedules computed together.
inline fn compress_group(
    comptime count: usize,
    state: *[8]u64,
    blocks: *const [count * block_length]u8,
) void {
    comptime assert(count >= 1 and count <= group);
    var wk: [80][group]u64 align(64) = undefined;
    schedule(count, blocks, &wk);
    inline for (0..count) |lane| rounds(state, &wk, lane);
}

/// The SHA-512 digest of `message`: its whole blocks compress straight from `message`, then
/// the tail is padded on the stack (the streaming state's buffer and its copies are skipped).
pub fn digest_message(message: []const u8, out: *[64]u8) void {
    const whole = message.len - message.len % block_length;
    var state = iv;
    compress(&state, message[0..whole]);
    const rest = message[whole..];
    assert(rest.len < block_length);
    var padded: [2 * block_length]u8 align(16) = @splat(0);
    @memcpy(padded[0..rest.len], rest);
    padded[rest.len] = 0x80;
    const len: usize = if (rest.len + 17 <= block_length) block_length else 2 * block_length;
    // The 128-bit bit length; a slice's byte count fits the low 64 bits times 8 only below
    // 2^61 bytes, so the high word carries the top three bits.
    const bits_low = @as(u64, message.len) << 3;
    const bits_high = @as(u64, message.len) >> 61;
    std.mem.writeInt(u64, padded[len - 16 ..][0..8], bits_high, .big);
    std.mem.writeInt(u64, padded[len - 8 ..][0..8], bits_low, .big);
    compress(&state, padded[0..len]);
    for (state, 0..) |word, i| std.mem.writeInt(u64, out[i * 8 ..][0..8], word, .big);
}

inline fn rotr(x: V, comptime n: u6) V {
    return std.math.rotr(V, x, n);
}

/// W+K of each of the `count` blocks of `blocks`, block `lane` in lane `lane`; lanes past
/// the last block hold the schedule of the first, unused.
fn schedule(
    comptime count: usize,
    blocks: *const [count * block_length]u8,
    wk: *[80][group]u64,
) void {
    comptime assert(count >= 1 and count <= group);
    var w: [16]V = undefined;
    inline for (0..16) |t| {
        var words: V = undefined;
        inline for (0..group) |lane| {
            const start = comptime (if (lane < count) lane else 0) * block_length + t * 8;
            words[lane] = std.mem.readInt(u64, blocks[start..][0..8], .big);
        }
        w[t] = words;
        wk[t] = words +% @as(V, @splat(K[t]));
    }
    inline for (16..80) |t| {
        const a = w[(t - 15) % 16];
        const b = w[(t - 2) % 16];
        const sigma0 = rotr(a, 1) ^ rotr(a, 8) ^ (a >> @splat(7));
        const sigma1 = rotr(b, 19) ^ rotr(b, 61) ^ (b >> @splat(6));
        const words = w[t % 16] +% sigma0 +% w[(t - 7) % 16] +% sigma1;
        w[t % 16] = words;
        wk[t] = words +% @as(V, @splat(K[t]));
    }
}

/// The 80 rounds of the block in lane `lane` of `wk`, then the feed-forward into `state`.
inline fn rounds(state: *[8]u64, wk: *const [80][group]u64, comptime lane: usize) void {
    comptime assert(lane < group);
    var v = state.*;
    // `b ^ c` of the next round is `a ^ b` of this one, so majority costs one xor, one and, and
    // one xor (as sha2's x86_avx2 `bool3ary_232`, kept off the `a` chain).
    var b_xor_c = v[1] ^ v[2];
    inline for (0..80) |i| {
        // Round i's a is v[(8 - i % 8) % 8]; the others follow it cyclically.
        const a = (8 - i % 8) % 8;
        const b = (a + 1) % 8;
        const d = (a + 3) % 8;
        const e = (a + 4) % 8;
        const f = (a + 5) % 8;
        const g = (a + 6) % 8;
        const h = (a + 7) % 8;
        const early = (v[h] +% wk[i][lane]) +% (v[g] ^ (v[e] & (v[f] ^ v[g])));
        const sigma1 = std.math.rotr(u64, v[e], 14) ^ std.math.rotr(u64, v[e], 18) ^
            std.math.rotr(u64, v[e], 41);
        const sigma0 = std.math.rotr(u64, v[a], 28) ^ std.math.rotr(u64, v[a], 34) ^
            std.math.rotr(u64, v[a], 39);
        const a_xor_b = v[a] ^ v[b];
        const majority = v[b] ^ (a_xor_b & b_xor_c);
        b_xor_c = a_xor_b;
        const t1 = early +% sigma1;
        v[d] = (v[d] +% early) +% sigma1;
        v[h] = t1 +% (sigma0 +% majority);
    }
    for (state, v) |*word, add| word.* +%= add;
}
