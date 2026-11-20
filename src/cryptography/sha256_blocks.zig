//! SHA-256 compression of many consecutive 64-byte blocks on the CPU's SHA extensions, with
//! the state in vector registers from the first block to the last (as the `sha2` crate's
//! `compress256`, commonware's large-message path, does). `std.crypto.hash.sha2.Sha256` uses
//! the same instructions, but per block it reloads and reshuffles the state from memory and
//! writes the message schedule to the stack. The round and schedule instruction sequences are
//! std's.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const V4u32 = @Vector(4, u32);

/// Whether `compress` runs here: x86-64 with SHA and AVX2 (std's own condition), or aarch64
/// with SHA2. The C backend cannot pass vectors to inline asm.
pub const available = builtin.zig_backend != .stage2_c and switch (builtin.cpu.arch) {
    .x86_64 => builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 }),
    .aarch64 => builtin.cpu.has(.aarch64, .sha2),
    else => false,
};

/// FIPS 180-4 round constants.
const K = [64]u32{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

/// Compresses `blocks` (a whole number of 64-byte blocks) into `state`.
pub fn compress(state: *[8]u32, blocks: []const u8) void {
    comptime assert(available);
    assert(blocks.len % 64 == 0);
    assert(blocks.len > 0);
    var states = [1]*[8]u32{state};
    compress_n(1, &states, .{blocks});
}

fn compress_n(comptime n: usize, states: *[n]*[8]u32, inputs: [n][]const u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => compress_x86(n, states, inputs),
        .aarch64 => compress_aarch64(n, states, inputs),
        else => comptime unreachable,
    }
}

/// The SHA-256 digests of `inputs`, each a whole padded message of the same length, hashed from
/// the initial state with the state kept in registers from the IV to the digest bytes (as
/// commonware's `hash_single` and `hash_pair` kernels do). Two inputs interleave, so each
/// fills the other's SHA instruction latency.
pub fn digest_n(comptime n: usize, inputs: [n][]const u8, outs: [n]*[32]u8) void {
    comptime assert(available);
    comptime assert(n == 1 or n == 2);
    const len = inputs[0].len;
    for (inputs) |input| assert(input.len == len);
    assert(len % 64 == 0 and len > 0);
    var x: [n]V4u32 = @splat(iv_x);
    var y: [n]V4u32 = @splat(iv_y);
    blocks_n(n, &x, &y, inputs);
    store_digests(n, x, y, outs);
}

/// The SHA-256 digest of `message`, of any length, with the state kept in registers from the
/// IV to the digest bytes: the whole blocks compress straight from `message`, then the tail is
/// padded on the stack (the streaming state's buffer and its copies are skipped).
pub fn digest_message(message: []const u8, out: *[32]u8) void {
    comptime assert(available);
    const whole = message.len - message.len % 64;
    var x: [1]V4u32 = .{iv_x};
    var y: [1]V4u32 = .{iv_y};
    blocks_n(1, &x, &y, .{message[0..whole]});
    const rest = message[whole..];
    assert(rest.len < 64);
    var padded: [128]u8 align(16) = @splat(0);
    @memcpy(padded[0..rest.len], rest);
    padded[rest.len] = 0x80;
    const len: usize = if (rest.len + 9 <= 64) 64 else 128;
    std.mem.writeInt(u64, padded[len - 8 ..][0..8], @as(u64, message.len) * 8, .big);
    blocks_n(1, &x, &y, .{padded[0..len]});
    store_digests(1, x, y, .{out});
}

/// The Merkle shapes whose words load straight into registers, skipping the padded copy on
/// the stack (commonware's `hash_36`, `hash_40`, `hash_64`, and `hash_72` and their pair
/// kernels): `leaf_36` is a 4-byte position then a digest and `leaf_40` an 8-byte position
/// then a digest, one block each; `node_64` is two digests, one message block then a padding
/// block whose schedule is a constant; `node_72` is an 8-byte position then two digests, two
/// blocks.
pub const Shape = enum {
    leaf_36,
    leaf_40,
    node_64,
    node_72,

    /// The lengths of the shape's parts.
    pub fn lens(comptime shape: Shape) []const usize {
        return switch (shape) {
            .leaf_36 => &.{ 4, 32 },
            .leaf_40 => &.{ 8, 32 },
            .node_64 => &.{ 32, 32 },
            .node_72 => &.{ 8, 32, 32 },
        };
    }
};

/// The digests of each `messages[j]` (the parts of one message in `shape`), `n` (1 or 2)
/// interleaved.
pub fn digest_shape(
    comptime n: usize,
    comptime shape: Shape,
    messages: [n][]const []const u8,
    outs: [n]*[32]u8,
) void {
    comptime assert(available);
    comptime assert(n == 1 or n == 2);
    const lens = comptime shape.lens();
    for (messages) |parts| {
        assert(parts.len == lens.len);
        inline for (lens, 0..) |len, i| assert(parts[i].len == len);
    }
    var x: [n]V4u32 = @splat(iv_x);
    var y: [n]V4u32 = @splat(iv_y);
    var m: [n][4]V4u32 = undefined;
    inline for (0..n) |j| m[j] = shape_words(shape, messages[j]);
    block_n(n, &x, &y, &m);
    switch (shape) {
        .leaf_36, .leaf_40 => {},
        .node_64 => fixed_block_n(n, &x, &y, &fixed_wk_64),
        .node_72 => {
            // The right digest's last two words, 0x80 then zeros, and the bit length 576.
            inline for (0..n) |j| {
                const hi = load(messages[j][2][0..32], 16);
                m[j] = .{ @shuffle(u32, hi, tail_pad, mask_23_01), @splat(0), @splat(0), .{
                    0, 0, 0, 72 * 8,
                } };
            }
            block_n(n, &x, &y, &m);
        },
    }
    store_digests(n, x, y, outs);
}

/// Lanes 2 and 3 of the first vector, then lanes 0 and 1 of the second.
const mask_23_01 = @Vector(4, i32){ 2, 3, -1, -2 };
/// The first padding word (0x80 then zeros) and three zero words.
const tail_pad: V4u32 = .{ 0x80000000, 0, 0, 0 };

/// The big-endian words of the first message block of `parts` in `shape`.
inline fn shape_words(comptime shape: Shape, parts: []const []const u8) [4]V4u32 {
    switch (shape) {
        .node_64 => {
            const left = parts[0][0..32];
            const right = parts[1][0..32];
            return .{ load(left, 0), load(left, 16), load(right, 0), load(right, 16) };
        },
        .leaf_36 => {
            // position, digest words 0 to 7, 0x80 then zeros, and the bit length 288.
            const lo = load(parts[1][0..32], 0);
            const hi = load(parts[1][0..32], 16);
            const head: V4u32 = .{ std.mem.readInt(u32, parts[0][0..4], .big), 0, 0, 0 };
            const tail: V4u32 = .{ 0, 0x80000000, 0, 0 };
            return .{
                @shuffle(u32, head, lo, @Vector(4, i32){ 0, -1, -2, -3 }),
                @shuffle(u32, lo, hi, @Vector(4, i32){ 3, -1, -2, -3 }),
                @shuffle(u32, hi, tail, @Vector(4, i32){ 3, -2, -3, -4 }),
                .{ 0, 0, 0, 36 * 8 },
            };
        },
        .leaf_40 => {
            // position words 0 and 1, digest words 0 to 7, 0x80 then zeros, bit length 320.
            const lo = load(parts[1][0..32], 0);
            const hi = load(parts[1][0..32], 16);
            const head = position_words(parts[0][0..8]);
            return .{
                @shuffle(u32, head, lo, @Vector(4, i32){ 0, 1, -1, -2 }),
                @shuffle(u32, lo, hi, mask_23_01),
                @shuffle(u32, hi, tail_pad, mask_23_01),
                .{ 0, 0, 0, 40 * 8 },
            };
        },
        .node_72 => {
            // position words 0 and 1, left digest words 0 to 7, right digest words 0 to 5.
            const left_lo = load(parts[1][0..32], 0);
            const left_hi = load(parts[1][0..32], 16);
            const right_lo = load(parts[2][0..32], 0);
            const right_hi = load(parts[2][0..32], 16);
            const head = position_words(parts[0][0..8]);
            return .{
                @shuffle(u32, head, left_lo, @Vector(4, i32){ 0, 1, -1, -2 }),
                @shuffle(u32, left_lo, left_hi, mask_23_01),
                @shuffle(u32, left_hi, right_lo, mask_23_01),
                @shuffle(u32, right_lo, right_hi, mask_23_01),
            };
        },
    }
}

/// The two big-endian words of an 8-byte position, in lanes 0 and 1.
inline fn position_words(position: *const [8]u8) V4u32 {
    return .{
        std.mem.readInt(u32, position[0..4], .big),
        std.mem.readInt(u32, position[4..8], .big),
        0,
        0,
    };
}

/// W[t] + K[t] of the padding block that ends a 64-byte message (0x80, zeros, and the bit
/// length 512): the schedule is constant, so its rounds take no message (commonware's
/// `FIXED_ROUNDS4` table).
const fixed_wk_64: [64]u32 = fixed: {
    @setEvalBranchQuota(10_000);
    var w: [64]u32 = @splat(0);
    w[0] = 0x80000000;
    w[15] = 64 * 8;
    for (16..64) |t| {
        const s0 = std.math.rotr(u32, w[t - 15], 7) ^ std.math.rotr(u32, w[t - 15], 18) ^
            (w[t - 15] >> 3);
        const s1 = std.math.rotr(u32, w[t - 2], 17) ^ std.math.rotr(u32, w[t - 2], 19) ^
            (w[t - 2] >> 10);
        w[t] = w[t - 16] +% s0 +% w[t - 7] +% s1;
    }
    var wk: [64]u32 = undefined;
    for (&wk, w, K) |*out, word, k| out.* = word +% k;
    break :fixed wk;
};

/// The 64 rounds of a block whose W + K is `wk`, then the feed-forward.
inline fn fixed_block_n(comptime n: usize, x: *[n]V4u32, y: *[n]V4u32, wk: *const [64]u32) void {
    const x_start = x.*;
    const y_start = y.*;
    inline for (0..16) |k| {
        const w: V4u32 = wk[4 * k ..][0..4].*;
        inline for (0..n) |j| rounds_wk(&x[j], &y[j], w);
    }
    inline for (0..n) |j| {
        x[j] +%= x_start[j];
        y[j] +%= y_start[j];
    }
}

// ABEF and CDGH on x86 (sha256rnds2's layout); ABCD and EFGH on aarch64.
const x86 = builtin.cpu.arch == .x86_64;
const iv_x: V4u32 = if (x86) .{ iv[5], iv[4], iv[1], iv[0] } else iv[0..4].*;
const iv_y: V4u32 = if (x86) .{ iv[7], iv[6], iv[3], iv[2] } else iv[4..8].*;

/// Writes each state's digest bytes to `outs`.
inline fn store_digests(comptime n: usize, x: [n]V4u32, y: [n]V4u32, outs: [n]*[32]u8) void {
    // Words A to H, from lanes of x (0 to 3) and y (-1 to -4).
    const order: @Vector(8, i32) = if (x86) .{ 3, 2, -4, -3, 1, 0, -2, -1 } else .{
        0, 1, 2, 3, -1, -2, -3, -4,
    };
    inline for (0..n) |j| {
        const words: @Vector(8, u32) = @shuffle(u32, x[j], y[j], order);
        const big = if (builtin.cpu.arch.endian() == .little) @byteSwap(words) else words;
        // A pointer store: a bitcast to the byte array compiled to byte extracts.
        @as(*align(1) @Vector(8, u32), @ptrCast(outs[j])).* = big;
    }
}

/// FIPS 180-4 initial state.
const iv = [8]u32{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

/// The four big-endian words at `bytes[offset..][0..16]`.
inline fn load(bytes: []const u8, offset: usize) V4u32 {
    assert(offset % 16 == 0);
    assert(offset + 16 <= bytes.len);
    // A pointer load: a bitcast from the byte array compiled to byte loads, shifts, and ors.
    const words: V4u32 = @as(*align(1) const V4u32, @ptrCast(bytes[offset..][0..16])).*;
    return @byteSwap(words);
}

inline fn load_block(bytes: []const u8, offset: usize) [4]V4u32 {
    return .{
        load(bytes, offset),      load(bytes, offset + 16),
        load(bytes, offset + 32), load(bytes, offset + 48),
    };
}

fn compress_x86(comptime n: usize, states: *[n]*[8]u32, inputs: [n][]const u8) void {
    // sha256rnds2 keeps the state as ABEF and CDGH.
    var x: [n]V4u32 = undefined;
    var y: [n]V4u32 = undefined;
    inline for (0..n) |j| {
        const state = states[j];
        x[j] = .{ state[5], state[4], state[1], state[0] };
        y[j] = .{ state[7], state[6], state[3], state[2] };
    }
    blocks_n(n, &x, &y, inputs);
    inline for (0..n) |j| {
        states[j].* = .{ x[j][3], x[j][2], y[j][3], y[j][2], x[j][1], x[j][0], y[j][1], y[j][0] };
    }
}

/// Compresses each input's blocks into its state, the `n` inputs interleaved.
inline fn blocks_n(comptime n: usize, x: *[n]V4u32, y: *[n]V4u32, inputs: [n][]const u8) void {
    const len = inputs[0].len;
    for (inputs) |input| assert(input.len == len);
    var offset: usize = 0;
    while (offset < len) : (offset += 64) {
        var m: [n][4]V4u32 = undefined;
        inline for (0..n) |j| m[j] = load_block(inputs[j], offset);
        block_n(n, x, y, &m);
    }
    assert(offset == len);
}

/// The 64 rounds of one block whose first sixteen words are `m`, then the feed-forward.
inline fn block_n(comptime n: usize, x: *[n]V4u32, y: *[n]V4u32, m: *[n][4]V4u32) void {
    const x_start = x.*;
    const y_start = y.*;
    inline for (0..16) |k| {
        inline for (0..n) |j| switch (builtin.cpu.arch) {
            .x86_64 => x86_rounds(k, &x[j], &y[j], &m[j]),
            .aarch64 => aarch64_rounds(k, &x[j], &y[j], &m[j]),
            else => comptime unreachable,
        };
    }
    inline for (0..n) |j| {
        x[j] +%= x_start[j];
        y[j] +%= y_start[j];
    }
}

/// Four rounds whose W + K is `w`.
inline fn rounds_wk(x: *V4u32, y: *V4u32, w: V4u32) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x86_rounds_wk(x, y, w),
        .aarch64 => aarch64_rounds_wk(x, y, w),
        else => comptime unreachable,
    }
}

/// Rounds 4k to 4k+3, then (for k < 12) message words 4(k+4) to 4(k+4)+3.
inline fn x86_rounds(comptime k: usize, x: *V4u32, y: *V4u32, m: *[4]V4u32) void {
    x86_rounds_wk(x, y, m[k % 4] +% @as(V4u32, K[4 * k ..][0..4].*));
    if (k < 12) {
        var tmp = m[k % 4];
        m[k % 4] = asm (
            \\ sha256msg1 %[w4_7], %[tmp]
            \\ vpalignr $0x4, %[w8_11], %[w12_15], %[result]
            \\ paddd %[tmp], %[result]
            \\ sha256msg2 %[w12_15], %[result]
            : [tmp] "=&x" (tmp),
              [result] "=&x" (-> V4u32),
            : [_] "0" (tmp),
              [w4_7] "x" (m[(k + 1) % 4]),
              [w8_11] "x" (m[(k + 2) % 4]),
              [w12_15] "x" (m[(k + 3) % 4]),
        );
    }
}

inline fn x86_rounds_wk(x: *V4u32, y: *V4u32, w: V4u32) void {
    y.* = asm ("sha256rnds2 %[x], %[y]"
        : [y] "=x" (-> V4u32),
        : [_] "0" (y.*),
          [x] "x" (x.*),
          [_] "{xmm0}" (w),
    );
    x.* = asm ("sha256rnds2 %[y], %[x]"
        : [x] "=x" (-> V4u32),
        : [_] "0" (x.*),
          [y] "x" (y.*),
          [_] "{xmm0}" (@as(V4u32, @bitCast(@as(u128, @bitCast(w)) >> 64))),
    );
}

fn compress_aarch64(comptime n: usize, states: *[n]*[8]u32, inputs: [n][]const u8) void {
    var x: [n]V4u32 = undefined;
    var y: [n]V4u32 = undefined;
    inline for (0..n) |j| {
        x[j] = states[j][0..4].*;
        y[j] = states[j][4..8].*;
    }
    blocks_n(n, &x, &y, inputs);
    inline for (0..n) |j| {
        states[j][0..4].* = x[j];
        states[j][4..8].* = y[j];
    }
}

/// (For k > 3) message words 4k to 4k+3, then rounds 4k to 4k+3.
inline fn aarch64_rounds(comptime k: usize, x: *V4u32, y: *V4u32, m: *[4]V4u32) void {
    if (k > 3) {
        m[k % 4] = asm (
            \\sha256su0.4s %[w0_3], %[w4_7]
            \\sha256su1.4s %[w0_3], %[w8_11], %[w12_15]
            : [w0_3] "=&w" (-> V4u32),
            : [_] "0" (m[k % 4]),
              [w4_7] "w" (m[(k + 1) % 4]),
              [w8_11] "w" (m[(k + 2) % 4]),
              [w12_15] "w" (m[(k + 3) % 4]),
        );
    }
    aarch64_rounds_wk(x, y, m[k % 4] +% @as(V4u32, K[4 * k ..][0..4].*));
}

inline fn aarch64_rounds_wk(x: *V4u32, y: *V4u32, w: V4u32) void {
    var x_next: V4u32 = undefined;
    var y_next: V4u32 = undefined;
    asm volatile (
        \\mov.4s v0, %[x]
        \\sha256h.4s %[x], %[y], %[w]
        \\sha256h2.4s %[y], v0, %[w]
        : [x] "=w" (x_next),
          [y] "=w" (y_next),
        : [_] "0" (x.*),
          [_] "1" (y.*),
          [w] "w" (w),
        : .{ .v0 = true });
    x.* = x_next;
    y.* = y_next;
}
