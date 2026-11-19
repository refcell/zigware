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
    switch (builtin.cpu.arch) {
        .x86_64 => compress_x86(state, blocks),
        .aarch64 => compress_aarch64(state, blocks),
        else => comptime unreachable,
    }
}

/// The four big-endian words at `bytes[offset..][0..16]`.
inline fn load(bytes: []const u8, offset: usize) V4u32 {
    assert(offset % 16 == 0);
    assert(offset + 16 <= bytes.len);
    const words: V4u32 = @bitCast(bytes[offset..][0..16].*);
    return @byteSwap(words);
}

fn compress_x86(state: *[8]u32, blocks: []const u8) void {
    assert(blocks.len % 64 == 0);
    // sha256rnds2 keeps the state as ABEF and CDGH.
    var x: V4u32 = .{ state[5], state[4], state[1], state[0] };
    var y: V4u32 = .{ state[7], state[6], state[3], state[2] };
    var offset: usize = 0;
    while (offset < blocks.len) : (offset += 64) {
        const x_start = x;
        const y_start = y;
        var m = [4]V4u32{
            load(blocks, offset),      load(blocks, offset + 16),
            load(blocks, offset + 32), load(blocks, offset + 48),
        };
        inline for (0..16) |k| {
            const w: V4u32 = m[k % 4] +% @as(V4u32, K[4 * k ..][0..4].*);
            y = asm ("sha256rnds2 %[x], %[y]"
                : [y] "=x" (-> V4u32),
                : [_] "0" (y),
                  [x] "x" (x),
                  [_] "{xmm0}" (w),
            );
            x = asm ("sha256rnds2 %[y], %[x]"
                : [x] "=x" (-> V4u32),
                : [_] "0" (x),
                  [y] "x" (y),
                  [_] "{xmm0}" (@as(V4u32, @bitCast(@as(u128, @bitCast(w)) >> 64))),
            );
            if (k < 12) {
                // Words 4(k+4) to 4(k+4)+3 from words 4k to 4k+15.
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
        x +%= x_start;
        y +%= y_start;
    }
    assert(offset == blocks.len);
    state.* = .{ x[3], x[2], y[3], y[2], x[1], x[0], y[1], y[0] };
}

fn compress_aarch64(state: *[8]u32, blocks: []const u8) void {
    assert(blocks.len % 64 == 0);
    var x: V4u32 = state[0..4].*;
    var y: V4u32 = state[4..8].*;
    var offset: usize = 0;
    while (offset < blocks.len) : (offset += 64) {
        const x_start = x;
        const y_start = y;
        var m = [4]V4u32{
            load(blocks, offset),      load(blocks, offset + 16),
            load(blocks, offset + 32), load(blocks, offset + 48),
        };
        inline for (0..16) |k| {
            if (k > 3) {
                // Words 4k to 4k+3 from words 4(k-4) to 4k-1.
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
            const w: V4u32 = m[k % 4] +% @as(V4u32, K[4 * k ..][0..4].*);
            asm volatile (
                \\mov.4s v0, %[x]
                \\sha256h.4s %[x], %[y], %[w]
                \\sha256h2.4s %[y], v0, %[w]
                : [x] "=w" (x),
                  [y] "=w" (y),
                : [_] "0" (x),
                  [_] "1" (y),
                  [w] "w" (w),
                : .{ .v0 = true });
        }
        x +%= x_start;
        y +%= y_start;
    }
    assert(offset == blocks.len);
    state[0..4].* = x;
    state[4..8].* = y;
}
