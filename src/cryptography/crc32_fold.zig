//! CRC-32C over long inputs by carry-less multiplication folding (VPCLMULQDQ on AVX-512), as
//! commonware's `crc-fast` does. Four 512-bit accumulators each fold 64 bytes of every 256-byte
//! block forward by 256 bytes; the accumulators then fold into one 128-bit value, which two
//! `crc32q` instructions reduce to the CRC, so no Barrett reduction is needed. Inputs shorter
//! than `min_len`, and the tail after the last whole block, go through std's CRC-32/ISCSI.
//!
//! Folding a 64-bit lane `x` (reflected) forward by `D` bytes multiplies it by x^(8D+32) and
//! x^(8D−32) for its low and high halves; with the reflected product's one-bit shift these
//! become the constants x^(8D+31) and x^(8D−33) mod P, computed at comptime below.
//!
//! `available` says whether the target has the instructions; callers keep std's path otherwise.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const Core = std.hash.crc.@"CRC-32/ISCSI";

/// Whether the target can run `update`'s folding path. The self-hosted x86 backend (Debug)
/// cannot pass 512-bit vectors to inline assembly, so only LLVM builds fold.
pub const available = builtin.zig_backend == .stage2_llvm and builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .vpclmulqdq, .avx512f, .sse4_2 });

/// Bytes folded per step: four 64-byte accumulators.
const block_size = 256;
/// The shortest input worth folding (two blocks); shorter ones go through std.
pub const min_len = 2 * block_size;

const V8 = @Vector(8, u64);
const V2 = @Vector(2, u64);

/// The continuation of the CRC-32C whose checksum so far is `crc` over `bytes`. Equal to std's
/// CRC-32/ISCSI resumed from `crc` for every input.
pub fn update(crc: u32, bytes: []const u8) u32 {
    comptime assert(available);
    if (bytes.len < min_len) return update_std(crc, bytes);
    const blocks = bytes.len / block_size;
    assert(blocks >= 2);
    var a0 = load8(bytes[0..]);
    var a1 = load8(bytes[64..]);
    var a2 = load8(bytes[128..]);
    var a3 = load8(bytes[192..]);
    a0 ^= V8{ ~crc, 0, 0, 0, 0, 0, 0, 0 };
    const k_block = comptime broadcast(block_size);
    var block: usize = 1;
    while (block < blocks) : (block += 1) {
        const at = bytes[block * block_size ..];
        a0 = fold8(a0, k_block) ^ load8(at[0..]);
        a1 = fold8(a1, k_block) ^ load8(at[64..]);
        a2 = fold8(a2, k_block) ^ load8(at[128..]);
        a3 = fold8(a3, k_block) ^ load8(at[192..]);
    }
    assert(block == blocks);
    const acc = fold8(a0, comptime broadcast(192)) ^ fold8(a1, comptime broadcast(128)) ^
        fold8(a2, comptime broadcast(64)) ^ a3;
    const lanes: [4]V2 = .{
        .{ acc[0], acc[1] }, .{ acc[2], acc[3] }, .{ acc[4], acc[5] }, .{ acc[6], acc[7] },
    };
    const r = fold2(lanes[0], 48) ^ fold2(lanes[1], 32) ^ fold2(lanes[2], 16) ^ lanes[3];
    const register: u32 = @truncate(crc32q(crc32q(0, r[0]), r[1]));
    return update_std(~register, bytes[blocks * block_size ..]);
}

/// std's CRC-32/ISCSI resumed from the checksum so far `crc`.
pub fn update_std(crc: u32, bytes: []const u8) u32 {
    var core = Core.init();
    core.crc = crc ^ Core.init().crc;
    assert(core.final() == crc);
    core.update(bytes);
    return core.final();
}

/// x^n mod P (P = 0x1EDC6F41, CRC-32C), bit-reflected.
fn x_pow_reflected(comptime n: u32) u32 {
    @setEvalBranchQuota(100_000);
    const poly: u32 = 0x1EDC6F41;
    var r: u32 = 1;
    for (0..n) |_| {
        const carry = r >> 31;
        r <<= 1;
        if (carry == 1) r ^= poly;
    }
    return @bitReverse(r);
}

/// The constants that fold a 128-bit lane forward by `bytes`: {low half, high half}.
fn fold_constants(comptime bytes: u32) [2]u64 {
    comptime assert(bytes >= 16 and bytes % 16 == 0);
    const bits = bytes * 8;
    return .{ x_pow_reflected(bits + 31), x_pow_reflected(bits - 33) };
}

fn broadcast(comptime bytes: u32) V8 {
    const k = fold_constants(bytes);
    return .{ k[0], k[1], k[0], k[1], k[0], k[1], k[0], k[1] };
}

fn clmul8(comptime imm: u8, a: V8, b: V8) V8 {
    return asm ("vpclmulqdq %[imm], %[b], %[a], %[out]"
        : [out] "=v" (-> V8),
        : [a] "v" (a),
          [b] "v" (b),
          [imm] "n" (imm),
    );
}

fn clmul2(comptime imm: u8, a: V2, b: V2) V2 {
    return asm ("vpclmulqdq %[imm], %[b], %[a], %[out]"
        : [out] "=x" (-> V2),
        : [a] "x" (a),
          [b] "x" (b),
          [imm] "n" (imm),
    );
}

inline fn fold8(x: V8, k: V8) V8 {
    return clmul8(0x00, x, k) ^ clmul8(0x11, x, k);
}

inline fn fold2(x: V2, comptime bytes: u32) V2 {
    const c = comptime fold_constants(bytes);
    const k: V2 = .{ c[0], c[1] };
    return clmul2(0x00, x, k) ^ clmul2(0x11, x, k);
}

/// Loads 64 unaligned bytes as one vector (a `@bitCast` of an array copies through the stack).
fn load8(bytes: []const u8) V8 {
    assert(bytes.len >= 64);
    const pointer: *align(1) const V8 = @ptrCast(bytes.ptr);
    return pointer.*;
}

fn crc32q(register: u64, data: u64) u64 {
    var r = register;
    asm ("crc32q %[d], %[r]"
        : [r] "+r" (r),
        : [d] "rm" (data),
    );
    return r;
}

test "crc32 fold matches std on random lengths, alignments and states" {
    if (!available) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    var buffer: [70_000]u8 = undefined;
    random.bytes(&buffer);
    for (0..4_000) |_| {
        const start = random.uintLessThan(usize, 64);
        const len = switch (random.uintLessThan(u8, 4)) {
            0 => random.uintLessThan(usize, 2 * min_len),
            1 => min_len - 2 + random.uintLessThan(usize, 4),
            else => random.uintLessThan(usize, buffer.len - start),
        };
        const crc = random.int(u32);
        const data = buffer[start..][0..len];
        try std.testing.expectEqual(update_std(crc, data), update(crc, data));
    }
}
