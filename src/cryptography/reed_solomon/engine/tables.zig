//! Lookup tables used by the engines (commonware `reed_solomon/engine/tables.rs`).
//!
//! All tables are global and live in static memory (no heap allocation). Each group is built
//! at most once, on first use, behind a small atomic once-guard, so engines on several threads
//! may share them.
//!
//! | Table       | Size      | Used by                                   |
//! | ----------- | --------- | ----------------------------------------- |
//! | `exp`/`log` | 128 KiB   | every engine and every other table        |
//! | `log_walsh` | 128 KiB   | decoding domains of `GF_ORDER` positions  |
//! | short Walsh | < 128 KiB | smaller power-of-two decoding domains     |
//! | `mul16`     | 8 MiB     | `Scalar`                                  |
//! | `skew`      | 128 KiB   | every engine (FFT and IFFT)               |
//! | `mul_gfni`  | 2 MiB     | `Avx512`                                  |

const std = @import("std");
const assert = std.debug.assert;

const engine = @import("../engine.zig");
const fwht = @import("fwht.zig");
const utils = @import("utils.zig");

const GF_BITS = engine.GF_BITS;
const GF_ORDER = engine.GF_ORDER;
const GF_MODULUS = engine.GF_MODULUS;
const GfElement = engine.GfElement;

/// Maps a logarithm to its field element. Entries `0` and `GF_MODULUS` both hold one.
pub const Exp = [GF_ORDER]GfElement;
/// Maps a field element to its logarithm in `0..GF_MODULUS`; zero maps to `GF_MODULUS`.
pub const Log = [GF_ORDER]GfElement;
/// The FWHT of `Log` with entry zero replaced by zero.
pub const LogWalsh = [GF_ORDER]GfElement;
/// Entry `[log_m][i][x]` is the product of `x << (4 * i)` and the element with logarithm `log_m`.
pub const Mul16 = [GF_ORDER][4][16]GfElement;
/// Logarithms of the butterfly coefficients; a `GF_MODULUS` entry encodes a zero coefficient.
pub const Skew = [GF_MODULUS]GfElement;
/// The GF2P8AFFINEQB matrices that multiply by one element: each maps an input byte (the low
/// or high byte of a field element) to its contribution to an output byte. Row `i` of a matrix
/// is byte `7 - i` of its `u64`, as the instruction reads it.
pub const MultiplyGfni = struct {
    low_from_low: u64,
    low_from_high: u64,
    high_from_low: u64,
    high_from_high: u64,
};
/// `MultiplyGfni` for every logarithm; `GF_MODULUS` duplicates the identity at zero.
pub const MulGfni = [GF_ORDER]MultiplyGfni;

/// Exponentiation and logarithm tables.
pub const ExpLog = struct {
    exp: *const Exp,
    log: *const Log,
};

/// Runs an initializer exactly once across threads.
const Once = struct {
    state: std.atomic.Value(u8) = .init(state_empty),

    const state_empty = 0;
    const state_busy = 1;
    const state_done = 2;

    fn call(once: *Once, comptime initialize: fn () void) void {
        if (once.state.load(.acquire) == state_done) return;
        if (once.state.cmpxchgStrong(state_empty, state_busy, .acquire, .acquire) == null) {
            initialize();
            once.state.store(state_done, .release);
            return;
        }
        // Another thread is building the table; it finishes in bounded time.
        while (once.state.load(.acquire) != state_done) std.atomic.spinLoopHint();
    }
};

var exp_table: Exp = undefined;
var log_table: Log = undefined;
var log_walsh_table: LogWalsh = undefined;
var mul16_table: Mul16 = undefined;
var skew_table: Skew = undefined;
var mul_gfni_table: MulGfni = undefined;
/// Short Walsh kernels: the kernel for `n = 1 << level` occupies `[n - 1, 2 * n - 1)`.
var short_log_walsh_table: [GF_ORDER - 1]GfElement = undefined;

var exp_log_once: Once = .{};
var log_walsh_once: Once = .{};
var mul16_once: Once = .{};
var skew_once: Once = .{};
var mul_gfni_once: Once = .{};
var short_log_walsh_once: Once = .{};

/// Lazily initialized exponentiation and logarithm tables.
pub fn get_exp_log() ExpLog {
    exp_log_once.call(initialize_exp_log);
    return .{ .exp = &exp_table, .log = &log_table };
}

/// Lazily initialized logarithmic Walsh transform table.
pub fn get_log_walsh() *const LogWalsh {
    log_walsh_once.call(initialize_log_walsh);
    return &log_walsh_table;
}

/// Lazily initialized logarithmic Walsh kernel over the first `n` positions, scaled by `n^-1`
/// modulo `GF_MODULUS`. `n` must be a power of two below `GF_ORDER`.
pub fn get_short_log_walsh(n: usize) []const GfElement {
    assert(std.math.isPowerOfTwo(n) and n < GF_ORDER);
    short_log_walsh_once.call(initialize_short_log_walsh);
    const kernel = short_log_walsh_table[n - 1 ..][0..n];
    assert(kernel.len == n);
    return kernel;
}

/// Lazily initialized multiplication table for the `Scalar` engine.
pub fn get_mul16() *const Mul16 {
    mul16_once.call(initialize_mul16);
    return &mul16_table;
}

/// Lazily initialized GFNI multiplication table for the `Avx512` engine.
pub fn get_mul_gfni() *const MulGfni {
    mul_gfni_once.call(initialize_mul_gfni);
    return &mul_gfni_table;
}

/// Lazily initialized skew table used in FFT and IFFT operations.
pub fn get_skew() *const Skew {
    skew_once.call(initialize_skew);
    return &skew_table;
}

/// Multiply `x` by `exp[log_m]` using the `Exp` and `Log` tables.
pub inline fn mul(x: GfElement, log_m: GfElement, exp: *const Exp, log: *const Log) GfElement {
    if (x == 0) return 0;
    return exp[utils.add_mod(log[x], log_m)];
}

/// Builds `Exp` and `Log` for elements expressed in the Cantor basis.
fn initialize_exp_log() void {
    const exp = &exp_table;
    const log = &log_table;

    // Generate the LFSR table.
    var state: usize = 1;
    var i: GfElement = 0;
    while (i < GF_MODULUS) : (i += 1) {
        exp[state] = i;
        state <<= 1;
        if (state >= GF_ORDER) state ^= engine.GF_POLYNOMIAL;
    }
    assert(state == 1);
    exp[0] = GF_MODULUS;

    // Convert to the Cantor basis.
    log[0] = 0;
    for (engine.CANTOR_BASIS, 0..) |basis, bit| {
        const width = @as(usize, 1) << @intCast(bit);
        for (0..width) |j| log[j + width] = log[j] ^ basis;
    }
    for (log) |*value| value.* = exp[value.*];
    for (log, 0..) |value, index| exp[value] = @intCast(index);

    exp[GF_MODULUS] = exp[0];
    assert(log[0] == GF_MODULUS);
    assert(exp[0] == 1);
}

/// Builds `LogWalsh`, the FWHT of `Log` with entry zero replaced by zero.
fn initialize_log_walsh() void {
    const exp_log = get_exp_log();
    log_walsh_table = exp_log.log.*;
    log_walsh_table[0] = 0;
    fwht.fwht(&log_walsh_table, GF_ORDER);
}

/// Builds every short Walsh kernel: the FWHT of `log[..n]` with entry zero replaced by zero,
/// scaled by `n^-1` modulo `GF_MODULUS`.
fn initialize_short_log_walsh() void {
    const exp_log = get_exp_log();
    for (0..GF_BITS) |level| {
        const n = @as(usize, 1) << @intCast(level);
        const kernel = short_log_walsh_table[n - 1 ..][0..n];
        @memcpy(kernel, exp_log.log[0..n]);
        kernel[0] = 0;
        fwht.fwht(kernel, n);
        // n^-1 = GF_ORDER / n modulo GF_MODULUS. Multiplying by 2^j modulo 2^16 - 1 rotates
        // left by j bits, so the scale is a right rotation by log2(n).
        for (kernel) |*factor| factor.* = std.math.rotr(GfElement, factor.*, level);
    }
}

/// Builds `Mul16` from `Exp` and `Log`.
fn initialize_mul16() void {
    const exp_log = get_exp_log();
    for (&mul16_table, 0..) |*lut, log_m_index| {
        const log_m: GfElement = @intCast(log_m_index);
        for (0..16) |x| {
            const value: GfElement = @intCast(x);
            lut[0][x] = mul(value, log_m, exp_log.exp, exp_log.log);
            lut[1][x] = mul(value << 4, log_m, exp_log.exp, exp_log.log);
            lut[2][x] = mul(value << 8, log_m, exp_log.exp, exp_log.log);
            lut[3][x] = mul(value << 12, log_m, exp_log.exp, exp_log.log);
        }
    }
    assert(mul16_table[0][0][1] == 1);
}

/// Builds `MulGfni` by combining one matrix per coefficient bit along a Gray code.
fn initialize_mul_gfni() void {
    const exp_log = get_exp_log();
    var basis_matrices: [GF_BITS][4]u64 = undefined;
    for (&basis_matrices, 0..) |*matrix, coefficient_bit| {
        const log_m = exp_log.log[@as(usize, 1) << @intCast(coefficient_bit)];
        var rows: [4][8]u8 = @splat(@splat(0));
        for (0..GF_BITS) |input_bit| {
            const input = @as(GfElement, 1) << @intCast(input_bit);
            const product = mul(input, log_m, exp_log.exp, exp_log.log);
            for (0..GF_BITS) |output_bit| {
                // Blocks follow the `MultiplyGfni` field order: 2 * output byte + input byte.
                const block = (output_bit / 8) * 2 + input_bit / 8;
                const bit: u8 = @truncate(product >> @intCast(output_bit));
                rows[block][output_bit % 8] |= (bit & 1) << @intCast(input_bit % 8);
            }
        }
        // GF2P8AFFINEQB reads row i from byte 7 - i of each 64-bit matrix.
        for (matrix, rows) |*block, row| block.* = std.mem.readInt(u64, &row, .big);
    }
    // Multiplication is linear in the coefficient. After each basis-matrix XOR, `current` is
    // the matrix for `step ^ (step >> 1)`: consecutive binary-reflected Gray codes differ in
    // bit `@ctz(step)`.
    var current: [4]u64 = @splat(0);
    for (1..GF_ORDER) |step| {
        for (&current, basis_matrices[@ctz(step)]) |*block, basis| block.* ^= basis;
        const coefficient = step ^ (step >> 1);
        mul_gfni_table[exp_log.log[coefficient]] = .{
            .low_from_low = current[0],
            .low_from_high = current[1],
            .high_from_low = current[2],
            .high_from_high = current[3],
        };
    }
    // Exponents are taken modulo `GF_MODULUS`, so exponent `GF_MODULUS` duplicates zero's.
    mul_gfni_table[GF_MODULUS] = mul_gfni_table[0];
    assert(mul_gfni_table[0].low_from_low == 0x0102040810204080);
}

/// Builds `Skew`, the logarithms of the FFT butterfly coefficients. A zero coefficient is
/// stored as `GF_MODULUS`, the logarithm `Log` assigns to zero.
fn initialize_skew() void {
    const exp_log = get_exp_log();
    const exp = exp_log.exp;
    const log = exp_log.log;
    const skew = &skew_table;

    var temp: [GF_BITS - 1]GfElement = undefined;
    for (&temp, 0..) |*value, i| value.* = @as(GfElement, 1) << @intCast(i + 1);

    for (0..GF_BITS - 1) |m| {
        const step = @as(usize, 1) << @intCast(m + 1);
        skew[(@as(usize, 1) << @intCast(m)) - 1] = 0;

        for (m..GF_BITS - 1) |i| {
            const s = @as(usize, 1) << @intCast(i + 1);
            var j = (@as(usize, 1) << @intCast(m)) - 1;
            while (j < s) : (j += step) skew[j + s] = skew[j] ^ temp[i];
        }

        temp[m] = GF_MODULUS - log[mul(temp[m], log[temp[m] ^ 1], exp, log)];

        for (m + 1..GF_BITS - 1) |i| {
            const sum = utils.add_mod(log[temp[i] ^ 1], temp[m]);
            temp[i] = mul(temp[i], sum, exp, log);
        }
    }

    for (skew) |*value| value.* = log[value.*];
    assert(skew[0] == GF_MODULUS);
}

test "exp and log are inverse" {
    const exp_log = get_exp_log();
    for (1..GF_ORDER) |x| {
        try std.testing.expectEqual(@as(GfElement, @intCast(x)), exp_log.exp[exp_log.log[x]]);
    }
    try std.testing.expectEqual(GF_MODULUS, exp_log.log[0]);
    try std.testing.expectEqual(exp_log.exp[0], exp_log.exp[GF_MODULUS]);
}

test "mul16 matches mul" {
    const exp_log = get_exp_log();
    const mul16 = get_mul16();
    const samples = [_]GfElement{ 0, 1, 2, 0x1234, 0xFFFF, 0x8000, 0x00FF };
    for ([_]GfElement{ 0, 1, 77, 0x8000, GF_MODULUS - 1, GF_MODULUS }) |log_m| {
        const lut = &mul16[log_m];
        for (samples) |x| {
            const product = lut[0][x & 15] ^ lut[1][(x >> 4) & 15] ^
                lut[2][(x >> 8) & 15] ^ lut[3][x >> 12];
            try std.testing.expectEqual(mul(x, log_m, exp_log.exp, exp_log.log), product);
        }
    }
}

/// GF2P8AFFINEQB on one byte: output bit `i` is the parity of `x` and row `i`, byte `7 - i`.
fn affine_byte(matrix: u64, x: u8) u8 {
    var out: u8 = 0;
    for (0..8) |i| {
        const row: u8 = @truncate(matrix >> @intCast(8 * (7 - i)));
        out |= @as(u8, @popCount(row & x) & 1) << @intCast(i);
    }
    return out;
}

test "mul_gfni matrix semantics" {
    // commonware `mul_gfni_matrix_semantics`: every matrix multiplies like `mul` under the
    // instruction's row order, and `GF_MODULUS` duplicates the identity.
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), @sizeOf(MulGfni));
    const exp_log = get_exp_log();
    const table = get_mul_gfni();
    const samples = [_]GfElement{ 1, 2, 0x80, 0x100, 0x1234, 0x8000, 0xFFFF };
    var log_m: usize = 0;
    while (log_m < GF_ORDER) : (log_m += 97) {
        const m = &table[log_m];
        for (samples) |x| {
            const lo: u8 = @truncate(x);
            const hi: u8 = @truncate(x >> 8);
            const low = affine_byte(m.low_from_low, lo) ^ affine_byte(m.low_from_high, hi);
            const high = affine_byte(m.high_from_low, lo) ^ affine_byte(m.high_from_high, hi);
            const expected = mul(x, @intCast(log_m), exp_log.exp, exp_log.log);
            try std.testing.expectEqual(expected, @as(GfElement, high) << 8 | low);
        }
    }
    try std.testing.expectEqual(table[0], table[GF_MODULUS]);
}
