//! SIMD backends and operations (commonware `simd` core, emulated backends, and dispatch).
//!
//! A backend is a zero-size token `Backend(profile)` whose methods operate on vectors of
//! `u8`, `u32`, and `u64` lanes. Every backend has the same vector width in bits for its
//! three element types (`u8_lanes == 4 * u32_lanes == 8 * u64_lanes`), and lanes are
//! little-endian. Profiles and widths match commonware's:
//!
//! | profile   | width    | extra instructions                                   |
//! | --------- | -------- | ---------------------------------------------------- |
//! | `scalar`  | 64 bits  | none (portable path)                                 |
//! | `x86_v3`  | 256 bits | none (portable path)                                 |
//! | `x86_v4c` | 512 bits | SHA-NI, ternary logic, GFNI, IFMA52, 128-bit shuffles |
//! | `neon`    | 128 bits | SHA2, carry-less multiply, widening multiply         |
//! | `arm_v9`  | 128 bits | NEON plus SVE2 xor-rotate and bit-clear-and-xor      |
//!
//! Commonware has separate emulated (array) and native (intrinsic) tokens. Zig's `@Vector`
//! is both: the same code lowers to native SIMD instructions when the compile target has
//! them and to scalar code otherwise, so each profile has one implementation here. `dispatch`
//! picks the best profile for the compile target's CPU features at comptime (Zig selects CPU
//! features per build, not per function).
//!
//! An operation is a value with `pub const Output: type`, `portable(self, simd) Output`, and
//! optionally `x86_v4c`, `neon`, and `arm_v9` specializations; `simd.execute(op)` runs the
//! path for the backend's profile (`arm_v9` falls back to `neon`, the rest to `portable`).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

pub const Profile = enum { scalar, x86_v3, x86_v4c, neon, arm_v9 };

fn u64_lanes_of(profile: Profile) comptime_int {
    return switch (profile) {
        .scalar => 1,
        .neon, .arm_v9 => 2,
        .x86_v3 => 4,
        .x86_v4c => 8,
    };
}

const little_endian = builtin.cpu.arch.endian() == .little;

fn rotate_right_vector(comptime T: type, comptime n: u32, value: anytype) @TypeOf(value) {
    const bits = @bitSizeOf(T);
    comptime assert(n < bits);
    if (n == 0) return value;
    const right: @Vector(@typeInfo(@TypeOf(value)).vector.len, std.math.Log2Int(T)) = @splat(n);
    const left: @TypeOf(right) = @splat(bits - n);
    return (value >> right) | (value << left);
}

fn shift_amount(comptime V: type, comptime T: type, comptime n: u32) @Vector(
    @typeInfo(V).vector.len,
    std.math.Log2Int(T),
) {
    comptime assert(n < @bitSizeOf(T));
    return @splat(n);
}

fn mask_vector(
    comptime T: type,
    comptime len: comptime_int,
    condition: @Vector(len, bool),
) @Vector(len, T) {
    const ones: @Vector(len, T) = @splat(std.math.maxInt(T));
    const zeros: @Vector(len, T) = @splat(0);
    return @select(T, condition, ones, zeros);
}

pub fn Backend(comptime profile_value: Profile) type {
    return struct {
        const Self = @This();

        pub const profile = profile_value;
        pub const u64_lanes = u64_lanes_of(profile);
        pub const u32_lanes = 2 * u64_lanes;
        pub const u8_lanes = 8 * u64_lanes;

        pub const U8 = @Vector(u8_lanes, u8);
        pub const U32 = @Vector(u32_lanes, u32);
        pub const U64 = @Vector(u64_lanes, u64);
        pub const U32x4 = @Vector(4, u32);
        /// A 16-entry byte table (the full register on 128-bit profiles).
        pub const U8Table = @Vector(16, u8);
        /// NEON 8 x u16 (carry-less products).
        pub const U16 = @Vector(8, u16);
        /// NEON 2 x u32 (half registers for widening multiplies).
        pub const U32Half = @Vector(2, u32);

        comptime {
            assert(u32_lanes == 2 * u64_lanes and u8_lanes == 4 * u32_lanes);
            assert(u8_lanes <= 64); // u8_movemask fits every lane in a u64.
        }

        /// Run the operation's path for this profile.
        pub fn execute(self: Self, operation: anytype) @TypeOf(operation).Output {
            const O = @TypeOf(operation);
            switch (profile) {
                .scalar, .x86_v3 => return operation.portable(self),
                .x86_v4c => {
                    if (@hasDecl(O, "x86_v4c")) return operation.x86_v4c(self);
                    return operation.portable(self);
                },
                .arm_v9 => {
                    if (@hasDecl(O, "arm_v9")) return operation.arm_v9(self);
                    if (@hasDecl(O, "neon")) return operation.neon(self);
                    return operation.portable(self);
                },
                .neon => {
                    if (@hasDecl(O, "neon")) return operation.neon(self);
                    return operation.portable(self);
                },
            }
        }

        // ---- u32x4 (fixed four-word registers on every profile) ----

        pub fn u32x4_load(_: Self, input: []const u32) U32x4 {
            return input[0..4].*;
        }

        pub fn u32x4_store(_: Self, value: U32x4, output: []u32) void {
            output[0..4].* = value;
        }

        pub fn u32x4_add(_: Self, a: U32x4, b: U32x4) U32x4 {
            return a +% b;
        }

        /// `r[i] = value[(mask >> 2i) & 3]`.
        pub fn u32x4_shuffle(_: Self, comptime mask: u8, value: U32x4) U32x4 {
            const indices: @Vector(4, i32) = .{
                mask & 3, (mask >> 2) & 3, (mask >> 4) & 3, mask >> 6,
            };
            return @shuffle(u32, value, undefined, indices);
        }

        pub fn u32x4_load_be(_: Self, input: []const u8) U32x4 {
            var out: [4]u32 = undefined;
            for (&out, 0..) |*word, i| word.* = std.mem.readInt(u32, input[4 * i ..][0..4], .big);
            return out;
        }

        /// Two big-endian words into the low lanes; the high lanes are zero.
        pub fn u32x4_load_be2(_: Self, input: []const u8) U32x4 {
            return .{
                std.mem.readInt(u32, input[0..4], .big),
                std.mem.readInt(u32, input[4..8], .big),
                0,
                0,
            };
        }

        pub fn u32x4_store_be(_: Self, value: U32x4, output: []u8) void {
            const words: [4]u32 = value;
            for (words, 0..) |word, i| std.mem.writeInt(u32, output[4 * i ..][0..4], word, .big);
        }

        /// The concatenation `a ++ b` shifted down by `n` words (`0 <= n <= 4`).
        pub fn u32x4_align(_: Self, comptime n: u32, a: U32x4, b: U32x4) U32x4 {
            comptime assert(n <= 4);
            const indices: @Vector(4, i32) = comptime blk: {
                var out: [4]i32 = undefined;
                for (&out, 0..) |*o, i| o.* = if (n + i < 4) n + i else ~@as(i32, n + i - 4);
                break :blk out;
            };
            return @shuffle(u32, a, b, indices);
        }

        /// `r[i] = b[i]` where bit i of mask is set, else `a[i]`.
        pub fn u32x4_blend(_: Self, comptime mask: u4, a: U32x4, b: U32x4) U32x4 {
            const select: @Vector(4, bool) = .{
                mask & 1 != 0, mask & 2 != 0, mask & 4 != 0, mask & 8 != 0,
            };
            return @select(u32, select, b, a);
        }

        // ---- u8 ----

        pub fn u8_load(_: Self, input: []const u8) U8 {
            return input[0..u8_lanes].*;
        }

        pub fn u8_store(_: Self, value: U8, output: []u8) void {
            output[0..u8_lanes].* = value;
        }

        pub fn u8_splat(_: Self, value: u8) U8 {
            return @splat(value);
        }

        /// Load up to `u8_lanes` bytes; missing lanes are zero.
        pub fn u8_load_partial(_: Self, input: []const u8) U8 {
            assert(input.len <= u8_lanes);
            var out: [u8_lanes]u8 = @splat(0);
            @memcpy(out[0..input.len], input);
            return out;
        }

        /// Store the first `output.len` lanes (`output.len <= u8_lanes`).
        pub fn u8_store_partial(_: Self, value: U8, output: []u8) void {
            assert(output.len <= u8_lanes);
            const bytes: [u8_lanes]u8 = value;
            @memcpy(output, bytes[0..output.len]);
        }

        pub fn u8_xor(_: Self, a: U8, b: U8) U8 {
            return a ^ b;
        }

        pub fn u8_and(_: Self, a: U8, b: U8) U8 {
            return a & b;
        }

        pub fn u8_or(_: Self, a: U8, b: U8) U8 {
            return a | b;
        }

        pub fn u8_add(_: Self, a: U8, b: U8) U8 {
            return a +% b;
        }

        pub fn u8_sub(_: Self, a: U8, b: U8) U8 {
            return a -% b;
        }

        pub fn u8_add_saturating(_: Self, a: U8, b: U8) U8 {
            return a +| b;
        }

        pub fn u8_sub_saturating(_: Self, a: U8, b: U8) U8 {
            return a -| b;
        }

        pub fn u8_min(_: Self, a: U8, b: U8) U8 {
            return @min(a, b);
        }

        pub fn u8_max(_: Self, a: U8, b: U8) U8 {
            return @max(a, b);
        }

        /// All-ones lanes where equal, zero elsewhere.
        pub fn u8_eq(_: Self, a: U8, b: U8) U8 {
            return mask_vector(u8, u8_lanes, a == b);
        }

        /// All-ones lanes where `a > b` (unsigned), zero elsewhere.
        pub fn u8_gt(_: Self, a: U8, b: U8) U8 {
            return mask_vector(u8, u8_lanes, a > b);
        }

        pub fn u8_table_load(_: Self, table: *const [16]u8) U8Table {
            return table.*;
        }

        /// `r[i] = table[indices[i]]` for indices below 16, else 0.
        pub fn u8_table_lookup(_: Self, table: U8Table, indices: U8) U8 {
            const entries: [16]u8 = table;
            const index_array: [u8_lanes]u8 = indices;
            var out: [u8_lanes]u8 = undefined;
            for (&out, index_array) |*o, index| o.* = if (index < 16) entries[index] else 0;
            return out;
        }

        /// Bit i is the top bit of lane i.
        pub fn u8_movemask(_: Self, value: U8) u64 {
            const bytes: [u8_lanes]u8 = value;
            var mask: u64 = 0;
            for (bytes, 0..) |byte, i| mask |= @as(u64, byte >> 7) << @intCast(i);
            return mask;
        }

        pub fn u8_any(_: Self, value: U8) bool {
            return @reduce(.Or, value != @as(U8, @splat(0)));
        }

        pub fn u8_all(_: Self, value: U8) bool {
            return @reduce(.And, value != @as(U8, @splat(0)));
        }

        fn zip_indices(comptime offset: usize) @Vector(u8_lanes, i32) {
            var out: [u8_lanes]i32 = undefined;
            for (&out, 0..) |*o, i| {
                const j = offset + i;
                o.* = if (j % 2 == 0) @intCast(j / 2) else ~@as(i32, @intCast(j / 2));
            }
            return out;
        }

        fn unzip_indices(comptime parity: usize) @Vector(u8_lanes, i32) {
            var out: [u8_lanes]i32 = undefined;
            for (&out, 0..) |*o, i| {
                const j = 2 * i + parity;
                o.* = if (j < u8_lanes) @intCast(j) else ~@as(i32, @intCast(j - u8_lanes));
            }
            return out;
        }

        /// Interleave the low halves: a0 b0 a1 b1 ...
        pub fn u8_zip_lo(_: Self, a: U8, b: U8) U8 {
            return @shuffle(u8, a, b, zip_indices(0));
        }

        /// Interleave the high halves.
        pub fn u8_zip_hi(_: Self, a: U8, b: U8) U8 {
            return @shuffle(u8, a, b, zip_indices(u8_lanes));
        }

        /// Even lanes of `a ++ b`.
        pub fn u8_unzip_even(_: Self, a: U8, b: U8) U8 {
            return @shuffle(u8, a, b, unzip_indices(0));
        }

        /// Odd lanes of `a ++ b`.
        pub fn u8_unzip_odd(_: Self, a: U8, b: U8) U8 {
            return @shuffle(u8, a, b, unzip_indices(1));
        }

        pub fn u8_shl(_: Self, comptime n: u32, value: U8) U8 {
            return value << shift_amount(U8, u8, n);
        }

        pub fn u8_shr(_: Self, comptime n: u32, value: U8) U8 {
            return value >> shift_amount(U8, u8, n);
        }

        pub fn u8_xor_fold(_: Self, value: U8) u8 {
            return @reduce(.Xor, value);
        }

        // ---- u32 ----

        pub fn u32_load(_: Self, input: []const u32) U32 {
            return input[0..u32_lanes].*;
        }

        pub fn u32_store(_: Self, value: U32, output: []u32) void {
            output[0..u32_lanes].* = value;
        }

        pub fn u32_splat(_: Self, value: u32) U32 {
            return @splat(value);
        }

        pub fn u32_xor(_: Self, a: U32, b: U32) U32 {
            return a ^ b;
        }

        pub fn u32_add(_: Self, a: U32, b: U32) U32 {
            return a +% b;
        }

        pub fn u32_sub(_: Self, a: U32, b: U32) U32 {
            return a -% b;
        }

        pub fn u32_and(_: Self, a: U32, b: U32) U32 {
            return a & b;
        }

        pub fn u32_or(_: Self, a: U32, b: U32) U32 {
            return a | b;
        }

        pub fn u32_rotate_right(_: Self, comptime n: u32, value: U32) U32 {
            return rotate_right_vector(u32, n, value);
        }

        pub fn u32_shl(_: Self, comptime n: u32, value: U32) U32 {
            return value << shift_amount(U32, u32, n);
        }

        pub fn u32_shr(_: Self, comptime n: u32, value: U32) U32 {
            return value >> shift_amount(U32, u32, n);
        }

        /// Bitwise `(mask & a) | (~mask & b)`.
        pub fn u32_select(_: Self, mask: U32, a: U32, b: U32) U32 {
            return (mask & a) | (~mask & b);
        }

        /// `r[i] = value[indices[i] mod u32_lanes]`.
        pub fn u32_permute(_: Self, value: U32, indices: U32) U32 {
            const values: [u32_lanes]u32 = value;
            const index_array: [u32_lanes]u32 = indices;
            var out: [u32_lanes]u32 = undefined;
            for (&out, index_array) |*o, index| o.* = values[index % u32_lanes];
            return out;
        }

        /// `r[i] = (a ++ b)[indices[i] mod 2 u32_lanes]`.
        pub fn u32_permute2(_: Self, a: U32, b: U32, indices: U32) U32 {
            const both: [2 * u32_lanes]u32 = @as([u32_lanes]u32, a) ++ @as([u32_lanes]u32, b);
            const index_array: [u32_lanes]u32 = indices;
            var out: [u32_lanes]u32 = undefined;
            for (&out, index_array) |*o, index| o.* = both[index % (2 * u32_lanes)];
            return out;
        }

        // ---- u64 ----

        pub fn u64_load(_: Self, input: []const u64) U64 {
            return input[0..u64_lanes].*;
        }

        pub fn u64_store(_: Self, value: U64, output: []u64) void {
            output[0..u64_lanes].* = value;
        }

        pub fn u64_splat(_: Self, value: u64) U64 {
            return @splat(value);
        }

        pub fn u64_add(_: Self, a: U64, b: U64) U64 {
            return a +% b;
        }

        pub fn u64_sub(_: Self, a: U64, b: U64) U64 {
            return a -% b;
        }

        pub fn u64_and(_: Self, a: U64, b: U64) U64 {
            return a & b;
        }

        pub fn u64_or(_: Self, a: U64, b: U64) U64 {
            return a | b;
        }

        pub fn u64_xor(_: Self, a: U64, b: U64) U64 {
            return a ^ b;
        }

        pub fn u64_shl(_: Self, comptime n: u32, value: U64) U64 {
            return value << shift_amount(U64, u64, n);
        }

        pub fn u64_shr(_: Self, comptime n: u32, value: U64) U64 {
            return value >> shift_amount(U64, u64, n);
        }

        pub fn u64_rotate_left(_: Self, comptime n: u32, value: U64) U64 {
            comptime assert(n < 64);
            return rotate_right_vector(u64, (64 - n) % 64, value);
        }

        pub fn u64_rotate_right(_: Self, comptime n: u32, value: U64) U64 {
            return rotate_right_vector(u64, n, value);
        }

        /// `a & ~b`.
        pub fn u64_andnot(_: Self, a: U64, b: U64) U64 {
            return a & ~b;
        }

        pub fn u64_xor3(_: Self, a: U64, b: U64, c: U64) U64 {
            return a ^ b ^ c;
        }

        pub fn u64_select(_: Self, mask: U64, a: U64, b: U64) U64 {
            return (mask & a) | (~mask & b);
        }

        pub fn u64_extract(_: Self, comptime n: usize, value: U64) u64 {
            comptime assert(n < u64_lanes);
            return value[n];
        }

        pub fn u64_insert(_: Self, comptime n: usize, value: U64, lane: u64) U64 {
            comptime assert(n < u64_lanes);
            var out = value;
            out[n] = lane;
            return out;
        }

        // ---- casts (bit relabeling, little-endian lanes) ----

        fn cast(comptime To: type, value: anytype) To {
            // Lanes are little-endian on every backend; a bit cast relabels them only on
            // little-endian targets, which is every target zigware supports.
            comptime assert(little_endian);
            comptime assert(@bitSizeOf(To) == @bitSizeOf(@TypeOf(value)));
            return @bitCast(value);
        }

        pub fn u8_as_u32(_: Self, value: U8) U32 {
            return cast(U32, value);
        }

        pub fn u32_as_u8(_: Self, value: U32) U8 {
            return cast(U8, value);
        }

        pub fn u8_as_u64(_: Self, value: U8) U64 {
            return cast(U64, value);
        }

        pub fn u64_as_u8(_: Self, value: U64) U8 {
            return cast(U8, value);
        }

        pub fn u32_as_u64(_: Self, value: U32) U64 {
            return cast(U64, value);
        }

        pub fn u64_as_u32(_: Self, value: U64) U32 {
            return cast(U32, value);
        }

        // ---- profile-specific instructions ----

        // Each set exists only on the profiles that have it; elsewhere its names are `void`,
        // so using one is a compile error.
        const x86 = if (profile == .x86_v4c) x86_v4c_instructions(Self) else unavailable;
        const neon_set = if (profile == .neon or profile == .arm_v9)
            neon_instructions(Self)
        else
            unavailable;
        const arm = if (profile == .arm_v9) arm_v9_instructions(Self) else unavailable;

        // x86v4c (AVX-512, SHA-NI, GFNI, IFMA).
        pub const u32_load_be = x86.u32_load_be;
        pub const sha256_rounds2 = x86.sha256_rounds2;
        pub const sha256_msg1 = x86.sha256_msg1;
        pub const sha256_msg2 = x86.sha256_msg2;
        pub const u32_ternary = x86.u32_ternary;
        pub const u64_ternary = x86.u64_ternary;
        pub const u8_shuffle128 = x86.u8_shuffle128;
        pub const u32_shuffle_groups = x86.u32_shuffle_groups;
        pub const u32_unpackhi64 = x86.u32_unpackhi64;
        pub const u32_shuffle128 = x86.u32_shuffle128;
        pub const u32_shuffle2_128 = x86.u32_shuffle2_128;
        pub const u32_blend128 = x86.u32_blend128;
        pub const u32_unpacklo32 = x86.u32_unpacklo32;
        pub const u32_unpackhi32 = x86.u32_unpackhi32;
        pub const u32_unpacklo64 = x86.u32_unpacklo64;
        pub const u8_gf_mul = x86.u8_gf_mul;
        pub const u64_madd52lo = x86.u64_madd52lo;
        pub const u64_madd52hi = x86.u64_madd52hi;

        // NEON (and Armv9).
        pub const sha256_h = neon_set.sha256_h;
        pub const sha256_h2 = neon_set.sha256_h2;
        pub const sha256_su0 = neon_set.sha256_su0;
        pub const sha256_su1 = neon_set.sha256_su1;
        pub const u8_table = neon_set.u8_table;
        pub const u8_clmul_lo = neon_set.u8_clmul_lo;
        pub const u8_clmul_hi = neon_set.u8_clmul_hi;
        pub const u16_xor = neon_set.u16_xor;
        pub const u16_shl = neon_set.u16_shl;
        pub const u16_shr = neon_set.u16_shr;
        pub const u16_narrow_pair = neon_set.u16_narrow_pair;
        pub const u64_narrow = neon_set.u64_narrow;
        pub const u32_half_splat = neon_set.u32_half_splat;
        pub const u32_half_add = neon_set.u32_half_add;
        pub const u32_half_shl = neon_set.u32_half_shl;
        pub const u32_widen_mul = neon_set.u32_widen_mul;
        pub const u32_widen_madd = neon_set.u32_widen_madd;

        // Armv9 (SVE2).
        pub const u32_xor_rotate_right = arm.u32_xor_rotate_right;
        pub const u64_xor_rotate_right = arm.u64_xor_rotate_right;
        pub const u64_bcax = arm.u64_bcax;
    };
}

const unavailable = struct {
    const u32_load_be = {};
    const sha256_rounds2 = {};
    const sha256_msg1 = {};
    const sha256_msg2 = {};
    const u32_ternary = {};
    const u64_ternary = {};
    const u8_shuffle128 = {};
    const u32_shuffle_groups = {};
    const u32_unpackhi64 = {};
    const u32_shuffle128 = {};
    const u32_shuffle2_128 = {};
    const u32_blend128 = {};
    const u32_unpacklo32 = {};
    const u32_unpackhi32 = {};
    const u32_unpacklo64 = {};
    const u8_gf_mul = {};
    const u64_madd52lo = {};
    const u64_madd52hi = {};
    const sha256_h = {};
    const sha256_h2 = {};
    const sha256_su0 = {};
    const sha256_su1 = {};
    const u8_table = {};
    const u8_clmul_lo = {};
    const u8_clmul_hi = {};
    const u16_xor = {};
    const u16_shl = {};
    const u16_shr = {};
    const u16_narrow_pair = {};
    const u64_narrow = {};
    const u32_half_splat = {};
    const u32_half_add = {};
    const u32_half_shl = {};
    const u32_widen_mul = {};
    const u32_widen_madd = {};
    const u32_xor_rotate_right = {};
    const u64_xor_rotate_right = {};
    const u64_bcax = {};
};

fn sigma0(x: u32) u32 {
    return std.math.rotr(u32, x, 7) ^ std.math.rotr(u32, x, 18) ^ (x >> 3);
}

fn sigma1(x: u32) u32 {
    return std.math.rotr(u32, x, 17) ^ std.math.rotr(u32, x, 19) ^ (x >> 10);
}

/// One SHA-256 round on state (a, b, c, d, e, f, g, h) with message word plus constant `wk`.
fn sha256_round(state: *[8]u32, wk: u32) void {
    const a = state[0];
    const e = state[4];
    const sum1 = std.math.rotr(u32, e, 6) ^ std.math.rotr(u32, e, 11) ^ std.math.rotr(u32, e, 25);
    const choice = (e & state[5]) ^ (~e & state[6]);
    const t1 = state[7] +% sum1 +% choice +% wk;
    const sum0 = std.math.rotr(u32, a, 2) ^ std.math.rotr(u32, a, 13) ^ std.math.rotr(u32, a, 22);
    const majority = (a & state[1]) ^ (a & state[2]) ^ (state[1] & state[2]);
    // Build the next state in a temporary: assigning the literal in place would read lanes
    // it already overwrote.
    const next: [8]u32 = .{
        t1 +% sum0 +% majority, a, state[1], state[2],
        state[3] +% t1,         e, state[5], state[6],
    };
    state.* = next;
}

/// Bitwise truth table: bit `(a << 2) | (b << 1) | c` of `mask` gives each result bit.
fn ternary(comptime V: type, comptime mask: u8, a: V, b: V, c: V) V {
    var out: V = @splat(0);
    inline for (0..8) |index| {
        if ((mask >> index) & 1 == 1) {
            const term_a = if (index & 4 != 0) a else ~a;
            const term_b = if (index & 2 != 0) b else ~b;
            const term_c = if (index & 1 != 0) c else ~c;
            out |= term_a & term_b & term_c;
        }
    }
    return out;
}

/// The x86v4c instructions (AVX-512, SHA-NI, GFNI, AVX-512IFMA) for backend `S`.
fn x86_v4c_instructions(comptime S: type) type {
    return struct {
        /// Sixteen big-endian words from `input[0..64]`.
        fn u32_load_be(_: S, input: []const u8) S.U32 {
            assert(input.len >= 64);
            var out: [S.u32_lanes]u32 = undefined;
            for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, input[4 * i ..][0..4], .big);
            return out;
        }

        /// Two rounds (SHA256RNDS2): `a` holds (c, d, g, h) as [h, g, d, c] lanes reversed,
        /// `b` holds [f, e, b, a]; uses `k[0]` and `k[1]`.
        fn sha256_rounds2(_: S, a: S.U32x4, b: S.U32x4, k: S.U32x4) S.U32x4 {
            var state: [8]u32 = .{ b[3], b[2], a[3], a[2], b[1], b[0], a[1], a[0] };
            const k_words: [4]u32 = k;
            sha256_round(&state, k_words[0]);
            sha256_round(&state, k_words[1]);
            return .{ state[5], state[4], state[1], state[0] };
        }

        fn sha256_msg1(_: S, a_vector: S.U32x4, b_vector: S.U32x4) S.U32x4 {
            const a: [4]u32 = a_vector;
            const b: [4]u32 = b_vector;
            const next: [4]u32 = .{ a[1], a[2], a[3], b[0] };
            var out: [4]u32 = undefined;
            for (&out, 0..) |*o, i| o.* = a[i] +% sigma0(next[i]);
            return out;
        }

        fn sha256_msg2(_: S, a_vector: S.U32x4, b_vector: S.U32x4) S.U32x4 {
            const a: [4]u32 = a_vector;
            const b: [4]u32 = b_vector;
            var r: [4]u32 = undefined;
            for (0..4) |i| {
                const x = if (i < 2) b[i + 2] else r[i - 2];
                r[i] = a[i] +% sigma1(x);
            }
            return r;
        }

        fn u32_ternary(_: S, comptime mask: u8, a: S.U32, b: S.U32, c: S.U32) S.U32 {
            return ternary(S.U32, mask, a, b, c);
        }

        fn u64_ternary(_: S, comptime mask: u8, a: S.U64, b: S.U64, c: S.U64) S.U64 {
            return ternary(S.U64, mask, a, b, c);
        }

        /// Byte shuffle within each 128-bit group; index bit 7 zeroes the lane.
        fn u8_shuffle128(_: S, value: S.U8, indices: S.U8) S.U8 {
            const bytes: [S.u8_lanes]u8 = value;
            const index_array: [S.u8_lanes]u8 = indices;
            var out: [S.u8_lanes]u8 = undefined;
            for (&out, index_array, 0..) |*o, index, i| {
                o.* = if (index & 0x80 != 0) 0 else bytes[i / 16 * 16 + (index & 15)];
            }
            return out;
        }

        /// 128-bit groups: lanes 0..8 from `a`, 8..16 from `b`, group chosen by mask bits.
        fn u32_shuffle_groups(_: S, comptime mask: u8, a: S.U32, b: S.U32) S.U32 {
            const indices = comptime blk: {
                var out: [16]i32 = undefined;
                for (&out, 0..) |*o, i| {
                    const group = (mask >> (2 * (i / 4))) & 3;
                    const source = group * 4 + i % 4;
                    o.* = if (i < 8) source else ~@as(i32, source);
                }
                break :blk out;
            };
            return @shuffle(u32, a, b, @as(@Vector(16, i32), indices));
        }

        fn per_group(comptime pattern: [4]struct { bool, u32 }) @Vector(16, i32) {
            var out: [16]i32 = undefined;
            for (&out, 0..) |*o, i| {
                const source: i32 = @intCast(i / 4 * 4 + pattern[i % 4][1]);
                o.* = if (pattern[i % 4][0]) ~source else source;
            }
            return out;
        }

        fn u32_unpacklo32(_: S, a: S.U32, b: S.U32) S.U32 {
            const pattern = .{ .{ false, 0 }, .{ true, 0 }, .{ false, 1 }, .{ true, 1 } };
            return @shuffle(u32, a, b, per_group(pattern));
        }

        fn u32_unpackhi32(_: S, a: S.U32, b: S.U32) S.U32 {
            const pattern = .{ .{ false, 2 }, .{ true, 2 }, .{ false, 3 }, .{ true, 3 } };
            return @shuffle(u32, a, b, per_group(pattern));
        }

        fn u32_unpacklo64(_: S, a: S.U32, b: S.U32) S.U32 {
            const pattern = .{ .{ false, 0 }, .{ false, 1 }, .{ true, 0 }, .{ true, 1 } };
            return @shuffle(u32, a, b, per_group(pattern));
        }

        fn u32_unpackhi64(_: S, a: S.U32, b: S.U32) S.U32 {
            const pattern = .{ .{ false, 2 }, .{ false, 3 }, .{ true, 2 }, .{ true, 3 } };
            return @shuffle(u32, a, b, per_group(pattern));
        }

        /// Shuffle words within each 128-bit group by 2-bit selectors.
        fn u32_shuffle128(_: S, comptime mask: u8, value: S.U32) S.U32 {
            const indices = comptime blk: {
                var out: [16]i32 = undefined;
                for (&out, 0..) |*o, i| o.* = i / 4 * 4 + ((mask >> (2 * (i % 4))) & 3);
                break :blk out;
            };
            return @shuffle(u32, value, undefined, @as(@Vector(16, i32), indices));
        }

        /// Like `u32_shuffle128`, with the low two lanes of each group from `a`, the high
        /// two from `b`.
        fn u32_shuffle2_128(_: S, comptime mask: u8, a: S.U32, b: S.U32) S.U32 {
            const indices = comptime blk: {
                var out: [16]i32 = undefined;
                for (&out, 0..) |*o, i| {
                    const source: i32 = i / 4 * 4 + ((mask >> (2 * (i % 4))) & 3);
                    o.* = if (i % 4 < 2) source else ~source;
                }
                break :blk out;
            };
            return @shuffle(u32, a, b, @as(@Vector(16, i32), indices));
        }

        fn u32_blend128(_: S, comptime mask: u4, a: S.U32, b: S.U32) S.U32 {
            const select = comptime blk: {
                var out: [16]bool = undefined;
                for (&out, 0..) |*o, i| o.* = (mask >> (i % 4)) & 1 == 1;
                break :blk out;
            };
            return @select(u32, @as(@Vector(16, bool), select), b, a);
        }

        /// GF(2^8) multiply modulo x^8 + x^4 + x^3 + x + 1 (GF2P8MULB).
        fn u8_gf_mul(_: S, a: S.U8, b: S.U8) S.U8 {
            var x = a;
            var y = b;
            var product: S.U8 = @splat(0);
            const zero: S.U8 = @splat(0);
            const one: S.U8 = @splat(1);
            for (0..8) |_| {
                product ^= @select(u8, (y & one) != zero, x, zero);
                const carry = (x >> @splat(7)) != zero;
                x = (x << @splat(1)) ^ @select(u8, carry, @as(S.U8, @splat(0x1b)), zero);
                y >>= @splat(1);
            }
            return product;
        }

        const mask52: u64 = (1 << 52) - 1;

        /// `acc + low52(low52(a) * low52(b))` (VPMADD52LUQ).
        fn u64_madd52lo(_: S, acc_vector: S.U64, a_vector: S.U64, b_vector: S.U64) S.U64 {
            const acc: [S.u64_lanes]u64 = acc_vector;
            const a: [S.u64_lanes]u64 = a_vector;
            const b: [S.u64_lanes]u64 = b_vector;
            var out: [S.u64_lanes]u64 = undefined;
            for (&out, 0..) |*o, i| {
                const product = @as(u128, a[i] & mask52) * (b[i] & mask52);
                o.* = acc[i] +% (@as(u64, @truncate(product)) & mask52);
            }
            return out;
        }

        /// `acc + high52(low52(a) * low52(b))` (VPMADD52HUQ).
        fn u64_madd52hi(_: S, acc_vector: S.U64, a_vector: S.U64, b_vector: S.U64) S.U64 {
            const acc: [S.u64_lanes]u64 = acc_vector;
            const a: [S.u64_lanes]u64 = a_vector;
            const b: [S.u64_lanes]u64 = b_vector;
            var out: [S.u64_lanes]u64 = undefined;
            for (&out, 0..) |*o, i| {
                const product = @as(u128, a[i] & mask52) * (b[i] & mask52);
                o.* = acc[i] +% @as(u64, @truncate(product >> 52));
            }
            return out;
        }
    };
}

/// The NEON (AArch64 NEON + SHA2) instructions for backend `S` (128-bit profiles).
fn neon_instructions(comptime S: type) type {
    comptime assert(S.u8_lanes == 16);
    return struct {
        fn rounds(abcd: S.U32x4, efgh: S.U32x4, wk: S.U32x4) [8]u32 {
            var state: [8]u32 = @as([4]u32, abcd) ++ @as([4]u32, efgh);
            const words: [4]u32 = wk;
            for (words) |word| sha256_round(&state, word);
            return state;
        }

        /// Four rounds, returning the new (a, b, c, d) (SHA256H).
        fn sha256_h(_: S, abcd: S.U32x4, efgh: S.U32x4, wk: S.U32x4) S.U32x4 {
            const state = rounds(abcd, efgh, wk);
            return state[0..4].*;
        }

        /// Four rounds, returning the new (e, f, g, h) (SHA256H2).
        fn sha256_h2(_: S, efgh: S.U32x4, abcd: S.U32x4, wk: S.U32x4) S.U32x4 {
            const state = rounds(abcd, efgh, wk);
            return state[4..8].*;
        }

        fn sha256_su0(_: S, a_vector: S.U32x4, b_vector: S.U32x4) S.U32x4 {
            const a: [4]u32 = a_vector;
            const b: [4]u32 = b_vector;
            const next: [4]u32 = .{ a[1], a[2], a[3], b[0] };
            var out: [4]u32 = undefined;
            for (&out, 0..) |*o, i| o.* = a[i] +% sigma0(next[i]);
            return out;
        }

        fn sha256_su1(_: S, a_vector: S.U32x4, b_vector: S.U32x4, c_vector: S.U32x4) S.U32x4 {
            const a: [4]u32 = a_vector;
            const b: [4]u32 = b_vector;
            const c: [4]u32 = c_vector;
            const next: [4]u32 = .{ b[1], b[2], b[3], c[0] };
            var r: [4]u32 = undefined;
            for (0..4) |i| {
                const previous = if (i < 2) c[i + 2] else r[i - 2];
                r[i] = a[i] +% next[i] +% sigma1(previous);
            }
            return r;
        }

        fn u8_table(_: S, table: S.U8) S.U8Table {
            return table;
        }

        fn clmul(x: u8, y: u8) u16 {
            var product: u16 = 0;
            for (0..8) |bit| {
                if (y & (@as(u8, 1) << @intCast(bit)) != 0) product ^= @as(u16, x) << @intCast(bit);
            }
            return product;
        }

        /// Carry-less products of the low eight byte lanes (PMULL).
        fn u8_clmul_lo(_: S, a_vector: S.U8, b_vector: S.U8) S.U16 {
            const a: [16]u8 = a_vector;
            const b: [16]u8 = b_vector;
            var out: [8]u16 = undefined;
            for (&out, 0..) |*o, i| o.* = clmul(a[i], b[i]);
            return out;
        }

        /// Carry-less products of the high eight byte lanes (PMULL2).
        fn u8_clmul_hi(_: S, a_vector: S.U8, b_vector: S.U8) S.U16 {
            const a: [16]u8 = a_vector;
            const b: [16]u8 = b_vector;
            var out: [8]u16 = undefined;
            for (&out, 0..) |*o, i| o.* = clmul(a[i + 8], b[i + 8]);
            return out;
        }

        fn u16_xor(_: S, a: S.U16, b: S.U16) S.U16 {
            return a ^ b;
        }

        fn u16_shl(_: S, comptime n: u32, value: S.U16) S.U16 {
            return value << shift_amount(S.U16, u16, n);
        }

        fn u16_shr(_: S, comptime n: u32, value: S.U16) S.U16 {
            return value >> shift_amount(S.U16, u16, n);
        }

        /// Truncate `low` into lanes 0..8 and `high` into lanes 8..16.
        fn u16_narrow_pair(_: S, low: S.U16, high: S.U16) S.U8 {
            const l: @Vector(8, u8) = @truncate(low);
            const h: @Vector(8, u8) = @truncate(high);
            return @as([8]u8, l) ++ @as([8]u8, h);
        }

        fn u64_narrow(_: S, value: S.U64) S.U32Half {
            return @truncate(value);
        }

        fn u32_half_splat(_: S, value: u32) S.U32Half {
            return @splat(value);
        }

        fn u32_half_add(_: S, a: S.U32Half, b: S.U32Half) S.U32Half {
            return a +% b;
        }

        fn u32_half_shl(_: S, comptime n: u32, value: S.U32Half) S.U32Half {
            return value << shift_amount(S.U32Half, u32, n);
        }

        fn u32_widen_mul(_: S, a: S.U32Half, b: S.U32Half) S.U64 {
            return @as(S.U64, a) * @as(S.U64, b);
        }

        fn u32_widen_madd(_: S, acc: S.U64, a: S.U32Half, b: S.U32Half) S.U64 {
            return acc +% @as(S.U64, a) * @as(S.U64, b);
        }
    };
}

/// The Armv9 (SVE2) instructions for backend `S`.
fn arm_v9_instructions(comptime S: type) type {
    return struct {
        fn u32_xor_rotate_right(_: S, comptime n: u32, a: S.U32, b: S.U32) S.U32 {
            return rotate_right_vector(u32, n, a ^ b);
        }

        fn u64_xor_rotate_right(_: S, comptime n: u32, a: S.U64, b: S.U64) S.U64 {
            return rotate_right_vector(u64, n, a ^ b);
        }

        /// `a ^ (b & ~c)` (BCAX).
        fn u64_bcax(_: S, a: S.U64, b: S.U64, c: S.U64) S.U64 {
            return a ^ (b & ~c);
        }
    };
}

pub const EmulatedScalar = Backend(.scalar);
pub const EmulatedX86V3 = Backend(.x86_v3);
pub const EmulatedX86V4C = Backend(.x86_v4c);
pub const EmulatedNeon = Backend(.neon);
pub const EmulatedArmV9 = Backend(.arm_v9);

/// The best profile for the compile target's CPU features.
pub const native_profile: Profile = blk: {
    const features = builtin.cpu.features;
    switch (builtin.cpu.arch) {
        .x86_64 => {
            const x86 = std.Target.x86;
            const v4c = x86.featureSetHasAll(features, .{
                .avx512f, .avx512bw, .gfni, .avx512ifma, .sha,
            });
            if (v4c) break :blk .x86_v4c;
            if (x86.featureSetHas(features, .avx2)) break :blk .x86_v3;
            break :blk .scalar;
        },
        .aarch64, .aarch64_be => {
            const arm = std.Target.aarch64;
            if (!arm.featureSetHas(features, .neon)) break :blk .scalar;
            if (arm.featureSetHasAll(features, .{ .sve, .sve2 })) break :blk .arm_v9;
            break :blk .neon;
        },
        else => break :blk .scalar,
    }
};

pub const Native = Backend(native_profile);

/// Execute with the best backend for the compile target.
pub fn dispatch(operation: anytype) @TypeOf(operation).Output {
    const simd: Native = .{};
    return simd.execute(operation);
}

/// Execute with the portable scalar backend on any host, so consumer tests agree everywhere.
pub fn test_dispatch(operation: anytype) @TypeOf(operation).Output {
    const simd: EmulatedScalar = .{};
    return simd.execute(operation);
}

/// Check an operation agrees on every profile. `factory.make()` builds a fresh, equivalent
/// operation for each run; outputs compare with `std.meta.eql`.
pub fn check_consistent(factory: anytype) !void {
    const expected = (EmulatedScalar{}).execute(factory.make());
    inline for (.{ EmulatedX86V3, EmulatedX86V4C, EmulatedArmV9, EmulatedNeon }) |B| {
        const actual = (B{}).execute(factory.make());
        if (!std.meta.eql(actual, expected)) {
            std.debug.print("simd: {s} differs from scalar\n", .{@tagName(B.profile)});
            return error.Inconsistent;
        }
    }
}
