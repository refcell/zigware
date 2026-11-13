//! simd tests: instruction contracts against scalar oracles on every profile, operation path
//! selection, consistency across profiles, SHA-256 rounds against `std.crypto`, and a seeded
//! plus coverage-guided differential fuzz (commonware simd tests, emulated test_utils, and
//! simd/fuzz).

const std = @import("std");
const build_options = @import("build_options");
const testing = std.testing;
const core = @import("core.zig");

const all_backends = .{
    core.EmulatedScalar,
    core.EmulatedX86V3,
    core.EmulatedX86V4C,
    core.EmulatedNeon,
    core.EmulatedArmV9,
};

/// Bytes for differential checks, zero-filled past the end like `arbitrary`.
const Source = struct {
    data: []const u8,
    position: usize = 0,

    fn fill(self: *Source, out: []u8) void {
        const take = @min(out.len, self.data.len - self.position);
        @memcpy(out[0..take], self.data[self.position..][0..take]);
        @memset(out[take..], 0);
        self.position += take;
    }

    fn array(self: *Source, comptime T: type, comptime n: usize) [n]T {
        var out: [n]T = undefined;
        self.fill(std.mem.sliceAsBytes(&out));
        return out;
    }
};

fn rotr(comptime T: type, x: T, n: u32) T {
    return std.math.rotr(T, x, n);
}

/// Every common instruction against a lane-by-lane oracle, on inputs from `source`.
fn check_common(comptime B: type, source: *Source) !void {
    const simd: B = .{};
    const a8 = source.array(u8, B.u8_lanes);
    const b8 = source.array(u8, B.u8_lanes);
    const av: B.U8 = a8;
    const bv: B.U8 = b8;
    const sum: [B.u8_lanes]u8 = simd.u8_add(av, bv);
    const sat: [B.u8_lanes]u8 = simd.u8_sub_saturating(av, bv);
    const gt: [B.u8_lanes]u8 = simd.u8_gt(av, bv);
    const eq: [B.u8_lanes]u8 = simd.u8_eq(av, av);
    var fold: u8 = 0;
    var movemask: u64 = 0;
    for (0..B.u8_lanes) |i| {
        try testing.expectEqual(a8[i] +% b8[i], sum[i]);
        try testing.expectEqual(a8[i] -| b8[i], sat[i]);
        try testing.expectEqual(@as(u8, if (a8[i] > b8[i]) 0xff else 0), gt[i]);
        try testing.expectEqual(@as(u8, 0xff), eq[i]);
        fold ^= a8[i];
        movemask |= @as(u64, a8[i] >> 7) << @intCast(i);
    }
    try testing.expectEqual(fold, simd.u8_xor_fold(av));
    try testing.expectEqual(movemask, simd.u8_movemask(av));
    try check_zips(B, a8, b8);
    try check_words(B, source);
    try check_longs(B, source);
}

fn check_zips(comptime B: type, a8: [B.u8_lanes]u8, b8: [B.u8_lanes]u8) !void {
    const simd: B = .{};
    const n = B.u8_lanes;
    const lo: [n]u8 = simd.u8_zip_lo(a8, b8);
    const hi: [n]u8 = simd.u8_zip_hi(a8, b8);
    const even: [n]u8 = simd.u8_unzip_even(a8, b8);
    const odd: [n]u8 = simd.u8_unzip_odd(a8, b8);
    const both = a8 ++ b8;
    for (0..n) |i| {
        try testing.expectEqual(if (i % 2 == 0) a8[i / 2] else b8[i / 2], lo[i]);
        const j = n + i;
        try testing.expectEqual(if (j % 2 == 0) a8[j / 2] else b8[j / 2], hi[i]);
        try testing.expectEqual(both[2 * i], even[i]);
        try testing.expectEqual(both[2 * i + 1], odd[i]);
    }
    var table: [16]u8 = undefined;
    for (&table, 0..) |*t, i| t.* = @intCast(i * 7 + 1);
    const looked: [n]u8 = simd.u8_table_lookup(simd.u8_table_load(&table), a8);
    for (a8, looked) |index, value| {
        try testing.expectEqual(if (index < 16) table[index] else 0, value);
    }
}

fn check_words(comptime B: type, source: *Source) !void {
    const simd: B = .{};
    const n = B.u32_lanes;
    const a = source.array(u32, n);
    const b = source.array(u32, n);
    const indices = source.array(u32, n);
    const rotated: [n]u32 = simd.u32_rotate_right(13, a);
    const shifted: [n]u32 = simd.u32_shl(5, a);
    const selected: [n]u32 = simd.u32_select(indices, a, b);
    const permuted: [n]u32 = simd.u32_permute(a, indices);
    const permuted2: [n]u32 = simd.u32_permute2(a, b, indices);
    const both = a ++ b;
    for (0..n) |i| {
        try testing.expectEqual(rotr(u32, a[i], 13), rotated[i]);
        try testing.expectEqual(a[i] << 5, shifted[i]);
        try testing.expectEqual((indices[i] & a[i]) | (~indices[i] & b[i]), selected[i]);
        try testing.expectEqual(a[indices[i] % n], permuted[i]);
        try testing.expectEqual(both[indices[i] % (2 * n)], permuted2[i]);
    }
    // Casts relabel little-endian lanes.
    const bytes: [4 * n]u8 = simd.u32_as_u8(a);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(&a), &bytes);
    const back: [n]u32 = simd.u8_as_u32(bytes);
    try testing.expectEqualSlices(u32, &a, &back);
}

fn check_longs(comptime B: type, source: *Source) !void {
    const simd: B = .{};
    const n = B.u64_lanes;
    const a = source.array(u64, n);
    const b = source.array(u64, n);
    const c = source.array(u64, n);
    const left: [n]u64 = simd.u64_rotate_left(17, a);
    const right: [n]u64 = simd.u64_rotate_right(1, a);
    const andnot: [n]u64 = simd.u64_andnot(a, b);
    const xor3: [n]u64 = simd.u64_xor3(a, b, c);
    const difference: [n]u64 = simd.u64_sub(a, b);
    for (0..n) |i| {
        try testing.expectEqual(std.math.rotl(u64, a[i], 17), left[i]);
        try testing.expectEqual(rotr(u64, a[i], 1), right[i]);
        try testing.expectEqual(a[i] & ~b[i], andnot[i]);
        try testing.expectEqual(a[i] ^ b[i] ^ c[i], xor3[i]);
        try testing.expectEqual(a[i] -% b[i], difference[i]);
    }
    try testing.expectEqual(a[0], simd.u64_extract(0, a));
    const inserted: [n]u64 = simd.u64_insert(n - 1, a, 7);
    try testing.expectEqual(@as(u64, 7), inserted[n - 1]);
    const halves: [2 * n]u32 = simd.u64_as_u32(a);
    for (0..n) |i| {
        try testing.expectEqual(@as(u32, @truncate(a[i])), halves[2 * i]);
        try testing.expectEqual(@as(u32, @truncate(a[i] >> 32)), halves[2 * i + 1]);
    }
}

fn differential(_: void, data: []const u8) !void {
    inline for (all_backends) |B| {
        var source: Source = .{ .data = data };
        try check_common(B, &source);
    }
}

test "common instructions match lane oracles (seeded)" {
    var prng = std.Random.DefaultPrng.init(0x51d ^ build_options.fuzz_seed);
    var buffer: [1024]u8 = undefined;
    for (0..200 * @as(u64, build_options.fuzz_soak)) |_| {
        const size = prng.random().uintAtMost(usize, buffer.len);
        prng.random().bytes(buffer[0..size]);
        try differential({}, buffer[0..size]);
    }
}

test "common instructions match lane oracles (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buffer: [1024]u8 = undefined;
            const size = smith.slice(&buffer);
            try differential({}, buffer[0..size]);
        }
    }.one, .{});
}

test "partial loads and stores" {
    inline for (all_backends) |B| {
        const simd: B = .{};
        var a: [B.u8_lanes]u8 = undefined;
        for (&a, 0..) |*x, i| x.* = @truncate(i *% 73 +% 0x81);
        for (0..B.u8_lanes + 1) |len| {
            const loaded: [B.u8_lanes]u8 = simd.u8_load_partial(a[0..len]);
            try testing.expectEqualSlices(u8, a[0..len], loaded[0..len]);
            for (loaded[len..]) |x| try testing.expectEqual(@as(u8, 0), x);
            var out: [B.u8_lanes + 2]u8 = @splat(0xa5);
            simd.u8_store_partial(a, out[1 .. len + 1]);
            try testing.expectEqualSlices(u8, a[0..len], out[1 .. len + 1]);
            try testing.expectEqual(@as(u8, 0xa5), out[0]);
            for (out[len + 1 ..]) |x| try testing.expectEqual(@as(u8, 0xa5), x);
        }
    }
}

test "u32x4 register instructions" {
    const simd: core.EmulatedScalar = .{};
    const a: [4]u32 = .{ 10, 11, 12, 13 };
    const b: [4]u32 = .{ 20, 21, 22, 23 };
    const shuffled: [4]u32 = simd.u32x4_shuffle(0b00_01_10_11, a);
    try testing.expectEqualSlices(u32, &.{ 13, 12, 11, 10 }, &shuffled);
    const aligned: [4]u32 = simd.u32x4_align(1, a, b);
    try testing.expectEqualSlices(u32, &.{ 11, 12, 13, 20 }, &aligned);
    const blended: [4]u32 = simd.u32x4_blend(0b0101, a, b);
    try testing.expectEqualSlices(u32, &.{ 20, 11, 22, 13 }, &blended);
    var bytes: [16]u8 = undefined;
    simd.u32x4_store_be(a, &bytes);
    const back: [4]u32 = simd.u32x4_load_be(&bytes);
    try testing.expectEqualSlices(u32, &a, &back);
    const two: [4]u32 = simd.u32x4_load_be2(&bytes);
    try testing.expectEqualSlices(u32, &.{ 10, 11, 0, 0 }, &two);
}

const Path = enum { portable, x86_v4c, arm_v9, neon };

fn Leaf(comptime S: type) type {
    return struct {
        value: S.U32,
        path: *?Path,

        pub const Output = S.U32;

        pub fn portable(self: @This(), simd: S) S.U32 {
            self.path.* = .portable;
            return simd.u32_rotate_right(7, simd.u32_xor(self.value, simd.u32_splat(0xa5a5_a5a5)));
        }

        pub fn x86_v4c(self: @This(), simd: S) S.U32 {
            self.path.* = .x86_v4c;
            const zero = simd.u32_splat(0);
            const value = simd.u32_ternary(0x96, self.value, simd.u32_splat(0xa5a5_a5a5), zero);
            return simd.u32_rotate_right(7, value);
        }

        pub fn arm_v9(self: @This(), simd: S) S.U32 {
            self.path.* = .arm_v9;
            return simd.u32_xor_rotate_right(7, self.value, simd.u32_splat(0xa5a5_a5a5));
        }

        pub fn neon(self: @This(), simd: S) S.U32 {
            self.path.* = .neon;
            return simd.u32_rotate_right(7, simd.u32_xor(self.value, simd.u32_splat(0xa5a5_a5a5)));
        }
    };
}

fn compose(comptime S: type, input: u32, path: *?Path) S.U32 {
    const simd: S = .{};
    const value = simd.execute(Leaf(S){ .value = simd.u32_splat(input), .path = path });
    return simd.u32_add(value, simd.u32_splat(1));
}

fn expected_value(input: u32) u32 {
    return rotr(u32, input ^ 0xa5a5_a5a5, 7) +% 1;
}

test "typed register composition takes each profile's path" {
    const cases = .{
        .{ core.EmulatedScalar, Path.portable },
        .{ core.EmulatedX86V3, Path.portable },
        .{ core.EmulatedX86V4C, Path.x86_v4c },
        .{ core.EmulatedArmV9, Path.arm_v9 },
        .{ core.EmulatedNeon, Path.neon },
    };
    inline for (cases) |case| {
        const S = case[0];
        var path: ?Path = null;
        const value: [S.u32_lanes]u32 = compose(S, 0xdead_beef, &path);
        try testing.expectEqual(@as(?Path, case[1]), path);
        for (value) |lane| try testing.expectEqual(expected_value(0xdead_beef), lane);
    }
}

const Root = struct {
    input: u32,

    pub const Output = u32;

    pub fn portable(self: Root, simd: anytype) u32 {
        var path: ?Path = null;
        const value = compose(@TypeOf(simd), self.input, &path);
        return value[0];
    }
};

test "normalize at the outer boundary" {
    for ([_]u32{ 0, 1, std.math.maxInt(u32), 0xdead_beef }) |input| {
        try core.check_consistent(struct {
            input: u32,
            pub fn make(self: @This()) Root {
                return .{ .input = self.input };
            }
        }{ .input = input });
        try testing.expectEqual(expected_value(input), core.dispatch(Root{ .input = input }));
        try testing.expectEqual(expected_value(input), core.test_dispatch(Root{ .input = input }));
    }
}

/// Rotate every aligned four-byte group left by one byte: full vectors rotate words right
/// by 8 bits, the tail is scalar.
fn rotate_groups(comptime S: type, data: []u8) void {
    const simd: S = .{};
    var rest = data;
    while (rest.len >= S.u8_lanes) : (rest = rest[S.u8_lanes..]) {
        const words = simd.u8_as_u32(simd.u8_load(rest));
        simd.u8_store(simd.u32_as_u8(simd.u32_rotate_right(8, words)), rest);
    }
    var group: usize = 0;
    while (group + 4 <= rest.len) : (group += 4) std.mem.rotate(u8, rest[group..][0..4], 1);
}

test "cast bytes to words and back" {
    inline for (all_backends) |S| {
        for ([_]usize{ 0, 3, 4, 16, 63, 64, 65, 130, 200 }) |len| {
            var input: [200]u8 = undefined;
            for (&input, 0..) |*x, i| x.* = @as(u8, @truncate(i *% 73)) ^ 0x5a;
            var expected = input;
            var group: usize = 0;
            while (group + 4 <= len) : (group += 4) std.mem.rotate(u8, expected[group..][0..4], 1);
            var actual = input;
            rotate_groups(S, actual[0..len]);
            try testing.expectEqualSlices(u8, expected[0..len], actual[0..len]);
        }
    }
}

test "readme hex example" {
    inline for (all_backends) |S| {
        const simd: S = .{};
        var input: [S.u8_lanes]u8 = undefined;
        for (&input, 0..) |*x, i| x.* = @truncate(i * 37 + 5);
        const table = simd.u8_table_load("0123456789abcdef");
        const value = simd.u8_load(&input);
        const high = simd.u8_table_lookup(table, simd.u8_shr(4, value));
        const low = simd.u8_table_lookup(table, simd.u8_and(value, simd.u8_splat(0x0f)));
        var output: [2 * S.u8_lanes]u8 = undefined;
        simd.u8_store(simd.u8_zip_lo(high, low), &output);
        simd.u8_store(simd.u8_zip_hi(high, low), output[S.u8_lanes..]);
        var expected: [2 * S.u8_lanes]u8 = undefined;
        _ = std.fmt.bufPrint(&expected, "{x}", .{&input}) catch unreachable; // Exact size.
        try testing.expectEqualSlices(u8, &expected, &output);
    }
}

test "x86v4c shuffles and ternary match their definitions" {
    const S = core.EmulatedX86V4C;
    const simd: S = .{};
    var a: [16]u32 = undefined;
    var b: [16]u32 = undefined;
    for (&a, &b, 0..) |*x, *y, i| {
        x.* = 0xa000_0000 + @as(u32, @intCast(i)) * 0x10101;
        y.* = 0xb000_0000 + @as(u32, @intCast(i)) * 0x30303;
    }
    inline for (.{ 0, 1, 27, 0x96, 0xe4, 0xff }) |mask_literal| {
        const mask: u8 = mask_literal;
        const groups: [16]u32 = simd.u32_shuffle_groups(mask, a, b);
        const tern: [16]u32 = simd.u32_ternary(mask, a, b, simd.u32_splat(0xaaaa_aaaa));
        const shuffle: [16]u32 = simd.u32_shuffle128(mask, a);
        const shuffle2: [16]u32 = simd.u32_shuffle2_128(mask, a, b);
        for (0..16) |i| {
            const group = (mask >> @intCast(2 * (i / 4))) & 3;
            const source = if (i < 8) a else b;
            try testing.expectEqual(source[group * 4 + i % 4], groups[i]);
            const selector = (mask >> @intCast(2 * (i % 4))) & 3;
            try testing.expectEqual(a[i / 4 * 4 + selector], shuffle[i]);
            const pick = if (i % 4 < 2) a else b;
            try testing.expectEqual(pick[i / 4 * 4 + selector], shuffle2[i]);
            var bits: u32 = 0;
            for (0..32) |bit| {
                const shift: u5 = @intCast(bit);
                const index = 4 * ((a[i] >> shift) & 1) + 2 * ((b[i] >> shift) & 1) +
                    ((@as(u32, 0xaaaa_aaaa) >> @intCast(bit)) & 1);
                bits |= ((@as(u32, mask) >> @intCast(index)) & 1) << @intCast(bit);
            }
            try testing.expectEqual(bits, tern[i]);
        }
    }
    const unpack: [16]u32 = simd.u32_unpacklo32(a, b);
    for (0..16) |i| {
        const source = i / 4 * 4 + i % 4 / 2;
        try testing.expectEqual(if (i % 2 == 0) a[source] else b[source], unpack[i]);
    }
}

test "gf mul, madd52, clmul, and widening multiplies" {
    const x86: core.EmulatedX86V4C = .{};
    // 0x57 * 0x83 = 0xc1 in AES's GF(2^8) (FIPS 197 example).
    const product: [64]u8 = x86.u8_gf_mul(x86.u8_splat(0x57), x86.u8_splat(0x83));
    try testing.expectEqual(@as(u8, 0xc1), product[0]);
    const big: u64 = (1 << 52) - 1;
    const lo: [8]u64 = x86.u64_madd52lo(x86.u64_splat(1), x86.u64_splat(big), x86.u64_splat(big));
    const hi: [8]u64 = x86.u64_madd52hi(x86.u64_splat(0), x86.u64_splat(big), x86.u64_splat(big));
    const full = @as(u128, big) * big;
    try testing.expectEqual(1 + @as(u64, @truncate(full & big)), lo[0]);
    try testing.expectEqual(@as(u64, @truncate(full >> 52)), hi[0]);
    const neon: core.EmulatedNeon = .{};
    const clmul: [8]u16 = neon.u8_clmul_lo(neon.u8_splat(0b11), neon.u8_splat(0b11));
    try testing.expectEqual(@as(u16, 0b101), clmul[0]);
    const half = neon.u64_narrow(.{ 0x1_0000_0003, 5 });
    const widened: [2]u64 = neon.u32_widen_madd(.{ 1, 2 }, half, neon.u32_half_splat(0xffff_ffff));
    try testing.expectEqual(1 + 3 * @as(u64, 0xffff_ffff), widened[0]);
    const arm: core.EmulatedArmV9 = .{};
    const bcax: [2]u64 = arm.u64_bcax(.{ 1, 1 }, .{ 0b110, 0 }, .{ 0b010, 0 });
    try testing.expectEqual(@as(u64, 0b101), bcax[0]);
}

const sha256_k = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

const sha256_initial = [8]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/// The padded single block of "abc" and its message schedule from the x86 instructions.
fn abc_schedule() [64]u32 {
    const simd: core.EmulatedX86V4C = .{};
    var block: [64]u8 = @splat(0);
    @memcpy(block[0..3], "abc");
    block[3] = 0x80;
    block[63] = 24;
    var w: [64]u32 = undefined;
    for (0..16) |i| w[i] = std.mem.readInt(u32, block[4 * i ..][0..4], .big);
    var i: usize = 16;
    while (i < 64) : (i += 4) {
        const w16 = simd.u32x4_load(w[i - 16 ..]);
        const partial = simd.sha256_msg1(w16, simd.u32x4_load(w[i - 12 ..]));
        const with_w7 = simd.u32x4_add(partial, simd.u32x4_load(w[i - 7 ..]));
        simd.u32x4_store(simd.sha256_msg2(with_w7, simd.u32x4_load(w[i - 4 ..])), w[i..]);
    }
    return w;
}

fn expect_abc_digest(state: [8]u32) !void {
    var digest: [32]u8 = undefined;
    for (state, 0..) |word, i| {
        std.mem.writeInt(u32, digest[4 * i ..][0..4], word +% sha256_initial[i], .big);
    }
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("abc", &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &digest);
}

test "x86 SHA-256 instructions compress a block like std.crypto" {
    const simd: core.EmulatedX86V4C = .{};
    const w = abc_schedule();
    const s = sha256_initial;
    // SHA256RNDS2 register layout: cdgh = [h, g, d, c], abef = [f, e, b, a].
    var cdgh: @Vector(4, u32) = .{ s[7], s[6], s[3], s[2] };
    var abef: @Vector(4, u32) = .{ s[5], s[4], s[1], s[0] };
    var i: usize = 0;
    while (i < 64) : (i += 2) {
        const wk: @Vector(4, u32) = .{
            w[i] +% sha256_k[i], w[i + 1] +% sha256_k[i + 1], 0xdeadbeef, 0,
        };
        const next = simd.sha256_rounds2(cdgh, abef, wk);
        cdgh = abef;
        abef = next;
    }
    try expect_abc_digest(.{
        abef[3], abef[2], cdgh[3], cdgh[2], abef[1], abef[0], cdgh[1], cdgh[0],
    });
}

test "NEON SHA-256 instructions compress a block like std.crypto" {
    inline for (.{ core.EmulatedNeon, core.EmulatedArmV9 }) |S| {
        const simd: S = .{};
        const w = abc_schedule();
        // The NEON message schedule agrees with x86's.
        var check: [4]u32 = undefined;
        const su0 = simd.sha256_su0(simd.u32x4_load(w[0..]), simd.u32x4_load(w[4..]));
        const su1 = simd.sha256_su1(su0, simd.u32x4_load(w[8..]), simd.u32x4_load(w[12..]));
        simd.u32x4_store(su1, &check);
        try testing.expectEqualSlices(u32, w[16..20], &check);
        var abcd: @Vector(4, u32) = sha256_initial[0..4].*;
        var efgh: @Vector(4, u32) = sha256_initial[4..8].*;
        var i: usize = 0;
        while (i < 64) : (i += 4) {
            var wk_words: [4]u32 = undefined;
            for (&wk_words, 0..) |*x, j| x.* = w[i + j] +% sha256_k[i + j];
            const wk: @Vector(4, u32) = wk_words;
            const new_abcd = simd.sha256_h(abcd, efgh, wk);
            efgh = simd.sha256_h2(efgh, abcd, wk);
            abcd = new_abcd;
        }
        try expect_abc_digest(@as([4]u32, abcd) ++ @as([4]u32, efgh));
    }
}
