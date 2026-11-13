//! Float formatting identical to the Rust `dtoa` crate (1.0), which prometheus-client uses for
//! every float in the text exposition: histogram sums, `le` bucket bounds, and float label
//! values. `dtoa` is Milo Yip's Grisu2 from RapidJSON, which is not always the shortest
//! representation, so `std.fmt`'s Ryu output differs for some values; this is a direct port.
//! Layout: `0.1`, `1.0`, `300.0`, `1e-7`, `1.5e300`, `NaN`, `inf`, `-inf`, `-0.0`.

const std = @import("std");
const assert = std.debug.assert;

/// Longest formatted value (the Rust crate's buffer size).
pub const buffer_size = 25;

const exponent_mask: u64 = 0x7FF0000000000000;
const significand_mask: u64 = 0x000FFFFFFFFFFFFF;
const sign_mask: u64 = 0x8000000000000000;
const hidden_bit: u64 = 0x0010000000000000;
const significand_size = 52;
const diy_significand_size = 64;
const exponent_bias = 0x3FF;
const min_power = -348;

/// 10^-348, 10^-340, ..., 10^340 as normalized 64-bit significands.
const cached_powers_f = [87]u64{
    0xfa8fd5a0081c0288, 0xbaaee17fa23ebf76, 0x8b16fb203055ac76, 0xcf42894a5dce35ea,
    0x9a6bb0aa55653b2d, 0xe61acf033d1a45df, 0xab70fe17c79ac6ca, 0xff77b1fcbebcdc4f,
    0xbe5691ef416bd60c, 0x8dd01fad907ffc3c, 0xd3515c2831559a83, 0x9d71ac8fada6c9b5,
    0xea9c227723ee8bcb, 0xaecc49914078536d, 0x823c12795db6ce57, 0xc21094364dfb5637,
    0x9096ea6f3848984f, 0xd77485cb25823ac7, 0xa086cfcd97bf97f4, 0xef340a98172aace5,
    0xb23867fb2a35b28e, 0x84c8d4dfd2c63f3b, 0xc5dd44271ad3cdba, 0x936b9fcebb25c996,
    0xdbac6c247d62a584, 0xa3ab66580d5fdaf6, 0xf3e2f893dec3f126, 0xb5b5ada8aaff80b8,
    0x87625f056c7c4a8b, 0xc9bcff6034c13053, 0x964e858c91ba2655, 0xdff9772470297ebd,
    0xa6dfbd9fb8e5b88f, 0xf8a95fcf88747d94, 0xb94470938fa89bcf, 0x8a08f0f8bf0f156b,
    0xcdb02555653131b6, 0x993fe2c6d07b7fac, 0xe45c10c42a2b3b06, 0xaa242499697392d3,
    0xfd87b5f28300ca0e, 0xbce5086492111aeb, 0x8cbccc096f5088cc, 0xd1b71758e219652c,
    0x9c40000000000000, 0xe8d4a51000000000, 0xad78ebc5ac620000, 0x813f3978f8940984,
    0xc097ce7bc90715b3, 0x8f7e32ce7bea5c70, 0xd5d238a4abe98068, 0x9f4f2726179a2245,
    0xed63a231d4c4fb27, 0xb0de65388cc8ada8, 0x83c7088e1aab65db, 0xc45d1df942711d9a,
    0x924d692ca61be758, 0xda01ee641a708dea, 0xa26da3999aef774a, 0xf209787bb47d6b85,
    0xb454e4a179dd1877, 0x865b86925b9bc5c2, 0xc83553c5c8965d3d, 0x952ab45cfa97a0b3,
    0xde469fbd99a05fe3, 0xa59bc234db398c25, 0xf6c69a72a3989f5c, 0xb7dcbf5354e9bece,
    0x88fcf317f22241e2, 0xcc20ce9bd35c78a5, 0x98165af37b2153df, 0xe2a0b5dc971f303a,
    0xa8d9d1535ce3b396, 0xfb9b7cd9a4a7443c, 0xbb764c4ca7a44410, 0x8bab8eefb6409c1a,
    0xd01fef10a657842c, 0x9b10a4e5e9913129, 0xe7109bfba19c0c9d, 0xac2820d9623bf429,
    0x80444b5e7aa7cf85, 0xbf21e44003acdd2d, 0x8e679c2f5e44ff8f, 0xd433179d9c8cb841,
    0x9e19db92b4e31ba9, 0xeb96bf6ebadf77d9, 0xaf87023b9bf0ee6b,
};

/// Binary exponents of `cached_powers_f`.
const cached_powers_e = [87]i16{
    -1220, -1193, -1166, -1140, -1113, -1087, -1060, -1034, -1007, -980, -954, -927,
    -901,  -874,  -847,  -821,  -794,  -768,  -741,  -715,  -688,  -661, -635, -608,
    -582,  -555,  -529,  -502,  -475,  -449,  -422,  -396,  -369,  -343, -316, -289,
    -263,  -236,  -210,  -183,  -157,  -130,  -103,  -77,   -50,   -24,  3,    30,
    56,    83,    109,   136,   162,   189,   216,   242,   269,   295,  322,  348,
    375,   402,   428,   455,   481,   508,   534,   561,   588,   614,  641,  667,
    694,   720,   747,   774,   800,   827,   853,   880,   907,   933,  960,  986,
    1013,  1039,  1066,
};

const pow10 = [10]u64{ 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };

comptime {
    assert(cached_powers_f.len == cached_powers_e.len);
    assert(diy_significand_size - significand_size - 2 == 10);
}

/// Formats `value` into `buffer` exactly as Rust's `dtoa::Buffer::format` does.
pub fn format(buffer: *[buffer_size]u8, value: f64) []const u8 {
    const bits: u64 = @bitCast(value);
    if (bits & exponent_mask == exponent_mask) {
        if (bits & significand_mask != 0) return "NaN";
        if (bits & sign_mask != 0) return "-inf";
        return "inf";
    }
    if (value == 0.0) {
        if (bits & sign_mask != 0) return "-0.0";
        return "0.0";
    }
    var start: usize = 0;
    var magnitude = value;
    if (value < 0.0) {
        buffer[0] = '-';
        start = 1;
        magnitude = -value;
    }
    assert(magnitude > 0.0);
    const digits = grisu2(magnitude, buffer[start..]);
    const end = prettify(buffer[start..], digits.length, digits.k);
    assert(start + end <= buffer_size);
    return buffer[0 .. start + end];
}

const DiyFp = struct {
    f: u64,
    e: i32,

    fn from(d: f64) DiyFp {
        const u: u64 = @bitCast(d);
        const biased_e: i32 = @intCast((u & exponent_mask) >> significand_size);
        const significand = u & significand_mask;
        if (biased_e != 0) {
            return .{
                .f = significand + hidden_bit,
                .e = biased_e - exponent_bias - significand_size,
            };
        }
        return .{ .f = significand, .e = 1 - exponent_bias - significand_size };
    }

    fn normalize(self: DiyFp) DiyFp {
        assert(self.f != 0);
        var result = self;
        while (result.f & (@as(u64, 1) << (diy_significand_size - 1)) == 0) {
            result.f <<= 1;
            result.e -= 1;
        }
        return result;
    }

    fn normalize_boundary(self: DiyFp) DiyFp {
        assert(self.f != 0);
        var result = self;
        while (result.f & (hidden_bit << 1) == 0) {
            result.f <<= 1;
            result.e -= 1;
        }
        result.f <<= diy_significand_size - significand_size - 2;
        result.e -= diy_significand_size - significand_size - 2;
        return result;
    }

    /// Returns the lower and upper boundaries, sharing the upper one's exponent.
    fn normalized_boundaries(self: DiyFp) [2]DiyFp {
        const plus = (DiyFp{ .f = (self.f << 1) + 1, .e = self.e - 1 }).normalize_boundary();
        var minus = if (self.f == hidden_bit)
            DiyFp{ .f = (self.f << 2) - 1, .e = self.e - 2 }
        else
            DiyFp{ .f = (self.f << 1) - 1, .e = self.e - 1 };
        assert(minus.e >= plus.e);
        minus.f <<= @intCast(minus.e - plus.e);
        minus.e = plus.e;
        return .{ minus, plus };
    }

    fn sub(self: DiyFp, other: DiyFp) DiyFp {
        assert(self.e == other.e);
        assert(self.f >= other.f);
        return .{ .f = self.f - other.f, .e = self.e };
    }

    fn mul(self: DiyFp, other: DiyFp) DiyFp {
        const m32: u64 = 0xFFFFFFFF;
        const a = self.f >> 32;
        const b = self.f & m32;
        const c = other.f >> 32;
        const d = other.f & m32;
        const ac = a * c;
        const bc = b * c;
        const ad = a * d;
        const bd = b * d;
        var tmp = (bd >> 32) + (ad & m32) + (bc & m32);
        tmp += @as(u64, 1) << 31; // Round the dropped low half.
        return .{ .f = ac + (ad >> 32) + (bc >> 32) + (tmp >> 32), .e = self.e + other.e + 64 };
    }
};

const CachedPower = struct { power: DiyFp, k: i32 };

fn get_cached_power(e: i32) CachedPower {
    const dk = @as(f64, @floatFromInt(3 - diy_significand_size - e)) * 0.30102999566398114 -
        @as(f64, @floatFromInt(min_power + 1));
    var k: i32 = @intFromFloat(dk); // Truncates toward zero like Rust's `as`.
    if (dk - @as(f64, @floatFromInt(k)) > 0.0) k += 1;
    const index: usize = @intCast((k >> 3) + 1);
    assert(index < cached_powers_f.len);
    return .{
        .power = .{ .f = cached_powers_f[index], .e = cached_powers_e[index] },
        .k = -(min_power + @as(i32, @intCast(index << 3))),
    };
}

fn count_decimal_digit32(n: u32) u32 {
    var digits: u32 = 1;
    var bound: u32 = 10;
    // Never reaches 10 digits in `digit_gen`.
    while (digits < 9 and n >= bound) : (bound *= 10) digits += 1;
    assert(digits >= 1 and digits <= 9);
    return digits;
}

fn grisu_round(
    buffer: []u8,
    len: usize,
    delta: u64,
    rest_start: u64,
    ten_kappa: u64,
    wp_w: u64,
) void {
    assert(len > 0);
    var rest = rest_start;
    while (rest < wp_w and delta - rest >= ten_kappa and
        (rest + ten_kappa < wp_w or wp_w - rest > rest + ten_kappa - wp_w))
    {
        buffer[len - 1] -= 1;
        rest += ten_kappa;
    }
}

const Digits = struct { length: usize, k: i32 };

fn grisu2(value: f64, buffer: []u8) Digits {
    assert(value > 0.0);
    const v = DiyFp.from(value);
    const boundaries = v.normalized_boundaries();
    const cached = get_cached_power(boundaries[1].e);
    const w = v.normalize().mul(cached.power);
    var wp = boundaries[1].mul(cached.power);
    var wm = boundaries[0].mul(cached.power);
    wm.f += 1;
    wp.f -= 1;
    return digit_gen(w, wp, wp.f - wm.f, buffer, cached.k);
}

fn digit_gen(w: DiyFp, mp: DiyFp, delta_start: u64, buffer: []u8, k_start: i32) Digits {
    assert(mp.e < 0 and mp.e > -64);
    const shift: u6 = @intCast(-mp.e);
    const one = DiyFp{ .f = @as(u64, 1) << shift, .e = mp.e };
    const wp_w = mp.sub(w);
    var delta = delta_start;
    var k = k_start;
    var p1: u32 = @intCast(mp.f >> shift);
    var p2: u64 = mp.f & (one.f - 1);
    var kappa: i32 = @intCast(count_decimal_digit32(p1));
    var len: usize = 0;
    while (kappa > 0) {
        const divisor: u32 = @intCast(pow10[@intCast(kappa - 1)]);
        const d = p1 / divisor;
        p1 %= divisor;
        if (d != 0 or len != 0) {
            buffer[len] = '0' + @as(u8, @intCast(d));
            len += 1;
        }
        kappa -= 1;
        const tmp = (@as(u64, p1) << shift) + p2;
        if (tmp <= delta) {
            k += kappa;
            grisu_round(buffer, len, delta, tmp, pow10[@intCast(kappa)] << shift, wp_w.f);
            return .{ .length = len, .k = k };
        }
    }
    // At most 20 fractional digits: delta grows tenfold per digit past one.f's range.
    var fraction_digits: u32 = 0;
    while (fraction_digits < 64) : (fraction_digits += 1) {
        p2 *= 10;
        delta *= 10;
        const d: u8 = @intCast(p2 >> shift);
        if (d != 0 or len != 0) {
            buffer[len] = '0' + d;
            len += 1;
        }
        p2 &= one.f - 1;
        kappa -= 1;
        if (p2 < delta) {
            k += kappa;
            const index = -kappa;
            const scale: u64 = if (index < 9) pow10[@intCast(index)] else 0;
            grisu_round(buffer, len, delta, p2, one.f, wp_w.f *% scale);
            return .{ .length = len, .k = k };
        }
    }
    unreachable; // Grisu2 always terminates: delta outgrows p2 < one.f within 20 digits.
}

fn write_exponent(k_start: i32, buffer: []u8) usize {
    var k = k_start;
    var index: usize = 0;
    if (k < 0) {
        buffer[0] = '-';
        index = 1;
        k = -k;
    }
    assert(k < 1000);
    const magnitude: u32 = @intCast(k);
    if (magnitude >= 100) {
        buffer[index] = '0' + @as(u8, @intCast(magnitude / 100));
        buffer[index + 1] = '0' + @as(u8, @intCast(magnitude / 10 % 10));
        buffer[index + 2] = '0' + @as(u8, @intCast(magnitude % 10));
        return index + 3;
    }
    if (magnitude >= 10) {
        buffer[index] = '0' + @as(u8, @intCast(magnitude / 10));
        buffer[index + 1] = '0' + @as(u8, @intCast(magnitude % 10));
        return index + 2;
    }
    buffer[index] = '0' + @as(u8, @intCast(magnitude));
    return index + 1;
}

/// RapidJSON's `Prettify` with `maxDecimalPlaces = 324`; returns the formatted length.
fn prettify(buffer: []u8, length: usize, k: i32) usize {
    assert(length > 0 and length <= 17);
    const len: i32 = @intCast(length);
    const kk = len + k; // 10^(kk-1) <= v < 10^kk
    if (0 <= k and kk <= 21) {
        // 1234e7 -> 12340000000.0
        const point: usize = @intCast(kk);
        @memset(buffer[length..point], '0');
        buffer[point] = '.';
        buffer[point + 1] = '0';
        return point + 2;
    }
    if (0 < kk and kk <= 21) {
        // 1234e-2 -> 12.34
        const point: usize = @intCast(kk);
        std.mem.copyBackwards(u8, buffer[point + 1 .. length + 1], buffer[point..length]);
        buffer[point] = '.';
        return length + 1;
    }
    if (-6 < kk and kk <= 0) {
        // 1234e-6 -> 0.001234
        const offset: usize = @intCast(2 - kk);
        std.mem.copyBackwards(u8, buffer[offset .. offset + length], buffer[0..length]);
        buffer[0] = '0';
        buffer[1] = '.';
        @memset(buffer[2..offset], '0');
        return length + offset;
    }
    if (kk < -324) {
        @memcpy(buffer[0..3], "0.0");
        return 3;
    }
    if (length == 1) {
        // 1e30
        buffer[1] = 'e';
        return 2 + write_exponent(kk - 1, buffer[2..]);
    }
    // 1234e30 -> 1.234e33
    std.mem.copyBackwards(u8, buffer[2 .. length + 1], buffer[1..length]);
    buffer[1] = '.';
    buffer[length + 1] = 'e';
    return length + 2 + write_exponent(kk - 1, buffer[length + 2 ..]);
}

const testing = std.testing;
const build_options = @import("build_options");
const utils = @import("utils");

test "dtoa matches the Rust crate on edge cases" {
    // Generated with dtoa 1.0.11 (`dtoa::Buffer::format`).
    const vectors = [_]struct { bits: u64, text: []const u8 }{
        .{ .bits = 0x3fb999999999999a, .text = "0.1" },
        .{ .bits = 0x3ff0000000000000, .text = "1.0" },
        .{ .bits = 0x4072c00000000000, .text = "300.0" },
        .{ .bits = 0x3ec92a737110e454, .text = "0.000003" },
        .{ .bits = 0x3ee4f8b588e368f1, .text = "0.00001" },
        .{ .bits = 0x3f50624dd2f1a9fc, .text = "0.001" },
        .{ .bits = 0x3f40624dd2f1a9fc, .text = "0.0005" },
        .{ .bits = 0x444b1ae4d6e2ef50, .text = "1e21" },
        .{ .bits = 0x4480f0cf064dd592, .text = "1e22" },
        .{ .bits = 0x441ac53a7e04bcda, .text = "123456789012345680000.0" },
        .{ .bits = 0x3e7ad7f29abcaf48, .text = "1e-7" },
        .{ .bits = 0x3eb0c6f7a0b5ed8d, .text = "0.000001" },
        .{ .bits = 0x0000000000000001, .text = "5e-324" },
        .{ .bits = 0x7fefffffffffffff, .text = "1.7976931348623157e308" },
        .{ .bits = 0x0010000000000000, .text = "2.2250738585072014e-308" },
        .{ .bits = 0xc004000000000000, .text = "-2.5" },
        .{ .bits = 0x3fd3333333333333, .text = "0.3" },
        .{ .bits = 0x3fe5555555555555, .text = "0.6666666666666666" },
        .{ .bits = 0x7e41eb2d66005835, .text = "1.5e300" },
        .{ .bits = 0x8000000000000000, .text = "-0.0" },
        .{ .bits = 0x0000000000000000, .text = "0.0" },
        .{ .bits = 0x7ff8000000000000, .text = "NaN" },
        .{ .bits = 0x7ff0000000000000, .text = "inf" },
        .{ .bits = 0xfff0000000000000, .text = "-inf" },
    };
    var buffer: [buffer_size]u8 = undefined;
    for (vectors) |vector| {
        try testing.expectEqualStrings(vector.text, format(&buffer, @bitCast(vector.bits)));
    }
}

fn splitmix(state: *u64) u64 {
    state.* +%= 0x9E3779B97F4A7C15;
    var z = state.*;
    z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
    return z ^ (z >> 31);
}

fn sample(index: u64, x: u64) f64 {
    return switch (index % 4) {
        0 => @bitCast(x),
        1 => @as(f64, @floatFromInt(x % 1_000_000)) / 1000.0,
        2 => @as(f64, @floatFromInt(x % 1_000_000_000)) * 1e-9,
        else => @as(f64, @floatFromInt(x >> 11)) / 9007199254740992.0,
    };
}

test "dtoa conformance hash over 200000 values" {
    // SHA-256 of every `format` output plus a newline, from the Rust crate on the same inputs:
    // raw bit patterns, millis, nanos, and unit-interval values drawn from splitmix64.
    const expected = "e71bbd4f36637e9dc2cefbf57c569282276c94ba62318a867422906c92ee5d6b";
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var state: u64 = 0;
    var buffer: [buffer_size]u8 = undefined;
    var index: u64 = 0;
    while (index < 200_000) : (index += 1) {
        hasher.update(format(&buffer, sample(index, splitmix(&state))));
        hasher.update("\n");
    }
    const digest = hasher.finalResult();
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&digest}) catch unreachable; // 64 bytes exactly.
    try testing.expectEqualStrings(expected, &hex);
}

test "dtoa round-trips every finite value (seeded fuzz)" {
    var rng = utils.rng.TestRng.init(0x7e1e_0001 ^ build_options.fuzz_seed);
    const total: u64 = 20_000 * @as(u64, build_options.fuzz_soak);
    var buffer: [buffer_size]u8 = undefined;
    var index: u64 = 0;
    while (index < total) : (index += 1) {
        const value = sample(index, rng.next_u64());
        if (std.math.isNan(value) or std.math.isInf(value)) continue;
        const text = format(&buffer, value);
        const parsed = try std.fmt.parseFloat(f64, text);
        try testing.expectEqual(@as(u64, @bitCast(value)), @as(u64, @bitCast(parsed)));
    }
}

test "dtoa fuzz" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            const value: f64 = @bitCast(smith.value(u64));
            var buffer: [buffer_size]u8 = undefined;
            const text = format(&buffer, value);
            if (std.math.isNan(value) or std.math.isInf(value)) return;
            const parsed = try std.fmt.parseFloat(f64, text);
            try testing.expectEqual(@as(u64, @bitCast(value)), @as(u64, @bitCast(parsed)));
        }
    }.one, .{});
}
