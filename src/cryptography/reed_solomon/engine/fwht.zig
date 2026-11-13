//! Fast Walsh-Hadamard transform modulo `GF_MODULUS`, used by `eval_poly` and the Walsh
//! tables (commonware `reed_solomon/engine/fwht.rs`).

const std = @import("std");
const assert = std.debug.assert;

const engine = @import("../engine.zig");
const utils = @import("utils.zig");

const GF_ORDER = engine.GF_ORDER;
const GfElement = engine.GfElement;

/// Decimation in time (DIT) Fast Walsh-Hadamard Transform modulo `GF_MODULUS`.
///
/// Entries at and after `m_truncated` must be zero. The transform is unnormalized: applying it
/// twice multiplies every entry by `data.len` modulo `GF_MODULUS`.
pub fn fwht(data: []GfElement, m_truncated: usize) void {
    assert(std.math.isPowerOfTwo(data.len) and data.len <= GF_ORDER);
    assert(m_truncated <= data.len);

    var dist: usize = 1;
    var dist4: usize = 4;
    while (dist4 <= data.len) {
        var r: usize = 0;
        while (r < m_truncated) : (r += dist4) {
            for (r..r + dist) |offset| fwht_4(data, offset, dist);
        }
        dist = dist4;
        dist4 <<= 2;
    }

    // An odd log2(data.len) leaves one radix-2 layer at dist == data.len / 2.
    if (dist < data.len) {
        assert(dist * 2 == data.len);
        var r: usize = 0;
        while (r < m_truncated) : (r += 2 * dist) {
            for (r..r + dist) |i| {
                const sum, const difference = fwht_2(data[i], data[i + dist]);
                data[i] = sum;
                data[i + dist] = difference;
            }
        }
    }
}

/// Returns `(a + b, a - b)` modulo `GF_MODULUS`.
inline fn fwht_2(a: GfElement, b: GfElement) struct { GfElement, GfElement } {
    return .{ utils.add_mod(a, b), utils.sub_mod(a, b) };
}

/// Applies the radix-2 layers at distances `dist` and `2 * dist` to the four entries
/// `data[offset + k * dist]` for `k` in `0..4`.
inline fn fwht_4(data: []GfElement, offset: usize, dist: usize) void {
    const index0 = offset;
    const index1 = offset + dist;
    const index2 = offset + dist * 2;
    const index3 = offset + dist * 3;

    const s0, const d0 = fwht_2(data[index0], data[index1]);
    const s1, const d1 = fwht_2(data[index2], data[index3]);
    const s2, const d2 = fwht_2(s0, s1);
    const s3, const d3 = fwht_2(d0, d1);

    data[index0] = s2;
    data[index1] = s3;
    data[index2] = d2;
    data[index3] = d3;
}

const testing = std.testing;
const ChaCha8Rng = @import("../test_util.zig").ChaCha8Rng;

/// Reference radix-2 implementation of `fwht` over the whole slice.
fn fwht_naive(data: []GfElement) void {
    var dist: usize = 1;
    var dist2: usize = 2;
    while (dist2 <= data.len) {
        var r: usize = 0;
        while (r < data.len) : (r += dist2) {
            for (r..r + dist) |offset| {
                const sum, const difference = fwht_2_naive(data[offset], data[offset + dist]);
                data[offset] = sum;
                data[offset + dist] = difference;
            }
        }
        dist = dist2;
        dist2 *= 2;
    }
}

/// Reference `fwht_2` built on wrapping `u16` arithmetic.
fn fwht_2_naive(a: GfElement, b: GfElement) struct { GfElement, GfElement } {
    var sum, const sum_overflow = @addWithOverflow(a, b);
    // The wrap reduced `sum` mod 65536; adding one reduces it mod GF_MODULUS (65535) instead.
    if (sum_overflow == 1) sum += 1;
    var difference, const difference_overflow = @subWithOverflow(a, b);
    if (difference_overflow == 1) difference -= 1;
    return .{ sum, difference };
}

test "fwht full" {
    var rng = ChaCha8Rng.init_key(@splat(0));
    const data1 = try testing.allocator.alloc(GfElement, GF_ORDER);
    defer testing.allocator.free(data1);
    const data2 = try testing.allocator.alloc(GfElement, GF_ORDER);
    defer testing.allocator.free(data2);
    for (data1) |*value| value.* = @truncate(rng.next_u32());
    @memcpy(data2, data1);
    fwht(data1, GF_ORDER);
    fwht_naive(data2);
    try testing.expectEqualSlices(GfElement, data2, data1);
}

test "fwht truncated" {
    var rng = ChaCha8Rng.init_key(@splat(0));
    const random = try testing.allocator.alloc(GfElement, GF_ORDER);
    defer testing.allocator.free(random);
    for (random) |*value| value.* = @truncate(rng.next_u32());
    const data1 = try testing.allocator.alloc(GfElement, GF_ORDER);
    defer testing.allocator.free(data1);
    const data2 = try testing.allocator.alloc(GfElement, GF_ORDER);
    defer testing.allocator.free(data2);

    const counts = [_]usize{
        0,            1,                2,            3,            4,
        64,           127,              16384 - 1,    16384 + 1,    GF_ORDER / 2 - 1,
        GF_ORDER / 2, GF_ORDER / 2 + 1, GF_ORDER - 4, GF_ORDER - 3, GF_ORDER - 2,
        GF_ORDER - 1, GF_ORDER,
    };
    for (counts) |nonzero_count| {
        @memset(data1, 0);
        @memcpy(data1[0..nonzero_count], random[0..nonzero_count]);
        @memcpy(data2, data1);
        fwht(data1, nonzero_count);
        fwht_naive(data2);
        try testing.expectEqualSlices(GfElement, data2, data1);
    }
}

test "fwht short odd and even lengths" {
    var rng = ChaCha8Rng.init_key(@splat(7));
    var actual: [1024]GfElement = undefined;
    var expected: [1024]GfElement = undefined;
    for ([_]usize{ 1, 2, 4, 8, 16, 512, 1024 }) |n| {
        for ([_]usize{ 0, 1, n / 2, n }) |nonzero| {
            for (actual[0..n]) |*value| value.* = @truncate(rng.next_u32());
            @memset(actual[nonzero..n], 0);
            @memcpy(expected[0..n], actual[0..n]);
            fwht(actual[0..n], nonzero);
            fwht_naive(expected[0..n]);
            try testing.expectEqualSlices(GfElement, expected[0..n], actual[0..n]);
        }
    }
}
