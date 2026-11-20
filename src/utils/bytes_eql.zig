//! Fixed-size byte-array equality, as an XOR-OR over 32-byte vectors.
//!
//! On AVX-512 targets `std.mem.eql` over a fixed-size array lowers its 64-byte chunk compare
//! through a slow `bool`-vector reduce: about 120 ns for 96 bytes, against about 2 ns here.
//! The fold has no data-dependent branch or early exit, so it is also constant-time in the
//! contents, which secret-key and tag comparisons rely on.

const std = @import("std");
const assert = std.debug.assert;

/// Vector width of the fold, in bytes.
const chunk = 32;

/// True when the `n` bytes at `a` equal the `n` bytes at `b`. Runs in time that depends only
/// on `n`, never on where (or whether) the arrays differ.
pub fn eql(comptime n: usize, a: *const [n]u8, b: *const [n]u8) bool {
    if (n < chunk) return eql_short(n, a, b) else return eql_long(n, a, b);
}

/// `eql` from one vector up: whole vectors, then the last vector's worth.
fn eql_long(comptime n: usize, a: *const [n]u8, b: *const [n]u8) bool {
    comptime assert(n >= chunk);
    var diff: @Vector(chunk, u8) = @splat(0);
    inline for (0..n / chunk) |i| diff |= window(chunk, n, a, b, i * chunk);
    // The last `chunk` bytes cover any tail; bytes compared twice do not change the result.
    if (n % chunk != 0) diff |= window(chunk, n, a, b, n - chunk);
    return @reduce(.Or, diff) == 0;
}

/// `eql` below one vector: two overlapping windows of the widest power of two that fits.
fn eql_short(comptime n: usize, a: *const [n]u8, b: *const [n]u8) bool {
    comptime assert(n < chunk);
    if (n == 0) return true;
    const width = comptime std.math.floorPowerOfTwo(usize, n);
    comptime assert(width <= n and n < 2 * width);
    const diff = window(width, n, a, b, 0) | window(width, n, a, b, n - width);
    return @reduce(.Or, diff) == 0;
}

/// The XOR of `width` bytes of `a` and `b` from `start`.
inline fn window(
    comptime width: usize,
    comptime n: usize,
    a: *const [n]u8,
    b: *const [n]u8,
    comptime start: usize,
) @Vector(width, u8) {
    comptime assert(start + width <= n);
    const left: @Vector(width, u8) = a[start..][0..width].*;
    const right: @Vector(width, u8) = b[start..][0..width].*;
    return left ^ right;
}

test "bytes_eql agrees with std.mem.eql at every length and position" {
    @setEvalBranchQuota(100_000);
    inline for (0..257) |n| {
        var a: [n]u8 = undefined;
        for (&a, 0..) |*byte, i| byte.* = @truncate(i *% 37 +% 11);
        try std.testing.expect(eql(n, &a, &a));
        var c = a;
        try std.testing.expect(eql(n, &a, &c));
        for (0..n) |position| {
            for ([_]u8{ 0x01, 0x80 }) |flip| {
                var b = a;
                b[position] ^= flip;
                const want = std.mem.eql(u8, &a, &b);
                try std.testing.expectEqual(want, eql(n, &a, &b));
                try std.testing.expectEqual(want, eql(n, &b, &a));
                try std.testing.expect(!want);
            }
        }
    }
}
