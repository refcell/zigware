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
    comptime assert(chunk % 8 == 0);
    comptime assert(n / chunk * chunk + n % chunk == n);
    var diff: @Vector(chunk, u8) = @splat(0);
    inline for (0..n / chunk) |i| {
        const left: @Vector(chunk, u8) = a[i * chunk ..][0..chunk].*;
        const right: @Vector(chunk, u8) = b[i * chunk ..][0..chunk].*;
        diff |= left ^ right;
    }
    var tail: u8 = 0;
    inline for (n / chunk * chunk..n) |i| tail |= a[i] ^ b[i];
    return (@reduce(.Or, diff) | tail) == 0;
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
