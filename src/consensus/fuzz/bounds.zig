//! Hardcoded quorum values as a root of trust for BFT calculations (commonware
//! `consensus/fuzz/src/bounds.rs`). If `utils.N3f1` changes by accident, the tests here
//! catch it.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const utils = @import("utils");

/// `f = (n - 1) / 3` for n = 1..=21.
const max_faults_table = [21]u32{ 0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6 };

/// `q = n - f` for n = 1..=21.
const quorum_table = [21]u32{
    1, 2, 3, 3, 4, 5, 5, 6, 7, 7, 8, 9, 9, 10, 11, 11, 12, 13, 13, 14, 15,
};

/// The most faults among `n` participants (1..=21).
pub fn max_faults(n: u32) u32 {
    assert(n > 0 and n <= max_faults_table.len);
    const result = max_faults_table[n - 1];
    assert(3 * result < n);
    return result;
}

/// The quorum among `n` participants (1..=21).
pub fn quorum(n: u32) u32 {
    assert(n > 0 and n <= quorum_table.len);
    const result = quorum_table[n - 1];
    assert(result <= n);
    return result;
}

test "hardcoded values match upstream" {
    for (1..22) |index| {
        const n: u32 = @intCast(index);
        const f = max_faults(n);
        const q = quorum(n);
        try testing.expectEqual(f, utils.N3f1.max_faults(n));
        try testing.expectEqual(q, utils.N3f1.quorum(n));
        // n = f + q, and the BFT safety property 2q > n + f.
        try testing.expectEqual(n, f + q);
        try testing.expect(2 * q > n + f);
    }
}

test "specific configurations" {
    try testing.expectEqual(1, max_faults(4));
    try testing.expectEqual(3, quorum(4));
    try testing.expectEqual(0, max_faults(3));
    try testing.expectEqual(2, max_faults(7));
    try testing.expectEqual(3, max_faults(10));
}
