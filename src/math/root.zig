//! math: Create and manipulate mathematical objects.
//!
//! Zig port of commonware's `commonware-math` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/math).
//!
//! - `algebra`: comptime interfaces for additive groups, rings, fields, modules (`Space`),
//!   cryptographic groups, and the generic algorithms behind them (`exp`, `scale`, `msm`).
//! - `fields.goldilocks`: the 64-bit Goldilocks field.
//! - `testing`: tiny field and group types for testing generic code, and the adapter that
//!   runs minifuzz bodies under `std.testing.fuzz`.
//!
//! Property tests draw from `invariants.minifuzz`, the port of commonware's minifuzz.

const std = @import("std");

pub const algebra = @import("algebra.zig");
pub const fields = struct {
    pub const goldilocks = @import("fields/goldilocks.zig");
};
pub const ntt = @import("ntt.zig");
pub const poly = @import("poly.zig");
pub const synthetic = @import("synthetic.zig");
pub const testing = @import("testing.zig");

const minifuzz = @import("invariants").minifuzz;

/// The crate's fuzz plan (commonware `math::fuzz::Plan`, the `math` fuzz target): a derived
/// enum tag selecting one module's plan, which then draws and runs its own case.
pub fn fuzz_plan(_: void, u: *minifuzz.Unstructured) !void {
    const Plan = enum { poly, algebra, goldilocks, testing, ntt, synthetic };
    switch (try u.arbitrary(Plan)) {
        .poly => try poly.fuzz_plan({}, u),
        .algebra => try algebra.fuzz_plan({}, u),
        .goldilocks => try fields.goldilocks.fuzz_plan({}, u),
        .testing => try testing.fuzz_plan({}, u),
        .ntt => try ntt.fuzz_plan({}, u),
        .synthetic => try synthetic.fuzz_plan({}, u),
    }
}

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(fields);
    _ = @import("conformance_test.zig");
}

test "math fuzz plan" {
    try minifuzz.run(std.testing.allocator, {}, fuzz_plan);
}

test "math fuzz plan (coverage-guided)" {
    try std.testing.fuzz({}, testing.smith_body(void, fuzz_plan), .{});
}
