//! math: Create and manipulate mathematical objects.
//!
//! Zig port of commonware's `commonware-math` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/math).
//!
//! - `algebra`: comptime interfaces for additive groups, rings, fields, modules (`Space`),
//!   cryptographic groups, and the generic algorithms behind them (`exp`, `scale`, `msm`).
//! - `fields.goldilocks`: the 64-bit Goldilocks field.
//! - `testing`: tiny field and group types for testing generic code.
//! - `fuzz`: structured fuzz input and drivers shared with packages that build on math.

const std = @import("std");

pub const algebra = @import("algebra.zig");
pub const fields = struct {
    pub const goldilocks = @import("fields/goldilocks.zig");
};
pub const ntt = @import("ntt.zig");
pub const poly = @import("poly.zig");
pub const testing = @import("testing.zig");
pub const wire = @import("wire.zig");
pub const fuzz = @import("fuzz.zig");

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(fields);
}
