//! BLS12-381 primitives (commonware `bls12381::primitives`).

const std = @import("std");

pub const arithmetic = @import("arithmetic/root.zig");
pub const group = @import("group.zig");
pub const variant = @import("variant.zig");
pub const ops = @import("ops.zig");
pub const sharing = @import("sharing.zig");
pub const Sharing = sharing.Sharing;
pub const Mode = sharing.Mode;
pub const Error = variant.Error;
pub const MinPk = variant.MinPk;
pub const MinSig = variant.MinSig;

test {
    std.testing.refAllDecls(@This());
}
