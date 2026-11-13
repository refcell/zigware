//! simd: Abstract over SIMD operations.
//!
//! Zig port of commonware's `commonware-simd` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/simd). See `core.zig` for the backend
//! profiles, the operation model, `dispatch`, `test_dispatch`, and `check_consistent`.

const std = @import("std");

const core = @import("core.zig");
pub const Profile = core.Profile;
pub const Backend = core.Backend;
pub const EmulatedScalar = core.EmulatedScalar;
pub const EmulatedX86V3 = core.EmulatedX86V3;
pub const EmulatedX86V4C = core.EmulatedX86V4C;
pub const EmulatedNeon = core.EmulatedNeon;
pub const EmulatedArmV9 = core.EmulatedArmV9;
pub const Native = core.Native;
pub const native_profile = core.native_profile;
pub const dispatch = core.dispatch;
pub const test_dispatch = core.test_dispatch;
pub const check_consistent = core.check_consistent;

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
}
