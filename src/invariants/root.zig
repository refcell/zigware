//! invariants: Define and exercise invariants.
//!
//! Zig port of commonware's `commonware-invariants` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/invariants). `minifuzz` is a
//! deterministic fuzz harness for unit tests: a body draws structured values from an
//! `Unstructured` (arbitrary 1.4's byte decoder) and returns an error on a violated
//! property; a failure prints a `MINIFUZZ_BRANCH` token that replays it.

const std = @import("std");

pub const minifuzz = @import("minifuzz.zig");
pub const Unstructured = minifuzz.Unstructured;

test {
    std.testing.refAllDecls(@This());
    _ = @import("unstructured.zig");
    _ = @import("minifuzz_test.zig");
}
