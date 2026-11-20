//! The test runner for Darwin targets: std's own runner (`lib/compiler/test_runner.zig`, which
//! build.zig copies beside this file as `std_runner.zig`), with std.debug's debug-info
//! allocator on `smp_allocator` instead of its default, a process-wide arena over
//! `page_allocator`.
//!
//! On Darwin, `std.testing.allocator` captures a stack trace on every allocation and free, and
//! aarch64-macos code unwinds through DWARF CFI, whose interpreter allocates from the debug-info
//! allocator on every frame. An arena never reuses those frees, so test-storage's
//! VM_ALLOCATE regions grew from 0.8 to 3.2 GB in 6 minutes on macOS CI (run 44676634589);
//! `smp_allocator` reuses them. Leak reports keep their stack traces.

const std = @import("std");
const builtin = @import("builtin");
const runner = @import("std_runner.zig");

comptime {
    std.debug.assert(builtin.is_test);
    std.debug.assert(builtin.os.tag.isDarwin());
}

pub const main = runner.main;
pub const std_options = runner.std_options;
pub const fuzz = runner.fuzz;

pub const debug = struct {
    pub fn getDebugInfoAllocator() std.mem.Allocator {
        return std.heap.smp_allocator;
    }
};
