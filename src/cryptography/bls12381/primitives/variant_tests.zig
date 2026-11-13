//! The variant tests live with the ops tests in `ops/tests.zig`, which exercise both
//! variants through signing; this file keeps `variant.zig`'s test hook.

test {
    _ = @import("ops/tests.zig");
}
