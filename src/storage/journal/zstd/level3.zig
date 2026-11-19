//! libzstd 1.5.7's level 3 compression (`zstd::bulk::compress(.., 3)`), byte for byte.

pub const params = @import("params.zig");
pub const dfast = @import("dfast.zig");
pub const fse = @import("fse_exact.zig");
pub const huf = @import("huf_exact.zig");

test {
    _ = params;
    _ = dfast;
    _ = @import("dfast_test.zig");
    _ = fse;
    _ = @import("fse_exact_test.zig");
    _ = huf;
    _ = @import("huf_exact_test.zig");
}
