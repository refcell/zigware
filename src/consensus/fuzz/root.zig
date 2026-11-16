//! Zig port of commonware's consensus fuzz crate (`consensus/fuzz`): the fuzz targets over
//! simplex's messages, electors, attributable maps, and engines. Each target is a seeded
//! minifuzz test in `zig build test` and a `std.testing.fuzz` test.

test {
    _ = @import("messages.zig");
    _ = @import("elector.zig");
    _ = @import("attributable_map.zig");
    _ = @import("bounds.zig");
    _ = @import("types.zig");
    _ = @import("invariants.zig");
    _ = @import("strategy.zig");
    _ = @import("simplex.zig");
}
