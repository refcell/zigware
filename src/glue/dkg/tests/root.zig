//! glue dkg's end-to-end test harnesses (commonware `glue::dkg::tests`): the one-shot DKG and
//! reshare harnesses, their properties, and the shared mocks. docs/lanes/glue.md's "dkg test
//! harnesses" section tracks what is ported.

test {
    _ = @import("mocks_network_test.zig");
    _ = @import("dkg/root.zig");
    _ = @import("reshare/root.zig");
}
