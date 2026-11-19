//! commonware's `#[should_panic]` tests of the merkle families, as death tests
//! (`utils.death`). The batch `add_many_past_limit` tests are not here: zigware returns
//! `error.LocationOverflow` where commonware panics, and batch_test.zig checks that.

const std = @import("std");
const death = @import("utils").death;
const merkle = @import("mod.zig");

// commonware `mmr::iterator::test_to_nearest_size_panic` ("size exceeds MAX_NODES").
test "mmr to_nearest_size panics past max_nodes" {
    try death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            const size = merkle.mmr.Family.max_nodes + 1;
            std.mem.doNotOptimizeAway(merkle.mmr.Family.to_nearest_size(size));
        }
    }.body);
}

// commonware `mmb::iterator::test_children_rejects_leaf_position` ("pos is not a valid parent
// position"): position 4 is a leaf, which has no birth leaf as a parent.
test "mmb children panics on a leaf position" {
    try death.expect_panic(@src(), "attempt to use null value", struct {
        fn body() !void {
            std.mem.doNotOptimizeAway(merkle.mmb.Family.children(4, 1));
        }
    }.body);
}
