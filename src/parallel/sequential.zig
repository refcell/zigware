//! `Sequential`: runs every operation on the calling thread, in input order (commonware's
//! `Sequential`). Useful for debugging and tests, single-threaded environments, small
//! workloads, and as the baseline a parallel strategy is compared against.

const std = @import("std");
const assert = std.debug.assert;
const ops = @import("ops.zig");
const shared = @import("strategy.zig");

pub const Sequential = struct {
    pub fn parallelism(_: Sequential) usize {
        return 1;
    }

    /// Every fold and map runs as one chunk.
    pub fn split(_: Sequential, len: usize) usize {
        _ = len;
        return 1;
    }

    /// Calls `body(context, index)` for `index` in `0..count`, in order.
    pub fn execute(
        _: Sequential,
        count: usize,
        context: anytype,
        comptime body: fn (@TypeOf(context), usize) void,
    ) void {
        assert(count >= 1);
        assert(count <= ops.max_chunks);
        for (0..count) |index| body(context, index);
    }

    /// No scratch memory: sorts run serially in place.
    pub fn scratch(_: Sequential) ?std.mem.Allocator {
        return null;
    }

    pub const run = shared.run;
    pub const try_run = shared.try_run;
    pub const run_batches = shared.run_batches;
    pub const try_run_batches = shared.try_run_batches;
    pub const fold = shared.fold;
    pub const fold_init = shared.fold_init;
    pub const try_fold = shared.try_fold;
    pub const map_into = shared.map_into;
    pub const map_init_into = shared.map_init_into;
    pub const try_map_into = shared.try_map_into;
    pub const map_collect = shared.map_collect;
    pub const map_init_collect = shared.map_init_collect;
    pub const map_collect_with_multiplier = shared.map_collect_with_multiplier;
    pub const map_init_collect_with_multiplier = shared.map_init_collect_with_multiplier;
    pub const try_map_collect = shared.try_map_collect;
    pub const map_partition_collect = shared.map_partition_collect;
    pub const join = shared.join;
    pub const sort_by = shared.sort_by;
    pub const sort_unstable_by = shared.sort_unstable_by;
};
