//! libzstd 1.5.7's compression parameters for level 3 (`clevels.h`), refined for a known
//! source size as `ZSTD_getCParams_internal` and `ZSTD_adjustCParams_internal` do for
//! `zstd::bulk::compress` (no dictionary, size pledged, strategy dfast).

const std = @import("std");
const assert = std.debug.assert;

/// `ZSTD_WINDOWLOG_ABSOLUTEMIN`: the smallest window a frame header may declare.
pub const window_log_min: u6 = 10;
/// `ZSTD_HASHLOG_MIN`.
const hash_log_min: u6 = 6;

/// `ZSTD_compressionParameters` (strategy is always dfast here).
pub const Params = struct {
    window_log: u6,
    chain_log: u6,
    hash_log: u6,
    search_log: u6,
    min_match: u6,
    target_length: u32,
};

/// Level 3's rows of `ZSTD_defaultCParameters`, by `tableID`: over 256 KiB, up to 256 KiB,
/// up to 128 KiB, up to 16 KiB.
const level3_rows = [4]Params{
    row(21, 16, 17, 1, 5),
    row(18, 16, 16, 1, 4),
    row(17, 15, 16, 2, 5),
    row(14, 14, 15, 2, 4),
};

fn row(window: u6, chain: u6, hash: u6, search: u6, min_match: u6) Params {
    return .{
        .window_log = window,
        .chain_log = chain,
        .hash_log = hash,
        .search_log = search,
        .min_match = min_match,
        .target_length = 0,
    };
}

/// The parameters libzstd level 3 applies to a source of `src_size` bytes.
pub fn level3(src_size: u64) Params {
    const table_id = @as(usize, @intFromBool(src_size <= 256 * 1024)) +
        @intFromBool(src_size <= 128 * 1024) + @intFromBool(src_size <= 16 * 1024);
    var params = level3_rows[table_id];
    // Resize the window to the source (`maxWindowResize` is 2^30).
    if (src_size <= 1 << 30) {
        const size: u32 = @intCast(src_size);
        const src_log: u6 = if (size < 1 << hash_log_min)
            hash_log_min
        else
            @intCast(32 - @clz(size - 1));
        params.window_log = @min(params.window_log, src_log);
    }
    // No dictionary: `dictAndWindowLog` is the window log, and dfast's cycle log is its
    // chain log.
    params.hash_log = @min(params.hash_log, params.window_log + 1);
    params.chain_log = @min(params.chain_log, params.window_log);
    params.window_log = @max(params.window_log, window_log_min);
    assert(params.window_log >= window_log_min and params.window_log <= 21);
    assert(params.hash_log <= 17 and params.chain_log <= 16);
    return params;
}

const testing = std.testing;

// Expected values follow libzstd's tables and adjustment by hand, on both sides of each row
// boundary and of the window resize.
test "level 3 parameters by source size" {
    const cases = [_]struct { size: u64, window: u6, chain: u6, hash: u6, min_match: u6 }{
        .{ .size = 0, .window = 10, .chain = 6, .hash = 7, .min_match = 4 },
        .{ .size = 1000, .window = 10, .chain = 10, .hash = 11, .min_match = 4 },
        .{ .size = 16 * 1024, .window = 14, .chain = 14, .hash = 15, .min_match = 4 },
        .{ .size = 16 * 1024 + 1, .window = 15, .chain = 15, .hash = 16, .min_match = 5 },
        .{ .size = 128 * 1024, .window = 17, .chain = 15, .hash = 16, .min_match = 5 },
        .{ .size = 128 * 1024 + 1, .window = 18, .chain = 16, .hash = 16, .min_match = 4 },
        .{ .size = 256 * 1024 + 1, .window = 19, .chain = 16, .hash = 17, .min_match = 5 },
        .{ .size = 2 * 1024 * 1024, .window = 21, .chain = 16, .hash = 17, .min_match = 5 },
        .{ .size = 1 << 40, .window = 21, .chain = 16, .hash = 17, .min_match = 5 },
    };
    for (cases) |case| {
        const params = level3(case.size);
        try testing.expectEqual(case.window, params.window_log);
        try testing.expectEqual(case.chain, params.chain_log);
        try testing.expectEqual(case.hash, params.hash_log);
        try testing.expectEqual(case.min_match, params.min_match);
    }
}
