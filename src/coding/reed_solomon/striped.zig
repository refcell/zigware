//! Striped Reed-Solomon: every shard is split by byte range, and each range is coded as an
//! independent Reed-Solomon instance. A whole-input run codes one stripe spanning the shard.
//!
//! ```text
//!   originals:
//!     O0: [ stripe 0 ][ stripe 1 ][ tail ]
//!     O(k-1): [ stripe 0 ][ stripe 1 ][ tail ]
//!
//!   encode stripe 0 -> R0[0], R1[0], more recoveries
//!   encode stripe 1 -> R0[1], R1[1], more recoveries
//!   recovery Ri = concat(Ri[0], Ri[1], Ri[t])
//! ```
//!
//! Every stripe but the last ends on a `SHARD_CHUNK_BYTES` boundary, because the engine lays
//! shards out in blocks of that width, so striping does not change the coded bytes. Each stripe
//! task codes its range in tiles targeting `max_tile_work_bytes` of transform storage, which
//! start on block boundaries too.
//!
//! Commonware keeps one encoder and decoder per thread across calls; here each stripe task
//! creates its own coder and reuses it across that stripe's tiles.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const parallel = @import("parallel");

const rs = cryptography.reed_solomon;
const Range = parallel.Range;

pub const shard_chunk_bytes = rs.SHARD_CHUNK_BYTES;

/// Minimum stripe width for amortizing coder setup: a positive multiple of
/// `shard_chunk_bytes`, so every stripe holds at least one complete block.
pub const min_stripe_bytes: usize = 8 * 1024;

/// Target transform storage per tile within a stripe; a tile uses at most twice this.
pub const max_tile_work_bytes: usize = 2 * 1024 * 1024;

pub const Error = rs.InitError || error{Inconsistent};

/// The tiles that code a stripe `range`.
///
/// The transform holds at most `2 * (k + m).next_power_of_two()` shards, so the target tile
/// width is the number of blocks whose transform storage fits in `max_tile_work_bytes` (at
/// least one). A partial final block counts as a block. A stripe under twice the target is one
/// tile; otherwise its blocks spread over the fewest tiles within the target, with widths that
/// differ by at most one block. The decoder's sixteen-shard AVX-512 leaf skips padded lengths
/// that are multiples of 4 KiB, so a split adds tiles until no tile has such a length.
pub const Tiles = struct {
    start: usize,
    end: usize,
    width: usize,
    extra: usize,
    count: usize,
    index: usize = 0,

    pub fn init(k: usize, m: usize, range: Range) Tiles {
        assert(k > 0 and m > 0);
        const work_count = 2 * std.math.ceilPowerOfTwoAssert(usize, k + m);
        const target = @max(max_tile_work_bytes / (work_count * shard_chunk_bytes), 1);
        const blocks = std.math.divCeil(usize, range.len(), shard_chunk_bytes) catch unreachable;
        var count: usize = if (blocks < 2 * target) 1 else blocks / target + @intFromBool(
            blocks % target != 0,
        );
        const page = 4096 / shard_chunk_bytes;
        while (count > 1 and count < blocks) : (count += 1) {
            const width = blocks / count;
            const extra = blocks % count;
            if (width % page != 0 and (extra == 0 or (width + 1) % page != 0)) break;
        }
        assert(count >= 1);
        return .{
            .start = range.start,
            .end = range.end,
            .width = blocks / count,
            .extra = blocks % count,
            .count = count,
        };
    }

    fn edge(self: *const Tiles, i: usize) usize {
        assert(i <= self.count);
        return self.start + (i * self.width + @min(i, self.extra)) * shard_chunk_bytes;
    }

    /// The next tile; the last one ends at the stripe's end, so its final block may be partial.
    pub fn next(self: *Tiles) ?Range {
        if (self.index == self.count) return null;
        const i = self.index;
        self.index += 1;
        const tile_end = if (i + 1 == self.count) self.end else self.edge(i + 1);
        assert(self.edge(i) <= tile_end);
        return .init(self.edge(i), tile_end);
    }

    pub fn first(self: *const Tiles) Range {
        var copy = self.*;
        copy.index = 0;
        return copy.next().?;
    }
};

/// Converts a batch of complete blocks into a byte range, attaching any partial final block
/// to the last batch.
pub fn byte_range(shard_len: usize, blocks: Range) Range {
    const full_blocks = shard_len / shard_chunk_bytes;
    assert(blocks.end <= full_blocks);
    const end = if (blocks.end == full_blocks) shard_len else blocks.end * shard_chunk_bytes;
    return .init(blocks.start * shard_chunk_bytes, end);
}

/// Runs `job.map` over the stripes the strategy chooses for a codeword of `job.shard_len`.
fn run_stripes(strategy: anytype, job: anytype) Error!void {
    const blocks = job.shard_len / shard_chunk_bytes;
    const multiplier = shard_chunk_bytes * (job.k + job.m);
    const minimum = min_stripe_bytes / shard_chunk_bytes;
    return strategy.try_run_batches(blocks, minimum, multiplier, job);
}

fn run_batches(job: anytype, batches: anytype) Error!void {
    var out: [parallel.max_chunks]void = undefined;
    return batches.try_map_collect(out[0..batches.count()], job);
}

/// Encodes the `m` recovery shards of `originals` into `recovery`, one shard of `shard_len`
/// bytes after another.
pub const EncodeJob = struct {
    gpa: Allocator,
    k: usize,
    m: usize,
    shard_len: usize,
    originals: []const []const u8,
    recovery: []u8,

    pub fn run(job: EncodeJob, batches: anytype) Error!void {
        return run_batches(job, batches);
    }

    pub fn map(job: EncodeJob, index: usize, blocks: Range) Error!void {
        _ = index;
        return encode_stripe(job, byte_range(job.shard_len, blocks));
    }
};

pub fn encode_recovery(strategy: anytype, job: EncodeJob) Error!void {
    assert(job.originals.len == job.k);
    assert(job.recovery.len == job.m * job.shard_len);
    return run_stripes(strategy, job);
}

/// Encodes one stripe's recovery bytes, tile by tile. An encode result's `deinit` clears the
/// added originals, so tiles of the configured length reuse the encoder and others reset it.
pub fn encode_stripe(job: EncodeJob, range: Range) Error!void {
    if (range.is_empty()) return;
    var tiles: Tiles = .init(job.k, job.m, range);
    var len = tiles.first().len();
    var encoder = try rs.Encoder.init(job.gpa, job.k, job.m, len);
    defer encoder.deinit(job.gpa);
    while (tiles.next()) |tile| {
        if (tile.len() != len) {
            len = tile.len();
            try encoder.reset(job.gpa, job.k, job.m, len);
        }
        for (job.originals) |shard| try encoder.add_original_shard(shard[tile.start..tile.end]);
        var result = try encoder.encode();
        defer result.deinit();
        var recovery = result.recovery_iter();
        var index: usize = 0;
        while (recovery.next()) |shard| : (index += 1) {
            assert(shard.len == len);
            @memcpy(job.recovery[index * job.shard_len + tile.start ..][0..len], shard);
        }
        assert(index == job.m);
    }
}

/// Reconstructs the missing originals and recoveries of a codeword from exactly `k` provided
/// shards. One decode reveals every position, so no separate re-encode is needed. Restored
/// shards are written in the order of `missing_originals` and `missing_recoveries`.
pub const RevealJob = struct {
    gpa: Allocator,
    k: usize,
    m: usize,
    shard_len: usize,
    original_indices: []const usize,
    originals: []const []const u8,
    recovery_indices: []const usize,
    recoveries: []const []const u8,
    /// Erasure coefficients depend only on the counts and provided indices, so every stripe
    /// shares one plan.
    plan: *const rs.Plan,
    missing_originals: []const usize,
    missing_recoveries: []const usize,
    restored_originals: []u8,
    restored_recoveries: []u8,

    pub fn run(job: RevealJob, batches: anytype) Error!void {
        return run_batches(job, batches);
    }

    pub fn map(job: RevealJob, index: usize, blocks: Range) Error!void {
        _ = index;
        return reveal_stripe(job, byte_range(job.shard_len, blocks));
    }
};

pub fn reveal(strategy: anytype, job: RevealJob) Error!void {
    assert(job.original_indices.len + job.recovery_indices.len == job.k);
    assert(job.restored_originals.len == job.missing_originals.len * job.shard_len);
    return run_stripes(strategy, job);
}

fn reveal_stripe(job: RevealJob, range: Range) Error!void {
    if (range.is_empty()) return;
    var tiles: Tiles = .init(job.k, job.m, range);
    var len = tiles.first().len();
    var decoder = try rs.Decoder.init(job.gpa, job.k, job.m, len);
    defer decoder.deinit(job.gpa);
    while (tiles.next()) |tile| {
        if (tile.len() != len) {
            len = tile.len();
            try decoder.reset(job.gpa, job.k, job.m, len);
        }
        for (job.original_indices, job.originals) |index, shard| {
            try decoder.add_original_shard(index, shard[tile.start..tile.end]);
        }
        for (job.recovery_indices, job.recoveries) |index, shard| {
            try decoder.add_recovery_shard(index, shard[tile.start..tile.end]);
        }
        // Proof: an original is missing, so the decode always runs.
        var result = (try decoder.decode_with_recovery_plan(job.plan)) orelse unreachable;
        defer result.deinit();
        for (job.missing_originals, 0..) |index, slot| {
            const shard = result.original(index) orelse return error.Inconsistent;
            @memcpy(job.restored_originals[slot * job.shard_len + tile.start ..][0..len], shard);
        }
        for (job.missing_recoveries, 0..) |index, slot| {
            const shard = result.recovery(index) orelse return error.Inconsistent;
            @memcpy(job.restored_recoveries[slot * job.shard_len + tile.start ..][0..len], shard);
        }
    }
}
