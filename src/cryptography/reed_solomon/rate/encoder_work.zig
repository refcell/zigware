//! Working space for rate encoders (commonware `reed_solomon/rate/encoder_work.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const root = @import("../root.zig");
const engine = @import("../engine.zig");

const Error = root.Error;
const Shards = engine.Shards;
const ShardsRefMut = engine.ShardsRefMut;

/// Working space for a rate encoder.
pub const EncoderWork = struct {
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,
    /// Number of originals added, which is also the position of the next one.
    original_received_count: usize,
    /// Originals are stored at `0..original_count`; an encode leaves the recovery shards at
    /// `0..recovery_count`.
    shards: Shards,

    /// No working space allocated.
    pub const empty: EncoderWork = .{
        .original_count = 0,
        .recovery_count = 0,
        .shard_bytes = 0,
        .original_received_count = 0,
        .shards = .empty,
    };

    pub fn deinit(work: *EncoderWork, gpa: Allocator) void {
        work.shards.deinit(gpa);
        work.* = .empty;
    }

    /// Stores the next original shard at position `original_received_count`.
    pub fn add_original_shard(work: *EncoderWork, original_shard: []const u8) Error!void {
        if (work.original_received_count == work.original_count) {
            return error.TooManyOriginalShards;
        }
        if (original_shard.len != work.shard_bytes) return error.DifferentShardSize;
        assert(work.original_received_count < work.original_count);
        work.shards.insert(work.original_received_count, original_shard);
        work.original_received_count += 1;
    }

    pub const Begin = struct {
        work: ShardsRefMut,
        original_count: usize,
        recovery_count: usize,
    };

    /// Returns the work shards and the shard counts for an encode, or
    /// `error.TooFewOriginalShards` unless all `original_count` originals were added.
    pub fn encode_begin(work: *EncoderWork) Error!Begin {
        if (work.original_received_count != work.original_count) {
            return error.TooFewOriginalShards;
        }
        assert(work.original_count > 0);
        return .{
            .work = work.shards.as_ref_mut(),
            .original_count = work.original_count,
            .recovery_count = work.recovery_count,
        };
    }

    /// Recovery shard `index`, or null if `index >= recovery_count`. Valid after an encode.
    pub fn recovery(work: *const EncoderWork, index: usize) ?[]const u8 {
        if (index >= work.recovery_count) return null;
        return work.shards.bytes(index, work.shard_bytes);
    }

    /// Configures this work for new shard counts, clears the received originals, and resizes
    /// the shards to `work_count`. On allocation failure nothing changes.
    pub fn reset(
        work: *EncoderWork,
        gpa: Allocator,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        work_count: usize,
    ) Allocator.Error!void {
        assert(shard_bytes % 2 == 0);
        assert(work_count >= original_count and work_count >= recovery_count);
        const chunk_count = std.math.divCeil(usize, shard_bytes, engine.SHARD_CHUNK_BYTES) catch
            unreachable; // The divisor is a nonzero constant.
        try work.shards.resize(gpa, work_count, chunk_count);
        work.original_count = original_count;
        work.recovery_count = recovery_count;
        work.shard_bytes = shard_bytes;
        work.original_received_count = 0;
    }

    /// Clears the received originals so new ones can be added under the same configuration.
    pub fn reset_received(work: *EncoderWork) void {
        work.original_received_count = 0;
    }

    /// Undoes the last-chunk encoding of the recovery shards at `0..recovery_count`.
    pub fn undo_last_chunk_encoding(work: *EncoderWork) void {
        work.shards.undo_last_chunk_encoding(work.shard_bytes, 0, work.recovery_count);
    }
};
