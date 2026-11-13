//! Working space for rate decoders (commonware `reed_solomon/rate/decoder_work.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const root = @import("../root.zig");
const engine = @import("../engine.zig");
const Plan = @import("../plan.zig").Plan;

const Error = root.Error;
const GfElement = engine.GfElement;
const Shards = engine.Shards;
const ShardsRefMut = engine.ShardsRefMut;
const BitSet = std.DynamicBitSetUnmanaged;

/// Working space for a rate decoder.
pub const DecoderWork = struct {
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,
    /// Index in `shards` of original shard 0.
    original_base_pos: usize,
    /// Index in `shards` of recovery shard 0.
    recovery_base_pos: usize,
    original_received_count: usize,
    recovery_received_count: usize,
    /// Received flags indexed by position in `shards`, not by shard index. May contain extra
    /// zero bits; never shrinks.
    received: BitSet,
    /// Original and recovery shard `i` sit at their base position plus `i`.
    shards: Shards,
    /// Scratch for the erasure locators: one entry per work shard, so decoding never allocates.
    erasures: []GfElement,

    /// No working space allocated.
    pub const empty: DecoderWork = .{
        .original_count = 0,
        .recovery_count = 0,
        .shard_bytes = 0,
        .original_base_pos = 0,
        .recovery_base_pos = 0,
        .original_received_count = 0,
        .recovery_received_count = 0,
        .received = .{},
        .shards = .empty,
        .erasures = &.{},
    };

    pub fn deinit(work: *DecoderWork, gpa: Allocator) void {
        work.received.deinit(gpa);
        work.shards.deinit(gpa);
        gpa.free(work.erasures);
        work.* = .empty;
    }

    /// `error.PlanMismatch` unless `plan` was built for these counts, this rate, and these
    /// received shard indices.
    pub fn validate_plan(work: *const DecoderWork, plan: *const Plan, high_rate: bool) Error!void {
        const matches = plan.matches(
            work.original_count,
            work.recovery_count,
            high_rate,
            &work.received,
        );
        if (!matches) return error.PlanMismatch;
    }

    /// Stores original shard `index` at `original_base_pos + index` and marks it received.
    pub fn add_original_shard(work: *DecoderWork, index: usize, shard: []const u8) Error!void {
        if (index >= work.original_count) return error.InvalidOriginalShardIndex;
        const pos = work.original_base_pos + index;
        if (work.received.isSet(pos)) return error.DuplicateOriginalShardIndex;
        if (shard.len != work.shard_bytes) return error.DifferentShardSize;
        work.shards.insert(pos, shard);
        work.original_received_count += 1;
        work.received.set(pos);
        assert(work.original_received_count <= work.original_count);
    }

    /// Stores recovery shard `index` at `recovery_base_pos + index` and marks it received.
    pub fn add_recovery_shard(work: *DecoderWork, index: usize, shard: []const u8) Error!void {
        if (index >= work.recovery_count) return error.InvalidRecoveryShardIndex;
        const pos = work.recovery_base_pos + index;
        if (work.received.isSet(pos)) return error.DuplicateRecoveryShardIndex;
        if (shard.len != work.shard_bytes) return error.DifferentShardSize;
        work.shards.insert(pos, shard);
        work.recovery_received_count += 1;
        work.received.set(pos);
        assert(work.recovery_received_count <= work.recovery_count);
    }

    pub const Begin = struct {
        work: ShardsRefMut,
        original_count: usize,
        recovery_count: usize,
        received: *const BitSet,
        /// Zeroed scratch of `work.len()` entries for the erasure locators.
        erasures: []GfElement,
    };

    /// Begins a decode: null if every original was received, `error.NotEnoughShards` if fewer
    /// than `original_count` shards were received.
    pub fn decode_begin(work: *DecoderWork) Error!?Begin {
        const received_count = work.original_received_count + work.recovery_received_count;
        if (received_count < work.original_count) return error.NotEnoughShards;
        if (work.original_received_count == work.original_count) return null;
        const view = work.shards.as_ref_mut();
        assert(work.erasures.len >= view.len());
        const erasures = work.erasures[0..view.len()];
        @memset(erasures, 0);
        return .{
            .work = view,
            .original_count = work.original_count,
            .recovery_count = work.recovery_count,
            .received = &work.received,
            .erasures = erasures,
        };
    }

    /// Configures this work for new shard counts, clears the received state, and resizes the
    /// shards to `work_count`. Original shard `i` is stored at `original_base_pos + i` and
    /// recovery shard `i` at `recovery_base_pos + i`. Retained shard contents are not zeroed.
    /// On allocation failure the configuration is unchanged.
    pub fn reset(
        work: *DecoderWork,
        gpa: Allocator,
        counts: struct { original: usize, recovery: usize, shard_bytes: usize },
        original_base_pos: usize,
        recovery_base_pos: usize,
        work_count: usize,
    ) Allocator.Error!void {
        assert(counts.shard_bytes % 2 == 0);
        const max_received_pos = @max(
            original_base_pos + counts.original,
            recovery_base_pos + counts.recovery,
        );
        assert(max_received_pos <= work_count);

        if (work.received.bit_length < max_received_pos) {
            try work.received.resize(gpa, max_received_pos, false);
        }
        if (work.erasures.len < work_count) {
            const erasures = try gpa.alloc(GfElement, work_count);
            gpa.free(work.erasures);
            work.erasures = erasures;
        }
        const chunk_count = std.math.divCeil(
            usize,
            counts.shard_bytes,
            engine.SHARD_CHUNK_BYTES,
        ) catch
            unreachable; // The divisor is a nonzero constant.
        try work.shards.resize(gpa, work_count, chunk_count);

        work.original_count = counts.original;
        work.recovery_count = counts.recovery;
        work.shard_bytes = counts.shard_bytes;
        work.original_base_pos = original_base_pos;
        work.recovery_base_pos = recovery_base_pos;
        work.reset_received();
    }

    /// Clears the received shards so new ones can be added under the same configuration.
    pub fn reset_received(work: *DecoderWork) void {
        work.original_received_count = 0;
        work.recovery_received_count = 0;
        work.received.unsetAll();
    }

    /// A restored original shard, or null if `index` is out of range or the shard was received.
    pub fn original(work: *const DecoderWork, index: usize) ?[]const u8 {
        if (index >= work.original_count) return null;
        const pos = work.original_base_pos + index;
        if (work.received.isSet(pos)) return null;
        return work.shards.bytes(pos, work.shard_bytes);
    }

    /// A reconstructed recovery shard, or null if `index` is not a missing recovery shard.
    /// Only meaningful after a recovery-computing decode.
    pub fn recovery(work: *const DecoderWork, index: usize) ?[]const u8 {
        if (index >= work.recovery_count) return null;
        const pos = work.recovery_base_pos + index;
        if (work.missing_original_count() == 0 or work.received.isSet(pos)) return null;
        return work.shards.bytes(pos, work.shard_bytes);
    }

    /// Undoes the last-chunk encoding of every original shard position.
    pub fn undo_last_chunk_encoding(work: *DecoderWork) void {
        const start = work.original_base_pos;
        work.shards.undo_last_chunk_encoding(work.shard_bytes, start, start + work.original_count);
    }

    /// Undoes the last-chunk encoding of every recovery shard position.
    pub fn undo_last_chunk_encoding_recovery(work: *DecoderWork) void {
        const start = work.recovery_base_pos;
        work.shards.undo_last_chunk_encoding(work.shard_bytes, start, start + work.recovery_count);
    }

    pub fn missing_original_count(work: *const DecoderWork) usize {
        return work.original_count - work.original_received_count;
    }

    pub fn missing_recovery_count(work: *const DecoderWork) usize {
        return work.recovery_count - work.recovery_received_count;
    }
};
