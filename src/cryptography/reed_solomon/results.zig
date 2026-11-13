//! Encoding and decoding results (commonware `reed_solomon/{encoder_result,decoder_result}.rs`).
//!
//! A result borrows its coder's working buffers. Rust resets the coder when the result is
//! dropped; here `deinit` does that, so call it before the coder's next round. A result that
//! is never deinitialized leaves the coder reporting a complete round (as a leaked Rust one).

const std = @import("std");
const assert = std.debug.assert;

const EncoderWork = @import("rate/encoder_work.zig").EncoderWork;
const DecoderWork = @import("rate/decoder_work.zig").DecoderWork;

/// Result of encoding: the generated recovery shards.
pub const EncoderResult = struct {
    work: *EncoderWork,

    /// Recovery shard `index`, or null if `index >= recovery_count`. Recovery shards have
    /// indexes `0..recovery_count`, and the same indexes must be used when decoding.
    pub fn recovery(result: EncoderResult, index: usize) ?[]const u8 {
        return result.work.recovery(index);
    }

    /// Iterator over all recovery shards, ordered by index.
    pub fn recovery_iter(result: EncoderResult) Recovery {
        return .{ .next_index = 0, .work = result.work };
    }

    /// Clears the received originals so the encoder can start a new round.
    pub fn deinit(result: *EncoderResult) void {
        result.work.reset_received();
        result.* = undefined;
    }
};

/// Iterator over generated recovery shards.
pub const Recovery = struct {
    next_index: usize,
    work: *const EncoderWork,

    pub fn next(iterator: *Recovery) ?[]const u8 {
        const shard = iterator.work.recovery(iterator.next_index) orelse return null;
        iterator.next_index += 1;
        assert(iterator.next_index <= iterator.work.recovery_count);
        return shard;
    }

    /// Number of shards not yet returned (`ExactSizeIterator::len`).
    pub fn len(iterator: Recovery) usize {
        assert(iterator.next_index <= iterator.work.recovery_count);
        return iterator.work.recovery_count - iterator.next_index;
    }
};

/// The restored original shards from a decode that ran (an original was missing).
pub const DecoderResult = struct {
    work: *DecoderWork,

    /// Restored original shard `index`, or null if `index` is not a missing original.
    pub fn original(result: DecoderResult, index: usize) ?[]const u8 {
        return result.work.original(index);
    }

    /// Iterator over all restored originals and their indexes, ordered by index.
    pub fn original_iter(result: DecoderResult) Restored {
        return .{
            .remaining = result.work.missing_original_count(),
            .next_index = 0,
            .work = result.work,
            .kind = .original,
        };
    }

    /// Clears the received shards so the decoder can start a new round.
    pub fn deinit(result: *DecoderResult) void {
        result.work.reset_received();
        result.* = undefined;
    }
};

/// The restored shards from a recovery-computing decode: the originals like `DecoderResult`,
/// and the reconstructed recovery shards.
pub const RecoveryDecoderResult = struct {
    inner: DecoderResult,

    pub fn original(result: RecoveryDecoderResult, index: usize) ?[]const u8 {
        return result.inner.original(index);
    }

    pub fn original_iter(result: RecoveryDecoderResult) Restored {
        return result.inner.original_iter();
    }

    /// Reconstructed recovery shard `index`, or null if it was provided or out of range.
    pub fn recovery(result: RecoveryDecoderResult, index: usize) ?[]const u8 {
        return result.inner.work.recovery(index);
    }

    /// Iterator over the reconstructed recovery shards and their indexes, ordered by index.
    pub fn recovery_iter(result: RecoveryDecoderResult) Restored {
        return .{
            .remaining = result.inner.work.missing_recovery_count(),
            .next_index = 0,
            .work = result.inner.work,
            .kind = .recovery,
        };
    }

    pub fn deinit(result: *RecoveryDecoderResult) void {
        result.inner.deinit();
    }
};

/// Iterator over restored shards and their indexes (Rust `Originals` and `Recoveries`).
pub const Restored = struct {
    /// Restored shards not yet returned.
    remaining: usize,
    /// Shard index at which the next scan starts.
    next_index: usize,
    work: *const DecoderWork,
    kind: enum { original, recovery },

    pub const Item = struct { index: usize, shard: []const u8 };

    pub fn next(iterator: *Restored) ?Item {
        if (iterator.remaining == 0) return null;
        const count = switch (iterator.kind) {
            .original => iterator.work.original_count,
            .recovery => iterator.work.recovery_count,
        };
        var index = iterator.next_index;
        while (index < count) : (index += 1) {
            const shard = switch (iterator.kind) {
                .original => iterator.work.original(index),
                .recovery => iterator.work.recovery(index),
            };
            if (shard) |found| {
                iterator.next_index = index + 1;
                iterator.remaining -= 1;
                return .{ .index = index, .shard = found };
            }
        }
        unreachable; // `remaining` counts exactly the restored shards below `count`.
    }

    pub fn len(iterator: Restored) usize {
        return iterator.remaining;
    }
};
