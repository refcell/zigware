//! Erasure coefficients prepared once for a fixed set of received shard indices
//! (commonware `reed_solomon/plan.rs`).
//!
//! A plan depends only on the shard counts and the received original and recovery indices, not
//! on shard contents or byte length, so decoders that receive the same indices can share one.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const root = @import("root.zig");
const engine = @import("engine.zig");
const rate = @import("rate.zig");

const Error = root.Error;
const InitError = root.InitError;
const GfElement = engine.GfElement;
const BitSet = std.DynamicBitSetUnmanaged;

pub const Plan = struct {
    original_count: usize,
    recovery_count: usize,
    /// Whether the high-rate layout applies, which places originals after the recovery block.
    high_rate: bool,
    /// Received flags indexed by work position, in the layout `DecoderWork` uses for this rate.
    received: BitSet,
    /// Log erasure locators indexed by work position (at least one per bit of `received`).
    /// Empty when every original was received.
    coefficients: []GfElement,

    /// Prepares coefficients for the received original and recovery shard indices. At least
    /// `original_count` indices must be given in total; extra recovery indices are allowed.
    pub fn init(
        gpa: Allocator,
        original_count: usize,
        recovery_count: usize,
        original_indices: []const usize,
        recovery_indices: []const usize,
    ) InitError!Plan {
        const high_rate = try rate.default.use_high_rate(original_count, recovery_count);
        // Mirror the received-bit layout each rate's `reset` gives `DecoderWork`.
        const original_base = if (high_rate) rate.next_power_of_two(recovery_count) else 0;
        const recovery_base = if (high_rate) 0 else rate.next_power_of_two(original_count);
        const end = @max(original_base + original_count, recovery_base + recovery_count);

        var received = try BitSet.initEmpty(gpa, end);
        errdefer received.deinit(gpa);
        for (original_indices) |index| {
            if (index >= original_count) return error.InvalidOriginalShardIndex;
            if (received.isSet(original_base + index)) return error.DuplicateOriginalShardIndex;
            received.set(original_base + index);
        }
        for (recovery_indices) |index| {
            if (index >= recovery_count) return error.InvalidRecoveryShardIndex;
            if (received.isSet(recovery_base + index)) return error.DuplicateRecoveryShardIndex;
            received.set(recovery_base + index);
        }
        if (original_indices.len + recovery_indices.len < original_count) {
            return error.NotEnoughShards;
        }
        assert(received.count() == original_indices.len + recovery_indices.len);

        // With every original received, decoding returns before reading coefficients.
        var coefficients: []GfElement = &.{};
        if (original_indices.len < original_count) {
            coefficients = try gpa.alloc(GfElement, rate.next_power_of_two(end));
            @memset(coefficients, 0);
            const E = engine.DefaultEngine;
            if (high_rate) {
                rate.high.eval_erasures(E, coefficients, original_count, recovery_count, &received);
            } else {
                rate.low.eval_erasures(E, coefficients, original_count, recovery_count, &received);
            }
        }
        return .{
            .original_count = original_count,
            .recovery_count = recovery_count,
            .high_rate = high_rate,
            .received = received,
            .coefficients = coefficients,
        };
    }

    pub fn deinit(plan: *Plan, gpa: Allocator) void {
        plan.received.deinit(gpa);
        gpa.free(plan.coefficients);
        plan.* = undefined;
    }

    /// Whether this plan was built for these counts, rate, and received positions.
    ///
    /// The decoder's bit set may be longer than the plan's (it never shrinks). With matching
    /// counts and rate the decoder sets no bit at or past the plan's length, since it rejects
    /// out-of-range indices, so comparing the plan's prefix is exact.
    pub fn matches(
        plan: *const Plan,
        original_count: usize,
        recovery_count: usize,
        high_rate: bool,
        received: *const BitSet,
    ) bool {
        if (plan.original_count != original_count) return false;
        if (plan.recovery_count != recovery_count) return false;
        if (plan.high_rate != high_rate) return false;
        if (received.bit_length < plan.received.bit_length) return false;
        for (0..plan.received.bit_length) |i| {
            if (received.isSet(i) != plan.received.isSet(i)) return false;
        }
        return true;
    }
};
