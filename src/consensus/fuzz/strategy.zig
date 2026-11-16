//! How a disrupter picks and mutates the views, parents, and payloads it sends (commonware
//! `consensus/fuzz/src/strategy.rs`): `small_scope` stays near the views it has seen,
//! `any_scope` draws anywhere, and `future_scope` stays just ahead. The scoped strategies
//! misbehave only in some views (`fault_bounds`).
//!
//! Draws follow rand 0.10 (`random::<u8>()` is a truncated `next_u32`, `random_bool` is
//! `utils.rng.bernoulli`, `random_range` is `utils.rng.range_less_than`).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const simplex = @import("../simplex/root.zig");
const fuzz_types = @import("types.zig");

const Digest = fuzz_types.Digest;
const Proposal = simplex.types.Proposal(Digest);
const sampling = utils.rng;

/// The highest views a disrupter has seen of each kind.
pub const Views = struct {
    vote: u64 = 0,
    finalized: u64 = 0,
    notarized: u64 = 0,
    nullified: u64 = 0,

    /// The same views with `view` as the latest vote (how commonware passes a proposal's
    /// view as the base of its parent).
    fn based_on(self: Views, view: u64) Views {
        var result = self;
        result.vote = view;
        return result;
    }
};

/// Faults in `fault_rounds` of every `fault_rounds_bound` views.
pub const FaultBounds = struct {
    fault_rounds: u64,
    fault_rounds_bound: u64,
};

pub const Strategy = union(enum) {
    small_scope: FaultBounds,
    any_scope,
    future_scope: FaultBounds,

    /// The fault rate, or null when every view is faulty.
    pub fn fault_bounds(self: Strategy) ?FaultBounds {
        return switch (self) {
            .small_scope, .future_scope => |bounds| bounds,
            .any_scope => null,
        };
    }

    pub fn random_proposal(self: Strategy, rng: anytype, views: Views) Proposal {
        const view = self.random_view_for_proposal(rng, views);
        const parent = self.random_parent_view(rng, views.based_on(view));
        return proposal_at(view, parent, random_payload(rng));
    }

    pub fn mutate_proposal(
        self: Strategy,
        rng: anytype,
        proposal: Proposal,
        views: Views,
    ) Proposal {
        return switch (self) {
            .small_scope => mutate_small(rng, proposal),
            .any_scope => mutate_any(rng, proposal, views),
            .future_scope => mutate_future(rng, proposal),
        };
    }

    pub fn mutate_nullify_view(self: Strategy, rng: anytype, views: Views) u64 {
        return switch (self) {
            .small_scope => switch (byte(rng) % 12) {
                0 => views.vote,
                1 => views.vote +| 1,
                2 => views.vote -| 1,
                3 => views.notarized,
                4 => views.notarized +| 1,
                5 => views.notarized -| 1,
                6 => views.finalized,
                7 => views.finalized +| 1,
                8 => views.finalized -| 1,
                9 => views.nullified,
                10 => views.nullified +| 1,
                else => views.nullified -| 1,
            },
            .any_scope => random_view(rng, views),
            .future_scope => views.vote +| bump(rng),
        };
    }

    pub fn random_view_for_proposal(self: Strategy, rng: anytype, views: Views) u64 {
        return switch (self) {
            .small_scope => switch (byte(rng) % 8) {
                0 => sample_inclusive(rng, views.finalized, notarized_cap(views)),
                1 => views.vote,
                2 => views.vote +| 1,
                3 => views.vote -| 1,
                4 => views.notarized +| 1,
                5 => views.notarized -| 1,
                6 => views.nullified +| 1,
                else => views.nullified -| 1,
            },
            .any_scope => random_view(rng, views),
            .future_scope => views.vote +| bump(rng),
        };
    }

    /// A parent for a proposal at `views.vote`.
    pub fn random_parent_view(self: Strategy, rng: anytype, views: Views) u64 {
        return switch (self) {
            .small_scope => switch (byte(rng) % 6) {
                0 => views.vote -| 1,
                1 => views.finalized,
                2 => views.notarized -| 1,
                3 => views.notarized,
                4 => views.nullified -| 1,
                else => views.finalized -| 1,
            },
            .any_scope => random_view(rng, views.based_on(views.vote -| 1)),
            .future_scope => views.vote -| bump(rng),
        };
    }

    /// A mutated certificate or resolver message: one flipped bit, or (`any_scope`) random
    /// bytes of the same length. Empty input becomes one zero byte. Caller owns the result.
    pub fn mutate_bytes(self: Strategy, rng: anytype, gpa: Allocator, bytes: []const u8) ![]u8 {
        if (bytes.len == 0) return gpa.dupe(u8, &.{0});
        const out = try gpa.alloc(u8, bytes.len);
        switch (self) {
            .any_scope => rng.fill_bytes(out),
            .small_scope, .future_scope => {
                @memcpy(out, bytes);
                const index = sampling.range_less_than(rng, usize, 0, out.len);
                out[index] ^= @as(u8, 1) << @intCast(byte(rng) % 8);
            },
        }
        assert(out.len == bytes.len);
        return out;
    }

    /// Which recent proposal to repeat, if any.
    pub fn repeated_proposal_index(self: Strategy, rng: anytype, proposals_len: usize) ?usize {
        if (proposals_len == 0) return null;
        switch (self) {
            .any_scope => {
                if (sampling.bernoulli(rng, 0.5)) return null;
                return sampling.range_less_than(rng, usize, 0, proposals_len);
            },
            .small_scope, .future_scope => {
                if (proposals_len <= 1) return 0;
                if (sampling.bernoulli(rng, 0.5)) return null;
                return proposals_len - 2;
            },
        }
    }
};

/// `rng.random::<u8>()`.
fn byte(rng: anytype) u8 {
    return @truncate(rng.next_u32());
}

fn bump(rng: anytype) u64 {
    return if (sampling.bernoulli(rng, 0.5)) 1 else 2;
}

fn notarized_cap(views: Views) u64 {
    return @max(@min(views.notarized, views.vote), views.finalized);
}

fn proposal_at(view: u64, parent: u64, payload: Digest) Proposal {
    return .init(.new(fuzz_types.epoch, .new(view)), .new(parent), payload);
}

fn with_view(proposal: Proposal, view: u64) Proposal {
    return proposal_at(view, proposal.parent.get(), proposal.payload);
}

fn with_parent(proposal: Proposal, parent: u64) Proposal {
    return proposal_at(proposal.view().get(), parent, proposal.payload);
}

fn with_payload(proposal: Proposal, payload: Digest) Proposal {
    return proposal_at(proposal.view().get(), proposal.parent.get(), payload);
}

fn random_payload(rng: anytype) Digest {
    var payload: Digest = undefined;
    rng.fill_bytes(&payload.bytes);
    return payload;
}

fn mutate_small(rng: anytype, proposal: Proposal) Proposal {
    const view = proposal.view().get();
    const parent = proposal.parent.get();
    return switch (byte(rng) % 5) {
        0 => with_view(proposal, view +| 1),
        1 => with_view(proposal, view -| 1),
        2 => with_parent(proposal, parent +| 1),
        3 => with_parent(proposal, parent -| 1),
        else => {
            var payload = proposal.payload;
            const index = sampling.range_less_than(rng, usize, 0, payload.bytes.len);
            payload.bytes[index] ^= @as(u8, 1) << @intCast(byte(rng) % 8);
            return with_payload(proposal, payload);
        },
    };
}

fn mutate_any(rng: anytype, proposal: Proposal, views: Views) Proposal {
    const at = views.based_on(proposal.view().get());
    return switch (byte(rng) % 4) {
        0 => with_payload(proposal, random_payload(rng)),
        1 => with_view(proposal, random_view(rng, at)),
        2 => with_parent(proposal, random_view(rng, at.based_on(at.vote -| 1))),
        else => {
            const view = random_view(rng, at);
            const parent = random_view(rng, at.based_on(view -| 1));
            return proposal_at(view, parent, random_payload(rng));
        },
    };
}

fn mutate_future(rng: anytype, proposal: Proposal) Proposal {
    const view = proposal.view().get();
    const parent = proposal.parent.get();
    const step = bump(rng);
    return switch (byte(rng) % 3) {
        0 => with_view(proposal, view +| step),
        1 => with_parent(proposal, parent +| step),
        else => proposal_at(view +| step, parent +| step, proposal.payload),
    };
}

/// commonware's `random_view`: below or at the finalized view, between it and the latest
/// vote, a little or a lot ahead, or anywhere.
fn random_view(rng: anytype, views: Views) u64 {
    return switch (byte(rng) % 7) {
        0 => if (views.finalized == 0) 0 else sample_inclusive(rng, 0, views.finalized - 1),
        1 => if (views.vote <= views.finalized)
            views.finalized
        else
            sample_inclusive(rng, views.finalized, views.vote),
        2 => sample_inclusive(rng, views.finalized, notarized_cap(views)),
        3 => add_or_sample_at_or_above(rng, views.vote, 1 + @as(u64, byte(rng) % 4)),
        4 => add_or_sample_at_or_above(rng, views.vote, 5 + @as(u64, byte(rng) % 6)),
        5 => {
            const view = @max(views.vote, views.nullified);
            return add_or_sample_at_or_above(rng, view, 1 + @as(u64, byte(rng) % 10));
        },
        else => rng.next_u64(),
    };
}

fn add_or_sample_at_or_above(rng: anytype, view: u64, delta: u64) u64 {
    const sum, const overflow = @addWithOverflow(view, delta);
    if (overflow == 0) return sum;
    return sample_inclusive(rng, view, std.math.maxInt(u64));
}

fn sample_inclusive(rng: anytype, low: u64, high: u64) u64 {
    if (high < low) return low;
    if (low == 0 and high == std.math.maxInt(u64)) return rng.next_u64();
    const width = high - low + 1;
    const result = low + rng.next_u64() % width;
    assert(result >= low and result <= high);
    return result;
}

test "scoped strategies stay in scope" {
    var rng = utils.rng.TestRng.init(7);
    const views: Views = .{ .vote = 20, .finalized = 15, .notarized = 19, .nullified = 18 };
    const future: Strategy = .{ .future_scope = .{ .fault_rounds = 1, .fault_rounds_bound = 2 } };
    const small: Strategy = .{ .small_scope = .{ .fault_rounds = 1, .fault_rounds_bound = 2 } };
    for (0..256) |_| {
        const ahead = future.random_view_for_proposal(&rng, views);
        try testing.expect(ahead == 21 or ahead == 22);
        try testing.expect(future.random_parent_view(&rng, views.based_on(ahead)) < ahead);
        const near = small.random_view_for_proposal(&rng, views);
        try testing.expect(near >= 14 and near <= 21);
        const proposal = small.random_proposal(&rng, views);
        try testing.expectEqual(fuzz_types.epoch, proposal.epoch());
        // A small-scope mutation changes exactly one of view, parent, or payload.
        const mutated = small.mutate_proposal(&rng, proposal, views);
        var changed: u32 = 0;
        if (mutated.view().get() != proposal.view().get()) changed += 1;
        if (mutated.parent.get() != proposal.parent.get()) changed += 1;
        if (mutated.payload.order(proposal.payload) != .eq) changed += 1;
        try testing.expect(changed <= 1);
    }
    const any: Strategy = .any_scope;
    try testing.expectEqual(null, any.fault_bounds());
}

test "mutated bytes keep their length" {
    var rng = utils.rng.TestRng.init(3);
    const strategies = [_]Strategy{
        .any_scope,
        .{ .small_scope = .{ .fault_rounds = 2, .fault_rounds_bound = 5 } },
    };
    for (strategies) |strategy| {
        const empty = try strategy.mutate_bytes(&rng, testing.allocator, &.{});
        defer testing.allocator.free(empty);
        try testing.expectEqualSlices(u8, &.{0}, empty);
        const input = [_]u8{ 1, 2, 3, 4 };
        const out = try strategy.mutate_bytes(&rng, testing.allocator, &input);
        defer testing.allocator.free(out);
        try testing.expectEqual(input.len, out.len);
    }
    // A bit flip differs from its input in exactly one bit.
    const small = strategies[1];
    const flipped = try small.mutate_bytes(&rng, testing.allocator, &.{ 0, 0, 0 });
    defer testing.allocator.free(flipped);
    var bits: u32 = 0;
    for (flipped) |b| bits += @popCount(b);
    try testing.expectEqual(1, bits);
}
