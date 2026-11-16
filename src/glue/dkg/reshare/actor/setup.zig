//! Epoch setup helpers of the reshare actor (commonware `reshare/actor/setup.rs`).
//!
//! The free functions setup uses to choose where the actor resumes, recover this node's
//! share, register an epoch's scheme before opening the fence, and keep a recovered dealer
//! only while it can still produce a selectable log.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const consensus = @import("consensus");
const utils = @import("utils");
const dkg = @import("../../root.zig");
const types = @import("../../types.zig");
const Fence = @import("../../fence.zig").Fence;

const Epoch = consensus.Epoch;
const EpochPhase = consensus.types.EpochPhase;
const FixedEpocher = consensus.types.FixedEpocher;
const Height = consensus.Height;
const Processed = consensus.marshal.core.floor.Processed;
const Share = @import("cryptography").bls12381.primitives.group.Share;

/// Height and digest of the latest finalized block the actor has applied.
pub fn FinalizedTip(comptime D: type) type {
    return struct { height: Height, digest: D };
}

/// Whether a state-sync floor lies after its epoch's midpoint, so the blocks it skipped may
/// have carried dealer logs.
pub fn state_sync_skips_inclusion_prefix(epocher: FixedEpocher, floor: ?Height) bool {
    const height = floor orelse return false;
    const bounds = epocher.containing(height) orelse @panic("epocher must know state sync floor");
    assert(bounds.first.get() <= height.get());
    return bounds.phase() == .late;
}

/// The later of marshal's processed position and the parent of the state-sync floor (null
/// when neither exists). `processed` pairs the position with the stored block that backs it:
/// the processed block, or its child when the processed block is absent. Borrows its blocks.
pub fn startup(
    comptime B: type,
    processed: ?struct { Processed, *const B },
    floor: ?*const B,
) ?FinalizedTip(B.Digest) {
    const Tip = FinalizedTip(B.Digest);
    const from_processed: ?Tip = if (processed) |entry| switch (entry[0]) {
        .block => |height| .{ .height = height, .digest = entry[1].digest() },
        .absent => |height| .{ .height = height, .digest = entry[1].inner().parent() },
    } else null;
    const from_floor: ?Tip = if (floor) |block| blk: {
        const height = block.inner().height().previous() orelse break :blk null;
        break :blk .{ .height = height, .digest = block.inner().parent() };
    } else null;
    const tip = from_processed orelse return from_floor;
    const other = from_floor orelse return tip;
    const result = if (other.height.get() > tip.height.get()) other else tip;
    assert(result.height.get() >= tip.height.get());
    assert(result.height.get() >= other.height.get());
    return result;
}

/// `public_key`'s share of `info.output`.
///
/// The share stored for `info.epoch` is returned when present. A failed ceremony carries the
/// previous output forward, so when none is stored for a failed epoch, the search walks back
/// to the newest share stored under an earlier epoch and returns it only if the output's
/// public polynomial confirms it as `public_key`'s share.
pub fn recovered_share(
    comptime V: type,
    store: anytype,
    public_key: anytype,
    info: anytype,
) !?Share {
    if (try store.share(info.epoch)) |share| return share;
    if (info.outcome != .failure) return null;
    const index = info.output.players.position(public_key) orelse return null;
    const expected = info.output.public.partial_public(.from_usize(index)) catch return null;
    var epoch = info.epoch;
    // Each pass moves one epoch down: at most `info.epoch` passes.
    while (epoch.previous()) |previous| : (epoch = previous) {
        assert(previous.get() < info.epoch.get());
        const share = try store.share(previous) orelse continue;
        return if (share.public(V).eql(expected)) share else null;
    }
    return null;
}

/// Registers `scheme_info` for `epoch` (the registrar takes it), then marks `fence`, so a gate
/// waiting on `epoch` opens only once the consensus provider serves the scheme.
pub fn register_and_mark(
    registrar: anytype,
    io: Io,
    fence: *Fence,
    epoch: Epoch,
    scheme_info: anytype,
) !void {
    comptime dkg.assert_registrar(@TypeOf(registrar.*));
    try registrar.register(io, epoch, scheme_info);
    fence.mark(epoch);
}

/// Keeps a dealer that can still produce a selectable log; frees and drops any other.
///
/// During the early phase, missing acknowledgements can still arrive. Afterward, a recovered
/// dealer is useful only when its durable acknowledgements already form a quorum.
pub fn dealer_for_phase(phase: EpochPhase, players: usize, dealer: anytype) @TypeOf(dealer) {
    var kept = dealer orelse return null;
    assert(players > 0);
    if (phase == .early or kept.has_acknowledgement_quorum(utils.N3f1, players)) return kept;
    kept.deinit();
    return null;
}

test {
    _ = @import("setup_test.zig");
}
