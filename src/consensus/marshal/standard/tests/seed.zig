//! Writes a validator's storage directly, bypassing the actor, to manufacture the states a
//! crash leaves behind (commonware `standard/mod.rs`'s `seed_*` test helpers).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const runtime = @import("runtime");
const storage = @import("storage");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const cache_api = @import("../../core/cache.zig");

const H = harness.StandardHarness;
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;

/// A finalization stored at `height` of the finalizations-by-height archive.
pub const FinalizationAt = struct {
    height: Height,
    finalization: harness.Finalization,
};

/// Writes `blocks` and `finalizations` (all borrowed) into the finalized archives of the
/// validator with partition `prefix` and syncs them. A finalization without its block is an
/// inconsistent state a crash between the two writes leaves (`seed_inconsistent_restart_state`).
pub fn inconsistent_restart_state(
    ctx: Ctx,
    prefix: []const u8,
    blocks: []const H.TestBlock,
    finalizations: []const FinalizationAt,
) !void {
    assert(prefix.len > 0);
    var archives: harness.Archives(harness.B) = undefined;
    try archives.open(ctx, prefix);
    defer archives.deinit();
    for (blocks) |*block| {
        try archives.blocks.put(H.height(block).get(), H.digest(block).bytes, block.inner().*);
    }
    try archives.blocks.sync();
    for (finalizations) |*entry| {
        const payload = entry.finalization.proposal.payload;
        try archives.finalizations.put(entry.height.get(), payload.bytes, entry.finalization);
    }
    try archives.finalizations.sync();
    for (finalizations) |*entry| {
        assert(try archives.finalizations.has(.{ .index = entry.height.get() }));
    }
}

/// The application metadata keys (`core/stream.zig`).
const latest_key: u64 = 0xFF;
const cutoff_epoch_key: u64 = 0xFE;
const cutoff_view_key: u64 = 0xFD;

/// Replaces the validator's application metadata with a store that holds `height` as the
/// processed height and, when given, `round` as the round floor. The store holds no epoch
/// cutoff, so a restart derives any higher floor from the archives and the epocher
/// (`seed_processed_height`).
pub fn processed_height(ctx: Ctx, prefix: []const u8, height: Height, round: ?Round) !void {
    const Value = codec.UInt(u64);
    var name: [192]u8 = undefined;
    const partition = try std.fmt.bufPrint(&name, "{s}-application-metadata", .{prefix});
    var metadata: storage.metadata.Metadata(u64, Value) = try .init(ctx.gpa(), ctx.storage, .{
        .partition = partition,
        .codec_config = {},
    });
    defer metadata.deinit();
    metadata.clear();
    _ = try metadata.put(latest_key, .{ .value = height.get() });
    if (round) |value| {
        _ = try metadata.put(cutoff_epoch_key, .{ .value = value.epoch.get() });
        _ = try metadata.put(cutoff_view_key, .{ .value = value.view.get() });
    }
    try metadata.sync();
    assert(metadata.get(latest_key).?.value == height.get());
}

/// Writes `block` (borrowed) into the per-epoch notarized cache at `round`, as a block that was
/// notarized but never finalized before a crash (`seed_cache_block`).
pub fn cache_block(ctx: Ctx, prefix: []const u8, round: Round, block: *const H.TestBlock) !void {
    const gpa = ctx.gpa();
    var cache_ref: runtime.buffer.paged.CacheRef = try .init(
        gpa,
        harness.page_size,
        harness.page_cache_size,
    );
    defer cache_ref.deinit();
    var name: [192]u8 = undefined;
    const cache_prefix = try std.fmt.bufPrint(&name, "{s}-cache", .{prefix});
    const Manager = cache_api.Manager(H.Variant, harness.S);
    var cache: Manager = try .init(gpa, ctx.storage, ctx.scope.child("seed_cache"), .{
        .partition_prefix = cache_prefix,
        .prunable_items_per_section = 10,
        .replay_buffer = 1024,
        .key_write_buffer = 1024,
        .value_write_buffer = 1024,
        .key_page_cache = &cache_ref,
    }, {});
    defer cache.deinit();
    try cache.load_persisted_epochs();
    assert(prefix.len > 0);
    try (try cache.put_notarized(round, H.digest(block), block)).wait_release();
}
