//! The marshal actor's finalized chain (commonware `core/actor.rs`): storing finalized blocks
//! and certificates, floor transitions, gap repair, round floors, pruning, and dispatch to the
//! application. Every function takes the actor (`*actor.Actor(P)`) as `self`.
//!
//! `start_finalized_sync` releases the dispatch gate and resumes dispatch in the same event
//! when the stores' handles are durable at once (the archives' always are); otherwise the
//! actor pools the sync (`Actor.Syncs`) and releases its batch when it becomes durable. The
//! gate holds dispatch at or above a buffered write until a sync covering it is durable.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const resolver_api = @import("resolver");
const types = @import("../../types.zig");
const handler = @import("../resolver/handler.zig");
const floor = @import("floor.zig");
const ingress = @import("actor_ingress.zig");

const Height = types.Height;
const Round = types.Round;
const Cutoff = floor.Cutoff;
const Processed = floor.Processed;

fn height_of(block: anytype) Height {
    return block.inner().height();
}

/// Restores the tip, reopens the cache epochs, installs a configured floor, repairs gaps, and
/// dispatches what is ready, before the actor handles its first event.
pub fn startup(self: anytype) !void {
    if (try get_latest(self)) |latest| {
        try advance_tip(self, latest.round, latest.height, latest.digest);
    }
    // Persisted cache epochs let `find_block` discover blocks written before shutdown.
    try self.cache.load_persisted_epochs();
    // A configured floor follows the same path as `set_floor`.
    if (self.floor.take_configured()) |finalization| {
        try ingress.install_floor(self, finalization);
    }
    if (try try_repair_gaps(self)) try sync_finalized(self);
    try try_dispatch_blocks(self);
    assert(self.stream.is_synced());
}

/// Notifies subscribers of a validated block (borrowed) and applies it to a pending floor.
/// Returns whether the block was consumed as the floor anchor.
///
/// Subscribers hear of the block before it is persisted; subscriptions make no durability
/// promise. Durable height-ordered delivery is application dispatch.
pub fn ingest(self: anytype, block: anytype) !bool {
    const V = @TypeOf(self.*).V;
    self.block_subscriptions.notify(self.gpa, block);
    var finalization = self.floor.take_matching(V.commitment(block)) orelse return false;
    defer finalization.deinit(self.gpa);
    try apply_floor(self, &finalization, block);
    return true;
}

/// Applies the floor transition `finalization` announces with its anchor `block` (both
/// borrowed).
fn apply_floor(self: anytype, finalization: anytype, block: anytype) !void {
    const V = @TypeOf(self.*).V;
    const height = height_of(block);
    // Floor anchors can bypass proposal verification, so check the parent link first.
    if (height.get() > 0) {
        const parent_commitment = V.parent_commitment(block);
        if (!block.inner().parent().eql(V.commitment_to_inner(parent_commitment))) {
            @panic("floor block parent commitment mismatch");
        }
    }
    // An anchor at or below the processed height cannot move the sync point, but its round
    // still raises the round floor, which is synced so a restart treats it as superseded.
    if (height.get() <= self.floor.processed_height().get()) {
        try witness_round(self, height, finalization.round());
        try self.stream.sync();
        if (try try_repair_gaps(self)) try sync_finalized(self);
        return try_dispatch_blocks(self);
    }
    const digest = block.digest();
    const round = finalization.round();
    const stored = V.stored_view(block);
    try self.finalized_blocks.put(digest, &stored);
    try self.finalizations_by_height.put(height, digest, finalization);
    try sync_finalized(self);
    try advance_tip(self, round, height, digest);
    try install_anchor(self, height, round);
}

/// Moves the processed position under a durable floor anchor at `height` and resumes.
fn install_anchor(self: anytype, height: Height, round: Round) !void {
    // The application still processes the anchor: dispatch resumes at it.
    const dispatch_floor = height.previous() orelse unreachable; // Proof: above processed.
    try update_processed(self, processed(self, dispatch_floor));
    self.staged.retain(self.gpa, height);
    // Raise the round floor through the anchor's round and every epoch ending at or below
    // it, and persist it with the dispatch floor before pruning finalized data.
    try witness_round(self, dispatch_floor, round);
    try cover_closed_epoch(self, height);
    try self.stream.sync();
    // In-flight acks below the new floor must not rewrite the processed floor.
    self.clear_acks();
    // Keep the processed block so the application can restart from it.
    try prune_after_floor(self, dispatch_floor);
    // Caller subscriptions stay: later local ingress can still satisfy them.
    if (try try_repair_gaps(self)) try sync_finalized(self);
    try try_dispatch_blocks(self);
    assert(self.floor.processed_height().get() == dispatch_floor.get());
}

/// Stores a finalized `block` (borrowed) and its `finalization` (owned, optional) at
/// `height`. Writes above the processed height are buffered for the caller's sync and gate
/// dispatch until then; returns whether the block is above the processed height.
///
/// At or below the processed height only a missing finalization for a stored block is
/// stored (and synced): the newest such finalization is the round-floor evidence restart
/// reads.
pub fn store_finalization(
    self: anytype,
    height: Height,
    block: anytype,
    finalization: anytype,
) !bool {
    const V = @TypeOf(self.*).V;
    var owned = finalization;
    defer if (owned) |*value| value.deinit(self.gpa);
    const digest = block.digest();
    if (height.get() <= self.floor.processed_height().get()) {
        const value = &(owned orelse return false);
        if (!has_finalized_block(self, height)) return false;
        if (try self.finalizations_by_height.has(height)) return false;
        try self.finalizations_by_height.put(height, digest, value);
        try self.finalizations_by_height.sync();
        try advance_tip(self, value.round(), height, digest);
        return false;
    }
    const stored = V.stored_view(block);
    try self.finalized_blocks.put(digest, &stored);
    if (owned) |*value| try self.finalizations_by_height.put(height, digest, value);
    // The write is readable before it is durable: hold dispatch at it until a sync.
    self.dispatch_gate.defer_write(height);
    // A block repaired without its finalization leaves the tip unchanged.
    if (owned) |*value| try advance_tip(self, value.round(), height, digest);
    return true;
}

/// Records `height` as the finalized tip and reports it when above the current tip.
pub fn advance_tip(self: anytype, round: Round, height: Height, digest: anytype) !void {
    if (height.get() <= self.tip.get()) return;
    _ = self.application.report(.{ .tip = .{
        .round = round,
        .height = height,
        .digest = digest,
    } });
    self.tip = height;
    self.certified.retain(height.next());
    _ = self.finalized_height.metric().try_set(height.get()) catch 0;
}

pub fn Latest(comptime D: type) type {
    return struct { height: Height, digest: D, round: Round };
}

/// The newest finalization whose block height is known: the highest stored by height.
pub fn get_latest(self: anytype) !?Latest(@TypeOf(self.*).Digest) {
    const V = @TypeOf(self.*).V;
    const height = self.finalizations_by_height.last_index() orelse return null;
    var finalization = try get_finalization_by_height(self, height) orelse
        @panic("finalization missing");
    defer finalization.deinit(self.gpa);
    return .{
        .height = height,
        .digest = V.commitment_to_inner(finalization.proposal.payload),
        .round = finalization.round(),
    };
}

/// Sends dispatchable finalized blocks to the application until the pipeline is full, and
/// watches the oldest acknowledgement. Only durable blocks go out (see `DispatchGate`); acks
/// advance the processed height later, in order.
pub fn try_dispatch_blocks(self: anytype) !void {
    const Actor = @TypeOf(self.*);
    defer assert(self.pending_acks.current() == null or self.ack_watch != null);
    // Dispatch resumes once the floor anchor is stored.
    if (self.floor.blocks_progress()) return;
    const barrier = self.dispatch_gate.barrier();
    while (self.pending_acks.has_capacity()) {
        const next_height = self.pending_acks.next_dispatch_height(self.stream.next_height());
        if (barrier) |lowest| if (next_height.get() >= lowest.get()) break;
        // Prefer the staged block and fall back to the archive.
        var block = self.staged.remove(next_height) orelse block: {
            const stored = try get_finalized_block(self, next_height) orelse break;
            break :block try restore_across(self, stored);
        };
        var block_owned = true;
        defer if (block_owned) Actor.V.deinit_block(self.gpa, &block);
        if (height_of(&block).get() != next_height.get()) {
            @panic("finalized block height mismatch");
        }
        const handle = try Actor.A.handle(self.gpa, self.io);
        self.pending_acks.enqueue(.{ .height = next_height, .waiter = handle.waiter });
        block_owned = false;
        _ = self.application.report(.{ .block = .{
            .block = Actor.V.into_shared(block),
            .ack = handle.acknowledgement,
        } });
        self.staged.retain(self.gpa, next_height.next());
    }
    try self.arm_ack();
}

/// Syncs both finalized archives; everything written before is durable afterwards.
pub fn sync_finalized(self: anytype) !void {
    try self.finalized_blocks.sync();
    try self.finalizations_by_height.sync();
    self.dispatch_gate.clear();
    assert(self.dispatch_gate.barrier() == null);
}

/// Starts a sync of the finalized archives if anything was written since the last sync; the
/// writes it covers are released for dispatch once it completes (commonware's pooled sync).
pub fn start_finalized_sync(self: anytype) !void {
    const seq = try self.dispatch_gate.adopt(self.gpa) orelse return;
    const blocks = try self.finalized_blocks.start_sync();
    const finalizations = self.finalizations_by_height.start_sync() catch |err| {
        blocks.release();
        return err;
    };
    return self.settle(.{ .finalized = seq }, try blocks.join(finalizations));
}

/// A finalized block in its stored form (owned by the caller).
pub fn get_finalized_block(self: anytype, height: Height) !?@TypeOf(self.*).V.StoredBlock {
    return self.finalized_blocks.get(.{ .index = height });
}

/// Whether the archive holds a finalized block at `height`, without reading it.
pub fn has_finalized_block(self: anytype, height: Height) bool {
    const current_end, _ = self.finalized_blocks.next_gap(height);
    return current_end != null;
}

pub fn get_finalization_by_height(
    self: anytype,
    height: Height,
) !?@TypeOf(self.*).Finalization {
    return self.finalizations_by_height.get(.{ .index = height });
}

/// Restores a stored block (taking ownership) across the strategy.
pub fn restore_across(self: anytype, stored: anytype) !@TypeOf(self.*).Block {
    const V = @TypeOf(self.*).V;
    return V.restore_across(self.gpa, stored, self.strategy) catch |err| {
        codec.free(V.StoredBlock, self.gpa, stored);
        return err;
    };
}

/// Restores a stored block (taking ownership) under its known `digest`.
pub fn restore(self: anytype, stored: anytype, digest: anytype) !@TypeOf(self.*).Block {
    const V = @TypeOf(self.*).V;
    return V.restore(self.gpa, stored, digest) catch |err| {
        codec.free(V.StoredBlock, self.gpa, stored);
        return err;
    };
}

/// Matches any cached block.
const AnyBlock = struct {
    pub fn matches(_: AnyBlock, _: anytype) bool {
        return true;
    }
};

fn Matching(comptime V: type) type {
    return struct {
        commitment: V.Commitment,

        pub fn matches(self: @This(), block: *const V.Block) bool {
            return V.commitment(block).eql(self.commitment);
        }
    };
}

/// A block from the cache or the finalized archive by digest (owned by the caller).
pub fn find_block_in_storage(self: anytype, digest: anytype) !?@TypeOf(self.*).Block {
    if (try self.cache.find_block_matching(digest, AnyBlock{})) |block| return block;
    const stored = try self.finalized_blocks.get(.{ .key = digest }) orelse return null;
    return try restore(self, stored, digest);
}

/// A block from the cache or the finalized archive by full commitment.
pub fn find_block_in_storage_by_commitment(
    self: anytype,
    commitment: anytype,
) !?@TypeOf(self.*).Block {
    const V = @TypeOf(self.*).V;
    const digest = V.commitment_to_inner(commitment);
    const matching: Matching(V) = .{ .commitment = commitment };
    if (try self.cache.find_block_matching(digest, matching)) |block| return block;
    const stored = try self.finalized_blocks.get(.{ .key = digest }) orelse return null;
    var block = try restore(self, stored, digest);
    if (V.commitment(&block).eql(commitment)) return block;
    V.deinit_block(self.gpa, &block);
    return null;
}

/// A block from the buffer, the cache, or the finalized archive by digest.
pub fn find_block_by_digest(self: anytype, digest: anytype) !?@TypeOf(self.*).Block {
    if (try self.buffer.find_by_digest(digest)) |block| return block;
    return find_block_in_storage(self, digest);
}

/// A block from the buffer, the cache, or the finalized archive by full commitment.
pub fn find_block_by_commitment(self: anytype, commitment: anytype) !?@TypeOf(self.*).Block {
    if (try self.buffer.find_by_commitment(commitment)) |block| return block;
    return find_block_in_storage_by_commitment(self, commitment);
}

/// Repairs gaps in the finalized blocks archive above the processed height, walking each
/// gap back from its end through local blocks; the first missing block is requested by
/// commitment, which ends this pass. Up to `max_repair` of the lowest missing heights are
/// also requested by finalization. A trailing finalization without its block is anchored
/// first. Writes are buffered; returns whether any happened (the caller syncs).
pub fn try_repair_gaps(self: anytype) !bool {
    // Repair needs a known processed floor; a pending floor may jump it.
    if (self.floor.blocks_progress()) return false;
    const start = self.floor.processed_height().next();
    var wrote = try repair_trailing(self);
    switch (try repair_walkback(self, start, &wrote)) {
        .no_gaps => return wrote,
        .requested => {},
    }
    const gpa = self.gpa;
    const out = try gpa.alloc(u64, self.max_repair);
    defer gpa.free(out);
    const missing = self.finalized_blocks.missing_items(start, out);
    const heights = try gpa.alloc(Height, missing.len);
    defer gpa.free(heights);
    for (missing, heights) |item, *height| height.* = .new(item);
    _ = try self.floor.fetch_finalizations_if_permitted(gpa, &self.resolver, heights);
    return wrote;
}

/// Stores the block of a finalization stored beyond the last stored block, or requests it.
fn repair_trailing(self: anytype) !bool {
    const last_finalized = self.finalizations_by_height.last_index() orelse return false;
    const have_block = if (self.finalized_blocks.last_index()) |last|
        last.get() >= last_finalized.get()
    else
        false;
    if (last_finalized.get() <= self.floor.processed_height().get() or have_block) return false;
    var finalization = try get_finalization_by_height(self, last_finalized) orelse
        @panic("finalization missing");
    const commitment = finalization.proposal.payload;
    const found_or_null = find_block_by_commitment(self, commitment) catch |err| {
        finalization.deinit(self.gpa);
        return err;
    };
    if (found_or_null) |found| {
        var block = found;
        defer @TypeOf(self.*).V.deinit_block(self.gpa, &block);
        return store_finalization(self, last_finalized, &block, @as(
            ?@TypeOf(finalization),
            finalization,
        ));
    }
    finalization.deinit(self.gpa);
    _ = try self.floor.fetch_if_permitted(&self.resolver, .{ .finalized_by_height = .{
        .commitment = commitment,
        .bound = last_finalized,
    } });
    return false;
}

const Walkback = enum { no_gaps, requested };

/// Fills gaps backward from each gap's end block until a block is missing locally.
fn repair_walkback(self: anytype, start: Height, wrote: *bool) !Walkback {
    const V = @TypeOf(self.*).V;
    while (true) {
        const gap_start, const gap_end_or_null = self.finalized_blocks.next_gap(start);
        const gap_end = gap_end_or_null orelse return .no_gaps;
        // The walkback needs only each block's height and parent linkage.
        const cursor = try get_finalized_block(self, gap_end) orelse
            std.debug.panic("gapped block missing that should exist: {d}", .{gap_end.get()});
        var height = cursor.height();
        var parent_digest = cursor.parent();
        var parent_commitment = V.stored_parent_commitment(&cursor);
        codec.free(V.StoredBlock, self.gpa, cursor);
        // Stop above the stored block at `gap_start`, or at `start`.
        const lower = if (gap_start) |stored| stored.next() else start;
        while (height.get() > lower.get()) {
            var block = try find_block_by_commitment(self, parent_commitment) orelse {
                // Finalized blocks are archived only after marshal validated the parent
                // link the walkback follows.
                const parent_height = height.previous() orelse unreachable;
                _ = try self.floor.fetch_if_permitted(&self.resolver, .{
                    .finalized_by_height = .{
                        .commitment = parent_commitment,
                        .bound = parent_height,
                    },
                });
                return .requested;
            };
            defer V.deinit_block(self.gpa, &block);
            const finalization = try self.cache.get_finalization_for(parent_digest);
            height = height_of(&block);
            parent_digest = block.inner().parent();
            parent_commitment = V.parent_commitment(&block);
            if (try store_finalization(self, height, &block, finalization)) wrote.* = true;
        }
    }
}

/// Buffers a processed height in memory and metrics; the caller syncs the stream.
pub fn update_processed(self: anytype, value: Processed) !void {
    const Actor = @TypeOf(self.*);
    const height = value.height();
    try self.stream.acknowledge(height);
    self.floor.set_processed(value);
    _ = self.processed_height.metric().try_set(self.floor.processed_height().get()) catch 0;
    // Resolver request retention is independent of caller-owned block subscriptions.
    const Predicate = resolver_api.Predicate(Actor.Key, handler.Annotation);
    const retain = struct {
        fn above(floor_height: Height, key: Actor.Key, annotation: handler.Annotation) bool {
            return handler.above_height_floor(Actor.Commitment, floor_height, key, annotation);
        }
    }.above;
    _ = try self.resolver.retain(Predicate.init(height, retain));
}

/// Classifies a processed height by whether its block is stored.
pub fn processed(self: anytype, height: Height) Processed {
    if (has_finalized_block(self, height)) return .{ .block = height };
    return .{ .absent = height };
}

/// The height of the newest stored finalization at or below `height`.
pub fn latest_finalization_height(self: anytype, height: Height) ?Height {
    var best: ?u64 = null;
    for (self.finalizations_by_height.ranges_from(.zero())) |range| {
        if (range.start > height.get()) continue;
        const end = @min(range.end, height.get());
        if (best == null or end > best.?) best = end;
    }
    return if (best) |value| .new(value) else null;
}

pub const Derived = struct { cutoff: Cutoff, witnessed: Round };

/// The round floor the archives and the epocher justify, and the newest archived
/// finalization round of a processed block or its durable successor.
///
/// The floor covers that round and every epoch ending at or below the processed height, or
/// at or below the successor when its block and finalization are both archived.
pub fn derive_cutoff(self: anytype, processed_height: ?Height) !Derived {
    var processed_round: Round = .zero();
    if (processed_height) |height| {
        if (latest_finalization_height(self, height)) |finalization_height| {
            var finalization = try get_finalization_by_height(self, finalization_height) orelse
                @panic("processed finalization missing from stored range");
            defer finalization.deinit(self.gpa);
            processed_round = finalization.round();
        }
    }
    var witnessed = processed_round;
    var anchor = processed_height;
    if (try durable_successor(self, processed_height)) |successor| {
        if (successor.round.order(witnessed) == .gt) witnessed = successor.round;
        anchor = successor.height;
    }
    var cutoff: Cutoff = .{ .round = witnessed };
    if (anchor) |height| {
        if (floor.closed_epoch(self.epocher, height)) |epoch| {
            cutoff = cutoff.max(.{ .epoch = epoch });
        }
    }
    return .{ .cutoff = cutoff, .witnessed = witnessed };
}

const Successor = struct { height: Height, round: Round };

/// The block just above `processed_height` (height zero when nothing is processed) and its
/// finalization round, if both are archived.
fn durable_successor(self: anytype, processed_height: ?Height) !?Successor {
    const V = @TypeOf(self.*).V;
    const successor: Height = if (processed_height) |height| successor: {
        if (height.get() == std.math.maxInt(u64)) return null;
        break :successor height.next();
    } else .zero();
    const stored = try get_finalized_block(self, successor) orelse return null;
    var finalization = try get_finalization_by_height(self, successor) orelse {
        codec.free(V.StoredBlock, self.gpa, stored);
        return null;
    };
    defer finalization.deinit(self.gpa);
    var block = try restore_across(self, stored);
    defer V.deinit_block(self.gpa, &block);
    if (!V.commitment(&block).eql(finalization.proposal.payload)) {
        @panic("successor block does not match stored finalization");
    }
    return .{ .height = successor, .round = finalization.round() };
}

/// Raises the round floor for an acknowledged block to its archived finalization, if any,
/// and every epoch ending at or below it (buffered like `raise_cutoff`).
pub fn cover_processed(self: anytype, height: Height) !void {
    if (try get_finalization_by_height(self, height)) |found| {
        var finalization = found;
        defer finalization.deinit(self.gpa);
        try witness_round(self, height, finalization.round());
    }
    try cover_closed_epoch(self, height);
}

/// Raises the round floor over every epoch that ends at or below `anchor`.
fn cover_closed_epoch(self: anytype, anchor: Height) !void {
    const epoch = floor.closed_epoch(self.epocher, anchor) orelse return;
    try raise_cutoff(self, .{ .epoch = epoch });
}

/// Witnesses `round` and raises the round floor through it, if `height` is processed. The
/// caller syncs the stream before the actor handles its next event.
pub fn witness_round(self: anytype, height: Height, round: Round) !void {
    if (height.get() > self.floor.processed_height().get()) return;
    // Keep `view_retention` views of cached data behind the previously witnessed round.
    if (self.floor.witness(round)) |previous| {
        const retained = floor.retained_from(self.epocher, previous, self.view_retention);
        try self.cache.prune_by_view(retained);
    }
    try raise_cutoff(self, .{ .round = round });
}

/// Raises the round floor to `cutoff`, buffers it in the stream, and prunes round-bound
/// requests it covers. A pending floor anchor whose round it covers is released, and repair
/// and dispatch resume.
fn raise_cutoff(self: anytype, cutoff: Cutoff) !void {
    const Actor = @TypeOf(self.*);
    if (cutoff.order(self.floor.cutoff) != .gt) return;
    self.floor.set_cutoff(cutoff);
    try self.stream.set_cutoff(cutoff);
    const Predicate = resolver_api.Predicate(Actor.Key, handler.Annotation);
    const retain = struct {
        fn above(floor_cutoff: Cutoff, key: Actor.Key, annotation: handler.Annotation) bool {
            return handler.above_round_floor(Actor.Commitment, floor_cutoff, key, annotation);
        }
    }.above;
    _ = try self.resolver.retain(Predicate.init(cutoff, retain));
    // Finalized rounds and heights rise together, so a pending anchor whose round is covered
    // sits at or below the processed height: its floor is already active.
    const pending = self.floor.pending_finalization() orelse return;
    if (!cutoff.covers(pending.round())) return;
    self.floor.clear_pending(self.gpa);
    if (try try_repair_gaps(self)) try sync_finalized(self);
    try try_dispatch_blocks(self);
}

/// Prunes finalized blocks below `height`, and certificates below the lower of `height` and
/// the newest finalization at or below the processed height (restart reads its round).
pub fn prune_finalized_archives(self: anytype, height: Height) !void {
    const retained = latest_finalization_height(self, self.floor.processed_height());
    const certificate_height = if (retained) |value|
        Height.new(@min(value.get(), height.get()))
    else
        height;
    try self.finalized_blocks.prune(height);
    try self.finalizations_by_height.prune(certificate_height);
}

/// Prunes the finalized archives and height-indexed certified cache data below `height`.
fn prune_after_floor(self: anytype, height: Height) !void {
    try self.cache.prune_by_height(height);
    try self.finalized_blocks.prune(height);
    try self.finalizations_by_height.prune(height);
}
