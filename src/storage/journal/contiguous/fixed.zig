//! An append-only log of fixed-length items (commonware's `journal/contiguous/fixed.rs`).
//!
//! Items are read by their position, the order of insertion starting from 0, which pruning
//! does not change.
//!
//! # Format
//!
//! Items are stored in blobs of at most `items_per_blob` items each, with page-level
//! integrity (`runtime.buffer.paged`). The newest blob may hold fewer items.
//!
//! ```text
//! +--------+--------+-----+----------+
//! | item_0 | item_1 | ... | item_n-1 |
//! +--------+--------+-----+----------+
//! ```
//!
//! Blobs live in the legacy partition (`cfg.partition`) if it already holds data, otherwise in
//! `{cfg.partition}-blobs`. The checkpoint (mid-blob pruning boundary, recovery watermark, and
//! any in-progress clear) lives in `{cfg.partition}-metadata`.
//!
//! # Recovery
//!
//! Blobs fill sequentially. Recovery walks them from oldest to newest and compares each blob's
//! item count to its capacity: a short or missing non-newest blob is a gap, so recovery stops
//! there and truncates newer blobs; the newest blob may be short. Only the two newest blobs
//! can hold non-durable data, so recovery re-reads them from the acknowledged prefix (the
//! watermark, lowered by a bounded open to its cap) and truncates each at the first missing or
//! corrupt page. A blob that no longer backs its acknowledged items fails init with
//! `Corruption`, as does a persisted watermark beyond the recovered size.
//!
//! # Watermark
//!
//! The watermark never exceeds what is durably on disk. `sync` completes its data sync before
//! writing the watermark. Syncs complete synchronously here, so `start_sync` advances the
//! watermark to the current size as well (commonware advances it to the last observed sync).
//!
//! # Clearing
//!
//! A clear records its target in the checkpoint before deleting any blob, so a crash mid-clear
//! is finished on reopen. `clear_to_size` clears an open journal; `init_at_size` opens straight
//! into an empty journal at a given size.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const Storage = runtime.storage.Storage;
const contiguous = @import("mod.zig");
const blobs_mod = @import("blobs.zig");
const checkpoint_mod = @import("checkpoint.zig");
const durability = @import("../durability.zig");

const Bounds = contiguous.Bounds;
const Checkpoint = checkpoint_mod.Checkpoint;
const Partition = blobs_mod.Partition;
const PendingBlob = blobs_mod.PendingBlob;
const Writable = blobs_mod.Writable;
const position_to_blob = contiguous.position_to_blob;

pub const Error = blobs_mod.Error || checkpoint_mod.Error;

/// Configuration for the fixed contiguous journal.
pub const Config = struct {
    /// Prefix of the journal's partitions.
    partition: []const u8,
    /// The maximum number of items in each blob.
    items_per_blob: u64,
    /// The page cache shared by the journal's blobs.
    cache_ref: *paged.CacheRef,
    /// Write buffer size of each blob.
    write_buffer: usize,
    /// Buffer size for sequential reads during recovery and replay.
    replay_buffer: usize,
};

/// A sync completion that has already succeeded: syncs complete synchronously.
const Done = struct {
    pub fn poll(_: *Done) ?bool {
        return true;
    }
};
const Barrier = durability.Barrier(Done);

/// The first retained position in `blob`.
fn first_in_blob(pruning_boundary: u64, blob: u64, items_per_blob: u64) Error!u64 {
    const start = try contiguous.blob_first_position(blob, items_per_blob);
    return @max(pruning_boundary, start);
}

/// The pruning boundary from the checkpoint hint if it still matches the oldest blob. A
/// missing or blob-aligned hint means the oldest blob is authoritative.
pub fn recover_pruning_boundary(hint: ?u64, oldest_blob: ?u64, items_per_blob: u64) Error!u64 {
    assert(items_per_blob > 0);
    const blob_boundary = if (oldest_blob) |oldest|
        try contiguous.blob_first_position(oldest, items_per_blob)
    else
        0;
    const boundary_hint = hint orelse return blob_boundary;
    if (boundary_hint % items_per_blob == 0) return blob_boundary;
    const hint_blob = position_to_blob(boundary_hint, items_per_blob);
    // A mid-blob hint with no blobs, or one ahead of blob state, should never arise.
    const oldest = oldest_blob orelse return error.Corruption;
    if (hint_blob == oldest) return boundary_hint;
    // A stale hint (the blob was pruned since) falls back to the blobs.
    if (hint_blob < oldest) return blob_boundary;
    return error.Corruption;
}

/// The recovered size and the watermark to persist.
const RecoveredBounds = struct { size: u64, watermark: u64 };

fn find_pending(pending: []PendingBlob, index: u64) ?*PendingBlob {
    for (pending) |*entry| if (entry.index == index) return entry;
    return null;
}

/// Storage under recovery, before appends or reads are available.
pub fn Recovery(comptime A: type) type {
    return struct {
        const Self = @This();
        const chunk: usize = Journal(A).chunk;
        const chunk_u64: u64 = chunk;
        /// The item type (`BackingRecovery`).
        pub const Item = A;

        gpa: Allocator,
        storage: Storage,
        /// `cfg.partition` points at the owned `prefix`.
        cfg: Config,
        prefix: []u8,
        checkpoint: Checkpoint,
        /// The active blob partition; null once publication moved it into the journal.
        partition: ?Partition = null,
        /// Opened recovery blobs by ascending index, including suffix candidates.
        pending: std.ArrayList(PendingBlob) = .empty,
        /// Blob indexes excluded by the cap; repair removes them unless needed as the tail.
        discarded: std.ArrayList(u64) = .empty,
        /// The selected item range.
        bounds: Bounds = .{ .start = 0, .end = 0 },
        /// Durable lower bound on the item end, lowered before removing a suffix.
        watermark: u64 = 0,
        /// Whether an explicit cap requires publication to persist the selected end.
        bounded: bool = false,

        fn init_empty(gpa: Allocator, storage: Storage, cfg: Config) Error!Self {
            assert(cfg.items_per_blob > 0);
            const prefix = try gpa.dupe(u8, cfg.partition);
            errdefer gpa.free(prefix);
            var config = cfg;
            config.partition = prefix;
            return .{
                .gpa = gpa,
                .storage = storage,
                .cfg = config,
                .prefix = prefix,
                .checkpoint = try Checkpoint.open(gpa, storage, prefix),
            };
        }

        /// Close every blob and the checkpoint without publishing.
        pub fn deinit(self: *Self) void {
            self.close_blobs();
            self.pending.deinit(self.gpa);
            self.discarded.deinit(self.gpa);
            self.checkpoint.deinit();
            self.gpa.free(self.prefix);
            self.* = undefined;
        }

        fn close_blobs(self: *Self) void {
            for (self.pending.items) |*entry| entry.writer.deinit();
            self.pending.clearRetainingCapacity();
            self.discarded.clearRetainingCapacity();
            if (self.partition) |*partition| partition.deinit();
            self.partition = null;
        }

        /// Open the journal's storage for recovery, completing any interrupted clear. With
        /// `max_size`, blobs that hold only positions at or above it are discarded.
        pub fn open(gpa: Allocator, storage: Storage, cfg: Config, max_size: ?u64) Error!Self {
            return open_dependent(gpa, storage, cfg, max_size, null);
        }

        /// `open`, removing the `dependent` partition before completing a staged clear
        /// (commonware's `init_cleared`), so state cleared under the intent never outlives it.
        pub fn open_dependent(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            max_size: ?u64,
            dependent: ?[]const u8,
        ) Error!Self {
            var self = try init_empty(gpa, storage, cfg);
            errdefer self.deinit();
            const ceiling = max_size orelse std.math.maxInt(u64);
            if (self.checkpoint.clear_target()) |target| {
                if (dependent) |name| try blobs_mod.remove_all(storage, name);
                // A persisted clear is authoritative even when the open requests another cap.
                try self.complete_clear(target);
                if (ceiling < target) return error.ItemPruned;
                return self;
            }
            try self.open_blobs(max_size);
            try self.scan_suspects(ceiling, max_size != null);
            const watermark_hint: ?u64 = if (self.checkpoint.watermark()) |watermark|
                @min(watermark, ceiling)
            else
                null;
            const recovered = try recover_bounds(
                self.pending.items,
                self.cfg.items_per_blob,
                self.bounds.start,
                watermark_hint,
            );
            self.bounds.end = @min(recovered.size, ceiling);
            self.watermark = @min(recovered.watermark, ceiling);
            self.bounded = max_size != null;
            return self;
        }

        /// Select the partition, reconcile the pruning boundary, and open retained blobs.
        fn open_blobs(self: *Self, max_size: ?u64) Error!void {
            const ceiling = max_size orelse std.math.maxInt(u64);
            const items_per_blob = self.cfg.items_per_blob;
            var selected = try blobs_mod.select(self.gpa, self.storage, self.prefix);
            defer selected.deinit(self.gpa);
            self.partition = try Partition.init(
                self.gpa,
                self.storage,
                selected.name,
                self.cfg.cache_ref,
                self.cfg.write_buffer,
            );
            const oldest: ?u64 = if (selected.indices.len > 0) selected.indices[0] else null;
            const hint = self.checkpoint.boundary_hint();
            const boundary = try recover_pruning_boundary(hint, oldest, items_per_blob);
            if (ceiling < boundary) return error.ItemPruned;
            self.bounds = .{ .start = boundary, .end = boundary };
            // Whole discarded blobs need no valid pages or item encodings.
            for (selected.indices) |blob| {
                const first = try first_in_blob(boundary, blob, items_per_blob);
                if (max_size != null and first >= ceiling) {
                    try self.discarded.append(self.gpa, blob);
                    continue;
                }
                try self.pending.ensureUnusedCapacity(self.gpa, 1);
                const writer = try self.partition.?.open_recovery(blob);
                self.pending.appendAssumeCapacity(.{ .index = blob, .writer = writer });
            }
        }

        /// Check the two newest blobs for interior holes before any resize, truncating each
        /// to its recoverable whole-item prefix above the acknowledged prefix.
        fn scan_suspects(self: *Self, ceiling: u64, bounded: bool) Error!void {
            const floor = @min(self.checkpoint.watermark() orelse 0, ceiling);
            const floor_blob = position_to_blob(floor, self.cfg.items_per_blob);
            var checked: usize = 0;
            var index = self.pending.items.len;
            while (checked < 2 and index > 0) : (checked += 1) {
                index -= 1;
                if (self.pending.items[index].index < floor_blob) continue;
                try self.check_suspect(index, floor, floor_blob, ceiling, bounded);
            }
        }

        fn check_suspect(
            self: *Self,
            index: usize,
            floor: u64,
            floor_blob: u64,
            ceiling: u64,
            bounded: bool,
        ) Error!void {
            const items_per_blob = self.cfg.items_per_blob;
            const entry = &self.pending.items[index];
            const first = try first_in_blob(self.bounds.start, entry.index, items_per_blob);
            // Retain the watermark's in-blob prefix in its containing blob and nothing above.
            const acknowledged = if (entry.index == floor_blob)
                try items_to_bytes(floor -| first)
            else
                0;
            const writer = &entry.writer;
            const required_items = @min(ceiling -| first, items_per_blob);
            // A bounded scan runs to the end of the cap's page.
            const limit = if (bounded) blk: {
                const page: u64 = self.cfg.cache_ref.page_size;
                const bytes = required_items *| chunk_u64;
                const rounded = (std.math.divCeil(u64, bytes, page) catch unreachable) *| page;
                break :blk @min(rounded, writer.size());
            } else writer.size();
            const recoverable = try writer.recoverable_prefix_len_at_most(acknowledged, limit);
            const valid_items = recoverable / chunk_u64;
            const valid = try items_to_bytes(valid_items);
            if (valid == writer.size()) return;
            if (bounded and recoverable == limit and valid_items >= required_items) return;
            // Missing acknowledged pages: the blob no longer backs acknowledged items.
            if (valid < acknowledged) return error.Corruption;
            try writer.truncate(valid);
        }

        fn items_to_bytes(items: u64) Error!u64 {
            return std.math.mul(u64, items, chunk_u64) catch error.OffsetOverflow;
        }

        /// Walk blob lengths from oldest to newest, stopping at the first short or missing
        /// non-newest blob. Returns the size and whether a gap ended the walk.
        fn walk_lengths(
            pending: []PendingBlob,
            items_per_blob: u64,
            boundary: u64,
        ) Error!struct { u64, bool } {
            if (pending.len == 0) return .{ boundary, false };
            const newest = pending[pending.len - 1].index;
            var total = boundary;
            var blob = pending[0].index;
            while (true) : (blob += 1) {
                const len = if (find_pending(pending, blob)) |entry|
                    entry.writer.size() / chunk_u64
                else
                    0;
                // The skipped prefix of a mid-blob boundary reduces the capacity.
                const start = try contiguous.blob_first_position(blob, items_per_blob);
                const capacity = items_per_blob - @min(boundary -| start, items_per_blob);
                if (len > capacity) return error.Corruption;
                total = std.math.add(u64, total, len) catch return error.OffsetOverflow;
                // The newest blob is the append frontier; short is normal there.
                if (blob == newest) return .{ total, false };
                // A short or missing interior blob is a gap: everything newer is unreachable.
                if (len < capacity) return .{ total, true };
            }
        }

        /// The recovered size and watermark. A watermark beyond the size is corruption.
        fn recover_bounds(
            pending: []PendingBlob,
            items_per_blob: u64,
            boundary: u64,
            watermark_hint: ?u64,
        ) Error!RecoveredBounds {
            const total, const has_gap = try walk_lengths(pending, items_per_blob, boundary);
            assert(total >= boundary);
            if (watermark_hint) |watermark| {
                if (watermark > total) return error.Corruption;
                return .{ .size = total, .watermark = watermark };
            }
            // A legacy journal (no watermark) with a short non-tail blob violates the old
            // rollover-sync invariant.
            if (has_gap) return error.Corruption;
            // Under that invariant all non-tail blobs are durable.
            const tail_first = try first_in_blob(
                boundary,
                position_to_blob(total, items_per_blob),
                items_per_blob,
            );
            return .{ .size = total, .watermark = tail_first };
        }

        /// Complete the clear to `target` staged in the checkpoint without opening any stored
        /// blob: remove both partitions, recreate the target tail, then drop the intent.
        fn complete_clear(self: *Self, target: u64) Error!void {
            self.close_blobs();
            const new_partition = try std.mem.concat(self.gpa, u8, &.{ self.prefix, "-blobs" });
            defer self.gpa.free(new_partition);
            try blobs_mod.remove_all(self.storage, self.prefix);
            try blobs_mod.remove_all(self.storage, new_partition);
            self.partition = try Partition.init(
                self.gpa,
                self.storage,
                new_partition,
                self.cfg.cache_ref,
                self.cfg.write_buffer,
            );
            const tail = position_to_blob(target, self.cfg.items_per_blob);
            try self.pending.ensureUnusedCapacity(self.gpa, 1);
            const writer = try self.partition.?.open_recovery(tail);
            self.pending.appendAssumeCapacity(.{ .index = tail, .writer = writer });
            try self.checkpoint.finish_clear(self.cfg.items_per_blob, target);
            self.bounds = .{ .start = target, .end = target };
            self.watermark = target;
            // `finish_clear` persisted `target` as the watermark.
            self.bounded = false;
        }

        /// Stage a clear to `size`, then complete it without opening any stored blob.
        pub fn open_cleared(gpa: Allocator, storage: Storage, cfg: Config, target: u64) Error!Self {
            return open_cleared_dependent(gpa, storage, cfg, target, null);
        }

        /// `open_cleared`, removing the `dependent` partition under the staged intent before
        /// completing the clear. A crash after staging leaves an intent the next open completes.
        pub fn open_cleared_dependent(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            target: u64,
            dependent: ?[]const u8,
        ) Error!Self {
            // A journal at `u64::MAX` can never accept an append.
            if (target == std.math.maxInt(u64)) return error.SizeOverflow;
            var self = try init_empty(gpa, storage, cfg);
            errdefer self.deinit();
            try self.checkpoint.stage_clear(target);
            if (dependent) |name| try blobs_mod.remove_all(storage, name);
            try self.complete_clear(target);
            return self;
        }

        /// The exclusive recovered item end.
        pub fn size(self: *const Self) u64 {
            return self.bounds.end;
        }

        /// The first retained item position.
        pub fn pruning_boundary(self: *const Self) u64 {
            return self.bounds.start;
        }

        /// The previously acknowledged item end, bounded by the recovery cap.
        pub fn recovery_watermark(self: *const Self) u64 {
            return self.watermark;
        }

        /// Available item positions, including the retained pruning boundary
        /// (`BackingRecovery::bounds`).
        pub fn get_bounds(self: *const Self) Bounds {
            assert(self.bounds.start <= self.bounds.end);
            return self.bounds;
        }

        /// Read a retained item (`BackingRecovery::read`).
        pub fn read(self: *Self, position: u64) Error!A {
            return self.item(position);
        }

        /// Discard stored items and continue empty at `size_new` (`BackingRecovery::reset`).
        pub fn reset(self: *Self, size_new: u64) Error!void {
            return self.clear_to_size(size_new);
        }

        /// Durably retain at most `max_size` items and publish the committed journal
        /// (`BackingRecovery::finish`). Consumes the recovery, also on error.
        pub fn finish(self: *Self, max_size: u64) Error!Journal(A) {
            var journal = try self.publish(max_size);
            errdefer journal.deinit();
            try journal.commit();
            return journal;
        }

        /// Read an item for recovery selection or validation.
        pub fn item(self: *Self, position: u64) Error!A {
            if (position < self.bounds.start) return error.ItemPruned;
            if (position >= self.bounds.end) return error.ItemOutOfRange;
            const items_per_blob = self.cfg.items_per_blob;
            const blob = position_to_blob(position, items_per_blob);
            const first = try first_in_blob(self.bounds.start, blob, items_per_blob);
            const offset = try items_to_bytes(position - first);
            // Every position inside bounds maps to a pending blob.
            const entry = find_pending(self.pending.items, blob).?;
            var bytes: [chunk]u8 = undefined;
            try entry.writer.read_into(&bytes, offset);
            return codec.decode_fixed(A, &bytes);
        }

        /// The pending writer of `blob`, opening it (as the newest) if missing.
        fn writer_for(self: *Self, blob: u64) Error!*paged.Writer {
            if (find_pending(self.pending.items, blob)) |entry| return &entry.writer;
            const items = self.pending.items;
            assert(items.len == 0 or items[items.len - 1].index < blob);
            try self.pending.ensureUnusedCapacity(self.gpa, 1);
            const writer = try self.partition.?.open_recovery(blob);
            self.pending.appendAssumeCapacity(.{ .index = blob, .writer = writer });
            return &self.pending.items[self.pending.items.len - 1].writer;
        }

        /// Append an item while recovery owns the blobs. The first append must follow a
        /// successful `truncate` or reset.
        pub fn append(self: *Self, value: A) Error!void {
            const position = self.bounds.end;
            const end = std.math.add(u64, position, 1) catch return error.SizeOverflow;
            const items_per_blob = self.cfg.items_per_blob;
            const writer = try self.writer_for(position_to_blob(position, items_per_blob));
            if (writer.try_append_value(A, value) == null) {
                const bytes = codec.encode_fixed(A, value);
                _ = try writer.append(&bytes);
            }
            // Completed blobs stay open until publication; flush them to bound buffers.
            if (end % items_per_blob == 0) try writer.sync();
            self.bounds.end = end;
        }

        /// Durably retain at most `max_size` items before accepting recovery appends.
        pub fn truncate(self: *Self, max_size: u64) Error!void {
            return self.repair_to(max_size);
        }

        /// Durably reconcile blobs and checkpoint to a prefix of at most `max_size` items.
        fn repair_to(self: *Self, max_size: u64) Error!void {
            const size_new = @min(self.bounds.end, max_size);
            if (size_new < self.bounds.start) return error.ItemPruned;
            const items_per_blob = self.cfg.items_per_blob;
            const tail_blob = position_to_blob(size_new, items_per_blob);
            const first = try first_in_blob(self.bounds.start, tail_blob, items_per_blob);
            const bytes = try items_to_bytes(size_new - first);
            // The checkpoint must not acknowledge a suffix once blob removal begins.
            self.watermark = @min(self.watermark, size_new);
            const start = self.bounds.start;
            const hint: ?u64 = if (start % items_per_blob != 0) start else null;
            if (self.checkpoint.watermark() != self.watermark or
                self.checkpoint.boundary_hint() != hint)
            {
                try self.checkpoint.persist(items_per_blob, start, self.watermark);
            }
            try self.keep_boundary_blob(size_new, tail_blob);
            try self.remove_suffix(tail_blob);
            // A truncated tail is durable by truncation; an appended one needs a sync.
            if (find_pending(self.pending.items, tail_blob)) |entry| {
                if (bytes < entry.writer.size()) {
                    try entry.writer.truncate(bytes);
                } else {
                    try entry.writer.sync();
                }
            }
            self.bounds.end = size_new;
        }

        /// An empty prefix needs a durable boundary blob before its last backing blob goes.
        fn keep_boundary_blob(self: *Self, size_new: u64, tail_blob: u64) Error!void {
            if (size_new != self.bounds.start) return;
            const items = self.pending.items;
            const newer = items.len > 0 and items[items.len - 1].index > tail_blob;
            if (self.discarded.items.len == 0 and !newer) return;
            if (find_pending(self.pending.items, tail_blob) == null) {
                var writer = try self.partition.?.open_recovery(tail_blob);
                errdefer writer.deinit();
                try writer.sync();
                try self.insert_pending(tail_blob, writer);
            }
            var kept: usize = 0;
            for (self.discarded.items) |blob| {
                if (blob == tail_blob) continue;
                self.discarded.items[kept] = blob;
                kept += 1;
            }
            self.discarded.items.len = kept;
        }

        fn insert_pending(self: *Self, index: u64, writer: paged.Writer) Allocator.Error!void {
            var position: usize = 0;
            while (position < self.pending.items.len and
                self.pending.items[position].index < index) position += 1;
            assert(position == self.pending.items.len or
                self.pending.items[position].index != index);
            try self.pending.insert(self.gpa, position, .{ .index = index, .writer = writer });
        }

        /// Remove every blob above `tail_blob`, newest first, so every crash cut leaves a
        /// contiguous physical prefix.
        fn remove_suffix(self: *Self, tail_blob: u64) Error!void {
            const partition = &self.partition.?;
            while (self.discarded.pop()) |blob| try partition.remove(blob);
            while (self.pending.items.len > 0) {
                const last = self.pending.items.len - 1;
                if (self.pending.items[last].index <= tail_blob) break;
                var entry = self.pending.pop().?;
                defer entry.writer.deinit();
                try partition.remove(entry.index);
            }
        }

        fn sync_pending(self: *Self) Error!void {
            for (self.pending.items) |*entry| {
                if (entry.writer.needs_sync()) try entry.writer.sync();
            }
        }

        /// Flush recovery data and publish the current end as the watermark.
        pub fn sync(self: *Self) Error!void {
            try self.sync_pending();
            self.watermark = self.bounds.end;
            try self.checkpoint.persist(self.cfg.items_per_blob, self.bounds.start, self.watermark);
        }

        /// Advance the pruning boundary to the whole-blob boundary containing `position`.
        /// Returns whether it moved.
        pub fn prune(self: *Self, position: u64) Error!bool {
            const items_per_blob = self.cfg.items_per_blob;
            const blob = position_to_blob(@min(position, self.bounds.end), items_per_blob);
            const boundary = try contiguous.blob_first_position(blob, items_per_blob);
            if (boundary <= self.bounds.start) return false;
            // Keep the retained position's blob before removing its predecessors.
            if (find_pending(self.pending.items, blob) == null) {
                var writer = try self.partition.?.open_recovery(blob);
                errdefer writer.deinit();
                try self.insert_pending(blob, writer);
            }
            // The retained anchor must be durable before any older blob is removed.
            try self.sync_pending();
            while (self.pending.items.len > 0 and self.pending.items[0].index < blob) {
                var entry = self.pending.orderedRemove(0);
                defer entry.writer.deinit();
                try self.partition.?.remove(entry.index);
            }
            self.bounds.start = boundary;
            return true;
        }

        /// Replace every blob with an empty journal at `size_new`.
        pub fn clear_to_size(self: *Self, size_new: u64) Error!void {
            return self.clear_to_size_dependent(size_new, null);
        }

        /// `clear_to_size`, removing the `dependent` partition under the staged intent
        /// (commonware's `clear_to_size_cleared`).
        pub fn clear_to_size_dependent(
            self: *Self,
            size_new: u64,
            dependent: ?[]const u8,
        ) Error!void {
            if (size_new == std.math.maxInt(u64)) return error.SizeOverflow;
            self.close_blobs();
            // The durable intent makes `size_new` authoritative across every later crash.
            try self.checkpoint.stage_clear(size_new);
            if (dependent) |name| try blobs_mod.remove_all(self.storage, name);
            try self.complete_clear(size_new);
        }

        /// Select a retained prefix of at most `max_size` items and publish the journal.
        /// Consumes the recovery, also on error.
        pub fn publish(self: *Self, max_size: u64) Error!Journal(A) {
            errdefer self.deinit();
            try self.repair_to(max_size);
            const size_new = self.bounds.end;
            const items_per_blob = self.cfg.items_per_blob;
            const tail_blob = position_to_blob(size_new, items_per_blob);
            const partition = self.partition.?;
            self.partition = null;
            const pending = self.pending.items;
            self.pending.items.len = 0;
            var blobs = try Writable.recover(partition, pending, tail_blob);
            errdefer blobs.deinit();
            // A bounded open publishes the selected end once every retained blob is durable.
            if (self.bounded and self.checkpoint.watermark() != size_new) {
                try self.checkpoint.persist(items_per_blob, self.bounds.start, size_new);
            }
            const watermark = self.checkpoint.watermark().?;
            const journal: Journal(A) = .{
                .gpa = self.gpa,
                .prefix = self.prefix,
                .blobs = blobs,
                .checkpoint = self.checkpoint,
                .bounds = .{ .start = self.bounds.start, .end = size_new },
                .items_per_blob = items_per_blob,
                .barrier = .init(watermark),
            };
            self.pending.deinit(self.gpa);
            self.discarded.deinit(self.gpa);
            self.* = undefined;
            return journal;
        }
    };
}

/// Items encoded for a deferred append (`prepare_append`, then `append_prepared`).
pub const PreparedAppend = struct {
    bytes: []u8,

    pub fn deinit(self: *PreparedAppend, gpa: Allocator) void {
        gpa.free(self.bytes);
        self.* = undefined;
    }
};

/// A batch of consecutive items yielded by `Replay.next`: `items[i]` is at `start + i`.
pub fn Batch(comptime A: type) type {
    return struct { start: u64, items: []const A };
}

/// Position-addressed journal of fixed-size items.
///
/// Like sqlite and rocksdb, the first invalid data read above the watermark's acknowledged
/// prefix is the new end of the journal; data below it is never repaired. Mutating methods
/// leave the journal failed after an error; only `deinit` may follow.
pub fn Journal(comptime A: type) type {
    const chunk_size = codec.fixed_size(A) orelse @compileError("journal items must be fixed-size");
    comptime assert(chunk_size > 0);
    comptime assert(!codec.owns_memory(A));
    return struct {
        const Self = @This();
        pub const chunk: usize = chunk_size;
        const chunk_u64: u64 = chunk_size;
        pub const RecoveryType = Recovery(A);
        /// `Backing` names: the configuration and recovery types.
        pub const BackingConfig = Config;
        pub const BackingRecovery = RecoveryType;
        pub const Replay = ReplayType(A);

        gpa: Allocator,
        /// Owned partition prefix.
        prefix: []u8,
        blobs: Writable,
        checkpoint: Checkpoint,
        /// The readable positions; `bounds.end` is the next append position.
        bounds: Bounds,
        items_per_blob: u64,
        /// The known-durable size of the journal.
        barrier: Barrier,
        /// Reused encoding buffer of `append_many`.
        scratch: std.ArrayList(u8) = .empty,
        failed: bool = false,
        /// Metrics.
        items_read: u64 = 0,
        cache_hits: u64 = 0,
        cache_misses: u64 = 0,

        /// Open the journal, recovering every retained item.
        pub fn init(gpa: Allocator, storage: Storage, cfg: Config) Error!Self {
            var recovery = try RecoveryType.open(gpa, storage, cfg, null);
            return recovery.publish(std.math.maxInt(u64));
        }

        /// Open the journal retaining at most `max_size` items: blobs holding only later
        /// positions are discarded unread. Fails with `ItemPruned` below the boundary.
        pub fn init_at_most(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            max_size: u64,
        ) Error!Self {
            var recovery = try RecoveryType.open(gpa, storage, cfg, max_size);
            return recovery.publish(max_size);
        }

        /// Open an empty journal whose next append is at `size`, discarding all data.
        pub fn init_at_size(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            size_new: u64,
        ) Error!Self {
            // Fail before writing intent if existing blob partitions are inconsistent.
            var selected = try blobs_mod.select(gpa, storage, cfg.partition);
            selected.deinit(gpa);
            var recovery = try RecoveryType.open_cleared(gpa, storage, cfg, size_new);
            return recovery.publish(std.math.maxInt(u64));
        }

        /// Open storage for an owner's recovery (commonware's `Backing::recover`).
        pub fn recover(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            max_size: ?u64,
        ) Error!RecoveryType {
            return RecoveryType.open(gpa, storage, cfg, max_size);
        }

        /// Clear storage to an empty journal at `size_new` for an owner's recovery
        /// (commonware's `Backing::clear`).
        pub fn clear(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            size_new: u64,
        ) Error!RecoveryType {
            var checkpoint = try Checkpoint.open(gpa, storage, cfg.partition);
            const staged = checkpoint.clear_target() != null;
            checkpoint.deinit();
            // A staged clear owns both partitions; otherwise fail early if inconsistent.
            if (!staged) {
                var selected = try blobs_mod.select(gpa, storage, cfg.partition);
                selected.deinit(gpa);
            }
            return RecoveryType.open_cleared(gpa, storage, cfg, size_new);
        }

        /// Positions the stored blobs may hold, from blob names and the checkpoint without
        /// opening blob contents (commonware's `Backing::span`). The end is an upper bound.
        pub fn span(gpa: Allocator, storage: Storage, cfg: Config) Error!Bounds {
            var checkpoint = try Checkpoint.open(gpa, storage, cfg.partition);
            defer checkpoint.deinit();
            if (checkpoint.clear_target()) |target| return .{ .start = target, .end = target };
            var selected = try blobs_mod.select(gpa, storage, cfg.partition);
            defer selected.deinit(gpa);
            const indices = selected.indices;
            const oldest: ?u64 = if (indices.len > 0) indices[0] else null;
            const per_blob = cfg.items_per_blob;
            const hint = checkpoint.boundary_hint();
            const start = try recover_pruning_boundary(hint, oldest, per_blob);
            if (indices.len == 0) return .{ .start = start, .end = start };
            const newest = indices[indices.len - 1];
            const first = try contiguous.blob_first_position(newest, per_blob);
            return .{ .start = start, .end = first +| per_blob };
        }

        /// Close every blob (dropping unsynced items).
        pub fn deinit(self: *Self) void {
            self.scratch.deinit(self.gpa);
            self.blobs.deinit();
            self.checkpoint.deinit();
            self.gpa.free(self.prefix);
            self.* = undefined;
        }

        pub fn size(self: *const Self) u64 {
            return self.bounds.end;
        }

        /// The readable positions.
        pub fn get_bounds(self: *const Self) Bounds {
            return self.bounds;
        }

        /// The position before which every item has been pruned.
        pub fn pruning_boundary(self: *const Self) u64 {
            return self.bounds.start;
        }

        /// Durably persist the journal so the current state survives a crash.
        pub fn commit(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.blobs.sync();
            self.barrier.mark_durable(self.bounds.end);
        }

        /// commonware's `start_sync`: the data sync completes synchronously, so the watermark
        /// advances to the current size.
        pub fn start_sync(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.blobs.sync();
            self.barrier.record(self.bounds.end, .{});
            try self.checkpoint.start_watermark_sync(self.barrier.boundary());
        }

        /// Durably persist the journal and its watermark, so no recovery is needed on startup.
        pub fn sync(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            const size_now = self.bounds.end;
            try self.blobs.sync();
            self.barrier.mark_durable(size_now);
            try self.checkpoint.persist(self.items_per_blob, self.bounds.start, size_now);
        }

        /// Append `value`, returning its position.
        pub fn append(self: *Self, value: A) Error!u64 {
            assert(!self.failed);
            const size_new = std.math.add(u64, self.bounds.end, 1) catch return error.SizeOverflow;
            if (self.blobs.tail.try_append_value(A, value) == null) {
                const bytes = codec.encode_fixed(A, value);
                return self.write_encoded(&bytes);
            }
            errdefer self.failed = true;
            try self.advance_tail(size_new);
            return self.bounds.end - 1;
        }

        /// Append `items`, returning the position of the last. Fails with `EmptyAppend` if
        /// there are none.
        pub fn append_many(self: *Self, items: []const A) Error!u64 {
            return self.append_many_nested(&.{items});
        }

        /// Append every slice of `nested` in order, returning the last position.
        pub fn append_many_nested(self: *Self, nested: []const []const A) Error!u64 {
            assert(!self.failed);
            self.scratch.clearRetainingCapacity();
            try encode_items(self.gpa, &self.scratch, nested);
            return self.write_encoded(self.scratch.items);
        }

        fn encode_items(gpa: Allocator, out: *std.ArrayList(u8), nested: []const []const A) !void {
            for (nested) |items| {
                const bytes = try out.addManyAsSlice(gpa, items.len * chunk);
                for (items, 0..) |value, index| {
                    bytes[index * chunk ..][0..chunk].* = codec.encode_fixed(A, value);
                }
            }
            assert(out.items.len % chunk == 0);
        }

        /// Encode `nested` for a later `append_prepared`.
        pub fn prepare_append(
            self: *const Self,
            nested: []const []const A,
        ) Allocator.Error!PreparedAppend {
            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(self.gpa);
            try encode_items(self.gpa, &out, nested);
            return .{ .bytes = try out.toOwnedSlice(self.gpa) };
        }

        /// Append prepared items, freeing them. Returns the last position.
        pub fn append_prepared(self: *Self, prepared: *PreparedAppend) Error!u64 {
            defer prepared.deinit(self.gpa);
            return self.write_encoded(prepared.bytes);
        }

        /// Write encoded items, splitting at blob boundaries so each full tail is sealed.
        fn write_encoded(self: *Self, bytes: []const u8) Error!u64 {
            assert(bytes.len % chunk == 0);
            const count = bytes.len / chunk;
            if (count == 0) return error.EmptyAppend;
            _ = std.math.add(u64, self.bounds.end, count) catch return error.SizeOverflow;
            errdefer self.failed = true;
            var written: usize = 0;
            while (written < count) {
                const batch = contiguous.batch_count_to_blob_boundary(
                    self.bounds.end,
                    count - written,
                    self.items_per_blob,
                );
                const slice = bytes[written * chunk ..][0 .. batch * chunk];
                const tail = &self.blobs.tail;
                if (tail.try_append(slice) == null) _ = try tail.append(slice);
                try self.advance_tail(self.bounds.end + batch);
                written += batch;
            }
            return self.bounds.end - 1;
        }

        /// Advance the end and rotate a full tail.
        fn advance_tail(self: *Self, size_new: u64) Error!void {
            assert(size_new > self.bounds.end);
            self.bounds.end = size_new;
            if (size_new % self.items_per_blob == 0) try self.blobs.seal_tail();
        }

        /// Prune blobs holding only items below `min_position` (capped at the end). Some
        /// earlier items may be retained by blob alignment. Returns whether any were pruned.
        pub fn prune(self: *Self, min_position: u64) Error!bool {
            assert(!self.failed);
            const target_blob = position_to_blob(min_position, self.items_per_blob);
            const tail_blob = position_to_blob(self.bounds.end, self.items_per_blob);
            const min_blob = @min(target_blob, tail_blob);
            if (min_blob <= self.blobs.oldest_blob_index) return false;
            errdefer self.failed = true;
            // Make all data durable before removing any: the prune target may be justified by
            // an unflushed item, and an unsynced survivor could be torn after the removal.
            try self.blobs.sync();
            self.barrier.mark_durable(self.bounds.end);
            const boundary = try contiguous.blob_first_position(min_blob, self.items_per_blob);
            try self.blobs.prune(min_blob);
            self.bounds.start = boundary;
            return true;
        }

        /// Remove every blob and the checkpoint, freeing the journal. An interrupted destroy
        /// reopens either recovered or empty at position zero.
        pub fn destroy(self: *Self) Error!void {
            return self.destroy_cleared(struct {
                fn clear(_: @This()) Error!void {}
            }{});
        }

        /// `destroy`, calling `dependents.clear()` under the staged clear before removing
        /// this journal's blobs, so an interrupted destroy also finishes clearing them.
        pub fn destroy_cleared(self: *Self, dependents: anytype) Error!void {
            assert(!self.failed);
            defer self.* = undefined;
            defer self.gpa.free(self.prefix);
            defer self.scratch.deinit(self.gpa);
            self.checkpoint.stage_clear(0) catch |err| {
                self.blobs.deinit();
                self.checkpoint.deinit();
                return err;
            };
            dependents.clear() catch |err| {
                self.blobs.deinit();
                self.checkpoint.deinit();
                return err;
            };
            self.blobs.destroy() catch |err| {
                self.checkpoint.deinit();
                return err;
            };
            try self.checkpoint.destroy();
        }

        /// Clear all data and continue at `size_new` (at or beyond the end), as if opened with
        /// `init_at_size`. A crash leaves either the prior state or `size_new..size_new`.
        pub fn clear_to_size(self: *Self, size_new: u64) Error!void {
            assert(!self.failed);
            if (size_new < self.bounds.end) return error.ItemOutOfRange;
            if (size_new == std.math.maxInt(u64)) return error.SizeOverflow;
            errdefer self.failed = true;
            try self.checkpoint.stage_clear(size_new);
            try self.blobs.clear(position_to_blob(size_new, self.items_per_blob));
            self.bounds = .{ .start = size_new, .end = size_new };
            self.barrier = .init(size_new);
            try self.checkpoint.finish_clear(self.items_per_blob, size_new);
        }

        /// Durably stage a clear to `size_new` without completing it.
        pub fn stage_clear_intent(self: *Self, size_new: u64) Error!void {
            assert(!self.failed);
            if (size_new == std.math.maxInt(u64)) return error.SizeOverflow;
            if (size_new < self.bounds.end) return error.ItemOutOfRange;
            errdefer self.failed = true;
            try self.checkpoint.stage_clear(size_new);
        }

        fn validate_readable(self: *const Self, position: u64) Error!void {
            if (position >= self.bounds.end) return error.ItemOutOfRange;
            if (position < self.bounds.start) return error.ItemPruned;
        }

        const Located = struct { writer: *paged.Writer, offset: u64 };

        fn locate(self: *Self, position: u64) Error!Located {
            try self.validate_readable(position);
            const blob = position_to_blob(position, self.items_per_blob);
            const first = try first_in_blob(self.bounds.start, blob, self.items_per_blob);
            const offset = std.math.mul(u64, position - first, chunk_u64) catch
                return error.OffsetOverflow;
            // A position in bounds maps to a retained blob.
            return .{ .writer = self.blobs.get(blob).?, .offset = offset };
        }

        /// Read the item at `position`.
        pub fn read(self: *Self, position: u64) Error!A {
            if (self.try_read_sync(position)) |value| return value;
            const located = try self.locate(position);
            self.cache_misses += 1;
            var bytes: [chunk]u8 = undefined;
            try located.writer.read_into(&bytes, located.offset);
            const value = try codec.decode_fixed(A, &bytes);
            self.items_read += 1;
            return value;
        }

        /// Read the items at strictly increasing `positions` into `out`.
        pub fn read_many(self: *Self, positions: []const u64, out: []A) Error!void {
            assert(out.len == positions.len);
            for (positions, 0..) |position, index| {
                if (index > 0) assert(positions[index - 1] < position);
                try self.validate_readable(position);
            }
            for (positions, out) |position, *value| value.* = try self.read(position);
        }

        /// The item if it can be read without I/O; decode failures also decline.
        pub fn try_read_sync(self: *Self, position: u64) ?A {
            const located = self.locate(position) catch return null;
            var bytes: [chunk]u8 = undefined;
            if (!located.writer.try_read_sync_into(&bytes, located.offset)) return null;
            const value = codec.decode_fixed(A, &bytes) catch return null;
            self.cache_hits += 1;
            self.items_read += 1;
            return value;
        }

        /// Probe strictly increasing `positions`, serving those readable without I/O.
        pub fn try_read_many_sync(self: *Self, positions: []const u64, out: []?A) void {
            assert(out.len == positions.len);
            for (positions, out, 0..) |position, *slot, index| {
                if (index > 0) assert(positions[index - 1] < position);
                slot.* = self.try_read_sync(position);
            }
        }

        /// Replay the items in `range` as batches of consecutive items, each within one blob
        /// and of at most about `buffer_bytes` bytes. Fails with `ItemPruned` if the range
        /// starts before the bounds, or `ItemOutOfRange` if it ends after them or is inverted.
        pub fn replay(self: *Self, range: Bounds, buffer_bytes: usize) Error!Replay {
            assert(buffer_bytes > 0);
            if (range.start > range.end or range.end > self.bounds.end) {
                return error.ItemOutOfRange;
            }
            if (range.start < self.bounds.start) return error.ItemPruned;
            return .{
                .journal = self,
                .range = range,
                .buffer_bytes = buffer_bytes,
                .items_per_batch = @max(buffer_bytes / chunk, 1),
                .position = range.start,
            };
        }

        // Test helpers.

        pub fn test_oldest_blob(self: *const Self) u64 {
            return self.blobs.oldest_blob_index;
        }

        pub fn test_newest_blob(self: *const Self) u64 {
            return self.blobs.tail_blob_index();
        }

        /// The persisted recovery watermark.
        pub fn recovery_watermark(self: *const Self) u64 {
            return self.checkpoint.watermark().?;
        }

        /// Durably set the recovery watermark.
        pub fn test_set_recovery_watermark(self: *Self, watermark: u64) Error!void {
            try self.checkpoint.set_watermark(watermark);
            try self.checkpoint.sync();
        }

        /// The watermark persisted for `partition`, without opening the journal.
        pub fn persisted_watermark(
            gpa: Allocator,
            storage: Storage,
            partition: []const u8,
        ) Error!?u64 {
            var checkpoint = try Checkpoint.open(gpa, storage, partition);
            defer checkpoint.deinit();
            return checkpoint.watermark();
        }

        /// Durably stage a clear of `partition` to `target` without opening the journal.
        pub fn test_stage_clear(
            gpa: Allocator,
            storage: Storage,
            partition: []const u8,
            target: u64,
        ) Error!void {
            var checkpoint = try Checkpoint.open(gpa, storage, partition);
            defer checkpoint.deinit();
            try checkpoint.stage_clear(target);
        }
    };
}

/// Sequential replay over a journal's retained blobs (borrows the journal).
fn ReplayType(comptime A: type) type {
    return struct {
        const Self = @This();
        const J = Journal(A);
        const chunk = J.chunk;

        journal: *J,
        range: Bounds,
        buffer_bytes: usize,
        items_per_batch: usize,
        /// Next position to yield.
        position: u64,
        /// The replay of the blob holding `position`, and that blob's exclusive end.
        reader: ?paged.Replay = null,
        blob_end: u64 = 0,
        items: std.ArrayList(A) = .empty,
        /// An error to yield after the batch decoded before it.
        pending_error: ?Error = null,
        done: bool = false,

        pub fn deinit(self: *Self) void {
            if (self.reader) |*reader| reader.deinit();
            self.items.deinit(self.journal.gpa);
            self.* = undefined;
        }

        /// The next batch (valid until the next call), or null once the range is replayed.
        /// An error ends the replay after the items decoded before it.
        pub fn next(self: *Self) Error!?Batch(A) {
            if (self.pending_error) |err| {
                self.pending_error = null;
                self.done = true;
                return err;
            }
            if (self.done or self.position >= self.range.end) return null;
            if (self.reader == null) try self.open_blob();
            const start = self.position;
            self.items.clearRetainingCapacity();
            self.decode_batch() catch |err| {
                if (self.items.items.len == 0) {
                    self.done = true;
                    return err;
                }
                self.pending_error = err;
            };
            self.position = start + self.items.items.len;
            if (self.position == self.blob_end) self.close_blob();
            assert(self.items.items.len > 0);
            return .{ .start = start, .items = self.items.items };
        }

        fn open_blob(self: *Self) Error!void {
            const journal = self.journal;
            const per_blob = journal.items_per_blob;
            const blob = position_to_blob(self.position, per_blob);
            const first = try first_in_blob(journal.bounds.start, blob, per_blob);
            const offset = (self.position - first) * chunk;
            const writer = journal.blobs.get(blob).?;
            var reader = try writer.replay(self.buffer_bytes);
            errdefer reader.deinit();
            try reader.seek_to(offset);
            self.reader = reader;
            self.blob_end = contiguous.blob_end_position(blob, per_blob, self.range.end);
            assert(self.blob_end > self.position);
        }

        fn close_blob(self: *Self) void {
            if (self.reader) |*reader| reader.deinit();
            self.reader = null;
        }

        /// Decode up to one batch of buffered whole items from the current blob.
        fn decode_batch(self: *Self) Error!void {
            const reader = &self.reader.?;
            // A short blob is corruption at the current position.
            if (!try reader.ensure(chunk)) return error.Corruption;
            const available = reader.remaining() / chunk;
            const remaining = self.blob_end - self.position;
            const count: usize = @intCast(@min(available, self.items_per_batch, remaining));
            assert(count > 0);
            const gpa = self.journal.gpa;
            try self.items.ensureTotalCapacity(gpa, count);
            for (0..count) |_| {
                const bytes = reader.bytes()[0..chunk];
                self.items.appendAssumeCapacity(try codec.decode_fixed(A, bytes));
                reader.advance(chunk);
            }
        }
    };
}

test {
    _ = @import("fixed_test.zig");
    _ = @import("fixed_recovery_test.zig");
}
