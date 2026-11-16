//! Segmented journal for oversized values (commonware's `segmented/oversized.rs`).
//!
//! Combines a fixed journal of index entries with a glob of variable-length values:
//!
//! ```text
//! +-------------------+     +-------------------+
//! | Fixed Journal     |     | Glob (Values)     |
//! | (Index Entries)   |     |                   |
//! +-------------------+     +-------------------+
//! | entry_0           | --> | value_0           |
//! | entry_1           | --> | value_1           |
//! +-------------------+     +-------------------+
//! ```
//!
//! Each index entry holds the `(offset, size)` of its value in the glob.
//!
//! # Crash recovery
//!
//! Values are appended before their index entries, so an unclean shutdown can leave an index
//! entry without durable value bytes, value bytes without an index entry, or a value section
//! without an index section. The index is the authority. Recovery durably shortens it before
//! releasing the value bytes it no longer references, so later appends cannot expose a
//! dropped entry or its stale bytes. Each index section ends paired with a value section that
//! stops at its last retained entry, and value sections without an index section are removed.
//!
//! The owner selects one of two recovery contracts at initialization:
//!
//! - `init_with_checkpoint` restores a `(section, index size)` checkpoint published only after
//!   a completed `sync` covered it. Sections below it are adopted at their validated terminal
//!   boundary without reading values, the checkpoint section is durably truncated, and later
//!   sections are removed unread. A restored journal keeps no markers.
//! - `init_with_markers` persists a per-section committed item count in a `Metadata` sidecar.
//!   Entries below the marker are adopted once their index/value boundary is proven, entries
//!   above it are value-verified in order, and the first invalid value truncates the rest of
//!   its section. Markers trail proven syncs, publishing once a section is durable and idle
//!   (or on an empty flush).
//!
//! Syncs complete synchronously, so marker generations are never in flight.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const Storage = runtime.storage.Storage;
const paged = runtime.buffer.paged;
const durability = @import("../durability.zig");
const metadata_mod = @import("../../metadata/mod.zig");
const fixed = @import("fixed.zig");
const glob_mod = @import("glob.zig");
const manager_mod = @import("manager.zig");

/// Where an index entry's value lives in the glob.
pub const Location = struct { offset: u64, size: u32 };

/// Index entries must be fixed-size codec types with
/// `value_location(self) Location` and `with_location(self, offset, size) Self`
/// (commonware's `Record`).
fn assert_record(comptime I: type) void {
    comptime assert(@hasDecl(I, "value_location"));
    comptime assert(@hasDecl(I, "with_location"));
}

/// A durable `(section, index size)` checkpoint.
pub const Checkpoint = struct { section: u64, size: u64 };

/// Configuration for the oversized journal.
pub fn Config(comptime V: type) type {
    return struct {
        /// Partition of the fixed index journal.
        index_partition: []const u8,
        /// Partition of the glob value storage.
        value_partition: []const u8,
        /// Page cache of the index journal.
        index_cache_ref: *paged.CacheRef,
        /// Write buffer size of the index journal.
        index_write_buffer: usize,
        /// Write buffer size of the value journal.
        value_write_buffer: usize,
        /// Buffer size for sequential index recovery.
        replay_buffer: usize,
        /// Optional zstd compression level for values. Keep the choice between none and some
        /// fixed while values are retained.
        compression: ?u8 = null,
        /// Codec configuration for values.
        codec_config: codec.Cfg(V),
    };
}

/// Where `append` placed an entry and its value.
pub const Appended = struct {
    /// Position in the index section.
    position: u64,
    /// Byte offset of the value in the glob section.
    offset: u64,
    /// Stored value size, including its checksum.
    size: u32,
};

/// A sync completion that has already succeeded: syncs complete synchronously.
const Done = struct {
    pub fn poll(_: *Done) ?bool {
        return true;
    }
};

const Barrier = durability.Barrier(Done);
const Markers = metadata_mod.Metadata(u64, u64);

/// Durable recovery state of a journal that validates every uncommitted value on replay.
const Tracking = struct {
    /// Per-section committed item counts, including staged updates.
    metadata: Markers,
    /// Joint index/value durability proofs not yet fully published as markers, by section.
    barriers: std.ArrayList(SectionBarrier) = .empty,

    const SectionBarrier = struct { section: u64, barrier: Barrier };

    fn deinit(self: *Tracking) void {
        self.barriers.deinit(self.metadata.gpa);
        self.metadata.deinit();
        self.* = undefined;
    }

    fn marker(self: *const Tracking, section: u64) u64 {
        const stored = self.metadata.get(section) orelse return 0;
        return stored.*;
    }

    /// Stage a changed marker, keeping absence as the canonical zero boundary.
    fn stage_marker(self: *Tracking, section: u64, floor: u64) Allocator.Error!bool {
        const stored = self.metadata.get(section);
        if (stored == null and floor == 0) return false;
        if (stored != null and stored.?.* == floor) return false;
        _ = try self.metadata.put(section, floor);
        assert(self.marker(section) == floor);
        return true;
    }

    /// The section's barrier, seeded at its staged floor (the newest boundary a replacement
    /// may claim without observing a completed sync).
    fn barrier(self: *Tracking, section: u64) Allocator.Error!*Barrier {
        const items = self.barriers.items;
        var index: usize = 0;
        while (index < items.len and items[index].section < section) index += 1;
        if (index < items.len and items[index].section == section) {
            return &items[index].barrier;
        }
        const gpa = self.metadata.gpa;
        try self.barriers.insert(gpa, index, .{
            .section = section,
            .barrier = .init(self.marker(section)),
        });
        assert(self.barriers.items[index].section == section);
        return &self.barriers.items[index].barrier;
    }

    /// Discard proofs the last marker generation fully published.
    fn retire_published(self: *Tracking) void {
        var kept: usize = 0;
        for (self.barriers.items) |*entry| {
            const published = self.marker(entry.section);
            if (entry.barrier.boundary() > published or !entry.barrier.settled()) {
                self.barriers.items[kept] = entry.*;
                kept += 1;
            }
        }
        self.barriers.items.len = kept;
        assert(kept <= self.barriers.capacity);
    }

    /// Persist staged markers, then retire the proofs they publish.
    fn persist(self: *Tracking) Markers.Error!void {
        try self.metadata.sync();
        self.retire_published();
    }
};

fn contains(sorted: []const u64, value: u64) bool {
    return std.sort.binarySearch(u64, sorted, value, order_u64) != null;
}

fn order_u64(a: u64, b: u64) std.math.Order {
    return std.math.order(a, b);
}

fn assert_ascending(sections: []const u64) void {
    if (sections.len < 2) return;
    for (sections[1..], sections[0 .. sections.len - 1]) |section, previous| {
        assert(section > previous);
    }
}

/// Segmented journal for entries with oversized values.
///
/// Mutating methods leave the journal failed after a storage error (commonware consumes it);
/// only `deinit` may follow. Mutations of pruned sections fail with `AlreadyPrunedToSection`.
pub fn Oversized(comptime I: type, comptime V: type) type {
    assert_record(I);
    return struct {
        const Self = @This();
        pub const Index = fixed.Journal(I);
        pub const Values = glob_mod.Glob(V);
        pub const ValuesRecovery = glob_mod.Recovery(V);
        pub const Error = Index.Error || Markers.Error;
        pub const Cfg = Config(V);
        pub const Recovery = RecoveryType(I, V);
        const chunk_u64: u64 = Index.chunk;

        index: Index,
        values: Values,
        tracking: ?Tracking,

        /// Close both journals (dropping unsynced data).
        pub fn deinit(self: *Self) void {
            if (self.tracking) |*tracking| tracking.deinit();
            self.index.deinit();
            self.values.deinit();
            self.* = undefined;
        }

        fn index_config(cfg: Cfg) fixed.Config {
            return .{
                .partition = cfg.index_partition,
                .cache_ref = cfg.index_cache_ref,
                .write_buffer = cfg.index_write_buffer,
                .replay_buffer = cfg.replay_buffer,
            };
        }

        fn value_config(cfg: Cfg) glob_mod.Config(V) {
            return .{
                .partition = cfg.value_partition,
                .compression = cfg.compression,
                .codec_config = cfg.codec_config,
                .write_buffer = cfg.value_write_buffer,
            };
        }

        /// The value bytes owned by an optional terminal index entry.
        fn boundary_value_end(entry: ?I) Error!u64 {
            const item = entry orelse return 0;
            const location: Location = item.value_location();
            return std.math.add(u64, location.offset, location.size) catch error.Corruption;
        }

        /// Initialize by restoring a durable checkpoint: sections below `section` are adopted
        /// at their validated terminal boundary, `section` is truncated to `size` index bytes,
        /// and every later section is removed unread. Value sections older than the oldest
        /// index section (left by an interrupted prune) are removed too. A missing or damaged
        /// boundary the checkpoint covers fails with `Corruption`. The empty checkpoint
        /// `(0, 0)` opens empty storage without writing any blob.
        pub fn init_with_checkpoint(
            gpa: Allocator,
            storage: Storage,
            cfg: Cfg,
            checkpoint: Checkpoint,
        ) Error!Self {
            var pending = try Pending(I, V).restore(gpa, storage, cfg, checkpoint);
            errdefer pending.deinit();
            try pending.cleanup_orphan_value_sections();
            return pending.publish(null);
        }

        /// Initialize with durable per-section markers in `marker_partition`, returning the
        /// `Recovery` to drain and finish.
        pub fn init_with_markers(
            gpa: Allocator,
            storage: Storage,
            cfg: Cfg,
            marker_partition: []const u8,
        ) Error!Recovery {
            // Open the commit markers before the data they constrain.
            var metadata = try Markers.init(gpa, storage, .{
                .partition = marker_partition,
                .codec_config = {},
            });
            errdefer metadata.deinit();
            const entries = metadata.items();
            const floors = try gpa.alloc(fixed.Floor, entries.len);
            defer gpa.free(floors);
            for (entries, floors) |entry, *floor| {
                floor.* = .{ .section = entry.key, .items = entry.value };
            }
            // Every advertised prefix is proven before suffix repair may mutate either journal.
            var index = try Index.preflight_floors(gpa, storage, index_config(cfg), floors);
            errdefer index.deinit();
            var values = try ValuesRecovery.init(gpa, storage, value_config(cfg));
            errdefer values.deinit();
            try validate_value_floors(&values, &index);
            return .{
                .index = index,
                .values = values,
                .tracking = .{ .metadata = metadata },
            };
        }

        /// Verify every floor's terminal value extent before repair can mutate either journal.
        fn validate_value_floors(values: *ValuesRecovery, index: *const Index.Recovery) Error!void {
            for (index.boundary_items()) |boundary| {
                const required = try boundary_value_end(boundary.item);
                if (required == 0) continue;
                const retained = try values.size(boundary.section);
                if (retained < required) return error.Corruption;
            }
        }

        /// Append `entry` and `value`: the value goes to the glob first, then the entry with
        /// the value's location to the index.
        pub fn append(self: *Self, section: u64, entry: I, value: V) Error!Appended {
            const stored = try self.values.append(section, value);
            const located: I = entry.with_location(stored.offset, stored.size);
            const position = try self.index.append(section, located);
            // Track the section so a later sync can prove and publish its new length. A fresh
            // barrier claims only the staged floor, never the unproven pre-append prefix.
            if (self.tracking) |*tracking| _ = try tracking.barrier(section);
            return .{ .position = position, .offset = stored.offset, .size = stored.size };
        }

        /// The index entry at `position` (not its value).
        pub fn get(self: *Self, section: u64, position: u64) Error!I {
            return self.index.get(section, position);
        }

        /// The last entry of `section`, or null if it is empty.
        pub fn last(self: *Self, section: u64) Error!?I {
            return self.index.last(section);
        }

        /// The value at an entry's location. Free it with `codec.free`.
        pub fn get_value(self: *Self, section: u64, offset: u64, size_bytes: u32) Error!V {
            return self.values.get(section, offset, size_bytes);
        }

        /// Sync `sections` (ascending) of both journals, then publish the proven lengths of
        /// tracked sections that are not `active` (ascending).
        pub fn sync_tracked(self: *Self, sections: []const u64, active: []const u64) Error!void {
            assert_ascending(sections);
            assert_ascending(active);
            const tracking = &self.tracking.?;
            const gpa = self.index.manager.gpa;
            const lengths = try gpa.alloc(u64, sections.len);
            defer gpa.free(lengths);
            for (sections, lengths) |section, *length| {
                length.* = try self.index.section_len(section);
            }
            try self.index.sync(sections);
            try self.values.sync(sections);
            // Every selected section's length is now proven durable.
            for (sections, lengths) |section, length| {
                (try tracking.barrier(section)).record(length, .{});
            }
            // Completed barriers stay as debt until their section is idle, or on an empty flush.
            var dirty = false;
            for (tracking.barriers.items) |*entry| {
                if (contains(active, entry.section)) continue;
                dirty = try tracking.stage_marker(entry.section, entry.barrier.boundary()) or dirty;
            }
            if (dirty) try tracking.persist();
        }

        /// commonware's `start_sync_tracked`: syncs complete synchronously.
        pub fn start_sync_tracked(
            self: *Self,
            sections: []const u64,
            active: []const u64,
        ) Error!void {
            return self.sync_tracked(sections, active);
        }

        /// Sync both journals for the given `sections` (ascending).
        pub fn sync(self: *Self, sections: []const u64) Error!void {
            if (self.tracking != null) return self.sync_tracked(sections, sections);
            try self.index.sync(sections);
            try self.values.sync(sections);
        }

        /// commonware's `start_sync`: syncs complete synchronously, so this is `sync`.
        pub fn start_sync(self: *Self, sections: []const u64) Error!void {
            return self.sync(sections);
        }

        /// Sync every section.
        pub fn sync_all(self: *Self) Error!void {
            if (self.tracking != null) {
                const gpa = self.index.manager.gpa;
                const open = self.index.open_sections();
                const sections = try gpa.alloc(u64, open.len);
                defer gpa.free(sections);
                for (open, sections) |entry, *section| section.* = entry.section;
                return self.sync_tracked(sections, sections);
            }
            try self.index.sync_all();
            try self.values.sync_all();
        }

        fn keep_at_least(min: u64, key: u64, _: *const u64) bool {
            return key >= min;
        }

        /// Prune both journals below `min`, index first: a crash between them leaves orphan
        /// values, which recovery removes. Returns whether any sections were pruned.
        pub fn prune(self: *Self, min: u64) Error!bool {
            // Remove and durably sync tracked floors before their section names can be reused.
            if (self.tracking) |*tracking| {
                const before = tracking.metadata.count();
                tracking.metadata.retain(min, keep_at_least);
                if (tracking.metadata.count() != before) try tracking.metadata.sync();
                var kept: usize = 0;
                for (tracking.barriers.items) |entry| {
                    if (entry.section < min) continue;
                    tracking.barriers.items[kept] = entry;
                    kept += 1;
                }
                tracking.barriers.items.len = kept;
            }
            const index_pruned = try self.index.prune(min);
            const value_pruned = try self.values.prune(min);
            return index_pruned or value_pruned;
        }

        /// The index size of `section` (the checkpoint size).
        pub fn size(self: *Self, section: u64) Error!u64 {
            return self.index.size(section);
        }

        /// The value size of `section`, derived from its last entry's location.
        pub fn value_size(self: *Self, section: u64) Error!u64 {
            const entry = self.index.last(section) catch |err| switch (err) {
                error.SectionOutOfRange => return 0,
                else => return err,
            } orelse return 0;
            const location: Location = entry.value_location();
            return std.math.add(u64, location.offset, location.size) catch error.OffsetOverflow;
        }

        /// Whether `section` is below this execution's prune floor (reset at init).
        pub fn pruned(self: *const Self, section: u64) bool {
            return self.index.pruned(section);
        }

        pub fn oldest_section(self: *const Self) ?u64 {
            return self.index.oldest_section();
        }

        pub fn newest_section(self: *const Self) ?u64 {
            return self.index.newest_section();
        }

        /// Remove all storage and free the journal. Tracked floors go first, so an interrupted
        /// destroy only forces conservative recovery of pair data left behind.
        pub fn destroy(self: *Self) Error!void {
            defer self.* = undefined;
            var markers_result: Markers.Error!void = {};
            if (self.tracking) |*tracking| {
                markers_result = tracking.metadata.destroy(); // Frees the markers.
                tracking.barriers.deinit(self.index.manager.gpa);
            }
            const index_result = self.index.destroy();
            const values_result = self.values.destroy();
            try markers_result;
            try index_result;
            try values_result;
        }
    };
}

/// Both journals while initialization may still discard unreferenced data.
fn Pending(comptime I: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const O = Oversized(I, V);
        const Error = O.Error;

        /// Unpublished index whose per-section extents are reconciled with value storage.
        index: O.Index,
        /// Unpublished values; bytes owned by a discarded index suffix are released only after
        /// its truncation is durable.
        values: O.ValuesRecovery,

        fn deinit(self: *Self) void {
            self.index.deinit();
            self.values.deinit();
            self.* = undefined;
        }

        /// Open both journals at a checkpoint, restoring `section` to `size` index bytes and
        /// removing every later section unread.
        fn restore(
            gpa: Allocator,
            storage: Storage,
            cfg: O.Cfg,
            checkpoint: Checkpoint,
        ) Error!Self {
            const section = checkpoint.section;
            const index_cfg = O.index_config(cfg);
            var preflight = try O.Index.preflight_restore(
                gpa,
                storage,
                index_cfg,
                section,
                checkpoint.size,
            );
            const value_cfg = O.value_config(cfg);
            var values = O.ValuesRecovery.init_bounded(gpa, storage, value_cfg, section) catch |err|
                {
                    preflight.deinit();
                    return err;
                };
            errdefer values.deinit();
            const value_end = validate_restore_values(&values, &preflight, section) catch |err| {
                preflight.deinit();
                return err;
            };
            // `finish` consumes the preflight, also on error.
            var index = try preflight.finish();
            errdefer index.deinit();
            // The index truncation is already durable. Release its unreferenced values only
            // after that proof, preserving the index-first crash-recovery order.
            try values.truncate(section, value_end);
            try values.sync(&.{section});
            return .{ .index = index, .values = values };
        }

        /// Verify checkpoint-covered value extents against the preflighted index boundaries,
        /// returning the checkpoint section's terminal value end.
        fn validate_restore_values(
            values: *O.ValuesRecovery,
            preflight: *const O.Index.Recovery,
            section: u64,
        ) Error!u64 {
            const boundaries = preflight.boundary_items();
            assert(boundaries.len > 0); // The preflight records the checkpoint section.
            assert(boundaries[boundaries.len - 1].section == section);
            // Every earlier section is immutable under the checkpoint, so its terminal index
            // entry must end exactly at the retained value length.
            for (boundaries[0 .. boundaries.len - 1]) |boundary| {
                const required = try O.boundary_value_end(boundary.item);
                if (try values.size(boundary.section) != required) return error.Corruption;
            }
            // A value-only section between the oldest index section and the checkpoint proves
            // covered index data was lost. Older value-only sections are what a prune
            // interrupted between its index and value removals leaves; restore removes them.
            const oldest_index = boundaries[0].section;
            var candidates = values.sections();
            while (candidates.next()) |candidate| {
                if (candidate < oldest_index or candidate >= section) continue;
                if (!has_boundary(boundaries, candidate)) return error.Corruption;
            }
            // The checkpoint section may retain a suffix but must cover its terminal value.
            const required = try O.boundary_value_end(boundaries[boundaries.len - 1].item);
            if (required > 0 and try values.size(section) < required) return error.Corruption;
            return required;
        }

        fn has_boundary(boundaries: []const O.Index.Recovery.Boundary, section: u64) bool {
            for (boundaries) |boundary| if (boundary.section == section) return true;
            return false;
        }

        fn has_index_section(self: *const Self, section: u64) bool {
            for (self.index.open_sections()) |entry| if (entry.section == section) return true;
            return false;
        }

        /// Remove value sections without an index section: a crash after writing values but
        /// before writing the index of a new section leaves them. Sections need not be
        /// contiguous, so the sets are compared.
        fn cleanup_orphan_value_sections(self: *Self) Error!void {
            const gpa = self.index.manager.gpa;
            var orphans: std.ArrayList(u64) = .empty;
            defer orphans.deinit(gpa);
            var sections = self.values.sections();
            while (sections.next()) |section| {
                if (!self.has_index_section(section)) try orphans.append(gpa, section);
            }
            for (orphans.items) |section| try self.values.remove_section(section);
        }

        /// Truncate each section's values to the end of its last index entry, then remove
        /// value sections without an index section.
        fn align_values_to_index(self: *Self) Error!void {
            const gpa = self.index.manager.gpa;
            var truncations: std.ArrayList(manager_mod.SectionSize) = .empty;
            defer truncations.deinit(gpa);
            for (self.index.open_sections()) |entry| {
                const target = try O.boundary_value_end(try self.index.last(entry.section));
                const retained = try self.values.size(entry.section);
                if (retained < target) return error.Corruption;
                if (retained > target) {
                    try truncations.append(gpa, .{ .section = entry.section, .size = target });
                }
            }
            try self.values.truncate_sections(truncations.items);
            try self.cleanup_orphan_value_sections();
        }

        /// Raise markers to each section's replayed length without syncing the data journals:
        /// the retained entries were readable when the run began, which the storage contract
        /// makes crash-durable, and recovery truncations are durable before this runs.
        fn reconcile_markers(self: *Self, tracking: *Tracking) Error!void {
            var dirty = false;
            for (self.index.open_sections()) |entry| {
                const items = try self.index.section_len(entry.section);
                dirty = try tracking.stage_marker(entry.section, items) or dirty;
            }
            if (dirty) try tracking.persist();
        }

        /// Publish both journals, consuming the pending state.
        fn publish(self: *Self, tracking: ?Tracking) O {
            const journal: O = .{
                .index = self.index,
                .values = self.values.finish(),
                .tracking = tracking,
            };
            self.* = undefined;
            return journal;
        }
    };
}

/// Validating startup recovery returned by `Oversized.init_with_markers`.
///
/// `next` yields `(section, position, entry)` in order, verifying each value at or above its
/// section's durable marker until the first invalid one. `deinit` abandons it.
fn RecoveryType(comptime I: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const O = Oversized(I, V);
        const Error = O.Error;

        pub const Item = O.Index.Recovery.Item;
        const Truncation = struct { section: u64, position: u64 };

        /// Index recovery, which modifies nothing until its first entry is requested.
        index: O.Index.Recovery,
        /// Value recovery owner.
        values: O.ValuesRecovery,
        /// Durable markers whose floors bound value validation.
        tracking: Tracking,
        /// Section whose cached `floor` and `truncated` state is active.
        current_section: ?u64 = null,
        /// Committed item count from the durable marker of the current section.
        floor: u64 = 0,
        /// Whether the current section reached its first invalid value.
        truncated: bool = false,
        /// First invalid position per section, applied to the index by `finish`.
        truncations: std.ArrayList(Truncation) = .empty,
        /// Whether replay yielded a value-verification error.
        failed: bool = false,

        /// Abandon the recovery, closing both journals and the markers.
        pub fn deinit(self: *Self) void {
            self.truncations.deinit(self.tracking.metadata.gpa);
            self.index.deinit();
            self.values.deinit();
            self.tracking.deinit();
            self.* = undefined;
        }

        /// The next entry, or null once every section is exhausted. An index error ends the
        /// section that produced it; a value-verification error does not, and either makes
        /// `finish` fail with `ReplayFailed`.
        pub fn next(self: *Self) Error!?Item {
            while (try self.index.next()) |item| {
                // Each section validates forward from its durable floor.
                if (self.current_section != item.section) {
                    self.current_section = item.section;
                    self.floor = self.tracking.marker(item.section);
                    self.truncated = false;
                }
                // Entries after the first invalid value are outside the retained prefix.
                if (self.truncated) continue;
                if (item.position < self.floor) return item;
                if (try self.verify(item)) return item;
                const gpa = self.tracking.metadata.gpa;
                try self.truncations.append(gpa, .{
                    .section = item.section,
                    .position = item.position,
                });
                self.truncated = true;
            }
            return null;
        }

        /// Whether `item`'s value has a valid checksum. A read error fails the recovery.
        fn verify(self: *Self, item: Item) Error!bool {
            const location: Location = item.item.value_location();
            errdefer self.failed = true;
            return self.values.verify(item.section, location.offset, location.size);
        }

        /// Replay every remaining entry, discarding them. Abandons the recovery on error.
        pub fn drain(self: *Self) Error!void {
            errdefer self.deinit();
            while (try self.next()) |_| {}
        }

        /// Return the journal, consuming the recovery (also on error). Fails with
        /// `ReplayFailed` unless the recovery was fully drained without errors. Each section
        /// is durably truncated at its first invalid entry, unreferenced values are released,
        /// and the retained lengths become the next markers.
        pub fn finish(self: *Self) Error!O {
            const gpa = self.tracking.metadata.gpa;
            defer self.* = undefined;
            defer self.truncations.deinit(gpa);
            var tracking = self.tracking;
            errdefer tracking.deinit();
            var values = self.values;
            if (self.failed) {
                self.index.deinit();
                values.deinit();
                return error.ReplayFailed;
            }
            const index = self.index.finish() catch |err| {
                values.deinit();
                return err;
            };
            var pending: Pending(I, V) = .{ .index = index, .values = values };
            errdefer pending.deinit();
            // Each index truncation is durable before alignment releases the values past it.
            for (self.truncations.items) |truncation| {
                const index_size = std.math.mul(u64, truncation.position, O.chunk_u64) catch
                    return error.OffsetOverflow;
                try pending.index.truncate_pending_section(truncation.section, index_size);
            }
            try pending.align_values_to_index();
            try pending.reconcile_markers(&tracking);
            return pending.publish(tracking);
        }
    };
}

test {
    _ = @import("oversized_test.zig");
    _ = @import("oversized_recovery_fuzz_test.zig");
}
