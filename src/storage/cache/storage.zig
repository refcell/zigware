//! The `Cache` implementation (commonware's `cache/storage.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const variable = @import("../journal/segmented/variable.zig");
const rmap = @import("../rmap/mod.zig");
const Config = @import("mod.zig").Config;

/// Record stored in the cache's journal: a varint index followed by the value.
pub fn Record(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Cfg = codec.Cfg(V);

        index: u64,
        value: V,

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.varint.write(u64, self.index, writer);
            codec.write(V, self.value, writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.varint.size(u64, self.index) + codec.encode_size(V, self.value);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const index = try codec.varint.read(u64, reader);
            const value = try codec.read_cfg(V, gpa, reader, cfg);
            return .{ .index = index, .value = value };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            codec.free(V, gpa, self.value);
            self.* = undefined;
        }
    };
}

/// A prunable cache of values by index, backed by a variable segmented journal.
///
/// An error from a mutating method (`put`, `put_sync`, `sync`, `prune`) leaves the cache
/// failed: only `deinit` may follow (commonware consumes the handle on error).
pub fn Cache(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Journal = variable.Journal(Record(V));
        pub const Error = Journal.Error;

        gpa: Allocator,
        items_per_blob: u64,
        journal: Journal,
        /// Sections with unsynced appends, ascending and unique.
        pending: std.ArrayList(u64) = .empty,
        /// Oldest allowed section to read from, set by `prune`.
        oldest_allowed: ?u64 = null,
        /// Journal offset of every stored index.
        indices: std.AutoHashMapUnmanaged(u64, u64) = .empty,
        intervals: rmap.RMap = .empty,
        failed: bool = false,

        items_tracked: metrics.Gauge,
        gets: metrics.Counter,
        has_checks: metrics.Counter,
        syncs: metrics.Counter,

        /// Open the cache, replaying its journal to rebuild the in-memory index.
        pub fn init(
            gpa: Allocator,
            storage: runtime.storage.Storage,
            scope: metrics.Scope,
            cfg: Config(V),
        ) Error!Self {
            assert(cfg.items_per_blob > 0);
            assert(cfg.write_buffer > 0 and cfg.replay_buffer > 0);
            var indices: std.AutoHashMapUnmanaged(u64, u64) = .empty;
            errdefer indices.deinit(gpa);
            var intervals: rmap.RMap = .empty;
            errdefer intervals.deinit(gpa);
            var recovery = try Journal.init(gpa, storage, .{
                .partition = cfg.partition,
                .compression = cfg.compression,
                .codec_config = cfg.codec_config,
                .cache_ref = cfg.cache_ref,
                .write_buffer = cfg.write_buffer,
                .replay_buffer = cfg.replay_buffer,
            });
            {
                errdefer recovery.deinit();
                while (try recovery.next()) |entry| {
                    var record = entry.item;
                    defer record.deinit(gpa);
                    try indices.put(gpa, record.index, entry.offset);
                    try intervals.insert(gpa, record.index);
                }
            }
            var journal = try recovery.finish();
            errdefer journal.deinit();
            return init_metrics(gpa, scope, cfg.items_per_blob, journal, indices, intervals);
        }

        fn init_metrics(
            gpa: Allocator,
            scope: metrics.Scope,
            items_per_blob: u64,
            journal: Journal,
            indices: std.AutoHashMapUnmanaged(u64, u64),
            intervals: rmap.RMap,
        ) Error!Self {
            var items_tracked = try scope.gauge("items_tracked", "Number of items tracked");
            errdefer items_tracked.deinit();
            var gets = try scope.counter("gets", "Number of gets performed");
            errdefer gets.deinit();
            var has_checks = try scope.counter("has", "Number of has performed");
            errdefer has_checks.deinit();
            const syncs = try scope.counter("syncs", "Number of syncs called");
            _ = items_tracked.metric().set(@intCast(indices.count()));
            return .{
                .gpa = gpa,
                .items_per_blob = items_per_blob,
                .journal = journal,
                .indices = indices,
                .intervals = intervals,
                .items_tracked = items_tracked,
                .gets = gets,
                .has_checks = has_checks,
                .syncs = syncs,
            };
        }

        /// Close the cache, dropping unsynced items.
        pub fn deinit(self: *Self) void {
            self.journal.deinit();
            self.release();
        }

        fn release(self: *Self) void {
            self.pending.deinit(self.gpa);
            self.indices.deinit(self.gpa);
            self.intervals.deinit(self.gpa);
            self.items_tracked.deinit();
            self.gets.deinit();
            self.has_checks.deinit();
            self.syncs.deinit();
            self.* = undefined;
        }

        /// The section holding `index`.
        fn section(self: *const Self, index: u64) u64 {
            const result = (index / self.items_per_blob) * self.items_per_blob;
            assert(result <= index);
            assert(index - result < self.items_per_blob);
            return result;
        }

        /// The value at `index`, or null. The caller frees it with `codec.free`.
        pub fn get(self: *Self, index: u64) Error!?V {
            assert(!self.failed);
            self.gets.metric().inc();
            const offset = self.indices.get(index) orelse return null;
            assert(self.intervals.get(index) != null);
            const record = try self.journal.get(self.section(index), offset);
            assert(record.index == index);
            return record.value;
        }

        /// The end of the range containing `index` and the start of the next range.
        pub fn next_gap(self: *const Self, index: u64) rmap.Gap {
            return self.intervals.next_gap(index);
        }

        /// The first stored index.
        pub fn first(self: *const Self) ?u64 {
            return self.intervals.first_index();
        }

        /// Up to `out.len` missing indices at or after `start`, before the last stored index.
        pub fn missing_items(self: *const Self, start: u64, out: []u64) []u64 {
            return self.intervals.missing_items(start, out);
        }

        /// Whether `index` is stored.
        pub fn has(self: *const Self, index: u64) bool {
            self.has_checks.metric().inc();
            return self.indices.contains(index);
        }

        /// Prune every section below the one holding `min`. A `min` at or below the last
        /// prune does nothing.
        pub fn prune(self: *Self, min_index: u64) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            const min = self.section(min_index);
            if (self.oldest_allowed) |oldest| {
                if (min <= oldest) return;
            }
            _ = try self.journal.prune(min);
            // Pending sections below `min` were removed with their blobs.
            var keep: usize = 0;
            while (keep < self.pending.items.len and self.pending.items[keep] < min) keep += 1;
            self.pending.replaceRangeAssumeCapacity(0, keep, &.{});
            self.remove_indices_below(min);
            if (min > 0) try self.intervals.remove(self.gpa, 0, min - 1);
            assert(self.intervals.first_index() == null or self.intervals.first_index().? >= min);
            self.oldest_allowed = min;
            _ = self.items_tracked.metric().set(@intCast(self.indices.count()));
        }

        /// Remove every tracked index below `min`, walking the intervals so the work is
        /// bounded by the number of removed items.
        fn remove_indices_below(self: *Self, min: u64) void {
            for (self.intervals.items()) |range| {
                if (range.start >= min) break;
                const end = @min(range.end, min - 1);
                var index = range.start;
                while (true) : (index += 1) {
                    const removed = self.indices.remove(index);
                    assert(removed);
                    if (index == end) break;
                }
            }
        }

        /// Store `value` at `index`. An existing index is left unchanged, and a put below the
        /// prune floor is satisfied without storing.
        pub fn put(self: *Self, index: u64, value: V) Error!void {
            _ = try self.put_inner(index, value);
        }

        /// Store `value` at `index` and sync every pending write. A put satisfied below the
        /// prune floor stores nothing and skips the sync.
        pub fn put_sync(self: *Self, index: u64, value: V) Error!void {
            if (!try self.put_inner(index, value)) return;
            try self.sync();
        }

        /// Returns false when `index` is below the prune floor.
        fn put_inner(self: *Self, index: u64, value: V) Error!bool {
            assert(!self.failed);
            errdefer self.failed = true;
            if (index < self.oldest_allowed orelse 0) return false;
            if (self.indices.contains(index)) return true;
            try self.indices.ensureUnusedCapacity(self.gpa, 1);
            try self.pending.ensureUnusedCapacity(self.gpa, 1);
            const section_index = self.section(index);
            const record: Record(V) = .{ .index = index, .value = value };
            const appended = try self.journal.append(section_index, record);
            self.indices.putAssumeCapacityNoClobber(index, appended.offset);
            try self.intervals.insert(self.gpa, index);
            self.insert_pending(section_index);
            _ = self.items_tracked.metric().set(@intCast(self.indices.count()));
            return true;
        }

        fn insert_pending(self: *Self, section_index: u64) void {
            const items = self.pending.items;
            var position: usize = items.len;
            while (position > 0 and items[position - 1] >= section_index) position -= 1;
            if (position < items.len and items[position] == section_index) return;
            self.pending.insertAssumeCapacity(position, section_index);
            assert(std.sort.isSorted(u64, self.pending.items, {}, std.sort.asc(u64)));
        }

        /// Sync every pending write.
        pub fn sync(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            self.syncs.metric().inc_by(self.pending.items.len);
            try self.journal.sync(self.pending.items);
            self.pending.clearRetainingCapacity();
        }

        /// Remove all persistent data created by this cache and free it.
        pub fn destroy(self: *Self) Error!void {
            defer self.release();
            return self.journal.destroy();
        }
    };
}
