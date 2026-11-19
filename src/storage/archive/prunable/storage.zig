//! The prunable `Archive` implementation (commonware's `archive/prunable/storage.rs`).
//!
//! Records (`index || key || value_offset || value_size`) and values live in an oversized
//! journal with per-section validation markers, one section per `items_per_section` indices.
//! In memory, each retained section holds its records' translated keys and the first position
//! of each index (see `sections.zig`); a `handles.Table` maps the hash of a translated key to
//! the handles of the records holding it, so a key lookup reads the index journal only for
//! records whose translated key matches, and never reads a value it does not return.
//!
//! An error from a mutating method (`put`, `put_multi`, `sync`, `start_sync`, `prune`), or a
//! failed `start_sync` completion, leaves the archive
//! failed: only `deinit` may follow (commonware consumes the handle on error). Puts below the
//! prune floor are satisfied without storing. The floor is not persisted.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const oversized_mod = @import("../../journal/segmented/oversized.zig");
const rmap = @import("../../rmap/mod.zig");
const translator_mod = @import("../../translator.zig");
const archive = @import("../mod.zig");
const mod = @import("mod.zig");
const sections_mod = @import("sections.zig");

const handle = sections_mod.handle;
const unpack = sections_mod.unpack;

/// A prunable archive of `V` values addressed by `u64` index and fixed-size key `K`, with keys
/// translated by `T` for the in-memory index.
pub fn Archive(comptime T: type, comptime K: type, comptime V: type) type {
    comptime translator_mod.check(T);
    const key_size = codec.fixed_size(K) orelse @compileError("archive keys are fixed-size");
    return struct {
        const Self = @This();
        pub const Record = mod.Record(K);
        pub const Oversized = oversized_mod.Oversized(Record, V);
        pub const Error = Oversized.Error || Allocator.Error || archive.Error;
        pub const Identifier = archive.Identifier(K);
        pub const Cfg = mod.Config(T, V);
        const Sections = sections_mod.Sections(T.Key);
        const Section = Sections.Section;
        const KeyTable = utils.handles.Table(u64);
        const Extras = std.AutoHashMapUnmanaged(u64, std.ArrayList(u64));
        const Completion = runtime.storage.Completion;

        gpa: Allocator,
        items_per_section: u64,
        /// Combined index + value storage with crash recovery.
        oversized: Oversized,
        /// Sections with writes not yet included in any sync request, ascending and unique.
        /// Moved into `requested` by a request; the `syncs` metric counts only this set.
        pending: std.ArrayList(u64) = .empty,
        /// Sections a `start_sync` requested, retained until a blocking `sync` completes,
        /// ascending and unique. A `start_sync` completion must cover every earlier accepted
        /// write, even when its call wrote nothing (a duplicate or below-floor put):
        /// re-requesting these sections returns their in-flight syncs (a completed one
        /// resolves at once). Pruned sections leave the set with their data.
        requested: std.ArrayList(u64) = .empty,
        /// Oldest section allowed to be read or written. Set by `prune`.
        oldest_allowed: ?u64 = null,
        translator: T,
        /// Handles of every retained record by the hash of its translated key.
        keys: KeyTable = .empty,
        /// Retained sections, which hold each record's translated key and position.
        sections: Sections = .{},
        /// Additional positions of indices with more than one record (from `put_multi`).
        extra_indices: Extras = .empty,
        /// Stored indices, for gap detection.
        intervals: rmap.RMap = .empty,
        /// Number of indices with at least one record.
        items: u64 = 0,
        failed: bool = false,

        items_tracked: metrics.Gauge,
        keys_tracked: metrics.Gauge,
        indices_pruned: metrics.Counter,
        unnecessary_reads: metrics.Counter,
        gets: metrics.Counter,
        has_checks: metrics.Counter,
        syncs: metrics.Counter,

        /// Rehashes a key handle from the translated key its section holds (the table calls
        /// this only when it grows).
        const Rehash = struct {
            translator: *const T,
            sections: *const Sections,

            pub fn rehash(context: Rehash, packed_handle: u64) u64 {
                const at = unpack(packed_handle);
                const held = context.sections.slot(at.slot);
                assert(at.position < held.keys.items.len);
                return context.translator.hash(held.keys.items[@intCast(at.position)]);
            }
        };

        fn rehash_context(self: *const Self) Rehash {
            return .{ .translator = &self.translator, .sections = &self.sections };
        }

        /// Open the archive, replaying the key journal to rebuild the in-memory index and
        /// CRC-validating every value above its section's durable marker.
        pub fn init(
            gpa: Allocator,
            storage: runtime.storage.Storage,
            scope: metrics.Scope,
            config: Cfg,
        ) Error!Self {
            config.validate();
            var recovery = try Oversized.init_with_markers(gpa, storage, .{
                .index_partition = config.key_partition,
                .value_partition = config.value_partition,
                .index_cache_ref = config.key_cache_ref,
                .index_write_buffer = config.key_write_buffer,
                .value_write_buffer = config.value_write_buffer,
                .replay_buffer = config.replay_buffer,
                .compression = config.compression,
                .codec_config = config.codec_config,
            }, config.metadata_partition);
            var recovering = true;
            defer if (recovering) recovery.deinit();
            var self = try init_metrics(scope);
            self.gpa = gpa;
            self.items_per_section = config.items_per_section;
            self.translator = config.translator;
            errdefer self.release();
            // One scan of the retained entries serves both recovery and indexing. A record
            // outside the section its index selects is unreachable by index: corruption.
            var records: usize = 0;
            while (try recovery.next()) |item| {
                if (self.section(item.item.index) != item.section) {
                    return error.RecordCorrupted;
                }
                _ = try self.track(item.section, item.position, item.item);
                records += 1;
            }
            recovering = false;
            self.oversized = try recovery.finish();
            errdefer self.oversized.deinit();
            try self.index_keys(records);
            self.update_gauges();
            assert(self.keys.len == records);
            return self;
        }

        /// Index every replayed record by key in a table sized once for all of them.
        fn index_keys(self: *Self, records: usize) Allocator.Error!void {
            assert(self.keys.len == 0);
            self.keys = try KeyTable.init_capacity(self.gpa, records);
            for (0..self.sections.slot_count()) |slot| {
                const held = self.sections.at_slot(slot) orelse continue;
                for (held.keys.items, 0..) |translated, position| {
                    const hash = self.translator.hash(translated);
                    const packed_handle = handle(slot, position);
                    try self.keys.insert(self.gpa, hash, packed_handle, self.rehash_context());
                }
            }
            assert(self.keys.len == records);
        }

        fn init_metrics(scope: metrics.Scope) Error!Self {
            var self: Self = undefined;
            self.items_tracked = try scope.gauge("items_tracked", "Number of items tracked");
            errdefer self.items_tracked.deinit();
            self.keys_tracked = try scope.gauge(
                "keys_tracked",
                "Number of records indexed by key",
            );
            errdefer self.keys_tracked.deinit();
            self.indices_pruned = try scope.counter("indices_pruned", "Number of indices pruned");
            errdefer self.indices_pruned.deinit();
            self.unnecessary_reads = try scope.counter(
                "unnecessary_reads",
                "Number of unnecessary reads performed during key lookups",
            );
            errdefer self.unnecessary_reads.deinit();
            self.gets = try scope.counter("gets", "Number of gets performed");
            errdefer self.gets.deinit();
            self.has_checks = try scope.counter("has", "Number of has performed");
            errdefer self.has_checks.deinit();
            self.syncs = try scope.counter("syncs", "Number of syncs called");
            self.pending = .empty;
            self.requested = .empty;
            self.oldest_allowed = null;
            self.keys = .empty;
            self.sections = .{};
            self.extra_indices = .empty;
            self.intervals = .empty;
            self.items = 0;
            self.failed = false;
            return self;
        }

        /// Close the journals (dropping unsynced data) and free the archive.
        pub fn deinit(self: *Self) void {
            self.oversized.deinit();
            self.release();
        }

        /// Free the in-memory state and metrics, leaving `oversized` alone.
        fn release(self: *Self) void {
            const gpa = self.gpa;
            self.pending.deinit(gpa);
            self.requested.deinit(gpa);
            self.keys.deinit(gpa);
            self.sections.deinit(gpa);
            var extras = self.extra_indices.valueIterator();
            while (extras.next()) |positions| positions.deinit(gpa);
            self.extra_indices.deinit(gpa);
            self.intervals.deinit(gpa);
            self.items_tracked.deinit();
            self.keys_tracked.deinit();
            self.indices_pruned.deinit();
            self.unnecessary_reads.deinit();
            self.gets.deinit();
            self.has_checks.deinit();
            self.syncs.deinit();
            self.* = undefined;
        }

        /// The first index of the section holding `index`.
        fn section(self: *const Self, index: u64) u64 {
            assert(self.items_per_section > 0);
            const start = (index / self.items_per_section) * self.items_per_section;
            assert(start <= index and index - start < self.items_per_section);
            return start;
        }

        /// The retained section holding `index`, if any.
        fn section_of(self: *const Self, index: u64) ?*const Section {
            return self.sections.get(self.section(index));
        }

        /// The first journal position of `index`, if present.
        fn first_position(self: *const Self, index: u64) ?u64 {
            const held = self.section_of(index) orelse return null;
            assert(held.start <= index);
            return held.positions.get(index - held.start);
        }

        /// The positions of `index` after its first (from `put_multi`).
        fn extra_positions(self: *const Self, index: u64) []const u64 {
            const extras = self.extra_indices.getPtr(index) orelse return &.{};
            assert(extras.items.len > 0);
            return extras.items;
        }

        /// Record the entry at `position` of section `start` by index and translated key
        /// (but not in the key table). Returns its section slot.
        fn track(self: *Self, start: u64, position: u64, record: Record) Error!usize {
            assert(self.section(record.index) == start);
            const key_bytes: [key_size]u8 = codec.encode_fixed(K, record.key);
            const translated = self.translator.transform(&key_bytes);
            try self.intervals.insert(self.gpa, record.index);
            const added = try self.sections.add(
                self.gpa,
                start,
                record.index - start,
                position,
                translated,
            );
            if (added.first) {
                self.items += 1;
            } else {
                const extras = try self.extra_indices.getOrPut(self.gpa, record.index);
                if (!extras.found_existing) extras.value_ptr.* = .empty;
                try extras.value_ptr.append(self.gpa, position);
            }
            assert(self.first_position(record.index) != null);
            return added.slot;
        }

        fn update_gauges(self: *Self) void {
            assert(self.items <= self.keys.len);
            assert(self.extra_indices.count() <= self.items);
            _ = self.items_tracked.metric().set(@intCast(self.items));
            _ = self.keys_tracked.metric().set(@intCast(self.keys.len));
        }

        /// Store `value` at `index` under `key`. A no-op when `index` is already stored or
        /// below the prune floor.
        pub fn put(self: *Self, index: u64, key: K, value: V) Error!void {
            return self.put_internal(index, key, value, true);
        }

        /// Store `value` at `index` under `key`, also when `index` already holds records.
        pub fn put_multi(self: *Self, index: u64, key: K, value: V) Error!void {
            return self.put_internal(index, key, value, false);
        }

        /// `put` then `sync`.
        pub fn put_sync(self: *Self, index: u64, key: K, value: V) Error!void {
            try self.put(index, key, value);
            try self.sync();
        }

        /// `put_multi` then `sync`.
        pub fn put_multi_sync(self: *Self, index: u64, key: K, value: V) Error!void {
            try self.put_multi(index, key, value);
            try self.sync();
        }

        /// `put` then `start_sync`: the completion covers this put and every earlier one.
        pub fn put_start_sync(self: *Self, index: u64, key: K, value: V) Error!Completion {
            try self.put(index, key, value);
            return self.start_sync();
        }

        /// `put_multi` then `start_sync`.
        pub fn put_multi_start_sync(self: *Self, index: u64, key: K, value: V) Error!Completion {
            try self.put_multi(index, key, value);
            return self.start_sync();
        }

        fn put_internal(self: *Self, index: u64, key: K, value: V, unique: bool) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            // A put below the prune floor is satisfied without storing.
            if (index < self.oldest_allowed orelse 0) return;
            if (unique and self.has_index(index)) return;
            // Write the value and index entry (glob first, then index).
            const start = self.section(index);
            const entry: Record = .{
                .index = index,
                .key = key,
                .value_offset = 0,
                .value_size = 0,
            };
            try self.pending.ensureUnusedCapacity(self.gpa, 1);
            const appended = try self.oversized.append(start, entry, value);
            const slot = try self.track(start, appended.position, entry);
            const key_bytes: [key_size]u8 = codec.encode_fixed(K, key);
            const hash = self.translator.hash(self.translator.transform(&key_bytes));
            const packed_handle = handle(slot, appended.position);
            try self.keys.insert(self.gpa, hash, packed_handle, self.rehash_context());
            // Include this section in the next sync.
            insert_sorted(&self.pending, start);
            self.update_gauges();
            assert(self.has_index(index));
        }

        fn insert_sorted(list: *std.ArrayList(u64), value: u64) void {
            const at = std.sort.lowerBound(u64, list.items, value, order_u64);
            if (at < list.items.len and list.items[at] == value) return;
            assert(list.unusedCapacitySlice().len > 0);
            list.insertAssumeCapacity(at, value);
        }

        fn order_u64(a: u64, b: u64) std.math.Order {
            return std.math.order(a, b);
        }

        fn has_index(self: *const Self, index: u64) bool {
            return self.first_position(index) != null;
        }

        /// The value at `index` (its first record) or under `key`. Free it with `codec.free`
        /// if `V` owns memory.
        pub fn get(self: *Self, identifier: Identifier) Error!?V {
            return self.get_with(identifier, self.gpa);
        }

        /// `get`, decoding the value's memory from `value_gpa` (such as a buffer the caller
        /// reuses across reads).
        pub fn get_with(self: *Self, identifier: Identifier, value_gpa: Allocator) Error!?V {
            assert(!self.failed);
            self.gets.metric().inc();
            const start, const entry = switch (identifier) {
                .index => |index| found: {
                    const position = self.first_position(index) orelse return null;
                    const start = self.section(index);
                    const entry = try self.oversized.get(start, position);
                    assert(entry.index == index);
                    break :found .{ start, entry };
                },
                .key => |key| found: {
                    const found = try self.find(key) orelse return null;
                    break :found .{ found.start, found.entry };
                },
            };
            return try self.read_value(start, entry, value_gpa);
        }

        fn read_value(self: *Self, start: u64, entry: Record, value_gpa: Allocator) Error!V {
            assert(self.section(entry.index) == start);
            assert(entry.value_size > 0);
            const offset, const size = .{ entry.value_offset, entry.value_size };
            return self.oversized.get_value_with(start, offset, size, value_gpa);
        }

        /// The section and index journal entry of a record storing `key`, if any. Candidates
        /// share the hash of their translated key: each is confirmed against the translated
        /// key in memory, then against the stored key, never reading values.
        fn find(self: *Self, key: *const K) Error!?Found {
            const key_bytes: [key_size]u8 = codec.encode_fixed(K, key.*);
            const translated = self.translator.transform(&key_bytes);
            var candidates = self.keys.get(self.translator.hash(translated));
            while (candidates.next()) |candidate| {
                const at = unpack(candidate);
                const held = self.sections.slot(at.slot);
                if (!T.eql(held.keys.items[@intCast(at.position)], translated)) continue;
                const entry = try self.oversized.get(held.start, at.position);
                if (keys_equal(entry.key, &key_bytes)) {
                    return .{ .start = held.start, .entry = entry };
                }
                self.unnecessary_reads.metric().inc();
            }
            return null;
        }

        const Found = struct { start: u64, entry: Record };

        fn keys_equal(stored: K, key_bytes: *const [key_size]u8) bool {
            const stored_bytes: [key_size]u8 = codec.encode_fixed(K, stored);
            return std.mem.eql(u8, &stored_bytes, key_bytes);
        }

        /// Whether `index` is stored, or any retained index stores `key`.
        pub fn has(self: *Self, identifier: Identifier) Error!bool {
            assert(!self.failed);
            self.has_checks.metric().inc();
            return switch (identifier) {
                .index => |index| self.has_index(index),
                .key => |key| (try self.find(key)) != null,
            };
        }

        /// Every value stored at `index`, first stored first, or null if `index` is absent.
        /// The caller owns the slice (allocated with `gpa`) and frees each value with
        /// `codec.free` if `V` owns memory.
        pub fn get_all(self: *Self, gpa: Allocator, index: u64) Error!?[]V {
            assert(!self.failed);
            self.gets.metric().inc();
            const first = self.first_position(index) orelse return null;
            const extras = self.extra_positions(index);
            const values = try gpa.alloc(V, 1 + extras.len);
            var filled: usize = 0;
            errdefer {
                for (values[0..filled]) |value| codec.free(V, gpa, value);
                gpa.free(values);
            }
            const start = self.section(index);
            for (values, 0..) |*value, i| {
                const position = if (i == 0) first else extras[i - 1];
                const entry = try self.oversized.get(start, position);
                value.* = try self.read_value(start, entry, self.gpa);
                filled += 1;
            }
            assert(filled == values.len);
            return values;
        }

        /// Whether `key` is stored at `index`. Records at `index` are filtered by translated
        /// key in memory and the rest confirmed against the stored key; no value is read.
        pub fn has_at(self: *Self, index: u64, key: *const K) Error!bool {
            assert(!self.failed);
            self.has_checks.metric().inc();
            const held = self.section_of(index) orelse return false;
            const first = held.positions.get(index - held.start) orelse return false;
            const key_bytes: [key_size]u8 = codec.encode_fixed(K, key.*);
            const translated = self.translator.transform(&key_bytes);
            const extras = self.extra_positions(index);
            for (0..1 + extras.len) |i| {
                const position = if (i == 0) first else extras[i - 1];
                if (!T.eql(held.keys.items[@intCast(position)], translated)) continue;
                const entry = try self.oversized.get(held.start, position);
                if (keys_equal(entry.key, &key_bytes)) return true;
                self.unnecessary_reads.metric().inc();
            }
            return false;
        }

        /// Make every accepted write durable, then publish the validation markers of synced
        /// sections that received no writes since. Also observes every earlier `start_sync`.
        pub fn sync(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.request(.blocking);
            self.requested.clearRetainingCapacity();
            assert(self.pending.items.len == 0);
        }

        /// Start making every accepted write durable, returning a completion (one reference,
        /// owned by the caller). Validation markers trail it: a later request publishes them.
        /// A failed completion leaves the archive failed; the next mutation reports it.
        pub fn start_sync(self: *Self) Error!Completion {
            assert(!self.failed);
            errdefer self.failed = true;
            return self.request(.started);
        }

        /// Move `pending` into `requested` and sync all of it, blocking or started; only the
        /// sections written since the last request are active (their markers wait).
        fn request(
            self: *Self,
            comptime mode: enum { blocking, started },
        ) Error!if (mode == .started) Completion else void {
            const pending = self.pending.items;
            self.syncs.metric().inc_by(pending.len);
            try self.requested.ensureUnusedCapacity(self.gpa, pending.len);
            for (pending) |start| insert_sorted(&self.requested, start);
            defer self.pending.clearRetainingCapacity();
            const requested = self.requested.items;
            return switch (mode) {
                .blocking => self.oversized.sync_tracked(requested, pending),
                .started => self.oversized.start_sync_tracked(requested, pending),
            };
        }

        /// Prune every section below the one holding `min`. A no-op unless that section is
        /// above the current floor.
        pub fn prune(self: *Self, min_index: u64) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            const min = self.section(min_index);
            if (self.oldest_allowed) |oldest| {
                if (min <= oldest) return;
            }
            // Prune the sections' records, values, and markers together.
            _ = try self.oversized.prune(min);
            retain_at_least(&self.pending, min);
            retain_at_least(&self.requested, min);
            // Drop the pruned sections and retire their records from the key table, found by
            // the translated keys the sections hold, so nothing is read.
            while (self.sections.pop_below(min)) |popped| {
                var dropped = popped.section;
                defer dropped.deinit(self.gpa);
                for (dropped.keys.items, 0..) |translated, position| {
                    const hash = self.translator.hash(translated);
                    const removed = self.keys.remove(hash, handle(popped.slot, position));
                    assert(removed); // Every retained record is indexed by key.
                }
                const pruned = dropped.positions.len();
                self.items -= pruned;
                self.indices_pruned.metric().inc_by(pruned);
            }
            self.prune_extras(min);
            if (min > 0) try self.intervals.remove(self.gpa, 0, min - 1);
            self.oldest_allowed = min;
            self.update_gauges();
        }

        fn retain_at_least(list: *std.ArrayList(u64), min: u64) void {
            const at = std.sort.lowerBound(u64, list.items, min, order_u64);
            const kept = list.items.len - at;
            std.mem.copyForwards(u64, list.items[0..kept], list.items[at..]);
            list.items.len = kept;
            assert(kept == 0 or list.items[0] >= min);
        }

        fn prune_extras(self: *Self, min: u64) void {
            var iterator = self.extra_indices.iterator();
            while (iterator.next()) |extra| {
                if (extra.key_ptr.* >= min) continue;
                extra.value_ptr.deinit(self.gpa);
                // Removal keeps the iterator valid (no rehash on remove).
                self.extra_indices.removeByPtr(extra.key_ptr);
            }
            assert(self.extra_indices.count() <= self.items);
        }

        /// The end of the range holding `index` and the start of the next range after it.
        pub fn next_gap(self: *const Self, index: u64) rmap.Gap {
            return self.intervals.next_gap(index);
        }

        /// Up to `out.len` missing indices from `start`.
        pub fn missing_items(self: *const Self, start: u64, out: []u64) []u64 {
            return self.intervals.missing_items(start, out);
        }

        /// Every stored range (inclusive), ascending.
        pub fn ranges(self: *const Self) []const rmap.Range {
            return self.intervals.items();
        }

        /// The stored ranges that hold or follow `from`.
        pub fn ranges_from(self: *const Self, from: u64) []const rmap.Range {
            return self.intervals.iter_from(from);
        }

        pub fn first_index(self: *const Self) ?u64 {
            return self.intervals.first_index();
        }

        pub fn last_index(self: *const Self) ?u64 {
            return self.intervals.last_index();
        }

        /// Remove all persistent data and free the archive.
        pub fn destroy(self: *Self) Error!void {
            defer self.release();
            try self.oversized.destroy();
        }
    };
}
