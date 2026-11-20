//! The immutable `Archive` implementation (commonware's `archive/immutable/storage.rs`).
//!
//! Values live in a freezer (by key), an ordinal maps each index to its freezer cursor, and a
//! metadata store is the commit record of both: the freezer checkpoint under
//! `(freezer_prefix, 0)` and each ordinal section's bitmap of stored indices under
//! `(ordinal_prefix, section)` (null once the section is full). On restart the metadata is the
//! source of truth: freezer and ordinal data it does not describe is discarded.
//!
//! An error from a mutating method (`put`, `sync`) leaves the archive failed: only `deinit`
//! may follow (commonware consumes the handle on error).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const freezer_mod = @import("../../freezer/mod.zig");
const ordinal_mod = @import("../../ordinal/mod.zig");
const metadata_mod = @import("../../metadata/mod.zig");
const rmap = @import("../../rmap/mod.zig");
const archive = @import("../mod.zig");
const mod = @import("mod.zig");

const PrefixedU64 = utils.sequence.PrefixedU64;
const Cursor = freezer_mod.Cursor;
const Record = mod.Record;
const BitMap = mod.BitMap;

comptime {
    assert(BitMap == ordinal_mod.BitMap);
}

/// The metadata key of the freezer checkpoint.
const freezer_key = PrefixedU64.init(mod.freezer_prefix, 0);

/// An immutable archive of `V` values addressed by `u64` index and fixed-size key `K`.
pub fn Archive(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Freezer = freezer_mod.Freezer(K, V);
        pub const Ordinal = ordinal_mod.Ordinal(Cursor);
        pub const Metadata = metadata_mod.Metadata(PrefixedU64, Record);
        pub const Error = Freezer.Error || ordinal_mod.Error || Metadata.Error || archive.Error;
        pub const Identifier = archive.Identifier(K);
        pub const Cfg = mod.Config(V);

        gpa: Allocator,
        items_per_section: u64,
        metadata: Metadata,
        freezer: Freezer,
        ordinal: Ordinal,
        failed: bool = false,

        gets: metrics.Counter,
        has_checks: metrics.Counter,
        syncs: metrics.Counter,

        /// Open the archive from its metadata commit record.
        pub fn init(
            gpa: Allocator,
            storage: runtime.storage.Storage,
            scope: metrics.Scope,
            config: Cfg,
        ) Error!Self {
            config.validate();
            var metadata = try Metadata.init(gpa, storage, .{
                .partition = config.metadata_partition,
                .codec_config = {},
            });
            errdefer metadata.deinit();
            // Without a committed checkpoint, the freezer treats stored blobs as uncommitted.
            const checkpoint: ?freezer_mod.Checkpoint = if (metadata.get(freezer_key)) |record|
                record.freezer
            else
                null;
            var freezer = try Freezer.init(
                gpa,
                storage,
                scope.child("freezer"),
                freezer_config(config),
                checkpoint,
            );
            errdefer freezer.deinit();
            var ordinal = try open_ordinal(gpa, storage, scope, config, &metadata);
            errdefer ordinal.deinit();
            var self: Self = .{
                .gpa = gpa,
                .items_per_section = config.items_per_section,
                .metadata = metadata,
                .freezer = freezer,
                .ordinal = ordinal,
                .gets = try scope.counter("gets", "Number of gets performed"),
                .has_checks = undefined,
                .syncs = undefined,
            };
            errdefer self.gets.deinit();
            self.has_checks = try scope.counter("has", "Number of has performed");
            errdefer self.has_checks.deinit();
            self.syncs = try scope.counter("syncs", "Number of syncs called");
            assert(!self.failed);
            return self;
        }

        fn freezer_config(config: Cfg) freezer_mod.Config(V) {
            return .{
                .key_partition = config.freezer_key_partition,
                .key_write_buffer = config.freezer_key_write_buffer,
                .key_cache_ref = config.freezer_key_cache_ref,
                .value_partition = config.freezer_value_partition,
                .value_compression = config.freezer_value_compression,
                .value_write_buffer = config.freezer_value_write_buffer,
                .value_target_size = config.freezer_value_target_size,
                .table_partition = config.freezer_table_partition,
                .table_initial_size = config.freezer_table_initial_size,
                .table_resize_frequency = config.freezer_table_resize_frequency,
                .table_resize_chunk_size = config.freezer_table_resize_chunk_size,
                .table_replay_buffer = config.replay_buffer,
                .codec_config = config.codec_config,
            };
        }

        /// Open the ordinal with the committed sections the metadata names. Stored sections
        /// it omits are removed, so an empty list is a committed empty ordinal.
        fn open_ordinal(
            gpa: Allocator,
            storage: runtime.storage.Storage,
            scope: metrics.Scope,
            config: Cfg,
            metadata: *const Metadata,
        ) Error!Ordinal {
            var sections: std.ArrayList(ordinal_mod.SectionBits) = .empty;
            defer sections.deinit(gpa);
            // Metadata entries are sorted by encoded key: ordinal sections ascend.
            // Iterate by pointer: `bits` must point into the metadata, not a loop copy.
            for (metadata.items()) |*entry| {
                if (entry.key.prefix() != mod.ordinal_prefix) continue;
                const bits: ?*const BitMap = switch (entry.value) {
                    .ordinal => |*bits| if (bits.*) |*present| present else null,
                    .freezer => return error.RecordCorrupted,
                };
                // A partial section's bitmap spans the whole section: a length mismatch would
                // serve records at the wrong indices.
                if (bits) |present| {
                    if (present.len() != config.items_per_section) return error.RecordCorrupted;
                }
                try sections.append(gpa, .{ .section = entry.key.value(), .bits = bits });
            }
            return Ordinal.init(gpa, storage, scope.child("ordinal"), .{
                .partition = config.ordinal_partition,
                .items_per_blob = config.items_per_section,
                .write_buffer = config.ordinal_write_buffer,
                .replay_buffer = config.replay_buffer,
            }, sections.items);
        }

        /// Close every store (dropping uncommitted data) and free the archive.
        pub fn deinit(self: *Self) void {
            self.metadata.deinit();
            self.freezer.deinit();
            self.ordinal.deinit();
            self.release_metrics();
        }

        fn release_metrics(self: *Self) void {
            self.gets.deinit();
            self.has_checks.deinit();
            self.syncs.deinit();
            self.* = undefined;
        }

        /// Store `value` at `index` under `key`. A no-op when `index` is already stored.
        pub fn put(self: *Self, index: u64, key: K, value: V) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            if (self.ordinal.has(index)) return;
            try self.mark(index);
            const cursor = try self.freezer.put(key, value);
            try self.ordinal.put(index, cursor);
            assert(self.ordinal.has(index));
        }

        /// Set the bit of `index` in its section's committed bitmap, creating the bitmap, and
        /// replace a full bitmap with null.
        fn mark(self: *Self, index: u64) Error!void {
            const section = index / self.items_per_section;
            const key = PrefixedU64.init(mod.ordinal_prefix, section);
            if (self.metadata.get(key) == null) {
                var bits = try BitMap.zeroes(self.gpa, self.items_per_section);
                errdefer bits.deinit(self.gpa);
                const previous = try self.metadata.put(key, .{ .ordinal = bits });
                assert(previous == null);
            }
            const record = (try self.metadata.get_mut(key)).?;
            const bits = switch (record.*) {
                .ordinal => |*bits| if (bits.*) |*present| present else return,
                .freezer => unreachable, // Ordinal keys only hold ordinal records.
            };
            assert(bits.len() == self.items_per_section);
            bits.set(index % self.items_per_section, true);
            if (bits.count_ones() == self.items_per_section) {
                bits.deinit(self.gpa);
                record.* = .{ .ordinal = null };
            }
        }

        /// `put` then `sync`.
        pub fn put_sync(self: *Self, index: u64, key: K, value: V) Error!void {
            try self.put(index, key, value);
            try self.sync();
        }

        /// The value at `index` or under `key`. Free it with `codec.free` if `V` owns memory.
        pub fn get(self: *Self, identifier: Identifier) Error!?V {
            return self.get_with(identifier, self.gpa);
        }

        /// `get`, decoding the value's memory from `value_gpa` (such as a buffer the caller
        /// reuses across reads).
        pub fn get_with(self: *Self, identifier: Identifier, value_gpa: Allocator) Error!?V {
            assert(!self.failed);
            self.gets.metric().inc();
            return switch (identifier) {
                .index => |index| {
                    const cursor = try self.ordinal.get(index) orelse return null;
                    return try self.freezer.get_with(.{ .cursor = cursor }, value_gpa);
                },
                .key => |key| try self.freezer.get_with(.{ .key = key }, value_gpa),
            };
        }

        /// `get_with` for every identifier at once: `values[i]` is the value of
        /// `identifiers[i]`, or null. Indices and keys are resolved one after another, then up
        /// to `workers` values are read at once as tasks on `io` (`Freezer.get_many`, whose
        /// requirements apply).
        pub fn get_many(
            self: *Self,
            io: std.Io,
            identifiers: []const Identifier,
            value_gpa: Allocator,
            values: []?V,
            workers: u32,
        ) Error!void {
            assert(!self.failed);
            assert(identifiers.len == values.len);
            const FreezerIdentifier = Freezer.Identifier;
            const resolved = try self.gpa.alloc(?FreezerIdentifier, identifiers.len);
            defer self.gpa.free(resolved);
            var present: usize = 0;
            for (identifiers, resolved) |identifier, *target| {
                self.gets.metric().inc();
                target.* = switch (identifier) {
                    .index => |index| if (try self.ordinal.get(index)) |cursor|
                        .{ .cursor = cursor }
                    else
                        null,
                    .key => |key| .{ .key = key },
                };
                if (target.* != null) present += 1;
            }
            const lookups = try self.gpa.alloc(FreezerIdentifier, present);
            defer self.gpa.free(lookups);
            const found = try self.gpa.alloc(?V, present);
            defer self.gpa.free(found);
            var next: usize = 0;
            for (resolved) |target| {
                lookups[next] = target orelse continue;
                next += 1;
            }
            assert(next == present);
            try self.freezer.get_many(io, lookups, value_gpa, found, workers);
            next = 0;
            for (resolved, values) |target, *value| {
                value.* = null;
                if (target == null) continue;
                value.* = found[next];
                next += 1;
            }
            assert(next == present);
        }

        /// Whether `index` is stored, or `key` is.
        pub fn has(self: *Self, identifier: Identifier) Error!bool {
            assert(!self.failed);
            self.has_checks.metric().inc();
            return switch (identifier) {
                .index => |index| self.ordinal.has(index),
                .key => |key| try self.freezer.has(key.*),
            };
        }

        /// Make the freezer and ordinal durable, then commit the freezer checkpoint and
        /// section bitmaps with one metadata sync.
        pub fn sync(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            self.syncs.metric().inc();
            const checkpoint = try self.freezer.sync();
            try self.ordinal.sync();
            try self.metadata.put_sync(freezer_key, .{ .freezer = checkpoint });
            assert(self.metadata.get(freezer_key) != null);
        }

        /// commonware's default `start_sync`: `sync`, then a completed completion.
        pub fn start_sync(self: *Self) Error!runtime.storage.Completion {
            try self.sync();
            return .ok;
        }

        pub fn next_gap(self: *const Self, index: u64) rmap.Gap {
            return self.ordinal.next_gap(index);
        }

        pub fn missing_items(self: *const Self, start: u64, out: []u64) []u64 {
            return self.ordinal.missing_items(start, out);
        }

        pub fn ranges(self: *const Self) []const rmap.Range {
            return self.ordinal.ranges();
        }

        pub fn ranges_from(self: *const Self, from: u64) []const rmap.Range {
            return self.ordinal.ranges_from(from);
        }

        pub fn first_index(self: *const Self) ?u64 {
            return self.ordinal.first_index();
        }

        pub fn last_index(self: *const Self) ?u64 {
            return self.ordinal.last_index();
        }

        /// Remove all persistent data and free the archive. The commit record goes first:
        /// whatever an interrupted destroy leaves behind is then uncommitted, and the next
        /// `init` discards it.
        pub fn destroy(self: *Self) Error!void {
            defer self.release_metrics();
            self.metadata.destroy() catch |err| {
                self.ordinal.deinit();
                self.freezer.deinit();
                return err;
            };
            self.ordinal.destroy() catch |err| {
                self.freezer.deinit();
                return err;
            };
            try self.freezer.destroy();
        }
    };
}
