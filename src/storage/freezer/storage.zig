//! The `Freezer` implementation (commonware's `freezer/storage.rs`).
//!
//! A table blob of `table_size` entries maps `crc32(key) & (table_size - 1)` to the head of a
//! collision chain of key records in an oversized journal (keys in its fixed index, values in
//! its glob). Each table entry holds two slots; a write goes to the slot of the current epoch,
//! or else to the older (or empty) one, so a torn table write never loses the committed head.

const std = @import("std");
const utils = @import("utils");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const oversized_mod = @import("../journal/segmented/oversized.zig");
const records = @import("records.zig");
const mod = @import("mod.zig");

const Blob = runtime.storage.Blob;
const Cursor = records.Cursor;
const Checkpoint = records.Checkpoint;
const Entry = records.Entry;

/// The percentage of table entries that must reach `table_resize_frequency` before a resize.
const resize_threshold_percent: u64 = 50;
/// Name of the table blob.
pub const table_blob_name = "table";

/// The latest valid slot of a table entry.
const Head = struct { section: u64, position: u64, added: u8 };

/// Byte offset of table entry `table_index`.
fn table_offset(table_index: u64) u64 {
    return table_index * Entry.full_size;
}

fn parse_entries(bytes: *const [Entry.full_size]u8) [2]Entry {
    var reader = codec.Reader.init(bytes);
    // unreachable: entries read any 29 bytes, and the buffer holds exactly two of them.
    const first = Entry.read(Allocator.failing, &reader, {}) catch unreachable;
    const second = Entry.read(Allocator.failing, &reader, {}) catch unreachable;
    assert(reader.remaining() == 0);
    return .{ first, second };
}

fn read_table(table: Blob, table_index: u64) runtime.storage.Error![2]Entry {
    var bytes: [Entry.full_size]u8 = undefined;
    try table.read_at(table_offset(table_index), &bytes);
    return parse_entries(&bytes);
}

/// The slot (byte offset within the entry) a write at `epoch` goes to: the slot already
/// written this epoch, else the empty or older slot.
fn compute_write_offset(first: Entry, second: Entry, epoch: u64) u64 {
    if (!first.is_empty() and first.epoch == epoch) return 0;
    if (!second.is_empty() and second.epoch == epoch) return Entry.fixed_size;
    if (first.is_empty()) return 0;
    if (second.is_empty()) return Entry.fixed_size;
    return if (first.epoch < second.epoch) 0 else Entry.fixed_size;
}

/// The latest valid slot of an entry, if any.
fn read_latest_entry(first: Entry, second: Entry) ?Head {
    const first_valid = !first.is_empty() and first.is_valid();
    const second_valid = !second.is_empty() and second.is_valid();
    const pick: Entry = if (first_valid and second_valid) pick: {
        assert(first.epoch != second.epoch); // Two valid slots never share an epoch.
        break :pick if (first.epoch > second.epoch) first else second;
    } else if (first_valid) first else if (second_valid) second else return null;
    return .{ .section = pick.section, .position = pick.position, .added = pick.added };
}

fn encode_entry(entry: Entry) [Entry.fixed_size]u8 {
    return codec.encode_fixed(Entry, entry);
}

/// The two slots of an entry with the slot chosen for `update` replaced.
fn rewrite_entries(first: Entry, second: Entry, update: Entry) [Entry.full_size]u8 {
    var bytes: [Entry.full_size]u8 = undefined;
    const first_slot = compute_write_offset(first, second, update.epoch) == 0;
    bytes[0..Entry.fixed_size].* = encode_entry(if (first_slot) update else first);
    bytes[Entry.fixed_size..].* = encode_entry(if (first_slot) second else update);
    return bytes;
}

/// An immutable key-value store. An error from a mutating method (`put`, `sync`, `close`)
/// leaves the freezer failed: only `deinit` may follow.
pub fn Freezer(comptime K: type, comptime V: type) type {
    const key_size = codec.fixed_size(K) orelse @compileError("freezer keys are fixed-size");
    return struct {
        const Self = @This();
        pub const Record = records.Record(K);
        pub const Oversized = oversized_mod.Oversized(Record, V);
        pub const Error = Oversized.Error || error{CheckpointMismatch};
        pub const Identifier = union(enum) { cursor: Cursor, key: *const K };

        gpa: Allocator,
        storage: runtime.storage.Storage,
        table_partition: []const u8,
        table_size: u32,
        table_resize_threshold: u64,
        table_resize_frequency: u8,
        table_resize_chunk_size: u32,
        table: Blob,
        oversized: Oversized,
        blob_target_size: u64,
        current_section: u64,
        /// End of the last value in the current section.
        current_value_size: u64,
        next_epoch: u64,
        /// Sections with unsynced appends, ascending and unique.
        modified_sections: std.ArrayList(u64) = .empty,
        resizable: u32,
        resize_progress: ?u32 = null,
        failed: bool = false,

        puts: metrics.Counter,
        gets: metrics.Counter,
        has_checks: metrics.Counter,
        unnecessary_reads: metrics.Counter,
        unnecessary_writes: metrics.Counter,
        resizes: metrics.Counter,

        /// Open the freezer, aligning stored data to `checkpoint`. A null or empty checkpoint
        /// deletes any existing freezer data and starts empty.
        pub fn init(
            gpa: Allocator,
            storage: runtime.storage.Storage,
            scope: metrics.Scope,
            config: mod.Config(V),
            checkpoint_or_null: ?Checkpoint,
        ) Error!Self {
            config.validate();
            const reset = if (checkpoint_or_null) |c| c.is_empty() else true;
            if (reset) try remove_partitions(storage, config);
            const restored: oversized_mod.Checkpoint = if (reset)
                .{ .section = 0, .size = 0 }
            else
                .{
                    .section = checkpoint_or_null.?.section,
                    .size = checkpoint_or_null.?.oversized_size,
                };
            var oversized = try Oversized.init_with_checkpoint(gpa, storage, .{
                .index_partition = config.key_partition,
                .value_partition = config.value_partition,
                .index_cache_ref = config.key_cache_ref,
                .index_write_buffer = config.key_write_buffer,
                .value_write_buffer = config.value_write_buffer,
                .replay_buffer = config.table_replay_buffer,
                .compression = config.value_compression,
                .codec_config = config.codec_config,
            }, restored);
            errdefer oversized.deinit();
            const opened = try storage.open(config.table_partition, table_blob_name);
            errdefer opened.blob.close();
            const checkpoint: Checkpoint, const resizable: u32 = if (reset) fresh: {
                try opened.blob.resize(table_offset(config.table_initial_size));
                try opened.blob.sync();
                break :fresh .{ Checkpoint.init(config.table_initial_size), 0 };
            } else .{
                checkpoint_or_null.?,
                try align_table(gpa, opened, config, checkpoint_or_null.?),
            };
            const current_value_size = try oversized.value_size(checkpoint.section);
            var self = try init_metrics(scope);
            self.gpa = gpa;
            self.storage = storage;
            self.table_partition = config.table_partition;
            self.table_size = checkpoint.table_size;
            self.table_resize_threshold = resize_threshold(checkpoint.table_size);
            self.table_resize_frequency = config.table_resize_frequency;
            self.table_resize_chunk_size = config.table_resize_chunk_size;
            self.table = opened.blob;
            self.oversized = oversized;
            self.blob_target_size = config.value_target_size;
            self.current_section = checkpoint.section;
            self.current_value_size = current_value_size;
            self.next_epoch = std.math.add(u64, checkpoint.epoch, 1) catch @panic("epoch overflow");
            self.resizable = resizable;
            return self;
        }

        fn resize_threshold(table_size: u32) u64 {
            return @as(u64, table_size) * resize_threshold_percent / 100;
        }

        fn remove_partitions(storage: runtime.storage.Storage, config: mod.Config(V)) Error!void {
            const partitions = [_][]const u8{
                config.key_partition,
                config.value_partition,
                config.table_partition,
            };
            for (partitions) |partition| {
                storage.remove(partition, null) catch |err| switch (err) {
                    error.PartitionMissing => {},
                    else => return err,
                };
            }
        }

        fn init_metrics(scope: metrics.Scope) Error!Self {
            var self: Self = undefined;
            self.puts = try scope.counter("puts", "number of put operations");
            errdefer self.puts.deinit();
            self.gets = try scope.counter("gets", "number of get operations");
            errdefer self.gets.deinit();
            self.has_checks = try scope.counter("has", "number of has operations");
            errdefer self.has_checks.deinit();
            self.unnecessary_reads = try scope.counter(
                "unnecessary_reads",
                "number of unnecessary reads performed during key lookups",
            );
            errdefer self.unnecessary_reads.deinit();
            self.unnecessary_writes = try scope.counter(
                "unnecessary_writes",
                "number of unnecessary writes performed during resize",
            );
            errdefer self.unnecessary_writes.deinit();
            self.resizes = try scope.counter("resizes", "number of table resizing operations");
            self.modified_sections = .empty;
            self.resize_progress = null;
            self.failed = false;
            return self;
        }

        /// Align an existing table to a non-empty checkpoint: shrink it to the checkpoint's
        /// size and clear slots that are invalid or newer than the checkpoint's epoch.
        /// Returns the number of resizable entries.
        fn align_table(
            gpa: Allocator,
            opened: runtime.storage.Opened,
            config: mod.Config(V),
            checkpoint: Checkpoint,
        ) Error!u32 {
            // A non-empty checkpoint against an empty table references data that does not exist.
            if (opened.len == 0) return error.CheckpointMismatch;
            assert(checkpoint.table_size > 0 and std.math.isPowerOfTwo(checkpoint.table_size));
            // Growing is never valid: the checkpoint publishes only after the table sync, so
            // zero-extending would fabricate empty heads.
            const expected_len = table_offset(checkpoint.table_size);
            if (opened.len < expected_len) return error.CheckpointMismatch;
            var modified = opened.len != expected_len;
            if (modified) try opened.blob.resize(expected_len);
            const resizable = try recover_table(gpa, opened.blob, config, checkpoint, &modified);
            if (modified) try opened.blob.sync();
            return resizable;
        }

        /// Scan the table, clearing every non-empty slot that is invalid or newer than
        /// `checkpoint.epoch`, and count the entries whose latest slot reached the resize
        /// frequency.
        fn recover_table(
            gpa: Allocator,
            table: Blob,
            config: mod.Config(V),
            checkpoint: Checkpoint,
            modified: *bool,
        ) Error!u32 {
            const entries_per_read = @max(1, config.table_replay_buffer / Entry.full_size);
            const buffer = try gpa.alloc(u8, entries_per_read * Entry.full_size);
            defer gpa.free(buffer);
            var resizable: u32 = 0;
            var table_index: u32 = 0;
            while (table_index < checkpoint.table_size) {
                const left = checkpoint.table_size - table_index;
                const count: u32 = @intCast(@min(entries_per_read, left));
                const chunk = buffer[0 .. count * Entry.full_size];
                try table.read_at(table_offset(table_index), chunk);
                for (0..count) |i| {
                    const index = table_index + @as(u32, @intCast(i));
                    const bytes = chunk[i * Entry.full_size ..][0..Entry.full_size];
                    var entries = parse_entries(bytes);
                    for (&entries, 0..) |*entry, slot| {
                        const offset = table_offset(index) + slot * Entry.fixed_size;
                        if (try recover_entry(table, entry, offset, checkpoint.epoch)) {
                            modified.* = true;
                        }
                    }
                    const head = read_latest_entry(entries[0], entries[1]) orelse continue;
                    if (head.added >= config.table_resize_frequency) resizable += 1;
                }
                table_index += count;
            }
            return resizable;
        }

        /// Clear a non-empty slot that is invalid or newer than `max_valid_epoch`. Returns
        /// whether it was cleared.
        fn recover_entry(table: Blob, entry: *Entry, offset: u64, max_valid_epoch: u64) Error!bool {
            if (entry.is_empty()) return false;
            if (entry.is_valid() and entry.epoch <= max_valid_epoch) return false;
            entry.* = .empty;
            const zeros: [Entry.fixed_size]u8 = @splat(0);
            try table.write_at(offset, &zeros, .{});
            return true;
        }

        /// Close every blob (dropping unsynced data).
        pub fn deinit(self: *Self) void {
            self.table.close();
            self.oversized.deinit();
            self.release();
        }

        fn release(self: *Self) void {
            self.modified_sections.deinit(self.gpa);
            self.puts.deinit();
            self.gets.deinit();
            self.has_checks.deinit();
            self.unnecessary_reads.deinit();
            self.unnecessary_writes.deinit();
            self.resizes.deinit();
            self.* = undefined;
        }

        /// The table index of `key`: its CRC32C masked to the table size.
        fn key_table_index(self: *const Self, key: K) u32 {
            assert(std.math.isPowerOfTwo(self.table_size));
            const bytes: [key_size]u8 = codec.encode_fixed(K, key);
            return cryptography.Crc32.checksum(&bytes) & (self.table_size - 1);
        }

        fn should_resize(self: *const Self) bool {
            return @as(u64, self.resizable) >= self.table_resize_threshold;
        }

        /// Move to a new section once the current one reaches the target size.
        fn update_section(self: *Self) Error!void {
            if (self.current_value_size < self.blob_target_size) return;
            self.current_section += 1;
            self.current_value_size = try self.oversized.value_size(self.current_section);
        }

        fn write_head(
            self: *Self,
            table_index_value: u64,
            entries: [2]Entry,
            update: Entry,
        ) Error!void {
            const start = compute_write_offset(entries[0], entries[1], update.epoch);
            const bytes = encode_entry(update);
            try self.table.write_at(table_offset(table_index_value) + start, &bytes, .{});
        }

        /// Store `value` under `key`, returning its cursor. Keys need not be unique: a later
        /// put shadows earlier ones for key lookups.
        pub fn put(self: *Self, key: K, value: V) Error!Cursor {
            assert(!self.failed);
            errdefer self.failed = true;
            self.puts.metric().inc();
            try self.update_section();
            const index = self.key_table_index(key);
            const entries = try read_table(self.table, index);
            const head = read_latest_entry(entries[0], entries[1]);
            const link: ?[2]u64 = if (head) |h| .{ h.section, h.position } else null;
            const record = Record.init(key, link, 0, 0);
            const section = self.current_section;
            try self.modified_sections.ensureUnusedCapacity(self.gpa, 1);
            const appended = try self.oversized.append(section, record, value);
            self.current_value_size = appended.offset + appended.size;
            const added = if (head) |h| h.added +| 1 else 1;
            if (added == self.table_resize_frequency) self.resizable += 1;
            insert_sorted(&self.modified_sections, section);
            const update = Entry.init(self.next_epoch, section, appended.position, added);
            try self.write_head(index, entries, update);
            // Mid-resize, an entry already split must update its new copy too. The copies
            // are still identical, so the old slots stand in for the new ones.
            if (self.resize_progress) |progress| {
                if (index < progress) {
                    self.unnecessary_writes.metric().inc();
                    if (added == self.table_resize_frequency) self.resizable += 1;
                    try self.write_head(@as(u64, self.table_size) + index, entries, update);
                }
            }
            return Cursor.init(section, appended.offset, appended.size);
        }

        fn insert_sorted(list: *std.ArrayList(u64), section: u64) void {
            const items = list.items;
            var position: usize = items.len;
            while (position > 0 and items[position - 1] >= section) position -= 1;
            if (position < items.len and items[position] == section) return;
            list.insertAssumeCapacity(position, section);
            // O(1): the scan above leaves smaller keys before `position` and larger after.
            assert(list.items[position] == section);
            assert(position == 0 or list.items[position - 1] < section);
            assert(position + 1 == list.items.len or list.items[position + 1] > section);
        }

        /// The first record matching `key` and its section, reading key records only.
        fn find_key(self: *Self, key: K) Error!?struct { u64, Record } {
            const entries = try read_table(self.table, self.key_table_index(key));
            const head = read_latest_entry(entries[0], entries[1]) orelse return null;
            var section = head.section;
            var position = head.position;
            const key_bytes: [key_size]u8 = codec.encode_fixed(K, key);
            // Each step follows a strictly older link, so the walk ends within the store.
            while (true) {
                const record = try self.oversized.get(section, position);
                const record_key: [key_size]u8 = codec.encode_fixed(K, record.key);
                if (utils.bytes_eql(key_size, &record_key, &key_bytes)) return .{ section, record };
                self.unnecessary_reads.metric().inc();
                const next = record.next() orelse return null;
                section = next[0];
                position = next[1];
            }
        }

        /// The value for `identifier`, or null for an unknown key. Free it with `codec.free`.
        pub fn get(self: *Self, identifier: Identifier) Error!?V {
            return self.get_with(identifier, self.gpa);
        }

        /// `get`, decoding the value's memory from `value_gpa` (such as a buffer the caller
        /// reuses across reads).
        pub fn get_with(self: *Self, identifier: Identifier, value_gpa: Allocator) Error!?V {
            const section, const offset, const size = switch (identifier) {
                .cursor => |cursor| .{ cursor.section(), cursor.offset(), cursor.size() },
                .key => |key| found: {
                    self.gets.metric().inc();
                    const section, const record = try self.find_key(key.*) orelse return null;
                    break :found .{ section, record.value_offset, record.value_size };
                },
            };
            return try self.oversized.get_value_with(section, offset, size, value_gpa);
        }

        /// Whether a value exists for `key` (walks the chain without reading values).
        pub fn has(self: *Self, key: K) Error!bool {
            self.has_checks.metric().inc();
            return (try self.find_key(key)) != null;
        }

        /// The next table entry a running resize will split, or null when not resizing.
        pub fn resizing(self: *const Self) ?u32 {
            return self.resize_progress;
        }

        /// The number of table entries whose head reached the resize frequency.
        pub fn resizable_entries(self: *const Self) u32 {
            return self.resizable;
        }

        /// Double the table and start splitting entries (nothing at the maximum size).
        fn start_resize(self: *Self) Error!void {
            self.resizes.metric().inc();
            const new_size = std.math.mul(u32, self.table_size, 2) catch return;
            try self.table.resize(table_offset(new_size));
            self.resize_progress = 0;
        }

        /// Split the next `table_resize_chunk_size` entries: each head is copied, with its
        /// `added` count reset, to its old index and to `old index + old size`.
        fn advance_resize(self: *Self) Error!void {
            const current = self.resize_progress.?;
            const old_size = self.table_size;
            const chunk_end = @min(current +| self.table_resize_chunk_size, old_size);
            assert(chunk_end > current);
            const chunk_len = (chunk_end - current) * Entry.full_size;
            const read = try self.gpa.alloc(u8, chunk_len);
            defer self.gpa.free(read);
            const writes = try self.gpa.alloc(u8, chunk_len);
            defer self.gpa.free(writes);
            const read_offset = table_offset(current);
            try self.table.read_at(read_offset, read);
            for (0..chunk_end - current) |i| {
                const bytes = read[i * Entry.full_size ..][0..Entry.full_size];
                const entries = parse_entries(bytes);
                const reset: Entry = if (read_latest_entry(entries[0], entries[1])) |head| reset: {
                    if (head.added >= self.table_resize_frequency) self.resizable -= 1;
                    break :reset Entry.init(self.next_epoch, head.section, head.position, 0);
                } else .empty;
                writes[i * Entry.full_size ..][0..Entry.full_size].* =
                    rewrite_entries(entries[0], entries[1], reset);
            }
            try self.table.write_at(read_offset, writes, .{});
            try self.table.write_at(table_offset(old_size) + read_offset, writes, .{});
            if (chunk_end >= old_size) {
                self.table_size = old_size * 2;
                self.table_resize_threshold = resize_threshold(self.table_size);
                self.resize_progress = null;
            } else {
                self.resize_progress = chunk_end;
            }
        }

        /// Sync pending data and return the checkpoint to restore it from. A resize starts
        /// here when needed and advances one chunk per sync.
        pub fn sync(self: *Self) Error!Checkpoint {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.oversized.sync(self.modified_sections.items);
            self.modified_sections.clearRetainingCapacity();
            if (self.should_resize() and self.resize_progress == null) try self.start_resize();
            if (self.resize_progress != null) try self.advance_resize();
            try self.table.sync();
            const stored_epoch = self.next_epoch;
            self.next_epoch = std.math.add(u64, stored_epoch, 1) catch @panic("epoch overflow");
            const checkpoint: Checkpoint = .{
                .epoch = stored_epoch,
                .section = self.current_section,
                .oversized_size = try self.oversized.size(self.current_section),
                .table_size = self.table_size,
            };
            assert(!checkpoint.is_empty());
            return checkpoint;
        }

        /// Finish any resize, sync, and close, returning the checkpoint for recovery.
        pub fn close(self: *Self) Error!Checkpoint {
            assert(!self.failed);
            {
                errdefer self.failed = true;
                while (self.resize_progress != null) try self.advance_resize();
            }
            const checkpoint = try self.sync();
            self.deinit();
            return checkpoint;
        }

        /// Remove every blob created by the freezer and free it.
        pub fn destroy(self: *Self) Error!void {
            defer self.release();
            self.table.close();
            const oversized_result = self.oversized.destroy();
            try self.storage.remove(self.table_partition, table_blob_name);
            try self.storage.remove(self.table_partition, null);
            return oversized_result;
        }
    };
}
