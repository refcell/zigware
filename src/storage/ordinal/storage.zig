//! The `Ordinal` implementation (commonware's `ordinal/storage.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const rmap = @import("../rmap/mod.zig");
const mod = @import("mod.zig");

const Write = runtime.buffer.Write;
const Blob = runtime.storage.Blob;
const BitMap = mod.BitMap;
const SectionBits = mod.SectionBits;
const Config = mod.Config;

pub const Error = runtime.storage.Error || error{
    /// A blob name is not an 8-byte big-endian section number.
    InvalidBlobName,
    /// A stored record fails its checksum or does not decode.
    InvalidRecord,
    /// A record the caller's bits require is missing or invalid.
    MissingRecord,
};

/// A record in an index blob: the fixed-size value followed by the CRC32 of its bytes.
pub fn Record(comptime V: type) type {
    const value_size = codec.fixed_size(V) orelse @compileError("ordinal values are fixed-size");
    comptime assert(!codec.owns_memory(V));
    comptime assert(codec.Cfg(V) == void);
    return struct {
        const Self = @This();
        pub const fixed_size: usize = value_size + 4;

        value: V,
        crc: u32,

        /// Serialize `value` followed by the CRC of its serialized bytes.
        pub fn encode(value: V) [fixed_size]u8 {
            var bytes: [fixed_size]u8 = undefined;
            bytes[0..value_size].* = codec.encode_fixed(V, value);
            const crc = cryptography.Crc32.checksum(bytes[0..value_size]);
            std.mem.writeInt(u32, bytes[value_size..], crc, .big);
            assert(decode_valid(&bytes) != null or !decodes(bytes[0..value_size]));
            return bytes;
        }

        fn decodes(bytes: *const [value_size]u8) bool {
            _ = codec.decode_fixed(V, bytes) catch return false;
            return true;
        }

        /// The value, only if the stored CRC matches the value bytes and the value decodes.
        pub fn decode_valid(bytes: *const [fixed_size]u8) ?V {
            const crc = cryptography.Crc32.checksum(bytes[0..value_size]);
            const stored = std.mem.readInt(u32, bytes[value_size..], .big);
            if (crc != stored) return null;
            return codec.decode_fixed(V, bytes[0..value_size]) catch null;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(V, self.value, writer);
            writer.write_int(u32, self.crc);
        }

        pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const value = try codec.read_fixed(V, reader);
            const crc = try reader.read_int(u32);
            return .{ .value = value, .crc = crc };
        }
    };
}

/// A persistent map from sparse `u64` indices to fixed-size values.
///
/// An error from a mutating method (`put`, `sync`, `prune`) leaves the store failed: only
/// `deinit` may follow (commonware consumes the handle on error).
pub fn Ordinal(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const RecordType = Record(V);
        const record_size: u64 = RecordType.fixed_size;

        gpa: Allocator,
        storage: runtime.storage.Storage,
        config: Config,
        /// One write-buffered index blob per section.
        blobs: std.AutoHashMapUnmanaged(u64, Write) = .empty,
        intervals: rmap.RMap = .empty,
        /// Sections with unsynced writes, ascending and unique.
        pending: std.ArrayList(u64) = .empty,
        failed: bool = false,

        puts: metrics.Counter,
        gets: metrics.Counter,
        has_checks: metrics.Counter,
        syncs: metrics.Counter,
        pruned: metrics.Counter,

        /// A stored section opened during recovery.
        const Opened = struct { section: u64, blob: Blob, len: u64 };

        /// Open the store. `bits` lists, by ascending section, which records the caller
        /// durably committed: a bitmap marks the committed records of its section, and a null
        /// bitmap requires every record of the section. Stored sections that `bits` omits or
        /// marks nothing in are removed. Null `bits` (or an empty list) removes every stored
        /// section and starts empty.
        pub fn init(
            gpa: Allocator,
            storage: runtime.storage.Storage,
            scope: metrics.Scope,
            config: Config,
            bits: ?[]const SectionBits,
        ) Error!Self {
            return init_diagnostic(gpa, storage, scope, config, bits, null);
        }

        /// `init` that stores the index of a `MissingRecord` or `InvalidRecord` failure in
        /// `failed_index` (commonware's error payload).
        pub fn init_diagnostic(
            gpa: Allocator,
            storage: runtime.storage.Storage,
            scope: metrics.Scope,
            config: Config,
            bits: ?[]const SectionBits,
            failed_index: ?*u64,
        ) Error!Self {
            config.validate();
            if (bits) |list| assert_sorted(list);
            var opened: std.ArrayList(Opened) = .empty;
            defer opened.deinit(gpa);
            defer for (opened.items) |entry| entry.blob.close();
            try open_stored(gpa, storage, config, bits, &opened);
            var intervals = try recover(gpa, config, opened.items, bits, failed_index);
            var self = init_metrics(gpa, storage, scope, config) catch |err| {
                intervals.deinit(gpa);
                return err;
            };
            self.intervals = intervals;
            errdefer self.deinit();
            try self.blobs.ensureTotalCapacity(gpa, @intCast(opened.items.len));
            // Wrap blobs in write buffers, taking ownership of each one as it is wrapped.
            while (opened.pop()) |entry| {
                const capacity = config.write_buffer;
                const writer = Write.init(gpa, entry.blob, entry.len, capacity) catch |err| {
                    entry.blob.close();
                    return err;
                };
                self.blobs.putAssumeCapacityNoClobber(entry.section, writer);
            }
            // Without bits the store starts empty.
            assert(bits != null or (self.blobs.count() == 0 and self.intervals.count() == 0));
            return self;
        }

        /// Clear unmarked records and rebuild the intervals from the committed ones.
        fn recover(
            gpa: Allocator,
            config: Config,
            opened: []const Opened,
            bits: ?[]const SectionBits,
            failed_index: ?*u64,
        ) Error!rmap.RMap {
            var intervals: rmap.RMap = .empty;
            errdefer intervals.deinit(gpa);
            const list = bits orelse return intervals;
            assert(opened.len <= list.len);
            try clear_unmarked(gpa, config, opened, list);
            var diagnostic: u64 = 0;
            rebuild(gpa, config, opened, list, &intervals, &diagnostic) catch |err| {
                if (failed_index) |out| out.* = diagnostic;
                return err;
            };
            return intervals;
        }

        fn init_metrics(
            gpa: Allocator,
            storage: runtime.storage.Storage,
            scope: metrics.Scope,
            config: Config,
        ) Error!Self {
            var puts = try scope.counter("puts", "Number of put calls");
            errdefer puts.deinit();
            var gets = try scope.counter("gets", "Number of get calls");
            errdefer gets.deinit();
            var has_checks = try scope.counter("has", "Number of has calls");
            errdefer has_checks.deinit();
            var syncs = try scope.counter("syncs", "Number of sync calls");
            errdefer syncs.deinit();
            const pruned = try scope.counter("pruned", "Number of pruned blobs");
            return .{
                .gpa = gpa,
                .storage = storage,
                .config = config,
                .puts = puts,
                .gets = gets,
                .has_checks = has_checks,
                .syncs = syncs,
                .pruned = pruned,
            };
        }

        fn assert_sorted(list: []const SectionBits) void {
            if (list.len < 2) return;
            for (list[1..], list[0 .. list.len - 1]) |entry, previous| {
                assert(entry.section > previous.section);
            }
        }

        /// The bits entry for `section`, or null if `bits` omits it.
        fn find_bits(list: []const SectionBits, section: u64) ?SectionBits {
            var low: usize = 0;
            var high: usize = list.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                if (list[middle].section < section) low = middle + 1 else high = middle;
            }
            if (low < list.len and list[low].section == section) return list[low];
            assert(low == list.len or list[low].section > section);
            return null;
        }

        /// Reset the partition (null bits) or open the stored sections `bits` keeps, removing
        /// the rest unopened and truncating each kept blob to whole records.
        fn open_stored(
            gpa: Allocator,
            storage: runtime.storage.Storage,
            config: Config,
            bits: ?[]const SectionBits,
            opened: *std.ArrayList(Opened),
        ) Error!void {
            const list = bits orelse {
                storage.remove(config.partition, null) catch |err| switch (err) {
                    error.PartitionMissing => {},
                    else => return err,
                };
                return;
            };
            const names = storage.scan(gpa, config.partition) catch |err| switch (err) {
                error.PartitionMissing => return,
                else => return err,
            };
            defer names.deinit(gpa);
            try opened.ensureTotalCapacity(gpa, names.items.len);
            for (names.items) |name| {
                if (name.len != 8) return error.InvalidBlobName;
                const section = std.mem.readInt(u64, name[0..8], .big);
                // A section the bits omit or mark nothing in is removed without being opened,
                // so a discarded section is never repaired.
                const keep = if (find_bits(list, section)) |entry|
                    entry.bits == null or entry.bits.?.count_ones() != 0
                else
                    false;
                if (!keep) {
                    try storage.remove(config.partition, name);
                    continue;
                }
                const blob = try storage.open(config.partition, name);
                errdefer blob.blob.close();
                var len = blob.len;
                if (len % record_size != 0) {
                    // A torn record at the tail: drop it.
                    len -= len % record_size;
                    try blob.blob.resize(len);
                    try blob.blob.sync();
                }
                assert(len % record_size == 0);
                opened.appendAssumeCapacity(.{ .section = section, .blob = blob.blob, .len = len });
            }
        }

        /// Clear every stored record whose bit is unset in its section's bitmap, so stored
        /// blobs match the committed view. Each run of unmarked slots is cleared with writes
        /// of at most `write_buffer` bytes (or one record if that is larger).
        fn clear_unmarked(
            gpa: Allocator,
            config: Config,
            opened: []const Opened,
            list: []const SectionBits,
        ) Error!void {
            const zeros = try gpa.alloc(u8, @max(config.write_buffer, record_size));
            defer gpa.free(zeros);
            @memset(zeros, 0);
            for (opened) |entry| {
                // A section with no bitmap requires every record, so nothing is cleared.
                const bitmap = (find_bits(list, entry.section) orelse continue).bits orelse
                    continue;
                const slots = entry.len / record_size;
                var modified = false;
                var run: u64 = 0;
                var bit_index: u64 = 0;
                while (bit_index <= slots) : (bit_index += 1) {
                    const unmarked = bit_index >= bitmap.len() or !bitmap.get(bit_index);
                    if (bit_index < slots and unmarked) {
                        run += 1;
                        continue;
                    }
                    if (run == 0) continue;
                    try write_zeros(entry.blob, zeros, bit_index - run, bit_index);
                    modified = true;
                    run = 0;
                }
                if (modified) try entry.blob.sync();
            }
        }

        /// Overwrite the records in slots `[start, end)` with zeros.
        fn write_zeros(blob: Blob, zeros: []const u8, start: u64, end: u64) Error!void {
            assert(start < end);
            var offset = start * record_size;
            const end_offset = end * record_size;
            while (offset < end_offset) {
                const len: usize = @intCast(@min(end_offset - offset, zeros.len));
                try blob.write_at(offset, zeros[0..len], .{});
                offset += len;
            }
            assert(offset == end_offset);
        }

        /// Rebuild the intervals from the records `list` commits.
        fn rebuild(
            gpa: Allocator,
            config: Config,
            opened: []const Opened,
            list: []const SectionBits,
            intervals: *rmap.RMap,
            diagnostic: *u64,
        ) Error!void {
            const replay_len = @max(record_size, config.replay_buffer / record_size * record_size);
            const replay = try gpa.alloc(u8, @intCast(replay_len));
            defer gpa.free(replay);
            for (list) |entry| {
                if (entry.bits) |bitmap| {
                    if (bitmap.count_ones() == 0) continue;
                }
                const items_per_blob = config.items_per_blob;
                const first = entry.section *| items_per_blob;
                const stored = find_opened(opened, entry.section) orelse {
                    diagnostic.* = first;
                    return error.MissingRecord;
                };
                if (entry.bits) |bitmap| {
                    var ones = bitmap.ones_iter();
                    while (ones.next()) |bit_index| {
                        try check_present(stored, bit_index, items_per_blob, diagnostic);
                        try intervals.insert(gpa, first + bit_index);
                    }
                } else {
                    try rebuild_whole(gpa, config, stored, replay, intervals, diagnostic);
                }
            }
        }

        fn find_opened(opened: []const Opened, section: u64) ?Opened {
            for (opened) |entry| {
                if (entry.section == section) return entry;
            }
            return null;
        }

        /// A committed record must lie within its section and its blob.
        fn check_present(
            stored: Opened,
            bit_index: u64,
            items_per_blob: u64,
            diagnostic: *u64,
        ) Error!void {
            diagnostic.* = stored.section *| items_per_blob +| bit_index;
            if (bit_index >= items_per_blob) return error.MissingRecord;
            if ((bit_index + 1) * record_size > stored.len) return error.MissingRecord;
        }

        /// A section kept whole: every one of its `items_per_blob` records must be valid. A
        /// committed bitmap proves membership on its own, but here membership comes from
        /// record validity, so the records are read.
        fn rebuild_whole(
            gpa: Allocator,
            config: Config,
            stored: Opened,
            replay: []u8,
            intervals: *rmap.RMap,
            diagnostic: *u64,
        ) Error!void {
            const items_per_blob = config.items_per_blob;
            const first = stored.section *| items_per_blob;
            // A longer blob was written under a larger `items_per_blob`; replaying only its
            // first records would hide the rest.
            const full = std.math.mul(u64, items_per_blob, record_size) catch
                std.math.maxInt(u64);
            if (stored.len > full) {
                diagnostic.* = first +| items_per_blob;
                return error.InvalidRecord;
            }
            var replay_start: u64 = 0;
            var replay_len: u64 = 0;
            var bit_index: u64 = 0;
            while (bit_index < items_per_blob) : (bit_index += 1) {
                try check_present(stored, bit_index, items_per_blob, diagnostic);
                const offset = bit_index * record_size;
                if (offset + record_size > replay_start + replay_len) {
                    replay_start = offset;
                    replay_len = @min(replay.len, stored.len - offset);
                    try stored.blob.read_at(offset, replay[0..@intCast(replay_len)]);
                }
                const start: usize = @intCast(offset - replay_start);
                const bytes = replay[start..][0..RecordType.fixed_size];
                if (RecordType.decode_valid(bytes) == null) return error.MissingRecord;
                try intervals.insert(gpa, first + bit_index);
            }
        }

        /// Close every blob (dropping unsynced writes).
        pub fn deinit(self: *Self) void {
            var writers = self.blobs.valueIterator();
            while (writers.next()) |writer| writer.deinit();
            self.release();
        }

        fn release(self: *Self) void {
            self.blobs.deinit(self.gpa);
            self.intervals.deinit(self.gpa);
            self.pending.deinit(self.gpa);
            self.puts.deinit();
            self.gets.deinit();
            self.has_checks.deinit();
            self.syncs.deinit();
            self.pruned.deinit();
            self.* = undefined;
        }

        /// Store `value` at `index` (pending until `sync`). An index that already holds a
        /// record is left unchanged, so a torn write can never damage a stored record.
        pub fn put(self: *Self, index: u64, value: V) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            self.puts.metric().inc();
            if (self.intervals.get(index) != null) return;
            const items_per_blob = self.config.items_per_blob;
            const section = index / items_per_blob;
            const offset = (index % items_per_blob) * record_size;
            const record = RecordType.encode(value);
            try self.pending.ensureUnusedCapacity(self.gpa, 1);
            const writer = try self.writer_for(section);
            try writer.write_at(offset, &record);
            insert_pending(&self.pending, section);
            try self.intervals.insert(self.gpa, index);
            assert(self.intervals.get(index) != null);
        }

        /// The section's writer, opening its blob if it has none.
        fn writer_for(self: *Self, section: u64) Error!*Write {
            if (self.blobs.getPtr(section)) |writer| return writer;
            try self.blobs.ensureUnusedCapacity(self.gpa, 1);
            const name = section_name(section);
            const opened = try self.storage.open(self.config.partition, &name);
            const capacity = self.config.write_buffer;
            const writer = Write.init(self.gpa, opened.blob, opened.len, capacity) catch |err|
                {
                    opened.blob.close();
                    return err;
                };
            const entry = self.blobs.getOrPutAssumeCapacity(section);
            assert(!entry.found_existing);
            entry.value_ptr.* = writer;
            return entry.value_ptr;
        }

        fn insert_pending(pending: *std.ArrayList(u64), section: u64) void {
            const items = pending.items;
            var position: usize = items.len;
            while (position > 0 and items[position - 1] >= section) position -= 1;
            if (position < items.len and items[position] == section) return;
            pending.insertAssumeCapacity(position, section);
            // O(1): the scan above leaves smaller keys before `position` and larger after.
            assert(pending.items[position] == section);
            assert(position == 0 or pending.items[position - 1] < section);
            assert(position + 1 == pending.items.len or pending.items[position + 1] > section);
        }

        /// The value at `index`, or null. A stored record that fails its checksum or does not
        /// decode is `InvalidRecord`.
        pub fn get(self: *Self, index: u64) Error!?V {
            self.gets.metric().inc();
            if (self.intervals.get(index) == null) return null;
            const items_per_blob = self.config.items_per_blob;
            const writer = self.blobs.getPtr(index / items_per_blob).?;
            var bytes: [RecordType.fixed_size]u8 = undefined;
            try writer.read_at((index % items_per_blob) * record_size, &bytes);
            return RecordType.decode_valid(&bytes) orelse error.InvalidRecord;
        }

        /// Whether `index` holds a record.
        pub fn has(self: *const Self, index: u64) bool {
            self.has_checks.metric().inc();
            return self.intervals.get(index) != null;
        }

        /// The end of the range containing `index` and the start of the next range.
        pub fn next_gap(self: *const Self, index: u64) rmap.Gap {
            return self.intervals.next_gap(index);
        }

        /// Every range of stored indices, ascending.
        pub fn ranges(self: *const Self) []const rmap.Range {
            return self.intervals.items();
        }

        /// The ranges that overlap or follow `from`.
        pub fn ranges_from(self: *const Self, from: u64) []const rmap.Range {
            return self.intervals.iter_from(from);
        }

        pub fn first_index(self: *const Self) ?u64 {
            return self.intervals.first_index();
        }

        pub fn last_index(self: *const Self) ?u64 {
            return self.intervals.last_index();
        }

        /// Up to `out.len` missing indices at or after `start`, before the last stored index.
        pub fn missing_items(self: *const Self, start: u64, out: []u64) []u64 {
            return self.intervals.missing_items(start, out);
        }

        /// Remove every section whose indices all lie below `min`.
        pub fn prune(self: *Self, min: u64) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            const items_per_blob = self.config.items_per_blob;
            const min_section = min / items_per_blob;
            var sections: std.ArrayList(u64) = .empty;
            defer sections.deinit(self.gpa);
            var keys = self.blobs.keyIterator();
            while (keys.next()) |section| {
                if (section.* < min_section) try sections.append(self.gpa, section.*);
            }
            std.sort.pdq(u64, sections.items, {}, std.sort.asc(u64));
            for (sections.items) |section| {
                var removed = self.blobs.fetchRemove(section).?;
                removed.value.deinit();
                const name = section_name(section);
                try self.storage.remove(self.config.partition, &name);
                const start = section * items_per_blob;
                try self.intervals.remove(self.gpa, start, start +| (items_per_blob - 1));
                self.pruned.metric().inc();
            }
            // Pending sections below `min_section` were removed with their blobs.
            var keep: usize = 0;
            while (keep < self.pending.items.len and self.pending.items[keep] < min_section) {
                keep += 1;
            }
            self.pending.replaceRangeAssumeCapacity(0, keep, &.{});
            assert(self.pending.items.len == 0 or self.pending.items[0] >= min_section);
        }

        /// Flush and sync every section with pending writes.
        pub fn sync(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            self.syncs.metric().inc();
            for (self.pending.items) |section| {
                try self.blobs.getPtr(section).?.sync();
            }
            self.pending.clearRetainingCapacity();
        }

        /// Remove every blob and the partition, and free the store.
        pub fn destroy(self: *Self) Error!void {
            defer self.release();
            var sections: std.ArrayList(u64) = .empty;
            defer sections.deinit(self.gpa);
            try sections.ensureTotalCapacity(self.gpa, self.blobs.count());
            var entries = self.blobs.iterator();
            while (entries.next()) |entry| {
                entry.value_ptr.deinit();
                sections.appendAssumeCapacity(entry.key_ptr.*);
            }
            self.blobs.clearRetainingCapacity();
            std.sort.pdq(u64, sections.items, {}, std.sort.asc(u64));
            for (sections.items) |section| {
                const name = section_name(section);
                try self.storage.remove(self.config.partition, &name);
            }
            self.storage.remove(self.config.partition, null) catch |err| switch (err) {
                error.PartitionMissing => {},
                else => return err,
            };
        }
    };
}

/// The blob name of `section`: its big-endian bytes.
pub fn section_name(section: u64) [8]u8 {
    var name: [8]u8 = undefined;
    std.mem.writeInt(u64, &name, section, .big);
    return name;
}
