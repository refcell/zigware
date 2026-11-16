//! A key-value store optimized for atomically committing a small collection of metadata.
//!
//! Port of commonware's `storage/src/metadata`. `Metadata` tracks a small collection of
//! metadata and commits many updates in one batch. It is commonly used with other storage
//! systems to persist application state across restarts.
//!
//! # Format
//!
//! Data is serialized as a sequence of key-value pairs in either a "left" or "right" blob:
//!
//! ```text
//! | Version (u64, BE) | Key1 | Value1 | ... | KeyN | ValueN | CRC32 (u32, BE) |
//! ```
//!
//! Keys are fixed-size and sorted by their encoded bytes (commonware's `BTreeMap` order for
//! `Span` keys); values use their codec encoding. The CRC-32C covers everything before it, so
//! partial writes are detected before any data is relied on.
//!
//! # Atomic updates
//!
//! A commit writes the older of the two blobs (by persisted version). Blob writes are not
//! atomic, so the newer blob is only overwritten once the older one has been synced: a restart
//! always finds at least one complete copy.
//!
//! # Overwrites and rewrites
//!
//! When keys and encoded value sizes are stable, the target blob is overwritten in place. A
//! store no larger than one blob page is written whole, in one write; larger stores write only
//! the changed values, version, and checksum. Any other update rewrites the entire blob.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime_storage = @import("runtime").storage;
const Storage = runtime_storage.Storage;
const Blob = runtime_storage.Blob;
const Crc32 = @import("cryptography").crc32.Crc32;

/// The names of the two blobs that store metadata.
const blob_names = [2][]const u8{ "left", "right" };
const version_size: usize = 8;
const checksum_size: usize = 4;
/// Runtime's `BLOB_PAGE_SIZE`.
const blob_page_size: usize = runtime_storage.blob_page_size;

/// Configuration for `Metadata`.
pub fn Config(comptime V: type) type {
    return struct {
        /// The storage partition holding the two blobs.
        partition: []const u8,
        /// The codec configuration for values.
        codec_config: codec.Cfg(V),
    };
}

/// A two-blob atomic key-value store over `runtime.storage`.
///
/// The store owns every value put into it and frees them with `codec.free`. Values must not
/// borrow their decoding input (`codec.Bytes`): the encoded buffer is reused on every sync.
/// Storage-mutating methods leave the store unusable after an error; only `deinit` may follow.
pub fn Metadata(comptime K: type, comptime V: type) type {
    const key_size = codec.fixed_size(K) orelse @compileError("metadata keys must be fixed-size");
    comptime assert(!codec.owns_memory(K));
    comptime assert(V != codec.Bytes);
    comptime assert(key_size > 0);
    return struct {
        const Self = @This();
        const KeyBytes = [key_size]u8;

        pub const Error = runtime_storage.Error || error{ Corruption, OutOfMemory };

        pub const Entry = struct { key_bytes: KeyBytes, key: K, value: V };

        /// Where a value sits in a blob's encoded buffer.
        const Info = struct { start: usize, length: usize };

        /// One of the two blobs and what this store knows of its contents.
        const Wrapper = struct {
            blob: Blob,
            version: u64 = 0,
            lengths: std.AutoHashMapUnmanaged(KeyBytes, Info) = .empty,
            /// Keys whose values changed since this blob was last written.
            modified: std.AutoArrayHashMapUnmanaged(KeyBytes, void) = .empty,
            data: std.ArrayList(u8) = .empty,

            fn deinit_memory(self: *Wrapper, gpa: Allocator) void {
                self.lengths.deinit(gpa);
                self.modified.deinit(gpa);
                self.data.deinit(gpa);
            }
        };

        /// One copy as loaded at startup; an invalid copy has no entries and an empty wrapper.
        const Loaded = struct {
            entries: std.ArrayList(Entry) = .empty,
            wrapper: Wrapper,
            valid: bool,
        };

        gpa: Allocator,
        storage: Storage,
        partition: []u8,
        codec_config: codec.Cfg(V),
        /// Entries sorted by `key_bytes`.
        entries: std.ArrayList(Entry),
        /// The blob holding the latest committed state.
        cursor: u1,
        next_version: u64,
        /// The version at which the key set last changed (forcing a full rewrite).
        key_order_changed: u64,
        blobs: [2]Wrapper,
        /// Set when a storage operation failed; the store may then only be dropped.
        failed: bool = false,

        /// Syncs that rewrote all data (`sync_rewrites`).
        sync_rewrites: u64 = 0,
        /// Syncs that modified existing data in place (`sync_overwrites`).
        sync_overwrites: u64 = 0,

        /// Open the store in `cfg.partition`, recovering the latest valid copy.
        pub fn init(gpa: Allocator, storage: Storage, cfg: Config(V)) Error!Self {
            const partition = try gpa.dupe(u8, cfg.partition);
            errdefer gpa.free(partition);
            const left = try storage.open(partition, blob_names[0]);
            errdefer left.blob.close();
            const right = try storage.open(partition, blob_names[1]);
            errdefer right.blob.close();

            // Syncs alternate copies and finish before the next starts, so at most one copy is
            // ever mid-write: both failing validation is corruption, and adopting a fresh store
            // would mask it.
            var copies: [2]Loaded = undefined;
            copies[0] = try load(gpa, cfg.codec_config, left.blob, left.len);
            errdefer free_loaded(gpa, &copies[0]);
            copies[1] = try load(gpa, cfg.codec_config, right.blob, right.len);
            errdefer free_loaded(gpa, &copies[1]);
            if (!copies[0].valid and !copies[1].valid) return error.Corruption;
            for (&copies) |*copy| {
                if (copy.valid) continue;
                try copy.wrapper.blob.resize(0);
                try copy.wrapper.blob.sync();
            }

            const cursor: u1 = if (copies[1].wrapper.version > copies[0].wrapper.version) 1 else 0;
            const version = copies[cursor].wrapper.version;
            const next_version = std.math.add(u64, version, 1) catch @panic("version overflow");
            free_entries(gpa, &copies[1 - cursor].entries);
            return .{
                .gpa = gpa,
                .storage = storage,
                .partition = partition,
                .codec_config = cfg.codec_config,
                .entries = copies[cursor].entries,
                .cursor = cursor,
                .next_version = next_version,
                // Rewrite on startup: there is no record of which values differ.
                .key_order_changed = next_version,
                .blobs = .{ copies[0].wrapper, copies[1].wrapper },
            };
        }

        /// Close both blobs and free all memory, dropping uncommitted changes.
        pub fn deinit(self: *Self) void {
            for (&self.blobs) |*wrapper| wrapper.blob.close();
            self.release();
        }

        fn release(self: *Self) void {
            free_entries(self.gpa, &self.entries);
            for (&self.blobs) |*wrapper| wrapper.deinit_memory(self.gpa);
            self.gpa.free(self.partition);
            self.* = undefined;
        }

        fn free_entries(gpa: Allocator, entries: *std.ArrayList(Entry)) void {
            for (entries.items) |entry| codec.free(V, gpa, entry.value);
            entries.deinit(gpa);
        }

        fn free_loaded(gpa: Allocator, loaded: *Loaded) void {
            free_entries(gpa, &loaded.entries);
            loaded.wrapper.deinit_memory(gpa);
        }

        /// Read and validate one copy. Bytes that fail the length or checksum check make it
        /// invalid; a checksummed copy that does not decode is corruption.
        fn load(gpa: Allocator, cfg: codec.Cfg(V), blob: Blob, len: u64) Error!Loaded {
            var loaded: Loaded = .{ .wrapper = .{ .blob = blob }, .valid = true };
            if (len == 0) return loaded;
            errdefer free_loaded(gpa, &loaded);

            const size = std.math.cast(usize, len) orelse return error.OutOfMemory;
            const data = try loaded.wrapper.data.addManyAsSlice(gpa, size);
            try blob.read_at(0, data);
            if (data.len < version_size + checksum_size) {
                loaded.valid = false;
                loaded.wrapper.data.clearRetainingCapacity();
                return loaded;
            }
            const checksum_index = data.len - checksum_size;
            const stored = std.mem.readInt(u32, data[checksum_index..][0..4], .big);
            if (stored != Crc32.checksum(data[0..checksum_index])) {
                loaded.valid = false;
                loaded.wrapper.data.clearRetainingCapacity();
                return loaded;
            }
            loaded.wrapper.version = std.mem.readInt(u64, data[0..version_size], .big);
            try decode_pairs(gpa, cfg, data[0..checksum_index], &loaded);
            return loaded;
        }

        /// Decode the key-value pairs after the version into `loaded`.
        fn decode_pairs(
            gpa: Allocator,
            cfg: codec.Cfg(V),
            data: []const u8,
            loaded: *Loaded,
        ) Error!void {
            var reader = codec.Reader.init(data);
            reader.position = version_size;
            // Every pair takes at least the key's bytes, so this bounds the loop.
            const pairs_max = data.len / key_size;
            var pairs: usize = 0;
            while (reader.remaining() > 0) : (pairs += 1) {
                assert(pairs < pairs_max);
                const key_bytes = (reader.take_array(key_size) catch
                    return error.Corruption).*;
                const key = codec.decode_fixed(K, &key_bytes) catch return error.Corruption;
                const start = reader.position;
                const value = codec.read_cfg(V, gpa, &reader, cfg) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.Corruption,
                };
                const length = codec.encode_size(V, value);
                if (reader.position - start != length) {
                    codec.free(V, gpa, value);
                    return error.Corruption;
                }
                put_entry(gpa, &loaded.entries, key_bytes, key, value) catch |err| {
                    codec.free(V, gpa, value);
                    return err;
                };
                try loaded.wrapper.lengths.put(gpa, key_bytes, .{
                    .start = start,
                    .length = length,
                });
            }
            assert(reader.position == data.len);
        }

        /// Insert into sorted `entries`, replacing (and freeing) an existing value.
        fn put_entry(
            gpa: Allocator,
            entries: *std.ArrayList(Entry),
            key_bytes: KeyBytes,
            key: K,
            value: V,
        ) Allocator.Error!void {
            const position = search(entries.items, &key_bytes);
            if (position.found) {
                codec.free(V, gpa, entries.items[position.index].value);
                entries.items[position.index].value = value;
                return;
            }
            try entries.insert(gpa, position.index, .{
                .key_bytes = key_bytes,
                .key = key,
                .value = value,
            });
        }

        const Position = struct { index: usize, found: bool };

        /// Binary search for `key_bytes`: its index, or where it would be inserted.
        fn search(entries: []const Entry, key_bytes: *const KeyBytes) Position {
            var low: usize = 0;
            var high: usize = entries.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (std.mem.order(u8, &entries[middle].key_bytes, key_bytes)) {
                    .lt => low = middle + 1,
                    .gt => high = middle,
                    .eq => return .{ .index = middle, .found = true },
                }
            }
            assert(low == entries.len or
                std.mem.order(u8, &entries[low].key_bytes, key_bytes) == .gt);
            return .{ .index = low, .found = false };
        }

        fn encode_key(key: K) KeyBytes {
            return codec.encode_fixed(K, key);
        }

        /// The number of keys.
        pub fn count(self: *const Self) usize {
            return self.entries.items.len;
        }

        /// The entries in key order.
        pub fn items(self: *const Self) []const Entry {
            return self.entries.items;
        }

        /// Get a value (if it exists).
        pub fn get(self: *const Self, key: K) ?*const V {
            const key_bytes = encode_key(key);
            const position = search(self.entries.items, &key_bytes);
            if (!position.found) return null;
            return &self.entries.items[position.index].value;
        }

        /// Get a mutable value (if it exists), marking it modified.
        pub fn get_mut(self: *Self, key: K) Allocator.Error!?*V {
            assert(!self.failed);
            const key_bytes = encode_key(key);
            const position = search(self.entries.items, &key_bytes);
            if (!position.found) return null;
            try self.mark_modified(key_bytes);
            return &self.entries.items[position.index].value;
        }

        /// Mark a key modified in both blobs: either may need the new value.
        fn mark_modified(self: *Self, key_bytes: KeyBytes) Allocator.Error!void {
            for (&self.blobs) |*wrapper| try wrapper.modified.ensureUnusedCapacity(self.gpa, 1);
            for (&self.blobs) |*wrapper| wrapper.modified.putAssumeCapacity(key_bytes, {});
            assert(self.blobs[0].modified.contains(key_bytes));
        }

        /// Remove every value. Not persisted until `sync`.
        pub fn clear(self: *Self) void {
            assert(!self.failed);
            for (self.entries.items) |entry| codec.free(V, self.gpa, entry.value);
            self.entries.clearRetainingCapacity();
            self.key_order_changed = self.next_version;
        }

        /// Put a value, returning the previous one (owned by the caller). The store takes
        /// ownership of `value` unless this fails. Not persisted until `sync`.
        pub fn put(self: *Self, key: K, value: V) Allocator.Error!?V {
            assert(!self.failed);
            const key_bytes = encode_key(key);
            const position = search(self.entries.items, &key_bytes);
            if (position.found) {
                try self.mark_modified(key_bytes);
                const previous = self.entries.items[position.index].value;
                self.entries.items[position.index].value = value;
                return previous;
            }
            try self.entries.insert(self.gpa, position.index, .{
                .key_bytes = key_bytes,
                .key = key,
                .value = value,
            });
            self.key_order_changed = self.next_version;
            return null;
        }

        /// `put` then `sync`; the previous value is freed. Commits all pending changes.
        pub fn put_sync(self: *Self, key: K, value: V) Error!void {
            if (try self.put(key, value)) |previous| codec.free(V, self.gpa, previous);
            try self.sync();
        }

        /// The value for `key`, inserting `default` first if it is missing, marked modified.
        /// Takes ownership of `default` (freed if unused).
        pub fn upsert(self: *Self, key: K, default: V) Allocator.Error!*V {
            if (try self.get_mut(key)) |value| {
                codec.free(V, self.gpa, default);
                return value;
            }
            // A new key changes the key order, so it needs no modified mark.
            const previous = try self.put(key, default);
            assert(previous == null);
            const key_bytes = encode_key(key);
            const position = search(self.entries.items, &key_bytes);
            assert(position.found);
            return &self.entries.items[position.index].value;
        }

        /// Remove a value, returning it (owned by the caller). Not persisted until `sync`.
        pub fn remove(self: *Self, key: K) ?V {
            assert(!self.failed);
            const key_bytes = encode_key(key);
            const position = search(self.entries.items, &key_bytes);
            if (!position.found) return null;
            const removed = self.entries.orderedRemove(position.index);
            self.key_order_changed = self.next_version;
            assert(std.mem.eql(u8, &removed.key_bytes, &key_bytes));
            return removed.value;
        }

        /// Keep only the entries for which `predicate(context, key, value)` holds.
        pub fn retain(
            self: *Self,
            context: anytype,
            comptime predicate: fn (@TypeOf(context), K, *const V) bool,
        ) void {
            assert(!self.failed);
            const old_len = self.entries.items.len;
            var kept: usize = 0;
            for (self.entries.items) |entry| {
                if (predicate(context, entry.key, &entry.value)) {
                    self.entries.items[kept] = entry;
                    kept += 1;
                } else {
                    codec.free(V, self.gpa, entry.value);
                }
            }
            self.entries.shrinkRetainingCapacity(kept);
            if (kept != old_len) self.key_order_changed = self.next_version;
            assert(kept <= old_len);
        }

        /// Atomically commit the current state.
        pub fn sync(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.write_next_version();
        }

        /// commonware's `start_sync`: blobs sync synchronously here, so the sync completes
        /// (or fails, leaving the store failed) before this returns, and no second sync can
        /// overlap it.
        pub fn start_sync(self: *Self) Error!void {
            return self.sync();
        }

        /// Write and persist the next version of the store to the target blob.
        fn write_next_version(self: *Self) Error!void {
            const next_version = self.next_version;
            const key_order_changed = self.key_order_changed;
            // Syncing once per millisecond would overflow in 584,942,417 years.
            const past_version = self.blobs[self.cursor].version;
            const next_next_version = std.math.add(u64, next_version, 1) catch
                @panic("version overflow");
            const target_cursor: u1 = 1 - self.cursor;

            // With a stable key order, each blob's modified set tracks the value changes it
            // has not received. If the target has none, the cursor already names a durable
            // copy of the latest state and writing would only rotate blobs.
            const stable = key_order_changed < past_version;
            if (stable and self.blobs[target_cursor].modified.count() == 0) return;

            self.cursor = target_cursor;
            self.next_version = next_next_version;
            const target = &self.blobs[target_cursor];
            if (stable and self.overwrite_values(target)) {
                return self.write_overwrite(target, next_version);
            }
            target.modified.clearRetainingCapacity();
            return self.write_rewrite(target, next_version);
        }

        /// Encode modified values into the target's buffer in place. Returns false (leaving
        /// the buffer to be rebuilt) when any value changed its encoded length.
        fn overwrite_values(self: *Self, target: *Wrapper) bool {
            for (target.modified.keys()) |key_bytes| {
                const info = target.lengths.get(key_bytes).?; // The key set is unchanged.
                const position = search(self.entries.items, &key_bytes);
                assert(position.found);
                const value = self.entries.items[position.index].value;
                if (codec.encode_size(V, value) != info.length) return false;
                var writer = codec.Writer.init(target.data.items[info.start..][0..info.length]);
                codec.write(V, value, &writer);
                assert(writer.end == info.length);
            }
            return true;
        }

        /// Persist an in-place overwrite: the new version, checksum, and changed values.
        fn write_overwrite(self: *Self, target: *Wrapper, version: u64) Error!void {
            const data = target.data.items;
            assert(data.len >= version_size + checksum_size);
            std.mem.writeInt(u64, data[0..version_size], version, .big);
            const checksum_index = data.len - checksum_size;
            const checksum = Crc32.checksum(data[0..checksum_index]);
            std.mem.writeInt(u32, data[checksum_index..][0..checksum_size], checksum, .big);

            // A store no larger than one blob page is written whole: its changed values,
            // version, and checksum share that page, so one write replaces several.
            if (data.len <= blob_page_size) {
                try target.blob.write_at(0, data, .{});
            } else {
                for (target.modified.keys()) |key_bytes| {
                    const info = target.lengths.get(key_bytes).?;
                    try target.blob.write_at(info.start, data[info.start..][0..info.length], .{});
                }
                try target.blob.write_at(0, data[0..version_size], .{});
                try target.blob.write_at(checksum_index, data[checksum_index..], .{});
            }
            try target.blob.sync();
            target.modified.clearRetainingCapacity();
            target.version = version;
            self.sync_overwrites += 1;
        }

        /// Persist a full rewrite of the target blob.
        fn write_rewrite(self: *Self, target: *Wrapper, version: u64) Error!void {
            const gpa = self.gpa;
            var data_len: usize = version_size + checksum_size;
            for (self.entries.items) |entry| {
                data_len += key_size + codec.encode_size(V, entry.value);
            }

            // Capture the old length before reusing the buffer so shrinking rewrites still
            // resize the persisted blob.
            const old_len = target.data.items.len;
            target.lengths.clearRetainingCapacity();
            try target.lengths.ensureTotalCapacity(gpa, @intCast(self.entries.items.len));
            target.data.clearRetainingCapacity();
            const data = try target.data.addManyAsSlice(gpa, data_len);

            var writer = codec.Writer.init(data);
            writer.write_int(u64, version);
            for (self.entries.items) |entry| {
                writer.write_bytes(&entry.key_bytes);
                const start = writer.end;
                codec.write(V, entry.value, &writer);
                target.lengths.putAssumeCapacity(entry.key_bytes, .{
                    .start = start,
                    .length = writer.end - start,
                });
            }
            writer.write_int(u32, Crc32.checksum(writer.written()));
            assert(writer.end == data_len);

            try target.blob.write_at(0, data, .{});
            if (data_len < old_len) try target.blob.resize(data_len);
            try target.blob.sync();
            target.version = version;
            self.sync_rewrites += 1;
        }

        /// Remove both blobs and the partition, then free the store.
        ///
        /// The older copy is removed first, so a reopen after an interrupted destroy finds
        /// either the newest generation or an empty store, never a superseded generation.
        pub fn destroy(self: *Self) Error!void {
            assert(!self.failed);
            const storage = self.storage;
            const cursor = self.cursor;
            for (&self.blobs) |*wrapper| wrapper.blob.close();
            defer self.release();

            for ([_]u1{ 1 - cursor, cursor }) |index| {
                try storage.remove(self.partition, blob_names[index]);
            }
            storage.remove(self.partition, null) catch |err| switch (err) {
                // Partition already removed or never existed.
                error.PartitionMissing => {},
                else => return err,
            };
        }
    };
}

test {
    _ = @import("tests.zig");
    _ = @import("recovery_fuzz_test.zig");
    _ = @import("conformance_test.zig");
    _ = @import("start_sync_test.zig");
}
