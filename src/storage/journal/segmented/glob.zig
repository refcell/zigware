//! Simple section-based blob storage for values (commonware's `segmented/glob.rs`).
//!
//! Values are stored where the size is tracked externally (in an index entry). Unlike the
//! segmented variable journal, entries carry no size prefix since the caller already knows the
//! size.
//!
//! # Format
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! |     Compressed Data (variable)    |   CRC32   |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! - **Compressed Data**: zstd compressed (if enabled) or raw codec output.
//! - **CRC32**: big-endian 4-byte checksum of the compressed data.
//!
//! # Read flow
//!
//! 1. Get `(offset, size)` from an index entry.
//! 2. Read `size` bytes directly from the blob at byte `offset`.
//! 3. The last 4 bytes are the CRC32; verify it.
//! 4. Decompress the remaining bytes if compression is enabled.
//! 5. Decode the value. Decoded values are owned by the caller; free them with `codec.free`.
//!
//! Sections are plain blobs buffered by `runtime.buffer.Write` (no page checksums, no page
//! cache), so reads of large values do not pollute a cache.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const Crc32 = @import("cryptography").crc32.Crc32;
const Storage = runtime.storage.Storage;
const frame = @import("../frame.zig");
const zstd = @import("../zstd.zig");
const manager_mod = @import("manager.zig");

/// Physical overhead appended to every entry: the CRC32 of the entry's data.
pub const checksum_size: usize = 4;

/// Configuration for blob storage.
pub fn Config(comptime V: type) type {
    return struct {
        /// The partition holding one blob per section.
        partition: []const u8,
        /// Optional zstd compression level for stored values. Keep the choice between none
        /// and some fixed while stored values are retained.
        compression: ?u8 = null,
        /// The codec configuration used to decode values.
        codec_config: codec.Cfg(V),
        /// The size of the write buffer of each section.
        write_buffer: usize,
        /// Where the section manager registers `tracked`, `synced`, and `pruned`.
        metrics: ?runtime.telemetry.metrics.Scope = null,
    };
}

/// Where `append` placed a value.
pub const Entry = struct {
    /// Byte offset of the entry in its section.
    offset: u64,
    /// Total stored bytes (data plus CRC32).
    size: u32,
};

/// Section-based blob storage for values.
///
/// Mutating methods leave the glob failed after a storage error (commonware consumes it);
/// only `deinit` may follow. Mutations of pruned sections fail with `AlreadyPrunedToSection`
/// without mutating; check `pruned` first.
pub fn Glob(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Factory = manager_mod.WriteFactory;
        pub const Manager = manager_mod.Manager(Factory);
        pub const Error = Manager.Error;
        pub const Cfg = Config(V);

        manager: Manager,
        compression: ?u8,
        codec_config: codec.Cfg(V),
        /// Reused entry encoding buffer.
        scratch: std.ArrayList(u8) = .empty,

        fn open(gpa: Allocator, storage: Storage, cfg: Cfg, ceiling: u64) Error!Self {
            assert(cfg.write_buffer > 0);
            const manager_cfg: manager_mod.Config(Factory) = .{
                .partition = cfg.partition,
                .factory = .{ .capacity = cfg.write_buffer },
                .metrics = cfg.metrics,
            };
            const manager = try Manager.init(gpa, storage, manager_cfg, ceiling);
            assert(manager.ceiling == ceiling);
            return .{
                .manager = manager,
                .compression = cfg.compression,
                .codec_config = cfg.codec_config,
            };
        }

        /// Close every section (dropping unsynced values).
        pub fn deinit(self: *Self) void {
            self.scratch.deinit(self.manager.gpa);
            self.manager.deinit();
            self.* = undefined;
        }

        /// Encode `value` (compressing if enabled) followed by its CRC32 into `scratch`.
        fn encode_entry(self: *Self, value: V) Error![]const u8 {
            const gpa = self.manager.gpa;
            self.scratch.clearRetainingCapacity();
            if (self.compression != null) {
                const encoded = try codec.encode(V, gpa, value);
                defer gpa.free(encoded);
                _ = try zstd.compress_into(gpa, encoded, &self.scratch);
            } else {
                const len = codec.encode_size(V, value);
                const out = try self.scratch.addManyAsSlice(gpa, len);
                var writer = codec.Writer.init(out);
                codec.write(V, value, &writer);
                assert(writer.end == len);
            }
            const checksum = Crc32.checksum(self.scratch.items);
            const trailer = try self.scratch.addManyAsArray(gpa, checksum_size);
            std.mem.writeInt(u32, trailer, checksum, .big);
            assert(self.scratch.items.len >= checksum_size);
            return self.scratch.items;
        }

        /// Append `value` to `section`. Store the returned offset and size in an index entry
        /// to read the value back.
        pub fn append(self: *Self, section: u64, value: V) Error!Entry {
            assert(!self.manager.failed);
            const bytes = try self.encode_entry(value);
            const entry_size = std.math.cast(u32, bytes.len) orelse return error.ValueTooLarge;
            const buffer = try self.manager.get_or_create(section);
            const offset = buffer.size();
            if (!buffer.try_write_at(offset, bytes)) {
                errdefer self.manager.failed = true;
                try buffer.write_at(offset, bytes);
            }
            assert(buffer.size() >= offset + entry_size);
            return .{ .offset = offset, .size = entry_size };
        }

        /// Read the value at `offset` with known `size` (from an index entry). Free it with
        /// `codec.free`.
        pub fn get(self: *Self, section: u64, offset: u64, size_bytes: u32) Error!V {
            const buffer = try self.manager.get(section) orelse return error.SectionOutOfRange;
            const gpa = self.manager.gpa;
            const buf = try gpa.alloc(u8, size_bytes);
            defer gpa.free(buf);
            try buffer.read_at(offset, buf);
            if (buf.len < checksum_size) return error.BlobInsufficientLength;
            const data_len = buf.len - checksum_size;
            const data = buf[0..data_len];
            const stored = std.mem.readInt(u32, buf[data_len..][0..checksum_size], .big);
            if (Crc32.checksum(data) != stored) return error.ChecksumMismatch;
            const compressed = self.compression != null;
            const value = frame.decode_item(V, gpa, data, self.codec_config, compressed);
            return value catch |err| return @errorCast(err);
        }

        /// Whether the entry at `(offset, size)` of `section` has a valid trailing checksum.
        fn verify(self: *Self, section: u64, offset: u64, size_bytes: u32) Error!bool {
            if (size_bytes < checksum_size) return false;
            const buffer = try self.manager.get(section) orelse return false;
            const gpa = self.manager.gpa;
            const buf = try gpa.alloc(u8, size_bytes);
            defer gpa.free(buf);
            buffer.read_at(offset, buf) catch |err| switch (err) {
                error.BlobInsufficientLength, error.OffsetOverflow => return false,
                else => return err,
            };
            const data_len = buf.len - checksum_size;
            const stored = std.mem.readInt(u32, buf[data_len..][0..checksum_size], .big);
            return Crc32.checksum(buf[0..data_len]) == stored;
        }

        /// Write arbitrary bytes at `offset` of an existing `section`, bypassing entry
        /// framing. For tests (commonware's test-only `inject`).
        pub fn inject(self: *Self, section: u64, offset: u64, bytes: []const u8) Error!void {
            assert(!self.manager.failed);
            const buffer = try self.manager.get(section) orelse return error.SectionOutOfRange;
            errdefer self.manager.failed = true;
            try buffer.write_at(offset, bytes);
        }

        /// Sync the given `sections` (flushes write buffers).
        pub fn sync(self: *Self, targets: []const u64) Error!void {
            return self.manager.sync(targets);
        }

        /// commonware's `start_sync`: syncs complete synchronously, so this is `sync`.
        pub fn start_sync(self: *Self, targets: []const u64) Error!void {
            return self.manager.start_sync(targets);
        }

        pub fn sync_all(self: *Self) Error!void {
            return self.manager.sync_all();
        }

        /// The size of `section` including buffered data (0 if missing).
        pub fn size(self: *Self, section: u64) Error!u64 {
            return self.manager.size(section);
        }

        /// Prune every section below `min`. Returns whether any were pruned.
        pub fn prune(self: *Self, min: u64) Error!bool {
            return self.manager.prune(min);
        }

        /// Whether `section` is below this execution's prune floor (reset at init).
        pub fn pruned(self: *const Self, section: u64) bool {
            return self.manager.pruned(section);
        }

        pub fn oldest_section(self: *const Self) ?u64 {
            return self.manager.oldest_section();
        }

        pub fn newest_section(self: *const Self) ?u64 {
            return self.manager.newest_section();
        }

        /// Iterate over the retained section numbers, ascending.
        pub fn sections(self: *const Self) Manager.SectionIterator {
            return self.manager.section_iterator();
        }

        /// Remove `section`. Returns whether it existed.
        pub fn remove_section(self: *Self, section: u64) Error!bool {
            return self.manager.remove_section(section);
        }

        /// Remove every blob and free the glob.
        pub fn destroy(self: *Self) Error!void {
            self.scratch.deinit(self.manager.gpa);
            defer self.* = undefined;
            return self.manager.destroy();
        }
    };
}

/// Owns value sections until paired initialization has finished.
pub fn Recovery(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const G = Glob(V);
        pub const Error = G.Error;

        glob: G,

        /// Open every value section under initialization ownership.
        pub fn init(gpa: Allocator, storage: Storage, cfg: G.Cfg) Error!Self {
            return init_bounded(gpa, storage, cfg, std.math.maxInt(u64));
        }

        /// Open value sections through `ceiling`. Later sections stay closed; paired recovery
        /// must remove them with `truncate` before `finish` publishes the glob.
        pub fn init_bounded(gpa: Allocator, storage: Storage, cfg: G.Cfg, ceiling: u64) Error!Self {
            const glob = try G.open(gpa, storage, cfg, ceiling);
            assert(!glob.manager.failed);
            return .{ .glob = glob };
        }

        /// Close every section without publishing the glob.
        pub fn deinit(self: *Self) void {
            self.glob.deinit();
            self.* = undefined;
        }

        /// Whether the entry at `(offset, size)` in `section` has a valid trailing checksum.
        /// False if the entry is smaller than its checksum, the section does not exist, the
        /// range is not covered by the section, or the checksum does not match.
        pub fn verify(self: *Self, section: u64, offset: u64, size_bytes: u32) Error!bool {
            return self.glob.verify(section, offset, size_bytes);
        }

        /// Truncate `section` to `size_bytes` and remove every later section. A shorter
        /// length is durable when this returns.
        pub fn truncate(self: *Self, section: u64, size_bytes: u64) Error!void {
            return self.glob.manager.truncate_pending(section, size_bytes);
        }

        /// Durably truncate the selected independent value sections.
        pub fn truncate_sections(self: *Self, sizes: []const manager_mod.SectionSize) Error!void {
            return self.glob.manager.truncate_pending_sections(sizes);
        }

        pub fn size(self: *Self, section: u64) Error!u64 {
            return self.glob.size(section);
        }

        pub fn sections(self: *const Self) G.Manager.SectionIterator {
            return self.glob.sections();
        }

        /// Make repaired value sections durable.
        pub fn sync(self: *Self, targets: []const u64) Error!void {
            return self.glob.sync(targets);
        }

        /// Remove an orphaned value section.
        pub fn remove_section(self: *Self, section: u64) Error!void {
            _ = try self.glob.remove_section(section);
        }

        /// Publish every value section after paired recovery.
        pub fn finish(self: *Self) G {
            assert(!self.glob.manager.failed);
            const glob = self.glob;
            self.* = undefined;
            return glob;
        }
    };
}

/// Flip one byte inside value entry `index` of the blob `name`, breaking that entry's CRC
/// while leaving every other entry valid. Models a value torn by a crash after its index
/// entry became durable. Addresses uncompressed fixed-size entries: `entry_size` is the
/// encoded value size plus its CRC32.
pub fn corrupt_frame(
    storage: Storage,
    partition: []const u8,
    name: []const u8,
    index: u64,
    entry_size: u64,
) !void {
    const offset = index * entry_size;
    const opened = try storage.open(partition, name);
    defer opened.blob.close();
    assert(offset < opened.len); // The corruption target must be inside the blob.
    var byte: [1]u8 = undefined;
    try opened.blob.read_at(offset, &byte);
    byte[0] ^= 0xFF;
    try opened.blob.write_at(offset, &byte, .{ .sync = true });
}

test {
    _ = @import("glob_test.zig");
}
