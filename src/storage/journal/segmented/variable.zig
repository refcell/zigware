//! Segmented journal for variable-size items (commonware's `segmented/variable.rs`).
//!
//! # Format
//!
//! Data is stored in one paged blob per section. Within a section, each item is a frame: a
//! varint `u32` length followed by the (optionally zstd-compressed) encoded item.
//!
//! ```text
//! +---+---+---+---+---+---+---+---+
//! |       0 ~ 4       |    ...    |
//! +---+---+---+---+---+---+---+---+
//! | Size (varint u32) |   Data    |
//! +---+---+---+---+---+---+---+---+
//! ```
//!
//! # Repair
//!
//! A section ends at its last complete item: replay truncates a torn page or an incomplete
//! trailing item to the end of the item before it. A complete item that fails to decode is not
//! repaired; replay returns its error and the recovery cannot finish. Because any blob could
//! have trailing bytes, `init` returns a `Recovery` that replays and repairs every section, and
//! the journal is available only once that replay completes.
//!
//! # Compression
//!
//! Keep the choice between no compression and some compression fixed while items are retained.
//!
//! Decoded items are owned by the caller; free them with `codec.free`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const Completion = runtime.storage.Completion;
const paged = runtime.buffer.paged;
const Storage = runtime.storage.Storage;
const frame = @import("../frame.zig");
const manager_mod = @import("manager.zig");

/// Configuration for the variable segmented journal.
pub fn Config(comptime V: type) type {
    return struct {
        /// The partition holding one blob per section.
        partition: []const u8,
        /// Optional zstd compression level applied to items before storing.
        compression: ?u8 = null,
        /// The codec configuration used to decode items.
        codec_config: codec.Cfg(V),
        /// The page cache shared by section writers.
        cache_ref: *paged.CacheRef,
        /// Write buffer size of each section.
        write_buffer: usize,
        /// Buffer size used to replay each section when the journal opens.
        replay_buffer: usize,
        /// Options of every blob read a replay makes (commonware's replay `read_options`):
        /// `dont_cache` keeps a one-pass recovery scan out of the OS cache. Opening the
        /// writers reads each section's last page with the default options.
        replay_read_options: runtime.storage.ReadOptions = .{},
        /// Where the section manager registers `tracked`, `synced`, and `pruned`.
        metrics: ?runtime.telemetry.metrics.Scope = null,
    };
}

/// Where `append` placed an item.
pub const Appended = struct {
    /// Offset of the item's frame in its section.
    offset: u64,
    /// Stored item length, excluding the length prefix (compressed length if compressed).
    size: u32,
};

pub fn Journal(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Manager = manager_mod.Manager(manager_mod.AppendFactory);
        pub const Error = Manager.Error;
        pub const Recovery = RecoveryType(V);
        pub const Cfg = Config(V);

        manager: Manager,
        compression: ?u8,
        codec_config: codec.Cfg(V),
        /// Reused frame encoding buffer.
        scratch: std.ArrayList(u8) = .empty,

        fn manager_config(cfg: Cfg) manager_mod.Config(manager_mod.AppendFactory) {
            return .{
                .partition = cfg.partition,
                .factory = .{ .write_buffer = cfg.write_buffer, .cache_ref = cfg.cache_ref },
                .metrics = cfg.metrics,
            };
        }

        /// Open every stored section. Opening discards a torn tail page.
        fn open(gpa: Allocator, storage: Storage, cfg: Cfg) Error!Self {
            const ceiling = std.math.maxInt(u64);
            const manager = try Manager.init(gpa, storage, manager_config(cfg), ceiling);
            return .{
                .manager = manager,
                .compression = cfg.compression,
                .codec_config = cfg.codec_config,
            };
        }

        /// Open every section and return the `Recovery` that replays them in order. Drain it
        /// and call `Recovery.finish` to obtain the journal.
        pub fn init(gpa: Allocator, storage: Storage, cfg: Cfg) Error!Recovery {
            const journal = try Self.open(gpa, storage, cfg);
            return Recovery.init(journal, cfg.replay_buffer, cfg.replay_read_options);
        }

        /// Close every section (dropping unsynced items).
        pub fn deinit(self: *Self) void {
            const gpa = self.manager.gpa;
            self.scratch.deinit(gpa);
            self.manager.deinit();
            self.* = undefined;
        }

        /// Open through `(section, logical byte end)`, removing later sections. An end inside
        /// an item rounds down. All retained data is validated before returning.
        pub fn init_at_most(
            gpa: Allocator,
            storage: Storage,
            cfg: Cfg,
            section: u64,
            end_requested: u64,
        ) Error!Self {
            var end = end_requested;
            const page_size: u64 = cfg.cache_ref.page_size;
            const partition = cfg.partition;
            try manager_mod.truncate_paged_tail(gpa, storage, partition, page_size, section, end);
            var journal = try Self.open(gpa, storage, cfg);
            {
                errdefer journal.deinit();
                // Resolve a torn page before truncation tries to rewrite its partial checksum.
                if (try journal.manager.get(section)) |buffer| {
                    if (end > 0 and end < buffer.size()) {
                        const recoverable =
                            try buffer.recoverable_prefix_len_scan(0, end, cfg.replay_buffer, .{});
                        end = @min(end, recoverable);
                    }
                }
                try journal.manager.truncate_pending(section, end);
            }
            // The recovery owns the journal from here, even when starting it fails.
            var recovery = try Recovery.init(journal, cfg.replay_buffer, cfg.replay_read_options);
            try recovery.drain();
            return recovery.finish();
        }

        /// Append `item` to `section`, returning its offset and stored size.
        pub fn append(self: *Self, section: u64, item: V) Error!Appended {
            const gpa = self.manager.gpa;
            // Size and validate the frame before creating the section so a rejected item
            // leaves no empty section.
            self.scratch.clearRetainingCapacity();
            const item_len =
                try frame.encode_frame_into(V, gpa, self.compression, item, &self.scratch);
            const bytes = self.scratch.items;
            assert(bytes.len > item_len);
            const buffer = try self.manager.get_or_create(section);
            const offset = buffer.try_append(bytes) orelse try buffer.append(bytes);
            return .{ .offset = offset, .size = item_len };
        }

        /// The item at `offset` of `section`. Free it with `codec.free`.
        pub fn get(self: *Self, section: u64, offset: u64) Error!V {
            const buffer = try self.manager.get(section) orelse return error.SectionOutOfRange;
            const compressed = self.compression != null;
            const gpa = self.manager.gpa;
            const read = frame.read_frame_at(V, gpa, buffer, offset, self.codec_config, compressed);
            return (read catch |err| return @errorCast(err)).item;
        }

        /// Read the items at ascending `offsets` of `section` into `items`. On error, items
        /// already read are freed.
        pub fn get_many(self: *Self, section: u64, offsets: []const u64, items: []V) Error!void {
            assert(items.len == offsets.len);
            if (offsets.len > 1) {
                for (offsets[1..], offsets[0 .. offsets.len - 1]) |offset, previous| {
                    assert(offset > previous);
                }
            }
            if (offsets.len == 0) return;
            _ = try self.manager.get(section) orelse return error.SectionOutOfRange;
            var done: usize = 0;
            errdefer codec.free_items(V, self.manager.gpa, items[0..done]);
            for (offsets, items) |offset, *item| {
                item.* = try self.get(section, offset);
                done += 1;
            }
        }

        /// The item if it can be read without I/O.
        pub fn try_get_sync(self: *Self, section: u64, offset: u64) ?V {
            const buffer = (self.manager.get(section) catch return null) orelse return null;
            const remaining = std.math.sub(u64, buffer.size(), offset) catch return null;
            const header_len: usize = @intCast(@min(remaining, frame.max_prefix_size));
            if (header_len == 0) return null;
            var header: [frame.max_prefix_size]u8 = undefined;
            if (!buffer.try_read_sync_into(header[0..header_len], offset)) return null;
            const found = frame.find_frame(header[0..header_len], offset) catch return null;
            const varint_len: usize, const data_len: usize = switch (found.info) {
                .complete => |complete| .{ complete.varint_len, complete.data_len },
                .incomplete => |incomplete| .{ incomplete.varint_len, incomplete.total_len },
            };
            const item_len = varint_len + data_len;
            if (item_len > remaining) return null;
            const gpa = self.manager.gpa;
            const compressed = self.compression != null;
            // A frame within the header read decodes directly.
            if (item_len <= header_len) {
                const payload = header[varint_len..item_len];
                return frame.decode_item(V, gpa, payload, self.codec_config, compressed) catch null;
            }
            const buf = gpa.alloc(u8, item_len) catch return null;
            defer gpa.free(buf);
            if (!buffer.try_read_sync_into(buf, offset)) return null;
            const payload = buf[varint_len..];
            return frame.decode_item(V, gpa, payload, self.codec_config, compressed) catch null;
        }

        /// The byte size of `section` (0 if missing).
        pub fn size(self: *Self, section: u64) Error!u64 {
            return self.manager.size(section);
        }

        pub fn sync(self: *Self, targets: []const u64) Error!void {
            return self.manager.sync(targets);
        }

        /// Start syncing `targets`, returning their completion (`Manager.start_sync`).
        pub fn start_sync(self: *Self, targets: []const u64) Error!Completion {
            return self.manager.start_sync(targets);
        }

        pub fn sync_all(self: *Self) Error!void {
            return self.manager.sync_all();
        }

        /// Prune every section below `min`. Returns whether any were pruned.
        pub fn prune(self: *Self, min: u64) Error!bool {
            return self.manager.prune(min);
        }

        /// Whether `section` is below this execution's prune floor.
        pub fn pruned(self: *const Self, section: u64) bool {
            return self.manager.pruned(section);
        }

        pub fn oldest_section(self: *const Self) ?u64 {
            return self.manager.oldest_section();
        }

        pub fn newest_section(self: *const Self) ?u64 {
            return self.manager.newest_section();
        }

        pub fn is_empty(self: *const Self) bool {
            return self.manager.is_empty();
        }

        pub fn num_sections(self: *const Self) usize {
            return self.manager.num_sections();
        }

        /// Durably shorten only `section` to `bytes`.
        pub fn truncate_pending_section(self: *Self, section: u64, bytes: u64) Error!void {
            return self.manager.truncate_pending_section(section, bytes);
        }

        /// Remove every blob and free the journal.
        pub fn destroy(self: *Self) Error!void {
            self.scratch.deinit(self.manager.gpa);
            defer self.* = undefined;
            return self.manager.destroy();
        }

        /// Remove all data, keeping the journal usable.
        pub fn clear(self: *Self) Error!void {
            return self.manager.clear();
        }
    };
}

/// Startup recovery returned by `Journal.init`.
///
/// `next` yields `(section, offset, size, item)` in order and repairs invalid trailing data as
/// it is encountered. An error ends the section that produced it and makes `finish` fail;
/// errors while mutating storage to repair a section end the replay.
fn RecoveryType(comptime V: type) type {
    return struct {
        const Self = @This();
        const J = Journal(V);
        const Error = J.Error;
        const max_prefix_size = frame.max_prefix_size;

        pub const Item = struct { section: u64, offset: u64, size: u32, item: V };
        const SectionReplay = struct {
            section: u64,
            reader: paged.Replay,
            /// End of the last decoded item, where the next item starts.
            offset: u64,
        };

        journal: ?J,
        replay_buffer: usize,
        read_options: runtime.storage.ReadOptions,
        /// Section replays still to drain; the front is `replays.items[head]`.
        replays: std.ArrayList(SectionReplay) = .empty,
        head: usize = 0,
        finished: bool = false,
        errored: bool = false,
        /// A call was canceled: the replay ends (commonware's `ReplayInterrupted`).
        interrupted: bool = false,

        /// Start replaying every section of `journal` from offset zero. Takes ownership of
        /// `journal`, closing it on error.
        fn init(
            journal: J,
            replay_buffer: usize,
            read_options: runtime.storage.ReadOptions,
        ) Error!Self {
            assert(replay_buffer > 0);
            var self: Self = .{
                .journal = journal,
                .replay_buffer = replay_buffer,
                .read_options = read_options,
            };
            errdefer self.deinit();
            const manager = &self.journal.?.manager;
            try self.replays.ensureTotalCapacity(manager.gpa, manager.sections.items.len);
            for (manager.sections.items) |*entry| {
                const reader = try entry.buffer.replay(replay_buffer, read_options);
                self.replays.appendAssumeCapacity(.{
                    .section = entry.section,
                    .reader = reader,
                    .offset = 0,
                });
            }
            self.finished = self.replays.items.len == 0;
            return self;
        }

        /// Abandon the recovery, closing its journal.
        pub fn deinit(self: *Self) void {
            if (self.journal) |*journal| {
                const journal_gpa = journal.manager.gpa;
                self.clear_replays();
                self.replays.deinit(journal_gpa);
                journal.deinit();
            }
            self.* = undefined;
        }

        fn allocator(self: *const Self) Allocator {
            return self.journal.?.manager.gpa;
        }

        fn clear_replays(self: *Self) void {
            for (self.replays.items[self.head..]) |*replay| replay.reader.deinit();
            self.replays.clearRetainingCapacity();
            self.head = 0;
        }

        fn pop_front(self: *Self) void {
            assert(self.head < self.replays.items.len);
            self.replays.items[self.head].reader.deinit();
            self.head += 1;
        }

        /// Replay every remaining item, freeing them. Abandons the recovery on error.
        pub fn drain(self: *Self) Error!void {
            errdefer self.deinit();
            while (try self.next()) |entry| codec.free(V, self.allocator(), entry.item);
            assert(self.finished);
        }

        /// The next item, or null once every section is exhausted. The caller owns the item.
        pub fn next(self: *Self) Error!?Item {
            if (self.interrupted) return null;
            const result = self.next_inner();
            if (result) |_| {} else |err| {
                self.errored = true;
                self.interrupted = err == error.Canceled;
            }
            assert(!self.interrupted or self.errored);
            return result;
        }

        fn next_inner(self: *Self) Error!?Item {
            while (self.head < self.replays.items.len) {
                const current = &self.replays.items[self.head];
                const ready = current.reader.ensure(max_prefix_size) catch |err| {
                    try self.repair(err);
                    continue;
                };
                // An exhausted reader may still hold a short final frame.
                if (!ready and current.reader.remaining() == 0) {
                    self.pop_front();
                    continue;
                }
                const before_remaining = current.reader.remaining();
                var header = codec.Reader.init(current.reader.bytes());
                const prefix = frame.decode_length_prefix(&header) catch |err| {
                    // An incomplete varint at the end is trailing bytes.
                    if (!current.reader.is_exhausted() and before_remaining >= max_prefix_size) {
                        self.pop_front();
                        return err;
                    }
                    try self.finish_section();
                    continue;
                };
                if (try self.next_item(prefix)) |item| return item;
            }
            self.finished = true;
            return null;
        }

        /// Read the front section's item after its length prefix, or repair the section and
        /// return null to continue.
        fn next_item(self: *Self, prefix: frame.LengthPrefix) Error!?Item {
            const current = &self.replays.items[self.head];
            const item_size: usize = prefix.size;
            const item_offset = current.offset;
            const frame_len = prefix.varint_len + item_size;
            const next_offset = std.math.add(u64, item_offset, frame_len) catch {
                self.pop_front();
                return error.OffsetOverflow;
            };
            // A frame past the end is an incomplete trailing item; checking first bounds the
            // replay buffer by the blob instead of a corrupt length.
            if (next_offset > current.reader.blob_size()) {
                try self.finish_section();
                return null;
            }
            current.reader.advance(prefix.varint_len);
            const ready = current.reader.ensure(item_size) catch |err| {
                try self.repair(err);
                return null;
            };
            if (!ready) {
                try self.finish_section();
                return null;
            }
            const journal = &self.journal.?;
            const payload = current.reader.bytes()[0..item_size];
            const compressed = journal.compression != null;
            const cfg = journal.codec_config;
            const decoded = frame.decode_item(V, self.allocator(), payload, cfg, compressed);
            const item = decoded catch |err| {
                self.pop_front();
                return err;
            };
            current.reader.advance(item_size);
            current.offset = next_offset;
            return .{
                .section = current.section,
                .offset = item_offset,
                .size = prefix.size,
                .item = item,
            };
        }

        /// The front section has no further complete item: truncate it durably to its
        /// validated prefix and move on.
        fn finish_section(self: *Self) Error!void {
            const current = &self.replays.items[self.head];
            const section = current.section;
            const valid_size = current.offset;
            const blob_size = current.reader.blob_size();
            self.pop_front();
            if (valid_size >= blob_size) return;
            // A failed storage mutation ends the replay.
            errdefer self.clear_replays();
            const buffer = (try self.journal.?.manager.get(section)).?;
            try buffer.truncate(valid_size);
        }

        /// Repair a torn page found by ordered replay and resume at the last complete item.
        fn repair(self: *Self, source: anyerror) Error!void {
            const current = &self.replays.items[self.head];
            const section = current.section;
            const offset = current.offset;
            const target = self.plan_repair(source) catch |err| {
                self.pop_front();
                return err;
            };
            errdefer self.clear_replays();
            const buffer = (try self.journal.?.manager.get(section)).?;
            try buffer.truncate(target);
            var reader = try buffer.replay(self.replay_buffer, self.read_options);
            errdefer reader.deinit();
            try reader.seek_to(offset);
            self.replays.items[self.head].reader.deinit();
            self.replays.items[self.head].reader = reader;
            assert(self.replays.items[self.head].section == section);
        }

        /// Validate that the front section's failure is a repairable torn page, returning the
        /// truncation target.
        fn plan_repair(self: *Self, source: anyerror) Error!u64 {
            // Only a checksum failure marks a torn write; other errors must not be masked.
            if (source != error.InvalidChecksum) return @errorCast(source);
            const current = &self.replays.items[self.head];
            const blob_size = current.reader.blob_size();
            const buffer = (try self.journal.?.manager.get(current.section)).?;
            const recoverable = try buffer.recoverable_prefix_len_scan(
                current.offset,
                std.math.maxInt(u64),
                self.replay_buffer,
                self.read_options,
            );
            // A whole-blob prefix means the failure was not a torn page.
            if (recoverable >= blob_size) return error.InvalidChecksum;
            // The cut must not drop below the prefix already handed out.
            if (recoverable < current.offset) return error.ItemOutOfRange;
            return recoverable;
        }

        /// Return the journal, consuming the recovery (also on error). Fails with
        /// `ReplayFailed` unless the recovery was fully drained without errors.
        pub fn finish(self: *Self) Error!J {
            defer self.deinit();
            if (self.errored or !self.finished) return error.ReplayFailed;
            assert(self.head == self.replays.items.len);
            const journal = self.journal.?;
            self.replays.deinit(journal.manager.gpa);
            self.replays = .empty;
            self.journal = null;
            return journal;
        }
    };
}

test {
    _ = @import("variable_test.zig");
    _ = @import("variable_start_sync_test.zig");
    _ = @import("variable_recovery_fuzz_test.zig");
}
