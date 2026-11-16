//! Segmented journal for fixed-size items (commonware's `segmented/fixed.rs`).
//!
//! # Format
//!
//! Data is stored in one paged blob per section. Items are stored sequentially:
//!
//! ```text
//! +--------+--------+--------+----------+
//! | item_0 | item_1 |   ...  | item_n-1 |
//! +--------+--------+--------+----------+
//! ```
//!
//! # Repair
//!
//! Opening a section reads its blob's last page to determine its length, discarding an
//! incomplete or invalid tail. Replay checks items in order: torn pages or incomplete trailing
//! items truncate the section to the last complete, validated item. Each section can have a
//! validation floor marking a prefix known durable; repair below it is `Corruption`.
//!
//! A journal is available only once its contents are replayed or proven by a checkpoint:
//! `preflight_floors` returns a `Recovery` that replays and repairs every section, and
//! `preflight_restore` one whose checkpoint proves the retained prefix. `Recovery.finish`
//! returns the journal. `init` opens with no floors and drains the replay.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const Storage = runtime.storage.Storage;
const manager_mod = @import("manager.zig");

/// Configuration for the fixed segmented journal.
pub const Config = struct {
    /// The partition holding one blob per section.
    partition: []const u8,
    /// The page cache shared by section writers.
    cache_ref: *paged.CacheRef,
    /// Write buffer size of each section.
    write_buffer: usize,
    /// Buffer size used to replay each section when the journal opens.
    replay_buffer: usize,
    /// Where the section manager registers `tracked`, `synced`, and `pruned`.
    metrics: ?runtime.telemetry.metrics.Scope = null,
};

/// A validation floor: `items` items of `section` are known durable.
pub const Floor = struct { section: u64, items: u64 };

pub fn Journal(comptime A: type) type {
    const chunk_size = codec.fixed_size(A) orelse @compileError("journal items must be fixed-size");
    comptime assert(chunk_size > 0);
    comptime assert(!codec.owns_memory(A));
    return struct {
        const Self = @This();
        pub const Manager = manager_mod.Manager(manager_mod.AppendFactory);
        pub const Error = Manager.Error;
        pub const Recovery = RecoveryType(A);
        /// Size of each item in bytes.
        pub const chunk: usize = chunk_size;
        const chunk_u64: u64 = chunk_size;

        manager: Manager,

        fn manager_config(cfg: Config) manager_mod.Config(manager_mod.AppendFactory) {
            return .{
                .partition = cfg.partition,
                .factory = .{ .write_buffer = cfg.write_buffer, .cache_ref = cfg.cache_ref },
                .metrics = cfg.metrics,
            };
        }

        /// Open every stored section through `ceiling`. Opening discards a torn tail page.
        fn open(gpa: Allocator, storage: Storage, cfg: Config, ceiling: u64) Error!Self {
            return .{ .manager = try Manager.init(gpa, storage, manager_config(cfg), ceiling) };
        }

        /// Open with no validation floors, replaying (and repairing) every section.
        pub fn init(gpa: Allocator, storage: Storage, cfg: Config) Error!Self {
            var recovery = try Self.preflight_floors(gpa, storage, cfg, &.{});
            try recovery.drain();
            return recovery.finish();
        }

        /// Close every section (dropping unsynced items).
        pub fn deinit(self: *Self) void {
            self.manager.deinit();
            self.* = undefined;
        }

        /// Open through `(section, logical byte end)`, removing later sections. An end inside
        /// an item rounds down. All retained data is validated before returning.
        pub fn init_at_most(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            section: u64,
            end_requested: u64,
        ) Error!Self {
            var end = end_requested - end_requested % chunk_u64;
            const page_size: u64 = cfg.cache_ref.page_size;
            const partition = cfg.partition;
            try manager_mod.truncate_paged_tail(gpa, storage, partition, page_size, section, end);
            var journal = try Self.open(gpa, storage, cfg, std.math.maxInt(u64));
            {
                errdefer journal.deinit();
                // Resolve a torn page before truncation tries to rewrite its partial checksum.
                if (end > 0) {
                    if (try journal.manager.get(section)) |buffer| {
                        if (end < buffer.size()) {
                            const recoverable = try buffer.recoverable_prefix_len_at_most(0, end);
                            end = recoverable - recoverable % chunk_u64;
                        }
                    }
                }
                try journal.manager.truncate_pending(section, end - end % chunk_u64);
            }
            // The recovery owns the journal from here, even when starting it fails.
            var recovery = try Recovery.from_journal(gpa, journal, cfg.replay_buffer);
            try recovery.drain();
            return recovery.finish();
        }

        /// Prove validation floors without mutating storage, and return the `Recovery` that
        /// replays every section from position zero. Every section named by a floor must exist.
        pub fn preflight_floors(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            floors: []const Floor,
        ) Error!Recovery {
            const stored = try manager_mod.stored_sections(gpa, storage, cfg.partition);
            defer gpa.free(stored);
            var recovery = Recovery.init(gpa, storage, cfg);
            errdefer recovery.deinit();
            for (floors) |floor| {
                // Every advertised floor must name a retained, representable byte prefix.
                if (std.sort.binarySearch(u64, stored, floor.section, order_u64) == null) {
                    return error.Corruption;
                }
                const required = std.math.mul(u64, floor.items, chunk_u64) catch
                    return error.Corruption;
                if (required == 0) {
                    const empty: Recovery.Boundary = .{ .section = floor.section, .item = null };
                    try recovery.boundaries.append(gpa, empty);
                    continue;
                }
                const entry = try boundary(gpa, storage, cfg, floor.section, required);
                try recovery.floors.append(gpa, .{ .section = floor.section, .bytes = required });
                try recovery.boundaries.append(gpa, .{ .section = floor.section, .item = entry });
            }
            recovery.finished = stored.len == 0;
            return recovery;
        }

        fn order_u64(a: u64, b: u64) std.math.Order {
            return std.math.order(a, b);
        }

        /// Validate the terminal boundary of every checkpoint-covered section without mutating
        /// storage, and return the `Recovery` that restores the checkpoint: `finish` durably
        /// truncates `section` to `size` bytes and removes every later section unread.
        pub fn preflight_restore(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            section: u64,
            size_bytes: u64,
        ) Error!Recovery {
            // The checkpoint can only identify a boundary between items.
            if (size_bytes % chunk_u64 != 0) return error.Corruption;
            const stored = try manager_mod.stored_sections(gpa, storage, cfg.partition);
            defer gpa.free(stored);
            const found = std.sort.binarySearch(u64, stored, section, order_u64) != null;
            if (size_bytes > 0 and !found) return error.Corruption;

            var recovery = Recovery.init(gpa, storage, cfg);
            errdefer recovery.deinit();
            for (stored) |candidate| {
                if (candidate > section) break;
                const entry: ?A = if (candidate != section)
                    try terminal_entry(gpa, storage, cfg, candidate)
                else if (size_bytes == 0)
                    null
                else
                    try boundary(gpa, storage, cfg, section, size_bytes);
                try recovery.boundaries.append(gpa, .{ .section = candidate, .item = entry });
            }
            if (!found) try recovery.boundaries.append(gpa, .{ .section = section, .item = null });
            recovery.restore = .{ .section = section, .size = size_bytes };
            return recovery;
        }

        /// The terminal entry of an earlier section's retained pages, which must hold whole
        /// items.
        fn terminal_entry(gpa: Allocator, storage: Storage, cfg: Config, section: u64) Error!?A {
            const opened = try storage.open(cfg.partition, &manager_mod.section_name(section));
            defer opened.blob.close();
            if (opened.len == 0) return null;
            const scratch = try gpa.alloc(u8, cfg.cache_ref.page_size + paged.checksum_size);
            defer gpa.free(scratch);
            var entry: [chunk_size]u8 = undefined;
            const logical_size = paged.read_tail(
                opened.blob,
                opened.len,
                cfg.cache_ref.page_size,
                &entry,
                scratch,
            ) catch |err| return boundary_error(err);
            if (logical_size % chunk_u64 != 0) return error.Corruption;
            return try codec.decode_fixed(A, &entry);
        }

        /// The terminal entry of a validated `size`-byte prefix of `section`.
        fn boundary(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            section: u64,
            size_bytes: u64,
        ) Error!A {
            const opened = try storage.open(cfg.partition, &manager_mod.section_name(section));
            defer opened.blob.close();
            const scratch = try gpa.alloc(u8, cfg.cache_ref.page_size + paged.checksum_size);
            defer gpa.free(scratch);
            var entry: [chunk_size]u8 = undefined;
            paged.read_range(
                opened.blob,
                cfg.cache_ref.page_size,
                size_bytes - chunk_u64,
                &entry,
                scratch,
            ) catch |err| return boundary_error(err);
            return codec.decode_fixed(A, &entry);
        }

        /// An invalid or missing boundary is committed corruption; I/O errors stay as they are.
        fn boundary_error(err: anyerror) Error {
            return switch (err) {
                error.InvalidChecksum, error.BlobInsufficientLength => error.Corruption,
                else => @errorCast(err),
            };
        }

        /// Append `item` to `section`, returning its position in the section.
        pub fn append(self: *Self, section: u64, item: A) Error!u64 {
            const buffer = try self.manager.get_or_create(section);
            const offset = buffer.try_append_value(A, item) orelse blk: {
                const bytes = codec.encode_fixed(A, item);
                break :blk try buffer.append(&bytes);
            };
            if (offset % chunk_u64 != 0) return error.InvalidBlobSize;
            return offset / chunk_u64;
        }

        /// The item at `position` of `section`.
        pub fn get(self: *Self, section: u64, position: u64) Error!A {
            const buffer = try self.manager.get(section) orelse return error.SectionOutOfRange;
            const offset = std.math.mul(u64, position, chunk_u64) catch return error.ItemOutOfRange;
            var bytes: [chunk_size]u8 = undefined;
            buffer.read_into(&bytes, offset) catch |err| switch (err) {
                error.BlobInsufficientLength, error.OffsetOverflow => return error.ItemOutOfRange,
                else => return err,
            };
            return codec.decode_fixed(A, &bytes);
        }

        /// Read strictly increasing `positions` of `section` into `items`. Returns how many
        /// were served without a blob read.
        pub fn get_many(self: *Self, section: u64, positions: []const u64, items: []A) Error!usize {
            assert(items.len == positions.len);
            if (positions.len > 1) {
                for (positions[1..], positions[0 .. positions.len - 1]) |position, previous| {
                    assert(position > previous);
                }
            }
            const buffer = try self.manager.get(section) orelse return error.SectionOutOfRange;
            var hits: usize = 0;
            for (positions, items) |position, *item| {
                const offset = std.math.mul(u64, position, chunk_u64) catch
                    return error.ItemOutOfRange;
                var bytes: [chunk_size]u8 = undefined;
                if (buffer.try_read_sync_into(&bytes, offset)) {
                    hits += 1;
                } else {
                    try buffer.read_into(&bytes, offset);
                }
                item.* = try codec.decode_fixed(A, &bytes);
            }
            return hits;
        }

        /// The item if it can be read without I/O.
        pub fn try_get_sync(self: *Self, section: u64, position: u64) ?A {
            const buffer = (self.manager.get(section) catch return null) orelse return null;
            const offset = std.math.mul(u64, position, chunk_u64) catch return null;
            var bytes: [chunk_size]u8 = undefined;
            if (!buffer.try_read_sync_into(&bytes, offset)) return null;
            return codec.decode_fixed(A, &bytes) catch null;
        }

        /// The last item of `section`, or null if it is empty.
        pub fn last(self: *Self, section: u64) Error!?A {
            const buffer = try self.manager.get(section) orelse return error.SectionOutOfRange;
            const bytes_size = buffer.size();
            if (bytes_size < chunk_u64) return null;
            const offset = (bytes_size / chunk_u64 - 1) * chunk_u64;
            var bytes: [chunk_size]u8 = undefined;
            try buffer.read_into(&bytes, offset);
            return try codec.decode_fixed(A, &bytes);
        }

        pub fn sync(self: *Self, targets: []const u64) Error!void {
            return self.manager.sync(targets);
        }

        pub fn start_sync(self: *Self, targets: []const u64) Error!void {
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

        /// The open sections, ascending.
        pub fn open_sections(self: *const Self) []const Manager.Section {
            return self.manager.sections.items;
        }

        /// The number of items in `section`.
        pub fn section_len(self: *Self, section: u64) Error!u64 {
            return try self.manager.size(section) / chunk_u64;
        }

        /// The byte size of `section`.
        pub fn size(self: *Self, section: u64) Error!u64 {
            return self.manager.size(section);
        }

        /// Durably shorten only `section` to `bytes`.
        pub fn truncate_pending_section(self: *Self, section: u64, bytes: u64) Error!void {
            return self.manager.truncate_pending_section(section, bytes);
        }

        /// Remove every blob and free the journal.
        pub fn destroy(self: *Self) Error!void {
            defer self.* = undefined;
            return self.manager.destroy();
        }

        /// Remove all data, keeping the journal usable.
        pub fn clear(self: *Self) Error!void {
            return self.manager.clear();
        }
    };
}

/// Startup recovery returned by `Journal.preflight_floors` and `Journal.preflight_restore`.
///
/// Nothing is modified until `next` opens the writers. `next` yields every item in order from
/// position zero of every section, repairing invalid trailing data (never below a floor). An
/// error ends the section that produced it and makes `finish` fail; iteration continues with
/// the next section. A restore recovery has nothing to replay.
fn RecoveryType(comptime A: type) type {
    return struct {
        const Self = @This();
        const J = Journal(A);
        const Error = J.Error;
        const Replay = paged.Replay;
        const chunk_u64: u64 = J.chunk;

        pub const Item = struct { section: u64, position: u64, item: A };
        pub const Boundary = struct { section: u64, item: ?A };
        const FloorBytes = struct { section: u64, bytes: u64 };
        const SectionReplay = struct { section: u64, reader: Replay, position: u64 };

        gpa: Allocator,
        storage: Storage,
        cfg: Config,
        /// Terminal entry at each validated boundary, by ascending section.
        boundaries: std.ArrayList(Boundary) = .empty,
        /// Logical byte prefix of each section that repair must preserve.
        floors: std.ArrayList(FloorBytes) = .empty,
        /// The checkpoint `finish` restores in place of a replay.
        restore: ?struct { section: u64, size: u64 } = null,
        /// The journal under replay, once its writers are open.
        journal: ?J = null,
        /// Section replays still to drain; the front is `replays.items[head]`.
        replays: std.ArrayList(SectionReplay) = .empty,
        head: usize = 0,
        finished: bool = false,
        errored: bool = false,

        fn init(gpa: Allocator, storage: Storage, cfg: Config) Self {
            return .{ .gpa = gpa, .storage = storage, .cfg = cfg };
        }

        /// A recovery replaying an already opened journal with no floors. Takes ownership of
        /// `journal`, closing it on error.
        fn from_journal(gpa: Allocator, journal: J, replay_buffer: usize) Error!Self {
            var self = Self.init(gpa, journal.manager.storage, .{
                .partition = journal.manager.partition,
                .cache_ref = journal.manager.factory.cache_ref,
                .write_buffer = journal.manager.factory.write_buffer,
                .replay_buffer = replay_buffer,
            });
            self.journal = journal;
            errdefer self.deinit();
            try self.begin();
            return self;
        }

        /// Replay every remaining item, discarding them. Abandons the recovery on error.
        pub fn drain(self: *Self) Error!void {
            errdefer self.deinit();
            while (try self.next()) |_| {}
            assert(self.finished or self.restore != null);
        }

        /// Abandon the recovery, closing any opened journal.
        pub fn deinit(self: *Self) void {
            self.clear_replays();
            self.replays.deinit(self.gpa);
            self.boundaries.deinit(self.gpa);
            self.floors.deinit(self.gpa);
            if (self.journal) |*journal| journal.deinit();
            self.* = undefined;
        }

        fn clear_replays(self: *Self) void {
            for (self.replays.items[self.head..]) |*replay| replay.reader.deinit();
            self.replays.clearRetainingCapacity();
            self.head = 0;
        }

        /// Terminal entries captured at each validated boundary.
        pub fn boundary_items(self: *const Self) []const Boundary {
            return self.boundaries.items;
        }

        /// Open the writers and start replaying every section from position zero.
        fn open(self: *Self) Error!void {
            self.journal = try J.open(self.gpa, self.storage, self.cfg, std.math.maxInt(u64));
            // Opening may discard a torn tail, which must not reach into a proven prefix.
            for (self.floors.items) |floor| {
                if (try self.journal.?.size(floor.section) < floor.bytes) return error.Corruption;
            }
            try self.begin();
        }

        fn begin(self: *Self) Error!void {
            const manager = &self.journal.?.manager;
            try self.replays.ensureTotalCapacity(self.gpa, manager.sections.items.len);
            for (manager.sections.items) |*entry| {
                const reader = try entry.buffer.replay(self.cfg.replay_buffer);
                self.replays.appendAssumeCapacity(.{
                    .section = entry.section,
                    .reader = reader,
                    .position = 0,
                });
            }
        }

        fn floor_of(self: *const Self, section: u64) u64 {
            for (self.floors.items) |floor| if (floor.section == section) return floor.bytes;
            return 0;
        }

        /// Reject a repair that would remove any floor-protected item.
        fn ensure_above_floor(self: *const Self, section: u64, target: u64) Error!void {
            if (target < self.floor_of(section)) return error.Corruption;
        }

        fn pop_front(self: *Self) void {
            assert(self.head < self.replays.items.len);
            self.replays.items[self.head].reader.deinit();
            self.head += 1;
        }

        /// The next `(section, position, item)`, or null once every section is drained.
        pub fn next(self: *Self) Error!?Item {
            const result = self.next_inner();
            if (result) |_| {} else |_| self.errored = true;
            return result;
        }

        fn next_inner(self: *Self) Error!?Item {
            // A checkpoint proves its retained items; only `finish` applies it.
            if (self.restore != null) return null;
            if (self.journal == null) try self.open();
            while (self.head < self.replays.items.len) {
                const current = &self.replays.items[self.head];
                const ready = current.reader.ensure(J.chunk) catch |err| {
                    try self.repair(err);
                    continue;
                };
                if (!ready) {
                    try self.finish_section();
                    continue;
                }
                var bytes: [J.chunk]u8 = undefined;
                @memcpy(&bytes, current.reader.bytes()[0..J.chunk]);
                current.reader.advance(J.chunk);
                const item = codec.decode_fixed(A, &bytes) catch |err| {
                    self.pop_front();
                    return err;
                };
                const yielded: Item = .{
                    .section = current.section,
                    .position = current.position,
                    .item = item,
                };
                current.position += 1;
                return yielded;
            }
            self.finished = true;
            return null;
        }

        /// The front section is exhausted: truncate an incomplete trailing item.
        fn finish_section(self: *Self) Error!void {
            const current = &self.replays.items[self.head];
            const section = current.section;
            const valid_size = std.math.mul(u64, current.position, chunk_u64) catch {
                self.pop_front();
                return error.OffsetOverflow;
            };
            const blob_size = current.reader.blob_size();
            self.pop_front();
            if (valid_size >= blob_size) return;
            try self.ensure_above_floor(section, valid_size);
            errdefer self.clear_replays();
            const buffer = (try self.journal.?.manager.get(section)).?;
            try buffer.truncate(valid_size);
        }

        /// Repair a torn page found by ordered replay and resume at the last complete item.
        fn repair(self: *Self, source: anyerror) Error!void {
            const current = &self.replays.items[self.head];
            const section = current.section;
            const position = current.position;
            const target = self.plan_repair(source) catch |err| {
                self.pop_front();
                return err;
            };
            const valid_size = position * chunk_u64;
            // A failed storage mutation ends the replay (commonware's `repairing`).
            errdefer self.clear_replays();
            const buffer = (try self.journal.?.manager.get(section)).?;
            try buffer.truncate(target);
            var reader = try buffer.replay(self.cfg.replay_buffer);
            errdefer reader.deinit();
            try reader.seek_to(valid_size);
            self.replays.items[self.head].reader.deinit();
            self.replays.items[self.head].reader = reader;
            assert(self.replays.items[self.head].section == section);
        }

        /// Validate that the front section's failure is a repairable torn page, returning the
        /// item-aligned truncation target.
        fn plan_repair(self: *Self, source: anyerror) Error!u64 {
            // Only a checksum failure marks a torn write; other errors must not be masked.
            if (source != error.InvalidChecksum) return @errorCast(source);
            const current = &self.replays.items[self.head];
            const size = current.reader.blob_size();
            const valid_size = std.math.mul(u64, current.position, chunk_u64) catch
                return error.OffsetOverflow;
            const buffer = (try self.journal.?.manager.get(current.section)).?;
            const recoverable = try buffer.recoverable_prefix_len(valid_size);
            // A whole-blob prefix means the failure was not a torn page.
            if (recoverable >= size) return error.InvalidChecksum;
            const target = recoverable - recoverable % chunk_u64;
            if (target < valid_size) return error.ItemOutOfRange;
            try self.ensure_above_floor(current.section, target);
            return target;
        }

        /// Return the journal, consuming the recovery (also on error). A floors recovery fails
        /// with `ReplayFailed` unless it was fully drained without errors. A restore recovery
        /// opens the sections through its checkpoint, durably truncates the checkpoint
        /// section, and removes later sections unread.
        pub fn finish(self: *Self) Error!J {
            defer self.deinit();
            if (self.restore) |restore| {
                var journal = try J.open(self.gpa, self.storage, self.cfg, restore.section);
                errdefer journal.deinit();
                try journal.manager.truncate_pending(restore.section, restore.size);
                try journal.manager.sync(&.{restore.section});
                return journal;
            }
            if (self.errored or !self.finished) return error.ReplayFailed;
            if (self.journal == null) try self.open();
            const journal = self.journal.?;
            self.journal = null;
            return journal;
        }
    };
}

test {
    _ = @import("fixed_test.zig");
}
