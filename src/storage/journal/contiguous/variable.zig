//! A position-based journal of variable-length items (commonware's
//! `journal/contiguous/variable.rs`).
//!
//! # Format
//!
//! Items are varint-framed (`journal/frame.zig`, optionally zstd-compressed) in data blobs of
//! `items_per_section` items each, in the `{partition}_data` partition. A fixed journal of
//! `u64` byte offsets (`{partition}_offsets`) indexes every item; its checkpoint is also this
//! journal's durable recovery record.
//!
//! # Recovery
//!
//! The data blobs are the source of truth; the offsets journal is an index that a crash may
//! leave behind or ahead of them. Recovery rebuilds every offset at or above the offsets
//! recovery watermark by scanning the data, truncates torn trailing frames, prunes offsets
//! that outlived pruned data, and removes empty trailing blobs. Data at or below the watermark
//! is never repaired: a blob that no longer backs acknowledged items fails init with
//! `Corruption`. Only the two newest data blobs can hold non-durable data, so recovery checks
//! them for interior holes (torn pages) and truncates at the first one.
//!
//! # Watermark
//!
//! The offsets watermark only ever takes a size proven durable for both the data and the
//! offsets. Syncs complete synchronously here, so `start_sync` advances it to the current size
//! (commonware advances it to the last completed combined sync).
//!
//! # Ownership
//!
//! Decoded items are owned by the caller; free them with `codec.free`. Replay batches are
//! owned by the replay and valid until its next call. Mutating methods leave the journal failed
//! after an error; only `deinit` may follow.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const Storage = runtime.storage.Storage;
const contiguous = @import("mod.zig");
const blobs_mod = @import("blobs.zig");
const checkpoint_mod = @import("checkpoint.zig");
const fixed = @import("fixed.zig");
const frame = @import("../frame.zig");
const durability = @import("../durability.zig");
const Metrics = @import("metrics.zig").Metrics;

const Bounds = contiguous.Bounds;
const Checkpoint = checkpoint_mod.Checkpoint;
const Partition = blobs_mod.Partition;
const PendingBlob = blobs_mod.PendingBlob;
const Writable = blobs_mod.Writable;
const position_to_blob = contiguous.position_to_blob;
const blob_first_position = contiguous.blob_first_position;
const Offsets = fixed.Journal(u64);
const OffsetsRecovery = fixed.Recovery(u64);
const max_prefix_size = frame.max_prefix_size;

pub const Error = fixed.Error;

/// Suffix of the data blob partition.
pub const data_suffix = "_data";
/// Suffix of the offsets journal partition.
pub const offsets_suffix = "_offsets";

/// Configuration of a variable journal.
pub fn Config(comptime V: type) type {
    return struct {
        /// Base partition; the data and offsets partitions append their suffixes.
        partition: []const u8,
        /// Items per data blob. Fixed for the lifetime of the journal.
        items_per_section: u64,
        /// Optional zstd compression level. Keep the choice between none and some fixed while
        /// items are retained.
        compression: ?u8 = null,
        /// Codec configuration for decoding items.
        codec_config: codec.Cfg(V),
        /// Page cache shared by the data and offsets blobs.
        cache_ref: *paged.CacheRef,
        /// Write buffer size of each blob.
        write_buffer: usize,
        /// Buffer size of sequential reads during recovery.
        replay_buffer: usize,
        /// Where to register the journal's metrics (commonware's context metrics); the offsets
        /// journal registers under its `offsets` child. Without a scope they are unregistered.
        metrics: ?runtime.telemetry.metrics.Scope = null,
    };
}

/// A sync completion that has already succeeded: syncs complete synchronously.
const Done = struct {
    pub fn poll(_: *Done) ?bool {
        return true;
    }
};
const Barrier = durability.Barrier(Done);

/// The owned data and offsets partition names of a base partition.
const Names = struct {
    data: []u8,
    offsets: []u8,

    fn init(gpa: Allocator, partition: []const u8) Allocator.Error!Names {
        assert(partition.len > 0);
        const data = try std.mem.concat(gpa, u8, &.{ partition, data_suffix });
        errdefer gpa.free(data);
        const offsets = try std.mem.concat(gpa, u8, &.{ partition, offsets_suffix });
        return .{ .data = data, .offsets = offsets };
    }

    fn deinit(self: *Names, gpa: Allocator) void {
        gpa.free(self.data);
        gpa.free(self.offsets);
        self.* = undefined;
    }
};

fn offsets_config(cfg: anytype, names: Names) fixed.Config {
    assert(cfg.items_per_section > 0);
    return .{
        .partition = names.offsets,
        .items_per_blob = cfg.items_per_section,
        .cache_ref = cfg.cache_ref,
        .write_buffer = cfg.write_buffer,
        .replay_buffer = cfg.replay_buffer,
        .metrics = if (cfg.metrics) |scope| scope.child("offsets") else null,
    };
}

/// The result of scanning a data blob's frames.
const BlobScan = struct {
    /// Complete items.
    items: u64,
    /// Byte offset one past the last complete item.
    valid_size: u64,
    /// Whether undecodable trailing bytes follow `valid_size`.
    torn: bool,
};

const ScanEntry = struct { blob: u64, scan: BlobScan };

/// One step of a recovery frame scan.
const Frame = union(enum) {
    /// A complete, decodable item at this byte offset.
    item: u64,
    /// No further complete frame.
    end,
};

/// Walks varint frames over a blob from offset zero during recovery.
fn Scanner(comptime V: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        replay: paged.Replay,
        /// Byte offset of the next frame.
        offset: u64 = 0,
        codec_config: codec.Cfg(V),
        compressed: bool,

        /// The next frame. Incomplete trailing bytes end the scan; a complete frame whose
        /// payload fails to decode is an error.
        fn next(self: *Self) Error!Frame {
            const replay = &self.replay;
            const ready = try replay.ensure(max_prefix_size);
            if (!ready and replay.remaining() == 0) return .end;
            const before = replay.remaining();
            var header = codec.Reader.init(replay.bytes());
            const prefix = frame.decode_length_prefix(&header) catch |err| {
                // An incomplete varint at the end of the blob is trailing junk.
                if (replay.is_exhausted() or before < max_prefix_size) return .end;
                return err;
            };
            const frame_len: u64 = prefix.varint_len + @as(u64, prefix.size);
            const item_offset = self.offset;
            const next_offset = std.math.add(u64, item_offset, frame_len) catch
                return error.OffsetOverflow;
            // A frame past the blob is torn; checking first bounds the buffer by the blob.
            if (next_offset > replay.blob_size()) return .end;
            replay.advance(prefix.varint_len);
            if (!try replay.ensure(prefix.size)) return .end;
            const payload = replay.bytes()[0..prefix.size];
            const cfg = self.codec_config;
            const item = try frame.decode_item(V, self.gpa, payload, cfg, self.compressed);
            codec.free(V, self.gpa, item);
            replay.advance(prefix.size);
            self.offset = next_offset;
            assert(self.offset > item_offset);
            return .{ .item = item_offset };
        }
    };
}

fn find_pending(pending: []PendingBlob, index: u64) ?*PendingBlob {
    for (pending) |*entry| {
        if (entry.index == index) return entry;
    }
    return null;
}

/// Variable data and derived offsets owned exclusively by initialization.
pub fn Recovery(comptime V: type) type {
    return struct {
        const Self = @This();
        const J = Journal(V);
        /// The item type (`BackingRecovery`).
        pub const Item = V;

        gpa: Allocator,
        storage: Storage,
        /// `cfg.partition` points at the owned `prefix`.
        cfg: Config(V),
        prefix: []u8,
        names: Names,
        /// The data blob partition; null once publication moved it into the journal.
        partition: ?Partition = null,
        /// Opened data blobs by ascending index, including suffix candidates.
        pending: std.ArrayList(PendingBlob) = .empty,
        /// Data blob indexes excluded by the cap, ascending; publication removes them.
        discarded: std.ArrayList(u64) = .empty,
        /// Validated frame counts and byte ends by ascending blob, reused by publication.
        scans: std.ArrayList(ScanEntry) = .empty,
        /// The offsets journal under recovery; null once publication moved it.
        offsets: ?OffsetsRecovery = null,
        /// The selected item range.
        bounds: Bounds = .{ .start = 0, .end = 0 },
        /// Whether an explicit cap bounded the open.
        bounded: bool = false,

        fn init_empty(gpa: Allocator, storage: Storage, cfg: Config(V)) Error!Self {
            assert(cfg.items_per_section > 0);
            assert(cfg.replay_buffer > 0);
            const prefix = try gpa.dupe(u8, cfg.partition);
            errdefer gpa.free(prefix);
            var config = cfg;
            config.partition = prefix;
            return .{
                .gpa = gpa,
                .storage = storage,
                .cfg = config,
                .prefix = prefix,
                .names = try Names.init(gpa, prefix),
            };
        }

        /// Close every blob without publishing.
        pub fn deinit(self: *Self) void {
            self.close_data();
            self.pending.deinit(self.gpa);
            self.discarded.deinit(self.gpa);
            self.scans.deinit(self.gpa);
            if (self.offsets) |*offsets| offsets.deinit();
            if (self.partition) |*partition| partition.deinit();
            self.names.deinit(self.gpa);
            self.gpa.free(self.prefix);
            self.* = undefined;
        }

        fn close_data(self: *Self) void {
            for (self.pending.items) |*entry| entry.writer.deinit();
            self.pending.clearRetainingCapacity();
        }

        fn per_blob(self: *const Self) u64 {
            return self.cfg.items_per_section;
        }

        fn init_partition(self: *Self) Allocator.Error!void {
            assert(self.partition == null);
            self.partition = try Partition.init(
                self.gpa,
                self.storage,
                self.names.data,
                self.cfg.cache_ref,
                self.cfg.write_buffer,
            );
        }

        /// Inspect retained frames before choosing a prefix to publish. With `max_size`,
        /// data blobs holding only positions at or above it are discarded unread.
        pub fn open(gpa: Allocator, storage: Storage, cfg: Config(V), max_size: ?u64) Error!Self {
            var self = try init_empty(gpa, storage, cfg);
            errdefer self.deinit();
            // A staged clear removes the data partition before the offsets reset completes,
            // so stale data is never replayed past the reset size.
            self.offsets = try OffsetsRecovery.open_dependent(
                gpa,
                storage,
                offsets_config(self.cfg, self.names),
                max_size,
                self.names.data,
            );
            try self.init_partition();
            try self.open_data(max_size);
            try self.scan_suspects();
            self.bounded = max_size != null;
            try self.inspect(max_size orelse std.math.maxInt(u64));
            return self;
        }

        /// An empty recovery at `size`, clearing both partitions under a staged offsets reset.
        /// With `check`, inconsistent offsets partitions fail before any intent is written;
        /// otherwise only when no clear is already staged.
        pub fn open_cleared(
            gpa: Allocator,
            storage: Storage,
            cfg: Config(V),
            size: u64,
            check: bool,
        ) Error!Self {
            var self = try init_empty(gpa, storage, cfg);
            errdefer self.deinit();
            var staged = false;
            if (!check) {
                var checkpoint = try Checkpoint.open(gpa, storage, self.names.offsets);
                staged = checkpoint.clear_target() != null;
                checkpoint.deinit();
            }
            if (!staged) {
                var selected = try blobs_mod.select(gpa, storage, self.names.offsets);
                selected.deinit(gpa);
            }
            if (size == std.math.maxInt(u64)) return error.SizeOverflow;
            self.offsets = try OffsetsRecovery.open_cleared_dependent(
                gpa,
                storage,
                offsets_config(self.cfg, self.names),
                size,
                self.names.data,
            );
            try self.init_partition();
            self.bounds = .{ .start = size, .end = size };
            return self;
        }

        /// Open data blobs, discarding those holding only positions at or above `max_size`.
        fn open_data(self: *Self, max_size: ?u64) Error!void {
            const indices = try blobs_mod.indices(self.gpa, self.storage, self.names.data);
            defer self.gpa.free(indices);
            for (indices) |index| {
                const first = try blob_first_position(index, self.per_blob());
                if (max_size) |cap| if (first >= cap) {
                    try self.discarded.append(self.gpa, index);
                    continue;
                };
                try self.pending.ensureUnusedCapacity(self.gpa, 1);
                const writer = try self.partition.?.open_recovery(index);
                self.pending.appendAssumeCapacity(.{ .index = index, .writer = writer });
            }
        }

        /// Check the two newest blobs for interior holes and truncate each at its last
        /// well-formed page. Only they can hold non-durable data, and a crash during an
        /// in-flight sync can lose an interior page while later pages survive.
        fn scan_suspects(self: *Self) Error!void {
            const offsets = &self.offsets.?;
            // Every position below the floor was covered by a completed data sync.
            const floor = @max(offsets.recovery_watermark(), offsets.pruning_boundary());
            const floor_blob = position_to_blob(floor, self.per_blob());
            var checked: usize = 0;
            var index = self.pending.items.len;
            while (checked < 2 and index > 0) : (checked += 1) {
                index -= 1;
                if (self.pending.items[index].index < floor_blob) continue;
                try self.check_suspect(index, floor, floor_blob);
            }
        }

        fn check_suspect(self: *Self, index: usize, floor: u64, floor_blob: u64) Error!void {
            const entry = &self.pending.items[index];
            const valid = try entry.writer.recoverable_prefix_len(0);
            const size = entry.writer.size();
            assert(valid <= size);
            if (valid == size) return;
            // The floor's blob must retain its acknowledged prefix: a cut at or below the
            // last acknowledged frame's start lost acknowledged data.
            const offsets = &self.offsets.?;
            const first = try blob_first_position(entry.index, self.per_blob());
            if (entry.index == floor_blob and floor > first and
                floor > offsets.pruning_boundary())
            {
                if (valid <= try offsets.item(floor - 1)) return error.Corruption;
            }
            try entry.writer.truncate(valid);
        }

        /// Reconcile the retained start and rebuild offsets from the data, stopping at the
        /// ceiling without decoding discarded frames.
        fn inspect(self: *Self, ceiling: u64) Error!void {
            const per = self.per_blob();
            const offsets = &self.offsets.?;
            const offsets_start = offsets.pruning_boundary();
            const oldest: ?u64 = if (self.pending.items.len > 0)
                self.pending.items[0].index
            else if (self.discarded.items.len > 0)
                self.discarded.items[0]
            else
                null;
            const oldest_blob = oldest orelse {
                const end = offsets.size();
                if (self.bounded and end > offsets_start) return error.Corruption;
                self.bounds = .{ .start = end, .end = end };
                return;
            };
            const data_start = try blob_first_position(oldest_blob, per);
            const start = @max(offsets_start, data_start);
            if (ceiling < start) return error.ItemPruned;
            if (offsets.size() < data_start) return error.Corruption;
            if (position_to_blob(offsets_start, per) > oldest_blob) return error.Corruption;
            self.bounds = .{ .start = start, .end = start };
            if (ceiling == start) return;
            const anchor = @max(offsets.recovery_watermark(), start);
            const blob = position_to_blob(anchor, per);
            try self.check_acknowledged(start, anchor, blob);
            // Rebuild the derived suffix without advancing the watermark, so an interrupted
            // inspection replays the same frames next time.
            if (anchor < ceiling) try offsets.truncate(anchor);
            self.bounds.end = try self.rebuild(start, anchor, blob, ceiling);
        }

        /// Bounds must not acknowledge missing blobs below the replay anchor's blob.
        fn check_acknowledged(self: *Self, start: u64, anchor: u64, blob: u64) Error!void {
            const per = self.per_blob();
            var expected = position_to_blob(start, per);
            for (self.pending.items) |entry| {
                if (entry.index < expected) continue;
                if (entry.index >= blob) break;
                if (entry.index != expected) return error.Corruption;
                expected += 1;
            }
            if (expected != blob) return error.Corruption;
            const missing = find_pending(self.pending.items, blob) == null;
            if (anchor > try blob_first_position(blob, per) and missing) return error.Corruption;
        }

        /// Scan blobs from `blob` and append every offset at or above `anchor`, stopping at
        /// a short blob or the ceiling. Returns the recovered end.
        fn rebuild(self: *Self, start: u64, anchor: u64, blob_first: u64, ceiling: u64) Error!u64 {
            const per = self.per_blob();
            var blob = blob_first;
            var end = anchor;
            while (find_pending(self.pending.items, blob)) |entry| {
                const first = @max(try blob_first_position(blob, per), start);
                const limit = contiguous.blob_end_position(blob, per, ceiling);
                const physical_size = entry.writer.size();
                var scanner: Scanner(V) = .{
                    .gpa = self.gpa,
                    .replay = try entry.writer.replay(self.cfg.replay_buffer),
                    .codec_config = self.cfg.codec_config,
                    .compressed = self.cfg.compression != null,
                };
                defer scanner.replay.deinit();
                const position = try self.scan_positions(&scanner, first, anchor, limit);
                // Retained data ending before the watermark lost acknowledged items.
                if (position < anchor) return error.Corruption;
                end = position;
                // A complete frame beyond a full blob is corruption.
                if (position == limit and position != ceiling) {
                    if ((try scanner.next()) == .item) return error.Corruption;
                }
                try self.record_scan(blob, .{
                    .items = position - first,
                    .valid_size = scanner.offset,
                    .torn = scanner.offset < physical_size,
                });
                if (position < limit or position == ceiling) break;
                blob = std.math.add(u64, blob, 1) catch return error.OffsetOverflow;
            }
            assert(end >= anchor);
            return end;
        }

        fn scan_positions(
            self: *Self,
            scanner: *Scanner(V),
            first: u64,
            anchor: u64,
            limit: u64,
        ) Error!u64 {
            var position = first;
            while (position < limit) {
                switch (try scanner.next()) {
                    .item => |offset| {
                        if (position >= anchor) try self.offsets.?.append(offset);
                        position = std.math.add(u64, position, 1) catch
                            return error.OffsetOverflow;
                    },
                    .end => break,
                }
            }
            assert(position <= limit);
            return position;
        }

        fn find_scan(self: *Self, blob: u64) ?*BlobScan {
            for (self.scans.items) |*entry| {
                if (entry.blob == blob) return &entry.scan;
            }
            return null;
        }

        fn record_scan(self: *Self, blob: u64, scan: BlobScan) Allocator.Error!void {
            if (self.find_scan(blob)) |existing| {
                existing.* = scan;
                return;
            }
            var position: usize = 0;
            while (position < self.scans.items.len and self.scans.items[position].blob < blob) {
                position += 1;
            }
            try self.scans.insert(self.gpa, position, .{ .blob = blob, .scan = scan });
        }

        /// The available item positions (`BackingRecovery::bounds`).
        pub fn get_bounds(self: *const Self) Bounds {
            assert(self.bounds.start <= self.bounds.end);
            return self.bounds;
        }

        /// The previously acknowledged item end.
        pub fn recovery_watermark(self: *const Self) u64 {
            return self.offsets.?.recovery_watermark();
        }

        /// Read a retained item through the acknowledged and rebuilt offsets
        /// (`BackingRecovery::read`). The caller owns the item.
        pub fn read(self: *Self, position: u64) Error!V {
            if (position < self.bounds.start) return error.ItemPruned;
            if (position >= self.bounds.end) return error.ItemOutOfRange;
            const blob = position_to_blob(position, self.per_blob());
            const entry = find_pending(self.pending.items, blob) orelse return error.Corruption;
            const offset = try self.offsets.?.item(position);
            const cfg = self.cfg.codec_config;
            const compressed = self.cfg.compression != null;
            const writer = &entry.writer;
            const read_frame = frame.read_frame_at(V, self.gpa, writer, offset, cfg, compressed);
            return (try read_frame).item;
        }

        /// Discard stored items and continue empty at `size` (`BackingRecovery::reset`).
        pub fn reset(self: *Self, size: u64) Error!void {
            self.close_data();
            self.discarded.clearRetainingCapacity();
            self.scans.clearRetainingCapacity();
            try self.offsets.?.clear_to_size_dependent(size, self.names.data);
            self.bounds = .{ .start = size, .end = size };
            self.bounded = false;
        }

        /// Publish at most `size` items (`BackingRecovery::finish`). Consumes the recovery.
        pub fn finish(self: *Self, size: u64) Error!J {
            return self.publish(size);
        }

        /// Resolve the byte end of the prefix at `size` without a discarded offset entry.
        fn terminal_offset(self: *Self, size: u64) Error!u64 {
            const blob = position_to_blob(size, self.per_blob());
            const first = @max(try blob_first_position(blob, self.per_blob()), self.bounds.start);
            if (size == first) return 0;
            if (size == self.bounds.end) {
                if (self.find_scan(blob)) |scan| return scan.valid_size;
            }
            return self.offsets.?.item(size);
        }

        /// Repair both partitions to a prefix of at most `max_size` items and publish the
        /// journal once that prefix is durable. Consumes the recovery, also on error.
        pub fn publish(self: *Self, max_size: u64) Error!J {
            errdefer self.deinit();
            const size = @min(max_size, self.bounds.end);
            if (size < self.bounds.start) return error.ItemPruned;
            // Offsets authorize releasing data: select their prefix first.
            const terminal = try self.terminal_offset(size);
            const offsets = &self.offsets.?;
            try offsets.truncate(size);
            // Establish the retained start in the offsets before deleting discarded data.
            _ = try offsets.prune(self.bounds.start);
            const tail = position_to_blob(size, self.per_blob());
            if (self.needs_data_repair(tail, terminal)) try self.repair_data(tail, terminal);
            try self.select_scans(tail, size, terminal);
            const bounds = try self.align_data();
            if (bounds.end > size) return error.Corruption;
            return self.into_journal(bounds);
        }

        fn writer_size(self: *Self, blob: u64) ?u64 {
            const entry = find_pending(self.pending.items, blob) orelse return null;
            return entry.writer.size();
        }

        fn needs_data_repair(self: *Self, tail: u64, terminal: u64) bool {
            if (self.discarded.items.len > 0) return true;
            const pending = self.pending.items;
            if (pending.len > 0 and pending[pending.len - 1].index > tail) return true;
            for (self.scans.items) |entry| {
                if (entry.blob >= tail) break;
                const size = self.writer_size(entry.blob) orelse continue;
                if (entry.scan.valid_size < size) return true;
            }
            const size = self.writer_size(tail) orelse return false;
            return terminal < size;
        }

        /// Remove data outside the selected prefix: excluded blobs newest-first so every
        /// crash leaves a contiguous prefix, then shorten each retained blob oldest first.
        fn repair_data(self: *Self, tail: u64, terminal: u64) Error!void {
            while (self.discarded.pop()) |blob| try self.partition.?.remove(blob);
            try self.remove_blobs_after(tail);
            for (self.scans.items) |entry| {
                if (entry.blob >= tail) break;
                const pending = find_pending(self.pending.items, entry.blob) orelse continue;
                if (entry.scan.valid_size < pending.writer.size()) {
                    try pending.writer.truncate(entry.scan.valid_size);
                }
            }
            const pending = find_pending(self.pending.items, tail) orelse return;
            if (terminal < pending.writer.size()) try pending.writer.truncate(terminal);
        }

        fn remove_blobs_after(self: *Self, blob: u64) Error!void {
            while (self.pending.items.len > 0) {
                const last = self.pending.items.len - 1;
                if (self.pending.items[last].index <= blob) break;
                var entry = self.pending.pop().?;
                entry.writer.deinit();
                try self.partition.?.remove(entry.index);
            }
        }

        /// Keep the selected scans so alignment does not decode those frames again.
        fn select_scans(self: *Self, tail: u64, size: u64, terminal: u64) Error!void {
            var kept: usize = 0;
            for (self.scans.items) |entry| {
                if (entry.blob > tail) continue;
                self.scans.items[kept] = entry;
                self.scans.items[kept].scan.torn = false;
                kept += 1;
            }
            self.scans.items.len = kept;
            if (find_pending(self.pending.items, tail) == null) return;
            const first = @max(try blob_first_position(tail, self.per_blob()), self.bounds.start);
            assert(size >= first);
            try self.record_scan(tail, .{
                .items = size - first,
                .valid_size = terminal,
                .torn = false,
            });
        }

        fn scan_blob(self: *Self, writer: *paged.Writer) Error!BlobScan {
            var scanner: Scanner(V) = .{
                .gpa = self.gpa,
                .replay = try writer.replay(self.cfg.replay_buffer),
                .codec_config = self.cfg.codec_config,
                .compressed = self.cfg.compression != null,
            };
            defer scanner.replay.deinit();
            var items: u64 = 0;
            while ((try scanner.next()) == .item) items += 1;
            const size = writer.size();
            assert(scanner.offset <= size);
            return .{ .items = items, .valid_size = scanner.offset, .torn = scanner.offset < size };
        }

        /// Align the offsets journal and the data blobs after a crash. Returns the recovered
        /// bounds once the data backing rebuilt offsets is durable.
        fn align_data(self: *Self) Error!Bounds {
            const per = self.per_blob();
            var newest: ?u64 = null;
            var items_in_newest: u64 = 0;
            // Find the newest item-bearing blob, truncating torn trailing bytes on the way.
            var index = self.pending.items.len;
            while (index > 0) {
                index -= 1;
                const entry = &self.pending.items[index];
                const scan = if (self.find_scan(entry.index)) |scan|
                    scan.*
                else
                    try self.scan_blob(&entry.writer);
                if (scan.items > per) return error.Corruption;
                if (scan.torn) try entry.writer.truncate(scan.valid_size);
                if (scan.items > 0) {
                    newest = entry.index;
                    items_in_newest = scan.items;
                    break;
                }
            }
            // Blobs above the tail are empty crash artifacts.
            const tail_blob = if (newest) |blob|
                (if (items_in_newest == per) blob +| 1 else blob)
            else if (self.pending.items.len > 0) self.pending.items[0].index else 0;
            try self.remove_blobs_after(tail_blob);
            const newest_blob = newest orelse return self.align_empty();
            return self.align_offsets(newest_blob, items_in_newest);
        }

        fn align_offsets(self: *Self, newest_blob: u64, items_in_newest: u64) Error!Bounds {
            const per = self.per_blob();
            const oldest_blob = self.pending.items[0].index;
            const data_oldest = try blob_first_position(oldest_blob, per);
            const offsets = &self.offsets.?;
            // Offsets ending before the oldest retained data blob is external corruption.
            if (offsets.size() < data_oldest) return error.Corruption;
            const offsets_start_blob = position_to_blob(offsets.pruning_boundary(), per);
            // A crash between pruning data and pruning offsets leaves offsets behind.
            if (offsets_start_blob < oldest_blob) _ = try offsets.prune(data_oldest);
            // Prune always removes data first, so offsets are never ahead by a blob.
            if (offsets_start_blob > oldest_blob) return error.Corruption;
            const start = offsets.pruning_boundary();
            const newest_first = @max(try blob_first_position(newest_blob, per), start);
            const data_size = std.math.add(u64, newest_first, items_in_newest) catch
                return error.OffsetOverflow;
            const sync_start = try recovery_anchor(offsets, data_size);
            if (offsets.size() != data_size) return error.Corruption;
            if (data_size > start and position_to_blob(start, per) != oldest_blob) {
                return error.Corruption;
            }
            // Make retained data durable before advancing the rebuilt offsets' watermark.
            try self.sync_data_range(sync_start, data_size);
            try offsets.sync();
            return .{ .start = start, .end = data_size };
        }

        /// The position to rebuild offsets from: a watermark below the pruning boundary is
        /// stale after a prune; one beyond the retained data is corruption.
        fn recovery_anchor(offsets: *OffsetsRecovery, data_end: u64) Error!u64 {
            const watermark = offsets.recovery_watermark();
            const start = offsets.pruning_boundary();
            if (watermark < start) return start;
            if (watermark > data_end) return error.Corruption;
            return watermark;
        }

        fn sync_data_range(self: *Self, start: u64, end: u64) Error!void {
            if (start >= end) return;
            const start_blob = position_to_blob(start, self.per_blob());
            const end_blob = position_to_blob(end - 1, self.per_blob());
            for (self.pending.items) |*entry| {
                if (entry.index < start_blob or entry.index > end_blob) continue;
                if (entry.writer.needs_sync()) try entry.writer.sync();
            }
        }

        /// Reconcile a data partition holding no items against the offsets journal. At most
        /// one empty blob remains: the tail of an empty journal.
        fn align_empty(self: *Self) Error!Bounds {
            const offsets = &self.offsets.?;
            const start = offsets.pruning_boundary();
            const end = offsets.size();
            if (self.pending.items.len == 0) {
                // A fresh partition, or a crash after pruning data before pruning offsets.
                if (end > start) try offsets.clear_to_size(end);
                return .{ .start = end, .end = end };
            }
            const blob = self.pending.items[0].index;
            const target = @max(try blob_first_position(blob, self.per_blob()), start);
            const aligned = position_to_blob(target, self.per_blob()) == blob;
            if (aligned and start == target and end == target) {
                return .{ .start = target, .end = target };
            }
            if (!aligned) {
                var entry = self.pending.orderedRemove(0);
                entry.writer.deinit();
                try self.partition.?.remove(blob);
            }
            try offsets.clear_to_size(target);
            return .{ .start = target, .end = target };
        }

        /// Seal the retained data blobs and publish the offsets into a live journal.
        fn into_journal(self: *Self, bounds: Bounds) Error!J {
            const tail = position_to_blob(bounds.end, self.per_blob());
            const partition = self.partition.?;
            self.partition = null;
            const pending = self.pending.items;
            self.pending.items.len = 0;
            const data_scope = if (self.cfg.metrics) |scope| scope.child("data") else null;
            var blobs = try Writable.recover(partition, pending, tail, data_scope);
            errdefer blobs.deinit();
            var metrics = try Metrics.init(self.gpa, self.cfg.metrics);
            errdefer metrics.deinit();
            metrics.update(bounds.end, bounds.start, self.per_blob());
            const watermark = self.offsets.?.recovery_watermark();
            var offsets_recovery = self.offsets.?;
            self.offsets = null;
            // Publish the offsets watermark only after the data it authorizes is durable.
            const offsets = try offsets_recovery.publish(bounds.end);
            const journal: J = .{
                .gpa = self.gpa,
                .storage = self.storage,
                .prefix = self.prefix,
                .names = self.names,
                .blobs = blobs,
                .offsets = offsets,
                .bounds = bounds,
                .items_per_blob = self.per_blob(),
                .compression = self.cfg.compression,
                .codec_config = self.cfg.codec_config,
                .cache_ref = self.cfg.cache_ref,
                .write_buffer = self.cfg.write_buffer,
                .replay_buffer = self.cfg.replay_buffer,
                .barrier = .init(watermark),
                .metrics = metrics,
            };
            self.pending.deinit(self.gpa);
            self.discarded.deinit(self.gpa);
            self.scans.deinit(self.gpa);
            self.* = undefined;
            return journal;
        }
    };
}

/// Items encoded for a deferred append (`prepare_append`, then `append_prepared`).
pub const PreparedAppend = struct {
    encoded: []u8,
    /// Byte offset of each item's frame in `encoded`.
    starts: []usize,
    compressed: bool,

    pub fn deinit(self: *PreparedAppend, gpa: Allocator) void {
        gpa.free(self.encoded);
        gpa.free(self.starts);
        self.* = undefined;
    }
};

/// Encode every item of `nested` as a frame, recording each frame's start.
fn encode_items(
    comptime V: type,
    gpa: Allocator,
    compression: ?u8,
    nested: []const []const V,
    out: *std.ArrayList(u8),
    starts: *std.ArrayList(usize),
) Error!void {
    for (nested) |items| {
        try starts.ensureUnusedCapacity(gpa, items.len);
        for (items) |item| {
            starts.appendAssumeCapacity(out.items.len);
            _ = try frame.encode_frame_into(V, gpa, compression, item, out);
        }
    }
    assert(starts.items.len == 0 or starts.items[starts.items.len - 1] < out.items.len);
}

/// A position-addressed journal of variable-size items.
///
/// Like sqlite and rocksdb, the first invalid data read above the watermark's acknowledged
/// prefix is the new end of the journal; data at or below it is never repaired. Complete
/// frames whose payloads fail to decode are corruption.
pub fn Journal(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const RecoveryType = Recovery(V);
        pub const Cfg = Config(V);
        pub const BackingConfig = Cfg;
        pub const BackingRecovery = RecoveryType;
        pub const Replay = ReplayType(V);

        gpa: Allocator,
        storage: Storage,
        prefix: []u8,
        names: Names,
        /// The data blobs: sealed history plus the writable tail.
        blobs: Writable,
        /// Maps positions to byte offsets within their data blob.
        offsets: Offsets,
        /// The readable positions; `bounds.end` is the next append position.
        bounds: Bounds,
        items_per_blob: u64,
        compression: ?u8,
        codec_config: codec.Cfg(V),
        cache_ref: *paged.CacheRef,
        write_buffer: usize,
        replay_buffer: usize,
        /// The size proven durable for both the data and the offsets.
        barrier: Barrier,
        scratch: std.ArrayList(u8) = .empty,
        starts: std.ArrayList(usize) = .empty,
        positions: std.ArrayList(u64) = .empty,
        failed: bool = false,
        metrics: Metrics,

        /// Open the journal, recovering every retained item.
        pub fn init(gpa: Allocator, storage: Storage, cfg: Cfg) Error!Self {
            var recovery = try RecoveryType.open(gpa, storage, cfg, null);
            return recovery.publish(std.math.maxInt(u64));
        }

        /// Open at most `max_size` items, including pruned positions. The discarded suffix is
        /// durably removed before success. A cap below the retained start fails with
        /// `ItemPruned`.
        pub fn init_at_most(gpa: Allocator, storage: Storage, cfg: Cfg, max_size: u64) Error!Self {
            var recovery = try RecoveryType.open(gpa, storage, cfg, max_size);
            return recovery.publish(max_size);
        }

        /// Open an empty journal whose next append is at `size`, discarding all data. A crash
        /// leaves an intent the next open completes.
        pub fn init_at_size(gpa: Allocator, storage: Storage, cfg: Cfg, size_new: u64) Error!Self {
            var recovery = try RecoveryType.open_cleared(gpa, storage, cfg, size_new, true);
            return recovery.publish(std.math.maxInt(u64));
        }

        /// Open storage for an owner's recovery (`Backing::recover`).
        pub fn recover(
            gpa: Allocator,
            storage: Storage,
            cfg: Cfg,
            max_size: ?u64,
        ) Error!RecoveryType {
            return RecoveryType.open(gpa, storage, cfg, max_size);
        }

        /// Clear storage to an empty journal at `size` for an owner's recovery
        /// (`Backing::clear`).
        pub fn clear(gpa: Allocator, storage: Storage, cfg: Cfg, size_new: u64) Error!RecoveryType {
            return RecoveryType.open_cleared(gpa, storage, cfg, size_new, false);
        }

        /// Positions stored items may occupy, from the offsets checkpoint and blob names,
        /// without opening any blob (`Backing::span`). The end is an upper bound. A retained
        /// watermark above the start with no data blob is corruption.
        pub fn span(gpa: Allocator, storage: Storage, cfg: Cfg) Error!Bounds {
            assert(cfg.items_per_section > 0);
            var names = try Names.init(gpa, cfg.partition);
            defer names.deinit(gpa);
            var checkpoint = try Checkpoint.open(gpa, storage, names.offsets);
            const clear_target = checkpoint.clear_target();
            const watermark = checkpoint.watermark();
            checkpoint.deinit();
            if (clear_target) |target| return .{ .start = target, .end = target };
            const offsets = try Offsets.span(gpa, storage, offsets_config(cfg, names));
            const data = try blobs_mod.indices(gpa, storage, names.data);
            defer gpa.free(data);
            if (data.len == 0) {
                if (watermark) |value| if (value > offsets.start) return error.Corruption;
                return .{ .start = offsets.start, .end = offsets.start };
            }
            const per = cfg.items_per_section;
            const start = @max(offsets.start, try blob_first_position(data[0], per));
            const end = (try blob_first_position(data[data.len - 1], per)) +| per;
            return .{ .start = start, .end = end };
        }

        /// Close every blob (dropping unsynced items).
        pub fn deinit(self: *Self) void {
            self.release();
            self.blobs.deinit();
            self.offsets.deinit();
        }

        fn release(self: *Self) void {
            self.metrics.deinit();
            self.scratch.deinit(self.gpa);
            self.starts.deinit(self.gpa);
            self.positions.deinit(self.gpa);
            self.names.deinit(self.gpa);
            self.gpa.free(self.prefix);
        }

        /// The next append position.
        pub fn size(self: *const Self) u64 {
            return self.bounds.end;
        }

        /// The readable positions.
        pub fn get_bounds(self: *const Self) Bounds {
            return self.bounds;
        }

        /// The position before which every item has been pruned.
        pub fn pruning_boundary(self: *const Self) u64 {
            return self.bounds.start;
        }

        /// Append `item`, returning its position.
        pub fn append(self: *Self, item: V) Error!u64 {
            self.metrics.append_calls.metric().inc();
            return self.append_nested(&.{&.{item}});
        }

        /// Append `items`, returning the position of the last. Fails with `EmptyAppend` if
        /// there are none.
        pub fn append_many(self: *Self, items: []const V) Error!u64 {
            return self.append_many_nested(&.{items});
        }

        /// Append every slice of `nested` in order, returning the last position.
        pub fn append_many_nested(self: *Self, nested: []const []const V) Error!u64 {
            self.metrics.append_many_calls.metric().inc();
            return self.append_nested(nested);
        }

        /// Appends without counting a call (each public append counts its own).
        fn append_nested(self: *Self, nested: []const []const V) Error!u64 {
            assert(!self.failed);
            self.scratch.clearRetainingCapacity();
            self.starts.clearRetainingCapacity();
            try encode_items(V, self.gpa, self.compression, nested, &self.scratch, &self.starts);
            return self.write_encoded(self.scratch.items, self.starts.items);
        }

        /// Encode `nested` for a later `append_prepared`.
        pub fn prepare_append(self: *const Self, nested: []const []const V) Error!PreparedAppend {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(self.gpa);
            var starts: std.ArrayList(usize) = .empty;
            defer starts.deinit(self.gpa);
            try encode_items(V, self.gpa, self.compression, nested, &out, &starts);
            const encoded = try out.toOwnedSlice(self.gpa);
            errdefer self.gpa.free(encoded);
            return .{
                .encoded = encoded,
                .starts = try starts.toOwnedSlice(self.gpa),
                .compressed = self.compression != null,
            };
        }

        /// Append prepared items, freeing them. Returns the last position. Fails with
        /// `InvalidConfiguration` if they were encoded with another compression setting.
        pub fn append_prepared(self: *Self, prepared: *PreparedAppend) Error!u64 {
            assert(!self.failed);
            defer prepared.deinit(self.gpa);
            if (prepared.starts.len == 0) return error.EmptyAppend;
            if (prepared.compressed != (self.compression != null)) {
                return error.InvalidConfiguration;
            }
            self.metrics.append_prepared_calls.metric().inc();
            return self.write_encoded(prepared.encoded, prepared.starts);
        }

        /// Write encoded frames, splitting at blob boundaries so data and offsets rotate
        /// together.
        fn write_encoded(self: *Self, bytes: []const u8, starts: []const usize) Error!u64 {
            const count = starts.len;
            if (count == 0) return error.EmptyAppend;
            // Reject before writing anything if the size would overflow.
            _ = std.math.add(u64, self.bounds.end, count) catch return error.SizeOverflow;
            errdefer self.failed = true;
            var written: usize = 0;
            while (written < count) {
                const batch = contiguous.batch_count_to_blob_boundary(
                    self.bounds.end,
                    count - written,
                    self.items_per_blob,
                );
                const batch_start = starts[written];
                const last = written + batch;
                const batch_end = if (last < count) starts[last] else bytes.len;
                const slice = bytes[batch_start..batch_end];
                const tail = &self.blobs.tail;
                const base = tail.try_append(slice) orelse try tail.append(slice);
                try self.append_offsets(base, starts[written..][0..batch], batch_start);
                self.bounds.end += batch;
                self.update_metrics();
                written += batch;
                // Seal the just-filled tail and open the next blob.
                if (self.bounds.end % self.items_per_blob == 0) try self.blobs.seal_tail();
            }
            return self.bounds.end - 1;
        }

        fn append_offsets(
            self: *Self,
            base: u64,
            starts: []const usize,
            batch_start: usize,
        ) Error!void {
            assert(starts.len > 0);
            self.positions.clearRetainingCapacity();
            try self.positions.ensureTotalCapacity(self.gpa, starts.len);
            for (starts) |start| {
                const offset = std.math.add(u64, base, start - batch_start) catch
                    return error.OffsetOverflow;
                self.positions.appendAssumeCapacity(offset);
            }
            const last = try self.offsets.append_many(self.positions.items);
            assert(last == self.bounds.end + starts.len - 1);
        }

        /// Prune blobs holding only items below `min_position` (capped at the tail). Returns
        /// whether any were pruned.
        pub fn prune(self: *Self, min_position: u64) Error!bool {
            assert(!self.failed);
            const per = self.items_per_blob;
            const target_blob = position_to_blob(min_position, per);
            const tail_blob = position_to_blob(self.bounds.end, per);
            const min_blob = @min(target_blob, tail_blob);
            if (min_blob <= self.blobs.oldest_blob_index) return false;
            errdefer self.failed = true;
            const boundary = try blob_first_position(min_blob, per);
            // Make all data and its offsets durable before removing any: removals are durable,
            // and offsets ending behind the retained data's start could not be rebuilt.
            try self.blobs.sync();
            try self.offsets.commit();
            self.barrier.mark_durable(self.bounds.end);
            try self.blobs.prune(min_blob);
            self.bounds.start = boundary;
            self.update_metrics();
            // Prune data before offsets: a crash leaves offsets behind, which init repairs.
            _ = try self.offsets.prune(boundary);
            return true;
        }

        /// Persist the data blobs so committed data survives a crash. Does not advance the
        /// recovery watermark, so a reopen may replay entries above it.
        pub fn commit(self: *Self) Error!void {
            assert(!self.failed);
            self.metrics.commit_calls.metric().inc();
            errdefer self.failed = true;
            try self.blobs.sync();
        }

        /// Durably persist the data and offsets and advance the watermark to the size proven
        /// durable for both (commonware's `start_sync`; syncs complete synchronously).
        pub fn start_sync(self: *Self) Error!void {
            assert(!self.failed);
            self.metrics.start_sync_calls.metric().inc();
            errdefer self.failed = true;
            try self.blobs.sync();
            try self.offsets.start_sync();
            self.barrier.record(self.bounds.end, .{});
        }

        /// Persist the data, then the offsets and their watermark.
        pub fn sync(self: *Self) Error!void {
            assert(!self.failed);
            self.metrics.sync_calls.metric().inc();
            errdefer self.failed = true;
            const size_now = self.bounds.end;
            // Make data durable before the offsets journal can acknowledge its prefix.
            try self.blobs.sync();
            try self.offsets.sync();
            self.barrier.mark_durable(size_now);
        }

        /// Remove the data blobs and the offsets journal, freeing the journal. An interrupted
        /// destroy reopens either recovered or empty at position zero.
        pub fn destroy(self: *Self) Error!void {
            assert(!self.failed);
            var data_cleared = false;
            defer {
                if (!data_cleared) self.blobs.deinit();
                self.release();
                self.* = undefined;
            }
            const Dependents = struct {
                blobs: *Writable,
                cleared: *bool,

                pub fn clear(dependents: @This()) Error!void {
                    dependents.cleared.* = true;
                    try dependents.blobs.destroy();
                }
            };
            // The offsets journal stages its clear before the data blobs are deleted.
            try self.offsets.destroy_cleared(Dependents{
                .blobs = &self.blobs,
                .cleared = &data_cleared,
            });
        }

        /// Discard all items and continue at `size_new` (at or beyond the end), as if opened
        /// with `init_at_size`. Fails with `ItemOutOfRange` below the end.
        pub fn clear_to_size(self: *Self, size_new: u64) Error!void {
            assert(!self.failed);
            if (size_new < self.bounds.end) return error.ItemOutOfRange;
            errdefer self.failed = true;
            // Stage in the offsets first, so a crash mid-clear leaves an intent.
            try self.offsets.stage_clear_intent(size_new);
            try self.blobs.clear(position_to_blob(size_new, self.items_per_blob));
            try self.offsets.clear_to_size(size_new);
            self.bounds = .{ .start = size_new, .end = size_new };
            self.update_metrics();
            self.barrier = .init(size_new);
        }

        fn update_metrics(self: *Self) void {
            self.metrics.update(self.bounds.end, self.bounds.start, self.items_per_blob);
        }

        fn validate_readable(self: *const Self, position: u64) Error!void {
            if (position >= self.bounds.end) return error.ItemOutOfRange;
            if (position < self.bounds.start) return error.ItemPruned;
        }

        fn data_writer(self: *Self, position: u64) *paged.Writer {
            // A position in bounds maps to a retained blob.
            return self.blobs.get(position_to_blob(position, self.items_per_blob)).?;
        }

        /// Read the item at `position`. The caller owns it.
        pub fn read(self: *Self, position: u64) Error!V {
            self.metrics.read_calls.metric().inc();
            return self.read_item(position);
        }

        /// `read` without counting a call (`read_many` counts one per batch).
        fn read_item(self: *Self, position: u64) Error!V {
            try self.validate_readable(position);
            const cached = self.offsets.try_read_sync(position);
            if (cached) |offset| {
                if (self.try_read_frame_sync(position, offset)) |item| {
                    self.metrics.cache_hits.metric().inc();
                    self.metrics.items_read.metric().inc();
                    return item;
                }
            }
            const offset = cached orelse try self.offsets.read(position);
            self.metrics.cache_misses.metric().inc();
            const writer = self.data_writer(position);
            const cfg = self.codec_config;
            const compressed = self.compression != null;
            const read_frame = frame.read_frame_at(V, self.gpa, writer, offset, cfg, compressed);
            const item = (try read_frame).item;
            self.metrics.items_read.metric().inc();
            return item;
        }

        /// Read the items at strictly increasing `positions` into `out`. The caller owns them.
        pub fn read_many(self: *Self, positions: []const u64, out: []V) Error!void {
            assert(out.len == positions.len);
            if (positions.len == 0) return;
            if (positions[0] < self.bounds.start) return error.ItemPruned;
            const last = positions[positions.len - 1];
            if (last >= self.bounds.end) return error.ItemOutOfRange;
            for (positions[1..], positions[0 .. positions.len - 1]) |position, previous| {
                assert(previous < position);
            }
            self.metrics.read_many_calls.metric().inc();
            var done: usize = 0;
            errdefer for (out[0..done]) |item| codec.free(V, self.gpa, item);
            for (positions, out) |position, *item| {
                item.* = try self.read_item(position);
                done += 1;
            }
        }

        /// The item if its offset and frame are readable without I/O.
        pub fn try_read_sync(self: *Self, position: u64) ?V {
            self.validate_readable(position) catch return null;
            const offset = self.offsets.try_read_sync(position) orelse return null;
            const item = self.try_read_frame_sync(position, offset) orelse return null;
            self.metrics.cache_hits.metric().inc();
            self.metrics.items_read.metric().inc();
            return item;
        }

        /// Probe strictly increasing `positions`, serving those readable without I/O.
        pub fn try_read_many_sync(self: *Self, positions: []const u64, out: []?V) void {
            assert(out.len == positions.len);
            for (positions, out, 0..) |position, *slot, index| {
                if (index > 0) assert(positions[index - 1] < position);
                slot.* = self.try_read_sync(position);
            }
        }

        /// Decode the frame at `offset` from cached bytes; any miss declines.
        fn try_read_frame_sync(self: *Self, position: u64, offset: u64) ?V {
            const writer = self.data_writer(position);
            const remaining = std.math.sub(u64, writer.size(), offset) catch return null;
            const header_len: usize = @intCast(@min(remaining, max_prefix_size));
            if (header_len == 0) return null;
            var header: [max_prefix_size]u8 = undefined;
            if (!writer.try_read_sync_into(header[0..header_len], offset)) return null;
            const found = frame.find_frame(header[0..header_len], offset) catch return null;
            const varint_len: usize, const data_len: usize = switch (found.info) {
                .complete => |complete| .{ complete.varint_len, complete.data_len },
                .incomplete => |incomplete| .{ incomplete.varint_len, incomplete.total_len },
            };
            const item_len = varint_len + data_len;
            if (item_len > remaining) return null;
            const cfg = self.codec_config;
            const compressed = self.compression != null;
            if (item_len <= header_len) {
                const payload = header[varint_len..item_len];
                return frame.decode_item(V, self.gpa, payload, cfg, compressed) catch null;
            }
            const buf = self.gpa.alloc(u8, item_len) catch return null;
            defer self.gpa.free(buf);
            if (!writer.try_read_sync_into(buf, offset)) return null;
            return frame.decode_item(V, self.gpa, buf[varint_len..], cfg, compressed) catch null;
        }

        /// Replay the items in `range` as batches of consecutive items, each within one blob
        /// and of about `buffer_bytes` encoded bytes. Fails with `ItemPruned` if the range
        /// starts before the bounds, or `ItemOutOfRange` if it ends after them or is inverted.
        pub fn replay(self: *Self, range: Bounds, buffer_bytes: usize) Error!Replay {
            assert(buffer_bytes > 0);
            if (range.start > range.end or range.end > self.bounds.end) {
                return error.ItemOutOfRange;
            }
            if (range.start < self.bounds.start) return error.ItemPruned;
            const offset = if (range.start < range.end) try self.offsets.read(range.start) else 0;
            return .{
                .journal = self,
                .range = range,
                .budget = buffer_bytes,
                .position = range.start,
                .offset = offset,
            };
        }

        // Test helpers.

        /// The persisted offsets recovery watermark.
        pub fn recovery_watermark(self: *const Self) u64 {
            return self.offsets.recovery_watermark();
        }

        pub fn test_offsets_size(self: *const Self) u64 {
            return self.offsets.size();
        }

        pub fn test_oldest_blob(self: *const Self) u64 {
            return self.blobs.oldest_blob_index;
        }

        /// Prune only the data blobs below `min_blob` (a crash before the offsets prune).
        pub fn test_prune_data(self: *Self, min_blob_in: u64) Error!bool {
            const min_blob = @min(min_blob_in, self.blobs.tail_blob_index());
            if (min_blob <= self.blobs.oldest_blob_index) return false;
            try self.blobs.prune(min_blob);
            return true;
        }

        /// Prune only the offsets journal.
        pub fn test_prune_offsets(self: *Self, position: u64) Error!bool {
            return self.offsets.prune(position);
        }

        /// Durably set the offsets recovery watermark.
        pub fn test_set_offsets_recovery_watermark(self: *Self, watermark: u64) Error!void {
            try self.offsets.test_set_recovery_watermark(watermark);
        }

        /// Append a frame straight to the data tail without indexing it (a crash between
        /// the data and offsets writes). Returns its offset.
        pub fn test_append_data(self: *Self, item: V) Error!u64 {
            self.scratch.clearRetainingCapacity();
            _ = try frame.encode_frame_into(V, self.gpa, self.compression, item, &self.scratch);
            return self.blobs.tail.append(self.scratch.items);
        }
    };
}

/// Sequential replay over a journal's retained data blobs (borrows the journal).
fn ReplayType(comptime V: type) type {
    return struct {
        const Self = @This();
        const J = Journal(V);

        journal: *J,
        range: Bounds,
        /// Encoded bytes decoded per batch, at least.
        budget: u64,
        /// Next position to yield.
        position: u64,
        /// Byte offset of `position`'s frame in its blob.
        offset: u64,
        /// The replay of the blob holding `position`, and that blob's exclusive end.
        reader: ?paged.Replay = null,
        blob_end: u64 = 0,
        items: std.ArrayList(V) = .empty,
        /// An error to yield after the batch decoded before it.
        pending_error: ?Error = null,
        done: bool = false,

        pub fn deinit(self: *Self) void {
            self.free_items();
            self.items.deinit(self.journal.gpa);
            if (self.reader) |*reader| reader.deinit();
            self.* = undefined;
        }

        fn free_items(self: *Self) void {
            for (self.items.items) |item| codec.free(V, self.journal.gpa, item);
            self.items.clearRetainingCapacity();
        }

        /// The next batch (owned by the replay, valid until the next call), or null once the
        /// range is replayed. An error ends the replay after the items decoded before it.
        pub fn next(self: *Self) Error!?fixed.Batch(V) {
            self.free_items();
            if (self.pending_error) |err| {
                self.pending_error = null;
                self.done = true;
                return err;
            }
            if (self.done or self.position >= self.range.end) return null;
            const start = self.position;
            self.decode_batch() catch |err| {
                if (self.items.items.len == 0) {
                    self.done = true;
                    return err;
                }
                self.pending_error = err;
            };
            if (self.position == self.blob_end) self.close_blob();
            assert(self.items.items.len > 0);
            assert(self.position == start + self.items.items.len);
            return .{ .start = start, .items = self.items.items };
        }

        fn open_blob(self: *Self) Error!void {
            const journal = self.journal;
            const per = journal.items_per_blob;
            const blob = position_to_blob(self.position, per);
            const writer = journal.blobs.get(blob).?;
            var reader = try writer.view_replay(journal.replay_buffer);
            errdefer reader.deinit();
            try reader.seek_to(self.offset);
            self.reader = reader;
            self.blob_end = contiguous.blob_end_position(blob, per, self.range.end);
            assert(self.blob_end > self.position);
        }

        fn close_blob(self: *Self) void {
            if (self.reader) |*reader| reader.deinit();
            self.reader = null;
            // Later blobs start at byte offset zero.
            self.offset = 0;
        }

        /// Decode frames from the current blob until the byte budget is reached.
        fn decode_batch(self: *Self) Error!void {
            if (self.reader == null) try self.open_blob();
            const reader = &self.reader.?;
            const start_offset = self.offset;
            while (self.position < self.blob_end) {
                // Bounds say this item exists, so a short blob is corruption.
                if (reader.remaining() < max_prefix_size) {
                    const ready = try reader.ensure(max_prefix_size);
                    if (!ready and reader.remaining() == 0) return error.Corruption;
                }
                const before = reader.remaining();
                var header = codec.Reader.init(reader.bytes());
                const prefix = frame.decode_length_prefix(&header) catch |err| {
                    if (reader.is_exhausted() or before < max_prefix_size) {
                        return error.Corruption;
                    }
                    return err;
                };
                const frame_len: u64 = prefix.varint_len + @as(u64, prefix.size);
                const next_offset = std.math.add(u64, self.offset, frame_len) catch
                    return error.OffsetOverflow;
                if (next_offset > reader.blob_size()) return error.Corruption;
                reader.advance(prefix.varint_len);
                if (!try reader.ensure(prefix.size)) return error.Corruption;
                try self.decode_item(reader.bytes()[0..prefix.size]);
                reader.advance(prefix.size);
                self.position += 1;
                self.offset = next_offset;
                if (self.offset - start_offset >= self.budget) break;
                if (reader.remaining() < max_prefix_size) break;
            }
        }

        fn decode_item(self: *Self, payload: []const u8) Error!void {
            const journal = self.journal;
            try self.items.ensureUnusedCapacity(journal.gpa, 1);
            const compressed = journal.compression != null;
            const cfg = journal.codec_config;
            const item = try frame.decode_item(V, journal.gpa, payload, cfg, compressed);
            self.items.appendAssumeCapacity(item);
        }
    };
}

test {
    _ = @import("variable_test.zig");
    _ = @import("variable_offsets_test.zig");
    _ = @import("variable_torn_test.zig");
    _ = @import("variable_size_test.zig");
}
