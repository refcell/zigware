//! Single-owner, append-only access to a paged blob (commonware's `paged/writer.rs`), and
//! `Replay` over its logical bytes (`paged/read.rs`).
//!
//! A `Writer` exclusively owns its blob. Appended bytes are readable immediately but durable
//! only after `sync`. Appends accumulate in a write buffer and reach the blob in whole physical
//! pages (logical page plus CRC record, see `mod.zig`); full pages are cached in a shared page
//! cache, so reads are served from the write buffer, the cache, or the blob. Large appends
//! bypass the buffer and write whole pages directly.
//!
//! `open_recovery` (commonware's `Recovery::open`) trims an invalid tail, backing up to the last
//! page with a valid checksum, and zeroes a stale checksum slot on a partial last page so a later
//! torn write cannot revalidate bytes past the page's valid length. Only a recovering writer may
//! `truncate`; `finish_recovery` turns it into an append-only writer (`Writer::from`).
//!
//! Storage-mutating methods leave the writer failed after an error (commonware consumes it);
//! only `deinit` may follow. On success the writer owns the blob and `deinit` closes it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Crc32 = @import("cryptography").crc32.Crc32;
const paged = @import("mod.zig");
const SyncState = @import("../mod.zig").SyncState;
const Buffer = @import("tip.zig").Buffer;
const CacheRef = @import("cache.zig").CacheRef;
const Checksum = paged.Checksum;
const ActiveChecksum = paged.ActiveChecksum;
const checksum_size: usize = paged.checksum_size;

pub const Error = paged.Error;

fn round_up(value: usize, multiple: usize) usize {
    assert(multiple > 0);
    return (value + multiple - 1) / multiple * multiple;
}

/// The write-buffer capacity actually used: a whole number of pages, at least two, so the
/// buffer can hold a full page of new data beside a nearly full cached page.
pub fn adjusted_capacity(capacity: usize, page_size: usize) usize {
    assert(page_size > 0);
    return @max(round_up(capacity, page_size), 2 * page_size);
}

/// Whether an append should bypass the write buffer: it would overflow capacity, and at least
/// one whole page remains after filling the current page to a boundary. A buffered append
/// therefore exceeds `capacity` by less than one page.
pub fn too_big_for_buffer(
    buffer_len: usize,
    buffer_capacity: usize,
    append_len: usize,
    page_size: usize,
) bool {
    const fill = round_up(buffer_len, page_size) - buffer_len;
    return buffer_len + append_len > buffer_capacity and append_len >= fill + page_size;
}

/// Whether a partial page of `partial_len` bytes needs a write when `full_pages` full pages
/// precede it in the same flush: an empty tip never writes, a moved tip always writes, and an
/// unmoved tip writes only when its length changed.
fn partial_page_dirty(full_pages: usize, partial_len: usize, flushed: ?ActiveChecksum) bool {
    if (partial_len == 0) return false;
    if (full_pages > 0) return true;
    const state = flushed orelse return true;
    return state.len != partial_len;
}

pub const Phase = enum { recovering, append };

/// What `read_last_valid_page` found.
const LastPage = struct {
    /// The last valid page if partial: its checksum, and whether its other slot is inert.
    /// Its logical bytes are left at the front of the scratch page.
    partial: ?struct { checksum: ActiveChecksum, inert: bool },
    /// Pages up to and including the last valid page.
    pages: u64,
    /// Whether bytes follow the last valid page.
    invalid: bool,
};

pub fn Writer(comptime Blob: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        blob: *Blob,
        phase: Phase,
        /// The page the next appended byte lands in.
        current_page: u64,
        /// The active checksum of the partial page in the blob, if any.
        partial_page_state: ?ActiveChecksum,
        /// The durable checksum of the page a partial-page flush would rewrite, if any. It
        /// trails `partial_page_state` until a sync proves the flushed state durable.
        durable_page_state: ?ActiveChecksum,
        sync_state: SyncState,
        /// This blob's id in the page cache.
        id: u64,
        cache_ref: *CacheRef,
        /// Logical bytes following the last full page in the blob.
        buffer: Buffer,
        /// Physical pages staged for one write: the buffer's full pages plus a partial page.
        scratch: []u8,
        /// One physical page for reads.
        page_scratch: []u8,
        failed: bool = false,

        pub fn page_size(self: *const Self) usize {
            return self.cache_ref.page_size;
        }

        fn physical_page_size(self: *const Self) usize {
            return self.page_size() + checksum_size;
        }

        /// Open `blob` (holding `blob_size` physical bytes) for recovery, trimming any invalid
        /// tail. On error the caller still owns `blob`.
        pub fn open_recovery(
            gpa: Allocator,
            blob: *Blob,
            blob_size: u64,
            capacity: usize,
            cache_ref: *CacheRef,
        ) Error!Self {
            const page_size_value: usize = cache_ref.page_size;
            const physical = page_size_value + checksum_size;
            const page_scratch = try gpa.alloc(u8, physical);
            errdefer gpa.free(page_scratch);
            const last = try read_last_valid_page(blob, blob_size, page_size_value, page_scratch);
            if (last.invalid) {
                try blob.resize(last.pages * physical);
                try blob.sync();
            }
            // A valid tail may still include unsynced writes from the wrapped blob handle.
            var sync_state: SyncState = if (last.invalid) .clean else .dirty;
            var current_page = last.pages;
            var partial_state: ?ActiveChecksum = null;
            var seed: []const u8 = &.{};
            if (last.partial) |partial| {
                // The next rewrite of this page lands its checksum in the other slot. If a torn
                // write left part of a checksum there, a second torn write could complete it
                // over bytes beyond the valid length, so it is zeroed first.
                if (!partial.inert) {
                    const slot_offset = last.pages * physical - checksum_size +
                        partial.checksum.slot.other().offset();
                    const zeros = Checksum.slot_bytes(0, 0);
                    try sync_state.write_at(blob, slot_offset, &zeros, true);
                }
                current_page -= 1;
                partial_state = partial.checksum;
                seed = page_scratch[0..partial.checksum.len];
            }
            const adjusted = adjusted_capacity(capacity, page_size_value);
            var buffer = try Buffer.init(
                gpa,
                current_page * page_size_value,
                seed,
                adjusted,
                page_size_value,
            );
            errdefer buffer.deinit(gpa);
            const scratch = try gpa.alloc(u8, (adjusted / page_size_value + 1) * physical);
            return .{
                .gpa = gpa,
                .blob = blob,
                .phase = .recovering,
                .current_page = current_page,
                .partial_page_state = partial_state,
                .durable_page_state = partial_state,
                .sync_state = sync_state,
                .id = cache_ref.next_id(),
                .cache_ref = cache_ref,
                .buffer = buffer,
                .scratch = scratch,
                .page_scratch = page_scratch,
            };
        }

        /// Open an append-only writer, repairing incomplete tail pages (`Writer::new`).
        pub fn init(
            gpa: Allocator,
            blob: *Blob,
            blob_size: u64,
            capacity: usize,
            cache_ref: *CacheRef,
        ) Error!Self {
            var result = try open_recovery(gpa, blob, blob_size, capacity, cache_ref);
            result.finish_recovery();
            return result;
        }

        /// Give up permission to shorten the blob (`Writer::from(Recovery)`).
        pub fn finish_recovery(self: *Self) void {
            assert(self.phase == .recovering);
            self.phase = .append;
        }

        /// Close the blob (dropping unsynced bytes) and free buffers.
        pub fn deinit(self: *Self) void {
            self.blob.deinit();
            self.buffer.deinit(self.gpa);
            self.gpa.free(self.scratch);
            self.gpa.free(self.page_scratch);
            self.* = undefined;
        }

        /// Scan backwards from the end of the blob to the last valid page.
        fn read_last_valid_page(
            blob: *Blob,
            blob_size: u64,
            page_size_value: usize,
            scratch: []u8,
        ) Error!LastPage {
            const physical = page_size_value + checksum_size;
            assert(scratch.len == physical);
            const partial_bytes = blob_size % physical;
            var last_end = blob_size - partial_bytes;
            // A truncated last physical page cannot hold a valid CRC record.
            var invalid = partial_bytes != 0;
            while (last_end != 0) {
                const start = last_end - physical;
                try blob.read_at(start, scratch);
                if (Checksum.validate_page(scratch)) |checksum| {
                    const pages = last_end / physical;
                    if (checksum.len == page_size_value) {
                        return .{ .partial = null, .pages = pages, .invalid = invalid };
                    }
                    const inert = Checksum.other_slot_is_inert(scratch, checksum);
                    return .{
                        .partial = .{ .checksum = checksum, .inert = inert },
                        .pages = pages,
                        .invalid = invalid,
                    };
                }
                last_end = start;
                invalid = true;
            }
            return .{ .partial = null, .pages = 0, .invalid = invalid };
        }

        /// The logical size, including buffered bytes.
        pub fn size(self: *const Self) u64 {
            return self.buffer.size();
        }

        /// Whether `sync` would write buffered bytes or sync the blob.
        pub fn needs_sync(self: *const Self) bool {
            return !self.sync_state.is_clean() or self.has_flush_work(true);
        }

        fn has_flush_work(self: *const Self, write_partial_page: bool) bool {
            const full_pages = self.buffer.len / self.page_size();
            if (full_pages > 0) return true;
            if (!write_partial_page) return false;
            const partial_len = self.buffer.len % self.page_size();
            return partial_page_dirty(full_pages, partial_len, self.partial_page_state);
        }

        /// Append `bytes`, returning the logical offset of the first byte.
        pub fn append(self: *Self, bytes: []const u8) Error!u64 {
            assert(!self.failed);
            errdefer self.failed = true;
            const page_size_value = self.page_size();
            const capacity = self.buffer.capacity;
            if (too_big_for_buffer(self.buffer.len, capacity, bytes.len, page_size_value)) {
                return self.append_bulk(bytes);
            }
            const offset = self.buffer.size();
            if (self.buffer.append(bytes)) _ = try self.flush_internal(false, false);
            assert(self.buffer.size() == offset + bytes.len);
            return offset;
        }

        /// Append to the write buffer if it fits without flushing; no I/O.
        pub fn try_append(self: *Self, bytes: []const u8) ?u64 {
            assert(!self.failed);
            return self.buffer.try_append(bytes);
        }

        /// Encode `value` into the write buffer if it fits without flushing; no I/O.
        pub fn try_append_value(self: *Self, comptime T: type, value: T) ?u64 {
            assert(!self.failed);
            return self.buffer.try_append_value(T, value);
        }

        /// A large append: top up the tip to a page boundary, write whole pages directly, and
        /// leave only the sub-page suffix buffered.
        fn append_bulk(self: *Self, bytes: []const u8) Error!u64 {
            const page_size_value = self.page_size();
            const offset = self.buffer.size();
            const fill = round_up(self.buffer.len, page_size_value) - self.buffer.len;
            if (fill > 0) _ = self.buffer.append(bytes[0..fill]);
            const boundary = self.buffer.size();
            if (!self.buffer.is_empty()) {
                _ = try self.flush_internal(false, false);
                assert(self.buffer.size() == boundary and self.buffer.is_empty());
            }
            assert(self.partial_page_state == null); // An empty tip has no partial page.

            const bulk_len = (bytes.len - fill) / page_size_value * page_size_value;
            const physical = self.physical_page_size();
            var start = fill;
            while (start < fill + bulk_len) {
                const chunk_len = @min(self.buffer.capacity, fill + bulk_len - start);
                const chunk = bytes[start..][0..chunk_len];
                const written = self.append_full_pages(chunk, null, self.scratch);
                const logical_offset = boundary + (start - fill);
                assert(self.cache_ref.cache(self.id, chunk, logical_offset) == 0);
                const write_offset = self.current_page * physical;
                self.current_page += chunk.len / page_size_value;
                const pages = self.scratch[0..written];
                try self.sync_state.write_at(self.blob, write_offset, pages, false);
                start += chunk.len;
            }
            self.buffer.replace(boundary + bulk_len, bytes[fill + bulk_len ..]);
            assert(self.current_page * page_size_value == self.buffer.offset);
            return offset;
        }

        /// Write every full buffered page (and with `write_partial_page`, the partial page) in
        /// one write. With `durable`, the write is made durable. Returns whether it was.
        fn flush_internal(self: *Self, write_partial_page: bool, durable: bool) Error!bool {
            if (!self.has_flush_work(write_partial_page)) return false;
            // With no unsynced mutation, the last flushed partial state is durable and becomes
            // the checksum the rewrite below must preserve.
            if (self.sync_state.is_clean()) self.durable_page_state = self.partial_page_state;

            const page_size_value = self.page_size();
            const full_len = self.buffer.full_len();
            const pages = full_len / page_size_value;
            const cache_offset = self.buffer.offset;
            const full = self.buffer.data[0..full_len];
            const partial = self.buffer.data[full_len..self.buffer.len];
            const built = self.to_physical_pages(full, partial, write_partial_page);
            assert(built.len > 0);
            // Cache full pages before publishing the new state so reads never see stale bytes.
            if (pages > 0) assert(self.cache_ref.cache(self.id, full, cache_offset) == 0);

            const write_offset = self.current_page * self.physical_page_size();
            self.current_page += pages;
            self.partial_page_state = built.partial;
            // A new tip page has no durable contents to preserve yet.
            if (pages > 0) self.durable_page_state = null;
            self.buffer.consume_full_pages();
            assert(self.current_page * page_size_value == self.buffer.offset);

            const pages_out = self.scratch[0..built.len];
            try self.sync_state.write_at(self.blob, write_offset, pages_out, durable);
            if (durable) self.durable_page_state = self.partial_page_state;
            return durable;
        }

        /// Stage physical pages for `full` pages and, if dirty and requested, the partial page.
        fn to_physical_pages(
            self: *Self,
            full: []const u8,
            partial: []const u8,
            include_partial_page: bool,
        ) struct { len: usize, partial: ?ActiveChecksum } {
            const page_size_value = self.page_size();
            const pages = full.len / page_size_value;
            const durable = self.durable_page_state;
            var len: usize = 0;
            if (pages > 0) len = self.append_full_pages(full, durable, self.scratch);
            if (!include_partial_page) return .{ .len = len, .partial = null };
            if (!partial_page_dirty(pages, partial.len, self.partial_page_state)) {
                return .{ .len = len, .partial = null };
            }
            // Only a rewrite of the same page preserves its durable checksum.
            const old = if (pages == 0) durable else null;
            const crc = Crc32.checksum(partial);
            const record, const active = paged.build_crc_record(@intCast(partial.len), crc, old);
            // A persisted partial page still occupies a whole physical page:
            // [partial logical bytes, zero padding, crc record].
            const page = self.scratch[len..][0..self.physical_page_size()];
            @memcpy(page[0..partial.len], partial);
            @memset(page[partial.len..page_size_value], 0);
            page[page_size_value..][0..checksum_size].* = record.to_bytes();
            return .{ .len = len + page.len, .partial = active };
        }

        /// Write whole logical pages in on-disk format into `out`. The first page preserves
        /// `old` in its original slot when present. Returns the bytes written.
        fn append_full_pages(self: *Self, data: []const u8, old: ?ActiveChecksum, out: []u8) usize {
            const page_size_value = self.page_size();
            assert(data.len % page_size_value == 0 and data.len > 0);
            const physical = self.physical_page_size();
            var page: usize = 0;
            while (page * page_size_value < data.len) : (page += 1) {
                const logical = data[page * page_size_value ..][0..page_size_value];
                const crc = Crc32.checksum(logical);
                const previous = if (page == 0) old else null;
                const record, _ = paged.build_crc_record(@intCast(page_size_value), crc, previous);
                const target = out[page * physical ..][0..physical];
                @memcpy(target[0..page_size_value], logical);
                target[page_size_value..][0..checksum_size].* = record.to_bytes();
            }
            return page * physical;
        }

        /// Flush buffered bytes and make all pending mutations durable.
        pub fn sync(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            if (try self.flush_internal(true, true)) return;
            try self.sync_state.sync(self.blob);
            self.durable_page_state = self.partial_page_state;
        }

        /// commonware's `start_sync`: blobs sync synchronously here, so this is `sync`.
        pub fn start_sync(self: *Self) Error!void {
            return self.sync();
        }

        /// Durably retain at most `target` logical bytes. A larger `target` leaves the length
        /// unchanged. Pending writes are synced either way. Recovery only.
        pub fn truncate(self: *Self, target: u64) Error!void {
            assert(self.phase == .recovering);
            assert(!self.failed);
            errdefer self.failed = true;
            if (target < self.size()) try self.shrink(target);
            try self.sync();
        }

        fn shrink(self: *Self, target: u64) Error!void {
            // Partial-page truncation requires a durable source page.
            try self.sync();
            const page_size_value: u64 = self.page_size();
            const physical: u64 = self.physical_page_size();
            const full_pages = target / page_size_value;
            const partial_bytes = target % page_size_value;
            const new_physical_size = (full_pages + @intFromBool(partial_bytes > 0)) * physical;
            const tail_offset = full_pages * page_size_value;
            const current_pages = self.current_page + @intFromBool(self.partial_page_state != null);
            // A logical shrink can leave the physical page count unchanged.
            if (new_physical_size != current_pages * physical) {
                try self.sync_state.resize(self.blob, new_physical_size);
            }
            if (partial_bytes > 0) {
                return self.shrink_to_partial(full_pages, @intCast(partial_bytes), tail_offset);
            }
            // A page-boundary shrink needs no CRC-slot rewrite.
            self.partial_page_state = null;
            self.durable_page_state = null;
            self.current_page = full_pages;
            self.buffer.replace(tail_offset, &.{});
        }

        /// Shrink to a partial tip page and make the shorter CRC slot authoritative.
        fn shrink_to_partial(
            self: *Self,
            full_pages: u64,
            partial_bytes: u16,
            tail_offset: u64,
        ) Error!void {
            self.current_page = full_pages;
            const page_data, const old = try paged.read_page_with_checksum(
                self.blob,
                full_pages,
                self.page_size(),
                self.page_scratch,
            );
            if (page_data.len < partial_bytes) return error.InvalidChecksum;
            const new_data = page_data[0..partial_bytes];
            self.buffer.replace(tail_offset, new_data);
            const crc = Crc32.checksum(new_data);
            const final = try self.sync_shrunk_page(full_pages, partial_bytes, crc, old);
            self.partial_page_state = final;
            self.durable_page_state = final;
        }

        /// Durably rewrite a committed page's checksum to a shorter length. Recovery chooses
        /// the valid slot with the larger length, so the new checksum is staged with length 0,
        /// then published, and only then is the old longer slot cleared: a crash at any point
        /// recovers either the old page or the new shorter one.
        fn sync_shrunk_page(
            self: *Self,
            page: u64,
            new_len: u16,
            new_crc: u32,
            old: ActiveChecksum,
        ) Error!ActiveChecksum {
            const physical: u64 = self.physical_page_size();
            const crc_start = page * physical + self.page_size();
            const new_slot = old.slot.other();
            const new_slot_offset = crc_start + new_slot.offset();
            const staged = Checksum.slot_bytes(0, new_crc);
            try self.sync_state.write_at(self.blob, new_slot_offset, &staged, true);
            const published = Checksum.slot_len_bytes(new_len);
            try self.sync_state.write_at(self.blob, new_slot_offset, &published, true);
            // Zeroing the CRC alongside the length keeps a later torn rewrite from reassembling
            // the retired longer checksum over the pre-shrink bytes.
            const zeros = Checksum.slot_bytes(0, 0);
            try self.sync_state.write_at(self.blob, crc_start + old.slot.offset(), &zeros, true);
            return .{ .slot = new_slot, .len = new_len, .crc = new_crc };
        }

        /// Read exactly `buf.len` bytes at logical `offset`.
        pub fn read_into(self: *Self, buf: []u8, offset: u64) Error!void {
            const end = std.math.add(u64, offset, buf.len) catch return error.OffsetOverflow;
            if (end > self.size()) return error.BlobInsufficientLength;
            const prefix_len = self.copy_tail_overlap(buf, offset);
            if (prefix_len > 0) try self.read_blob(buf[0..prefix_len], offset);
        }

        /// Read up to `buf.len` bytes at `offset`, returning how many were available. Fails if
        /// none are.
        pub fn read_up_to(self: *Self, offset: u64, buf: []u8) Error!usize {
            if (offset >= self.size()) return error.BlobInsufficientLength;
            const len: usize = @intCast(@min(buf.len, self.size() - offset));
            try self.read_into(buf[0..len], offset);
            return len;
        }

        /// Read into `buf` only from the write buffer and page cache. Returns false (leaving
        /// `buf` unspecified) if any byte needs a blob read.
        pub fn try_read_sync_into(self: *Self, buf: []u8, offset: u64) bool {
            const end = std.math.add(u64, offset, buf.len) catch return false;
            if (end > self.size()) return false;
            const prefix_len = self.copy_tail_overlap(buf, offset);
            if (prefix_len == 0) return true;
            return self.cache_ref.read_cached(self.id, buf[0..prefix_len], offset) == prefix_len;
        }

        /// Copy the part of `[offset, offset + buf.len)` held in the write buffer; returns the
        /// length of the prefix below it.
        fn copy_tail_overlap(self: *const Self, buf: []u8, offset: u64) usize {
            const tail_start = @max(self.buffer.offset, offset);
            const end = offset + buf.len;
            if (tail_start >= end) return buf.len;
            const prefix_len: usize = @intCast(tail_start - offset);
            const from: usize = @intCast(tail_start - self.buffer.offset);
            @memcpy(buf[prefix_len..], self.buffer.bytes()[from..][0 .. buf.len - prefix_len]);
            return prefix_len;
        }

        /// Read full pages below the write buffer through the page cache.
        fn read_blob(self: *Self, buf: []u8, offset: u64) Error!void {
            const page_size_value = self.page_size();
            var done = self.cache_ref.read_cached(self.id, buf, offset);
            while (done < buf.len) {
                const page, const in_page = self.cache_ref.offset_to_page(offset + done);
                const logical, _ = try paged.read_page_with_checksum(
                    self.blob,
                    page,
                    page_size_value,
                    self.page_scratch,
                );
                // Pages below the tip are full; a shorter one fell back to a partial checksum.
                if (logical.len != page_size_value) return error.InvalidChecksum;
                assert(self.cache_ref.cache(self.id, logical, page * page_size_value) == 0);
                const count = @min(buf.len - done, page_size_value - in_page);
                @memcpy(buf[done..][0..count], logical[@intCast(in_page)..][0..count]);
                done += count;
                done += self.cache_ref.read_cached(self.id, buf[done..], offset + done);
            }
            assert(done == buf.len);
        }

        /// Flush buffered data, then return a `Replay` of the logical bytes reading
        /// `buffer_size` bytes of pages per blob read. The replay borrows the blob: it must not
        /// outlive this writer. Durability is not established.
        pub fn replay(self: *Self, buffer_size: usize) Error!Replay(Blob) {
            assert(!self.failed);
            errdefer self.failed = true;
            _ = try self.flush_internal(true, false);
            const batch_pages = @max(1, buffer_size / self.physical_page_size());
            return Replay(Blob).init(
                self.gpa,
                self.blob,
                self.page_size(),
                self.current_page,
                self.buffer.partial(),
                batch_pages,
            );
        }

        /// Length of the longest contiguous prefix of well-formed pages on the blob, at most
        /// `max_size`. Pages wholly below `proven` (a logical offset known valid) are accepted
        /// without reading. All appended bytes must have reached the blob.
        pub fn recoverable_prefix_len_at_most(self: *Self, proven: u64, max_size: u64) Error!u64 {
            const page_size_value: u64 = self.page_size();
            const pages = self.current_page + @intFromBool(self.partial_page_state != null);
            const total_pages = @min(pages, std.math.divCeil(u64, max_size, page_size_value) catch
                unreachable);
            const start_page = @min(proven / page_size_value, self.current_page, total_pages);
            var valid_len = start_page * page_size_value;
            var page = start_page;
            while (page < total_pages) : (page += 1) {
                const start, _ = try paged.physical_page(page, page_size_value);
                try self.blob.read_at(start, self.page_scratch);
                const checksum = Checksum.validate_page(self.page_scratch) orelse break;
                valid_len += checksum.len;
                // A valid partial page ends the contiguous prefix wherever it appears.
                if (checksum.len < page_size_value) break;
            }
            return @min(valid_len, max_size);
        }

        /// `recoverable_prefix_len_at_most` without a cap.
        pub fn recoverable_prefix_len(self: *Self, proven: u64) Error!u64 {
            return self.recoverable_prefix_len_at_most(proven, std.math.maxInt(u64));
        }
    };
}

/// Read the logical range `[offset, offset + buf.len)` directly from a raw paged blob,
/// validating every page it spans. Fails with `BlobInsufficientLength` when valid page
/// contents do not cover the range. `scratch` holds one physical page.
pub fn read_range(
    blob: anytype,
    logical_page_size: usize,
    offset: u64,
    buf: []u8,
    scratch: []u8,
) Error!void {
    assert(logical_page_size > 0);
    assert(scratch.len == logical_page_size + checksum_size);
    const end = std.math.add(u64, offset, buf.len) catch return error.OffsetOverflow;
    if (buf.len == 0) return;
    const first_page = offset / logical_page_size;
    const last_page = (end - 1) / logical_page_size;
    var done: usize = 0;
    var page = first_page;
    while (page <= last_page) : (page += 1) {
        const logical, _ =
            try paged.read_page_with_checksum(blob, page, logical_page_size, scratch);
        const page_start = page * logical_page_size;
        const overlap_start = @max(offset, page_start);
        const overlap_end = @min(end, page_start + logical.len);
        if (overlap_start >= overlap_end) return error.BlobInsufficientLength;
        const piece_start: usize = @intCast(overlap_start - page_start);
        const piece_end: usize = @intCast(overlap_end - page_start);
        const piece = logical[piece_start..piece_end];
        @memcpy(buf[done..][0..piece.len], piece);
        done += piece.len;
    }
    // A short terminal page can leave the range only partially covered.
    if (done != buf.len) return error.BlobInsufficientLength;
}

/// Read the last `buf.len` logical bytes of a raw paged blob of `physical_size` bytes (whole
/// physical pages only) and return its logical size. The last page decides the logical end.
pub fn read_tail(
    blob: anytype,
    physical_size: u64,
    logical_page_size: usize,
    buf: []u8,
    scratch: []u8,
) Error!u64 {
    assert(logical_page_size > 0);
    assert(scratch.len == logical_page_size + checksum_size);
    if (physical_size == 0) {
        if (buf.len == 0) return 0;
        return error.BlobInsufficientLength;
    }
    const physical = logical_page_size + checksum_size;
    if (physical_size % physical != 0) return error.BlobInsufficientLength;
    const page = physical_size / physical - 1;
    const tail, _ = try paged.read_page_with_checksum(blob, page, logical_page_size, scratch);
    const page_start = page * logical_page_size;
    const logical_size = page_start + tail.len;
    const offset = std.math.sub(u64, logical_size, buf.len) catch
        return error.BlobInsufficientLength;
    // Copy the validated suffix first: reading the prefix reuses `scratch`.
    const tail_start: usize = @intCast(@max(offset, page_start) - page_start);
    const suffix = tail[tail_start..];
    const prefix_len = buf.len - suffix.len;
    @memcpy(buf[prefix_len..], suffix);
    if (prefix_len > 0) {
        try read_range(blob, logical_page_size, offset, buf[0..prefix_len], scratch);
    }
    return logical_size;
}

/// Replays the logical bytes of a paged blob, validating every page.
///
/// Full pages are read from the blob in batches; the final partial page is a frozen copy taken
/// when the replay was created. `ensure(n)` fills until `n` bytes are available, `bytes()`
/// exposes them contiguously, and `advance` consumes them.
pub fn Replay(comptime Blob: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        blob: *Blob,
        page_size: usize,
        /// Full pages stored on the blob.
        full_pages: u64,
        /// The frozen final partial page.
        partial: []u8,
        /// Physical pages per blob read.
        batch_pages: usize,
        batch: []u8,
        /// Logical bytes read and not yet consumed start at `start`.
        data: std.ArrayList(u8),
        start: usize = 0,
        /// The next full page to read.
        next_page: u64 = 0,
        partial_done: bool = false,
        /// Bytes to skip at the start of the next page (after a seek).
        skip: usize = 0,
        exhausted: bool = false,

        fn init(
            gpa: Allocator,
            blob: *Blob,
            page_size: usize,
            full_pages: u64,
            partial: []const u8,
            batch_pages: usize,
        ) Allocator.Error!Self {
            assert(partial.len < page_size);
            assert(batch_pages > 0);
            const partial_copy = try gpa.dupe(u8, partial);
            errdefer gpa.free(partial_copy);
            const batch = try gpa.alloc(u8, batch_pages * (page_size + checksum_size));
            errdefer gpa.free(batch);
            var data: std.ArrayList(u8) = .empty;
            try data.ensureTotalCapacity(gpa, batch_pages * page_size + page_size);
            return .{
                .gpa = gpa,
                .blob = blob,
                .page_size = page_size,
                .full_pages = full_pages,
                .partial = partial_copy,
                .batch_pages = batch_pages,
                .batch = batch,
                .data = data,
            };
        }

        pub fn deinit(self: *Self) void {
            self.gpa.free(self.partial);
            self.gpa.free(self.batch);
            self.data.deinit(self.gpa);
            self.* = undefined;
        }

        /// The logical size of the blob.
        pub fn blob_size(self: *const Self) u64 {
            return self.full_pages * self.page_size + self.partial.len;
        }

        pub fn is_exhausted(self: *const Self) bool {
            return self.exhausted;
        }

        /// Bytes available without another read.
        pub fn remaining(self: *const Self) usize {
            return self.data.items.len - self.start;
        }

        /// The available bytes.
        pub fn bytes(self: *const Self) []const u8 {
            return self.data.items[self.start..];
        }

        pub fn advance(self: *Self, count: usize) void {
            assert(count <= self.remaining());
            self.start += count;
        }

        /// Fill until at least `n` bytes are available (true) or the blob is exhausted (false;
        /// fewer bytes may remain to process).
        pub fn ensure(self: *Self, n: usize) Error!bool {
            while (self.remaining() < n and !self.exhausted) try self.fill();
            return self.remaining() >= n;
        }

        fn fill(self: *Self) Error!void {
            // Compact consumed bytes.
            const kept = self.remaining();
            std.mem.copyForwards(u8, self.data.items[0..kept], self.data.items[self.start..]);
            self.data.items.len = kept;
            self.start = 0;

            if (self.next_page < self.full_pages) return self.fill_pages();
            if (!self.partial_done) {
                self.partial_done = true;
                if (self.skip < self.partial.len) {
                    try self.data.appendSlice(self.gpa, self.partial[self.skip..]);
                }
                self.skip = 0;
                return;
            }
            self.exhausted = true;
        }

        fn fill_pages(self: *Self) Error!void {
            const physical = self.page_size + checksum_size;
            const count: usize = @intCast(@min(self.batch_pages, self.full_pages - self.next_page));
            const batch = self.batch[0 .. count * physical];
            try self.blob.read_at(self.next_page * physical, batch);
            try self.data.ensureUnusedCapacity(self.gpa, count * self.page_size);
            for (0..count) |index| {
                const page = batch[index * physical ..][0..physical];
                // Every stored page must hold a full page: the partial page is frozen.
                const checksum = Checksum.validate_page(page) orelse return error.InvalidChecksum;
                if (checksum.len != self.page_size) return error.InvalidChecksum;
                self.data.appendSliceAssumeCapacity(page[self.skip..self.page_size]);
                self.skip = 0;
            }
            self.next_page += count;
        }

        /// Position the replay at logical `offset`.
        pub fn seek_to(self: *Self, offset: u64) Error!void {
            if (offset > self.blob_size()) return error.BlobInsufficientLength;
            self.data.clearRetainingCapacity();
            self.start = 0;
            self.exhausted = false;
            self.next_page = offset / self.page_size;
            self.skip = @intCast(offset % self.page_size);
            self.partial_done = false;
            assert(self.next_page <= self.full_pages);
        }
    };
}

test {
    _ = @import("writer_test.zig");
}
