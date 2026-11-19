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
const storage_iface = @import("../../storage.zig");
const Blob = storage_iface.Blob;
const Completion = storage_iface.Completion;
const PendingRead = storage_iface.PendingRead;
const ReadOptions = storage_iface.ReadOptions;
const SyncState = @import("../mod.zig").SyncState;
const Buffer = @import("tip.zig").Buffer;
const CacheRef = @import("cache.zig").CacheRef;
const view_mod = @import("view.zig");
const View = view_mod.View;
const Sealed = @import("sealed.zig").Sealed;
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

pub const Writer = struct {
    const Self = @This();

    gpa: Allocator,
    blob: Blob,
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
        blob: Blob,
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
        blob: Blob,
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
        self.sync_state.deinit();
        self.blob.close();
        self.buffer.deinit(self.gpa);
        self.gpa.free(self.scratch);
        self.gpa.free(self.page_scratch);
        self.* = undefined;
    }

    /// Scan backwards from the end of the blob to the last valid page.
    fn read_last_valid_page(
        blob: Blob,
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
        if (self.buffer.append(bytes)) _ = try self.flush_internal(false, false, .{});
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
            _ = try self.flush_internal(false, false, .{});
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
    fn flush_internal(
        self: *Self,
        write_partial_page: bool,
        durable: bool,
        options: storage_iface.WriteOptions,
    ) Error!bool {
        // Without flush work, return before observing a pending sync: an empty `start_sync`
        // must stay a cheap re-observation of the in-flight sync.
        if (!self.has_flush_work(write_partial_page)) return false;
        // A flush mutates the blob, so first resolve an outstanding `start_sync`. With no
        // unsynced mutation, the last flushed partial state is durable and becomes the
        // checksum the rewrite below must preserve.
        try self.sync_state.wait_for_pending();
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
        try self.sync_state.write_at_options(self.blob, write_offset, pages_out, durable, options);
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
        return self.sync_options(.{});
    }

    /// `sync` whose flush writes with `options`.
    fn sync_options(self: *Self, options: storage_iface.WriteOptions) Error!void {
        assert(!self.failed);
        errdefer self.failed = true;
        if (try self.flush_internal(true, true, options)) return;
        try self.sync_state.sync(self.blob);
        self.durable_page_state = self.partial_page_state;
    }

    /// Flush buffered bytes and start making every pending mutation durable, returning a
    /// completion (one reference, owned by the caller). Waiting on it gives `sync`'s guarantee
    /// for the state flushed by this call. Later `sync`s and blob mutations first wait for it;
    /// its failure is reported by the completion and by the next such call. Flush errors are
    /// returned directly. Buffered appends during the sync do no I/O and do not wait.
    pub fn start_sync(self: *Self) Error!Completion {
        assert(!self.failed);
        errdefer self.failed = true;
        _ = try self.flush_internal(true, false, .{});
        assert(!self.has_flush_work(true));
        return self.sync_state.start_sync(self.blob);
    }

    /// Wait for an outstanding `start_sync` (commonware `wait_for_sync`).
    pub fn wait_for_sync(self: *Self) Error!void {
        assert(!self.failed);
        errdefer self.failed = true;
        try self.sync_state.wait_for_pending();
        assert(self.sync_state != .pending);
    }

    /// A sealed view and the completion of the sync `seal` started.
    pub const Sealing = struct { sealed: Sealed, completion: Completion };

    /// Consume the writer: flush every byte and start syncing it, then return a `Sealed` view
    /// that owns the blob and keeps this writer's page-cache id, plus the sync's completion
    /// (one reference, owned by the caller). Reads through the view see the flushed bytes at
    /// once; they are durable once the completion succeeds. On error the writer is still owned
    /// by the caller (and only `deinit` may follow).
    pub fn seal(self: *Self) Error!Sealing {
        assert(self.phase == .append);
        assert(!self.failed);
        errdefer self.failed = true;
        // Complete earlier syncs before flushing the final bytes.
        try self.sync_state.wait_for_pending();
        // The sealed bytes are read back through the page cache, not the OS cache.
        _ = try self.flush_internal(true, false, .{ .dont_cache = true });
        assert(self.buffer.len < self.page_size());
        const completion = try self.sync_state.start_sync(self.blob);
        errdefer completion.release();
        const sealed = try self.sealed_handle(true);
        self.sync_state.deinit();
        self.buffer.deinit(self.gpa);
        self.gpa.free(self.scratch);
        self.gpa.free(self.page_scratch);
        self.* = undefined;
        return .{ .sealed = sealed, .completion = completion };
    }

    /// Write complete pages, then return an immutable `Sealed` view of the logical bytes. It
    /// borrows the blob (it must not outlive this writer) and owns a copy of the partial
    /// page, so later appends do not change what it reads. Durability is not established.
    pub fn snapshot(self: *Self) Error!Sealed {
        assert(!self.failed);
        errdefer self.failed = true;
        _ = try self.flush_internal(false, false, .{});
        return self.sealed_handle(false);
    }

    /// `snapshot` without its flush: null while the write buffer holds a full page that has
    /// not been written.
    pub fn try_snapshot(self: *Self) Allocator.Error!?Sealed {
        assert(!self.failed);
        if (self.has_flush_work(false)) return null;
        return try self.sealed_handle(false);
    }

    fn sealed_handle(self: *Self, owns_blob: bool) Allocator.Error!Sealed {
        assert(self.current_page * self.page_size() == self.buffer.offset);
        assert(self.buffer.len < self.page_size());
        return Sealed.init(
            self.gpa,
            self.blob,
            owns_blob,
            self.cache_ref,
            self.id,
            self.size(),
            self.buffer.partial(),
        );
    }

    /// This writer's page-cache id (kept by `seal`).
    pub fn cache_id(self: *const Self) u64 {
        return self.id;
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
        // The retained prefix moves into the in-memory tip, so its read skips the OS cache.
        const page_data, const old = try paged.read_page_with_checksum(
            self.blob,
            full_pages,
            self.page_size(),
            self.page_scratch,
            .{ .dont_cache = true },
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

    /// The read view over the flushed pages and the write buffer.
    pub fn view(self: *const Self) View {
        assert(self.buffer.size() >= self.buffer.offset);
        assert(self.buffer.offset == self.current_page * self.page_size());
        return .{
            .blob = self.blob,
            .cache_ref = self.cache_ref,
            .id = self.id,
            .size = self.size(),
            .tail_offset = self.buffer.offset,
            .tail = self.buffer.bytes(),
        };
    }

    /// Read exactly `buf.len` bytes at logical `offset`.
    pub fn read_into(self: *const Self, buf: []u8, offset: u64) Error!void {
        return self.view().read_into(buf, offset);
    }

    /// Read exactly `buf.len` bytes at logical `offset` (the `Blob.read_at` argument order).
    pub fn read_at(self: *const Self, offset: u64, buf: []u8) Error!void {
        return self.view().read_into(buf, offset);
    }

    /// Read up to `buf.len` bytes at `offset`, returning how many were available. Fails if
    /// none are.
    pub fn read_up_to(self: *const Self, offset: u64, buf: []u8) Error!usize {
        return self.view().read_up_to(offset, buf);
    }

    /// Read into `buf` only from the write buffer and page cache. Returns false (leaving
    /// `buf` unspecified) if any byte needs a blob read.
    pub fn try_read_sync_into(self: *const Self, buf: []u8, offset: u64) bool {
        return self.view().try_read_sync_into(buf, offset);
    }

    pub const Range = view_mod.Range;

    /// Read `ranges` into consecutive slots of `buf`. Returns how many were served from the
    /// write buffer and page cache without a blob read (empty ranges count as served).
    pub fn read_ranges_into(self: *const Self, buf: []u8, ranges: []const Range) Error!usize {
        return self.view().read_ranges_into(buf, ranges);
    }

    /// Read `item_size`-byte items at sorted `offsets` into consecutive slots of `buf`.
    /// Returns how many were served without a blob read.
    pub fn read_many_into(
        self: *Self,
        buf: []u8,
        offsets: []const u64,
        item_size: usize,
    ) Error!usize {
        return self.view().read_many_into(buf, offsets, item_size);
    }

    /// Cache-only `read_ranges_into` (see `View.try_read_ranges_sync_into`).
    pub fn try_read_ranges_sync_into(
        self: *Self,
        buf: []u8,
        ranges: []const Range,
        misses: []usize,
    ) usize {
        return self.view().try_read_ranges_sync_into(buf, ranges, misses);
    }

    /// Flush buffered data, then return a `Replay` of the logical bytes reading
    /// `buffer_size` bytes of pages per blob read. The replay borrows the blob: it must not
    /// outlive this writer. Durability is not established.
    /// Every blob read of the replay, refills after a seek included, uses `read_options`.
    pub fn replay(self: *Self, buffer_size: usize, read_options: ReadOptions) Error!Replay {
        assert(!self.failed);
        errdefer self.failed = true;
        _ = try self.flush_internal(true, false, .{});
        const batch_pages = @max(1, buffer_size / self.physical_page_size());
        return Replay.init(
            self.gpa,
            self.blob,
            self.page_size(),
            self.current_page,
            self.buffer.partial(),
            batch_pages,
            read_options,
        );
    }

    /// A `Replay` of the current logical bytes that writes nothing, as commonware's replay
    /// through a reader view: the flushed full pages are read from the blob and the buffered
    /// tail is a frozen copy. The replay borrows the blob: it must not outlive this writer.
    pub fn view_replay(
        self: *Self,
        buffer_size: usize,
        read_options: ReadOptions,
    ) Allocator.Error!Replay {
        assert(!self.failed);
        assert(self.current_page * self.page_size() == self.buffer.offset);
        const batch_pages = @max(1, buffer_size / self.physical_page_size());
        return Replay.init(
            self.gpa,
            self.blob,
            self.page_size(),
            self.current_page,
            self.buffer.data[0..self.buffer.len],
            batch_pages,
            read_options,
        );
    }

    /// Length of the longest contiguous prefix of well-formed pages on the blob, at most
    /// `max_size`, read one page at a time (`recoverable_prefix_len_scan` with a one-page
    /// budget).
    pub fn recoverable_prefix_len_at_most(self: *Self, proven: u64, max_size: u64) Error!u64 {
        return self.recoverable_prefix_len_scan(proven, max_size, 1, .{});
    }

    /// `recoverable_prefix_len_at_most` without a cap.
    pub fn recoverable_prefix_len(self: *Self, proven: u64) Error!u64 {
        return self.recoverable_prefix_len_at_most(proven, std.math.maxInt(u64));
    }

    /// Length of the longest contiguous prefix of well-formed pages on the blob, at most
    /// `max_size` (commonware `recoverable_prefix_len_at_most`). Scans forward, stopping at the
    /// first invalid or short page. Pages wholly below `proven` (a logical offset known valid)
    /// are accepted without reading. Each blob read covers at most `buffer_size` bytes of whole
    /// physical pages, and at least one page. All appended bytes must have reached the blob.
    pub fn recoverable_prefix_len_scan(
        self: *Self,
        proven: u64,
        max_size: u64,
        buffer_size: usize,
        read_options: ReadOptions,
    ) Error!u64 {
        assert(buffer_size > 0);
        const page_size_value: u64 = self.page_size();
        const physical: usize = self.page_scratch.len;
        const pages = self.current_page + @intFromBool(self.partial_page_state != null);
        const total_pages = @min(pages, std.math.divCeil(u64, max_size, page_size_value) catch
            unreachable);
        const start_page = @min(proven / page_size_value, self.current_page, total_pages);
        var valid_len = start_page * page_size_value;
        if (start_page == total_pages) return @min(valid_len, max_size);
        const batch_max: u64 = @min(@max(buffer_size / physical, 1), total_pages - start_page);
        const batch_buffer = if (batch_max == 1)
            self.page_scratch
        else
            try self.gpa.alloc(u8, @intCast(batch_max * physical));
        defer if (batch_max > 1) self.gpa.free(batch_buffer);
        var page = start_page;
        while (page < total_pages) {
            const batch: usize = @intCast(@min(batch_max, total_pages - page));
            const start, _ = try paged.physical_page(page, page_size_value);
            const bytes = batch_buffer[0 .. batch * physical];
            try self.blob.read_at_options(start, bytes, read_options);
            for (0..batch) |index| {
                const page_bytes = bytes[index * physical ..][0..physical];
                const checksum = Checksum.validate_page(page_bytes) orelse
                    return @min(valid_len, max_size);
                valid_len += checksum.len;
                // A valid partial page ends the contiguous prefix wherever it appears.
                if (checksum.len < page_size_value) return @min(valid_len, max_size);
            }
            page += batch;
        }
        assert(page == total_pages);
        return @min(valid_len, max_size);
    }
};

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
            try paged.read_page_with_checksum(blob, page, logical_page_size, scratch, .{});
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
    const tail, _ = try paged.read_page_with_checksum(blob, page, logical_page_size, scratch, .{});
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
/// Full pages are read from the blob in batches; the bytes after them (the final partial page,
/// or every buffered byte of a view replay) are a frozen copy taken when the replay was
/// created. `ensure(n)` fills until `n` bytes are available, `bytes()`
/// exposes them contiguously, and `advance` consumes them.
pub const Replay = struct {
    const Self = @This();

    gpa: Allocator,
    blob: Blob,
    page_size: usize,
    /// Full pages stored on the blob.
    full_pages: u64,
    /// The frozen bytes after the full pages.
    partial: []u8,
    /// Physical pages per blob read.
    batch_pages: usize,
    /// The options of every blob read.
    read_options: ReadOptions,
    /// `slot_count` buffers of `batch_pages` physical pages: one being validated and the rest
    /// for reads in flight.
    batch: []u8,
    /// 1 when the blob reads inline; `read_ahead_max + 1` when it starts reads ahead.
    slot_count: u8,
    /// Bit `i` set: slot `i` holds no batch.
    free_slots: u8,
    /// Batches read ahead of `next_page`, contiguous and in page order, oldest first.
    inflight: [read_ahead_max]Inflight = undefined,
    inflight_len: u8 = 0,
    /// Logical bytes read and not yet consumed start at `start`.
    data: std.ArrayList(u8),
    start: usize = 0,
    /// The next full page to read.
    next_page: u64 = 0,
    partial_done: bool = false,
    /// Bytes to skip at the start of the next page (after a seek).
    skip: usize = 0,
    exhausted: bool = false,

    /// Batches kept in flight ahead of the one being validated (commonware `MAX_READ_AHEAD`),
    /// on blobs that start reads ahead. One request at a time leaves the device idle for a
    /// request latency at every batch boundary; the replay buffer is split among them.
    pub const read_ahead_max = 3;

    /// A batch started ahead of the decoder.
    const Inflight = struct { first_page: u64, pages: usize, slot: u8, read: PendingRead };

    /// A batch whose bytes have landed in its slot.
    const Landed = struct { pages: usize, slot: u8 };

    /// `batch_pages` physical pages per blob read, or that split among the batches in flight
    /// (rounded up) when the blob starts reads ahead (commonware's `PageReader`).
    pub fn init(
        gpa: Allocator,
        blob: Blob,
        page_size: usize,
        full_pages: u64,
        partial: []const u8,
        batch_pages: usize,
        read_options: ReadOptions,
    ) Allocator.Error!Self {
        assert(page_size > 0);
        assert(batch_pages > 0);
        const slot_count: u8 = if (blob.reads_ahead()) read_ahead_max + 1 else 1;
        // A read never spans more than the stored pages (`pages_at`), so capping the batch
        // there leaves every read unchanged and sizes the buffers to the blob, not the
        // requested buffer: commonware allocates per read, sized to what it reads.
        const stored_pages: usize = @intCast(@max(1, full_pages));
        const read_pages = @min(
            std.math.divCeil(usize, batch_pages, slot_count) catch unreachable,
            stored_pages,
        );
        assert(read_pages > 0);
        const partial_copy = try gpa.dupe(u8, partial);
        errdefer gpa.free(partial_copy);
        const batch = try gpa.alloc(u8, slot_count * read_pages * (page_size + checksum_size));
        errdefer gpa.free(batch);
        var data: std.ArrayList(u8) = .empty;
        try data.ensureTotalCapacity(gpa, read_pages * page_size + page_size);
        comptime assert(read_ahead_max + 1 <= 8); // `free_slots` is one bit per slot.
        return .{
            .gpa = gpa,
            .blob = blob,
            .page_size = page_size,
            .full_pages = full_pages,
            .partial = partial_copy,
            .batch_pages = read_pages,
            .read_options = read_options,
            .batch = batch,
            .slot_count = slot_count,
            .free_slots = @intCast((@as(u16, 1) << @intCast(slot_count)) - 1),
            .data = data,
        };
    }

    pub fn deinit(self: *Self) void {
        self.abandon_inflight();
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
        const landed = try self.take_batch();
        defer self.free_slot(landed.slot);
        const batch = self.slot_bytes(landed.slot)[0 .. landed.pages * physical];
        try self.data.ensureUnusedCapacity(self.gpa, landed.pages * self.page_size);
        for (0..landed.pages) |index| {
            const page = batch[index * physical ..][0..physical];
            // Every stored page must hold a full page: the partial page is frozen.
            const checksum = Checksum.validate_page(page) orelse return error.InvalidChecksum;
            if (checksum.len != self.page_size) return error.InvalidChecksum;
            self.data.appendSliceAssumeCapacity(page[self.skip..self.page_size]);
            self.skip = 0;
        }
        // The position advances only past validated pages, so a corrupt page fails every
        // fill that reaches it.
        self.next_page += landed.pages;
    }

    /// The batch at `next_page`: the one read ahead for it when it landed, else a read on
    /// demand. Either way the batches after it are started first, so the device works while
    /// the caller validates and decodes (commonware `read_batch`).
    fn take_batch(self: *Self) Error!Landed {
        assert(self.next_page < self.full_pages);
        if (self.inflight_len > 0 and self.inflight[0].first_page == self.next_page) {
            var front = self.pop_front();
            self.top_up(front.first_page + front.pages);
            // A failed read ahead (perhaps abandoned by whoever started it) is read again
            // on demand below.
            if (front.read.wait()) {
                return .{ .pages = front.pages, .slot = front.slot };
            } else |_| self.free_slot(front.slot);
        }
        self.abandon_inflight();
        const pages = self.pages_at(self.next_page);
        const slot = self.claim_slot();
        errdefer self.free_slot(slot);
        self.top_up(self.next_page + pages);
        errdefer self.abandon_inflight();
        // Inline, so the caller's own cancel and errors surface here.
        const physical = self.page_size + checksum_size;
        const offset = self.next_page * physical;
        const target = self.slot_bytes(slot)[0 .. pages * physical];
        try self.blob.read_at_options(offset, target, self.read_options);
        return .{ .pages = pages, .slot = slot };
    }

    /// Starts batches after the queued ones, or after `consumed_end` when none is queued,
    /// until `read_ahead_max` are in flight or the stored pages end. A batch that cannot
    /// start stops the top-up: the decoder reads it on demand when it gets there.
    fn top_up(self: *Self, consumed_end: u64) void {
        if (self.slot_count == 1) return;
        var next = if (self.inflight_len > 0) blk: {
            const back = self.inflight[self.inflight_len - 1];
            break :blk back.first_page + back.pages;
        } else consumed_end;
        // Bounded: one batch per pass, at most `read_ahead_max`.
        while (self.inflight_len < read_ahead_max and next < self.full_pages) {
            const pages = self.pages_at(next);
            const slot = self.claim_slot();
            const physical = self.page_size + checksum_size;
            const target = self.slot_bytes(slot)[0 .. pages * physical];
            const read = self.blob.start_read(next * physical, target, self.read_options) catch {
                // A cancel taken here is the caller's; the demand read will see it again.
                self.free_slot(slot);
                return;
            };
            self.inflight[self.inflight_len] = .{
                .first_page = next,
                .pages = pages,
                .slot = slot,
                .read = read,
            };
            self.inflight_len += 1;
            next += pages;
        }
        assert(self.inflight_len <= read_ahead_max);
    }

    /// Physical pages of the batch starting at stored page `first`.
    fn pages_at(self: *const Self, first: u64) usize {
        assert(first < self.full_pages);
        return @intCast(@min(self.batch_pages, self.full_pages - first));
    }

    fn pop_front(self: *Self) Inflight {
        assert(self.inflight_len > 0);
        const front = self.inflight[0];
        std.mem.copyForwards(
            Inflight,
            self.inflight[0 .. self.inflight_len - 1],
            self.inflight[1..self.inflight_len],
        );
        self.inflight_len -= 1;
        return front;
    }

    /// Discards every batch read ahead, waiting until none touches its slot.
    fn abandon_inflight(self: *Self) void {
        for (self.inflight[0..self.inflight_len]) |*entry| {
            entry.read.abandon();
            self.free_slot(entry.slot);
        }
        self.inflight_len = 0;
    }

    fn claim_slot(self: *Self) u8 {
        assert(self.free_slots != 0);
        const slot: u8 = @ctz(self.free_slots);
        assert(slot < self.slot_count);
        self.free_slots &= ~(@as(u8, 1) << @intCast(slot));
        return slot;
    }

    fn free_slot(self: *Self, slot: u8) void {
        const bit = @as(u8, 1) << @intCast(slot);
        assert(slot < self.slot_count and self.free_slots & bit == 0);
        self.free_slots |= bit;
    }

    fn slot_bytes(self: *const Self, slot: u8) []u8 {
        const len = self.batch_pages * (self.page_size + checksum_size);
        assert(slot < self.slot_count);
        return self.batch[slot * len ..][0..len];
    }

    /// Position the replay at logical `offset`.
    pub fn seek_to(self: *Self, offset: u64) Error!void {
        if (offset > self.blob_size()) return error.BlobInsufficientLength;
        self.abandon_inflight();
        self.data.clearRetainingCapacity();
        self.start = 0;
        self.exhausted = false;
        self.next_page = @min(offset / self.page_size, self.full_pages);
        self.skip = @intCast(offset - self.next_page * self.page_size);
        self.partial_done = false;
        assert(self.next_page <= self.full_pages);
        assert(self.next_page == self.full_pages or self.skip < self.page_size);
    }
};

test {
    _ = @import("writer_test.zig");
    _ = @import("read_ahead_test.zig");
    _ = @import("delayed_read_test.zig");
    _ = @import("integrity_fuzz_test.zig");
}
