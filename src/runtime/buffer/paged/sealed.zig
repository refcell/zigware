//! Read-only counterpart to `Writer` (commonware's `buffer/paged/sealed.rs`): an immutable,
//! page-cache-backed read handle for a blob whose logical content will no longer change.
//!
//! `Writer.seal` consumes the writer, makes its bytes durable, and returns a `Sealed` that owns
//! the blob. `Writer.snapshot` and `Writer.try_snapshot` return a `Sealed` that borrows the
//! writer's blob and must not outlive it; it owns a frozen copy of the partial last page, so the
//! writer's later appends do not change what it reads. Full pages are read through the page
//! cache under the writer's id, which a seal preserves, so hot pages stay valid.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const paged = @import("mod.zig");
const storage_iface = @import("../../storage.zig");
const Blob = storage_iface.Blob;
const ReadOptions = storage_iface.ReadOptions;
const CacheRef = @import("cache.zig").CacheRef;
const view_mod = @import("view.zig");
const View = view_mod.View;
const Replay = @import("writer.zig").Replay;
const checksum_size: usize = paged.checksum_size;

pub const Error = paged.Error;
pub const Range = view_mod.Range;

pub const Sealed = struct {
    const Self = @This();

    gpa: Allocator,
    blob: Blob,
    /// Whether `deinit` closes the blob (a seal) or leaves it to its writer (a snapshot).
    owns_blob: bool,
    cache_ref: *CacheRef,
    /// The page-cache id, shared with the writer this came from.
    id: u64,
    /// The logical size of the sealed view.
    size: u64,
    /// Logical bytes of the partial last page: offsets `[size - partial.len, size)`.
    partial: []u8,

    /// Build a sealed view of `size` logical bytes whose last `partial.len` bytes are
    /// `partial` (copied). Called by `Writer.seal` and `Writer.snapshot`.
    pub fn init(
        gpa: Allocator,
        blob: Blob,
        owns_blob: bool,
        cache_ref: *CacheRef,
        id: u64,
        size: u64,
        partial: []const u8,
    ) Allocator.Error!Self {
        assert(partial.len < cache_ref.page_size);
        assert(partial.len <= size);
        assert((size - partial.len) % cache_ref.page_size == 0);
        const partial_copy = try gpa.dupe(u8, partial);
        return .{
            .gpa = gpa,
            .blob = blob,
            .owns_blob = owns_blob,
            .cache_ref = cache_ref,
            .id = id,
            .size = size,
            .partial = partial_copy,
        };
    }

    /// Free the frozen tail, closing the blob if this view owns it.
    pub fn deinit(self: *Self) void {
        if (self.owns_blob) self.blob.close();
        self.gpa.free(self.partial);
        self.* = undefined;
    }

    /// The page-cache id used for reads (preserved across `Writer.seal`).
    pub fn cache_id(self: *const Self) u64 {
        return self.id;
    }

    /// Full pages stored on the blob below the partial page.
    fn full_pages(self: *const Self) u64 {
        const full_len = self.size - self.partial.len;
        assert(full_len % self.cache_ref.page_size == 0);
        return full_len / self.cache_ref.page_size;
    }

    /// The read view over the full pages and the frozen partial page.
    pub fn view(self: *const Self) View {
        assert(self.partial.len <= self.size);
        return .{
            .blob = self.blob,
            .cache_ref = self.cache_ref,
            .id = self.id,
            .size = self.size,
            .tail_offset = self.size - self.partial.len,
            .tail = self.partial,
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

    /// Read up to `buf.len` bytes at `offset`, returning how many were available.
    pub fn read_up_to(self: *const Self, offset: u64, buf: []u8) Error!usize {
        return self.view().read_up_to(offset, buf);
    }

    /// Read into `buf` only from the page cache and the frozen partial page.
    pub fn try_read_sync_into(self: *const Self, buf: []u8, offset: u64) bool {
        return self.view().try_read_sync_into(buf, offset);
    }

    /// See `View.read_many_into`.
    pub fn read_many_into(
        self: *Self,
        buf: []u8,
        offsets: []const u64,
        item_size: usize,
    ) Error!usize {
        return self.view().read_many_into(buf, offsets, item_size);
    }

    /// See `View.read_ranges_into`.
    pub fn read_ranges_into(self: *const Self, buf: []u8, ranges: []const Range) Error!usize {
        return self.view().read_ranges_into(buf, ranges);
    }

    /// See `View.try_read_many_sync_into`.
    pub fn try_read_many_sync_into(
        self: *Self,
        buf: []u8,
        offsets: []const u64,
        item_size: usize,
        misses: []usize,
    ) usize {
        return self.view().try_read_many_sync_into(buf, offsets, item_size, misses);
    }

    /// See `View.try_read_ranges_sync_into`.
    pub fn try_read_ranges_sync_into(
        self: *Self,
        buf: []u8,
        ranges: []const Range,
        misses: []usize,
    ) usize {
        return self.view().try_read_ranges_sync_into(buf, ranges, misses);
    }

    /// A `Replay` of every logical byte, reading `buffer_size` bytes of pages per blob read.
    /// Full pages are validated as they are read; the partial page is the frozen copy. The
    /// replay borrows the blob: it must not outlive this view (or a snapshot's writer). Every
    /// blob read uses `read_options`, refills after a seek included.
    pub fn replay(
        self: *Self,
        buffer_size: usize,
        read_options: ReadOptions,
    ) Allocator.Error!Replay {
        const physical = self.cache_ref.page_size + checksum_size;
        const batch_pages = @max(1, buffer_size / physical);
        assert(batch_pages > 0);
        return Replay.init(
            self.gpa,
            self.blob,
            self.cache_ref.page_size,
            self.full_pages(),
            self.partial,
            batch_pages,
            read_options,
        );
    }
};

test {
    _ = @import("sealed_test.zig");
    _ = @import("panic_test.zig");
}
