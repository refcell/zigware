//! Storage interface: partitions of named blobs (commonware `Storage` and `Blob` traits in
//! `runtime/src/lib.rs`, and `runtime/src/storage/mod.rs`).
//!
//! `Storage` and `Blob` are small vtable interfaces, like `std.Io`, so storage structures take
//! a `Storage` value and run unchanged on the in-memory backend (deterministic runtime, with
//! fault injection) and on disk (production runtime).
//!
//! - `Storage.open(partition, name)` opens or creates a blob and returns it with its logical
//!   length (`Opened.len`). Only one handle per blob may be open at a time: a second open returns
//!   `error.BlobAlreadyOpen` until the first is closed or the blob is removed.
//! - `Storage.remove(partition, name)` removes one blob, or the whole partition when `name` is
//!   null. Open handles stay readable (they keep the removed contents).
//! - `Storage.scan(gpa, partition)` lists blob names, sorted.
//! - `Blob.read_at` fills a caller buffer with exactly `buffer.len` bytes at `offset`;
//!   `Blob.write_at` writes bytes (or chunks, `write_at_vectored`) at `offset`, extending the
//!   blob; `Blob.resize` truncates or zero-extends; `Blob.sync` makes every completed write and
//!   resize durable, and `Blob.start_sync` starts that and returns a `Completion` to observe
//!   it. `Blob.close` releases the handle and does not sync.
//!
//! Durability: after a crash, data not covered by a completed sync may be lost or torn; data
//! readable when a run starts is durable. Blob contents start after a runtime-owned header
//! (`storage/header.zig`, byte-identical to commonware) that records the layout and the
//! application's blob version.
//!
//! Zig errors carry no payload, so commonware's error details (partition, name, reason) are
//! not returned; the error names match commonware's variants.

const std = @import("std");
const assert = std.debug.assert;

pub const header = @import("storage/header.zig");
pub const memory = @import("storage/memory.zig");
pub const faulty = @import("storage/faulty.zig");
pub const audited = @import("storage/audited.zig");
pub const metered = @import("storage/metered.zig");
pub const mocks = @import("storage/mocks.zig");
pub const tests = @import("storage/tests.zig");
pub const Completion = @import("storage/completion.zig").Completion;
pub const PendingRead = @import("storage/pending_read.zig").PendingRead;

pub const Error = error{
    PartitionNameInvalid,
    PartitionCreationFailed,
    PartitionMissing,
    PartitionCorrupt,
    BlobAlreadyOpen,
    BlobOpenFailed,
    BlobMissing,
    BlobResizeFailed,
    BlobSyncFailed,
    BlobInsufficientLength,
    BlobCorrupt,
    BlobLayoutMismatch,
    BlobVersionMismatch,
    ReadFailed,
    WriteFailed,
    OffsetOverflow,
    Io,
    Canceled,
    OutOfMemory,
};

/// Runtime-owned layout of a blob: its header and data offset (commonware `BlobLayout`).
pub const BlobLayout = enum(u16) {
    /// An 8-byte header with data right after it. Deprecated upstream: unaligned pages.
    v0 = 0,
    /// A header padded to one 4096-byte page, so data begins page-aligned.
    v1 = 1,

    pub fn data_offset(layout: BlobLayout) u64 {
        return switch (layout) {
            .v0 => 8,
            .v1 => blob_page_size,
        };
    }
};

/// Layouts a runtime accepts, inclusive.
pub const LayoutRange = struct {
    min: BlobLayout,
    max: BlobLayout,

    pub const all: LayoutRange = .{ .min = .v0, .max = default_blob_layout };

    pub fn only(layout: BlobLayout) LayoutRange {
        return .{ .min = layout, .max = layout };
    }

    pub fn contains(range: LayoutRange, layout: BlobLayout) bool {
        assert(@backingInt(range.min) <= @backingInt(range.max));
        const value = @backingInt(layout);
        return value >= @backingInt(range.min) and value <= @backingInt(range.max);
    }
};

/// Latest layout, used to create new blobs.
pub const default_blob_layout: BlobLayout = .v1;

/// Size of a blob page, the unit storage reads and persists in.
pub const blob_page_size: u32 = 4096;

comptime {
    assert(std.math.isPowerOfTwo(blob_page_size));
    assert(default_blob_layout.data_offset() % blob_page_size == 0);
}

/// Application-owned version of a blob's contents (commonware `BlobVersion`).
pub const BlobVersion = u16;

/// Version used by `Storage.open`.
pub const default_blob_version: BlobVersion = 0;

/// Blob versions an application accepts, inclusive. Must be non-empty.
pub const VersionRange = struct {
    min: BlobVersion,
    max: BlobVersion,

    pub fn only(version: BlobVersion) VersionRange {
        return .{ .min = version, .max = version };
    }

    pub fn contains(range: VersionRange, version: BlobVersion) bool {
        assert(range.min <= range.max);
        return version >= range.min and version <= range.max;
    }
};

/// Options for one read (commonware `ReadOptions`).
pub const ReadOptions = packed struct(u8) {
    /// Hint: the data need not stay in the OS page cache.
    dont_cache: bool = false,
    _padding: u7 = 0,
};

/// Options for one write (commonware `WriteOptions`).
pub const WriteOptions = packed struct(u8) {
    /// Durably persist the written bytes before returning (not a barrier for earlier writes).
    sync: bool = false,
    /// Hint: the bytes need not stay in the OS page cache.
    dont_cache: bool = false,
    _padding: u6 = 0,
};

/// An open blob handle.
pub const Blob = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read_at: *const fn (ptr: *anyopaque, offset: u64, buffer: []u8, ReadOptions) Error!void,
        write_at: *const fn (
            ptr: *anyopaque,
            offset: u64,
            chunks: []const []const u8,
            options: WriteOptions,
        ) Error!void,
        resize: *const fn (ptr: *anyopaque, length: u64) Error!void,
        sync: *const fn (ptr: *anyopaque) Error!void,
        close: *const fn (ptr: *anyopaque) void,
        /// Null for backends whose `start_sync` is `sync` run inline (`Blob.start_sync`).
        start_sync: ?*const fn (ptr: *anyopaque) Error!Completion = null,
        /// Null for backends whose `start_read` is `read_at` run inline (`Blob.start_read`).
        start_read: ?*const fn (
            ptr: *anyopaque,
            offset: u64,
            buffer: []u8,
            options: ReadOptions,
        ) Error!PendingRead = null,
        /// The `Io` the blob's backend runs on, which readers sharing a page cache wait with;
        /// null for backends without one (`Blob.io`).
        io: ?*const fn (ptr: *anyopaque) ?std.Io = null,
    };

    /// The `Io` of the blob's backend, or null if it has none. Wrappers forward their inner
    /// blob's.
    pub fn io(blob: Blob) ?std.Io {
        const get = blob.vtable.io orelse return null;
        return get(blob.ptr);
    }

    /// Read exactly `buffer.len` bytes at `offset`; `error.BlobInsufficientLength` if the blob
    /// is shorter.
    pub fn read_at(blob: Blob, offset: u64, buffer: []u8) Error!void {
        return blob.vtable.read_at(blob.ptr, offset, buffer, .{});
    }

    pub fn read_at_options(blob: Blob, offset: u64, buffer: []u8, options: ReadOptions) Error!void {
        return blob.vtable.read_at(blob.ptr, offset, buffer, options);
    }

    pub fn write_at(blob: Blob, offset: u64, bytes: []const u8, options: WriteOptions) Error!void {
        return blob.vtable.write_at(blob.ptr, offset, &.{bytes}, options);
    }

    /// Write the chunks as one logical byte sequence at `offset`.
    pub fn write_at_vectored(
        blob: Blob,
        offset: u64,
        chunks: []const []const u8,
        options: WriteOptions,
    ) Error!void {
        return blob.vtable.write_at(blob.ptr, offset, chunks, options);
    }

    pub fn resize(blob: Blob, length: u64) Error!void {
        return blob.vtable.resize(blob.ptr, length);
    }

    pub fn sync(blob: Blob) Error!void {
        return blob.vtable.sync(blob.ptr);
    }

    /// Request that every write and resize completed before this call becomes durable
    /// (commonware `start_sync`). The writes covered are fixed at the call; the returned
    /// completion (one reference, owned by the caller) only observes, so releasing it without
    /// waiting cancels nothing. A sync failure is reported by the completion. Backends without
    /// a `start_sync` entry sync inline and return a ready completion, as commonware's memory
    /// backend does.
    pub fn start_sync(blob: Blob) Error!Completion {
        const start = blob.vtable.start_sync orelse {
            // A cancel the inline sync took is the caller's, not the completion's: returned
            // in a ready completion that is only polled or released, it would be lost, and the
            // task's next wait would never wake.
            blob.sync() catch |err| {
                if (err == error.Canceled) return error.Canceled;
                return .ready(err);
            };
            return .ok;
        };
        return start(blob.ptr);
    }

    /// Start reading exactly `buffer.len` bytes at `offset` (commonware `start_read_many` of one
    /// range). The read proceeds whether or not the result is waited for; `buffer` must stay
    /// alive until the returned handle is waited or abandoned. Backends without a `start_read`
    /// entry read inline and return a ready handle, so their callers see no concurrency.
    pub fn start_read(
        blob: Blob,
        offset: u64,
        buffer: []u8,
        options: ReadOptions,
    ) Error!PendingRead {
        const start = blob.vtable.start_read orelse {
            // As in `start_sync`, a cancel the inline read took is the caller's.
            blob.read_at_options(offset, buffer, options) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                return .ready(err);
            };
            return .ready({});
        };
        return start(blob.ptr, offset, buffer, options);
    }

    /// Whether `start_read` can overlap reads with the caller's work.
    pub fn reads_ahead(blob: Blob) bool {
        return blob.vtable.start_read != null;
    }

    /// Release the handle. Unsynced changes may be discarded; closing does not sync.
    pub fn close(blob: Blob) void {
        blob.vtable.close(blob.ptr);
    }
};

/// Result of opening a blob.
pub const Opened = struct {
    blob: Blob,
    /// Logical length in bytes (excluding the header).
    len: u64,
    version: BlobVersion,
};

/// Blob names of one partition, owned by the caller.
pub const Names = struct {
    items: [][]u8,

    pub fn deinit(names: Names, gpa: std.mem.Allocator) void {
        for (names.items) |name| gpa.free(name);
        gpa.free(names.items);
    }

    pub fn contains(names: Names, name: []const u8) bool {
        for (names.items) |item| {
            if (std.mem.eql(u8, item, name)) return true;
        }
        return false;
    }
};

pub const Storage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        open_versioned: *const fn (
            ptr: *anyopaque,
            partition: []const u8,
            name: []const u8,
            versions: VersionRange,
        ) Error!Opened,
        remove: *const fn (ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void,
        scan: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            partition: []const u8,
        ) Error!Names,
    };

    /// Open or create a blob with `default_blob_version` as the only accepted version.
    pub fn open(storage: Storage, partition: []const u8, name: []const u8) Error!Opened {
        return storage.vtable.open_versioned(storage.ptr, partition, name, .only(0));
    }

    /// Open or create a blob. A new blob gets `versions.max`; an existing blob whose version
    /// is outside `versions` returns `error.BlobVersionMismatch`.
    pub fn open_versioned(
        storage: Storage,
        partition: []const u8,
        name: []const u8,
        versions: VersionRange,
    ) Error!Opened {
        assert(versions.min <= versions.max);
        return storage.vtable.open_versioned(storage.ptr, partition, name, versions);
    }

    /// Remove a blob, or the whole partition when `name` is null.
    pub fn remove(storage: Storage, partition: []const u8, name: ?[]const u8) Error!void {
        return storage.vtable.remove(storage.ptr, partition, name);
    }

    /// Every blob name in `partition`, sorted. Free with `Names.deinit`.
    pub fn scan(storage: Storage, gpa: std.mem.Allocator, partition: []const u8) Error!Names {
        return storage.vtable.scan(storage.ptr, gpa, partition);
    }
};

/// Partition names are non-empty ASCII alphanumerics, `-`, and `_`.
pub fn validate_partition_name(partition: []const u8) Error!void {
    if (partition.len == 0) return error.PartitionNameInvalid;
    for (partition) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_')) {
            return error.PartitionNameInvalid;
        }
    }
}

test "partition name validation" {
    try validate_partition_name("abc-DEF_123");
    for ([_][]const u8{ "", "a/b", "a.b", "a b", "ä", "a\x00" }) |bad| {
        try std.testing.expectError(error.PartitionNameInvalid, validate_partition_name(bad));
    }
}

test "options are single bits" {
    try std.testing.expectEqual(@as(u8, 1), @as(u8, @bitCast(WriteOptions{ .sync = true })));
    try std.testing.expectEqual(@as(u8, 2), @as(u8, @bitCast(WriteOptions{ .dont_cache = true })));
    try std.testing.expectEqual(@as(u8, 1), @as(u8, @bitCast(ReadOptions{ .dont_cache = true })));
}

/// A blob whose `sync` waits until canceled, with no `start_sync` entry.
const CancelableSync = struct {
    const Ctx = @import("deterministic.zig").Context;
    const vtable: Blob.VTable = .{
        .read_at = unused_read,
        .write_at = unused_write,
        .resize = unused_resize,
        .sync = sync,
        .close = unused_close,
    };

    fn sync(ptr: *anyopaque) Error!void {
        const ctx: *const Ctx = @ptrCast(@alignCast(ptr));
        ctx.sleep(.fromSeconds(3600)) catch return error.Canceled;
        unreachable; // The test cancels the sync.
    }
    fn unused_read(_: *anyopaque, _: u64, _: []u8, _: ReadOptions) Error!void {
        unreachable;
    }
    fn unused_write(_: *anyopaque, _: u64, _: []const []const u8, _: WriteOptions) Error!void {
        unreachable;
    }
    fn unused_resize(_: *anyopaque, _: u64) Error!void {
        unreachable;
    }
    fn unused_close(_: *anyopaque) void {}

    /// Starts a sync that is canceled inside, then sleeps 5 s, which a swallowed cancel
    /// would let run to the end.
    fn task(ctx: Ctx, started: *std.Io.Event, outcome: *?anyerror) anyerror!void {
        const blob: Blob = .{ .ptr = @constCast(&ctx), .vtable = &vtable };
        started.set(ctx.io());
        const completion = blob.start_sync() catch |err| {
            outcome.* = err;
            return err;
        };
        completion.release();
        outcome.* = error.CancelSwallowed;
        try ctx.sleep(.fromSeconds(5));
    }

    fn body(ctx: Ctx) !void {
        var started: std.Io.Event = .unset;
        var outcome: ?anyerror = null;
        const handle = try ctx.child("sync").spawn(task, .{ &started, &outcome });
        try started.wait(ctx.io());
        try ctx.sleep(.fromMilliseconds(1));
        const before = ctx.current();
        if (handle.abort()) |_| {} else |_| {} // The task's own result is checked below.
        const elapsed = before.durationTo(ctx.current()).toNanoseconds();
        try std.testing.expectEqual(@as(?anyerror, error.Canceled), outcome);
        // Its next wait does not run out the 5 s sleep.
        try std.testing.expect(elapsed < std.time.ns_per_s);
    }
};

test "an inline start_sync canceled inside its sync returns error.Canceled" {
    const deterministic = @import("deterministic.zig");
    var runner = try deterministic.Runner.init(std.testing.allocator, .{});
    defer runner.deinit();
    try try runner.start_context(CancelableSync.body, .{});
}

test {
    _ = header;
    _ = memory;
    _ = faulty;
    _ = audited;
    _ = metered;
    _ = mocks;
    _ = @import("storage/completion.zig");
    _ = @import("storage/pending_read.zig");
    _ = @import("storage/memory_test.zig");
    _ = @import("storage/blob_creation_fuzz_test.zig");
}
