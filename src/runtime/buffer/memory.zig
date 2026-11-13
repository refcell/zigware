//! In-memory `Storage` and `Blob`: a stand-in for the runtime's storage until it lands.
//!
//! Mirrors commonware's `runtime/src/storage/memory` with the same method names (`open`,
//! `remove`, `scan`; `read_at`, `write_at`, `resize`, `sync`), so switching journal, metadata,
//! and queue to `runtime`'s storage is mechanical. Like commonware's, a blob handle holds live
//! contents and `sync` publishes them: dropping a handle (`deinit`) without syncing loses its
//! unsynced writes, which is how tests simulate a crash. Only one handle per blob may be
//! open; removing a blob unlinks it, and its open handle stays readable but can no longer sync.
//!
//! `write_bytes` and `writes` count every `write_at`, standing in for the runtime's
//! `runtime_storage_write_bytes_total` metric, `reads` counts every `read_at` (commonware's
//! `RecordingContext`), and `remove_failures_after` injects a removal fault after that many
//! successful removals. `mutations_allowed` is commonware's `MutationFaults`: once set, that
//! many more mutations (blob creation, `remove`, `write_at`, `resize`, `sync`) succeed and every
//! later one fails with `Io`, recording `mutation_refused`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Size of one blob page (commonware's `BLOB_PAGE_SIZE`).
pub const blob_page_size: u32 = 4096;

/// Subset of commonware's `runtime::Error` raised by storage.
pub const Error = memory_error;
const memory_error = error{
    PartitionNameInvalid,
    PartitionMissing,
    BlobMissing,
    BlobAlreadyOpen,
    BlobInsufficientLength,
    OffsetOverflow,
    /// An injected I/O failure.
    Io,
    OutOfMemory,
};

/// Published contents of one blob.
const Durable = struct {
    bytes: std.ArrayList(u8) = .empty,
    /// Distinguishes a re-created blob from one removed while a handle was open.
    generation: u64,
    open: bool = false,
};

const Partition = std.StringArrayHashMapUnmanaged(Durable);

/// Partition names hold only ASCII alphanumerics, `-`, and `_`, and are non-empty.
pub fn validate_partition_name(partition: []const u8) Error!void {
    if (partition.len == 0) return error.PartitionNameInvalid;
    for (partition) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-')) {
            return error.PartitionNameInvalid;
        }
    }
}

pub const Storage = struct {
    gpa: Allocator,
    partitions: std.StringArrayHashMapUnmanaged(Partition) = .empty,
    generation_next: u64 = 0,
    /// Bytes passed to `write_at` across all blobs.
    write_bytes: u64 = 0,
    /// Calls to `write_at` across all blobs.
    writes: u64 = 0,
    /// When set, removals fail with `Io` once this many more have succeeded.
    remove_failures_after: ?u32 = null,
    /// Calls to `read_at` across all blobs.
    reads: u64 = 0,
    /// When set, mutations fail with `Io` once this many more have succeeded.
    mutations_allowed: ?u64 = null,
    /// Whether a mutation failed since `mutations_allowed` was last set.
    mutation_refused: bool = false,

    pub const Error = memory_error;
    pub const Blob = MemoryBlob;
    pub const Opened = struct { blob: *Blob, len: u64 };

    pub fn init(gpa: Allocator) Storage {
        return .{ .gpa = gpa };
    }

    /// Let `operations` more mutations succeed, then fail every later one.
    pub fn allow_mutations(self: *Storage, operations: u64) void {
        self.mutations_allowed = operations;
        self.mutation_refused = false;
    }

    /// Charge one mutation against `mutations_allowed`.
    fn check_mutation(self: *Storage) memory_error!void {
        const allowed = &(self.mutations_allowed orelse return);
        if (allowed.* == 0) {
            self.mutation_refused = true;
            return error.Io;
        }
        allowed.* -= 1;
    }

    /// Frees every blob. Every handle must be closed first.
    pub fn deinit(self: *Storage) void {
        for (self.partitions.keys(), self.partitions.values()) |name, *partition| {
            free_partition(self.gpa, partition);
            self.gpa.free(name);
        }
        self.partitions.deinit(self.gpa);
        self.* = undefined;
    }

    fn free_partition(gpa: Allocator, partition: *Partition) void {
        for (partition.keys(), partition.values()) |name, *durable| {
            assert(!durable.open);
            durable.bytes.deinit(gpa);
            gpa.free(name);
        }
        partition.deinit(gpa);
    }

    /// Open the blob `name` in `partition`, creating it empty if missing; returns the handle
    /// and the blob's length.
    pub fn open(self: *Storage, partition: []const u8, name: []const u8) memory_error!Opened {
        try validate_partition_name(partition);
        const gpa = self.gpa;
        const partition_entry = try self.partitions.getOrPut(gpa, partition);
        if (!partition_entry.found_existing) {
            partition_entry.key_ptr.* = gpa.dupe(u8, partition) catch |err| {
                self.partitions.swapRemoveAt(partition_entry.index);
                return err;
            };
            partition_entry.value_ptr.* = .empty;
        }
        const blobs = partition_entry.value_ptr;
        // Opening a blob that is not stored creates it. Creation is a mutation.
        if (!blobs.contains(name)) {
            self.check_mutation() catch |err| {
                if (blobs.count() == 0 and !partition_entry.found_existing) {
                    self.gpa.free(partition_entry.key_ptr.*);
                    self.partitions.swapRemoveAt(partition_entry.index);
                }
                return err;
            };
        }
        const blob_entry = try blobs.getOrPut(gpa, name);
        if (!blob_entry.found_existing) {
            blob_entry.key_ptr.* = gpa.dupe(u8, name) catch |err| {
                blobs.swapRemoveAt(blob_entry.index);
                return err;
            };
            blob_entry.value_ptr.* = .{ .generation = self.generation_next };
            self.generation_next += 1;
        }
        const durable = blob_entry.value_ptr;
        if (durable.open) return error.BlobAlreadyOpen;

        const blob = try gpa.create(Blob);
        errdefer gpa.destroy(blob);
        blob.* = .{ .storage = self, .generation = durable.generation };
        try blob.live.appendSlice(gpa, durable.bytes.items);
        durable.open = true;
        assert(blob.live.items.len == durable.bytes.items.len);
        return .{ .blob = blob, .len = blob.live.items.len };
    }

    /// Remove the blob `name` from `partition`, or the whole partition if `name` is null.
    pub fn remove(self: *Storage, partition: []const u8, name: ?[]const u8) memory_error!void {
        try validate_partition_name(partition);
        try self.check_mutation();
        if (self.remove_failures_after) |*budget| {
            if (budget.* == 0) return error.Io;
            budget.* -= 1;
        }
        const index = self.partitions.getIndex(partition) orelse return error.PartitionMissing;
        const blobs = &self.partitions.values()[index];
        if (name) |blob_name| {
            const blob_index = blobs.getIndex(blob_name) orelse return error.BlobMissing;
            const key = blobs.keys()[blob_index];
            blobs.values()[blob_index].bytes.deinit(self.gpa);
            blobs.orderedRemoveAt(blob_index);
            self.gpa.free(key);
            assert(blobs.getIndex(blob_name) == null);
            return;
        }
        const key = self.partitions.keys()[index];
        for (blobs.keys(), blobs.values()) |blob_name, *durable| {
            durable.bytes.deinit(self.gpa);
            self.gpa.free(blob_name);
        }
        blobs.deinit(self.gpa);
        self.partitions.orderedRemoveAt(index);
        self.gpa.free(key);
    }

    /// The names of every blob in `partition`, sorted. The caller frees the list and names.
    pub fn scan(self: *Storage, gpa: Allocator, partition: []const u8) memory_error![][]u8 {
        try validate_partition_name(partition);
        const blobs = self.partitions.getPtr(partition) orelse return error.PartitionMissing;
        const names = try gpa.alloc([]u8, blobs.count());
        var filled: usize = 0;
        errdefer {
            for (names[0..filled]) |name| gpa.free(name);
            gpa.free(names);
        }
        for (blobs.keys()) |name| {
            names[filled] = try gpa.dupe(u8, name);
            filled += 1;
        }
        std.mem.sortUnstable([]u8, names, {}, less_than_bytes);
        return names;
    }

    fn less_than_bytes(_: void, a: []u8, b: []u8) bool {
        return std.mem.order(u8, a, b) == .lt;
    }
};

/// An open handle to one blob.
pub const MemoryBlob = struct {
    storage: *Storage,
    /// Identifies the published blob; generations are never reused, so a removed blob's
    /// handle finds nothing.
    generation: u64,
    live: std.ArrayList(u8) = .empty,

    /// Close the handle, dropping unsynced writes.
    pub fn deinit(self: *MemoryBlob) void {
        const storage = self.storage;
        if (self.durable_lookup()) |durable| {
            assert(durable.open);
            durable.open = false;
        }
        self.live.deinit(storage.gpa);
        storage.gpa.destroy(self);
    }

    /// The published blob this handle refers to, if it still exists.
    fn durable_lookup(self: *MemoryBlob) ?*Durable {
        for (self.storage.partitions.values()) |*blobs| {
            for (blobs.values()) |*durable| {
                if (durable.generation == self.generation) return durable;
            }
        }
        return null;
    }

    /// Read exactly `buf.len` bytes at `offset`.
    pub fn read_at(self: *MemoryBlob, offset: u64, buf: []u8) Error!void {
        const end = std.math.add(u64, offset, buf.len) catch return error.OffsetOverflow;
        if (end > self.live.items.len) return error.BlobInsufficientLength;
        @memcpy(buf, self.live.items[@intCast(offset)..@intCast(end)]);
        self.storage.reads += 1;
    }

    /// Write `bytes` at `offset`, zero-filling any gap past the current end.
    pub fn write_at(self: *MemoryBlob, offset: u64, bytes: []const u8) Error!void {
        const end = std.math.add(u64, offset, bytes.len) catch return error.OffsetOverflow;
        const end_index = std.math.cast(usize, end) orelse return error.OffsetOverflow;
        try self.storage.check_mutation();
        if (end_index > self.live.items.len) {
            const old_len = self.live.items.len;
            try self.live.resize(self.storage.gpa, end_index);
            @memset(self.live.items[old_len..], 0);
        }
        @memcpy(self.live.items[@intCast(offset)..end_index], bytes);
        self.storage.write_bytes += bytes.len;
        self.storage.writes += 1;
        assert(self.live.items.len >= end_index);
    }

    /// Set the blob's length, truncating or zero-extending.
    pub fn resize(self: *MemoryBlob, len: u64) Error!void {
        const len_index = std.math.cast(usize, len) orelse return error.OffsetOverflow;
        try self.storage.check_mutation();
        const old_len = self.live.items.len;
        try self.live.resize(self.storage.gpa, len_index);
        if (len_index > old_len) @memset(self.live.items[old_len..], 0);
        assert(self.live.items.len == len_index);
    }

    /// Publish the live contents, so they survive closing the handle.
    pub fn sync(self: *MemoryBlob) Error!void {
        try self.storage.check_mutation();
        const durable = self.durable_lookup() orelse return error.BlobMissing;
        durable.bytes.clearRetainingCapacity();
        try durable.bytes.appendSlice(self.storage.gpa, self.live.items);
        assert(durable.bytes.items.len == self.live.items.len);
    }

    /// The blob's current (live) length.
    pub fn size(self: *const MemoryBlob) u64 {
        return self.live.items.len;
    }
};

const testing = std.testing;

test "unsynced writes are lost when the handle closes" {
    var storage = Storage.init(testing.allocator);
    defer storage.deinit();
    const first = try storage.open("partition", "blob");
    try testing.expectEqual(@as(u64, 0), first.len);
    try first.blob.write_at(0, "durable");
    try first.blob.sync();
    try first.blob.write_at(7, "lost");
    try testing.expectError(error.BlobAlreadyOpen, storage.open("partition", "blob"));
    first.blob.deinit();

    const second = try storage.open("partition", "blob");
    defer second.blob.deinit();
    try testing.expectEqual(@as(u64, 7), second.len);
    var buf: [7]u8 = undefined;
    try second.blob.read_at(0, &buf);
    try testing.expectEqualStrings("durable", &buf);
    try testing.expectError(error.BlobInsufficientLength, second.blob.read_at(1, &buf));
    try testing.expectEqual(@as(u64, 11), storage.write_bytes);
}

test "write past the end zero fills and resize truncates" {
    var storage = Storage.init(testing.allocator);
    defer storage.deinit();
    const opened = try storage.open("p", "b");
    defer opened.blob.deinit();
    try opened.blob.write_at(4, "x");
    var buf: [5]u8 = undefined;
    try opened.blob.read_at(0, &buf);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 'x' }, &buf);
    try opened.blob.resize(2);
    try testing.expectEqual(@as(u64, 2), opened.blob.size());
    try opened.blob.resize(3);
    try opened.blob.read_at(0, buf[0..3]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, buf[0..3]);
}

test "remove, scan, and partition names" {
    const gpa = testing.allocator;
    var storage = Storage.init(gpa);
    defer storage.deinit();
    try testing.expectError(error.PartitionNameInvalid, storage.open("bad/name", "b"));
    try testing.expectError(error.PartitionNameInvalid, storage.open("", "b"));
    try testing.expectError(error.PartitionMissing, storage.scan(gpa, "missing"));

    for ([_][]const u8{ "right", "left" }) |name| {
        const opened = try storage.open("part_1-a", name);
        opened.blob.deinit();
    }
    const names = try storage.scan(gpa, "part_1-a");
    defer {
        for (names) |name| gpa.free(name);
        gpa.free(names);
    }
    try testing.expectEqual(@as(usize, 2), names.len);
    try testing.expectEqualStrings("left", names[0]);
    try testing.expectEqualStrings("right", names[1]);

    // A handle to a removed blob stays readable but cannot sync, and reopening creates a
    // new empty blob.
    const opened = try storage.open("part_1-a", "left");
    try opened.blob.write_at(0, "abc");
    try storage.remove("part_1-a", "left");
    try testing.expectError(error.BlobMissing, storage.remove("part_1-a", "left"));
    try testing.expectError(error.BlobMissing, opened.blob.sync());
    const reopened = try storage.open("part_1-a", "left");
    try testing.expectEqual(@as(u64, 0), reopened.len);
    reopened.blob.deinit();
    opened.blob.deinit();

    try storage.remove("part_1-a", null);
    try testing.expectError(error.PartitionMissing, storage.remove("part_1-a", null));
}

test "remove fault injection" {
    var storage = Storage.init(testing.allocator);
    defer storage.deinit();
    for ([_][]const u8{ "a", "b" }) |name| (try storage.open("p", name)).blob.deinit();
    storage.remove_failures_after = 1;
    try storage.remove("p", "a");
    try testing.expectError(error.Io, storage.remove("p", "b"));
    storage.remove_failures_after = null;
    try storage.remove("p", "b");
}

test "mutation faults fail after allowed operations" {
    const gpa = testing.allocator;
    var storage = Storage.init(gpa);
    defer storage.deinit();
    var opened = try storage.open("mutation", "blob");
    // Two mutations succeed, then every later one fails, whatever its kind.
    storage.allow_mutations(2);
    try opened.blob.write_at(0, "data");
    try opened.blob.sync();
    try testing.expect(!storage.mutation_refused);
    try testing.expectError(error.Io, opened.blob.resize(2));
    try testing.expect(storage.mutation_refused);
    try testing.expectError(error.Io, opened.blob.write_at(0, "more"));
    try testing.expectError(error.Io, opened.blob.sync());
    try testing.expectError(error.Io, storage.remove("mutation", "blob"));
    try testing.expectError(error.Io, storage.open("mutation", "created"));
    try testing.expectError(error.Io, storage.open("fresh", "created"));
    // Reads still succeed, and no failed mutation reached storage.
    var read: [4]u8 = undefined;
    const reads = storage.reads;
    try opened.blob.read_at(0, &read);
    try testing.expectEqualStrings("data", &read);
    try testing.expectEqual(reads + 1, storage.reads);
    const names = try storage.scan(gpa, "mutation");
    defer {
        for (names) |name| gpa.free(name);
        gpa.free(names);
    }
    try testing.expectEqual(@as(usize, 1), names.len);
    try testing.expectError(error.PartitionMissing, storage.scan(gpa, "fresh"));
    // Opening a stored blob is not a mutation.
    opened.blob.deinit();
    opened = try storage.open("mutation", "blob");
    defer opened.blob.deinit();
    // Disarming lets mutations through again.
    storage.mutations_allowed = null;
    try opened.blob.resize(2);
}
