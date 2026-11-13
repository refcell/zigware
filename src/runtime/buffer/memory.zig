//! In-memory test backend for `runtime.storage` (`Storage` and `Blob` vtables).
//!
//! Stands in for the runtime's in-memory backend until it lands; tests across the buffer,
//! journal, and metadata run against it. Like commonware's memory storage, a blob handle holds
//! live contents and `sync` publishes them: closing a handle without syncing loses its unsynced
//! writes, which is how tests simulate a crash. Only one handle per blob may be open; removing
//! a blob unlinks it, and its open handle stays readable but can no longer sync. The runtime
//! header is not modeled: `Opened.len` is the logical length.
//!
//! `write_bytes` and `writes` count every `write_at` (the runtime's
//! `runtime_storage_write_bytes_total`), `reads` counts every `read_at` (commonware's
//! `RecordingContext`), and `remove_failures_after` injects a removal fault after that many
//! successful removals. `mutations_allowed` is commonware's `MutationFaults`: once set, that
//! many more mutations (blob creation, `remove`, `write_at`, `resize`, `sync`) succeed and every
//! later one fails with `Io`, recording `mutation_refused`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const storage_mod = @import("../storage.zig");

pub const Error = storage_mod.Error;
pub const Opened = storage_mod.Opened;
pub const Names = storage_mod.Names;
const validate_partition_name = storage_mod.validate_partition_name;

/// Published contents of one blob.
const Durable = struct {
    bytes: std.ArrayList(u8) = .empty,
    /// Distinguishes a re-created blob from one removed while a handle was open.
    generation: u64,
    version: storage_mod.BlobVersion,
    open: bool = false,
};

const Partition = std.StringArrayHashMapUnmanaged(Durable);

pub const Storage = struct {
    gpa: Allocator,
    partitions: std.StringArrayHashMapUnmanaged(Partition) = .empty,
    generation_next: u64 = 0,
    /// Bytes passed to `write_at` across all blobs.
    write_bytes: u64 = 0,
    /// Calls to `write_at` across all blobs.
    writes: u64 = 0,
    /// Calls to `read_at` across all blobs.
    reads: u64 = 0,
    /// When set, removals fail with `Io` once this many more have succeeded.
    remove_failures_after: ?u32 = null,
    /// When set, mutations fail with `Io` once this many more have succeeded.
    mutations_allowed: ?u64 = null,
    /// Whether a mutation failed since `mutations_allowed` was last set.
    mutation_refused: bool = false,

    const vtable: storage_mod.Storage.VTable = .{
        .open_versioned = open_erased,
        .remove = remove_erased,
        .scan = scan_erased,
    };

    pub fn init(gpa: Allocator) Storage {
        return .{ .gpa = gpa };
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

    /// The `runtime.storage.Storage` interface over this backend.
    pub fn interface(self: *Storage) storage_mod.Storage {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn from(ptr: *anyopaque) *Storage {
        return @ptrCast(@alignCast(ptr));
    }

    fn open_erased(
        ptr: *anyopaque,
        partition: []const u8,
        name: []const u8,
        versions: storage_mod.VersionRange,
    ) Error!Opened {
        return from(ptr).open_versioned(partition, name, versions);
    }

    fn remove_erased(ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void {
        return from(ptr).remove(partition, name);
    }

    fn scan_erased(ptr: *anyopaque, gpa: Allocator, partition: []const u8) Error!Names {
        return from(ptr).scan(gpa, partition);
    }

    fn free_partition(gpa: Allocator, partition: *Partition) void {
        for (partition.keys(), partition.values()) |name, *durable| {
            assert(!durable.open);
            durable.bytes.deinit(gpa);
            gpa.free(name);
        }
        partition.deinit(gpa);
    }

    /// The published length of a blob, even while a handle is open (commonware's
    /// `logical_blob`), or null if it does not exist.
    pub fn durable_len(self: *Storage, partition: []const u8, name: []const u8) ?u64 {
        const blobs = self.partitions.getPtr(partition) orelse return null;
        const durable = blobs.getPtr(name) orelse return null;
        assert(durable.generation < self.generation_next);
        return durable.bytes.items.len;
    }

    /// Let `operations` more mutations succeed, then fail every later one.
    pub fn allow_mutations(self: *Storage, operations: u64) void {
        self.mutations_allowed = operations;
        self.mutation_refused = false;
    }

    /// Charge one mutation against `mutations_allowed`.
    fn check_mutation(self: *Storage) Error!void {
        const allowed = &(self.mutations_allowed orelse return);
        if (allowed.* == 0) {
            self.mutation_refused = true;
            return error.Io;
        }
        allowed.* -= 1;
    }

    /// Open the blob `name` with the default version (`Storage.open`).
    pub fn open(self: *Storage, partition: []const u8, name: []const u8) Error!Opened {
        return self.open_versioned(partition, name, .only(storage_mod.default_blob_version));
    }

    /// Open the blob `name` in `partition`, creating it empty with `versions.max` if missing.
    pub fn open_versioned(
        self: *Storage,
        partition: []const u8,
        name: []const u8,
        versions: storage_mod.VersionRange,
    ) Error!Opened {
        try validate_partition_name(partition);
        assert(versions.min <= versions.max);
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
            blob_entry.value_ptr.* = .{
                .generation = self.generation_next,
                .version = versions.max,
            };
            self.generation_next += 1;
        }
        const durable = blob_entry.value_ptr;
        if (durable.open) return error.BlobAlreadyOpen;
        if (!versions.contains(durable.version)) return error.BlobVersionMismatch;

        const blob = try gpa.create(MemoryBlob);
        errdefer gpa.destroy(blob);
        blob.* = .{ .storage = self, .generation = durable.generation };
        try blob.live.appendSlice(gpa, durable.bytes.items);
        durable.open = true;
        assert(blob.live.items.len == durable.bytes.items.len);
        return .{ .blob = blob.handle(), .len = blob.live.items.len, .version = durable.version };
    }

    /// Remove the blob `name` from `partition`, or the whole partition if `name` is null.
    pub fn remove(self: *Storage, partition: []const u8, name: ?[]const u8) Error!void {
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

    /// The names of every blob in `partition`, sorted. Free with `Names.deinit`.
    pub fn scan(self: *Storage, gpa: Allocator, partition: []const u8) Error!Names {
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
        assert(filled == names.len);
        return .{ .items = names };
    }

    fn less_than_bytes(_: void, a: []u8, b: []u8) bool {
        return std.mem.order(u8, a, b) == .lt;
    }
};

/// An open handle to one blob, exposed as a `runtime.storage.Blob`.
const MemoryBlob = struct {
    storage: *Storage,
    /// Identifies the published blob; generations are never reused, so a removed blob's
    /// handle finds nothing.
    generation: u64,
    live: std.ArrayList(u8) = .empty,

    const vtable: storage_mod.Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize,
        .sync = sync,
        .close = close,
    };

    fn handle(self: *MemoryBlob) storage_mod.Blob {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn from(ptr: *anyopaque) *MemoryBlob {
        return @ptrCast(@alignCast(ptr));
    }

    /// Close the handle, dropping unsynced writes.
    fn close(ptr: *anyopaque) void {
        const self = from(ptr);
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

    fn read_at(
        ptr: *anyopaque,
        offset: u64,
        buf: []u8,
        options: storage_mod.ReadOptions,
    ) Error!void {
        _ = options;
        const self = from(ptr);
        const end = std.math.add(u64, offset, buf.len) catch return error.OffsetOverflow;
        if (end > self.live.items.len) return error.BlobInsufficientLength;
        @memcpy(buf, self.live.items[@intCast(offset)..@intCast(end)]);
        self.storage.reads += 1;
    }

    /// Write the chunks at `offset`, zero-filling any gap past the current end. A `sync` write
    /// also publishes the written range (not earlier writes).
    fn write_at(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: storage_mod.WriteOptions,
    ) Error!void {
        const self = from(ptr);
        var len: u64 = 0;
        for (chunks) |chunk| len += chunk.len;
        const end = std.math.add(u64, offset, len) catch return error.OffsetOverflow;
        const end_index = std.math.cast(usize, end) orelse return error.OffsetOverflow;
        try self.storage.check_mutation();
        try write_into(self.storage.gpa, &self.live, @intCast(offset), end_index, chunks);
        if (options.sync) {
            const durable = self.durable_lookup() orelse return error.BlobMissing;
            try write_into(self.storage.gpa, &durable.bytes, @intCast(offset), end_index, chunks);
        }
        self.storage.write_bytes += len;
        self.storage.writes += 1;
        assert(self.live.items.len >= end_index);
    }

    fn write_into(
        gpa: Allocator,
        bytes: *std.ArrayList(u8),
        offset: usize,
        end: usize,
        chunks: []const []const u8,
    ) Error!void {
        if (end > bytes.items.len) {
            const old_len = bytes.items.len;
            try bytes.resize(gpa, end);
            @memset(bytes.items[old_len..], 0);
        }
        var at = offset;
        for (chunks) |chunk| {
            @memcpy(bytes.items[at..][0..chunk.len], chunk);
            at += chunk.len;
        }
        assert(at == end);
    }

    /// Set the blob's length, truncating or zero-extending.
    fn resize(ptr: *anyopaque, len: u64) Error!void {
        const self = from(ptr);
        const len_index = std.math.cast(usize, len) orelse return error.OffsetOverflow;
        try self.storage.check_mutation();
        const old_len = self.live.items.len;
        try self.live.resize(self.storage.gpa, len_index);
        if (len_index > old_len) @memset(self.live.items[old_len..], 0);
        assert(self.live.items.len == len_index);
    }

    /// Publish the live contents, so they survive closing the handle.
    fn sync(ptr: *anyopaque) Error!void {
        const self = from(ptr);
        try self.storage.check_mutation();
        const durable = self.durable_lookup() orelse return error.BlobMissing;
        durable.bytes.clearRetainingCapacity();
        try durable.bytes.appendSlice(self.storage.gpa, self.live.items);
        assert(durable.bytes.items.len == self.live.items.len);
    }
};

const testing = std.testing;

test "unsynced writes are lost when the handle closes" {
    var storage = Storage.init(testing.allocator);
    defer storage.deinit();
    const first = try storage.open("partition", "blob");
    try testing.expectEqual(@as(u64, 0), first.len);
    try first.blob.write_at(0, "durable", .{});
    try first.blob.sync();
    try first.blob.write_at(7, "lost", .{});
    try testing.expectError(error.BlobAlreadyOpen, storage.open("partition", "blob"));
    first.blob.close();

    const second = try storage.open("partition", "blob");
    defer second.blob.close();
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
    defer opened.blob.close();
    try opened.blob.write_at(4, "x", .{});
    var buf: [5]u8 = undefined;
    try opened.blob.read_at(0, &buf);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 'x' }, &buf);
    try opened.blob.resize(2);
    try testing.expectError(error.BlobInsufficientLength, opened.blob.read_at(0, buf[0..3]));
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
        opened.blob.close();
    }
    const names = try storage.scan(gpa, "part_1-a");
    defer names.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), names.items.len);
    try testing.expectEqualStrings("left", names.items[0]);
    try testing.expectEqualStrings("right", names.items[1]);

    // A handle to a removed blob stays readable but cannot sync, and reopening creates a
    // new empty blob.
    const opened = try storage.open("part_1-a", "left");
    try opened.blob.write_at(0, "abc", .{});
    try storage.remove("part_1-a", "left");
    try testing.expectError(error.BlobMissing, storage.remove("part_1-a", "left"));
    try testing.expectError(error.BlobMissing, opened.blob.sync());
    const reopened = try storage.open("part_1-a", "left");
    try testing.expectEqual(@as(u64, 0), reopened.len);
    reopened.blob.close();
    opened.blob.close();

    try storage.remove("part_1-a", null);
    try testing.expectError(error.PartitionMissing, storage.remove("part_1-a", null));
}

test "remove fault injection" {
    var storage = Storage.init(testing.allocator);
    defer storage.deinit();
    for ([_][]const u8{ "a", "b" }) |name| (try storage.open("p", name)).blob.close();
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
    try opened.blob.write_at(0, "data", .{});
    try opened.blob.sync();
    try testing.expect(!storage.mutation_refused);
    try testing.expectError(error.Io, opened.blob.resize(2));
    try testing.expect(storage.mutation_refused);
    try testing.expectError(error.Io, opened.blob.write_at(0, "more", .{}));
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
    defer names.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), names.items.len);
    try testing.expectError(error.PartitionMissing, storage.scan(gpa, "fresh"));
    // Opening a stored blob is not a mutation.
    opened.blob.close();
    opened = try storage.open("mutation", "blob");
    defer opened.blob.close();
    // Disarming lets mutations through again.
    storage.mutations_allowed = null;
    try opened.blob.resize(2);
}
