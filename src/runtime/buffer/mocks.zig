//! Test storage: `runtime.storage.memory` behind commonware's storage mocks
//! (`runtime/src/mocks.rs`: `RecordingContext` and `MutationFaultContext`).
//!
//! Every operation goes to the runtime's in-memory backend, which keeps commonware's
//! semantics (exclusive opens, unsynced changes discarded on close or `crash`). The wrapper
//! adds what storage tests observe or inject:
//!
//! - `reads`, `writes`, and `write_bytes` count every blob `read_at` and `write_at`
//!   (commonware's recorded reads and `runtime_storage_write_bytes_total`).
//! - `allow_mutations(n)` is `MutationFaults::allow`: `n` more mutations (creating a blob,
//!   `remove`, `write_at`, `resize`, `sync`) succeed, then every later one fails with `Io` and
//!   sets `mutation_refused`. Reads and opens of stored blobs are not mutations.
//! - `remove_failures_after` fails removals with `Io` once that many more have succeeded.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const iface = @import("../storage.zig");
const memory = @import("../storage/memory.zig");

const Error = iface.Error;

pub const Storage = struct {
    gpa: Allocator,
    backend: memory.Storage,
    /// Calls to `read_at` across all blobs.
    reads: u64 = 0,
    /// Calls to `read_at` with `dont_cache` set (commonware's recorded read options).
    dont_cache_reads: u64 = 0,
    /// Calls to `write_at` across all blobs.
    writes: u64 = 0,
    /// Bytes passed to `write_at` across all blobs.
    write_bytes: u64 = 0,
    /// When set, removals fail with `Io` once this many more have succeeded.
    remove_failures_after: ?u32 = null,
    /// When set, mutations fail with `Io` once this many more have succeeded.
    mutations_allowed: ?u64 = null,
    /// Whether a mutation failed since `allow_mutations`.
    mutation_refused: bool = false,

    const vtable: iface.Storage.VTable = .{
        .open_versioned = open_erased,
        .remove = remove_erased,
        .scan = scan_erased,
    };

    pub fn init(gpa: Allocator) Storage {
        return .{ .gpa = gpa, .backend = memory.Storage.init(gpa) };
    }

    /// Frees every blob. Every handle must be closed first.
    pub fn deinit(self: *Storage) void {
        self.backend.deinit();
        self.* = undefined;
    }

    /// The `runtime.storage.Storage` interface of this mock.
    pub fn interface(self: *Storage) iface.Storage {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Crash: durable contents survive, unsynced changes of open handles are lost, and every
    /// blob can be opened again (open handles must still be closed).
    pub fn crash(self: *Storage) void {
        self.backend.crash();
    }

    /// The durable logical length of a blob, even while a handle is open (commonware's
    /// `logical_blob`), or null if it is missing.
    pub fn durable_len(self: *Storage, partition: []const u8, name: []const u8) !?u64 {
        const contents = try self.backend.logical_blob(self.gpa, partition, name) orelse
            return null;
        defer self.gpa.free(contents);
        return contents.len;
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

    fn from(ptr: *anyopaque) *Storage {
        return @ptrCast(@alignCast(ptr));
    }

    fn open_erased(
        ptr: *anyopaque,
        partition: []const u8,
        name: []const u8,
        versions: iface.VersionRange,
    ) Error!iface.Opened {
        return from(ptr).open_versioned(partition, name, versions);
    }

    fn remove_erased(ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void {
        return from(ptr).remove(partition, name);
    }

    fn scan_erased(ptr: *anyopaque, gpa: Allocator, partition: []const u8) Error!iface.Names {
        return from(ptr).scan(gpa, partition);
    }

    pub fn open(self: *Storage, partition: []const u8, name: []const u8) Error!iface.Opened {
        return self.open_versioned(partition, name, .only(iface.default_blob_version));
    }

    pub fn open_versioned(
        self: *Storage,
        partition: []const u8,
        name: []const u8,
        versions: iface.VersionRange,
    ) Error!iface.Opened {
        // Opening a blob that is not stored creates it. Creation is a mutation.
        if (!try self.stored(partition, name)) try self.check_mutation();
        const handle = try self.gpa.create(Blob);
        errdefer self.gpa.destroy(handle);
        const opened = try self.backend.open_versioned(partition, name, versions);
        handle.* = .{ .storage = self, .inner = opened.blob };
        return .{ .blob = handle.blob(), .len = opened.len, .version = opened.version };
    }

    fn stored(self: *Storage, partition: []const u8, name: []const u8) Error!bool {
        const names = self.backend.scan(self.gpa, partition) catch |err| switch (err) {
            error.PartitionMissing => return false,
            else => return err,
        };
        defer names.deinit(self.gpa);
        return names.contains(name);
    }

    pub fn remove(self: *Storage, partition: []const u8, name: ?[]const u8) Error!void {
        try iface.validate_partition_name(partition);
        try self.check_mutation();
        if (self.remove_failures_after) |*budget| {
            if (budget.* == 0) return error.Io;
            budget.* -= 1;
        }
        return self.backend.remove(partition, name);
    }

    pub fn scan(self: *Storage, gpa: Allocator, partition: []const u8) Error!iface.Names {
        return self.backend.scan(gpa, partition);
    }
};

/// A counted, fault-injecting handle over a backend blob.
const Blob = struct {
    storage: *Storage,
    inner: iface.Blob,

    const vtable: iface.Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize,
        .sync = sync,
        .close = close,
    };

    fn blob(self: *Blob) iface.Blob {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn from(ptr: *anyopaque) *Blob {
        return @ptrCast(@alignCast(ptr));
    }

    fn read_at(ptr: *anyopaque, offset: u64, buf: []u8, options: iface.ReadOptions) Error!void {
        const self = from(ptr);
        self.storage.reads += 1;
        if (options.dont_cache) self.storage.dont_cache_reads += 1;
        return self.inner.read_at_options(offset, buf, options);
    }

    fn write_at(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: iface.WriteOptions,
    ) Error!void {
        const self = from(ptr);
        try self.storage.check_mutation();
        var len: u64 = 0;
        for (chunks) |chunk| len += chunk.len;
        self.storage.writes += 1;
        self.storage.write_bytes += len;
        return self.inner.write_at_vectored(offset, chunks, options);
    }

    fn resize(ptr: *anyopaque, length: u64) Error!void {
        const self = from(ptr);
        try self.storage.check_mutation();
        return self.inner.resize(length);
    }

    fn sync(ptr: *anyopaque) Error!void {
        const self = from(ptr);
        try self.storage.check_mutation();
        return self.inner.sync();
    }

    fn close(ptr: *anyopaque) void {
        const self = from(ptr);
        const gpa = self.storage.gpa;
        self.inner.close();
        gpa.destroy(self);
    }
};

const testing = std.testing;

test "counters record reads and writes" {
    var storage = Storage.init(testing.allocator);
    defer storage.deinit();
    const opened = try storage.open("partition", "blob");
    defer opened.blob.close();
    try opened.blob.write_at(0, "durable", .{});
    try opened.blob.write_at_vectored(7, &.{ "a", "bc" }, .{});
    var buf: [10]u8 = undefined;
    try opened.blob.read_at(0, &buf);
    try testing.expectEqualStrings("durableabc", &buf);
    try testing.expectEqual(@as(u64, 2), storage.writes);
    try testing.expectEqual(@as(u64, 10), storage.write_bytes);
    try testing.expectEqual(@as(u64, 1), storage.reads);
}

test "crash discards unsynced changes" {
    var storage = Storage.init(testing.allocator);
    defer storage.deinit();
    const first = try storage.open("partition", "blob");
    try first.blob.write_at(0, "durable", .{});
    try first.blob.sync();
    try first.blob.write_at(7, "lost", .{});
    storage.crash();
    first.blob.close();
    const second = try storage.open("partition", "blob");
    defer second.blob.close();
    try testing.expectEqual(@as(u64, 7), second.len);
    try testing.expectEqual(@as(?u64, 7), try storage.durable_len("partition", "blob"));
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
    // Reads still succeed, and no failed mutation reached storage.
    var read: [4]u8 = undefined;
    try opened.blob.read_at(0, &read);
    try testing.expectEqualStrings("data", &read);
    const names = try storage.scan(gpa, "mutation");
    defer names.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), names.items.len);
    // Opening a stored blob is not a mutation.
    opened.blob.close();
    opened = try storage.open("mutation", "blob");
    defer opened.blob.close();
    // Disarming lets mutations through again.
    storage.mutations_allowed = null;
    try opened.blob.resize(2);
}
