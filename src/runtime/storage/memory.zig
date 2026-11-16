//! In-memory storage (commonware `runtime/src/storage/memory`, with the exclusive-open
//! registry of `memory/open.rs`).
//!
//! Durable contents live in sorted partitions of sorted blobs, so scans and audits are
//! deterministic. Each open copies the blob's durable contents into its handle; writes stay
//! in that copy until `sync` publishes them (or a `WriteOptions.sync` write publishes its own
//! range). Closing a handle without syncing discards its unsynced changes.
//!
//! Every durable blob records the generation of its current incarnation. Removing a blob,
//! installing raw contents, or a crash retires that generation, so an old handle stays
//! readable but can no longer publish into a newer incarnation (its sync returns
//! `error.BlobMissing`). A blob also records its one live handle: a second open returns
//! `error.BlobAlreadyOpen` until that handle closes or the blob is removed.
//!
//! One spin lock guards everything, so a `Storage` may be shared by threads; no operation
//! blocks or yields while holding it. Handles must be closed before `deinit`; `deinit`
//! frees any that were not.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const iface = @import("../storage.zig");
const header = @import("header.zig");
const AuditHasher = @import("../deterministic.zig").AuditHasher;

const Error = iface.Error;
const BlobVersion = iface.BlobVersion;
const VersionRange = iface.VersionRange;

/// Durable state of one blob.
const Entry = struct {
    name: []u8,
    /// Durable raw contents, header included.
    content: std.ArrayList(u8),
    /// Generation of the incarnation live handles publish into; null when none is current.
    generation: ?u64,
    /// The exclusive open, until it closes or the blob is removed.
    live: ?*Blob,

    fn deinit(entry: *Entry, gpa: Allocator) void {
        gpa.free(entry.name);
        entry.content.deinit(gpa);
        entry.* = undefined;
    }
};

const Partition = struct {
    name: []u8,
    entries: std.ArrayList(Entry),

    fn deinit(partition: *Partition, gpa: Allocator) void {
        for (partition.entries.items) |*entry| entry.deinit(gpa);
        partition.entries.deinit(gpa);
        gpa.free(partition.name);
        partition.* = undefined;
    }
};

/// Index of the first item whose name is not less than `name`.
fn lower_bound(comptime T: type, items: []const T, name: []const u8) usize {
    var low: usize = 0;
    var high: usize = items.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (std.mem.order(u8, items[middle].name, name) == .lt) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    assert(low <= items.len);
    assert(low == 0 or std.mem.order(u8, items[low - 1].name, name) == .lt);
    return low;
}

fn find(comptime T: type, items: []const T, name: []const u8) ?usize {
    const index = lower_bound(T, items, name);
    if (index < items.len and std.mem.eql(u8, items[index].name, name)) return index;
    return null;
}

pub const Storage = struct {
    gpa: Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    partitions: std.ArrayList(Partition) = .empty,
    generation_next: u64 = 0,
    /// Every handle not yet closed, including handles of removed blobs.
    handles: std.DoublyLinkedList = .{},

    pub fn init(gpa: Allocator) Storage {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Storage) void {
        while (self.handles.popFirst()) |node| {
            const blob: *Blob = @fieldParentPtr("node", node);
            blob.destroy();
        }
        for (self.partitions.items) |*partition| partition.deinit(self.gpa);
        self.partitions.deinit(self.gpa);
        self.* = undefined;
    }

    /// The `Storage` interface of this backend.
    pub fn storage(self: *Storage) iface.Storage {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: iface.Storage.VTable = .{
        .open_versioned = open_erased,
        .remove = remove_erased,
        .scan = scan_erased,
    };

    fn open_erased(
        ptr: *anyopaque,
        partition: []const u8,
        name: []const u8,
        versions: VersionRange,
    ) Error!iface.Opened {
        const self: *Storage = @ptrCast(@alignCast(ptr));
        return self.open_versioned(partition, name, versions);
    }

    fn remove_erased(ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void {
        const self: *Storage = @ptrCast(@alignCast(ptr));
        return self.remove(partition, name);
    }

    fn scan_erased(ptr: *anyopaque, gpa: Allocator, partition: []const u8) Error!iface.Names {
        const self: *Storage = @ptrCast(@alignCast(ptr));
        return self.scan(gpa, partition);
    }

    fn lock(self: *Storage) void {
        // Critical sections never block, so contention is brief.
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    fn unlock(self: *Storage) void {
        self.mutex.unlock();
    }

    pub fn open(self: *Storage, partition: []const u8, name: []const u8) Error!iface.Opened {
        return self.open_versioned(partition, name, .only(iface.default_blob_version));
    }

    /// Open or create a blob (see `iface.Storage.open_versioned`).
    pub fn open_versioned(
        self: *Storage,
        partition: []const u8,
        name: []const u8,
        versions: VersionRange,
    ) Error!iface.Opened {
        return self.open_layout(partition, name, iface.default_blob_layout, versions);
    }

    /// Open or create a blob, creating new blobs with `layout` (tests write legacy layouts).
    pub fn open_layout(
        self: *Storage,
        partition: []const u8,
        name: []const u8,
        layout: iface.BlobLayout,
        versions: VersionRange,
    ) Error!iface.Opened {
        assert(versions.min <= versions.max);
        try iface.validate_partition_name(partition);
        self.lock();
        defer self.unlock();
        const entry = try self.entry_get_or_create(partition, name);
        const content = entry.content.items;
        const raw = content[0..header.resolve_len(content.len)];
        const resolved = try header.resolve(raw, content.len, .all, versions, partition, name);
        var opened: header.Resolved = undefined;
        if (resolved) |existing| {
            opened = existing;
            if (entry.generation == null) entry.generation = self.generation_rotate();
        } else {
            // A new blob, or one left torn by an interrupted creation: write a fresh header.
            var region: [header.region_max]u8 = undefined;
            const created = header.create(.only(layout), versions, &region);
            entry.content.clearRetainingCapacity();
            try entry.content.appendSlice(self.gpa, created.region);
            entry.generation = self.generation_rotate();
            opened = .{
                .len = 0,
                .blob_version = created.blob_version,
                .data_offset = created.region.len,
            };
        }
        if (entry.live != null) return error.BlobAlreadyOpen;
        const blob = try Blob.create(self, partition, entry, opened.data_offset);
        entry.live = blob;
        assert(entry.content.items.len == opened.data_offset + opened.len);
        return .{ .blob = blob.blob(), .len = opened.len, .version = opened.blob_version };
    }

    fn generation_rotate(self: *Storage) u64 {
        const generation = self.generation_next;
        self.generation_next = std.math.add(u64, generation, 1) catch
            @panic("blob generation overflow");
        assert(self.generation_next > generation);
        return generation;
    }

    fn entry_get_or_create(self: *Storage, partition: []const u8, name: []const u8) !*Entry {
        const partition_index = lower_bound(Partition, self.partitions.items, partition);
        if (find(Partition, self.partitions.items, partition) == null) {
            const owned = try self.gpa.dupe(u8, partition);
            errdefer self.gpa.free(owned);
            try self.partitions.insert(self.gpa, partition_index, .{
                .name = owned,
                .entries = .empty,
            });
        }
        const entries = &self.partitions.items[partition_index].entries;
        assert(std.mem.eql(u8, self.partitions.items[partition_index].name, partition));
        const entry_index = lower_bound(Entry, entries.items, name);
        if (find(Entry, entries.items, name) == null) {
            const owned = try self.gpa.dupe(u8, name);
            errdefer self.gpa.free(owned);
            try entries.insert(self.gpa, entry_index, .{
                .name = owned,
                .content = .empty,
                .generation = null,
                .live = null,
            });
        }
        return &entries.items[entry_index];
    }

    fn entry_get(self: *Storage, partition: []const u8, name: []const u8) ?*Entry {
        const partition_index = find(Partition, self.partitions.items, partition) orelse
            return null;
        const entries = self.partitions.items[partition_index].entries.items;
        const entry_index = find(Entry, entries, name) orelse return null;
        assert(std.mem.eql(u8, entries[entry_index].name, name));
        return &entries[entry_index];
    }

    /// Remove a blob, or the whole partition when `name` is null. Open handles stay readable.
    pub fn remove(self: *Storage, partition: []const u8, name: ?[]const u8) Error!void {
        try iface.validate_partition_name(partition);
        self.lock();
        defer self.unlock();
        const partition_index = find(Partition, self.partitions.items, partition) orelse
            return error.PartitionMissing;
        const removed = &self.partitions.items[partition_index];
        if (name) |blob_name| {
            const entry_index = find(Entry, removed.entries.items, blob_name) orelse
                return error.BlobMissing;
            var entry = removed.entries.orderedRemove(entry_index);
            entry.deinit(self.gpa);
            assert(self.entry_get(partition, blob_name) == null);
        } else {
            var partition_removed = self.partitions.orderedRemove(partition_index);
            partition_removed.deinit(self.gpa);
            assert(find(Partition, self.partitions.items, partition) == null);
        }
    }

    /// Every blob name in `partition`, sorted.
    pub fn scan(self: *Storage, gpa: Allocator, partition: []const u8) Error!iface.Names {
        try iface.validate_partition_name(partition);
        self.lock();
        defer self.unlock();
        const partition_index = find(Partition, self.partitions.items, partition) orelse
            return error.PartitionMissing;
        const entries = self.partitions.items[partition_index].entries.items;
        const items = try gpa.alloc([]u8, entries.len);
        var count: usize = 0;
        errdefer {
            for (items[0..count]) |item| gpa.free(item);
            gpa.free(items);
        }
        while (count < entries.len) : (count += 1) {
            items[count] = try gpa.dupe(u8, entries[count].name);
        }
        assert(count == items.len);
        return .{ .items = items };
    }

    /// CRC32C digest of every durable blob, in partition then name order
    /// (commonware `Storage::audit`).
    pub fn audit(self: *Storage) [4]u8 {
        self.lock();
        defer self.unlock();
        var hasher: AuditHasher = .{};
        hasher.update("commonware-runtime-storage-audit-v1");
        for (self.partitions.items) |partition| {
            assert(partition.name.len > 0);
            for (partition.entries.items) |entry| {
                hasher.update("partition");
                hasher.update(partition.name);
                hasher.update("blob");
                hasher.update(entry.name);
                hasher.update("content");
                hasher.update(entry.content.items);
            }
        }
        return hasher.finalize();
    }

    /// Retire every live generation and open, as a crash does: durable contents survive, open
    /// handles stay readable but can no longer publish, and every blob can be opened again.
    pub fn crash(self: *Storage) void {
        self.lock();
        defer self.unlock();
        for (self.partitions.items) |*partition| {
            for (partition.entries.items) |*entry| {
                entry.generation = null;
                entry.live = null;
            }
        }
        assert(self.partitions.items.len == 0 or self.partitions.items[0].name.len > 0);
    }

    /// The durable entry whose current incarnation is `generation`. Called with the lock held.
    fn entry_of_generation(self: *Storage, generation: u64) ?*Entry {
        for (self.partitions.items) |*partition| {
            for (partition.entries.items) |*entry| {
                if (entry.generation == generation) return entry;
            }
        }
        return null;
    }

    /// Whether `generation` is still a blob's current incarnation (not removed, replaced, or
    /// crashed).
    pub fn generation_live(self: *Storage, generation: u64) bool {
        self.lock();
        defer self.unlock();
        return self.entry_of_generation(generation) != null;
    }

    /// Merge the `selected` bytes of a write at physical `offset` into the durable contents of
    /// incarnation `generation`, leaving live handles untouched (commonware
    /// `retain_crash_write`). Does nothing if the incarnation is gone.
    pub fn retain_crash_write(
        self: *Storage,
        generation: u64,
        offset: u64,
        bytes: []const u8,
        selected: []const bool,
    ) Error!void {
        assert(bytes.len == selected.len);
        const end = std.math.add(u64, offset, bytes.len) catch return error.OffsetOverflow;
        const start = std.math.cast(usize, offset) orelse return error.OffsetOverflow;
        _ = std.math.cast(usize, end) orelse return error.OffsetOverflow;
        self.lock();
        defer self.unlock();
        const entry = self.entry_of_generation(generation) orelse return;
        const content = &entry.content;
        for (bytes, selected, 0..) |byte, keep, index| {
            if (!keep) continue;
            const position = start + index;
            if (position >= content.items.len) {
                try content.appendNTimes(self.gpa, 0, position + 1 - content.items.len);
            }
            content.items[position] = byte;
        }
    }

    /// Truncate or zero-extend the durable contents of incarnation `generation` to physical
    /// `length`, leaving live handles untouched (commonware `retain_crash_resize`). Does
    /// nothing if the incarnation is gone.
    pub fn retain_crash_resize(self: *Storage, generation: u64, length: u64) Error!void {
        const end = std.math.cast(usize, length) orelse return error.OffsetOverflow;
        self.lock();
        defer self.unlock();
        const entry = self.entry_of_generation(generation) orelse return;
        const content = &entry.content;
        if (end > content.items.len) {
            try content.appendNTimes(self.gpa, 0, end - content.items.len);
        } else {
            content.shrinkRetainingCapacity(end);
        }
        assert(content.items.len == end);
    }

    /// A copy of a blob's durable raw contents, header included, or null if it is missing.
    pub fn raw_blob(
        self: *Storage,
        gpa: Allocator,
        partition: []const u8,
        name: []const u8,
    ) !?[]u8 {
        self.lock();
        defer self.unlock();
        const entry = self.entry_get(partition, name) orelse return null;
        return try gpa.dupe(u8, entry.content.items);
    }

    /// A copy of a blob's durable logical contents, or null when the blob is missing or its
    /// header does not resolve.
    pub fn logical_blob(
        self: *Storage,
        gpa: Allocator,
        partition: []const u8,
        name: []const u8,
    ) !?[]u8 {
        self.lock();
        defer self.unlock();
        const entry = self.entry_get(partition, name) orelse return null;
        const content = entry.content.items;
        const raw = content[0..header.resolve_len(content.len)];
        const versions: VersionRange = .{ .min = 0, .max = std.math.maxInt(BlobVersion) };
        const resolved = header.parse(raw, content.len, .all, versions) catch return null;
        assert(resolved.data_offset <= content.len);
        return try gpa.dupe(u8, content[@intCast(resolved.data_offset)..]);
    }

    /// Install durable raw contents without validating the header, retiring the blob's live
    /// generation and open.
    pub fn set_raw_blob(
        self: *Storage,
        partition: []const u8,
        name: []const u8,
        content: []const u8,
    ) Error!void {
        self.lock();
        defer self.unlock();
        const entry = try self.entry_get_or_create(partition, name);
        entry.content.clearRetainingCapacity();
        try entry.content.appendSlice(self.gpa, content);
        entry.generation = null;
        entry.live = null;
        assert(std.mem.eql(u8, entry.content.items, content));
    }
};

/// An open blob of the memory backend.
pub const Blob = struct {
    storage: *Storage,
    node: std.DoublyLinkedList.Node = .{},
    partition: []u8,
    name: []u8,
    /// Live raw contents, header included.
    content: std.ArrayList(u8),
    /// Physical offset of logical offset 0: the size of the header region.
    data_offset: u64,
    /// The generation captured at open.
    generation: u64,

    /// Called with the storage locked.
    fn create(storage: *Storage, partition: []const u8, entry: *Entry, data_offset: u64) !*Blob {
        assert(entry.generation != null);
        assert(entry.content.items.len >= data_offset);
        const gpa = storage.gpa;
        const self = try gpa.create(Blob);
        errdefer gpa.destroy(self);
        const partition_owned = try gpa.dupe(u8, partition);
        errdefer gpa.free(partition_owned);
        const name_owned = try gpa.dupe(u8, entry.name);
        errdefer gpa.free(name_owned);
        var content: std.ArrayList(u8) = .empty;
        try content.appendSlice(gpa, entry.content.items);
        self.* = .{
            .storage = storage,
            .partition = partition_owned,
            .name = name_owned,
            .content = content,
            .data_offset = data_offset,
            .generation = entry.generation.?,
        };
        storage.handles.append(&self.node);
        return self;
    }

    /// Called with the storage locked.
    fn destroy(self: *Blob) void {
        const gpa = self.storage.gpa;
        assert(self.data_offset <= header.region_max);
        assert(self.content.items.len >= self.data_offset);
        self.content.deinit(gpa);
        gpa.free(self.partition);
        gpa.free(self.name);
        gpa.destroy(self);
    }

    /// The `Blob` interface of this handle.
    pub fn blob(self: *Blob) iface.Blob {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: iface.Blob.VTable = .{
        .read_at = read_at_erased,
        .write_at = write_at_erased,
        .resize = resize_erased,
        .sync = sync_erased,
        .close = close_erased,
    };

    fn read_at_erased(
        ptr: *anyopaque,
        offset: u64,
        buffer: []u8,
        options: iface.ReadOptions,
    ) Error!void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        return self.read_at(offset, buffer, options);
    }

    fn write_at_erased(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: iface.WriteOptions,
    ) Error!void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        return self.write_at(offset, chunks, options);
    }

    fn resize_erased(ptr: *anyopaque, length: u64) Error!void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        return self.resize(length);
    }

    fn sync_erased(ptr: *anyopaque) Error!void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        return self.sync();
    }

    fn close_erased(ptr: *anyopaque) void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        self.close();
    }

    /// The physical offset of logical `offset` plus `length` bytes, as a slice index.
    fn physical_end(self: *const Blob, offset: u64, length: usize) Error!usize {
        const start = std.math.add(u64, offset, self.data_offset) catch
            return error.OffsetOverflow;
        const end = std.math.add(u64, start, length) catch return error.OffsetOverflow;
        assert(end >= self.data_offset);
        return std.math.cast(usize, end) orelse error.OffsetOverflow;
    }

    pub fn read_at(self: *Blob, offset: u64, buffer: []u8, options: iface.ReadOptions) Error!void {
        _ = options; // Cache hints do not apply to memory.
        const end = try self.physical_end(offset, buffer.len);
        self.storage.lock();
        defer self.storage.unlock();
        if (end > self.content.items.len) return error.BlobInsufficientLength;
        @memcpy(buffer, self.content.items[end - buffer.len .. end]);
        assert(end - buffer.len >= self.data_offset);
    }

    pub fn write_at(
        self: *Blob,
        offset: u64,
        chunks: []const []const u8,
        options: iface.WriteOptions,
    ) Error!void {
        var total: usize = 0;
        for (chunks) |chunk| total = std.math.add(usize, total, chunk.len) catch
            return error.OffsetOverflow;
        if (options.sync and total == 0) return;
        const end = try self.physical_end(offset, total);
        const start = end - total;
        self.storage.lock();
        defer self.storage.unlock();
        if (end > self.content.items.len) {
            try self.content.appendNTimes(self.storage.gpa, 0, end - self.content.items.len);
        }
        var position = start;
        for (chunks) |chunk| {
            @memcpy(self.content.items[position..][0..chunk.len], chunk);
            position += chunk.len;
        }
        assert(position == end);
        if (options.sync) try self.publish_range(start, end);
    }

    /// Merge live bytes `start..end` into the durable contents. Called with the storage locked.
    fn publish_range(self: *Blob, start: usize, end: usize) Error!void {
        assert(start <= end);
        assert(end <= self.content.items.len);
        const entry = try self.current();
        const durable = &entry.content;
        if (end > durable.items.len) {
            try durable.appendNTimes(self.storage.gpa, 0, end - durable.items.len);
        }
        @memcpy(durable.items[start..end], self.content.items[start..end]);
    }

    /// The durable entry of this handle's generation. Called with the storage locked.
    fn current(self: *Blob) Error!*Entry {
        const entry = self.storage.entry_get(self.partition, self.name) orelse
            return error.BlobMissing;
        if (entry.generation != self.generation) return error.BlobMissing;
        assert(std.mem.eql(u8, entry.name, self.name));
        return entry;
    }

    pub fn resize(self: *Blob, length: u64) Error!void {
        const end = try self.physical_end(length, 0);
        self.storage.lock();
        defer self.storage.unlock();
        if (end > self.content.items.len) {
            try self.content.appendNTimes(self.storage.gpa, 0, end - self.content.items.len);
        } else {
            self.content.shrinkRetainingCapacity(end);
        }
        assert(self.content.items.len == end);
    }

    /// Publish the live contents as the durable contents.
    pub fn sync(self: *Blob) Error!void {
        self.storage.lock();
        defer self.storage.unlock();
        const entry = try self.current();
        entry.content.clearRetainingCapacity();
        try entry.content.appendSlice(self.storage.gpa, self.content.items);
        assert(entry.content.items.len == self.content.items.len);
    }

    /// Release the handle, discarding unsynced changes.
    pub fn close(self: *Blob) void {
        const storage = self.storage;
        storage.lock();
        defer storage.unlock();
        if (storage.entry_get(self.partition, self.name)) |entry| {
            if (entry.live == self) entry.live = null;
        }
        storage.handles.remove(&self.node);
        self.destroy();
    }
};
