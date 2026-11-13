//! Blob management for a contiguous journal (commonware's `journal/contiguous/blobs.rs`).
//!
//! A journal's blobs are contiguous sealed blobs ending in one writable tail. Syncs complete
//! synchronously, so a sealed blob is a fully synced paged writer: no sync is ever in flight
//! and there is no separate `Sealed` view or snapshot.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const manager_mod = @import("../segmented/manager.zig");
const journal = @import("../mod.zig");

const Storage = runtime.storage.Storage;
const Writer = paged.Writer;

pub const Error = journal.Error || paged.Error;

/// A storage partition holding blobs named by big-endian `u64` indexes.
pub const Partition = struct {
    gpa: Allocator,
    storage: Storage,
    /// Owned partition name.
    name: []u8,
    cache_ref: *paged.CacheRef,
    write_buffer: usize,

    pub fn init(
        gpa: Allocator,
        storage: Storage,
        name: []const u8,
        cache_ref: *paged.CacheRef,
        write_buffer: usize,
    ) Allocator.Error!Partition {
        assert(write_buffer > 0);
        assert(name.len > 0);
        return .{
            .gpa = gpa,
            .storage = storage,
            .name = try gpa.dupe(u8, name),
            .cache_ref = cache_ref,
            .write_buffer = write_buffer,
        };
    }

    pub fn deinit(self: *Partition) void {
        self.gpa.free(self.name);
        self.* = undefined;
    }

    /// Open `index` under recovery ownership (it may be truncated), creating it if missing.
    pub fn open_recovery(self: *Partition, index: u64) Error!Writer {
        const opened = try self.storage.open(self.name, &manager_mod.section_name(index));
        errdefer opened.blob.close();
        const capacity = self.write_buffer;
        return Writer.open_recovery(self.gpa, opened.blob, opened.len, capacity, self.cache_ref);
    }

    /// Open `index` as an append-only writer, creating it if missing.
    pub fn open(self: *Partition, index: u64) Error!Writer {
        var writer = try self.open_recovery(index);
        writer.finish_recovery();
        assert(writer.phase == .append);
        return writer;
    }

    pub fn remove(self: *Partition, index: u64) Error!void {
        try self.storage.remove(self.name, &manager_mod.section_name(index));
    }
};

/// Sorted blob indexes in `name`, treating a missing partition as empty. Caller frees.
pub fn indices(gpa: Allocator, storage: Storage, name: []const u8) Error![]u64 {
    return manager_mod.stored_sections(gpa, storage, name) catch |err| return @errorCast(err);
}

/// Remove an entire partition, treating "already missing" as success.
pub fn remove_all(storage: Storage, name: []const u8) Error!void {
    storage.remove(name, null) catch |err| switch (err) {
        error.PartitionMissing => {},
        else => return err,
    };
}

/// The blob partition chosen for a prefix, with the blob indexes found in it.
pub const Selected = struct {
    /// Owned partition name.
    name: []u8,
    /// Owned sorted blob indexes.
    indices: []u64,

    pub fn deinit(self: *Selected, gpa: Allocator) void {
        gpa.free(self.name);
        gpa.free(self.indices);
        self.* = undefined;
    }
};

/// Select the blob partition for `prefix` with legacy-first compatibility: the legacy
/// partition (`prefix` itself) if it holds data, otherwise `{prefix}-blobs`. Both holding
/// data is corruption.
pub fn select(gpa: Allocator, storage: Storage, prefix: []const u8) Error!Selected {
    const new_partition = try std.mem.concat(gpa, u8, &.{ prefix, "-blobs" });
    errdefer gpa.free(new_partition);
    const legacy = try indices(gpa, storage, prefix);
    errdefer gpa.free(legacy);
    const current = try indices(gpa, storage, new_partition);
    errdefer gpa.free(current);
    if (legacy.len > 0 and current.len > 0) return error.Corruption;
    if (legacy.len == 0) {
        gpa.free(legacy);
        return .{ .name = new_partition, .indices = current };
    }
    gpa.free(current);
    gpa.free(new_partition);
    return .{ .name = try gpa.dupe(u8, prefix), .indices = legacy };
}

/// A recovered blob awaiting publication, keyed by index.
pub const PendingBlob = struct { index: u64, writer: Writer };

/// A journal's blobs: contiguous sealed blobs ending in one writable tail.
pub const Writable = struct {
    partition: Partition,
    /// The writable tail.
    tail: Writer,
    /// Index of the first blob in `sealed`.
    oldest_blob_index: u64,
    /// Sealed (fully synced) historical blobs.
    sealed: std.ArrayList(Writer) = .empty,
    /// Metrics: blob sync requests and pruned blobs (`tracked` is `sealed.items.len + 1`).
    synced: u64 = 0,
    pruned: u64 = 0,
    /// Set while `clear` has closed the tail; a failed reopen leaves it set for `deinit`.
    tail_closed: bool = false,

    /// Build from recovered writers (ascending, contiguous, none above `tail_blob`, ending at
    /// it): seal every blob below `tail_blob` and install the tail, opening an empty one if
    /// absent. Takes ownership of `partition` and of every pending writer, also on error.
    pub fn recover(partition_in: Partition, pending: []PendingBlob, tail_blob: u64) Error!Writable {
        var partition = partition_in;
        var taken: usize = 0;
        errdefer for (pending[taken..]) |*entry| entry.writer.deinit();
        errdefer partition.deinit();
        if (pending.len > 0 and pending[pending.len - 1].index > tail_blob) {
            return error.Corruption;
        }
        var sealed: std.ArrayList(Writer) = .empty;
        errdefer {
            for (sealed.items) |*writer| writer.deinit();
            sealed.deinit(partition.gpa);
        }
        try sealed.ensureTotalCapacity(partition.gpa, pending.len);
        var tail: ?Writer = null;
        errdefer if (tail) |*writer| writer.deinit();
        for (pending, 0..) |*entry, position| {
            // Retained blobs must be contiguous.
            if (position > 0 and pending[position - 1].index + 1 != entry.index) {
                return error.Corruption;
            }
            taken += 1;
            entry.writer.finish_recovery();
            if (entry.index == tail_blob) {
                tail = entry.writer;
            } else {
                sealed.appendAssumeCapacity(entry.writer);
                try sealed.items[sealed.items.len - 1].sync();
            }
        }
        // The retained blobs must reach the tail.
        const count: u64 = sealed.items.len;
        if (count > tail_blob) return error.Corruption;
        if (count > 0 and pending[0].index != tail_blob - count) return error.Corruption;
        const tail_writer = tail orelse try partition.open(tail_blob);
        return .{
            .partition = partition,
            .tail = tail_writer,
            .oldest_blob_index = tail_blob - count,
            .sealed = sealed,
        };
    }

    /// Close every blob (dropping unsynced data) and free the partition.
    pub fn deinit(self: *Writable) void {
        for (self.sealed.items) |*writer| writer.deinit();
        self.sealed.deinit(self.partition.gpa);
        if (!self.tail_closed) self.tail.deinit();
        self.partition.deinit();
        self.* = undefined;
    }

    pub fn tail_blob_index(self: *const Writable) u64 {
        return self.oldest_blob_index + self.sealed.items.len;
    }

    /// The writer of a retained blob.
    pub fn get(self: *Writable, index: u64) ?*Writer {
        if (index < self.oldest_blob_index) return null;
        const offset = index - self.oldest_blob_index;
        if (offset < self.sealed.items.len) return &self.sealed.items[@intCast(offset)];
        if (index == self.tail_blob_index()) return &self.tail;
        return null;
    }

    /// Seal the full tail (making it durable) and open the next blob as the new tail.
    pub fn seal_tail(self: *Writable) Error!void {
        const next_blob = std.math.add(u64, self.tail_blob_index(), 1) catch
            return error.OffsetOverflow;
        try self.sealed.ensureUnusedCapacity(self.partition.gpa, 1);
        try self.tail.sync();
        self.synced += 1;
        const next = try self.partition.open(next_blob);
        self.sealed.appendAssumeCapacity(self.tail);
        self.tail = next;
        assert(self.tail_blob_index() == next_blob);
    }

    /// Drop every blob below `min_blob` and remove its file, oldest first.
    /// Requires `oldest_blob_index < min_blob <= tail_blob_index`.
    pub fn prune(self: *Writable, min_blob: u64) Error!void {
        assert(self.oldest_blob_index < min_blob and min_blob <= self.tail_blob_index());
        const drop_count: usize = @intCast(min_blob - self.oldest_blob_index);
        for (self.sealed.items[0..drop_count]) |*writer| writer.deinit();
        const kept = self.sealed.items.len - drop_count;
        std.mem.copyForwards(Writer, self.sealed.items[0..kept], self.sealed.items[drop_count..]);
        self.sealed.items.len = kept;
        const previous = self.oldest_blob_index;
        self.oldest_blob_index = min_blob;
        var blob = previous;
        while (blob < min_blob) : (blob += 1) {
            try self.partition.remove(blob);
            self.pruned += 1;
        }
    }

    /// Remove every blob and start an empty journal with its tail at `tail_blob`.
    pub fn clear(self: *Writable, tail_blob: u64) Error!void {
        const newest = self.tail_blob_index();
        for (self.sealed.items) |*writer| writer.deinit();
        self.sealed.clearRetainingCapacity();
        self.tail_closed = true;
        self.tail.deinit();
        var blob = self.oldest_blob_index;
        while (blob <= newest) : (blob += 1) try self.partition.remove(blob);
        self.oldest_blob_index = tail_blob;
        self.tail = try self.partition.open(tail_blob);
        self.tail_closed = false;
        assert(self.tail_blob_index() == tail_blob);
    }

    /// Make the tail durable (every sealed blob already is).
    pub fn sync(self: *Writable) Error!void {
        try self.tail.sync();
        self.synced += 1;
    }

    /// Remove every blob and the partition, freeing the blobs.
    pub fn destroy(self: *Writable) Error!void {
        const newest = self.tail_blob_index();
        const oldest = self.oldest_blob_index;
        assert(!self.tail_closed);
        for (self.sealed.items) |*writer| writer.deinit();
        self.sealed.deinit(self.partition.gpa);
        self.tail.deinit();
        var partition = self.partition;
        self.* = undefined;
        defer partition.deinit();
        var blob = oldest;
        while (blob <= newest) : (blob += 1) try partition.remove(blob);
        try remove_all(partition.storage, partition.name);
    }
};
