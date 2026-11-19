//! Blob management for a contiguous journal (commonware's `journal/contiguous/blobs.rs`).
//!
//! A journal's blobs are contiguous sealed blobs ending in one writable tail. A sealed blob is
//! a paged writer whose last started sync (the tail predecessor's) may still be in flight;
//! there is no separate `Sealed` view or snapshot.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const metrics = runtime.telemetry.metrics;
const manager_mod = @import("../segmented/manager.zig");
const journal = @import("../mod.zig");

const Storage = runtime.storage.Storage;
const Writer = paged.Writer;
const Completion = runtime.storage.Completion;

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

/// The blob manager's metrics (commonware's `contiguous/blobs.rs` `Metrics`).
pub const Metrics = struct {
    /// Blobs held.
    tracked: metrics.Gauge,
    /// Blob sync requests.
    synced: metrics.Counter,
    /// Blobs pruned.
    pruned: metrics.Counter,

    /// Help strings: commonware's contiguous and segmented managers word them differently.
    pub const Help = struct {
        tracked: []const u8,
        synced: []const u8,
        pruned: []const u8,
    };

    pub const contiguous_help: Help = .{
        .tracked = "Number of blobs held",
        .synced = "Number of blob sync requests",
        .pruned = "Number of blobs pruned",
    };

    /// Registers under `scope`, or records unregistered without one.
    pub fn init(gpa: Allocator, scope: ?metrics.Scope) Allocator.Error!Metrics {
        return init_with_help(gpa, scope, contiguous_help);
    }

    pub fn init_with_help(
        gpa: Allocator,
        scope: ?metrics.Scope,
        help: Help,
    ) Allocator.Error!Metrics {
        const s = scope orelse return .{
            .tracked = try metrics.Gauge.detached(gpa, .{}),
            .synced = try metrics.Counter.detached(gpa, .{}),
            .pruned = try metrics.Counter.detached(gpa, .{}),
        };
        var tracked = try s.gauge("tracked", help.tracked);
        errdefer tracked.deinit();
        var synced = try s.counter("synced", help.synced);
        errdefer synced.deinit();
        const pruned = try s.counter("pruned", help.pruned);
        return .{ .tracked = tracked, .synced = synced, .pruned = pruned };
    }

    pub fn deinit(self: *Metrics) void {
        self.tracked.deinit();
        self.synced.deinit();
        self.pruned.deinit();
        self.* = undefined;
    }
};

/// A journal's blobs: contiguous sealed blobs ending in one writable tail.
pub const Writable = struct {
    partition: Partition,
    /// The writable tail.
    tail: Writer,
    /// Index of the first blob in `sealed`.
    oldest_blob_index: u64,
    /// Sealed (fully synced) historical blobs.
    sealed: std.ArrayList(Writer) = .empty,
    metrics: Metrics,
    /// Set while `clear` has closed the tail; a failed reopen leaves it set for `deinit`.
    tail_closed: bool = false,
    /// The started sync of the tail's predecessor, sealed by `seal_tail` (commonware
    /// `tail_predecessor_sync`). Kept until a later operation observes it.
    tail_predecessor_sync: ?Completion = null,

    /// Build from recovered writers (ascending, contiguous, none above `tail_blob`, ending at
    /// it): seal every blob below `tail_blob` and install the tail, opening an empty one if
    /// absent. Takes ownership of `partition` and of every pending writer, also on error.
    /// Metrics register under `scope`.
    pub fn recover(
        partition_in: Partition,
        pending: []PendingBlob,
        tail_blob: u64,
        scope: ?metrics.Scope,
    ) Error!Writable {
        var partition = partition_in;
        var taken: usize = 0;
        errdefer for (pending[taken..]) |*entry| entry.writer.deinit();
        errdefer partition.deinit();
        var blob_metrics = try Metrics.init(partition.gpa, scope);
        errdefer blob_metrics.deinit();
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
        _ = blob_metrics.tracked.metric().set(@intCast(count + 1));
        return .{
            .partition = partition,
            .tail = tail_writer,
            .oldest_blob_index = tail_blob - count,
            .sealed = sealed,
            .metrics = blob_metrics,
        };
    }

    /// Close every blob (dropping unsynced data) and free the partition.
    pub fn deinit(self: *Writable) void {
        if (self.tail_predecessor_sync) |completion| completion.release();
        for (self.sealed.items) |*writer| writer.deinit();
        self.sealed.deinit(self.partition.gpa);
        if (!self.tail_closed) self.tail.deinit();
        self.partition.deinit();
        self.metrics.deinit();
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

    /// The writer of a retained blob, for reads.
    pub fn get_const(self: *const Writable, index: u64) ?*const Writer {
        if (index < self.oldest_blob_index) return null;
        const offset = index - self.oldest_blob_index;
        if (offset < self.sealed.items.len) return &self.sealed.items[@intCast(offset)];
        if (index == self.tail_blob_index()) return &self.tail;
        return null;
    }

    /// Seal the full tail, start syncing it, and open the next blob as the new tail. The
    /// sealed blob's sync stays in flight in `tail_predecessor_sync`.
    pub fn seal_tail(self: *Writable) Error!void {
        // Observe both outstanding syncs before creating a successor blob.
        try self.drain_tail_predecessor_sync();
        try self.tail.wait_for_sync();
        const next_blob = std.math.add(u64, self.tail_blob_index(), 1) catch
            return error.OffsetOverflow;
        try self.sealed.ensureUnusedCapacity(self.partition.gpa, 1);
        var next = try self.partition.open(next_blob);
        errdefer next.deinit();
        const completion = try self.tail.start_sync();
        self.metrics.synced.metric().inc();
        self.sealed.appendAssumeCapacity(self.tail);
        self.tail = next;
        self.metrics.tracked.metric().inc();
        assert(self.tail_predecessor_sync == null);
        self.tail_predecessor_sync = completion;
        assert(self.tail_blob_index() == next_blob);
    }

    /// Wait for the predecessor's started sync. A failure stays retained, so it surfaces again.
    fn drain_tail_predecessor_sync(self: *Writable) Error!void {
        const completion = self.tail_predecessor_sync orelse return;
        try completion.wait();
        completion.release();
        self.tail_predecessor_sync = null;
        assert(self.tail_predecessor_sync == null);
    }

    /// Wait for every started sync, surfacing a failure without changing any blob.
    pub fn wait_for_sync(self: *Writable) Error!void {
        try self.drain_tail_predecessor_sync();
        try self.tail.wait_for_sync();
        assert(self.tail_predecessor_sync == null);
    }

    /// Start syncing the tail, returning a completion (one reference, owned by the caller) for
    /// both the tail and its predecessor. At most one tail sync is in flight: an earlier one is
    /// waited for first; the predecessor's is joined, not waited for.
    pub fn start_sync(self: *Writable) Error!Completion {
        assert(!self.tail_closed);
        try self.tail.wait_for_sync();
        const tail_sync = try self.tail.start_sync();
        self.metrics.synced.metric().inc();
        const predecessor = self.tail_predecessor_sync orelse return tail_sync;
        // `join` consumes both references, also on error.
        return Completion.join(predecessor.retain(), tail_sync);
    }

    /// Drop every blob below `min_blob` and remove its file, oldest first.
    /// Requires `oldest_blob_index < min_blob <= tail_blob_index`.
    pub fn prune(self: *Writable, min_blob: u64) Error!void {
        assert(self.oldest_blob_index < min_blob and min_blob <= self.tail_blob_index());
        // Observe outstanding sync failures before removing any retained data.
        try self.wait_for_sync();
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
            self.metrics.tracked.metric().dec();
            self.metrics.pruned.metric().inc();
        }
    }

    /// Remove every blob and start an empty journal with its tail at `tail_blob`.
    pub fn clear(self: *Writable, tail_blob: u64) Error!void {
        // Observe outstanding sync failures before removing any retained data.
        try self.wait_for_sync();
        const newest = self.tail_blob_index();
        for (self.sealed.items) |*writer| writer.deinit();
        self.sealed.clearRetainingCapacity();
        self.tail_closed = true;
        self.tail.deinit();
        var blob = self.oldest_blob_index;
        while (blob <= newest) : (blob += 1) try self.partition.remove(blob);
        _ = self.metrics.tracked.metric().set(0);
        self.oldest_blob_index = tail_blob;
        self.tail = try self.partition.open(tail_blob);
        self.tail_closed = false;
        self.metrics.tracked.metric().inc();
        assert(self.tail_blob_index() == tail_blob);
    }

    /// Make the tail and its sealed predecessor durable (older sealed blobs already are).
    pub fn sync(self: *Writable) Error!void {
        try self.drain_tail_predecessor_sync();
        try self.tail.sync();
        self.metrics.synced.metric().inc();
    }

    /// Remove every blob and the partition, freeing the blobs.
    pub fn destroy(self: *Writable) Error!void {
        // A failed sync removes nothing.
        try self.wait_for_sync();
        const newest = self.tail_blob_index();
        const oldest = self.oldest_blob_index;
        assert(!self.tail_closed);
        for (self.sealed.items) |*writer| writer.deinit();
        self.sealed.deinit(self.partition.gpa);
        self.tail.deinit();
        self.metrics.deinit();
        var partition = self.partition;
        self.* = undefined;
        defer partition.deinit();
        var blob = oldest;
        while (blob <= newest) : (blob += 1) try partition.remove(blob);
        try remove_all(partition.storage, partition.name);
    }
};
