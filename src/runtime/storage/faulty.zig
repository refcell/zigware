//! Storage fault injection (commonware `runtime/src/storage/faulty.rs`) over the in-memory
//! backend, for crash-recovery tests on the deterministic runtime.
//!
//! Every operation may fail with `error.Io` at its configured rate (`Config`), drawn from the
//! runtime RNG, so a seed replays the same faults. Rates of zero or one draw nothing.
//!
//! Crash outcomes: unsynced writes and resizes are journaled with the policy in force when
//! they were issued (`WriteConfig.retention_rate`, `ResizeConfig.failure_rate`). `crash`
//! replays the journal in issue order onto the durable contents: a write keeps the bytes its
//! retention selects (a prefix, or an independent subset), and a selected resize is applied.
//! A failed write may durably keep part of its bytes at once, and a failed resize may leave an
//! intermediate size. `sync` (and a `WriteOptions.sync` write over its own range) retires the
//! journal it covers; a successful open retires the blob's journal, since the new handle sees
//! only durable contents (commonware's deterministic `Context::open_versioned` admits it).
//!
//! `start_sync` rolls its fault at start and starts the inner blob's sync without waiting; the
//! journal keeps the cut (commonware `PendingMutation::Sync`), which a crash honors only if
//! the sync succeeded. Over the memory backend the sync completes at once and settles as
//! `sync` does. With `io` set, each handle serializes its mutations and sync starts (commonware
//! `FileGeneration::mutation`), for an inner blob that blocks mid-operation (`wrap`).
//!
//! Differences from commonware: a journaled mutation is identified by the memory backend's
//! blob generation rather than by a shared file-generation handle; both retire on the same
//! events. A cut settles at a crash rather than when its completion is awaited; the replay is
//! the same. Only the deterministic runtime uses this wrapper, from one thread, so the journal
//! itself has no lock.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const iface = @import("../storage.zig");
const memory = @import("memory.zig");

const Error = iface.Error;
const Completion = iface.Completion;
const Io = std.Io;
pub const Probability = utils.Probability;

/// Operation kinds that can fail.
pub const Op = enum { open, read, write, sync, resize, remove, scan };

/// How a write's submitted bytes are retained; both leave bytes outside the write untouched.
pub const PartialWriteMode = enum {
    /// Bytes from the start of the write up to the first omitted byte.
    prefix,
    /// Each byte independently.
    subset,
};

/// Faults of `write_at`, and retention of failed writes and of unsynced writes at a crash.
pub const WriteConfig = struct {
    /// Probability that `write_at` fails.
    failure_rate: Probability,
    /// Probability the selected mode uses to retain each submitted byte.
    retention_rate: Probability,
    mode: PartialWriteMode,
};

/// Faults of `resize`.
pub const ResizeConfig = struct {
    /// Probability that `resize` fails; also, independently, that a successful unsynced
    /// resize survives a crash.
    failure_rate: Probability,
    /// Probability that a failed resize leaves an intermediate size.
    partial_rate: Probability,
};

/// Fault rates; null disables an operation's faults (commonware `faulty::Config`).
pub const Config = struct {
    open_rate: ?Probability = null,
    read_rate: ?Probability = null,
    write_rate: ?WriteConfig = null,
    sync_rate: ?Probability = null,
    resize_rate: ?ResizeConfig = null,
    remove_rate: ?Probability = null,
    scan_rate: ?Probability = null,

    /// The failure rate of `op`.
    pub fn rate_for(config: *const Config, op: Op) Probability {
        const rate: ?Probability = switch (op) {
            .open => config.open_rate,
            .read => config.read_rate,
            .write => if (config.write_rate) |write| write.failure_rate else null,
            .sync => config.sync_rate,
            .resize => if (config.resize_rate) |resize| resize.failure_rate else null,
            .remove => config.remove_rate,
            .scan => config.scan_rate,
        };
        return rate orelse .zero;
    }
};

/// A write's retention policy, snapshotted when it is issued.
pub const Policy = struct {
    mode: PartialWriteMode,
    rate: Probability,
};

/// The bytes of one journaled write and its retention, shared by the fragments a later sync
/// write leaves of it. The selection is drawn at the first crash that replays it.
const Retention = struct {
    policy: Policy,
    bytes: []u8,
    selected: ?[]bool = null,
    fragments: u32 = 1,
};

/// A journaled mutation whose crash outcome is unresolved.
const Pending = struct {
    /// The memory backend's generation of the blob incarnation (unique across blobs).
    generation: u64,
    data_offset: u64,
    kind: union(enum) {
        /// Bytes `retention.bytes[start..end]` written at logical `offset`.
        write: struct { offset: u64, retention: *Retention, start: usize, end: usize },
        /// A successful resize selected to survive a crash.
        resize: u64,
        /// A started sync not yet complete (commonware `PendingMutation::Sync`): once its
        /// completion succeeds, the generation's earlier entries no longer replay at a crash.
        sync: Completion,
    },
};

/// Draws which of `len` submitted bytes survive (commonware `Oracle::retained_bytes`).
pub fn retained_bytes(gpa: Allocator, rng: anytype, len: usize, policy: Policy) ![]bool {
    const selected = try gpa.alloc(bool, len);
    switch (policy.mode) {
        .prefix => {
            var kept: usize = 0;
            while (kept < len and policy.rate.sample(rng)) kept += 1;
            @memset(selected[0..kept], true);
            @memset(selected[kept..], false);
        },
        .subset => for (selected) |*keep| {
            keep.* = policy.rate.sample(rng);
        },
    }
    assert(selected.len == len);
    return selected;
}

/// A value strictly between `from` and `to`, if one exists (commonware `random_between`).
fn random_between(rng: anytype, from: u64, to: u64) ?u64 {
    const low = @min(from, to);
    const high = @max(from, to);
    if (high - low <= 1) return null;
    const value = utils.rng.range_less_than(rng, u64, low + 1, high);
    assert(value > low and value < high);
    return value;
}

fn coalesce(gpa: Allocator, chunks: []const []const u8, total: usize) ![]u8 {
    const bytes = try gpa.alloc(u8, total);
    var position: usize = 0;
    for (chunks) |chunk| {
        @memcpy(bytes[position..][0..chunk.len], chunk);
        position += chunk.len;
    }
    assert(position == total);
    return bytes;
}

/// Fault-injecting storage over `memory.Storage`, drawing from `*Rng` (a `utils.rng`
/// generator, the runtime RNG in the deterministic runner).
pub fn Storage(comptime Rng: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        inner: *memory.Storage,
        rng: *Rng,
        /// Fault rates; change them at any time.
        config: Config,
        /// Journal of mutations, in issue order.
        pending: std.ArrayList(Pending) = .empty,
        /// Every handle not yet closed.
        handles: std.DoublyLinkedList = .{},
        /// When set, each handle serializes its mutations and sync starts on a lock (commonware's
        /// `FileGeneration::mutation`), for inner blobs that block mid-operation. The memory
        /// backend completes every operation at once, so the deterministic runner leaves it null.
        io: ?Io = null,

        pub fn init(gpa: Allocator, inner: *memory.Storage, rng: *Rng, config: Config) Self {
            return .{ .gpa = gpa, .inner = inner, .rng = rng, .config = config };
        }

        /// Closes handles left open and drops the journal. Call before the inner deinit.
        pub fn deinit(self: *Self) void {
            while (self.handles.popFirst()) |node| {
                const blob: *Blob = @fieldParentPtr("node", node);
                blob.inner.close();
                self.gpa.destroy(blob);
            }
            for (self.pending.items) |*mutation| self.release(mutation);
            self.pending.deinit(self.gpa);
            self.* = undefined;
        }

        /// The `Storage` interface of this wrapper.
        pub fn storage(self: *Self) iface.Storage {
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
            versions: iface.VersionRange,
        ) Error!iface.Opened {
            const self: *Self = @ptrCast(@alignCast(ptr));
            return self.open_versioned(partition, name, versions);
        }

        fn remove_erased(ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            return self.remove(partition, name);
        }

        fn scan_erased(ptr: *anyopaque, gpa: Allocator, partition: []const u8) Error!iface.Names {
            const self: *Self = @ptrCast(@alignCast(ptr));
            return self.scan(gpa, partition);
        }

        fn should_fail(self: *Self, op: Op) bool {
            return self.config.rate_for(op).sample(self.rng);
        }

        pub fn open(self: *Self, partition: []const u8, name: []const u8) Error!iface.Opened {
            return self.open_versioned(partition, name, .only(iface.default_blob_version));
        }

        pub fn open_versioned(
            self: *Self,
            partition: []const u8,
            name: []const u8,
            versions: iface.VersionRange,
        ) Error!iface.Opened {
            if (self.should_fail(.open)) return error.Io;
            const opened = try self.inner.open_versioned(partition, name, versions);
            errdefer opened.blob.close();
            const inner_blob: *memory.Blob = @ptrCast(@alignCast(opened.blob.ptr));
            const generation = inner_blob.generation;
            const blob = try self.wrap(opened.blob, generation, inner_blob.data_offset, opened.len);
            // The new handle sees only durable contents: retire this incarnation's journal.
            self.retire(generation);
            return .{ .blob = blob, .len = opened.len, .version = opened.version };
        }

        /// Wraps `inner` (taken), which reaches the memory backend's blob incarnation
        /// `generation`, possibly through another blob such as a test gate, so crash replay
        /// reaches its durable contents (commonware's `Blob::new`).
        pub fn wrap(
            self: *Self,
            inner: iface.Blob,
            generation: u64,
            data_offset: u64,
            size: u64,
        ) Allocator.Error!iface.Blob {
            const blob = try self.gpa.create(Blob);
            blob.* = .{
                .storage = self,
                .inner = inner,
                .generation = generation,
                .data_offset = data_offset,
                .size = size,
            };
            self.handles.append(&blob.node);
            assert(blob.generation == generation);
            return blob.blob();
        }

        /// Removes a blob or a partition and retires the journal of what was removed.
        pub fn remove(self: *Self, partition: []const u8, name: ?[]const u8) Error!void {
            if (self.should_fail(.remove)) return error.Io;
            try self.inner.remove(partition, name);
            self.retire(null);
        }

        pub fn scan(self: *Self, gpa: Allocator, partition: []const u8) Error!iface.Names {
            if (self.should_fail(.scan)) return error.Io;
            return self.inner.scan(gpa, partition);
        }

        /// Replays the journal in issue order onto the durable contents and clears it
        /// (commonware `faulty::Storage::crash`). The runner then crashes the memory backend.
        /// A started sync covers the generation's entries before it only if its completion
        /// succeeded by now.
        pub fn crash(self: *Self) Error!void {
            var journal = self.pending;
            self.pending = .empty;
            defer {
                for (journal.items) |*mutation| self.release(mutation);
                journal.deinit(self.gpa);
            }
            var synced: std.ArrayList(u64) = .empty;
            defer synced.deinit(self.gpa);
            const skip = try self.gpa.alloc(bool, journal.items.len);
            defer self.gpa.free(skip);
            // Newest first, so a succeeded cut covers every entry issued before it.
            var index = journal.items.len;
            while (index > 0) {
                index -= 1;
                const mutation = &journal.items[index];
                const covered = std.mem.indexOfScalar(u64, synced.items, mutation.generation);
                skip[index] = covered != null or mutation.kind == .sync;
                if (mutation.kind != .sync or covered != null) continue;
                const done = mutation.kind.sync.poll() orelse continue;
                if (done) |_| try synced.append(self.gpa, mutation.generation) else |_| {}
            }
            for (journal.items, skip) |*mutation, skipped| {
                if (!skipped) try self.replay(mutation);
            }
            assert(self.pending.items.len == 0);
        }

        fn replay(self: *Self, mutation: *const Pending) Error!void {
            switch (mutation.kind) {
                .write => |write| {
                    const retention = write.retention;
                    if (retention.selected == null) {
                        const len = retention.bytes.len;
                        retention.selected =
                            try retained_bytes(self.gpa, self.rng, len, retention.policy);
                    }
                    const physical = std.math.add(u64, write.offset, mutation.data_offset) catch
                        return error.OffsetOverflow;
                    try self.inner.retain_crash_write(
                        mutation.generation,
                        physical,
                        retention.bytes[write.start..write.end],
                        retention.selected.?[write.start..write.end],
                    );
                },
                .resize => |length| {
                    const physical = std.math.add(u64, length, mutation.data_offset) catch
                        return error.OffsetOverflow;
                    try self.inner.retain_crash_resize(mutation.generation, physical);
                },
                .sync => unreachable, // `crash` skips sync cuts.
            }
        }

        /// Frees a journal entry's share of its write.
        fn release(self: *Self, mutation: *Pending) void {
            switch (mutation.kind) {
                .write => |write| {
                    const retention = write.retention;
                    assert(retention.fragments > 0);
                    retention.fragments -= 1;
                    if (retention.fragments > 0) return;
                    if (retention.selected) |selected| self.gpa.free(selected);
                    self.gpa.free(retention.bytes);
                    self.gpa.destroy(retention);
                },
                .resize => {},
                .sync => |completion| completion.release(),
            }
        }

        /// Drops the journal of `generation`, or, when null, of every incarnation that is no
        /// longer live (removed blobs). Keeps the rest in issue order.
        fn retire(self: *Self, generation: ?u64) void {
            var kept: usize = 0;
            for (self.pending.items) |*mutation| {
                const drop = if (generation) |target|
                    mutation.generation == target
                else
                    !self.inner.generation_live(mutation.generation);
                if (drop) {
                    self.release(mutation);
                } else {
                    self.pending.items[kept] = mutation.*;
                    kept += 1;
                }
            }
            assert(kept <= self.pending.items.len);
            self.pending.shrinkRetainingCapacity(kept);
        }

        /// Journals an unsynced write; takes ownership of `bytes`.
        fn record_write(
            self: *Self,
            blob: *const Blob,
            offset: u64,
            bytes: []u8,
            policy: Policy,
        ) Allocator.Error!void {
            errdefer self.gpa.free(bytes);
            if (bytes.len == 0) return self.gpa.free(bytes);
            const retention = try self.gpa.create(Retention);
            errdefer self.gpa.destroy(retention);
            retention.* = .{ .policy = policy, .bytes = bytes };
            try self.pending.append(self.gpa, .{
                .generation = blob.generation,
                .data_offset = blob.data_offset,
                .kind = .{ .write = .{
                    .offset = offset,
                    .retention = retention,
                    .start = 0,
                    .end = bytes.len,
                } },
            });
        }

        fn record_resize(self: *Self, blob: *const Blob, length: u64) Allocator.Error!void {
            try self.pending.append(self.gpa, .{
                .generation = blob.generation,
                .data_offset = blob.data_offset,
                .kind = .{ .resize = length },
            });
        }

        /// Retires journaled bytes of `blob` that `offset..offset + bytes.len` made durable,
        /// splitting partly covered writes, and journals the range again after any earlier
        /// resize so a replayed resize cannot undo it (commonware `record_durable_range`).
        fn record_durable_range(
            self: *Self,
            blob: *const Blob,
            offset: u64,
            bytes: []const u8,
        ) Allocator.Error!void {
            if (bytes.len == 0) return;
            const end = offset + bytes.len;
            var retained: std.ArrayList(Pending) = .empty;
            // Each write splits into at most two fragments.
            try retained.ensureTotalCapacity(self.gpa, self.pending.items.len * 2);
            var follows_resize = false;
            for (self.pending.items) |*mutation| {
                if (mutation.generation != blob.generation) {
                    retained.appendAssumeCapacity(mutation.*);
                    continue;
                }
                switch (mutation.kind) {
                    .resize => {
                        follows_resize = true;
                        retained.appendAssumeCapacity(mutation.*);
                    },
                    .sync => retained.appendAssumeCapacity(mutation.*),
                    .write => self.split_write(&retained, mutation, offset, end),
                }
            }
            assert(retained.items.len <= self.pending.items.len * 2);
            self.pending.deinit(self.gpa);
            self.pending = retained;
            if (follows_resize) {
                const copy = try self.gpa.dupe(u8, bytes);
                try self.record_write(blob, offset, copy, .{ .mode = .prefix, .rate = .one });
            }
        }

        /// Appends the parts of journaled write `mutation` outside `offset..end` to
        /// `retained` (capacity reserved) and drops `mutation`'s own share of its write.
        fn split_write(
            self: *Self,
            retained: *std.ArrayList(Pending),
            mutation: *Pending,
            offset: u64,
            end: u64,
        ) void {
            const write = mutation.kind.write;
            const write_end = write.offset + (write.end - write.start);
            const overlap_start = @max(write.offset, offset);
            const overlap_end = @min(write_end, end);
            if (overlap_start >= overlap_end) {
                retained.appendAssumeCapacity(mutation.*);
                return;
            }
            var piece = mutation.*;
            if (overlap_start > write.offset) {
                const prefix_len: usize = @intCast(overlap_start - write.offset);
                piece.kind.write.end = write.start + prefix_len;
                retained.appendAssumeCapacity(piece);
                write.retention.fragments += 1;
            }
            if (overlap_end < write_end) {
                piece.kind.write = .{
                    .offset = overlap_end,
                    .retention = write.retention,
                    .start = write.start + @as(usize, @intCast(overlap_end - write.offset)),
                    .end = write.end,
                };
                retained.appendAssumeCapacity(piece);
                write.retention.fragments += 1;
            }
            self.release(mutation);
        }

        /// Draws a resize's faults (commonware `check_resize_fault`): whether it fails, its
        /// partial rate, and whether a successful resize survives a crash.
        fn resize_fault(self: *Self) struct { fail: bool, partial: Probability, retain: bool } {
            const config = self.config.resize_rate orelse
                return .{ .fail = false, .partial = .zero, .retain = false };
            const fail = config.failure_rate.sample(self.rng);
            const retain = !fail and config.failure_rate.sample(self.rng);
            assert(!(fail and retain));
            return .{ .fail = fail, .partial = config.partial_rate, .retain = retain };
        }

        /// The retention policy of new writes, or null when writes are never retained.
        fn write_policy(self: *const Self) ?Policy {
            const config = self.config.write_rate orelse return null;
            if (config.retention_rate.is_zero()) return null;
            return .{ .mode = config.mode, .rate = config.retention_rate };
        }

        /// An open blob that injects faults.
        pub const Blob = struct {
            storage: *Self,
            node: std.DoublyLinkedList.Node = .{},
            inner: iface.Blob,
            generation: u64,
            data_offset: u64,
            /// Logical size as this handle last set it, for partial resizes.
            size: u64,
            /// Serializes mutations and sync starts when the storage has an `Io`.
            mutation: Io.Mutex = .init,

            /// The `Blob` interface of this handle.
            pub fn blob(self: *Blob) iface.Blob {
                return .{ .ptr = self, .vtable = &blob_vtable };
            }

            const blob_vtable: iface.Blob.VTable = .{
                .read_at = read_at_erased,
                .write_at = write_at_erased,
                .resize = resize_erased,
                .sync = sync_erased,
                .start_sync = start_sync_erased,
                .close = close_erased,
                .io = io_erased,
            };

            fn from(ptr: *anyopaque) *Blob {
                return @ptrCast(@alignCast(ptr));
            }

            fn io_erased(ptr: *anyopaque) ?Io {
                return from(ptr).inner.io();
            }

            fn read_at_erased(
                ptr: *anyopaque,
                offset: u64,
                buffer: []u8,
                options: iface.ReadOptions,
            ) Error!void {
                return from(ptr).read_at(offset, buffer, options);
            }

            fn write_at_erased(
                ptr: *anyopaque,
                offset: u64,
                chunks: []const []const u8,
                options: iface.WriteOptions,
            ) Error!void {
                return from(ptr).write_at(offset, chunks, options);
            }

            fn resize_erased(ptr: *anyopaque, length: u64) Error!void {
                return from(ptr).resize(length);
            }

            fn sync_erased(ptr: *anyopaque) Error!void {
                return from(ptr).sync();
            }

            fn start_sync_erased(ptr: *anyopaque) Error!Completion {
                return from(ptr).start_sync();
            }

            fn lock(self: *Blob) Io.Cancelable!void {
                const io = self.storage.io orelse return;
                try self.mutation.lock(io);
            }

            fn unlock(self: *Blob) void {
                const io = self.storage.io orelse return;
                self.mutation.unlock(io);
            }

            fn close_erased(ptr: *anyopaque) void {
                from(ptr).close();
            }

            pub fn read_at(
                self: *Blob,
                offset: u64,
                buffer: []u8,
                options: iface.ReadOptions,
            ) Error!void {
                if (self.storage.should_fail(.read)) return error.Io;
                return self.inner.read_at_options(offset, buffer, options);
            }

            pub fn write_at(
                self: *Blob,
                offset: u64,
                chunks: []const []const u8,
                options: iface.WriteOptions,
            ) Error!void {
                var total: u64 = 0;
                for (chunks) |chunk| total = std.math.add(u64, total, chunk.len) catch
                    return error.OffsetOverflow;
                if (options.sync and total == 0) return;
                const end = std.math.add(u64, offset, total) catch return error.OffsetOverflow;
                const owner = self.storage;
                const fail = owner.should_fail(.write);
                const policy = owner.write_policy();
                const gpa = owner.gpa;
                const bytes = try coalesce(gpa, chunks, @intCast(total));
                defer gpa.free(bytes);
                try self.lock();
                defer self.unlock();
                if (fail) {
                    if (policy) |retention| {
                        try self.write_retained(offset, bytes, retention, options);
                    }
                    return error.Io;
                }
                if (options.sync and owner.should_fail(.sync)) {
                    var unsynced = options;
                    unsynced.sync = false;
                    try self.inner.write_at(offset, bytes, unsynced);
                    self.size = @max(self.size, end);
                    if (policy) |retention| {
                        try owner.record_write(self, offset, try gpa.dupe(u8, bytes), retention);
                    }
                    return error.Io;
                }
                try self.inner.write_at(offset, bytes, options);
                self.size = @max(self.size, end);
                if (options.sync) {
                    try owner.record_durable_range(self, offset, bytes);
                } else if (policy) |retention| {
                    try owner.record_write(self, offset, try gpa.dupe(u8, bytes), retention);
                }
            }

            /// A failed write durably keeps the runs of bytes `policy` selects.
            fn write_retained(
                self: *Blob,
                offset: u64,
                bytes: []const u8,
                policy: Policy,
                options: iface.WriteOptions,
            ) Error!void {
                const owner = self.storage;
                const selected = try retained_bytes(owner.gpa, owner.rng, bytes.len, policy);
                defer owner.gpa.free(selected);
                var durable = options;
                durable.sync = true;
                var position: usize = 0;
                while (position < bytes.len) {
                    if (!selected[position]) {
                        position += 1;
                        continue;
                    }
                    const start = position;
                    while (position < bytes.len and selected[position]) position += 1;
                    const run_offset = offset + start;
                    const run = bytes[start..position];
                    try self.inner.write_at(run_offset, run, durable);
                    try owner.record_durable_range(self, run_offset, run);
                    self.size = @max(self.size, run_offset + run.len);
                }
                assert(position == bytes.len);
            }

            pub fn resize(self: *Blob, length: u64) Error!void {
                const owner = self.storage;
                const fault = owner.resize_fault();
                try self.lock();
                defer self.unlock();
                if (fault.fail) {
                    if (!fault.partial.sample(owner.rng)) return error.Io;
                    const partial = random_between(owner.rng, self.size, length) orelse
                        return error.Io;
                    try self.inner.resize(partial);
                    try owner.record_resize(self, partial);
                    self.size = partial;
                    return error.Io;
                }
                try self.inner.resize(length);
                if (fault.retain) try owner.record_resize(self, length);
                self.size = length;
            }

            /// Makes the handle's contents durable and retires its journal.
            pub fn sync(self: *Blob) Error!void {
                if (self.storage.should_fail(.sync)) return error.Io;
                try self.lock();
                defer self.unlock();
                try self.inner.sync();
                self.storage.retire(self.generation);
            }

            /// Starts the inner blob's sync and returns its completion (commonware's
            /// `start_sync`), without waiting for it: a later write proceeds while it runs. The
            /// journal keeps the cut until a crash, where it covers earlier entries only if the
            /// sync succeeded; a sync already complete settles at once, as `sync` would.
            pub fn start_sync(self: *Blob) Error!Completion {
                const owner = self.storage;
                if (owner.should_fail(.sync)) return Completion.ready(error.Io);
                try self.lock();
                defer self.unlock();
                const completion = try self.inner.start_sync();
                if (completion.poll()) |result| {
                    if (result) |_| owner.retire(self.generation) else |_| {}
                    return completion;
                }
                owner.pending.append(owner.gpa, .{
                    .generation = self.generation,
                    .data_offset = self.data_offset,
                    .kind = .{ .sync = completion.retain() },
                }) catch |err| {
                    completion.release();
                    completion.release();
                    return err;
                };
                assert(owner.pending.items.len > 0);
                return completion;
            }

            /// Releases the handle; its journal stays until a sync, reopen, removal, or crash.
            pub fn close(self: *Blob) void {
                const owner = self.storage;
                self.inner.close();
                owner.handles.remove(&self.node);
                owner.gpa.destroy(self);
            }
        };
    };
}

test {
    _ = @import("faulty_test.zig");
    _ = @import("faulty_gate_test.zig");
}
