//! A small durable record that recovery reads before trusting anything on disk
//! (commonware's `journal/contiguous/checkpoint.rs`).
//!
//! A journal's contents are mostly recovered from its blobs: blob indexes give positions and
//! blob lengths give item counts. The checkpoint records the three facts blob state alone
//! cannot provide:
//!
//! - The pruning boundary, when it falls mid-blob (from `init_at_size`).
//! - The recovery watermark: a durable floor on the journal size. Items below it must survive
//!   a crash unless an initialization bound discards them.
//! - The clear target, while a clear is in progress: it is recorded before any blob is
//!   deleted, so a crash mid-clear is finished on reopen instead of misread as corruption.
//!
//! The journal keeps the checkpoint a safe under-estimate of what is on disk: an entry
//! advances only after the blob state it describes is durable, and is lowered before blob
//! state moves backward.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const VecU64 = @import("utils").sequence.VecU64;
const metadata_mod = @import("../../metadata/mod.zig");

const Storage = runtime.storage.Storage;
const Store = metadata_mod.Metadata(u64, VecU64);

/// Key of the mid-blob pruning boundary. Absent when the boundary is blob-aligned.
const pruning_boundary_key: u64 = 1;
/// Key of the target of an in-progress clear.
const clear_target_key: u64 = 2;
/// Key of the recovery watermark.
const recovery_watermark_key: u64 = 3;

pub const Error = Store.Error;

/// The journal's durable recovery checkpoint, stored in `{partition}-metadata`.
pub const Checkpoint = struct {
    metadata: Store,

    pub fn open(gpa: Allocator, storage: Storage, partition_prefix: []const u8) Error!Checkpoint {
        assert(partition_prefix.len > 0);
        const partition = try std.mem.concat(gpa, u8, &.{ partition_prefix, "-metadata" });
        defer gpa.free(partition);
        assert(partition.len > partition_prefix.len);
        return .{ .metadata = try Store.init(gpa, storage, .{
            .partition = partition,
            .codec_config = {},
        }) };
    }

    /// Close the store, dropping staged changes.
    pub fn deinit(self: *Checkpoint) void {
        self.metadata.deinit();
        self.* = undefined;
    }

    fn get(self: *const Checkpoint, key: u64) ?u64 {
        const value = self.metadata.get(key) orelse return null;
        return value.value;
    }

    fn put(self: *Checkpoint, key: u64, value: u64) Allocator.Error!void {
        _ = try self.metadata.put(key, .init(value));
        assert(self.get(key).? == value);
    }

    fn remove(self: *Checkpoint, key: u64) void {
        _ = self.metadata.remove(key);
        assert(self.get(key) == null);
    }

    /// The recovery watermark, if one has been recorded.
    pub fn watermark(self: *const Checkpoint) ?u64 {
        return self.get(recovery_watermark_key);
    }

    /// The recorded mid-blob pruning boundary, if any.
    pub fn boundary_hint(self: *const Checkpoint) ?u64 {
        return self.get(pruning_boundary_key);
    }

    /// The target of an in-progress clear, if one was staged.
    pub fn clear_target(self: *const Checkpoint) ?u64 {
        return self.get(clear_target_key);
    }

    /// Durably record the boundary and watermark, staging only entries that changed.
    pub fn persist(
        self: *Checkpoint,
        items_per_blob: u64,
        boundary: u64,
        watermark_new: u64,
    ) Error!void {
        assert(items_per_blob > 0);
        // A blob-aligned boundary is derived from the oldest blob, so the entry is only kept
        // while the boundary is mid-blob.
        if (boundary % items_per_blob == 0) {
            if (self.boundary_hint() != null) self.remove(pruning_boundary_key);
        } else if (self.boundary_hint() != boundary) {
            try self.put(pruning_boundary_key, boundary);
        }
        if (self.watermark() != watermark_new) try self.put(recovery_watermark_key, watermark_new);
        // Always sync: `lower_watermark` stages without syncing.
        try self.sync();
    }

    /// Raise the watermark to `watermark_new` (all items below it are durable). A value at or
    /// below the current one is ignored. Syncs complete synchronously (commonware's
    /// `start_watermark_sync`).
    pub fn start_watermark_sync(self: *Checkpoint, watermark_new: u64) Error!void {
        if (self.watermark()) |current| {
            if (current >= watermark_new) return;
        }
        try self.put(recovery_watermark_key, watermark_new);
        try self.sync();
    }

    /// Lower a recorded watermark to `limit` if it is higher, staging the change. Call this
    /// before blob state moves backward; the caller must sync it.
    pub fn lower_watermark(self: *Checkpoint, limit: u64) Allocator.Error!void {
        const current = self.watermark() orelse return;
        if (current > limit) try self.put(recovery_watermark_key, limit);
        assert(self.watermark().? <= @max(limit, current));
    }

    /// Durably record the intent to clear to `target`, lowering the watermark first.
    pub fn stage_clear(self: *Checkpoint, target: u64) Error!void {
        try self.lower_watermark(target);
        try self.put(clear_target_key, target);
        try self.sync();
    }

    /// Durably complete a clear to `target`: drop the intent and record `target` as both the
    /// boundary and the watermark.
    pub fn finish_clear(self: *Checkpoint, items_per_blob: u64, target: u64) Error!void {
        self.remove(clear_target_key);
        try self.persist(items_per_blob, target, target);
        assert(self.clear_target() == null);
    }

    /// Make staged entries durable.
    pub fn sync(self: *Checkpoint) Error!void {
        return self.metadata.sync();
    }

    /// Remove the checkpoint's partition, freeing the checkpoint.
    pub fn destroy(self: *Checkpoint) Error!void {
        defer self.* = undefined;
        return self.metadata.destroy();
    }

    // Direct-injection helpers for tests: plant states the production API never produces.

    /// Set the watermark directly, or remove it with null (a legacy journal).
    pub fn set_watermark(self: *Checkpoint, value: ?u64) Allocator.Error!void {
        if (value) |watermark_new| return self.put(recovery_watermark_key, watermark_new);
        self.remove(recovery_watermark_key);
    }

    /// Set the mid-blob pruning boundary directly.
    pub fn set_boundary_hint(self: *Checkpoint, boundary: u64) Allocator.Error!void {
        return self.put(pruning_boundary_key, boundary);
    }

    /// Stage a clear intent directly.
    pub fn set_clear_target(self: *Checkpoint, target: u64) Allocator.Error!void {
        return self.put(clear_target_key, target);
    }

    /// Remove every entry, simulating metadata corruption.
    pub fn clear(self: *Checkpoint) void {
        self.metadata.clear();
        assert(self.metadata.count() == 0);
    }
};

const testing = std.testing;
const mocks = runtime.buffer.mocks;

test "checkpoint: lower watermark only lowers" {
    var storage = mocks.Storage.init(testing.allocator);
    defer storage.deinit();
    var checkpoint = try Checkpoint.open(testing.allocator, storage.interface(), "lw");
    defer checkpoint.deinit();
    // Without a recorded watermark, lowering has no effect.
    try checkpoint.lower_watermark(5);
    try testing.expectEqual(null, checkpoint.watermark());
    try checkpoint.persist(10, 0, 8);
    // An equal or higher limit leaves the watermark unchanged.
    try checkpoint.lower_watermark(8);
    try testing.expectEqual(8, checkpoint.watermark());
    try checkpoint.lower_watermark(12);
    try testing.expectEqual(8, checkpoint.watermark());
    // A strictly lower limit lowers the watermark.
    try checkpoint.lower_watermark(3);
    try testing.expectEqual(3, checkpoint.watermark());
}

test "checkpoint: persist round trips across reopen" {
    var storage = mocks.Storage.init(testing.allocator);
    defer storage.deinit();
    {
        var checkpoint = try Checkpoint.open(testing.allocator, storage.interface(), "rt");
        defer checkpoint.deinit();
        // A mid-blob boundary is kept; the watermark is recorded.
        try checkpoint.persist(10, 13, 25);
    }
    var checkpoint = try Checkpoint.open(testing.allocator, storage.interface(), "rt");
    defer checkpoint.deinit();
    try testing.expectEqual(13, checkpoint.boundary_hint());
    try testing.expectEqual(25, checkpoint.watermark());
    try testing.expectEqual(null, checkpoint.clear_target());
}

test "checkpoint: persist boundary hint tracks alignment" {
    var storage = mocks.Storage.init(testing.allocator);
    defer storage.deinit();
    var checkpoint = try Checkpoint.open(testing.allocator, storage.interface(), "align");
    defer checkpoint.deinit();
    // A mid-blob boundary is recorded as a hint.
    try checkpoint.persist(10, 13, 0);
    try testing.expectEqual(13, checkpoint.boundary_hint());
    // A later blob-aligned boundary drops the stale hint.
    try checkpoint.persist(10, 20, 0);
    try testing.expectEqual(null, checkpoint.boundary_hint());
}

test "checkpoint: clear lifecycle survives crash" {
    var storage = mocks.Storage.init(testing.allocator);
    defer storage.deinit();
    {
        var checkpoint = try Checkpoint.open(testing.allocator, storage.interface(), "clear");
        defer checkpoint.deinit();
        try checkpoint.persist(10, 0, 30);
        // Staging records the intent and lowers the watermark to the target.
        try checkpoint.stage_clear(20);
        try testing.expectEqual(20, checkpoint.clear_target());
        try testing.expectEqual(20, checkpoint.watermark());
    }
    storage.crash();
    {
        // A crash after staging leaves the intent durable.
        var checkpoint = try Checkpoint.open(testing.allocator, storage.interface(), "clear");
        defer checkpoint.deinit();
        try testing.expectEqual(20, checkpoint.clear_target());
        // Completing drops the intent and records the target as boundary and watermark.
        try checkpoint.finish_clear(10, 20);
    }
    var checkpoint = try Checkpoint.open(testing.allocator, storage.interface(), "clear");
    defer checkpoint.deinit();
    try testing.expectEqual(null, checkpoint.clear_target());
    try testing.expectEqual(20, checkpoint.watermark());
    // 20 is blob-aligned, so no hint is retained.
    try testing.expectEqual(null, checkpoint.boundary_hint());
}

test "checkpoint: stage clear does not raise watermark" {
    var storage = mocks.Storage.init(testing.allocator);
    defer storage.deinit();
    var checkpoint = try Checkpoint.open(testing.allocator, storage.interface(), "sc");
    defer checkpoint.deinit();
    try checkpoint.persist(10, 0, 5);
    // A target above the current watermark records the intent but the watermark holds.
    try checkpoint.stage_clear(9);
    try testing.expectEqual(9, checkpoint.clear_target());
    try testing.expectEqual(5, checkpoint.watermark());
}
