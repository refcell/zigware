//! Buffers for reading and writing to blobs (commonware's `runtime/src/utils/buffer`).
//!
//! Owned by the storage-journal lane (docs/lanes/storage-journal.md). Buffers wrap a
//! `runtime.storage.Blob`; `mocks` wraps the runtime's in-memory storage with commonware's
//! recording and mutation-fault mocks for tests.

const std = @import("std");
const assert = std.debug.assert;
const Blob = @import("../storage.zig").Blob;

pub const mocks = @import("mocks.zig");
pub const paged = @import("paged/mod.zig");

/// Tracks whether blob mutations still need a sync (commonware's `SyncState`).
///
/// commonware also tracks a started-but-unobserved sync (`Pending`). zigware's blobs sync
/// synchronously on the calling fiber, so `start_sync` completes the sync before returning and
/// a pending state never exists.
pub const SyncState = enum {
    /// No unsynced mutations.
    clean,
    /// Unsynced mutations need a sync.
    dirty,

    pub fn is_clean(self: SyncState) bool {
        return self == .clean;
    }

    /// Write `bytes` at `offset`; with `durable`, make it (and every earlier mutation) durable
    /// before returning.
    pub fn write_at(
        self: *SyncState,
        blob: Blob,
        offset: u64,
        bytes: []const u8,
        durable: bool,
    ) !void {
        try blob.write_at(offset, bytes, .{});
        if (!durable) {
            self.* = .dirty;
            return;
        }
        try blob.sync();
        self.* = .clean;
    }

    /// Resize the blob, requiring a later sync.
    pub fn resize(self: *SyncState, blob: Blob, len: u64) !void {
        try blob.resize(len);
        self.* = .dirty;
    }

    /// Make all pending mutations durable.
    pub fn sync(self: *SyncState, blob: Blob) !void {
        if (self.* == .clean) return;
        try blob.sync();
        self.* = .clean;
        assert(self.is_clean());
    }
};

test {
    std.testing.refAllDecls(@This());
}
