//! Buffers for reading and writing to blobs (commonware's `runtime/src/utils/buffer`).
//!
//! Owned by the storage-journal lane (docs/lanes/storage-journal.md). Buffers wrap a
//! `runtime.storage.Blob`; `mocks` wraps the runtime's in-memory storage with commonware's
//! recording and mutation-fault mocks for tests.

const std = @import("std");
const assert = std.debug.assert;
const Blob = @import("../storage.zig").Blob;
const WriteOptions = @import("../storage.zig").WriteOptions;
const Completion = @import("../storage.zig").Completion;

pub const mocks = @import("mocks.zig");
pub const tip = @import("tip.zig");
pub const write = @import("write.zig");
pub const Write = write.Write;
pub const read = @import("read.zig");
pub const Read = read.Read;
pub const paged = @import("paged/mod.zig");

/// Tracks whether blob mutations still need a sync (commonware's `SyncState`).
///
/// - Every operation that mutates the blob first waits for an in-flight sync, so a started
///   sync's coverage is never disturbed by later writes.
/// - `start_sync` on a pending state returns another reference to the in-flight sync, so
///   re-requesting a sync is a cheap way to observe outstanding work.
/// - A failure is never lost: every reference reports it, and an unobserved failure surfaces
///   on the next `wait_for_pending`. The owner is failed after any failed operation (only
///   `deinit` may follow).
pub const SyncState = union(enum) {
    /// No unsynced mutations.
    clean,
    /// Unsynced mutations need a sync.
    dirty,
    /// A started sync is in flight or awaits observation; this is the state's reference.
    pending: Completion,

    pub fn is_clean(self: SyncState) bool {
        return self == .clean;
    }

    /// Return the pending reference, if any. The sync itself continues.
    pub fn deinit(self: *SyncState) void {
        switch (self.*) {
            .pending => |completion| completion.release(),
            .clean, .dirty => {},
        }
        self.* = .dirty;
        assert(!self.is_clean());
    }

    /// Wait for an in-flight sync before mutating the blob; on success the state is clean.
    pub fn wait_for_pending(self: *SyncState) !void {
        const completion = switch (self.*) {
            .pending => |completion| completion,
            .clean, .dirty => return,
        };
        // On failure the reference stays, so the failure surfaces again until `deinit`.
        try completion.wait();
        completion.release();
        self.* = .clean;
        assert(self.is_clean());
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
        return self.write_at_options(blob, offset, bytes, durable, .{});
    }

    /// `write_at` with the blob write's `options` (such as the `dont_cache` hint).
    pub fn write_at_options(
        self: *SyncState,
        blob: Blob,
        offset: u64,
        bytes: []const u8,
        durable: bool,
        options: WriteOptions,
    ) !void {
        return self.write_chunks(blob, offset, &.{bytes}, durable, options);
    }

    /// `write_at_options` of `chunks` written as one byte sequence.
    pub fn write_chunks(
        self: *SyncState,
        blob: Blob,
        offset: u64,
        chunks: []const []const u8,
        durable: bool,
        options: WriteOptions,
    ) !void {
        assert(!options.sync);
        try self.wait_for_pending();
        assert(self.* != .pending);
        if (durable and self.* == .clean) {
            // No earlier mutation is owed, so the write carries its own barrier (commonware's
            // `WriteOptions::SYNC`, one `RWF_DSYNC` write on Linux).
            var synced = options;
            synced.sync = true;
            try blob.write_at_vectored(offset, chunks, synced);
            assert(self.is_clean());
            return;
        }
        try blob.write_at_vectored(offset, chunks, options);
        if (!durable) {
            self.* = .dirty;
            return;
        }
        try blob.sync();
        self.* = .clean;
    }

    /// Resize the blob, requiring a later sync.
    pub fn resize(self: *SyncState, blob: Blob, len: u64) !void {
        try self.wait_for_pending();
        try blob.resize(len);
        self.* = .dirty;
        assert(!self.is_clean());
    }

    /// Make all pending mutations durable.
    pub fn sync(self: *SyncState, blob: Blob) !void {
        try self.wait_for_pending();
        if (self.* == .clean) return;
        try blob.sync();
        self.* = .clean;
        assert(self.is_clean());
    }

    /// Start making pending mutations durable and return a completion for it (one reference,
    /// owned by the caller). The state keeps its own reference until a later call observes it.
    pub fn start_sync(self: *SyncState, blob: Blob) !Completion {
        switch (self.*) {
            .clean => return Completion.ok,
            .pending => |completion| return completion.retain(),
            .dirty => {
                const completion = try blob.start_sync();
                self.* = .{ .pending = completion };
                assert(!self.is_clean());
                return completion.retain();
            },
        }
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("start_sync_test.zig");
    _ = @import("sync_wait_test.zig");
    _ = @import("buffer_fuzz_test.zig");
}
