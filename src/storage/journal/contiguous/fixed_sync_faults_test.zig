//! commonware's `journal/contiguous/fixed.rs` start-sync and truncate fault tests that apply
//! to zigware's synchronous syncs: a failed flush inside `start_sync`, a failed watermark
//! advance, a failed watermark lowering on a bounded reopen, and truncation below the durable
//! size. commonware's `WriteFaults` (fail every write while armed) becomes a write failure
//! rate of one on `runtime.storage.faulty`, retaining none of the failed bytes.
//!
//! The in-flight start-sync tests (`DelayedSyncContext`, `PendingSyncs`) are in
//! start_sync_test.zig.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const contiguous = @import("mod.zig");

const gpa = testing.allocator;
const Journal = fixed.Journal(u64);
const Bounds = contiguous.Bounds;

const Harness = struct {
    const Faulty = runtime.storage.faulty.Storage(utils.rng.TestRng);

    inner: runtime.storage.memory.Storage,
    rng: utils.rng.TestRng,
    storage: Faulty,
    cache_ref: paged.CacheRef,
    items_per_blob: u64,

    fn init(self: *Harness, items_per_blob: u64, page_size: u16) !void {
        self.inner = .init(gpa);
        self.rng = .init(0);
        self.storage = .init(gpa, &self.inner, &self.rng, .{});
        self.cache_ref = try paged.CacheRef.init(gpa, page_size, 3);
        self.items_per_blob = items_per_blob;
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
        self.inner.deinit();
    }

    fn cfg(self: *Harness) fixed.Config {
        return .{
            .partition = "test-partition",
            .items_per_blob = self.items_per_blob,
            .cache_ref = &self.cache_ref,
            .write_buffer = 2048,
            .replay_buffer = 2048,
        };
    }

    fn open(self: *Harness, cap: ?u64) !Journal {
        const storage = self.storage.storage();
        if (cap) |c| return Journal.init_at_most(gpa, storage, self.cfg(), c);
        return Journal.init(gpa, storage, self.cfg());
    }

    /// Fail every write, durably keeping none of its bytes.
    fn arm(self: *Harness) void {
        self.storage.config = .{
            .write_rate = .{ .failure_rate = .one, .retention_rate = .zero, .mode = .prefix },
        };
    }

    fn disarm(self: *Harness) void {
        self.storage.config = .{};
    }
};

fn append_values(journal: *Journal, values: []const u64) !void {
    for (values) |value| _ = try journal.append(value);
}

test "fixed: a failed flush inside start sync returns an error" {
    var h: Harness = undefined;
    try h.init(3, 44);
    defer h.deinit();
    var journal = try h.open(null);
    defer journal.deinit();
    // A buffered item makes start_sync flush.
    _ = try journal.append(0);
    h.arm();
    try testing.expectError(error.Io, journal.start_sync());
}

// The advance's metadata writes fail after the data is durable: the call fails, and a reopen
// still recovers every item.
test "fixed: a failed watermark advance keeps the data" {
    var h: Harness = undefined;
    try h.init(100, 44);
    defer h.deinit();
    {
        var journal = try h.open(null);
        defer journal.deinit();
        try append_values(&journal, &.{ 1, 2, 3 });
        try (try journal.start_sync()).wait_release();
        try testing.expectEqual(3, journal.recovery_watermark());
        _ = try journal.append(4);
        try journal.commit();
        h.arm();
        try testing.expect(std.meta.isError(journal.start_sync()));
        h.disarm();
    }
    var journal = try h.open(null);
    try testing.expectEqual(Bounds{ .start = 0, .end = 4 }, journal.get_bounds());
    try journal.sync();
    try testing.expectEqual(4, journal.recovery_watermark());
    try journal.destroy();
}

// Two items per page make the two-item cap page aligned, so the only write the bounded
// reopen needs is the checkpoint rewrite lowering the watermark. When it fails, the blobs
// stay intact.
test "fixed: a failed watermark lowering keeps the blobs" {
    var h: Harness = undefined;
    try h.init(100, 16);
    defer h.deinit();
    {
        var journal = try h.open(null);
        defer journal.deinit();
        try append_values(&journal, &.{ 1, 2, 3, 4 });
        try journal.sync();
        try testing.expectEqual(4, journal.recovery_watermark());
    }
    h.arm();
    try testing.expect(std.meta.isError(h.open(2)));
    h.disarm();
    var journal = try h.open(null);
    try testing.expectEqual(4, journal.recovery_watermark());
    try testing.expectEqual(Bounds{ .start = 0, .end = 4 }, journal.get_bounds());
    for (0..4) |i| try testing.expectEqual(i + 1, try journal.read(i));
    try journal.destroy();
}

// A truncate discards the proof for the positions above it: the watermark drops to the
// truncate point, and a later sync acknowledges only the re-appended item.
test "fixed: truncate lowers the durable size" {
    var h: Harness = undefined;
    try h.init(100, 44);
    defer h.deinit();
    {
        var journal = try h.open(null);
        defer journal.deinit();
        try append_values(&journal, &.{ 1, 2, 3 });
        try journal.sync();
        try testing.expectEqual(3, journal.recovery_watermark());
    }
    {
        var journal = try h.open(2);
        defer journal.deinit();
        try testing.expectEqual(2, journal.recovery_watermark());
        _ = try journal.append(9);
        try (try journal.start_sync()).wait_release();
    }
    try h.storage.crash();
    h.inner.crash();
    var journal = try h.open(null);
    try testing.expectEqual(Bounds{ .start = 0, .end = 3 }, journal.get_bounds());
    try testing.expectEqual(9, try journal.read(2));
    try journal.destroy();
}
