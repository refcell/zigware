//! commonware's `journal/contiguous/variable.rs` batched `read_many` tests of frame extents:
//! tampered offsets a batched read must reject (`test_variable_read_many_rejects_*`), a cached
//! frame whose successor offset is cold, and a blob's last frame ending at the blob size.
//!
//! commonware pairs the real data blobs with an offsets journal of the test's choosing by
//! building a `Reader`; here the test swaps that offsets journal into the journal's `offsets`
//! field and restores the real one before closing. Tests that count recorded blob reads or
//! metrics, and `test_variable_read_many_buffer_len` (zigware bounds the buffer by the blob
//! sizes with checked adds instead of `read_buffer_len`), are not ported.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const variable = @import("variable.zig");
const fixed = @import("fixed.zig");

const gpa = testing.allocator;
/// 300-byte items, 302-byte frames.
const Wide = [300]u8;
const Journal = variable.Journal(Wide);
const Offsets = fixed.Journal(u64);

fn wide(position: u64) Wide {
    return @splat(@truncate(position));
}

const Fixture = struct {
    storage: mocks.Storage,
    cache_ref: paged.CacheRef,
    offsets_cache: paged.CacheRef,
    journal: Journal,
    /// The journal's real offsets while a tampered journal is swapped in.
    real: ?Offsets = null,

    /// A journal of `count` synced frames in one 128-item section, with a separate offsets
    /// cache of `offsets_page` bytes per page for tampered offsets.
    fn init(self: *Fixture, count: u64, offsets_page: u16) !void {
        self.storage = .init(gpa);
        errdefer self.storage.deinit();
        self.cache_ref = try .init(gpa, 512, 16);
        errdefer self.cache_ref.deinit();
        self.offsets_cache = try .init(gpa, offsets_page, 16);
        errdefer self.offsets_cache.deinit();
        self.journal = try self.open(null);
        errdefer self.journal.deinit();
        for (0..count) |position| _ = try self.journal.append(wide(position));
        try self.journal.sync();
        self.real = null;
    }

    fn open(self: *Fixture, max_size: ?u64) !Journal {
        const cfg: variable.Config(Wide) = .{
            .partition = "read-many",
            .items_per_section = 128,
            .compression = null,
            .codec_config = {},
            .cache_ref = &self.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
        const storage = self.storage.interface();
        if (max_size) |cap| return Journal.init_at_most(gpa, storage, cfg, cap);
        return Journal.init(gpa, storage, cfg);
    }

    fn deinit(self: *Fixture) void {
        self.restore();
        self.journal.deinit();
        self.offsets_cache.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    /// Pair the real data with offsets of the test's choosing.
    fn tamper(self: *Fixture, partition: []const u8, offsets: []const u64) !void {
        self.restore();
        var tampered = try Offsets.init(gpa, self.storage.interface(), .{
            .partition = partition,
            .items_per_blob = 128,
            .cache_ref = &self.offsets_cache,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        });
        errdefer tampered.deinit();
        for (offsets) |offset| _ = try tampered.append(offset);
        try tampered.sync();
        self.real = self.journal.offsets;
        self.journal.offsets = tampered;
    }

    fn restore(self: *Fixture) void {
        const real = self.real orelse return;
        self.journal.offsets.deinit();
        self.journal.offsets = real;
        self.real = null;
    }

    fn expect_sync(self: *Fixture, positions: []const u64, expected: []const ?u64) !void {
        var out: [8]?Wide = undefined;
        self.journal.try_read_many_sync(positions, out[0..positions.len]);
        for (out[0..positions.len], expected) |item, want| {
            if (want) |position| {
                try testing.expectEqualSlices(u8, &wide(position), &(item orelse
                    return error.TestExpectedServed));
            } else try testing.expect(item == null);
        }
    }

    fn expect_read_many(self: *Fixture, positions: []const u64) !void {
        var out: [8]Wide = undefined;
        try self.journal.read_many(positions, out[0..positions.len]);
        for (positions, out[0..positions.len]) |position, item| {
            try testing.expectEqualSlices(u8, &wide(position), &item);
        }
    }

    fn expect_read_many_error(self: *Fixture, expected: anyerror, positions: []const u64) !void {
        var out: [8]Wide = undefined;
        try testing.expectError(expected, self.journal.read_many(positions, out[0..positions.len]));
    }
};

test "variable read_many rejects inconsistent offsets" {
    // commonware `test_variable_read_many_rejects_inconsistent_offsets`: offsets that run
    // backwards, overlap, or point past the blob never reach the batched read. The cached pass
    // serves nothing from a batch holding one, and completion reports `Corruption`. A successor
    // offset that only disagrees with the frame's own length prefix fails when it decodes.
    var f: Fixture = undefined;
    try f.init(4, 512);
    defer f.deinit();
    // Frames are 302 bytes, so the consistent offsets are 0, 302, 604, and 906. Frame 1 would
    // end before it starts, and frame 2 would start inside frame 0.
    try f.tamper("backwards", &.{ 0, 302, 100, 906 });
    try f.expect_sync(&.{ 0, 1, 2 }, &.{ null, null, null });
    try f.expect_read_many_error(error.Corruption, &.{ 0, 1, 2 });
    f.cache_ref.clear();
    f.offsets_cache.clear();
    try f.expect_read_many_error(error.Corruption, &.{ 0, 2 });
    // Frame 2 claims frame 0's bytes, whether frame 0 is cold or cached.
    try f.tamper("aliased", &.{ 0, 302, 0, 302 });
    f.cache_ref.clear();
    try f.expect_read_many_error(error.Corruption, &.{ 0, 2 });
    try f.expect_read_many(&.{0});
    try f.expect_sync(&.{ 0, 2 }, &.{ null, null });
    try f.expect_read_many_error(error.Corruption, &.{ 0, 2 });
    // Frame 2's successor offset lies far past the blob.
    try f.tamper("oversized", &.{ 0, 302, 604, std.math.maxInt(u64) / 2 });
    try f.expect_sync(&.{2}, &.{null});
    try f.expect_read_many_error(error.Corruption, &.{2});
    // Frame 1's successor offset is one byte short; only its length prefix reveals that.
    try f.tamper("short", &.{ 0, 302, 603, 906 });
    try f.expect_sync(&.{1}, &.{null});
    try f.expect_read_many_error(error.OffsetDataMismatch, &.{1});
}

test "variable read_many rejects an overlapping prefix frame" {
    // commonware `test_variable_read_many_rejects_overlapping_prefix_frame`: a frame whose
    // successor offset is cold is bounded by its length prefix, and the overlap is rejected
    // whether the first or the second frame of the batch uses its prefix.
    var f: Fixture = undefined;
    // One offset per page lets either frame's successor be cold independently.
    try f.init(128, 8);
    defer f.deinit();
    // Point frame 63 at frame 0's bytes.
    var offsets: [128]u64 = undefined;
    for (&offsets, 0..) |*offset, position| offset.* = position * 302;
    offsets[63] = 0;
    try f.tamper("overlapping-prefix", &offsets);
    try f.expect_read_many(&.{0});
    for ([_][2]u64{ .{ 1, 64 }, .{ 64, 1 } }) |ends| {
        const warm_end, const cold_end = ends;
        f.offsets_cache.clear();
        for ([_]u64{ 0, 63, warm_end }) |position| _ = try f.journal.offsets.read(position);
        try f.expect_sync(&.{0}, &.{0});
        try testing.expect(f.journal.offsets.try_read_sync(warm_end) != null);
        try testing.expect(f.journal.offsets.try_read_sync(cold_end) == null);
        try f.expect_sync(&.{ 0, 63 }, &.{ null, null });
        try f.expect_read_many_error(error.Corruption, &.{ 0, 63 });
    }
}

test "variable read_many cached frame with a cold successor" {
    // commonware `test_variable_read_many_cached_frame_with_cold_successor`: frame 63's cached
    // length prefix bounds it although the offset of position 64 is cold.
    var f: Fixture = undefined;
    try f.init(128, 512);
    defer f.deinit();
    // Position 62 spans the data pages of frames 62 and 63. Its offsets page holds entries 0
    // through 63, so reading it leaves position 64's offset cold.
    f.journal.deinit();
    f.journal = try f.open(null);
    f.cache_ref.clear();
    try f.expect_read_many(&.{62});
    try testing.expect(f.journal.offsets.try_read_sync(63) != null);
    try testing.expect(f.journal.offsets.try_read_sync(64) == null);
    try f.expect_sync(&.{ 62, 63 }, &.{ 62, 63 });
    try f.expect_read_many(&.{ 62, 63 });
    try f.expect_sync(&.{ 63, 64 }, &.{ 63, null });
    try testing.expect(f.journal.offsets.try_read_sync(64) == null);
}

test "variable read_many last frame uses the blob size" {
    // commonware `test_variable_read_many_last_frame_uses_blob_size` (its reopen half; zigware
    // has no snapshot): a reopen capped at four items ends the blob after frame 3, so frame 3's
    // extent ends at the blob's size.
    var f: Fixture = undefined;
    try f.init(6, 512);
    defer f.deinit();
    f.journal.deinit();
    f.journal = try f.open(4);
    try testing.expectEqual(@as(u64, 4), f.journal.size());
    f.cache_ref.clear();
    try f.expect_sync(&.{3}, &.{null});
    try f.expect_read_many(&.{ 2, 3 });
    try f.expect_sync(&.{3}, &.{3});
}
