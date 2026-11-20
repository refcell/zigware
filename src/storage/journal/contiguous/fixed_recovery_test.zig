//! The fixed contiguous journal's own tests (commonware's `journal/contiguous/fixed.rs`):
//! partitions, replay, recovery, watermarks, and interrupted clears.
//!
//! commonware's random storage faults become deterministic mutation budgets
//! (`allow_mutations`); `start_and_recover` becomes `crash()`. Snapshot readers are not ported,
//! so tests that replay through one replay the journal directly.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const Sha256 = @import("cryptography").sha256.Sha256;
const Digest = @import("cryptography").sha256.Digest;
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const contiguous = @import("mod.zig");
const manager_mod = @import("../segmented/manager.zig");

const gpa = testing.allocator;
const Storage = mocks.Storage;
const Journal = fixed.Journal(Digest);
const Bounds = contiguous.Bounds;
const digest_size = 32;

fn test_digest(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

const Harness = struct {
    storage: Storage,
    cache_ref: paged.CacheRef,
    items_per_blob: u64,
    partition: []const u8 = "test-partition",
    blobs: []const u8 = "test-partition-blobs",

    fn init(items_per_blob: u64) !Harness {
        return .{
            .storage = Storage.init(gpa),
            .cache_ref = try paged.CacheRef.init(gpa, 44, 3),
            .items_per_blob = items_per_blob,
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg(self: *Harness) fixed.Config {
        return .{
            .partition = self.partition,
            .items_per_blob = self.items_per_blob,
            .cache_ref = &self.cache_ref,
            .write_buffer = 2048,
            .replay_buffer = 2048,
        };
    }

    fn iface(self: *Harness) runtime.storage.Storage {
        return self.storage.interface();
    }

    fn open(self: *Harness) !Journal {
        return Journal.init(gpa, self.iface(), self.cfg());
    }

    fn open_at_size(self: *Harness, size: u64) !Journal {
        return Journal.init_at_size(gpa, self.iface(), self.cfg(), size);
    }

    /// Append `count` digests of `first + i`.
    fn fill(journal: *Journal, first: u64, count: u64) !void {
        for (0..count) |index| _ = try journal.append(test_digest(first + index));
    }

    /// Durably write `bytes` at `offset` of blob `index` in `partition`.
    fn write_raw(
        self: *Harness,
        partition: []const u8,
        index: u64,
        offset: u64,
        bytes: []const u8,
    ) !void {
        const opened = try self.iface().open(partition, &manager_mod.section_name(index));
        defer opened.blob.close();
        try opened.blob.write_at(offset, bytes, .{ .sync = true });
    }

    /// Durably shorten blob `index` by `bytes` physical bytes.
    fn shorten(self: *Harness, index: u64, bytes: u64) !void {
        const opened = try self.iface().open(self.blobs, &manager_mod.section_name(index));
        defer opened.blob.close();
        try opened.blob.resize(opened.len - bytes);
        try opened.blob.sync();
    }

    /// Durably truncate blob `index` to `len` logical bytes through a paged recovery writer.
    fn truncate_logical(self: *Harness, index: u64, len: u64) !void {
        const opened = try self.iface().open(self.blobs, &manager_mod.section_name(index));
        const cache_ref = &self.cache_ref;
        // The writer owns the blob once it opens.
        var writer = open: {
            errdefer opened.blob.close();
            const blob = opened.blob;
            break :open try paged.Writer.open_recovery(gpa, blob, opened.len, 2048, cache_ref);
        };
        defer writer.deinit();
        try writer.truncate(len);
    }

    fn remove_blob(self: *Harness, index: u64) !void {
        try self.iface().remove(self.blobs, &manager_mod.section_name(index));
    }

    fn blob_count(self: *Harness, partition: []const u8) !usize {
        const indices = try fixed_blobs_indices(self.iface(), partition);
        defer gpa.free(indices);
        return indices.len;
    }
};

/// Check that positions `[start, end)` hold `test_digest(first + position - start)`.
fn expect_digests(journal: *Journal, start: u64, end: u64, first: u64) !void {
    var position = start;
    while (position < end) : (position += 1) {
        const expected = test_digest(first + position - start);
        try testing.expectEqual(expected, try journal.read(position));
    }
}

fn fixed_blobs_indices(storage: runtime.storage.Storage, partition: []const u8) ![]u64 {
    return contiguous.blobs.indices(gpa, storage, partition);
}

test "fixed: init with data in both partitions is corruption" {
    var h = try Harness.init(2);
    defer h.deinit();
    try h.write_raw(h.partition, 0, 0, &.{0});
    try h.write_raw(h.blobs, 0, 0, &.{0});
    try testing.expectError(error.Corruption, h.open());
}

test "fixed: init prefers the legacy partition" {
    var h = try Harness.init(2);
    defer h.deinit();
    try h.write_raw(h.partition, 0, 0, &.{0});
    var journal = try h.open();
    _ = try journal.append(test_digest(1));
    try journal.sync();
    journal.deinit();
    try testing.expect(try h.blob_count(h.partition) > 0);
    try testing.expectEqual(0, try h.blob_count(h.blobs));
}

test "fixed: init defaults to the blobs partition" {
    var h = try Harness.init(2);
    defer h.deinit();
    var journal = try h.open();
    _ = try journal.append(test_digest(1));
    try journal.sync();
    journal.deinit();
    try testing.expectEqual(0, try h.blob_count(h.partition));
    try testing.expect(try h.blob_count(h.blobs) > 0);
}

test "fixed: append and prune" {
    var h = try Harness.init(2);
    defer h.deinit();
    var journal = try h.open();
    try testing.expectEqual(0, try journal.append(test_digest(0)));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    defer journal.destroy() catch {};
    try testing.expectEqual(1, journal.size());
    try testing.expectEqual(1, try journal.append(test_digest(1)));
    try testing.expectEqual(2, try journal.append(test_digest(2)));
    try expect_digests(&journal, 0, 3, 0);
    try testing.expectError(error.ItemOutOfRange, journal.read(3));
    try journal.sync();
    _ = try journal.prune(1);
    _ = try journal.prune(2);
    try testing.expectEqual(2, journal.pruning_boundary());
    try testing.expectError(error.ItemPruned, journal.read(0));
    try testing.expectError(error.ItemPruned, journal.read(1));
    try testing.expectEqual(test_digest(2), try journal.read(2));
    for (3..10) |position| {
        try testing.expectEqual(position, try journal.append(test_digest(position)));
    }
    // A no-op prune.
    _ = try journal.prune(0);
    try testing.expectEqual(1, journal.test_oldest_blob());
    try testing.expectEqual(5, journal.test_newest_blob());
    try testing.expectEqual(2, journal.pruning_boundary());
    _ = try journal.prune(3 * 2);
    try testing.expectEqual(3, journal.test_oldest_blob());
    try testing.expectEqual(6, journal.pruning_boundary());
    // Pruning past the end prunes to the tail blob.
    _ = try journal.prune(10_000);
    try testing.expectEqual(10, journal.size());
    try testing.expectEqual(5, journal.test_oldest_blob());
    try testing.expectEqual(5, journal.test_newest_blob());
    try testing.expectEqual(Bounds{ .start = 10, .end = 10 }, journal.get_bounds());
    try testing.expectError(error.ItemPruned, journal.replay(.{ .start = 0, .end = 10 }, 1024));
    var replay = try journal.replay(.{ .start = 10, .end = 10 }, 1024);
    defer replay.deinit();
    try testing.expectEqual(null, try replay.next());
}

test "fixed: append a lot of data" {
    var h = try Harness.init(10_000);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 2 * 10_000 - 1);
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try expect_digests(&journal, 0, 10_000, 0);
    try journal.destroy();
}

/// Replay `range` expecting `test_digest(position)` items; returns the replayed count and the
/// error that ended the replay, if any (after which the replay must be exhausted).
fn replay_digests(journal: *Journal, range: Bounds, buffer: usize) !struct { u64, ?anyerror } {
    var replay = try journal.replay(range, buffer);
    defer replay.deinit();
    var next = range.start;
    while (true) {
        const batch = replay.next() catch |err| {
            try testing.expectEqual(null, try replay.next());
            return .{ next - range.start, err };
        } orelse break;
        try testing.expectEqual(next, batch.start);
        for (batch.items, 0..) |item, index| {
            try testing.expectEqual(test_digest(next + index), item);
        }
        next += batch.items.len;
    }
    try testing.expectEqual(range.end, next);
    return .{ next - range.start, null };
}

test "fixed: replay and corrupt historical page" {
    var h = try Harness.init(7);
    defer h.deinit();
    var journal = try h.open();
    const total = 7 * 100 + 3;
    try Harness.fill(&journal, 0, total);
    try expect_digests(&journal, 0, total, 0);
    const count, const failure = try replay_digests(&journal, .{ .start = 0, .end = total }, 1024);
    try testing.expectEqual(total, count);
    try testing.expectEqual(null, failure);
    try journal.sync();
    journal.deinit();
    // Corrupt the first page of blob 40.
    var bad: [4]u8 = undefined;
    std.mem.writeInt(u32, &bad, 123456789, .big);
    try h.write_raw(h.blobs, 40, 1, &bad);
    h.cache_ref.clear();
    journal = try h.open();
    defer journal.deinit();
    try testing.expectError(error.InvalidChecksum, journal.read(40 * 7 + 1));
    // The error aborts the replay after the items before the bad blob.
    _, const replay_failure = try replay_digests(&journal, .{ .start = 0, .end = total }, 1024);
    try testing.expectEqual(error.InvalidChecksum, replay_failure.?);
}

test "fixed: replay stops after error" {
    var h = try Harness.init(10);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 30);
    try journal.sync();
    journal.deinit();
    var bad: [4]u8 = undefined;
    std.mem.writeInt(u32, &bad, 123456789, .big);
    try h.write_raw(h.blobs, 1, 1, &bad);
    h.cache_ref.clear();
    journal = try h.open();
    const count, const failure = try replay_digests(&journal, .{ .start = 0, .end = 30 }, 1024);
    try testing.expectEqual(10, count);
    try testing.expectEqual(error.InvalidChecksum, failure.?);
    try journal.destroy();
}

test "fixed: missing historical blob is corruption" {
    var h = try Harness.init(2);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 5);
    try journal.sync();
    journal.deinit();
    try h.remove_blob(1);
    try testing.expectError(error.Corruption, h.open());
}

test "fixed: partial replay and replay range" {
    var h = try Harness.init(7);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 7 * 100 + 3);
    const count, _ = try replay_digests(&journal, .{ .start = 53, .end = 703 }, 1024);
    try testing.expectEqual(703 - 53, count);
    const ranged, _ = try replay_digests(&journal, .{ .start = 12, .end = 40 }, 1024);
    try testing.expectEqual(28, ranged);
    const empty, _ = try replay_digests(&journal, .{ .start = 5, .end = 5 }, 1024);
    try testing.expectEqual(0, empty);
    const past_end = journal.replay(.{ .start = 0, .end = 704 }, 1024);
    try testing.expectError(error.ItemOutOfRange, past_end);
    const inverted = journal.replay(.{ .start = 10, .end = 5 }, 1024);
    try testing.expectError(error.ItemOutOfRange, inverted);
    try journal.destroy();
}

/// commonware's `check_replay_batches` over digests: batches tile `range` in position order,
/// are non-empty, never cross a blob, and exceed `buffer` by less than one item.
fn check_digest_batches(journal: *Journal, range: Bounds, buffer: usize) !void {
    var replay = try journal.replay(range, buffer);
    defer replay.deinit();
    var next = range.start;
    while (try replay.next()) |batch| {
        try testing.expectEqual(next, batch.start);
        try testing.expect(batch.items.len > 0);
        try testing.expect((batch.items.len - 1) * digest_size < buffer);
        const end = batch.start + batch.items.len;
        try testing.expect(end <= range.end);
        try testing.expectEqual(batch.start / 7, (end - 1) / 7);
        for (batch.items, 0..) |item, index| {
            try testing.expectEqual(test_digest(batch.start + index), item);
        }
        next = end;
    }
    try testing.expectEqual(range.end, next);
}

// Replay tiles a range in position order without crossing blob boundaries, through sealed
// blobs and the unsynced tail, at budgets of one item, part of a blob, and the whole journal;
// a synced tail is replayed through its sealed pages.
test "fixed: replay batches stay within blobs and budgets" {
    var h = try Harness.init(7);
    defer h.deinit();
    var journal = try h.open();
    const total = 7 * 10 + 3;
    try Harness.fill(&journal, 0, total);
    const ranges = [_]Bounds{
        .{ .start = 0, .end = total }, .{ .start = 12, .end = 40 },    .{ .start = 20, .end = 21 },
        .{ .start = 30, .end = 30 },   .{ .start = 70, .end = total },
    };
    for ([_]usize{ digest_size, 100, 2048 }) |buffer| {
        for (ranges) |range| try check_digest_batches(&journal, range, buffer);
    }
    try journal.sync();
    try check_digest_batches(&journal, .{ .start = 65, .end = total }, 100);
    try journal.destroy();
}

// A page with a bad checksum ends the replay after the items decoded before it, with exactly
// one `InvalidChecksum`, whether the page starts its fill or sits inside it, at buffers of 8
// and 64 physical pages. commonware splits the buffer into four read-ahead batches; zigware
// fills the whole buffer at once, so the bad page sits in the third fill and the items of the
// two fills before it are yielded. Valid pages of the bad page's fill are not yielded.
test "fixed: a bad page in a read-ahead fill ends the replay" {
    const page = 64;
    const items = 1280;
    const physical = page + 12;
    const items_per_page = page / 8;
    for ([_][2]u64{ .{ 8, 0 }, .{ 8, 1 }, .{ 64, 0 }, .{ 64, 1 } }) |scenario| {
        const buffer_pages, const within_fill = scenario;
        const bad_page = 2 * buffer_pages + within_fill;
        const expected_items = 2 * buffer_pages * items_per_page;
        var storage = Storage.init(gpa);
        defer storage.deinit();
        var cache_ref = try paged.CacheRef.init(gpa, page, 4);
        defer cache_ref.deinit();
        const cfg: fixed.Config = .{
            .partition = "bad-page",
            .items_per_blob = items,
            .cache_ref = &cache_ref,
            .write_buffer = 2048,
            .replay_buffer = 2048,
        };
        {
            var journal = try fixed.Journal(u64).init(gpa, storage.interface(), cfg);
            defer journal.deinit();
            for (0..items) |item| _ = try journal.append(item);
            try journal.sync();
        }
        const name = manager_mod.section_name(0);
        try paged.corrupt_page(storage.interface(), "bad-page-blobs", &name, bad_page, page);
        cache_ref.clear();
        var journal = try fixed.Journal(u64).init(gpa, storage.interface(), cfg);
        defer journal.deinit();
        const range: Bounds = .{ .start = 0, .end = items };
        var replay = try journal.replay_options(range, buffer_pages * physical, .{
            .dont_cache = true,
        });
        defer replay.deinit();
        var next: u64 = 0;
        const failure = while (true) {
            const batch = replay.next() catch |err| break err;
            const yielded = batch orelse return error.TestUnexpectedResult;
            try testing.expectEqual(next, yielded.start);
            for (yielded.items) |item| {
                try testing.expectEqual(next, item);
                next += 1;
            }
        };
        try testing.expectEqual(error.InvalidChecksum, failure);
        try testing.expectEqual(expected_items, next);
        try testing.expectEqual(null, try replay.next());
    }
}

/// Replay `range` with `options`, checking `[range.start, range.start + count)` are
/// `test_digest(position)`, and return how many backing reads it made and how many of them
/// were `dont_cache`.
fn replay_reads(
    h: *Harness,
    journal: *Journal,
    range: Bounds,
    buffer: usize,
    options: runtime.storage.ReadOptions,
) !struct { u64, u64 } {
    h.cache_ref.clear();
    var replay = try journal.replay_options(range, buffer, options);
    defer replay.deinit();
    const reads = h.storage.reads;
    const dont_cache = h.storage.dont_cache_reads;
    var next = range.start;
    while (try replay.next()) |batch| {
        try testing.expectEqual(next, batch.start);
        for (batch.items, 0..) |item, index| {
            try testing.expectEqual(test_digest(next + index), item);
        }
        next += batch.items.len;
    }
    try testing.expectEqual(range.end, next);
    return .{ h.storage.reads - reads, h.storage.dont_cache_reads - dont_cache };
}

// Replay's read options reach sealed history and the writable tip: sealed blobs carry the
// caller's options on every read, and a synced tip's full pages arrive in one read carrying
// them. commonware replays a tip holding an unwritten full page through the page cache, which
// faults pages with `dont_cache` whatever the caller passed; zigware replays the tip's flushed
// pages from the blob and its buffered bytes from memory, so the caller's option still holds.
test "fixed: replay read options reach history and tip" {
    var h = try Harness.init(6);
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    // The tip blob holds three items across two full pages and a partial page.
    try Harness.fill(&journal, 0, 9);
    try journal.sync();
    const dont_cache: runtime.storage.ReadOptions = .{ .dont_cache = true };
    const history = try replay_reads(&h, &journal, .{ .start = 0, .end = 9 }, 56, dont_cache);
    try testing.expect(history[0] > 0);
    try testing.expectEqual(history[0], history[1]);
    for ([_]runtime.storage.ReadOptions{ .{}, dont_cache }) |options| {
        const tip = try replay_reads(&h, &journal, .{ .start = 6, .end = 9 }, 2048, options);
        try testing.expectEqual(1, tip[0]);
        try testing.expectEqual(@intFromBool(options.dont_cache), tip[1]);
        // A replay that skipped the cache leaves the next read to fault the page in.
        const before = h.storage.reads;
        try testing.expectEqual(test_digest(6), try journal.read(6));
        try testing.expect(h.storage.reads > before);
        const cached = h.storage.reads;
        try testing.expectEqual(test_digest(6), try journal.read(6));
        try testing.expectEqual(cached, h.storage.reads);
    }
    // A tip with a buffered full page is still replayed with the caller's options.
    try Harness.fill(&journal, 9, 2);
    const buffered = try replay_reads(&h, &journal, .{ .start = 6, .end = 11 }, 2048, .{});
    try testing.expectEqual(0, buffered[1]);
}

test "fixed: replay batches stop at codec error" {
    for ([_]u64{ 5, 14, 20 }) |invalid| {
        var h = try Harness.init(1000);
        defer h.deinit();
        {
            var writer = try fixed.Journal([3]u8).init(gpa, h.iface(), h.cfg());
            for (0..100) |index| {
                const item: [3]u8 = if (index == invalid) .{ 0, 2, 0 } else .{ 0, 1, 0 };
                _ = try writer.append(item);
            }
            try writer.sync();
            writer.deinit();
        }
        var reader = try fixed.Journal([3]bool).init(gpa, h.iface(), h.cfg());
        defer reader.destroy() catch {};
        var replay = try reader.replay(.{ .start = 0, .end = 100 }, 2048);
        defer replay.deinit();
        var decoded: u64 = 0;
        while (true) {
            const batch = replay.next() catch break orelse break;
            try testing.expectEqual(decoded, batch.start);
            for (batch.items) |item| try testing.expectEqual([3]bool{ false, true, false }, item);
            decoded += batch.items.len;
        }
        try testing.expectEqual(invalid, decoded);
        try testing.expectEqual(null, try replay.next());
    }
}

test "fixed: corrupted tail blob is corruption" {
    var h = try Harness.init(3);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 5);
    try journal.sync();
    journal.deinit();
    // Losing acknowledged bytes of the tail is corruption.
    try h.shorten(1, 1);
    try testing.expectError(error.Corruption, h.open());
}

/// Reopen after an interrupted `action` and check the journal is in one of `allowed` states,
/// readable and appendable.
fn check_reopen(h: *Harness, allowed: []const Bounds, first: u64) !Bounds {
    var journal = try h.open();
    const bounds = journal.get_bounds();
    var matched = false;
    for (allowed) |candidate| matched = matched or std.meta.eql(candidate, bounds);
    try testing.expect(matched);
    try expect_digests(&journal, bounds.start, bounds.end, first);
    try testing.expectEqual(bounds.end, try journal.append(test_digest(99)));
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(test_digest(99), try journal.read(bounds.end));
    journal.deinit();
    return bounds;
}

test "fixed: interrupted init at size reopens" {
    for ([_]u64{ 0, 2, 8, 13, 15 }) |target| {
        var interrupted: u64 = 0;
        while (true) : (interrupted += 1) {
            var h = try Harness.init(5);
            defer h.deinit();
            var journal = try h.open_at_size(7);
            try Harness.fill(&journal, 7, 5);
            try journal.sync();
            journal.deinit();
            h.storage.allow_mutations(interrupted);
            const completed = if (h.open_at_size(target)) |reset| blk: {
                var opened = reset;
                opened.deinit();
                break :blk true;
            } else |_| false;
            const stopped = h.storage.mutation_refused;
            h.storage.mutations_allowed = null;
            h.storage.crash();
            try testing.expectEqual(!stopped, completed);
            const reset: Bounds = .{ .start = target, .end = target };
            const allowed: []const Bounds = if (completed)
                &.{reset}
            else
                &.{ .{ .start = 7, .end = 12 }, reset };
            _ = try check_reopen(&h, allowed, 7);
            if (!stopped) break;
        }
        try testing.expect(interrupted >= 3);
    }
}

test "fixed: interrupted destroy reopens unchanged or empty" {
    var unchanged: u32 = 0;
    var emptied: u32 = 0;
    var interrupted: u64 = 0;
    while (true) : (interrupted += 1) {
        var h = try Harness.init(2);
        defer h.deinit();
        var journal = try h.open_at_size(5);
        try Harness.fill(&journal, 5, 6);
        try journal.sync();
        h.storage.allow_mutations(interrupted);
        const destroyed = if (journal.destroy()) true else |_| false;
        h.storage.mutations_allowed = null;
        h.storage.crash();
        if (destroyed) break;
        const bounds = try check_reopen(&h, &.{
            .{ .start = 5, .end = 11 },
            .{ .start = 0, .end = 0 },
        }, 5);
        if (bounds.start == 5) unchanged += 1 else emptied += 1;
    }
    try testing.expect(unchanged > 0 and emptied > 0);
}

test "fixed: crash during recovery repair" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 15);
    try journal.sync();
    try testing.expectEqual(15, journal.recovery_watermark());
    // A repair lowered the watermark to 9 and crashed before truncating blob 1.
    try journal.checkpoint.persist(5, 0, 9);
    journal.deinit();
    try h.truncate_logical(1, 4 * digest_size);
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 0, .end = 9 }, journal.get_bounds());
    try testing.expectEqual(9, journal.recovery_watermark());
    try testing.expectEqual(test_digest(8), try journal.read(8));
    try testing.expectError(error.ItemOutOfRange, journal.read(9));
    // Stale blobs beyond the repair point are removed.
    try testing.expectEqual(1, journal.test_newest_blob());
    try journal.destroy();
}

test "fixed: recovery accepts clean short and empty tails" {
    for ([_]u64{ 7, 5 }) |count| {
        var h = try Harness.init(5);
        defer h.deinit();
        var journal = try h.open();
        try Harness.fill(&journal, 0, count);
        try journal.sync();
        journal.deinit();
        journal = try h.open();
        try testing.expectEqual(count, journal.size());
        try expect_digests(&journal, 0, count, 0);
        try testing.expectEqual(1, journal.test_newest_blob());
        try journal.destroy();
    }
}

test "fixed: recovery repairs sparse blob ids at the gap" {
    var h = try Harness.init(1);
    defer h.deinit();
    var journal = try h.open();
    _ = try journal.append(test_digest(0));
    try journal.sync();
    journal.deinit();
    {
        const name = manager_mod.section_name(std.math.maxInt(u64));
        const opened = try h.iface().open(h.blobs, &name);
        var writer = try paged.Writer.init(gpa, opened.blob, opened.len, 2048, &h.cache_ref);
        defer writer.deinit();
        _ = try writer.append(&test_digest(999).bytes);
        try writer.sync();
    }
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 0, .end = 1 }, journal.get_bounds());
    try testing.expectEqual(test_digest(0), try journal.read(0));
    try testing.expectError(error.ItemOutOfRange, journal.read(1));
    try testing.expectEqual(1, journal.test_newest_blob());
    try journal.destroy();
}

test "fixed: recovery truncates after a short oldest blob" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try Harness.fill(&journal, 100, 8);
    try journal.sync();
    try testing.expectEqual(Bounds{ .start = 7, .end = 15 }, journal.get_bounds());
    try journal.test_set_recovery_watermark(6);
    journal.deinit();
    try h.shorten(1, 1);
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 7, .end = 9 }, journal.get_bounds());
    try testing.expectEqual(test_digest(100), try journal.read(7));
    try testing.expectEqual(test_digest(101), try journal.read(8));
    try testing.expectError(error.ItemOutOfRange, journal.read(9));
    try testing.expectEqual(1, journal.test_oldest_blob());
    try testing.expectEqual(1, journal.test_newest_blob());
    try journal.destroy();
}

test "fixed: stale pruning metadata preserves the watermark" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try Harness.fill(&journal, 0, 10);
    try journal.sync();
    try testing.expectEqual(Bounds{ .start = 7, .end = 17 }, journal.get_bounds());
    try journal.test_set_recovery_watermark(12);
    journal.deinit();
    try h.truncate_logical(2, 2 * digest_size);
    try h.remove_blob(1);
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 10, .end = 12 }, journal.get_bounds());
    try testing.expectEqual(12, journal.recovery_watermark());
    try testing.expectEqual(test_digest(3), try journal.read(10));
    try testing.expectEqual(test_digest(4), try journal.read(11));
    try testing.expectError(error.ItemOutOfRange, journal.read(12));
    try journal.destroy();
}

test "fixed: stale pruning metadata without watermark walks lengths" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try Harness.fill(&journal, 0, 10);
    try journal.sync();
    try journal.checkpoint.set_watermark(null);
    try journal.checkpoint.sync();
    journal.deinit();
    try h.remove_blob(1);
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 10, .end = 17 }, journal.get_bounds());
    try testing.expectEqual(15, journal.recovery_watermark());
    try testing.expectEqual(test_digest(3), try journal.read(10));
    try testing.expectEqual(test_digest(9), try journal.read(16));
    try journal.sync();
    try testing.expectEqual(17, journal.recovery_watermark());
    try journal.destroy();
}

test "fixed: boundary hint ahead of blobs is corruption" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open_at_size(3);
    try Harness.fill(&journal, 0, 12);
    try journal.sync();
    try journal.checkpoint.set_boundary_hint(8);
    try journal.checkpoint.set_watermark(3);
    try journal.checkpoint.sync();
    journal.deinit();
    try h.remove_blob(1);
    try testing.expectError(error.Corruption, h.open());
}

test "fixed: boundary hint with no blobs is corruption" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try Harness.fill(&journal, 0, 3);
    try journal.sync();
    journal.deinit();
    const indices = try fixed_blobs_indices(h.iface(), h.blobs);
    defer gpa.free(indices);
    for (indices) |index| try h.remove_blob(index);
    try testing.expectError(error.Corruption, h.open());
}

test "fixed: legacy recovery installs a watermark" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 12);
    try journal.sync();
    try journal.checkpoint.set_watermark(null);
    try journal.checkpoint.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 0, .end = 12 }, journal.get_bounds());
    try testing.expectEqual(10, journal.recovery_watermark());
    try journal.sync();
    try testing.expectEqual(12, journal.recovery_watermark());
    try journal.destroy();
}

test "fixed: commit does not advance the recovery watermark" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open();
    _ = try journal.append(test_digest(0));
    try journal.sync();
    try testing.expectEqual(1, journal.recovery_watermark());
    _ = try journal.append(test_digest(1));
    try journal.commit();
    try testing.expectEqual(1, journal.recovery_watermark());
    try journal.sync();
    try testing.expectEqual(2, journal.recovery_watermark());
    try journal.destroy();
}

test "fixed: recovery scans unacknowledged pages in replay-buffer batches" {
    var h = try Harness.init(1000);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 1);
    try journal.sync();
    // Committed items are durable but above the watermark, so reopening scans their pages:
    // 9,600 bytes of 44-byte pages. The 2,048-byte replay buffer reads 36 physical pages at a
    // time (commonware's `recoverable_prefix_len_at_most` budget) instead of one per read.
    try Harness.fill(&journal, 1, 300);
    try journal.commit();
    try testing.expectEqual(1, journal.recovery_watermark());
    journal.deinit();
    const before = h.storage.reads;
    journal = try h.open();
    const reads = h.storage.reads - before;
    try testing.expectEqual(Bounds{ .start = 0, .end = 301 }, journal.get_bounds());
    try testing.expectEqual(test_digest(300), try journal.read(300));
    try testing.expect(reads > 0);
    try testing.expect(reads < 40);
    try journal.destroy();
}

test "fixed: prune to a blob boundary removes the pruning hint" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open_at_size(7);
    try Harness.fill(&journal, 0, 8);
    try journal.sync();
    try testing.expectEqual(Bounds{ .start = 7, .end = 15 }, journal.get_bounds());
    _ = try journal.prune(10);
    try journal.sync();
    try testing.expectEqual(Bounds{ .start = 10, .end = 15 }, journal.get_bounds());
    try testing.expectEqual(null, journal.checkpoint.boundary_hint());
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 10, .end = 15 }, journal.get_bounds());
    try testing.expectEqual(test_digest(3), try journal.read(10));
    try journal.destroy();
}
