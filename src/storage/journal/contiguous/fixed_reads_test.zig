//! commonware's `journal/contiguous/fixed.rs` tests of synchronous probes, `read_many` over
//! sparse and cold positions with their cache hit and miss accounting, and the journal's
//! metrics. Snapshot readers are not ported, so reads run on the journal directly; the
//! metrics test checks the counters and gauges (duration histograms are not ported).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const Sha256 = @import("cryptography").sha256.Sha256;
const Digest = @import("cryptography").sha256.Digest;
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");

const gpa = testing.allocator;
const Journal = fixed.Journal(Digest);

fn test_digest(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

const Harness = struct {
    storage: mocks.Storage,
    cache_ref: paged.CacheRef,
    items_per_blob: u64,
    pages: u32,

    /// commonware's `test_cfg` with `pages` cache pages of 44 bytes.
    fn init(items_per_blob: u64, pages: u32) !Harness {
        return .{
            .storage = mocks.Storage.init(gpa),
            .cache_ref = try paged.CacheRef.init(gpa, 44, pages),
            .items_per_blob = items_per_blob,
            .pages = pages,
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    /// A fresh, empty page cache (commonware's reopen with a new `CacheRef`).
    fn fresh_cache(self: *Harness) !void {
        self.cache_ref.deinit();
        self.cache_ref = try paged.CacheRef.init(gpa, 44, self.pages);
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

    fn open(self: *Harness) !Journal {
        return Journal.init(gpa, self.storage.interface(), self.cfg());
    }

    fn open_at_most(self: *Harness, max_size: u64) !Journal {
        return Journal.init_at_most(gpa, self.storage.interface(), self.cfg(), max_size);
    }
};

fn append_digests(journal: *Journal, count: u64) !void {
    for (0..count) |i| try testing.expectEqual(i, try journal.append(test_digest(i)));
}

fn expect_read_many(journal: *Journal, positions: []const u64) !void {
    var out: [64]Digest = undefined;
    try journal.read_many(positions, out[0..positions.len]);
    for (positions, out[0..positions.len]) |position, item| {
        try testing.expect(item.eql(test_digest(position)));
    }
}

fn expect_served(journal: *Journal, positions: []const u64, served: []const bool) !void {
    var out: [8]?Digest = undefined;
    journal.try_read_many_sync(positions, out[0..positions.len]);
    for (positions, out[0..positions.len], served) |position, item, want| {
        try testing.expectEqual(want, item != null);
        if (item) |digest| try testing.expect(digest.eql(test_digest(position)));
    }
}

// Cached positions are served synchronously and match `read_many`; positions that fail
// validation (past the end, pruned, past a capped reopen) are misses, never errors.
test "fixed: try_read_many_sync matches read_many" {
    var h = try Harness.init(4, 3);
    defer h.deinit();
    var journal = try h.open();
    try append_digests(&journal, 20);
    try journal.sync();
    var all: [20]u64 = undefined;
    for (&all, 0..) |*position, i| position.* = i;
    try expect_read_many(&journal, &all);
    var served: [20]?Digest = undefined;
    journal.try_read_many_sync(&all, &served);
    for (served, 0..) |item, position| {
        if (item) |digest| try testing.expect(digest.eql(test_digest(position)));
    }

    // Consume tail-page history, then fill the cache with unrelated single-page reads.
    h.cache_ref.clear();
    try expect_read_many(&journal, &.{ 16, 17, 18, 19 });
    h.cache_ref.clear();
    for ([_]u64{ 0, 4, 8 }) |position| _ = try journal.read(position);
    // 18 and 19 span one cached page and the in-memory tail.
    try expect_read_many(&journal, &.{ 18, 19 });
    try expect_served(&journal, &.{ 18, 19 }, &.{ true, true });
    try expect_served(&journal, &.{0}, &.{false});
    try expect_served(&journal, &.{ 19, 20 }, &.{ true, false });
    try journal.sync();
    journal.deinit();

    // A capped reopen leaves the end mid-blob: 18 shares a blob with 17 but is a miss.
    journal = try h.open_at_most(18);
    defer journal.deinit();
    try expect_read_many(&journal, &.{17});
    try expect_served(&journal, &.{ 17, 18 }, &.{ true, false });
    // A pruned position is a miss; the valid one beside it is still served.
    _ = try journal.prune(8);
    try expect_read_many(&journal, &.{8});
    try expect_served(&journal, &.{ 3, 8 }, &.{ false, true });
}

// A probe completed by one `read_many` over its declined positions returns the same items as
// `read_many`, cold and warm.
test "fixed: a probe completed by read_many matches read_many" {
    var h = try Harness.init(4, 3);
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    try append_digests(&journal, 20);
    try journal.sync();
    var all: [20]u64 = undefined;
    for (&all, 0..) |*position, i| position.* = i;
    for (0..2) |_| {
        var served: [20]?Digest = undefined;
        journal.try_read_many_sync(&all, &served);
        var misses: [20]u64 = undefined;
        var count: usize = 0;
        for (all, served) |position, item| {
            if (item == null) {
                misses[count] = position;
                count += 1;
            }
        }
        var fetched: [20]Digest = undefined;
        try journal.read_many(misses[0..count], fetched[0..count]);
        var next: usize = 0;
        for (&served) |*item| {
            if (item.* == null) {
                item.* = fetched[next];
                next += 1;
            }
        }
        try testing.expectEqual(count, next);
        for (served, 0..) |item, position| try testing.expect(item.?.eql(test_digest(position)));
    }
    try expect_read_many(&journal, &all);
}

// A sparse batch across blobs with a mid-blob pruning boundary equals per-item reads, and
// counts one hit per item the probes found cached and one miss per other item.
test "fixed: read_many over sparse sections counts hits and misses" {
    var h = try Harness.init(8, 16);
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    try append_digests(&journal, 50);
    try journal.sync();
    _ = try journal.prune(11);
    const positions = [_]u64{ 11, 12, 19, 20, 23, 31, 40, 47, 49 };
    var expected_hits: u64 = 0;
    for (positions) |position| {
        expected_hits += @intFromBool(journal.try_read_sync(position) != null);
    }
    const hits = journal.metrics.cache_hits.metric().get();
    const misses = journal.metrics.cache_misses.metric().get();
    var batch: [positions.len]Digest = undefined;
    try journal.read_many(&positions, &batch);
    try testing.expectEqual(hits + expected_hits, journal.metrics.cache_hits.metric().get());
    const missed = positions.len - expected_hits;
    try testing.expectEqual(misses + missed, journal.metrics.cache_misses.metric().get());
    for (positions, batch) |position, item| {
        try testing.expect(item.eql(try journal.read(position)));
        try testing.expect(item.eql(test_digest(position)));
    }
    var retained: [39]u64 = undefined;
    for (&retained, 11..) |*position, i| position.* = i;
    try expect_read_many(&journal, &retained);
}

// After a reopen with a fresh cache, a batch over four blobs is all misses and returns each
// item in its own slot; the second pass is all hits.
test "fixed: read_many of cold positions across blob groups" {
    var h = try Harness.init(8, 32);
    defer h.deinit();
    var journal = try h.open();
    try append_digests(&journal, 40);
    try journal.sync();
    journal.deinit();
    try h.fresh_cache();
    journal = try h.open();
    defer journal.deinit();
    const positions = [_]u64{ 1, 5, 10, 14, 17, 22, 25, 30 };
    for (positions) |position| try testing.expectEqual(null, journal.try_read_sync(position));
    const m = &journal.metrics;
    for ([_]bool{ true, false }) |cold| {
        const hits = m.cache_hits.metric().get();
        const misses = m.cache_misses.metric().get();
        var batch: [positions.len]Digest = undefined;
        try journal.read_many(&positions, &batch);
        const new_hits = m.cache_hits.metric().get() - hits;
        const new_misses = m.cache_misses.metric().get() - misses;
        try testing.expectEqual(@as(u64, if (cold) 0 else positions.len), new_hits);
        try testing.expectEqual(@as(u64, if (cold) positions.len else 0), new_misses);
        for (positions, batch) |position, item| try testing.expect(item.eql(test_digest(position)));
    }
}

test "fixed: journal metrics" {
    var h = try Harness.init(2, 3);
    defer h.deinit();
    var journal = try h.open();
    defer journal.deinit();
    var items: [5]Digest = undefined;
    for (&items, 0..) |*item, i| item.* = test_digest(i);
    _ = try journal.append_many(&items);
    _ = try journal.append(test_digest(5));
    try journal.commit();
    try journal.sync();
    try (try journal.start_sync()).wait_release();
    _ = try journal.read(0);
    try testing.expect(journal.try_read_sync(0) != null);
    var three: [3]Digest = undefined;
    try journal.read_many(&.{ 1, 2, 4 }, &three);
    _ = try journal.prune(2);
    const m = &journal.metrics;
    try testing.expectEqual(6, m.size.metric().get());
    try testing.expectEqual(2, m.pruning_boundary.metric().get());
    try testing.expectEqual(4, m.retained.metric().get());
    try testing.expectEqual(2, m.tail_items.metric().get());
    try testing.expectEqual(1, m.append_calls.metric().get());
    try testing.expectEqual(1, m.append_many_calls.metric().get());
    try testing.expectEqual(1, m.read_calls.metric().get());
    try testing.expectEqual(1, m.read_many_calls.metric().get());
    try testing.expectEqual(5, m.items_read.metric().get());
    try testing.expectEqual(1, m.start_sync_calls.metric().get());
    try testing.expectEqual(1, m.commit_calls.metric().get());
    try testing.expectEqual(1, m.sync_calls.metric().get());
    try testing.expectEqual(5, m.cache_hits.metric().get() + m.cache_misses.metric().get());
}
