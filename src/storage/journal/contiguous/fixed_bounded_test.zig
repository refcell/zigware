//! The rest of commonware's `journal/contiguous/fixed.rs` tests: bounded opens
//! (`init_at_most`), overlong and zero-extended blobs, truncation crashes, and torn pages.
//!
//! `start_and_recover` becomes `crash()`. Crash tests that keep unsynced writes and drop
//! unsynced resizes run on `runtime.storage.faulty`.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const Sha256 = @import("cryptography").sha256.Sha256;
const Digest = @import("cryptography").sha256.Digest;
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const contiguous = @import("mod.zig");
const manager_mod = @import("../segmented/manager.zig");

const gpa = testing.allocator;
const Journal = fixed.Journal(Digest);
const Bounds = contiguous.Bounds;
const page_size = 44;

fn test_digest(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

const Harness = struct {
    storage: mocks.Storage,
    cache_ref: paged.CacheRef,
    items_per_blob: u64,
    partition: []const u8 = "test-partition",
    blobs: []const u8 = "test-partition-blobs",

    fn init(items_per_blob: u64) !Harness {
        return .{
            .storage = mocks.Storage.init(gpa),
            .cache_ref = try paged.CacheRef.init(gpa, page_size, 3),
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

    fn open_at_most(self: *Harness, max_size: u64) !Journal {
        return Journal.init_at_most(gpa, self.iface(), self.cfg(), max_size);
    }

    /// Sync and close `journal`, then reopen it retaining at most `max_size` items.
    fn reopen_at_most(self: *Harness, journal: *Journal, max_size: u64) !void {
        try journal.sync();
        journal.deinit();
        journal.* = try self.open_at_most(max_size);
    }

    fn fill(journal: *Journal, first: u64, count: u64) !void {
        for (0..count) |index| _ = try journal.append(test_digest(first + index));
    }
};

fn expect_digests(journal: *Journal, start: u64, end: u64, first: u64) !void {
    var position = start;
    while (position < end) : (position += 1) {
        try testing.expectEqual(test_digest(first + position - start), try journal.read(position));
    }
}

test "fixed: recovery rejects an overlong blob, bounded or not" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 5);
    try journal.sync();
    journal.deinit();
    // Append a sixth item to blob 0 below the journal, past `items_per_blob`.
    {
        const opened = try h.iface().open(h.blobs, &manager_mod.section_name(0));
        var writer = try paged.Writer.init(gpa, opened.blob, opened.len, 2048, &h.cache_ref);
        defer writer.deinit();
        _ = try writer.append(&test_digest(99).bytes);
        try writer.sync();
    }
    try testing.expectError(error.Corruption, h.open());
    // A bound does not excuse the overlong blob, inside it or at its boundary.
    for ([_]u64{ 3, 5 }) |cap| try testing.expectError(error.Corruption, h.open_at_most(cap));
}

test "fixed: recovery drops zero-extended pages" {
    var h = try Harness.init(10);
    defer h.deinit();
    var journal = try h.open();
    _ = try journal.append(test_digest(0));
    try testing.expectEqual(1, journal.size());
    try journal.sync();
    journal.deinit();
    // The file grew but no bytes were written.
    {
        const opened = try h.iface().open(h.blobs, &manager_mod.section_name(0));
        defer opened.blob.close();
        const zeros: [page_size * 3]u8 = @splat(0);
        try opened.blob.write_at(opened.len, &zeros, .{ .sync = true });
    }
    journal = try h.open();
    try testing.expectEqual(1, journal.size());
    try testing.expectEqual(1, try journal.append(test_digest(1)));
    try journal.destroy();
}

test "fixed: init at most" {
    var h = try Harness.init(2);
    defer h.deinit();
    var journal = try h.open();
    try h.reopen_at_most(&journal, 0);
    journal.deinit();
    journal = try h.open_at_most(1);
    try testing.expectEqual(0, journal.size());
    journal.deinit();
    journal = try h.open();
    _ = try journal.append(test_digest(0));
    try h.reopen_at_most(&journal, 1); // A no-op.
    try testing.expectEqual(1, journal.size());
    try h.reopen_at_most(&journal, 0);
    try testing.expectEqual(0, journal.size());
    for (0..7) |i| try testing.expectEqual(i, try journal.append(test_digest(i)));
    try h.reopen_at_most(&journal, 4);
    try testing.expectEqual(4, journal.size());
    try expect_digests(&journal, 0, 4, 0);
    try h.reopen_at_most(&journal, 0);
    try testing.expectEqual(0, journal.size());
    try append_and_back_off(&h, &journal);
    try journal.sync();
    journal.deinit();
    // Again with three items per blob.
    h.items_per_blob = 3;
    h.partition = "test-partition-2";
    h.blobs = "test-partition-2-blobs";
    journal = try h.open();
    try append_and_back_off(&h, &journal);
    try journal.sync();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(10 * (100 - 49), journal.size());
    _ = try journal.prune(300);
    try testing.expectEqual(10 * (100 - 49), journal.size());
    // Truncating to the prune point keeps an empty journal; below it fails.
    try h.reopen_at_most(&journal, 300);
    try testing.expectEqual(Bounds{ .start = 300, .end = 300 }, journal.get_bounds());
    try journal.sync();
    journal.deinit();
    try testing.expectError(error.ItemPruned, h.open_at_most(299));
}

/// Ten times, append 100 items and reopen 49 items earlier.
fn append_and_back_off(h: *Harness, journal: *Journal) !void {
    for (0..10) |_| {
        try Harness.fill(journal, 0, 100);
        try h.reopen_at_most(journal, journal.size() - 49);
    }
    try testing.expectEqual(10 * (100 - 49), journal.size());
}

test "fixed: init at most then commit and reopen" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 12);
    try h.reopen_at_most(&journal, 7);
    try journal.commit();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 0, .end = 7 }, journal.get_bounds());
    try expect_digests(&journal, 0, 7, 0);
    try testing.expectError(error.ItemOutOfRange, journal.read(7));
    try journal.destroy();
}

test "fixed: init at most persists the lower watermark" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 12);
    try h.reopen_at_most(&journal, 7);
    journal.deinit();
    const watermark = try Journal.persisted_watermark(gpa, h.iface(), h.partition);
    try testing.expectEqual(7, watermark.?);
    journal = try h.open();
    try journal.destroy();
}

test "fixed: recovery after the watermark is lowered before truncation" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 12);
    try journal.sync();
    try journal.test_set_recovery_watermark(7);
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 0, .end = 12 }, journal.get_bounds());
    try testing.expectEqual(7, journal.recovery_watermark());
    try testing.expectEqual(test_digest(11), try journal.read(11));
    try journal.destroy();
}

test "fixed: truncate, append, commit, and reopen" {
    var h = try Harness.init(5);
    defer h.deinit();
    var journal = try h.open();
    try Harness.fill(&journal, 0, 12);
    try h.reopen_at_most(&journal, 7);
    try Harness.fill(&journal, 100, 3);
    try journal.commit();
    journal.deinit();
    journal = try h.open();
    try testing.expectEqual(Bounds{ .start = 0, .end = 10 }, journal.get_bounds());
    try testing.expectEqual(7, journal.recovery_watermark());
    try expect_digests(&journal, 0, 7, 0);
    try expect_digests(&journal, 7, 10, 100);
    try testing.expectError(error.ItemOutOfRange, journal.read(10));
    try journal.destroy();
}

/// A journal over fault-injecting storage with two digests per 64-byte page and a one-byte
/// write buffer, so a five-item append writes four items as two full pages directly.
const FaultyHarness = struct {
    const Faulty = runtime.storage.faulty.Storage(utils.rng.TestRng);
    const crash_page_size = 64;

    inner: runtime.storage.memory.Storage,
    rng: utils.rng.TestRng,
    storage: Faulty,
    cache_ref: paged.CacheRef,
    partition: []const u8,

    fn init(self: *FaultyHarness, partition: []const u8) !void {
        self.inner = .init(gpa);
        self.rng = .init(0);
        self.storage = .init(gpa, &self.inner, &self.rng, .{});
        self.cache_ref = try paged.CacheRef.init(gpa, crash_page_size, 3);
        self.partition = partition;
    }

    fn deinit(self: *FaultyHarness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
        self.inner.deinit();
    }

    fn cfg(self: *FaultyHarness) fixed.Config {
        return .{
            .partition = self.partition,
            .items_per_blob = 100,
            .cache_ref = &self.cache_ref,
            .write_buffer = 1,
            .replay_buffer = 2048,
        };
    }

    fn open(self: *FaultyHarness, max_size: ?u64) !Journal {
        const storage = self.storage.storage();
        if (max_size) |cap| return Journal.init_at_most(gpa, storage, self.cfg(), cap);
        return Journal.init(gpa, storage, self.cfg());
    }

    /// Keep unsynced writes and drop unsynced resizes at the next crash.
    fn keep_writes_drop_resizes(self: *FaultyHarness) void {
        self.storage.config = .{
            .write_rate = .{ .failure_rate = .zero, .retention_rate = .one, .mode = .prefix },
            .resize_rate = .{ .failure_rate = .zero, .partial_rate = .zero },
        };
    }

    fn crash(self: *FaultyHarness) !void {
        try self.storage.crash();
        self.inner.crash();
        self.storage.config = .{};
    }

    /// Recover and check the journal holds `test_digest(0..base)` followed by a prefix of at
    /// most `kept` of `appended`.
    fn expect_prefix(self: *FaultyHarness, base: u64, appended: []const Digest, kept: u64) !void {
        var journal = try self.open(null);
        const size = journal.size();
        try testing.expect(size >= base and size <= base + kept);
        try expect_digests(&journal, 0, base, 0);
        var position = base;
        while (position < size) : (position += 1) {
            try testing.expectEqual(appended[position - base], try journal.read(position));
        }
        try journal.destroy();
    }
};

fn new_history() [5]Digest {
    var appended: [5]Digest = undefined;
    for (&appended, 100..) |*digest, value| digest.* = test_digest(value);
    return appended;
}

// Reopen at a page-aligned bound, append over the freed pages, and crash with the appends
// kept and the unsynced resize lost: recovery must not join new pages to the discarded suffix.
test "fixed: init at most truncation survives a crash" {
    const bound = 4;
    const appended = new_history();
    var h: FaultyHarness = undefined;
    try h.init("init-at-most-truncation-crash");
    defer h.deinit();
    var journal = try h.open(null);
    try Harness.fill(&journal, 0, 12);
    try journal.sync();
    journal.deinit();
    h.keep_writes_drop_resizes();
    journal = try h.open(bound);
    try testing.expectEqual(Bounds{ .start = 0, .end = bound }, journal.get_bounds());
    _ = try journal.append_many(&appended);
    journal.deinit();
    try h.crash();
    try h.expect_prefix(bound, &appended, appended.len);
}

// Repair a torn page at a page-aligned item boundary during init, append over the freed
// pages, and crash. With writes kept, recovery is a prefix of the new history; with the
// default faults (both dropped), it is exactly the repaired size.
test "fixed: repair truncation survives a crash" {
    const repaired = 4;
    const appended = new_history();
    for ([_]bool{ true, false }) |retained| {
        var h: FaultyHarness = undefined;
        try h.init("repair-truncation-crash");
        defer h.deinit();
        var journal = try h.open(null);
        try Harness.fill(&journal, 0, 12);
        // Commit leaves the watermark behind, so init scans the whole blob.
        try journal.commit();
        journal.deinit();
        // Tear page 2 of six: init repairs the blob to the four items on pages 0 and 1.
        const blobs = "repair-truncation-crash-blobs";
        const name = manager_mod.section_name(0);
        const page = FaultyHarness.crash_page_size;
        try paged.corrupt_page(h.storage.storage(), blobs, &name, 2, page);
        if (retained) h.keep_writes_drop_resizes();
        journal = try h.open(null);
        try testing.expectEqual(Bounds{ .start = 0, .end = repaired }, journal.get_bounds());
        _ = try journal.append_many(&appended);
        journal.deinit();
        try h.crash();
        try h.expect_prefix(repaired, &appended, if (retained) appended.len else 0);
    }
}
