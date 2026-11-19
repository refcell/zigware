//! commonware's `journal/contiguous/fixed.rs` recovery tests for rollovers without a commit,
//! partial items, torn interior and boundary pages, pages below the watermark (adopted, not
//! rescanned), gaps between blobs, and prune crashes.
//!
//! commonware's `test_sync_blob` (await one blob's rollover sync) has no counterpart: zigware's
//! rollover syncs the filled blob before it returns, and `commit` makes later blobs durable
//! without advancing the watermark, which leaves the same durable state.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const Sha256 = @import("cryptography").sha256.Sha256;
const Digest = @import("cryptography").sha256.Digest;
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const contiguous = @import("mod.zig");
const authenticated = @import("../authenticated.zig");
const manager_mod = @import("../segmented/manager.zig");

const gpa = testing.allocator;
const Bounds = contiguous.Bounds;
const checksum_size = 12;

fn test_digest(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

const Options = struct {
    items_per_blob: u64 = 10,
    page_size: u16 = 44,
    cache_pages: u32 = 3,
    buffer: usize = 2048,
};

fn Harness(comptime partition: []const u8) type {
    return struct {
        const Self = @This();
        const blobs = partition ++ "-blobs";

        storage: mocks.Storage,
        cache_ref: paged.CacheRef,
        options: Options,

        fn init(options: Options) !Self {
            return .{
                .storage = mocks.Storage.init(gpa),
                .cache_ref = try paged.CacheRef.init(gpa, options.page_size, options.cache_pages),
                .options = options,
            };
        }

        fn deinit(self: *Self) void {
            self.cache_ref.deinit();
            self.storage.deinit();
        }

        fn cfg(self: *Self) fixed.Config {
            return .{
                .partition = partition,
                .items_per_blob = self.options.items_per_blob,
                .cache_ref = &self.cache_ref,
                .write_buffer = self.options.buffer,
                .replay_buffer = self.options.buffer,
            };
        }

        fn iface(self: *Self) runtime.storage.Storage {
            return self.storage.interface();
        }

        fn open(self: *Self, comptime A: type) !fixed.Journal(A) {
            return fixed.Journal(A).init(gpa, self.iface(), self.cfg());
        }

        /// A journal of `count` digests of their positions, closed without a sync.
        fn seed(self: *Self, count: u64, durability: enum { none, commit, sync }) !void {
            var journal = try self.open(Digest);
            defer journal.deinit();
            for (0..count) |i| _ = try journal.append(test_digest(i));
            switch (durability) {
                .none => {},
                .commit => try journal.commit(),
                .sync => try journal.sync(),
            }
        }

        fn blob_count(self: *Self) !usize {
            const indices = try contiguous.blobs.indices(gpa, self.iface(), blobs);
            defer gpa.free(indices);
            return indices.len;
        }

        fn blob_len(self: *Self, index: u64) !u64 {
            const opened = try self.iface().open(blobs, &manager_mod.section_name(index));
            defer opened.blob.close();
            return opened.len;
        }

        /// A paged writer over blob `index`, below the journal.
        fn writer(self: *Self, index: u64, recovering: bool) !paged.Writer {
            const opened = try self.iface().open(blobs, &manager_mod.section_name(index));
            errdefer opened.blob.close();
            const buffer = self.options.buffer;
            const cache_ref = &self.cache_ref;
            const blob = opened.blob;
            var result = try paged.Writer.open_recovery(gpa, blob, opened.len, buffer, cache_ref);
            if (!recovering) result.finish_recovery();
            return result;
        }

        /// Tear physical page `page` of blob `index` (one flipped byte).
        fn corrupt(self: *Self, index: u64, page: u64) !void {
            const name = manager_mod.section_name(index);
            try paged.corrupt_page(self.iface(), blobs, &name, page, self.options.page_size);
        }

        /// Durably replace byte `offset` of physical page `page` of blob `index` with
        /// `byte` (or its complement when null), returning the old byte.
        fn set_byte(self: *Self, index: u64, page: u64, offset: u64, byte: ?u8) !u8 {
            const physical = @as(u64, self.options.page_size) + checksum_size;
            const position = page * physical + offset;
            const opened = try self.iface().open(blobs, &manager_mod.section_name(index));
            defer opened.blob.close();
            var old: [1]u8 = undefined;
            try opened.blob.read_at(position, &old);
            const new: [1]u8 = .{byte orelse ~old[0]};
            try opened.blob.write_at(position, &new, .{ .sync = true });
            return old[0];
        }

        fn resize_blob(self: *Self, index: u64, len: u64) !void {
            const opened = try self.iface().open(blobs, &manager_mod.section_name(index));
            defer opened.blob.close();
            try opened.blob.resize(len);
            try opened.blob.sync();
        }
    };
}

fn be_bytes(values: []const u64, out: []u8) []u8 {
    for (values, 0..) |value, i| std.mem.writeInt(u64, out[i * 8 ..][0..8], value, .big);
    return out[0 .. values.len * 8];
}

fn expect_digests(journal: *fixed.Journal(Digest), start: u64, end: u64) !void {
    for (start..end) |i| try testing.expectEqual(test_digest(i), try journal.read(i));
}

/// How many of positions `[start, end)` fail to read; the rest must hold their digests.
fn damaged_reads(journal: *fixed.Journal(Digest), start: u64, end: u64) !u64 {
    var damaged: u64 = 0;
    for (start..end) |i| {
        if (journal.read(i)) |item| {
            try testing.expectEqual(test_digest(i), item);
        } else |_| damaged += 1;
    }
    return damaged;
}

test "fixed: recovery preserves rolled predecessors without commit" {
    var h = try Harness("test-partition").init(.{ .items_per_blob = 1 });
    defer h.deinit();
    var journal = try h.open(Digest);
    try testing.expectEqual(0, try journal.append(test_digest(10)));
    try journal.sync();
    try testing.expectEqual(1, try journal.append(test_digest(20)));
    try testing.expectEqual(2, try journal.append(test_digest(30)));
    journal.deinit();
    try testing.expect(try h.blob_count() > 2);
    journal = try h.open(Digest);
    try testing.expectEqual(Bounds{ .start = 0, .end = 3 }, journal.get_bounds());
    for (0..3) |i| try testing.expectEqual(test_digest(10 * (i + 1)), try journal.read(i));
    journal.deinit();
    // The filled predecessors plus the empty tail.
    try testing.expectEqual(4, try h.blob_count());
    journal = try h.open(Digest);
    try testing.expectEqual(3, try journal.append(test_digest(42)));
    try testing.expectEqual(test_digest(42), try journal.read(3));
    try journal.destroy();
}

test "fixed: recovery preserves the first rollover without commit" {
    var h = try Harness("test-partition").init(.{ .items_per_blob = 1 });
    defer h.deinit();
    var journal = try h.open(Digest);
    try testing.expectEqual(0, try journal.append(test_digest(10)));
    try testing.expectEqual(1, try journal.append(test_digest(20)));
    journal.deinit();
    try testing.expect(try h.blob_count() > 1);
    journal = try h.open(Digest);
    try testing.expectEqual(Bounds{ .start = 0, .end = 2 }, journal.get_bounds());
    journal.deinit();
    try testing.expectEqual(3, try h.blob_count());
    journal = try h.open(Digest);
    try testing.expectEqual(2, try journal.append(test_digest(42)));
    try testing.expectEqual(test_digest(42), try journal.read(2));
    try journal.destroy();
}

// Five-byte pages crossed by eight-byte items, with page 4 torn:
//   pages: [0..5) [5..10) [10..15) [15..20) [20..25) [25..30)
//   state:    ok      ok       ok       ok      torn       ok
// Backward sizing would stop at page 5 and round 30 bytes to 24, inside the torn page.
// Forward validation stops at 20 and rounds down to 16, inside valid page 3.
test "fixed: recovery validates pages before trimming trailing bytes" {
    const Test = Harness("fixed-validate-before-tail-trim");
    var h = try Test.init(.{ .page_size = 5, .cache_pages = 4, .buffer = 128 });
    defer h.deinit();
    {
        var writer = try h.writer(0, true);
        defer writer.deinit();
        var buffer: [32]u8 = undefined;
        _ = try writer.append(be_bytes(&.{ 11, 22, 33, 44 }, &buffer));
        try writer.truncate(30);
        try writer.sync();
    }
    try h.corrupt(0, 4);
    var journal = try h.open(u64);
    try testing.expectEqual(Bounds{ .start = 0, .end = 2 }, journal.get_bounds());
    try testing.expectEqual(11, try journal.read(0));
    try testing.expectEqual(22, try journal.read(1));
    try journal.destroy();
}

// The oldest blob may begin after its natural start: the watermark's acknowledged bytes are
// measured from the retained start before a partial item is repaired.
test "fixed: recovery watermark uses the retained blob start" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    {
        var journal = try fixed.Journal(u64).init_at_size(gpa, h.iface(), h.cfg(), 7);
        defer journal.deinit();
        try testing.expectEqual(7, try journal.append(11));
        try testing.expectEqual(8, try journal.append(22));
        try journal.sync();
    }
    {
        var writer = try h.writer(0, true);
        defer writer.deinit();
        try testing.expectEqual(16, writer.size());
        _ = try writer.append(&.{ 0, 0, 0, 0 });
        try testing.expectEqual(20, writer.size());
        try writer.sync();
    }
    var journal = try h.open(u64);
    try testing.expectEqual(Bounds{ .start = 7, .end = 9 }, journal.get_bounds());
    try testing.expectEqual(11, try journal.read(7));
    try testing.expectEqual(22, try journal.read(8));
    try journal.destroy();
}

// A torn item write can leave a partial item on the tail with every page valid: recovery
// floors to whole items and later appends stay aligned.
test "fixed: recovery truncates a partial item tail" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    {
        var journal = try h.open(u64);
        defer journal.deinit();
        for ([_]u64{ 11, 22, 33 }) |value| _ = try journal.append(value);
        try journal.sync();
    }
    {
        var writer = try h.writer(0, false);
        defer writer.deinit();
        try testing.expectEqual(24, writer.size());
        var buffer: [8]u8 = undefined;
        _ = try writer.append(be_bytes(&.{44}, &buffer)[0..3]);
        try writer.sync();
    }
    var journal = try h.open(u64);
    try testing.expectEqual(Bounds{ .start = 0, .end = 3 }, journal.get_bounds());
    try testing.expectEqual(33, try journal.read(2));
    try testing.expectEqual(3, try journal.append(44));
    try journal.sync();
    try testing.expectEqual(44, try journal.read(3));
    try journal.destroy();
}

// A hole between a mid-blob watermark and the blob's end truncates above the acknowledged
// prefix (acknowledged 16 < recoverable floor 24 < size 32), while a tear beneath the
// watermark is adopted and fails lazily at read.
test "fixed: recovery truncates above a mid-blob watermark" {
    const Test = Harness("fixed-truncate-above-watermark");
    var h = try Test.init(.{ .page_size = 5, .cache_pages = 4, .buffer = 128 });
    defer h.deinit();
    {
        var journal = try h.open(u64);
        defer journal.deinit();
        for ([_]u64{ 11, 22 }) |value| _ = try journal.append(value);
        try journal.sync();
    }
    {
        var writer = try h.writer(0, false);
        defer writer.deinit();
        try testing.expectEqual(16, writer.size());
        var buffer: [16]u8 = undefined;
        _ = try writer.append(be_bytes(&.{ 33, 44 }, &buffer));
        try writer.sync();
    }
    try h.corrupt(0, 1);
    try h.corrupt(0, 5);
    var journal = try h.open(u64);
    try testing.expectEqual(Bounds{ .start = 0, .end = 3 }, journal.get_bounds());
    try testing.expect(std.meta.isError(journal.read(0)));
    try testing.expect(std.meta.isError(journal.read(1)));
    try testing.expectEqual(33, try journal.read(2));
    try journal.destroy();
}

// A valid last page above a lost interior page (a crash during the rollover sync) is invisible
// to the writer's backward scan: recovery forward-validates and truncates at the hole.
test "fixed: recovery truncates a torn interior page" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    try h.seed(15, .commit);
    // Blob 0 holds 320 bytes across 8 pages; pages 0-2 hold 132 bytes, four whole items.
    try h.corrupt(0, 3);
    var journal = try h.open(Digest);
    try testing.expectEqual(Bounds{ .start = 0, .end = 4 }, journal.get_bounds());
    try expect_digests(&journal, 0, 4);
    try testing.expectEqual(4, try journal.append(test_digest(42)));
    try journal.destroy();
}

test "fixed: recovery truncates a torn interior page in the tail" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    try h.seed(15, .commit);
    // Blob 1 keeps only page 0: one whole item after blob 0's ten.
    try h.corrupt(1, 1);
    var journal = try h.open(Digest);
    try testing.expectEqual(Bounds{ .start = 0, .end = 11 }, journal.get_bounds());
    try expect_digests(&journal, 0, 11);
    try testing.expectEqual(11, try journal.append(test_digest(42)));
    try journal.destroy();
}

// A bounded open whose cap lies inside a torn page: one byte of an unsynced rewrite of page 10
// was lost, so only its shorter durable checksum slot validates. Recovery truncates at the
// hole before serving the retained prefix.
test "fixed: bounded recovery repairs a torn rewrite at the cap" {
    const Test = Harness("torn-rewrite-at-cap");
    var h = try Test.init(.{ .items_per_blob = 64, .page_size = 100 });
    defer h.deinit();
    {
        var journal = try h.open(Digest);
        defer journal.deinit();
        for (0..33) |i| _ = try journal.append(test_digest(i));
        // Page 10 holds the acknowledged prefix's last 56 bytes; the watermark is 33.
        try journal.sync();
        for (33..38) |i| _ = try journal.append(test_digest(i));
        // Pages 10..12 are written without advancing the watermark.
        try journal.commit();
    }
    try testing.expect(try h.set_byte(0, 10, 60, 0) != 0);
    var recovery = try fixed.Recovery(Digest).open(gpa, h.iface(), h.cfg(), 32);
    try testing.expectEqual(Bounds{ .start = 0, .end = 32 }, recovery.get_bounds());
    try testing.expectEqual(test_digest(31), try recovery.item(31));
    try testing.expectEqual(32, try authenticated.last_matching(&recovery, 32, {}, match_all));
    var journal = try recovery.publish(32);
    try testing.expectEqual(Bounds{ .start = 0, .end = 32 }, journal.get_bounds());
    try testing.expectEqual(test_digest(31), try journal.read(31));
    try journal.destroy();
}

// A bounded open whose cap lies below the watermark, both inside a torn page, repairs the page
// at the end of its durable prefix. The acknowledged items survive, the persisted watermark is
// untouched, and a later open with a larger cap or none recovers all of them.
test "fixed: bounded recovery below the watermark keeps acknowledged items" {
    const Test = Harness("torn-rewrite-below-watermark");
    var h = try Test.init(.{ .items_per_blob = 64, .page_size = 100 });
    defer h.deinit();
    {
        var journal = try h.open(Digest);
        defer journal.deinit();
        for (0..33) |i| _ = try journal.append(test_digest(i));
        try journal.sync();
        for (33..38) |i| _ = try journal.append(test_digest(i));
        try journal.commit();
    }
    try testing.expect(try h.set_byte(0, 10, 60, 0) != 0);
    // Cap 32 and watermark 33 both end inside torn page 10.
    {
        var recovery = try fixed.Recovery(Digest).open(gpa, h.iface(), h.cfg(), 32);
        defer recovery.deinit();
        try testing.expectEqual(Bounds{ .start = 0, .end = 32 }, recovery.get_bounds());
        try testing.expectEqual(test_digest(31), try recovery.item(31));
    }
    const partition = "torn-rewrite-below-watermark";
    const watermark = try fixed.Journal(Digest).persisted_watermark(gpa, h.iface(), partition);
    try testing.expectEqual(33, watermark.?);
    // A larger cap and no cap both recover the 33 acknowledged items.
    {
        var recovery = try fixed.Recovery(Digest).open(gpa, h.iface(), h.cfg(), 36);
        defer recovery.deinit();
        try testing.expectEqual(Bounds{ .start = 0, .end = 33 }, recovery.get_bounds());
        try testing.expectEqual(test_digest(32), try recovery.item(32));
    }
    var journal = try h.open(Digest);
    try testing.expectEqual(Bounds{ .start = 0, .end = 33 }, journal.get_bounds());
    for (0..33) |i| try testing.expectEqual(test_digest(i), try journal.read(i));
    try journal.destroy();
}

fn match_all(_: void, _: Digest) bool {
    return true;
}

// A torn page beneath the watermark is external corruption: an unbounded open adopts the
// journal without mutating it, and the damage surfaces as read errors.
test "fixed: recovery adopts a torn page below the watermark" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    try h.seed(15, .sync);
    try h.corrupt(0, 3);
    const len_before = try h.blob_len(0);
    var journal = try h.open(Digest);
    try testing.expect(try damaged_reads(&journal, 0, 10) > 0);
    try expect_digests(&journal, 10, 15);
    journal.deinit();
    try testing.expectEqual(len_before, try h.blob_len(0));
    // A retry adopts the same state.
    journal = try h.open(Digest);
    journal.deinit();
    try testing.expectEqual(len_before, try h.blob_len(0));
}

test "fixed: recovery skips watermark-covered blobs" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    try h.seed(15, .sync);
    try h.corrupt(0, 2);
    var journal = try h.open(Digest);
    try testing.expectEqual(Bounds{ .start = 0, .end = 15 }, journal.get_bounds());
    try testing.expectEqual(test_digest(0), try journal.read(0));
    try testing.expect(std.meta.isError(journal.read(2)));
    try testing.expectEqual(test_digest(14), try journal.read(14));
    try journal.destroy();
}

test "fixed: recovery adopts a torn page below a mid-blob watermark" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    // The watermark (15) is mid-blob: blob 1 holds 160 bytes across 4 pages.
    try h.seed(15, .sync);
    try h.corrupt(1, 1);
    const len_before = try h.blob_len(1);
    for (0..2) |_| {
        var journal = try h.open(Digest);
        defer journal.deinit();
        try testing.expect(try damaged_reads(&journal, 10, 15) > 0);
        try expect_digests(&journal, 0, 10);
    }
    try testing.expectEqual(len_before, try h.blob_len(1));
}

// The torn page holding the watermark's boundary no longer backs acknowledged items: init
// fails, and a retry fails the same way without mutating further.
test "fixed: recovery rejects a torn boundary page" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    // The watermark acknowledges 160 bytes of blob 1, ending inside page 3.
    try h.seed(15, .sync);
    _ = try h.set_byte(1, 3, 5, null);
    try testing.expectError(error.Corruption, h.open(Digest));
    const len_mid = try h.blob_len(1);
    try testing.expectError(error.Corruption, h.open(Digest));
    try testing.expectEqual(len_mid, try h.blob_len(1));
}

// Blobs 0 and 1 are durable from rollover; blob 2's items were only buffered.
test "fixed: recovery of an unsynced tail keeps the contiguous prefix" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    try h.seed(25, .none);
    try testing.expectEqual(3, try h.blob_count());
    try testing.expect(try h.blob_len(0) > 0);
    try testing.expect(try h.blob_len(1) > 0);
    try testing.expectEqual(0, try h.blob_len(2));
    var journal = try h.open(Digest);
    try testing.expectEqual(Bounds{ .start = 0, .end = 20 }, journal.get_bounds());
    try expect_digests(&journal, 0, 20);
    try testing.expectError(error.ItemOutOfRange, journal.read(20));
    try testing.expectEqual(20, try journal.append(test_digest(999)));
    try testing.expectEqual(test_digest(999), try journal.read(20));
    try journal.destroy();
}

// A durable blob beyond an emptied intermediate blob, above the watermark, is rolled back.
test "fixed: recovery rolls back a durable blob after a gap" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    {
        var journal = try h.open(Digest);
        defer journal.deinit();
        for (0..10) |i| _ = try journal.append(test_digest(i));
        try journal.sync();
        for (10..28) |i| _ = try journal.append(test_digest(i));
        try journal.commit();
    }
    try h.resize_blob(1, 0);
    try testing.expectEqual(3, try h.blob_count());
    try testing.expect(try h.blob_len(0) > 0);
    try testing.expectEqual(0, try h.blob_len(1));
    try testing.expect(try h.blob_len(2) > 0);
    var journal = try h.open(Digest);
    try testing.expectEqual(Bounds{ .start = 0, .end = 10 }, journal.get_bounds());
    try expect_digests(&journal, 0, 10);
    try testing.expectError(error.ItemOutOfRange, journal.read(10));
    // The orphaned blob 2 is gone; the emptied blob 1 is the recovered tail.
    try testing.expectEqual(2, try h.blob_count());
    try testing.expectEqual(10, try journal.append(test_digest(999)));
    try testing.expectEqual(test_digest(999), try journal.read(10));
    try journal.destroy();
}

// Blob removal is durable, so prune makes the unsynced tail durable first.
test "fixed: a prune crash retains the unsynced tail" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    {
        var journal = try h.open(Digest);
        defer journal.deinit();
        for (0..10) |i| _ = try journal.append(test_digest(i));
        try journal.sync();
        for (10..25) |i| _ = try journal.append(test_digest(i));
        try testing.expect(try journal.prune(10));
    }
    h.storage.crash();
    var journal = try h.open(Digest);
    try testing.expectEqual(Bounds{ .start = 10, .end = 25 }, journal.get_bounds());
    try expect_digests(&journal, 10, 25);
    try journal.destroy();
}

// An emptied oldest blob under a watermark of 20 is corruption.
test "fixed: recovery of an empty oldest blob with an orphaned newer blob" {
    var h = try Harness("test-partition").init(.{});
    defer h.deinit();
    try h.seed(20, .sync);
    try testing.expect(try h.blob_len(0) > 0);
    try h.resize_blob(0, 0);
    try testing.expectError(error.Corruption, h.open(Digest));
}
