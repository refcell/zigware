//! Tests of the backing contract over the fixed contiguous journal, ported from commonware's
//! `journal/contiguous/fixed.rs` and `journal/contiguous/tests.rs` (`init_sync`,
//! `last_matching`).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const Sha256 = @import("cryptography").sha256.Sha256;
const Digest = @import("cryptography").sha256.Digest;
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const authenticated = @import("authenticated.zig");
const contiguous = @import("contiguous/mod.zig");
const fixed = contiguous.fixed;

const gpa = testing.allocator;
const Journal = fixed.Journal(Digest);
const Bounds = contiguous.Bounds;

comptime {
    authenticated.assert_backing(Journal);
    authenticated.assert_backing(fixed.Journal(u64));
}

fn test_digest(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

const Harness = struct {
    storage: mocks.Storage,
    cache_ref: paged.CacheRef,
    items_per_blob: u64 = 10,
    partition: []const u8 = "test-partition",

    fn init() !Harness {
        return .{ .storage = mocks.Storage.init(gpa), .cache_ref = try .init(gpa, 44, 3) };
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

    /// A synced journal holding `test_digest(0..count)`.
    fn seed(self: *Harness, count: u64) !void {
        var journal = try Journal.init(gpa, self.storage.interface(), self.cfg());
        defer journal.deinit();
        for (0..count) |index| _ = try journal.append(test_digest(index));
        try journal.sync();
    }

    fn init_sync(self: *Harness, range: Bounds) !Journal {
        return authenticated.init_sync(Journal, gpa, self.storage.interface(), self.cfg(), range);
    }
};

test "authenticated: covers" {
    try testing.expect(authenticated.covers(.{ .start = 5, .end = 5 }, 5));
    try testing.expect(authenticated.covers(.{ .start = 5, .end = 10 }, 9));
    try testing.expect(!authenticated.covers(.{ .start = 5, .end = 10 }, 10));
    try testing.expect(!authenticated.covers(.{ .start = 5, .end = 10 }, 4));
    try testing.expect(!authenticated.covers(.{ .start = 5, .end = 5 }, 6));
}

test "authenticated: init sync after interrupted clear" {
    // State sync is the first open after a clear crashed with its intent staged. The cases
    // start below, at, and above the staged target 50.
    for ([_]u64{ 7, 50, 60 }) |start| {
        var h = try Harness.init();
        defer h.deinit();
        try h.seed(30);
        // Stage a clear to 50 and crash before any blob is removed.
        try Journal.test_stage_clear(gpa, h.storage.interface(), h.partition, 50);
        h.storage.crash();
        // A staged clear spans only its target. Any other start replaces the intent without
        // recovering the stale blobs; a start at 50 completes it.
        var journal = try h.init_sync(.{ .start = start, .end = start + 20 });
        try testing.expectEqual(Bounds{ .start = start, .end = start }, journal.get_bounds());
        for (0..3) |index| {
            try testing.expectEqual(start + index, try journal.append(test_digest(100 + index)));
        }
        try journal.sync();
        journal.deinit();
        // A surviving intent would clear the new items; stale blobs would surface below the
        // start or in place of the new items.
        journal = try Journal.init(gpa, h.storage.interface(), h.cfg());
        try testing.expectEqual(Bounds{ .start = start, .end = start + 3 }, journal.get_bounds());
        try testing.expectError(error.ItemPruned, journal.read(start - 1));
        for (0..3) |index| {
            try testing.expectEqual(test_digest(100 + index), try journal.read(start + index));
        }
        try journal.destroy();
    }
}

test "authenticated: fresh sync avoids reset writes" {
    var ordinary = try Harness.init();
    defer ordinary.deinit();
    ordinary.items_per_blob = 5;
    var plain = try fixed.Journal(u64).init(gpa, ordinary.storage.interface(), ordinary.cfg());
    plain.deinit();
    var synced = try Harness.init();
    defer synced.deinit();
    synced.items_per_blob = 5;
    const iface = synced.storage.interface();
    const range: Bounds = .{ .start = 0, .end = 10 };
    var journal = try authenticated.init_sync(fixed.Journal(u64), gpa, iface, synced.cfg(), range);
    defer journal.deinit();
    try testing.expectEqual(Bounds{ .start = 0, .end = 0 }, journal.get_bounds());
    try testing.expectEqual(ordinary.storage.writes, synced.storage.writes);
}

test "authenticated: init sync without existing data" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.init_sync(.{ .start = 15, .end = 40 });
    try testing.expectEqual(Bounds{ .start = 15, .end = 15 }, journal.get_bounds());
    try testing.expectEqual(15, try journal.append(test_digest(15)));
    try journal.destroy();
}

test "authenticated: init sync keeps an overlapping prefix and prunes below the start" {
    var h = try Harness.init();
    defer h.deinit();
    try h.seed(30);
    var journal = try h.init_sync(.{ .start = 10, .end = 25 });
    // The prefix is capped at the range end; pruning is blob-aligned.
    try testing.expectEqual(Bounds{ .start = 10, .end = 25 }, journal.get_bounds());
    for (10..25) |position| {
        try testing.expectEqual(test_digest(position), try journal.read(position));
    }
    try journal.destroy();
}

test "authenticated: init sync clears storage whose span misses the start" {
    var h = try Harness.init();
    defer h.deinit();
    try h.seed(30);
    var journal = try h.init_sync(.{ .start = 35, .end = 50 });
    try testing.expectEqual(Bounds{ .start = 35, .end = 35 }, journal.get_bounds());
    try journal.destroy();
}

test "authenticated: init sync resets a recovered prefix short of the start" {
    var h = try Harness.init();
    defer h.deinit();
    // The span of a 25-item journal reaches 30 (blob capacity), but recovery ends at 25.
    try h.seed(25);
    var journal = try h.init_sync(.{ .start = 27, .end = 40 });
    try testing.expectEqual(Bounds{ .start = 27, .end = 27 }, journal.get_bounds());
    try testing.expectEqual(27, try journal.append(test_digest(27)));
    try journal.destroy();
}

fn digest_below(limit: u64, item: Digest) bool {
    for (0..limit) |index| {
        if (std.mem.eql(u8, &item.bytes, &test_digest(index).bytes)) return true;
    }
    return false;
}

fn match_all(_: void, _: Digest) bool {
    return true;
}

fn match_none(_: void, _: Digest) bool {
    return false;
}

test "authenticated: last matching" {
    var h = try Harness.init();
    defer h.deinit();
    try h.seed(30);
    var recovery = try Journal.recover(gpa, h.storage.interface(), h.cfg(), 32);
    defer recovery.deinit();
    try testing.expectEqual(Bounds{ .start = 0, .end = 30 }, recovery.get_bounds());
    try testing.expectEqual(30, try authenticated.last_matching(&recovery, 32, {}, match_all));
    try testing.expectEqual(12, try authenticated.last_matching(&recovery, 12, {}, match_all));
    // The latest match below the ceiling: items 0..7 match.
    const below: u64 = 7;
    try testing.expectEqual(7, try authenticated.last_matching(&recovery, 30, below, digest_below));
    // No match in an unpruned journal selects genesis.
    try testing.expectEqual(0, try authenticated.last_matching(&recovery, 30, {}, match_none));
    // A pruned journal cannot select genesis or a ceiling below its start.
    _ = try recovery.prune(10);
    const none = authenticated.last_matching(&recovery, 30, {}, match_none);
    try testing.expectError(error.ItemPruned, none);
    const below_start = authenticated.last_matching(&recovery, 5, {}, match_all);
    try testing.expectError(error.ItemPruned, below_start);
}
