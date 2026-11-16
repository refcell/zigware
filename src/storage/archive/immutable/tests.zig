//! Tests for the immutable archive, ported from commonware's `archive/immutable/mod.rs` and the
//! immutable cases of the shared `archive/mod.rs` tests.
//!
//! Restarts drop the archive (`deinit`) and reopen it on the same storage; `crash()` drops
//! unsynced data as commonware's `start_and_recover` does. Commonware's interrupted-destroy
//! test samples removal faults by seed; here every removal budget up to a full destroy runs.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const immutable = @import("mod.zig");

const MockStorage = runtime.buffer.mocks.Storage;
const gpa = testing.allocator;

pub const Harness = struct {
    storage: MockStorage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,
    /// Opens so far, naming each open's metric scope.
    opens: u32 = 0,

    pub fn init() !Harness {
        return .{
            .storage = MockStorage.init(gpa),
            .cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10),
            .registry = metrics.Registry.init(gpa),
        };
    }

    pub fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    /// Open an archive with metrics under a scope unique to this open.
    pub fn open(
        self: *Harness,
        comptime K: type,
        comptime V: type,
        cfg: immutable.Config(V),
    ) !immutable.Archive(K, V) {
        var name: [16]u8 = undefined;
        const scope_name = try std.fmt.bufPrint(&name, "open{d}", .{self.opens});
        self.opens += 1;
        const scope = metrics.Scope.init(&self.registry).child(scope_name);
        return immutable.Archive(K, V).init(gpa, self.storage.interface(), scope, cfg);
    }

    /// The archive configuration of commonware's shared `create_immutable`.
    pub fn shared_config(self: *Harness, compression: ?u8) immutable.Config(i32) {
        return .{
            .metadata_partition = "test-metadata",
            .freezer_table_partition = "test-freezer-table",
            .freezer_table_initial_size = 64,
            .freezer_table_resize_frequency = 2,
            .freezer_table_resize_chunk_size = 32,
            .freezer_key_partition = "test-freezer-key",
            .freezer_key_cache_ref = &self.cache_ref,
            .freezer_value_partition = "test-freezer-value",
            .freezer_value_target_size = 1024 * 1024,
            .freezer_value_compression = compression,
            .ordinal_partition = "test-ordinal",
            .items_per_section = 1024,
            .freezer_key_write_buffer = 1024 * 1024,
            .freezer_value_write_buffer = 1024 * 1024,
            .ordinal_write_buffer = 1024 * 1024,
            .replay_buffer = 1024 * 1024,
            .codec_config = {},
        };
    }

    /// commonware's small-section `config(items_per_section)`.
    pub fn small_config(self: *Harness, items_per_section: u64) immutable.Config(i32) {
        return .{
            .metadata_partition = "destroy-metadata",
            .freezer_table_partition = "destroy-freezer-table",
            .freezer_table_initial_size = 4,
            .freezer_table_resize_frequency = 2,
            .freezer_table_resize_chunk_size = 2,
            .freezer_key_partition = "destroy-freezer-key",
            .freezer_key_cache_ref = &self.cache_ref,
            .freezer_value_partition = "destroy-freezer-value",
            .freezer_value_target_size = 64,
            .ordinal_partition = "destroy-ordinal",
            .items_per_section = items_per_section,
            .freezer_key_write_buffer = 1024,
            .freezer_value_write_buffer = 1024,
            .ordinal_write_buffer = 1024,
            .replay_buffer = 1024,
            .codec_config = {},
        };
    }
};

const Key = [64]u8;
const Shared = immutable.Archive(Key, i32);
const Digest = [32]u8;
const Small = immutable.Archive(Digest, i32);

fn test_key(name: []const u8) Key {
    std.debug.assert(name.len <= 64);
    var key: Key = @splat(0);
    @memcpy(key[0..name.len], name);
    return key;
}

/// commonware's `Sha256::hash(&[&index.to_be_bytes()])` keys.
fn digest_key(index: u64) Digest {
    var digest: Digest = undefined;
    const bytes = std.mem.toBytes(std.mem.nativeToBig(u64, index));
    std.crypto.hash.sha2.Sha256.hash(&bytes, &digest, .{});
    return digest;
}

fn expect_index(archive: anytype, index: u64, expected: ?i32) !void {
    try testing.expectEqual(expected, try archive.get(.{ .index = index }));
}

fn expect_key(archive: anytype, key: anytype, expected: ?i32) !void {
    try testing.expectEqual(expected, try archive.get(.{ .key = &key }));
}

// Shared archive tests (commonware `archive/mod.rs`).

fn check_put_get(compression: ?u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var archive = try harness.open(Key, i32, harness.shared_config(compression));
    defer archive.deinit();
    const key = test_key("testkey");
    try testing.expect(!try archive.has(.{ .index = 1 }));
    try testing.expect(!try archive.has(.{ .key = &key }));
    try archive.put(1, key, 1);
    try testing.expect(try archive.has(.{ .index = 1 }));
    try testing.expect(try archive.has(.{ .key = &key }));
    try expect_key(&archive, key, 1);
    try expect_index(&archive, 1, 1);
    try archive.sync();
}

test "immutable put get" {
    try check_put_get(null);
    try check_put_get(3);
}

fn check_duplicate_key(compression: ?u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var archive = try harness.open(Key, i32, harness.shared_config(compression));
    defer archive.deinit();
    try archive.put(1, test_key("duplicate"), 1);
    try archive.put(1, test_key("duplicate"), 2); // Idempotent.
    try expect_index(&archive, 1, 1);
    try expect_key(&archive, test_key("duplicate"), 1);
    // The same key at two indices: both indices resolve, and the key resolves to either.
    const key = test_key("dupe-xindex");
    try archive.put(2, key, 20);
    try archive.put(5, key, 50);
    try expect_index(&archive, 2, 20);
    try expect_index(&archive, 5, 50);
    const got = (try archive.get(.{ .key = &key })).?;
    try testing.expect(got == 20 or got == 50);
    try testing.expect(try archive.has(.{ .key = &key }));
    // Missing entries.
    try expect_index(&archive, 3, null);
    try expect_key(&archive, test_key("nonexistent"), null);
}

test "immutable duplicate key, cross index, and nonexistent" {
    try check_duplicate_key(null);
    try check_duplicate_key(3);
}

fn check_persistence(compression: ?u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.shared_config(compression);
    const names = [_][]const u8{ "key1", "key2", "key3" };
    {
        var archive = try harness.open(Key, i32, cfg);
        defer archive.deinit();
        for (names, 1..) |name, index| try archive.put(index, test_key(name), @intCast(index));
        try archive.sync();
    }
    var archive = try harness.open(Key, i32, cfg);
    defer archive.deinit();
    for (names, 1..) |name, index| {
        try expect_index(&archive, index, @intCast(index));
        try expect_key(&archive, test_key(name), @intCast(index));
    }
}

test "immutable persistence" {
    try check_persistence(null);
    try check_persistence(3);
}

fn check_ranges(compression: ?u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.shared_config(compression);
    var rng = utils.rng.TestRng.init(0);
    var indices: [100]u64 = undefined;
    {
        var archive = try harness.open(Key, i32, cfg);
        defer archive.deinit();
        var last: u64 = 0;
        for (&indices) |*index| {
            last += utils.rng.range_at_most(&rng, u64, 1, 10);
            index.* = last;
            var key: Key = undefined;
            rng.fill_bytes(&key);
            try archive.put(last, key, @bitCast(rng.next_u32()));
        }
        try archive.sync();
    }
    var archive = try harness.open(Key, i32, cfg);
    defer archive.deinit();
    const before = archive.next_gap(0);
    try testing.expectEqual(null, before.current_end);
    try testing.expectEqual(indices[0], before.next_start);
    var i: usize = 0;
    while (i < indices.len) {
        var j = i;
        while (j + 1 < indices.len and indices[j + 1] == indices[j] + 1) j += 1;
        const next: ?u64 = if (j + 1 < indices.len) indices[j + 1] else null;
        const gap = archive.next_gap(indices[i]);
        try testing.expectEqual(indices[j], gap.current_end);
        try testing.expectEqual(next, gap.next_start);
        if (next != null and next.? > indices[j] + 1) {
            const inside = archive.next_gap(indices[j] + 1);
            try testing.expectEqual(null, inside.current_end);
            try testing.expectEqual(next, inside.next_start);
        }
        i = j + 1;
    }
}

test "immutable ranges" {
    try check_ranges(null);
    try check_ranges(3);
}

/// commonware's `test_many_keys_impl`: random keys with random syncs, checked before and
/// after a restart. Returns the storage audit.
fn check_many_keys(compression: ?u8, count: usize) ![4]u8 {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.shared_config(compression);
    var rng = utils.rng.TestRng.init(0);
    const keys = try gpa.alloc(Key, count);
    defer gpa.free(keys);
    const values = try gpa.alloc(i32, count);
    defer gpa.free(values);
    {
        var archive = try harness.open(Key, i32, cfg);
        defer archive.deinit();
        for (keys, values, 0..) |*key, *value, index| {
            rng.fill_bytes(key);
            value.* = @bitCast(rng.next_u32());
            try archive.put(index, key.*, value.*);
            if (utils.rng.bernoulli(&rng, 0.1)) try archive.sync();
        }
        try archive.sync();
        try check_keys(&archive, keys, values);
    }
    var archive = try harness.open(Key, i32, cfg);
    defer archive.deinit();
    try check_keys(&archive, keys, values);
    return harness.storage.backend.audit();
}

fn check_keys(archive: anytype, keys: []const Key, values: []const i32) !void {
    for (keys, values, 0..) |*key, value, index| {
        try testing.expectEqual(@as(?i32, value), try archive.get(.{ .index = index }));
        try testing.expectEqual(@as(?i32, value), try archive.get(.{ .key = key }));
    }
}

test "immutable many keys and determinism" {
    const first = try check_many_keys(null, 1000);
    try testing.expectEqual(first, try check_many_keys(null, 1000));
    const compressed = try check_many_keys(3, 1000);
    try testing.expectEqual(compressed, try check_many_keys(3, 1000));
}

// Immutable archive tests (commonware `archive/immutable/mod.rs`).

test "immutable init rejects changed items per section" {
    var harness = try Harness.init();
    defer harness.deinit();
    // A partial section records its size in its bitmap.
    {
        var archive = try harness.open(Digest, i32, harness.small_config(4));
        defer archive.deinit();
        try archive.put(0, digest_key(0), 0);
        try archive.put_sync(5, digest_key(5), 50);
    }
    for ([_]u64{ 8, 2 }) |items_per_section| {
        const cfg = harness.small_config(items_per_section);
        try testing.expectError(error.RecordCorrupted, harness.open(Digest, i32, cfg));
    }
    {
        var archive = try harness.open(Digest, i32, harness.small_config(4));
        try archive.destroy();
    }
    // A complete section records its size only through the length of its ordinal blob.
    {
        var archive = try harness.open(Digest, i32, harness.small_config(8));
        defer archive.deinit();
        for (0..8) |index| try archive.put(index, digest_key(index), @intCast(index));
        try archive.sync();
    }
    for ([_]u64{ 4, 16 }) |items_per_section| {
        // An ordinal error (commonware's `Error::Ordinal(_)`), not the archive's own check.
        if (harness.open(Digest, i32, harness.small_config(items_per_section))) |opened| {
            var archive = opened;
            archive.deinit();
            return error.TestExpectedError;
        } else |err| {
            try testing.expect(err == error.MissingRecord or err == error.InvalidRecord);
        }
    }
    var archive = try harness.open(Digest, i32, harness.small_config(8));
    defer archive.deinit();
    for (0..8) |index| try expect_index(&archive, index, @intCast(index));
}

/// The entries of the interrupted-destroy test.
fn destroy_value(index: u64) i32 {
    return @intCast(index * 7);
}

/// Commit two generations (indices 0..10), leave index 10 unsynced, then destroy with
/// `removals` successful removals. Returns whether the destroy was interrupted.
fn interrupted_destroy(harness: *Harness, removals: u32) !bool {
    var archive = try harness.open(Digest, i32, harness.small_config(4));
    for (0..11) |index| {
        try archive.put(index, digest_key(index), destroy_value(index));
        if (index == 4 or index == 9) try archive.sync();
    }
    harness.storage.remove_failures_after = removals;
    defer harness.storage.remove_failures_after = null;
    archive.destroy() catch return true;
    return false;
}

test "immutable interrupted destroy reopens" {
    var interrupted: u32 = 0;
    var removals: u32 = 0;
    while (true) : (removals += 1) {
        var harness = try Harness.init();
        defer harness.deinit();
        if (!try interrupted_destroy(&harness, removals)) break;
        interrupted += 1;
        harness.storage.crash();
        // The reopened archive holds exactly the latest commit or nothing, with index and
        // key views agreeing.
        var archive = try harness.open(Digest, i32, harness.small_config(4));
        var present: u64 = 0;
        for (0..11) |index| {
            const key = digest_key(index);
            const by_index = try archive.get(.{ .index = index });
            if (by_index) |stored| try testing.expectEqual(destroy_value(index), stored);
            try testing.expectEqual(by_index, try archive.get(.{ .key = &key }));
            try testing.expectEqual(by_index != null, try archive.has(.{ .index = index }));
            try testing.expectEqual(by_index != null, try archive.has(.{ .key = &key }));
            if (by_index != null) {
                try testing.expectEqual(present, index);
                present += 1;
            }
        }
        try testing.expect(present == 0 or present == 10);
        // A retried destroy completes and leaves nothing behind.
        try archive.destroy();
        var reopened = try harness.open(Digest, i32, harness.small_config(4));
        defer reopened.deinit();
        try testing.expectEqual(null, reopened.first_index());
    }
    try testing.expect(interrupted > 3);
}

fn unclean_config(harness: *Harness) !immutable.Config(i32) {
    var cfg = harness.shared_config(3);
    cfg.freezer_table_initial_size = 8192;
    cfg.freezer_table_resize_frequency = 4;
    cfg.freezer_table_resize_chunk_size = 8192;
    cfg.items_per_section = 512;
    cfg.freezer_key_write_buffer = 1024;
    cfg.freezer_value_write_buffer = 1024;
    cfg.ordinal_write_buffer = 1024;
    cfg.replay_buffer = 1024;
    return cfg;
}

test "immutable unclean shutdown" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = try unclean_config(&harness);
    {
        var archive = try harness.open(Digest, i32, cfg);
        archive.deinit();
    }
    const key1 = digest_key(1);
    const key2 = digest_key(2);
    {
        var archive = try harness.open(Digest, i32, cfg);
        defer archive.deinit();
        try archive.put(1, key1, 2000);
        try archive.put(2, key2, 2001);
        try archive.sync();
    }
    var archive = try harness.open(Digest, i32, cfg);
    defer archive.deinit();
    try expect_key(&archive, key1, 2000);
    try expect_key(&archive, key2, 2001);
}

test "immutable sync empty archive then restart" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = try unclean_config(&harness);
    {
        var archive = try harness.open(Digest, i32, cfg);
        defer archive.deinit();
        try archive.sync();
    }
    const key = digest_key(42);
    {
        var archive = try harness.open(Digest, i32, cfg);
        defer archive.deinit();
        try archive.put_sync(0, key, 42);
    }
    var archive = try harness.open(Digest, i32, cfg);
    defer archive.deinit();
    try expect_key(&archive, key, 42);
}

test "immutable crash drops uncommitted writes" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.small_config(4);
    {
        var archive = try harness.open(Digest, i32, cfg);
        defer archive.deinit();
        for (0..6) |index| try archive.put(index, digest_key(index), destroy_value(index));
        try archive.sync();
        for (6..10) |index| try archive.put(index, digest_key(index), destroy_value(index));
        harness.storage.crash();
    }
    var archive = try harness.open(Digest, i32, cfg);
    defer archive.deinit();
    try testing.expectEqual(5, archive.last_index());
    for (0..10) |index| {
        const expected: ?i32 = if (index < 6) destroy_value(index) else null;
        try expect_index(&archive, index, expected);
        try expect_key(&archive, digest_key(index), expected);
    }
    // The lost indices can be stored again and survive a restart.
    try archive.put_sync(7, digest_key(7), 70);
    archive.deinit();
    archive = try harness.open(Digest, i32, cfg);
    try expect_index(&archive, 7, 70);
    try expect_index(&archive, 6, null);
}

comptime {
    _ = Shared;
    _ = Small;
}
