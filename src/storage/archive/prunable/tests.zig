//! Tests for the prunable archive, ported from commonware's `archive/prunable/mod.rs` and the
//! prunable cases of the shared `archive/mod.rs` tests.
//!
//! Restarts drop the archive (`deinit`) and reopen it on the same storage; `crash()` drops
//! unsynced data as commonware's `start_and_recover` does. Commonware's pipelined
//! `start_sync` tests have no counterpart: syncs here complete before returning.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const metrics = runtime.telemetry.metrics;
const translator = @import("../../translator.zig");
const glob = @import("../../journal/segmented/glob.zig");
const prunable = @import("mod.zig");

const MockStorage = runtime.buffer.mocks.Storage;
const gpa = testing.allocator;

const Key = [64]u8;
const default_items_per_section: u64 = 65536;
const default_write_buffer: usize = 1024;
const default_replay_buffer: usize = 4096;
/// Physical size of one uncompressed i32 value frame: the value and its CRC32.
const i32_frame_size: u64 = 4 + glob.checksum_size;
const section_zero = std.mem.toBytes(std.mem.nativeToBig(u64, 0));

pub fn test_key(name: []const u8) Key {
    std.debug.assert(name.len <= 64);
    var key: Key = @splat(0);
    @memcpy(key[0..name.len], name);
    return key;
}

pub const Harness = struct {
    storage: MockStorage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

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

    /// commonware's `test_config(prefix, items_per_section, translator)`.
    pub fn config(
        self: *Harness,
        comptime prefix: []const u8,
        items_per_section: u64,
        comptime T: type,
    ) prunable.Config(T, i32) {
        return .{
            .translator = .{},
            .metadata_partition = prefix ++ "-metadata",
            .key_partition = prefix ++ "-index",
            .key_cache_ref = &self.cache_ref,
            .value_partition = prefix ++ "-value",
            .codec_config = {},
            .items_per_section = items_per_section,
            .key_write_buffer = default_write_buffer,
            .value_write_buffer = default_write_buffer,
            .replay_buffer = default_replay_buffer,
        };
    }

    /// Open an archive with metrics under `scope_name`.
    pub fn open(
        self: *Harness,
        comptime T: type,
        comptime V: type,
        cfg: prunable.Config(T, V),
        scope_name: []const u8,
    ) !prunable.Archive(T, Key, V) {
        const scope = metrics.Scope.init(&self.registry).child(scope_name);
        return prunable.Archive(T, Key, V).init(gpa, self.storage.interface(), scope, cfg);
    }

    pub fn has_metric(self: *Harness, name: []const u8, value: anytype) !bool {
        const text = try self.registry.encode(gpa);
        defer gpa.free(text);
        if (metrics.has_metric_value(text, name, value)) return true;
        std.debug.print("missing {s} = {any} in:\n{s}\n", .{ name, value, text });
        return false;
    }

    pub fn reset_metrics(self: *Harness) void {
        self.registry.deinit();
        self.registry = metrics.Registry.init(gpa);
    }

    /// The durable length of the blob of section 0 in `partition`.
    fn section_zero_len(self: *Harness, partition: []const u8) !?u64 {
        return self.storage.durable_len(partition, &section_zero);
    }
};

fn expect_index(archive: anytype, index: u64, expected: ?i32) !void {
    try testing.expectEqual(expected, try archive.get(.{ .index = index }));
}

fn expect_key(archive: anytype, name: []const u8, expected: ?i32) !void {
    const key = test_key(name);
    try testing.expectEqual(expected, try archive.get(.{ .key = &key }));
}

fn has_key(archive: anytype, name: []const u8) !bool {
    const key = test_key(name);
    return archive.has(.{ .key = &key });
}

fn expect_all(archive: anytype, index: u64, expected: ?[]const i32) !void {
    const values = try archive.get_all(gpa, index);
    defer if (values) |slice| gpa.free(slice);
    if (expected) |want| {
        try testing.expectEqualSlices(i32, want, values orelse return error.TestExpectedValues);
    } else {
        try testing.expectEqual(null, values);
    }
}

/// The archive configuration of commonware's shared `create_prunable`.
fn shared_config(harness: *Harness, compression: ?u8) prunable.Config(translator.TwoCap, i32) {
    var cfg = harness.config("test", 1024, translator.TwoCap);
    cfg.key_partition = "test-key";
    cfg.compression = compression;
    cfg.replay_buffer = 1024;
    return cfg;
}

// Shared archive tests (commonware `archive/mod.rs`).

fn check_put_get(compression: ?u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = shared_config(&harness, compression);
    var archive = try harness.open(translator.TwoCap, i32, cfg, "a");
    defer archive.deinit();
    try testing.expect(!try archive.has(.{ .index = 1 }));
    try testing.expect(!try has_key(&archive, "testkey"));
    try archive.put(1, test_key("testkey"), 1);
    try testing.expect(try archive.has(.{ .index = 1 }));
    try testing.expect(try has_key(&archive, "testkey"));
    try expect_key(&archive, "testkey", 1);
    try expect_index(&archive, 1, 1);
    try archive.sync();
}

test "prunable put get no compression" {
    try check_put_get(null);
}

test "prunable put get compression" {
    try check_put_get(3);
}

fn check_duplicate_key(compression: ?u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = shared_config(&harness, compression);
    var archive = try harness.open(translator.TwoCap, i32, cfg, "a");
    defer archive.deinit();
    try archive.put(1, test_key("duplicate"), 1);
    try archive.put(1, test_key("duplicate"), 2); // Idempotent.
    try expect_index(&archive, 1, 1);
    try expect_key(&archive, "duplicate", 1);
    // The same key at two indices: both indices resolve, and the key resolves to either.
    try archive.put(2, test_key("dupe-xindex"), 20);
    try archive.put(5, test_key("dupe-xindex"), 50);
    try expect_index(&archive, 2, 20);
    try expect_index(&archive, 5, 50);
    const key = test_key("dupe-xindex");
    const got = (try archive.get(.{ .key = &key })).?;
    try testing.expect(got == 20 or got == 50);
    try testing.expect(try archive.has(.{ .key = &key }));
    // Missing entries.
    try expect_index(&archive, 3, null);
    try expect_key(&archive, "nonexistent", null);
}

test "prunable duplicate key, cross index, and nonexistent" {
    try check_duplicate_key(null);
    try check_duplicate_key(3);
}

fn check_persistence(compression: ?u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = shared_config(&harness, compression);
    const names = [_][]const u8{ "key1", "key2", "key3" };
    {
        var archive = try harness.open(translator.TwoCap, i32, cfg, "first");
        defer archive.deinit();
        for (names, 1..) |name, index| try archive.put(index, test_key(name), @intCast(index));
        try archive.sync();
    }
    var archive = try harness.open(translator.TwoCap, i32, cfg, "second");
    defer archive.deinit();
    for (names, 1..) |name, index| {
        try expect_index(&archive, index, @intCast(index));
        try expect_key(&archive, name, @intCast(index));
    }
}

test "prunable persistence" {
    try check_persistence(null);
    try check_persistence(3);
}

fn check_ranges(compression: ?u8) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = shared_config(&harness, compression);
    var rng = @import("utils").rng.TestRng.init(0);
    var indices: [100]u64 = undefined;
    {
        var archive = try harness.open(translator.TwoCap, i32, cfg, "first");
        defer archive.deinit();
        var last: u64 = 0;
        for (&indices) |*index| {
            last += @import("utils").rng.range_at_most(&rng, u64, 1, 10);
            index.* = last;
            var key: Key = undefined;
            rng.fill_bytes(&key);
            try archive.put(last, key, @bitCast(rng.next_u32()));
        }
        try archive.sync();
    }
    var archive = try harness.open(translator.TwoCap, i32, cfg, "second");
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

test "prunable ranges" {
    try check_ranges(null);
    try check_ranges(3);
}

/// commonware's `test_many_keys_impl`: random keys with random syncs, checked before and
/// after a restart. Returns the storage audit.
fn check_many_keys(compression: ?u8, count: usize) ![4]u8 {
    const utils = @import("utils");
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = shared_config(&harness, compression);
    var rng = utils.rng.TestRng.init(0);
    const keys = try gpa.alloc(Key, count);
    defer gpa.free(keys);
    const values = try gpa.alloc(i32, count);
    defer gpa.free(values);
    {
        var archive = try harness.open(translator.TwoCap, i32, cfg, "first");
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
    var archive = try harness.open(translator.TwoCap, i32, cfg, "second");
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

test "prunable many keys and determinism" {
    const first = try check_many_keys(null, 1000);
    try testing.expectEqual(first, try check_many_keys(null, 1000));
    const compressed = try check_many_keys(3, 1000);
    try testing.expectEqual(compressed, try check_many_keys(3, 1000));
}

test "prunable put_multi and get" {
    var harness = try Harness.init();
    defer harness.deinit();
    var archive = try harness.open(translator.TwoCap, i32, shared_config(&harness, null), "a");
    defer archive.deinit();
    try archive.put_multi(5, test_key("aaa"), 10);
    try archive.put_multi(5, test_key("bbb"), 20);
    try archive.put_multi(5, test_key("ccc"), 30);
    try expect_key(&archive, "aaa", 10);
    try expect_key(&archive, "bbb", 20);
    try expect_key(&archive, "ccc", 30);
    try expect_key(&archive, "zzz", null);
    try testing.expect(try harness.has_metric("items_tracked", 1));
    // get_all returns every value in insertion order.
    try archive.put_multi(7, test_key("ddd"), 40);
    try expect_all(&archive, 5, &.{ 10, 20, 30 });
    try expect_all(&archive, 7, &.{40});
    try expect_all(&archive, 99, null);
    try expect_index(&archive, 5, 10);
}

test "prunable put_multi duplicate key" {
    var harness = try Harness.init();
    defer harness.deinit();
    var archive = try harness.open(translator.TwoCap, i32, shared_config(&harness, null), "a");
    defer archive.deinit();
    try archive.put_multi(5, test_key("dup"), 10);
    try archive.put_multi(7, test_key("dup"), 20);
    try expect_index(&archive, 5, 10);
    try expect_index(&archive, 7, 20);
    try expect_all(&archive, 5, &.{10});
    try expect_all(&archive, 7, &.{20});
    const key = test_key("dup");
    const got = (try archive.get(.{ .key = &key })).?;
    try testing.expect(got == 10 or got == 20);
    try testing.expect(try harness.has_metric("items_tracked", 2));
}

test "prunable put_multi preserves put semantics" {
    var harness = try Harness.init();
    defer harness.deinit();
    var archive = try harness.open(translator.TwoCap, i32, shared_config(&harness, null), "a");
    defer archive.deinit();
    try archive.put_multi(1, test_key("aaa"), 10);
    try archive.put_multi(1, test_key("bbb"), 20);
    try archive.put(1, test_key("ccc"), 30); // A no-op: index 1 is stored.
    try expect_key(&archive, "aaa", 10);
    try expect_key(&archive, "bbb", 20);
    try expect_key(&archive, "ccc", null);
    try expect_index(&archive, 1, 10);
}

test "prunable put_multi restart" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = shared_config(&harness, null);
    {
        var archive = try harness.open(translator.TwoCap, i32, cfg, "first");
        defer archive.deinit();
        try archive.put_multi(5, test_key("aaa"), 10);
        try archive.put_multi(5, test_key("bbb"), 20);
        try archive.put_multi(7, test_key("ccc"), 30);
        try archive.sync();
    }
    harness.reset_metrics();
    var archive = try harness.open(translator.TwoCap, i32, cfg, "second");
    defer archive.deinit();
    try expect_key(&archive, "aaa", 10);
    try expect_key(&archive, "bbb", 20);
    try expect_key(&archive, "ccc", 30);
    try expect_all(&archive, 5, &.{ 10, 20 });
    try testing.expect(try harness.has_metric("items_tracked", 2));
}

test "prunable put_multi mixed indices" {
    var harness = try Harness.init();
    defer harness.deinit();
    var archive = try harness.open(translator.TwoCap, i32, shared_config(&harness, null), "a");
    defer archive.deinit();
    try archive.put(1, test_key("single"), 100);
    try archive.put_multi(2, test_key("multi-a"), 200);
    try archive.put_multi(2, test_key("multi-b"), 201);
    try archive.put_multi(3, test_key("multi-c"), 300);
    try expect_key(&archive, "single", 100);
    try expect_key(&archive, "multi-a", 200);
    try expect_key(&archive, "multi-b", 201);
    try expect_key(&archive, "multi-c", 300);
    try expect_index(&archive, 2, 200);
    const gap = archive.next_gap(1);
    try testing.expectEqual(3, gap.current_end);
    try testing.expectEqual(null, gap.next_start);
    try testing.expect(try harness.has_metric("items_tracked", 3));
}

// Prunable archive tests (commonware `archive/prunable/mod.rs`).

test "prunable truncates at first invalid value" {
    const cases = [_]struct { bad: u64, retained: u64 }{
        .{ .bad = 0, .retained = 0 },
        .{ .bad = 1, .retained = 1 },
    };
    for (cases) |case| {
        var harness = try Harness.init();
        defer harness.deinit();
        const cfg = harness.config("invalid", 4, translator.FourCap);
        // The sync leaves the values durable with no marker (the active section's boundary
        // stays debt), so a reopen CRC-validates every frame from position 0.
        {
            var archive = try harness.open(translator.FourCap, i32, cfg, "seed");
            defer archive.deinit();
            for ([_]i32{ 10, 20, 30 }, 0..) |value, index| {
                var name: [8]u8 = undefined;
                try archive.put(index, test_key(try key_name(&name, index)), value);
            }
            try archive.sync();
        }
        const iface = harness.storage.interface();
        try glob.corrupt_frame(iface, cfg.value_partition, &section_zero, case.bad, i32_frame_size);
        // Every frame after the first invalid one belongs to the same uncommitted suffix.
        for (0..2) |reopen| {
            harness.reset_metrics();
            var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
            defer archive.deinit();
            const ranges = archive.ranges();
            if (case.retained == 0) {
                try testing.expectEqual(0, ranges.len);
            } else {
                try testing.expectEqual(1, ranges.len);
                try testing.expectEqual(prunable_range(0, case.retained - 1), ranges[0]);
            }
            for ([_]i32{ 10, 20, 30 }, 0..) |value, index| {
                const expected: ?i32 = if (index < case.retained) value else null;
                try expect_index(&archive, index, expected);
            }
            // The truncation was durable before the first reopen returned.
            if (reopen == 1) {
                const last: ?u64 = if (case.retained == 0) null else case.retained - 1;
                try testing.expectEqual(last, archive.last_index());
            }
        }
    }
}

fn prunable_range(start: u64, end: u64) @import("../../rmap/mod.zig").Range {
    return .{ .start = start, .end = end };
}

fn key_name(buffer: *[8]u8, index: u64) ![]const u8 {
    return std.fmt.bufPrint(buffer, "key-{d}", .{index});
}

test "prunable completes interrupted rewind to empty section" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("empty-rewind", 4, translator.FourCap);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "seed");
        defer archive.deinit();
        try archive.put(0, test_key("zero"), 10);
        try archive.sync();
    }
    // Drop the sidecar so startup must reconcile the journals alone, then model a crash
    // between the archive's two durable section truncations: index [ ], values [A].
    try harness.storage.remove(cfg.metadata_partition, null);
    {
        const opened = try harness.storage.open(cfg.key_partition, &section_zero);
        defer opened.blob.close();
        try opened.blob.resize(0);
        try opened.blob.sync();
    }
    try testing.expectEqual(i32_frame_size, try harness.section_zero_len(cfg.value_partition));
    {
        harness.reset_metrics();
        var archive = try harness.open(translator.FourCap, i32, cfg, "repair");
        defer archive.deinit();
        try testing.expectEqual(null, archive.last_index());
    }
    // Startup finished the value truncation.
    try testing.expectEqual(0, try harness.section_zero_len(cfg.value_partition));
    harness.storage.remove(cfg.metadata_partition, null) catch {};
    // With both halves empty, a restart without metadata writes nothing.
    harness.reset_metrics();
    const writes = harness.storage.writes;
    var archive = try harness.open(translator.FourCap, i32, cfg, "clean");
    defer archive.deinit();
    try testing.expectEqual(writes, harness.storage.writes);
    // The repaired empty section accepts a write at the reclaimed offsets.
    try archive.put(0, test_key("new"), 20);
    try archive.sync();
    try testing.expectEqual(i32_frame_size, try harness.section_zero_len(cfg.value_partition));
    archive.deinit();
    harness.reset_metrics();
    archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
    try expect_index(&archive, 0, 20);
}

test "prunable validation marker skips previously validated values" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("marker-skip", 4, translator.FourCap);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "seed");
        defer archive.deinit();
        try archive.put(0, test_key("zero"), 10);
        try archive.put(1, test_key("one"), 20);
        try archive.sync();
    }
    // An archive created before validation markers: the first open validates and writes the
    // sidecar; the second adopts both values.
    try harness.storage.remove(cfg.metadata_partition, null);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "first_open");
        defer archive.deinit();
        try testing.expectEqualSlices(@import("../../rmap/mod.zig").Range, &.{
            prunable_range(0, 1),
        }, archive.ranges());
    }
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "second_open");
        defer archive.deinit();
        try expect_index(&archive, 0, 10);
        try expect_index(&archive, 1, 20);
        // A value above the marker: the third open validates the suffix only.
        try archive.put(2, test_key("two"), 30);
        try archive.sync();
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "third_open");
    defer archive.deinit();
    try testing.expectEqual(prunable_range(0, 2), archive.ranges()[0]);
    try expect_index(&archive, 0, 10);
    try expect_index(&archive, 1, 20);
    try expect_index(&archive, 2, 30);
}

test "prunable validation marker skips covered interior values" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("marker-covered-interior", 4, translator.FourCap);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "seed");
        defer archive.deinit();
        try archive.put(0, test_key("zero"), 10);
        try archive.put(1, test_key("one"), 20);
        // The first sync proves the data durable; the second publishes the marker.
        try archive.sync();
        try archive.sync();
    }
    // Damage only the covered interior frame: init skips it, a direct read still fails.
    const iface = harness.storage.interface();
    try glob.corrupt_frame(iface, cfg.value_partition, &section_zero, 0, i32_frame_size);
    var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
    defer archive.deinit();
    try testing.expectError(error.ChecksumMismatch, archive.get(.{ .index = 0 }));
    try expect_index(&archive, 1, 20);
}

test "prunable compression then none" {
    var harness = try Harness.init();
    defer harness.deinit();
    var cfg = harness.config("test", default_items_per_section, translator.FourCap);
    cfg.compression = 3;
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "first");
        defer archive.deinit();
        try archive.put(1, test_key("testkey"), 1);
        try archive.sync();
    }
    // Index replay succeeds without compression, but the value read fails.
    cfg.compression = null;
    var archive = try harness.open(translator.FourCap, i32, cfg, "second");
    defer archive.deinit();
    try testing.expectError(error.ExtraData, archive.get(.{ .index = 1 }));
}

test "prunable overlapping key basic" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", default_items_per_section, translator.FourCap);
    var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
    defer archive.deinit();
    try archive.put(1, test_key("keys1"), 1);
    try archive.put(2, test_key("keys2"), 2);
    try expect_key(&archive, "keys1", 1);
    try expect_key(&archive, "keys2", 2);
    try testing.expect(try harness.has_metric("items_tracked", 2));
    try testing.expect(try harness.has_metric("unnecessary_reads_total", 1));
    try testing.expect(try harness.has_metric("gets_total", 2));
}

test "prunable overlapping key multiple sections" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", default_items_per_section, translator.FourCap);
    var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
    defer archive.deinit();
    try archive.put(1, test_key("keys1"), 1);
    try archive.put(2_000_000, test_key("keys2"), 2);
    try expect_key(&archive, "keys1", 1);
    try expect_key(&archive, "keys2", 2);
}

test "prunable prune keys" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 1, translator.FourCap);
    var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
    defer archive.deinit();
    const names = [_][]const u8{ "key1-blah", "key2-blah", "key3-blah", "key3-bleh", "key4-blah" };
    const values = [_]i32{ 1, 2, 3, 3, 4 };
    for (names, values, 1..) |name, value, index| try archive.put(index, test_key(name), value);
    try testing.expect(try harness.has_metric("items_tracked", 5));
    try archive.prune(3);
    for (names, values, 1..) |name, value, index| {
        try expect_key(&archive, name, if (index < 3) null else value);
    }
    try testing.expect(try harness.has_metric("items_tracked", 3));
    try testing.expect(try harness.has_metric("indices_pruned_total", 2));
    try testing.expect(try harness.has_metric("keys_tracked", 3));
    try archive.prune(2); // Older: a no-op.
    try archive.prune(3); // Current: a no-op.
    // A key sharing a pruned key's translated key adds one tracked key.
    try archive.put(6, test_key("key2-blfh"), 5);
    try testing.expect(try harness.has_metric("items_tracked", 4));
    try testing.expect(try harness.has_metric("indices_pruned_total", 2));
    try testing.expect(try harness.has_metric("keys_tracked", 4));
    // Puts below the prune floor are satisfied without storing.
    try archive.put(1, test_key("key1-blah"), 1);
    try expect_key(&archive, "key1-blah", null);
    try archive.put(1, test_key("key1-blah"), 1);
    try archive.start_sync();
    try archive.put_sync(2, test_key("key2-blfh"), 2);
    try expect_index(&archive, 1, null);
    try expect_index(&archive, 2, null);
}

/// commonware's `test_archive_keys_and_restart` with 1 KiB values. Returns the storage audit.
fn check_keys_and_restart(count: usize) ![4]u8 {
    const utils = @import("utils");
    const Value = [1024]u8;
    var harness = try Harness.init();
    defer harness.deinit();
    const items_per_section: u64 = 256;
    var cfg = harness.config("test", items_per_section, translator.TwoCap);
    var rng = utils.rng.TestRng.init(0);
    const keys = try gpa.alloc(Key, count);
    defer gpa.free(keys);
    const values = try gpa.alloc(Value, count);
    defer gpa.free(values);
    const value_cfg: prunable.Config(translator.TwoCap, Value) = .{
        .translator = .{},
        .metadata_partition = cfg.metadata_partition,
        .key_partition = cfg.key_partition,
        .key_cache_ref = cfg.key_cache_ref,
        .value_partition = cfg.value_partition,
        .codec_config = {},
        .items_per_section = items_per_section,
        .key_write_buffer = cfg.key_write_buffer,
        .value_write_buffer = cfg.value_write_buffer,
        .replay_buffer = cfg.replay_buffer,
    };
    cfg = undefined;
    {
        var archive = try harness.open(translator.TwoCap, Value, value_cfg, "first");
        defer archive.deinit();
        for (keys, values, 0..) |*key, *value, index| {
            rng.fill_bytes(key);
            rng.fill_bytes(value);
            try archive.put(index, key.*, value.*);
        }
        try check_values(&archive, keys, values);
        try testing.expect(try harness.has_metric("first_items_tracked", count));
        try testing.expect(try harness.has_metric("first_keys_tracked", count));
        try archive.sync();
    }
    var archive = try harness.open(translator.TwoCap, Value, value_cfg, "second");
    defer archive.deinit();
    try check_values(&archive, keys, values);
    try prune_half(&harness, &archive, keys, values, items_per_section);
    return harness.storage.backend.audit();
}

fn check_values(archive: anytype, keys: anytype, values: anytype) !void {
    for (keys, values, 0..) |*key, value, index| {
        try testing.expectEqual(value, (try archive.get(.{ .index = index })).?);
        try testing.expectEqual(value, (try archive.get(.{ .key = key })).?);
    }
}

fn prune_half(
    harness: *Harness,
    archive: anytype,
    keys: anytype,
    values: anytype,
    items_per_section: u64,
) !void {
    const count = keys.len;
    try archive.prune(count / 2);
    const min = (count / 2) / items_per_section * items_per_section;
    var removed: u64 = 0;
    for (keys, values, 0..) |*key, value, index| {
        const gap = archive.next_gap(index);
        if (index >= min) {
            try testing.expectEqual(value, (try archive.get(.{ .key = key })).?);
            try testing.expectEqual(count - 1, gap.current_end);
            try testing.expectEqual(null, gap.next_start);
        } else {
            try testing.expectEqual(null, try archive.get(.{ .key = key }));
            try testing.expectEqual(null, gap.current_end);
            try testing.expectEqual(min, gap.next_start);
            removed += 1;
        }
    }
    try testing.expect(try harness.has_metric("second_items_tracked", count - removed));
    try testing.expect(try harness.has_metric("second_indices_pruned_total", removed));
    try testing.expect(try harness.has_metric("second_keys_tracked", count - removed));
}

test "prunable keys and restart determinism" {
    const first = try check_keys_and_restart(1000);
    try testing.expectEqual(first, try check_keys_and_restart(1000));
}

test "prunable key lookup skips pruned duplicates" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 1, translator.FourCap);
    var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
    defer archive.deinit();
    try archive.put(2, test_key("dupe-key"), 20);
    try archive.put(5, test_key("dupe-key"), 50);
    try testing.expect(try has_key(&archive, "dupe-key"));
    // Prune the earlier index: the later one is the sole surviving answer.
    try archive.prune(3);
    try expect_key(&archive, "dupe-key", 50);
    try testing.expect(try has_key(&archive, "dupe-key"));
    try archive.prune(6);
    try expect_key(&archive, "dupe-key", null);
    try testing.expect(!try has_key(&archive, "dupe-key"));
}

test "prunable get_all after prune" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 1, translator.FourCap);
    var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
    defer archive.deinit();
    try archive.put_multi(1, test_key("aaa"), 10);
    try archive.put_multi(1, test_key("bbb"), 20);
    try archive.put_multi(3, test_key("ccc"), 30);
    try archive.prune(3);
    try expect_all(&archive, 1, null);
    try expect_all(&archive, 3, &.{30});
}

fn has_at(archive: anytype, index: u64, name: []const u8) !bool {
    const key = test_key(name);
    return archive.has_at(index, &key);
}

test "prunable has_at across a crash" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 2, translator.FourCap);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
        defer archive.deinit();
        try testing.expect(!try has_at(&archive, 1, "aaaa1"));
        try archive.put_multi(1, test_key("aaaa1"), 10);
        try testing.expect(try has_at(&archive, 1, "aaaa1"));
        try testing.expect(!try has_at(&archive, 2, "aaaa1"));
        // "aaaa2" shares the translated key of "aaaa1".
        try testing.expect(!try has_at(&archive, 1, "aaaa2"));
        try archive.put_multi(1, test_key("aaaa2"), 20);
        try testing.expect(try has_at(&archive, 1, "aaaa1"));
        try testing.expect(try has_at(&archive, 1, "aaaa2"));
        try testing.expect(!try has_at(&archive, 1, "bbbb"));
        try archive.put_multi(3, test_key("cccc"), 30);
        try archive.sync();
        harness.storage.crash();
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "reopen");
    defer archive.deinit();
    try testing.expect(try has_at(&archive, 1, "aaaa1"));
    try testing.expect(try has_at(&archive, 1, "aaaa2"));
    try testing.expect(!try has_at(&archive, 1, "bbbb"));
    try archive.prune(2);
    try testing.expect(!try has_at(&archive, 1, "aaaa1"));
    try testing.expect(!try has_at(&archive, 1, "aaaa2"));
    try testing.expect(try has_at(&archive, 3, "cccc"));
}

test "prunable has key" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 2, translator.FourCap);
    var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
    try testing.expect(!try has_key(&archive, "aaaa1"));
    try archive.put(1, test_key("aaaa1"), 10);
    try testing.expect(try has_key(&archive, "aaaa1"));
    try testing.expect(!try has_key(&archive, "aaaa2"));
    try archive.put(2, test_key("aaaa2"), 20);
    try testing.expect(try has_key(&archive, "aaaa2"));
    try archive.put(4, test_key("cccc"), 30);
    try archive.prune(4);
    try testing.expect(!try has_key(&archive, "aaaa1"));
    try testing.expect(!try has_key(&archive, "aaaa2"));
    try testing.expect(try has_key(&archive, "cccc"));
    try archive.destroy();
    // Destroy removed every partition.
    try testing.expectEqual(null, try harness.section_zero_len(cfg.key_partition));
}

test "prunable put_multi prune" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 1, translator.FourCap);
    var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
    defer archive.deinit();
    try archive.put_multi(1, test_key("aaa"), 10);
    try archive.put_multi(1, test_key("bbb"), 20);
    try archive.put_multi(3, test_key("ccc"), 30);
    try testing.expect(try harness.has_metric("items_tracked", 2));
    try archive.prune(3);
    try expect_key(&archive, "aaa", null);
    try expect_key(&archive, "bbb", null);
    try expect_key(&archive, "ccc", 30);
    try testing.expect(try harness.has_metric("items_tracked", 1));
    try testing.expect(try harness.has_metric("indices_pruned_total", 1));
    // Below-floor multi puts are satisfied without storing.
    try archive.put_multi(2, test_key("ddd"), 40);
    try expect_key(&archive, "ddd", null);
    try archive.put_multi(2, test_key("ddd"), 41);
    try archive.start_sync();
    try expect_all(&archive, 2, null);
    try archive.put_multi_sync(2, test_key("ddd"), 42);
    try expect_all(&archive, 2, null);
}

fn hex_key(index: u64) Key {
    var name: [4]u8 = undefined;
    _ = std.fmt.bufPrint(&name, "{x:0>4}", .{index}) catch unreachable; // 4 hex digits fit.
    return test_key(&name);
}

fn expect_hex(archive: anytype, index: u64, expected: ?i32) !void {
    const key = hex_key(index);
    try testing.expectEqual(expected, try archive.get(.{ .key = &key }));
}

test "prunable prune retires keys" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 4, translator.EightCap);
    {
        var archive = try harness.open(translator.EightCap, i32, cfg, "storage");
        defer archive.deinit();
        for (0..32) |batch| {
            const first = batch * 16;
            for (first..first + 16) |index| try archive.put(index, hex_key(index), @intCast(index));
            try archive.prune(first);
            try testing.expect(try harness.has_metric("storage_items_tracked", 16));
            try testing.expect(try harness.has_metric("storage_keys_tracked", 16));
            try expect_hex(&archive, first, @intCast(first));
            if (first > 0) try expect_hex(&archive, first - 1, null);
            try archive.prune(first + 1);
            try testing.expect(try harness.has_metric("storage_keys_tracked", 16));
        }
        try archive.sync();
    }
    var archive = try harness.open(translator.EightCap, i32, cfg, "reopened");
    defer archive.deinit();
    try testing.expect(try harness.has_metric("reopened_keys_tracked", 16));
    try expect_hex(&archive, 511, 511);
    try expect_hex(&archive, 495, null);
    try archive.prune(512);
    try testing.expect(try harness.has_metric("reopened_items_tracked", 0));
    try testing.expect(try harness.has_metric("reopened_keys_tracked", 0));
    try expect_hex(&archive, 511, null);
}

fn check_colliding(archive: anytype) !void {
    try expect_all(archive, 5, &.{ 50, 51, 61 });
    try expect_key(archive, "head-kept", 50);
    try expect_key(archive, "tail-kept", 51);
    try expect_key(archive, "same", 61);
    try expect_key(archive, "head-pruned", null);
    try expect_key(archive, "tail-pruned", null);
}

test "prunable prune keeps colliding retained keys" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 4, translator.FourCap);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
        defer archive.deinit();
        try archive.put(1, test_key("head-pruned"), 10);
        try archive.put(5, test_key("head-kept"), 50);
        try archive.put_multi(5, test_key("tail-kept"), 51);
        try archive.put(2, test_key("tail-pruned"), 20);
        try archive.put_multi(1, test_key("same"), 60);
        try archive.put_multi(5, test_key("same"), 61);
        try archive.prune(7);
        try check_colliding(&archive);
        try testing.expect(try harness.has_metric("storage_items_tracked", 1));
        try testing.expect(try harness.has_metric("storage_keys_tracked", 3));
        try testing.expect(try harness.has_metric("storage_indices_pruned_total", 2));
        try archive.sync();
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "reopened");
    defer archive.deinit();
    try check_colliding(&archive);
    try testing.expect(try harness.has_metric("reopened_keys_tracked", 3));
}

test "prunable positions match model" {
    const utils = @import("utils");
    var rng = utils.rng.TestRng.init(0);
    var positions: prunable.Positions = .{};
    defer positions.deinit(gpa);
    var model: std.AutoHashMapUnmanaged(u64, u64) = .empty;
    defer model.deinit(gpa);
    for (0..4000) |step| {
        const offset: u64 = switch (step) {
            0...99 => step,
            100...199 => utils.rng.range_less_than(&rng, u64, 0, 100_000),
            else => utils.rng.range_less_than(&rng, u64, 0, 2_000),
        };
        const inserted = try positions.insert(gpa, offset, step);
        try testing.expectEqual(!model.contains(offset), inserted);
        if (inserted) try model.put(gpa, offset, step);
        try testing.expectEqual(model.count(), positions.len());
        const random_probe = utils.rng.range_less_than(&rng, u64, 0, 100_000);
        for ([_]u64{ offset, offset + 1, random_probe }) |probe| {
            try testing.expectEqual(model.get(probe), positions.get(probe));
        }
    }
}

const out_of_order_indices = [_]u64{ 0, 1, 2, 10, 5_000, 3, 7, 4 };

fn check_out_of_order(archive: anytype) !void {
    for (out_of_order_indices ++ [_]u64{6}) |index| {
        var name: [8]u8 = undefined;
        const text = try std.fmt.bufPrint(&name, "k{d}", .{index});
        try expect_index(archive, index, @intCast(index));
        try expect_key(archive, text, @intCast(index));
    }
    for ([_]u64{ 5, 8, 9, 11, 4_999, 5_001 }) |index| {
        try expect_index(archive, index, null);
        try testing.expect(!try archive.has(.{ .index = index }));
    }
    try expect_all(archive, 7, &.{ 7, 70 });
    try testing.expect(try has_at(archive, 7, "k7-dup"));
    try testing.expect(!try has_at(archive, 7, "k6"));
    try testing.expect(!try has_at(archive, 8, "k7"));
    const first = archive.next_gap(0);
    try testing.expectEqual(4, first.current_end);
    try testing.expectEqual(6, first.next_start);
    const second = archive.next_gap(6);
    try testing.expectEqual(7, second.current_end);
    try testing.expectEqual(10, second.next_start);
}

test "prunable out of order section" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 1 << 20, translator.FourCap);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
        defer archive.deinit();
        for (out_of_order_indices) |index| {
            var name: [8]u8 = undefined;
            const text = try std.fmt.bufPrint(&name, "k{d}", .{index});
            try archive.put(index, test_key(text), @intCast(index));
        }
        try archive.put_multi(7, test_key("k7-dup"), 70);
        try archive.put(6, test_key("k6"), 6);
        try check_out_of_order(&archive);
        try testing.expect(try harness.has_metric("storage_items_tracked", 9));
        try testing.expect(try harness.has_metric("storage_keys_tracked", 10));
        try archive.sync();
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "reopened");
    defer archive.deinit();
    try testing.expect(try harness.has_metric("reopened_items_tracked", 9));
    try testing.expect(try harness.has_metric("reopened_keys_tracked", 10));
    try check_out_of_order(&archive);
}

test "prunable init rejects changed items per section" {
    var harness = try Harness.init();
    defer harness.deinit();
    {
        const cfg = harness.config("test", 16, translator.FourCap);
        var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
        defer archive.deinit();
        for (0..40) |index| {
            var name: [8]u8 = undefined;
            const text = try std.fmt.bufPrint(&name, "k{d}", .{index});
            try archive.put(index, test_key(text), @intCast(index));
        }
        try archive.sync();
    }
    const cfg = harness.config("test", 32, translator.FourCap);
    try testing.expectError(
        error.RecordCorrupted,
        harness.open(translator.FourCap, i32, cfg, "reopened"),
    );
}

test "prunable crash drops unsynced writes" {
    var harness = try Harness.init();
    defer harness.deinit();
    const cfg = harness.config("test", 4, translator.FourCap);
    {
        var archive = try harness.open(translator.FourCap, i32, cfg, "storage");
        defer archive.deinit();
        for (0..6) |index| try archive.put(index, hex_key(index), @intCast(index));
        try archive.sync();
        for (6..10) |index| try archive.put(index, hex_key(index), @intCast(index));
        harness.storage.crash();
    }
    var archive = try harness.open(translator.FourCap, i32, cfg, "reopened");
    defer archive.deinit();
    try testing.expectEqual(5, archive.last_index());
    for (0..10) |index| {
        const expected: ?i32 = if (index < 6) @intCast(index) else null;
        try expect_index(&archive, index, expected);
        try expect_hex(&archive, index, expected);
    }
    // The reopened archive accepts the lost indices again.
    try archive.put(6, hex_key(6), 60);
    try expect_index(&archive, 6, 60);
}
