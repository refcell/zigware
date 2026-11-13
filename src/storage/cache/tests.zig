//! Tests for the cache, ported from commonware's `cache/mod.rs`, and the `cache_operations`
//! fuzz target (storage/fuzz) checked against a reference model.
//!
//! Restarts close the cache after a sync and reopen it on the same storage; `crash()` drops
//! unsynced data as commonware's `start_and_recover` does. Commonware's determinism test
//! compares auditor states; here it compares storage audits.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const paged = runtime.buffer.paged;
const cache_mod = @import("mod.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");

const MockStorage = runtime.buffer.mocks.Storage;
const gpa = testing.allocator;

const default_items_per_blob: u64 = 65536;
const default_write_buffer: usize = 1024;
const default_replay_buffer: usize = 4096;
const page_size: u16 = 1024;
const page_cache_size: u32 = 10;

const Harness = struct {
    storage: MockStorage,
    cache_ref: paged.CacheRef,
    registry: metrics.Registry,

    fn init(cache_page_size: u16, cache_pages: u32) !Harness {
        return .{
            .storage = MockStorage.init(gpa),
            .cache_ref = try paged.CacheRef.init(gpa, cache_page_size, cache_pages),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg(self: *Harness, comptime V: type, items_per_blob: u64) cache_mod.Config(V) {
        return .{
            .partition = "test-partition",
            .codec_config = {},
            .items_per_blob = items_per_blob,
            .write_buffer = default_write_buffer,
            .replay_buffer = default_replay_buffer,
            .cache_ref = &self.cache_ref,
        };
    }

    fn open(self: *Harness, comptime V: type, config: cache_mod.Config(V)) !cache_mod.Cache(V) {
        const scope = metrics.Scope.init(&self.registry).child("storage");
        return cache_mod.Cache(V).init(gpa, self.storage.interface(), scope, config);
    }

    fn has_metric(self: *Harness, name: []const u8, value: u64) !bool {
        const text = try self.registry.encode(gpa);
        defer gpa.free(text);
        return metrics.has_metric_value(text, name, value);
    }
};

fn expect_get(cache: anytype, index: u64, expected: anytype) !void {
    const value = try cache.get(index);
    try testing.expectEqual(expected, value);
}

fn expect_gap(cache: anytype, index: u64, current_end: ?u64, next_start: ?u64) !void {
    const gap = cache.next_gap(index);
    try testing.expectEqual(current_end, gap.current_end);
    try testing.expectEqual(next_start, gap.next_start);
}

fn expect_missing(cache: anytype, start: u64, max: usize, expected: []const u64) !void {
    var out: [64]u64 = undefined;
    try testing.expectEqualSlices(u64, expected, cache.missing_items(start, out[0..max]));
}

test "cache compression then none" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    var config = harness.cfg(i32, default_items_per_blob);
    config.compression = 3;
    {
        var cache = try harness.open(i32, config);
        defer cache.deinit();
        try cache.put(1, 1);
        try cache.sync();
    }
    // Reopening without compression reads the compressed frame as a raw value.
    config.compression = null;
    const result = harness.open(i32, config);
    try testing.expectError(error.ExtraData, result);
}

test "cache prune" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    var cache = try harness.open(i32, harness.cfg(i32, 1));
    defer cache.deinit();
    const items = [_]struct { u64, i32 }{ .{ 1, 1 }, .{ 2, 2 }, .{ 3, 3 }, .{ 4, 4 }, .{ 5, 5 } };
    for (items) |item| try cache.put(item[0], item[1]);
    try testing.expectEqual(@as(?u64, 1), cache.first());
    try testing.expect(try harness.has_metric("items_tracked", 5));

    try cache.prune(3);
    for (items) |item| {
        const expected: ?i32 = if (item[0] < 3) null else item[1];
        try expect_get(&cache, item[0], expected);
    }
    try testing.expectEqual(@as(?u64, 3), cache.first());
    try testing.expect(try harness.has_metric("items_tracked", 3));

    // Pruning an older or the current section again does nothing.
    try cache.prune(2);
    try testing.expectEqual(@as(?u64, 3), cache.first());
    try cache.prune(3);
    try testing.expectEqual(@as(?u64, 3), cache.first());

    // A put below the prune floor is satisfied without storing.
    try cache.put(1, 1);
    try expect_get(&cache, 1, @as(?i32, null));
    try testing.expect(!cache.has(1));

    // put_sync below the prune floor skips the sync.
    const syncs_before = cache.syncs.metric().get();
    try cache.put_sync(1, 1);
    try expect_get(&cache, 1, @as(?i32, null));
    try testing.expectEqual(syncs_before, cache.syncs.metric().get());
}

const Value = [1024]u8;

/// Commonware's `test_cache_restart`: fill, restart, prune half, and check every item.
/// Returns the storage audit.
fn check_restart(num_items: u64) ![4]u8 {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    const items_per_blob: u64 = 256;
    const values = try gpa.alloc(Value, num_items);
    defer gpa.free(values);
    var rng = utils.rng.TestRng.init(0);
    {
        var cache = try harness.open(Value, harness.cfg(Value, items_per_blob));
        defer cache.deinit();
        for (values, 0..) |*value, index| {
            rng.fill_bytes(value);
            try cache.put(index, value.*);
        }
        for (values, 0..) |value, index| try expect_get(&cache, index, @as(?Value, value));
        try testing.expect(try harness.has_metric("items_tracked", num_items));
        try cache.sync();
    }
    harness.registry.deinit();
    harness.registry = metrics.Registry.init(gpa);
    var cache = try harness.open(Value, harness.cfg(Value, items_per_blob));
    defer cache.deinit();
    for (values, 0..) |value, index| try expect_get(&cache, index, @as(?Value, value));

    const min = num_items / 2;
    try cache.prune(min);
    const floor = (min / items_per_blob) * items_per_blob;
    var removed: u64 = 0;
    for (values, 0..) |value, index| {
        if (index >= floor) {
            try expect_get(&cache, index, @as(?Value, value));
        } else {
            try expect_get(&cache, index, @as(?Value, null));
            removed += 1;
        }
    }
    try testing.expect(try harness.has_metric("items_tracked", num_items - removed));
    return harness.storage.backend.audit();
}

test "cache many items and restart" {
    _ = try check_restart(2_000);
}

test "cache determinism" {
    const first = try check_restart(600);
    const second = try check_restart(600);
    try testing.expectEqual(first, second);
}

test "cache clean restart reads journal once" {
    var harness = try Harness.init(64, 10);
    defer harness.deinit();
    var config = harness.cfg(u64, 64);
    config.write_buffer = 256;
    config.replay_buffer = 1024;
    {
        var cache = try harness.open(u64, config);
        defer cache.deinit();
        for (0..15) |index| try cache.put(index, index);
        try cache.sync();
    }
    harness.registry.deinit();
    harness.registry = metrics.Registry.init(gpa);
    harness.storage.reads = 0;
    var cache = try harness.open(u64, config);
    defer cache.deinit();
    for (0..15) |index| try testing.expect(cache.has(index));
    // The 150 logical bytes occupy three pages. Writer construction reads the tail page, then
    // one replay prefetch validates and decodes all three pages.
    try testing.expectEqual(@as(u64, 2), harness.storage.reads);
}

test "cache next gap" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    var cache = try harness.open(i32, harness.cfg(i32, default_items_per_blob));
    defer cache.deinit();
    try testing.expectEqual(@as(?u64, null), cache.first());
    for ([_]u64{ 1, 10, 11, 14 }) |index| try cache.put(index, @intCast(index));

    try expect_gap(&cache, 0, null, 1);
    try testing.expectEqual(@as(?u64, 1), cache.first());
    try expect_gap(&cache, 1, 1, 10);
    try expect_gap(&cache, 10, 11, 14);
    try expect_gap(&cache, 11, 11, 14);
    try expect_gap(&cache, 12, null, 14);
    try expect_gap(&cache, 14, 14, null);
}

test "cache missing items" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    var cache = try harness.open(i32, harness.cfg(i32, default_items_per_blob));
    defer cache.deinit();

    // Empty cache: no items.
    try testing.expectEqual(@as(?u64, null), cache.first());
    try expect_missing(&cache, 0, 5, &.{});
    try expect_missing(&cache, 100, 10, &.{});

    for ([_]u64{ 1, 2, 5, 6, 10 }) |index| try cache.put(index, @intCast(index));
    // From the beginning.
    try expect_missing(&cache, 0, 5, &.{ 0, 3, 4, 7, 8 });
    try expect_missing(&cache, 0, 6, &.{ 0, 3, 4, 7, 8, 9 });
    try expect_missing(&cache, 0, 7, &.{ 0, 3, 4, 7, 8, 9 });
    // From within a gap.
    try expect_missing(&cache, 3, 3, &.{ 3, 4, 7 });
    try expect_missing(&cache, 4, 2, &.{ 4, 7 });
    // From within a range.
    try expect_missing(&cache, 1, 3, &.{ 3, 4, 7 });
    try expect_missing(&cache, 2, 4, &.{ 3, 4, 7, 8 });
    try expect_missing(&cache, 5, 2, &.{ 7, 8 });
    // After the last range.
    try expect_missing(&cache, 11, 5, &.{});
    try expect_missing(&cache, 100, 10, &.{});

    // A large gap.
    try cache.put(1000, 1000);
    try expect_missing(&cache, 11, 10, &.{ 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 });
    try expect_missing(&cache, 990, 15, &.{ 990, 991, 992, 993, 994, 995, 996, 997, 998, 999 });

    // Syncing keeps the ranges.
    try cache.sync();
    try expect_missing(&cache, 0, 5, &.{ 0, 3, 4, 7, 8 });
    try expect_missing(&cache, 3, 3, &.{ 3, 4, 7 });

    // Across a section boundary.
    try cache.put(default_items_per_blob - 1, 99);
    try cache.put(default_items_per_blob + 1, 101);
    const start = default_items_per_blob - 2;
    try expect_missing(&cache, start, 5, &.{ start, default_items_per_blob });
}

test "cache intervals after restart" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    const config = harness.cfg(i32, default_items_per_blob);
    {
        var cache = try harness.open(i32, config);
        defer cache.deinit();
        for ([_]u64{ 0, 100, 1000 }) |index| try cache.put(index, @intCast(index));
        try cache.sync();
    }
    harness.registry.deinit();
    harness.registry = metrics.Registry.init(gpa);
    var cache = try harness.open(i32, config);
    defer cache.deinit();
    try expect_gap(&cache, 0, 0, 100);
    try expect_gap(&cache, 100, 100, 1000);
    try expect_missing(&cache, 1, 5, &.{ 1, 2, 3, 4, 5 });
}

test "cache intervals with pruning" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    var cache = try harness.open(i32, harness.cfg(i32, 100));
    defer cache.deinit();
    for ([_]u64{ 50, 150, 250, 350 }) |index| try cache.put(index, @intCast(index));
    try expect_gap(&cache, 0, null, 50);

    try cache.prune(200);
    try testing.expect(!cache.has(50));
    try testing.expect(!cache.has(150));
    // Gaps and missing items exclude the pruned ranges.
    try expect_gap(&cache, 200, null, 250);
    try expect_missing(&cache, 200, 5, &.{ 200, 201, 202, 203, 204 });
    try testing.expect(cache.has(250));
    try testing.expect(cache.has(350));
    try expect_get(&cache, 250, @as(?i32, 250));
    try expect_get(&cache, 350, @as(?i32, 350));
}

test "cache sparse indices" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    var cache = try harness.open(i32, harness.cfg(i32, 100));
    defer cache.deinit();
    const indices = [_]u64{ 0, 99, 100, 500 };
    for (indices) |index| try cache.put(index, @intCast(index));
    for ([_]u64{ 1, 50, 101, 499 }) |index| try testing.expect(!cache.has(index));
    try expect_gap(&cache, 50, null, 99);
    try expect_gap(&cache, 99, 100, 500);
    try cache.sync();
    for (indices) |index| try expect_get(&cache, index, @as(?i32, @intCast(index)));
}

test "cache intervals edge cases" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    var cache = try harness.open(i32, harness.cfg(i32, default_items_per_blob));
    defer cache.deinit();
    // A single item.
    try cache.put(42, 42);
    try expect_gap(&cache, 42, 42, null);
    try expect_gap(&cache, 41, null, 42);
    try expect_gap(&cache, 43, null, null);
    // Consecutive items.
    try cache.put(43, 43);
    try cache.put(44, 44);
    try expect_gap(&cache, 42, 44, null);
    // Boundary values.
    const max = std.math.maxInt(u64);
    try cache.put(max - 1, 999);
    try expect_gap(&cache, max - 2, null, max - 1);
    try expect_gap(&cache, max - 1, max - 1, null);
}

test "cache intervals duplicate inserts" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    var cache = try harness.open(i32, harness.cfg(i32, default_items_per_blob));
    defer cache.deinit();
    try cache.put(10, 10);
    try testing.expect(cache.has(10));
    try expect_get(&cache, 10, @as(?i32, 10));
    // A duplicate put keeps the original value.
    try cache.put(10, 20);
    try testing.expect(cache.has(10));
    try expect_get(&cache, 10, @as(?i32, 10));
    try expect_gap(&cache, 10, 10, null);
    // Adjacent values merge.
    try cache.put(9, 9);
    try cache.put(11, 11);
    try expect_gap(&cache, 9, 11, null);
}

test "cache crash drops unsynced items" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    const config = harness.cfg(u64, 4);
    {
        var cache = try harness.open(u64, config);
        defer cache.deinit();
        for (0..6) |index| try cache.put(index, index * 3);
        try cache.sync();
        for (6..10) |index| try cache.put(index, index * 3);
    }
    harness.storage.crash();
    harness.registry.deinit();
    harness.registry = metrics.Registry.init(gpa);
    var cache = try harness.open(u64, config);
    defer cache.deinit();
    for (0..6) |index| try expect_get(&cache, index, @as(?u64, index * 3));
    for (6..10) |index| try testing.expect(!cache.has(index));
    try expect_gap(&cache, 0, 5, null);
    // The cache keeps accepting writes after recovery.
    try cache.put(7, 21);
    try cache.sync();
    try expect_get(&cache, 7, @as(?u64, 21));
}

test "cache destroy removes every blob" {
    var harness = try Harness.init(page_size, page_cache_size);
    defer harness.deinit();
    const config = harness.cfg(u64, 2);
    {
        var cache = try harness.open(u64, config);
        for (0..8) |index| try cache.put(index, index);
        try cache.sync();
        try cache.destroy();
    }
    var cache = try harness.open(u64, config);
    defer cache.deinit();
    try testing.expectEqual(@as(?u64, null), cache.first());
    try testing.expect(try harness.has_metric("items_tracked", 0));
}

// `cache_operations` fuzz target: random operations against a reference model, with syncs,
// prunes, and restarts. Fewer, smaller operations than commonware's so the seeded run is fast.

const fuzz_operations_max = 50;
const fuzz_index_max: u64 = 10000;
const fuzz_value_max: u32 = 1000000;

const FuzzModel = struct {
    values: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    pruned_min: ?u64 = null,
    items_per_blob: u64,

    fn retained(self: *const FuzzModel, index: u64) bool {
        const section = (index / self.items_per_blob) * self.items_per_blob;
        return self.pruned_min == null or section >= self.pruned_min.?;
    }

    fn first(self: *const FuzzModel) ?u64 {
        var result: ?u64 = null;
        var keys = self.values.keyIterator();
        while (keys.next()) |key| {
            if (result == null or key.* < result.?) result = key.*;
        }
        return result;
    }
};

const FuzzConfig = struct {
    items_per_blob: u64,
    write_buffer: usize,
    replay_buffer: usize,
    compression: ?u8,
    page_size: u16,
    page_cache_capacity: u32,

    fn arbitrary(reader: *fuzz_bytes.Reader) FuzzConfig {
        return .{
            .items_per_blob = @max(reader.int(u16) % 2048, 256),
            .write_buffer = @max(reader.int(u16), 256),
            .replay_buffer = @max(reader.int(u16) % (2 * 8192), 256),
            .compression = if (reader.boolean()) @intCast(1 + reader.below(21)) else null,
            .page_size = @intCast(511 + reader.below(4097 - 511 + 1)),
            .page_cache_capacity = @intCast(10 + reader.below(64 - 10 + 1)),
        };
    }
};

fn fuzz_open(
    storage: *MockStorage,
    registry: *metrics.Registry,
    config: cache_mod.Config(u32),
) !cache_mod.Cache(u32) {
    const scope = metrics.Scope.init(registry).child("storage");
    return cache_mod.Cache(u32).init(gpa, storage.interface(), scope, config);
}

fn fuzz_check_lookup(cache: *cache_mod.Cache(u32), model: *const FuzzModel, index: u64) !void {
    const expected = if (model.retained(index)) model.values.get(index) else null;
    try testing.expectEqual(expected != null, cache.has(index));
    try testing.expectEqual(expected, try cache.get(index));
}

fn fuzz_prune(cache: *cache_mod.Cache(u32), model: *FuzzModel, min: u64) !void {
    try cache.prune(min);
    const section_min = (min / model.items_per_blob) * model.items_per_blob;
    model.pruned_min = @max(model.pruned_min orelse section_min, section_min);
    var removed: std.ArrayList(u64) = .empty;
    defer removed.deinit(gpa);
    var keys = model.values.keyIterator();
    while (keys.next()) |key| {
        if (!model.retained(key.*)) try removed.append(gpa, key.*);
    }
    for (removed.items) |key| _ = model.values.remove(key);
}

fn fuzz_query(cache: *cache_mod.Cache(u32), model: *const FuzzModel, op: u64, from: u64) !void {
    switch (op) {
        3 => try testing.expectEqual(model.first(), cache.first()),
        4 => {
            const gap = cache.next_gap(from);
            if (gap.current_end) |end| try testing.expect(model.values.contains(end));
            if (gap.next_start) |start| try testing.expect(model.values.contains(start));
        },
        else => unreachable,
    }
}

fn fuzz_run(input: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(input);
    const fuzz_config = FuzzConfig.arbitrary(&reader);
    var storage = MockStorage.init(gpa);
    defer storage.deinit();
    var cache_ref = try paged.CacheRef.init(
        gpa,
        fuzz_config.page_size,
        fuzz_config.page_cache_capacity,
    );
    defer cache_ref.deinit();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const config: cache_mod.Config(u32) = .{
        .partition = "fuzz-cache",
        .compression = fuzz_config.compression,
        .codec_config = {},
        .items_per_blob = fuzz_config.items_per_blob,
        .write_buffer = fuzz_config.write_buffer,
        .replay_buffer = fuzz_config.replay_buffer,
        .cache_ref = &cache_ref,
    };
    var cache = try fuzz_open(&storage, &registry, config);
    defer cache.deinit();
    var model: FuzzModel = .{ .items_per_blob = fuzz_config.items_per_blob };
    defer model.values.deinit(gpa);
    var operations: u32 = 0;
    while (!reader.done() and operations < fuzz_operations_max) : (operations += 1) {
        const op = reader.below(9);
        switch (op) {
            0 => {
                const index = reader.below(fuzz_index_max);
                const value: u32 = @intCast(reader.below(fuzz_value_max));
                try cache.put(index, value);
                if (model.retained(index)) {
                    const entry = try model.values.getOrPut(gpa, index);
                    if (!entry.found_existing) entry.value_ptr.* = value;
                }
            },
            1, 2 => try fuzz_check_lookup(&cache, &model, reader.below(fuzz_index_max)),
            3, 4 => try fuzz_query(&cache, &model, op, reader.below(fuzz_index_max)),
            5 => {
                const from = reader.below(fuzz_index_max);
                var out: [100]u64 = undefined;
                const limit: usize = @intCast(reader.below(100) + 1);
                const missing = cache.missing_items(from, out[0..limit]);
                for (missing) |item| {
                    try testing.expect(item >= from);
                    try testing.expect(!model.values.contains(item));
                }
            },
            6 => try cache.sync(),
            7 => try fuzz_prune(&cache, &model, reader.below(fuzz_index_max)),
            8 => {
                // Make pending writes durable, restart, and replay; the floor resets.
                try cache.sync();
                cache.deinit();
                storage.crash();
                cache = try fuzz_open(&storage, &registry, config);
                model.pruned_min = null;
            },
            else => unreachable,
        }
    }
    try cache.sync();
}

test "fuzz cache operations (seeded)" {
    try fuzz_bytes.seeded(512, 0x63616368, 64, fuzz_run);
}

test "fuzz cache operations" {
    try testing.fuzz({}, fuzz_bytes.smith(512, fuzz_run), .{});
}
