//! Tests for the ordinal, ported from commonware's `ordinal/mod.rs` and `ordinal/storage.rs`,
//! and the `ordinal_operations` fuzz target (storage/fuzz) checked against a reference model.
//!
//! Commonware counts recovery syncs with a delayed-sync context and writes with a recording
//! context; here the storage mock's mutation budget and write counter check the same claims.
//! Commonware's determinism test compares auditor states; here it compares storage audits.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const ordinal = @import("mod.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");

const MockStorage = runtime.buffer.mocks.Storage;
const BitMap = ordinal.BitMap;
const SectionBits = ordinal.SectionBits;
const gpa = testing.allocator;

const default_items_per_blob: u64 = 1000;
const default_write_buffer: usize = 4096;
const default_replay_buffer: usize = 1024 * 1024;
const partition = "test-ordinal";
/// `FixedBytes<32>`.
const Value = [32]u8;
const record_size: u64 = 36;

fn fixed(byte: u8) Value {
    return @splat(byte);
}

fn config_with(items_per_blob: u64) ordinal.Config {
    return .{
        .partition = partition,
        .items_per_blob = items_per_blob,
        .write_buffer = default_write_buffer,
        .replay_buffer = default_replay_buffer,
    };
}

const Harness = struct {
    storage: MockStorage,
    registry: metrics.Registry,

    fn init() Harness {
        return .{ .storage = MockStorage.init(gpa), .registry = metrics.Registry.init(gpa) };
    }

    fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.storage.deinit();
    }

    fn open(
        self: *Harness,
        comptime V: type,
        config: ordinal.Config,
        bits: ?[]const SectionBits,
    ) !ordinal.Ordinal(V) {
        return self.open_diagnostic(V, config, bits, null);
    }

    fn open_diagnostic(
        self: *Harness,
        comptime V: type,
        config: ordinal.Config,
        bits: ?[]const SectionBits,
        failed_index: ?*u64,
    ) !ordinal.Ordinal(V) {
        const scope = metrics.Scope.init(&self.registry).child("storage");
        const store = self.storage.interface();
        return ordinal.Ordinal(V).init_diagnostic(gpa, store, scope, config, bits, failed_index);
    }

    fn metrics_text(self: *Harness) ![]u8 {
        return self.registry.encode(gpa);
    }

    fn expect_metric(self: *Harness, needle: []const u8) !void {
        const text = try self.metrics_text();
        defer gpa.free(text);
        if (std.mem.indexOf(u8, text, needle) == null) {
            std.debug.print("missing '{s}' in:\n{s}\n", .{ needle, text });
            return error.TestExpectedMetric;
        }
    }

    /// Write `bytes` durably at `offset` of section `section`'s raw blob (null appends).
    fn write_raw(self: *Harness, section: u64, offset: ?u64, bytes: []const u8) !void {
        const opened = try self.storage.open(partition, &ordinal.section_name(section));
        defer opened.blob.close();
        try opened.blob.write_at(offset orelse opened.len, bytes, .{});
        try opened.blob.sync();
    }

    /// Tear the last byte off a stored section so its length is no longer record-aligned.
    fn tear(self: *Harness, section: u64) !void {
        const opened = try self.storage.open(partition, &ordinal.section_name(section));
        defer opened.blob.close();
        try opened.blob.resize(opened.len - 1);
        try opened.blob.sync();
    }

    fn blob_len(self: *Harness, section: u64) !u64 {
        const opened = try self.storage.open(partition, &ordinal.section_name(section));
        defer opened.blob.close();
        return opened.len;
    }

    /// The sorted blob names of the partition, as section numbers. Caller frees.
    fn sections(self: *Harness) ![]u64 {
        const names = self.storage.scan(gpa, partition) catch |err| switch (err) {
            error.PartitionMissing => return gpa.alloc(u64, 0),
            else => return err,
        };
        defer names.deinit(gpa);
        const result = try gpa.alloc(u64, names.items.len);
        for (names.items, result) |name, *section| {
            section.* = std.mem.readInt(u64, name[0..8], .big);
        }
        return result;
    }

    /// Reset the registry so a reopened store registers its metrics afresh.
    fn reset_metrics(self: *Harness) void {
        self.registry.deinit();
        self.registry = metrics.Registry.init(gpa);
    }
};

/// A bitmap of `len` bits with `set` marked. Free with `deinit(gpa)`.
fn bitmap_with(len: u64, set: []const u64) !BitMap {
    var bitmap = try BitMap.zeroes(gpa, len);
    for (set) |bit| bitmap.set(bit, true);
    return bitmap;
}

fn expect_value(store: anytype, index: u64, expected: ?Value) !void {
    const value = try store.get(index);
    try testing.expectEqual(expected, value);
}

fn expect_gap(store: anytype, index: u64, current_end: ?u64, next_start: ?u64) !void {
    const gap = store.next_gap(index);
    try testing.expectEqual(current_end, gap.current_end);
    try testing.expectEqual(next_start, gap.next_start);
}

fn expect_missing(store: anytype, start: u64, max: usize, expected: []const u64) !void {
    var out: [64]u64 = undefined;
    try testing.expectEqualSlices(u64, expected, store.missing_items(start, out[0..max]));
}

test "ordinal record checks its crc and length" {
    const Record = ordinal.Record(Value);
    const encoded = Record.encode(fixed(7));
    try testing.expectEqual(fixed(7), Record.decode_valid(&encoded).?);
    var corrupt = encoded;
    corrupt[0] ^= 1;
    try testing.expectEqual(@as(?Value, null), Record.decode_valid(&corrupt));
    var corrupt_crc = encoded;
    corrupt_crc[35] ^= 1;
    try testing.expectEqual(@as(?Value, null), Record.decode_valid(&corrupt_crc));
    // A record encodes as the value and the big-endian CRC32C of its bytes.
    const crc = @import("cryptography").Crc32.checksum(&fixed(7));
    try testing.expectEqual(crc, std.mem.readInt(u32, encoded[32..36], .big));
}

test "ordinal put get" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(default_items_per_blob), null);
    defer store.deinit();
    try testing.expect(!store.has(0));
    try store.put(0, fixed(42));
    try testing.expect(store.has(0));
    try expect_value(&store, 0, fixed(42));
    try store.sync();
    try harness.expect_metric("gets_total 1");
    try harness.expect_metric("puts_total 1");
    try harness.expect_metric("has_total 2");
    try harness.expect_metric("syncs_total 1");
    try harness.expect_metric("pruned_total 0");
    try expect_value(&store, 0, fixed(42));
}

test "ordinal put existing index is ignored" {
    var harness = Harness.init();
    defer harness.deinit();
    const config = config_with(default_items_per_blob);
    {
        var store = try harness.open(Value, config, null);
        defer store.deinit();
        try store.put(7, fixed(1));
        // A later put to the index is ignored, whether or not the first is synced.
        try store.put(7, fixed(2));
        try expect_value(&store, 7, fixed(1));
        try store.sync();
        try store.put(7, fixed(3));
        try expect_value(&store, 7, fixed(1));
        try store.sync();
    }
    harness.reset_metrics();
    var committed = try bitmap_with(default_items_per_blob, &.{7});
    defer committed.deinit(gpa);
    var store = try harness.open(Value, config, &.{.{ .section = 0, .bits = &committed }});
    defer store.deinit();
    try expect_value(&store, 7, fixed(1));
}

test "ordinal sync does not report success while flush fails" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(default_items_per_blob), null);
    defer store.deinit();
    try store.put(0, fixed(42));
    // Removing the blob under the store makes its flush fail.
    try harness.storage.remove(partition, &ordinal.section_name(0));
    try testing.expect(std.meta.isError(store.sync()));
}

test "ordinal multiple indices" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(default_items_per_blob), null);
    defer store.deinit();
    const indices = [_]struct { u64, u8 }{
        .{ 0, 0 }, .{ 5, 5 }, .{ 10, 10 }, .{ 100, 100 }, .{ 1000, 200 },
    };
    for (indices) |entry| try store.put(entry[0], fixed(entry[1]));
    try store.sync();
    for (indices) |entry| try expect_value(&store, entry[0], fixed(entry[1]));
}

test "ordinal sparse indices" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(100), null);
    defer store.deinit();
    const indices = [_]struct { u64, u8 }{ .{ 0, 0 }, .{ 99, 99 }, .{ 100, 100 }, .{ 500, 200 } };
    for (indices) |entry| try store.put(entry[0], fixed(entry[1]));
    for ([_]u64{ 1, 50, 101, 499 }) |index| try testing.expect(!store.has(index));
    try store.sync();
    for (indices) |entry| try expect_value(&store, entry[0], fixed(entry[1]));
}

test "ordinal next gap" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(default_items_per_blob), null);
    defer store.deinit();
    for ([_]u8{ 1, 10, 11, 14 }) |index| try store.put(index, fixed(index));
    try expect_gap(&store, 0, null, 1);
    try expect_gap(&store, 1, 1, 10);
    try expect_gap(&store, 10, 11, 14);
    try expect_gap(&store, 11, 11, 14);
    try expect_gap(&store, 12, null, 14);
    try expect_gap(&store, 14, 14, null);
}

test "ordinal missing items" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(default_items_per_blob), null);
    defer store.deinit();
    try expect_missing(&store, 0, 5, &.{});
    try expect_missing(&store, 100, 10, &.{});
    for ([_]u8{ 1, 2, 5, 6, 10 }) |index| try store.put(index, fixed(index));
    try expect_missing(&store, 0, 5, &.{ 0, 3, 4, 7, 8 });
    try expect_missing(&store, 0, 6, &.{ 0, 3, 4, 7, 8, 9 });
    try expect_missing(&store, 0, 7, &.{ 0, 3, 4, 7, 8, 9 });
    try expect_missing(&store, 3, 3, &.{ 3, 4, 7 });
    try expect_missing(&store, 4, 2, &.{ 4, 7 });
    try expect_missing(&store, 1, 3, &.{ 3, 4, 7 });
    try expect_missing(&store, 2, 4, &.{ 3, 4, 7, 8 });
    try expect_missing(&store, 5, 2, &.{ 7, 8 });
    try expect_missing(&store, 11, 5, &.{});
    try expect_missing(&store, 100, 10, &.{});
    try store.put(1000, fixed(100));
    try expect_missing(&store, 11, 10, &.{ 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 });
    try expect_missing(&store, 990, 15, &.{ 990, 991, 992, 993, 994, 995, 996, 997, 998, 999 });
    try store.sync();
    try expect_missing(&store, 0, 5, &.{ 0, 3, 4, 7, 8 });
    try expect_missing(&store, 3, 3, &.{ 3, 4, 7 });
    // Across the blob boundary at 10000.
    try store.put(9999, fixed(99));
    try store.put(10001, fixed(101));
    try expect_missing(&store, 9998, 5, &.{ 9998, 10000 });
}

test "ordinal restart" {
    var harness = Harness.init();
    defer harness.deinit();
    const config = config_with(default_items_per_blob);
    const values = [_]struct { u64, u8 }{ .{ 0, 0 }, .{ 100, 100 }, .{ 1000, 200 } };
    {
        var store = try harness.open(Value, config, null);
        defer store.deinit();
        for (values) |entry| try store.put(entry[0], fixed(entry[1]));
        try store.sync();
    }
    harness.reset_metrics();
    var bits0 = try bitmap_with(default_items_per_blob, &.{ 0, 100 });
    defer bits0.deinit(gpa);
    var bits1 = try bitmap_with(default_items_per_blob, &.{0});
    defer bits1.deinit(gpa);
    var store = try harness.open(Value, config, &.{
        .{ .section = 0, .bits = &bits0 },
        .{ .section = 1, .bits = &bits1 },
    });
    defer store.deinit();
    for (values) |entry| try expect_value(&store, entry[0], fixed(entry[1]));
    try expect_gap(&store, 0, 0, 100);
}

/// Open without bits after `corrupt`, which must delete every stored record.
fn check_reset_after(
    items_per_blob: u64,
    puts: []const u64,
    corruption: struct { section: u64, offset: ?u64, bytes: []const u8 },
) !void {
    var harness = Harness.init();
    defer harness.deinit();
    const config = config_with(items_per_blob);
    {
        var store = try harness.open(Value, config, null);
        defer store.deinit();
        for (puts) |index| try store.put(index, fixed(@truncate(index)));
        try store.sync();
    }
    try harness.write_raw(corruption.section, corruption.offset, corruption.bytes);
    harness.reset_metrics();
    var store = try harness.open(Value, config, null);
    defer store.deinit();
    for (puts) |index| {
        try testing.expect(!store.has(index));
        try expect_value(&store, index, null);
    }
    // The store stays usable.
    try store.put(2, fixed(44));
    try expect_value(&store, 2, fixed(44));
}

test "ordinal invalid record" {
    try check_reset_after(default_items_per_blob, &.{0}, .{
        .section = 0,
        .offset = 32,
        .bytes = &.{0xFF},
    });
}

test "ordinal partial record write" {
    const partial: [32]u8 = @splat(0xFF);
    try check_reset_after(default_items_per_blob, &.{ 0, 1 }, .{
        .section = 0,
        .offset = 36,
        .bytes = &partial,
    });
}

test "ordinal corrupted value" {
    try check_reset_after(default_items_per_blob, &.{ 0, 1 }, .{
        .section = 0,
        .offset = 10,
        .bytes = &.{ 0xFF, 0xFF, 0xFF, 0xFF },
    });
}

test "ordinal crc corruptions" {
    try check_reset_after(10, &.{ 0, 5, 10, 15 }, .{
        .section = 1,
        .offset = 5,
        .bytes = &.{ 0xFF, 0xFF, 0xFF, 0xFF },
    });
}

test "ordinal extra bytes in blob" {
    var garbage: [36]u8 = @splat(0xFF);
    std.mem.writeInt(u32, garbage[32..36], 0xDEADBEEF, .big);
    try check_reset_after(default_items_per_blob, &.{ 0, 1 }, .{
        .section = 0,
        .offset = null,
        .bytes = &garbage,
    });
}

test "ordinal get nonexistent" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(default_items_per_blob), null);
    defer store.deinit();
    try expect_value(&store, 999, null);
    try testing.expect(!store.has(999));
}

test "ordinal destroy" {
    var harness = Harness.init();
    defer harness.deinit();
    const config = config_with(default_items_per_blob);
    {
        var store = try harness.open(Value, config, null);
        try store.put(0, fixed(0));
        try store.put(1000, fixed(100));
        try store.destroy();
    }
    harness.reset_metrics();
    var store = try harness.open(Value, config, &.{});
    defer store.deinit();
    try expect_value(&store, 0, null);
    try expect_value(&store, 1000, null);
    try testing.expect(!store.has(0));
    try testing.expect(!store.has(1000));
    const stored = try harness.sections();
    defer gpa.free(stored);
    try testing.expectEqual(@as(usize, 0), stored.len);
}

test "ordinal zero filled records" {
    var harness = Harness.init();
    defer harness.deinit();
    const zeros: [36 * 5]u8 = @splat(0);
    try harness.write_raw(0, 0, &zeros);
    try harness.write_raw(0, 36 * 5, &ordinal.Record(Value).encode(fixed(44)));
    var section = try bitmap_with(default_items_per_blob, &.{5});
    defer section.deinit(gpa);
    var store = try harness.open(
        Value,
        config_with(default_items_per_blob),
        &.{.{ .section = 0, .bits = &section }},
    );
    defer store.deinit();
    for (0..5) |index| try testing.expect(!store.has(index));
    try testing.expect(store.has(5));
    try expect_value(&store, 5, fixed(44));
}

/// Commonware's `test_operations_and_restart`: random sparse puts, restart with their bits,
/// and more puts. Returns the storage audit.
fn check_operations_and_restart(num_values: usize) ![4]u8 {
    const Big = [128]u8;
    var harness = Harness.init();
    defer harness.deinit();
    const config = config_with(100);
    var rng = utils.rng.TestRng.init(0);
    const indices = try gpa.alloc(u64, num_values);
    defer gpa.free(indices);
    const values = try gpa.alloc(Big, num_values);
    defer gpa.free(values);
    {
        var store = try harness.open(Big, config, null);
        defer store.deinit();
        var next_index: u64 = 0;
        for (indices, values) |*index, *value| {
            var index_bytes: [8]u8 = undefined;
            rng.fill_bytes(&index_bytes);
            index.* = next_index + std.mem.readInt(u64, &index_bytes, .big) % 1000;
            next_index = index.* + 1;
            rng.fill_bytes(value);
            try store.put(index.*, value.*);
        }
        try store.sync();
        for (indices, values) |index, value| {
            try testing.expectEqual(value, (try store.get(index)).?);
        }
        for (0..10) |i| _ = store.next_gap(i * 100);
        try store.sync();
    }
    harness.reset_metrics();
    const bits = try ordinal.bits_for_indices(gpa, 100, indices);
    defer ordinal.free_bits(gpa, bits);
    var store = try harness.open(Big, config, bits);
    defer store.deinit();
    for (indices, values) |index, value| try testing.expectEqual(value, (try store.get(index)).?);
    for (0..10) |_| {
        var index_bytes: [8]u8 = undefined;
        rng.fill_bytes(&index_bytes);
        var value: Big = undefined;
        rng.fill_bytes(&value);
        try store.put(std.mem.readInt(u64, &index_bytes, .big) % 10000, value);
    }
    try store.sync();
    return harness.storage.backend.audit();
}

test "ordinal determinism" {
    const first = try check_operations_and_restart(100);
    const second = try check_operations_and_restart(100);
    try testing.expectEqual(first, second);
}

test "ordinal prune basic" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(100), null);
    defer store.deinit();
    const values = [_]struct { u64, u8 }{
        .{ 0, 0 }, .{ 50, 50 }, .{ 100, 100 }, .{ 150, 150 }, .{ 200, 200 }, .{ 300, 44 },
    };
    for (values) |entry| try store.put(entry[0], fixed(entry[1]));
    try store.sync();
    for (values) |entry| try expect_value(&store, entry[0], fixed(entry[1]));

    try store.prune(150);
    try harness.expect_metric("pruned_total 1");
    for (values[0..2]) |entry| {
        try testing.expect(!store.has(entry[0]));
        try expect_value(&store, entry[0], null);
    }
    for (values[2..]) |entry| {
        try testing.expect(store.has(entry[0]));
        try expect_value(&store, entry[0], fixed(entry[1]));
    }

    try store.prune(250);
    try harness.expect_metric("pruned_total 2");
    for (values[0..4]) |entry| {
        try testing.expect(!store.has(entry[0]));
        try expect_value(&store, entry[0], null);
    }
    for (values[4..]) |entry| try expect_value(&store, entry[0], fixed(entry[1]));
}

test "ordinal prune with gaps" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(100), null);
    defer store.deinit();
    try store.put(5, fixed(5));
    try store.put(105, fixed(105));
    try store.put(305, fixed(49));
    try store.sync();
    try expect_gap(&store, 0, null, 5);
    try expect_gap(&store, 5, 5, 105);
    try store.prune(150);
    try testing.expect(!store.has(5));
    try expect_value(&store, 5, null);
    try testing.expect(store.has(105));
    try testing.expect(store.has(305));
    try expect_gap(&store, 0, null, 105);
    try expect_gap(&store, 105, 105, 305);
}

test "ordinal prune no op" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(100), null);
    defer store.deinit();
    try store.put(100, fixed(100));
    try store.put(200, fixed(200));
    try store.sync();
    // Pruning below the first blob, or exactly at its start, removes nothing.
    for ([_]u64{ 50, 100 }) |min| {
        try store.prune(min);
        try testing.expect(store.has(100));
        try testing.expect(store.has(200));
        try harness.expect_metric("pruned_total 0");
    }
}

test "ordinal prune empty store" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(100), null);
    defer store.deinit();
    try store.prune(1000);
    try store.put(0, fixed(0));
    try testing.expect(store.has(0));
}

test "ordinal prune after restart" {
    var harness = Harness.init();
    defer harness.deinit();
    const config = config_with(100);
    {
        var store = try harness.open(Value, config, null);
        defer store.deinit();
        for ([_]u8{ 0, 100, 200 }) |index| try store.put(index, fixed(index));
        try store.sync();
    }
    var first = try bitmap_with(100, &.{0});
    defer first.deinit(gpa);
    harness.reset_metrics();
    {
        var store = try harness.open(Value, config, &.{
            .{ .section = 0, .bits = &first },
            .{ .section = 1, .bits = &first },
            .{ .section = 2, .bits = &first },
        });
        defer store.deinit();
        for ([_]u64{ 0, 100, 200 }) |index| try testing.expect(store.has(index));
        try store.prune(150);
        try testing.expect(!store.has(0));
        try testing.expect(store.has(100));
        try testing.expect(store.has(200));
        try store.sync();
    }
    harness.reset_metrics();
    var store = try harness.open(Value, config, &.{
        .{ .section = 1, .bits = &first },
        .{ .section = 2, .bits = &first },
    });
    defer store.deinit();
    try testing.expect(!store.has(0));
    try testing.expect(store.has(100));
    try testing.expect(store.has(200));
    try expect_gap(&store, 0, null, 100);
}

test "ordinal prune multiple operations" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(50), null);
    defer store.deinit();
    for (0..10) |i| try store.put(i * 50 + 25, fixed(@intCast(i)));
    try store.sync();
    for (1..5) |i| {
        const min = i * 50 + 10;
        try store.prune(min);
        for (0..10) |j| {
            const index = j * 50 + 25;
            try testing.expectEqual(index >= min, store.has(index));
        }
    }
    try harness.expect_metric("pruned_total 4");
    for (4..10) |i| try expect_value(&store, i * 50 + 25, fixed(@intCast(i)));
}

test "ordinal prune blob boundaries" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(100), null);
    defer store.deinit();
    for ([_]u8{ 0, 99, 100, 199, 200 }) |index| try store.put(index, fixed(index));
    try store.sync();
    // Exactly at a boundary prunes the blob before it.
    try store.prune(100);
    try testing.expect(!store.has(0));
    try testing.expect(!store.has(99));
    for ([_]u64{ 100, 199, 200 }) |index| try testing.expect(store.has(index));
    // Just before the next boundary prunes nothing.
    try store.prune(199);
    for ([_]u64{ 100, 199, 200 }) |index| try testing.expect(store.has(index));
    try store.prune(200);
    try testing.expect(!store.has(100));
    try testing.expect(!store.has(199));
    try testing.expect(store.has(200));
    try harness.expect_metric("pruned_total 2");
}

test "ordinal prune non contiguous sections" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(100), null);
    defer store.deinit();
    const indices = [_]u64{ 0, 250, 500, 750 };
    for (indices, [_]u8{ 0, 50, 44, 45 }) |index, byte| try store.put(index, fixed(byte));
    try store.sync();
    for (indices) |index| try testing.expect(store.has(index));
    const steps = [_]struct { u64, usize, []const u8 }{
        .{ 300, 2, "pruned_total 2" },
        .{ 600, 3, "pruned_total 3" },
        .{ 1000, 4, "pruned_total 4" },
    };
    for (steps) |step| {
        try store.prune(step[0]);
        for (indices, 0..) |index, position| {
            try testing.expectEqual(position >= step[1], store.has(index));
        }
        try harness.expect_metric(step[2]);
    }
}

test "ordinal prune removes correct pending" {
    var harness = Harness.init();
    defer harness.deinit();
    var store = try harness.open(Value, config_with(100), null);
    defer store.deinit();
    try store.put(5, fixed(5));
    try store.sync();
    try store.put(10, fixed(10));
    try store.put(110, fixed(110));
    for ([_]u64{ 5, 10, 110 }) |index| try testing.expect(store.has(index));
    try store.prune(150);
    try testing.expect(!store.has(5));
    try testing.expect(!store.has(10));
    try testing.expect(store.has(110));
    try expect_value(&store, 110, fixed(110));
    try store.sync();
    try expect_value(&store, 110, fixed(110));
}

/// Fill `puts` (value byte = index) in a store of `items_per_blob` and sync.
fn fill(harness: *Harness, items_per_blob: u64, puts: []const u64) !void {
    {
        var store = try harness.open(Value, config_with(items_per_blob), null);
        defer store.deinit();
        for (puts) |index| try store.put(index, fixed(@truncate(index)));
        try store.sync();
    }
    harness.reset_metrics();
}

test "ordinal init without bits deletes existing data" {
    var harness = Harness.init();
    defer harness.deinit();
    try fill(&harness, 10, &.{ 0, 5, 9, 10, 15, 25 });
    var store = try harness.open(Value, config_with(10), null);
    defer store.deinit();
    for ([_]u64{ 0, 5, 9, 10, 15, 25, 1, 11, 20 }) |index| try testing.expect(!store.has(index));
    const stored = try harness.sections();
    defer gpa.free(stored);
    try testing.expectEqual(@as(usize, 0), stored.len);
}

test "ordinal init empty bits" {
    var harness = Harness.init();
    defer harness.deinit();
    try fill(&harness, 10, &.{ 0, 10, 20 });
    {
        var store = try harness.open(Value, config_with(10), &.{});
        defer store.deinit();
        for ([_]u64{ 0, 10, 20 }) |index| try testing.expect(!store.has(index));
    }
    harness.reset_metrics();
    // The empty list deleted every blob, so a later claim on one is missing.
    var section = try bitmap_with(10, &.{0});
    defer section.deinit(gpa);
    var failed_index: u64 = std.math.maxInt(u64);
    const bits: []const SectionBits = &.{.{ .section = 0, .bits = &section }};
    const result = harness.open_diagnostic(Value, config_with(10), bits, &failed_index);
    try testing.expectError(error.MissingRecord, result);
    try testing.expectEqual(@as(u64, 0), failed_index);
}

test "ordinal init selective sections" {
    var harness = Harness.init();
    defer harness.deinit();
    var all: [30]u64 = undefined;
    for (&all, 0..) |*index, i| index.* = i;
    try fill(&harness, 10, &all);
    {
        var section = try bitmap_with(10, &.{ 2, 5, 8 });
        defer section.deinit(gpa);
        const bits: []const SectionBits = &.{.{ .section = 1, .bits = &section }};
        var store = try harness.open(Value, config_with(10), bits);
        defer store.deinit();
        for (0..30) |index| {
            const expected = index == 12 or index == 15 or index == 18;
            try testing.expectEqual(expected, store.has(index));
        }
        for ([_]u8{ 12, 15, 18 }) |index| try expect_value(&store, index, fixed(index));
    }
    harness.reset_metrics();
    // Unselected records of a retained section were cleared. A later bitmap claiming one is
    // trusted at init (it proves membership), so the damage surfaces at get.
    var section = try bitmap_with(10, &.{0});
    defer section.deinit(gpa);
    var store = try harness.open(Value, config_with(10), &.{.{ .section = 1, .bits = &section }});
    defer store.deinit();
    try testing.expect(store.has(10));
    try testing.expectError(error.InvalidRecord, store.get(10));
}

test "ordinal init null bitmap requires every record" {
    var harness = Harness.init();
    defer harness.deinit();
    try fill(&harness, 5, &.{ 5, 6, 7, 8, 9 });
    var store = try harness.open(Value, config_with(5), &.{.{ .section = 1, .bits = null }});
    defer store.deinit();
    for (5..10) |index| {
        try testing.expect(store.has(index));
        try expect_value(&store, index, fixed(@intCast(index)));
    }
}

test "ordinal init null bitmap with a missing record fails" {
    var harness = Harness.init();
    defer harness.deinit();
    try fill(&harness, 5, &.{ 5, 7, 8, 9 });
    var failed_index: u64 = 0;
    const bits: []const SectionBits = &.{.{ .section = 1, .bits = null }};
    const result = harness.open_diagnostic(Value, config_with(5), bits, &failed_index);
    try testing.expectError(error.MissingRecord, result);
    try testing.expectEqual(@as(u64, 6), failed_index);
}

test "ordinal init mixed sections" {
    var harness = Harness.init();
    defer harness.deinit();
    try fill(&harness, 5, &.{ 0, 1, 2, 3, 4, 5, 7, 9, 10, 11, 12, 13, 14 });
    var section1 = try bitmap_with(5, &.{ 0, 2 });
    defer section1.deinit(gpa);
    // Section 0 is kept whole, section 1 by bitmap, and section 2 is removed.
    var store = try harness.open(Value, config_with(5), &.{
        .{ .section = 0, .bits = null },
        .{ .section = 1, .bits = &section1 },
    });
    defer store.deinit();
    for (0..5) |index| try expect_value(&store, index, fixed(@intCast(index)));
    try testing.expect(store.has(5));
    try testing.expect(store.has(7));
    for ([_]u64{ 6, 8, 9, 10, 11, 12, 13, 14 }) |index| try testing.expect(!store.has(index));
}

test "ordinal marked record damage surfaces at get" {
    var harness = Harness.init();
    defer harness.deinit();
    try fill(&harness, 5, &.{ 0, 1, 2, 3, 4 });
    try harness.write_raw(0, 2 * 36 + 32, &.{0xFF});
    var section = try bitmap_with(5, &.{ 0, 2, 4 });
    defer section.deinit(gpa);
    var store = try harness.open(Value, config_with(5), &.{.{ .section = 0, .bits = &section }});
    defer store.deinit();
    try expect_value(&store, 0, fixed(0));
    try testing.expectError(error.InvalidRecord, store.get(2));
    try expect_value(&store, 4, fixed(4));
}

/// A value that fails to decode when zero (commonware's `DummyValue`).
const DummyValue = struct {
    value: u64,

    pub const fixed_size: usize = 8;

    pub fn write(self: DummyValue, writer: *codec.Writer) void {
        writer.write_int(u64, self.value);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!DummyValue {
        const value = try reader.read_int(u64);
        if (value == 0) return reader.invalid("DummyValue", "value must be non-zero");
        return .{ .value = value };
    }
};

test "ordinal unparseable record is invalid" {
    var harness = Harness.init();
    defer harness.deinit();
    const config = config_with(1);
    {
        var store = try harness.open(DummyValue, config, null);
        defer store.deinit();
        try store.put(1, .{ .value = 1 });
        try store.put(2, .{ .value = 0 });
        try store.put(4, .{ .value = 4 });
        try store.sync();
        // A record whose CRC matches but whose value fails to decode is invalid.
        try testing.expectError(error.InvalidRecord, store.get(2));
    }
    harness.reset_metrics();
    var store = try harness.open(DummyValue, config, null);
    defer store.deinit();
    for ([_]u64{ 1, 2, 4 }) |index| try testing.expect(!store.has(index));
}

test "ordinal init clean sections sync nothing" {
    var harness = Harness.init();
    defer harness.deinit();
    try fill(&harness, 2, &.{ 0, 1, 2, 3 });
    // Recovering aligned sections kept whole mutates nothing.
    harness.storage.allow_mutations(0);
    var store = try harness.open(Value, config_with(2), &.{
        .{ .section = 0, .bits = null },
        .{ .section = 1, .bits = null },
    });
    defer store.deinit();
    try testing.expect(!harness.storage.mutation_refused);
    for (0..4) |index| try testing.expect(store.has(index));
}

test "ordinal init removes uncovered torn section unopened" {
    for ([_]bool{ false, true }) |unmarked| {
        var harness = Harness.init();
        defer harness.deinit();
        try fill(&harness, 2, &.{ 0, 1, 2, 3 });
        try harness.tear(1);
        // Holding section 1 open makes any open of it by recovery fail with BlobAlreadyOpen.
        const held = try harness.storage.open(partition, &ordinal.section_name(1));
        defer held.blob.close();
        var zeroes = try BitMap.zeroes(gpa, 2);
        defer zeroes.deinit(gpa);
        const omitted: []const SectionBits = &.{.{ .section = 0, .bits = null }};
        const marked_nothing: []const SectionBits = &.{
            .{ .section = 0, .bits = null },
            .{ .section = 1, .bits = &zeroes },
        };
        // Removing section 1 is the only mutation: it is never repaired or synced.
        harness.storage.allow_mutations(1);
        const bits = if (unmarked) marked_nothing else omitted;
        var store = try harness.open(Value, config_with(2), bits);
        defer store.deinit();
        try testing.expect(!harness.storage.mutation_refused);
        try testing.expect(store.has(0));
        try testing.expect(store.has(1));
        try testing.expect(!store.has(2));
        try testing.expect(!store.has(3));
        try expect_value(&store, 1, fixed(1));
        const stored = try harness.sections();
        defer gpa.free(stored);
        try testing.expectEqualSlices(u64, &.{0}, stored);
    }
}

test "ordinal init repairs covered torn section" {
    var harness = Harness.init();
    defer harness.deinit();
    try fill(&harness, 2, &.{ 0, 1, 2, 3 });
    try harness.tear(0);
    var partial = try bitmap_with(2, &.{0});
    defer partial.deinit(gpa);
    // Only the tail repair (a resize and its sync) mutates storage: truncation already
    // removed the unmarked record, so clearing writes nothing.
    harness.storage.allow_mutations(2);
    {
        var store = try harness.open(Value, config_with(2), &.{
            .{ .section = 0, .bits = &partial },
            .{ .section = 1, .bits = null },
        });
        defer store.deinit();
        try testing.expect(!harness.storage.mutation_refused);
        try testing.expectEqual(@as(?u64, 0), harness.storage.mutations_allowed);
        try testing.expect(store.has(0));
        try testing.expect(!store.has(1));
        try testing.expect(store.has(2));
        try testing.expect(store.has(3));
        try expect_value(&store, 0, fixed(0));
    }
    harness.storage.mutations_allowed = null;
    try testing.expectEqual(record_size, try harness.blob_len(0));
}

test "ordinal init rejects whole section with extra records" {
    var harness = Harness.init();
    defer harness.deinit();
    try fill(&harness, 8, &.{ 0, 1, 2, 3, 4, 5, 6, 7 });
    const bits: []const SectionBits = &.{.{ .section = 0, .bits = null }};
    var failed_index: u64 = 0;
    const result = harness.open_diagnostic(Value, config_with(4), bits, &failed_index);
    try testing.expectError(error.InvalidRecord, result);
    try testing.expectEqual(@as(u64, 4), failed_index);
    harness.reset_metrics();
    // The original size still opens the section.
    var store = try harness.open(Value, config_with(8), bits);
    defer store.deinit();
    for (0..8) |index| try testing.expect(store.has(index));
}

test "ordinal init clears unmarked runs" {
    const cases = [_]struct { usize, u64 }{
        .{ 36 * default_items_per_blob, 2 },
        .{ 36 * 100, 10 },
    };
    for (cases) |case| {
        var harness = Harness.init();
        defer harness.deinit();
        var config = config_with(default_items_per_blob);
        config.write_buffer = case[0];
        {
            var store = try harness.open(Value, config, null);
            defer store.deinit();
            try store.put(1, fixed(1));
            try store.put(900, fixed(9));
            try store.sync();
        }
        harness.reset_metrics();
        var marked = try bitmap_with(default_items_per_blob, &.{ 1, 900 });
        defer marked.deinit(gpa);
        harness.storage.writes = 0;
        var store = try harness.open(Value, config, &.{.{ .section = 0, .bits = &marked }});
        defer store.deinit();
        // Slot 0 and slots 2..900 are the two unmarked runs.
        try testing.expectEqual(case[1], harness.storage.writes);
        try testing.expect(store.has(1));
        try testing.expect(store.has(900));
        try testing.expect(!store.has(0));
        try testing.expect(!store.has(2));
        try testing.expect(!store.has(899));
    }
}

test "ordinal init clears unmarked records" {
    var harness = Harness.init();
    defer harness.deinit();
    const config = config_with(default_items_per_blob);
    {
        var store = try harness.open(Value, config, null);
        defer store.deinit();
        for (0..901) |index| try store.put(index, fixed(@truncate(index)));
        try store.sync();
    }
    harness.reset_metrics();
    // A bitmap marking slot 1 that ends before slot 900.
    var marked = try bitmap_with(500, &.{1});
    defer marked.deinit(gpa);
    {
        var recordings: runtime.storage.mocks.Recordings = .init(gpa);
        defer recordings.deinit();
        const inner = harness.storage.interface();
        var recording: runtime.storage.mocks.Recording = .init(gpa, inner, &recordings);
        const scope = metrics.Scope.init(&harness.registry).child("storage");
        const bits: []const SectionBits = &.{.{ .section = 0, .bits = &marked }};
        var store = try ordinal.Ordinal(Value).init_diagnostic(
            gpa,
            recording.storage(),
            scope,
            config,
            bits,
            null,
        );
        defer store.deinit();
        // Recovery zeroes every unmarked record and makes that durable with one sync.
        try testing.expectEqual(@as(u64, 1), recordings.syncs);
        try testing.expect(store.has(1));
        try testing.expect(!store.has(5));
        try testing.expect(!store.has(900));
    }
    const opened = try harness.storage.open(partition, &ordinal.section_name(0));
    defer opened.blob.close();
    try testing.expectEqual(901 * record_size, opened.len);
    const bytes = try gpa.alloc(u8, @intCast(opened.len));
    defer gpa.free(bytes);
    try opened.blob.read_at(0, bytes);
    for (0..901) |slot| {
        const record = bytes[slot * record_size ..][0..record_size];
        if (slot == 1) {
            try testing.expectEqualSlices(u8, &fixed(1), record[0..32]);
        } else {
            try testing.expect(std.mem.allEqual(u8, record, 0));
        }
    }
}

// `ordinal_operations` fuzz target: random puts, gets, syncs, prunes, batches, and reopens
// from the synced bits, checked against a reference map.

const fuzz_operations_max = 64;

const FuzzModel = struct {
    expected: std.AutoHashMapUnmanaged(u64, Value) = .empty,

    fn deinit(self: *FuzzModel) void {
        self.expected.deinit(gpa);
    }

    fn put(self: *FuzzModel, index: u64, value: Value) !void {
        const entry = try self.expected.getOrPut(gpa, index);
        if (!entry.found_existing) entry.value_ptr.* = value;
    }

    fn prune(self: *FuzzModel, min_section: u64, items_per_blob: u64) !void {
        var removed: std.ArrayList(u64) = .empty;
        defer removed.deinit(gpa);
        var keys = self.expected.keyIterator();
        while (keys.next()) |key| {
            if (key.* / items_per_blob < min_section) try removed.append(gpa, key.*);
        }
        for (removed.items) |key| _ = self.expected.remove(key);
    }

    fn indices(self: *const FuzzModel) ![]u64 {
        const result = try gpa.alloc(u64, self.expected.count());
        var keys = self.expected.keyIterator();
        var position: usize = 0;
        while (keys.next()) |key| : (position += 1) result[position] = key.*;
        return result;
    }
};

fn fuzz_index(reader: *fuzz_bytes.Reader) u64 {
    // Mostly small indices so operations collide, sometimes anywhere in u64.
    return if (reader.below(8) == 0) reader.int(u64) else reader.below(4096);
}

fn fuzz_check_gap(store: *ordinal.Ordinal(Value), index: u64) !void {
    const gap = store.next_gap(index);
    if (gap.current_end) |end| {
        try testing.expect(store.has(end));
        if (end < std.math.maxInt(u64)) try testing.expect(!store.has(end + 1));
    }
    if (gap.next_start) |start| {
        try testing.expect(store.has(start));
        if (start > 0) try testing.expect(!store.has(start - 1));
    }
}

fn fuzz_reopen(
    harness: *Harness,
    store: *ordinal.Ordinal(Value),
    model: *const FuzzModel,
    config: ordinal.Config,
) !void {
    try store.sync();
    store.deinit();
    harness.storage.crash();
    harness.reset_metrics();
    const indices = try model.indices();
    defer gpa.free(indices);
    const bits = try ordinal.bits_for_indices(gpa, config.items_per_blob, indices);
    defer ordinal.free_bits(gpa, bits);
    store.* = harness.open(Value, config, bits) catch |err| {
        // Leave a live store behind for the caller to close.
        store.* = try harness.open(Value, config, null);
        return err;
    };
    for (indices) |index| try expect_value(store, index, model.expected.get(index).?);
}

fn fuzz_step(
    harness: *Harness,
    store: *ordinal.Ordinal(Value),
    model: *FuzzModel,
    config: ordinal.Config,
    reader: *fuzz_bytes.Reader,
) !void {
    switch (reader.below(9)) {
        0 => {
            const index = fuzz_index(reader);
            var value: Value = @splat(0);
            for (value[0..@intCast(reader.below(33))]) |*byte| byte.* = reader.int(u8);
            try store.put(index, value);
            try model.put(index, value);
        },
        1 => {
            const index = fuzz_index(reader);
            try expect_value(store, index, model.expected.get(index));
            try testing.expectEqual(model.expected.contains(index), store.has(index));
        },
        2 => try fuzz_check_gap(store, fuzz_index(reader)),
        3 => try store.sync(),
        4 => {
            const min = fuzz_index(reader);
            try store.prune(min);
            try model.prune(min / config.items_per_blob, config.items_per_blob);
        },
        5 => {
            // Sparse puts, then a sync.
            for (0..@intCast(1 + reader.below(10))) |i| {
                const index = fuzz_index(reader);
                const value = fixed(@intCast(i));
                try store.put(index, value);
                try model.put(index, value);
            }
            try store.sync();
        },
        6 => {
            // A consecutive batch, then a sync.
            const start = reader.below(4096);
            for (0..@intCast(reader.below(256))) |i| {
                const value = fixed(@truncate(i));
                try store.put(start + i, value);
                try model.put(start + i, value);
            }
            try store.sync();
        },
        7 => try fuzz_reopen(harness, store, model, config),
        8 => try testing.expectEqual(model.expected.count() > 0, store.first_index() != null),
        else => unreachable,
    }
}

fn fuzz_run(input: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(input);
    var harness = Harness.init();
    defer harness.deinit();
    const config: ordinal.Config = .{
        .partition = "ordinal-operations-fuzz-test",
        .items_per_blob = @max(reader.int(u16), 1),
        .write_buffer = 4096,
        .replay_buffer = 64 * 1024,
    };
    var store = try harness.open(Value, config, null);
    var model: FuzzModel = .{};
    defer model.deinit();
    var operations: u32 = 0;
    while (!reader.done() and operations < fuzz_operations_max) : (operations += 1) {
        fuzz_step(&harness, &store, &model, config, &reader) catch |err| {
            store.deinit();
            return err;
        };
    }
    try store.destroy();
}

test "fuzz ordinal operations (seeded)" {
    try fuzz_bytes.seeded(512, 0x6f72646e, 64, fuzz_run);
}

test "fuzz ordinal operations" {
    try testing.fuzz({}, fuzz_bytes.smith(512, fuzz_run), .{});
}
