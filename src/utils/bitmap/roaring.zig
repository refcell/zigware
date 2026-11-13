//! A 64-bit roaring compressed bitmap (commonware `utils/src/bitmap/roaring`): each value
//! splits into a 48-bit container key and a 16-bit index, and each key's values live in a
//! `Container` (an `Array`, `BitmapContainer`, or `Run`, converting as density changes).
//!
//! Encoding: the containers as a `BTreeMap<u64, Container>` (u32 varint count, then each key
//! as a big-endian `u64` and its canonical container), keys strictly ascending. Decoding
//! bounds the container count with a `RangeCfg(usize)` and rejects keys past 48 bits and
//! empty containers.

const std = @import("std");
const codec = @import("codec");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const array = @import("roaring/array.zig");
pub const Array = array.Array;
pub const bitmap_container = @import("roaring/bitmap.zig");
/// The 8 KB container kind (Rust `container::Bitmap`).
pub const BitmapContainer = bitmap_container.Bitmap;
pub const run = @import("roaring/run.zig");
pub const Run = run.Run;
pub const container = @import("roaring/container.zig");
pub const Container = container.Container;
pub const prunable = @import("roaring/prunable.zig");
pub const Prunable = prunable.Prunable;
pub const ops = @import("roaring/ops.zig");

pub const MAX_KEY: u64 = (1 << 48) - 1;

pub fn high_bits(value: u64) u64 {
    return value >> 16;
}

pub fn low_bits(value: u64) u16 {
    return @truncate(value);
}

pub fn combine(key: u64, index: u16) u64 {
    assert(key <= MAX_KEY);
    return key << 16 | index;
}

const ContainerMap = codec.Map(u64, Container);

pub const Bitmap = struct {
    /// Containers by strictly ascending key; none is empty.
    containers: std.ArrayList(Entry) = .empty,

    pub const Entry = ContainerMap.Entry;
    /// Bounds the number of containers.
    pub const Cfg = codec.RangeCfg(usize);
    pub const empty: Bitmap = .{};

    // Set operations (ops.zig).
    pub const @"union" = ops.@"union";
    pub const intersection = ops.intersection;
    pub const difference = ops.difference;
    pub const is_subset = ops.is_subset;
    pub const intersects = ops.intersects;

    pub fn deinit(self: *Bitmap, gpa: Allocator) void {
        for (self.containers.items) |*entry| entry.value.deinit(gpa);
        self.containers.deinit(gpa);
        self.* = undefined;
    }

    pub fn clone(self: *const Bitmap, gpa: Allocator) Allocator.Error!Bitmap {
        var result: Bitmap = .{};
        errdefer result.deinit(gpa);
        try result.containers.ensureTotalCapacity(gpa, self.containers.items.len);
        for (self.containers.items) |*entry| {
            const copy = try entry.value.clone(gpa);
            result.containers.appendAssumeCapacity(.{ .key = entry.key, .value = copy });
        }
        return result;
    }

    pub fn clear(self: *Bitmap, gpa: Allocator) void {
        for (self.containers.items) |*entry| entry.value.deinit(gpa);
        self.containers.clearRetainingCapacity();
    }

    pub fn len(self: *const Bitmap) u64 {
        var total: u64 = 0;
        for (self.containers.items) |*entry| total += entry.value.len();
        return total;
    }

    pub fn is_empty(self: *const Bitmap) bool {
        return self.containers.items.len == 0;
    }

    pub fn container_count(self: *const Bitmap) usize {
        return self.containers.items.len;
    }

    /// The position of `key`, or where it would go.
    fn search(self: *const Bitmap, key: u64) struct { usize, bool } {
        const items = self.containers.items;
        var low: usize = 0;
        var high: usize = items.len;
        // Each pass halves `high - low`: at most 64 passes.
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (items[middle].key < key) low = middle + 1 else high = middle;
        }
        return .{ low, low < items.len and items[low].key == key };
    }

    pub fn get(self: *const Bitmap, key: u64) ?*const Container {
        const position, const found = self.search(key);
        return if (found) &self.containers.items[position].value else null;
    }

    fn get_or_insert(self: *Bitmap, gpa: Allocator, key: u64) Allocator.Error!*Container {
        assert(key <= MAX_KEY);
        const position, const found = self.search(key);
        if (!found) try self.containers.insert(gpa, position, .{ .key = key, .value = .empty });
        return &self.containers.items[position].value;
    }

    /// Drops a container left empty by a failed insert, keeping every container non-empty.
    fn drop_if_empty(self: *Bitmap, gpa: Allocator, key: u64) void {
        const position, const found = self.search(key);
        if (!found or !self.containers.items[position].value.is_empty()) return;
        var removed = self.containers.orderedRemove(position);
        removed.value.deinit(gpa);
    }

    pub fn contains(self: *const Bitmap, value: u64) bool {
        const found = self.get(high_bits(value)) orelse return false;
        return found.contains(low_bits(value));
    }

    /// Returns whether `value` was new.
    pub fn insert(self: *Bitmap, gpa: Allocator, value: u64) Allocator.Error!bool {
        const key = high_bits(value);
        errdefer self.drop_if_empty(gpa, key);
        const target = try self.get_or_insert(gpa, key);
        return target.insert(gpa, low_bits(value));
    }

    /// Inserts `[start, end)`; returns how many values were new.
    pub fn insert_range(
        self: *Bitmap,
        gpa: Allocator,
        start: u64,
        end: u64,
    ) Allocator.Error!u64 {
        if (start >= end) return 0;
        const start_key = high_bits(start);
        const end_key = high_bits(end - 1);
        var inserted: u64 = 0;
        var key = start_key;
        // One pass per container key in the range.
        while (key <= end_key) : (key += 1) {
            inserted += try self.insert_in_container(gpa, key, start, end - 1);
        }
        return inserted;
    }

    /// Inserts the part of `[first, last]` that falls in container `key`.
    fn insert_in_container(
        self: *Bitmap,
        gpa: Allocator,
        key: u64,
        first: u64,
        last: u64,
    ) Allocator.Error!u64 {
        errdefer self.drop_if_empty(gpa, key);
        const low: u16 = if (key == high_bits(first)) low_bits(first) else 0;
        const high: u16 = if (key == high_bits(last)) low_bits(last) else 65535;
        const target = try self.get_or_insert(gpa, key);
        if (low == 0 and high == 65535) {
            const added = bitmap_container.BITS - target.len();
            const full: Container = .{ .run = try Run.full(gpa) };
            target.deinit(gpa);
            target.* = full;
            return added;
        }
        if (high < 65535) return try target.insert_range(gpa, low, high + 1);
        const added = try target.insert_range(gpa, low, 65535);
        return added + @intFromBool(try target.insert(gpa, 65535));
    }

    pub fn min(self: *const Bitmap) ?u64 {
        if (self.containers.items.len == 0) return null;
        const first = &self.containers.items[0];
        return combine(first.key, first.value.min().?);
    }

    pub fn max(self: *const Bitmap) ?u64 {
        const items = self.containers.items;
        if (items.len == 0) return null;
        return combine(items[items.len - 1].key, items[items.len - 1].value.max().?);
    }

    /// Drops every container with a key below `key`.
    pub fn truncate_containers_below(self: *Bitmap, gpa: Allocator, key: u64) void {
        const position, _ = self.search(key);
        for (self.containers.items[0..position]) |*entry| entry.value.deinit(gpa);
        self.containers.replaceRangeAssumeCapacity(0, position, &.{});
        assert(self.containers.items.len == 0 or self.containers.items[0].key >= key);
    }

    /// Container counts by kind: arrays, bitmaps, runs.
    pub fn container_variant_counts(self: *const Bitmap) [3]usize {
        var counts: [3]usize = @splat(0);
        for (self.containers.items) |*entry| counts[@backingInt(entry.value)] += 1;
        return counts;
    }

    pub fn eql(a: *const Bitmap, b: *const Bitmap) bool {
        if (a.containers.items.len != b.containers.items.len) return false;
        for (a.containers.items, b.containers.items) |*left, *right| {
            if (left.key != right.key or !left.value.eql(&right.value)) return false;
        }
        return true;
    }

    // Iteration.

    /// Values in increasing order, optionally bounded to `[start, end)`.
    pub const Iterator = struct {
        entries: []const Entry,
        position: usize,
        current: ?Container.Iterator,
        start: u64,
        /// The last position to report (inclusive, so `maxInt(u64)` can be included).
        last: u64,

        pub fn next(it: *Iterator) ?u64 {
            // Each pass consumes a value or a container: bounded by both.
            while (true) {
                if (it.current) |*values| {
                    if (values.next()) |index| {
                        return combine(it.entries[it.position - 1].key, index);
                    }
                }
                if (it.position == it.entries.len) return null;
                it.position += 1;
                it.current = it.open(&it.entries[it.position - 1]);
            }
        }

        fn open(it: *const Iterator, entry: *const Entry) Container.Iterator {
            const low: u32 = if (entry.key == high_bits(it.start)) low_bits(it.start) else 0;
            const high: u32 = if (entry.key == high_bits(it.last))
                @as(u32, low_bits(it.last)) + 1
            else
                bitmap_container.BITS;
            return entry.value.iter_range(low, high);
        }
    };

    pub fn iter(self: *const Bitmap) Iterator {
        return self.iter_inclusive(0, std.math.maxInt(u64));
    }

    /// Values in `[start, end)`.
    pub fn iter_range(self: *const Bitmap, start: u64, end: u64) Iterator {
        if (start >= end) {
            const none = self.containers.items[0..0];
            return .{ .entries = none, .position = 0, .current = null, .start = 0, .last = 0 };
        }
        return self.iter_inclusive(start, end - 1);
    }

    fn iter_inclusive(self: *const Bitmap, start: u64, last: u64) Iterator {
        assert(start <= last);
        const items = self.containers.items;
        const first, _ = self.search(high_bits(start));
        const past, const found = self.search(high_bits(last));
        const entries = items[first .. past + @intFromBool(found)];
        return .{
            .entries = entries,
            .position = 0,
            .current = null,
            .start = start,
            .last = last,
        };
    }

    // Codec.

    pub fn write(self: Bitmap, writer: *codec.Writer) void {
        ContainerMap.init(self.containers.items).write(writer);
    }

    pub fn encode_size(self: Bitmap) usize {
        return ContainerMap.init(self.containers.items).encode_size();
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Bitmap {
        var map = try ContainerMap.read(gpa, reader, .{ .range = cfg });
        errdefer map.deinit(gpa);
        const entries = map.entries;
        if (entries.len > 0 and entries[entries.len - 1].key > MAX_KEY) {
            return reader.invalid("Bitmap", "container key exceeds 48-bit range");
        }
        for (entries) |entry| {
            if (entry.value.is_empty()) return reader.invalid("Bitmap", "empty container");
        }
        return .{ .containers = .fromOwnedSlice(@constCast(entries)) };
    }

    /// commonware's `Arbitrary`: up to 1000 containers at increasing keys, skipping empty
    /// ones.
    pub fn arbitrary(
        gpa: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Bitmap {
        const count = u.int_in_range(u32, 0, 1000);
        var result: Bitmap = .{};
        errdefer result.deinit(gpa);
        var previous: u64 = 0;
        for (0..count) |_| {
            const key = if (result.is_empty()) u.int_in_range(u64, 0, MAX_KEY) else key: {
                const remaining = MAX_KEY - previous;
                if (remaining == 0) break;
                break :key previous +| u.int_in_range(u64, 1, remaining);
            };
            if (key > MAX_KEY) break;
            var value = try Container.arbitrary(gpa, u);
            if (value.is_empty()) {
                value.deinit(gpa);
                continue;
            }
            errdefer value.deinit(gpa);
            try result.containers.append(gpa, .{ .key = key, .value = value });
            previous = key;
        }
        return result;
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("roaring/container_test.zig");
    _ = @import("roaring/roaring_test.zig");
    _ = @import("roaring/ops_test.zig");
    _ = @import("roaring/fuzz_test.zig");
}
