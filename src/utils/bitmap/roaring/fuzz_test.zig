//! Property fuzz for roaring bitmaps (commonware `utils/src/bitmap/roaring/fuzz.rs` `Plan`,
//! run by `utils/fuzz/fuzz_targets/roaring.rs`). Each iteration draws one plan and its
//! inputs from the fuzz bytes and checks the plan's invariants. Set operations are checked
//! against sorted reference lists.

const std = @import("std");
const codec = @import("codec");
const fuzz = @import("../../fuzz.zig");
const rng = @import("../../rng.zig");
const roaring = @import("../roaring.zig");
const Bitmap = roaring.Bitmap;
const Prunable = roaring.Prunable;
const Allocator = std.mem.Allocator;

const testing = std.testing;
const gpa = testing.allocator;

const MAX_CONTAINERS: usize = 100;
/// Values stay within `MAX_CONTAINERS` containers.
const MAX_VALUE: u64 = MAX_CONTAINERS << 16;
/// Random values per drawn set (commonware caps at 10000).
const values_max: usize = 512;

const Plan = enum {
    insert,
    insert_range,
    contains,
    codec,
    codec_range,
    @"union",
    intersection,
    difference,
    iterator,
    iter_range,
    min_max,
    multiple_ranges,
    mixed_operations,
    concentrated_shelf,
    prunable_ops,
};

fn bounded(generator: *rng.FuzzRng) u64 {
    return generator.next_u64() % MAX_VALUE;
}

/// A value domain: narrow domains make independently drawn sets overlap.
fn draw_domain(generator: *rng.FuzzRng) u64 {
    return switch (rng.range_less_than(generator, u8, 0, 3)) {
        0 => 1 << 10,
        1 => 1 << 17,
        else => MAX_VALUE,
    };
}

/// Up to `values_max` values in `[0, domain)`, plus, two times in three, a contiguous or
/// strided block of up to 6000 values, which forms run and bitmap containers.
fn draw_set(generator: *rng.FuzzRng, domain: u64) ![]u64 {
    std.debug.assert(domain > 0 and domain <= MAX_VALUE);
    var values: std.ArrayList(u64) = .empty;
    errdefer values.deinit(gpa);
    const count = rng.range_at_most(generator, usize, 0, values_max);
    for (0..count) |_| try values.append(gpa, generator.next_u64() % domain);
    const shape = rng.range_less_than(generator, u8, 0, 3);
    if (shape > 0) {
        const step: u64 = if (shape == 1) 1 else rng.range_at_most(generator, u64, 2, 3);
        const start = generator.next_u64() % domain;
        const block = rng.range_at_most(generator, u64, 0, 6000);
        var index: u64 = 0;
        while (index < block and start + index * step < MAX_VALUE) : (index += 1) {
            try values.append(gpa, start + index * step);
        }
    }
    return values.toOwnedSlice(gpa);
}

fn draw_values(generator: *rng.FuzzRng) ![]u64 {
    return draw_set(generator, draw_domain(generator));
}

/// A drawn limit: unlimited a third of the time, else small.
fn draw_limit(generator: *rng.FuzzRng) u64 {
    if (rng.ratio(generator, 1, 3)) return std.math.maxInt(u64);
    return rng.range_at_most(generator, u64, 0, 2 * values_max);
}

/// `[start, start + len)` clipped to `MAX_VALUE`.
fn draw_range(generator: *rng.FuzzRng) struct { u64, u64 } {
    const start = bounded(generator);
    const len: u64 = rng.range_at_most(generator, u16, 0, std.math.maxInt(u16));
    return .{ start, @min(start + len, MAX_VALUE) };
}

fn build(values: []const u64) !Bitmap {
    var result: Bitmap = .empty;
    errdefer result.deinit(gpa);
    for (values) |value| _ = try result.insert(gpa, value);
    return result;
}

/// `values` sorted and deduplicated, in a new allocation.
fn sorted_unique(values: []const u64) ![]u64 {
    const copy = try gpa.dupe(u64, values);
    std.mem.sort(u64, copy, {}, std.sort.asc(u64));
    var len: usize = 0;
    for (copy) |value| {
        if (len > 0 and copy[len - 1] == value) continue;
        copy[len] = value;
        len += 1;
    }
    return gpa.realloc(copy, len);
}

fn expect_roundtrip(comptime T: type, value: *const T) !void {
    const encoded = try codec.encode(T, gpa, value.*);
    defer gpa.free(encoded);
    try testing.expectEqual(value.encode_size(), encoded.len);
    var decoded = try codec.decode_cfg(T, gpa, encoded, .to_inclusive(MAX_CONTAINERS));
    defer decoded.deinit(gpa);
    try testing.expect(value.eql(&decoded));
    try testing.expectEqual(value.len(), decoded.len());
    const reencoded = try codec.encode(T, gpa, decoded);
    defer gpa.free(reencoded);
    try testing.expectEqualSlices(u8, encoded, reencoded);
}

/// `iterator` yields exactly `expected`.
fn expect_values(iterator: Bitmap.Iterator, expected: []const u64) !void {
    var it = iterator;
    for (expected) |value| try testing.expectEqual(@as(?u64, value), it.next());
    try testing.expectEqual(@as(?u64, null), it.next());
}

fn fuzz_roaring(_: void, generator: *rng.FuzzRng) !void {
    const plans = comptime std.enums.values(Plan);
    switch (plans[rng.range_less_than(generator, usize, 0, plans.len)]) {
        .insert => try plan_insert(generator),
        .insert_range, .codec_range => try plan_insert_range(generator),
        .contains => try plan_contains(generator),
        .codec, .iterator, .min_max => try plan_values(generator),
        .@"union" => try plan_combine(generator, .@"union"),
        .intersection => try plan_combine(generator, .intersection),
        .difference => try plan_combine(generator, .difference),
        .iter_range => try plan_iter_range(generator),
        .multiple_ranges, .mixed_operations => try plan_mixed(generator),
        .concentrated_shelf => try plan_concentrated_shelf(generator),
        .prunable_ops => try plan_prunable(generator),
    }
}

fn plan_insert(generator: *rng.FuzzRng) !void {
    const values = try draw_values(generator);
    defer gpa.free(values);
    var bitmap: Bitmap = .empty;
    defer bitmap.deinit(gpa);
    var expected_len: u64 = 0;
    for (values) |value| {
        if (try bitmap.insert(gpa, value)) expected_len += 1;
        try testing.expect(bitmap.contains(value));
    }
    try testing.expectEqual(expected_len, bitmap.len());
}

/// InsertRange and CodecRange.
fn plan_insert_range(generator: *rng.FuzzRng) !void {
    const start, const end = draw_range(generator);
    var bitmap: Bitmap = .empty;
    defer bitmap.deinit(gpa);
    try testing.expectEqual(end - start, try bitmap.insert_range(gpa, start, end));
    try testing.expectEqual(end - start, bitmap.len());
    var it = bitmap.iter();
    for (start..end) |value| try testing.expectEqual(@as(?u64, value), it.next());
    try testing.expectEqual(@as(?u64, null), it.next());
    if (start > 0) try testing.expect(!bitmap.contains(start - 1));
    try testing.expect(!bitmap.contains(end));
    try expect_roundtrip(Bitmap, &bitmap);
}

fn plan_contains(generator: *rng.FuzzRng) !void {
    const values = try draw_values(generator);
    defer gpa.free(values);
    var bitmap = try build(values);
    defer bitmap.deinit(gpa);
    // Half the queries hit a drawn value.
    const query = if (values.len > 0 and rng.boolean(generator))
        values[rng.range_less_than(generator, usize, 0, values.len)]
    else
        bounded(generator);
    const expected = std.mem.indexOfScalar(u64, values, query) != null;
    try testing.expectEqual(expected, bitmap.contains(query));
}

/// Codec, Iterator, and MinMax.
fn plan_values(generator: *rng.FuzzRng) !void {
    const values = try draw_values(generator);
    defer gpa.free(values);
    var bitmap = try build(values);
    defer bitmap.deinit(gpa);
    const expected = try sorted_unique(values);
    defer gpa.free(expected);
    try testing.expectEqual(expected.len, bitmap.len());
    try expect_values(bitmap.iter(), expected);
    for (expected) |value| try testing.expect(bitmap.contains(value));
    if (expected.len == 0) {
        try testing.expect(bitmap.is_empty());
        try testing.expectEqual(@as(?u64, null), bitmap.min());
        try testing.expectEqual(@as(?u64, null), bitmap.max());
    } else {
        try testing.expectEqual(@as(?u64, expected[0]), bitmap.min());
        try testing.expectEqual(@as(?u64, expected[expected.len - 1]), bitmap.max());
    }
    try expect_roundtrip(Bitmap, &bitmap);
}

const Operation = enum { @"union", intersection, difference };

fn plan_combine(generator: *rng.FuzzRng, comptime operation: Operation) !void {
    const domain = draw_domain(generator);
    const values_a = try draw_set(generator, domain);
    defer gpa.free(values_a);
    const values_b = try draw_set(generator, domain);
    defer gpa.free(values_b);
    const limit = draw_limit(generator);
    var a = try build(values_a);
    defer a.deinit(gpa);
    var b = try build(values_b);
    defer b.deinit(gpa);
    var result = switch (operation) {
        .@"union" => try a.@"union"(&b, gpa, limit),
        .intersection => try a.intersection(&b, gpa, limit),
        .difference => try a.difference(&b, gpa, limit),
    };
    defer result.deinit(gpa);

    const expected = try reference(values_a, values_b, operation);
    defer gpa.free(expected);
    const count: usize = @intCast(@min(limit, expected.len));
    try expect_values(result.iter(), expected[0..count]);
    try testing.expectEqual(count, result.len());
    try testing.expectEqual(count == 0, result.is_empty());
    try expect_roundtrip(Bitmap, &result);
}

/// The full (unlimited) result of `operation`, sorted.
fn reference(values_a: []const u64, values_b: []const u64, operation: Operation) ![]u64 {
    const a = try sorted_unique(values_a);
    defer gpa.free(a);
    const b = try sorted_unique(values_b);
    defer gpa.free(b);
    var result: std.ArrayList(u64) = .empty;
    errdefer result.deinit(gpa);
    var a_index: usize = 0;
    var b_index: usize = 0;
    // Each pass consumes at least one value of `a` or `b`.
    while (a_index < a.len or b_index < b.len) {
        const take_a = b_index == b.len or (a_index < a.len and a[a_index] <= b[b_index]);
        const take_b = a_index == a.len or (b_index < b.len and b[b_index] <= a[a_index]);
        const value = if (take_a) a[a_index] else b[b_index];
        const keep = switch (operation) {
            .@"union" => true,
            .intersection => take_a and take_b,
            .difference => take_a and !take_b,
        };
        if (keep) try result.append(gpa, value);
        if (take_a) a_index += 1;
        if (take_b) b_index += 1;
    }
    return result.toOwnedSlice(gpa);
}

fn plan_iter_range(generator: *rng.FuzzRng) !void {
    const values = try draw_values(generator);
    defer gpa.free(values);
    const start = bounded(generator);
    const end = bounded(generator);
    var bitmap = try build(values);
    defer bitmap.deinit(gpa);
    const sorted = try sorted_unique(values);
    defer gpa.free(sorted);
    var first: usize = 0;
    while (first < sorted.len and sorted[first] < start) first += 1;
    var last = first;
    while (last < sorted.len and sorted[last] < end) last += 1;
    try expect_values(bitmap.iter_range(start, end), sorted[first..last]);
}

/// MultipleRanges and MixedOperations: interleaved inserts, range inserts, and queries.
fn plan_mixed(generator: *rng.FuzzRng) !void {
    var bitmap: Bitmap = .empty;
    defer bitmap.deinit(gpa);
    const operations = rng.range_at_most(generator, u32, 0, 100);
    for (0..operations) |_| {
        switch (rng.range_less_than(generator, u8, 0, 3)) {
            0 => {
                const value = bounded(generator);
                _ = try bitmap.insert(gpa, value);
                try testing.expect(bitmap.contains(value));
            },
            1 => {
                const start, const end = draw_range(generator);
                const before = bitmap.len();
                const inserted = try bitmap.insert_range(gpa, start, end);
                try testing.expectEqual(before + inserted, bitmap.len());
                if (start < end) try testing.expect(bitmap.contains(end - 1));
            },
            else => _ = bitmap.contains(bounded(generator)),
        }
    }
    try expect_roundtrip(Bitmap, &bitmap);
}

/// Many inserts in one 16-bit shelf, crossing the Array/Bitmap/Run conversions.
fn plan_concentrated_shelf(generator: *rng.FuzzRng) !void {
    const base: u64 = @as(u64, rng.range_less_than(generator, u8, 0, MAX_CONTAINERS)) << 16;
    var bitmap: Bitmap = .empty;
    defer bitmap.deinit(gpa);
    var truth = try std.DynamicBitSetUnmanaged.initEmpty(gpa, 1 << 16);
    defer truth.deinit(gpa);
    const operations = rng.range_at_most(generator, u32, 0, 500);
    for (0..operations) |_| {
        const start: u64 = generator.next_u32() & 0xFFFF;
        const end = if (rng.boolean(generator))
            start + 1
        else
            @min(start + (generator.next_u32() & 0xFFFF), 1 << 16);
        _ = try bitmap.insert_range(gpa, base + start, base + end);
        if (start < end) truth.setRangeValue(.{ .start = start, .end = end }, true);
    }
    try testing.expectEqual(truth.count(), bitmap.len());
    var it = bitmap.iter();
    var expected = truth.iterator(.{});
    while (expected.next()) |index| try testing.expectEqual(@as(?u64, base + index), it.next());
    try testing.expectEqual(@as(?u64, null), it.next());
    try expect_roundtrip(Bitmap, &bitmap);
}

fn plan_prunable(generator: *rng.FuzzRng) !void {
    var p: Prunable = .empty;
    defer p.deinit(gpa);
    const operations = rng.range_at_most(generator, u32, 0, 100);
    for (0..operations) |_| {
        switch (rng.range_less_than(generator, u8, 0, 3)) {
            0 => {
                const value = bounded(generator);
                if (value >= p.pruned_below()) _ = try p.insert(gpa, value);
            },
            1 => {
                const start, const end = draw_range(generator);
                if (start >= p.pruned_below()) _ = try p.insert_range(gpa, start, end);
            },
            else => {
                const before = p.pruned_below();
                const after = p.prune(gpa, bounded(generator));
                try testing.expect(after >= before);
                try testing.expectEqual(after, p.pruned_below());
            },
        }
        try testing.expectEqual(0, p.pruned_below() % (1 << 16));
        if (p.min()) |minimum| try testing.expect(minimum >= p.pruned_below());
    }
    try expect_roundtrip(Prunable, &p);
}

test "fuzz roaring" {
    try fuzz.run({}, fuzz_roaring, 0x726f_6172, 300);
}
