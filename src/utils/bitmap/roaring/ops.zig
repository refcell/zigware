//! Set operations for roaring bitmaps (commonware `utils/src/bitmap/roaring/ops.rs`): union,
//! intersection, and difference stop once a result limit is reached (pass
//! `std.math.maxInt(u64)` for no limit); `is_subset` and `intersects` short-circuit.
//! `roaring.Bitmap` re-exports these as methods.

const std = @import("std");
const roaring = @import("../roaring.zig");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Bitmap = roaring.Bitmap;
const Container = roaring.Container;

/// The union of `a` and `b`, holding at most `limit` values.
pub fn @"union"(
    a: *const Bitmap,
    b: *const Bitmap,
    gpa: Allocator,
    limit: u64,
) Allocator.Error!Bitmap {
    const a_entries = a.containers.items;
    const b_entries = b.containers.items;
    var result: Bitmap = .empty;
    errdefer result.deinit(gpa);
    var remaining = limit;
    var a_index: usize = 0;
    var b_index: usize = 0;
    // Each pass consumes at least one entry of `a` or `b`.
    while (remaining > 0 and (a_index < a_entries.len or b_index < b_entries.len)) {
        const a_key: ?u64 = if (a_index < a_entries.len) a_entries[a_index].key else null;
        const b_key: ?u64 = if (b_index < b_entries.len) b_entries[b_index].key else null;
        const take_a = b_key == null or (a_key != null and a_key.? <= b_key.?);
        const take_b = a_key == null or (b_key != null and b_key.? <= a_key.?);
        assert(take_a or take_b);
        const key = if (take_a) a_key.? else b_key.?;
        const combined = if (take_a and take_b) try Container.combine(
            &a_entries[a_index].value,
            &b_entries[b_index].value,
            gpa,
            remaining,
            .@"union",
        ) else if (take_a)
            try a_entries[a_index].value.limit(gpa, remaining)
        else
            try b_entries[b_index].value.limit(gpa, remaining);
        if (take_a) a_index += 1;
        if (take_b) b_index += 1;
        remaining -= try append(&result, gpa, key, combined);
    }
    assert(result.len() <= limit);
    return result;
}

/// The intersection of `a` and `b`, holding at most `limit` values.
pub fn intersection(
    a: *const Bitmap,
    b: *const Bitmap,
    gpa: Allocator,
    limit: u64,
) Allocator.Error!Bitmap {
    const a_smaller = a.containers.items.len <= b.containers.items.len;
    const smaller = if (a_smaller) a else b;
    const larger = if (a_smaller) b else a;
    var result: Bitmap = .empty;
    errdefer result.deinit(gpa);
    var remaining = limit;
    for (smaller.containers.items) |*entry| {
        if (remaining == 0) break;
        const other = larger.get(entry.key) orelse continue;
        const combined = try Container.combine(&entry.value, other, gpa, remaining, .intersection);
        remaining -= try append(&result, gpa, entry.key, combined);
    }
    assert(result.len() <= limit);
    return result;
}

/// The difference `a - b`, holding at most `limit` values.
pub fn difference(
    a: *const Bitmap,
    b: *const Bitmap,
    gpa: Allocator,
    limit: u64,
) Allocator.Error!Bitmap {
    var result: Bitmap = .empty;
    errdefer result.deinit(gpa);
    var remaining = limit;
    for (a.containers.items) |*entry| {
        if (remaining == 0) break;
        const combined = if (b.get(entry.key)) |other|
            try Container.combine(&entry.value, other, gpa, remaining, .difference)
        else
            try entry.value.limit(gpa, remaining);
        remaining -= try append(&result, gpa, entry.key, combined);
    }
    assert(result.len() <= limit);
    return result;
}

/// Appends a non-empty `combined` at `key` (above every key in `result`); frees an empty
/// one. Returns its count.
fn append(
    result: *Bitmap,
    gpa: Allocator,
    key: u64,
    combined: Container.Result,
) Allocator.Error!u64 {
    var value = combined.container;
    assert(value.len() == combined.count);
    if (combined.count == 0) {
        value.deinit(gpa);
        return 0;
    }
    const items = result.containers.items;
    assert(items.len == 0 or items[items.len - 1].key < key);
    errdefer value.deinit(gpa);
    try result.containers.append(gpa, .{ .key = key, .value = value });
    return combined.count;
}

/// Whether every value of `a` is in `b`.
pub fn is_subset(a: *const Bitmap, b: *const Bitmap) bool {
    if (a.len() > b.len()) return false;
    for (a.containers.items) |*entry| {
        const other = b.get(entry.key) orelse return false;
        if (!entry.value.is_subset(other)) return false;
    }
    return true;
}

/// Whether `a` and `b` share a value.
pub fn intersects(a: *const Bitmap, b: *const Bitmap) bool {
    const a_smaller = a.containers.items.len <= b.containers.items.len;
    const smaller = if (a_smaller) a else b;
    const larger = if (a_smaller) b else a;
    for (smaller.containers.items) |*entry| {
        const other = larger.get(entry.key) orelse continue;
        if (entry.value.intersects(other)) return true;
    }
    return false;
}
