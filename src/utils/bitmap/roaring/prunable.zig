//! Container-aligned prunable wrapper around the roaring `Bitmap` (commonware
//! `utils/src/bitmap/roaring/prunable.rs`).
//!
//! `Prunable` adds a "pruned-below" watermark to a `Bitmap`. Values strictly below the
//! watermark never exist in the bitmap; querying or inserting one is a programming error
//! (an assertion; commonware panics).
//!
//! Pruning is container-aligned: thresholds round down to a multiple of 65536, so values
//! below the requested threshold may linger in the boundary container. `prune` returns the
//! threshold actually applied, which is also `pruned_below()`.
//!
//! Codec: `pruned_below` as a big-endian `u64`, then the `Bitmap`. Decoding rejects a
//! misaligned watermark and any container below it.

const std = @import("std");
const codec = @import("codec");
const roaring = @import("../roaring.zig");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Bitmap = roaring.Bitmap;

/// Number of values per container. Pruning aligns to multiples of this value.
pub const CONTAINER_SIZE: u64 = 1 << 16;
const CONTAINER_MASK: u64 = CONTAINER_SIZE - 1;

pub const Prunable = struct {
    /// Invariant: contains no values `< pruned_below_value`.
    bitmap: Bitmap = .empty,
    /// The lowest value that may exist in the bitmap. Always a multiple of 65536.
    pruned_below_value: u64 = 0,

    pub const Cfg = Bitmap.Cfg;
    pub const Iterator = Bitmap.Iterator;
    pub const empty: Prunable = .{};

    pub fn deinit(self: *Prunable, gpa: Allocator) void {
        self.bitmap.deinit(gpa);
        self.* = undefined;
    }

    pub fn clone(self: *const Prunable, gpa: Allocator) Allocator.Error!Prunable {
        return .{
            .bitmap = try self.bitmap.clone(gpa),
            .pruned_below_value = self.pruned_below_value,
        };
    }

    /// Builds a bitmap from `values` (commonware's `FromIterator`).
    pub fn from_values(gpa: Allocator, values: []const u64) Allocator.Error!Prunable {
        var result: Prunable = .empty;
        errdefer result.deinit(gpa);
        try result.extend(gpa, values);
        assert(result.pruned_below_value == 0);
        return result;
    }

    /// The cardinality. Unlike the dense `bitmap.Prunable`, pruning reduces it.
    pub fn len(self: *const Prunable) u64 {
        return self.bitmap.len();
    }

    pub fn is_empty(self: *const Prunable) bool {
        return self.bitmap.is_empty();
    }

    /// The pruning watermark: a multiple of 65536; no value below it exists.
    pub fn pruned_below(self: *const Prunable) u64 {
        assert(self.pruned_below_value & CONTAINER_MASK == 0);
        return self.pruned_below_value;
    }

    /// Inserts `value`; returns whether it was new. Asserts `value >= pruned_below()`.
    pub fn insert(self: *Prunable, gpa: Allocator, value: u64) Allocator.Error!bool {
        assert(value >= self.pruned_below_value);
        return self.bitmap.insert(gpa, value);
    }

    /// Inserts each value (commonware's `Extend`). Asserts each is `>= pruned_below()`.
    pub fn extend(self: *Prunable, gpa: Allocator, values: []const u64) Allocator.Error!void {
        for (values) |value| _ = try self.insert(gpa, value);
    }

    /// Inserts `[start, end)`; returns how many values were new. An empty range is a no-op
    /// anywhere; otherwise asserts `start >= pruned_below()`.
    pub fn insert_range(
        self: *Prunable,
        gpa: Allocator,
        start: u64,
        end: u64,
    ) Allocator.Error!u64 {
        if (start >= end) return 0;
        assert(start >= self.pruned_below_value);
        return self.bitmap.insert_range(gpa, start, end);
    }

    /// Asserts `value >= pruned_below()`.
    pub fn contains(self: *const Prunable, value: u64) bool {
        assert(value >= self.pruned_below_value);
        return self.bitmap.contains(value);
    }

    /// Drops every container wholly below `threshold` rounded down to a container boundary.
    /// Returns the watermark in effect afterwards; a lower threshold is a no-op.
    pub fn prune(self: *Prunable, gpa: Allocator, threshold: u64) u64 {
        const aligned = threshold & ~CONTAINER_MASK;
        if (aligned <= self.pruned_below_value) return self.pruned_below_value;
        self.bitmap.truncate_containers_below(gpa, aligned >> 16);
        self.pruned_below_value = aligned;
        if (self.bitmap.min()) |minimum| assert(minimum >= aligned);
        return aligned;
    }

    pub fn min(self: *const Prunable) ?u64 {
        return self.bitmap.min();
    }

    pub fn max(self: *const Prunable) ?u64 {
        return self.bitmap.max();
    }

    pub fn iter(self: *const Prunable) Iterator {
        return self.bitmap.iter();
    }

    /// Values in `[start, end)`. An empty range is empty anywhere; otherwise asserts
    /// `start >= pruned_below()`.
    pub fn iter_range(self: *const Prunable, start: u64, end: u64) Iterator {
        if (start >= end) return self.bitmap.iter_range(0, 0);
        assert(start >= self.pruned_below_value);
        return self.bitmap.iter_range(start, end);
    }

    /// Clears all values; keeps `pruned_below()`.
    pub fn clear(self: *Prunable, gpa: Allocator) void {
        self.bitmap.clear(gpa);
        assert(self.is_empty());
    }

    pub fn eql(a: *const Prunable, b: *const Prunable) bool {
        return a.pruned_below_value == b.pruned_below_value and a.bitmap.eql(&b.bitmap);
    }

    // Codec.

    pub fn write(self: Prunable, writer: *codec.Writer) void {
        writer.write_int(u64, self.pruned_below_value);
        self.bitmap.write(writer);
    }

    pub fn encode_size(self: Prunable) usize {
        return @sizeOf(u64) + self.bitmap.encode_size();
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Prunable {
        const watermark = try reader.read_int(u64);
        if (watermark & CONTAINER_MASK != 0) {
            return reader.invalid("Prunable", "pruned_below must be a multiple of 65536");
        }
        var bitmap = try Bitmap.read(gpa, reader, cfg);
        errdefer bitmap.deinit(gpa);
        const containers = bitmap.containers.items;
        if (containers.len > 0 and containers[0].key < watermark >> 16) {
            return reader.invalid("Prunable", "container key below pruned_below");
        }
        return .{ .bitmap = bitmap, .pruned_below_value = watermark };
    }

    /// commonware's `Arbitrary`: an arbitrary `Bitmap` pruned at an arbitrary threshold in
    /// `[0, max]`.
    pub fn arbitrary(
        gpa: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Prunable {
        var result: Prunable = .{ .bitmap = try Bitmap.arbitrary(gpa, u) };
        errdefer result.deinit(gpa);
        const threshold = u.int_in_range(u64, 0, result.max() orelse 0);
        _ = result.prune(gpa, threshold);
        return result;
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("prunable_test.zig");
}
