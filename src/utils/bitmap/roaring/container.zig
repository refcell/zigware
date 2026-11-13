//! A roaring container (commonware `bitmap/roaring/container/mod.rs`): the values of one
//! 65,536-value chunk as an `Array`, a `Bitmap`, or a `Run`.
//!
//! Containers convert after every insert: Array -> Bitmap past 4096 values, Bitmap -> Run
//! below 1500 runs, Run -> Bitmap above 2500 runs (a hysteresis band around the ~2048-run
//! break-even), and a Bitmap with at most 4096 values back to an Array.
//!
//! Encoding: a type byte (0 Array, 1 Bitmap, 2 Run) and that container's encoding, always in
//! the canonical kind: the smallest encoding, ties broken Array > Run > Bitmap. Decoding
//! rejects a kind that is not canonical for its payload.

const std = @import("std");
const codec = @import("codec");
const array_container = @import("array.zig");
const bitmap_container = @import("bitmap.zig");
const run_container = @import("run.zig");
const Array = array_container.Array;
const Bitmap = bitmap_container.Bitmap;
const Run = run_container.Run;
const Span = run_container.Span;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const BITMAP_TO_RUN_THRESHOLD: usize = 1500;
pub const RUN_TO_BITMAP_THRESHOLD: usize = 2500;
const BITMAP_ENCODED_BYTES = bitmap_container.ENCODED_BYTES;
const TYPE_ARRAY: u8 = 0;
const TYPE_BITMAP: u8 = 1;
const TYPE_RUN: u8 = 2;
const not_canonical = "container type is not canonical for payload";

pub const Kind = enum { array, bitmap, run };

pub const Container = union(Kind) {
    array: Array,
    /// Heap-allocated: 8 KB.
    bitmap: *Bitmap,
    run: Run,

    pub const empty: Container = .{ .array = .empty };
    pub const max_encode_size: usize = 1 + BITMAP_ENCODED_BYTES;

    /// A container and how many values it holds (Rust's `(Self, u64)`).
    pub const Result = struct { container: Container, count: u64 };

    pub fn deinit(self: *Container, gpa: Allocator) void {
        switch (self.*) {
            .array => |*array| array.deinit(gpa),
            .bitmap => |bitmap| gpa.destroy(bitmap),
            .run => |*run| run.deinit(gpa),
        }
        self.* = undefined;
    }

    pub fn clone(self: *const Container, gpa: Allocator) Allocator.Error!Container {
        return switch (self.*) {
            .array => |*array| .{ .array = try array.clone(gpa) },
            .bitmap => |bitmap| .{ .bitmap = try create_bitmap(gpa, bitmap.*) },
            .run => |*run| .{ .run = try run.clone(gpa) },
        };
    }

    fn create_bitmap(gpa: Allocator, value: Bitmap) Allocator.Error!*Bitmap {
        const bitmap = try gpa.create(Bitmap);
        bitmap.* = value;
        return bitmap;
    }

    pub fn len(self: *const Container) u32 {
        return switch (self.*) {
            .array => |*array| @intCast(array.len()),
            .bitmap => |bitmap| bitmap.len(),
            .run => |*run| run.len(),
        };
    }

    pub fn is_empty(self: *const Container) bool {
        return switch (self.*) {
            .array => |*array| array.is_empty(),
            .bitmap => |bitmap| bitmap.is_empty(),
            .run => |*run| run.is_empty(),
        };
    }

    pub fn contains(self: *const Container, value: u16) bool {
        return switch (self.*) {
            .array => |*array| array.contains(value),
            .bitmap => |bitmap| bitmap.contains(value),
            .run => |*run| run.contains(value),
        };
    }

    pub fn min(self: *const Container) ?u16 {
        return switch (self.*) {
            .array => |*array| array.min(),
            .bitmap => |bitmap| bitmap.min(),
            .run => |*run| run.min(),
        };
    }

    pub fn max(self: *const Container) ?u16 {
        return switch (self.*) {
            .array => |*array| array.max(),
            .bitmap => |bitmap| bitmap.max(),
            .run => |*run| run.max(),
        };
    }

    pub fn run_count(self: *const Container) usize {
        return switch (self.*) {
            .array => |*array| array.run_count(),
            .bitmap => |bitmap| bitmap.run_count(),
            .run => |*run| run.run_count(),
        };
    }

    /// Returns whether `value` was new, then converts the container if needed.
    pub fn insert(self: *Container, gpa: Allocator, value: u16) Allocator.Error!bool {
        const inserted = switch (self.*) {
            .array => |*array| try array.insert(gpa, value),
            .bitmap => |bitmap| bitmap.insert(value),
            .run => |*run| try run.insert(gpa, value),
        };
        try self.normalize(gpa);
        assert(self.contains(value));
        return inserted;
    }

    /// Inserts `[start, end)`; returns how many values were new.
    pub fn insert_range(
        self: *Container,
        gpa: Allocator,
        start: u16,
        end: u16,
    ) Allocator.Error!u32 {
        if (start >= end) return 0;
        const inserted: u32 = switch (self.*) {
            .array => |*array| inserted: {
                const range_len: usize = end - start;
                // A long range into an empty array is one run: store it as one.
                if (array.is_empty() and range_len >= 64) {
                    var run: Run = .empty;
                    errdefer run.deinit(gpa);
                    const count = try run.insert_range(gpa, start, end);
                    array.deinit(gpa);
                    self.* = .{ .run = run };
                    return count;
                }
                const added = range_len - array.count_in_range(start, end);
                if (array.len() + added > array_container.MAX_CARDINALITY) {
                    try self.convert(gpa, .bitmap);
                    break :inserted self.bitmap.insert_range(start, end);
                }
                break :inserted @intCast(try array.insert_range(gpa, start, end));
            },
            .bitmap => |bitmap| bitmap.insert_range(start, end),
            .run => |*run| try run.insert_range(gpa, start, end),
        };
        try self.normalize(gpa);
        return inserted;
    }

    /// Converts in place after a mutation (Rust `normalize_in_memory`). On allocation failure
    /// the container keeps its values in its current kind.
    fn normalize(self: *Container, gpa: Allocator) Allocator.Error!void {
        if (self.is_empty()) {
            if (self.* != .array) {
                self.deinit(gpa);
                self.* = .empty;
            }
            return;
        }
        // Each pass converts toward a stable kind: at most three passes.
        for (0..3) |_| {
            switch (self.*) {
                .array => |*array| {
                    if (array.len() <= array_container.MAX_CARDINALITY) return;
                    try self.convert(gpa, .bitmap);
                },
                .bitmap => |bitmap| {
                    if (bitmap.len() <= array_container.MAX_CARDINALITY) {
                        return self.convert(gpa, .array);
                    }
                    if (bitmap.run_count() >= BITMAP_TO_RUN_THRESHOLD) return;
                    try self.convert(gpa, .run);
                },
                .run => |*run| {
                    if (run.run_count() <= RUN_TO_BITMAP_THRESHOLD) return;
                    try self.convert(gpa, .bitmap);
                },
            }
        }
        unreachable; // Proof: Array -> Bitmap -> Run, or Run -> Bitmap -> Array/stop.
    }

    /// Replaces the container with the same values as `kind`.
    fn convert(self: *Container, gpa: Allocator, kind: Kind) Allocator.Error!void {
        const converted: Container = switch (kind) {
            .array => .{ .array = try self.to_array(gpa) },
            .bitmap => .{ .bitmap = try create_bitmap(gpa, self.to_bitmap()) },
            .run => .{ .run = switch (self.*) {
                .array => |*array| try Run.from_array(gpa, array),
                .bitmap => |bitmap| try Run.from_bitmap(gpa, bitmap),
                .run => |*run| try run.clone(gpa),
            } },
        };
        assert(converted.len() == self.len());
        self.deinit(gpa);
        self.* = converted;
    }

    fn to_array(self: *const Container, gpa: Allocator) Allocator.Error!Array {
        const values = try gpa.alloc(u16, self.len());
        var it = self.iter();
        for (values) |*value| value.* = it.next().?;
        assert(it.next() == null);
        return Array.from_owned(values);
    }

    fn to_bitmap(self: *const Container) Bitmap {
        return switch (self.*) {
            .array => |*array| Bitmap.from_array(array),
            .bitmap => |bitmap| bitmap.*,
            .run => |*run| Bitmap.from_runs(run.spans()),
        };
    }

    // Iteration.

    pub const Iterator = union(Kind) {
        array: struct { values: []const u16, position: usize },
        bitmap: Bitmap.Iterator,
        run: Run.Iterator,

        pub fn next(it: *Iterator) ?u16 {
            switch (it.*) {
                .array => |*array| {
                    if (array.position == array.values.len) return null;
                    array.position += 1;
                    return array.values[array.position - 1];
                },
                .bitmap => |*bitmap| return bitmap.next(),
                .run => |*run| return run.next(),
            }
        }

        /// Values left (Rust `size_hint`).
        pub fn remaining(it: *const Iterator) usize {
            return switch (it.*) {
                .array => |array| array.values.len - array.position,
                .bitmap => |*bitmap| bitmap.remaining(),
                .run => |*run| run.remaining(),
            };
        }
    };

    pub fn iter(self: *const Container) Iterator {
        return self.iter_range(0, bitmap_container.BITS);
    }

    /// Values in `[start, end)`, both clamped to 65536.
    pub fn iter_range(self: *const Container, start: u32, end: u32) Iterator {
        const low = @min(start, bitmap_container.BITS);
        const high = @min(end, bitmap_container.BITS);
        return switch (self.*) {
            .array => |*array| array: {
                const values = array.as_slice();
                const first = lower_bound_u32(values, low);
                const past = @max(lower_bound_u32(values, high), first);
                break :array .{ .array = .{ .values = values[first..past], .position = 0 } };
            },
            .bitmap => |bitmap| .{ .bitmap = bitmap.iter_range(low, high) },
            .run => |*run| .{ .run = run.iter_range(low, high) },
        };
    }

    fn lower_bound_u32(values: []const u16, bound: u32) usize {
        if (bound > std.math.maxInt(u16)) return values.len;
        return array_container.lower_bound(values, @intCast(bound));
    }

    pub fn eql(a: *const Container, b: *const Container) bool {
        if (a.len() != b.len()) return false;
        var left = a.iter();
        var right = b.iter();
        // Both hold `len` values: `len` passes.
        while (left.next()) |value| if (right.next().? != value) return false;
        return true;
    }

    // Set operations.

    /// The first `limit` values (Rust `limit`).
    pub fn limit(self: *const Container, gpa: Allocator, count_max: u64) Allocator.Error!Result {
        const count = self.len();
        if (count <= count_max) return .{ .container = try self.clone(gpa), .count = count };
        var result: Container = .empty;
        errdefer result.deinit(gpa);
        var it = self.iter();
        var taken: u64 = 0;
        while (taken < count_max) : (taken += 1) _ = try result.insert(gpa, it.next().?);
        return .{ .container = result, .count = taken };
    }

    pub const Operation = enum { @"union", intersection, difference };

    /// The union, intersection, or difference, holding at most `count_max` values.
    pub fn combine(
        a: *const Container,
        b: *const Container,
        gpa: Allocator,
        count_max: u64,
        comptime operation: Operation,
    ) Allocator.Error!Result {
        if (a.* == .array and b.* == .array) {
            const capped: usize = std.math.cast(usize, count_max) orelse std.math.maxInt(usize);
            const merged = switch (operation) {
                .@"union" => try a.array.@"union"(gpa, &b.array, capped),
                .intersection => try a.array.intersection(gpa, &b.array, capped),
                .difference => try a.array.difference(gpa, &b.array, capped),
            };
            var result: Container = .{ .array = merged.array };
            errdefer result.deinit(gpa);
            if (operation == .@"union") try result.normalize(gpa);
            return .{ .container = result, .count = merged.count };
        }
        if (a.* == .bitmap and b.* == .bitmap) {
            const words = Bitmap.combine(a.bitmap, b.bitmap, switch (operation) {
                .@"union" => .@"or",
                .intersection => .@"and",
                .difference => .and_not,
            });
            var result: Container = .{ .bitmap = try create_bitmap(gpa, words) };
            if (words.len() > count_max) {
                defer result.deinit(gpa);
                return result.limit(gpa, count_max);
            }
            errdefer result.deinit(gpa);
            try result.normalize(gpa);
            return .{ .container = result, .count = words.len() };
        }
        return switch (operation) {
            .@"union" => mixed_union(a, b, gpa, count_max),
            .intersection => if (a.len() <= b.len())
                filter(a, b, gpa, count_max, true)
            else
                filter(b, a, gpa, count_max, true),
            .difference => filter(a, b, gpa, count_max, false),
        };
    }

    fn mixed_union(
        a: *const Container,
        b: *const Container,
        gpa: Allocator,
        count_max: u64,
    ) Allocator.Error!Result {
        var result: Container = .empty;
        errdefer result.deinit(gpa);
        var left = a.iter();
        var right = b.iter();
        var next_left = left.next();
        var next_right = right.next();
        var taken: u64 = 0;
        while (taken < count_max) : (taken += 1) {
            const l: u32 = if (next_left) |value| value else 65536;
            const r: u32 = if (next_right) |value| value else 65536;
            const value = @min(l, r);
            if (value == 65536) break;
            _ = try result.insert(gpa, @intCast(value));
            if (l == value) next_left = left.next();
            if (r == value) next_right = right.next();
        }
        return .{ .container = result, .count = taken };
    }

    /// Values of `source` that `other` contains (`keep_contained`) or lacks.
    fn filter(
        source: *const Container,
        other: *const Container,
        gpa: Allocator,
        count_max: u64,
        keep_contained: bool,
    ) Allocator.Error!Result {
        var result: Container = .empty;
        errdefer result.deinit(gpa);
        var it = source.iter();
        var taken: u64 = 0;
        while (taken < count_max) {
            const value = it.next() orelse break;
            if (other.contains(value) != keep_contained) continue;
            _ = try result.insert(gpa, value);
            taken += 1;
        }
        return .{ .container = result, .count = taken };
    }

    pub fn is_subset(self: *const Container, other: *const Container) bool {
        if (self.len() > other.len()) return false;
        switch (self.*) {
            .array => |*a| if (other.* == .array) return a.is_subset(&other.array),
            .bitmap => |a| if (other.* == .bitmap) return a.is_subset(other.bitmap),
            .run => |*a| if (other.* == .run) return a.is_subset(&other.run),
        }
        var it = self.iter();
        while (it.next()) |value| if (!other.contains(value)) return false;
        return true;
    }

    pub fn intersects(self: *const Container, other: *const Container) bool {
        switch (self.*) {
            .array => |*a| if (other.* == .array) return a.intersects(&other.array),
            .bitmap => |a| if (other.* == .bitmap) return a.intersects(other.bitmap),
            .run => |*a| if (other.* == .run) return a.intersects(&other.run),
        }
        const smaller, const larger = if (self.len() <= other.len())
            .{ self, other }
        else
            .{ other, self };
        var it = smaller.iter();
        while (it.next()) |value| if (larger.contains(value)) return true;
        return false;
    }

    // Codec.

    fn array_size(count: usize) usize {
        return codec.encode_size(usize, count) + 2 * count;
    }

    fn run_size(count: usize) usize {
        return codec.encode_size(usize, count) + 4 * count;
    }

    /// The smallest encoding, ties broken Array > Run > Bitmap.
    pub fn canonical_kind(self: *const Container) Kind {
        if (self.is_empty()) return .array;
        const cardinality: usize = self.len();
        var best: Kind = .run;
        var best_size = run_size(self.run_count());
        const fits_array = cardinality <= array_container.MAX_CARDINALITY;
        if (fits_array and array_size(cardinality) <= best_size) {
            best = .array;
            best_size = array_size(cardinality);
        }
        if (BITMAP_ENCODED_BYTES < best_size) best = .bitmap;
        return best;
    }

    pub fn write(self: Container, writer: *codec.Writer) void {
        switch (self.canonical_kind()) {
            .array => {
                writer.write_int(u8, TYPE_ARRAY);
                codec.write(usize, self.len(), writer);
                var it = self.iter();
                while (it.next()) |value| writer.write_int(u16, value);
            },
            .bitmap => {
                writer.write_int(u8, TYPE_BITMAP);
                self.to_bitmap().write(writer);
            },
            .run => {
                writer.write_int(u8, TYPE_RUN);
                write_runs(&self, writer);
            },
        }
    }

    /// The container's maximal runs in the `Run` encoding, without converting it.
    fn write_runs(self: *const Container, writer: *codec.Writer) void {
        if (self.* == .run) return self.run.write(writer);
        codec.write(usize, self.run_count(), writer);
        var it = self.iter();
        var span: ?Span = null;
        while (it.next()) |value| {
            if (span) |*open| {
                if (@as(u32, open[1]) + 1 == value) {
                    open[1] = value;
                    continue;
                }
                writer.write_int(u16, open[0]);
                writer.write_int(u16, open[1]);
            }
            span = .{ value, value };
        }
        if (span) |last| {
            writer.write_int(u16, last[0]);
            writer.write_int(u16, last[1]);
        }
    }

    pub fn encode_size(self: Container) usize {
        return 1 + switch (self.canonical_kind()) {
            .array => array_size(self.len()),
            .bitmap => BITMAP_ENCODED_BYTES,
            .run => run_size(self.run_count()),
        };
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Container {
        const kind = try reader.read_int(u8);
        var result: Container = switch (kind) {
            TYPE_ARRAY => .{ .array = try Array.read(gpa, reader, {}) },
            TYPE_BITMAP => .{ .bitmap = try create_bitmap(gpa, try Bitmap.read(gpa, reader, {})) },
            TYPE_RUN => run: {
                // Peek the run count: a run payload above the bitmap size is never canonical.
                var peek = reader.*;
                const count = try codec.read_usize(&peek, .to_inclusive(run_container.MAX_RUNS));
                if (run_size(count) > BITMAP_ENCODED_BYTES) {
                    reader.* = peek;
                    return reader.invalid("Container", not_canonical);
                }
                break :run .{ .run = try Run.read(gpa, reader, {}) };
            },
            else => return reader.fail(error.InvalidEnum, kind),
        };
        errdefer result.deinit(gpa);
        const expected: u8 = switch (result.canonical_kind()) {
            .array => TYPE_ARRAY,
            .bitmap => TYPE_BITMAP,
            .run => TYPE_RUN,
        };
        if (kind != expected) {
            return reader.invalid("Container", not_canonical);
        }
        return result;
    }

    /// commonware's `Arbitrary`: a kind in `0..=2`, then that container's `Arbitrary`.
    pub fn arbitrary(
        gpa: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Container {
        return switch (u.int_in_range(u32, 0, 2)) {
            0 => .{ .array = try Array.arbitrary(gpa, u) },
            1 => .{ .bitmap = try create_bitmap(gpa, try Bitmap.arbitrary(gpa, u)) },
            else => .{ .run = try Run.arbitrary(gpa, u) },
        };
    }
};
