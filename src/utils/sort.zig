//! Unstable sorting: a port of Rust's `slice::sort_unstable_by` (ipnsort,
//! rust-lang/rust `library/core/src/slice/sort`), which commonware's `sort_unstable` runs.
//!
//! Up to 20 items take an insertion sort. Longer slices first look for one existing run, then
//! run an introsort quicksort: a recursive pseudo-median pivot, a branchless cyclic Lomuto
//! partition (a branchy cyclic Hoare one above 96-byte items), a small-sort at 32 items or
//! fewer (sorting networks for word-sized items, a stable merge into stack scratch up to
//! 85-byte items, insertion sort beyond), and heapsort once the depth limit runs out. Rust's
//! recursion becomes bounded explicit stacks. Partitioning moves each item once through a gap
//! instead of swapping pairs (three moves), most of the gain over `std.sort.pdq` on wide items.

const std = @import("std");
const assert = std.debug.assert;

/// Sorts `items` by `less_than`, not keeping the order of equal items. Same signature as
/// `std.sort.pdq`; `less_than` must be a strict weak order.
pub fn unstable(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime less_than: fn (@TypeOf(context), T, T) bool,
) void {
    Sorter(T, @TypeOf(context), less_than).sort(items, context);
}

/// The heapsort `unstable` falls back to once its depth limit runs out.
pub fn heap(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime less_than: fn (@TypeOf(context), T, T) bool,
) void {
    Sorter(T, @TypeOf(context), less_than).heapsort(items, context);
}

fn Sorter(comptime T: type, comptime C: type, comptime less_than: fn (C, T, T) bool) type {
    return struct {
        const Context = C;
        const insertion_max = 20;
        const stack_bytes_max = 4096;
        const network_scratch = 32;
        const general_scratch = 48;
        const branchless_size_max = 96;
        /// The depth limit is at most 2 * log2(usize max); split frames strictly decrease it.
        const frames_max = 2 * @bitSizeOf(usize) + 1;

        const SmallSort = enum { network, general, fallback };
        const small_sort: SmallSort = if (@sizeOf(T) <= 8 and
            @sizeOf(T) * network_scratch <= stack_bytes_max)
            .network
        else if (@sizeOf(T) * general_scratch <= stack_bytes_max)
            .general
        else
            .fallback;
        const small_threshold: usize = if (small_sort == .fallback) 16 else 32;

        const Frame = struct { start: usize, end: usize, ancestor: ?usize, limit: u32 };
        const Step = union(enum) { done, again, split: Frame };

        fn sort(items: []T, context: Context) void {
            if (@sizeOf(T) == 0 or items.len < 2) return;
            if (items.len <= insertion_max) return insertion_sort(items, 1, context);
            const run = find_run(items, context);
            assert(run.len >= 2 and run.len <= items.len);
            if (run.len == items.len) {
                if (run.descending) std.mem.reverse(T, items);
                return;
            }
            const limit: u32 = 2 * @as(u32, std.math.log2_int(usize, items.len | 1));
            quicksort(items, limit, context);
        }

        /// The length of the strictly descending or non-descending run at the start.
        fn find_run(items: []const T, context: Context) struct { len: usize, descending: bool } {
            assert(items.len >= 2);
            var len: usize = 2;
            const descending = less_than(context, items[1], items[0]);
            // A descending run must be strict, so reversing it keeps equal items in place.
            while (len < items.len and
                less_than(context, items[len], items[len - 1]) == descending) len += 1;
            assert(len <= items.len);
            return .{ .len = len, .descending = descending };
        }

        /// Rust's recursive quicksort: each split sorts its left part first, so the deferred
        /// right parts form a stack whose limits strictly decrease.
        fn quicksort(items: []T, limit: u32, context: Context) void {
            var frames: [frames_max]Frame = undefined;
            var depth: usize = 0;
            var frame: Frame = .{ .start = 0, .end = items.len, .ancestor = null, .limit = limit };
            // Every step shrinks the frame or finishes it, so the loop ends.
            while (true) {
                switch (step(items, &frame, context)) {
                    .again => {},
                    .split => |right| {
                        assert(depth < frames_max);
                        assert(depth == 0 or right.limit < frames[depth - 1].limit);
                        frames[depth] = right;
                        depth += 1;
                    },
                    .done => {
                        if (depth == 0) return;
                        depth -= 1;
                        frame = frames[depth];
                    },
                }
            }
        }

        fn step(items: []T, frame: *Frame, context: Context) Step {
            assert(frame.start <= frame.end and frame.end <= items.len);
            const v = items[frame.start..frame.end];
            if (v.len <= small_threshold) {
                small(v, context);
                return .done;
            }
            if (frame.limit == 0) {
                heapsort(v, context);
                return .done;
            }
            frame.limit -= 1;
            const pivot = choose_pivot(v, context);
            assert(pivot < v.len);
            if (frame.ancestor) |ancestor| {
                // No item is below the ancestor pivot. When the chosen pivot is not above it,
                // the items equal to it go left and are done.
                if (!less_than(context, items[ancestor], v[pivot])) {
                    const num_le = partition(true, v, pivot, context);
                    frame.start += num_le + 1;
                    frame.ancestor = null;
                    return .again;
                }
            }
            const num_lt = partition(false, v, pivot, context);
            assert(num_lt < v.len);
            const middle = frame.start + num_lt;
            const right: Frame = .{
                .start = middle + 1,
                .end = frame.end,
                .ancestor = middle,
                .limit = frame.limit,
            };
            frame.end = middle;
            return .{ .split = right };
        }

        /// `less_than(a, b)`, or `a <= b` when `or_equal`.
        inline fn before(comptime or_equal: bool, context: Context, a: T, b: T) bool {
            return if (or_equal) !less_than(context, b, a) else less_than(context, a, b);
        }

        /// Moves the items before the pivot ahead of it and returns the pivot's new index.
        fn partition(comptime or_equal: bool, v: []T, pivot: usize, context: Context) usize {
            assert(v.len > 0);
            assert(pivot < v.len);
            std.mem.swap(T, &v[0], &v[pivot]);
            const pivot_value = v[0];
            const num_lt = if (@sizeOf(T) <= branchless_size_max)
                partition_lomuto(or_equal, v[1..], pivot_value, context)
            else
                partition_hoare(or_equal, v[1..], pivot_value, context);
            assert(num_lt < v.len);
            std.mem.swap(T, &v[0], &v[num_lt]);
            return num_lt;
        }

        /// Branchless cyclic Lomuto: the first item leaves a gap that every step fills from
        /// the front of the right part, then refills from the scanned item.
        fn partition_lomuto(comptime or_equal: bool, v: []T, pivot: T, context: Context) usize {
            if (v.len == 0) return 0;
            const gap_value = v[0];
            var gap: usize = 0;
            var num_lt: usize = 0;
            for (1..v.len) |right| {
                // Copy `v[right]` slot to slot rather than through a local: a local lives in
                // word registers, and its word stores stall the next step's wide reload.
                const is_lt = before(or_equal, context, v[right], pivot);
                v[gap] = v[num_lt];
                v[num_lt] = v[right];
                gap = right;
                num_lt += @intFromBool(is_lt);
            }
            const is_lt = before(or_equal, context, gap_value, pivot);
            v[gap] = v[num_lt];
            v[num_lt] = gap_value;
            num_lt += @intFromBool(is_lt);
            assert(num_lt <= v.len);
            return num_lt;
        }

        /// Branchy cyclic Hoare, for items too wide to move on every step.
        fn partition_hoare(comptime or_equal: bool, v: []T, pivot: T, context: Context) usize {
            var left: usize = 0;
            var right: usize = v.len;
            var gap: ?struct { position: usize, value: T } = null;
            while (true) {
                while (left < right and before(or_equal, context, v[left], pivot)) left += 1;
                while (true) {
                    right -= 1;
                    if (left >= right or before(or_equal, context, v[right], pivot)) break;
                }
                if (left >= right) break;
                if (gap) |*held| {
                    v[held.position] = v[left];
                    held.position = right;
                } else {
                    gap = .{ .position = right, .value = v[left] };
                }
                v[left] = v[right];
                left += 1;
            }
            if (gap) |held| v[held.position] = held.value;
            assert(left <= v.len);
            return left;
        }

        /// Median of three for short slices, else Rust's recursive pseudo-median of
        /// `len^(log8 3)` samples, evaluated with an explicit stack.
        fn choose_pivot(v: []const T, context: Context) usize {
            assert(v.len >= 8);
            const PivotFrame = struct { base: usize, n: usize, stage: u2, picks: [3]usize };
            const offsets = [3]usize{ 0, 4, 7 };
            var frames: [@bitSizeOf(usize) / 3 + 2]PivotFrame = undefined;
            frames[0] = .{ .base = 0, .n = v.len / 8, .stage = 0, .picks = undefined };
            var depth: usize = 1;
            // Each pass picks one sample or finishes one frame; the tree is finite.
            while (true) {
                const top = &frames[depth - 1];
                if (top.stage == 3) {
                    const pick = median3(v, top.picks, context);
                    assert(pick < v.len);
                    depth -= 1;
                    if (depth == 0) return pick;
                    const parent = &frames[depth - 1];
                    parent.picks[parent.stage] = pick;
                    parent.stage += 1;
                    continue;
                }
                const child = top.base + offsets[top.stage] * top.n;
                if (top.n >= 8) {
                    assert(depth < frames.len);
                    frames[depth] = .{
                        .base = child,
                        .n = top.n / 8,
                        .stage = 0,
                        .picks = undefined,
                    };
                    depth += 1;
                } else {
                    top.picks[top.stage] = child;
                    top.stage += 1;
                }
            }
        }

        fn median3(v: []const T, picks: [3]usize, context: Context) usize {
            const a, const b, const c = picks;
            assert(a < v.len and b < v.len and c < v.len);
            const x = less_than(context, v[a], v[b]);
            const y = less_than(context, v[a], v[c]);
            if (x != y) return a;
            const z = less_than(context, v[b], v[c]);
            return if (z != x) c else b;
        }

        fn heapsort(v: []T, context: Context) void {
            const len = v.len;
            var i = len + len / 2;
            while (i > 0) {
                i -= 1;
                const node = if (i >= len) i - len else blk: {
                    std.mem.swap(T, &v[0], &v[i]);
                    break :blk 0;
                };
                sift_down(v[0..@min(i, len)], node, context);
            }
            assert(i == 0);
        }

        fn sift_down(v: []T, node_start: usize, context: Context) void {
            assert(node_start <= v.len);
            var node = node_start;
            // The node index at least doubles each pass.
            while (true) {
                var child = 2 * node + 1;
                if (child >= v.len) break;
                if (child + 1 < v.len) {
                    child += @intFromBool(less_than(context, v[child], v[child + 1]));
                }
                if (!less_than(context, v[node], v[child])) break;
                std.mem.swap(T, &v[node], &v[child]);
                node = child;
            }
            assert(node < v.len or v.len == 0);
        }

        fn small(v: []T, context: Context) void {
            assert(v.len <= small_threshold);
            switch (small_sort) {
                .network => network_sort(v, context),
                .general => general_sort(v, context),
                .fallback => if (v.len >= 2) insertion_sort(v, 1, context),
            }
        }

        /// Sorts `v[tail]` into the sorted `v[0..tail]`, moving the larger items up one.
        fn insert_tail(v: []T, tail: usize, context: Context) void {
            assert(tail > 0 and tail < v.len);
            var sift = tail - 1;
            if (!less_than(context, v[tail], v[sift])) return;
            const value = v[tail];
            var gap = tail;
            while (true) {
                v[gap] = v[sift];
                gap = sift;
                if (sift == 0) break;
                sift -= 1;
                if (!less_than(context, value, v[sift])) break;
            }
            v[gap] = value;
            assert(gap < tail);
        }

        /// Insertion sort of `v` whose first `offset` items are already sorted.
        fn insertion_sort(v: []T, offset: usize, context: Context) void {
            assert(offset >= 1 and offset <= v.len);
            for (offset..v.len) |tail| insert_tail(v, tail, context);
        }

        fn swap_if_less(v: []T, a: usize, b: usize, context: Context) void {
            assert(a < b and b < v.len);
            const left = v[a];
            const right = v[b];
            const swap = less_than(context, right, left);
            v[a] = if (swap) right else left;
            v[b] = if (swap) left else right;
        }

        fn network_region(v: []T, context: Context) void {
            assert(v.len <= network_scratch);
            const presorted: usize = if (v.len >= 13) blk: {
                inline for (sort13_pairs) |pair| swap_if_less(v, pair[0], pair[1], context);
                break :blk 13;
            } else if (v.len >= 9) blk: {
                inline for (sort9_pairs) |pair| swap_if_less(v, pair[0], pair[1], context);
                break :blk 9;
            } else 1;
            if (v.len > 1) insertion_sort(v, presorted, context);
        }

        /// Sorting networks on each half, then one merge (Rust's `small_sort_network`).
        fn network_sort(v: []T, context: Context) void {
            if (v.len < 2) return;
            assert(v.len <= network_scratch);
            if (v.len < 18) return network_region(v, context);
            const half = v.len / 2;
            network_region(v[0..half], context);
            network_region(v[half..], context);
            var scratch: [network_scratch]T = undefined;
            merge(v, scratch[0..v.len], context);
            @memcpy(v, scratch[0..v.len]);
        }

        /// Presorts each half into scratch, insertion-sorts the rest of it in, then merges
        /// the halves back (Rust's `small_sort_general_with_scratch`).
        fn general_sort(v: []T, context: Context) void {
            if (v.len < 2) return;
            assert(v.len <= small_threshold and v.len + 16 <= general_scratch);
            var scratch: [general_scratch]T = undefined;
            const len = v.len;
            const half = len / 2;
            const presorted: usize = if (@sizeOf(T) <= 16 and len >= 16) blk: {
                sort8(v[0..8], scratch[0..8], scratch[len..][0..8], context);
                sort8(v[half..][0..8], scratch[half..][0..8], scratch[len + 8 ..][0..8], context);
                break :blk 8;
            } else if (len >= 8) blk: {
                sort4(v[0..4], scratch[0..4], context);
                sort4(v[half..][0..4], scratch[half..][0..4], context);
                break :blk 4;
            } else blk: {
                scratch[0] = v[0];
                scratch[half] = v[half];
                break :blk 1;
            };
            for ([2]usize{ 0, half }) |offset| {
                const desired = if (offset == 0) half else len - half;
                const region = scratch[offset..][0..desired];
                for (presorted..desired) |i| {
                    region[i] = v[offset + i];
                    insert_tail(region, i, context);
                }
            }
            merge(scratch[0..len], v, context);
        }

        /// A stable branchless sort of four items into `dst`.
        fn sort4(src: *const [4]T, dst: *[4]T, context: Context) void {
            const c1 = less_than(context, src[1], src[0]);
            const c2 = less_than(context, src[3], src[2]);
            const a: usize = @intFromBool(c1);
            const b: usize = @intFromBool(!c1);
            const c: usize = 2 + @as(usize, @intFromBool(c2));
            const d: usize = 2 + @as(usize, @intFromBool(!c2));
            const c3 = less_than(context, src[c], src[a]);
            const c4 = less_than(context, src[d], src[b]);
            const min = if (c3) c else a;
            const max = if (c4) b else d;
            const unknown_left = if (c3) a else if (c4) c else b;
            const unknown_right = if (c4) d else if (c3) b else c;
            const c5 = less_than(context, src[unknown_right], src[unknown_left]);
            const lo = if (c5) unknown_right else unknown_left;
            const hi = if (c5) unknown_left else unknown_right;
            assert(min != max and lo != hi);
            dst.* = .{ src[min], src[lo], src[hi], src[max] };
        }

        fn sort8(src: *const [8]T, dst: *[8]T, scratch: *[8]T, context: Context) void {
            assert(@intFromPtr(src) != @intFromPtr(dst));
            sort4(src[0..4], scratch[0..4], context);
            sort4(src[4..8], scratch[4..8], context);
            merge(scratch, dst, context);
        }

        /// Merges the sorted halves of `src` into `dst` from both ends at once.
        fn merge(src: []const T, dst: []T, context: Context) void {
            assert(src.len == dst.len and src.len >= 2);
            const len = src.len;
            const half = len / 2;
            var left: usize = 0;
            var right: usize = half;
            var out: usize = 0;
            var left_rev: usize = half - 1;
            var right_rev: usize = len - 1;
            var out_rev: usize = len - 1;
            for (0..half) |_| {
                const up = !less_than(context, src[right], src[left]);
                dst[out] = if (up) src[left] else src[right];
                left += @intFromBool(up);
                right += @intFromBool(!up);
                out += 1;
                const down = !less_than(context, src[right_rev], src[left_rev]);
                dst[out_rev] = if (down) src[right_rev] else src[left_rev];
                right_rev -%= @intFromBool(down);
                left_rev -%= @intFromBool(!down);
                out_rev -%= 1;
            }
            const left_end = left_rev +% 1;
            const right_end = right_rev +% 1;
            if (len % 2 == 1) {
                const left_nonempty = left < left_end;
                dst[out] = if (left_nonempty) src[left] else src[right];
                left += @intFromBool(left_nonempty);
                right += @intFromBool(!left_nonempty);
            }
            if (left != left_end or right != right_end) {
                @panic("user-provided comparison function does not implement a total order");
            }
        }

        const sort9_pairs = [_][2]u8{
            .{ 0, 3 }, .{ 1, 7 }, .{ 2, 5 }, .{ 4, 8 }, .{ 0, 7 }, .{ 2, 4 }, .{ 3, 8 },
            .{ 5, 6 }, .{ 0, 2 }, .{ 1, 3 }, .{ 4, 5 }, .{ 7, 8 }, .{ 1, 4 }, .{ 3, 6 },
            .{ 5, 7 }, .{ 0, 1 }, .{ 2, 4 }, .{ 3, 5 }, .{ 6, 8 }, .{ 2, 3 }, .{ 4, 5 },
            .{ 6, 7 }, .{ 1, 2 }, .{ 3, 4 }, .{ 5, 6 },
        };

        const sort13_pairs = [_][2]u8{
            .{ 0, 12 },  .{ 1, 10 }, .{ 2, 9 },   .{ 3, 7 },  .{ 5, 11 },  .{ 6, 8 },
            .{ 1, 6 },   .{ 2, 3 },  .{ 4, 11 },  .{ 7, 9 },  .{ 8, 10 },  .{ 0, 4 },
            .{ 1, 2 },   .{ 3, 6 },  .{ 7, 8 },   .{ 9, 10 }, .{ 11, 12 }, .{ 4, 6 },
            .{ 5, 9 },   .{ 8, 11 }, .{ 10, 12 }, .{ 0, 5 },  .{ 3, 8 },   .{ 4, 7 },
            .{ 6, 11 },  .{ 9, 10 }, .{ 0, 1 },   .{ 2, 5 },  .{ 6, 9 },   .{ 7, 8 },
            .{ 10, 11 }, .{ 1, 3 },  .{ 2, 4 },   .{ 5, 6 },  .{ 9, 10 },  .{ 1, 2 },
            .{ 3, 4 },   .{ 5, 7 },  .{ 6, 8 },   .{ 2, 3 },  .{ 4, 5 },   .{ 6, 7 },
            .{ 8, 9 },   .{ 3, 4 },  .{ 5, 6 },
        };
    };
}

/// A test item `width` bytes wide: a 16-bit key, a 16-bit tag naming its original index, and
/// filler derived from the tag, so a lost, duplicated, or torn item shows.
fn TestItem(comptime width: usize) type {
    comptime assert(width >= 4);
    return struct {
        bytes: [width]u8,

        const Self = @This();

        fn init(key_value: u16, tag_value: u16) Self {
            var item: Self = undefined;
            std.mem.writeInt(u16, item.bytes[0..2], key_value, .big);
            std.mem.writeInt(u16, item.bytes[2..4], tag_value, .little);
            for (item.bytes[4..], 4..) |*byte, i| byte.* = @truncate(tag_value *% 31 +% i);
            return item;
        }

        fn key(item: Self) u16 {
            return std.mem.readInt(u16, item.bytes[0..2], .big);
        }

        fn tag(item: Self) u16 {
            return std.mem.readInt(u16, item.bytes[2..4], .little);
        }

        fn less_than(_: void, a: Self, b: Self) bool {
            return a.key() < b.key();
        }
    };
}

const Shape = enum { random, three_values, ascending, descending, equal };

fn fill(comptime Item: type, items: []Item, shape: Shape, random: std.Random) void {
    const n: u16 = @intCast(items.len);
    for (items, 0..) |*item, i| {
        const index: u16 = @intCast(i);
        const key: u16 = switch (shape) {
            .random => random.int(u16),
            .three_values => random.uintLessThan(u16, 3),
            .ascending => index,
            .descending => n - index,
            .equal => 7,
        };
        item.* = .init(key, index);
    }
}

/// Sorted by key, and a permutation of the input with every item intact.
fn expect_sorted(comptime Item: type, items: []const Item, seen: []bool) !void {
    @memset(seen[0..items.len], false);
    for (items, 0..) |item, i| {
        if (i > 0) try std.testing.expect(items[i - 1].key() <= item.key());
        try std.testing.expect(item.tag() < items.len);
        try std.testing.expect(!seen[item.tag()]);
        seen[item.tag()] = true;
        try std.testing.expectEqual(Item.init(item.key(), item.tag()), item);
    }
}

const test_lengths = blk: {
    var lengths: [201 + 11]usize = undefined;
    for (0..201) |i| lengths[i] = i;
    const long = [_]usize{ 255, 256, 257, 500, 511, 512, 513, 1000, 1024, 2047, 3000 };
    for (long, 201..) |length, i| lengths[i] = length;
    break :blk lengths;
};

test "sort.unstable sorts every shape and length across each small-sort and partition" {
    var prng = std.Random.DefaultPrng.init(0x5eed_5047);
    const items_buffer = try std.testing.allocator.alloc(TestItem(100), 3000);
    defer std.testing.allocator.free(items_buffer);
    var seen: [3000]bool = undefined;
    // 4 bytes: networks; 12: stable sort8; 33 and 64: stable sort4; 100: insertion + Hoare.
    inline for (.{ 4, 12, 33, 64, 100 }) |width| {
        const Item = TestItem(width);
        const items: []Item = @as([*]Item, @ptrCast(items_buffer.ptr))[0..3000];
        for (test_lengths) |length| {
            for (std.enums.values(Shape)) |shape| {
                fill(Item, items[0..length], shape, prng.random());
                unstable(Item, items[0..length], {}, Item.less_than);
                try expect_sorted(Item, items[0..length], &seen);
            }
        }
    }
}

test "sort.heap sorts every shape directly" {
    var prng = std.Random.DefaultPrng.init(0x4ea9);
    var seen: [300]bool = undefined;
    inline for (.{ 4, 33 }) |width| {
        const Item = TestItem(width);
        var items: [300]Item = undefined;
        for ([_]usize{ 0, 1, 2, 3, 7, 8, 31, 32, 33, 100, 255, 300 }) |length| {
            for (std.enums.values(Shape)) |shape| {
                fill(Item, items[0..length], shape, prng.random());
                heap(Item, items[0..length], {}, Item.less_than);
                try expect_sorted(Item, items[0..length], &seen);
            }
        }
    }
}

test "sort.unstable matches std.sort.pdq on 100k random u64" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(42);
    const a = try gpa.alloc(u64, 100_000);
    defer gpa.free(a);
    for (a) |*value| value.* = prng.random().int(u64) % 50_000;
    const b = try gpa.dupe(u64, a);
    defer gpa.free(b);
    unstable(u64, a, {}, std.sort.asc(u64));
    std.sort.pdq(u64, b, {}, std.sort.asc(u64));
    try std.testing.expectEqualSlices(u64, b, a);
}
