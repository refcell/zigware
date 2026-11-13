//! Owned shard storage and mutable shard views, laid out as flat arrays of chunks
//! (commonware `reed_solomon/engine/shards.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const engine = @import("../engine.zig");

const SHARD_CHUNK_BYTES = engine.SHARD_CHUNK_BYTES;
const Chunk = engine.Chunk;

/// Alignment of work buffers, so SIMD engines can load whole chunks.
pub const chunk_alignment: std.mem.Alignment = .@"64";

/// Owned work buffer of `shard_count` shards, each `shard_chunk_count` chunks long.
///
/// Shard `i` occupies chunks `i * shard_chunk_count..(i + 1) * shard_chunk_count` of `data`.
/// The buffer grows on `resize` and never shrinks, like the Rust `Vec` it replaces.
pub const Shards = struct {
    shard_count: usize,
    /// Shard length in `SHARD_CHUNK_BYTES` chunks.
    shard_chunk_count: usize,
    /// Chunks in use: `shard_count * shard_chunk_count`.
    len: usize,
    /// The whole allocation; `data[0..len]` is in use.
    capacity: []align(64) Chunk,

    pub const empty: Shards = .{
        .shard_count = 0,
        .shard_chunk_count = 0,
        .len = 0,
        .capacity = &.{},
    };

    pub fn deinit(shards: *Shards, gpa: Allocator) void {
        gpa.free(shards.capacity);
        shards.* = .empty;
    }

    /// Returns a `ShardsRefMut` view of all shards.
    pub fn as_ref_mut(shards: *Shards) ShardsRefMut {
        return .init(shards.shard_count, shards.shard_chunk_count, shards.capacity[0..shards.len]);
    }

    /// Sets the dimensions to `shard_count` shards of `shard_chunk_count` chunks each.
    ///
    /// Existing chunks keep their bytes at the same flat positions and chunks added by growth
    /// are zeroed (as `Vec::resize`). On allocation failure nothing changes.
    pub fn resize(
        shards: *Shards,
        gpa: Allocator,
        shard_count: usize,
        shard_chunk_count: usize,
    ) Allocator.Error!void {
        const len = std.math.mul(usize, shard_count, shard_chunk_count) catch
            return error.OutOfMemory;
        if (len > shards.capacity.len) {
            const grown = try gpa.alignedAlloc(Chunk, chunk_alignment, len);
            @memcpy(grown[0..shards.len], shards.capacity[0..shards.len]);
            gpa.free(shards.capacity);
            shards.capacity = grown;
        }
        if (len > shards.len) @memset(shards.capacity[shards.len..len], @splat(0));
        shards.shard_count = shard_count;
        shards.shard_chunk_count = shard_chunk_count;
        shards.len = len;
        assert(shards.len <= shards.capacity.len);
    }

    /// Shard `index` as chunks.
    pub fn get(shards: *const Shards, index: usize) []Chunk {
        assert(index < shards.shard_count);
        const start = index * shards.shard_chunk_count;
        return shards.capacity[start..][0..shards.shard_chunk_count];
    }

    /// Shard `index` as bytes, truncated to `shard_bytes`.
    pub fn bytes(shards: *const Shards, index: usize, shard_bytes: usize) []const u8 {
        const flat = std.mem.sliceAsBytes(shards.get(index));
        assert(shard_bytes <= flat.len);
        return flat[0..shard_bytes];
    }

    /// Copies `shard` into shard `index` using the last-chunk encoding.
    ///
    /// Whole chunks are copied verbatim. A partial tail of `2 * n` bytes places `n` low bytes at
    /// offset 0 and `n` high bytes at offset `SHARD_CHUNK_BYTES / 2` of the final chunk (see
    /// `algorithm.md`). Bytes past the copied data keep their previous values.
    pub fn insert(shards: *Shards, index: usize, shard: []const u8) void {
        assert(shard.len % 2 == 0);
        const whole_chunk_count = shard.len / SHARD_CHUNK_BYTES;
        const tail_len = shard.len % SHARD_CHUNK_BYTES;
        const dst = shards.get(index);
        assert(whole_chunk_count + @intFromBool(tail_len > 0) <= dst.len);

        const whole = shard.len - tail_len;
        @memcpy(std.mem.sliceAsBytes(dst[0..whole_chunk_count]), shard[0..whole]);
        if (tail_len > 0) {
            const half = tail_len / 2;
            const last = &dst[whole_chunk_count];
            @memcpy(last[0..half], shard[whole..][0..half]);
            @memcpy(last[SHARD_CHUNK_BYTES / 2 ..][0..half], shard[whole + half ..][0..half]);
        }
    }

    /// Undoes the last-chunk encoding for shards `start..end`: moves the high bytes of a
    /// partial final chunk to directly follow its low bytes.
    pub fn undo_last_chunk_encoding(
        shards: *Shards,
        shard_bytes: usize,
        start: usize,
        end: usize,
    ) void {
        assert(start <= end and end <= shards.shard_count);
        const whole_chunk_count = shard_bytes / SHARD_CHUNK_BYTES;
        const tail_len = shard_bytes % SHARD_CHUNK_BYTES;
        if (tail_len == 0) return;
        const half = tail_len / 2;
        for (start..end) |index| {
            const last = &shards.get(index)[whole_chunk_count];
            // Source `[32, 32 + half)` lies after destination `[half, 2 * half)`.
            std.mem.copyForwards(
                u8,
                last[half..][0..half],
                last[SHARD_CHUNK_BYTES / 2 ..][0..half],
            );
        }
    }
};

/// Mutable view of a shard array: `shard_count` shards of `shard_chunk_count` chunks each.
pub const ShardsRefMut = struct {
    shard_count: usize,
    /// Shard length in `SHARD_CHUNK_BYTES` chunks.
    shard_chunk_count: usize,
    /// Exactly `shard_count * shard_chunk_count` chunks.
    data: []Chunk,

    /// Creates a view of the first `shard_count * shard_chunk_count` chunks of `data`.
    /// Zero-length shards are supported.
    pub fn init(shard_count: usize, shard_chunk_count: usize, data: []Chunk) ShardsRefMut {
        const chunk_count = std.math.mul(usize, shard_count, shard_chunk_count) catch
            @panic("shard dimensions overflow");
        assert(data.len >= chunk_count);
        return .{
            .shard_count = shard_count,
            .shard_chunk_count = shard_chunk_count,
            .data = data[0..chunk_count],
        };
    }

    /// Number of shards.
    pub fn len(view: ShardsRefMut) usize {
        return view.shard_count;
    }

    pub fn is_empty(view: ShardsRefMut) bool {
        return view.shard_count == 0;
    }

    /// Shard `index` as chunks.
    pub fn get(view: ShardsRefMut, index: usize) []Chunk {
        assert(index < view.shard_count);
        return view.data[index * view.shard_chunk_count ..][0..view.shard_chunk_count];
    }

    /// Shards at `pos` and `pos + dist`.
    pub fn dist2(view: ShardsRefMut, pos: usize, dist: usize) [2][]Chunk {
        assert(pos < view.shard_count and dist > 0 and dist < view.shard_count - pos);
        return .{ view.get(pos), view.get(pos + dist) };
    }

    /// Shards at `pos`, `pos + dist`, `pos + dist * 2` and `pos + dist * 3`.
    pub fn dist4(view: ShardsRefMut, pos: usize, dist: usize) [4][]Chunk {
        assert(pos < view.shard_count and dist > 0);
        assert(dist <= (view.shard_count - 1 - pos) / 3);
        return .{
            view.get(pos),
            view.get(pos + dist),
            view.get(pos + dist * 2),
            view.get(pos + dist * 3),
        };
    }

    /// Splits into shards `0..mid` and `mid..`.
    pub fn split_at(view: ShardsRefMut, mid: usize) [2]ShardsRefMut {
        assert(mid <= view.shard_count);
        const split = mid * view.shard_chunk_count;
        return .{
            .init(mid, view.shard_chunk_count, view.data[0..split]),
            .init(view.shard_count - mid, view.shard_chunk_count, view.data[split..]),
        };
    }

    /// Fills shards `start..end` with zero bytes.
    pub fn zero(view: ShardsRefMut, start: usize, end: usize) void {
        assert(start <= end and end <= view.shard_count);
        const chunks = view.shard_chunk_count;
        @memset(view.data[start * chunks .. end * chunks], @splat(0));
    }

    /// Copies shards `src..src + count` to `dest..dest + count`; the ranges may overlap.
    pub fn copy_within(view: ShardsRefMut, src: usize, dest: usize, count: usize) void {
        assert(src <= view.shard_count and count <= view.shard_count - src);
        assert(dest <= view.shard_count and count <= view.shard_count - dest);
        const chunks = view.shard_chunk_count;
        const from = view.data[src * chunks ..][0 .. count * chunks];
        const to = view.data[dest * chunks ..][0 .. count * chunks];
        if (dest <= src) std.mem.copyForwards(Chunk, to, from) else {
            std.mem.copyBackwards(Chunk, to, from);
        }
    }

    /// Flat slices of shard ranges `x..x + count` and `y..y + count`, which must not overlap.
    pub fn flat2(view: ShardsRefMut, x: usize, y: usize, count: usize) [2][]Chunk {
        assert(x <= view.shard_count and count <= view.shard_count - x);
        assert(y <= view.shard_count and count <= view.shard_count - y);
        assert(@max(x, y) - @min(x, y) >= count);
        const chunks = view.shard_chunk_count;
        return .{
            view.data[x * chunks ..][0 .. count * chunks],
            view.data[y * chunks ..][0 .. count * chunks],
        };
    }
};

const testing = std.testing;

test "empty shards" {
    const shards: ShardsRefMut = .init(4, 0, &.{});
    try testing.expectEqual(4, shards.len());
    try testing.expect(!shards.is_empty());
    try testing.expectEqual(0, shards.get(3).len);
    _ = shards.dist2(1, 2);
    _ = shards.dist4(0, 1);
    shards.zero(1, 4);
    const left, const right = shards.split_at(4);
    try testing.expectEqual(4, left.len());
    try testing.expect(right.is_empty());
}

test "views preserve shard boundaries" {
    var data: [14]Chunk = @splat(@splat(9));
    const shards: ShardsRefMut = .init(6, 2, &data);
    shards.zero(2, 4);
    for ([_]usize{ 2, 3 }) |index| {
        for (shards.get(index)) |chunk| try testing.expectEqual(@as(Chunk, @splat(0)), chunk);
    }
    const first, const last = shards.dist2(0, 5);
    @memset(first, @splat(1));
    @memset(last, @splat(6));
    for (shards.dist4(0, 1), 0..) |shard, index| {
        @memset(shard, @splat(@as(u8, @intCast(index)) + 1));
    }
    _, const right = shards.split_at(3);
    @memset(right.get(1), @splat(5));
    for (0..7) |index| {
        const expected: u8 = if (index < 6) @intCast(index + 1) else 9;
        for (data[index * 2 ..][0..2]) |chunk| {
            try testing.expectEqual(@as(Chunk, @splat(expected)), chunk);
        }
    }
}

test "insert and undo last chunk encoding" {
    var shards: Shards = .empty;
    defer shards.deinit(testing.allocator);
    try shards.resize(testing.allocator, 2, 2);
    var shard: [70]u8 = undefined;
    for (&shard, 0..) |*byte, i| byte.* = @intCast(i);
    shards.insert(1, &shard);
    const last = shards.get(1)[1];
    try testing.expectEqualSlices(u8, shard[64..67], last[0..3]);
    try testing.expectEqualSlices(u8, shard[67..70], last[32..35]);
    shards.undo_last_chunk_encoding(shard.len, 1, 2);
    try testing.expectEqualSlices(u8, &shard, shards.bytes(1, shard.len));
}
