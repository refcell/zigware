//! Read access shared by every bitmap (commonware `bitmap::Readable` and `OnesIter`).
//!
//! The Rust trait becomes a comptime interface: a readable bitmap of `N`-byte chunks declares
//! `len() u64`, `pruned_chunks() usize`, and `get_chunk(absolute_chunk_index) [N]u8`. The free
//! functions here (`get_bit`, `pruned_bits`, `ones_iter_from`, `ones_iter_range`) are the
//! trait's provided methods.

const std = @import("std");
const assert = std.debug.assert;

/// Comptime check that `B` implements the readable interface.
pub fn assert_readable(comptime B: type) void {
    comptime {
        assert(@hasDecl(B, "len"));
        assert(@hasDecl(B, "pruned_chunks"));
        assert(@hasDecl(B, "get_chunk"));
    }
}

fn chunk_bits(comptime N: usize) u64 {
    return @as(u64, N) * 8;
}

/// Bits removed from the front by pruning.
pub fn pruned_bits(comptime N: usize, bitmap: anytype) u64 {
    return @as(u64, bitmap.pruned_chunks()) * chunk_bits(N);
}

/// The value of `bit` (an absolute position; it must be retained and below `len`).
pub fn get_bit(comptime N: usize, bitmap: anytype, bit: u64) bool {
    assert(bit < bitmap.len());
    const chunk = bitmap.get_chunk(@intCast(bit / chunk_bits(N)));
    const offset = bit % chunk_bits(N);
    return chunk[@intCast(offset / 8)] & (@as(u8, 1) << @intCast(offset % 8)) != 0;
}

/// Iterates the positions of set bits in increasing order, one 64-bit word at a time.
pub fn OnesIter(comptime B: type, comptime N: usize) type {
    assert_readable(B);
    return struct {
        bitmap: *const B,
        /// One past the last position to report.
        end: u64,
        /// Position of bit 0 of `word`.
        base: u64,
        /// Unreported set bits of the current word.
        word: u64,
        /// The chunk containing `base`.
        chunk: [N]u8,

        const Self = @This();

        fn load_word(self: *const Self) u64 {
            assert(self.base < self.end);
            const offset: usize = @intCast((self.base % chunk_bits(N)) / 8);
            const take = @min(N - offset, 8);
            var buffer: [8]u8 = @splat(0);
            @memcpy(buffer[0..take], self.chunk[offset..][0..take]);
            var word = std.mem.readInt(u64, &buffer, .little);
            const remaining = self.end - self.base;
            if (remaining < 64) word &= (@as(u64, 1) << @intCast(remaining)) - 1;
            return word;
        }

        pub fn next(self: *Self) ?u64 {
            // Each pass advances `base` by at least one byte toward `end`: bounded.
            while (self.word == 0) {
                const relative = self.base % chunk_bits(N);
                const same_chunk = relative + 64 < chunk_bits(N);
                const stride = if (same_chunk) 64 else chunk_bits(N) - relative;
                const advanced = std.math.add(u64, self.base, stride) catch return null;
                if (advanced >= self.end) return null;
                self.base = advanced;
                if (!same_chunk) {
                    self.chunk = self.bitmap.get_chunk(@intCast(advanced / chunk_bits(N)));
                }
                self.word = self.load_word();
            }
            const bit: u64 = @ctz(self.word);
            self.word &= self.word - 1;
            assert(self.base + bit < self.end);
            return self.base + bit;
        }
    };
}

/// Set bits at positions in `[start, end)`, skipping pruned bits; `end` is clamped to `len`.
pub fn ones_iter_range(
    comptime N: usize,
    bitmap: anytype,
    start: u64,
    end: u64,
) OnesIter(@typeInfo(@TypeOf(bitmap)).pointer.child, N) {
    const B = @typeInfo(@TypeOf(bitmap)).pointer.child;
    const clamped_end = @min(end, bitmap.len());
    const position = @max(start, pruned_bits(N, bitmap));
    var iter: OnesIter(B, N) = .{
        .bitmap = bitmap,
        .end = clamped_end,
        .base = clamped_end,
        .word = 0,
        .chunk = @splat(0),
    };
    if (position < clamped_end) {
        const chunk_index = position / chunk_bits(N);
        const chunk_start = chunk_index * chunk_bits(N);
        iter.chunk = bitmap.get_chunk(@intCast(chunk_index));
        iter.base = chunk_start + (position - chunk_start) / 64 * 64;
        const below = std.math.shl(u64, std.math.maxInt(u64), position - iter.base);
        iter.word = iter.load_word() & below;
    }
    return iter;
}

/// Set bits at positions from `start` to the end.
pub fn ones_iter_from(
    comptime N: usize,
    bitmap: anytype,
    start: u64,
) OnesIter(@typeInfo(@TypeOf(bitmap)).pointer.child, N) {
    return ones_iter_range(N, bitmap, start, std.math.maxInt(u64));
}
