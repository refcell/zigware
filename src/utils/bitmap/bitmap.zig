//! `BitMap(N)`: a growable bit vector stored in `N`-byte chunks (commonware
//! `utils/src/bitmap/mod.rs`).
//!
//! Bit `i` lives in chunk `i / (8N)`, byte `(i / 8) % N`, bit `i % 8` (least significant first).
//! Bits past `len` are always zero. The encoding is `len` as a big-endian `u64` followed by
//! every chunk; decoding checks `len` against a `RangeCfg(u64)` and rejects set trailing bits.
//! Chunks live in a ring buffer so the front can be pruned and restored cheaply.

const std = @import("std");
const codec = @import("codec");
const readable = @import("readable.zig");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const DEFAULT_CHUNK_SIZE: usize = 8;

pub fn BitMap(comptime N: usize) type {
    comptime assert(N > 0);
    return struct {
        chunks: std.Deque(Chunk) = .empty,
        bit_len: u64 = 0,

        const Self = @This();

        pub const Chunk = [N]u8;
        pub const CHUNK_SIZE_BITS: u64 = @as(u64, N) * 8;
        pub const EMPTY_CHUNK: Chunk = @splat(0);
        pub const FULL_CHUNK: Chunk = @splat(0xff);
        pub const Cfg = codec.RangeCfg(u64);
        pub const empty: Self = .{};

        // Constructors.

        /// An empty bitmap with room for `size` bits.
        pub fn init_capacity(gpa: Allocator, size: u64) Allocator.Error!Self {
            return .{ .chunks = try .initCapacity(gpa, chunk_count(size)) };
        }

        /// Reserves room for `size` bits in total, so growing to that size cannot fail.
        pub fn ensure_total_capacity(self: *Self, gpa: Allocator, size: u64) Allocator.Error!void {
            try self.chunks.ensureTotalCapacity(gpa, chunk_count(size));
            assert(self.chunks.buffer.len >= chunk_count(size));
        }

        pub fn zeroes(gpa: Allocator, size: u64) Allocator.Error!Self {
            return filled(gpa, size, EMPTY_CHUNK);
        }

        pub fn ones(gpa: Allocator, size: u64) Allocator.Error!Self {
            var result = try filled(gpa, size, FULL_CHUNK);
            _ = result.clear_trailing_bits();
            return result;
        }

        fn filled(gpa: Allocator, size: u64, chunk: Chunk) Allocator.Error!Self {
            var result = try init_capacity(gpa, size);
            for (0..chunk_count(size)) |_| result.chunks.pushBackAssumeCapacity(chunk);
            result.bit_len = size;
            assert(result.chunks.len == chunk_count(size));
            return result;
        }

        pub fn from_bools(gpa: Allocator, bools: []const bool) Allocator.Error!Self {
            var result = try init_capacity(gpa, bools.len);
            errdefer result.deinit(gpa);
            for (bools) |bit| try result.push(gpa, bit);
            assert(result.bit_len == bools.len);
            return result;
        }

        pub fn to_bools(self: *const Self, gpa: Allocator) Allocator.Error![]bool {
            const result = try gpa.alloc(bool, @intCast(self.bit_len));
            for (result, 0..) |*bit, index| bit.* = self.get(index);
            return result;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var result = try init_capacity(gpa, self.bit_len);
            var chunk_iter = self.chunks.iterator();
            while (chunk_iter.next()) |chunk| result.chunks.pushBackAssumeCapacity(chunk);
            result.bit_len = self.bit_len;
            return result;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.chunks.deinit(gpa);
            self.* = undefined;
        }

        // Length.

        pub fn len(self: *const Self) u64 {
            assert(self.chunks.len == chunk_count(self.bit_len));
            return self.bit_len;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.len() == 0;
        }

        pub fn is_chunk_aligned(self: *const Self) bool {
            return self.bit_len % CHUNK_SIZE_BITS == 0;
        }

        pub fn chunks_len(self: *const Self) usize {
            return self.chunks.len;
        }

        /// Chunks fully filled with bits.
        pub fn complete_chunks(self: *const Self) usize {
            return self.chunks.len - @intFromBool(!self.is_chunk_aligned() and self.chunks.len > 0);
        }

        /// A plain bitmap never prunes (the `Readable` interface).
        pub fn pruned_chunks(_: *const Self) usize {
            return 0;
        }

        /// Encoded size of a bitmap of `bits` bits (Rust `BitMap::max_encode_size`).
        pub fn encode_size_max(bits: u64) usize {
            return chunk_count(bits) * N + @sizeOf(u64);
        }

        fn chunk_count(bits: u64) usize {
            return @intCast(std.math.divCeil(u64, bits, CHUNK_SIZE_BITS) catch unreachable);
        }

        // Getters.

        pub fn get(self: *const Self, bit: u64) bool {
            return get_bit_from_chunk(self.get_chunk_containing(bit), bit);
        }

        pub fn get_chunk_containing(self: *const Self, bit: u64) *const Chunk {
            self.assert_bit(bit);
            return self.chunks.atPtr(to_chunk_index(bit));
        }

        pub fn get_chunk(self: *const Self, chunk: usize) Chunk {
            if (chunk >= self.chunks.len) {
                std.debug.panic("chunk {d} out of bounds (chunks: {d})", .{
                    chunk, self.chunks.len,
                });
            }
            return self.chunks.at(chunk);
        }

        pub fn get_bit_from_chunk(chunk: *const Chunk, bit: u64) bool {
            return chunk[chunk_byte_offset(bit)] & chunk_byte_bitmask(bit) != 0;
        }

        /// The last chunk and how many of its bits are in use (`CHUNK_SIZE_BITS` when full).
        pub fn last_chunk(self: *const Self) struct { Chunk, u64 } {
            assert(self.chunks.len > 0);
            const remainder = self.bit_len % CHUNK_SIZE_BITS;
            const bits = if (remainder == 0) CHUNK_SIZE_BITS else remainder;
            return .{ self.chunks.back().?, bits };
        }

        // Setters.

        /// Grows to `new_len` bits with zeros; a smaller `new_len` is a no-op.
        pub fn extend_to(self: *Self, gpa: Allocator, new_len: u64) Allocator.Error!void {
            if (new_len <= self.bit_len) return;
            const needed = chunk_count(new_len);
            try self.chunks.ensureTotalCapacity(gpa, needed);
            while (self.chunks.len < needed) self.chunks.pushBackAssumeCapacity(EMPTY_CHUNK);
            self.bit_len = new_len;
        }

        pub fn push(self: *Self, gpa: Allocator, bit: bool) Allocator.Error!void {
            if (self.is_chunk_aligned()) try self.chunks.pushBack(gpa, EMPTY_CHUNK);
            if (bit) {
                self.chunks.backPtr().?[chunk_byte_offset(self.bit_len)] |=
                    chunk_byte_bitmask(self.bit_len);
            }
            self.bit_len += 1;
            assert(self.chunks.len == chunk_count(self.bit_len));
        }

        pub fn pop(self: *Self) bool {
            if (self.is_empty()) @panic("Cannot pop from empty bitmap");
            const last = self.bit_len - 1;
            const bit = get_bit_from_chunk(self.chunks.backPtr().?, last);
            self.bit_len = last;
            self.chunks.backPtr().?[chunk_byte_offset(last)] &= ~chunk_byte_bitmask(last);
            if (self.is_chunk_aligned()) _ = self.chunks.popBack();
            assert(self.chunks.len == chunk_count(self.bit_len));
            return bit;
        }

        pub fn truncate(self: *Self, new_len: u64) void {
            if (new_len > self.bit_len) @panic("cannot truncate to a larger size");
            while (self.bit_len > new_len and !self.is_chunk_aligned()) _ = self.pop();
            while (self.bit_len - new_len >= CHUNK_SIZE_BITS) _ = self.pop_chunk();
            while (self.bit_len > new_len) _ = self.pop();
            assert(self.bit_len == new_len);
        }

        pub fn pop_chunk(self: *Self) Chunk {
            if (self.bit_len < CHUNK_SIZE_BITS) {
                @panic("cannot pop chunk: bitmap has fewer than CHUNK_SIZE_BITS bits");
            }
            if (!self.is_chunk_aligned()) @panic("cannot pop chunk when not chunk aligned");
            const chunk = self.chunks.popBack().?;
            self.bit_len -= CHUNK_SIZE_BITS;
            return chunk;
        }

        pub fn flip(self: *Self, bit: u64) void {
            self.assert_bit(bit);
            self.chunks.atPtr(to_chunk_index(bit))[chunk_byte_offset(bit)] ^=
                chunk_byte_bitmask(bit);
        }

        pub fn flip_all(self: *Self) void {
            var chunk_iter = self.chunks.iterator();
            while (chunk_iter.nextPtr()) |chunk| {
                for (chunk) |*byte| byte.* = ~byte.*;
            }
            _ = self.clear_trailing_bits();
        }

        pub fn set(self: *Self, bit: u64, value: bool) void {
            self.assert_bit(bit);
            const byte = &self.chunks.atPtr(to_chunk_index(bit))[chunk_byte_offset(bit)];
            if (value) byte.* |= chunk_byte_bitmask(bit) else byte.* &= ~chunk_byte_bitmask(bit);
            assert(self.get(bit) == value);
        }

        pub fn set_all(self: *Self, value: bool) void {
            var chunk_iter = self.chunks.iterator();
            while (chunk_iter.nextPtr()) |chunk| chunk.* = if (value) FULL_CHUNK else EMPTY_CHUNK;
            if (value) _ = self.clear_trailing_bits();
        }

        pub fn push_byte(self: *Self, gpa: Allocator, byte: u8) Allocator.Error!void {
            if (self.bit_len % 8 != 0) @panic("cannot add byte when not byte aligned");
            if (self.is_chunk_aligned()) try self.chunks.pushBack(gpa, EMPTY_CHUNK);
            self.chunks.backPtr().?[chunk_byte_offset(self.bit_len)] = byte;
            self.bit_len += 8;
        }

        pub fn push_chunk(self: *Self, gpa: Allocator, chunk: *const Chunk) Allocator.Error!void {
            if (!self.is_chunk_aligned()) @panic("cannot add chunk when not chunk aligned");
            try self.chunks.pushBack(gpa, chunk.*);
            self.bit_len += CHUNK_SIZE_BITS;
        }

        /// Appends every bit of `other` (any chunk size), a byte at a time once aligned.
        pub fn extend_from_bitmap(
            self: *Self,
            gpa: Allocator,
            comptime M: usize,
            other: *const BitMap(M),
        ) Allocator.Error!void {
            var next: u64 = 0;
            while (next < other.len() and !self.is_chunk_aligned()) : (next += 1) {
                try self.push(gpa, other.get(next));
            }
            const remaining = other.len() - next;
            const new_chunks = chunk_count(remaining);
            try self.chunks.ensureUnusedCapacity(gpa, new_chunks);
            const shift: u4 = @intCast(next % 8);
            var index: usize = @intCast(next / 8);
            var current = other.byte_at(index);
            for (0..new_chunks) |_| {
                var chunk: Chunk = undefined;
                for (&chunk) |*out| {
                    index += 1;
                    const following = other.byte_at(index);
                    const pair = @as(u16, current) | (@as(u16, following) << 8);
                    out.* = @truncate(pair >> shift);
                    current = following;
                }
                self.chunks.pushBackAssumeCapacity(chunk);
            }
            self.bit_len += remaining;
            assert(self.chunks.len == chunk_count(self.bit_len));
        }

        /// Byte `index` of the chunk bytes laid end to end, or zero past the end.
        fn byte_at(self: *const Self, index: usize) u8 {
            if (index >= self.chunks.len * N) return 0;
            return self.chunks.atPtr(index / N)[index % N];
        }

        // Invariant maintenance.

        /// Zeroes bits past `len`; returns whether any were set.
        pub fn clear_trailing_bits(self: *Self) bool {
            const position = self.bit_len % CHUNK_SIZE_BITS;
            if (self.chunks.len == 0 or position == 0) return false;
            const last = self.chunks.backPtr().?;
            const last_byte: usize = @intCast((position - 1) / 8);
            var flipped = false;
            for (last[last_byte + 1 ..]) |*byte| {
                flipped = flipped or byte.* != 0;
                byte.* = 0;
            }
            const bits_in_last_byte: u3 = @intCast(position % 8);
            if (bits_in_last_byte != 0) {
                const masked = last[last_byte] & ((@as(u8, 1) << bits_in_last_byte) - 1);
                flipped = flipped or masked != last[last_byte];
                last[last_byte] = masked;
            }
            return flipped;
        }

        // Pruning (used by the prunable bitmaps).

        /// Drops the first `count` chunks.
        pub fn prune_chunks(self: *Self, count: usize) void {
            if (count > self.chunks.len) {
                std.debug.panic("cannot prune {d} chunks, only {d} available", .{
                    count, self.chunks.len,
                });
            }
            for (0..count) |_| _ = self.chunks.popFront();
            self.bit_len -|= @as(u64, count) * CHUNK_SIZE_BITS;
            assert(self.chunks.len == chunk_count(self.bit_len));
        }

        pub fn prepend_chunk(
            self: *Self,
            gpa: Allocator,
            chunk: *const Chunk,
        ) Allocator.Error!void {
            try self.chunks.pushFront(gpa, chunk.*);
            self.bit_len += CHUNK_SIZE_BITS;
        }

        pub fn set_chunk_by_index(self: *Self, index: usize, chunk: *const Chunk) void {
            if (index >= self.chunks.len) {
                std.debug.panic("chunk index {d} out of bounds (chunks_len: {d})", .{
                    index, self.chunks.len,
                });
            }
            self.chunks.atPtr(index).* = chunk.*;
        }

        // Counting.

        pub fn count_ones(self: *const Self) u64 {
            // Trailing bits are always zero, so every set bit in the chunks counts. Count the
            // deque's two contiguous segments a 64-bit word at a time, as commonware does.
            const segments = self.chunk_segments();
            const total = count_ones_in(segments[0]) + count_ones_in(segments[1]);
            assert(total <= self.bit_len);
            return total;
        }

        fn count_ones_in(chunks: []const Chunk) u64 {
            const bytes = std.mem.sliceAsBytes(chunks);
            var total: u64 = 0;
            var index: usize = 0;
            while (index + 8 <= bytes.len) : (index += 8) {
                total += @popCount(@as(u64, @bitCast(bytes[index..][0..8].*)));
            }
            for (bytes[index..]) |byte| total += @popCount(byte);
            assert(total <= bytes.len * 8);
            return total;
        }

        /// The chunks in order, as the ring buffer's two contiguous segments (commonware's
        /// `VecDeque::as_slices`); the second is empty unless the chunks wrap.
        fn chunk_segments(self: *const Self) [2][]const Chunk {
            const deque = self.chunks;
            const head_len = @min(deque.len, deque.buffer.len - deque.head);
            const segments: [2][]const Chunk = .{
                deque.buffer[deque.head..][0..head_len],
                deque.buffer[0 .. deque.len - head_len],
            };
            assert(segments[0].len + segments[1].len == deque.len);
            return segments;
        }

        pub fn count_zeros(self: *const Self) u64 {
            return self.len() - self.count_ones();
        }

        // Indexing helpers.

        pub fn chunk_byte_bitmask(bit: u64) u8 {
            return @as(u8, 1) << @intCast(bit % 8);
        }

        pub fn chunk_byte_offset(bit: u64) usize {
            return @intCast((bit / 8) % N);
        }

        pub fn to_chunk_index(bit: u64) usize {
            return std.math.cast(usize, bit / CHUNK_SIZE_BITS) orelse
                @panic("chunk overflow: exceeds usize::MAX");
        }

        fn assert_bit(self: *const Self, bit: u64) void {
            if (bit >= self.bit_len) {
                std.debug.panic("bit {d} out of bounds (len: {d})", .{ bit, self.bit_len });
            }
        }

        // Iterators.

        pub const Iterator = struct {
            bitmap: *const Self,
            position: u64,

            pub fn next(it: *Iterator) ?bool {
                if (it.position >= it.bitmap.len()) return null;
                const bit = it.bitmap.get(it.position);
                it.position += 1;
                return bit;
            }

            pub fn remaining(it: *const Iterator) u64 {
                return it.bitmap.len() -| it.position;
            }
        };

        pub fn iter(self: *const Self) Iterator {
            return .{ .bitmap = self, .position = 0 };
        }

        pub const OnesIter = readable.OnesIter(Self, N);

        pub fn ones_iter(self: *const Self) OnesIter {
            return readable.ones_iter_from(N, self, 0);
        }

        pub fn ones_iter_from(self: *const Self, start: u64) OnesIter {
            return readable.ones_iter_from(N, self, start);
        }

        pub fn ones_iter_range(self: *const Self, start: u64, end: u64) OnesIter {
            return readable.ones_iter_range(N, self, start, end);
        }

        // Bitwise operations.

        fn binary_op(self: *Self, other: *const Self, comptime op: fn (u8, u8) u8) void {
            if (self.bit_len != other.bit_len) {
                std.debug.panic("BitMap lengths don't match: {d} vs {d}", .{
                    self.bit_len, other.bit_len,
                });
            }
            for (0..self.chunks.len) |index| {
                const a = self.chunks.atPtr(index);
                const b = other.chunks.atPtr(index);
                for (a, b) |*x, y| x.* = op(x.*, y);
            }
            _ = self.clear_trailing_bits();
        }

        pub fn @"and"(self: *Self, other: *const Self) void {
            self.binary_op(other, struct {
                fn f(a: u8, b: u8) u8 {
                    return a & b;
                }
            }.f);
        }

        pub fn @"or"(self: *Self, other: *const Self) void {
            self.binary_op(other, struct {
                fn f(a: u8, b: u8) u8 {
                    return a | b;
                }
            }.f);
        }

        pub fn xor(self: *Self, other: *const Self) void {
            self.binary_op(other, struct {
                fn f(a: u8, b: u8) u8 {
                    return a ^ b;
                }
            }.f);
        }

        /// Whether every bit in `[start, end)` is zero. `end` must be at most `len`.
        pub fn is_unset(self: *const Self, start: u64, end: u64) bool {
            if (end > self.bit_len) {
                std.debug.panic("range end {d} out of bounds (len: {d})", .{ end, self.bit_len });
            }
            if (start >= end) return true;
            const last = end - 1;
            const first_chunk = to_chunk_index(start);
            const last_chunk_index = to_chunk_index(last);
            for (first_chunk + 1..@max(first_chunk + 1, last_chunk_index)) |index| {
                if (!std.mem.eql(u8, self.chunks.atPtr(index), &EMPTY_CHUNK)) return false;
            }
            const start_byte = chunk_byte_offset(start);
            const end_byte = chunk_byte_offset(last);
            const start_mask: u8 = @truncate(@as(u16, 0xff) << @intCast(start % 8));
            const end_mask: u8 = @truncate(@as(u16, 0xff) >> @intCast(7 - last % 8));
            const first = self.chunks.atPtr(first_chunk);
            const single = first_chunk == last_chunk_index;
            const first_end = if (single) end_byte else N - 1;
            for (first[start_byte .. first_end + 1], start_byte..) |byte, index| {
                var mask: u8 = 0xff;
                if (index == start_byte) mask &= start_mask;
                if (single and index == end_byte) mask &= end_mask;
                if (byte & mask != 0) return false;
            }
            if (single) return true;
            const tail = self.chunks.atPtr(last_chunk_index);
            for (tail[0 .. end_byte + 1], 0..) |byte, index| {
                const mask: u8 = if (index == end_byte) end_mask else 0xff;
                if (byte & mask != 0) return false;
            }
            return true;
        }

        // Equality and formatting.

        pub fn eql(a: *const Self, b: *const Self) bool {
            if (a.bit_len != b.bit_len) return false;
            for (0..a.chunks.len) |index| {
                if (!std.mem.eql(u8, a.chunks.atPtr(index), b.chunks.atPtr(index))) return false;
            }
            return true;
        }

        /// `BitMap[0101...]`, eliding the middle of bitmaps longer than 64 bits.
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            const display_max = 64;
            try writer.writeAll("BitMap[");
            if (self.bit_len <= display_max) {
                try self.write_bits(writer, 0, self.bit_len);
            } else {
                try self.write_bits(writer, 0, display_max / 2);
                try writer.writeAll("...");
                try self.write_bits(writer, self.bit_len - display_max / 2, self.bit_len);
            }
            try writer.writeByte(']');
        }

        fn write_bits(self: Self, writer: *std.Io.Writer, start: u64, end: u64) !void {
            assert(start <= end and end <= self.bit_len);
            for (start..end) |bit| try writer.writeByte(if (self.get(bit)) '1' else '0');
        }

        // Codec.

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_int(u64, self.bit_len);
            for (self.chunk_segments()) |segment| writer.write_bytes(std.mem.sliceAsBytes(segment));
        }

        pub fn encode_size(self: Self) usize {
            return @sizeOf(u64) + self.chunks.len * N;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const bit_len = try reader.read_int(u64);
            if (!cfg.contains(bit_len)) return reader.fail(error.InvalidLength, bit_len);
            const count = std.math.cast(usize, std.math.divCeil(u64, bit_len, CHUNK_SIZE_BITS) catch
                unreachable) orelse return error.EndOfBuffer;
            // Reject a short payload before allocating anything for it.
            try reader.at_least_items(count, N);
            var result: Self = .{ .chunks = try .initCapacity(gpa, count), .bit_len = bit_len };
            errdefer result.deinit(gpa);
            for (0..count) |_| result.chunks.pushBackAssumeCapacity((try reader.take_array(N)).*);
            if (result.clear_trailing_bits()) {
                return reader.invalid("BitMap", "Invalid trailing bits in encoded data");
            }
            return result;
        }

        /// commonware's `Arbitrary`: up to 1024 bits, one arbitrary `bool` each.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const size = u.int_in_range(u64, 0, 1024);
            var result = try init_capacity(gpa, size);
            for (0..size) |_| try result.push(gpa, u.boolean());
            return result;
        }
    };
}

comptime {
    readable.assert_readable(BitMap(DEFAULT_CHUNK_SIZE));
}
