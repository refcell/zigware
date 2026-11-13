//! `Prunable(N)`: a `BitMap(N)` whose leading chunks can be pruned (commonware
//! `utils/src/bitmap/prunable.rs`).
//!
//! Positions stay absolute after pruning: `len` counts pruned bits, and pruned bits can no
//! longer be read or written. The encoding is the pruned chunk count as a big-endian `u64`
//! followed by the retained `BitMap`; the codec `Cfg` bounds the retained bits only.

const std = @import("std");
const codec = @import("codec");
const readable = @import("readable.zig");
const BitMap = @import("bitmap.zig").BitMap;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Error = error{
    /// `pruned_chunks * CHUNK_SIZE_BITS` overflows `u64`.
    PrunedChunksOverflow,
};

pub fn Prunable(comptime N: usize) type {
    return struct {
        bitmap: Bits = .empty,
        /// Chunks dropped from the front. Invariant:
        /// `pruned * CHUNK_SIZE_BITS + bitmap.len() <= maxInt(u64)`.
        pruned: usize = 0,

        const Self = @This();
        const Bits = BitMap(N);

        pub const Chunk = Bits.Chunk;
        pub const CHUNK_SIZE_BITS: u64 = Bits.CHUNK_SIZE_BITS;
        pub const Cfg = Bits.Cfg;
        pub const empty: Self = .{};

        /// An empty bitmap whose first `pruned_chunks` chunks are already pruned.
        pub fn init_pruned(pruned_chunks_count: usize) Error!Self {
            _ = std.math.mul(u64, pruned_chunks_count, CHUNK_SIZE_BITS) catch
                return error.PrunedChunksOverflow;
            return .{ .pruned = pruned_chunks_count };
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return .{ .bitmap = try self.bitmap.clone(gpa), .pruned = self.pruned };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.bitmap.deinit(gpa);
            self.* = undefined;
        }

        // Length.

        /// Bits including pruned ones.
        pub fn len(self: *const Self) u64 {
            return self.pruned_bits() + self.bitmap.len();
        }

        pub fn is_empty(self: *const Self) bool {
            return self.len() == 0;
        }

        pub fn is_chunk_aligned(self: *const Self) bool {
            return self.len() % CHUNK_SIZE_BITS == 0;
        }

        /// Chunks including pruned ones.
        pub fn chunks_len(self: *const Self) usize {
            return self.pruned + self.bitmap.chunks_len();
        }

        pub fn pruned_chunks(self: *const Self) usize {
            return self.pruned;
        }

        /// Fully written chunks, including pruned ones.
        pub fn complete_chunks(self: *const Self) usize {
            const partial = @intFromBool(!self.is_chunk_aligned());
            return self.pruned + (self.bitmap.chunks_len() -| partial);
        }

        pub fn pruned_bits(self: *const Self) u64 {
            return @as(u64, self.pruned) * CHUNK_SIZE_BITS;
        }

        // Getters.

        pub fn get_bit(self: *const Self, bit: u64) bool {
            self.assert_retained(bit);
            return self.bitmap.get(bit - self.pruned_bits());
        }

        pub fn get_chunk_containing(self: *const Self, bit: u64) *const Chunk {
            self.assert_retained(bit);
            return self.bitmap.get_chunk_containing(bit - self.pruned_bits());
        }

        pub fn get_bit_from_chunk(chunk: *const Chunk, bit: u64) bool {
            return Bits.get_bit_from_chunk(chunk, bit);
        }

        /// The last chunk and how many of its bits are in use.
        pub fn last_chunk(self: *const Self) struct { Chunk, u64 } {
            return self.bitmap.last_chunk();
        }

        /// The chunk at absolute index `chunk` (it must be retained).
        pub fn get_chunk(self: *const Self, chunk: usize) Chunk {
            if (chunk < self.pruned) {
                std.debug.panic("chunk {d} is pruned (pruned_chunks: {d})", .{
                    chunk, self.pruned,
                });
            }
            return self.bitmap.get_chunk(chunk - self.pruned);
        }

        // Setters.

        pub fn set_bit(self: *Self, bit: u64, value: bool) void {
            self.assert_retained(bit);
            self.bitmap.set(bit - self.pruned_bits(), value);
        }

        pub fn push(self: *Self, gpa: Allocator, bit: bool) Allocator.Error!void {
            try self.bitmap.push(gpa, bit);
        }

        /// Grows to `new_len` total bits with zeros; a smaller `new_len` is a no-op.
        pub fn extend_to(self: *Self, gpa: Allocator, new_len: u64) Allocator.Error!void {
            if (new_len <= self.len()) return;
            try self.bitmap.extend_to(gpa, new_len - self.pruned_bits());
            assert(self.len() == new_len);
        }

        pub fn pop(self: *Self) bool {
            return self.bitmap.pop();
        }

        /// Shrinks to `new_len` total bits; `new_len` must not reach into the pruned bits.
        pub fn truncate(self: *Self, new_len: u64) void {
            if (new_len < self.pruned_bits()) @panic("cannot truncate into pruned region");
            self.bitmap.truncate(new_len - self.pruned_bits());
        }

        pub fn push_byte(self: *Self, gpa: Allocator, byte: u8) Allocator.Error!void {
            try self.bitmap.push_byte(gpa, byte);
        }

        pub fn push_chunk(self: *Self, gpa: Allocator, chunk: *const Chunk) Allocator.Error!void {
            try self.bitmap.push_chunk(gpa, chunk);
        }

        pub fn extend_from_bitmap(
            self: *Self,
            gpa: Allocator,
            comptime M: usize,
            other: *const BitMap(M),
        ) Allocator.Error!void {
            try self.bitmap.extend_from_bitmap(gpa, M, other);
        }

        pub fn pop_chunk(self: *Self) Chunk {
            return self.bitmap.pop_chunk();
        }

        // Pruning.

        /// Prunes every chunk before the one containing `bit` (`bit <= len`); pruning to an
        /// already pruned position is a no-op.
        pub fn prune_to_bit(self: *Self, bit: u64) void {
            if (bit > self.len()) {
                std.debug.panic("bit {d} out of bounds (len: {d})", .{ bit, self.len() });
            }
            const chunk = to_chunk_index(bit);
            if (chunk < self.pruned) return;
            self.bitmap.prune_chunks(chunk - self.pruned);
            self.pruned = chunk;
            assert(self.pruned_bits() <= bit);
        }

        /// Overwrites the retained chunk at absolute index `chunk_index`. In the last partial
        /// chunk, bits past `len` must be zero (the codec rejects them).
        pub fn set_chunk_by_index(self: *Self, chunk_index: usize, chunk: *const Chunk) void {
            if (chunk_index < self.pruned) {
                std.debug.panic("cannot set pruned chunk {d} (pruned_chunks: {d})", .{
                    chunk_index, self.pruned,
                });
            }
            const index = chunk_index - self.pruned;
            const trailing = self.bitmap.len() % CHUNK_SIZE_BITS;
            if (index + 1 == self.bitmap.chunks_len() and trailing != 0) {
                const last_byte: usize = @intCast((trailing - 1) / 8);
                const bits_in_last_byte: u3 = @intCast(trailing % 8);
                const byte_mask: u8 = if (bits_in_last_byte != 0)
                    ~((@as(u8, 1) << bits_in_last_byte) - 1)
                else
                    0;
                const tail_zero = std.mem.allEqual(u8, chunk[last_byte + 1 ..], 0);
                if (chunk[last_byte] & byte_mask != 0 or !tail_zero) {
                    @panic("non-zero bits beyond bitmap length");
                }
            }
            self.bitmap.set_chunk_by_index(index, chunk);
        }

        /// Restores pruned chunks to the front. `chunks` is in reverse order: to restore
        /// chunks 0, 1, 2 pass them as 2, 1, 0.
        pub fn unprune_chunks(
            self: *Self,
            gpa: Allocator,
            chunks: []const Chunk,
        ) Allocator.Error!void {
            if (chunks.len > self.pruned) {
                std.debug.panic("cannot unprune {d} chunks (only {d} pruned)", .{
                    chunks.len, self.pruned,
                });
            }
            for (chunks) |*chunk| try self.bitmap.prepend_chunk(gpa, chunk);
            self.pruned -= chunks.len;
        }

        // Indexing helpers.

        pub fn chunk_byte_bitmask(bit: u64) u8 {
            return Bits.chunk_byte_bitmask(bit);
        }

        pub fn chunk_byte_offset(bit: u64) usize {
            return Bits.chunk_byte_offset(bit);
        }

        pub fn to_chunk_index(bit: u64) usize {
            return Bits.to_chunk_index(bit);
        }

        fn assert_retained(self: *const Self, bit: u64) void {
            if (to_chunk_index(bit) < self.pruned) std.debug.panic("bit pruned: {d}", .{bit});
        }

        // Iterators (the `Readable` provided methods).

        pub const OnesIter = readable.OnesIter(Self, N);

        pub fn ones_iter_from(self: *const Self, start: u64) OnesIter {
            return readable.ones_iter_from(N, self, start);
        }

        pub fn ones_iter_range(self: *const Self, start: u64, end: u64) OnesIter {
            return readable.ones_iter_range(N, self, start, end);
        }

        // Codec.

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_int(u64, self.pruned);
            self.bitmap.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return @sizeOf(u64) + self.bitmap.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const pruned_count = try reader.read_int(u64);
            const pruned_bits_count = std.math.mul(u64, pruned_count, CHUNK_SIZE_BITS) catch
                return reader.invalid(
                    "Prunable",
                    "pruned_chunks would overflow when computing pruned_bits",
                );
            const pruned = std.math.cast(usize, pruned_count) orelse
                return reader.invalid("Prunable", "pruned_chunks doesn't fit in usize");
            var bitmap = try Bits.read(gpa, reader, cfg);
            errdefer bitmap.deinit(gpa);
            _ = std.math.add(u64, pruned_bits_count, bitmap.len()) catch return reader.invalid(
                "Prunable",
                "total bitmap length (pruned + unpruned) would overflow u64",
            );
            return .{ .bitmap = bitmap, .pruned = pruned };
        }

        /// commonware's `Arbitrary`: an arbitrary `BitMap`, pruned to an arbitrary bit.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            var result: Self = .{ .bitmap = try Bits.arbitrary(gpa, u) };
            result.prune_to_bit(u.int_in_range(u64, 0, result.len()));
            return result;
        }
    };
}

comptime {
    readable.assert_readable(Prunable(8));
}
