//! A Bloom filter (commonware `cryptography/src/bloomfilter`).
//!
//! `k` bit indices come from one digest with the Kirsch-Mitzenmacher optimization:
//! `h_i(x) = (h1 + i * h2) mod m`, where `h1` and `h2` are the digest's first two big-endian
//! `u64`s and `h2` is forced odd. The bit count is a power of two, so `mod m` is a mask.
//!
//! Encoded as the hasher count (`u8`), then the bits as a `BitMap` (big-endian `u64` bit
//! length, then 8-byte chunks).
//!
//! The rational-arithmetic parts (`with_rate`, `optimal_bits`, `optimal_hashers`, and the
//! estimates) wait for `utils.rational` (commonware `BigRationalExt::log2_floor`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const Sha256 = @import("sha256.zig").Sha256;

const BitMap = utils.bitmap.DefaultBitMap;

/// A Bloom filter hashing items with `H`, whose digest must be at least 16 bytes. Use a
/// cryptographic, unkeyed hasher when items are untrusted or the filter must be
/// deterministic across machines; `Sha256` is the default (`BloomFilter(Sha256)`).
pub fn BloomFilter(comptime H: type) type {
    comptime assert(H.Digest.fixed_size >= 16);
    return struct {
        const Self = @This();

        /// The number of hash functions, never zero.
        hashers: u8,
        /// The filter bits; the length is a power of two.
        bits: BitMap,

        /// The hasher count and the exact bit count the decoded filter must have.
        pub const Cfg = struct { hashers: u8, bits: u64 };

        /// A filter with `hashers` hash functions and `bits` bits rounded up to a power of
        /// two (2^63 when that would overflow).
        pub fn init(gpa: Allocator, hashers: u8, bits: u64) Allocator.Error!Self {
            assert(hashers > 0);
            assert(bits > 0);
            const length = std.math.ceilPowerOfTwo(u64, bits) catch 1 << 63;
            assert(std.math.isPowerOfTwo(length));
            return .{ .hashers = hashers, .bits = try BitMap.zeroes(gpa, length) };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.bits.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return .{ .hashers = self.hashers, .bits = try self.bits.clone(gpa) };
        }

        /// The number of bits.
        pub fn bit_count(self: *const Self) u64 {
            return self.bits.len();
        }

        /// The bit indices of `item`, written to `out` (one per hasher).
        fn indices(self: *const Self, item: []const u8, out: []u64) void {
            assert(out.len == self.hashers);
            const length = self.bits.len();
            assert(std.math.isPowerOfTwo(length));
            const digest = H.hash(&.{item});
            const h1 = std.mem.readInt(u64, digest.bytes[0..8], .big);
            // An odd `h2` keeps the hashers from all landing on `h1`.
            const h2 = std.mem.readInt(u64, digest.bytes[8..16], .big) | 1;
            const mask = length - 1;
            for (out, 0..) |*index, hasher| {
                index.* = (h1 +% @as(u64, hasher) *% h2) & mask;
            }
        }

        /// Inserts `item`.
        pub fn insert(self: *Self, item: []const u8) void {
            var buffer: [std.math.maxInt(u8)]u64 = undefined;
            const out = buffer[0..self.hashers];
            self.indices(item, out);
            for (out) |index| self.bits.set(index, true);
            assert(self.contains(item));
        }

        /// Whether `item` is possibly in the filter: false means it certainly is not.
        pub fn contains(self: *const Self, item: []const u8) bool {
            var buffer: [std.math.maxInt(u8)]u64 = undefined;
            const out = buffer[0..self.hashers];
            self.indices(item, out);
            for (out) |index| {
                if (!self.bits.get(index)) return false;
            }
            return true;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.hashers == b.hashers and a.bits.eql(&b.bits);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(u8, self.hashers, writer);
            self.bits.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return 1 + self.bits.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            assert(cfg.hashers > 0);
            assert(cfg.bits > 0);
            if (!std.math.isPowerOfTwo(cfg.bits)) {
                return reader.invalid("BloomFilter", "bits must be a power of 2");
            }
            const hashers = try reader.read_int(u8);
            if (hashers != cfg.hashers) {
                return reader.invalid("BloomFilter", "hashers doesn't match config");
            }
            const range = codec.RangeCfg(u64).exact(cfg.bits);
            return .{ .hashers = hashers, .bits = try BitMap.read(gpa, reader, range) };
        }

        /// commonware's `Arbitrary`: a non-zero hasher count (zero becomes one), then
        /// `next_power_of_two(int_in_range(0..=u16::MAX))` arbitrary bits.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const hashers = @max(u.int(u8), 1);
            const raw = u.int_in_range(u64, 0, std.math.maxInt(u16));
            const length = std.math.ceilPowerOfTwo(u64, @max(raw, 1)) catch unreachable;
            var bits = try BitMap.init_capacity(gpa, length);
            errdefer bits.deinit(gpa);
            for (0..length) |_| try bits.push(gpa, u.boolean());
            assert(bits.len() == length);
            return .{ .hashers = hashers, .bits = bits };
        }
    };
}

/// The default filter, over SHA-256.
pub const Default = BloomFilter(Sha256);

test {
    _ = @import("bloomfilter_test.zig");
}
