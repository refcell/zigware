//! Primitive key translators: map a key to a smaller representation for an index.
//!
//! Port of commonware's `storage/src/translator.rs`. A translator is a comptime interface: a
//! type with
//!
//! - `pub const Key: type`, the translated representation;
//! - `pub const ordered: bool`, true when `transform` preserves lexicographic key order
//!   (commonware's `OrderedTranslator`), which ordered indices rely on;
//! - `pub fn transform(self, key: []const u8) Key`;
//! - `pub fn hash(self, key: Key) u64`, the bucket hash for a hash table keyed by `Key`
//!   (commonware's `BuildHasher` impl, which hashes with `UintIdentity`);
//! - `pub fn order(a: Key, b: Key) std.math.Order` and `pub fn eql(a: Key, b: Key) bool`.
//!
//! `check` asserts a type implements it.

const std = @import("std");
const utils = @import("utils");
const assert = std.debug.assert;

/// Mixing constant (`commonware_utils::GOLDEN_RATIO`), the 64-bit golden ratio.
const golden_ratio: u64 = utils.GOLDEN_RATIO;
comptime {
    assert(golden_ratio == 0x9e37_79b9_7f4a_7c15);
}

/// Asserts at comptime that `T` implements the translator interface.
pub fn check(comptime T: type) void {
    comptime {
        assert(@hasDecl(T, "Key"));
        assert(@TypeOf(T.ordered) == bool);
        assert(@hasDecl(T, "transform"));
        assert(@hasDecl(T, "hash"));
        assert(@hasDecl(T, "order"));
        assert(@hasDecl(T, "eql"));
    }
}

/// A lightweight hasher for translated integer keys. Translated keys are usually already
/// hashed, so rehashing them would waste CPU: integer writes copy the value, and `finish`
/// multiplies it by `golden_ratio` to spread low bits into the high bits a hash table uses.
pub const UintIdentity = struct {
    value: u64 = 0,

    /// Writes at most 8 bytes, read as a little-endian integer (zero-padded on the right).
    pub fn write(self: *UintIdentity, bytes: []const u8) void {
        assert(bytes.len <= 8); // UintIdentity hasher cannot handle >8 bytes.
        var word: [8]u8 = @splat(0);
        @memcpy(word[0..bytes.len], bytes);
        self.value = std.mem.readInt(u64, &word, .little);
    }

    pub fn write_u8(self: *UintIdentity, value: u8) void {
        self.value = value;
    }

    pub fn write_u16(self: *UintIdentity, value: u16) void {
        self.value = value;
    }

    pub fn write_u32(self: *UintIdentity, value: u32) void {
        self.value = value;
    }

    pub fn write_u64(self: *UintIdentity, value: u64) void {
        self.value = value;
    }

    pub fn finish(self: UintIdentity) u64 {
        return self.value *% golden_ratio;
    }
};

/// Copies `key` into an `n`-byte array: zero-padded if shorter, truncated if longer.
fn cap(comptime n: usize, key: []const u8) [n]u8 {
    comptime assert(n > 0);
    var capped: [n]u8 = @splat(0);
    const len = @min(key.len, n);
    @memcpy(capped[0..len], key[0..len]);
    assert(len <= n);
    return capped;
}

/// A translator that caps a key to `@sizeOf(Int)` bytes, packed big-endian into `Int`.
/// Truncation, zero-padding, and big-endian packing preserve key order.
fn IntCap(comptime Int: type) type {
    comptime assert(@typeInfo(Int).int.signedness == .unsigned);
    comptime assert(@bitSizeOf(Int) % 8 == 0 and @bitSizeOf(Int) <= 64);
    return struct {
        const Self = @This();
        pub const Key = Int;
        pub const ordered = true;

        pub fn transform(_: Self, key: []const u8) Key {
            const capped = cap(@sizeOf(Int), key);
            return std.mem.readInt(Int, &capped, .big);
        }

        pub fn hash(_: Self, key: Key) u64 {
            var hasher: UintIdentity = .{};
            hasher.write_u64(key);
            return hasher.finish();
        }

        pub fn order(a: Key, b: Key) std.math.Order {
            return std.math.order(a, b);
        }

        pub fn eql(a: Key, b: Key) bool {
            return a == b;
        }
    };
}

pub const OneCap = IntCap(u8);
pub const TwoCap = IntCap(u16);
pub const FourCap = IntCap(u32);
pub const EightCap = IntCap(u64);

/// A fixed-size byte array key, hashed without a length prefix.
pub fn UnhashedArray(comptime n: usize) type {
    comptime assert(n > 0);
    return struct {
        const Self = @This();
        inner: [n]u8,

        /// The array as a big-endian integer, zero-padded on the right. Requires `n <= 8`.
        fn word(self: Self) u64 {
            comptime assert(n <= 8);
            var bytes: [8]u8 = @splat(0);
            @memcpy(bytes[0..n], &self.inner);
            return std.mem.readInt(u64, &bytes, .big);
        }

        /// Orders like the bytes; arrays that fit in a word compare as one integer.
        pub fn order(a: Self, b: Self) std.math.Order {
            if (n <= 8) return std.math.order(a.word(), b.word());
            return std.mem.order(u8, &a.inner, &b.inner);
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u8, &a.inner, &b.inner);
        }

        /// Hashes like commonware: one `write` of the bytes into `UintIdentity`.
        pub fn hash(self: Self) u64 {
            var hasher: UintIdentity = .{};
            hasher.write(&self.inner);
            return hasher.finish();
        }
    };
}

/// A translator for keys that are not the width of a standard integer: caps keys to `n`
/// bytes (1 to 8). Order-preserving.
pub fn Cap(comptime n: usize) type {
    comptime assert(n > 0 and n <= 8); // Cap must be between 1 and 8.
    return struct {
        const Self = @This();
        pub const Key = UnhashedArray(n);
        pub const ordered = true;

        pub fn transform(_: Self, key: []const u8) Key {
            return .{ .inner = cap(n, key) };
        }

        pub fn hash(_: Self, key: Key) u64 {
            return key.hash();
        }

        pub fn order(a: Key, b: Key) std.math.Order {
            return Key.order(a, b);
        }

        pub fn eql(a: Key, b: Key) bool {
            return Key.eql(a, b);
        }
    };
}

/// Collision-resistant wrapper for any translator: hashes the full key with a per-instance
/// secret seed before delegating to `Inner`, so translated-key collisions are unpredictable
/// to an adversary who does not know the seed. Hashing destroys key order, so `Hashed` is
/// never `ordered`.
///
/// Commonware uses `ahash`, whose output is not stable across versions; zigware uses
/// `std.hash.Wyhash`. Either way the output is an in-memory hardening mechanism, never a
/// persisted encoding, so the two need not agree.
pub fn Hashed(comptime Inner: type) type {
    check(Inner);
    return struct {
        const Self = @This();
        pub const Key = Inner.Key;
        pub const ordered = false;

        seed: u64,
        inner: Inner,

        /// A translator with a specific seed (deterministic, for tests).
        pub fn from_seed(seed: u64, inner: Inner) Self {
            return .{ .seed = seed, .inner = inner };
        }

        /// A translator with a seed drawn from the runtime's randomness.
        pub fn init_random(random: std.Random, inner: Inner) Self {
            return .{ .seed = random.int(u64), .inner = inner };
        }

        pub fn transform(self: Self, key: []const u8) Key {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, std.hash.Wyhash.hash(self.seed, key), .little);
            return self.inner.transform(&bytes);
        }

        pub fn hash(self: Self, key: Key) u64 {
            return self.inner.hash(key);
        }

        pub fn order(a: Key, b: Key) std.math.Order {
            return Inner.order(a, b);
        }

        pub fn eql(a: Key, b: Key) bool {
            return Inner.eql(a, b);
        }
    };
}

comptime {
    check(OneCap);
    check(TwoCap);
    check(FourCap);
    check(EightCap);
    check(Cap(3));
    check(Hashed(TwoCap));
}

const testing = std.testing;

test "one cap" {
    const t: OneCap = .{};
    try testing.expectEqual(@as(u8, 0), t.transform(""));
    try testing.expectEqual(@as(u8, 'a'), t.transform("a"));
    try testing.expectEqual(@as(u8, 'a'), t.transform("ab"));
    try testing.expectEqual(@as(u8, 'a'), t.transform("abc"));
}

test "two cap" {
    const t: TwoCap = .{};
    try testing.expectEqual(@as(u16, 0), t.transform(""));
    try testing.expectEqual(t.transform("ab"), t.transform("abc"));
    try testing.expect(t.transform("") < t.transform("a"));
    try testing.expect(t.transform("a") < t.transform("b"));
    try testing.expect(t.transform("ab") < t.transform("ac"));
    try testing.expect(t.transform("z") < t.transform("zz"));
    try testing.expectEqual(t.transform("zz"), t.transform("zzabc"));
}

test "four cap" {
    const t: FourCap = .{};
    const t1 = t.transform("");
    const t2 = t.transform("a");
    const t3 = t.transform("abcd");
    const t4 = t.transform("abcdef");
    const t5 = t.transform("b");
    try testing.expectEqual(@as(u32, 0), t1);
    try testing.expect(t1 < t2);
    try testing.expect(t2 < t3);
    try testing.expectEqual(t3, t4);
    try testing.expect(t3 < t5);
    try testing.expect(t4 < t5);
}

test "eight cap" {
    const t: EightCap = .{};
    const t1 = t.transform("");
    const t2 = t.transform("a");
    const t3 = t.transform("abcdefghaaaaaaa");
    const t4 = t.transform("abcdefghijkzzzzzzzzzzzzzzzzzz");
    const t5 = t.transform("b");
    try testing.expectEqual(@as(u64, 0), t1);
    try testing.expect(t1 < t2);
    try testing.expect(t2 < t3);
    try testing.expectEqual(t3, t4);
    try testing.expect(t3 < t5);
    try testing.expect(t4 < t5);
}

fn check_unhashed_array_order(comptime n: usize, rng: *utils.rng.TestRng) !void {
    const Array = UnhashedArray(n);
    var arrays: [204]Array = undefined;
    for (arrays[0..200]) |*array| rng.fill_bytes(&array.inner);
    var last: [n]u8 = @splat(0xab);
    arrays[200] = .{ .inner = last };
    last[n - 1] = 0xac;
    arrays[201] = .{ .inner = last };
    arrays[202] = .{ .inner = @splat(0xff) };
    arrays[203] = .{ .inner = @splat(0) };
    for (arrays) |a| {
        for (arrays) |b| {
            try testing.expectEqual(std.mem.order(u8, &a.inner, &b.inner), Array.order(a, b));
        }
    }
}

test "unhashed array orders like its bytes" {
    var rng = utils.test_rng();
    inline for (.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 }) |n| try check_unhashed_array_order(n, &rng);
}

test "cap 3" {
    const t: Cap(3) = .{};
    try testing.expectEqual(@as([3]u8, @splat(0)), t.transform("").inner);
    try testing.expectEqual("abc".*, t.transform("abc").inner);
    try testing.expectEqual("abc".*, t.transform("abcdef").inner);
    try testing.expectEqual([_]u8{ 'a', 'b', 0 }, t.transform("ab").inner);
}

test "cap 6" {
    const t: Cap(6) = .{};
    try testing.expectEqual(@as([6]u8, @splat(0)), t.transform("").inner);
    try testing.expectEqual("abcdef".*, t.transform("abcdef").inner);
    try testing.expectEqual("abcdef".*, t.transform("abcdefghi").inner);
    try testing.expectEqual([_]u8{ 'a', 'b', 'c', 0, 0, 0 }, t.transform("abc").inner);
}

const ordering_key_count = 10_000;
const ordering_key_len_max = 10;
const OrderingKey = struct {
    len: u8,
    bytes: [ordering_key_len_max]u8,

    fn slice(self: *const OrderingKey) []const u8 {
        return self.bytes[0..self.len];
    }

    fn less_than(_: void, a: OrderingKey, b: OrderingKey) bool {
        return std.mem.order(u8, a.slice(), b.slice()) == .lt;
    }
};

/// Asserts that `t` maps byte-sorted keys to non-decreasing translated keys.
fn assert_order_preserving(comptime T: type, t: T, keys: []OrderingKey) !void {
    comptime assert(T.ordered);
    for (keys[0 .. keys.len - 1], keys[1..]) |a, b| {
        try testing.expect(T.order(t.transform(a.slice()), t.transform(b.slice())) != .gt);
    }
}

test "cap translators preserve order" {
    // A small alphabet makes shared prefixes, zero padding, and high bytes common.
    const alphabet = [_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff };
    var rng = utils.test_rng();
    const keys = try testing.allocator.alloc(OrderingKey, ordering_key_count);
    defer testing.allocator.free(keys);
    for (keys) |*key| {
        key.len = utils.rng.range_at_most(&rng, u8, 0, ordering_key_len_max);
        for (key.bytes[0..key.len]) |*byte| {
            byte.* = alphabet[utils.rng.range_less_than(&rng, usize, 0, alphabet.len)];
        }
    }
    std.mem.sort(OrderingKey, keys, {}, OrderingKey.less_than);
    try assert_order_preserving(OneCap, .{}, keys);
    try assert_order_preserving(TwoCap, .{}, keys);
    try assert_order_preserving(FourCap, .{}, keys);
    try assert_order_preserving(EightCap, .{}, keys);
    try assert_order_preserving(Cap(1), .{}, keys);
    try assert_order_preserving(Cap(3), .{}, keys);
    try assert_order_preserving(Cap(5), .{}, keys);
    try assert_order_preserving(Cap(8), .{}, keys);
}

fn identity_hash_bytes(bytes: []const u8) u64 {
    var hasher: UintIdentity = .{};
    hasher.write(bytes);
    return hasher.finish();
}

test "identity hasher small slices differ" {
    try testing.expect(identity_hash_bytes("abc") != identity_hash_bytes("abd"));
    try testing.expect(identity_hash_bytes("a") != identity_hash_bytes("b"));
    try testing.expect(identity_hash_bytes("") != identity_hash_bytes("a"));
}

test "identity hasher sets high bits" {
    for ([_]u64{ 1, 7, 17, 255 }) |value| {
        var hasher: UintIdentity = .{};
        hasher.write_u64(value);
        try testing.expect(hasher.finish() >> 57 != 0);
    }
}

test "identity hasher integer writes differ" {
    var h8: UintIdentity = .{};
    var h16: UintIdentity = .{};
    var h32: UintIdentity = .{};
    var h64: UintIdentity = .{};
    h8.write_u8(7);
    h16.write_u16(7);
    h32.write_u32(7);
    h64.write_u64(7);
    try testing.expectEqual(h8.finish(), h16.finish());
    try testing.expectEqual(h16.finish(), h32.finish());
    try testing.expectEqual(h32.finish(), h64.finish());
    var zero: UintIdentity = .{};
    zero.write_u8(0);
    try testing.expect(zero.finish() != h8.finish());
    // 0 and 1 hash apart at every write width.
    inline for (.{ u8, u16, u32, u64 }) |Int| {
        var h0: UintIdentity = .{};
        var h1: UintIdentity = .{};
        @field(UintIdentity, "write_" ++ @typeName(Int))(&h0, 0);
        @field(UintIdentity, "write_" ++ @typeName(Int))(&h1, 1);
        try testing.expect(h0.finish() != h1.finish());
    }
}

test "hashed consistency and seed determinism" {
    const t = Hashed(TwoCap).from_seed(42, .{});
    try testing.expectEqual(t.transform("hello"), t.transform("hello"));
    try testing.expectEqual(t.transform(""), t.transform(""));
    try testing.expectEqual(t.transform("abcdef"), t.transform("abcdef"));
    const t2 = Hashed(TwoCap).from_seed(42, .{});
    try testing.expectEqual(t.transform("hello"), t2.transform("hello"));
    try testing.expectEqual(t.transform("world"), t2.transform("world"));
}

test "hashed seed independence and prefix collisions avoided" {
    const t1 = Hashed(EightCap).from_seed(1, .{});
    const t2 = Hashed(EightCap).from_seed(2, .{});
    try testing.expect(t1.transform("hello") != t2.transform("hello"));
    const t = Hashed(TwoCap).from_seed(99, .{});
    try testing.expect(t.transform("abXXX") != t.transform("abYYY"));
}

test "hashed all cap sizes" {
    const t1 = Hashed(OneCap).from_seed(7, .{});
    try testing.expectEqual(t1.transform("test"), t1.transform("test"));
    const t4 = Hashed(FourCap).from_seed(7, .{});
    try testing.expectEqual(t4.transform("test"), t4.transform("test"));
    const t8 = Hashed(EightCap).from_seed(7, .{});
    try testing.expectEqual(t8.transform("test"), t8.transform("test"));
    const tc = Hashed(Cap(3)).from_seed(7, .{});
    try testing.expect(Cap(3).eql(tc.transform("test"), tc.transform("test")));
}

test "hashed random seed" {
    var rng = utils.rng.TestRng.init(3);
    const a = Hashed(EightCap).init_random(utils.rng.random(&rng), .{});
    const b = Hashed(EightCap).init_random(utils.rng.random(&rng), .{});
    try testing.expect(a.transform("hello") != b.transform("hello"));
}
