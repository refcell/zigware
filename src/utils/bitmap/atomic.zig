//! A fixed-length bitmap whose bits can be set concurrently through shared pointers
//! (commonware `utils/src/bitmap/atomic.rs`).
//!
//! `set` uses monotonic (relaxed) ordering, published by ownership transfer rather than by the
//! operations themselves: the bits are read back only by consuming the map (`into_bitmap`), so
//! whatever reclaims exclusive ownership from the setters (awaiting their tasks) is what makes
//! their writes visible.

const std = @import("std");
const bitmap = @import("bitmap.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const word_bits: u64 = 64;
const BitMap = bitmap.BitMap(bitmap.DEFAULT_CHUNK_SIZE);

comptime {
    // One word is one default chunk, so words convert to chunks byte for byte.
    assert(BitMap.CHUNK_SIZE_BITS == word_bits);
}

pub const Atomic = struct {
    /// Bit `i` is bit `i % 64` of word `i / 64`; bits at or past `len` stay zero.
    words: []std.atomic.Value(u64),
    len: u64,

    /// A bitmap of `len` zero bits.
    pub fn zeroes(gpa: Allocator, len: u64) Allocator.Error!Atomic {
        const count = std.math.cast(usize, std.math.divCeil(u64, len, word_bits) catch
            unreachable) orelse return error.OutOfMemory; // The divisor is a constant.
        const words = try gpa.alloc(std.atomic.Value(u64), count);
        @memset(words, .init(0));
        return .{ .words = words, .len = len };
    }

    /// Frees the bitmap without converting it.
    pub fn deinit(self: *Atomic, gpa: Allocator) void {
        gpa.free(self.words);
        self.* = undefined;
    }

    /// Sets `bit` to 1; panics if the bit does not exist.
    pub fn set(self: *const Atomic, bit: u64) void {
        if (bit >= self.len) {
            std.debug.panic("bit {d} out of bounds (len: {d})", .{ bit, self.len });
        }
        const mask = @as(u64, 1) << @intCast(bit % word_bits);
        _ = self.words[@intCast(bit / word_bits)].fetchOr(mask, .monotonic);
    }

    /// Converts into a `BitMap` holding the same bits, consuming `self`.
    pub fn into_bitmap(self: *Atomic, gpa: Allocator) Allocator.Error!BitMap {
        var result = try BitMap.zeroes(gpa, self.len);
        assert(result.chunks.len == self.words.len);
        for (self.words, 0..) |*word, index| {
            std.mem.writeInt(u64, result.chunks.atPtr(index), word.raw, .little);
        }
        self.deinit(gpa);
        return result;
    }
};

const testing = std.testing;
const gpa_test = testing.allocator;

test "atomic: into_bitmap matches plain sets" {
    for ([_]u64{ 0, 1, 63, 64, 65, 128, 200 }) |len| {
        var atomic = try Atomic.zeroes(gpa_test, len);
        var expected = try BitMap.zeroes(gpa_test, len);
        defer expected.deinit(gpa_test);
        var bit: u64 = 0;
        while (bit < len) : (bit += 3) {
            atomic.set(bit);
            expected.set(bit, true);
        }
        if (len > 0) {
            atomic.set(len - 1);
            expected.set(len - 1, true);
        }
        var actual = try atomic.into_bitmap(gpa_test);
        defer actual.deinit(gpa_test);
        try testing.expect(actual.eql(&expected));
    }
}

fn set_stripe(atomic: *const Atomic, stripe: u64) void {
    var bit = stripe;
    while (bit < atomic.len) : (bit += 4) atomic.set(bit);
}

test "atomic: shared setters" {
    var atomic = try Atomic.zeroes(gpa_test, 1000);
    var group: std.Io.Group = .init;
    for (0..4) |stripe| group.async(testing.io, set_stripe, .{ &atomic, @as(u64, stripe) });
    try group.await(testing.io);
    var actual = try atomic.into_bitmap(gpa_test);
    defer actual.deinit(gpa_test);
    var expected = try BitMap.ones(gpa_test, 1000);
    defer expected.deinit(gpa_test);
    try testing.expect(actual.eql(&expected));
}

const death = @import("../death.zig");

test "atomic: set past len panics" {
    // commonware `bitmap/atomic.rs test_set_past_len_panics` (#[should_panic]).
    try death.expect_panic(@src(), "bit 64 out of bounds (len: 64)", struct {
        fn body() !void {
            var bits = try Atomic.zeroes(gpa_test, 64);
            defer bits.deinit(gpa_test);
            bits.set(64);
        }
    }.body);
}

test "atomic: set past len in the tail word panics" {
    // commonware `bitmap/atomic.rs test_set_past_len_in_tail_word_panics` (#[should_panic]).
    try death.expect_panic(@src(), "bit 70 out of bounds (len: 65)", struct {
        fn body() !void {
            var bits = try Atomic.zeroes(gpa_test, 65);
            defer bits.deinit(gpa_test);
            bits.set(70);
        }
    }.body);
}

test "atomic: set on empty panics" {
    // commonware `bitmap/atomic.rs test_set_on_empty_panics` (#[should_panic]).
    try death.expect_panic(@src(), "bit 0 out of bounds (len: 0)", struct {
        fn body() !void {
            var bits = try Atomic.zeroes(gpa_test, 0);
            defer bits.deinit(gpa_test);
            bits.set(0);
        }
    }.body);
}
