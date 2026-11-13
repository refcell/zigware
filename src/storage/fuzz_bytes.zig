//! Fuzz input helpers shared by storage's fuzz tests.
//!
//! Each fuzz target decodes its operations from a byte string, as commonware's targets do
//! with `arbitrary`. The same decoder runs under `std.testing.fuzz` (bytes from the fuzzer)
//! and under the seeded fuzz in `zig build test` (bytes from a seeded PRNG), so a failing
//! seed and a failing fuzzer input reproduce through the same code.

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");

/// Reads integers from a byte string; reads past the end return zero, like `arbitrary`.
pub const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    /// True once every byte has been consumed.
    pub fn done(self: *const Reader) bool {
        assert(self.offset <= self.bytes.len);
        return self.offset == self.bytes.len;
    }

    pub fn int(self: *Reader, comptime T: type) T {
        comptime assert(@typeInfo(T).int.signedness == .unsigned);
        const size = @sizeOf(T);
        var buffer: [size]u8 = @splat(0);
        const available = @min(size, self.bytes.len - self.offset);
        @memcpy(buffer[0..available], self.bytes[self.offset..][0..available]);
        self.offset += available;
        assert(self.offset <= self.bytes.len);
        return @truncate(std.mem.readInt(@Int(.unsigned, size * 8), &buffer, .little));
    }

    /// A value in `[0, bound)`.
    pub fn below(self: *Reader, bound: u64) u64 {
        assert(bound > 0);
        const value = self.int(u64) % bound;
        assert(value < bound);
        return value;
    }

    pub fn boolean(self: *Reader) bool {
        return self.int(u8) & 1 == 1;
    }
};

/// The number of seeded iterations for a target whose default is `base`.
pub fn iterations(base: u32) u32 {
    assert(base > 0);
    assert(build_options.fuzz_soak > 0);
    return base * build_options.fuzz_soak;
}

/// The seed for a target, mixed with `-Dfuzz-seed`.
pub fn seed(base: u64) u64 {
    return base ^ build_options.fuzz_seed;
}

/// Runs `run_one(bytes)` on `iterations(base_iterations)` seeded random byte strings of up
/// to `len_max` bytes. On failure, prints the seed and iteration that reproduce it.
pub fn seeded(
    comptime len_max: usize,
    base_seed: u64,
    base_iterations: u32,
    comptime run_one: fn ([]const u8) anyerror!void,
) !void {
    comptime assert(len_max > 0);
    const target_seed = seed(base_seed);
    var prng = std.Random.DefaultPrng.init(target_seed);
    const random = prng.random();
    var buffer: [len_max]u8 = undefined;
    const count = iterations(base_iterations);
    for (0..count) |iteration| {
        const len = random.uintAtMost(usize, len_max);
        random.bytes(buffer[0..len]);
        run_one(buffer[0..len]) catch |err| {
            std.debug.print("fuzz failure: seed={d} iteration={d}\n", .{ target_seed, iteration });
            return err;
        };
    }
}

/// Adapts `run_one(bytes)` to `std.testing.fuzz`: the fuzzer's input is the byte string.
pub fn smith(
    comptime len_max: usize,
    comptime run_one: fn ([]const u8) anyerror!void,
) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn test_one(_: void, input: *std.testing.Smith) anyerror!void {
            var buffer: [len_max]u8 = undefined;
            const len = input.slice(&buffer);
            assert(len <= len_max);
            try run_one(buffer[0..len]);
        }
    }.test_one;
}

test "reader pads past the end with zeros" {
    var reader = Reader.init(&.{ 0x01, 0x02, 0x03 });
    try std.testing.expectEqual(@as(u16, 0x0201), reader.int(u16));
    try std.testing.expect(!reader.done());
    try std.testing.expectEqual(@as(u32, 0x03), reader.int(u32));
    try std.testing.expect(reader.done());
    try std.testing.expectEqual(@as(u64, 0), reader.int(u64));
}
