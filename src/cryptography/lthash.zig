//! A homomorphic lattice hash (commonware `cryptography/src/lthash`).
//!
//! The state is 1024 `u16`s. `add` expands its input with BLAKE3 in XOF mode to 2048 bytes,
//! read as little-endian `u16`s, and adds them element-wise with wrapping arithmetic;
//! `subtract` and `combine` do the same with subtraction and another state. The hash of a set
//! is therefore independent of insertion order, and elements can be removed. `checksum` is
//! the BLAKE3 hash of the state as little-endian `u16`s; the codec encoding writes each `u16`
//! big-endian, as commonware's codec does.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const Blake3 = @import("blake3.zig").Blake3;
const tree = @import("blake3_tree.zig");

/// Bytes of state.
pub const size = 2048;
/// `u16` elements of state.
pub const elements = size / 2;

/// `u16`s per arithmetic step: a 64-byte vector. Vectors stay `u16` arrays end to end: a
/// bitcast from bytes compiled to element-wise code (lthash::add ran 130x slow at 1024 lanes
/// and 4x slow at 32).
const vector_len = 32;
const Words = @Vector(vector_len, u16);
const native_little = @import("builtin").cpu.arch.endian() == .little;

/// The lattice hash state.
pub const LtHash = struct {
    state: [elements]u16,

    pub const fixed_size: usize = size;
    /// The empty set.
    pub const zero: LtHash = .{ .state = @splat(0) };

    pub fn init() LtHash {
        return zero;
    }

    /// Adds `data` to the set.
    pub fn add(self: *LtHash, data: []const u8) void {
        var words: [elements]u16 = undefined;
        expand(data, &words);
        self.apply(&words, .add);
    }

    /// Removes `data` from the set.
    pub fn subtract(self: *LtHash, data: []const u8) void {
        var words: [elements]u16 = undefined;
        expand(data, &words);
        self.apply(&words, .subtract);
    }

    /// Adds every element of `other` to the set.
    pub fn combine(self: *LtHash, other: *const LtHash) void {
        self.apply(&other.state, .add);
    }

    /// Adds or subtracts `words` element-wise with wrapping.
    fn apply(self: *LtHash, words: *const [elements]u16, comptime op: enum { add, subtract }) void {
        comptime assert(elements % vector_len == 0);
        var index: usize = 0;
        while (index < elements) : (index += vector_len) {
            const delta: Words = words[index..][0..vector_len].*;
            const current: Words = self.state[index..][0..vector_len].*;
            self.state[index..][0..vector_len].* = switch (op) {
                .add => current +% delta,
                .subtract => current -% delta,
            };
        }
        assert(index == elements);
    }

    /// The BLAKE3 hash of the state as little-endian `u16`s.
    pub fn checksum(self: *const LtHash) Blake3.Digest {
        if (native_little) return .{ .bytes = tree.hash(&.{std.mem.asBytes(&self.state)}) };
        var bytes: [size]u8 = undefined;
        for (self.state, 0..) |value, index| {
            std.mem.writeInt(u16, bytes[index * 2 ..][0..2], value, .little);
        }
        return .{ .bytes = tree.hash(&.{&bytes}) };
    }

    pub fn reset(self: *LtHash) void {
        self.* = zero;
        assert(self.is_zero());
    }

    pub fn is_zero(self: *const LtHash) bool {
        return std.mem.allEqual(u16, &self.state, 0);
    }

    /// `data` expanded by BLAKE3 XOF to `elements` little-endian `u16`s.
    fn expand(data: []const u8, words: *[elements]u16) void {
        // The 2 KiB XOF compresses its output blocks many at a time (`blake3_tree.xof`),
        // as the `blake3` crate's `fill` does; std's `final` compresses one block at a time.
        tree.xof(&.{data}, std.mem.asBytes(words));
        if (!native_little) {
            for (words) |*word| word.* = @byteSwap(word.*);
        }
    }

    pub fn write(self: *const LtHash, writer: *codec.Writer) void {
        for (self.state) |value| writer.write_int(u16, value);
    }

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, cfg: void) codec.Error!LtHash {
        _ = gpa;
        _ = cfg;
        try reader.at_least(size);
        var result: LtHash = undefined;
        for (&result.state) |*value| value.* = try reader.read_int(u16);
        return result;
    }
};

comptime {
    assert(@sizeOf([elements]u16) == size);
    assert(codec.fixed_size(LtHash).? == size);
}

test {
    _ = @import("lthash_test.zig");
}
