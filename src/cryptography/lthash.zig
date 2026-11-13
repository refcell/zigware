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
const StdBlake3 = std.crypto.hash.Blake3;

/// Bytes of state.
pub const size = 2048;
/// `u16` elements of state.
pub const elements = size / 2;

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
        const expanded = expand(data);
        for (&self.state, expanded) |*value, delta| value.* +%= delta;
    }

    /// Removes `data` from the set.
    pub fn subtract(self: *LtHash, data: []const u8) void {
        const expanded = expand(data);
        for (&self.state, expanded) |*value, delta| value.* -%= delta;
    }

    /// Adds every element of `other` to the set.
    pub fn combine(self: *LtHash, other: *const LtHash) void {
        for (&self.state, other.state) |*value, delta| value.* +%= delta;
    }

    /// The BLAKE3 hash of the state as little-endian `u16`s.
    pub fn checksum(self: *const LtHash) Blake3.Digest {
        var bytes: [size]u8 = undefined;
        for (self.state, 0..) |value, index| {
            std.mem.writeInt(u16, bytes[index * 2 ..][0..2], value, .little);
        }
        return Blake3.hash(&.{&bytes});
    }

    pub fn reset(self: *LtHash) void {
        self.* = zero;
        assert(self.is_zero());
    }

    pub fn is_zero(self: *const LtHash) bool {
        return std.mem.allEqual(u16, &self.state, 0);
    }

    /// `data` expanded by BLAKE3 XOF to `elements` little-endian `u16`s.
    fn expand(data: []const u8) [elements]u16 {
        var bytes: [size]u8 = undefined;
        var hasher = StdBlake3.init(.{});
        hasher.update(data);
        hasher.final(&bytes);
        var result: [elements]u16 = undefined;
        for (&result, 0..) |*value, index| {
            value.* = std.mem.readInt(u16, bytes[index * 2 ..][0..2], .little);
        }
        return result;
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
