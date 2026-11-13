//! Type-state for operations with fixed or variable size (qmdb/value.rs).
//!
//! commonware wraps a value type in `FixedEncoding<V>` or `VariableEncoding<V>` so one
//! operation type serves both on-disk layouts. Here an encoding is a comptime struct with
//! `Value` (the wrapped type) and `fixed` (whether operations pad to a uniform size).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");

/// A fixed-size value: operations over it pad to one uniform size.
pub fn Fixed(comptime V: type) type {
    comptime assert(codec.fixed_size(V) != null);
    return struct {
        pub const Value = V;
        pub const fixed = true;
        pub const value_size: usize = codec.fixed_size(V).?;
    };
}

/// A variable-size value: operations over it are not padded.
pub fn Variable(comptime V: type) type {
    return struct {
        pub const Value = V;
        pub const fixed = false;
    };
}

/// Asserts at comptime that `E` is a value encoding.
pub fn check(comptime E: type) void {
    comptime {
        assert(@hasDecl(E, "Value"));
        assert(@TypeOf(E.fixed) == bool);
        if (E.fixed) assert(codec.fixed_size(E.Value) != null);
    }
}

/// Whether two values are equal: `eql` when the type declares it, bytes for slices,
/// `std.meta.eql` otherwise.
pub fn eql(comptime V: type, a: V, b: V) bool {
    switch (@typeInfo(V)) {
        .@"struct", .@"union", .@"enum" => if (@hasDecl(V, "eql")) return a.eql(b),
        .pointer => |info| if (info.size == .slice) {
            if (info.child == u8) return std.mem.eql(u8, a, b);
            if (a.len != b.len) return false;
            for (a, b) |x, y| if (!eql(info.child, x, y)) return false;
            return true;
        },
        .optional => |info| {
            if (a == null or b == null) return a == null and b == null;
            return eql(info.child, a.?, b.?);
        },
        else => {},
    }
    return std.meta.eql(a, b);
}

/// The bytes of a key (`AsRef<[u8]>`): the slice itself, or the type's `as_slice`.
pub fn bytes(comptime K: type, key: *const K) []const u8 {
    if (K == []const u8 or K == []u8) return key.*;
    switch (@typeInfo(K)) {
        .array => |info| {
            comptime assert(info.child == u8);
            return key;
        },
        else => return key.as_slice(),
    }
}

/// A copy of `value` that owns its memory (commonware's `Clone`).
pub fn clone(comptime V: type, gpa: std.mem.Allocator, value: V) std.mem.Allocator.Error!V {
    if (comptime !codec.owns_memory(V)) return value;
    switch (@typeInfo(V)) {
        .pointer => |info| {
            comptime assert(info.size == .slice and !codec.owns_memory(info.child));
            return gpa.dupe(info.child, value);
        },
        .optional => |info| return if (value) |inner| try clone(info.child, gpa, inner) else null,
        else => return value.clone(gpa),
    }
}

/// `V::arbitrary` for the value, key, and digest types QMDB's conformance tests use:
/// byte arrays such as `U64` (`#[derive(Arbitrary)]` over `[u8; N]`), SHA-256 digests (the
/// hash of `0..=256` arbitrary bytes), and everything `codec.arbitrary.value` handles.
pub fn arbitrary(
    comptime V: type,
    gpa: std.mem.Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error!V {
    switch (@typeInfo(V)) {
        .optional => |info| {
            if (!u.boolean()) return null;
            return try arbitrary(info.child, gpa, u);
        },
        .@"struct" => if (comptime !@hasDecl(V, "arbitrary")) {
            if (comptime @hasDecl(V, "label")) {
                comptime assert(std.mem.eql(u8, V.label, "sha256"));
                const len = u.int_in_range(u64, 0, 256);
                var data: [256]u8 = undefined;
                try u.bytes(data[0..len]);
                return cryptography.Sha256.hash(&.{data[0..len]});
            }
            if (comptime @hasDecl(V, "from_bytes")) {
                var data: [V.fixed_size]u8 = undefined;
                u.fill(&data);
                return V.from_bytes(data);
            }
        },
        else => {},
    }
    return codec.arbitrary.value(V, gpa, u);
}

const cryptography = @import("cryptography");
const testing = std.testing;
const utils = @import("utils");

test "encodings" {
    const U64 = utils.sequence.U64;
    const F = Fixed(U64);
    const V = Variable([]const u8);
    check(F);
    check(V);
    try testing.expect(F.fixed);
    try testing.expect(!V.fixed);
    try testing.expectEqual(@as(usize, 8), F.value_size);
}

test "eql and clone" {
    const gpa = testing.allocator;
    try testing.expect(eql([]const u8, "abc", "abc"));
    try testing.expect(!eql([]const u8, "abc", "abd"));
    try testing.expect(eql(?u64, null, null));
    try testing.expect(!eql(?u64, null, 1));
    const copy = try clone([]const u8, gpa, "xyz");
    defer gpa.free(copy);
    try testing.expectEqualStrings("xyz", copy);
    try testing.expectEqual(@as(u64, 5), try clone(u64, gpa, 5));
}
