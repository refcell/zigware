//! A wrapper for secret values (commonware `cryptography/src/secret.rs`): formatting never
//! shows the value, comparisons are constant-time, and the memory is zeroized when the
//! secret is released.
//!
//! Zig has no destructors, so the owner calls `deinit` (or `expose_unwrap`) to zeroize;
//! `expose` is the explicit door to the value.

const std = @import("std");
const assert = std.debug.assert;

/// Holds key material where std.fmt cannot print it. `{f}` calls a type's `format`, but `{}`
/// and `{any}` ignore `format` and print every field of a struct; they never look inside an
/// untagged union (it prints `.{ ... }`). Every field that stores key material is an `Opaque`.
pub fn Opaque(comptime T: type) type {
    return union {
        value: T,
    };
}

pub fn Secret(comptime T: type) type {
    // Constant-time comparison reads every byte, so padding would leak or compare garbage.
    comptime assert(@sizeOf(T) * 8 == @bitSizeOf(T));
    return struct {
        const Self = @This();

        value: Opaque(T),

        pub fn init(value: T) Self {
            return .{ .value = .{ .value = value } };
        }

        /// A read-only view of the value.
        pub fn expose(self: *const Self) *const T {
            return &self.value.value;
        }

        /// Moves the value out and zeroizes the secret's copy.
        pub fn expose_unwrap(self: *Self) T {
            const value = self.value.value;
            self.deinit();
            return value;
        }

        /// Zeroizes the value; the secret must not be used afterwards.
        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.asBytes(&self.value.value));
            assert(std.mem.allEqual(u8, std.mem.asBytes(&self.value.value), 0));
        }

        /// Constant-time equality of the bytes.
        pub fn eql(a: *const Self, b: *const Self) bool {
            const a_bytes = std.mem.asBytes(&a.value.value);
            const b_bytes = std.mem.asBytes(&b.value.value);
            return std.crypto.timing_safe.eql([@sizeOf(T)]u8, a_bytes.*, b_bytes.*);
        }

        /// Commonware's `Display` (`{f}`); `Debug` prints `Secret([REDACTED])`.
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            _ = self;
            try writer.writeAll("[REDACTED]");
        }

        pub const debug_text = "Secret([REDACTED])";
    };
}

const testing = std.testing;

test "secret is redacted" {
    var buffer: [32]u8 = undefined;
    const secret = Secret([4]u8).init(.{ 1, 2, 3, 4 });
    try testing.expectEqualStrings("[REDACTED]", try std.fmt.bufPrint(&buffer, "{f}", .{secret}));
    try testing.expectEqualStrings("Secret([REDACTED])", Secret([4]u8).debug_text);
}

test "secret expose, unwrap, clone, and equality" {
    var secret = Secret([4]u8).init(.{ 1, 2, 3, 4 });
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, secret.expose());
    const cloned = Secret([4]u8).init(secret.expose().*);
    try testing.expect(secret.eql(&cloned));
    try testing.expect(!secret.eql(&Secret([4]u8).init(.{ 5, 6, 7, 8 })));
    const value = secret.expose_unwrap();
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, &value);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &secret.value.value);

    var many = Secret([32]u8).init(@splat(42));
    try testing.expectEqual(@as(u8, 42), many.expose()[0]);
    try testing.expectEqual(@as(u8, 42), many.expose()[31]);
    many.deinit();
    try testing.expect(std.mem.allEqual(u8, &many.value.value, 0));
}
