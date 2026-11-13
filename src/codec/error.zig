//! Error types for codec operations (codec/src/error.rs).
//!
//! Zig errors carry no payload, so the values commonware attaches to an error (the number of
//! extra bytes, the varint width, the invalid enum tag, the invalid length, the validation
//! context and message) are recorded in the `Reader`'s `Diagnostic` instead.

const std = @import("std");

/// Error set for codec operations. Mirrors commonware's `Error` variant for variant.
pub const Error = error{
    /// The input did not contain enough bytes to read the next value.
    EndOfBuffer,
    /// After decoding a value, bytes remained unconsumed. `Diagnostic.value` holds the count.
    ExtraData,
    /// A varint was malformed or overflowed its type. `Diagnostic.value` holds the type's
    /// width in bytes.
    InvalidVarint,
    /// A `usize`-sized varint was invalid.
    InvalidUsize,
    /// A boolean byte was neither 0 nor 1.
    InvalidBool,
    /// An enum tag did not match any variant. `Diagnostic.value` holds the tag.
    InvalidEnum,
    /// A length prefix fell outside its permitted `RangeCfg`. `Diagnostic.value` holds it.
    InvalidLength,
    /// Semantic validation failed. `Diagnostic.context` and `Diagnostic.message` say why.
    Invalid,
    /// An error from underlying code. `Diagnostic.context` says which operation failed.
    Wrapped,
    /// Allocating decoded storage failed.
    OutOfMemory,
};

/// Payload of the most recent decode error, the data commonware stores in its error variants.
pub const Diagnostic = struct {
    /// Numeric payload: extra bytes, varint width, enum tag, or invalid length.
    value: u64 = 0,
    /// Context, such as the name of the type being decoded.
    context: []const u8 = "",
    /// Specific error message.
    message: []const u8 = "",
};

test "error set has every commonware variant" {
    const names = [_][]const u8{
        "EndOfBuffer", "ExtraData",     "InvalidVarint", "InvalidUsize", "InvalidBool",
        "InvalidEnum", "InvalidLength", "Invalid",       "Wrapped",      "OutOfMemory",
    };
    const errors = @typeInfo(Error).error_set.error_names.?;
    try std.testing.expectEqual(names.len, errors.len);
    for (names) |name| {
        var found = false;
        for (errors) |error_name| {
            if (std.mem.eql(u8, name, error_name)) found = true;
        }
        try std.testing.expect(found);
    }
}
