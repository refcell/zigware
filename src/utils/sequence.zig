//! Fixed and variable byte sequences used as keys and values (commonware
//! `utils/src/sequence`).
//!
//! commonware's `Span` (a codec type with unit config, ordered, hashable, displayable) and
//! `Array` (a `Span` that is fixed-size and viewable as bytes) traits become comptime checks:
//! `assert_span(T)` and `assert_array(T)`.

const std = @import("std");
const codec = @import("codec");
const assert = std.debug.assert;

const uint = @import("sequence/uint.zig");
pub const fixed_bytes = @import("sequence/fixed_bytes.zig");
pub const FixedBytes = fixed_bytes.FixedBytes;
pub const U32 = uint.U32;
pub const U64 = uint.U64;
pub const PrefixedU64 = uint.PrefixedU64;
pub const VecU64 = uint.VecU64;
pub const Unit = uint.Unit;

/// Checks that `T` is a `Span`: a codec type with unit config that orders and formats.
pub fn assert_span(comptime T: type) void {
    comptime {
        assert(codec.Cfg(T) == void);
        assert(@hasDecl(T, "order"));
        assert(@hasDecl(T, "format"));
    }
}

/// Checks that `T` is an `Array`: a fixed-size `Span` whose bytes are its encoding.
pub fn assert_array(comptime T: type) void {
    comptime {
        assert_span(T);
        assert(codec.fixed_size(T) != null);
        assert(@hasDecl(T, "as_slice"));
    }
}

comptime {
    assert_array(FixedBytes(32));
    assert_array(U32);
    assert_array(U64);
    assert_array(PrefixedU64);
    assert_array(Unit);
}

test {
    std.testing.refAllDecls(@This());
    _ = uint;
    _ = fixed_bytes;
    _ = @import("sequence/fuzz_test.zig");
}
