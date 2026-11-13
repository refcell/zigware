//! commonware's `Digestible`, `Committable`, and `Digested` (`cryptography/src/lib.rs`).
//!
//! - A digestible type `T` declares `T.Digest` and has `value.digest() T.Digest`; it may add
//!   `value.digest_across(strategy) T.Digest` to split the work across a `parallel`
//!   strategy. `digest_across(T, value, strategy)` calls it, or falls back to `digest()`.
//! - A committable type `T` declares `T.Commitment` and has `value.commitment()`. Two values
//!   with the same digest must have the same commitment.
//! - `Digested(T)` pairs a value with its digest so holders read the digest for free. Rust's
//!   `Arc<T>` becomes a borrowed `*const T`: the owner keeps the value alive, and unchanged in
//!   anything its digest covers, while a `Digested` refers to it. `compute` hashes on the
//!   calling thread through `strategy` instead of returning a future; the digest is the same.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const parallel = @import("parallel");

fn assert_decls(
    comptime T: type,
    comptime decls: []const []const u8,
    comptime name: []const u8,
) void {
    comptime {
        for (decls) |decl| {
            if (!@hasDecl(T, decl)) {
                @compileError(@typeName(T) ++ " lacks " ++ name ++ "." ++ decl);
            }
        }
    }
}

/// Asserts `T` implements `Digestible`.
pub fn assert_digestible(comptime T: type) void {
    assert_decls(T, &.{ "Digest", "digest" }, "Digestible");
    comptime assert(codec.fixed_size(T.Digest) != null);
}

/// Asserts `T` implements `Committable`.
pub fn assert_committable(comptime T: type) void {
    assert_decls(T, &.{ "Commitment", "commitment" }, "Committable");
    comptime assert(codec.fixed_size(T.Commitment) != null);
}

/// `value.digest_across(strategy)`, or `value.digest()` when `T` does not split its work.
pub fn digest_across(comptime T: type, value: *const T, strategy: anytype) T.Digest {
    assert_digestible(T);
    parallel.assert_strategy(@TypeOf(strategy));
    if (@hasDecl(T, "digest_across")) return value.digest_across(strategy);
    return value.digest();
}

/// A borrowed value paired with its digest (commonware `Digested<T>`). Equality is digest
/// equality, which the `Digestible` contract makes value equality. `write`/`encode_size`
/// encode the value; there is no decoding (so it is not a codec type): pair a decoded value
/// with its digest through a constructor.
pub fn Digested(comptime T: type) type {
    assert_digestible(T);
    return struct {
        const Self = @This();
        pub const Digest = T.Digest;

        inner_value: *const T,
        digest_value: T.Digest,

        /// Computes the digest of `value` through `strategy`.
        pub fn compute(value: *const T, strategy: anytype) Self {
            return .{ .inner_value = value, .digest_value = digest_across(T, value, strategy) };
        }

        /// Pairs `value` with a digest a local source already computed from this exact value
        /// (the key it was stored under, a checked commitment, or an earlier `compute`). It
        /// says nothing about whether the value is valid or certified.
        pub fn precomputed(value: *const T, digest_value: T.Digest) Self {
            return .{ .inner_value = value, .digest_value = digest_value };
        }

        pub fn inner(self: Self) *const T {
            return self.inner_value;
        }

        pub fn digest(self: Self) T.Digest {
            return self.digest_value;
        }

        pub fn eql(a: Self, b: Self) bool {
            return codec.order(T.Digest, a.digest_value, b.digest_value) == .eq;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(T, self.inner_value.*, writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(T, self.inner_value.*);
        }
    };
}

test {
    _ = @import("digestible_test.zig");
}
