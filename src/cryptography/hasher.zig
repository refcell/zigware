//! The `Hasher` concept of commonware's `lib.rs`, as a comptime interface, and `Streaming`,
//! which builds a hasher from a `std.crypto`-style core (`init`, `update`, `final`).
//!
//! A hasher `H` provides:
//! - `H.Digest`, a fixed-size digest type (see `digest.zig`);
//! - `H.init() H`, `h.update(bytes)`, and `h.finalize() Digest`, which also resets `h`
//!   (commonware returns the reset hasher alongside the digest);
//! - `H.hash(parts) Digest`, the one-shot hash of the concatenation of `parts`;
//! - `H.hash_across(parts, strategy)`, `H.hash_pair(left, right, strategy)`, and
//!   `H.hash_many(messages, digests, strategy)`, which must equal hashing each message with
//!   `hash`. `strategy` is a `parallel` strategy; until that package lands the work runs on
//!   the calling thread and any value (such as `{}`) is accepted.

const std = @import("std");
const assert = std.debug.assert;

/// Asserts at compile time that `H` implements the hasher interface.
pub fn assert_hasher(comptime H: type) void {
    comptime {
        assert(@hasDecl(H, "Digest"));
        assert(@hasDecl(H.Digest, "fixed_size"));
        for ([_][]const u8{
            "init", "update", "finalize", "hash", "hash_across", "hash_pair", "hash_many",
        }) |decl| {
            if (!@hasDecl(H, decl)) @compileError(@typeName(H) ++ " lacks Hasher." ++ decl);
        }
    }
}

/// A hasher over `Core`, a `std.crypto` hash with `init(.{})`, `update`, and `final`.
pub fn Streaming(comptime Core: type, comptime DigestType: type) type {
    comptime assert(DigestType.fixed_size > 0);
    return struct {
        const Self = @This();
        pub const Digest = DigestType;

        core: Core,

        pub fn init() Self {
            return .{ .core = Core.init(.{}) };
        }

        /// Appends `bytes` to the running state.
        pub fn update(self: *Self, bytes: []const u8) void {
            self.core.update(bytes);
        }

        /// Returns the digest of everything written so far and resets the hasher.
        pub fn finalize(self: *Self) Digest {
            var digest: Digest = undefined;
            self.core.final(&digest.bytes);
            self.* = init();
            return digest;
        }

        /// Hashes the concatenation of `parts` in one shot.
        pub fn hash(parts: []const []const u8) Digest {
            var self = init();
            for (parts) |part| self.update(part);
            return self.finalize();
        }

        pub fn hash_across(parts: []const []const u8, strategy: anytype) Digest {
            _ = strategy;
            return hash(parts);
        }

        pub fn hash_pair(
            left: []const []const u8,
            right: []const []const u8,
            strategy: anytype,
        ) [2]Digest {
            _ = strategy;
            return .{ hash(left), hash(right) };
        }

        /// Hashes each message alone into `digests`, which must be as long as `messages`.
        pub fn hash_many(messages: []const []const u8, digests: []Digest, strategy: anytype) void {
            _ = strategy;
            hash_each(Self, messages, digests);
        }
    };
}

/// Hashes each of `messages` alone with `H.hash` into `digests`.
pub fn hash_each(comptime H: type, messages: []const []const u8, digests: []H.Digest) void {
    assert(messages.len == digests.len);
    for (messages, digests) |message, *digest| digest.* = H.hash(&.{message});
}
