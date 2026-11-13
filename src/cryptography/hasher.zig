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
//!   `hash`. `strategy` is a `parallel` strategy (`parallel.sequential` or a `Rayon`); `{}`
//!   still means `parallel.sequential` for callers written before `parallel` landed.

const std = @import("std");
const assert = std.debug.assert;
const parallel = @import("parallel");

/// The strategy type `resolve_strategy` returns for a `strategy` argument of type `S`.
pub fn Strategy(comptime S: type) type {
    return if (S == void) parallel.Sequential else S;
}

/// `strategy`, or `parallel.sequential` for the `{}` placeholder.
pub fn resolve_strategy(strategy: anytype) Strategy(@TypeOf(strategy)) {
    if (@TypeOf(strategy) == void) return parallel.sequential;
    comptime parallel.assert_strategy(@TypeOf(strategy));
    return strategy;
}

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

        /// `hash(parts)`: these hashes do not split one message across threads.
        pub fn hash_across(parts: []const []const u8, strategy: anytype) Digest {
            _ = resolve_strategy(strategy);
            return hash(parts);
        }

        pub fn hash_pair(
            left: []const []const u8,
            right: []const []const u8,
            strategy: anytype,
        ) [2]Digest {
            _ = resolve_strategy(strategy);
            return .{ hash(left), hash(right) };
        }

        /// Hashes each message alone into `digests`, which must be as long as `messages`.
        pub fn hash_many(messages: []const []const u8, digests: []Digest, strategy: anytype) void {
            hash_batches(Self, messages, digests, strategy);
        }
    };
}

/// Hashes each of `messages` alone with `H.hash` into `digests`.
pub fn hash_each(comptime H: type, messages: []const []const u8, digests: []H.Digest) void {
    assert(messages.len == digests.len);
    for (messages, digests) |message, *digest| digest.* = H.hash(&.{message});
}

/// commonware `hash_batches` with one lane: hashes `messages` into `digests` in
/// strategy-supplied batches, estimating the work per message as its average length.
pub fn hash_batches(
    comptime H: type,
    messages: []const []const u8,
    digests: []H.Digest,
    strategy: anytype,
) void {
    const resolved = resolve_strategy(strategy);
    assert(messages.len == digests.len);
    if (messages.len == 0) return;
    var bytes: usize = 0;
    for (messages) |message| bytes +|= message.len;
    const Batch = struct {
        messages: []const []const u8,
        digests: []H.Digest,

        pub fn run(batch: @This(), batches: anytype) void {
            // A serial run hashes the whole input as one batch.
            if (batches.is_whole()) return hash_each(H, batch.messages, batch.digests);
            var done: [parallel.max_chunks]void = undefined;
            batches.map_collect(done[0..batches.count()], batch);
        }

        pub fn map(batch: @This(), _: usize, range: parallel.Range) void {
            const messages_range = batch.messages[range.start..range.end];
            hash_each(H, messages_range, batch.digests[range.start..range.end]);
        }
    };
    const batch: Batch = .{ .messages = messages, .digests = digests };
    // `messages` is not empty, so the division is defined.
    const bytes_per_message = std.math.divCeil(usize, bytes, messages.len) catch unreachable;
    resolved.run_batches(messages.len, 1, bytes_per_message, batch);
}
