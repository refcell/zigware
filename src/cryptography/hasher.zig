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
    return StreamingWith(Core, DigestType, void);
}

/// `Streaming` whose `hash_many` hashes runs of equal-length messages with `Kernel` (`void`
/// for none): a multi-message kernel with `lanes`, `minimum_batch_len`, and
/// `hash([lanes][]const u8) [lanes][digest_length]u8`, as commonware's SHA-256 x16 kernel.
pub fn StreamingWith(comptime Core: type, comptime DigestType: type, comptime Kernel: type) type {
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
            if (Kernel == void) return hash_batches(Self, messages, digests, strategy);
            hash_batches_with(Self, Kernel, messages, digests, strategy);
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
    run_hash_batches(H, 1, hash_each, messages, digests, strategy);
}

/// commonware `hash_batches` with `Kernel.lanes` lanes: batches hold whole units of
/// `Kernel.lanes` messages, so the kernel finds every unit but the last one full.
pub fn hash_batches_with(
    comptime H: type,
    comptime Kernel: type,
    messages: []const []const u8,
    digests: []H.Digest,
    strategy: anytype,
) void {
    const Each = struct {
        fn each(comptime Hash: type, batch: []const []const u8, out: []Hash.Digest) void {
            hash_runs(Hash, Kernel, batch, out);
        }
    };
    run_hash_batches(H, Kernel.lanes, Each.each, messages, digests, strategy);
}

fn run_hash_batches(
    comptime H: type,
    comptime lanes: usize,
    comptime each: fn (comptime type, []const []const u8, []H.Digest) void,
    messages: []const []const u8,
    digests: []H.Digest,
    strategy: anytype,
) void {
    comptime assert(lanes > 0);
    const resolved = resolve_strategy(strategy);
    assert(messages.len == digests.len);
    if (messages.len == 0) return;
    var bytes: usize = 0;
    for (messages) |message| bytes +|= message.len;
    const units = std.math.divCeil(usize, messages.len, lanes) catch unreachable;
    const Batch = struct {
        messages: []const []const u8,
        digests: []H.Digest,

        pub fn run(batch: @This(), batches: anytype) void {
            // A serial run hashes the whole input as one batch.
            if (batches.is_whole()) return each(H, batch.messages, batch.digests);
            var done: [parallel.max_chunks]void = undefined;
            batches.map_collect(done[0..batches.count()], batch);
        }

        pub fn map(batch: @This(), _: usize, range: parallel.Range) void {
            const start = range.start * lanes;
            const end = @min(range.end *| lanes, batch.messages.len);
            each(H, batch.messages[start..end], batch.digests[start..end]);
        }
    };
    const batch: Batch = .{ .messages = messages, .digests = digests };
    // `units` is not zero (`messages` is not empty), so the division is defined.
    const bytes_per_unit = std.math.divCeil(usize, bytes, units) catch unreachable;
    resolved.run_batches(units, 1, bytes_per_unit, batch);
}

/// commonware sha256 `hash_batch`: adjacent equal-length runs go through `Kernel` in chunks of
/// `Kernel.lanes` (spare lanes borrow the chunk's first message); a chunk shorter than
/// `Kernel.minimum_batch_len` hashes one message at a time.
fn hash_runs(
    comptime H: type,
    comptime Kernel: type,
    messages: []const []const u8,
    digests: []H.Digest,
) void {
    comptime assert(Kernel.minimum_batch_len >= 1 and Kernel.minimum_batch_len <= Kernel.lanes);
    assert(messages.len == digests.len);
    var start: usize = 0;
    while (start < messages.len) {
        const len = messages[start].len;
        var end = start + 1;
        while (end < messages.len and end - start < Kernel.lanes and
            messages[end].len == len) end += 1;
        const count = end - start;
        if (count < Kernel.minimum_batch_len) {
            hash_each(H, messages[start..end], digests[start..end]);
        } else {
            var inputs: [Kernel.lanes][]const u8 = @splat(messages[start]);
            @memcpy(inputs[0..count], messages[start..end]);
            const out = Kernel.hash(inputs);
            for (digests[start..end], out[0..count]) |*digest, bytes| digest.bytes = bytes;
        }
        start = end;
    }
    assert(start == messages.len);
}
