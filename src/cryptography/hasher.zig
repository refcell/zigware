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
/// A kernel with `mixed_lengths = true` instead takes `hash([]const []const u8)` of up to
/// `lanes` messages of any lengths, as commonware's SHA-512 x8 kernel.
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

        /// Hashes the concatenation of `parts` in one shot, through `Core.hash_parts` when the
        /// core has a one-shot path.
        pub fn hash(parts: []const []const u8) Digest {
            if (comptime @hasDecl(Core, "hash_parts")) {
                var digest: Digest = undefined;
                Core.hash_parts(parts, &digest.bytes);
                return digest;
            }
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
            if (comptime @hasDecl(Core, "hash_pair_parts")) {
                var out: [2]Digest = undefined;
                var bytes: [2][Digest.fixed_size]u8 = undefined;
                Core.hash_pair_parts(left, right, &bytes);
                for (&out, bytes) |*digest, value| digest.bytes = value;
                return out;
            }
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

/// commonware `hash_batches` with `Kernel.batch_lanes` lanes: batches hold whole units of that
/// many messages. A kernel that costs the same however few lanes are active batches by its full
/// width; one that falls back to a faster single-message hash (SHA-NI) batches by one, so the
/// strategy may split the messages one at a time across more workers.
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
    run_hash_batches(H, Kernel.batch_lanes, Each.each, messages, digests, strategy);
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
    assert(messages.len == digests.len);
    if (comptime @hasDecl(Kernel, "mixed_lengths") and Kernel.mixed_lengths) {
        // commonware sha512 `hash_batch`: any `Kernel.lanes` consecutive messages share a
        // call, whatever their lengths, and a short last chunk passes only its own.
        var start: usize = 0;
        while (start < messages.len) : (start += Kernel.lanes) {
            const end = @min(start + Kernel.lanes, messages.len);
            const out = Kernel.hash(messages[start..end]);
            for (digests[start..end], out[0 .. end - start]) |*digest, bytes| digest.bytes = bytes;
        }
        return;
    }
    comptime assert(Kernel.minimum_batch_len >= 1 and Kernel.minimum_batch_len <= Kernel.lanes);
    var start: usize = 0;
    while (start < messages.len) {
        const len = messages[start].len;
        var end = start + 1;
        while (end < messages.len and end - start < Kernel.lanes and
            messages[end].len == len) end += 1;
        const count = end - start;
        if (count < Kernel.minimum_batch_len) {
            // Pairs of the run hash together, where `H.hash_pair` interleaves them (SHA-NI).
            var index = start;
            while (index + 2 <= end) : (index += 2) {
                const left: []const []const u8 = &.{messages[index]};
                const right: []const []const u8 = &.{messages[index + 1]};
                const pair = H.hash_pair(left, right, parallel.sequential);
                digests[index] = pair[0];
                digests[index + 1] = pair[1];
            }
            hash_each(H, messages[index..end], digests[index..end]);
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

const testing = std.testing;

/// A hasher stand-in whose "digest" of a message is its index and the index of the first
/// message of its batch (commonware's `test_hash_batches_shares_whole_units` closure).
const Recording = struct {
    pub const Digest = struct { bytes: [8]u8 };

    fn each(comptime H: type, batch: []const []const u8, out: []H.Digest) void {
        assert(batch.len == out.len);
        assert(batch.len > 0);
        for (batch, out) |message, *digest| {
            digest.bytes[0..4].* = message[0..4].*;
            digest.bytes[4..8].* = batch[0][0..4].*;
        }
    }
};

// commonware lib.rs `test_hash_batches_shares_whole_units`.
test "hash_batches shares hold whole units of lanes" {
    const strategy = try parallel.mocks.pooled(testing.allocator, testing.io, 4, 8);
    defer strategy.pool.destroy();
    const explorer = parallel.mocks.Explorer.parallel(strategy);
    var storage: [200][4]u8 = undefined;
    var messages: [200][]const u8 = undefined;
    for (&storage, &messages, 0..) |*bytes, *message, index| {
        std.mem.writeInt(u32, bytes, @intCast(index), .little);
        message.* = bytes;
    }
    var digests: [200]Recording.Digest = undefined;
    inline for (.{ 1, 2, 8, 16 }) |lanes| {
        for ([_]usize{ 0, 1, lanes + 1, 3 * lanes, 7 * lanes + 1, 9 * lanes, 100 }) |count| {
            const out = digests[0..count];
            run_hash_batches(Recording, lanes, Recording.each, messages[0..count], out, explorer);
            var shares: usize = 0;
            var share_len: usize = 0;
            for (out, 0..) |digest, index| {
                const own = std.mem.readInt(u32, digest.bytes[0..4], .little);
                const first = std.mem.readInt(u32, digest.bytes[4..8], .little);
                try testing.expectEqual(@as(u32, @intCast(index)), own);
                if (first == own) {
                    // Every share but the last holds a multiple of `lanes` messages.
                    if (shares > 0) try testing.expectEqual(@as(usize, 0), share_len % lanes);
                    shares += 1;
                    share_len = 0;
                }
                share_len += 1;
            }
            const units = std.math.divCeil(usize, count, lanes) catch unreachable;
            try testing.expectEqual(@min(units, 8), shares);
        }
    }
}
