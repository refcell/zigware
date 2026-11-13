//! A shared, owned value paired with its digest: commonware's `cryptography::Digested`
//! (`Arc<T>` plus its digest). `cryptography.Digested` borrows its value (`*const T`); the
//! broadcast cache, its waiters, and its responders share values received from the network,
//! so they need this reference-counted form.
//!
//! `compute` hashes the value; `precomputed` pairs it with a digest a local source already
//! computed from this exact value. Handles share one reference-counted value: `clone` adds a
//! reference and `deinit` drops one, freeing the value with the last (`T.deinit(*T, gpa)` when
//! `T` declares it, the codec convention). Two handles are equal when their digests are equal.
//! The value encodes as the inner value does; there is no decoding.
//!
//! `T` is Digestible: `pub const Digest` and `digest(*const T) Digest`. commonware computes the
//! digest as a job on a `Strategy`; with no work to split, `compute` hashes inline.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");

pub fn Digested(comptime T: type) type {
    comptime assert(@hasDecl(T, "Digest"));
    comptime assert(@hasDecl(T, "digest"));
    return struct {
        const Self = @This();
        pub const Digest = T.Digest;
        pub const Inner = T;

        shared: *Shared,
        digest_value: Digest,

        const Shared = struct {
            gpa: Allocator,
            references: std.atomic.Value(u32),
            inner: T,
        };

        /// Pairs `inner` (owned from now on) with `digest_value`. On error the caller keeps
        /// `inner`.
        pub fn precomputed(gpa: Allocator, inner_value: T, digest_value: Digest) !Self {
            const shared = try gpa.create(Shared);
            shared.* = .{ .gpa = gpa, .references = .init(1), .inner = inner_value };
            return .{ .shared = shared, .digest_value = digest_value };
        }

        /// Computes the digest of `inner` (owned from now on). On error the caller keeps
        /// `inner`.
        pub fn compute(gpa: Allocator, inner_value: T) !Self {
            const digest_value = inner_value.digest();
            const result = try precomputed(gpa, inner_value, digest_value);
            assert(result.digest().eql(digest_value));
            return result;
        }

        pub fn inner(self: Self) *const T {
            assert(self.shared.references.load(.monotonic) > 0);
            return &self.shared.inner;
        }

        /// The digest, computed once (commonware `Digestible::digest`).
        pub fn digest(self: Self) Digest {
            return self.digest_value;
        }

        /// Another handle to the same value.
        pub fn clone(self: Self) Self {
            const previous = self.shared.references.fetchAdd(1, .monotonic);
            assert(previous > 0);
            assert(previous < std.math.maxInt(u32));
            return self;
        }

        /// Drops this handle; the last one frees the value.
        pub fn deinit(self: *Self) void {
            const shared = self.shared;
            self.* = undefined;
            const previous = shared.references.fetchSub(1, .acq_rel);
            assert(previous > 0);
            if (previous > 1) return;
            if (comptime @hasDecl(T, "deinit")) shared.inner.deinit(shared.gpa);
            shared.gpa.destroy(shared);
        }

        /// Drops a handle passed by value (the hook channels and mailboxes call for values
        /// they drop).
        pub fn discard(self: Self) void {
            var owned = self;
            owned.deinit();
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.digest_value.eql(b.digest_value);
        }

        /// codec: the inner value's encoding.
        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(T, self.shared.inner, writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(T, self.shared.inner);
        }
    };
}

const testing = std.testing;

test "digested shares one value across clones" {
    const Sha256 = cryptography.Sha256;
    const Value = struct {
        bytes: []u8,
        pub const Digest = Sha256.Digest;
        pub fn digest(value: *const @This()) Digest {
            return Sha256.hash(&.{value.bytes});
        }
        pub fn deinit(value: *@This(), gpa: Allocator) void {
            gpa.free(value.bytes);
        }
    };
    const bytes = try testing.allocator.dupe(u8, "hello");
    var first = try Digested(Value).compute(testing.allocator, .{ .bytes = bytes });
    var second = first.clone();
    try testing.expect(first.eql(second));
    try testing.expect(first.digest().eql(Sha256.hash(&.{"hello"})));
    try testing.expectEqual(first.inner(), second.inner());
    first.deinit();
    try testing.expectEqualStrings("hello", second.inner().bytes);
    second.deinit();
}
