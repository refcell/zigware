//! BLS12-381 threshold VRF for simplex (commonware
//! `simplex::scheme::bls12381_threshold::vrf`): every vote carries a vote signature and a
//! seed signature over the round, so a certificate yields a per-round random seed.
//!
//! This file has the wire types (`Signature`, `Certificate`, `Seed`); the signing scheme
//! follows once the bls-math lane lands threshold recovery.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const consensus_types = @import("../../../types.zig");

const group = cryptography.bls12381.primitives.group;
const Round = consensus_types.Round;
const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;

/// commonware's `G1`/`G2` `Arbitrary`: the generator times `Scalar::from_ikm` of 64 drawn
/// bytes (zero-filled once the data runs out, as `[u8; 64]::arbitrary` does).
pub fn arbitrary_point(comptime G: type, u: *Unstructured) G {
    var ikm: [64]u8 = undefined;
    u.fill(&ikm);
    const point = G.generator.mul(group.Scalar.from_ikm(&ikm));
    assert(!point.is_zero());
    return point;
}

/// A vote signature and a seed signature (partial, or recovered in a certificate).
pub fn Signature(comptime V: type) type {
    return struct {
        const Self = @This();
        const Point = V.Signature;

        vote_signature: Point,
        seed_signature: Point,

        pub const fixed_size: usize = 2 * Point.fixed_size;

        pub fn eql(a: Self, b: Self) bool {
            return a.vote_signature.eql(b.vote_signature) and
                a.seed_signature.eql(b.seed_signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.vote_signature.write(writer);
            self.seed_signature.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const vote_signature = try Point.read(gpa, reader, {});
            return .{
                .vote_signature = vote_signature,
                .seed_signature = try Point.read(gpa, reader, {}),
            };
        }

        pub fn arbitrary(_: Allocator, u: *Unstructured) ArbitraryError!Self {
            const vote_signature = arbitrary_point(Point, u);
            const seed_signature = arbitrary_point(Point, u);
            return .{ .vote_signature = vote_signature, .seed_signature = seed_signature };
        }
    };
}

/// A recovered signature pair, decoded on demand (commonware `Lazy<Signature<V>>`).
pub fn Certificate(comptime V: type) type {
    return struct {
        const Self = @This();
        const Inner = cryptography.certificate.Deferred(Signature(V));

        signature: Inner,

        pub const fixed_size: usize = Inner.fixed_size;

        pub fn init(signature: Signature(V)) Self {
            return .{ .signature = .init(signature) };
        }

        /// The decoded signature pair, or null when the bytes are not valid points.
        pub fn get(self: *const Self) ?Signature(V) {
            return self.signature.get();
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.signature.eql(b.signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.signature.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{ .signature = try Inner.read(gpa, reader, {}) };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            return init(try Signature(V).arbitrary(gpa, u));
        }
    };
}

/// A threshold signature over a round: the round's random seed.
pub fn Seed(comptime V: type) type {
    return struct {
        const Self = @This();
        const Point = V.Signature;

        round: Round,
        signature: Point,

        pub const max_encode_size: usize = Round.max_encode_size + Point.fixed_size;

        pub fn epoch(self: Self) Epoch {
            return self.round.epoch;
        }

        pub fn view(self: Self) View {
            return self.round.view;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.round == b.round and a.signature.eql(b.signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.round.write(writer);
            self.signature.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.round.encode_size() + Point.fixed_size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const round = try Round.read(gpa, reader, {});
            return .{ .round = round, .signature = try Point.read(gpa, reader, {}) };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const round = try Round.arbitrary(gpa, u);
            return .{ .round = round, .signature = arbitrary_point(Point, u) };
        }
    };
}
