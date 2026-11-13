//! BLS signature variants (commonware `bls12381::primitives::variant`).
//!
//! A variant `V` is a comptime interface: `V.Public` and `V.Signature` (the two groups),
//! the domain separation tags `V.proof_of_possession` and `V.message`, and
//! `V.verify(public, hm, signature)`, `V.batch_verify(rng, publics, hms, signatures)`, and
//! `V.pairing(public, signature)`.
//!
//! - `MinPk`: public keys in G1 (48 bytes), signatures in G2 (96 bytes).
//! - `MinSig`: public keys in G2 (96 bytes), signatures in G1 (48 bytes).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const utils = @import("utils");
const math = @import("math");
const group = @import("group.zig");

const Allocator = std.mem.Allocator;
const G1 = group.G1;
const G2 = group.G2;
const GT = group.GT;
const Scalar = group.Scalar;
const SmallScalar = group.SmallScalar;

/// Errors of the BLS12-381 primitives (commonware `primitives::Error`).
pub const Error = error{
    NotEnoughPartialSignatures,
    InvalidSignature,
    InvalidRecovery,
    InvalidIndex,
};

/// Public keys in G1, signatures in G2.
pub const MinPk = Variant(G1, G2);
/// Public keys in G2, signatures in G1.
pub const MinSig = Variant(G2, G1);

fn Variant(comptime PublicGroup: type, comptime SignatureGroup: type) type {
    comptime assert(PublicGroup != SignatureGroup);
    return struct {
        const Self = @This();
        pub const Public = PublicGroup;
        pub const Signature = SignatureGroup;
        pub const proof_of_possession = Signature.proof_of_possession_dst;
        pub const message = Signature.message_dst;
        pub const name = if (Public == G1) "MinPk" else "MinSig";

        /// Adds `e(public, hm)` with the G1 element first.
        fn add_pair(check: *group.PairingCheck, public: Public, hm: Signature) void {
            if (Public == G1) check.add(public, hm) else check.add(hm, public);
        }

        /// Checks `e(public, hm) == e(generator, signature)` as one product with the negated
        /// generator. Identity signatures are invalid.
        pub fn verify(public: Public, hm: Signature, signature: Signature) Error!void {
            if (signature.is_zero()) return error.InvalidSignature;
            var check: group.PairingCheck = .{};
            add_pair(&check, public, hm);
            add_pair(&check, Public.generator.neg(), signature);
            if (!check.verify()) return error.InvalidSignature;
        }

        /// Verifies signatures with a random linear combination: 128-bit scalars r_i from
        /// `rng`, then `prod_i e(r_i * (G1 side)_i, (G2 side)_i) * e(-generator, sum_i r_i
        /// sig_i) == 1`, scaling whichever of the public key and message hash is in G1. An
        /// empty batch and any identity signature are invalid.
        pub fn batch_verify(
            rng: anytype,
            publics: []const Public,
            hms: []const Signature,
            signatures: []const Signature,
        ) Error!void {
            assert(publics.len == hms.len);
            assert(publics.len == signatures.len);
            if (publics.len == 0) return error.InvalidSignature;
            for (signatures) |signature| {
                if (signature.is_zero()) return error.InvalidSignature;
            }
            const chunk = 64;
            var check: group.PairingCheck = .{};
            var aggregate = Signature.zero;
            var start: usize = 0;
            while (start < publics.len) : (start += chunk) {
                const count = @min(chunk, publics.len - start);
                var scalars: [chunk]SmallScalar = undefined;
                // Scalars are drawn in index order, as commonware draws them up front.
                for (scalars[0..count]) |*scalar| scalar.* = SmallScalar.random(rng);
                const end = start + count;
                aggregate = aggregate.add(Signature.msm(signatures[start..end], scalars[0..count]));
                for (publics[start..end], hms[start..end], scalars[0..count]) |p, hm, scalar| {
                    if (Public == G1) {
                        check.add(p.mul(scalar), hm);
                    } else {
                        check.add(hm.mul(scalar), p);
                    }
                }
            }
            add_pair(&check, Public.generator.neg(), aggregate);
            if (!check.verify()) return error.InvalidSignature;
        }

        /// The pairing `e(public, signature)`, with the G1 element first.
        pub fn pairing(public: Public, signature: Signature) GT {
            if (Public == G1) return group.pairing(public, signature);
            return group.pairing(signature, public);
        }
    };
}

/// A partial signature: the signer's participant index, then the signature
/// (`PartialSignature<V>`). Orders by index, then by the signature's encoding.
pub fn PartialSignature(comptime V: type) type {
    return struct {
        const Self = @This();
        index: utils.Participant,
        value: V.Signature,

        pub const max_encode_size: usize =
            utils.Participant.max_encode_size + V.Signature.fixed_size;

        pub fn encode_size(self: Self) usize {
            return self.index.encode_size() + V.Signature.fixed_size;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.index.write(writer);
            self.value.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const index = try utils.Participant.read(gpa, reader, {});
            const value = try V.Signature.read(gpa, reader, {});
            return .{ .index = index, .value = value };
        }

        pub fn arbitrary(u: *math.fuzz.Unstructured) Self {
            const index = utils.Participant.init(u.int(u32));
            return .{ .index = index, .value = V.Signature.generator.mul(Scalar.arbitrary(u)) };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.index.index == b.index.index and a.value.eql(b.value);
        }

        pub fn order(a: Self, b: Self) std.math.Order {
            const by_index = a.index.order(b.index);
            if (by_index != .eq) return by_index;
            return a.value.order(b.value);
        }
    };
}

test {
    _ = @import("variant_tests.zig");
}
