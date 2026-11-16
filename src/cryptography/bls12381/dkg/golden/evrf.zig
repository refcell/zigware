//! The golden DKG's eVRF keys (commonware `bls12381/dkg/golden/evrf/mod.rs`): Banderwagon
//! private and public keys with Schnorr signatures, and the receiver-side VRF evaluation.
//!
//! Signing uses a deterministic nonce drawn from a transcript fork that commits the secret
//! key, so a key signs a message the same way every time, byte-identical to commonware.
//! The bulletproofs `Setup`, `vrf_batch_checked`, and `VrfCommitments` follow once crypto's
//! zk bulletproofs lands.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const formatting = @import("formatting");
const signer = @import("../../../signer.zig");
const secret = @import("../../../secret.zig");
const transcript = @import("../../../transcript.zig");

pub const banderwagon = @import("evrf/banderwagon.zig");

const F = banderwagon.F;
const G = banderwagon.G;
const Scalar = @import("../../primitives/group.zig").Scalar;
const Transcript = transcript.Transcript;
const Summary = transcript.Summary;

const schnorr_namespace = "_COMMONWARE_CRYPTOGRAPHY_BANDERSNATCH_SCHNORR";

/// A Banderwagon private key. Formatting never shows the key.
pub const PrivateKey = struct {
    inner: secret.Secret(F),

    pub const fixed_size: usize = F.fixed_size;
    pub const PublicKey = evrf_public_key;
    pub const Signature = evrf_signature;

    pub fn random(rng: anytype) PrivateKey {
        return .{ .inner = .init(F.random(rng)) };
    }

    /// Commonware `Signer::from_seed`: insecure, for tests and examples only.
    pub fn from_seed(seed: u64) PrivateKey {
        return signer.from_seed(PrivateKey, seed);
    }

    pub fn public_key(self: *const PrivateKey) PrivateKey.PublicKey {
        return .from_point(G.generator.mul(self.inner.expose().*));
    }

    /// A Schnorr signature `(K, s)` with `K = [k] G`, `s = k + e x`, where the challenge
    /// `e` commits the namespace, message, public key, and `K`.
    pub fn sign(
        self: *const PrivateKey,
        namespace: []const u8,
        message: []const u8,
    ) PrivateKey.Signature {
        const public = self.public_key();
        var t = Transcript.init(schnorr_namespace, .v1);
        t.commit(namespace);
        t.commit(message);
        t.commit(&public.raw);

        // A deterministic nonce from the secret key and the public transcript state.
        var nonce_transcript = t.fork("nonce");
        var x_bytes = codec.encode_fixed(F, self.inner.expose().*);
        defer std.crypto.secureZero(u8, &x_bytes);
        nonce_transcript.commit(&x_bytes);
        var nonce_noise = nonce_transcript.noise("k");
        var k = F.random(&nonce_noise);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&k));

        const k_big_bytes = codec.encode_fixed(G, G.generator.mul(k));
        t.commit(&k_big_bytes);
        var challenge_noise = t.noise("challenge");
        const e = F.random(&challenge_noise);
        const s = e.mul(self.inner.expose().*).add(k);

        var raw: [PrivateKey.Signature.fixed_size]u8 = undefined;
        raw[0..G.fixed_size].* = k_big_bytes;
        raw[G.fixed_size..].* = codec.encode_fixed(F, s);
        return .{ .raw = raw };
    }

    /// The VRF output between this key (as receiver) and `sender` for `message`; both
    /// sides derive it from the symmetric ECDH secret.
    pub fn vrf_recv(self: *const PrivateKey, message: Summary, sender: evrf_public_key) Scalar {
        return banderwagon.vrf_recv(&message.bytes, sender.point, self.inner.expose().*);
    }

    /// Constant-time comparison.
    pub fn eql(a: *const PrivateKey, b: *const PrivateKey) bool {
        return a.inner.eql(&b.inner);
    }

    pub fn zeroize(self: *PrivateKey) void {
        self.inner.deinit();
    }

    pub fn write(self: *const PrivateKey, writer: *codec.Writer) void {
        self.inner.expose().write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!PrivateKey {
        return .{ .inner = .init(try F.read(gpa, reader, {})) };
    }

    pub fn format(_: PrivateKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("PrivateKey([REDACTED])");
    }
};

const evrf_public_key = PublicKey;
const evrf_signature = Signature;

/// A Banderwagon public key: the point and its canonical encoding, which equality, order,
/// and formatting use.
pub const PublicKey = struct {
    raw: [fixed_size]u8,
    point: G,

    pub const fixed_size: usize = G.fixed_size;
    pub const Signature = evrf_signature;

    pub fn from_point(point: G) PublicKey {
        return .{ .raw = codec.encode_fixed(G, point), .point = point };
    }

    /// Checks `[s] G == K + [e] X` with the recomputed challenge `e`.
    pub fn verify(
        self: *const PublicKey,
        namespace: []const u8,
        message: []const u8,
        signature: *const PublicKey.Signature,
    ) bool {
        var reader: codec.Reader = .init(signature.raw[0..G.fixed_size]);
        const k_big = G.read(undefined, &reader, {}) catch return false;
        reader = .init(signature.raw[G.fixed_size..]);
        const s = F.read(undefined, &reader, {}) catch return false;
        assert(reader.remaining() == 0);

        var t = Transcript.init(schnorr_namespace, .v1);
        t.commit(namespace);
        t.commit(message);
        t.commit(&self.raw);
        t.commit(signature.raw[0..G.fixed_size]);
        var challenge_noise = t.noise("challenge");
        const e = F.random(&challenge_noise);
        return G.generator.mul(s).eql(k_big.add(self.point.mul(e)));
    }

    pub fn as_slice(self: *const PublicKey) []const u8 {
        return &self.raw;
    }

    pub fn eql(a: PublicKey, b: PublicKey) bool {
        return std.mem.eql(u8, &a.raw, &b.raw);
    }

    pub fn order(a: PublicKey, b: PublicKey) std.math.Order {
        return std.mem.order(u8, &a.raw, &b.raw);
    }

    pub fn less_than(_: void, a: PublicKey, b: PublicKey) bool {
        return a.order(b) == .lt;
    }

    pub fn write(self: *const PublicKey, writer: *codec.Writer) void {
        writer.write_bytes(&self.raw);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!PublicKey {
        const raw = (try reader.take_array(fixed_size)).*;
        var inner: codec.Reader = .init(&raw);
        const point = G.read(gpa, &inner, {}) catch |err| {
            reader.diagnostic = inner.diagnostic;
            return err;
        };
        return .{ .raw = raw, .point = point };
    }

    pub fn format(self: PublicKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try formatting.fmt_hex(&self.raw).format(writer);
    }
};

/// A Schnorr signature over Banderwagon: the commitment point `K` and the response `s`.
pub const Signature = struct {
    raw: [fixed_size]u8,

    pub const fixed_size: usize = G.fixed_size + F.fixed_size;

    pub fn as_slice(self: *const Signature) []const u8 {
        return &self.raw;
    }

    pub fn eql(a: Signature, b: Signature) bool {
        return std.mem.eql(u8, &a.raw, &b.raw);
    }

    pub fn order(a: Signature, b: Signature) std.math.Order {
        return std.mem.order(u8, &a.raw, &b.raw);
    }

    pub fn write(self: *const Signature, writer: *codec.Writer) void {
        writer.write_bytes(&self.raw);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Signature {
        return .{ .raw = (try reader.take_array(fixed_size)).* };
    }

    pub fn format(self: Signature, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try formatting.fmt_hex(&self.raw).format(writer);
    }
};

comptime {
    signer.assert_signer(PrivateKey);
}

test {
    _ = banderwagon;
    _ = @import("evrf_tests.zig");
}
