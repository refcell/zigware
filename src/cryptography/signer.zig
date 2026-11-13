//! The signing traits of commonware's `lib.rs` as comptime interfaces.
//!
//! - A signer `S` (`Signer`, `PrivateKey`) has `S.PublicKey`, `S.Signature`,
//!   `S.random(rng)`, `S.from_seed(u64)`, `s.public_key()`, and `s.sign(namespace, message)`,
//!   and encodes through codec.
//! - A public key `P` (`Verifier`, `PublicKey`) has `P.Signature` and
//!   `p.verify(namespace, message, *const Signature) bool`, encodes through codec, and orders
//!   by its encoding (`eql`, `order`).
//! - A signature (`Signature`) encodes through codec and has `eql` and `order`.
//! - A batch verifier (`BatchVerifier`) has `P.verify_batch(rng, items, projector, strategy)`:
//!   `projector.project(index, *const Item) BatchEntry(P)` views each item as an entry.
//! - A recoverable signature (`Recoverable`) has `sig.recover_signer(namespace, message)`.
//!
//! The namespace is framed into the signed payload as commonware's `union_unique`: the varint
//! of the namespace length, the namespace, then the message. A signature for one namespace
//! never verifies under another.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const ChaCha20Rng = @import("rng.zig").ChaCha20Rng;

/// A borrowed view of one signature and the message it authenticates.
pub fn BatchEntry(comptime P: type) type {
    return struct {
        namespace: []const u8,
        message: []const u8,
        public_key: *const P,
        signature: *const P.Signature,
    };
}

/// Projects a slice of `BatchEntry` values onto themselves.
pub const entries: Entries = .{};
pub const Entries = struct {
    pub fn project(_: Entries, _: usize, entry: anytype) @TypeOf(entry.*) {
        return entry.*;
    }
};

/// Creates a signer from a `u64` seed with commonware's `Signer::from_seed`
/// (`random(ChaCha20Rng::seed_from_u64(seed))`). Insecure: for tests and examples only.
pub fn from_seed(comptime S: type, seed: u64) S {
    var rng = ChaCha20Rng.init(seed);
    return S.random(&rng);
}

fn assert_decls(
    comptime T: type,
    comptime decls: []const []const u8,
    comptime trait: []const u8,
) void {
    comptime {
        for (decls) |decl| {
            if (!@hasDecl(T, decl)) {
                @compileError(@typeName(T) ++ " lacks " ++ trait ++ "." ++ decl);
            }
        }
    }
}

fn assert_codec_fixed(comptime T: type) void {
    comptime {
        assert(codec.fixed_size(T) != null);
        assert_decls(T, &.{ "write", "read" }, "codec");
    }
}

/// Asserts `S` implements `Signer` and `PrivateKey`.
pub fn assert_signer(comptime S: type) void {
    comptime {
        const decls = .{ "PublicKey", "Signature", "random", "from_seed", "public_key", "sign" };
        assert_decls(S, &decls, "Signer");
        assert_codec_fixed(S);
        assert_public_key(S.PublicKey);
        assert(S.PublicKey.Signature == S.Signature);
    }
}

/// Asserts `P` implements `Verifier` and `PublicKey`.
pub fn assert_public_key(comptime P: type) void {
    comptime {
        assert_decls(P, &.{ "Signature", "verify", "eql", "order" }, "PublicKey");
        assert_codec_fixed(P);
        assert_signature(P.Signature);
    }
}

/// Asserts `T` implements `Signature`.
pub fn assert_signature(comptime T: type) void {
    comptime {
        assert_decls(T, &.{ "eql", "order" }, "Signature");
        assert_codec_fixed(T);
    }
}

/// Asserts `P` implements `BatchVerifier`.
pub fn assert_batch_verifier(comptime P: type) void {
    comptime {
        assert_public_key(P);
        assert_decls(P, &.{"verify_batch"}, "BatchVerifier");
    }
}

/// Asserts the signature type `T` implements `Recoverable`.
pub fn assert_recoverable(comptime T: type) void {
    comptime {
        assert_signature(T);
        assert_decls(T, &.{ "PublicKey", "recover_signer" }, "Recoverable");
    }
}
