//! Send succinct consensus certificates between two networks (commonware `examples/bridge`).
//!
//! Each of two networks runs simplex with a BLS12-381 threshold scheme. A leader's block holds
//! either 16 random bytes or the other network's latest finalization; blocks and
//! finalizations travel through an `indexer` that both networks talk to. See README.md.
//!
//! Binaries: `bridge-dealer` (a network's threshold secret), `bridge-validator`, and
//! `bridge-indexer`. This module is what they share: commonware's `lib.rs`.

const zigware = @import("zigware");

const simplex = zigware.consensus.simplex;
const cryptography = zigware.cryptography;

/// The digest blocks are named by.
pub const Digest = cryptography.sha256.Digest;
/// Network identities and certificate keys: BLS12-381 MinSig.
pub const Variant = cryptography.bls12381.primitives.MinSig;
/// The consensus scheme: threshold BLS over ed25519 participants (commonware's `Scheme`).
pub const Scheme = simplex.scheme.bls12381_threshold.standard.Scheme(
    Digest,
    cryptography.ed25519.PublicKey,
    Variant,
);

pub const application_namespace = "_COMMONWARE_EXAMPLES_BRIDGE";
pub const p2p_suffix = "_P2P";
pub const consensus_suffix = "_CONSENSUS";
pub const indexer_namespace = "_COMMONWARE_EXAMPLES_BRIDGE_INDEXER";
pub const max_message_size: u32 = 1024 * 1024;
pub const mailbox_size: u32 = 1_000;

pub const types = @import("types.zig");
pub const store = @import("store.zig");
pub const application = @import("application.zig");

test {
    _ = types;
    _ = store;
    _ = application;
}
