//! The bootstrap engine's message size bound (commonware `glue::dkg::bootstrap::max_payload_size`).
//!
//! The engine runs Simplex on its vote, certificate, and resolver channels, marshal on its
//! backfill and broadcast channels, and the reshare dealing protocol on its DKG channel.
//! `max_payload_size` is the largest of the three bounds, with marshal's bounded by the block
//! codec configuration the engine decodes with.

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const dkg_limits = @import("../limits.zig");
const block = @import("block.zig");

const Digest = cryptography.Sha256.Digest;
const PublicKey = cryptography.ed25519.PublicKey;
const ModeVersion = cryptography.bls12381.primitives.sharing.ModeVersion;

/// The one-shot chain's consensus scheme (commonware `ConsensusScheme`).
pub const ConsensusScheme = consensus.simplex.scheme.ed25519.Scheme(Digest);

/// Marshal's variant over the one-shot block.
pub fn MarshalVariant(comptime V: type, comptime D: type) type {
    return consensus.marshal.standard.Standard(block.Block(V, D));
}

/// An upper bound on the payloads the engine sends for a ceremony among `participants`
/// decoding blocks with `max_supported_mode`.
pub fn max_payload_size(
    comptime V: type,
    comptime D: type,
    participants: u32,
    max_supported_mode: ModeVersion,
) usize {
    assert(participants > 0);
    const cfg: block.Block(V, D).Cfg = .{
        .max_participants = participants,
        .max_supported_mode = max_supported_mode,
    };
    const simplex = consensus.simplex.limits.max_payload_size(
        ConsensusScheme,
        Digest,
        participants,
    );
    const marshal = consensus.marshal.max_payload_size(
        MarshalVariant(V, D),
        ConsensusScheme,
        participants,
        cfg,
    );
    const dkg = dkg_limits.max_payload_size(V, PublicKey, participants);
    const result = @max(simplex, marshal, dkg);
    assert(result >= dkg);
    return result;
}
