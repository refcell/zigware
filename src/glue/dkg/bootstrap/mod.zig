//! One-shot engine for generating an initial BLS threshold output (commonware
//! `glue::dkg::bootstrap`).
//!
//! The engine runs an independent Ed25519 Simplex chain for one epoch and performs a single
//! ceremony among the configured participants, using reshare's dealing and inclusion
//! protocol. `Block` is the chain's block; `max_payload_size` bounds every message the engine
//! sends (the largest of Simplex's, marshal's for that block, and the DKG's).

const block = @import("block.zig");
const limits = @import("limits.zig");

pub const Block = block.Block;
pub const ConsensusScheme = limits.ConsensusScheme;
pub const MarshalVariant = limits.MarshalVariant;
pub const max_payload_size = limits.max_payload_size;

test {
    _ = @import("block_test.zig");
}
