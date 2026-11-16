//! Ordered delivery of erasure-coded blocks (commonware `consensus/src/marshal/coding`).
//!
//! The coding marshal couples the consensus pipeline with erasure-coded block broadcast:
//! blocks are encoded into `types.Shard`s, fanned out to peers, and reconstructed when a
//! notarization or finalization proves the data is needed. Compared to the standard marshal,
//! it spreads the load of block dissemination across all participants.
//!
//! Ported so far: `types` (shards, coded blocks, stored coded blocks) and `validation`. docs/lanes/
//! broadcast-collector.md tracks the rest (shards engine, variant, validation, marshaled).

pub const types = @import("types.zig");
pub const Shard = types.Shard;
pub const CodedBlock = types.CodedBlock;
pub const StoredCodedBlock = types.StoredCodedBlock;
pub const hash_context = types.hash_context;
pub const coding_config_for_participants = types.coding_config_for_participants;
pub const validation = @import("validation.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("types_test.zig");
    _ = @import("validation_test.zig");
}
