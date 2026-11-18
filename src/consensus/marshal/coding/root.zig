//! Ordered delivery of erasure-coded blocks (commonware `consensus/src/marshal/coding`).
//!
//! The coding marshal couples the consensus pipeline with erasure-coded block broadcast:
//! blocks are encoded into `types.Shard`s, fanned out to peers, and reconstructed when a
//! notarization or finalization proves the data is needed. Compared to the standard marshal,
//! it spreads the load of block dissemination across all participants.
//!
//! Ported so far: `types` (shards, coded blocks, stored coded blocks), `validation`, the
//! `shards` engine, the `Coding` variant with its `Buffer`, and the `Marshaled` application
//! wrapper. docs/lanes/broadcast-collector.md tracks the rest (the harness and the mod.rs
//! tests).

pub const types = @import("types.zig");
pub const Shard = types.Shard;
pub const CodedBlock = types.CodedBlock;
pub const StoredCodedBlock = types.StoredCodedBlock;
pub const hash_context = types.hash_context;
pub const coding_config_for_participants = types.coding_config_for_participants;
pub const validation = @import("validation.zig");
pub const shards = @import("shards/root.zig");
pub const max_buffer_payload_size = types.max_buffer_payload_size;
pub const variant = @import("variant.zig");
pub const Coding = variant.Coding;
pub const Buffer = variant.Buffer;
pub const marshaled = @import("marshaled.zig");
pub const Marshaled = marshaled.Marshaled;
pub const MarshaledConfig = marshaled.MarshaledConfig;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("types_test.zig");
    _ = @import("validation_test.zig");
    _ = @import("variant_test.zig");
    _ = @import("marshaled.zig");
    _ = @import("harness.zig");
    _ = @import("mod_test.zig");
    _ = @import("fuzz.zig");
    _ = @import("test_block.zig");
    _ = @import("shards/root.zig");
}
