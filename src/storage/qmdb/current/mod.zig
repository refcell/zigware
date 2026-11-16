//! `current` databases (commonware's `qmdb/current`): an `any` database whose root also
//! commits to an activity bitmap grafted onto the ops tree, so proofs can show that an
//! operation is the current value of its key. So far: grafting and the proof codecs.

pub const canonical = @import("canonical.zig");
pub const grafted = @import("grafted.zig");
pub const grafting = @import("grafting.zig");
pub const proof = @import("proof.zig");
pub const verification = @import("verification.zig");
pub const OpsRootWitness = proof.OpsRootWitness;
pub const RangeProof = proof.RangeProof;
pub const OperationProof = proof.OperationProof;
pub const ordered = struct {
    pub const proof = @import("ordered/proof.zig");
};
pub const unordered = struct {
    pub const proof = @import("unordered/proof.zig");
};

test {
    _ = @import("canonical_test.zig");
    _ = @import("grafting_test.zig");
    _ = @import("proof_test.zig");
    _ = @import("verification_test.zig");
}
