//! `current` databases (commonware's `qmdb/current`): an `any` database whose root also
//! commits to an activity bitmap grafted onto the ops tree, so proofs can show that an
//! operation is the current value of its key. So far: unordered fixed databases.

pub const batch = @import("batch.zig");
pub const canonical = @import("canonical.zig");
pub const db = @import("db.zig");
pub const Db = db.Db;
pub const Config = db.Config;
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

/// State sync (`sync.Database(Db, H)`).
pub const sync = @import("sync.zig");

test {
    _ = @import("canonical_test.zig");
    _ = @import("db_test.zig");
    _ = @import("batch_root_fuzz_test.zig");
    _ = @import("operations_fuzz_test.zig");
    _ = @import("prune_grow_fuzz_test.zig");
    _ = @import("recovery_fuzz_test.zig");
    _ = @import("sync.zig");
    _ = @import("grafting_test.zig");
    _ = @import("proof_test.zig");
    _ = @import("verification_test.zig");
    _ = @import("variable_test.zig");
}
