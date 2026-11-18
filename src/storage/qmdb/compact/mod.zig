//! A compact authenticated db that discards historical operations, retaining only a witness
//! for each applied state (commonware's `qmdb/compact`).
//!
//! One `Db(F, O, H)` serves the keyless and immutable operations: `Keyless` pins a keyless
//! operation (batches `append`), `Immutable` an immutable one (batches `set`). The API mirrors
//! the full dbs (`new_batch`, `merkleize`, `apply_batch`, `commit`, `sync`, `start_sync`,
//! chained batches, `StaleBatch` validation) over the peak-only `merkle.compact` structure.
//! Because history is discarded there is no `get`, `proof`, or `bounds`: a merkleized batch
//! proves only its own operations, and only until it is applied.
//!
//! The witness journal is the single durable source of truth: each entry is a complete witness
//! of one applied state, so a bounded `init` restores a retained state, and each retained
//! witness serves compact sync at its size. Entries strictly increase in committed size. A
//! compact-sync import (`init_from_sync`) is journaled by its first apply or durability
//! operation, which replaces the partition's previous witnesses without decoding them.
//!
//! Commits carry the inactivity floor, so the compact db's root matches the full db's.

const std = @import("std");
const merkle = @import("../../merkle/mod.zig");
const keyless = @import("../keyless/mod.zig");
const immutable = @import("../immutable/mod.zig");

pub const witness = @import("witness.zig");
pub const operation = @import("operation.zig");
pub const db = @import("db.zig");
pub const Db = db.Db;
pub const Config = db.Config;
pub const initial_root = db.initial_root;

/// The compact keyless db over values encoded by `E` (commonware's `keyless::CompactDb`).
pub fn Keyless(comptime F: type, comptime E: type, comptime H: type) type {
    merkle.check_family(F);
    return Db(F, keyless.Operation(F, E), H);
}

/// The compact immutable db over keys `K` and values encoded by `E` (commonware's
/// `immutable::CompactDb`).
pub fn Immutable(comptime F: type, comptime K: type, comptime E: type, comptime H: type) type {
    merkle.check_family(F);
    return Db(F, immutable.Operation(F, K, E), H);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("conformance_test.zig");
    _ = @import("db_test.zig");
    _ = @import("recovery_test.zig");
    _ = @import("sync_test.zig");
}
