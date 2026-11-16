//! Sync errors (commonware's `qmdb/sync/error.rs`).
//!
//! Commonware's three enums become error sets. Payloads (the mismatched roots, the invalid
//! bounds) are not carried: Zig errors have none, so the engine logs them where they arise.
//! The full sync error set is `qmdb.Error || EngineError || S.Error` for a source `S`
//! (commonware's `Error::{Database, Engine, Source}`).

const qmdb = @import("../mod.zig");

/// Errors from a source when serving a request (commonware's `ServeError`).
pub const ServeError = qmdb.Error || error{
    /// The source is missing.
    MissingSource,
};

/// Errors raised by the sync engine itself (commonware's `EngineError`).
pub const EngineError = error{
    /// The synced database's root differs from the target's.
    RootMismatch,
    /// The source finished without a response that satisfies the request.
    InvalidResponse,
    /// The target's lower bound is not below its upper bound, or a bound is out of domain.
    InvalidTarget,
    /// The client is in an invalid state.
    InvalidState,
    /// A target update kept the same root.
    SyncTargetRootUnchanged,
    /// Sync stalled with no pending fetches.
    SyncStalled,
    /// The finish signal channel closed before finish was requested.
    FinishChannelClosed,
};

/// All errors of a sync from a source whose errors are `SourceError`.
pub fn Error(comptime SourceError: type) type {
    return qmdb.Error || EngineError || SourceError;
}
