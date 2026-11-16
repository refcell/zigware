//! Processed-height introspection for simulation state (commonware
//! `glue/src/simulate/processed.rs`).

/// The latest application-acknowledged processed height of a validator's `state` (commonware
/// `ProcessedHeight`): `S.processed_height(*const S) u64`, or zero for `void` and `bool` states.
pub fn processed_height(comptime S: type, state: *const S) u64 {
    if (S == void or S == bool) return 0;
    return state.processed_height();
}
