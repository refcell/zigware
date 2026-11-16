//! Size limits for the payloads the state sync p2p actor sends (commonware
//! `glue/src/stateful/db/p2p/limits.rs`).
//!
//! The actor fetches and serves through a resolver, which frames each sync request (an 8-byte
//! id, a tag, and the sync request as its key) and response (the id, a tag, a length varint,
//! and the sync response as its value). An operations response carries at most
//! `max_serve_ops` operations and a boundary response one; a peer decodes at most
//! `max_proof_digests_per_element` proof digests per operation and `max_pinned_nodes` pinned
//! nodes. `max_payload_size` bounds every request and response with every count at these
//! bounds and every varint at its widest.

const std = @import("std");
const assert = std.debug.assert;
const resolver = @import("resolver");
const storage = @import("storage");

const sync = storage.qmdb.sync;

/// An upper bound on the payloads the sync actor sends when it serves at most `max_serve_ops`
/// operations per request, each encoding to at most `op` bytes. Fails with
/// `TooManyOperations` when `max_serve_ops` exceeds `u32` (commonware panics).
pub fn max_payload_size(
    comptime F: type,
    comptime D: type,
    max_serve_ops: u64,
    op: usize,
) error{TooManyOperations}!usize {
    assert(max_serve_ops > 0);
    if (max_serve_ops > std.math.maxInt(u32)) return error.TooManyOperations;
    // A response carries a proof with its operations, or a boundary operation with its pinned
    // nodes, as the resolver's value. A request carries a sync request as its key.
    const response = sync.max_response_size(F, D, @intCast(max_serve_ops), op);
    const result = resolver.p2p.wire.max_message_size(sync.Request(F), response);
    assert(result > response);
    return result;
}

test {
    _ = @import("limits_test.zig");
}
