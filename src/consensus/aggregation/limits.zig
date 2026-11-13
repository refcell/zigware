//! Size limits for the payloads aggregation sends (commonware `aggregation/limits.rs`).

const std = @import("std");
const types = @import("types.zig");
const scheme = @import("scheme.zig");

/// The largest payload aggregation sends: a tip ack with every varint at its widest.
pub fn max_payload_size(comptime S: type, comptime D: type) usize {
    comptime scheme.assert_scheme(S, D);
    const size = types.TipAck(S, D).max_encode_size;
    std.debug.assert(size > types.Item(D).max_encode_size);
    return size;
}
