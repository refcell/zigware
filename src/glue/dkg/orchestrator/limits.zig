//! Size limits for the payloads the orchestrator sends (commonware
//! `glue::dkg::orchestrator::limits`).

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("consensus");
const p2p = @import("p2p");

/// An upper bound on the payloads the orchestrator sends for committees of at most
/// `participants` members: every Simplex message travels on the subchannel of its epoch.
pub fn max_payload_size(comptime S: type, comptime D: type, participants: u32) usize {
    assert(participants > 0);
    const simplex = consensus.simplex.limits.max_payload_size(S, D, participants);
    const result = p2p.utils.mux.prefixed(simplex);
    assert(result > simplex);
    return result;
}

const testing = std.testing;
const cryptography = @import("cryptography");

// commonware `prefixes_simplex`.
test "orchestrator limits: payloads are simplex's plus the subchannel prefix" {
    const Digest = cryptography.Sha256.Digest;
    const Scheme = consensus.simplex.scheme.ed25519.Scheme(Digest);
    for ([_]u32{ 1, 4, 128 }) |participants| {
        const bound = max_payload_size(Scheme, Digest, participants);
        const simplex = consensus.simplex.limits.max_payload_size(Scheme, Digest, participants);
        try testing.expectEqual(p2p.utils.mux.prefixed(simplex), bound);
        try testing.expectEqual(simplex + 10, bound);
    }
}
