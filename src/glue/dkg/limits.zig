//! Size limits for the payloads DKG sends (commonware `glue::dkg::limits`).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const types = @import("types.zig");

/// The widest epoch subchannel prefix (commonware `p2p::utils::mux::prefixed`): a `u64` varint.
const subchannel_prefix_max = codec.varint.max_size(u64);

/// An upper bound on the payloads DKG sends for committees of at most `max_participants`
/// members. DKG sends only dealings and acknowledgements, each on the subchannel of its epoch.
pub fn max_payload_size(comptime V: type, comptime P: type, max_participants: u32) usize {
    assert(max_participants > 0);
    const message = types.Message(V, P).max_encode_size_with(max_participants);
    assert(message > subchannel_prefix_max);
    return message + subchannel_prefix_max;
}

test {
    _ = @import("limits_test.zig");
}
