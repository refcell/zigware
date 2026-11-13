//! What the simplex actors take from the runtime (commonware's `E: Clock + CryptoRng +
//! Spawner`): time and randomness, both through `std.Io`, so the deterministic runtime
//! replays a run exactly.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

/// Draws from the runtime RNG through `std.Io` (the context as `CryptoRng`).
pub const IoRng = struct {
    io: Io,

    pub fn next_u64(rng: IoRng) u64 {
        var bytes: [8]u8 = undefined;
        rng.io.random(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }

    pub fn next_u32(rng: IoRng) u32 {
        return @truncate(rng.next_u64());
    }

    pub fn fill_bytes(rng: IoRng, dest: []u8) void {
        rng.io.random(dest);
    }
};

/// The runtime's current time in nanoseconds (`Clock::current`).
pub fn now_ns(io: Io) i96 {
    const now = Io.Timestamp.now(io, .awake).nanoseconds;
    assert(now >= 0);
    return now;
}
