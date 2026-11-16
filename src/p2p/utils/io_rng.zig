//! The runtime's RNG through `std.Io` (commonware draws from the context, which is the RNG).
//! The deterministic runtime seeds it, so draws replay with the seed.

const std = @import("std");
const Io = std.Io;

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
