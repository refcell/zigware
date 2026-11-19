//! The clock a `Rayon` strategy reads to time measured runs and spawns (commonware's
//! `rayon::Clock`): the pool's `std.Io` clock, or a `TestClock` that tests advance by hand so
//! every measurement is exact whatever the machine's load.

const std = @import("std");
const assert = std.debug.assert;

pub const Clock = union(enum) {
    /// The pool's monotonic `std.Io` clock.
    wall,
    /// A clock tests advance explicitly.
    virtual: *TestClock,

    /// Nanoseconds on this clock, reading `io` for the wall clock.
    pub fn now_ns(clock: Clock, io: std.Io) u64 {
        switch (clock) {
            .wall => {
                const now = std.Io.Clock.awake.now(io).nanoseconds;
                assert(now >= 0);
                return @intCast(now);
            },
            .virtual => |virtual| return virtual.now_ns(),
        }
    }
};

/// A clock tests advance (commonware `TestClock`). `spin` passes time on the calling thread
/// alone, so only the job running there is charged for it; `elapse` passes it for every thread.
pub const TestClock = struct {
    elapsed_ns: std.atomic.Value(u64) = .init(0),

    /// The nanoseconds the calling thread has spun on virtual clocks.
    threadlocal var spun_ns: u64 = 0;

    /// Passes `ns` on the calling thread alone.
    pub fn spin(clock: *TestClock, ns: u64) void {
        _ = clock;
        const before = spun_ns;
        spun_ns +%= ns;
        assert(spun_ns -% before == ns);
    }

    /// Passes `ns` for every thread.
    pub fn elapse(clock: *TestClock, ns: u64) void {
        const before = clock.elapsed_ns.fetchAdd(ns, .acq_rel);
        assert(before +% ns >= before);
    }

    pub fn now_ns(clock: *const TestClock) u64 {
        return clock.elapsed_ns.load(.acquire) +% spun_ns;
    }
};
