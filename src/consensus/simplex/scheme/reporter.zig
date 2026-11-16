//! A reporter wrapper that filters and verifies activity by scheme attributability
//! (commonware `simplex/scheme/reporter.rs`):
//!
//! 1. Peer activities (votes and faults) are verified before they are reported, when
//!    `verify` is set.
//! 2. Non-attributable schemes (threshold BLS) never report per-validator activity: any `t`
//!    partial signatures can forge another participant's, so it proves nothing.
//! 3. Certificates are always reported: consensus verified them, and they prove a quorum.
//!
//! Activities arrive borrowed, as with every simplex reporter; a filtered activity is simply
//! not forwarded.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const types = @import("../types.zig");

/// Wraps reporter `R` (a pointer with `report(Activity) Feedback`) for scheme `S` over
/// digests `D`, verifying with randomness `Rng` and strategy `Strategy`.
pub fn AttributableReporter(
    comptime S: type,
    comptime D: type,
    comptime Rng: type,
    comptime Strategy: type,
    comptime R: type,
) type {
    return struct {
        const Self = @This();
        pub const Activity = types.Activity(S, D);

        gpa: Allocator,
        io: Io,
        /// Guards `rng`: actors may report concurrently (commonware's `Arc<Mutex<E>>`).
        mutex: Io.Mutex = .init,
        rng: Rng,
        scheme: S,
        reporter: R,
        strategy: Strategy,
        /// Whether peer activities are verified before they are reported.
        verify: bool,

        pub fn init(
            gpa: Allocator,
            io: Io,
            rng: Rng,
            scheme: S,
            reporter: R,
            strategy: Strategy,
            verify: bool,
        ) Self {
            return .{
                .gpa = gpa,
                .io = io,
                .rng = rng,
                .scheme = scheme,
                .reporter = reporter,
                .strategy = strategy,
                .verify = verify,
            };
        }

        pub fn report(self: *Self, activity: Activity) actor.Feedback {
            // Only certificates count as verified, so this drops exactly the per-validator
            // activities of a non-attributable scheme, before spending work on them.
            if (!S.is_attributable() and !activity.verified()) return .ok;
            if (self.verify and !activity.verified() and !self.verified(activity)) return .ok;
            assert(S.is_attributable() or activity.verified());
            return self.reporter.report(activity);
        }

        /// Verifies a peer activity. Running out of memory drops it, as an unverifiable one.
        fn verified(self: *Self, activity: Activity) bool {
            assert(!activity.verified());
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return switch (activity) {
                // Proof: certificates report verified, and the caller checked it is not.
                .notarization, .certification, .nullification, .finalization => unreachable,
                inline else => |*value| value.verify(
                    self.gpa,
                    &self.rng,
                    &self.scheme,
                    self.strategy,
                ) catch false,
            };
        }
    };
}

test {
    _ = @import("reporter_test.zig");
}
