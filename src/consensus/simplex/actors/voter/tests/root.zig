//! commonware `simplex/actors/voter/mod.rs` tests, generic over the harness fixture: ed25519
//! per push, and every scheme of `harness.fixtures` with `-Dslow-tests`.

const harness = @import("harness.zig");

test {
    inline for (harness.fixtures) |F| {
        if (comptime harness.runs(F, .schemes) or harness.runs(F, .schemes_round_robin)) {
            const h = harness.Harness(F);
            _ = @as(type, h); // The harness smoke test.
            _ = @import("restart.zig").Tests(h);
            _ = @import("backfill.zig").Tests(h);
            _ = @import("conflicts.zig").Tests(h);
            _ = @import("timeouts.zig").Tests(h);
            _ = @import("optimistic.zig").Tests(h);
            _ = @import("handoff.zig").Tests(h);
            _ = @import("handoff_held.zig").Tests(h);
            _ = @import("nullify_test.zig").Tests(h);
            _ = @import("certification_test.zig").Tests(h);
            _ = @import("verification_test.zig").Tests(h);
            _ = @import("handoff_cancel.zig").Tests(h);
            _ = @import("handoff_supersede.zig").Tests(h);
            _ = @import("handoff_restart.zig").Tests(h);
            _ = @import("handoff_dropped.zig").Tests(h);
            _ = @import("handoff_displaced.zig").Tests(h);
        }
    }
}
