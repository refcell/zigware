//! What marshal reports to the application (commonware `marshal::Update`).

const std = @import("std");
const broadcast = @import("broadcast");
const types = @import("../types.zig");

/// An update for the application over blocks `B` and acknowledgements `A`.
pub fn Update(comptime B: type, comptime A: type) type {
    return union(enum) {
        const Self = @This();

        /// A new finalized tip and its finalization round. It can be reported before the
        /// finalized archives are durable, so it is no durability signal; `block` is.
        tip: struct { round: types.Round, height: types.Height, digest: B.Digest },
        /// A finalized block and the acknowledgement to signal once it is processed. Marshal
        /// emits a block only after persisting it durably, and dropping the acknowledgement
        /// while marshal waits for it stops marshal. The receiver owns both.
        block: struct { block: broadcast.Digested(B), ack: A },

        /// Releases an update nobody handled.
        pub fn deinit(self: *Self) void {
            switch (self.*) {
                .tip => {},
                .block => |*value| {
                    value.block.deinit();
                    value.ack.deinit();
                },
            }
            self.* = undefined;
        }
    };
}
