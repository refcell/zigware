//! Resolver deliveries awaiting batch certificate verification (commonware
//! `marshal/core/delivery.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const broadcast = @import("broadcast");
const cryptography = @import("cryptography");
const resolver_api = @import("resolver");
const utils = @import("utils");
const types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");

const oneshot = utils.channel.oneshot;
const Outcome = resolver_api.Outcome;

/// A resolver delivery whose certificate is parsed and awaits batch verification. Each item
/// carries the scope it was admitted under, so verification does not depend on the provider
/// still serving that epoch. It owns everything it holds.
pub fn PendingVerification(comptime S: type, comptime V: type) type {
    return union(enum) {
        const Self = @This();
        pub const Scoped = cryptography.certificate.Scoped(S);
        pub const Notarization = simplex_types.Notarization(S, V.Commitment);
        pub const Finalization = simplex_types.Finalization(S, V.Commitment);

        notarized: struct {
            scoped: Scoped,
            notarization: Notarization,
            /// The delivered bytes; the block's encoding starts at `block_offset`.
            value: []const u8,
            block_offset: usize,
            response: oneshot.Sender(Outcome),
        },
        finalized: struct {
            scoped: Scoped,
            finalization: Finalization,
            block: broadcast.Digested(V.ApplicationBlock),
            response: oneshot.Sender(Outcome),
        },

        /// The scope the delivery was admitted under.
        pub fn scoped(self: *const Self) Scoped {
            return switch (self.*) {
                inline else => |*item| item.scoped,
            };
        }

        pub fn response_closed(self: *const Self) bool {
            return switch (self.*) {
                inline else => |*item| item.response.is_closed(),
            };
        }

        /// What the certificate signs and the certificate itself (borrowed).
        pub fn certificate_item(self: *const Self) cryptography.certificate.CertificateItem(S) {
            return switch (self.*) {
                .notarized => |*item| .{
                    .subject = item.notarization.subject(),
                    .certificate = &item.notarization.certificate,
                },
                .finalized => |*item| .{
                    .subject = item.finalization.subject(),
                    .certificate = &item.finalization.certificate,
                },
            };
        }

        pub fn epoch(self: *const Self) types.Epoch {
            return switch (self.*) {
                .notarized => |*item| item.notarization.epoch(),
                .finalized => |*item| item.finalization.epoch(),
            };
        }

        /// Answers the delivery with `outcome`; a requester that stopped waiting is ignored.
        pub fn respond(self: *Self, outcome: Outcome) void {
            switch (self.*) {
                inline else => |*item| item.response.send(outcome) catch {},
            }
        }

        /// Releases the delivery, closing its response if it was not answered.
        pub fn deinit(self: *Self, gpa: Allocator, answered: bool) void {
            switch (self.*) {
                .notarized => |*item| {
                    if (!answered) item.response.deinit();
                    item.notarization.deinit(gpa);
                    gpa.free(item.value);
                },
                .finalized => |*item| {
                    if (!answered) item.response.deinit();
                    item.finalization.deinit(gpa);
                    item.block.deinit();
                },
            }
            self.* = undefined;
        }
    };
}

test {
    _ = PendingVerification;
}
