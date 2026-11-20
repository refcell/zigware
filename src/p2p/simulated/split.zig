//! Split senders and receivers for twin (Byzantine) tests (commonware
//! `p2p/src/simulated/network.rs`: `SplitTarget`, `SplitOrigin`, `SplitForwarder`,
//! `SplitRouter`, `SplitSender`, `SplitCheckedSender`).
//!
//! A twin runs two halves of one identity over a single registered channel. `Sender.split_with`
//! yields a primary and a secondary sender whose sends a forwarder may redirect, and
//! `Receiver.split_with` routes each inbound message to the primary half, the secondary half,
//! both, or neither.
//!
//! - A forwarder `F` has `forward(f, origin: SplitOrigin, recipients: Recipients(P),
//!   message: []const u8) ?Recipients(P)`; null drops the send. A returned `some` slice must
//!   stay valid until the send returns (the input recipients qualify).
//! - A router `R` has `route(r, message: *const p2p.Message(P)) SplitTarget`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const p2p = @import("../root.zig");

const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;

/// Where a split receiver delivers an inbound message.
pub const SplitTarget = enum { none, primary, secondary, both };

/// Which half of a split sender sent a message.
pub const SplitOrigin = enum { primary, secondary };

/// The two halves of a split.
pub fn Halves(comptime T: type) type {
    return struct { primary: T, secondary: T };
}

/// One half of a split limited sender `L` (a `LimitedSender` whose checked sender has
/// `into_inner`), redirected by forwarder `F`.
pub fn SplitSender(comptime L: type, comptime F: type) type {
    const P = L.PublicKey;
    return struct {
        const Self = @This();
        pub const PublicKey = P;

        origin: SplitOrigin,
        inner: L,
        forwarder: F,

        /// Splits `sender` (consumed) into a primary and a secondary half that share its rate
        /// limiter.
        pub fn split(sender: L, forwarder: F) Halves(Self) {
            return .{
                .primary = .{ .origin = .primary, .inner = sender.clone(), .forwarder = forwarder },
                .secondary = .{ .origin = .secondary, .inner = sender, .forwarder = forwarder },
            };
        }

        pub fn clone(self: *const Self) Self {
            const inner = self.inner.clone();
            return .{ .origin = self.origin, .inner = inner, .forwarder = self.forwarder };
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit();
            self.* = undefined;
        }

        /// Defers the forwarder to send time, when the message is known (commonware
        /// `SplitCheckedSender`).
        pub const Checked = struct {
            checked: L.Checked,
            origin: SplitOrigin,
            forwarder: F,
            /// The recipients passed to `check`, borrowed from its caller.
            original: p2p.Recipients(P),

            pub const PublicKey = P;

            pub fn recipients(checked: *const Checked) []const P {
                return checked.checked.recipients();
            }

            /// Sends `parts` (concatenated) wherever the forwarder sends this half's message,
            /// bypassing the rate limiter for those recipients; null from the forwarder rejects.
            pub fn send(
                checked: Checked,
                parts: []const []const u8,
                priority: bool,
            ) Unreliable(Feedback) {
                const gpa = checked.checked.gpa;
                const owned = if (parts.len <= 1) null else std.mem.concat(gpa, u8, parts) catch {
                    checked.deinit();
                    return .rejected;
                };
                defer if (owned) |bytes| gpa.free(bytes);
                const message = owned orelse if (parts.len == 1) parts[0] else "";
                const forwarded = checked.forwarder.forward(
                    checked.origin,
                    checked.original,
                    message,
                ) orelse {
                    checked.deinit();
                    return .rejected;
                };
                // Rate limiting covered the original recipients, which may over-limit some that
                // the forwarder dropped; that is preferred to giving no feedback at all.
                const inner = checked.checked.into_inner();
                return inner.send(forwarded, &.{message}, priority);
            }

            pub fn deinit(checked: Checked) void {
                checked.checked.deinit();
            }
        };

        /// Checks the rate limit against every original recipient, as commonware does.
        pub fn check(self: *Self, recipients: p2p.Recipients(P)) !p2p.Check(Checked) {
            return switch (try self.inner.check(recipients)) {
                .limited => |time| .{ .limited = time },
                .checked => |checked| .{ .checked = .{
                    .checked = checked,
                    .origin = self.origin,
                    .forwarder = self.forwarder,
                    .original = recipients,
                } },
            };
        }

        /// Checks and sends (commonware's blanket `Sender::send`): the recipients attempted,
        /// owned by the caller; empty when every one is limited or the send is not accepted.
        pub fn send(
            self: *Self,
            recipients: p2p.Recipients(P),
            parts: []const []const u8,
            priority: bool,
        ) ![]P {
            return p2p.send(self.inner.state.gpa, self, recipients, parts, priority);
        }
    };
}
