//! collector: Collect responses to committable requests.
//!
//! Zig port of commonware's `commonware-collector` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/collector). docs/lanes/
//! broadcast-collector.md tracks what is ported.
//!
//! The lib.rs traits are comptime interfaces, checked with the `assert_*` functions below:
//!
//! - `Originator`: `O.PublicKey`, `O.Request` (Committable, Digestible, codec),
//!   `o.send(recipients, request)` and `o.cancel(commitment)`, each returning `Feedback` (in
//!   an `Allocator.Error!` union when they may allocate). Tracked commitments are not removed
//!   until explicitly canceled.
//! - `Handler`: `H.PublicKey`, `H.Request`, `H.Response` (same commitment and digest types as
//!   the request), and `h.process(origin, request, responder: oneshot.Sender(Response))`,
//!   which owns `request` and `responder`; drop (`deinit`) the responder to send no reply.
//! - `Monitor`: `M.PublicKey`, `M.Response`, and `m.collected(handler, response, count)`,
//!   called once per handler with the number of responses collected so far for the same
//!   commitment.

const std = @import("std");
const actor = @import("actor");
const cryptography = @import("cryptography");

pub const p2p = @import("p2p/mod.zig");

pub const Feedback = actor.Feedback;

fn assert_decls(
    comptime T: type,
    comptime decls: []const []const u8,
    comptime trait: []const u8,
) void {
    comptime {
        for (decls) |decl| {
            if (!@hasDecl(T, decl)) {
                @compileError(@typeName(T) ++ " lacks " ++ trait ++ "." ++ decl);
            }
        }
    }
}

/// Asserts `O` implements `Originator`.
pub fn assert_originator(comptime O: type) void {
    assert_decls(O, &.{ "PublicKey", "Request", "send", "cancel" }, "Originator");
    cryptography.assert_committable(O.Request);
    cryptography.assert_digestible(O.Request);
}

/// Asserts `H` implements `Handler`.
pub fn assert_handler(comptime H: type) void {
    assert_decls(H, &.{ "PublicKey", "Request", "Response", "process" }, "Handler");
    cryptography.assert_committable(H.Request);
    cryptography.assert_digestible(H.Request);
    comptime std.debug.assert(H.Response.Commitment == H.Request.Commitment);
    comptime std.debug.assert(H.Response.Digest == H.Request.Digest);
}

/// Asserts `M` implements `Monitor`.
pub fn assert_monitor(comptime M: type) void {
    assert_decls(M, &.{ "PublicKey", "Response", "collected" }, "Monitor");
    cryptography.assert_committable(M.Response);
}

test {
    std.testing.refAllDecls(@This());
    _ = p2p;
}
