//! broadcast: Disseminate data over a wide-area network.
//!
//! Zig port of commonware's `commonware-broadcast` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/broadcast). docs/lanes/
//! broadcast-collector.md tracks what is ported.
//!
//! `Broadcaster` (lib.rs) is a comptime interface, checked with `assert_broadcaster`:
//! `B.Recipients`, `B.Message` (encodable), and `b.broadcast(recipients, message)` returning
//! `Feedback` (wrapped in an error union when the request may fail to allocate). Feedback says
//! whether the local broadcast request was accepted for processing, not whether recipients
//! received the message.

const std = @import("std");
const actor = @import("actor");

pub const digested = @import("digested.zig");
pub const Digested = digested.Digested;
pub const buffered = @import("buffered/mod.zig");

pub const Feedback = actor.Feedback;

/// Asserts `B` implements `Broadcaster`.
pub fn assert_broadcaster(comptime B: type) void {
    comptime {
        for ([_][]const u8{ "Recipients", "Message", "broadcast" }) |decl| {
            if (!@hasDecl(B, decl)) @compileError(@typeName(B) ++ " lacks Broadcaster." ++ decl);
        }
    }
}

test {
    std.testing.refAllDecls(@This());
    _ = digested;
    _ = buffered;
}

test "buffered mailbox is a broadcaster" {
    const Key = @import("cryptography").ed25519.PublicKey;
    assert_broadcaster(buffered.Mailbox(Key, buffered.mocks.TestMessage));
}
