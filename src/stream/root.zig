//! stream: Exchange messages over arbitrary transport.
//!
//! Zig port of commonware's `commonware-stream` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/stream).
//!
//! - `cups`: CUPS, an upgrader that runs a handshake, then exchanges encrypted, ordered records.
//! - `sake`: the SAKE handshake over a byte stream; `SakeCups(S, C)` combines the two.
//! - `utils.codec`: length-prefixed framing.
//! - Transports are any sink/stream pair with the contract in `runtime.mocks`:
//!   `runtime.mocks.channel` for tests, `runtime.network` connections otherwise.
//!
//! # Interfaces (commonware `Handshake`, `Upgrader`)
//!
//! A handshake authenticates a raw connection and agrees on a secret transcript `T` that
//! commits to the namespace and both identities, is fresh and secret, and is returned by each
//! peer only after it verified that the other holds `T`. It must not read past its final
//! message. Shape (duck-typed):
//!
//! ```zig
//! pub fn public_key(self) PublicKey
//! pub fn dial(self, io, namespace, peer: PublicKey, stream: *Stream, sink: *Sink) !Transcript
//! pub fn listen(self, io, namespace, bouncer, stream: *Stream, sink: *Sink)
//!     !stream.Accepted(PublicKey)
//! ```
//!
//! The bouncer sees the peer's unauthenticated identity claim through `bouncer.admit(peer)
//! !bool`; only a successful `listen` proves it. An upgrader (`cups.Cups`) takes ownership of
//! a stream and sink, runs the handshake, and returns sender and receiver halves. Callers
//! enforce a deadline on every attempt and discard the connection after any error.

const std = @import("std");
const cryptography = @import("cryptography");

pub const cups = @import("cups.zig");
pub const sake = @import("sake.zig");
pub const utils = @import("utils.zig");

/// CUPS running a SAKE handshake with signer `S` and cipher `C`.
pub fn SakeCups(comptime S: type, comptime C: type) type {
    return cups.Cups(sake.Sake(S), C);
}

/// What a handshake's `listen` returns: the admitted peer and the shared secret transcript.
pub fn Accepted(comptime PublicKey: type) type {
    return struct {
        peer: PublicKey,
        transcript: cryptography.Transcript,
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("fuzz.zig");
}
