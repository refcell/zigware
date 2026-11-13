//! Run Simple Authenticated Key Exchange (SAKE) over an ordered byte stream (commonware
//! `stream/src/sake`). `Sake` implements the handshake contract in `root.zig` on top of
//! `cryptography.handshake.sake`, returning a confirmed secret transcript.
//!
//! # Protocol
//!
//! The dialer knows the expected listener identity. It first sends its own public key in a
//! cleartext prelude. The listener passes this unauthenticated claim to its bouncer and
//! proceeds only if admitted, using that identity as the expected peer in SAKE. The peers then
//! exchange `Syn`, `SynAck`, and `Ack`. The listener verifies `Syn` before sending `SynAck`; the
//! dialer returns its transcript after sending `Ack`; the listener returns the admitted
//! identity and its transcript only after verifying `Ack`.
//!
//! Every prelude or handshake message is a canonical u32 varint length prefix followed by its
//! encoding, bounded by that type's fixed size and decoded exactly. Completion leaves later
//! bytes for the record protocol.
//!
//! Each peer samples its clock when it builds its SAKE context: the dialer before sending
//! `Syn`, the listener after receiving it. Peer timestamps must lie in
//! `[now - max_handshake_age, now + synchrony_bound)`, saturating at the u64 bounds. Callers
//! enforce a deadline covering the whole attempt, bouncer included.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const handshake = cryptography.handshake.sake;
const Transcript = cryptography.Transcript;

const stream_root = @import("root.zig");
const framing = @import("utils/codec.zig");

pub const Version = handshake.Version;

/// Errors that can occur during a SAKE handshake.
pub const Error = error{
    /// The bouncer rejected the peer's identity claim.
    PeerRejected,
    /// A handshake frame does not decode as its message.
    UnableToDecode,
} || handshake.Error || framing.Error;

/// Adapts `std.Io` randomness (the runtime RNG) to the `fill_bytes` generator interface.
const IoRng = struct {
    io: Io,

    pub fn fill_bytes(rng: *IoRng, dest: []u8) void {
        rng.io.random(dest);
    }
};

/// Sends `value` as one frame bounded by its fixed encoded size.
fn send_handshake_frame(comptime T: type, sink: anytype, value: T) framing.Error!void {
    const size = comptime codec.fixed_size(T).?;
    const bytes = codec.encode_fixed(T, value);
    comptime assert(bytes.len == size);
    try framing.send_frame(sink, &.{&bytes}, size);
}

/// Receives one frame bounded by `T`'s fixed encoded size and decodes it exactly.
fn recv_handshake_frame(comptime T: type, stream: anytype) Error!T {
    const size = comptime codec.fixed_size(T).?;
    var buffer: [size]u8 = undefined;
    const frame = try framing.recv_frame(stream, &buffer, size);
    assert(frame.len <= size);
    return codec.decode(T, std.mem.Allocator.failing, frame) catch error.UnableToDecode;
}

/// The SAKE handshake for signer type `S` (for example `cryptography.ed25519.PrivateKey`).
pub fn Sake(comptime S: type) type {
    const Protocol = handshake.Sake(S);
    return struct {
        const Self = @This();
        pub const PublicKey = S.PublicKey;

        /// Signer used to authenticate the local peer.
        signer: S,
        /// Maximum time drift allowed for future timestamps.
        synchrony_bound_ms: u64,
        /// Maximum age of handshake messages before rejection.
        max_handshake_age_ms: u64,
        version: Version,

        pub fn public_key(self: Self) PublicKey {
            return self.signer.public_key();
        }

        /// The SAKE context for a handshake with `peer` in `namespace`, sampling the clock now.
        fn context(self: Self, io: Io, namespace: []const u8, peer: PublicKey) Protocol.Context {
            const now_ns = Io.Clock.real.now(io).nanoseconds;
            assert(now_ns >= 0);
            const now_ms: u64 = @intCast(@divFloor(now_ns, std.time.ns_per_ms));
            // Accept peer timestamps from `max_handshake_age` before now up to, but excluding,
            // `synchrony_bound` after now.
            const ok_timestamps: handshake.Range = .{
                .start = now_ms -| self.max_handshake_age_ms,
                .end = now_ms +| self.synchrony_bound_ms,
            };
            return .init(namespace, now_ms, ok_timestamps, self.signer, peer, self.version);
        }

        /// Authenticates an outbound connection to `peer` and returns the secret transcript.
        pub fn dial(
            self: Self,
            io: Io,
            namespace: []const u8,
            peer: PublicKey,
            stream: anytype,
            sink: anytype,
        ) Error!Transcript {
            // Send the local identity as a cleartext prelude for the listener's bouncer.
            try send_handshake_frame(PublicKey, sink, self.signer.public_key());

            var rng: IoRng = .{ .io = io };
            const start = Protocol.dial_start(&rng, self.context(io, namespace, peer));
            try send_handshake_frame(Protocol.Syn, sink, start.syn);

            const syn_ack = try recv_handshake_frame(Protocol.SynAck, stream);
            const end = try Protocol.dial_end(start.state, syn_ack);
            try send_handshake_frame(handshake.Ack, sink, end.ack);
            return end.transcript;
        }

        /// Authenticates an inbound connection admitted by `bouncer` (`admit(peer) !bool`) and
        /// returns the peer with the secret transcript.
        pub fn listen(
            self: Self,
            io: Io,
            namespace: []const u8,
            bouncer: anytype,
            stream: anytype,
            sink: anytype,
        ) !stream_root.Accepted(PublicKey) {
            // Consult the bouncer on the unauthenticated claim before any handshake work. Only a
            // successful `listen_end` authenticates it.
            const peer = try recv_handshake_frame(PublicKey, stream);
            if (!try bouncer.admit(peer)) return error.PeerRejected;

            const syn = try recv_handshake_frame(Protocol.Syn, stream);
            // Read the clock only after the Syn arrives, so the acceptance window and the SynAck
            // timestamp reflect when the Syn is checked.
            var rng: IoRng = .{ .io = io };
            const start = try Protocol.listen_start(&rng, self.context(io, namespace, peer), syn);
            try send_handshake_frame(Protocol.SynAck, sink, start.syn_ack);

            const ack = try recv_handshake_frame(handshake.Ack, stream);
            const transcript = try Protocol.listen_end(start.state, ack);
            return .{ .peer = peer, .transcript = transcript };
        }
    };
}

test {
    _ = @import("sake_test.zig");
}
