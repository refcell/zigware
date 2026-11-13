//! Simple Authenticated Key Exchange (commonware `handshake/sake`): a shared secret
//! transcript from signed ephemeral X25519 keys, with BLAKE3 transcripts and identity
//! signatures from any signer.
//!
//! ```text
//! Dialer                                       Listener
//!   |-- Syn(t_D, X, sig_D) ----------------------->|
//!   |<-- SynAck(t_L, Y, sig_L, confirmation_l2d) --|
//!   |-- Ack(confirmation_d2l) -------------------->|
//! ```
//!
//! The transcript commits the application namespace, forks with the version's protocol
//! namespace, and (V1) commits the mode byte `1`. Then each field is one committed packet:
//!
//! | Point | V0 fields | V1 fields |
//! |-------|-----------|-----------|
//! | Before `sig_D` | `t_D, L, X` | `t_D, L, D, X` |
//! | Before `sig_L` | `t_D, L, X, D, t_L, Y` | `t_D, L, D, X, t_L, Y` |
//! | Before confirmation | then the X25519 shared secret | then the X25519 shared secret |
//!
//! Confirmations are the summaries of the final transcript forked with `confirmation_l2d`
//! and `confirmation_d2l`. Messages and transcripts are byte-identical to commonware's.
//! Callers enforce a handshake deadline separately from the accepted timestamp range.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const transcript_mod = @import("../transcript.zig");
const exchange = @import("exchange.zig");
const signer_mod = @import("../signer.zig");

const Transcript = transcript_mod.Transcript;
pub const Summary = transcript_mod.Summary;
pub const EphemeralPublicKey = exchange.EphemeralPublicKey;
pub const SecretKey = exchange.SecretKey;

const label_confirmation_l2d = "confirmation_l2d";
const label_confirmation_d2l = "confirmation_d2l";

pub const Error = error{
    /// A peer's signature does not verify over the transcript.
    InvalidSignature,
    /// A peer's ephemeral key yields a non-contributory shared secret.
    InvalidEphemeralKey,
    /// A peer's confirmation does not match the transcript.
    InvalidConfirmation,
    /// The peer's timestamp is outside the accepted range.
    InvalidTimestamp,
};

pub const Version = enum {
    v0,
    v1,

    pub fn namespace(self: Version) []const u8 {
        return switch (self) {
            .v0 => "_COMMONWARE_CRYPTOGRAPHY_HANDSHAKE",
            .v1 => "_COMMONWARE_CRYPTOGRAPHY_SAKE",
        };
    }

    pub fn transcript_version(self: Version) transcript_mod.Version {
        return switch (self) {
            .v0 => .v0,
            .v1 => .v1,
        };
    }

    /// V1 commits the dialer's identity before the dialer signs.
    pub fn binds_identity_before_syn(self: Version) bool {
        return self == .v1;
    }
};

/// Accepted peer timestamps, `[start, end)` in milliseconds.
pub const Range = struct {
    start: u64,
    end: u64,

    pub fn contains(self: Range, value: u64) bool {
        return value >= self.start and value < self.end;
    }
};

/// The final confirmation, sent by the dialer.
pub const Ack = struct {
    confirmation: Summary,

    pub const fixed_size: usize = Summary.fixed_size;

    pub fn write(self: *const Ack, writer: *codec.Writer) void {
        writer.write_bytes(&self.confirmation.bytes);
    }

    pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, cfg: void) codec.Error!Ack {
        return .{ .confirmation = try Summary.read(gpa, reader, cfg) };
    }
};

fn commit_u64(transcript: *Transcript, value: u64) void {
    transcript.commit(&codec.encode_fixed(u64, value));
}

fn commit_encoded(transcript: *Transcript, comptime T: type, value: T) void {
    transcript.commit(&codec.encode_fixed(T, value));
}

/// Commits the shared secret and zeroizes it.
fn commit_secret(transcript: *Transcript, shared: *exchange.SharedSecret) void {
    transcript.commit(shared);
    std.crypto.secureZero(u8, shared);
}

fn confirmation(transcript: *const Transcript, label: []const u8) Summary {
    return transcript.fork(label).summarize();
}

/// SAKE for the signer type `S` (with `S.PublicKey` and `S.Signature`).
pub fn Sake(comptime S: type) type {
    comptime signer_mod.assert_signer(S);
    const P = S.PublicKey;
    const Sig = S.Signature;
    const signature_size = codec.fixed_size(Sig).?;

    return struct {
        /// The dialer's greeting.
        pub const Syn = struct {
            time_ms: u64,
            epk: EphemeralPublicKey,
            signature: Sig,

            pub const fixed_size: usize = 8 + EphemeralPublicKey.fixed_size + signature_size;

            pub fn write(self: *const Syn, writer: *codec.Writer) void {
                writer.write_int(u64, self.time_ms);
                self.epk.write(writer);
                codec.write(Sig, self.signature, writer);
            }

            pub fn read(gpa: std.mem.Allocator, reader: *codec.Reader, cfg: void) codec.Error!Syn {
                return .{
                    .time_ms = try reader.read_int(u64),
                    .epk = try EphemeralPublicKey.read(gpa, reader, cfg),
                    .signature = try codec.read(Sig, gpa, reader),
                };
            }
        };

        /// The listener's response with its key confirmation.
        pub const SynAck = struct {
            time_ms: u64,
            epk: EphemeralPublicKey,
            signature: Sig,
            confirmation: Summary,

            pub const fixed_size: usize = Syn.fixed_size + Summary.fixed_size;

            pub fn write(self: *const SynAck, writer: *codec.Writer) void {
                writer.write_int(u64, self.time_ms);
                self.epk.write(writer);
                codec.write(Sig, self.signature, writer);
                writer.write_bytes(&self.confirmation.bytes);
            }

            pub fn read(
                gpa: std.mem.Allocator,
                reader: *codec.Reader,
                cfg: void,
            ) codec.Error!SynAck {
                return .{
                    .time_ms = try reader.read_int(u64),
                    .epk = try EphemeralPublicKey.read(gpa, reader, cfg),
                    .signature = try codec.read(Sig, gpa, reader),
                    .confirmation = try Summary.read(gpa, reader, cfg),
                };
            }
        };

        /// One peer's setup: its signer, the expected peer, its clock, and the accepted range.
        pub const Context = struct {
            version: Version,
            transcript: Transcript,
            current_time_ms: u64,
            ok_timestamps: Range,
            my_identity: S,
            peer_identity: P,

            pub fn init(
                namespace: []const u8,
                current_time_ms: u64,
                ok_timestamps: Range,
                my_identity: S,
                peer_identity: P,
                version: Version,
            ) Context {
                const base = Transcript.init(namespace, version.transcript_version());
                var transcript = base.fork(version.namespace());
                if (version == .v1) transcript.commit(&.{1});
                return .{
                    .version = version,
                    .transcript = transcript,
                    .current_time_ms = current_time_ms,
                    .ok_timestamps = ok_timestamps,
                    .my_identity = my_identity,
                    .peer_identity = peer_identity,
                };
            }
        };

        pub const DialState = struct {
            esk: SecretKey,
            peer_identity: P,
            transcript: Transcript,
            ok_timestamps: Range,
        };

        pub const ListenState = struct {
            transcript: Transcript,
        };

        pub const DialStart = struct { state: DialState, syn: Syn };
        pub const DialEnd = struct { ack: Ack, transcript: Transcript };
        pub const ListenStart = struct { state: ListenState, syn_ack: SynAck };

        /// Draws the dialer's ephemeral key from `rng` and signs the initial transcript.
        pub fn dial_start(rng: anytype, context: Context) DialStart {
            var ctx = context;
            const esk = SecretKey.random(rng);
            const epk = esk.public();
            const dialer = ctx.my_identity.public_key();
            const binds = ctx.version.binds_identity_before_syn();
            commit_u64(&ctx.transcript, ctx.current_time_ms);
            commit_encoded(&ctx.transcript, P, ctx.peer_identity);
            if (binds) commit_encoded(&ctx.transcript, P, dialer);
            ctx.transcript.commit(&epk.bytes);
            const signature = ctx.transcript.sign(&ctx.my_identity);
            if (!binds) commit_encoded(&ctx.transcript, P, dialer);
            return .{
                .state = .{
                    .esk = esk,
                    .peer_identity = ctx.peer_identity,
                    .transcript = ctx.transcript,
                    .ok_timestamps = ctx.ok_timestamps,
                },
                .syn = .{ .time_ms = ctx.current_time_ms, .epk = epk, .signature = signature },
            };
        }

        /// Checks the listener's response; returns the `Ack` to send (before any application
        /// data) and the secret transcript.
        pub fn dial_end(dial_state: DialState, message: SynAck) Error!DialEnd {
            var state = dial_state;
            defer state.esk.zeroize();
            if (!state.ok_timestamps.contains(message.time_ms)) return error.InvalidTimestamp;
            commit_u64(&state.transcript, message.time_ms);
            state.transcript.commit(&message.epk.bytes);
            if (!state.transcript.verify(&state.peer_identity, &message.signature)) {
                return error.InvalidSignature;
            }
            var shared = state.esk.exchange(&message.epk) orelse return error.InvalidEphemeralKey;
            commit_secret(&state.transcript, &shared);
            const l2d = confirmation(&state.transcript, label_confirmation_l2d);
            if (!l2d.eql(message.confirmation)) return error.InvalidConfirmation;
            const d2l = confirmation(&state.transcript, label_confirmation_d2l);
            return .{ .ack = .{ .confirmation = d2l }, .transcript = state.transcript };
        }

        /// Checks the dialer's greeting, then draws the listener's ephemeral key from `rng`
        /// and responds.
        pub fn listen_start(rng: anytype, context: Context, message: Syn) Error!ListenStart {
            var ctx = context;
            if (!ctx.ok_timestamps.contains(message.time_ms)) return error.InvalidTimestamp;
            try verify_syn(&ctx, &message);
            var esk = SecretKey.random(rng);
            defer esk.zeroize();
            const epk = esk.public();
            commit_u64(&ctx.transcript, ctx.current_time_ms);
            ctx.transcript.commit(&epk.bytes);
            const signature = ctx.transcript.sign(&ctx.my_identity);
            var shared = esk.exchange(&message.epk) orelse return error.InvalidEphemeralKey;
            commit_secret(&ctx.transcript, &shared);
            return .{
                .state = .{ .transcript = ctx.transcript },
                .syn_ack = .{
                    .time_ms = ctx.current_time_ms,
                    .epk = epk,
                    .signature = signature,
                    .confirmation = confirmation(&ctx.transcript, label_confirmation_l2d),
                },
            };
        }

        /// Commits the dialer's fields and verifies its signature.
        fn verify_syn(ctx: *Context, message: *const Syn) Error!void {
            const binds = ctx.version.binds_identity_before_syn();
            commit_u64(&ctx.transcript, message.time_ms);
            commit_encoded(&ctx.transcript, P, ctx.my_identity.public_key());
            if (binds) commit_encoded(&ctx.transcript, P, ctx.peer_identity);
            ctx.transcript.commit(&message.epk.bytes);
            if (!ctx.transcript.verify(&ctx.peer_identity, &message.signature)) {
                return error.InvalidSignature;
            }
            if (!binds) commit_encoded(&ctx.transcript, P, ctx.peer_identity);
        }

        /// Checks the dialer's confirmation and returns the secret transcript.
        pub fn listen_end(state: ListenState, message: Ack) Error!Transcript {
            const d2l = confirmation(&state.transcript, label_confirmation_d2l);
            if (!d2l.eql(message.confirmation)) return error.InvalidConfirmation;
            return state.transcript;
        }
    };
}

comptime {
    assert(Ack.fixed_size == 32);
}

test {
    _ = @import("exchange.zig");
    _ = @import("sake_test.zig");
}
