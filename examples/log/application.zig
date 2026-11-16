//! The log application (commonware `examples/log/src/application`): the automaton, relay, and
//! reporter simplex drives.
//!
//! Proposing fills a 16-byte secret message from the runtime RNG and proposes its hash;
//! verifying accepts every payload (consensus already checked the votes, and payloads do not
//! link to a parent); broadcasting sends nothing. Commonware runs the automaton as an actor
//! answering a mailbox one request at a time. Here it is the automaton itself, called from
//! the voter's request tasks: each call is independent, so no queue is needed. Events go to
//! the `commonware_log::application` target, which the GUI shows in its Activity pane.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const zigware = @import("zigware");

const actor = zigware.actor;
const simplex = zigware.consensus.simplex;
const traces = zigware.runtime.telemetry.traces;
const ed25519 = zigware.cryptography.ed25519;

/// The log target the GUI routes to its Activity pane.
pub const target = "commonware_log::application";

/// The signing scheme of this network.
pub fn Scheme(comptime D: type) type {
    return simplex.scheme.ed25519.Scheme(D);
}

/// Genesis message to use during initialization.
pub const genesis_message = "commonware is neat";

/// The initial payload of the single consensus epoch: the hash of the genesis message. The
/// example does not link proposals to a parent, so this only seeds the consensus floor.
pub fn genesis(comptime H: type) H.Digest {
    return H.hash(&.{genesis_message});
}

/// Bytes of the secret message behind each proposal.
pub const message_size = 16;

/// The automaton and relay over hasher `H`.
pub fn Application(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const Digest = H.Digest;
        pub const PublicKey = ed25519.PublicKey;
        pub const Context = simplex.types.Context(Digest, PublicKey);
        pub const Plan = simplex.Plan(PublicKey);

        tracer: traces.Tracer,

        pub fn init(tracer: traces.Tracer) Self {
            return .{ .tracer = tracer };
        }

        /// Generates a random message (secret to us) and proposes its hash.
        pub fn propose(self: *Self, io: Io, context: Context) Io.Cancelable!?Digest {
            _ = context; // Linking payloads to their parent would include it here.
            var message: [message_size]u8 = undefined;
            io.random(&message);
            const digest = H.hash(&.{&message});
            var hex: [2 * message_size]u8 = undefined;
            const text = zigware.formatting.hex_encode(&hex, &message);
            assert(text.len == hex.len);
            self.tracer.event(.info, "proposed", .{ .msg = text, .payload = digest });
            return digest;
        }

        /// Accepts every payload: digests are already verified by consensus.
        pub fn verify(
            self: *Self,
            io: Io,
            context: Context,
            payload: Digest,
        ) Io.Cancelable!?bool {
            _ = self;
            _ = io;
            _ = context; // Linking payloads to their parent would check it here.
            _ = payload;
            return true;
        }

        /// Sends nothing: raw messages stay secret (a blockchain would send its block here).
        pub fn broadcast(self: *Self, payload: Digest, plan: Plan) actor.Feedback {
            _ = self;
            _ = payload;
            _ = plan;
            return .ok;
        }

        comptime {
            zigware.consensus.traits.assert_automaton(Self);
            zigware.consensus.traits.assert_relay(Self);
        }
    };
}

/// Logs notarizations, finalizations, and nullifications (commonware `Reporter`).
pub fn Reporter(comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Activity = simplex.types.Activity(Scheme(D), D);

        tracer: traces.Tracer,

        pub fn init(tracer: traces.Tracer) Self {
            return .{ .tracer = tracer };
        }

        pub fn report(self: *Self, activity: Activity) actor.Feedback {
            const view = activity.view().get();
            switch (activity) {
                .notarization => |notarization| self.tracer.event(.info, "notarized", .{
                    .view = view,
                    .payload = notarization.proposal.payload,
                }),
                .finalization => |finalization| self.tracer.event(.info, "finalized", .{
                    .view = view,
                    .payload = finalization.proposal.payload,
                }),
                .nullification => self.tracer.event(.info, "nullified", .{ .view = view }),
                else => {},
            }
            return .ok;
        }

        comptime {
            zigware.consensus.traits.assert_reporter(Self);
        }
    };
}
