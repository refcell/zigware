//! The engine definition a plan runs on every validator (commonware
//! `glue/src/simulate/engine.rs`).
//!
//! An engine definition `D` is a type with:
//! - `pub const PublicKey`, `pub const Engine`, and `pub const State`;
//! - `pub fn participants(self: *const D) []const PublicKey`: the validator set;
//! - `pub fn channels(self: *const D) []const ChannelSpec`: the p2p channels each validator
//!   registers, in the order `InitContext.channels` holds them;
//! - `pub fn max_message_size(self: *const D) u32`: the simulated network's frame limit;
//! - `pub fn init(self: *const D, ctx: InitContext(PublicKey)) !struct { Engine, State }`;
//! - `pub fn start(engine: Engine) !Handle(void)`: starts every actor, returning a handle the
//!   plan aborts to crash the validator;
//! - optionally `pub fn deinit_state(state: *State) void`, called when a validator's state is
//!   replaced on restart or the plan ends. `State` may also declare `processed_height`.
//!
//! On restart after a crash, `init` and `start` run again with the same identity and a fresh
//! context; the deterministic runtime keeps storage.

const std = @import("std");
const p2p = @import("p2p");
const runtime = @import("runtime");
const events = @import("events.zig");
const action = @import("action.zig");

pub const Context = runtime.deterministic.Context;
pub const Handle = runtime.context.Handle(void);

/// A p2p channel each validator registers, with its rate limit.
pub const ChannelSpec = struct { channel: p2p.Channel, quota: p2p.Quota };

/// What `init` receives for one validator (commonware `InitContext<P>`).
pub fn InitContext(comptime P: type) type {
    const Network = p2p.simulated.Network(P);
    return struct {
        /// Labeled runtime context for this validator.
        context: Context,
        /// Index of this validator in the participant list.
        index: usize,
        /// Whether this validator was configured as a delayed participant.
        delayed: bool,
        /// This validator's public key.
        public_key: P,
        /// Network oracle for peer management.
        oracle: Network.Oracle,
        /// Registered channels, in `channels()` order. The engine owns the senders and
        /// receivers and deinits them when its task ends; the plan owns the slice.
        channels: []Network.Registered,
        /// All participants in the simulation.
        participants: []const P,
        /// Where to report finalizations to the plan.
        monitor: events.Monitor(P),
        /// The live storage fault configuration.
        storage_faults: *const action.FaultConfig,
    };
}

/// Asserts that `D` is an engine definition.
pub fn assert_engine(comptime D: type) void {
    comptime {
        for ([_][]const u8{
            "PublicKey", "Engine", "State", "participants", "channels", "max_message_size",
            "init",      "start",
        }) |decl| {
            if (!@hasDecl(D, decl)) @compileError("engine definition lacks " ++ decl);
        }
    }
}
