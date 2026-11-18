//! Simplex-like BFT agreement with an embedded VRF and succinct certificates (commonware
//! `consensus::simplex`). docs/lanes/consensus-simplex.md tracks what is ported.

const std = @import("std");

pub const types = @import("types.zig");
pub const Attestation = @import("cryptography").certificate.Attestation;
pub const Deferred = @import("cryptography").certificate.Deferred;
pub const elector = @import("elector.zig");
pub const limits = @import("limits.zig");
pub const config = @import("config.zig");
pub const metrics = @import("metrics.zig");
pub const lookahead = @import("lookahead.zig");
pub const Lookahead = lookahead.Lookahead;
pub const Viewport = lookahead.Viewport;
pub const Plan = lookahead.Plan;

pub const actors = struct {
    pub const batcher = struct {
        pub const votes = @import("actors/batcher/votes.zig");
        pub const verifier = @import("actors/batcher/verifier.zig");
        pub const round = @import("actors/batcher/round.zig");
        pub const ingress = @import("actors/batcher/ingress.zig");
        pub const actor = @import("actors/batcher/actor.zig");
    };
    pub const ask = @import("actors/ask.zig");
    pub const inbox = @import("actors/inbox.zig");
    pub const voter = struct {
        pub const ingress = @import("actors/voter/ingress.zig");
        pub const slot = @import("actors/voter/slot.zig");
        pub const round = @import("actors/voter/round.zig");
        pub const views = @import("actors/voter/views.zig");
        pub const state = @import("actors/voter/state.zig");
        pub const actor = @import("actors/voter/actor.zig");
    };
    pub const resolver = struct {
        pub const ingress = @import("actors/resolver/ingress.zig");
        pub const state = @import("actors/resolver/state.zig");
        pub const actor = @import("actors/resolver/actor.zig");
    };
};

pub const engine = @import("engine.zig");
pub const Engine = engine.Engine;

pub const mocks = struct {
    pub const relay = @import("mocks/relay.zig");
    pub const application = @import("mocks/application.zig");
    pub const reporter = @import("mocks/reporter.zig");
    pub const conflicter = @import("mocks/conflicter.zig");
    pub const nuller = @import("mocks/nuller.zig");
    pub const impersonator = @import("mocks/impersonator.zig");
    pub const outdated = @import("mocks/outdated.zig");
    pub const equivocator = @import("mocks/equivocator.zig");
    pub const reconfigurer = @import("mocks/reconfigurer.zig");
    pub const nullify_only = @import("mocks/nullify_only.zig");
    pub const twins = @import("mocks/twins.zig");
    pub const wrapped = @import("mocks/wrapped.zig");
    pub const scheme = @import("mocks/scheme.zig");
};

pub const scheme = struct {
    pub const namespace = @import("scheme/namespace.zig");
    pub const Namespace = namespace.Namespace;
    pub const ed25519 = @import("scheme/ed25519.zig");
    pub const bls12381_multisig = @import("scheme/bls12381_multisig.zig");
    pub const secp256r1 = @import("scheme/secp256r1.zig");
    pub const reporter = @import("scheme/reporter.zig");
    pub const bls12381_threshold = struct {
        pub const vrf = @import("scheme/bls12381_threshold/vrf.zig");
        pub const standard = @import("scheme/bls12381_threshold/standard.zig");
    };
};

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = elector;
    _ = limits;
    _ = config;
    _ = metrics;
    _ = lookahead;
    _ = actors.batcher.votes;
    _ = actors.batcher.verifier;
    _ = actors.batcher.round;
    _ = @import("actors/ingress_test.zig");
    _ = @import("actors/batcher/actor_test.zig");
    _ = actors.voter.slot;
    _ = actors.voter.round;
    _ = actors.voter.views;
    _ = actors.voter.state;
    _ = actors.ask;
    _ = actors.resolver.state;
    _ = @import("actors/resolver/state_test.zig");
    _ = @import("actors/resolver/actor_test.zig");
    _ = @import("actors/resolver/actor_network_test.zig");
    _ = @import("actors/resolver/ingress_test.zig");
    _ = @import("actors/voter/ingress_test.zig");
    _ = @import("engine_test.zig");
    _ = @import("twins_campaign_test.zig");
    _ = @import("tle_test.zig");
    _ = @import("fixtures_test.zig");
    _ = scheme.bls12381_threshold.vrf;
    _ = scheme.bls12381_threshold.standard;
    _ = scheme.namespace;
    _ = scheme.reporter;
    _ = mocks.twins;
    _ = scheme.ed25519;
    _ = scheme.bls12381_multisig;
    _ = scheme.secp256r1;
}
