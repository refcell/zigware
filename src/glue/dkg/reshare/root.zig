//! Continuous BLS threshold-key resharing for an application chain (commonware
//! `glue::dkg::reshare`).
//!
//! Each epoch runs a Feldman-Desmedt reshare ceremony that preserves the group public key
//! without exposing the group secret. Dealers (the previous output's players) reshare their
//! shares to the epoch's players; the ceremony's public outcome is carried in finalized
//! application blocks.

pub const event = @import("event.zig");
pub const Event = event.Event;
pub const store = @import("store.zig");
pub const Store = store.Store;
pub const Dealer = store.Dealer;
pub const Player = store.Player;
pub const AckOutcome = store.AckOutcome;

test {
    @import("std").testing.refAllDecls(@This());
}
