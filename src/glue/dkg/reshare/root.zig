//! Continuous BLS threshold-key resharing for an application chain (commonware
//! `glue::dkg::reshare`).
//!
//! Each epoch runs a Feldman-Desmedt reshare ceremony that preserves the group public key
//! without exposing the group secret. Dealers (the previous output's players) reshare their
//! shares to the epoch's players; the ceremony's public outcome is carried in finalized
//! application blocks.

pub const actor = @import("actor/root.zig");
pub const event = @import("event.zig");
pub const Event = event.Event;
pub const store = @import("store.zig");
pub const Store = store.Store;
pub const Dealer = store.Dealer;
pub const Player = store.Player;
pub const AckOutcome = store.AckOutcome;
pub const mailbox = @import("mailbox.zig");
pub const Mailbox = mailbox.Mailbox;
pub const Message = mailbox.Message;
pub const LogReservation = mailbox.LogReservation;
pub const EpochInfoResponse = mailbox.EpochInfoResponse;
pub const metrics = @import("metrics.zig");
pub const Metrics = metrics.Metrics;
pub const Phase = metrics.Phase;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("mailbox_test.zig");
    _ = @import("metrics_test.zig");
}
