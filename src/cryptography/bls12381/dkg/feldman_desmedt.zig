//! Feldman-Desmedt distributed key generation and resharing (commonware
//! `bls12381::dkg::feldman_desmedt`).
//!
//! A round binds every message to an `Info`. Each dealer (`Dealer`) deals shares of a
//! secret (its previous share when resharing) to every player and publishes a signed log of
//! the acks and reveals. Players (`Player`) acknowledge dealings and, once the logs are
//! agreed (`Logs`), finalize their share; observers compute the same public output with
//! `observe`. `deal` and `deal_anonymous` skip the protocol with a trusted dealer.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const math = @import("math");
const primitives = @import("../primitives/root.zig");

const Allocator = std.mem.Allocator;
const group = primitives.group;
const sharing_mod = primitives.sharing;
const Scalar = group.Scalar;
const Share = group.Share;
const Private = group.Private;
const Mode = sharing_mod.Mode;
const Sharing = sharing_mod.Sharing;
const Poly = sharing_mod.Poly;
const messages = @import("feldman_desmedt/messages.zig");

pub const Reveal = messages.Reveal;
pub const DealerPubMsg = messages.DealerPubMsg;
pub const DealerPrivMsg = messages.DealerPrivMsg;
pub const PlayerAck = messages.PlayerAck;
pub const AckOrReveal = messages.AckOrReveal;
pub const DealerResult = messages.DealerResult;
pub const DealerLog = messages.DealerLog;
pub const DealerLogSummary = messages.DealerLogSummary;
pub const SignedDealerLog = messages.SignedDealerLog;
pub const Output = messages.Output;

const round = @import("feldman_desmedt/round.zig");
pub const Error = round.Error;
pub const PubMsgError = round.PubMsgError;
pub const Info = round.Info;
pub const Dealer = round.Dealer;
pub const PrivMsgFor = round.PrivMsgFor;
pub const transcript_for_ack = round.transcript_for_ack;
pub const transcript_for_log = round.transcript_for_log;
pub const sign_log = round.sign_log;
pub const check_log = round.check_log;
pub const sig_ack = round.sig_ack;
pub const sig_log = round.sig_log;
pub const transcript_version = round.transcript_version;

const logs = @import("feldman_desmedt/logs.zig");
pub const Observed = logs.Observed;
pub const FaultReason = logs.FaultReason;
pub const Check = logs.Check;
pub const Failure = logs.Failure;
pub const Logs = logs.Logs;
pub const Selection = logs.Selection;
pub const check_dealer_log = logs.check_dealer_log;
pub const observe = logs.observe;

const player = @import("feldman_desmedt/player.zig");
pub const DealerMessageError = player.DealerMessageError;
pub const PersistedDealing = player.PersistedDealing;
pub const Player = player.Player;
pub const Dealt = player.Dealt;
pub const deal = player.deal;

/// A trusted dealer's sharing and every participant's share.
pub fn Dealing(comptime V: type) type {
    return struct {
        const Self = @This();
        sharing: Sharing(V),
        shares: []Share,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.sharing.deinit(gpa);
            for (self.shares) |*share| share.private.zeroize();
            gpa.free(self.shares);
            self.* = undefined;
        }
    };
}

/// Like `deal`, but for participants `0..n` without public keys (commonware
/// `deal_anonymous`): convenient for tests, though the result cannot seed a reshare.
/// Draws from `rng` exactly as commonware does.
pub fn deal_anonymous(
    comptime V: type,
    comptime M: type,
    gpa: Allocator,
    rng: anytype,
    mode: Mode,
    n: u32,
) !Dealing(V) {
    assert(n > 0);
    const dealt = try player.deal_poly(V, M, gpa, rng, mode, n);
    assert(dealt.shares.len == n);
    return .{ .sharing = dealt.public, .shares = dealt.shares };
}

test {
    _ = @import("feldman_desmedt/tests.zig");
    std.testing.refAllDecls(messages);
    std.testing.refAllDecls(round);
    std.testing.refAllDecls(logs);
    std.testing.refAllDecls(player);
    inline for (.{ variant_types.MinPk, variant_types.MinSig }) |V| {
        std.testing.refAllDecls(Info(V, ed25519.PublicKey));
        std.testing.refAllDecls(Dealer(V, ed25519.PrivateKey));
        std.testing.refAllDecls(Logs(V, ed25519.PublicKey, utils.N3f1));
        std.testing.refAllDecls(Player(V, ed25519.PrivateKey));
    }
    inline for (.{ variant_types.MinPk, variant_types.MinSig }) |V| {
        _ = DealerPubMsg(V);
        _ = DealerLog(V, ed25519.PublicKey);
        _ = SignedDealerLog(V, ed25519.PublicKey);
        _ = Output(V, ed25519.PublicKey);
        std.testing.refAllDecls(DealerLog(V, ed25519.PublicKey));
        std.testing.refAllDecls(SignedDealerLog(V, ed25519.PublicKey));
        std.testing.refAllDecls(Output(V, ed25519.PublicKey));
        std.testing.refAllDecls(DealerPubMsg(V));
    }
    std.testing.refAllDecls(AckOrReveal(ed25519.PublicKey));
    std.testing.refAllDecls(DealerResult(ed25519.PublicKey));
}

const variant_types = primitives.variant;
const ed25519 = @import("../../ed25519.zig");
