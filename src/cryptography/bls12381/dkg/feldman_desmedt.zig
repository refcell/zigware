//! Feldman-Desmedt distributed key generation and resharing (commonware
//! `bls12381::dkg::feldman_desmedt`).
//!
//! Ported so far: the trusted dealer `deal_anonymous`, which tests use to create sharings.

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

/// Bytes of the transcript summary a dealing draws after its polynomial.
const summary_length = 32;

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

/// A trusted dealer: a random polynomial of degree `quorum(n) - 1` under fault model `M`,
/// with participant i's share at `mode.scalar(n, i)` (commonware `deal_anonymous`). Draws
/// from `rng` exactly as commonware's `deal` does, including the output's summary.
pub fn deal_anonymous(
    comptime V: type,
    comptime M: type,
    gpa: Allocator,
    rng: anytype,
    mode: Mode,
    n: u32,
) !Dealing(V) {
    assert(n > 0);
    const t = M.quorum(n);
    assert(t >= 1 and t <= n);
    var private = try Poly(Scalar).random(gpa, rng, t - 1);
    defer {
        for (private.coeffs) |*c| c.zeroize();
        private.deinit(gpa);
    }
    const shares = try gpa.alloc(Share, n);
    errdefer gpa.free(shares);
    for (shares, 0..) |*share, i| {
        const participant = utils.Participant.from_usize(i);
        const eval = private.eval(Scalar, mode.scalar(n, participant).?);
        share.* = Share.init(participant, Private.init(eval));
    }
    var summary: [summary_length]u8 = undefined;
    rng.fill_bytes(&summary);
    var committed = try math.poly.commit(gpa, V.Public, private);
    errdefer committed.deinit(gpa);
    const sharing = try Sharing(V).init(gpa, mode, n, committed);
    return .{ .sharing = sharing, .shares = shares };
}

test {
    std.testing.refAllDecls(messages);
    std.testing.refAllDecls(round);
    inline for (.{ variant_types.MinPk, variant_types.MinSig }) |V| {
        std.testing.refAllDecls(Info(V, ed25519.PublicKey));
        std.testing.refAllDecls(Dealer(V, ed25519.PrivateKey));
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
