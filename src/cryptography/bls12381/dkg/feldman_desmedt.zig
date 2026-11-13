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
