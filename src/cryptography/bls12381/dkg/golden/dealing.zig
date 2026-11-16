//! The golden DKG's dealer messages (commonware `bls12381/dkg/golden/mod.rs`): a `Dealing`
//! (the dealer's polynomial commitment and its shares masked by the eVRF outputs), the
//! `DealerLog` pairing it with the eVRF commitments, and the signed `SignedDealerLog` that
//! dealers broadcast. Encodings match commonware byte for byte.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const math = @import("math");
const utils = @import("utils");
const primitives = @import("../../primitives/root.zig");
const transcript_mod = @import("../../../transcript.zig");
const golden = @import("../golden.zig");
const evrf = @import("evrf.zig");

const Info = golden.Info;
const PrivateKey = evrf.PrivateKey;
const PublicKey = evrf.PublicKey;
const Signature = evrf.Signature;
const Setup = evrf.Setup;
const VrfCommitments = evrf.VrfCommitments;
const Map = utils.ordered.Map;
const Poly = math.poly.Poly;
const Transcript = transcript_mod.Transcript;
const Summary = transcript_mod.Summary;
const group = primitives.group;
const Scalar = group.Scalar;
const SmallScalar = group.SmallScalar;
const G1 = group.G1;
const ModeVersion = primitives.sharing.ModeVersion;

/// The dealer-log signing namespace (commonware `NAMESPACE`).
pub const namespace_golden = "_COMMONWARE_CRYPTOGRAPHY_BLS12381_GOLDEN_DKG";

/// commonware's `(NonZeroU32, ModeVersion)` read config of the dealer messages.
pub const ReadCfg = struct { max_players: u32, max_supported_mode: ModeVersion };

/// The dealer's polynomial commitment and each player's share `f(x_i) + mask_i`.
pub const Dealing = struct {
    pub const Cfg = ReadCfg;

    nonce: Summary,
    poly: Poly(G1),
    masked_shares: Map(PublicKey, Scalar),

    pub fn deinit(self: *Dealing, gpa: Allocator) void {
        self.poly.deinit(gpa);
        self.masked_shares.deinit(gpa);
        self.* = undefined;
    }

    pub fn clone(self: Dealing, gpa: Allocator) Allocator.Error!Dealing {
        var poly = try self.poly.clone(gpa);
        errdefer poly.deinit(gpa);
        var keys = try self.masked_shares.keys.clone(gpa);
        errdefer keys.deinit(gpa);
        const values = try gpa.dupe(Scalar, self.masked_shares.values);
        return .{
            .nonce = self.nonce,
            .poly = poly,
            .masked_shares = Map(PublicKey, Scalar).from_parts(keys, values).?,
        };
    }

    pub fn encode_size(self: Dealing) usize {
        return Summary.fixed_size + self.poly.encode_size() + self.masked_shares.encode_size();
    }

    pub fn write(self: Dealing, writer: *codec.Writer) void {
        codec.write(Summary, self.nonce, writer);
        self.poly.write(writer);
        self.masked_shares.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: ReadCfg) codec.Error!Dealing {
        assert(cfg.max_players > 0);
        const nonce = try codec.read(Summary, gpa, reader);
        var poly = try Poly(G1).read(gpa, reader, .{ .range = .inclusive(1, cfg.max_players) });
        errdefer poly.deinit(gpa);
        const masked_shares = try Map(PublicKey, Scalar).read(gpa, reader, .{
            .range = .to_inclusive(cfg.max_players),
            .value = .allow_zero,
        });
        return .{ .nonce = nonce, .poly = poly, .masked_shares = masked_shares };
    }

    /// Masks each player's evaluation of `poly` with its eVRF output in `masks` (taking
    /// ownership of `masks`) and commits to `poly`.
    pub fn reckon(
        gpa: Allocator,
        info: *const Info,
        nonce: Summary,
        poly: Poly(Scalar),
        masks: Map(PublicKey, Scalar),
    ) !Dealing {
        var shares = masks;
        errdefer shares.deinit(gpa);
        for (shares.keys.items, shares.values) |player, *mask| {
            mask.* = mask.add(poly.eval(Scalar, try info.player_scalar(player)));
        }
        const commitment = try math.poly.commit(gpa, G1, poly);
        assert(commitment.coeffs.len == poly.coeffs.len);
        return .{ .nonce = nonce, .poly = commitment, .masked_shares = shares };
    }

    /// Whether the dealing is consistent with the round and the dealer's verified mask
    /// commitments `M_i = [m_i] G1`. For random small `r_i` over every player but the
    /// dealer, checks `[sum r_i z_i] G1 - sum r_i M_i == sum r_i F(x_i)`.
    pub fn check(
        self: *const Dealing,
        gpa: Allocator,
        rng: anytype,
        info: *const Info,
        dealer: PublicKey,
        mask_commitments: *const Map(PublicKey, G1),
    ) !bool {
        if (self.poly.degree_exact() != info.degree()) return false;
        if (!self.matches_previous(info, dealer)) return false;
        const count = info.players.len();
        assert(count > 0);
        const small = try gpa.alloc(SmallScalar, count);
        defer gpa.free(small);
        const commitments = try gpa.alloc(G1, count);
        defer gpa.free(commitments);
        const pairs = try gpa.alloc([2]Scalar, count);
        defer gpa.free(pairs);
        var r_z = Scalar.zero;
        var used: usize = 0;
        for (info.players.items) |player| {
            // Every player needs a masked share, the dealer too: `play` recovers from it.
            const z = self.masked_shares.get_value(player) orelse return false;
            if (player.eql(dealer)) continue;
            const r = SmallScalar.random(rng);
            const m = mask_commitments.get_value(player) orelse return false;
            // Proof: `player` is in the round's player set.
            const x = info.player_scalar(player) catch unreachable;
            small[used] = r;
            commitments[used] = m.*;
            pairs[used] = .{ r.to_scalar(), x };
            r_z = r_z.add(r.to_scalar().mul(z.*));
            used += 1;
        }
        assert(used + 1 >= count);
        const r_m = G1.msm(commitments[0..used], small[0..used]);
        const lhs = G1.generator.mul(r_z).sub(r_m);
        const rhs = try self.poly.lin_comb_eval(gpa, Scalar, pairs[0..used]);
        return lhs.eql(rhs);
    }

    /// In a reshare, the polynomial's constant must commit to the dealer's previous share.
    fn matches_previous(self: *const Dealing, info: *const Info, dealer: PublicKey) bool {
        const previous = info.previous orelse return true;
        const index = previous.players.index(dealer) orelse return false;
        const expected = previous.public.partial_public(index) catch return false;
        return self.poly.constant().eql(expected);
    }
};

/// A dealer's dealing and the eVRF commitments to its masks.
pub const DealerLog = struct {
    pub const Cfg = ReadCfg;

    commitments: VrfCommitments,
    dealing: Dealing,

    pub fn deinit(self: *DealerLog, gpa: Allocator) void {
        self.commitments.deinit(gpa);
        self.dealing.deinit(gpa);
        self.* = undefined;
    }

    pub fn encode_size(self: DealerLog) usize {
        return self.dealing.encode_size() + self.commitments.encode_size();
    }

    pub fn write(self: DealerLog, writer: *codec.Writer) void {
        self.dealing.write(writer);
        self.commitments.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: ReadCfg) codec.Error!DealerLog {
        var dealing = try Dealing.read(gpa, reader, cfg);
        errdefer dealing.deinit(gpa);
        const commitments = try VrfCommitments.read(gpa, reader, cfg.max_players);
        return .{ .commitments = commitments, .dealing = dealing };
    }
};

/// A dealer and its verified log, borrowed from the caller's logs.
pub const Entry = struct { dealer: PublicKey, log: *const DealerLog };

/// The dealers of `batch` whose eVRF commitments verify (in one batched check) and whose
/// dealings are consistent with them, in `batch` order (caller frees).
pub fn batch_check(
    gpa: Allocator,
    rng: anytype,
    setup: *const Setup,
    info: *const Info,
    batch: []const Entry,
) ![]Entry {
    const entries = try gpa.alloc(VrfCommitments.Entry, batch.len);
    defer gpa.free(entries);
    for (entries, batch) |*entry, item| entry.* = .{
        .sender = item.dealer,
        .msg = &item.log.dealing.nonce.bytes,
        .commitments = &item.log.commitments,
    };
    const outer = Transcript.resume_from(info.summary, .v1);
    var verified = try VrfCommitments.check_batch(gpa, rng, setup, &outer, &info.players, entries);
    defer {
        for (verified.values) |*value| value.deinit(gpa);
        verified.keys.deinit(gpa);
        gpa.free(verified.values);
    }
    var kept: std.ArrayList(Entry) = .empty;
    errdefer kept.deinit(gpa);
    for (batch) |item| {
        const mask_commitments = verified.get_value(item.dealer) orelse continue;
        const dealing = &item.log.dealing;
        if (!try dealing.check(gpa, rng, info, item.dealer, mask_commitments)) continue;
        try kept.append(gpa, item);
    }
    assert(kept.items.len <= batch.len);
    return kept.toOwnedSlice(gpa);
}

/// A `DealerLog` signed by its dealer; `identify` verifies it against a round.
pub const SignedDealerLog = struct {
    pub const Cfg = ReadCfg;

    dealer: PublicKey,
    signature: Signature,
    log: DealerLog,

    pub fn deinit(self: *SignedDealerLog, gpa: Allocator) void {
        self.log.deinit(gpa);
        self.* = undefined;
    }

    pub fn encode_size(self: SignedDealerLog) usize {
        return PublicKey.fixed_size + Signature.fixed_size + self.log.encode_size();
    }

    pub fn write(self: SignedDealerLog, writer: *codec.Writer) void {
        self.dealer.write(writer);
        self.signature.write(writer);
        self.log.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: ReadCfg) codec.Error!SignedDealerLog {
        const dealer = try PublicKey.read(gpa, reader, {});
        const signature = try Signature.read(gpa, reader, {});
        const log = try DealerLog.read(gpa, reader, cfg);
        return .{ .dealer = dealer, .signature = signature, .log = log };
    }

    /// Signs `log` (taking ownership) for the round `info`.
    pub fn sign(
        gpa: Allocator,
        signer: *const PrivateKey,
        info: *const Info,
        log: DealerLog,
    ) Allocator.Error!SignedDealerLog {
        var owned = log;
        errdefer owned.deinit(gpa);
        const message = try signature_message(gpa, info, &owned);
        const signature = signer.sign(namespace_golden, &message.bytes);
        return .{ .dealer = signer.public_key(), .signature = signature, .log = owned };
    }

    /// The dealer and its log when the signature verifies for `info`'s round; consumes the
    /// signed log either way (null releases it).
    pub fn identify(
        self: SignedDealerLog,
        gpa: Allocator,
        info: *const Info,
    ) Allocator.Error!?struct { PublicKey, DealerLog } {
        var owned = self;
        errdefer owned.deinit(gpa);
        const message = try signature_message(gpa, info, &owned.log);
        if (!owned.dealer.verify(namespace_golden, &message.bytes, &owned.signature)) {
            owned.deinit(gpa);
            return null;
        }
        return .{ owned.dealer, owned.log };
    }

    /// The round's transcript, forked with "dealer log" and committing the log.
    fn signature_message(gpa: Allocator, info: *const Info, log: *const DealerLog) !Summary {
        const bytes = try codec.encode(DealerLog, gpa, log.*);
        defer gpa.free(bytes);
        var t = Transcript.resume_from(info.summary, .v1).fork("dealer log");
        t.commit(bytes);
        return t.summarize();
    }
};
