//! The golden DKG's eVRF keys (commonware `bls12381/dkg/golden/evrf/mod.rs`): Banderwagon
//! private and public keys with Schnorr signatures, and the receiver-side VRF evaluation.
//!
//! Signing uses a deterministic nonce drawn from a transcript fork that commits the secret
//! key, so a key signs a message the same way every time, byte-identical to commonware.
//!
//! A dealer proves its VRF outputs with `PrivateKey.vrf_batch_checked`: a bulletproofs
//! circuit proof (over a shared `Setup`) that commits each receiver's output, and one
//! pedersen_to_plain proof per receiver that opens the commitment as `[output] G1`.
//! `VrfCommitments.check_batch` verifies many dealers in one batched check.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const formatting = @import("formatting");
const signer = @import("../../../signer.zig");
const secret = @import("../../../secret.zig");
const transcript = @import("../../../transcript.zig");
const utils = @import("utils");
const math = @import("math");
const bulletproofs = @import("../../../zk/bulletproofs.zig").circuit;
const pedersen_to_plain = @import("../../../zk/pedersen_to_plain.zig");

pub const banderwagon = @import("evrf/banderwagon.zig");

const F = banderwagon.F;
const G = banderwagon.G;
const group = @import("../../primitives/group.zig");
const Scalar = group.Scalar;
const G1 = group.G1;
const Map = utils.ordered.Map;
const Set = utils.ordered.Set;
const Transcript = transcript.Transcript;
const Summary = transcript.Summary;

const schnorr_namespace = "_COMMONWARE_CRYPTOGRAPHY_BANDERSNATCH_SCHNORR";
const bulletproofs_dst = "_COMMONWARE_CRYPTOGRAPHY_GOLDEN_DKG_BULLETPROOFS";

// A linear fit of the circuit's internal variables (commonware measures it with
// `vrf_batch_checked_circuit`): `wires_per_player * n + wires_base`.
const wires_per_player: usize = 2247;
const wires_base: usize = 1327;

/// `ceil(log2(wires_per_player * players + wires_base))`: the log2 of the smallest power of
/// two that fits the VRF circuit for `players` receivers.
fn lg_len_for_players(players: u32) u8 {
    const internal = wires_per_player * @as(usize, players) + wires_base;
    var padded: usize = 1;
    var lg: u8 = 0;
    while (padded < internal) : (lg += 1) padded <<= 1;
    assert(padded >= internal and padded / 2 < internal);
    return lg;
}

/// A bulletproofs setup for the eVRF circuit, for rounds of up to `max_players` players.
/// Building one hashes about `2 * 2^lg_len` points, so build it once and share it: it is
/// publicly derivable and holds no secrets.
pub const Setup = struct {
    inner: bulletproofs.Setup(G1),
    max_players: u32,

    /// The exact `max_players` the setup was built for.
    pub const Cfg = u32;

    pub fn init(gpa: Allocator, max_players: u32) !Setup {
        assert(max_players > 0);
        // The BLS12-381 generator is the value generator, so `[value] G1` (computed by the
        // DKG) matches the Pedersen commitments of `Witness.claim`.
        const inner: bulletproofs.Setup(G1) = try .hashed(
            gpa,
            bulletproofs_dst,
            lg_len_for_players(max_players),
            G1.generator,
        );
        return .{ .inner = inner, .max_players = max_players };
    }

    pub fn deinit(self: *Setup, gpa: Allocator) void {
        self.inner.deinit(gpa);
        self.* = undefined;
    }

    /// Whether the setup supports a round with `players` players.
    pub fn supports(self: *const Setup, players: u32) bool {
        return players <= self.max_players;
    }

    pub fn encode_size(self: Setup) usize {
        return codec.encode_size(u32, self.max_players) + self.inner.encode_size();
    }

    pub fn write(self: Setup, writer: *codec.Writer) void {
        codec.write(u32, self.max_players, writer);
        self.inner.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, expected: u32) codec.Error!Setup {
        assert(expected > 0);
        const max_players = try codec.read(u32, gpa, reader);
        if (max_players == 0) return reader.invalid("Setup", "max_players must be nonzero");
        if (max_players != expected) return reader.invalid("Setup", "max_players mismatch");
        const lg_len = lg_len_for_players(max_players);
        const max_len = @as(usize, 1) << @intCast(lg_len);
        var inner = try bulletproofs.Setup(G1).read(gpa, reader, .{ max_len, {} });
        if (!inner.supports(lg_len)) {
            inner.deinit(gpa);
            return reader.invalid("Setup", "inner setup too small");
        }
        return .{ .inner = inner, .max_players = max_players };
    }
};

/// A Banderwagon private key. Formatting never shows the key.
pub const PrivateKey = struct {
    inner: secret.Secret(F),

    pub const fixed_size: usize = F.fixed_size;
    pub const PublicKey = evrf_public_key;
    pub const Signature = evrf_signature;

    pub fn random(rng: anytype) PrivateKey {
        return .{ .inner = .init(F.random(rng)) };
    }

    /// Commonware `Signer::from_seed`: insecure, for tests and examples only.
    pub fn from_seed(seed: u64) PrivateKey {
        return signer.from_seed(PrivateKey, seed);
    }

    pub fn public_key(self: *const PrivateKey) PrivateKey.PublicKey {
        return .from_point(G.generator.mul(self.inner.expose().*));
    }

    /// A Schnorr signature `(K, s)` with `K = [k] G`, `s = k + e x`, where the challenge
    /// `e` commits the namespace, message, public key, and `K`.
    pub fn sign(
        self: *const PrivateKey,
        namespace: []const u8,
        message: []const u8,
    ) PrivateKey.Signature {
        const public = self.public_key();
        var t = Transcript.init(schnorr_namespace, .v1);
        t.commit(namespace);
        t.commit(message);
        t.commit(&public.raw);

        // A deterministic nonce from the secret key and the public transcript state.
        var nonce_transcript = t.fork("nonce");
        var x_bytes = codec.encode_fixed(F, self.inner.expose().*);
        defer std.crypto.secureZero(u8, &x_bytes);
        nonce_transcript.commit(&x_bytes);
        var nonce_noise = nonce_transcript.noise("k");
        var k = F.random(&nonce_noise);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&k));

        const k_big_bytes = codec.encode_fixed(G, G.generator.mul(k));
        t.commit(&k_big_bytes);
        var challenge_noise = t.noise("challenge");
        const e = F.random(&challenge_noise);
        const s = e.mul(self.inner.expose().*).add(k);

        var raw: [PrivateKey.Signature.fixed_size]u8 = undefined;
        raw[0..G.fixed_size].* = k_big_bytes;
        raw[G.fixed_size..].* = codec.encode_fixed(F, s);
        return .{ .raw = raw };
    }

    /// The VRF output between this key (as receiver) and `sender` for `message`; both
    /// sides derive it from the symmetric ECDH secret.
    pub fn vrf_recv(self: *const PrivateKey, message: Summary, sender: evrf_public_key) Scalar {
        return banderwagon.vrf_recv(&message.bytes, sender.point, self.inner.expose().*);
    }

    /// Each receiver's VRF output (receivers deduplicated, in key order), with commitments
    /// that bind them and prove they were evaluated correctly. `t` is the dealer's
    /// transcript (the round's, forked with "dealer vrf" and committing the dealer's key).
    /// Caller deinits both.
    pub fn vrf_batch_checked(
        self: *const PrivateKey,
        gpa: Allocator,
        rng: anytype,
        setup: *const Setup,
        t: *Transcript,
        message: Summary,
        receivers: []const evrf_public_key,
        strategy: anytype,
    ) !struct { Map(evrf_public_key, Scalar), VrfCommitments } {
        var keys = try Set(evrf_public_key).from_dedup(gpa, receivers);
        errdefer keys.deinit(gpa);
        const points = try gpa.alloc(G, keys.len());
        defer gpa.free(points);
        for (points, keys.as_slice()) |*point, key| point.* = key.point;
        const x = self.inner.expose().*;
        var vrf_circuit, var witness = try banderwagon.vrf_batch_checked(
            gpa,
            &message.bytes,
            x,
            points,
        );
        defer vrf_circuit.deinit(gpa);
        defer witness.deinit(gpa);
        const inner = &setup.inner;
        var claim = try witness.claim(G1, gpa, inner);
        errdefer claim.deinit(gpa);
        const proved = try bulletproofs.prove(
            G1,
            gpa,
            rng,
            t,
            inner,
            &vrf_circuit,
            claim,
            &witness,
            strategy,
        );
        var circuit_proof = proved orelse return error.SetupTooSmall;
        errdefer circuit_proof.deinit(gpa);
        const plain_setup: pedersen_to_plain.Setup(G1) = .{
            .value_generator = inner.value_generator,
            .blinding_generator = inner.blinding_generator,
        };
        const plain_proofs = try gpa.alloc(PlainProof, keys.len());
        errdefer gpa.free(plain_proofs);
        for (plain_proofs, witness.values, claim.commitments) |*proof, output, commitment| {
            const plain_claim: pedersen_to_plain.Claim(G1) = .{
                .plain = commitment,
                .pedersen = commitment,
            };
            const opening: pedersen_to_plain.Witness(Scalar) = .{
                .value = output,
                .blinding = Scalar.zero,
            };
            proof.* = pedersen_to_plain.prove(G1, rng, t, plain_setup, plain_claim, opening);
        }
        const values = try gpa.dupe(Scalar, witness.values);
        errdefer gpa.free(values);
        const output_keys = try keys.clone(gpa);
        const outputs = Map(evrf_public_key, Scalar).from_parts(output_keys, values).?;
        const commitments = Map(evrf_public_key, G1).from_parts(keys, claim.commitments).?;
        const proof: Proof = .{ .circuit_proof = circuit_proof, .pedersen_to_plain = plain_proofs };
        return .{ outputs, .{ .proof = proof, .commitments = commitments } };
    }

    /// Constant-time comparison.
    pub fn eql(a: *const PrivateKey, b: *const PrivateKey) bool {
        return a.inner.eql(&b.inner);
    }

    pub fn zeroize(self: *PrivateKey) void {
        self.inner.deinit();
    }

    pub fn write(self: *const PrivateKey, writer: *codec.Writer) void {
        self.inner.expose().write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!PrivateKey {
        return .{ .inner = .init(try F.read(gpa, reader, {})) };
    }

    pub fn format(_: PrivateKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("PrivateKey([REDACTED])");
    }
};

const evrf_public_key = PublicKey;
const evrf_signature = Signature;

/// A Banderwagon public key: the point and its canonical encoding, which equality, order,
/// and formatting use.
pub const PublicKey = struct {
    raw: [fixed_size]u8,
    point: G,

    pub const fixed_size: usize = G.fixed_size;
    pub const Signature = evrf_signature;

    pub fn from_point(point: G) PublicKey {
        return .{ .raw = codec.encode_fixed(G, point), .point = point };
    }

    /// Checks `[s] G == K + [e] X` with the recomputed challenge `e`.
    pub fn verify(
        self: *const PublicKey,
        namespace: []const u8,
        message: []const u8,
        signature: *const PublicKey.Signature,
    ) bool {
        var reader: codec.Reader = .init(signature.raw[0..G.fixed_size]);
        const k_big = G.read(undefined, &reader, {}) catch return false;
        reader = .init(signature.raw[G.fixed_size..]);
        const s = F.read(undefined, &reader, {}) catch return false;
        assert(reader.remaining() == 0);

        var t = Transcript.init(schnorr_namespace, .v1);
        t.commit(namespace);
        t.commit(message);
        t.commit(&self.raw);
        t.commit(signature.raw[0..G.fixed_size]);
        var challenge_noise = t.noise("challenge");
        const e = F.random(&challenge_noise);
        return G.generator.mul(s).eql(k_big.add(self.point.mul(e)));
    }

    pub fn as_slice(self: *const PublicKey) []const u8 {
        return &self.raw;
    }

    pub fn eql(a: PublicKey, b: PublicKey) bool {
        return utils.bytes_eql(a.raw.len, &a.raw, &b.raw);
    }

    pub fn order(a: PublicKey, b: PublicKey) std.math.Order {
        return std.mem.order(u8, &a.raw, &b.raw);
    }

    pub fn less_than(_: void, a: PublicKey, b: PublicKey) bool {
        return a.order(b) == .lt;
    }

    pub fn write(self: *const PublicKey, writer: *codec.Writer) void {
        writer.write_bytes(&self.raw);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!PublicKey {
        const raw = (try reader.take_array(fixed_size)).*;
        var inner: codec.Reader = .init(&raw);
        const point = G.read(gpa, &inner, {}) catch |err| {
            reader.diagnostic = inner.diagnostic;
            return err;
        };
        return .{ .raw = raw, .point = point };
    }

    pub fn format(self: PublicKey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try formatting.fmt_hex(&self.raw).format(writer);
    }
};

/// A Schnorr signature over Banderwagon: the commitment point `K` and the response `s`.
pub const Signature = struct {
    raw: [fixed_size]u8,

    pub const fixed_size: usize = G.fixed_size + F.fixed_size;

    pub fn as_slice(self: *const Signature) []const u8 {
        return &self.raw;
    }

    pub fn eql(a: Signature, b: Signature) bool {
        return utils.bytes_eql(a.raw.len, &a.raw, &b.raw);
    }

    pub fn order(a: Signature, b: Signature) std.math.Order {
        return std.mem.order(u8, &a.raw, &b.raw);
    }

    pub fn write(self: *const Signature, writer: *codec.Writer) void {
        writer.write_bytes(&self.raw);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Signature {
        return .{ .raw = (try reader.take_array(fixed_size)).* };
    }

    pub fn format(self: Signature, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try formatting.fmt_hex(&self.raw).format(writer);
    }
};

const PlainProof = pedersen_to_plain.Proof(Scalar, G1);
const CircuitProof = bulletproofs.Proof(Scalar, G1);
const Synthetic = math.synthetic.Synthetic(Scalar, G1);

/// Proves the VRF was evaluated correctly for each receiver and binds the outputs to the
/// accompanying commitments.
pub const Proof = struct {
    circuit_proof: CircuitProof,
    /// One per receiver, in receiver order.
    pedersen_to_plain: []PlainProof,

    /// `max_players` bounds the pedersen_to_plain proofs and, through `lg_len_for_players`,
    /// the IPA rounds of the circuit proof.
    pub const Cfg = u32;

    pub fn deinit(self: *Proof, gpa: Allocator) void {
        self.circuit_proof.deinit(gpa);
        gpa.free(self.pedersen_to_plain);
        self.* = undefined;
    }

    pub fn encode_size(self: Proof) usize {
        return self.circuit_proof.encode_size() +
            codec.encode_size([]const PlainProof, self.pedersen_to_plain);
    }

    pub fn write(self: Proof, writer: *codec.Writer) void {
        self.circuit_proof.write(writer);
        codec.write([]const PlainProof, self.pedersen_to_plain, writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, max_players: u32) codec.Error!Proof {
        assert(max_players > 0);
        const max_len = @as(usize, 1) << @intCast(lg_len_for_players(max_players));
        var circuit_proof = try CircuitProof.read(gpa, reader, .{ max_len, .{ {}, .allow_zero } });
        errdefer circuit_proof.deinit(gpa);
        const proofs = try codec.read_cfg([]const PlainProof, gpa, reader, .{
            .range = .to_inclusive(max_players),
            .item = .{ {}, .allow_zero },
        });
        return .{ .circuit_proof = circuit_proof, .pedersen_to_plain = @constCast(proofs) };
    }
};

/// Commitments to `PrivateKey.vrf_recv`'s output for several receivers, with the proof
/// binding them; the outputs stay hidden.
pub const VrfCommitments = struct {
    proof: Proof,
    commitments: Map(PublicKey, G1),

    pub const Cfg = u32;

    pub fn deinit(self: *VrfCommitments, gpa: Allocator) void {
        self.proof.deinit(gpa);
        self.commitments.deinit(gpa);
        self.* = undefined;
    }

    pub fn encode_size(self: VrfCommitments) usize {
        return self.proof.encode_size() + self.commitments.encode_size();
    }

    pub fn write(self: VrfCommitments, writer: *codec.Writer) void {
        self.proof.write(writer);
        self.commitments.write(writer);
    }

    pub fn read(
        gpa: Allocator,
        reader: *codec.Reader,
        max_players: u32,
    ) codec.Error!VrfCommitments {
        var proof = try Proof.read(gpa, reader, max_players);
        errdefer proof.deinit(gpa);
        const commitments = try Map(PublicKey, G1).read(gpa, reader, .{
            .range = .to_inclusive(max_players),
        });
        return .{ .proof = proof, .commitments = commitments };
    }

    /// Shifts `receiver`'s commitment by `delta` (a tampered copy fails `check_batch`).
    pub fn perturb(self: *VrfCommitments, receiver: PublicKey, delta: G1) void {
        if (self.commitments.get_value_mut(receiver)) |commitment| {
            commitment.* = commitment.add(delta);
        }
    }

    /// One dealer's output in a `check_batch`.
    pub const Entry = struct {
        sender: PublicKey,
        /// The nonce the dealer passed to `vrf_batch_checked` (a `Summary` encoding).
        msg: []const u8,
        commitments: *const VrfCommitments,
    };

    /// Verifies the dealers' commitments in one batched check and returns each verified
    /// dealer's commitments (`[output] G1` per receiver); failing dealers are left out.
    /// `outer` must be the transcript the dealers forked when proving. Dealers that commit
    /// to a receiver outside `players`, whose `msg` is not a `Summary`, or whose
    /// pedersen_to_plain proofs do not match their commitments are dropped before any proof
    /// work, so the cost is bounded by `players` rather than the setup. Duplicate senders
    /// fail with `DuplicateKey`.
    pub fn check_batch(
        gpa: Allocator,
        rng: anytype,
        setup: *const Setup,
        outer: *const Transcript,
        players: *const Set(PublicKey),
        outputs: []const Entry,
    ) !Map(PublicKey, Map(PublicKey, G1)) {
        for (outputs, 0..) |entry, index| {
            for (outputs[0..index]) |earlier| {
                if (earlier.sender.eql(entry.sender)) return error.DuplicateKey;
            }
        }
        var admitted: std.ArrayList(Entry) = .empty;
        defer admitted.deinit(gpa);
        for (outputs) |entry| {
            if (admissible(entry, players)) try admitted.append(gpa, entry);
        }
        const context: BatchContext = .{ .outer = outer, .entries = admitted.items };
        const verdicts = (try setup.inner.eval_check_batched(
            gpa,
            Scalar,
            rng,
            context,
            BatchContext.equations,
        )) orelse return .empty;
        defer gpa.free(verdicts);
        assert(verdicts.len == admitted.items.len);
        var pairs: std.ArrayList(Checked.Pair) = .empty;
        defer pairs.deinit(gpa);
        try collect_verified(gpa, admitted.items, verdicts, &pairs);
        // `init` takes the pairs' items, also when it fails.
        return Checked.init(gpa, pairs.items);
    }

    const Checked = Map(PublicKey, Map(PublicKey, G1));

    /// Copies each verified dealer's commitments into `pairs`.
    fn collect_verified(
        gpa: Allocator,
        entries: []const Entry,
        verdicts: []const bool,
        pairs: *std.ArrayList(Checked.Pair),
    ) Allocator.Error!void {
        assert(entries.len == verdicts.len);
        assert(pairs.items.len == 0);
        errdefer for (pairs.items) |*pair| pair[1].deinit(gpa);
        for (entries, verdicts) |entry, valid| {
            if (!valid) continue;
            try pairs.ensureUnusedCapacity(gpa, 1);
            var keys = try entry.commitments.commitments.keys.clone(gpa);
            const values = gpa.dupe(G1, entry.commitments.commitments.values) catch |err| {
                keys.deinit(gpa);
                return err;
            };
            const commitments = Map(PublicKey, G1).from_parts(keys, values).?;
            pairs.appendAssumeCapacity(.{ entry.sender, commitments });
        }
    }

    fn admissible(entry: Entry, players: *const Set(PublicKey)) bool {
        if (entry.msg.len < Summary.fixed_size) return false;
        const commitments = entry.commitments;
        if (commitments.proof.pedersen_to_plain.len != commitments.commitments.len()) {
            return false;
        }
        for (commitments.commitments.keys.as_slice()) |receiver| {
            if (players.position(receiver) == null) return false;
        }
        return true;
    }
};

/// Builds `check_batch`'s per-dealer equations over the virtual setup.
const BatchContext = struct {
    outer: *const Transcript,
    entries: []const VrfCommitments.Entry,

    fn equations(
        self: BatchContext,
        gpa: Allocator,
        virtual: *const bulletproofs.Setup(Synthetic),
        rng: anytype,
    ) !?[]?Synthetic {
        const result = try gpa.alloc(?Synthetic, self.entries.len);
        @memset(result, null);
        errdefer {
            for (result) |*equation| if (equation.*) |*present| present.deinit(gpa);
            gpa.free(result);
        }
        // pedersen_to_plain uses the bulletproofs value and blinding generators (borrowed).
        const plain_setup: pedersen_to_plain.Setup(Synthetic) = .{
            .value_generator = virtual.value_generator,
            .blinding_generator = virtual.blinding_generator,
        };
        for (self.entries, result) |entry, *equation| {
            equation.* = try self.dealer_equation(gpa, virtual, &plain_setup, rng, entry);
        }
        return result;
    }

    /// The dealer's circuit equation plus its pedersen_to_plain equations, each scaled by a
    /// random weight; null when the circuit proof is malformed.
    fn dealer_equation(
        self: BatchContext,
        gpa: Allocator,
        virtual: *const bulletproofs.Setup(Synthetic),
        plain_setup: *const pedersen_to_plain.Setup(Synthetic),
        rng: anytype,
        entry: VrfCommitments.Entry,
    ) !?Synthetic {
        const commitments = &entry.commitments.commitments;
        const receivers = try gpa.alloc(G, commitments.len());
        defer gpa.free(receivers);
        for (receivers, commitments.keys.as_slice()) |*point, key| point.* = key.point;
        var vrf_circuit = try banderwagon.vrf_batch_checked_circuit(
            gpa,
            entry.msg,
            entry.sender.point,
            receivers,
        );
        defer vrf_circuit.deinit(gpa);
        // The dealer's forked transcript, as in `golden.deal`.
        var t = self.outer.fork("dealer vrf");
        t.commit(&entry.sender.raw);
        const claim: bulletproofs.Claim(G1) = .{ .commitments = commitments.values };
        const proof = entry.commitments.proof;
        var out = (try bulletproofs.verify(
            G1,
            gpa,
            rng,
            &t,
            virtual,
            &vrf_circuit,
            claim,
            proof.circuit_proof,
        )) orelse return null;
        errdefer out.deinit(gpa);
        out.mul_assign(Scalar.random(rng));
        assert(proof.pedersen_to_plain.len == commitments.values.len);
        for (commitments.values, proof.pedersen_to_plain) |commitment, plain_proof| {
            const plain_claim: pedersen_to_plain.Claim(G1) = .{
                .plain = commitment,
                .pedersen = commitment,
            };
            var term = try pedersen_to_plain.verify(
                G1,
                gpa,
                rng,
                &t,
                plain_setup,
                plain_claim,
                plain_proof,
            );
            defer term.deinit(gpa);
            term.mul_assign(Scalar.random(rng));
            try out.add_assign(gpa, term);
        }
        return out;
    }
};

comptime {
    signer.assert_signer(PrivateKey);
}

test {
    _ = banderwagon;
    _ = @import("evrf_tests.zig");
}
