//! BLS12-381 threshold VRF for simplex (commonware
//! `simplex::scheme::bls12381_threshold::vrf`): every vote carries a vote signature and a
//! seed signature over the round, so a certificate yields a per-round random seed.
//!
//! The scheme is not attributable (a certificate is one recovered signature pair) and is
//! batchable. Vote and seed partials are verified in two same-message batches, each with
//! its own RNG seeded from `rng` (ChaCha20 here, `StdRng` in commonware; the draws only pick
//! verification weights, so results are the same).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const simplex_types = @import("../../types.zig");

const base = cryptography.certificate;
const primitives = cryptography.bls12381.primitives;
const group = primitives.group;
const batch = primitives.ops.batch;
const threshold_ops = primitives.ops.threshold;
const threshold_certificate = cryptography.bls12381.certificate.threshold;
const tle = cryptography.bls12381.tle;
const seed_suffix = @import("../namespace.zig").seed_suffix;
const Share = group.Share;
const Sharing = primitives.sharing.Sharing;
const PartialSignature = primitives.variant.PartialSignature;
const Participant = utils.Participant;
const Set = utils.ordered.Set;
const ChaCha20Rng = cryptography.ChaCha20Rng;
const Round = consensus_types.Round;
const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;

/// commonware's `G1`/`G2` `Arbitrary`: the generator times `Scalar::from_ikm` of 64 drawn
/// bytes (zero-filled once the data runs out, as `[u8; 64]::arbitrary` does).
pub fn arbitrary_point(comptime G: type, u: *Unstructured) G {
    var ikm: [64]u8 = undefined;
    u.fill(&ikm);
    const point = G.generator.mul(group.Scalar.from_ikm(&ikm));
    assert(!point.is_zero());
    return point;
}

/// A vote signature and a seed signature (partial, or recovered in a certificate).
pub fn Signature(comptime V: type) type {
    return struct {
        const Self = @This();
        const Point = V.Signature;

        vote_signature: Point,
        seed_signature: Point,

        pub const fixed_size: usize = 2 * Point.fixed_size;

        pub fn eql(a: Self, b: Self) bool {
            return a.vote_signature.eql(b.vote_signature) and
                a.seed_signature.eql(b.seed_signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.vote_signature.write(writer);
            self.seed_signature.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const vote_signature = try Point.read(gpa, reader, {});
            return .{
                .vote_signature = vote_signature,
                .seed_signature = try Point.read(gpa, reader, {}),
            };
        }

        pub fn arbitrary(_: Allocator, u: *Unstructured) ArbitraryError!Self {
            const vote_signature = arbitrary_point(Point, u);
            const seed_signature = arbitrary_point(Point, u);
            return .{ .vote_signature = vote_signature, .seed_signature = seed_signature };
        }
    };
}

/// A recovered signature pair, decoded on demand (commonware `Lazy<Signature<V>>`).
pub fn Certificate(comptime V: type) type {
    return struct {
        const Self = @This();
        const Inner = cryptography.certificate.Deferred(Signature(V));

        signature: Inner,

        pub const fixed_size: usize = Inner.fixed_size;

        pub fn init(signature: Signature(V)) Self {
            return .{ .signature = .init(signature) };
        }

        /// The decoded signature pair, or null when the bytes are not valid points.
        pub fn get(self: *const Self) ?Signature(V) {
            return self.signature.get();
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.signature.eql(b.signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.signature.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{ .signature = try Inner.read(gpa, reader, {}) };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            return init(try Signature(V).arbitrary(gpa, u));
        }
    };
}

/// A threshold signature over a round: the round's random seed.
pub fn Seed(comptime V: type) type {
    return struct {
        const Self = @This();
        const Point = V.Signature;

        round: Round,
        signature: Point,

        pub const max_encode_size: usize = Round.max_encode_size + Point.fixed_size;

        pub fn epoch(self: Self) Epoch {
            return self.round.epoch;
        }

        pub fn view(self: Self) View {
            return self.round.view;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.round == b.round and a.signature.eql(b.signature);
        }

        /// Whether this is the group's signature over its round, for a `Scheme` instance
        /// (commonware `Seed::verify`).
        pub fn verify(self: Self, scheme: anytype) bool {
            return verify_seed(V, self, scheme);
        }

        /// Decrypts a ciphertext encrypted to this seed's round, or returns null when it was
        /// encrypted to another round or tampered with (commonware `Seed::decrypt`).
        pub fn decrypt(self: Self, ciphertext: tle.Ciphertext(V)) ?tle.Block {
            return decrypt_with(V, self, ciphertext);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.round.write(writer);
            self.signature.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.round.encode_size() + Point.fixed_size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const round = try Round.read(gpa, reader, {});
            return .{ .round = round, .signature = try Point.read(gpa, reader, {}) };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const round = try Round.arbitrary(gpa, u);
            return .{ .round = round, .signature = arbitrary_point(Point, u) };
        }
    };
}

/// The seed a verified notarization or finalization carries (commonware `Seedable::seed`):
/// the recovered seed signature over its proposal's round. Panics when the certificate does
/// not decode, which a verified certificate always does.
pub fn seed(comptime V: type, certified: anytype) Seed(V) {
    const signature = certified.certificate.get() orelse
        @panic("verified certificate must decode");
    const result: Seed(V) = .{
        .round = certified.proposal.round,
        .signature = signature.seed_signature,
    };
    assert(result.round == certified.proposal.round);
    assert(result.signature.eql(signature.seed_signature));
    return result;
}

fn verify_seed(comptime V: type, seed_value: Seed(V), scheme: anytype) bool {
    var buffer: [Round.max_encode_size]u8 = undefined;
    const message = codec.encode_to(Round, seed_value.round, &buffer);
    assert(message.len > 0);
    assert(scheme.namespace.seed.len > 0);
    primitives.ops.verify_message(
        V,
        scheme.identity(),
        scheme.namespace.seed,
        message,
        seed_value.signature,
    ) catch return false;
    return true;
}

/// commonware `vrf::decrypt`: decrypts `ciphertext` with the seed signature.
pub fn decrypt_with(
    comptime V: type,
    seed_value: Seed(V),
    ciphertext: tle.Ciphertext(V),
) ?tle.Block {
    assert(!ciphertext.u.is_zero());
    return tle.decrypt(V, seed_value.signature, ciphertext);
}

/// commonware `vrf::encrypt`: encrypts `message` to the seed of `target` under the group key
/// `identity` and the application `namespace` (its seed namespace is derived here).
pub fn encrypt(
    comptime V: type,
    gpa: Allocator,
    rng: anytype,
    identity: V.Public,
    namespace: []const u8,
    target: Round,
    message: *const tle.Block,
) (tle.Error || Allocator.Error)!tle.Ciphertext(V) {
    const seed_namespace = try std.mem.concat(gpa, u8, &.{ namespace, seed_suffix });
    defer gpa.free(seed_namespace);
    var buffer: [Round.max_encode_size]u8 = undefined;
    const target_message = codec.encode_to(Round, target, &buffer);
    assert(std.mem.endsWith(u8, seed_namespace, seed_suffix));
    return tle.encrypt(V, rng, identity, seed_namespace, target_message, message);
}

/// The message a subject's seed signature covers: its round, encoded.
fn seed_message(subject: anytype, buffer: *[Round.max_encode_size]u8) []u8 {
    const round: Round = switch (subject) {
        .notarize, .finalize => |proposal| proposal.round,
        .nullify => |round| round,
    };
    const message = codec.encode_to(Round, round, buffer);
    assert(message.len > 0);
    assert(message.len <= Round.max_encode_size);
    return message;
}

/// The threshold VRF scheme for proposals with payload digest `D`, identity keys `P`, and
/// BLS variant `V` (commonware `bls12381_threshold::vrf::Scheme<P, V>`). Its roles are a
/// signer (participants, sharing, share), a verifier (participants, sharing), and a
/// certificate verifier (the group public key only).
pub fn Scheme(comptime D: type, comptime P: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Subject = simplex_types.Subject(D);
        pub const Faults = utils.N3f1;
        pub const Namespace = Subject.Namespace;
        pub const PublicKey = P;
        pub const Variant = V;
        pub const Signature = signature_of(V);
        pub const Certificate = certificate_of(V);
        pub const Attestation = base.Attestation(Self);
        pub const Verification = base.Verification(Self);
        pub const Assembled = base.Assembled(Self);
        pub const Item = base.CertificateItem(Self);
        pub const Participants = Set(P);
        const Pair = struct { vote: PartialSignature(V), seed: PartialSignature(V) };

        /// Present for signers and verifiers.
        committee: ?Committee,
        /// Present for signers.
        signing_share: ?Share,
        group_public: V.Public,
        member_index: ?Participant,
        namespace: Namespace,

        const Committee = struct { participants: Participants, sharing: Sharing(V) };

        fn committee_of(set: Participants, sharing: Sharing(V)) Committee {
            if (sharing.total != set.len()) {
                @panic("polynomial total must equal participant len");
            }
            if (sharing.required() != set.quorum(Faults)) {
                @panic("polynomial threshold must equal quorum");
            }
            sharing.precompute_partial_publics();
            return .{ .participants = set, .sharing = sharing };
        }

        /// A signing scheme, or null when `key_share` does not match `sharing`. Takes
        /// ownership of `set` and `sharing`; panics when the sharing does not fit.
        pub fn signer(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            sharing: Sharing(V),
            key_share: Share,
        ) Allocator.Error!?Self {
            var committee = committee_of(set, sharing);
            const expected = committee.sharing.partial_public(key_share.index) catch
                @panic("share index must match participant indices");
            if (!expected.eql(key_share.public(V))) {
                committee.participants.deinit(gpa);
                committee.sharing.deinit(gpa);
                return null;
            }
            errdefer committee.participants.deinit(gpa);
            errdefer committee.sharing.deinit(gpa);
            return .{
                .committee = committee,
                .signing_share = key_share,
                .group_public = committee.sharing.public(),
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        /// A scheme that verifies but cannot sign. Takes ownership of its arguments.
        pub fn verifier(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            sharing: Sharing(V),
        ) Allocator.Error!Self {
            var committee = committee_of(set, sharing);
            errdefer committee.participants.deinit(gpa);
            errdefer committee.sharing.deinit(gpa);
            return .{
                .committee = committee,
                .signing_share = null,
                .group_public = committee.sharing.public(),
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        /// A verifier that knows its index, or null when `public_key` is not a participant.
        pub fn member(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            sharing: Sharing(V),
            public_key: P,
        ) Allocator.Error!?Self {
            const index = set.index(public_key) orelse {
                var owned = set;
                owned.deinit(gpa);
                var owned_sharing = sharing;
                owned_sharing.deinit(gpa);
                return null;
            };
            var result = try verifier(gpa, namespace, set, sharing);
            result.member_index = index;
            assert(result.me().?.member.get() == index.get());
            return result;
        }

        /// A scheme that verifies certificates and seeds against the group key `identity`.
        pub fn certificate_verifier(
            gpa: Allocator,
            namespace: []const u8,
            group_public: V.Public,
        ) Allocator.Error!Self {
            return .{
                .committee = null,
                .signing_share = null,
                .group_public = group_public,
                .member_index = null,
                .namespace = try Namespace.derive(gpa, namespace),
            };
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var committee: ?Committee = null;
            if (self.committee) |c| {
                var set = try c.participants.clone(gpa);
                errdefer set.deinit(gpa);
                committee = .{ .participants = set, .sharing = try c.sharing.clone(gpa) };
            }
            errdefer if (committee) |*c| {
                c.participants.deinit(gpa);
                c.sharing.deinit(gpa);
            };
            return .{
                .committee = committee,
                .signing_share = self.signing_share,
                .group_public = self.group_public,
                .member_index = self.member_index,
                .namespace = try self.namespace.clone(gpa),
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.committee) |*c| {
                c.participants.deinit(gpa);
                c.sharing.deinit(gpa);
            }
            if (self.signing_share) |*key_share| key_share.private.zeroize();
            self.namespace.deinit(gpa);
            self.* = undefined;
        }

        fn committee_or_panic(self: *const Self) *const Committee {
            if (self.committee) |*c| return c;
            @panic("can only be called for signer and verifier");
        }

        pub fn me(self: *const Self) ?base.Membership {
            if (self.signing_share) |key_share| return .{ .signer = key_share.index };
            if (self.member_index) |index| return .{ .member = index };
            return null;
        }

        /// The participants; panics for a certificate verifier.
        pub fn participants(self: *const Self) *const Participants {
            return &self.committee_or_panic().participants;
        }

        /// The sharing; panics for a certificate verifier.
        pub fn polynomial(self: *const Self) *const Sharing(V) {
            return &self.committee_or_panic().sharing;
        }

        /// The group public key.
        pub fn identity(self: *const Self) V.Public {
            return self.group_public;
        }

        /// The key share, for signers.
        pub fn share(self: *const Self) ?Share {
            return self.signing_share;
        }

        /// Encrypts `message` so that the seed of round `target` decrypts it (timelock
        /// encryption to a future round). Fails when the group key is the identity.
        pub fn encrypt(
            self: *const Self,
            rng: anytype,
            target: Round,
            message: *const tle.Block,
        ) tle.Error!tle.Ciphertext(V) {
            var buffer: [Round.max_encode_size]u8 = undefined;
            const target_message = codec.encode_to(Round, target, &buffer);
            assert(target_message.len > 0);
            assert(self.namespace.seed.len >= seed_suffix.len);
            const seed_namespace = self.namespace.seed;
            return tle.encrypt(V, rng, self.group_public, seed_namespace, target_message, message);
        }

        /// Signs `subject`'s vote message and its round's seed with the key share, or
        /// returns null when this instance cannot sign.
        pub fn sign(
            self: *const Self,
            gpa: Allocator,
            subject: Subject,
        ) Allocator.Error!?Attestation {
            _ = gpa;
            const key_share = self.signing_share orelse return null;
            var vote_buffer: [Subject.message_max_size]u8 = undefined;
            const vote_message = subject.message_to(&vote_buffer);
            var seed_buffer: [Round.max_encode_size]u8 = undefined;
            const seed_bytes = seed_message(subject, &seed_buffer);
            const namespace = subject.namespace(&self.namespace);
            const vote = threshold_ops.sign_message(V, key_share, namespace, vote_message);
            const seed_signature =
                threshold_ops.sign_message(V, key_share, self.namespace.seed, seed_bytes);
            assert(vote.index.get() == key_share.index.get());
            return Attestation.init(key_share.index, .{
                .vote_signature = vote.value,
                .seed_signature = seed_signature.value,
            });
        }

        /// Verifies one attestation's vote and seed partials together; panics for a
        /// certificate verifier.
        pub fn verify_attestation(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestation: *const Attestation,
            strategy: anytype,
        ) Allocator.Error!bool {
            _ = gpa;
            _ = strategy;
            const sharing = self.committee_or_panic().sharing;
            const public_key = sharing.partial_public(attestation.signer) catch return false;
            const signature = attestation.signature.get() orelse return false;
            return self.verify_pair(rng, public_key, subject, signature);
        }

        /// Batch-verifies a vote signature and a seed signature from one signer.
        fn verify_pair(
            self: *const Self,
            rng: anytype,
            public_key: V.Public,
            subject: Subject,
            signature: Self.Signature,
        ) bool {
            var vote_buffer: [Subject.message_max_size]u8 = undefined;
            var seed_buffer: [Round.max_encode_size]u8 = undefined;
            const entries = [_]batch.SignerEntry(V){
                .{
                    .namespace = subject.namespace(&self.namespace),
                    .message = subject.message_to(&vote_buffer),
                    .signature = signature.vote_signature,
                },
                .{
                    .namespace = self.namespace.seed,
                    .message = seed_message(subject, &seed_buffer),
                    .signature = signature.seed_signature,
                },
            };
            assert(entries[0].message.len > 0);
            assert(entries[1].message.len > 0);
            batch.verify_same_signer(V, rng, public_key, &entries) catch return false;
            return true;
        }

        /// Batch-verifies attestations (vote partials, then seed partials) and returns the
        /// verified ones and the sorted invalid signers. A signer with any invalid or
        /// malformed attestation has all of its attestations rejected.
        pub fn verify_attestations(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestations: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Verification {
            _ = strategy;
            const sharing = self.committee_or_panic().sharing;
            var invalid: std.ArrayList(Participant) = .empty;
            defer invalid.deinit(gpa);
            var pairs: std.ArrayList(Pair) = try .initCapacity(gpa, attestations.len);
            defer pairs.deinit(gpa);
            for (attestations) |attestation| {
                const index = attestation.signer;
                if (attestation.signature.get()) |value| pairs.appendAssumeCapacity(.{
                    .vote = .{ .index = index, .value = value.vote_signature },
                    .seed = .{ .index = index, .value = value.seed_signature },
                }) else try invalid.append(gpa, index);
            }
            if (pairs.items.len > 0) {
                try self.batch_invalid(gpa, rng, sharing, subject, pairs.items, &invalid);
            }
            return collect(gpa, pairs.items, invalid.items);
        }

        /// Appends the signers whose vote or seed partial fails verification to `invalid`.
        fn batch_invalid(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            sharing: Sharing(V),
            subject: Subject,
            pairs: []const Pair,
            invalid: *std.ArrayList(Participant),
        ) Allocator.Error!void {
            assert(pairs.len > 0);
            const partials = try gpa.alloc(PartialSignature(V), 2 * pairs.len);
            defer gpa.free(partials);
            const votes = partials[0..pairs.len];
            const seeds = partials[pairs.len..];
            for (pairs, votes, seeds) |pair, *vote, *seed_partial| {
                vote.* = pair.vote;
                seed_partial.* = pair.seed;
            }
            // Independent RNGs, drawn vote first, as commonware seeds its two batches.
            var keys: [2][32]u8 = undefined;
            for (&keys) |*key| rng.fill_bytes(key);
            var vote_buffer: [Subject.message_max_size]u8 = undefined;
            var seed_buffer: [Round.max_encode_size]u8 = undefined;
            const batches = [2]struct { []const u8, []const u8, []PartialSignature(V) }{
                .{ subject.namespace(&self.namespace), subject.message_to(&vote_buffer), votes },
                .{ self.namespace.seed, seed_message(subject, &seed_buffer), seeds },
            };
            for (batches, keys) |entry, key| {
                var batch_rng = ChaCha20Rng.init_key(key);
                const bad = try threshold_ops.batch_verify_same_message(
                    V,
                    gpa,
                    &batch_rng,
                    sharing,
                    entry[0],
                    entry[1],
                    entry[2],
                );
                defer gpa.free(bad);
                for (bad) |position| try invalid.append(gpa, entry[2][position].index);
            }
        }

        fn collect(
            gpa: Allocator,
            pairs: []const Pair,
            invalid_unsorted: []Participant,
        ) Allocator.Error!Verification {
            const invalid_sorted = base.sort_unique(invalid_unsorted);
            var verified: std.ArrayList(Attestation) = try .initCapacity(gpa, pairs.len);
            errdefer verified.deinit(gpa);
            for (pairs) |pair| {
                if (contains(invalid_sorted, pair.vote.index)) continue;
                verified.appendAssumeCapacity(.init(pair.vote.index, .{
                    .vote_signature = pair.vote.value,
                    .seed_signature = pair.seed.value,
                }));
            }
            const invalid = try gpa.dupe(Participant, invalid_sorted);
            errdefer gpa.free(invalid);
            assert(verified.items.len + invalid.len >= @min(pairs.len, 1));
            return .{ .verified = try verified.toOwnedSlice(gpa), .invalid = invalid };
        }

        fn contains(sorted: []const Participant, participant: Participant) bool {
            for (sorted) |item| {
                if (item.get() == participant.get()) return true;
            }
            return false;
        }

        pub fn optimistic_assemble(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            pending: []const Attestation,
            verified: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Assembled {
            return base.optimistic_assemble(self, gpa, rng, subject, pending, verified, strategy);
        }

        /// Recovers the vote and seed signatures from a non-empty list of attestations,
        /// which need not be verified. Signers must be in range, unique, and reach quorum.
        pub fn assemble(
            self: *const Self,
            gpa: Allocator,
            attestations: []const Attestation,
            strategy: anytype,
        ) (base.AssemblyError || Allocator.Error)!Self.Certificate {
            _ = strategy;
            assert(attestations.len > 0);
            const sharing = self.committee_or_panic().sharing;
            const partials = try gpa.alloc(PartialSignature(V), 2 * attestations.len);
            defer gpa.free(partials);
            const votes = partials[0..attestations.len];
            const seeds = partials[attestations.len..];
            const indices = try gpa.alloc(Participant, attestations.len);
            defer gpa.free(indices);
            for (attestations, votes, seeds, indices) |attestation, *vote, *seed_partial, *i| {
                const index = attestation.signer;
                const value = attestation.signature.get() orelse return error.MalformedSignature;
                vote.* = .{ .index = index, .value = value.vote_signature };
                seed_partial.* = .{ .index = index, .value = value.seed_signature };
                i.* = index;
            }
            var signers = try base.Signers.init(gpa, sharing.total, indices);
            defer signers.deinit(gpa);
            try signers.require(sharing.required());
            const recovered = threshold_ops.recover_pair(V, gpa, sharing, votes, seeds) catch |err|
                switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.RecoveryFailed,
                };
            return .init(.{ .vote_signature = recovered[0], .seed_signature = recovered[1] });
        }

        /// Verifies a certificate's vote and seed signatures against the group key.
        pub fn verify_certificate(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            cert: *const Self.Certificate,
            strategy: anytype,
        ) Allocator.Error!bool {
            _ = gpa;
            _ = strategy;
            const signature = cert.get() orelse return false;
            return self.verify_pair(rng, self.group_public, subject, signature);
        }

        /// Verifies certificates in one same-signer batch. Certificates for one round share
        /// a seed, so each seed is verified once, and differing seeds for a round fail.
        pub fn verify_certificates(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            items: []const Item,
            strategy: anytype,
        ) Allocator.Error!bool {
            _ = strategy;
            assert(items.len > 0);
            const entries = try gpa.alloc(batch.SignerEntry(V), 2 * items.len);
            defer gpa.free(entries);
            const SeedMessage = struct { bytes: [Round.max_encode_size]u8, len: usize };
            const seeds = try gpa.alloc(SeedMessage, items.len);
            defer gpa.free(seeds);
            var count: usize = 0;
            var seed_count: usize = 0;
            defer for (entries[0..count]) |entry| {
                if (entry.namespace.ptr != self.namespace.seed.ptr) gpa.free(entry.message);
            };
            for (items) |item| {
                const signature = item.certificate.get() orelse return false;
                entries[count] = .{
                    .namespace = item.subject.namespace(&self.namespace),
                    .message = try item.subject.message(gpa),
                    .signature = signature.vote_signature,
                };
                count += 1;
                const slot = &seeds[seed_count];
                const message = seed_message(item.subject, &slot.bytes);
                slot.len = message.len;
                if (find_seed(entries[0..count], self.namespace.seed, message)) |previous| {
                    if (!previous.eql(signature.seed_signature)) return false;
                    continue;
                }
                seed_count += 1;
                entries[count] = .{
                    .namespace = self.namespace.seed,
                    .message = slot.bytes[0..slot.len],
                    .signature = signature.seed_signature,
                };
                count += 1;
            }
            assert(seed_count > 0 and count == items.len + seed_count);
            batch.verify_same_signer(V, rng, self.group_public, entries[0..count]) catch
                return false;
            return true;
        }

        /// The seed signature already queued for `message`, if any.
        fn find_seed(
            entries: []const batch.SignerEntry(V),
            seed_namespace: []const u8,
            message: []const u8,
        ) ?V.Signature {
            for (entries) |entry| {
                if (entry.namespace.ptr != seed_namespace.ptr) continue;
                if (std.mem.eql(u8, entry.message, message)) return entry.signature;
            }
            return null;
        }

        pub fn is_attributable() bool {
            return false;
        }

        pub fn is_batchable() bool {
            return true;
        }

        pub fn max_certificate_size(count: u32) usize {
            _ = count;
            return Self.Certificate.fixed_size;
        }

        pub fn certificate_codec_config(self: *const Self) void {
            _ = self;
        }

        pub fn certificate_codec_config_unbounded() void {}

        comptime {
            base.assert_scheme(Self);
        }
    };
}

const signature_of = Signature;
const certificate_of = Certificate;

/// ed25519 identities and a dealt sharing, with a VRF signing scheme per share (commonware
/// `bls12381_threshold::vrf::fixture`, which draws as the threshold mocks fixture does).
pub fn fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!base.mocks.Fixture(S) {
    return threshold_certificate.fixture(S, gpa, rng, namespace, n);
}

test {
    _ = @import("vrf_test.zig");
}
