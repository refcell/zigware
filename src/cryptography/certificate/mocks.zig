//! Mocks for certificate signing schemes (commonware `certificate/mocks.rs`).
//!
//! `Scheme(Subject, Faults, P, options)` is commonware's `impl_certificate_mock!` with its
//! `Generic`: signatures and certificates are synthetic `U64` IDs recorded in a `Shared`
//! ledger, and verification succeeds only for what that ledger recorded. The `Options` flags
//! are the macro's `ATTRIBUTABLE`, `BATCHABLE`, and `ALLOW_INVALID` const generics, so
//! `fixture_with::<A, B, I>` is `fixture` over `Scheme(..., .{ ... })`.
//!
//! A `U64` signature is any eight bytes, so commonware's truncated-`Lazy` cases have no
//! counterpart here; the overflow and strict-request panics are death tests.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const ed25519 = @import("../ed25519.zig");
const certificate = @import("../certificate.zig");
const ed25519_mocks = @import("../ed25519/certificate/mocks.zig");

const Participant = utils.Participant;
const U64 = utils.sequence.U64;
const Signers = certificate.Signers;

/// Identities, identity private keys, per-participant signing schemes, and one verifier.
/// Every slice is owned and released by `deinit`.
pub fn Fixture(comptime S: type) type {
    return struct {
        const Self = @This();

        /// The participants' ed25519 identity keys, sorted.
        participants: []ed25519.PublicKey,
        /// The identity private keys, in the order of `participants`.
        private_keys: []ed25519.PrivateKey,
        /// One signing scheme per participant, in the order of `participants`.
        schemes: []S,
        /// A scheme that verifies but cannot sign.
        verifier: S,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            assert(self.participants.len == self.private_keys.len);
            assert(self.participants.len == self.schemes.len);
            for (self.private_keys) |*key| key.zeroize();
            for (self.schemes) |*scheme| scheme.deinit(gpa);
            gpa.free(self.participants);
            gpa.free(self.private_keys);
            gpa.free(self.schemes);
            self.verifier.deinit(gpa);
            self.* = undefined;
        }
    };
}

/// The ledger shared by mock schemes from one fixture (commonware `Shared`), reference
/// counted: every scheme holds one reference. A signed subject is commonware's
/// `SignedSubject` as the `union_unique` of its namespace and message, which is injective.
pub const Shared = struct {
    gpa: Allocator,
    references: std.atomic.Value(u32),
    mutex: std.atomic.Mutex = .unlocked,
    /// Global, so a signature ID never matches two signers (a swapped signer fails).
    signature_next: u64 = 0,
    /// The signer (big-endian `u32`) then the signed subject, to its ID; owns the keys.
    signature_by_key: std.StringHashMapUnmanaged(u64) = .empty,
    /// A signature ID to its signer and signed subject (a slice of its key).
    signature_by_id: std.AutoHashMapUnmanaged(u64, Signed) = .empty,
    certificate_next: u64 = 0,
    /// The subject length (big-endian `u64`), the subject, then the encoded signers, to the
    /// certificate's ID; owns the keys.
    certificate_by_key: std.StringHashMapUnmanaged(u64) = .empty,
    /// A certificate ID to its signed subject (a slice of its key).
    certificate_by_id: std.AutoHashMapUnmanaged(u64, []const u8) = .empty,

    const Signed = struct { signer: u32, subject: []const u8 };

    /// A ledger with one reference, released by `release`.
    pub fn create(gpa: Allocator) Allocator.Error!*Shared {
        const shared = try gpa.create(Shared);
        shared.* = .{ .gpa = gpa, .references = .init(1) };
        return shared;
    }

    pub fn retain(self: *Shared) *Shared {
        const previous = self.references.fetchAdd(1, .monotonic);
        assert(previous > 0);
        return self;
    }

    /// Drops one reference and frees the ledger with the last one.
    pub fn release(self: *Shared) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        assert(previous > 0);
        if (previous > 1) return;
        assert(self.mutex == .unlocked);
        var signature_keys = self.signature_by_key.keyIterator();
        while (signature_keys.next()) |key| self.gpa.free(key.*);
        var certificate_keys = self.certificate_by_key.keyIterator();
        while (certificate_keys.next()) |key| self.gpa.free(key.*);
        self.signature_by_key.deinit(self.gpa);
        self.signature_by_id.deinit(self.gpa);
        self.certificate_by_key.deinit(self.gpa);
        self.certificate_by_id.deinit(self.gpa);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    fn lock(self: *Shared) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    fn unlock(self: *Shared) void {
        self.mutex.unlock();
    }

    fn next(counter: *u64, comptime what: []const u8) u64 {
        const current = counter.*;
        counter.* = std.math.add(u64, current, 1) catch @panic(what ++ " overflow");
        assert(counter.* > current);
        return current;
    }

    /// The signature `signer` made over `subject`, recording a new one the first time.
    fn signature_for(self: *Shared, signer: u32, subject: []const u8) Allocator.Error!u64 {
        const key = try self.gpa.alloc(u8, 4 + subject.len);
        std.mem.writeInt(u32, key[0..4], signer, .big);
        @memcpy(key[4..], subject);
        self.lock();
        defer self.unlock();
        if (self.signature_by_key.get(key)) |id| {
            self.gpa.free(key);
            return id;
        }
        errdefer self.gpa.free(key);
        try self.signature_by_key.ensureUnusedCapacity(self.gpa, 1);
        try self.signature_by_id.ensureUnusedCapacity(self.gpa, 1);
        const id = next(&self.signature_next, "signature");
        self.signature_by_key.putAssumeCapacityNoClobber(key, id);
        const signed: Signed = .{ .signer = signer, .subject = key[4..] };
        self.signature_by_id.putAssumeCapacityNoClobber(id, signed);
        return id;
    }

    /// The subject `signer` signed with signature `id`; the caller holds the lock. The
    /// slice stays valid for the ledger's lifetime.
    fn signed_subject_locked(self: *Shared, signer: u32, id: u64) ?[]const u8 {
        assert(self.mutex == .locked);
        const signed = self.signature_by_id.get(id) orelse return null;
        if (signed.signer != signer) return null;
        return signed.subject;
    }

    /// The certificate over `subject` by `signers`, recording a new one the first time;
    /// the caller holds the lock.
    fn certificate_for_locked(
        self: *Shared,
        subject: []const u8,
        signers: *const Signers,
    ) Allocator.Error!u64 {
        assert(self.mutex == .locked);
        const signers_size = codec.encode_size(Signers, signers.*);
        const key = try self.gpa.alloc(u8, 8 + subject.len + signers_size);
        std.mem.writeInt(u64, key[0..8], subject.len, .big);
        @memcpy(key[8..][0..subject.len], subject);
        _ = codec.encode_to(Signers, signers.*, key[8 + subject.len ..]);
        if (self.certificate_by_key.get(key)) |id| {
            self.gpa.free(key);
            return id;
        }
        errdefer self.gpa.free(key);
        try self.certificate_by_key.ensureUnusedCapacity(self.gpa, 1);
        try self.certificate_by_id.ensureUnusedCapacity(self.gpa, 1);
        const id = next(&self.certificate_next, "certificate");
        self.certificate_by_key.putAssumeCapacityNoClobber(key, id);
        self.certificate_by_id.putAssumeCapacityNoClobber(id, key[8..][0..subject.len]);
        return id;
    }

    /// Whether certificate `id` was assembled over `subject`.
    fn certificate_matches(self: *Shared, id: u64, subject: []const u8) bool {
        self.lock();
        defer self.unlock();
        const stored = self.certificate_by_id.get(id) orelse return false;
        return std.mem.eql(u8, stored, subject);
    }
};

/// The mock scheme's const-generic flags.
pub const Options = struct {
    attributable: bool = true,
    batchable: bool = true,
    /// When false, an invalid request panics instead of failing.
    allow_invalid: bool = true,
};

/// The subject's namespace and message, as commonware's `SignedSubject` compares them.
fn signed_subject(gpa: Allocator, subject: anytype, namespace: anytype) ![]u8 {
    const message = try subject.message(gpa);
    defer gpa.free(message);
    return utils.union_unique(gpa, subject.namespace(namespace), message);
}

/// A ledger-backed mock certificate scheme over `Subject` for participants identified by
/// keys of type `P`.
pub fn Scheme(comptime T: type, comptime F: type, comptime P: type, comptime opts: Options) type {
    certificate.assert_subject(T);
    return struct {
        const Self = @This();
        pub const Subject = T;
        pub const Faults = F;
        pub const Namespace = Subject.Namespace;
        pub const PublicKey = P;
        pub const Signature = U64;
        pub const Certificate = U64;
        pub const Attestation = certificate.Attestation(Self);
        pub const Verification = certificate.Verification(Self);
        pub const Assembled = certificate.Assembled(Self);
        pub const Item = certificate.CertificateItem(Self);
        pub const Participants = utils.ordered.Set(P);

        membership: ?certificate.Membership,
        committee: Participants,
        namespace: Namespace,
        shared: *Shared,

        fn init(
            gpa: Allocator,
            namespace: []const u8,
            committee: Participants,
            membership: ?certificate.Membership,
            shared: *Shared,
        ) Allocator.Error!Self {
            return .{
                .membership = membership,
                .committee = committee,
                .namespace = try Namespace.derive(gpa, namespace),
                .shared = shared.retain(),
            };
        }

        /// A signer at `index`, or null when `index` is outside `set`. Takes ownership of
        /// `set` and a new reference to `shared`.
        pub fn signer(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            index: Participant,
            shared: *Shared,
        ) Allocator.Error!?Self {
            var committee = set;
            errdefer committee.deinit(gpa);
            if (committee.key(index) == null) {
                committee.deinit(gpa);
                return null;
            }
            return try init(gpa, namespace, committee, .{ .signer = index }, shared);
        }

        /// A verifier sharing `shared`. Takes ownership of `set`.
        pub fn verifier(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            shared: *Shared,
        ) Allocator.Error!Self {
            var committee = set;
            errdefer committee.deinit(gpa);
            return init(gpa, namespace, committee, null, shared);
        }

        /// A verifier reporting the membership of `public_key`, or null when it is not a
        /// participant. Takes ownership of `set`.
        pub fn member(
            gpa: Allocator,
            namespace: []const u8,
            set: Participants,
            public_key: P,
            shared: *Shared,
        ) Allocator.Error!?Self {
            var committee = set;
            errdefer committee.deinit(gpa);
            const index = committee.index(public_key) orelse {
                committee.deinit(gpa);
                return null;
            };
            return try init(gpa, namespace, committee, .{ .member = index }, shared);
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var committee = try self.committee.clone(gpa);
            errdefer committee.deinit(gpa);
            return .{
                .membership = self.membership,
                .committee = committee,
                .namespace = try self.namespace.clone(gpa),
                .shared = self.shared.retain(),
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.committee.deinit(gpa);
            self.namespace.deinit(gpa);
            self.shared.release();
            self.* = undefined;
        }

        fn invalid(comptime reason: []const u8) bool {
            if (opts.allow_invalid) return false;
            @panic("invalid mock certificate request: " ++ reason);
        }

        fn assembly_error(err: certificate.AssemblyError) certificate.AssemblyError {
            if (opts.allow_invalid) return err;
            std.debug.panic("invalid mock certificate request: {s}", .{@errorName(err)});
        }

        pub fn me(self: *const Self) ?certificate.Membership {
            return self.membership;
        }

        pub fn participants(self: *const Self) *const Participants {
            return &self.committee;
        }

        /// A synthetic signature over `subject`; re-signing a subject reuses its signature.
        pub fn sign(self: *const Self, gpa: Allocator, subject: Subject) !?Attestation {
            const membership = self.membership orelse return null;
            const index = membership.signer_index() orelse return null;
            const signed = try signed_subject(gpa, subject, &self.namespace);
            defer gpa.free(signed);
            const id = try self.shared.signature_for(index.get(), signed);
            return Attestation.init(index, U64.init(id));
        }

        pub fn verify_attestation(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestation: *const Attestation,
            strategy: anytype,
        ) Allocator.Error!bool {
            _ = rng;
            _ = strategy;
            if (self.committee.key(attestation.signer) == null) {
                return invalid("attestation signer missing from participant set");
            }
            const signature = attestation.signature.get() orelse
                return invalid("attestation signature missing");
            const expected = try signed_subject(gpa, subject, &self.namespace);
            defer gpa.free(expected);
            self.shared.lock();
            const stored =
                self.shared.signed_subject_locked(attestation.signer.get(), signature.get());
            self.shared.unlock();
            if (stored) |bytes| {
                if (std.mem.eql(u8, bytes, expected)) return true;
            }
            return invalid("attestation not found or subject mismatched");
        }

        /// Verifies each attestation on its own.
        pub fn verify_attestations(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            attestations: []const Attestation,
            strategy: anytype,
        ) Allocator.Error!Verification {
            var verified: std.ArrayList(Attestation) = try .initCapacity(gpa, attestations.len);
            errdefer verified.deinit(gpa);
            var invalid_list: std.ArrayList(Participant) = .empty;
            defer invalid_list.deinit(gpa);
            for (attestations) |*attestation| {
                if (try self.verify_attestation(gpa, rng, subject, attestation, strategy)) {
                    verified.appendAssumeCapacity(attestation.*);
                } else {
                    try invalid_list.append(gpa, attestation.signer);
                }
            }
            const sorted = certificate.sort_unique(invalid_list.items);
            const invalid_owned = try gpa.dupe(Participant, sorted);
            errdefer gpa.free(invalid_owned);
            return .{ .verified = try verified.toOwnedSlice(gpa), .invalid = invalid_owned };
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
            return certificate.optimistic_assemble(
                self,
                gpa,
                rng,
                subject,
                pending,
                verified,
                strategy,
            );
        }

        /// The subject every attestation signed, or an assembly error.
        fn common_subject_locked(
            self: *const Self,
            attestations: []const Attestation,
        ) certificate.AssemblyError![]const u8 {
            var subject: ?[]const u8 = null;
            for (attestations) |attestation| {
                const signer_index = attestation.signer;
                if (self.committee.key(signer_index) == null) {
                    return assembly_error(error.UnknownSigner);
                }
                const signature = attestation.signature.get() orelse
                    return assembly_error(error.MalformedSignature);
                const stored =
                    self.shared.signed_subject_locked(signer_index.get(), signature.get()) orelse
                    return assembly_error(error.MalformedSignature);
                if (subject) |existing| {
                    if (!std.mem.eql(u8, existing, stored)) {
                        return assembly_error(error.MalformedSignature);
                    }
                } else subject = stored;
            }
            return subject.?;
        }

        /// Assembles attestations over one subject into a synthetic certificate; the same
        /// subject and signers always yield the same certificate.
        pub fn assemble(
            self: *const Self,
            gpa: Allocator,
            attestations: []const Attestation,
            strategy: anytype,
        ) (certificate.AssemblyError || Allocator.Error)!U64 {
            _ = strategy;
            assert(attestations.len > 0);
            const indices = try gpa.alloc(Participant, attestations.len);
            defer gpa.free(indices);
            for (attestations, indices) |attestation, *index| index.* = attestation.signer;
            self.shared.lock();
            defer self.shared.unlock();
            const subject = try self.common_subject_locked(attestations);
            var signers = Signers.from_set(gpa, &self.committee, indices) catch |err| {
                return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => |other| assembly_error(other),
                };
            };
            defer signers.deinit(gpa);
            try signers.require(self.committee.quorum(Faults));
            return U64.init(try self.shared.certificate_for_locked(subject, &signers));
        }

        pub fn verify_certificate(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            cert: *const U64,
            strategy: anytype,
        ) Allocator.Error!bool {
            _ = rng;
            _ = strategy;
            const expected = try signed_subject(gpa, subject, &self.namespace);
            defer gpa.free(expected);
            if (self.shared.certificate_matches(cert.get(), expected)) return true;
            return invalid("certificate not found or subject mismatched");
        }

        /// Verifies a non-empty list of certificates one by one.
        pub fn verify_certificates(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            items: []const Item,
            strategy: anytype,
        ) Allocator.Error!bool {
            assert(items.len > 0);
            for (items) |item| {
                const valid = try self.verify_certificate(
                    gpa,
                    rng,
                    item.subject,
                    item.certificate,
                    strategy,
                );
                if (!valid) return false;
            }
            return true;
        }

        pub fn is_attributable() bool {
            return opts.attributable;
        }

        pub fn is_batchable() bool {
            return opts.batchable;
        }

        pub fn max_certificate_size(_: u32) usize {
            return U64.fixed_size;
        }

        pub fn certificate_codec_config(_: *const Self) void {}

        pub fn certificate_codec_config_unbounded() void {}

        comptime {
            certificate.assert_scheme(Self);
        }
    };
}

/// Builds `n` ed25519 identities, one mock signer per identity sharing one ledger, and a
/// verifier (commonware `fixture` / `fixture_with`). `S` is a mock `Scheme` over
/// `ed25519.PublicKey`.
pub fn fixture(
    comptime S: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    n: u32,
) Allocator.Error!Fixture(S) {
    assert(n > 0);
    const public_keys, const private_keys = try ed25519_mocks.participants(gpa, rng, n);
    errdefer gpa.free(public_keys);
    errdefer gpa.free(private_keys);
    var set = S.Participants.init(gpa, public_keys) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Proof: `participants` returns strictly increasing keys.
        else => unreachable,
    };
    defer set.deinit(gpa);
    const shared = try Shared.create(gpa);
    defer shared.release();
    const schemes = try gpa.alloc(S, n);
    errdefer gpa.free(schemes);
    var built: usize = 0;
    errdefer for (schemes[0..built]) |*scheme| scheme.deinit(gpa);
    for (schemes, 0..) |*scheme, index| {
        const position: Participant = .from_usize(index);
        const signer = try S.signer(gpa, namespace, try set.clone(gpa), position, shared);
        scheme.* = signer orelse unreachable; // Proof: `index < n == set.len()`.
        built += 1;
    }
    assert(built == n);
    return .{
        .participants = public_keys,
        .private_keys = private_keys,
        .schemes = schemes,
        .verifier = try S.verifier(gpa, namespace, try set.clone(gpa), shared),
    };
}

test {
    _ = @import("mocks_test.zig");
}
