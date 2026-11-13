//! Multi-party certificates (commonware `cryptography/src/certificate.rs`).
//!
//! Participants sign a subject and produce attestations; a quorum of attestations assembles
//! into a certificate that anyone holding the participant set can verify. Rust's `Verifier`,
//! `Scheme`, `Subject`, `Namespace`, and `Provider` traits are comptime interfaces here:
//!
//! - A subject type `T` declares `T.Namespace` (with `derive(gpa, base) !Namespace`,
//!   `clone(*const Namespace, gpa) !Namespace`, and `deinit(*Namespace, gpa)`;
//!   `BytesNamespace` is commonware's `Vec<u8>`), and has
//!   `subject.namespace(*const Namespace) []const u8` and `subject.message(gpa) ![]u8` (the
//!   caller frees the message).
//! - A scheme `S` declares `Signature`, `PublicKey`, `Certificate` (with `deinit(gpa)` if it
//!   owns memory),
//!   `Subject`, and `Faults`, and has `me`, `participants`, `sign`, `verify_attestation`,
//!   `verify_attestations`, `optimistic_assemble`, `assemble`, `verify_certificate`,
//!   `verify_certificates`, `is_batchable`, `is_attributable`, `max_certificate_size`,
//!   `certificate_codec_config`, and `certificate_codec_config_unbounded` (see
//!   `assert_scheme`). Operations that build messages or lists take an allocator and return
//!   `Allocator.Error` on top of commonware's result.
//!
//! Zig errors carry no payload, so `AssemblyError` drops the signer and counts commonware
//! attaches to its variants.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const parallel = @import("parallel");
const ChaCha20Rng = @import("rng.zig").ChaCha20Rng;

pub const mocks = @import("certificate/mocks.zig");

const Participant = utils.Participant;
const BitMap = utils.bitmap.BitMap(1);

/// The scheme's own place in the participant set.
pub const Membership = union(enum) {
    /// A participant that holds signing material at this index.
    signer: Participant,
    /// A participant without signing material at this index.
    member: Participant,

    pub fn index(self: Membership) Participant {
        return switch (self) {
            .signer, .member => |participant| participant,
        };
    }

    /// The index if this participant can sign.
    pub fn signer_index(self: Membership) ?Participant {
        return switch (self) {
            .signer => |participant| participant,
            .member => null,
        };
    }

    pub fn eql(a: Membership, b: Membership) bool {
        return std.meta.eql(a, b);
    }
};

/// Errors returned while assembling attestations into a certificate.
pub const AssemblyError = error{
    /// Structurally valid attestations do not meet the scheme's quorum.
    InsufficientAttestations,
    /// An attestation references an index outside the participant set.
    UnknownSigner,
    /// More than one attestation references the same signer.
    DuplicateSigner,
    /// An attestation contains a malformed encoded signature.
    MalformedSignature,
    /// The scheme could not recover a certificate from structurally valid attestations.
    RecoveryFailed,
};

/// A fixed-size value kept as its encoding and decoded on demand (commonware `Lazy<T>` for
/// the fixed-size signatures of attestations and certificates). Unlike `codec.Lazy` it owns
/// its bytes inline, so a decoded attestation outlives the message it came from. Decoding
/// never allocates.
pub fn Deferred(comptime T: type) type {
    const size = codec.fixed_size(T) orelse @compileError("Deferred needs a fixed-size type");
    comptime assert(!codec.owns_memory(T));
    comptime assert(size > 0);
    return struct {
        const Self = @This();
        pub const Value = T;
        pub const fixed_size: usize = size;

        bytes: [size]u8,

        pub fn init(value: T) Self {
            var bytes: [size]u8 = undefined;
            const written = codec.encode_to(T, value, &bytes);
            assert(written.len == size);
            return .{ .bytes = bytes };
        }

        /// The decoded value, or null when the bytes are not a valid `T`.
        pub fn get(self: *const Self) ?T {
            return codec.decode_fixed(T, &self.bytes) catch null;
        }

        /// Byte equality: for canonical encodings the same as value equality.
        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u8, &a.bytes, &b.bytes);
        }

        pub fn order(a: Self, b: Self) std.math.Order {
            return std.mem.order(u8, &a.bytes, &b.bytes);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_bytes(&self.bytes);
        }

        pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const bytes = try reader.take_array(size);
            return .{ .bytes = bytes.* };
        }
    };
}

/// A participant's attestation: the signer's index and its signature over a subject.
/// Encoded as the signer (a `u32` varint), then the scheme's fixed-size signature.
pub fn Attestation(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Signature = S.Signature;

        signer: Participant,
        signature: Deferred(S.Signature),

        pub const max_encode_size: usize = Participant.max_encode_size +
            Deferred(S.Signature).fixed_size;

        pub fn init(signer: Participant, signature: S.Signature) Self {
            return .{ .signer = signer, .signature = .init(signature) };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.signer.index == b.signer.index and a.signature.eql(b.signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.signer.write(writer);
            self.signature.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            const size = self.signer.encode_size() + Deferred(S.Signature).fixed_size;
            assert(size <= max_encode_size);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const signer = try Participant.read(gpa, reader, {});
            return .{ .signer = signer, .signature = try .read(gpa, reader, {}) };
        }
    };
}

/// The result of verifying attestations: those accepted, and the sorted, distinct indices
/// of the signers rejected. Both slices are allocated with the allocator passed to
/// `deinit`.
pub fn Verification(comptime S: type) type {
    return struct {
        const Self = @This();

        verified: []Attestation(S),
        invalid: []Participant,

        pub const empty: Self = .{ .verified = &.{}, .invalid = &.{} };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.verified);
            gpa.free(self.invalid);
            self.* = undefined;
        }
    };
}

/// `optimistic_assemble`'s result: the certificate, or the verification of the pending
/// attestations (commonware's `Err(Verification)`).
pub fn Assembled(comptime S: type) type {
    return union(enum) {
        certificate: S.Certificate,
        verification: Verification(S),

        pub fn deinit(self: *@This(), gpa: Allocator) void {
            switch (self.*) {
                .certificate => |*value| deinit_certificate(S.Certificate, gpa, value),
                .verification => |*value| value.deinit(gpa),
            }
            self.* = undefined;
        }
    };
}

/// Releases a certificate that owns memory; fixed-size certificates (such as the mock
/// scheme's `U64`) have nothing to release.
pub fn deinit_certificate(comptime C: type, gpa: Allocator, value: *C) void {
    if (@hasDecl(C, "deinit")) value.deinit(gpa);
}

/// One certificate to verify with its subject.
pub fn CertificateItem(comptime S: type) type {
    return struct {
        subject: S.Subject,
        certificate: *const S.Certificate,
    };
}

/// commonware's `Namespace for Vec<u8>`: the base namespace itself.
pub const BytesNamespace = struct {
    bytes: []u8,

    pub fn derive(gpa: Allocator, base: []const u8) Allocator.Error!BytesNamespace {
        return .{ .bytes = try gpa.dupe(u8, base) };
    }

    pub fn clone(self: *const BytesNamespace, gpa: Allocator) Allocator.Error!BytesNamespace {
        return derive(gpa, self.bytes);
    }

    pub fn deinit(self: *BytesNamespace, gpa: Allocator) void {
        gpa.free(self.bytes);
        self.* = undefined;
    }
};

fn assert_decls(
    comptime T: type,
    comptime decls: []const []const u8,
    comptime name: []const u8,
) void {
    comptime {
        for (decls) |decl| {
            if (!@hasDecl(T, decl)) @compileError(@typeName(T) ++ " lacks " ++ name ++ "." ++ decl);
        }
    }
}

/// Asserts `T` implements `Subject`.
pub fn assert_subject(comptime T: type) void {
    assert_decls(T, &.{ "Namespace", "namespace", "message" }, "Subject");
    assert_decls(T.Namespace, &.{ "derive", "clone", "deinit" }, "Namespace");
}

/// Asserts `V` implements `Verifier`.
pub fn assert_verifier(comptime V: type) void {
    assert_decls(V, &.{
        "Subject",                            "Faults",               "PublicKey",
        "Certificate",                        "verify_certificate",   "verify_certificates",
        "is_batchable",                       "max_certificate_size", "certificate_codec_config",
        "certificate_codec_config_unbounded",
    }, "Verifier");
    assert_subject(V.Subject);
    utils.faults.assert_faults(V.Faults);
}

/// Asserts `S` implements `Scheme`.
pub fn assert_scheme(comptime S: type) void {
    assert_verifier(S);
    assert_decls(S, &.{
        "Signature",          "me",                  "participants", "sign",
        "verify_attestation", "verify_attestations", "assemble",     "optimistic_assemble",
        "is_attributable",
    }, "Scheme");
    comptime assert(codec.fixed_size(S.Signature) != null);
}

/// Which participants signed a certificate: a bitmap over the participant set, stored in
/// 1-byte chunks (`BitMap<1>`). Encoded as the bit length (big-endian `u64`), then the
/// chunks.
pub const Signers = struct {
    bitmap: BitMap,

    /// The largest participant count the decoded bitmap may cover.
    pub const Cfg = usize;

    /// Builds the bitmap over `participants` from signer indices in any order.
    pub fn init(
        gpa: Allocator,
        participants: u32,
        signers: []const Participant,
    ) (AssemblyError || Allocator.Error)!Signers {
        var bitmap = try BitMap.zeroes(gpa, participants);
        errdefer bitmap.deinit(gpa);
        for (signers) |signer| {
            const index: u64 = signer.get();
            if (index >= bitmap.len()) return error.UnknownSigner;
            if (bitmap.get(index)) return error.DuplicateSigner;
            bitmap.set(index, true);
        }
        assert(bitmap.count_ones() == signers.len);
        return .{ .bitmap = bitmap };
    }

    /// `init` over a participant set (Rust `TryFrom<(&Set<P>, I)>`).
    pub fn from_set(
        gpa: Allocator,
        participants: anytype,
        signers: []const Participant,
    ) (AssemblyError || Allocator.Error)!Signers {
        const total = std.math.cast(u32, participants.len()) orelse
            @panic("participant count exceeds u32::MAX");
        return init(gpa, total, signers);
    }

    pub fn deinit(self: *Signers, gpa: Allocator) void {
        self.bitmap.deinit(gpa);
        self.* = undefined;
    }

    pub fn clone(self: *const Signers, gpa: Allocator) Allocator.Error!Signers {
        return .{ .bitmap = try self.bitmap.clone(gpa) };
    }

    /// Fails with `InsufficientAttestations` when fewer than `required` signed.
    pub fn require(self: *const Signers, required: u32) AssemblyError!void {
        if (self.count() < required) return error.InsufficientAttestations;
    }

    /// The size of the participant set the bitmap covers.
    pub fn len(self: *const Signers) usize {
        return @intCast(self.bitmap.len());
    }

    /// How many participants signed.
    pub fn count(self: *const Signers) usize {
        return @intCast(self.bitmap.count_ones());
    }

    /// Iterates over the signers in ascending order.
    pub fn iter(self: *const Signers) Iterator {
        return .{ .inner = self.bitmap.ones_iter() };
    }

    pub const Iterator = struct {
        inner: BitMap.OnesIter,

        pub fn next(self: *Iterator) ?Participant {
            const index = self.inner.next() orelse return null;
            return Participant.from_usize(@intCast(index));
        }
    };

    pub fn eql(a: *const Signers, b: *const Signers) bool {
        return a.bitmap.eql(&b.bitmap);
    }

    /// The largest encoding over at most `participants` participants.
    pub fn max_encode_size(participants: u32) usize {
        return BitMap.encode_size_max(participants);
    }

    pub fn write(self: Signers, writer: *codec.Writer) void {
        self.bitmap.write(writer);
    }

    pub fn encode_size(self: Signers) usize {
        return self.bitmap.encode_size();
    }

    /// Reads a bitmap over at most `max_participants` participants. The exact length is
    /// checked against the participant set when a certificate is verified.
    pub fn read(
        gpa: Allocator,
        reader: *codec.Reader,
        max_participants: usize,
    ) codec.Error!Signers {
        const range = codec.RangeCfg(u64).to_inclusive(max_participants);
        return .{ .bitmap = try BitMap.read(gpa, reader, range) };
    }
};

/// An upper bound on the encoding of a certificate with a signer bitmap over at most
/// `participants` participants and one `signature_size`-byte signature per signer.
pub fn max_individual_certificate_size(participants: u32, signature_size: usize) usize {
    return Signers.max_encode_size(participants) +
        codec.util.max_items_size(participants, signature_size);
}

/// A certificate of individual signatures, as ed25519 and secp256r1 build them: the signer
/// bitmap, then one signature per signer in index order (a `Vec` of fixed-size signatures).
/// `context` names the type in decode errors.
pub fn Individual(comptime Sig: type, comptime context: []const u8) type {
    return struct {
        const Self = @This();
        pub const Signature = Sig;

        /// Participant indices that contributed signatures.
        signers: Signers,
        /// The signatures, ordered by signer index.
        signatures: []Deferred(Sig),

        /// The participant count bounding both the bitmap and the signature list.
        pub const Cfg = usize;

        const Signed = struct { signer: Participant, signature: Deferred(Sig) };

        fn signed_less(_: void, a: Signed, b: Signed) bool {
            return a.signer.get() < b.signer.get();
        }

        /// Assembles a non-empty list of attestations, which need not be verified, over a
        /// committee of `participants` with quorum `quorum`, sorting the signatures by signer
        /// (the shared body of the ed25519 and secp256r1 `assemble`).
        pub fn assemble(
            gpa: Allocator,
            participants: usize,
            quorum: u32,
            attestations: anytype,
        ) (AssemblyError || Allocator.Error)!Self {
            assert(attestations.len > 0);
            const total = std.math.cast(u32, participants) orelse
                @panic("participant count exceeds u32::MAX");
            const entries = try gpa.alloc(Signed, attestations.len);
            defer gpa.free(entries);
            for (attestations, entries) |attestation, *entry| {
                if (attestation.signer.get() >= total) return error.UnknownSigner;
                if (attestation.signature.get() == null) return error.MalformedSignature;
                entry.* = .{ .signer = attestation.signer, .signature = attestation.signature };
            }
            std.mem.sort(Signed, entries, {}, signed_less);
            const indices = try gpa.alloc(Participant, entries.len);
            defer gpa.free(indices);
            for (entries, indices) |entry, *index| index.* = entry.signer;
            var signers = try Signers.init(gpa, total, indices);
            errdefer signers.deinit(gpa);
            try signers.require(quorum);
            const signatures = try gpa.alloc(Deferred(Sig), entries.len);
            for (entries, signatures) |entry, *signature| signature.* = entry.signature;
            assert(signers.count() == signatures.len);
            return .{ .signers = signers, .signatures = signatures };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.signers.deinit(gpa);
            gpa.free(self.signatures);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var signers = try self.signers.clone(gpa);
            errdefer signers.deinit(gpa);
            const signatures = try gpa.dupe(Deferred(Sig), self.signatures);
            return .{ .signers = signers, .signatures = signatures };
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            if (!a.signers.eql(&b.signers)) return false;
            if (a.signatures.len != b.signatures.len) return false;
            for (a.signatures, b.signatures) |left, right| {
                if (!left.eql(right)) return false;
            }
            return true;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.signers.write(writer);
            codec.write([]const Deferred(Sig), self.signatures, writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.signers.encode_size() +
                codec.encode_size([]const Deferred(Sig), self.signatures);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, participants: usize) codec.Error!Self {
            var signers = try Signers.read(gpa, reader, participants);
            errdefer signers.deinit(gpa);
            if (signers.count() == 0) {
                return reader.invalid(context, "Certificate contains no signers");
            }
            const range = codec.RangeCfg(usize).to_inclusive(participants);
            const signatures = try codec.read_range([]const Deferred(Sig), gpa, reader, range);
            errdefer gpa.free(signatures);
            if (signers.count() != signatures.len) {
                return reader.invalid(context, "Signers and signatures counts differ");
            }
            return .{ .signers = signers, .signatures = @constCast(signatures) };
        }
    };
}

/// Verifies each certificate and writes its result to `out` (commonware
/// `verify_certificates_bisect`). A batchable scheme first checks every certificate at once
/// and bisects failing ranges; others check each certificate alone.
pub fn verify_certificates_bisect(
    scheme: anytype,
    gpa: Allocator,
    rng: anytype,
    items: anytype,
    out: []bool,
    strategy: anytype,
) Allocator.Error!void {
    const S = @TypeOf(scheme.*);
    assert(items.len == out.len);
    @memset(out, false);
    if (items.len == 0) return;
    if (!S.is_batchable()) {
        for (items, out) |item, *verified| {
            verified.* = try scheme.verify_certificate(
                gpa,
                rng,
                item.subject,
                item.certificate,
                strategy,
            );
        }
        return;
    }
    // Each split pushes two halves and pops one range, so the stack holds at most one
    // pending range per level of a 64-level bisection, plus the range being split.
    var stack: [66]parallel.Range = undefined;
    stack[0] = .init(0, items.len);
    var depth: usize = 1;
    while (depth > 0) {
        depth -= 1;
        const range = stack[depth];
        assert(range.start < range.end);
        if (try scheme.verify_certificates(gpa, rng, items[range.start..range.end], strategy)) {
            @memset(out[range.start..range.end], true);
        } else if (range.end - range.start > 1) {
            const middle = range.start + (range.end - range.start) / 2;
            assert(depth + 2 <= stack.len);
            stack[depth] = .init(middle, range.end);
            stack[depth + 1] = .init(range.start, middle);
            depth += 2;
        }
    }
}

/// Verifies the pending attestations, then assembles them with the verified ones (commonware
/// `verify_then_assemble`). A rejected attestation returns the verification even when the
/// rest could certify, preserving fault evidence; so does a failed assembly.
pub fn verify_then_assemble(
    scheme: anytype,
    gpa: Allocator,
    rng: anytype,
    subject: anytype,
    pending: anytype,
    verified: anytype,
    strategy: anytype,
) Allocator.Error!Assembled(@TypeOf(scheme.*)) {
    const S = @TypeOf(scheme.*);
    var result: Verification(S) = if (pending.len == 0)
        .empty
    else
        try scheme.verify_attestations(gpa, rng, subject, pending, strategy);
    errdefer result.deinit(gpa);
    if (result.invalid.len != 0) return .{ .verification = result };
    if (result.verified.len + verified.len == 0) return .{ .verification = result };

    const combined = try std.mem.concat(gpa, Attestation(S), &.{ result.verified, verified });
    defer gpa.free(combined);
    const certificate = scheme.assemble(gpa, combined, strategy) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .verification = result },
    };
    result.deinit(gpa);
    return .{ .certificate = certificate };
}

/// Assembles a candidate certificate from every attestation and checks it first, verifying
/// the pending attestations only when it fails (commonware `optimistic_assemble`). The
/// fallback splits the pending attestations in two halves, each verified with its own RNG
/// seeded from `rng`, so the halves may run in parallel.
pub fn optimistic_assemble(
    scheme: anytype,
    gpa: Allocator,
    rng: anytype,
    subject: anytype,
    pending: anytype,
    verified: anytype,
    strategy: anytype,
) Allocator.Error!Assembled(@TypeOf(scheme.*)) {
    const S = @TypeOf(scheme.*);
    if (pending.len == 0) {
        return verify_then_assemble(scheme, gpa, rng, subject, pending, verified, strategy);
    }
    const combined = try std.mem.concat(gpa, Attestation(S), &.{ pending, verified });
    defer gpa.free(combined);
    if (scheme.assemble(gpa, combined, strategy)) |candidate| {
        var certificate = candidate;
        const result = scheme.verify_certificate(gpa, rng, subject, &certificate, strategy);
        const valid = result catch |err| {
            deinit_certificate(S.Certificate, gpa, &certificate);
            return err;
        };
        if (valid) return .{ .certificate = certificate };
        deinit_certificate(S.Certificate, gpa, &certificate);
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }
    if (pending.len == 1) {
        const verification = try scheme.verify_attestations(gpa, rng, subject, pending, strategy);
        return .{ .verification = verification };
    }
    return verify_halves(scheme, gpa, rng, subject, pending, strategy);
}

fn verify_halves(
    scheme: anytype,
    gpa: Allocator,
    rng: anytype,
    subject: anytype,
    pending: anytype,
    strategy: anytype,
) Allocator.Error!Assembled(@TypeOf(scheme.*)) {
    const S = @TypeOf(scheme.*);
    assert(pending.len >= 2);
    const middle = std.math.divCeil(usize, pending.len, 2) catch unreachable;
    var seeds: [2][32]u8 = undefined;
    for (&seeds) |*seed| rng.fill_bytes(seed);
    const Half = struct {
        scheme: *const S,
        gpa: Allocator,
        rng: ChaCha20Rng,
        subject: S.Subject,
        attestations: []const Attestation(S),
        strategy: @TypeOf(strategy),

        pub fn call(self: @This()) Allocator.Error!Verification(S) {
            var half_rng = self.rng;
            return self.scheme.verify_attestations(
                self.gpa,
                &half_rng,
                self.subject,
                self.attestations,
                self.strategy,
            );
        }
    };
    const first: Half = .{
        .scheme = scheme,
        .gpa = gpa,
        .rng = .init_key(seeds[0]),
        .subject = subject,
        .attestations = pending[0..middle],
        .strategy = strategy,
    };
    var rest = first;
    rest.rng = .init_key(seeds[1]);
    rest.attestations = pending[middle..];
    const results = strategy.join(first, rest);
    var left = results[0] catch |err| {
        if (results[1]) |value| {
            var right = value;
            right.deinit(gpa);
        } else |_| {}
        return err;
    };
    defer left.deinit(gpa);
    var right = try results[1];
    defer right.deinit(gpa);
    const halves = [_][]const Attestation(S){ left.verified, right.verified };
    const verified_all = try std.mem.concat(gpa, Attestation(S), &halves);
    errdefer gpa.free(verified_all);
    const invalid = try std.mem.concat(gpa, Participant, &.{ left.invalid, right.invalid });
    return .{ .verification = .{ .verified = verified_all, .invalid = invalid } };
}

/// Sorts and deduplicates `invalid` in place and returns the distinct prefix (a `BTreeSet`).
pub fn sort_unique(invalid: []Participant) []Participant {
    std.mem.sort(Participant, invalid, {}, struct {
        fn less(_: void, a: Participant, b: Participant) bool {
            return a.get() < b.get();
        }
    }.less);
    var kept: usize = @min(invalid.len, 1);
    for (1..@max(invalid.len, 1)) |cursor| {
        if (invalid[cursor].get() != invalid[kept - 1].get()) {
            invalid[kept] = invalid[cursor];
            kept += 1;
        }
    }
    return invalid[0..kept];
}

/// A scheme handle for one scope (commonware `Scoped`): always a verifier; the signing
/// scheme comes back from `into_scheme` only when built with `scheme`.
pub fn Scoped(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Subject = S.Subject;
        pub const Faults = S.Faults;
        pub const PublicKey = S.PublicKey;
        pub const Certificate = S.Certificate;

        inner: *const S,
        can_sign: bool,

        /// A verify-only scope.
        pub fn verifier(inner: *const S) Self {
            return .{ .inner = inner, .can_sign = false };
        }

        /// A full signing scope.
        pub fn scheme(inner: *const S) Self {
            return .{ .inner = inner, .can_sign = true };
        }

        /// The signing scheme, or null for a verify-only scope.
        pub fn into_scheme(self: Self) ?*const S {
            return if (self.can_sign) self.inner else null;
        }

        pub fn verify_certificate(
            self: Self,
            gpa: Allocator,
            rng: anytype,
            subject: Subject,
            certificate: *const Certificate,
            strategy: anytype,
        ) Allocator.Error!bool {
            return self.inner.verify_certificate(gpa, rng, subject, certificate, strategy);
        }

        pub fn verify_certificates(
            self: Self,
            gpa: Allocator,
            rng: anytype,
            items: []const CertificateItem(S),
            strategy: anytype,
        ) Allocator.Error!bool {
            return self.inner.verify_certificates(gpa, rng, items, strategy);
        }

        pub fn is_batchable() bool {
            return S.is_batchable();
        }

        pub fn max_certificate_size(participants: u32) usize {
            return S.max_certificate_size(participants);
        }

        pub fn certificate_codec_config(self: Self) codec.Cfg(Certificate) {
            return self.inner.certificate_codec_config();
        }

        pub fn certificate_codec_config_unbounded() codec.Cfg(Certificate) {
            return S.certificate_codec_config_unbounded();
        }
    };
}

/// A provider that returns the same scheme for every scope (commonware `ConstantProvider`).
/// A provider has `scoped(scope) ?Scoped(S)` and `scheme(scope) ?*const S`.
pub fn ConstantProvider(comptime S: type) type {
    return struct {
        const Self = @This();

        inner: *const S,

        pub fn init(inner: *const S) Self {
            return .{ .inner = inner };
        }

        pub fn scoped(self: Self, scope: anytype) ?Scoped(S) {
            _ = scope;
            return Scoped(S).scheme(self.inner);
        }

        pub fn scheme(self: Self, scope: anytype) ?*const S {
            const handle = self.scoped(scope) orelse return null;
            return handle.into_scheme();
        }
    };
}

test {
    _ = @import("certificate_test.zig");
    _ = mocks;
}
