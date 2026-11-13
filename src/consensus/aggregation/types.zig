//! Types used in aggregation (commonware `consensus/src/aggregation/types.rs`).
//!
//! - `Item(D)`: a height and the digest validators sign at it. It is also the certificate
//!   `Subject`: the signed message is the encoded item (height and digest, never the epoch).
//! - `Ack(S, D)`: a validator's attestation over an item, tagged with the epoch whose scheme
//!   verifies it (the epoch is not signed; see the module docs on epoch-independent
//!   signatures).
//! - `TipAck(S, D)`: the network message, an ack and the sender's tip.
//! - `Certificate(S, D)`: an item and the certificate a quorum of acks assembled.
//! - `Activity(S, D)`: what the engine reports and journals (ack, certificate, or tip).
//!
//! `S` is a certificate scheme over `Item(D)` with the `N3f1` fault model (`scheme.zig`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const consensus_types = @import("../types.zig");

const Epoch = consensus_types.Epoch;
const Height = consensus_types.Height;
const Participant = consensus_types.Participant;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;
const certificate = cryptography.certificate;

pub const Attestation = certificate.Attestation;
pub const AssemblyError = certificate.AssemblyError;

/// Errors met while handling acks (commonware `aggregation::Error`). Zig errors carry no
/// payload; commonware attaches the epoch, height, or sender.
pub const Error = error{
    /// The application canceled a digest request.
    AppProposeCanceled,
    /// The sender is not a participant in the ack's epoch.
    UnknownValidator,
    /// The sender's key does not match the attestation's signer.
    PeerMismatch,
    /// The attestation does not verify.
    InvalidAckSignature,
    /// The ack's epoch is outside the accepted bounds.
    AckEpochOutsideBounds,
    /// The ack's height is at or beyond the window above the tip.
    AckHeight,
    /// The ack's digest differs from the verified digest at its height.
    AckDigest,
    /// The sender already sent an ack for this height and epoch.
    AckDuplicate,
    /// The height already has a certificate (or is below the activity threshold).
    AckCertified,
    /// No scheme is known for the epoch.
    UnknownEpoch,
};

/// Whether `err` is a blockable offense by the peer that caused it.
pub fn blockable(err: Error) bool {
    return switch (err) {
        error.PeerMismatch, error.InvalidAckSignature => true,
        else => false,
    };
}

/// Appended to the application namespace for acks, so an ack signature never verifies as
/// any other message.
pub const ack_suffix = "_AGG_ACK";

/// The ack signing namespace: the application namespace with `_AGG_ACK` appended.
pub const Namespace = struct {
    bytes: []u8,

    /// `certificate::Namespace::derive`.
    pub fn derive(gpa: Allocator, base: []const u8) Allocator.Error!Namespace {
        const bytes = try std.mem.concat(gpa, u8, &.{ base, ack_suffix });
        assert(bytes.len == base.len + ack_suffix.len);
        assert(std.mem.endsWith(u8, bytes, ack_suffix));
        return .{ .bytes = bytes };
    }

    pub fn clone(self: *const Namespace, gpa: Allocator) Allocator.Error!Namespace {
        assert(std.mem.endsWith(u8, self.bytes, ack_suffix));
        return .{ .bytes = try gpa.dupe(u8, self.bytes) };
    }

    pub fn deinit(self: *Namespace, gpa: Allocator) void {
        assert(self.bytes.len >= ack_suffix.len);
        gpa.free(self.bytes);
        self.* = undefined;
    }
};

const AckNamespace = Namespace;

/// An item to aggregate: a height and the digest validators sign at it.
pub fn Item(comptime D: type) type {
    const digest_size = codec.fixed_size(D) orelse @compileError("digests are fixed-size");
    return struct {
        const Self = @This();
        pub const Digest = D;
        pub const Namespace = AckNamespace;

        height: Height,
        digest: D,

        pub const max_encode_size: usize = Height.max_encode_size + digest_size;

        pub fn order(a: Self, b: Self) std.math.Order {
            const by_height = Height.order(a.height, b.height);
            if (by_height != .eq) return by_height;
            return codec.order(D, a.digest, b.digest);
        }

        pub fn eql(a: Self, b: Self) bool {
            return order(a, b) == .eq;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.height.write(writer);
            codec.write(D, self.digest, writer);
        }

        pub fn encode_size(self: Self) usize {
            const size = self.height.encode_size() + digest_size;
            assert(size <= max_encode_size);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const height = try Height.read(gpa, reader, {});
            return .{ .height = height, .digest = try codec.read(D, gpa, reader) };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const height = try Height.arbitrary(gpa, u);
            return .{ .height = height, .digest = try codec.arbitrary.value(D, gpa, u) };
        }

        /// The signed message, written into `buffer`: the encoded item (no epoch).
        pub fn message_to(self: Self, buffer: *[max_encode_size]u8) []u8 {
            const encoded = codec.encode_to(Self, self, buffer);
            assert(encoded.len == self.encode_size());
            return encoded;
        }

        /// `certificate::Subject::message`; the caller frees the result.
        pub fn message(self: Self, gpa: Allocator) Allocator.Error![]u8 {
            var buffer: [max_encode_size]u8 = undefined;
            const encoded = self.message_to(&buffer);
            assert(encoded.len > digest_size);
            return gpa.dupe(u8, encoded);
        }

        /// `certificate::Subject::namespace`.
        pub fn namespace(self: Self, derived: *const AckNamespace) []const u8 {
            _ = self;
            assert(derived.bytes.len >= ack_suffix.len);
            return derived.bytes;
        }

        comptime {
            certificate.assert_subject(Self);
        }
    };
}

/// A validator's vote on an item: the item, the epoch whose scheme verifies it, and the
/// attestation. Encoded as the item, the epoch, then the attestation.
pub fn Ack(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();

        item: Item(D),
        /// Selects the verifying scheme; not part of the signed message.
        epoch: Epoch,
        attestation: Attestation(S),

        pub const max_encode_size: usize = Item(D).max_encode_size + Epoch.max_encode_size +
            Attestation(S).max_encode_size;

        /// Signs `item` with `scheme` for `epoch`, or returns null when `scheme` cannot
        /// sign. Signatures are deterministic.
        pub fn sign(gpa: Allocator, scheme: *const S, epoch: Epoch, item: Item(D)) !?Self {
            const attestation = try scheme.sign(gpa, item) orelse return null;
            return .{ .item = item, .epoch = epoch, .attestation = attestation };
        }

        /// Whether the attestation verifies for the item under `scheme`.
        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: *const S,
            strategy: anytype,
        ) Allocator.Error!bool {
            return scheme.verify_attestation(gpa, rng, self.item, &self.attestation, strategy);
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.item.eql(b.item) and a.epoch == b.epoch and
                a.attestation.eql(b.attestation);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.item.write(writer);
            self.epoch.write(writer);
            self.attestation.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            const size = self.item.encode_size() + self.epoch.encode_size() +
                self.attestation.encode_size();
            assert(size <= max_encode_size);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const item = try Item(D).read(gpa, reader, {});
            const epoch = try Epoch.read(gpa, reader, {});
            const attestation = try Attestation(S).read(gpa, reader, {});
            return .{ .item = item, .epoch = epoch, .attestation = attestation };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const item = try Item(D).arbitrary(gpa, u);
            const epoch = try Epoch.arbitrary(gpa, u);
            const signer = Participant.init(u.int(u32));
            const signature = try codec.arbitrary.value(S.Signature, gpa, u);
            return .{ .item = item, .epoch = epoch, .attestation = .init(signer, signature) };
        }
    };
}

/// The network message: the sender's tip (its lowest unconfirmed height) and an ack.
pub fn TipAck(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();

        tip: Height,
        ack: Ack(S, D),

        pub const max_encode_size: usize = Height.max_encode_size + Ack(S, D).max_encode_size;

        pub fn eql(a: Self, b: Self) bool {
            return a.tip == b.tip and a.ack.eql(b.ack);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.tip.write(writer);
            self.ack.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            const size = self.tip.encode_size() + self.ack.encode_size();
            assert(size <= max_encode_size);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const tip = try Height.read(gpa, reader, {});
            return .{ .tip = tip, .ack = try Ack(S, D).read(gpa, reader, {}) };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const tip = try Height.arbitrary(gpa, u);
            return .{ .tip = tip, .ack = try Ack(S, D).arbitrary(gpa, u) };
        }
    };
}

/// A certificate recovered for an item. Owns the scheme certificate; release with `deinit`.
pub fn Certificate(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Cfg = codec.Cfg(S.Certificate);

        item: Item(D),
        certificate: S.Certificate,

        /// Assembles the attestations of the acks for the first ack's item (acks for other
        /// items are skipped). `acks` is non-empty; its elements are `Ack(S, D)` values or
        /// pointers to them.
        pub fn from_acks(
            gpa: Allocator,
            scheme: *const S,
            acks: anytype,
            strategy: anytype,
        ) (AssemblyError || Allocator.Error)!Self {
            assert(acks.len > 0);
            const item: Item(D) = acks[0].item;
            const attestations = try gpa.alloc(Attestation(S), acks.len);
            defer gpa.free(attestations);
            var count: usize = 0;
            for (acks) |ack| {
                if (!ack.item.eql(item)) continue;
                attestations[count] = ack.attestation;
                count += 1;
            }
            assert(count > 0 and count <= acks.len);
            const assembled = try scheme.assemble(gpa, attestations[0..count], strategy);
            return .{ .item = item, .certificate = assembled };
        }

        /// Whether the certificate verifies for the item under `scheme`.
        pub fn verify(
            self: *const Self,
            gpa: Allocator,
            rng: anytype,
            scheme: *const S,
            strategy: anytype,
        ) Allocator.Error!bool {
            return scheme.verify_certificate(gpa, rng, self.item, &self.certificate, strategy);
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return .{ .item = self.item, .certificate = try self.certificate.clone(gpa) };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.certificate.deinit(gpa);
            self.* = undefined;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.item.eql(b.item) and a.certificate.eql(&b.certificate);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.item.write(writer);
            codec.write(S.Certificate, self.certificate, writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.item.encode_size() + codec.encode_size(S.Certificate, self.certificate);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const item = try Item(D).read(gpa, reader, {});
            const assembled = try codec.read_cfg(S.Certificate, gpa, reader, cfg);
            return .{ .item = item, .certificate = assembled };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            const item = try Item(D).arbitrary(gpa, u);
            const value = try codec.arbitrary.value(S.Certificate, gpa, u);
            return .{ .item = item, .certificate = value };
        }
    };
}

/// What the engine reports and journals: an ack it received or signed, a certificate it
/// recovered, or a new tip. Encoded as a `u8` tag (0, 1, 2), then the variant.
pub fn Activity(comptime S: type, comptime D: type) type {
    return union(enum(u8)) {
        const Self = @This();
        pub const Cfg = codec.Cfg(S.Certificate);
        const context = "consensus::aggregation::Activity";

        ack: Ack(S, D),
        certified: Certificate(S, D),
        tip: Height,

        /// The height the activity is about.
        pub fn height(self: Self) Height {
            return switch (self) {
                .ack => |ack| ack.item.height,
                .certified => |value| value.item.height,
                .tip => |tip| tip,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            return switch (a) {
                .ack => |ack| ack.eql(b.ack),
                .certified => |value| value.eql(b.certified),
                .tip => |tip| tip == b.tip,
            };
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return switch (self.*) {
                .certified => |*value| .{ .certified = try value.clone(gpa) },
                else => self.*,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .certified => |*value| value.deinit(gpa),
                .ack, .tip => {},
            }
            self.* = undefined;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_byte(@backingInt(std.meta.activeTag(self)));
            switch (self) {
                .ack => |ack| ack.write(writer),
                .certified => |value| value.write(writer),
                .tip => |tip| tip.write(writer),
            }
        }

        pub fn encode_size(self: Self) usize {
            return 1 + switch (self) {
                .ack => |ack| ack.encode_size(),
                .certified => |value| value.encode_size(),
                .tip => |tip| tip.encode_size(),
            };
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            return switch (try reader.read_byte()) {
                0 => .{ .ack = try Ack(S, D).read(gpa, reader, {}) },
                1 => .{ .certified = try Certificate(S, D).read(gpa, reader, cfg) },
                2 => .{ .tip = try Height.read(gpa, reader, {}) },
                else => reader.invalid(context, "Invalid type"),
            };
        }

        pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Self {
            return switch (u.int_in_range(u32, 0, 2)) {
                0 => .{ .ack = try Ack(S, D).arbitrary(gpa, u) },
                1 => .{ .certified = try Certificate(S, D).arbitrary(gpa, u) },
                2 => .{ .tip = try Height.arbitrary(gpa, u) },
                else => unreachable, // Proof: int_in_range returns a value in [0, 2].
            };
        }
    };
}

test {
    _ = @import("types_test.zig");
}
