//! A participant's attestation (commonware `cryptography::certificate::Attestation`).
//!
//! Stand-in until the crypto lane ports `certificate.rs`: same wire format, the signer as a
//! `u32` varint then the scheme's fixed-size signature. Switch to
//! `cryptography.certificate.Attestation` once it lands.
//!
//! Commonware holds the signature as `Lazy<Signature>`, decoded on first use so a vote can be
//! relayed and stored without paying for point decompression. `Deferred(T)` keeps that
//! behavior but owns its bytes inline instead of borrowing the input buffer, so a decoded vote
//! outlives the network message it came from.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");

const Participant = utils.Participant;

/// A fixed-size value kept as its encoding and decoded on demand (commonware `Lazy<T>` for
/// fixed-size `T`). Decoding never allocates.
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

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return init(try codec.arbitrary.value(T, gpa, u));
        }
    };
}

/// A participant's signature over a subject: `signer` indexes the participant set.
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

        /// commonware: `Participant::arbitrary` then `S::Signature::arbitrary`.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const signer = Participant.init(u.int(u32));
            return .{ .signer = signer, .signature = try .arbitrary(gpa, u) };
        }
    };
}

const testing = std.testing;

const Byte = struct {
    value: u8,
    pub const fixed_size: usize = 1;
    pub fn write(self: Byte, writer: *codec.Writer) void {
        writer.write_byte(self.value);
    }
    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Byte {
        const value = try reader.read_byte();
        if (value > 100) return reader.invalid("Byte", "above 100");
        return .{ .value = value };
    }
};

test "deferred decodes on demand and keeps invalid bytes" {
    const D = Deferred(Byte);
    const valid = D.init(.{ .value = 7 });
    try testing.expectEqual(7, valid.get().?.value);
    const invalid = try codec.decode(D, testing.allocator, &.{200});
    try testing.expectEqual(null, invalid.get());
    // Re-encoding an undecodable value reproduces its bytes.
    const encoded = try codec.encode(D, testing.allocator, invalid);
    defer testing.allocator.free(encoded);
    try testing.expectEqualSlices(u8, &.{200}, encoded);
    try testing.expect(!valid.eql(invalid) and valid.eql(.init(.{ .value = 7 })));
}

test "attestation codec" {
    const S = struct {
        pub const Signature = Byte;
    };
    const A = Attestation(S);
    const attestation = A.init(.init(300), .{ .value = 9 });
    const encoded = try codec.encode(A, testing.allocator, attestation);
    defer testing.allocator.free(encoded);
    // 300 as a varint is two bytes, then the signature byte.
    try testing.expectEqualSlices(u8, &.{ 0xac, 0x02, 9 }, encoded);
    const decoded = try codec.decode(A, testing.allocator, encoded);
    try testing.expect(decoded.eql(attestation));
    try testing.expectError(error.EndOfBuffer, codec.decode(A, testing.allocator, &.{0xac}));
}
