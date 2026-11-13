//! Aggregation of BLS12-381 public keys and signatures (commonware `ops::aggregate`).
//!
//! An aggregate verifies when the sum is valid, not when each element is: use `batch` to
//! check every signature. Aggregating signatures from several public keys over one message
//! also requires a verified proof of possession for every public key (rogue-key attacks).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const math = @import("math");
const ops = @import("../ops.zig");
const variant = @import("../variant.zig");

const Allocator = std.mem.Allocator;
const Error = variant.Error;

const Kind = enum { public_key, signature, message };

/// A group element in a newtype that keeps aggregates apart from single values (and the
/// three kinds apart from each other). It encodes as the element.
fn Wrapper(comptime Element: type, comptime kind: Kind) type {
    return struct {
        const Self = @This();
        pub const aggregate_kind = kind;
        value: Element,

        pub const fixed_size: usize = Element.fixed_size;
        pub const zero: Self = .{ .value = Element.zero };

        pub fn add(self: *Self, other: Element) void {
            self.value = self.value.add(other);
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.value.eql(b.value);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.value.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{ .value = try Element.read(gpa, reader, {}) };
        }

        pub fn arbitrary(u: *math.fuzz.Unstructured) Self {
            return .{ .value = Element.arbitrary(u) };
        }
    };
}

/// An aggregate of public keys (`aggregate::PublicKey<V>`). Before `verify_same_message`,
/// every included key must be group-checked, unique, and have a verified proof of
/// possession; decoding an aggregate does not check these.
pub fn PublicKey(comptime V: type) type {
    return Wrapper(V.Public, .public_key);
}

/// An aggregate of signatures (`aggregate::Signature<V>`).
pub fn Signature(comptime V: type) type {
    return Wrapper(V.Signature, .signature);
}

/// A sum of hashed messages (`aggregate::Message<V>`).
pub fn Message(comptime V: type) type {
    return Wrapper(V.Signature, .message);
}

/// A namespaced message for `combine_messages`.
pub const NamespacedMessage = struct { namespace: []const u8, message: []const u8 };

/// Sums public keys. Every key must be group-checked, unique, and have a verified proof of
/// possession.
pub fn combine_public_keys(comptime V: type, public_keys: []const V.Public) PublicKey(V) {
    assert(public_keys.len > 0);
    var sum: PublicKey(V) = .zero;
    for (public_keys) |public_key| sum.add(public_key);
    return sum;
}

/// Sums signatures. Every signature must be group-checked and unique.
pub fn combine_signatures(comptime V: type, signatures: []const V.Signature) Signature(V) {
    assert(signatures.len > 0);
    var sum: Signature(V) = .zero;
    for (signatures) |signature| sum.add(signature);
    return sum;
}

/// Sums the hashes of namespaced messages. Messages must not repeat.
pub fn combine_messages(comptime V: type, messages: []const NamespacedMessage) Message(V) {
    assert(messages.len > 0);
    var sum: Message(V) = .zero;
    for (messages) |item| {
        sum.add(ops.hash_with_namespace(V, V.message, item.namespace, item.message));
    }
    return sum;
}

/// Verifies an aggregate signature over one message from the keys summed in `public`.
pub fn verify_same_message(
    comptime V: type,
    public: PublicKey(V),
    namespace: []const u8,
    message: []const u8,
    signature: Signature(V),
) Error!void {
    const hm = ops.hash_with_namespace(V, V.message, namespace, message);
    return V.verify(public.value, hm, signature.value);
}

/// Verifies an aggregate signature over the messages summed in `message` from one key.
pub fn verify_same_signer(
    comptime V: type,
    public: V.Public,
    message: Message(V),
    signature: Signature(V),
) Error!void {
    return V.verify(public, message.value, signature.value);
}
