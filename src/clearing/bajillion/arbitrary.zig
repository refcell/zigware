//! `arbitrary` 1.4 values for the protocol types (commonware's `arbitrary` feature).
//!
//! The conformance hashes and fuzz targets build values the way commonware's `Arbitrary`
//! impls do. `value(T, ...)` reproduces them for the account, signature, and digest types the
//! crate's tests use (ed25519 keys and signatures, SHA-256 digests), for the protocol types
//! (each declares `arbitrary(gpa, u)`), and for codec's primitives, recursing through
//! optionals, tuples, arrays, and slices so that a `Vec<(P, A)>` draws its keys here as well.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const utils = @import("utils");

const arbitrary = codec.arbitrary;
pub const Unstructured = arbitrary.Unstructured;
pub const Error = arbitrary.Error;
const ed25519 = cryptography.ed25519;

/// A value of `T` drawn as commonware's `T::arbitrary` draws it.
pub fn value(comptime T: type, gpa: Allocator, u: *Unstructured) Error!T {
    if (T == ed25519.PrivateKey) return private_key(u);
    if (T == ed25519.PublicKey) return (try private_key(u)).public_key();
    if (T == ed25519.Signature) return signature(gpa, u);
    switch (@typeInfo(T)) {
        .optional => |info| return if (u.boolean()) try value(info.child, gpa, u) else null,
        .array => |info| {
            var result: T = undefined;
            for (&result) |*item| item.* = try value(info.child, gpa, u);
            return result;
        },
        .pointer => |info| {
            comptime assert(info.size == .slice);
            return collect(info.child, gpa, u);
        },
        .@"struct" => |info| {
            if (info.is_tuple) {
                var result: T = undefined;
                inline for (info.field_types, 0..) |field_type, index| {
                    result[index] = try value(field_type, gpa, u);
                }
                return result;
            }
            if (comptime @hasDecl(T, "arbitrary")) return T.arbitrary(gpa, u);
            if (comptime @hasDecl(T, "label")) return digest(T, u);
            return arbitrary.value(T, gpa, u);
        },
        else => return arbitrary.value(T, gpa, u),
    }
}

/// `arbitrary_iter().collect()`: a continuation bit before each element.
pub fn collect(comptime T: type, gpa: Allocator, u: *Unstructured) Error![]T {
    var list: std.ArrayList(T) = .empty;
    // Each continuation consumes a byte until the data runs out, then reads zero: bounded.
    while (u.keep_going()) try list.append(gpa, try value(T, gpa, u));
    return list.toOwnedSlice(gpa);
}

/// `PrivateKey::random(StdRng::from_seed(u.arbitrary::<[u8; 32]>()))`.
fn private_key(u: *Unstructured) Error!ed25519.PrivateKey {
    var seed: [32]u8 = undefined;
    u.fill(&seed);
    var rng = utils.rng.TestRng.init_key(seed);
    return ed25519.PrivateKey.random(&rng);
}

/// A random key signs up to 255 arbitrary bytes under the empty namespace.
fn signature(gpa: Allocator, u: *Unstructured) Error!ed25519.Signature {
    const key = try private_key(u);
    const len = try arbitrary.value(usize, gpa, u) % 256;
    // `arbitrary_iter().take(len)`: a continuation byte before each element, none after.
    var message: [255]u8 = undefined;
    var count: usize = 0;
    while (count < len and u.keep_going()) : (count += 1) message[count] = u.int(u8);
    assert(count <= len);
    return key.sign("", message[0..count]);
}

/// The digest impls: `int_in_range(0..=256)` bytes of data, then their SHA-256 hash.
fn digest(comptime D: type, u: *Unstructured) Error!D {
    comptime assert(std.mem.eql(u8, D.label, "sha256"));
    const len = u.int_in_range(u64, 0, 256);
    var data: [256]u8 = undefined;
    try u.bytes(data[0..len]);
    return cryptography.Sha256.hash(&.{data[0..len]});
}

/// A stable sort of `items` by `key_order`, keeping the first of each run of equal keys
/// (Rust's `sort_by` then `dedup_by`). Returns the kept prefix.
pub fn sort_dedup(
    comptime T: type,
    items: []T,
    comptime key_order: fn (*const T, *const T) std.math.Order,
) []T {
    const Context = struct {
        fn less(_: void, a: T, b: T) bool {
            return key_order(&a, &b) == .lt;
        }
    };
    std.sort.insertion(T, items, {}, Context.less);
    var kept: usize = 0;
    for (items) |item| {
        if (kept > 0 and key_order(&items[kept - 1], &item) == .eq) continue;
        items[kept] = item;
        kept += 1;
    }
    assert(kept <= items.len);
    return items[0..kept];
}
