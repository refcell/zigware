//! Helpers shared by the unit tests (commonware `bajillion/tests.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const mod = @import("mod.zig");

pub const Sha256 = cryptography.Sha256;
pub const Digest = Sha256.Digest;
pub const PrivateKey = cryptography.ed25519.PrivateKey;
pub const PublicKey = cryptography.ed25519.PublicKey;
pub const Signature = cryptography.ed25519.Signature;
pub const TestAmounts = mod.Amounts(PublicKey, u64);

/// Namespace of the deployment under test.
pub const namespace_bytes = "_COMMONWARE_CLEARING_BAJILLION_TEST";

/// Returns the signature namespaces of the deployment under test.
pub fn namespace(gpa: Allocator) !mod.Namespace {
    return mod.Namespace.init(gpa, namespace_bytes);
}

/// Returns the signing key of user `index`.
pub fn user(index: u64) PrivateKey {
    return PrivateKey.from_seed(index);
}

/// Returns the account of user `index`.
pub fn account(index: u64) PublicKey {
    return user(index).public_key();
}

/// Returns the operator's signing key.
pub fn operator_key() PrivateKey {
    return PrivateKey.from_seed(1_000);
}

fn key_less(_: void, a: PrivateKey, b: PrivateKey) bool {
    return a.public_key().order(b.public_key()) == .lt;
}

/// Returns the signing keys of users `0..count`, in increasing order of their accounts.
pub fn users(comptime count: usize) [count]PrivateKey {
    var result: [count]PrivateKey = undefined;
    for (&result, 0..) |*key, index| key.* = user(index);
    std.mem.sort(PrivateKey, &result, {}, key_less);
    return result;
}

/// Returns the accounts of users `0..count` in increasing order.
pub fn accounts(comptime count: usize) [count]PublicKey {
    var result: [count]PublicKey = undefined;
    for (users(count), &result) |key, *public_key| public_key.* = key.public_key();
    for (result[0..count -| 1], result[@min(1, count)..]) |a, b| assert(a.order(b) == .lt);
    return result;
}

/// Returns amounts paying user `index` its `amount` for each `{ index, amount }`.
pub fn amounts(gpa: Allocator, entries: []const [2]u64) !TestAmounts {
    var list: std.ArrayList(TestAmounts.Entry) = .empty;
    defer list.deinit(gpa);
    for (entries) |entry| try list.append(gpa, .{ account(entry[0]), entry[1] });
    return TestAmounts.init(gpa, list.items);
}

/// Returns the root of the empty payment map.
pub fn empty_root() Digest {
    return TestAmounts.empty.root(Sha256);
}
