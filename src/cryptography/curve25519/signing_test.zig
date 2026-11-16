//! commonware-cryptography-curve25519's `signing.rs` and `signing/core.rs` tests that check
//! observable behavior (the rest test the crate's private batch phases and MSM backends).

const std = @import("std");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const signing = @import("signing.zig");
const core = cryptography.ed25519.core;
const testing = std.testing;
const gpa = testing.allocator;
const SigningKey = signing.SigningKey;
const VerifyingKey = signing.VerifyingKey;
const Signature = signing.Signature;
const Point = core.Point;

fn verify_entries(entries: []const VerifyingKey.Entry, strategy: anytype) bool {
    var rng = utils.test_rng();
    return VerifyingKey.verify_batch(&rng, entries, cryptography.entries, strategy);
}

test "curve25519 signing: batch entries use union_unique framing" {
    // An empty namespace and message, and a 200-byte namespace with a two-byte length prefix.
    const signer = SigningKey.from_seed(@splat(3));
    const key = signer.verifying_key();
    const long_namespace: [200]u8 = @splat(7);
    const pairs = [_][2][]const u8{ .{ "", "" }, .{ "ns", "message" }, .{ &long_namespace, "m" } };
    var signatures: [pairs.len]Signature = undefined;
    var entries: [pairs.len]VerifyingKey.Entry = undefined;
    for (pairs, &signatures, &entries) |pair, *signature, *entry| {
        signature.* = signer.sign(pair[0], pair[1]);
        entry.* = .{
            .namespace = pair[0],
            .message = pair[1],
            .public_key = &key,
            .signature = signature,
        };
    }
    try testing.expect(verify_entries(&entries, parallel.sequential));

    // Moving bytes from the message into the namespace changes the framed message.
    var moved = entries[1];
    moved.namespace = "nsm";
    moved.message = "essage";
    try testing.expect(!verify_entries(&.{moved}, parallel.sequential));
}

test "curve25519 signing: verifying key identity follows encoding" {
    var rng = utils.test_rng();
    const key = SigningKey.random(&rng).verifying_key();
    const decoded = VerifyingKey.from_bytes(key.bytes);
    try testing.expect(key.eql(decoded));
    try testing.expectEqual(std.math.Order.eq, key.order(decoded));

    // `y = 1` and the non-canonical `y = p + 1` both encode the identity.
    var canonical: [32]u8 = @splat(0);
    canonical[0] = 1;
    var noncanonical: [32]u8 = @splat(0xff);
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    const a = core.decompress(canonical).?;
    const b = core.decompress(noncanonical).?;
    try testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());
    const first = VerifyingKey.from_bytes(canonical);
    const second = VerifyingKey.from_bytes(noncanonical);
    try testing.expect(!first.eql(second));
    try testing.expect(first.order(second) != .eq);
}

test "curve25519 signing: empty and oversized batches are invalid" {
    try testing.expect(!verify_entries(&.{}, parallel.sequential));

    // A slice longer than the batch limit is rejected before any item is projected.
    const Panics = struct {
        pub fn project(_: @This(), _: usize, _: *const void) VerifyingKey.Entry {
            unreachable; // The length check rejects the batch first.
        }
    };
    const none: []const void = &.{};
    var oversized = none;
    oversized.len = @as(usize, std.math.maxInt(u32)) + 1;
    var rng = utils.test_rng();
    try testing.expect(!VerifyingKey.verify_batch(&rng, oversized, Panics{}, parallel.sequential));
}

test "curve25519 signing: signature is bound to namespace" {
    const namespace = "_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST";
    const wrong_namespace = "_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST_WRONG";
    const signing_key = SigningKey.from_seed(@splat(42));
    const verifying_key = signing_key.verifying_key();
    const signature = signing_key.sign(namespace, "message");
    try testing.expect(verifying_key.verify(namespace, "message", &signature));
    try testing.expect(!verifying_key.verify(wrong_namespace, "message", &signature));
}

test "curve25519 signing: sign and verify" {
    const signing_key = SigningKey.from_seed(@splat(5));
    const verifying_key = signing_key.verifying_key();
    const signature = signing_key.sign("namespace", "message");
    try testing.expect(signature.eql(signing_key.sign("namespace", "message")));
    try testing.expect(verifying_key.verify("namespace", "message", &signature));
    try testing.expect(!verifying_key.verify("other", "message", &signature));
}

/// The smallest `y` whose encoding is not a curve point (commonware's `undecodable`).
fn undecodable() [32]u8 {
    var encoding: [32]u8 = @splat(0);
    for (2..256) |y| {
        encoding[0] = @intCast(y);
        if (core.decompress(encoding) == null) return encoding;
    }
    unreachable; // Half of all y values are not on the curve.
}

/// A raw batch: keys, signatures, and 32-byte messages.
const Batch = struct {
    const capacity = 1100;
    keys: [capacity]VerifyingKey = undefined,
    signatures: [capacity]Signature = undefined,
    messages: [capacity][32]u8 = undefined,
    count: usize = 0,

    /// commonware's `mixed_batch_with_repeats`: every third signature reuses one signer.
    fn mixed(batch: *Batch, seed: u64, count: usize) void {
        std.debug.assert(count <= capacity);
        var rng = utils.TestRng.init(seed);
        const repeated = SigningKey.random(&rng);
        batch.count = count;
        for (0..count) |i| {
            rng.fill_bytes(&batch.messages[i]);
            const signer = if (i % 3 == 0) repeated else SigningKey.random(&rng);
            batch.keys[i] = signer.verifying_key();
            batch.signatures[i] = signer.sign_raw(&batch.messages[i]);
        }
    }

    fn verify(batch: *const Batch, strategy: anytype) bool {
        var entries: [capacity]VerifyingKey.RawEntry = undefined;
        for (0..batch.count) |i| {
            entries[i] = .{
                .key = &batch.keys[i],
                .signature = &batch.signatures[i],
                .message = &batch.messages[i],
            };
        }
        var rng = utils.test_rng();
        return VerifyingKey.verify_batch_raw(&rng, entries[0..batch.count], strategy);
    }

    /// Verifies under every strategy shape when `explored`, else sequentially.
    fn check(batch: *const Batch, explored: bool) !bool {
        if (explored) return batch.verify_explored();
        return batch.verify(parallel.sequential);
    }

    /// Verifies under every strategy shape, which must agree.
    fn verify_explored(batch: *const Batch) !bool {
        const Op = struct {
            batch: *const Batch,
            pub fn run(op: @This(), explorer: parallel.mocks.Explorer) bool {
                return op.batch.verify(explorer);
            }
        };
        const verdict = try parallel.mocks.explore(gpa, testing.io, Op{ .batch = batch });
        try testing.expectEqual(verdict, batch.verify(parallel.sequential));
        return verdict;
    }
};

test "curve25519 signing: batch rejects an invalid signature at any position" {
    const invalid = undecodable();
    const batch = try gpa.create(Batch);
    defer gpa.destroy(batch);
    batch.mixed(0, 70);
    try testing.expect(try batch.verify_explored());
    const altered = try gpa.create(Batch);
    defer gpa.destroy(altered);
    for ([_]usize{ 0, 1, 7, 8, 15, 16, 23, 24, 39, 40, 63, 64, 69 }) |position| {
        for (0..4) |corruption| {
            altered.* = batch.*;
            switch (corruption) {
                0 => altered.signatures[position].bytes[0..32].* = invalid,
                1 => altered.keys[position] = VerifyingKey.from_bytes(invalid),
                2 => altered.signatures[position].bytes[63] |= 0x80,
                else => altered.messages[position][0] ^= 1,
            }
            // Every strategy shape at the unit boundaries; the rest sequentially, for speed.
            const explored = position % 8 == 0;
            testing.expect(!try altered.check(explored)) catch |err| {
                std.debug.print("position {d}, corruption {d}\n", .{ position, corruption });
                return err;
            };
        }
    }
}

/// A raw signature `(R, s)` over `message` by the key encoded as `key`.
fn forged(batch: *Batch, index: usize, r: [32]u8, key: [32]u8, s: [32]u8) void {
    batch.messages[index] = @splat(0xd0);
    batch.keys[index] = VerifyingKey.from_bytes(key);
    batch.signatures[index] = .{ .bytes = r ++ s };
}

/// commonware's `decode_only_forgeries`: signatures whose equation holds when an undecodable
/// point counts as the identity, each with a control that uses the identity's encoding instead.
/// Writes forgery `which` (or its control) at `index`.
fn decode_only(batch: *Batch, index: usize, which: usize, control: bool) void {
    const invalid = undecodable();
    var identity: [32]u8 = @splat(0);
    identity[0] = 1;
    const basepoint = Point.basePoint.toBytes();
    const message: [32]u8 = @splat(0xd0);
    if (which == 0) {
        // With `A = B` and `s = h`, `s*B = R + h*A` holds for `R` the identity.
        const r = if (control) identity else invalid;
        forged(batch, index, r, basepoint, core.challenge(&r, &basepoint, null, &message));
    } else {
        // With `R = k*B` and `s = k`, the equation holds for `A` the identity.
        var k: [32]u8 = @splat(0);
        std.mem.writeInt(u128, k[0..16], 0x1234_5678_9abc_def0, .little);
        const r = (Point.basePoint.mulPublic(k) catch unreachable).toBytes(); // k*B != 0.
        forged(batch, index, r, if (control) identity else invalid, k);
    }
}

fn verify_first(batch: *const Batch) bool {
    return batch.keys[0].verify_raw(&batch.messages[0], &batch.signatures[0]);
}

test "curve25519 signing: batch rejects undecodable points alone" {
    const batch = try gpa.create(Batch);
    defer gpa.destroy(batch);
    const altered = try gpa.create(Batch);
    defer gpa.destroy(altered);
    batch.mixed(1, 70);
    for (0..2) |which| {
        // In place of one signature of a valid batch, the control keeps the batch valid, so the
        // forgery can fail only on its undecodable point.
        for ([_]usize{ 0, 7, 8, 15, 16, 39, 69 }) |position| {
            const explored = position % 8 == 0;
            altered.* = batch.*;
            decode_only(altered, position, which, true);
            try testing.expect(try altered.check(explored));
            decode_only(altered, position, which, false);
            try testing.expect(!try altered.check(explored));
        }
        altered.count = 1;
        decode_only(altered, 0, which, true);
        try testing.expect(try altered.verify_explored());
        try testing.expect(verify_first(altered));
        decode_only(altered, 0, which, false);
        try testing.expect(!try altered.verify_explored());
        try testing.expect(!verify_first(altered));
    }
}

test "curve25519 signing: batch coalesces repeated signers" {
    const batch = try gpa.create(Batch);
    defer gpa.destroy(batch);
    var signers: [3]SigningKey = undefined;
    for (&signers, 1..) |*signer, i| signer.* = SigningKey.from_seed(@splat(@intCast(i)));
    for ([_][2]usize{ .{ 520, 1 }, .{ 1100, 1 }, .{ 300, 3 } }) |shape| {
        const count, const distinct = shape;
        batch.count = count;
        for (0..count) |i| {
            const signer = &signers[i % distinct];
            batch.messages[i] = @splat(0);
            std.mem.writeInt(u64, batch.messages[i][0..8], i, .little);
            batch.keys[i] = signer.verifying_key();
            batch.signatures[i] = signer.sign_raw(&batch.messages[i]);
        }
        // Every strategy shape for the smallest batch; the large ones sequentially, for speed.
        const explored = count == 300;
        try testing.expect(try batch.check(explored));
        batch.messages[count / 2][0] ^= 1;
        try testing.expect(!try batch.check(explored));
    }
}
