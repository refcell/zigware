//! The crate's fuzz plans (`src/fuzz.rs`, `src/test.rs` module `fuzz`, and the curve plan),
//! checked against the independent `reference.zig` where commonware uses ed25519-consensus and
//! x25519-dalek.
//!
//! - `batch_matches_individual`: a batch verifies exactly when it is nonempty and every item
//!   verifies alone, under every strategy shape.
//! - `signing_matches_reference`, `verification_matches_reference`,
//!   `key_exchange_matches_reference`: the public API agrees with the reference.
//! - `curve`: std.crypto's Edwards25519 (which zigware uses in place of the crate's own field
//!   and group backends) agrees with the reference on ZIP-215 decoding and scalar multiples.

const std = @import("std");
const assert = std.debug.assert;
const cryptography = @import("cryptography");
const codec = @import("codec");
const parallel = @import("parallel");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const formatting = @import("formatting");
const signing = @import("signing.zig");
const key_exchange = @import("key_exchange.zig");
const reference = @import("reference.zig");
const core = cryptography.ed25519.core;
const Unstructured = minifuzz.Unstructured;
const Error = minifuzz.Error;
const VerifyingKey = signing.VerifyingKey;
const Signature = signing.Signature;
const SigningKey = signing.SigningKey;
const hex = formatting.hex_literal;

pub const Plan = enum {
    curve,
    batch_matches_individual,
    signing_matches_reference,
    verification_matches_reference,
    key_exchange_matches_reference,

    /// Runs the plan on the rest of `u`. `context` supplies the allocator and `std.Io` for the
    /// strategy explorer.
    pub fn run(plan: Plan, context: Context, u: *Unstructured) !void {
        switch (plan) {
            .curve => try run_curve(u),
            .batch_matches_individual => {
                const batch = try context.gpa.create(Batch);
                defer context.gpa.destroy(batch);
                try batch.arbitrary(context, u);
                try batch.run(context);
            },
            .signing_matches_reference => try run_signing(u),
            .verification_matches_reference => {
                var item: Item = undefined;
                try item.arbitrary(u);
                _ = try item.verify();
            },
            .key_exchange_matches_reference => try run_key_exchange(u),
        }
    }
};

pub const Context = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// The largest batch drawn: commonware uses 17 in unit tests and 64 when fuzzing.
    max_batch_size: usize = 17,
    /// How many of the interesting batch sizes to draw from (12 in tests, 17 when fuzzing).
    interesting_batch_sizes: usize = 12,
};

const scalar_order: [32]u8 =
    hex("0xedd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
const zeros: [31]u8 = @splat(0);
const one_bytes: [32]u8 = .{1} ++ zeros;
const two_bytes: [32]u8 = .{2} ++ zeros;
const basepoint_u: [32]u8 = .{9} ++ zeros;

const interesting_secret_bytes = table: {
    @setEvalBranchQuota(20_000);
    break :table [_][32]u8{
        @splat(0),
        @splat(0xff),
        hex("0x0100000000000000000000000000000000000000000000000000000000000000"),
        hex("0x0000000000000000000000000000000000000000000000000000000000000080"),
    };
};

const interesting_x25519_public_keys = table: {
    @setEvalBranchQuota(20_000);
    break :table [_][32]u8{
        @splat(0),
        hex("0x0100000000000000000000000000000000000000000000000000000000000000"),
        hex("0xe0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex("0x5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hex("0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("0xedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("0x0900000000000000000000000000000000000000000000000000000000000000"),
        hex("0x0900000000000000000000000000000000000000000000000000000000000080"),
        @splat(0xff),
    };
};

const low_order_encodings = table: {
    @setEvalBranchQuota(20_000);
    break :table [_][32]u8{
        hex("0x0100000000000000000000000000000000000000000000000000000000000000"),
        hex("0x0100000000000000000000000000000000000000000000000000000000000080"),
        hex("0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex("0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    };
};

const interesting_lengths = [_]usize{
    0, 1, 31, 32, 47, 48, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 256,
};
const interesting_batch_sizes = [_]usize{
    0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64,
};
const max_batch_capacity = 64;
const max_bytes = 256;

fn arbitrary_length(u: *Unstructured) Error!usize {
    if (u.ratio(u8, 3, 4)) return u.choose(usize, &interesting_lengths);
    return u.int_in_range(usize, 0, max_bytes);
}

/// A byte string of up to `max_bytes` (plus one for a mutation's appended byte).
const Bytes = struct {
    buffer: [max_bytes + 1]u8,
    len: usize,

    fn slice(bytes: *const Bytes) []const u8 {
        return bytes.buffer[0..bytes.len];
    }

    fn arbitrary(bytes: *Bytes, u: *Unstructured) Error!void {
        const len = try arbitrary_length(u);
        assert(len <= max_bytes);
        bytes.len = len;
        switch (u.int_in_range(u8, 0, 3)) {
            0 => @memset(bytes.buffer[0..len], 0),
            1 => @memset(bytes.buffer[0..len], try u.arbitrary(u8)),
            2 => for (bytes.buffer[0..len], 0..) |*byte, i| {
                byte.* = @truncate(i);
            },
            else => @memcpy(bytes.buffer[0..len], try u.bytes(len)),
        }
    }

    /// commonware's `mutate_bytes`: append a byte, or flip one bit.
    fn mutate(bytes: *Bytes, u: *Unstructured) Error!void {
        if (bytes.len == 0 or u.ratio(u8, 1, 4)) {
            if (bytes.len == bytes.buffer.len) {
                bytes.buffer[0] ^= 1;
                return;
            }
            bytes.buffer[bytes.len] = try u.arbitrary(u8);
            bytes.len += 1;
        } else {
            const index = u.int_in_range(usize, 0, bytes.len - 1);
            const bit = u.int_in_range(u8, 0, 7);
            bytes.buffer[index] ^= @as(u8, 1) << @intCast(bit);
        }
    }
};

fn secret_bytes(u: *Unstructured) Error![32]u8 {
    if (u.ratio(u8, 1, 4)) return u.choose([32]u8, &interesting_secret_bytes);
    return u.arbitrary([32]u8);
}

fn x25519_public_key(u: *Unstructured) Error![32]u8 {
    if (u.ratio(u8, 3, 4)) return u.choose([32]u8, &interesting_x25519_public_keys);
    return u.arbitrary([32]u8);
}

fn encoded_point(u: *Unstructured) Error![32]u8 {
    return switch (u.int_in_range(u8, 0, 9)) {
        0...3 => u.choose([32]u8, &low_order_encodings),
        4 => two_bytes,
        5 => @splat(0),
        6 => @splat(0xff),
        7 => SigningKey.from_seed(try secret_bytes(u)).verifying_key().bytes,
        else => u.arbitrary([32]u8),
    };
}

fn encoded_scalar(u: *Unstructured) Error![32]u8 {
    var bytes = scalar_order;
    switch (u.int_in_range(u8, 0, 7)) {
        0 => bytes = @splat(0),
        1 => bytes = one_bytes,
        2 => bytes[0] -= 1,
        3 => {},
        4 => bytes[0] += 1,
        5 => bytes = @splat(0xff),
        else => bytes = try u.arbitrary([32]u8),
    }
    return bytes;
}

/// The namespaced payload `union_unique(namespace, message)` into `buffer`.
fn frame(buffer: []u8, namespace: []const u8, message: []const u8) []const u8 {
    var writer = codec.Writer.init(buffer);
    codec.varint.write(u32, @intCast(namespace.len), &writer);
    writer.write_bytes(namespace);
    writer.write_bytes(message);
    return writer.written();
}

const frame_capacity = 5 + 2 * (max_bytes + 1);

fn run_signing(u: *Unstructured) !void {
    const seed = try secret_bytes(u);
    var namespace: Bytes = undefined;
    var message: Bytes = undefined;
    try namespace.arbitrary(u);
    try message.arbitrary(u);
    const signing_key = SigningKey.from_seed(seed);
    const expected_key = reference.public_key(seed);
    try std.testing.expectEqualSlices(u8, &expected_key, &signing_key.verifying_key().bytes);
    var buffer: [frame_capacity]u8 = undefined;
    const payload = frame(&buffer, namespace.slice(), message.slice());
    const signature = signing_key.sign(namespace.slice(), message.slice());
    try std.testing.expectEqualSlices(u8, &reference.sign(seed, payload), &signature.bytes);
}

fn run_key_exchange(u: *Unstructured) !void {
    const secret = try secret_bytes(u);
    const public_bytes = try x25519_public_key(u);
    var rng = utils.FuzzRng.init(&secret);
    const secret_key = key_exchange.SecretKey.random(&rng);
    const expected_public = reference.x25519(secret_key.bytes, basepoint_u);
    try std.testing.expectEqualSlices(u8, &expected_public, &secret_key.public_key().bytes);
    const shared = secret_key.exchange(.{ .bytes = public_bytes });
    const expected = reference.x25519(secret_key.bytes, public_bytes);
    const zero = std.mem.allEqual(u8, &expected, 0);
    try std.testing.expectEqual(zero, shared == null);
    if (shared) |value| try std.testing.expectEqualSlices(u8, &expected, &value.bytes);
}

const Item = struct {
    namespace: Bytes,
    message: Bytes,
    key: VerifyingKey,
    signature: Signature,

    fn payload(item: *Item, u: *Unstructured) Error!void {
        try item.namespace.arbitrary(u);
        try item.message.arbitrary(u);
    }

    fn signed(item: *Item, u: *Unstructured, seed: ?[32]u8) Error!void {
        try item.payload(u);
        const signing_key = SigningKey.from_seed(seed orelse try secret_bytes(u));
        item.key = signing_key.verifying_key();
        item.signature = signing_key.sign(item.namespace.slice(), item.message.slice());
    }

    fn low_order(item: *Item, u: *Unstructured) Error!void {
        try item.payload(u);
        item.key = VerifyingKey.from_bytes(try u.choose([32]u8, &low_order_encodings));
        const r = try u.choose([32]u8, &low_order_encodings);
        item.signature = .{ .bytes = r ++ @as([32]u8, @splat(0)) };
    }

    fn valid(item: *Item, u: *Unstructured, seed: ?[32]u8) Error!void {
        if (seed == null and u.ratio(u8, 1, 8)) return item.low_order(u);
        return item.signed(u, seed);
    }

    fn raw(item: *Item, u: *Unstructured) Error!void {
        try item.payload(u);
        item.key = VerifyingKey.from_bytes(try encoded_point(u));
        const r = try encoded_point(u);
        item.signature = .{ .bytes = r ++ try encoded_scalar(u) };
    }

    /// Changes one part of the item, then makes `s` non-canonical if it still verifies.
    fn invalidate(item: *Item, u: *Unstructured) !void {
        switch (u.int_in_range(u8, 0, 5)) {
            0 => try item.namespace.mutate(u),
            1 => try item.message.mutate(u),
            2 => item.key = VerifyingKey.from_bytes(try encoded_point(u)),
            3 => item.signature.bytes[0..32].* = try encoded_point(u),
            4 => item.signature.bytes[32..64].* = try encoded_scalar(u),
            else => item.signature.bytes[32..64].* = scalar_order,
        }
        if (try item.verify()) item.signature.bytes[32..64].* = scalar_order;
    }

    fn arbitrary(item: *Item, u: *Unstructured) !void {
        switch (u.int_in_range(u8, 0, 9)) {
            0...3 => try item.signed(u, null),
            4 => try item.low_order(u),
            5...7 => {
                try item.signed(u, null);
                try item.invalidate(u);
            },
            else => try item.raw(u),
        }
    }

    /// Verifies the item through the API, a freshly decoded key, and the reference, which
    /// must all agree.
    fn verify(item: *const Item) !bool {
        const namespace = item.namespace.slice();
        const message = item.message.slice();
        const actual = item.key.verify(namespace, message, &item.signature);
        const decoded = VerifyingKey.from_bytes(item.key.bytes);
        try std.testing.expectEqual(actual, decoded.verify(namespace, message, &item.signature));
        var buffer: [frame_capacity]u8 = undefined;
        const payload_bytes = frame(&buffer, namespace, message);
        const expected = reference.verify(item.key.bytes, item.signature.bytes, payload_bytes);
        try std.testing.expectEqual(expected, actual);
        return actual;
    }
};

const Batch = struct {
    rng_seed: [32]u8,
    items: [max_batch_capacity]Item,
    len: usize,

    fn arbitrary(batch: *Batch, context: Context, u: *Unstructured) !void {
        assert(context.max_batch_size <= max_batch_capacity);
        const sizes = interesting_batch_sizes[0..context.interesting_batch_sizes];
        batch.len = if (u.ratio(u8, 3, 4))
            try u.choose(usize, sizes)
        else
            u.int_in_range(usize, 0, context.max_batch_size);
        batch.rng_seed = try secret_bytes(u);
        const shared_seed = try secret_bytes(u);
        const items = batch.items[0..batch.len];
        switch (u.int_in_range(u8, 0, 5)) {
            0 => for (items) |*item| try item.valid(u, null),
            1 => for (items) |*item| try item.signed(u, shared_seed),
            2 => if (batch.len != 0) {
                try items[0].valid(u, null);
                for (items[1..]) |*item| item.* = items[0];
            },
            3 => {
                for (items) |*item| try item.valid(u, null);
                if (batch.len != 0) try items[try item_index(u, batch.len)].invalidate(u);
            },
            4 => {
                for (items) |*item| try item.signed(u, shared_seed);
                if (batch.len != 0) try items[try item_index(u, batch.len)].invalidate(u);
            },
            else => for (items) |*item| try item.arbitrary(u),
        }
    }

    fn item_index(u: *Unstructured, len: usize) Error!usize {
        assert(len > 0);
        const last = len - 1;
        const interesting = [_]usize{
            0, last, len / 2, @min(3, last), @min(4, last), @min(7, last), @min(8, last),
        };
        return u.choose(usize, &interesting);
    }

    fn run(batch: *const Batch, context: Context) !void {
        var expected = batch.len != 0;
        for (batch.items[0..batch.len]) |*item| expected = (try item.verify()) and expected;
        const Op = struct {
            batch: *const Batch,
            pub fn run(op: @This(), explorer: parallel.mocks.Explorer) bool {
                return op.batch.verify(explorer);
            }
        };
        const actual = try parallel.mocks.explore(context.gpa, context.io, Op{ .batch = batch });
        try std.testing.expectEqual(expected, actual);
    }

    fn verify(batch: *const Batch, strategy: anytype) bool {
        var entries: [max_batch_capacity]VerifyingKey.Entry = undefined;
        for (batch.items[0..batch.len], entries[0..batch.len]) |*item, *entry| {
            entry.* = .{
                .namespace = item.namespace.slice(),
                .message = item.message.slice(),
                .public_key = &item.key,
                .signature = &item.signature,
            };
        }
        var rng = utils.FuzzRng.init(&batch.rng_seed);
        const items = entries[0..batch.len];
        return VerifyingKey.verify_batch(&rng, items, cryptography.entries, strategy);
    }
};

/// std.crypto's Edwards25519 against the reference: ZIP-215 decoding (accept or reject, and
/// the point), and `[s]P` through `ed25519.core.MultiScalar` (any point, any scalar) and std's
/// `mulPublic` (points that are not small order, scalars below 2^253).
fn run_curve(u: *Unstructured) !void {
    const encoding = try encoded_point(u);
    const expected = reference.Point.decompress(encoding);
    const actual = core.decompress(encoding);
    try std.testing.expectEqual(expected == null, actual == null);
    const point = actual orelse return;
    try std.testing.expectEqualSlices(u8, &expected.?.compress(), &point.toBytes());

    var scalar = try u.arbitrary([32]u8);
    var sum = core.MultiScalar.init();
    sum.add(point, scalar);
    const product = expected.?.scale(std.mem.readInt(u256, &scalar, .little));
    try std.testing.expectEqualSlices(u8, &product.compress(), &sum.finish().toBytes());

    if (core.is_small_order(point)) return;
    scalar[31] &= 0x1f;
    const masked = expected.?.scale(std.mem.readInt(u256, &scalar, .little));
    const std_product = point.mulPublic(scalar) catch {
        // std rejects a product that is the identity.
        try std.testing.expect(masked.is_identity());
        return;
    };
    try std.testing.expectEqualSlices(u8, &masked.compress(), &std_product.toBytes());
}
