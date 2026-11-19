//! Private keys and secrets never print their bytes, through any std.fmt path (commonware's
//! `Secret` and private-key `Debug`/`Display` redact). `{f}` calls a type's `format`, but
//! `{}` and `{any}` ignore it and print every field, so each secret keeps its bytes in a
//! `secret.Opaque` field, which those paths print as `.{ ... }`.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const root = @import("root.zig");
const Exchange = @import("handshake/exchange.zig");

const gpa = testing.allocator;

/// Whether `text` shows one of `secrets` (as `{any}` prints an array, or as hex) or, with
/// `digits`, any run of more than four digits (a printed limb or field element). Keys with a
/// public point print its limbs, so they are matched on their secret bytes only.
fn shows(text: []const u8, secrets: []const []const u8, digits: bool) !bool {
    for (secrets) |secret| {
        std.debug.assert(secret.len >= 4);
        const decimal = try std.fmt.allocPrint(gpa, "{d}, {d}, {d}, {d}", .{
            secret[0], secret[1], secret[2], secret[3],
        });
        defer gpa.free(decimal);
        const hex = try std.fmt.allocPrint(gpa, "{x}", .{secret[0..4]});
        defer gpa.free(hex);
        if (std.mem.indexOf(u8, text, decimal) != null) return true;
        if (std.mem.indexOf(u8, text, hex) != null) return true;
    }
    if (!digits) return false;
    var run: usize = 0;
    for (text) |char| {
        run = if (std.ascii.isDigit(char)) run + 1 else 0;
        if (run > 4) return true;
    }
    return false;
}

/// Whether any std.fmt path prints `value`'s key material `secret`.
fn leaks(value: anytype, secrets: []const []const u8, digits: bool) !bool {
    // std.fmt stops at `fmt_max_depth` (3); a deeper print must not reach the bytes either.
    var deep: std.Io.Writer.Allocating = .init(gpa);
    defer deep.deinit();
    try deep.writer.printValue("any", .{}, value, 16);
    const texts = [_][]u8{
        try gpa.dupe(u8, deep.written()),
        try std.fmt.allocPrint(gpa, "{any}", .{value}),
        try std.fmt.allocPrint(gpa, "{}", .{value}),
        try std.fmt.allocPrint(gpa, "{any}", .{&value}),
        if (std.meta.hasMethod(@TypeOf(value), "format"))
            try std.fmt.allocPrint(gpa, "{f}", .{value})
        else
            try gpa.dupe(u8, ""),
    };
    defer for (texts) |text| gpa.free(text);
    for (texts) |text| {
        if (try shows(text, secrets, digits)) return true;
    }
    return false;
}

test "secrets and private keys print no key material" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*byte, index| byte.* = @intCast((index * 7 + 101) % 251);
    // The check itself catches a plain struct holding the bytes.
    try testing.expect(try leaks(.{ .raw = seed }, &.{&seed}, false));
    try testing.expect(try leaks(.{ .limb = @as(u64, 1) << 40 }, &.{}, true));

    try testing.expect(!try leaks(root.Secret([32]u8).init(seed), &.{&seed}, true));
    const ed25519 = root.ed25519.PrivateKey.from_bytes(seed);
    const expanded = &.{ &seed, &ed25519.key.secret.value, &ed25519.key.prefix.value };
    try testing.expect(!try leaks(ed25519, expanded, false));
    const standard = root.secp256r1.standard.PrivateKey.from_bytes(seed).?;
    try testing.expect(!try leaks(standard, &.{&seed}, false));
    const recoverable = root.secp256r1.recoverable.PrivateKey.from_bytes(seed).?;
    try testing.expect(!try leaks(recoverable, &.{&seed}, false));
    const bls = root.bls12381;
    const private = bls.PrivateKey.from_seed(7);
    const scalar_bytes = private.key.scalar.value.to_bytes();
    try testing.expect(!try leaks(private, &.{&scalar_bytes}, true));
    try testing.expect(!try leaks(private.key, &.{&scalar_bytes}, true));
    const share = bls.primitives.group.Share.init(.init(3), private.key);
    try testing.expect(!try leaks(share, &.{&scalar_bytes}, true));
    var rng = utils.test_rng();
    try testing.expect(!try leaks(bls.dkg.golden.evrf.PrivateKey.random(&rng), &.{}, true));
    const exchange = Exchange.SecretKey.random(&rng);
    try testing.expect(!try leaks(exchange, &.{&exchange.bytes.value}, true));
}
