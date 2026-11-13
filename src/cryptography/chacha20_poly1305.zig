//! ChaCha20-Poly1305 implementation of the `Cipher` trait (commonware
//! `cryptography/src/chacha20_poly1305.rs`): authenticated encryption of an ordered
//! sequence of messages under one key.
//!
//! The nth message is sealed with the 96-bit little-endian nonce `n`, so the nth `open`
//! accepts only the nth sealed message: replayed, reordered, or modified messages fail. A
//! failed call poisons the cipher (commonware consumes it), so every later call fails too.
//! The counter stops before the nonce would wrap. At most one instance may seal under a key.
//!
//! Backed by `std.crypto.aead.chacha_poly.ChaCha20Poly1305` (RFC 8439), which checks the tag
//! before it writes any plaintext and never releases unauthenticated plaintext.

const std = @import("std");
const assert = std.debug.assert;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const tag_length = 16;
pub const nonce_length = 12;
pub const key_length = 32;

/// The authentication tag of one message; encodes as its 16 raw bytes.
pub const Tag = [tag_length]u8;
const tag_type = Tag;

pub const Error = error{
    /// The 2^96 nonces are spent, or an earlier call failed.
    Exhausted,
    /// The tag does not authenticate the message under this key, position, and aad.
    AuthenticationFailed,
};

comptime {
    assert(Aead.tag_length == tag_length);
    assert(Aead.nonce_length == nonce_length);
    assert(Aead.key_length == key_length);
}

pub const ChaCha20Poly1305 = struct {
    pub const Tag = tag_type;

    /// Nonces are `[0, nonce_limit)`; reaching the limit poisons the cipher.
    pub const nonce_limit: u128 = 1 << (8 * nonce_length);

    key: [key_length]u8,
    nonce: u128,

    /// A cipher with a key of 32 bytes drawn from `rng` (`fill_bytes`).
    pub fn random(rng: anytype) ChaCha20Poly1305 {
        var key: [key_length]u8 = undefined;
        rng.fill_bytes(&key);
        defer std.crypto.secureZero(u8, &key);
        return init(key);
    }

    pub fn init(key: [key_length]u8) ChaCha20Poly1305 {
        return .{ .key = key, .nonce = 0 };
    }

    /// The next nonce, or `Exhausted`.
    fn next_nonce(self: *ChaCha20Poly1305) Error![nonce_length]u8 {
        assert(self.nonce <= nonce_limit);
        if (self.nonce == nonce_limit) return error.Exhausted;
        var bytes: [16]u8 = undefined;
        std.mem.writeInt(u128, &bytes, self.nonce, .little);
        self.nonce += 1;
        return bytes[0..nonce_length].*;
    }

    /// Encrypts the next message in place, authenticated with `aad`, and returns its tag.
    /// On failure `data` is unchanged and the cipher is poisoned.
    pub fn seal(self: *ChaCha20Poly1305, aad: []const u8, data: []u8) Error!tag_type {
        const nonce = self.next_nonce() catch |err| return self.poison(err);
        var tag: tag_type = undefined;
        Aead.encrypt(data, &tag, data, aad, nonce, self.key);
        return tag;
    }

    /// Decrypts the next message in place if `tag` authenticates it with `aad`. On failure
    /// the contents of `data` are unspecified (as in commonware) and the cipher is poisoned.
    pub fn open(
        self: *ChaCha20Poly1305,
        aad: []const u8,
        data: []u8,
        tag: *const tag_type,
    ) Error!void {
        const nonce = self.next_nonce() catch |err| return self.poison(err);
        Aead.decrypt(data, data, tag.*, aad, nonce, self.key) catch
            return self.poison(error.AuthenticationFailed);
    }

    fn poison(self: *ChaCha20Poly1305, err: Error) Error {
        assert(self.nonce <= nonce_limit);
        self.nonce = nonce_limit;
        return err;
    }

    pub fn zeroize(self: *ChaCha20Poly1305) void {
        std.crypto.secureZero(u8, &self.key);
        self.nonce = nonce_limit;
    }

    pub fn format(self: ChaCha20Poly1305, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = self;
        try writer.writeAll("[REDACTED]");
    }
};

comptime {
    @import("signer.zig").assert_cipher(ChaCha20Poly1305);
}

const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const conformance = @import("conformance.zig");

fn test_cipher(seed: u64) ChaCha20Poly1305 {
    var rng = utils.rng.TestRng.init(seed);
    return ChaCha20Poly1305.random(&rng);
}

test "chacha20_poly1305 seal and open round trip" {
    var send = test_cipher(0);
    var receive = test_cipher(0);
    for ([_][]const u8{ "", "hello", "world" }) |message| {
        var data: [5]u8 = undefined;
        @memcpy(data[0..message.len], message);
        const tag = try send.seal("aad", data[0..message.len]);
        if (message.len > 0) try testing.expect(!std.mem.eql(u8, message, data[0..message.len]));
        try receive.open("aad", data[0..message.len], &tag);
        try testing.expectEqualSlices(u8, message, data[0..message.len]);
    }
}

test "chacha20_poly1305 rejects wrong key, aad, order, and corruption" {
    var data = "hello".*;
    var send = test_cipher(0);
    var tag = try send.seal("aad", &data);
    const sealed = data;

    var wrong_key = test_cipher(1);
    try testing.expectError(error.AuthenticationFailed, wrong_key.open("aad", &data, &tag));
    // A failed open poisons the cipher, even for the right message afterwards.
    data = sealed;
    try testing.expectError(error.Exhausted, wrong_key.open("aad", &data, &tag));

    var wrong_aad = test_cipher(0);
    data = sealed;
    try testing.expectError(error.AuthenticationFailed, wrong_aad.open("other", &data, &tag));

    var second = "second".*;
    const second_tag = try send.seal("aad", &second);
    var out_of_order = test_cipher(0);
    const result = out_of_order.open("aad", &second, &second_tag);
    try testing.expectError(error.AuthenticationFailed, result);

    var corrupted = test_cipher(0);
    data = sealed;
    data[0] ^= 0xff;
    try testing.expectError(error.AuthenticationFailed, corrupted.open("aad", &data, &tag));

    var corrupted_tag = test_cipher(0);
    data = sealed;
    tag[0] ^= 0xff;
    try testing.expectError(error.AuthenticationFailed, corrupted_tag.open("aad", &data, &tag));

    // The untouched message still opens with a fresh receiver.
    var receive = test_cipher(0);
    data = sealed;
    tag[0] ^= 0xff;
    try receive.open("aad", &data, &tag);
    try testing.expectEqualSlices(u8, "hello", &data);
}

test "chacha20_poly1305 exhausted counter fails" {
    var send = test_cipher(0);
    send.nonce = ChaCha20Poly1305.nonce_limit - 1;
    _ = try send.seal("", &.{});
    try testing.expectError(error.Exhausted, send.seal("", &.{}));
    var receive = test_cipher(0);
    receive.nonce = ChaCha20Poly1305.nonce_limit;
    const tag: Tag = @splat(0);
    try testing.expectError(error.Exhausted, receive.open("", &.{}, &tag));
}

test "chacha20_poly1305 RFC 8439 vector through the nonce counter" {
    // RFC 8439 section 2.8.2. Its nonce 07000000 4041424344454647 is counter value
    // 0x4746454443424140_00000007 in the cipher's little-endian layout.
    var key: [key_length]u8 = undefined;
    for (&key, 0..) |*byte, i| byte.* = @intCast(0x80 + i);
    var cipher = ChaCha20Poly1305.init(key);
    cipher.nonce = 0x4746454443424140_00000007;
    const aad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    var data = ("Ladies and Gentlemen of the class of '99: If I could offer you only one " ++
        "tip for the future, sunscreen would be it.").*;
    const tag = try cipher.seal(&aad, &data);
    var expected_tag: Tag = undefined;
    _ = try std.fmt.hexToBytes(&expected_tag, "1ae10b594f09e26a7e902ecbd0600691");
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
    var expected_start: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_start, "d31a8d34648e60db7b86afbc53ef7ec2");
    try testing.expectEqualSlices(u8, &expected_start, data[0..16]);
    try testing.expectEqual(@as(u128, 0x4746454443424140_00000008), cipher.nonce);
}

/// Commonware's `Seal` conformance: four seals of random aad and data from `TestRng(seed)`,
/// logged as `aad.encode() || data.encode() || tag`.
fn commit_seal(gpa: std.mem.Allocator, seed: u64, log: *std.ArrayList(u8)) !void {
    var rng = utils.rng.TestRng.init(seed);
    var cipher = ChaCha20Poly1305.random(&rng);
    var aad_buffer: [32]u8 = undefined;
    var data_buffer: [256]u8 = undefined;
    for (0..4) |_| {
        const aad = aad_buffer[0..utils.rng.range_less_than(&rng, u32, 0, 32)];
        rng.fill_bytes(aad);
        const data = data_buffer[0..utils.rng.range_less_than(&rng, u32, 0, 256)];
        rng.fill_bytes(data);
        const tag = try cipher.seal(aad, data);
        for ([_][]const u8{ aad, data }) |bytes| {
            const encoded = try codec.encode([]const u8, gpa, bytes);
            defer gpa.free(encoded);
            try log.appendSlice(gpa, encoded);
        }
        try log.appendSlice(gpa, &tag);
    }
}

test "chacha20_poly1305 conformance: Seal" {
    try conformance.expect(
        4096,
        "71757a47b2a770101ab8c2ad2c5537f70fc033a38543e5598baf7c4219f1d3ae",
        commit_seal,
    );
}
