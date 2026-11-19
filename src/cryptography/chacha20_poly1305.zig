//! ChaCha20-Poly1305 implementation of the `Cipher` trait (commonware
//! `cryptography/src/chacha20_poly1305.rs`): authenticated encryption of an ordered
//! sequence of messages under one key.
//!
//! The nth message is sealed with the 96-bit little-endian nonce `n`, so the nth `open`
//! accepts only the nth sealed message: replayed, reordered, or modified messages fail. A
//! failed call poisons the cipher (commonware consumes it), so every later call fails too.
//! The counter stops before the nonce would wrap. At most one instance may seal under a key.
//!
//! The AEAD is RFC 8439's, as `std.crypto.aead.chacha_poly.ChaCha20Poly1305` builds it: open
//! checks the tag before it writes any plaintext and never releases unauthenticated plaintext.
//! The keystream runs `lanes` blocks at once, one vector lane per block (`xor_keystream`),
//! because std's ChaCha20 is several times slower than commonware's (aws-lc) on AVX-512, where
//! it picks a 4-way layout that LLVM lowers poorly; Poly1305 is std's.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;
const Poly1305 = std.crypto.onetimeauth.Poly1305;

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
        return encrypt(data, aad, nonce, self.key);
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
        decrypt(data, tag, aad, nonce, self.key) catch
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

/// RFC 8439 section 2.8: encrypts `data` in place with keystream blocks from 1 and returns the
/// tag over `aad` and the ciphertext.
fn encrypt(data: []u8, aad: []const u8, nonce: [nonce_length]u8, key: [key_length]u8) Tag {
    assert(data.len <= 64 * (@as(u64, 1 << 32) - 1));
    var poly_key = poly1305_key(nonce, key);
    defer std.crypto.secureZero(u8, &poly_key);
    xor_keystream(data, 1, key, nonce);
    return authenticate(&poly_key, aad, data);
}

/// RFC 8439 section 2.8: decrypts `data` in place if `tag` authenticates it; on failure `data`
/// is unchanged.
fn decrypt(
    data: []u8,
    tag: *const Tag,
    aad: []const u8,
    nonce: [nonce_length]u8,
    key: [key_length]u8,
) error{AuthenticationFailed}!void {
    var poly_key = poly1305_key(nonce, key);
    defer std.crypto.secureZero(u8, &poly_key);
    var computed = authenticate(&poly_key, aad, data);
    defer std.crypto.secureZero(u8, &computed);
    if (!std.crypto.timing_safe.eql(Tag, computed, tag.*)) return error.AuthenticationFailed;
    xor_keystream(data, 1, key, nonce);
}

/// The one-time Poly1305 key: the first 32 bytes of keystream block 0.
fn poly1305_key(nonce: [nonce_length]u8, key: [key_length]u8) [Poly1305.key_length]u8 {
    var poly_key: [Poly1305.key_length]u8 = @splat(0);
    ChaCha20.xor(&poly_key, &poly_key, 0, key, nonce);
    return poly_key;
}

/// Poly1305 over `aad`, `ciphertext`, each zero-padded to 16 bytes, and their lengths.
fn authenticate(
    poly_key: *const [Poly1305.key_length]u8,
    aad: []const u8,
    ciphertext: []const u8,
) Tag {
    const zeros: [16]u8 = @splat(0);
    var mac = Poly1305.init(poly_key);
    mac.update(aad);
    mac.update(zeros[0 .. (16 - aad.len % 16) % 16]);
    mac.update(ciphertext);
    mac.update(zeros[0 .. (16 - ciphertext.len % 16) % 16]);
    var lengths: [16]u8 = undefined;
    std.mem.writeInt(u64, lengths[0..8], aad.len, .little);
    std.mem.writeInt(u64, lengths[8..16], ciphertext.len, .little);
    mac.update(&lengths);
    var tag: Tag = undefined;
    mac.final(&tag);
    return tag;
}

/// Keystream blocks per wide step: one u32 vector lane per block, so the rounds need no
/// shuffles, and one transpose per step turns the lanes back into blocks.
pub const lanes = @min(16, @max(4, std.simd.suggestVectorLength(u32) orelse 4));
const Lanes = @Vector(lanes, u32);
const wide_bytes = lanes * 64;

comptime {
    assert(std.math.isPowerOfTwo(lanes));
    assert(16 % lanes == 0);
}

/// XORs the ChaCha20 (RFC 8439) keystream from block `counter` into `data` in place: `lanes`
/// blocks at a time, then std's ChaCha20 for the tail.
fn xor_keystream(data: []u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
    assert(data.len / 64 <= std.math.maxInt(u32) - counter);
    var offset: usize = 0;
    var block = counter;
    if (builtin.cpu.arch.endian() == .little) {
        var input: [16]u32 = undefined;
        input[0..4].* = .{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
        for (0..8) |i| input[4 + i] = std.mem.readInt(u32, key[i * 4 ..][0..4], .little);
        input[12] = counter;
        for (0..3) |i| input[13 + i] = std.mem.readInt(u32, nonce[i * 4 ..][0..4], .little);
        defer std.crypto.secureZero(u32, &input);
        while (data.len - offset >= wide_bytes) : (offset += wide_bytes) {
            xor_wide(data[offset..][0..wide_bytes], &input, block);
            block += lanes;
        }
    }
    assert(data.len - offset < wide_bytes or builtin.cpu.arch.endian() != .little);
    const tail = data[offset..];
    if (tail.len > 0) ChaCha20.xor(tail, tail, block, key, nonce);
}

inline fn rotate(v: Lanes, comptime bits: u5) Lanes {
    return (v << @splat(bits)) | (v >> @splat(@as(u5, @intCast(32 - @as(u6, bits)))));
}

/// One quarter round on words `a`, `b`, `c`, `d` of every lane's block.
inline fn quarter(
    x: *[16]Lanes,
    comptime a: u8,
    comptime b: u8,
    comptime c: u8,
    comptime d: u8,
) void {
    x[a] +%= x[b];
    x[d] = rotate(x[d] ^ x[a], 16);
    x[c] +%= x[d];
    x[b] = rotate(x[b] ^ x[c], 12);
    x[a] +%= x[b];
    x[d] = rotate(x[d] ^ x[a], 8);
    x[c] +%= x[d];
    x[b] = rotate(x[b] ^ x[c], 7);
}

/// XORs blocks `counter .. counter + lanes` of keystream into `data`. Word w of every block
/// lives in vector `x[w]`, lane b holding block b.
fn xor_wide(data: *[wide_bytes]u8, input: *const [16]u32, counter: u32) void {
    @setEvalBranchQuota(100_000);
    var start: [16]Lanes = undefined;
    for (&start, input) |*word, value| word.* = @splat(value);
    start[12] = @as(Lanes, @splat(counter)) +% std.simd.iota(u32, lanes);
    var x = start;
    inline for (0..10) |_| {
        quarter(&x, 0, 4, 8, 12);
        quarter(&x, 1, 5, 9, 13);
        quarter(&x, 2, 6, 10, 14);
        quarter(&x, 3, 7, 11, 15);
        quarter(&x, 0, 5, 10, 15);
        quarter(&x, 1, 6, 11, 12);
        quarter(&x, 2, 7, 8, 13);
        quarter(&x, 3, 4, 9, 14);
    }
    inline for (&x, start) |*word, initial| word.* +%= initial;
    defer std.crypto.secureZero(Lanes, &x);
    // Transposes each lanes-by-lanes square of words (a butterfly over halves, quarters, ...),
    // so row b of square g holds words g*lanes .. g*lanes + lanes - 1 of block b.
    inline for (0..16 / lanes) |g| {
        const rows = x[g * lanes ..][0..lanes];
        comptime var d = lanes / 2;
        inline while (d >= 1) : (d /= 2) {
            inline for (0..lanes) |i| {
                if (i & d == 0) {
                    const low = rows[i];
                    const high = rows[i + d];
                    rows[i] = @shuffle(u32, low, high, swap_mask(d, 0));
                    rows[i + d] = @shuffle(u32, low, high, swap_mask(d, d));
                }
            }
        }
        inline for (0..lanes) |b| {
            // An unaligned vector pointer: a byte-array @bitCast lowers to scalar code.
            const chunk: *align(1) Lanes = @ptrCast(data[b * 64 + g * lanes * 4 ..]);
            chunk.* ^= rows[b];
        }
    }
}

/// The butterfly step at distance `d`: lanes with bit `d` clear take the first row's lane
/// `k + shift`, the rest the second row's lane `k - d + shift`.
fn swap_mask(comptime d: usize, comptime shift: usize) [lanes]i32 {
    assert(shift == 0 or shift == d);
    var mask: [lanes]i32 = undefined;
    for (0..lanes) |k| {
        mask[k] = if (k & d == 0) @intCast(k + shift) else ~@as(i32, @intCast(k - d + shift));
    }
    return mask;
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

const fuzz = @import("fuzz.zig");

/// Seals and opens a message decoded from `bytes` (key, nonce, aad, and a length that reaches
/// several wide steps and their boundaries) and checks the ciphertext and tag against std's
/// ChaCha20-Poly1305, then that a flipped tag bit fails and leaves the ciphertext unchanged.
fn check_against_std(bytes: []const u8) !void {
    var input = fuzz.Input.init(bytes);
    var key: [key_length]u8 = undefined;
    input.fill(&key);
    var nonce: [nonce_length]u8 = undefined;
    input.fill(&nonce);
    var aad: [80]u8 = undefined;
    const aad_length = input.int_in_range(0, aad.len);
    input.fill(aad[0..aad_length]);
    const steps = input.int_in_range(0, 3);
    const length = steps * wide_bytes + input.int_in_range(0, wide_bytes + 64);
    var message: [4 * wide_bytes + 64]u8 = undefined;
    for (message[0..length], 0..) |*byte, i| byte.* = @truncate(i *% 131 +% key[i % 32]);
    var expected: [message.len]u8 = undefined;
    var expected_tag: Tag = undefined;
    const plain = message[0..length];
    Aead.encrypt(expected[0..length], &expected_tag, plain, aad[0..aad_length], nonce, key);
    var data = message;
    var tag = encrypt(data[0..length], aad[0..aad_length], nonce, key);
    try testing.expectEqualSlices(u8, expected[0..length], data[0..length]);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
    tag[input.int_in_range(0, tag_length - 1)] ^= 1;
    const forged = decrypt(data[0..length], &tag, aad[0..aad_length], nonce, key);
    try testing.expectError(error.AuthenticationFailed, forged);
    try testing.expectEqualSlices(u8, expected[0..length], data[0..length]);
    tag = expected_tag;
    try decrypt(data[0..length], &tag, aad[0..aad_length], nonce, key);
    try testing.expectEqualSlices(u8, plain, data[0..length]);
}

test "chacha20_poly1305 fuzz: wide keystream matches std" {
    var random = fuzz.prng(0x5ea1);
    var bytes: [128]u8 = undefined;
    for (0..fuzz.iterations(64)) |_| {
        random.random().bytes(&bytes);
        try check_against_std(&bytes);
    }
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var input: [128]u8 = undefined;
            smith.bytes(&input);
            try check_against_std(&input);
        }
    }.run, .{});
}
