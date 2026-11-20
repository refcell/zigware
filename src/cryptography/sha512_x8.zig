//! Eight-lane SHA-512 for AVX-512F (commonware `cryptography/src/sha512/avx512.rs` and
//! `padding.rs`): lane `i` of each `@Vector(8, u64)` holds message `i`'s copy of one state or
//! schedule word, so every instruction advances eight independent hashes. Messages of any
//! lengths share a call: lanes run in lockstep while at least two have blocks left, each lane
//! masked out once its blocks run out, and the longest finishes one lane wide on std's
//! compressor.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const lanes = 8;
/// Any eight consecutive messages share a call, whatever their lengths (commonware hashes
/// `hash_many` in chunks of eight).
pub const mixed_lengths = true;
/// Messages per batch unit `hash_many` hands the strategy: commonware's sha512 `lanes()`.
pub const batch_lanes = lanes;
pub const digest_bytes = 64;
const block_length = 128;
const V = @Vector(lanes, u64);

/// Whether `hash` runs on this target (commonware requires AVX-512F).
pub const supported = builtin.cpu.arch == .x86_64 and builtin.cpu.has(.x86, .avx512f);

/// SHA-512 round constants (FIPS 180-4, section 4.2.3).
pub const K = [80]u64{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

const iv = Sha512.init(.{}).s;

/// The number of blocks in the padded encoding of a `len`-byte message: the fewest that hold
/// the message, one `0x80` byte, and the 16-byte bit length.
pub fn block_count(len: usize) usize {
    const count = (len + 16) / block_length + 1;
    assert(count * block_length >= len + 17);
    return count;
}

/// Block `index` of the padded encoding of `message` (commonware `padding::block`).
pub inline fn block(message: []const u8, index: usize, out: *[block_length]u8) void {
    assert(index < block_count(message.len));
    const start = index * block_length;
    if (start + block_length <= message.len) {
        out.* = message[start..][0..block_length].*;
        return;
    }
    // The block holding the message's end appends 0x80; the last block ends with the length
    // in bits, pushed into one more block when the tail leaves no room for it.
    out.* = @splat(0);
    const rest = if (start < message.len) message[start..] else message[0..0];
    @memcpy(out[0..rest.len], rest);
    if (start <= message.len) out[rest.len] = 0x80;
    if (index + 1 == block_count(message.len)) {
        std.mem.writeInt(u128, out[block_length - 16 ..], @as(u128, message.len) * 8, .big);
    }
}

/// The digests of `messages` (one to eight, of any lengths), lane `i` for `messages[i]`.
pub fn hash(messages: []const []const u8) [lanes][digest_bytes]u8 {
    comptime assert(supported);
    assert(messages.len >= 1 and messages.len <= lanes);
    var counts: [lanes]usize = @splat(0);
    for (counts[0..messages.len], messages) |*count, message| count.* = block_count(message.len);
    // Only `longest` has blocks past `shared`.
    var longest: usize = 0;
    for (counts, 0..) |count, lane| {
        if (count > counts[longest]) longest = lane;
    }
    var shared: usize = 0;
    for (counts, 0..) |count, lane| {
        if (lane != longest) shared = @max(shared, count);
    }
    // A tail that starts inside the message resumes std's streaming state; one that starts in
    // the padding stays in lockstep with only `longest` active.
    if (shared * block_length > messages[longest].len) shared = counts[longest];
    var state: [8]V = undefined;
    for (&state, iv) |*word, value| word.* = @splat(value);
    var words: [16][lanes]u64 = @splat(@splat(0));
    for (0..shared) |index| {
        var active: [lanes]bool = @splat(false);
        for (messages, 0..) |message, lane| {
            if (index >= counts[lane]) continue;
            active[lane] = true;
            var bytes: [block_length]u8 = undefined;
            block(message, index, &bytes);
            for (&words, 0..) |*row, j| {
                row[lane] = std.mem.readInt(u64, bytes[j * 8 ..][0..8], .big);
            }
        }
        compress(&state, &words, active);
    }
    var rows: [8][lanes]u64 = undefined;
    for (&rows, state) |*row, word| row.* = word;
    var out: [lanes][digest_bytes]u8 = @splat(@splat(0));
    for (out[0..messages.len], 0..) |*digest, lane| {
        for (rows, 0..) |row, j| std.mem.writeInt(u64, digest[j * 8 ..][0..8], row[lane], .big);
    }
    if (shared < counts[longest]) finish(messages[longest], shared, &rows, longest, &out);
    return out;
}

/// Finishes `message` (lane `lane`) from block `shared` on std's compressor.
fn finish(
    message: []const u8,
    shared: usize,
    rows: *const [8][lanes]u64,
    lane: usize,
    out: *[lanes][digest_bytes]u8,
) void {
    const start = shared * block_length;
    assert(start <= message.len);
    var tail = Sha512.init(.{});
    for (&tail.s, rows) |*word, row| word.* = row[lane];
    tail.total_len = start;
    tail.update(message[start..]);
    tail.final(&out[lane]);
}

inline fn rotr(x: V, comptime n: u6) V {
    return std.math.rotr(V, x, n);
}

/// Compresses one block per lane (`words[j][lane]`, word `j` of lane `lane`'s block) into
/// `state`, updating only the `active` lanes.
fn compress(state: *[8]V, words: *const [16][lanes]u64, active_lanes: [lanes]bool) void {
    const active: @Vector(lanes, bool) = active_lanes;
    var w: [16]V = undefined;
    for (&w, words) |*vector, row| vector.* = row;
    var a, var b, var c, var d = .{ state[0], state[1], state[2], state[3] };
    var e, var f, var g, var h = .{ state[4], state[5], state[6], state[7] };
    inline for (0..80) |t| {
        if (t >= 16) {
            const w15 = w[(t + 1) % 16];
            const w2 = w[(t + 14) % 16];
            const s0 = rotr(w15, 1) ^ rotr(w15, 8) ^ (w15 >> @splat(7));
            const s1 = rotr(w2, 19) ^ rotr(w2, 61) ^ (w2 >> @splat(6));
            w[t % 16] +%= s0 +% w[(t + 9) % 16] +% s1;
        }
        const sigma1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        const choose = (e & f) ^ (~e & g);
        const t1 = h +% @as(V, @splat(K[t])) +% w[t % 16] +% sigma1 +% choose;
        const sigma0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        h = g;
        g = f;
        f = e;
        e = d +% t1;
        d = c;
        c = b;
        b = a;
        a = t1 +% sigma0 +% majority;
    }
    const working = [8]V{ a, b, c, d, e, f, g, h };
    for (state, working) |*word, value| word.* = @select(u64, active, word.* +% value, word.*);
    assert(state.len == 8);
}
