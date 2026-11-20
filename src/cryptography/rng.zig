//! `ChaCha20Rng`: byte-identical to Rust `rand_chacha` 0.10's `ChaCha20Rng`, which
//! commonware's `Signer::from_seed` seeds with `SeedableRng::seed_from_u64`.
//!
//! Keys derived with `from_seed` (in tests, examples, and conformance hashes) must match
//! commonware's bit for bit, so the expansion follows `rand_core`: the 32-byte key is eight
//! PCG32 outputs, the stream id is zero, the block counter is 64 bits, and words come four
//! blocks at a time. Only for tests and examples: production keys come from the runtime's RNG.

const std = @import("std");
const assert = std.debug.assert;
const pcg32 = @import("utils").rng.pcg32;

/// ChaCha20 keystream as a random number generator, buffered four blocks at a time.
pub const ChaCha20Rng = struct {
    const ChaCha = std.crypto.stream.chacha.ChaCha20With64BitNonce;
    const block_words = 16;
    const buffer_blocks = 4;
    const buffer_words = block_words * buffer_blocks;

    key: [32]u8,
    /// Block counter of the next buffer to generate.
    block_counter: u64,
    words: [buffer_words]u32,
    /// Next word to return; `buffer_words` means the buffer is exhausted.
    index: usize,

    /// Rust `ChaCha20Rng::seed_from_u64`.
    pub fn init(seed: u64) ChaCha20Rng {
        var key: [32]u8 = undefined;
        var state = seed;
        for (0..key.len / 4) |chunk| key[chunk * 4 ..][0..4].* = pcg32(&state);
        return init_key(key);
    }

    /// Rust `ChaCha20Rng::from_seed`.
    pub fn init_key(key: [32]u8) ChaCha20Rng {
        const rng: ChaCha20Rng = .{
            .key = key,
            .block_counter = 0,
            .words = undefined,
            .index = buffer_words,
        };
        assert(rng.index == buffer_words);
        return rng;
    }

    fn generate(rng: *ChaCha20Rng) void {
        assert(rng.index == buffer_words);
        var bytes: [buffer_words * 4]u8 = undefined;
        ChaCha.stream(&bytes, rng.block_counter, rng.key, @splat(0));
        for (&rng.words, 0..) |*word, i| {
            word.* = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little);
        }
        rng.block_counter +%= buffer_blocks;
        rng.index = 0;
    }

    pub fn next_u32(rng: *ChaCha20Rng) u32 {
        assert(rng.index <= buffer_words);
        if (rng.index == buffer_words) rng.generate();
        const value = rng.words[rng.index];
        rng.index += 1;
        return value;
    }

    /// Two consecutive words, low then high (`BlockRng::next_u64_from_u32`).
    pub fn next_u64(rng: *ChaCha20Rng) u64 {
        const low = rng.next_u32();
        const high = rng.next_u32();
        return (@as(u64, high) << 32) | low;
    }

    /// Fills `dest` with little-endian words; a partially used final word is discarded.
    pub fn fill_bytes(rng: *ChaCha20Rng, dest: []u8) void {
        var written: usize = 0;
        while (written < dest.len) {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, rng.next_u32(), .little);
            const take = @min(bytes.len, dest.len - written);
            @memcpy(dest[written..][0..take], bytes[0..take]);
            written += take;
        }
        assert(written == dest.len);
    }
};

test "chacha20 rng matches rand_chacha" {
    // Generated with rand_chacha 0.10: `ChaCha20Rng::seed_from_u64(seed)` gives three words;
    // a fresh one skips 63 words, then draws a u64 across the refill, 7 bytes, and a word.
    const Vector = struct { seed: u64, words: [3]u32, straddle: u64, bytes: u56, after: u32 };
    const vectors = [_]Vector{
        .{
            .seed = 0,
            .words = .{ 0x81f5f7b2, 0x063cded6, 0x6efd22a8 },
            .straddle = 0x1fdeae1aea85273b,
            .bytes = 0x1a5f95723b160c,
            .after = 0x2387e922,
        },
        .{
            .seed = 1,
            .words = .{ 0x5044379a, 0x9e636045, 0xa1b770c6 },
            .straddle = 0x63e975e9af728947,
            .bytes = 0x1036c05d62fcfd,
            .after = 0x123e3404,
        },
        .{
            .seed = 42,
            .words = .{ 0xd7b54878, 0x8398bc11, 0xa3176399 },
            .straddle = 0x7d9251b99a87a6b9,
            .bytes = 0x3a1ca3a7e96683,
            .after = 0x91af93e0,
        },
        .{
            .seed = std.math.maxInt(u64),
            .words = .{ 0x67a9438e, 0x3fd18d4d, 0x089a55ad },
            .straddle = 0xd9339a96da3e2009,
            .bytes = 0x5c336bcda3e0ad,
            .after = 0x299fb450,
        },
    };
    for (vectors) |vector| {
        var rng = ChaCha20Rng.init(vector.seed);
        for (vector.words) |word| try std.testing.expectEqual(word, rng.next_u32());
        rng = ChaCha20Rng.init(vector.seed);
        for (0..63) |_| _ = rng.next_u32();
        try std.testing.expectEqual(vector.straddle, rng.next_u64());
        var bytes: [7]u8 = undefined;
        rng.fill_bytes(&bytes);
        try std.testing.expectEqual(vector.bytes, std.mem.readInt(u56, &bytes, .big));
        try std.testing.expectEqual(vector.after, rng.next_u32());
    }
}
