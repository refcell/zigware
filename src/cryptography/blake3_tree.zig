//! BLAKE3's tree, for hashing one long message across a `parallel` strategy (commonware
//! `cryptography/src/blake3`'s `hash_subtrees`). The digest equals `std.crypto.hash.Blake3`'s.
//!
//! `std.crypto.hash.Blake3` keeps the tree's internals private, so this file has its own
//! compression function, written once over vectors of `lanes` words so it compresses that many
//! chunks or parents at once (a vector of one word for single blocks).
//!
//! Commonware splits the root recursively with `strategy.join` until every subtree fits a task
//! bound. Here the bound rounds down to a power of two, `subtree_len`, and the message is cut
//! into aligned subtrees of that length, each a node of the BLAKE3 tree. Rounds of at most
//! `round_subtrees` subtrees hash with `strategy.map_into`, and their chaining values merge on
//! the same chaining-value stack the streaming hasher keeps. The bytes after the last whole
//! subtree, at least one and at most `subtree_len`, hash on the calling thread, so the last
//! chunk is the root's rightmost leaf. No recursion, no allocation.

const std = @import("std");
const parallel = @import("parallel");
const assert = std.debug.assert;

pub const chunk_len = 1024;
const block_len = 64;
const blocks_per_chunk = chunk_len / block_len;

/// Minimum number of tasks a split message spreads across: the subtree each task hashes is at
/// most the message's length divided by this (commonware `SUBTREES`).
pub const subtrees = 8;
/// Lower clamp, in bytes, on the subtree bound: 16 chunks (commonware `MIN_SUBTREE_LEN`).
pub const subtree_len_min = 16 * chunk_len;
/// Upper clamp, in bytes, on the subtree bound: 64 chunks (commonware `MAX_SUBTREE_LEN`).
pub const subtree_len_max = 64 * chunk_len;
/// Length, in bytes, of the shortest message `hash_across` splits (commonware `MIN_SPLIT_LEN`).
pub const split_len_min = subtrees * subtree_len_min;

const subtree_chunks_max = subtree_len_max / chunk_len;
/// Subtrees one `map_into` round hashes, bounding the chaining values held between rounds.
const round_subtrees = 64;
/// Chaining values on the stack: one per set bit of a 64-bit chunk count.
const stack_depth_max = 64;

/// Chunks or parents one vectorized compression covers.
const lanes = std.simd.suggestVectorLength(u32) orelse 1;

const flag_chunk_start: u32 = 1 << 0;
const flag_chunk_end: u32 = 1 << 1;
const flag_parent: u32 = 1 << 2;
const flag_root: u32 = 1 << 3;

const iv: [8]u32 = .{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

const msg_schedule: [7][16]u8 = .{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
    .{ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 },
    .{ 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 },
    .{ 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 },
    .{ 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 },
    .{ 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 },
};

comptime {
    assert(std.math.isPowerOfTwo(lanes));
    assert(lanes <= subtree_len_min / chunk_len);
    assert(split_len_min > subtree_len_max);
}

/// A chaining value: the first eight output words of a compression.
pub const Cv = [8]u32;

fn Vec(comptime n: usize) type {
    return @Vector(n, u32);
}

inline fn rotr(comptime n: usize, x: Vec(n), comptime r: u5) Vec(n) {
    return (x >> @splat(r)) | (x << @splat(@as(u5, @intCast(32 - @as(u6, r)))));
}

inline fn g(comptime n: usize, v: *[16]Vec(n), comptime i: [4]u8, x: Vec(n), y: Vec(n)) void {
    v[i[0]] +%= v[i[1]] +% x;
    v[i[3]] = rotr(n, v[i[3]] ^ v[i[0]], 16);
    v[i[2]] +%= v[i[3]];
    v[i[1]] = rotr(n, v[i[1]] ^ v[i[2]], 12);
    v[i[0]] +%= v[i[1]] +% y;
    v[i[3]] = rotr(n, v[i[3]] ^ v[i[0]], 8);
    v[i[2]] +%= v[i[3]];
    v[i[1]] = rotr(n, v[i[1]] ^ v[i[2]], 7);
}

/// The block's input words of a compression, per lane.
fn Words(comptime n: usize) type {
    return struct {
        counter_low: Vec(n),
        counter_high: Vec(n),
        block_len: Vec(n),
        flags: Vec(n),
    };
}

/// BLAKE3's compression of `n` independent blocks, returning their chaining values.
fn compress(comptime n: usize, cv: [8]Vec(n), m: [16]Vec(n), words: Words(n)) [8]Vec(n) {
    var v: [16]Vec(n) = undefined;
    inline for (0..8) |i| v[i] = cv[i];
    inline for (0..4) |i| v[8 + i] = @splat(iv[i]);
    v[12] = words.counter_low;
    v[13] = words.counter_high;
    v[14] = words.block_len;
    v[15] = words.flags;
    inline for (msg_schedule) |s| {
        g(n, &v, .{ 0, 4, 8, 12 }, m[s[0]], m[s[1]]);
        g(n, &v, .{ 1, 5, 9, 13 }, m[s[2]], m[s[3]]);
        g(n, &v, .{ 2, 6, 10, 14 }, m[s[4]], m[s[5]]);
        g(n, &v, .{ 3, 7, 11, 15 }, m[s[6]], m[s[7]]);
        g(n, &v, .{ 0, 5, 10, 15 }, m[s[8]], m[s[9]]);
        g(n, &v, .{ 1, 6, 11, 12 }, m[s[10]], m[s[11]]);
        g(n, &v, .{ 2, 7, 8, 13 }, m[s[12]], m[s[13]]);
        g(n, &v, .{ 3, 4, 9, 14 }, m[s[14]], m[s[15]]);
    }
    var out: [8]Vec(n) = undefined;
    inline for (0..8) |i| out[i] = v[i] ^ v[i + 8];
    return out;
}

fn read_word(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn splat_cv(comptime n: usize, cv: Cv) [8]Vec(n) {
    var out: [8]Vec(n) = undefined;
    inline for (0..8) |i| out[i] = @splat(cv[i]);
    return out;
}

fn lane_cvs(comptime n: usize, cv: [8]Vec(n), out: *[n]Cv) void {
    inline for (0..8) |i| {
        const words: [n]u32 = cv[i];
        for (out, words) |*lane, word| lane[i] = word;
    }
}

/// The chaining values of the `n` whole chunks at `chunks`, the first at chunk `counter`.
fn chunk_cvs(comptime n: usize, chunks: *const [n][*]const u8, counter: u64, out: *[n]Cv) void {
    var low: [n]u32 = undefined;
    var high: [n]u32 = undefined;
    for (&low, &high, 0..) |*l, *h, lane| {
        l.* = @truncate(counter + lane);
        h.* = @truncate((counter + lane) >> 32);
    }
    var cv = splat_cv(n, iv);
    for (0..blocks_per_chunk) |block| {
        var m: [16]Vec(n) = undefined;
        for (&m, 0..) |*word, w| {
            var column: [n]u32 = undefined;
            const at = block * block_len + 4 * w;
            for (&column, chunks) |*c, chunk| c.* = read_word(chunk[at..][0..4]);
            word.* = column;
        }
        var flags: u32 = 0;
        if (block == 0) flags |= flag_chunk_start;
        if (block == blocks_per_chunk - 1) flags |= flag_chunk_end;
        cv = compress(n, cv, m, .{
            .counter_low = low,
            .counter_high = high,
            .block_len = @splat(block_len),
            .flags = @splat(flags),
        });
    }
    lane_cvs(n, cv, out);
}

/// The chaining values of the `n` parents of `children[2i]` and `children[2i + 1]`, with
/// `extra_flags` (`flag_root` for the root) added to the parent flag.
fn parent_cvs(comptime n: usize, children: *const [2 * n]Cv, extra_flags: u32, out: *[n]Cv) void {
    assert(extra_flags & ~flag_root == 0);
    var m: [16]Vec(n) = undefined;
    inline for (0..16) |w| {
        var column: [n]u32 = undefined;
        for (&column, 0..) |*c, lane| c.* = children[2 * lane + w / 8][w % 8];
        m[w] = column;
    }
    const cv = compress(n, splat_cv(n, iv), m, .{
        .counter_low = @splat(0),
        .counter_high = @splat(0),
        .block_len = @splat(block_len),
        .flags = @splat(flag_parent | extra_flags),
    });
    lane_cvs(n, cv, out);
}

fn parent_cv(left: Cv, right: Cv, extra_flags: u32) Cv {
    var out: [1]Cv = undefined;
    parent_cvs(1, &.{ left, right }, extra_flags, &out);
    return out[0];
}

/// Reads a message given as `parts` in order, chunk by chunk, copying a chunk only when it
/// straddles parts.
const Cursor = struct {
    parts: []const []const u8,
    index: usize,
    skip: usize,

    /// A cursor at byte `offset` of `parts`, which holds more than `offset` bytes.
    fn at(parts: []const []const u8, offset: usize) Cursor {
        return .{ .parts = parts, .index = 0, .skip = offset };
    }

    /// Moves past exhausted parts, so the cursor's part has a byte at `skip`.
    fn settle(cursor: *Cursor) void {
        while (cursor.skip >= cursor.parts[cursor.index].len) {
            cursor.skip -= cursor.parts[cursor.index].len;
            cursor.index += 1;
        }
        assert(cursor.skip < cursor.parts[cursor.index].len);
    }

    /// The next `len` bytes, in place or copied into `scratch`, and advances past them.
    fn take(cursor: *Cursor, len: usize, scratch: *[chunk_len]u8) []const u8 {
        assert(len > 0);
        assert(len <= chunk_len);
        cursor.settle();
        const part = cursor.parts[cursor.index][cursor.skip..];
        if (part.len >= len) {
            cursor.skip += len;
            return part[0..len];
        }
        var copied: usize = 0;
        while (copied < len) {
            cursor.settle();
            const bytes = cursor.parts[cursor.index][cursor.skip..];
            const step = @min(bytes.len, len - copied);
            @memcpy(scratch[copied..][0..step], bytes[0..step]);
            copied += step;
            cursor.skip += step;
        }
        assert(copied == len);
        return scratch[0..len];
    }
};

/// Chaining values of `out.len` whole chunks read from `cursor`, the first at chunk `counter`.
fn chunks_cvs(cursor: *Cursor, counter: u64, out: []Cv) void {
    var scratch: [lanes][chunk_len]u8 = undefined;
    var done: usize = 0;
    while (out.len - done >= lanes) : (done += lanes) {
        var chunks: [lanes][*]const u8 = undefined;
        for (&chunks, &scratch) |*chunk, *buffer| chunk.* = cursor.take(chunk_len, buffer).ptr;
        chunk_cvs(lanes, &chunks, counter + done, out[done..][0..lanes]);
    }
    while (done < out.len) : (done += 1) {
        const chunk = cursor.take(chunk_len, &scratch[0]);
        chunk_cvs(1, &.{chunk.ptr}, counter + done, out[done..][0..1]);
    }
}

/// Merges `cvs`, a power-of-two count of sibling chaining values, into their subtree's.
fn merge_subtree(cvs: []Cv) Cv {
    assert(std.math.isPowerOfTwo(cvs.len));
    var count = cvs.len;
    while (count > 1) : (count /= 2) {
        const pairs = count / 2;
        var done: usize = 0;
        while (pairs - done >= lanes) : (done += lanes) {
            var merged: [lanes]Cv = undefined;
            parent_cvs(lanes, cvs[2 * done ..][0 .. 2 * lanes], 0, &merged);
            @memcpy(cvs[done..][0..lanes], &merged);
        }
        while (done < pairs) : (done += 1) {
            cvs[done] = parent_cv(cvs[2 * done], cvs[2 * done + 1], 0);
        }
    }
    return cvs[0];
}

/// The chaining value of the aligned subtree of `chunks` chunks at byte `offset`.
fn subtree_cv(parts: []const []const u8, offset: usize, chunks: usize) Cv {
    assert(std.math.isPowerOfTwo(chunks));
    assert(chunks <= subtree_chunks_max);
    assert(offset % (chunks * chunk_len) == 0);
    var cvs: [subtree_chunks_max]Cv = undefined;
    var cursor = Cursor.at(parts, offset);
    chunks_cvs(&cursor, offset / chunk_len, cvs[0..chunks]);
    return merge_subtree(cvs[0..chunks]);
}

/// The streaming hasher's chaining-value stack: each entry covers an aligned power-of-two run
/// of chunks, in order, and entries merge as runs complete.
const Stack = struct {
    cvs: [stack_depth_max]Cv = undefined,
    len: usize = 0,

    /// Pushes the chaining value of the run starting at chunk `counter`, first merging the
    /// runs it completes: the stack keeps one entry per set bit of `counter`.
    fn push(stack: *Stack, cv: Cv, counter: u64) void {
        stack.merge(counter);
        assert(stack.len < stack_depth_max);
        stack.cvs[stack.len] = cv;
        stack.len += 1;
    }

    /// Merges the runs that end before chunk `counter`, leaving one entry per set bit of it.
    fn merge(stack: *Stack, counter: u64) void {
        const keep = @popCount(counter);
        while (stack.len > keep) {
            stack.len -= 1;
            const left = stack.cvs[stack.len - 1];
            stack.cvs[stack.len - 1] = parent_cv(left, stack.cvs[stack.len], 0);
        }
        assert(stack.len == keep);
    }
};

/// The root digest of a message whose earlier chunks are on `stack` and whose last chunk,
/// `chunk` (1 to `chunk_len` bytes), is chunk number `counter`.
fn finish(stack_unmerged: Stack, chunk: []const u8, counter: u64) [32]u8 {
    assert(counter > 0);
    assert(chunk.len > 0 and chunk.len <= chunk_len);
    var stack = stack_unmerged;
    stack.merge(counter);
    assert(stack.len > 0);
    const blocks = (chunk.len + block_len - 1) / block_len;
    var cv: [8]Vec(1) = splat_cv(1, iv);
    var last: [block_len]u8 = @splat(0);
    for (0..blocks) |block| {
        const bytes = chunk[block * block_len .. @min(chunk.len, (block + 1) * block_len)];
        @memset(&last, 0);
        @memcpy(last[0..bytes.len], bytes);
        var m: [16]Vec(1) = undefined;
        for (&m, 0..) |*word, w| word.* = @splat(read_word(last[4 * w ..][0..4]));
        var flags: u32 = 0;
        if (block == 0) flags |= flag_chunk_start;
        if (block == blocks - 1) flags |= flag_chunk_end;
        cv = compress(1, cv, m, .{
            .counter_low = @splat(@truncate(counter)),
            .counter_high = @splat(@truncate(counter >> 32)),
            .block_len = @splat(@intCast(bytes.len)),
            .flags = @splat(flags),
        });
    }
    var right: [1]Cv = undefined;
    lane_cvs(1, cv, &right);
    var output = right[0];
    var index = stack.len;
    while (index > 1) {
        index -= 1;
        output = parent_cv(stack.cvs[index], output, 0);
    }
    const root = parent_cv(stack.cvs[0], output, flag_root);
    var digest: [32]u8 = undefined;
    for (root, 0..) |word, i| std.mem.writeInt(u32, digest[4 * i ..][0..4], word, .little);
    return digest;
}

/// The length of the aligned subtrees a message of `len` bytes is cut into: commonware's task
/// bound, `len / subtrees` clamped to `subtree_len_min` and `subtree_len_max`, rounded down to
/// a power of two.
pub fn subtree_len_for(len: usize) usize {
    const bound = std.math.clamp(len / subtrees, subtree_len_min, subtree_len_max);
    const subtree_len = std.math.floorPowerOfTwo(usize, bound);
    assert(subtree_len >= subtree_len_min and subtree_len <= bound);
    return subtree_len;
}

const SubtreeOp = struct {
    parts: []const []const u8,
    subtree_len: usize,

    pub fn map(op: SubtreeOp, index: usize) Cv {
        return subtree_cv(op.parts, index * op.subtree_len, op.subtree_len / chunk_len);
    }
};

/// The BLAKE3 digest of the `len`-byte concatenation of `parts`, which spans more than one
/// chunk, with its whole subtrees hashed across `strategy`.
pub fn hash_subtrees(parts: []const []const u8, len: usize, strategy: anytype) [32]u8 {
    assert(len > chunk_len);
    const subtree_len = subtree_len_for(len);
    const subtree_chunks = subtree_len / chunk_len;
    // Leave the last chunk, and so at least one byte, to the calling thread.
    const whole = (len - 1) / subtree_len;
    var stack: Stack = .{};
    var done: usize = 0;
    while (done < whole) {
        const count = @min(round_subtrees, whole - done);
        var cvs: [round_subtrees]Cv = undefined;
        const op: SubtreeOp = .{ .parts = parts, .subtree_len = subtree_len };
        strategy.map_into(parallel.Range.init(done, done + count), cvs[0..count], op);
        for (cvs[0..count], done..) |cv, index| stack.push(cv, index * subtree_chunks);
        done += count;
    }
    // The rest: its whole chunks, then the last chunk.
    const rest_offset = whole * subtree_len;
    const rest_chunks = (len - rest_offset - 1) / chunk_len;
    assert(rest_chunks < subtree_chunks_max);
    var cursor = Cursor.at(parts, rest_offset);
    var cvs: [subtree_chunks_max]Cv = undefined;
    const first = rest_offset / chunk_len;
    chunks_cvs(&cursor, first, cvs[0..rest_chunks]);
    for (cvs[0..rest_chunks], first..) |cv, counter| stack.push(cv, counter);
    var scratch: [chunk_len]u8 = undefined;
    const last_len = len - rest_offset - rest_chunks * chunk_len;
    const last = cursor.take(last_len, &scratch);
    return finish(stack, last, first + rest_chunks);
}
