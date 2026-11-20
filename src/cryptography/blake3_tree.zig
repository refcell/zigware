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
//! subtree, at least one and at most `subtree_len`, hash as one more item of the last round,
//! and its last chunk is the root's rightmost leaf. No recursion, no allocation.

const std = @import("std");
const parallel = @import("parallel");
const assert = std.debug.assert;
const native_endian = @import("builtin").cpu.arch.endian();

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
/// Lower bound, in bytes, on the subtrees a split message is actually cut into: 32 chunks.
/// Below this, dispatching a task to the pool costs more than the 16 chunks it hashes save
/// (128 KiB at conc=8: 14.5 µs as 4 subtrees against 17.3 µs as 8, min of 4 rounds), so the
/// shortest split messages spread across fewer, larger tasks than commonware's bound.
const subtree_len_floor = 2 * subtree_len_min;
/// Length, in bytes, of the shortest message `hash_across` splits (commonware `MIN_SPLIT_LEN`).
pub const split_len_min = subtrees * subtree_len_min;

/// Chunks in the longest run `run_cv` merges, and in the subtrees `hash_serial` cuts.
const run_chunks_max = 1024;
/// Length, in bytes, of the subtrees `hash_serial` cuts a message into: one run each.
const serial_subtree_len = run_chunks_max * chunk_len;
/// Subtrees one `map_into` round hashes, bounding the chaining values held between rounds.
const round_subtrees = 64;
/// Chaining values on the stack: one per set bit of a 64-bit chunk count.
const stack_depth_max = 64;

/// Chunks or parents one vectorized compression covers.
const lanes = std.simd.suggestVectorLength(u32) orelse 1;
/// Whether full-width compressions load each block with one vector load and transpose the
/// words (16 lanes, AVX-512); narrower ones gather the words one at a time.
pub const transposed = lanes == 16;

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
    assert(subtree_len_max <= serial_subtree_len);
    // A transposed load reads one block of 16 words.
    assert(@sizeOf(@Vector(16, u32)) == block_len);
    assert(split_len_min > subtree_len_max);
    assert(subtree_len_floor >= subtree_len_min and subtree_len_floor <= subtree_len_max);
}

/// A chaining value: the first eight output words of a compression.
pub const Cv = [8]u32;

fn Vec(comptime n: usize) type {
    return @Vector(n, u32);
}

/// One round over `n` lanes, as std's `roundFnVec`: the four column G functions, then the
/// four diagonal ones, interleaved step by step so their independent operations overlap.
inline fn round(comptime n: usize, v: *[16]Vec(n), m: *const [16]Vec(n), comptime r: usize) void {
    const s = msg_schedule[r];
    const rotr = std.math.rotr;
    const columns = .{ .{ 0, 4, 8, 12 }, .{ 1, 5, 9, 13 }, .{ 2, 6, 10, 14 }, .{ 3, 7, 11, 15 } };
    const diagonals = .{ .{ 0, 5, 10, 15 }, .{ 1, 6, 11, 12 }, .{ 2, 7, 8, 13 }, .{ 3, 4, 9, 14 } };
    inline for (.{ columns, diagonals }, 0..) |quads, half| {
        inline for (.{ .{ 0, 16, 12 }, .{ 1, 8, 7 } }) |step| {
            inline for (quads, 0..) |q, i| v[q[0]] +%= m[s[8 * half + 2 * i + step[0]]];
            inline for (quads) |q| v[q[0]] +%= v[q[1]];
            inline for (quads) |q| v[q[3]] ^= v[q[0]];
            inline for (quads) |q| v[q[3]] = rotr(Vec(n), v[q[3]], step[1]);
            inline for (quads) |q| v[q[2]] +%= v[q[3]];
            inline for (quads) |q| v[q[1]] ^= v[q[2]];
            inline for (quads) |q| v[q[1]] = rotr(Vec(n), v[q[1]], step[2]);
        }
    }
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
fn compress(comptime n: usize, cv: [8]Vec(n), m: *const [16]Vec(n), words: Words(n)) [8]Vec(n) {
    @setEvalBranchQuota(20_000);
    var v: [16]Vec(n) = undefined;
    inline for (0..8) |i| v[i] = cv[i];
    inline for (0..4) |i| v[8 + i] = @splat(iv[i]);
    v[12] = words.counter_low;
    v[13] = words.counter_high;
    v[14] = words.block_len;
    v[15] = words.flags;
    inline for (0..msg_schedule.len) |r| round(n, &v, m, r);
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

/// Transposes the `n` rows of an `n`-by-`n` matrix of words into its columns, swapping the
/// off-diagonal blocks of each power-of-two size in turn (one two-source permute per row and
/// stage, as the BLAKE3 reference's AVX-512 transpose).
inline fn transpose(comptime n: usize, rows: *[n]Vec(n)) void {
    comptime var s = n / 2;
    inline while (s >= 1) : (s /= 2) {
        comptime var low: [n]i32 = undefined;
        comptime var high: [n]i32 = undefined;
        inline for (0..n) |j| {
            low[j] = if (j & s == 0) j else ~@as(i32, j - s);
            high[j] = if (j & s == 0) j + s else ~@as(i32, j);
        }
        inline for (0..n) |i| {
            if (i & s == 0) {
                const a = rows[i];
                const b = rows[i + s];
                rows[i] = @shuffle(u32, a, b, low);
                rows[i + s] = @shuffle(u32, a, b, high);
            }
        }
    }
}

/// The 16 little-endian words of each 64-byte block at `blocks`, one block per lane: each
/// block loads as `16 / n` vectors of `n` words, and each group of `n` words transposes. Vector
/// loads, as copying a `[64]u8` instead lowers to byte loads, and gathering words one at a
/// time costs more than the transposes (4 KiB: 4 lanes).
inline fn load_transposed(comptime n: usize, blocks: *const [n][*]const u8) [16]Vec(n) {
    comptime assert(std.math.isPowerOfTwo(n) and n <= 16);
    var m: [16]Vec(n) = undefined;
    inline for (0..16 / n) |group| {
        var rows: [n]Vec(n) = undefined;
        inline for (&rows, blocks) |*row, block| {
            row.* = @as(*align(1) const Vec(n), @ptrCast(block + group * n * 4)).*;
            if (native_endian == .big) row.* = @byteSwap(row.*);
        }
        transpose(n, &rows);
        m[group * n ..][0..n].* = rows;
    }
    return m;
}

/// The message words of block `block` of each of the `n` chunks at `chunks`, one per lane.
inline fn chunk_words(comptime n: usize, chunks: *const [n][*]const u8, block: usize) [16]Vec(n) {
    assert(block < blocks_per_chunk);
    var blocks: [n][*]const u8 = undefined;
    inline for (&blocks, chunks) |*b, chunk| b.* = chunk + block * block_len;
    return load_transposed(n, &blocks);
}

/// The chaining values, in vector form, of the `n` whole chunks at `chunks`, the first at chunk
/// `counter`.
fn chunk_nodes(comptime n: usize, chunks: *const [n][*]const u8, counter: u64) [8]Vec(n) {
    var low: [n]u32 = undefined;
    var high: [n]u32 = undefined;
    for (&low, &high, 0..) |*l, *h, lane| {
        l.* = @truncate(counter + lane);
        h.* = @truncate((counter + lane) >> 32);
    }
    var cv = splat_cv(n, iv);
    for (0..blocks_per_chunk) |block| {
        const m = chunk_words(n, chunks, block);
        var flags: u32 = 0;
        if (block == 0) flags |= flag_chunk_start;
        if (block == blocks_per_chunk - 1) flags |= flag_chunk_end;
        // Inlined, so the chaining value stays in registers across the chunk's blocks.
        cv = @call(.always_inline, compress, .{ n, cv, &m, Words(n){
            .counter_low = low,
            .counter_high = high,
            .block_len = @splat(block_len),
            .flags = @splat(flags),
        } });
    }
    return cv;
}

/// The chaining values of the `n` whole chunks at `chunks`, the first at chunk `counter`.
fn chunk_cvs(comptime n: usize, chunks: *const [n][*]const u8, counter: u64, out: *[n]Cv) void {
    lane_cvs(n, chunk_nodes(n, chunks, counter), out);
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
    const cv = compress(n, splat_cv(n, iv), &m, .{
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

/// A `@shuffle` mask taking every other lane of the `2n` lanes of `a` then `b`, from lane
/// `first` (0: the left children of their pairs, 1: the right ones).
fn pair_mask(comptime n: usize, comptime first: usize) [n]i32 {
    var mask: [n]i32 = undefined;
    for (&mask, 0..) |*index, lane| {
        const source = 2 * lane + first;
        index.* = if (source < n) source else ~@as(i32, source - n);
    }
    return mask;
}

/// The `n` parents, in vector form, of the `2n` sibling nodes `left` then `right` (chaining
/// values in vector form): each parent's message is a pair of adjacent nodes, gathered with
/// two shuffles per word instead of storing the nodes and transposing them back.
fn parent_nodes(comptime n: usize, left: [8]Vec(n), right: [8]Vec(n)) [8]Vec(n) {
    var m: [16]Vec(n) = undefined;
    inline for (0..8) |w| {
        m[w] = @shuffle(u32, left[w], right[w], pair_mask(n, 0));
        m[8 + w] = @shuffle(u32, left[w], right[w], pair_mask(n, 1));
    }
    return @call(.always_inline, compress, .{ n, splat_cv(n, iv), &m, Words(n){
        .counter_low = @splat(0),
        .counter_high = @splat(0),
        .block_len = @splat(block_len),
        .flags = @splat(flag_parent),
    } });
}

/// The chaining value of the subtree whose `n` sibling nodes are `nodes`, a power of two, each
/// level at half the width of the one below. The recursion is over the comptime width, so it
/// unrolls at compile time into `log2(n)` levels.
inline fn collapse(comptime n: usize, nodes: [8]Vec(n)) Cv {
    comptime assert(std.math.isPowerOfTwo(n));
    if (n == 1) {
        var out: [1]Cv = undefined;
        lane_cvs(1, nodes, &out);
        return out[0];
    }
    return collapse(n / 2, parents_of(n, nodes));
}

/// The `n / 2` parents, in vector form, of the `n` sibling nodes `nodes`: lane `i` is the
/// parent of nodes `2i` and `2i + 1`.
inline fn parents_of(comptime n: usize, nodes: [8]Vec(n)) [8]Vec(n / 2) {
    comptime assert(std.math.isPowerOfTwo(n) and n >= 2);
    const half = n / 2;
    comptime var low: [half]i32 = undefined;
    inline for (&low, 0..) |*index, lane| index.* = lane;
    comptime var high: [half]i32 = undefined;
    inline for (&high, 0..) |*index, lane| index.* = half + lane;
    var left: [8]Vec(half) = undefined;
    var right: [8]Vec(half) = undefined;
    inline for (0..8) |w| {
        left[w] = @shuffle(u32, nodes[w], nodes[w], low);
        right[w] = @shuffle(u32, nodes[w], nodes[w], high);
    }
    return parent_nodes(half, left, right);
}

/// The chaining value of the aligned run of `chunks` whole chunks read from `cursor`, the
/// first at chunk `counter`: a power of two from `lanes` to `run_chunks_max`. Batches of
/// `lanes` chunks merge in vector form as a binary counter: each batch merges with the
/// pending batch of every level its index completes, so every merge but the top `lanes`
/// nodes runs at full width.
fn run_cv(cursor: *Cursor, counter: u64, chunks: usize) Cv {
    return collapse(lanes, run_top(cursor, counter, chunks));
}

/// The top `lanes` nodes, in vector form, of the run `run_cv` merges, before they collapse.
fn run_top(cursor: *Cursor, counter: u64, chunks: usize) [8]Vec(lanes) {
    assert(std.math.isPowerOfTwo(chunks));
    assert(chunks >= lanes and chunks <= run_chunks_max);
    assert(counter % chunks == 0);
    const levels = comptime std.math.log2_int(usize, run_chunks_max / lanes) + 1;
    var pending: [levels][8]Vec(lanes) = undefined;
    var scratch: [lanes][chunk_len]u8 = undefined;
    const batches = chunks / lanes;
    for (0..batches) |batch| {
        var pointers: [lanes][*]const u8 = undefined;
        for (&pointers, &scratch) |*pointer, *buffer| {
            pointer.* = cursor.take(chunk_len, buffer).ptr;
        }
        var nodes = chunk_nodes(lanes, &pointers, counter + batch * lanes);
        var level: usize = 0;
        while ((batch >> @intCast(level)) & 1 == 1) : (level += 1) {
            nodes = parent_nodes(lanes, pending[level], nodes);
        }
        pending[level] = nodes;
    }
    const top = std.math.log2_int(usize, batches);
    assert(top < levels);
    return pending[top];
}

/// The chaining values of two runs from their top nodes `a` and `b`, collapsed side by side:
/// each level is one compression of both runs' nodes, so the narrow, latency-bound levels at
/// the top of a run cost half as many compressions as collapsing each run alone.
fn collapse_pair(a: [8]Vec(lanes), b: [8]Vec(lanes)) [2]Cv {
    comptime assert(lanes >= 2);
    var out: [2]Cv = undefined;
    lane_cvs(2, collapse_to_two(lanes, parent_nodes(lanes, a, b)), &out);
    return out;
}

/// Halves `nodes`, whose first half descends from one run and second from another, down to
/// one node per run.
inline fn collapse_to_two(comptime n: usize, nodes: [8]Vec(n)) [8]Vec(2) {
    comptime assert(std.math.isPowerOfTwo(n) and n >= 2);
    if (n == 2) return nodes;
    return collapse_to_two(n / 2, parents_of(n, nodes));
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

/// The widest power-of-two compression width, at most `lanes`, that fits `count` items.
fn width_for(count: usize) usize {
    assert(count > 0);
    const width = @min(lanes, std.math.floorPowerOfTwo(usize, count));
    assert(width <= count);
    return width;
}

/// Compression widths: `lanes`, then every smaller power of two down to one.
const widths = blk: {
    var list: [std.math.log2_int(usize, lanes) + 1]usize = undefined;
    for (&list, 0..) |*width, index| width.* = lanes >> index;
    break :blk list;
};

/// The compression width for a batch of `count` chunks: the narrowest power of two that
/// covers it, except that with transposed loads a batch of more than 4 chunks pads to full
/// width, which costs less than a narrower width's gathered loads (8 chunks: 1.31 us at 16
/// lanes against 1.46 us at 8).
fn width_of_batch(count: usize) usize {
    assert(count > 0 and count <= lanes);
    if (transposed and count > 4) return lanes;
    return std.math.ceilPowerOfTwoAssert(usize, count);
}

/// Chaining values of `out.len` whole chunks read from `cursor`, the first at chunk `counter`,
/// compressed `lanes` at a time. A short last batch compresses at the narrowest width that
/// covers it, padded with copies of its last chunk whose outputs are dropped: one compression
/// costs less than the narrower ones that would cover it, and a narrower one less than a wider
/// one (2 chunks: 1.7 µs at 2 lanes, 2.2 µs at 16).
fn chunks_cvs(cursor: *Cursor, counter: u64, out: []Cv) void {
    var scratch: [lanes][chunk_len]u8 = undefined;
    var done: usize = 0;
    while (done < out.len) {
        // `usize`, not the narrowed type `@min` gives: `2 * count` must not overflow.
        const count: usize = @min(lanes, out.len - done);
        const width: usize = width_of_batch(count);
        assert(width >= count and width <= lanes);
        var chunks: [lanes][*]const u8 = undefined;
        for (chunks[0..count], scratch[0..count]) |*chunk, *buffer| {
            chunk.* = cursor.take(chunk_len, buffer).ptr;
        }
        for (chunks[count..width]) |*chunk| chunk.* = chunks[count - 1];
        inline for (widths) |n| {
            if (n == width) {
                var cvs: [n]Cv = undefined;
                chunk_cvs(n, chunks[0..n], counter + done, &cvs);
                @memcpy(out[done..][0..count], cvs[0..count]);
            }
        }
        done += count;
    }
    assert(done == out.len);
}

/// Merges `cvs`, a power-of-two count of sibling chaining values, into their subtree's, each
/// level at the widest width that fits its pairs.
fn merge_subtree(cvs: []Cv) Cv {
    assert(std.math.isPowerOfTwo(cvs.len));
    var count = cvs.len;
    while (count > 1) : (count /= 2) {
        const pairs = count / 2;
        var done: usize = 0;
        while (done < pairs) {
            const width = width_for(pairs - done);
            inline for (widths) |n| {
                if (n == width) {
                    var merged: [n]Cv = undefined;
                    parent_cvs(n, cvs[2 * done ..][0 .. 2 * n], 0, &merged);
                    @memcpy(cvs[done..][0..n], &merged);
                }
            }
            done += width;
        }
    }
    return cvs[0];
}

/// The chaining value of the aligned subtree of `chunks` chunks at byte `offset`.
fn subtree_cv(parts: []const []const u8, offset: usize, chunks: usize) Cv {
    assert(offset % (chunks * chunk_len) == 0);
    var cursor = Cursor.at(parts, offset);
    return run_cv(&cursor, offset / chunk_len, chunks);
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

/// The chaining value of the last chunk, `chunk` (1 to `chunk_len` bytes), chunk `counter`.
fn last_chunk_cv(chunk: []const u8, counter: u64) Cv {
    assert(chunk.len > 0 and chunk.len <= chunk_len);
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
        cv = compress(1, cv, &m, .{
            .counter_low = @splat(@truncate(counter)),
            .counter_high = @splat(@truncate(counter >> 32)),
            .block_len = @splat(@intCast(bytes.len)),
            .flags = @splat(flags),
        });
    }
    var out: [1]Cv = undefined;
    lane_cvs(1, cv, &out);
    return out[0];
}

/// The root digest of a message whose earlier chunks are on `stack` and whose last chunk,
/// chunk number `counter`, has chaining value `last`.
fn finish(stack_unmerged: Stack, last: Cv, counter: u64) [32]u8 {
    assert(counter > 0);
    var stack = stack_unmerged;
    stack.merge(counter);
    assert(stack.len > 0);
    var output = last;
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
/// bound, `len / subtrees` clamped to `subtree_len_floor` and `subtree_len_max`, rounded down
/// to a power of two.
pub fn subtree_len_for(len: usize) usize {
    const bound = std.math.clamp(len / subtrees, subtree_len_floor, subtree_len_max);
    const subtree_len = std.math.floorPowerOfTwo(usize, bound);
    assert(subtree_len >= subtree_len_floor and subtree_len <= bound);
    return subtree_len;
}

/// The chaining values of a message's rest, the bytes after its last whole subtree: aligned
/// runs of decreasing powers of two of its whole chunks, then its last node, `last`, at chunk
/// `last_counter`: its last run when its last chunk is whole, its last chunk otherwise.
const Rest = struct {
    /// Runs of up to `run_chunks_max` chunks: one per set bit, plus a split one.
    const runs_max = std.math.log2_int(usize, run_chunks_max) + 2;

    runs: [runs_max]Cv = undefined,
    run_starts: [runs_max]u64 = undefined,
    run_count: usize = 0,
    last: Cv = undefined,
    last_counter: u64 = 0,

    fn push(rest: *Rest, cv: Cv, start: u64) void {
        assert(rest.run_count < runs_max);
        rest.runs[rest.run_count] = cv;
        rest.run_starts[rest.run_count] = start;
        rest.run_count += 1;
    }
};

/// The length of the next run of a rest's `whole` chunks, `done` of them already in runs: the
/// largest power of two left, except that a message that is one power-of-two run (`first` 0,
/// no partial last chunk) splits into two, since its root merges two runs.
fn next_run(first: u64, whole: usize, done: usize, partial: bool) usize {
    assert(done < whole);
    const run = std.math.floorPowerOfTwo(usize, whole - done);
    if (first == 0 and done == 0 and !partial and run == whole) return run / 2;
    return run;
}

/// Hashes the rest of the `len`-byte message `parts` from byte `offset`, a subtree boundary.
/// Runs of at least `lanes` chunks merge in vector form (`run_cv`); the shorter ones left,
/// at most `lanes` chunks in all, compress in one batch.
fn hash_rest(parts: []const []const u8, len: usize, offset: usize, rest: *Rest) void {
    assert(offset < len);
    const rest_len = len - offset;
    const first: u64 = offset / chunk_len;
    const whole = rest_len / chunk_len;
    const partial = rest_len % chunk_len;
    assert(whole <= run_chunks_max);
    var cursor = Cursor.at(parts, offset);
    rest.run_count = 0;
    var done: usize = 0;
    // Runs of at least `lanes` chunks collapse in pairs (`collapse_pair`).
    var held: ?struct { top: [8]Vec(lanes), start: u64 } = null;
    while (done < whole) {
        const run = next_run(first, whole, done, partial > 0);
        if (run < lanes) break;
        assert((first + done) % run == 0);
        const top = run_top(&cursor, first + done, run);
        if (lanes == 1) {
            rest.push(collapse(lanes, top), first + done);
        } else if (held) |pair| {
            const cvs = collapse_pair(pair.top, top);
            rest.push(cvs[0], pair.start);
            rest.push(cvs[1], first + done);
            held = null;
        } else {
            held = .{ .top = top, .start = first + done };
        }
        done += run;
    }
    if (held) |pair| rest.push(collapse(lanes, pair.top), pair.start);
    if (whole - done >= 2) {
        const width = std.math.ceilPowerOfTwoAssert(usize, whole - done);
        inline for (widths) |n| {
            if (n >= 2 and n == width) {
                rest_runs_vector(n, &cursor, first, whole, done, partial > 0, rest);
            }
        }
        done = whole;
    }
    if (done < whole) {
        var cvs: [lanes]Cv = undefined;
        const small = cvs[0 .. whole - done];
        chunks_cvs(&cursor, first + done, small);
        var merged: usize = 0;
        while (done + merged < whole) {
            const run = next_run(first, whole, done + merged, partial > 0);
            assert(run <= small.len - merged);
            rest.push(merge_subtree(small[merged..][0..run]), first + done + merged);
            merged += run;
        }
        done += merged;
    }
    assert(done == whole);
    if (partial == 0) {
        // The last run is the root's rightmost node; a message of one run has two runs here.
        assert(rest.run_count > 0);
        rest.run_count -= 1;
        rest.last = rest.runs[rest.run_count];
        rest.last_counter = rest.run_starts[rest.run_count];
        assert(rest.last_counter > 0);
        return;
    }
    var scratch: [chunk_len]u8 = undefined;
    rest.last_counter = first + whole;
    rest.last = last_chunk_cv(cursor.take(partial, &scratch), rest.last_counter);
}

/// The runs of a rest's last `whole - done` whole chunks, 2 to `lanes` of them, from one batch
/// padded to the width `n` that covers them and merged in vector form: level `l` of the merge
/// holds every aligned run of `2^l` chunks, so each run's chaining value is one lane of one
/// level, and the runs' parents share compressions instead of each gathering its own (4 KiB:
/// the two 2-chunk runs merge in one 2-lane compression).
fn rest_runs_vector(
    comptime n: usize,
    cursor: *Cursor,
    first: u64,
    whole: usize,
    done_before: usize,
    partial: bool,
    rest: *Rest,
) void {
    comptime assert(std.math.isPowerOfTwo(n) and n >= 2 and n <= lanes);
    const count = whole - done_before;
    assert(count > n / 2 and count <= n);
    const start = first + done_before;
    assert(start % n == 0);
    var scratch: [n][chunk_len]u8 = undefined;
    var chunks: [n][*]const u8 = undefined;
    for (chunks[0..count], scratch[0..count]) |*chunk, *buffer| {
        chunk.* = cursor.take(chunk_len, buffer).ptr;
    }
    for (chunks[count..]) |*chunk| chunk.* = chunks[count - 1];
    // Padded lanes' nodes are never read: a run covering one is never pushed.
    var levels: [std.math.log2_int(usize, n) + 1][n]Cv = undefined;
    // The first run is the largest; levels above it would be compressions no run reads.
    const top = std.math.log2_int(usize, next_run(first, whole, done_before, partial));
    store_levels(n, chunk_nodes(n, &chunks, start), &levels, 0, top);
    var done = done_before;
    while (done < whole) {
        const run = next_run(first, whole, done, partial);
        assert(run <= n);
        const offset = done - done_before;
        assert(offset % run == 0);
        const level = std.math.log2_int(usize, run);
        rest.push(levels[level][offset / run], first + done);
        done += run;
    }
    assert(done == whole);
}

/// Stores the `w` nodes `nodes` as level `level` of `levels`, then their parents above them,
/// up to level `top`. Recursion over the comptime width unrolls at compile time.
inline fn store_levels(
    comptime w: usize,
    nodes: [8]Vec(w),
    levels: anytype,
    comptime level: usize,
    top: usize,
) void {
    assert(level <= top);
    lane_cvs(w, nodes, levels[level][0..w]);
    if (w > 1 and level < top) store_levels(w / 2, parents_of(w, nodes), levels, level + 1, top);
}

/// Item `index` of a round: subtree `index`, or, at index `whole`, the rest, which it writes
/// to `rest` (its own output slot is unused). Hashing the rest in the round keeps it off the
/// calling thread's critical path.
const SubtreeOp = struct {
    parts: []const []const u8,
    len: usize,
    subtree_len: usize,
    whole: usize,
    rest: *Rest,

    pub fn map(op: SubtreeOp, index: usize) Cv {
        assert(index <= op.whole);
        if (index == op.whole) {
            hash_rest(op.parts, op.len, op.whole * op.subtree_len, op.rest);
            return @splat(0);
        }
        return subtree_cv(op.parts, index * op.subtree_len, op.subtree_len / chunk_len);
    }
};

/// The BLAKE3 digest of the `len`-byte concatenation of `parts`, which spans more than one
/// chunk, with its whole subtrees and its rest hashed across `strategy`.
pub fn hash_subtrees(parts: []const []const u8, len: usize, strategy: anytype) [32]u8 {
    return hash_tree(parts, len, subtree_len_for(len), strategy);
}

/// `hash_subtrees` on the calling thread, in subtrees of `serial_subtree_len` bytes: with no
/// tasks to spread across, longer runs leave fewer narrow merges at their tops.
pub fn hash_serial(parts: []const []const u8, len: usize) [32]u8 {
    return hash_tree(parts, len, serial_subtree_len, parallel.sequential);
}

/// The digest of `parts`, `len` bytes and more than one chunk, cut into aligned subtrees of
/// `subtree_len` bytes and a rest, hashed across `strategy`.
fn hash_tree(parts: []const []const u8, len: usize, subtree_len: usize, strategy: anytype) [32]u8 {
    assert(len > chunk_len);
    assert(std.math.isPowerOfTwo(subtree_len));
    assert(subtree_len >= subtree_len_min and subtree_len <= serial_subtree_len);
    const subtree_chunks = subtree_len / chunk_len;
    // The rest holds the last chunk, and so at least one byte.
    const whole = (len - 1) / subtree_len;
    var rest: Rest = .{};
    const op: SubtreeOp = .{
        .parts = parts,
        .len = len,
        .subtree_len = subtree_len,
        .whole = whole,
        .rest = &rest,
    };
    var stack: Stack = .{};
    var done: usize = 0;
    // Rounds of `round_subtrees` items; the last one also hashes the rest.
    while (done <= whole) {
        const count = @min(round_subtrees, whole + 1 - done);
        var cvs: [round_subtrees]Cv = undefined;
        strategy.map_into(parallel.Range.init(done, done + count), cvs[0..count], op);
        for (cvs[0..count], done..) |cv, index| {
            if (index < whole) stack.push(cv, index * subtree_chunks);
        }
        done += count;
    }
    assert(done == whole + 1);
    for (rest.runs[0..rest.run_count], rest.run_starts[0..rest.run_count]) |cv, start| {
        stack.push(cv, start);
    }
    return finish(stack, rest.last, rest.last_counter);
}

/// The root node of a BLAKE3 tree: the inputs of its last compression, which the XOF repeats
/// with output block counters 0, 1, 2, ... and the root flag.
const Root = struct {
    cv: Cv,
    block: [16]u32,
    block_len: u32,
    flags: u32,
};

/// The root node of the `len`-byte concatenation of `parts`, hashed on the calling thread.
fn root_of(parts: []const []const u8, len: usize) Root {
    var cursor = Cursor.at(parts, 0);
    var scratch: [chunk_len]u8 = undefined;
    // Every chunk but the last, then the last (empty when the message is).
    const before = if (len == 0) 0 else (len - 1) / chunk_len;
    const last_len = len - before * chunk_len;
    // A whole last chunk of a longer message is not the root, so it compresses in the same
    // wide batch as the chunks before it.
    const batched = before + @intFromBool(before > 0 and last_len == chunk_len);
    var stack: Stack = .{};
    var counter: u64 = 0;
    var cvs: [lanes]Cv = undefined;
    var output: Cv = undefined;
    while (counter < batched) {
        const count = @min(lanes, batched - counter);
        chunks_cvs(&cursor, counter, cvs[0..count]);
        for (cvs[0..count], 0..) |cv, index| {
            if (counter + index == before) output = cv else stack.push(cv, counter + index);
        }
        counter += count;
    }
    counter = before;
    if (batched == before) {
        const last = if (last_len == 0) &.{} else cursor.take(last_len, &scratch);
        if (before == 0) return chunk_root(last);
        output = last_chunk_cv(last, counter);
    }
    stack.merge(counter);
    assert(stack.len > 0);
    var index = stack.len;
    while (index > 1) {
        index -= 1;
        output = parent_cv(stack.cvs[index], output, 0);
    }
    var block: [16]u32 = undefined;
    block[0..8].* = stack.cvs[0];
    block[8..16].* = output;
    return .{ .cv = iv, .block = block, .block_len = block_len, .flags = flag_parent };
}

/// The root node of a message of one chunk, `chunk` (0 to `chunk_len` bytes).
fn chunk_root(chunk: []const u8) Root {
    assert(chunk.len <= chunk_len);
    const blocks = @max(1, (chunk.len + block_len - 1) / block_len);
    var cv: [8]Vec(1) = splat_cv(1, iv);
    var bytes: [block_len]u8 = @splat(0);
    var root: Root = undefined;
    for (0..blocks) |block| {
        const start = @min(chunk.len, block * block_len);
        const part = chunk[start..@min(chunk.len, start + block_len)];
        @memset(&bytes, 0);
        @memcpy(bytes[0..part.len], part);
        var flags: u32 = if (block == 0) flag_chunk_start else 0;
        if (block == blocks - 1) {
            flags |= flag_chunk_end;
            var out: [1]Cv = undefined;
            lane_cvs(1, cv, &out);
            root = .{
                .cv = out[0],
                .block = undefined,
                .block_len = @intCast(part.len),
                .flags = flags,
            };
            for (&root.block, 0..) |*word, w| word.* = read_word(bytes[4 * w ..][0..4]);
            break;
        }
        var m: [16]Vec(1) = undefined;
        for (&m, 0..) |*word, w| word.* = @splat(read_word(bytes[4 * w ..][0..4]));
        cv = compress(1, cv, &m, .{
            .counter_low = @splat(0),
            .counter_high = @splat(0),
            .block_len = @splat(block_len),
            .flags = @splat(flags),
        });
    }
    assert(root.flags & flag_chunk_end != 0);
    return root;
}

/// The BLAKE3 digest of the concatenation of `parts`, as std's, with whole chunks compressed
/// `lanes` at a time.
pub fn hash(parts: []const []const u8) [32]u8 {
    var len: usize = 0;
    for (parts) |part| len += part.len;
    const root = root_of(parts, len);
    // The digest is the root's first output block's first half: one one-lane compression,
    // where the XOF would compress `lanes` output blocks.
    var m: [16]Vec(1) = undefined;
    for (&m, root.block) |*word, value| word.* = @splat(value);
    const cv = compress(1, splat_cv(1, root.cv), &m, .{
        .counter_low = @splat(0),
        .counter_high = @splat(0),
        .block_len = @splat(root.block_len),
        .flags = @splat(root.flags | flag_root),
    });
    var out: [32]u8 = undefined;
    inline for (0..8) |w| std.mem.writeInt(u32, out[4 * w ..][0..4], cv[w][0], .little);
    assert(root.flags & flag_root == 0);
    return out;
}

/// BLAKE3's extended output of the concatenation of `parts` into `out`, as std's `final`
/// with `out.len` bytes: the root's output blocks compress `lanes` at a time, as the
/// `blake3` crate's `fill` does.
pub fn xof(parts: []const []const u8, out: []u8) void {
    var len: usize = 0;
    for (parts) |part| len += part.len;
    const root = root_of(parts, len);
    var m: [16]Vec(lanes) = undefined;
    for (&m, root.block) |*word, value| word.* = @splat(value);
    const cv = splat_cv(lanes, root.cv);
    var block_counter: u64 = 0;
    var written: usize = 0;
    while (written < out.len) : (block_counter += lanes) {
        var low: [lanes]u32 = undefined;
        var high: [lanes]u32 = undefined;
        for (&low, &high, 0..) |*l, *h, lane| {
            l.* = @truncate(block_counter + lane);
            h.* = @truncate((block_counter + lane) >> 32);
        }
        const words = compress_full(cv, &m, .{
            .counter_low = low,
            .counter_high = high,
            .block_len = @splat(root.block_len),
            .flags = @splat(root.flags | flag_root),
        });
        var blocks: [lanes][block_len]u8 = undefined;
        for (words, 0..) |word, w| {
            const column: [lanes]u32 = word;
            for (&blocks, column) |*bytes, value| {
                std.mem.writeInt(u32, bytes[4 * w ..][0..4], value, .little);
            }
        }
        const step = @min(out.len - written, lanes * block_len);
        @memcpy(out[written..][0..step], std.mem.asBytes(&blocks)[0..step]);
        written += step;
    }
    assert(written == out.len);
}

/// `compress` with BLAKE3's full 16-word output, which the XOF emits.
fn compress_full(cv: [8]Vec(lanes), m: *const [16]Vec(lanes), words: Words(lanes)) [16]Vec(lanes) {
    @setEvalBranchQuota(20_000);
    var v: [16]Vec(lanes) = undefined;
    inline for (0..8) |i| v[i] = cv[i];
    inline for (0..4) |i| v[8 + i] = @splat(iv[i]);
    v[12] = words.counter_low;
    v[13] = words.counter_high;
    v[14] = words.block_len;
    v[15] = words.flags;
    inline for (0..msg_schedule.len) |r| round(lanes, &v, m, r);
    var out: [16]Vec(lanes) = undefined;
    inline for (0..8) |i| {
        out[i] = v[i] ^ v[i + 8];
        out[i + 8] = v[i + 8] ^ cv[i];
    }
    return out;
}

// `lanes` is 8 in Debug builds and 16 in ReleaseFast on AVX-512, so the 16-lane transposed
// loads get their own check at that width whatever `lanes` is.
test "blake3 16-lane chunk compressions and vector merges match one lane at a time" {
    var random = std.Random.DefaultPrng.init(0x16);
    // Chunks start one byte past an aligned address, so the loads must be unaligned ones.
    var data: [16 * chunk_len + 1]u8 align(64) = undefined;
    random.random().bytes(&data);
    var chunks: [16][*]const u8 = undefined;
    for (&chunks, 0..) |*chunk, lane| chunk.* = data[1 + lane * chunk_len ..].ptr;
    // Lane counters cross the high word of the chunk counter.
    const counter: u64 = (1 << 32) - 5;
    var wide: [16]Cv = undefined;
    chunk_cvs(16, &chunks, counter, &wide);
    for (wide, &chunks, 0..) |cv, *chunk, lane| {
        var one: [1]Cv = undefined;
        chunk_cvs(1, chunk[0..1], counter + lane, &one);
        try std.testing.expectEqualSlices(u32, &one[0], &cv);
    }
    var children: [32]Cv = undefined;
    random.random().bytes(std.mem.asBytes(&children));
    var left: [8]Vec(16) = undefined;
    var right: [8]Vec(16) = undefined;
    for (0..8) |w| {
        var low: [16]u32 = undefined;
        var high: [16]u32 = undefined;
        for (&low, &high, 0..) |*l, *h, lane| {
            l.* = children[lane][w];
            h.* = children[16 + lane][w];
        }
        left[w] = low;
        right[w] = high;
    }
    var parents: [16]Cv = undefined;
    lane_cvs(16, parent_nodes(16, left, right), &parents);
    for (parents, 0..) |cv, lane| {
        const expected = parent_cv(children[2 * lane], children[2 * lane + 1], 0);
        try std.testing.expectEqualSlices(u32, &expected, &cv);
    }
    // The 16 nodes of the left batch collapse to the subtree their pairs build.
    var level = children[0..16].*;
    var count: usize = 16;
    while (count > 1) : (count /= 2) {
        for (0..count / 2) |i| level[i] = parent_cv(level[2 * i], level[2 * i + 1], 0);
    }
    try std.testing.expectEqualSlices(u32, &level[0], &collapse(16, left));
}
