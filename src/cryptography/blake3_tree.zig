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
        var rows: [n][16]u32 = undefined;
        for (&rows, chunks) |*row, chunk| {
            const bytes = chunk + block * block_len;
            for (row, 0..) |*word, w| word.* = read_word(bytes[4 * w ..][0..4]);
        }
        var m: [16]Vec(n) = undefined;
        for (&m, 0..) |*word, w| {
            inline for (0..n) |lane| word[lane] = rows[lane][w];
        }
        var flags: u32 = 0;
        if (block == 0) flags |= flag_chunk_start;
        if (block == blocks_per_chunk - 1) flags |= flag_chunk_end;
        cv = compress(n, cv, &m, .{
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
        const width: usize = @min(lanes, std.math.ceilPowerOfTwoAssert(usize, count));
        assert(width >= count and width < 2 * count);
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

/// The chaining values of a message's rest, the bytes after its last whole subtree: its whole
/// chunks as aligned runs of decreasing powers of two, then its last chunk.
const Rest = struct {
    /// A rest of fewer than `subtree_chunks_max` whole chunks has at most this many runs.
    const runs_max = std.math.log2_int(usize, subtree_chunks_max);

    runs: [runs_max]Cv = undefined,
    run_starts: [runs_max]u64 = undefined,
    run_count: usize = 0,
    last: Cv = undefined,
    last_counter: u64 = 0,
};

comptime {
    assert(@popCount(@as(usize, subtree_chunks_max - 1)) <= Rest.runs_max);
}

/// Hashes the rest of the `len`-byte message `parts` from byte `offset`, a subtree boundary.
fn hash_rest(parts: []const []const u8, len: usize, offset: usize, rest: *Rest) void {
    assert(offset < len);
    // A whole last chunk compresses in the same batch as the others; only its merge into the
    // root differs.
    const rest_len = len - offset;
    const last_whole = rest_len % chunk_len == 0;
    const rest_chunks = (rest_len - 1) / chunk_len;
    const batched = rest_chunks + @intFromBool(last_whole);
    assert(batched <= subtree_chunks_max);
    var cursor = Cursor.at(parts, offset);
    var cvs: [subtree_chunks_max]Cv = undefined;
    const first = offset / chunk_len;
    chunks_cvs(&cursor, first, cvs[0..batched]);
    // Merge the whole chunks as aligned runs, so the stack takes one entry per run and every
    // merge inside a run runs at full width.
    rest.run_count = 0;
    var merged: usize = 0;
    while (merged < rest_chunks) {
        const run = std.math.floorPowerOfTwo(usize, rest_chunks - merged);
        assert((first + merged) % run == 0);
        rest.runs[rest.run_count] = merge_subtree(cvs[merged..][0..run]);
        rest.run_starts[rest.run_count] = first + merged;
        rest.run_count += 1;
        merged += run;
    }
    assert(merged == rest_chunks);
    rest.last_counter = first + rest_chunks;
    if (last_whole) {
        rest.last = cvs[rest_chunks];
        return;
    }
    var scratch: [chunk_len]u8 = undefined;
    const last = cursor.take(rest_len - rest_chunks * chunk_len, &scratch);
    rest.last = last_chunk_cv(last, rest.last_counter);
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
    assert(len > chunk_len);
    const subtree_len = subtree_len_for(len);
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
