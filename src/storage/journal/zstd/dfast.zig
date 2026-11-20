//! libzstd 1.5.7's double-fast match finder without a dictionary
//! (`ZSTD_compressBlock_doubleFast_noDict_generic` in `zstd_double_fast.c`), the strategy of
//! level 3. It must find exactly libzstd's sequences, so it follows the C step by step: the
//! same hashes, table updates, skip schedule, repeat checks, and complementary insertions.
//!
//! Positions are indexes into the frame; libzstd's window indexes are positions plus the
//! frame's `base`. A fresh state starts at `start_index`, so table entries 0 and 1 are never
//! valid matches; a reused one starts each frame where the last ended (`restart`), so every
//! entry an earlier frame left is below the window and the tables need no clearing.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Params = @import("params.zig").Params;

/// `ZSTD_WINDOW_START_INDEX`: the window index of the frame's first byte.
pub const start_index: u32 = 2;
/// `ZSTD_REP_NUM`: an `off_base` at or below it selects a repeat offset.
pub const rep_num = 3;
/// `kSearchStrength`: the skip step grows after this many log2 positions without a match.
const search_strength = 8;
/// `HASH_READ_SIZE`: hashing reads this many bytes, so positions stop that far from the end.
const hash_read_size = 8;
/// The window index past which `restart` clears the tables and starts again from
/// `start_index` (libzstd's `ZSTD_indexTooCloseToMax`; any bound gives the same frames).
const index_max: u32 = 1 << 31;
/// `MINMATCH`: match lengths are stored minus this.
pub const match_min = 3;

/// What `select_equal` reads for an index outside the window (libzstd's `dummy`).
const select_backup = [8]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };

const prime4: u32 = 2654435761;
const prime5: u64 = 889523592379;
const prime8: u64 = 0xCF1BBCDCB7A56463;

/// One `SeqDef`: `literal_length` literals, then `match_length` bytes copied from `off_base`
/// (1 to 3 select a repeat offset, larger values are the offset plus 3).
pub const Sequence = struct {
    literal_length: u32,
    off_base: u32,
    match_length: u32,
};

/// The match state of one frame: the two hash tables and the window limits.
pub const State = struct {
    /// `hashTable`: positions hashed on 8 bytes.
    long: []u32,
    /// `chainTable`: positions hashed on `min_match` bytes.
    short: []u32,
    /// The allocated lengths of `long` and `short`, which a smaller frame uses a prefix of.
    long_capacity: usize,
    short_capacity: usize,
    long_log: u6,
    short_log: u6,
    min_match: u6,
    window_log: u6,
    low_limit: u32 = start_index,
    dict_limit: u32 = start_index,
    /// The window index of the frame's first byte.
    base: u32 = start_index,
    /// The window index past the last block's end, where the next frame starts.
    end_index: u32 = start_index,

    pub fn init(gpa: Allocator, params: Params) Allocator.Error!State {
        assert(params.min_match >= 4 and params.min_match <= 5);
        assert(params.hash_log <= 32 and params.chain_log <= 32);
        const long = try gpa.alloc(u32, @as(usize, 1) << params.hash_log);
        errdefer gpa.free(long);
        const short = try gpa.alloc(u32, @as(usize, 1) << params.chain_log);
        var state: State = .{
            .long = long,
            .short = short,
            .long_capacity = long.len,
            .short_capacity = short.len,
            .long_log = undefined,
            .short_log = undefined,
            .min_match = undefined,
            .window_log = undefined,
        };
        state.reset(params);
        return state;
    }

    pub fn deinit(self: *State, gpa: Allocator) void {
        gpa.free(self.long.ptr[0..self.long_capacity]);
        gpa.free(self.short.ptr[0..self.short_capacity]);
        self.* = undefined;
    }

    /// Whether `reset` can take `params` without growing the tables.
    pub fn fits(self: *const State, params: Params) bool {
        return (@as(usize, 1) << params.hash_log) <= self.long_capacity and
            (@as(usize, 1) << params.chain_log) <= self.short_capacity;
    }

    /// Start a new frame with `params` in the same tables: every entry cleared and the
    /// window back at its start, as `ZSTD_resetCCtx_internal` leaves a reused context.
    pub fn reset(self: *State, params: Params) void {
        assert(params.min_match >= 4 and params.min_match <= 5);
        assert(self.fits(params));
        self.long = self.long.ptr[0 .. @as(usize, 1) << params.hash_log];
        self.short = self.short.ptr[0 .. @as(usize, 1) << params.chain_log];
        @memset(self.long, 0);
        @memset(self.short, 0);
        self.long_log = params.hash_log;
        self.short_log = params.chain_log;
        self.min_match = params.min_match;
        self.window_log = params.window_log;
        self.low_limit = start_index;
        self.dict_limit = start_index;
        self.base = start_index;
        self.end_index = start_index;
    }

    /// Start a new frame of `len` bytes with `params`, as `ZSTD_resetCCtx_internal` restarts a
    /// reused context (`ZSTDirp_continue`): the frame's indexes continue past the last frame's
    /// end and the window starts there, so stale entries never match and the tables stay as
    /// they are. Near `index_max` it clears them instead, as `reset` does.
    pub fn restart(self: *State, params: Params, len: usize) void {
        assert(self.fits(params));
        assert(self.end_index >= self.base);
        if (len > index_max or self.end_index > index_max - len) return self.reset(params);
        self.long = self.long.ptr[0 .. @as(usize, 1) << params.hash_log];
        self.short = self.short.ptr[0 .. @as(usize, 1) << params.chain_log];
        self.long_log = params.hash_log;
        self.short_log = params.chain_log;
        self.min_match = params.min_match;
        self.window_log = params.window_log;
        self.base = self.end_index;
        self.low_limit = self.base;
        self.dict_limit = self.base;
        assert(self.low_limit == self.base);
    }

    /// `ZSTD_window_enforceMaxDist` before compressing a block ending at position `end`.
    pub fn enforce_max_dist(self: *State, end: usize) void {
        const block_end_index = index_of(self.base, end);
        assert(block_end_index >= self.end_index or self.end_index == self.base);
        self.end_index = block_end_index;
        const max_dist = @as(u32, 1) << @intCast(self.window_log);
        if (block_end_index > max_dist) {
            self.low_limit = @max(self.low_limit, block_end_index - max_dist);
            self.dict_limit = @max(self.dict_limit, self.low_limit);
        }
        assert(self.dict_limit >= self.low_limit);
    }

    /// `ZSTD_getLowestPrefixIndex` for window index `current`.
    fn lowest_prefix_index(self: *const State, current: u32) u32 {
        const max_distance = @as(u32, 1) << @intCast(self.window_log);
        assert(current >= self.dict_limit);
        if (current - self.dict_limit > max_distance) return current - max_distance;
        return self.dict_limit;
    }
};

fn index_of(base: u32, position: usize) u32 {
    return @intCast(position + base);
}

fn read32(src: []const u8, position: usize) u32 {
    return std.mem.readInt(u32, src[position..][0..4], .little);
}

fn read64(src: []const u8, position: usize) u64 {
    return std.mem.readInt(u64, src[position..][0..8], .little);
}

fn hash8(src: []const u8, position: usize, log: u6) usize {
    return hash8_word(read64(src, position), log);
}

/// `hash8` of the 8 bytes `word` holds (read little-endian).
fn hash8_word(word: u64, log: u6) usize {
    assert(log > 0 and log <= 32);
    return @intCast((word *% prime8) >> @intCast(64 - @as(u7, log)));
}

/// `ZSTD_hashPtr` with `mls` 4 or 5.
fn hash_short(src: []const u8, position: usize, log: u6, min_match: u6) usize {
    assert(min_match == 4 or min_match == 5);
    return if (min_match == 4)
        hash_short_mls(src, position, log, 4)
    else
        hash_short_mls(src, position, log, 5);
}

/// `hash_short` for a `min_match` known at compile time, as libzstd templates its loop on.
fn hash_short_mls(src: []const u8, position: usize, log: u6, comptime min_match: u6) usize {
    return hash_short_word(read64(src, position), log, min_match);
}

/// `hash_short_mls` of the 8 bytes `word` holds (read little-endian).
fn hash_short_word(word: u64, log: u6, comptime min_match: u6) usize {
    assert(log > 0 and log <= 32);
    if (min_match == 4) {
        const low: u32 = @truncate(word);
        return @intCast((low *% prime4) >> @intCast(32 - @as(u6, log)));
    }
    comptime assert(min_match == 5);
    return @intCast(((word << 24) *% prime5) >> @intCast(64 - @as(u7, log)));
}

/// The 8 or 4 bytes at `address`, little-endian.
fn load64(address: usize) u64 {
    return std.mem.readInt(u64, @as(*const [8]u8, @ptrFromInt(address)), .little);
}

fn load32(address: usize) u32 {
    return std.mem.readInt(u32, @as(*const [4]u8, @ptrFromInt(address)), .little);
}

/// `ZSTD_count`: equal bytes at `a` and `b`, counting only bytes of `a` before `limit`. Like
/// libzstd, it compares eight bytes at a time and finds the first differing byte from the
/// XOR's trailing zeros (the words are read little-endian), then finishes byte by byte.
pub fn count(src: []const u8, a: usize, b: usize, limit: usize) u32 {
    assert(b < a and limit <= src.len);
    var length: usize = 0;
    // Skip 32 equal bytes at a time; the word loop below finds the difference in a block
    // that has one.
    const Lane = @Vector(32, u8);
    while (a + length + 32 <= limit) : (length += 32) {
        const left: Lane = src[a + length ..][0..32].*;
        const right: Lane = src[b + length ..][0..32].*;
        if (@reduce(.Or, left ^ right) != 0) break;
    }
    while (a + length + 8 <= limit) {
        const difference = read64(src, a + length) ^ read64(src, b + length);
        if (difference != 0) return @intCast(length + @ctz(difference) / 8);
        length += 8;
    }
    while (a + length < limit and src[a + length] == src[b + length]) length += 1;
    assert(a + length <= limit);
    return @intCast(length);
}

/// Find the sequences of block `src[start..end]`, appending them to `sequences` (which must
/// have room for `end - start` of them) and updating `rep` as libzstd's block compressor
/// does. Returns the length of the trailing literals.
pub fn compress_block(
    state: *State,
    src: []const u8,
    start: usize,
    end: usize,
    sequences: *std.ArrayList(Sequence),
    rep: *[rep_num]u32,
) u32 {
    assert(start < end and end <= src.len);
    assert(sequences.unusedCapacitySlice().len >= end - start);
    var block: Block = .{
        .state = state,
        .src = src,
        .end = end,
        .anchor = start,
        .ip = start,
        .sequences = sequences,
        .offset_1 = rep[0],
        .offset_2 = rep[1],
        .base = state.base,
        .prefix_lowest_index = state.lowest_prefix_index(index_of(state.base, end)),
    };
    block.prefix_lowest = block.prefix_lowest_index - state.base;
    assert(block.prefix_lowest <= start);
    block.prepare();
    block.run();
    // If offset_1 started invalid and became valid, rotate the saved offsets.
    if (block.saved_1 != 0 and block.offset_1 != 0) block.saved_2 = block.saved_1;
    rep[0] = if (block.offset_1 != 0) block.offset_1 else block.saved_1;
    rep[1] = if (block.offset_2 != 0) block.offset_2 else block.saved_2;
    assert(block.anchor <= end);
    return @intCast(end - block.anchor);
}

const Found = union(enum) {
    /// A repeat match found at `ip + 1` (already stored).
    stored: u32,
    /// A long or short match at `ip` with `offset` and `length`.
    match: struct { offset: u32, length: u32 },
    /// No match before the block's limit.
    none,
};

const Block = struct {
    state: *State,
    src: []const u8,
    end: usize,
    anchor: usize,
    ip: usize,
    sequences: *std.ArrayList(Sequence),
    offset_1: u32,
    offset_2: u32,
    saved_1: u32 = 0,
    saved_2: u32 = 0,
    /// The frame's `State.base`.
    base: u32,
    prefix_lowest_index: u32,
    prefix_lowest: usize = 0,
    /// Window index of the last position inserted by the search (`curr`).
    current: u32 = 0,
    step: usize = 1,
    /// The next position's long hash and position (`hl1`, `ip1`), for `found`.
    hash_next: usize = 0,
    ip_next: usize = 0,

    /// Skip the window's first byte and drop repeat offsets reaching before the window.
    fn prepare(block: *Block) void {
        if (block.ip == block.prefix_lowest) block.ip += 1;
        const current = index_of(block.base, block.ip);
        const window_low = block.state.lowest_prefix_index(current);
        const rep_max = current - window_low;
        if (block.offset_2 > rep_max) {
            block.saved_2 = block.offset_2;
            block.offset_2 = 0;
        }
        if (block.offset_1 > rep_max) {
            block.saved_1 = block.offset_1;
            block.offset_1 = 0;
        }
        assert(block.offset_1 <= rep_max and block.offset_2 <= rep_max);
    }

    /// Whether `position` may be hashed: at most `ilimit = iend - HASH_READ_SIZE`.
    fn in_limit(block: *const Block, position: usize) bool {
        return position + hash_read_size <= block.end;
    }

    fn store(block: *Block, literal_length: usize, off_base: u32, match_length: u32) void {
        assert(match_length >= match_min + 1);
        assert(block.anchor + literal_length + match_length <= block.end);
        block.sequences.appendAssumeCapacity(.{
            .literal_length = @intCast(literal_length),
            .off_base = off_base,
            .match_length = match_length,
        });
    }

    fn run(block: *Block) void {
        while (true) {
            const found = block.search();
            switch (found) {
                .none => return,
                .stored => |length| block.after_match(length),
                .match => |match| {
                    block.offset_2 = block.offset_1;
                    block.offset_1 = match.offset;
                    // Safe while ip1 cannot pass the match end (step under the 4-byte
                    // minimum match).
                    if (block.step < 4) block.state.long[block.hash_next] =
                        index_of(block.base, block.ip_next);
                    const literal_length = block.ip - block.anchor;
                    block.store(literal_length, match.offset + rep_num, match.length);
                    block.after_match(match.length);
                },
            }
        }
    }

    /// The inner loop: one iteration per position searched. The search state lives in locals
    /// and is written back to `block` only when a match ends it: the tables are `u32`s the
    /// compiler cannot prove apart from `block`'s fields, so keeping them there reloaded
    /// them after every table store.
    fn search(block: *Block) Found {
        assert(block.state.min_match == 4 or block.state.min_match == 5);
        const repeat = block.offset_1 > 0;
        if (block.state.min_match == 4) {
            return if (repeat) block.search_mls(4, true) else block.search_mls(4, false);
        }
        return if (repeat) block.search_mls(5, true) else block.search_mls(5, false);
    }

    /// `search` for one `min_match`, with or without a repeat offset to check. Like libzstd
    /// 1.5.7, it reads a candidate through `select_equal` instead of branching on whether its
    /// table entry is in the window: on incompressible input that branch is a coin flip at
    /// every position. Positions are window indexes read through `window` (libzstd's
    /// `base`), and each position's 8 bytes are read once for both hashes and the repeat
    /// check, so the loop's state fits in registers.
    fn search_mls(block: *Block, comptime min_match: u6, comptime repeat: bool) Found {
        const state = block.state;
        const long = state.long;
        const short = state.short;
        const long_log = state.long_log;
        const short_log = state.short_log;
        const lowest = block.prefix_lowest_index;
        const base = block.base;
        assert(lowest >= base);
        assert(repeat == (block.offset_1 > 0));
        if (block.end < hash_read_size) return .none;
        // `ilimit`: the last index that may be hashed.
        const limit = index_of(base, block.end - hash_read_size);
        const window = @intFromPtr(block.src.ptr) -% base;
        // `window + ip + 1 - offset_1`, the repeat candidate of index `ip`'s next byte.
        const repeat_window = window +% 1 -% block.offset_1;
        var ip = index_of(base, block.ip);
        var step: u32 = 1;
        var next_step = ip + (1 << search_strength);
        if (ip + step > limit) return .none;
        var word = load64(window + ip);
        var index_long_0 = blk: {
            const hash_long_0 = hash8_word(word, long_log);
            const index = long[hash_long_0];
            long[hash_long_0] = ip;
            break :blk index;
        };
        // Each iteration enters with `long[hash(ip)]` already set to `ip`: libzstd stores it at
        // the top of the iteration, and nothing reads the long table in between.
        while (true) {
            const ip1 = ip + step;
            assert(ip < ip1 and ip1 <= limit);
            const hash_short_0 = hash_short_word(word, short_log, min_match);
            const index_short_0 = short[hash_short_0];
            short[hash_short_0] = ip;
            if (repeat and load32(repeat_window + ip) == @as(u32, @truncate(word >> 8))) {
                block.resume_at(ip - base, step, 0, 0);
                return block.found_repeat();
            }
            const word_1 = load64(window + ip1);
            const hash_long_1 = hash8_word(word_1, long_log);
            if (select_equal(window, index_long_0, lowest, word, 8)) {
                block.resume_at(ip - base, step, hash_long_1, ip1 - base);
                return block.long_candidate(index_long_0).?;
            }
            const index_long_1 = long[hash_long_1];
            if (select_equal(window, index_short_0, lowest, word, 4)) {
                block.resume_at(ip - base, step, hash_long_1, ip1 - base);
                return block.search_next_long(index_short_0, index_long_1, ip1 - base);
            }
            if (ip1 >= next_step) {
                step += 1;
                next_step += 1 << search_strength;
            }
            ip = ip1;
            word = word_1;
            index_long_0 = index_long_1;
            if (ip + step > limit) {
                block.resume_at(ip - base, step, 0, 0);
                return .none;
            }
            long[hash_long_1] = ip;
        }
    }

    /// Whether the `bytes` (4 or 8) at window index `index` equal `word`'s and `index` is at or
    /// above `lowest`, without branching on the index (`ZSTD_selectAddr`): an index outside
    /// the window reads `select_backup` instead, so the one branch that depends on the data
    /// is on equal bytes, which are rare. The address is chosen with a conditional move the
    /// optimizer cannot turn back into a branch.
    inline fn select_equal(
        window: usize,
        index: u32,
        lowest: u32,
        word: u64,
        comptime bytes: u4,
    ) bool {
        comptime assert(bytes == 4 or bytes == 8);
        const real = window +% index;
        const backup = @intFromPtr(&select_backup);
        const address = if (builtin.cpu.arch == .x86_64) asm (
            \\cmpl %[lowest], %[index]
            \\cmovbq %[backup], %[address]
            : [address] "=r" (-> usize),
            : [real] "0" (real),
              [index] "r" (index),
              [lowest] "r" (lowest),
              [backup] "r" (backup),
            : .{ .cc = true }) else address: {
            // Elsewhere a mask, hidden from the optimizer the same way.
            const keep = asm (""
                : [keep] "=r" (-> usize),
                : [in] "0" (-%@as(usize, @intFromBool(index >= lowest))),
            );
            break :address (real & keep) | (backup & ~keep);
        };
        const mask: u64 = if (bytes == 8) std.math.maxInt(u64) else std.math.maxInt(u32);
        return (load64(address) ^ word) & mask == 0 and address == real;
    }

    /// Write the search's locals back for the match handlers and `run`.
    fn resume_at(block: *Block, ip: usize, step: usize, hash_next: usize, ip_next: usize) void {
        assert(ip >= block.anchor and ip < block.end);
        assert(step >= 1);
        block.ip = ip;
        block.current = index_of(block.base, ip);
        block.step = step;
        block.hash_next = hash_next;
        block.ip_next = ip_next;
    }

    /// `ZSTD_selectAddr`: a table index at or above the prefix's lowest index.
    fn valid(block: *const Block, index: u32) bool {
        return index >= block.prefix_lowest_index;
    }

    fn found_repeat(block: *Block) Found {
        const ip = block.ip + 1;
        const length = count(block.src, ip + 4, ip + 4 - block.offset_1, block.end) + 4;
        block.ip = ip;
        block.store(ip - block.anchor, 1, length);
        return .{ .stored = length };
    }

    /// The long-table match at `ip`, extended backward.
    fn long_candidate(block: *Block, index: u32) ?Found {
        if (!block.valid(index)) return null;
        var match = index - block.base;
        if (read64(block.src, match) != read64(block.src, block.ip)) return null;
        var length = count(block.src, block.ip + 8, match + 8, block.end) + 8;
        const offset: u32 = @intCast(block.ip - match);
        while (block.ip > block.anchor and match > block.prefix_lowest and
            block.src[block.ip - 1] == block.src[match - 1])
        {
            block.ip -= 1;
            match -= 1;
            length += 1;
        }
        return .{ .match = .{ .offset = offset, .length = length } };
    }

    /// A short match at `ip`: prefer the long match at `ip1` when it is longer.
    fn search_next_long(block: *Block, index_short: u32, index_long_1: u32, ip1: usize) Found {
        const src = block.src;
        var match = index_short - block.base;
        var length = count(src, block.ip + 4, match + 4, block.end) + 4;
        var offset: u32 = @intCast(block.ip - match);
        if (index_long_1 > block.prefix_lowest_index) {
            const match_1 = index_long_1 - block.base;
            if (read64(src, match_1) == read64(src, ip1)) {
                const length_1 = count(src, ip1 + 8, match_1 + 8, block.end) + 8;
                if (length_1 > length) {
                    block.ip = ip1;
                    length = length_1;
                    offset = @intCast(ip1 - match_1);
                    match = match_1;
                }
            }
        }
        while (block.ip > block.anchor and match > block.prefix_lowest and
            src[block.ip - 1] == src[match - 1])
        {
            block.ip -= 1;
            match -= 1;
            length += 1;
        }
        assert(offset > 0);
        return .{ .match = .{ .offset = offset, .length = length } };
    }

    /// `_match_stored`: skip the match, insert positions inside it, and take immediate
    /// repeats of `offset_2`.
    fn after_match(block: *Block, length: u32) void {
        const state = block.state;
        const src = block.src;
        block.ip += length;
        block.anchor = block.ip;
        if (!block.in_limit(block.ip)) return;
        const insert = block.current + 2 - block.base;
        state.long[hash8(src, insert, state.long_log)] = block.current + 2;
        const before_end = block.ip - 2;
        state.long[hash8(src, before_end, state.long_log)] = index_of(block.base, before_end);
        state.short[hash_short(src, insert, state.short_log, state.min_match)] = block.current + 2;
        state.short[hash_short(src, block.ip - 1, state.short_log, state.min_match)] =
            index_of(block.base, block.ip - 1);
        while (block.in_limit(block.ip) and block.offset_2 > 0 and
            read32(src, block.ip) == read32(src, block.ip - block.offset_2))
        {
            const ip = block.ip;
            const repeat_length = count(src, ip + 4, ip + 4 - block.offset_2, block.end) + 4;
            std.mem.swap(u32, &block.offset_1, &block.offset_2);
            const index = index_of(block.base, ip);
            state.short[hash_short(src, ip, state.short_log, state.min_match)] = index;
            state.long[hash8(src, ip, state.long_log)] = index;
            block.store(0, 1, repeat_length);
            block.ip += repeat_length;
            block.anchor = block.ip;
        }
    }
};
