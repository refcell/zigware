//! Compressed zstd blocks (RFC 8878 §3.1.1.3): a literals section (raw, RLE, or Huffman) and
//! a sequences section whose literal length, offset, and match length codes each use the
//! predefined, RLE, or a fresh FSE table, whichever costs fewest bits.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const zstd_std = std.compress.zstd;
const bits = @import("bits.zig");
const fse = @import("fse.zig");
const huffman = @import("huffman.zig");
const match = @import("match.zig");

const block_size_max = zstd_std.block_size_max;
/// Literals below this count stay raw; a Huffman tree would not pay for itself.
const huffman_literals_min = 32;

/// Per-frame encoder state, allocated once per compressed frame.
pub const Context = struct {
    matcher: match.Matcher,
    sequences: []match.Sequence,
    literals: []u8,
    ll_codes: []u8,
    ml_codes: []u8,
    of_codes: []u8,
    /// A block's encoded content; never larger than the raw block.
    out: []u8,
    huffman_scratch: huffman.Scratch,

    pub fn create(gpa: Allocator, len: usize) Allocator.Error!*Context {
        const block_len: usize = @max(1, @min(len, block_size_max));
        const context = try gpa.create(Context);
        errdefer gpa.destroy(context);
        context.matcher = try .init(gpa, len);
        errdefer context.matcher.deinit(gpa);
        const sequences_max = block_len / match.match_length_min + 1;
        context.sequences = try gpa.alloc(match.Sequence, sequences_max);
        errdefer gpa.free(context.sequences);
        // One allocation for the literals, the three code arrays, and the output.
        const bytes = try gpa.alloc(u8, 2 * block_len + 3 * sequences_max);
        context.literals = bytes[0..block_len];
        context.out = bytes[block_len..][0..block_len];
        context.ll_codes = bytes[2 * block_len ..][0..sequences_max];
        context.ml_codes = bytes[2 * block_len + sequences_max ..][0..sequences_max];
        context.of_codes = bytes[2 * block_len + 2 * sequences_max ..][0..sequences_max];
        assert(context.of_codes.len == sequences_max);
        return context;
    }

    pub fn destroy(context: *Context, gpa: Allocator) void {
        const block_len = context.literals.len;
        const sequences_max = context.sequences.len;
        gpa.free(context.literals.ptr[0 .. 2 * block_len + 3 * sequences_max]);
        gpa.free(context.sequences);
        context.matcher.deinit(gpa);
        gpa.destroy(context);
    }

    /// The compressed content of block `src[start..end]`, or null when it would not be
    /// smaller than the raw block (the repeat offsets are then left as they were).
    pub fn compress(context: *Context, src: []const u8, start: usize, end: usize) ?[]const u8 {
        assert(start < end and end - start <= context.out.len);
        const repeats = context.matcher.repeats;
        var literals_len: usize = 0;
        const count = context.matcher.find(
            src,
            start,
            end,
            context.sequences,
            context.literals,
            &literals_len,
        );
        const budget = context.out[0 .. end - start - 1];
        const literals = context.literals[0..literals_len];
        const result = context.encode(literals, count, budget);
        if (result == null) context.matcher.repeats = repeats;
        assert(result == null or result.?.len < end - start);
        return result;
    }

    fn encode(context: *Context, literals: []const u8, count: usize, out: []u8) ?[]const u8 {
        assert(count <= context.sequences.len);
        const literals_size = write_literals(&context.huffman_scratch, literals, out) orelse
            return null;
        const sequences_size = context.write_sequences(count, out[literals_size..]) orelse
            return null;
        assert(literals_size + sequences_size <= out.len);
        return out[0 .. literals_size + sequences_size];
    }

    fn write_sequences(context: *Context, count: usize, out: []u8) ?usize {
        const header_size = write_sequence_count(count, out) orelse return null;
        if (count == 0) return header_size;
        var counts: Counts = .{};
        for (context.sequences[0..count], 0..) |sequence, i| {
            context.ll_codes[i] = literal_length_code(sequence.literal_length);
            context.ml_codes[i] = match_length_code(sequence.match_length);
            context.of_codes[i] = offset_code(sequence.offset_value);
            counts.ll[context.ll_codes[i]] += 1;
            counts.ml[context.ml_codes[i]] += 1;
            counts.of[context.of_codes[i]] += 1;
        }
        const n: u32 = @intCast(count);
        const log_max = zstd_std.table_accuracy_log_max;
        const ll = choose_mode(&counts.ll, n, &predefined_ll, log_max.literal);
        const of = choose_mode(&counts.of, n, &predefined_of, log_max.offset);
        const ml = choose_mode(&counts.ml, n, &predefined_ml, log_max.match);
        var position = header_size;
        if (position >= out.len) return null;
        out[position] = (@as(u8, @backingInt(ll.mode)) << 6) |
            (@as(u8, @backingInt(of.mode)) << 4) | (@as(u8, @backingInt(ml.mode)) << 2);
        position += 1;
        for ([_]*const Choice{ &ll, &of, &ml }) |choice| {
            position += choice.write(out[position..]) orelse return null;
        }
        const tables: Tables = .{ .ll = .init(&ll), .of = .init(&of), .ml = .init(&ml) };
        var stream: bits.Writer = .init(out[position..]);
        context.encode_sequences(count, &tables, &stream);
        const stream_bytes = stream.finish_marked() orelse return null;
        return position + stream_bytes.len;
    }

    /// Writes the sequences last to first, so the decoder reads them first to last: initial
    /// states, then per sequence the offset, match, and literal extra bits, then the literal,
    /// match, and offset state updates.
    fn encode_sequences(
        context: *Context,
        count: usize,
        tables: *const Tables,
        w: *bits.Writer,
    ) void {
        assert(count > 0);
        const last = count - 1;
        var ll = tables.ll.start(context.ll_codes[last]);
        var ml = tables.ml.start(context.ml_codes[last]);
        var of = tables.of.start(context.of_codes[last]);
        context.add_extra_bits(last, w);
        var index = last;
        while (index > 0) {
            index -= 1;
            tables.of.encode(&of, w, context.of_codes[index]);
            tables.ml.encode(&ml, w, context.ml_codes[index]);
            tables.ll.encode(&ll, w, context.ll_codes[index]);
            context.add_extra_bits(index, w);
        }
        tables.ml.flush(ml, w);
        tables.of.flush(of, w);
        tables.ll.flush(ll, w);
        assert(index == 0);
    }

    fn add_extra_bits(context: *const Context, index: usize, w: *bits.Writer) void {
        const sequence = context.sequences[index];
        const ll = zstd_std.literals_length_code_table[context.ll_codes[index]];
        const ml = zstd_std.match_length_code_table[context.ml_codes[index]];
        const of_code = context.of_codes[index];
        assert(sequence.literal_length >= ll[0] and sequence.match_length >= ml[0]);
        w.add(sequence.literal_length - ll[0], ll[1]);
        w.add(sequence.match_length - ml[0], ml[1]);
        w.add(sequence.offset_value - (@as(u32, 1) << @intCast(of_code)), @intCast(of_code));
    }
};

const Counts = struct {
    ll: [36]u32 = @splat(0),
    ml: [53]u32 = @splat(0),
    of: [32]u32 = @splat(0),
};

const Mode = enum(u2) { predefined = 0, rle = 1, fse = 2 };

const Choice = struct {
    mode: Mode,
    distribution: fse.Distribution,
    rle_symbol: u8 = 0,

    fn write(choice: *const Choice, out: []u8) ?usize {
        switch (choice.mode) {
            .predefined => return 0,
            .rle => {
                if (out.len == 0) return null;
                out[0] = choice.rle_symbol;
                return 1;
            },
            .fse => {
                var writer: bits.Writer = .init(out);
                fse.write_description(&choice.distribution, &writer);
                const bytes = writer.finish_aligned() orelse return null;
                assert(bytes.len > 0);
                return bytes.len;
            },
        }
    }
};

/// An FSE table, or nothing for RLE (the decoder reads no bits for it).
const CodeTable = struct {
    table: ?fse.Table,

    fn init(choice: *const Choice) CodeTable {
        if (choice.mode == .rle) return .{ .table = null };
        return .{ .table = .init(&choice.distribution) };
    }

    fn start(self: *const CodeTable, symbol: u8) fse.State {
        const table = &(self.table orelse return .{ .value = 0 });
        return .init(table, symbol);
    }

    fn encode(self: *const CodeTable, state: *fse.State, w: *bits.Writer, symbol: u8) void {
        if (self.table) |*table| state.encode(table, w, symbol);
    }

    fn flush(self: *const CodeTable, state: fse.State, w: *bits.Writer) void {
        if (self.table) |*table| state.flush(table, w);
    }
};

const Tables = struct { ll: CodeTable, of: CodeTable, ml: CodeTable };

const predefined_ll: fse.Distribution = .predefined(
    &zstd_std.literals_length_default_distribution,
    zstd_std.default_accuracy_log.literal,
);
const predefined_ml: fse.Distribution = .predefined(
    &zstd_std.match_lengths_default_distribution,
    zstd_std.default_accuracy_log.match,
);
const predefined_of: fse.Distribution = .predefined(
    &zstd_std.offset_codes_default_distribution,
    zstd_std.default_accuracy_log.offset,
);

/// The cheapest of the predefined table, RLE, and a fresh FSE table for `counts`.
fn choose_mode(
    counts: []const u32,
    total: u32,
    predefined: *const fse.Distribution,
    max_log: u4,
) Choice {
    assert(total > 0);
    var distinct: usize = 0;
    var max_symbol: u8 = 0;
    for (counts, 0..) |count, symbol| {
        if (count == 0) continue;
        distinct += 1;
        max_symbol = @intCast(symbol);
    }
    assert(distinct > 0);
    if (distinct == 1) return .{ .mode = .rle, .distribution = .{}, .rle_symbol = max_symbol };
    const log = fse.optimal_accuracy_log(max_log, total, max_symbol);
    const fresh = fse.normalize(counts[0 .. @as(usize, max_symbol) + 1], log);
    var description: [128]u8 = undefined;
    var writer: bits.Writer = .init(&description);
    fse.write_description(&fresh, &writer);
    const description_len = if (writer.finish_aligned()) |bytes| bytes.len else description.len;
    const description_bits: f64 = @floatFromInt(8 * description_len);
    const fresh_cost = fresh.cost(counts).? + description_bits;
    if (predefined.cost(counts)) |predefined_cost| {
        if (predefined_cost <= fresh_cost) {
            return .{ .mode = .predefined, .distribution = predefined.* };
        }
    }
    return .{ .mode = .fse, .distribution = fresh };
}

fn write_sequence_count(count: usize, out: []u8) ?usize {
    assert(count < 0x7F00 + 0x10000);
    if (out.len < 3) return null;
    if (count < 128) {
        out[0] = @intCast(count);
        return 1;
    }
    if (count < 0x7F00) {
        out[0] = @intCast((count >> 8) + 128);
        out[1] = @truncate(count);
        return 2;
    }
    out[0] = 255;
    std.mem.writeInt(u16, out[1..3], @intCast(count - 0x7F00), .little);
    return 3;
}

/// The largest code whose baseline is at most `value`, for small values.
fn small_codes(comptime table: anytype, comptime len: usize, comptime bias: u32) [len]u8 {
    @setEvalBranchQuota(100_000);
    var codes: [len]u8 = undefined;
    for (&codes, 0..) |*code, value| {
        var best: u8 = 0;
        for (table, 0..) |entry, c| {
            if (entry[0] - bias <= value) best = c;
        }
        code.* = best;
    }
    return codes;
}

const ll_small = small_codes(zstd_std.literals_length_code_table, 64, 0);
const ml_small = small_codes(zstd_std.match_length_code_table, 128, 3);

fn literal_length_code(length: u32) u8 {
    const code: u8 = if (length < 64)
        ll_small[length]
    else
        @as(u8, std.math.log2_int(u32, length)) + 19;
    const entry = zstd_std.literals_length_code_table[code];
    assert(entry[0] <= length and length - entry[0] < @as(u64, 1) << entry[1]);
    return code;
}

fn match_length_code(length: u32) u8 {
    assert(length >= 3);
    const base = length - 3;
    const code: u8 = if (base < 128) ml_small[base] else @as(u8, std.math.log2_int(u32, base)) + 36;
    const entry = zstd_std.match_length_code_table[code];
    assert(entry[0] <= length and length - entry[0] < @as(u64, 1) << entry[1]);
    return code;
}

fn offset_code(offset_value: u32) u8 {
    assert(offset_value > 0);
    const code = std.math.log2_int(u32, offset_value);
    assert(code < 32);
    return code;
}

/// Writes the literals section: Huffman when it is smaller than raw, RLE for one repeated
/// byte, raw otherwise.
fn write_literals(scratch: *huffman.Scratch, literals: []const u8, out: []u8) ?usize {
    const n = literals.len;
    if (n > 0 and std.mem.allEqual(u8, literals, literals[0])) {
        const header = write_raw_header(1, n, out) orelse return null;
        if (header >= out.len) return null;
        out[header] = literals[0];
        return header + 1;
    }
    if (n >= huffman_literals_min) {
        if (write_huffman_literals(scratch, literals, out)) |size| return size;
    }
    const header = write_raw_header(0, n, out) orelse return null;
    if (header + n > out.len) return null;
    @memcpy(out[header..][0..n], literals);
    return header + n;
}

fn write_raw_header(block_type: u8, n: usize, out: []u8) ?usize {
    assert(block_type <= 1);
    assert(n < 1 << 20);
    if (out.len < 3) return null;
    if (n < 32) {
        out[0] = block_type | @as(u8, @intCast(n << 3));
        return 1;
    }
    if (n < 4096) {
        out[0] = block_type | (1 << 2) | @as(u8, @intCast((n & 0xF) << 4));
        out[1] = @intCast(n >> 4);
        return 2;
    }
    out[0] = block_type | (3 << 2) | @as(u8, @intCast((n & 0xF) << 4));
    out[1] = @truncate(n >> 4);
    out[2] = @intCast(n >> 12);
    return 3;
}

/// Huffman literals, or null when they are not smaller than raw ones.
fn write_huffman_literals(scratch: *huffman.Scratch, literals: []const u8, out: []u8) ?usize {
    const n = literals.len;
    assert(n >= huffman_literals_min);
    var counts: [256]u32 = @splat(0);
    for (literals) |byte| counts[byte] += 1;
    const code = huffman.build(&counts, scratch) orelse return null;
    const estimate = code.cost_bits(&counts) / 8 + 8;
    if (estimate >= n) return null;
    const header_max = 5;
    const raw_size = n + 3;
    if (out.len < header_max + 1) return null;
    const body = out[header_max..out.len];
    const tree_size = huffman.write_description(&code, body) orelse return null;
    // The tree and streams together must stay below the raw section.
    const limit = @min(body.len, raw_size);
    if (tree_size >= limit) return null;
    const streams = huffman.encode_literals(&code, literals, body[tree_size..limit]) orelse
        return null;
    const compressed = tree_size + streams;
    const header = compressed_header_size(n, compressed);
    if (header + compressed >= raw_size) return null;
    std.mem.copyForwards(u8, out[header..][0..compressed], body[0..compressed]);
    write_compressed_header(n, compressed, out[0..header]);
    return header + compressed;
}

fn compressed_header_size(regenerated: usize, compressed: usize) usize {
    const largest = @max(regenerated, compressed);
    assert(largest < 1 << 18);
    if (largest < 1024) return 3;
    if (largest < 16384) return 4;
    return 5;
}

fn write_compressed_header(regenerated: usize, compressed: usize, out: []u8) void {
    const one_stream = regenerated < 256;
    const r: u32 = @intCast(regenerated);
    const c: u32 = @intCast(compressed);
    const size_format: u8 = switch (out.len) {
        3 => if (one_stream) 0 else 1,
        4 => 2,
        5 => 3,
        else => unreachable,
    };
    assert(!one_stream or size_format == 0);
    out[0] = 2 | (size_format << 2) | @as(u8, @truncate((r & 0xF) << 4));
    switch (size_format) {
        0, 1 => {
            out[1] = @truncate(((r >> 4) & 0x3F) | ((c & 0x3) << 6));
            out[2] = @truncate(c >> 2);
        },
        2 => {
            out[1] = @truncate(r >> 4);
            out[2] = @truncate(((r >> 12) & 0x3) | ((c & 0x3F) << 2));
            out[3] = @truncate(c >> 6);
        },
        else => {
            out[1] = @truncate(r >> 4);
            out[2] = @truncate(((r >> 12) & 0x3F) | ((c & 0x3) << 6));
            out[3] = @truncate(c >> 2);
            out[4] = @truncate(c >> 10);
        },
    }
}

const testing = std.testing;

test "length codes match the code tables" {
    // Every length a block can need: up to 128 KiB of literals or of match.
    for (0..131_072) |value| _ = literal_length_code(@intCast(value));
    for (3..131_075) |value| _ = match_length_code(@intCast(value));
    try testing.expectEqual(@as(u8, 35), literal_length_code(131_071));
    try testing.expectEqual(@as(u8, 52), match_length_code(131_074));
    try testing.expectEqual(@as(u8, 17), offset_code(131_074));
}
