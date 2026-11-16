//! Huffman-coded literals (RFC 8878 §4.2): length-limited codes, their tree descriptions
//! (direct or FSE-compressed weights), and one or four literal streams.
//!
//! Code lengths come from package-merge, which gives optimal complete codes of at most
//! `max_bits` bits; zstd needs complete codes because the decoder derives the last symbol's
//! weight from the others. Codes are assigned canonically in the decoder's order: by weight,
//! then by symbol, each weight group continuing from the previous group's last prefix.

const std = @import("std");
const assert = std.debug.assert;
const bits = @import("bits.zig");
const fse = @import("fse.zig");

/// Longest code (libzstd's `HUF_TABLELOG_DEFAULT`).
pub const max_bits = 11;
/// Most FSE-compressed weight bytes a tree description may hold (its header is that count).
const fse_weights_size_max = 127;

pub const Code = struct {
    /// Code length per symbol; 0 for absent symbols.
    lengths: [256]u4 = @splat(0),
    codes: [256]u16 = @splat(0),
    max_length: u4 = 0,
    /// The largest present symbol; its weight is implied by the others.
    last_symbol: u8 = 0,

    fn weight(self: *const Code, symbol: usize) u4 {
        const length = self.lengths[symbol];
        return if (length == 0) 0 else self.max_length + 1 - length;
    }

    /// The bits `counts` take under this code.
    pub fn cost_bits(self: *const Code, counts: *const [256]u32) u64 {
        var sum: u64 = 0;
        for (counts, self.lengths) |count, length| sum += @as(u64, count) * length;
        assert(sum > 0);
        return sum;
    }
};

/// Package-merge levels: level `j` holds `max_bits - j` items' weights and whether each is a
/// leaf. Kept off the stack by the caller.
pub const Scratch = struct {
    weights: [max_bits][511]u64,
    leaf: [max_bits][511]bool,
    len: [max_bits]u16,
    order: [256]u8,
};

/// The optimal code of at most `max_bits` bits for `counts`, or null with fewer than two
/// symbols.
pub fn build(counts: *const [256]u32, scratch: *Scratch) ?Code {
    var keys: [256]u64 = undefined;
    var n: usize = 0;
    for (counts, 0..) |count, symbol| {
        if (count == 0) continue;
        keys[n] = (@as(u64, count) << 8) | symbol;
        n += 1;
    }
    if (n < 2) return null;
    std.mem.sort(u64, keys[0..n], {}, std.sort.asc(u64));
    for (keys[0..n], 0..) |key, rank| scratch.order[rank] = @truncate(key);

    var code: Code = .{};
    package_merge(scratch, keys[0..n]);
    select_lengths(scratch, n, &code);
    assign_codes(&code);
    return code;
}

/// Fills the package-merge levels, deepest (`max_bits - 1`) first.
fn package_merge(scratch: *Scratch, keys: []const u64) void {
    assert(keys.len >= 2 and keys.len <= 256);
    const deepest = max_bits - 1;
    for (keys, 0..) |key, rank| {
        scratch.weights[deepest][rank] = key >> 8;
        scratch.leaf[deepest][rank] = true;
    }
    scratch.len[deepest] = @intCast(keys.len);
    var level: usize = deepest;
    while (level > 0) {
        level -= 1;
        const below = level + 1;
        const packages = scratch.len[below] / 2;
        var leaf_index: usize = 0;
        var package_index: usize = 0;
        var out: usize = 0;
        while (leaf_index < keys.len or package_index < packages) : (out += 1) {
            const package_weight = if (package_index < packages)
                scratch.weights[below][2 * package_index] +
                    scratch.weights[below][2 * package_index + 1]
            else
                std.math.maxInt(u64);
            const take_leaf = leaf_index < keys.len and keys[leaf_index] >> 8 <= package_weight;
            scratch.leaf[level][out] = take_leaf;
            if (take_leaf) {
                scratch.weights[level][out] = keys[leaf_index] >> 8;
                leaf_index += 1;
            } else {
                scratch.weights[level][out] = package_weight;
                package_index += 1;
            }
        }
        scratch.len[level] = @intCast(out);
        assert(out <= 2 * keys.len - 1);
    }
}

/// Takes the first `2n - 2` items of the shallowest level: every leaf among a level's taken
/// items lengthens that symbol's code by one bit, and every package takes two items below.
fn select_lengths(scratch: *const Scratch, n: usize, code: *Code) void {
    assert(n >= 2);
    var lengths: [256]u8 = @splat(0);
    var taken: usize = 2 * n - 2;
    for (0..max_bits) |level| {
        assert(taken <= scratch.len[level]);
        var leaves: usize = 0;
        for (scratch.leaf[level][0..taken]) |is_leaf| leaves += @intFromBool(is_leaf);
        for (scratch.order[0..leaves]) |symbol| lengths[symbol] += 1;
        taken = 2 * (taken - leaves);
    }
    assert(taken == 0);
    for (scratch.order[0..n]) |symbol| {
        assert(lengths[symbol] >= 1 and lengths[symbol] <= max_bits);
        code.lengths[symbol] = @intCast(lengths[symbol]);
        code.max_length = @max(code.max_length, code.lengths[symbol]);
        code.last_symbol = @max(code.last_symbol, symbol);
    }
}

/// Assigns prefixes in the decoder's order (weight, then symbol).
fn assign_codes(code: *Code) void {
    var keys: [256]u16 = undefined;
    var n: usize = 0;
    for (0..256) |symbol| {
        const weight = code.weight(symbol);
        if (weight == 0) continue;
        keys[n] = (@as(u16, weight) << 8) | @as(u16, @intCast(symbol));
        n += 1;
    }
    std.mem.sort(u16, keys[0..n], {}, std.sort.asc(u16));
    var prefix: u32 = 0;
    var previous: u4 = @intCast(keys[0] >> 8);
    for (keys[0..n]) |key| {
        const weight: u4 = @intCast(key >> 8);
        if (weight != previous) {
            prefix = ((prefix - 1) >> (weight - previous)) + 1;
            previous = weight;
        }
        code.codes[key & 0xFF] = @intCast(prefix);
        prefix += 1;
    }
    // A complete code ends exactly at the shortest length's code space.
    assert(prefix == @as(u32, 1) << (code.max_length + 1 - previous));
    assert(n >= 2);
}

/// Writes the tree description into `out`; null when neither form fits.
pub fn write_description(code: *const Code, out: []u8) ?usize {
    const count: usize = code.last_symbol;
    assert(count >= 1);
    var weights: [255]u8 = undefined;
    for (weights[0..count], 0..) |*weight, symbol| weight.* = code.weight(symbol);
    var fse_buffer: [1 + fse_weights_size_max]u8 = undefined;
    const fse_size = write_fse_weights(weights[0..count], code.max_length, &fse_buffer);
    const direct_size: ?usize = if (count <= 128) 1 + (count + 1) / 2 else null;
    if (fse_size) |size| {
        if (direct_size == null or size < direct_size.?) {
            if (size > out.len) return null;
            @memcpy(out[0..size], fse_buffer[0..size]);
            return size;
        }
    }
    const size = direct_size orelse return null;
    if (size > out.len) return null;
    out[0] = @intCast(127 + count);
    for (0..(count + 1) / 2) |i| {
        const high = weights[2 * i];
        const low = if (2 * i + 1 < count) weights[2 * i + 1] else 0;
        out[1 + i] = (high << 4) | low;
    }
    assert(size <= 65);
    return size;
}

/// FSE-compressed weights: a size byte, the table description, then two interleaved states
/// (libzstd's `FSE_compress_usingCTable`). Null for a single distinct weight or no gain.
fn write_fse_weights(weights: []const u8, max_weight: u4, out: []u8) ?usize {
    if (weights.len < 2) return null;
    var counts: [max_bits + 1]u32 = @splat(0);
    for (weights) |weight| counts[weight] += 1;
    for (counts) |count| if (count == weights.len) return null;
    const log = fse.optimal_accuracy_log(6, @intCast(weights.len), max_weight);
    const distribution = fse.normalize(&counts, log);
    const table: fse.Table = .init(&distribution);

    var description: bits.Writer = .init(out[1..]);
    fse.write_description(&distribution, &description);
    const description_len = (description.finish_aligned() orelse return null).len;
    var stream: bits.Writer = .init(out[1 + description_len ..]);
    encode_weights(&table, weights, &stream);
    const stream_len = (stream.finish_marked() orelse return null).len;
    const size = description_len + stream_len;
    if (size > fse_weights_size_max) return null;
    out[0] = @intCast(size);
    assert(out[0] < 128);
    return 1 + size;
}

/// The decoder alternates two states, starting with the first, and stops when the state that
/// decoded the next-to-last weight has no bits left to update with; `State.init` makes that
/// update need at least one bit.
fn encode_weights(table: *const fse.Table, weights: []const u8, stream: *bits.Writer) void {
    const n = weights.len;
    assert(n >= 2);
    var first: fse.State = undefined;
    var second: fse.State = undefined;
    var index = n - 2;
    if (n % 2 == 1) {
        first = .init(table, weights[n - 1]);
        second = .init(table, weights[n - 2]);
        first.encode(table, stream, weights[n - 3]);
        index = n - 3;
    } else {
        second = .init(table, weights[n - 1]);
        first = .init(table, weights[n - 2]);
    }
    while (index > 0) : (index -= 2) {
        second.encode(table, stream, weights[index - 1]);
        first.encode(table, stream, weights[index - 2]);
    }
    second.flush(table, stream);
    first.flush(table, stream);
    assert(index == 0);
}

/// Encodes `literals` as one stream (fewer than 256) or four streams behind a jump table into
/// `out`; null when the output does not fit.
pub fn encode_literals(code: *const Code, literals: []const u8, out: []u8) ?usize {
    assert(literals.len > 0);
    if (literals.len < 256) return encode_stream(code, literals, out);
    if (out.len < 6) return null;
    const segment = (literals.len + 3) / 4;
    var written: usize = 6;
    for (0..4) |stream| {
        const start = stream * segment;
        const end = @min(literals.len, start + segment);
        const size = encode_stream(code, literals[start..end], out[written..]) orelse return null;
        if (stream < 3) {
            if (size > std.math.maxInt(u16)) return null;
            std.mem.writeInt(u16, out[2 * stream ..][0..2], @intCast(size), .little);
        }
        written += size;
    }
    assert(written <= out.len);
    return written;
}

/// The decoder reads the last-written literal first, so literals are written back to front.
fn encode_stream(code: *const Code, literals: []const u8, out: []u8) ?usize {
    assert(literals.len > 0);
    var writer: bits.Writer = .init(out);
    var index = literals.len;
    while (index > 0) {
        index -= 1;
        const symbol = literals[index];
        assert(code.lengths[symbol] > 0);
        writer.add(code.codes[symbol], code.lengths[symbol]);
    }
    const bytes = writer.finish_marked() orelse return null;
    return bytes.len;
}

const testing = std.testing;

test "package-merge limits code lengths and keeps the code complete" {
    var scratch: Scratch = undefined;
    var counts: [256]u32 = @splat(0);
    // Fibonacci counts would need 25-bit codes without the limit.
    var a: u32 = 1;
    var b: u32 = 1;
    for (0..25) |symbol| {
        counts[symbol] = a;
        const next = a + b;
        a = b;
        b = next;
    }
    const code = build(&counts, &scratch).?;
    try testing.expectEqual(@as(u4, max_bits), code.max_length);
    var kraft: u64 = 0;
    for (code.lengths[0..25]) |length| kraft += @as(u64, 1) << (max_bits - length);
    try testing.expectEqual(@as(u64, 1) << max_bits, kraft);
    try testing.expect(code.lengths[24] <= code.lengths[0]);
}

test "two symbols get one-bit codes" {
    var scratch: Scratch = undefined;
    var counts: [256]u32 = @splat(0);
    counts['a'] = 10;
    counts['z'] = 1;
    const code = build(&counts, &scratch).?;
    try testing.expectEqual(@as(u4, 1), code.lengths['a']);
    try testing.expectEqual(@as(u4, 1), code.lengths['z']);
    try testing.expectEqual(@as(u8, 'z'), code.last_symbol);
    counts['z'] = 0;
    try testing.expectEqual(@as(?Code, null), build(&counts, &scratch));
}
