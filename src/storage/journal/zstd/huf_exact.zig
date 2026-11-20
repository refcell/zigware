//! libzstd 1.5.7's Huffman literal encoder (`huf_compress.c`) and literals section
//! (`zstd_compress_literals.c`) for the double-fast strategy, byte for byte.
//!
//! libzstd fills two bit containers from the top and merges them, but the bits it emits are
//! those of one LSB-first stream that writes the literals last to first, so this reuses the
//! FSE bit stream (whose `capacity - 8` overflow rule is the same as `HUF_closeCStream`'s).

const std = @import("std");
const assert = std.debug.assert;
const fse = @import("fse_exact.zig");

pub const table_log_max = 12;
pub const table_log_default = 11;
/// `LitHufLog`.
pub const lit_huf_log = 11;
/// `HUF_BLOCKSIZE_MAX`.
pub const block_size_max = 128 * 1024;

pub const Error = error{HufGeneric};

/// `HUF_CElt[]`: each symbol's code length and code, and the header's table log and largest
/// symbol.
pub const CTable = struct {
    log: u32 = 0,
    max_symbol: u32 = 0,
    nb_bits: [256]u8 = @splat(0),
    value: [256]u16 = @splat(0),
};

/// `HUF_repeat`.
pub const Repeat = enum { none, check, valid };

/// `ZSTD_hufCTables_t`: the table a block may reuse, and whether it may.
pub const Tables = struct {
    table: CTable = .{},
    repeat: Repeat = .none,
};

/// `SymbolEncodingType_e`.
pub const EncodingType = enum(u2) { basic = 0, rle = 1, compressed = 2, repeat = 3 };

const Node = struct { count: u32 = 0, parent: u16 = 0, byte: u8 = 0, nb_bits: u8 = 0 };

/// `huffNodeTable`, with libzstd's `huffNode0` as entry 0, so `huffNode[i]` is `node(i)`.
const Work = [2 * 256]Node;

fn node(work: *Work, i: i64) *Node {
    assert(i >= -1);
    assert(i + 1 < work.len);
    return &work[@intCast(i + 1)];
}

const rank_table_size = 192;
const rank_log_buckets_begin = rank_table_size - 1 - 32 - 1;
const rank_distinct_cutoff = rank_log_buckets_begin +
    @as(u32, std.math.log2_int(u32, rank_log_buckets_begin));

comptime {
    assert(rank_log_buckets_begin == 158);
    assert(rank_distinct_cutoff == 165);
}

fn rank_index(count: u32) u32 {
    if (count < rank_distinct_cutoff) return count;
    const index = @as(u32, fse.highbit32(count)) + rank_log_buckets_begin;
    assert(index >= rank_distinct_cutoff);
    return index;
}

/// `HUF_insertionSort` over `arr[low..=high]`, by descending count.
fn insertion_sort(arr: []Node, low: i32, high: i32) void {
    assert(low >= 0);
    assert(high < @as(i32, @intCast(arr.len)));
    if (high <= low) return;
    const base: usize = @intCast(low);
    const size: usize = @intCast(high - low + 1);
    for (1..size) |i| {
        const key = arr[base + i];
        var j: isize = @as(isize, @intCast(i)) - 1;
        while (j >= 0 and arr[base + @as(usize, @intCast(j))].count < key.count) : (j -= 1) {
            arr[base + @as(usize, @intCast(j)) + 1] = arr[base + @as(usize, @intCast(j))];
        }
        arr[base + @as(usize, @intCast(j + 1))] = key;
    }
}

/// `HUF_quickSortPartition`: the rightmost element is the pivot.
fn partition(arr: []Node, low: i32, high: i32) i32 {
    assert(low < high);
    assert(low >= 0);
    const pivot = arr[@intCast(high)].count;
    var i = low - 1;
    var j = low;
    while (j < high) : (j += 1) {
        if (arr[@intCast(j)].count > pivot) {
            i += 1;
            std.mem.swap(Node, &arr[@intCast(i)], &arr[@intCast(j)]);
        }
    }
    std.mem.swap(Node, &arr[@intCast(i + 1)], &arr[@intCast(high)]);
    return i + 1;
}

/// `HUF_simpleQuickSort`, with its recursion on the smaller side kept on an explicit stack.
/// The sides are disjoint, so the order they are sorted in does not change the result.
fn quick_sort(arr: []Node) void {
    assert(arr.len > 1);
    assert(arr.len <= 256);
    var stack: [257][2]i32 = undefined;
    stack[0] = .{ 0, @intCast(arr.len - 1) };
    var depth: usize = 1;
    while (depth > 0) {
        depth -= 1;
        var low = stack[depth][0];
        var high = stack[depth][1];
        if (high - low < 8) {
            insertion_sort(arr, @max(low, 0), high);
            continue;
        }
        while (low < high) {
            const pivot = partition(arr, low, high);
            assert(depth < stack.len);
            if (pivot - low < high - pivot) {
                stack[depth] = .{ low, pivot - 1 };
                low = pivot + 1;
            } else {
                stack[depth] = .{ pivot + 1, high };
                high = pivot - 1;
            }
            depth += 1;
        }
    }
}

/// `HUF_sort`: symbols `0..=max_symbol` into `nodes` by descending count, bucketed.
fn sort(nodes: []Node, counts: []const u32, max_symbol: u32) void {
    const RankPosition = struct { base: u16 = 0, current: u16 = 0 };
    const symbols = max_symbol + 1;
    assert(symbols <= nodes.len);
    var ranks: [rank_table_size]RankPosition = @splat(.{});
    for (counts[0..symbols]) |count| {
        const lower = rank_index(count);
        assert(lower < rank_table_size - 1);
        ranks[lower].base += 1;
    }
    assert(ranks[rank_table_size - 1].base == 0);
    var n: usize = rank_table_size - 1;
    while (n > 0) : (n -= 1) {
        ranks[n - 1].base += ranks[n].base;
        ranks[n - 1].current = ranks[n - 1].base;
    }
    for (counts[0..symbols], 0..) |count, symbol| {
        const rank = &ranks[rank_index(count) + 1];
        const position = rank.current;
        rank.current += 1;
        assert(position < symbols);
        nodes[position].count = count;
        nodes[position].byte = @intCast(symbol);
    }
    for (rank_distinct_cutoff..rank_table_size - 1) |bucket| {
        const size = ranks[bucket].current - ranks[bucket].base;
        if (size > 1) quick_sort(nodes[ranks[bucket].base..][0..size]);
    }
    for (1..symbols) |i| assert(nodes[i].count <= nodes[i - 1].count);
}

const start_node = 256;

/// `HUF_buildTree`: an unlimited-depth tree over the sorted leaves. Returns the last leaf
/// with a nonzero count.
fn build_tree(work: *Work, max_symbol: u32) i32 {
    var non_null: i32 = @intCast(max_symbol);
    while (node(work, non_null).count == 0) non_null -= 1;
    assert(non_null >= 1);
    var low_s = non_null;
    const root = start_node + low_s - 1;
    var low_n: i32 = start_node;
    var node_nb: i32 = start_node;
    node(work, node_nb).count = node(work, low_s).count + node(work, low_s - 1).count;
    node(work, low_s).parent = @intCast(node_nb);
    node(work, low_s - 1).parent = @intCast(node_nb);
    node_nb += 1;
    low_s -= 2;
    var n = node_nb;
    while (n <= root) : (n += 1) node(work, n).count = 1 << 30;
    node(work, -1).count = 1 << 31;
    while (node_nb <= root) : (node_nb += 1) {
        var pair: [2]i32 = undefined;
        for (&pair) |*pick| {
            if (node(work, low_s).count < node(work, low_n).count) {
                pick.* = low_s;
                low_s -= 1;
            } else {
                pick.* = low_n;
                low_n += 1;
            }
        }
        node(work, node_nb).count = node(work, pair[0]).count + node(work, pair[1]).count;
        node(work, pair[0]).parent = @intCast(node_nb);
        node(work, pair[1]).parent = @intCast(node_nb);
    }
    node(work, root).nb_bits = 0;
    n = root - 1;
    while (n >= start_node) : (n -= 1) {
        node(work, n).nb_bits = node(work, node(work, n).parent).nb_bits + 1;
    }
    n = 0;
    while (n <= non_null) : (n += 1) {
        node(work, n).nb_bits = node(work, node(work, n).parent).nb_bits + 1;
    }
    return non_null;
}

/// `HUF_setMaxHeight`: caps code lengths at `target`, then repays the Kraft overshoot.
fn set_max_height(work: *Work, last_non_null: i32, target: u32) u32 {
    const largest: u32 = node(work, last_non_null).nb_bits;
    if (largest <= target) return largest;
    assert(largest - target < 31);
    const shift: u5 = @intCast(largest - target);
    const base_cost: i32 = @as(i32, 1) << shift;
    var total_cost: i32 = 0;
    var n: i32 = last_non_null;
    while (node(work, n).nb_bits > target) : (n -= 1) {
        const bits = node(work, n).nb_bits;
        total_cost += base_cost - (@as(i32, 1) << @intCast(largest - bits));
        node(work, n).nb_bits = @intCast(target);
    }
    assert(node(work, n).nb_bits <= target);
    while (node(work, n).nb_bits == target) n -= 1;
    assert(total_cost & (base_cost - 1) == 0);
    total_cost >>= shift;
    assert(total_cost > 0);
    repay_cost(work, n, target, total_cost);
    return target;
}

const no_symbol: u32 = 0xF0F0F0F0;

/// `HUF_setMaxHeight`'s "repay normalized cost" step.
fn repay_cost(work: *Work, n_start: i32, target: u32, cost: i32) void {
    assert(cost > 0);
    assert(target <= table_log_max);
    var rank_last: [table_log_max + 2]u32 = @splat(no_symbol);
    var current: u32 = target;
    var pos: i32 = n_start;
    while (pos >= 0) : (pos -= 1) {
        const bits = node(work, pos).nb_bits;
        if (bits >= current) continue;
        current = bits;
        rank_last[target - current] = @intCast(pos);
    }
    var total = cost;
    while (total > 0) {
        var decrease: u32 = @as(u32, fse.highbit32(@intCast(total))) + 1;
        while (decrease > 1) : (decrease -= 1) {
            const high = rank_last[decrease];
            const low = rank_last[decrease - 1];
            if (high == no_symbol) continue;
            if (low == no_symbol) break;
            if (node(work, high).count <= 2 * node(work, low).count) break;
        }
        assert(rank_last[decrease] != no_symbol or decrease == 1);
        while (decrease <= table_log_max and rank_last[decrease] == no_symbol) decrease += 1;
        assert(rank_last[decrease] != no_symbol);
        total -= @as(i32, 1) << @intCast(decrease - 1);
        node(work, rank_last[decrease]).nb_bits += 1;
        if (rank_last[decrease - 1] == no_symbol) rank_last[decrease - 1] = rank_last[decrease];
        if (rank_last[decrease] == 0) {
            rank_last[decrease] = no_symbol;
        } else {
            rank_last[decrease] -= 1;
            if (node(work, rank_last[decrease]).nb_bits != target -% decrease) {
                rank_last[decrease] = no_symbol;
            }
        }
    }
    repay_overshoot(work, &rank_last, n_start, target, total);
}

/// `HUF_setMaxHeight`'s overshoot correction: moves rank-0 nodes back to rank 1.
fn repay_overshoot(work: *Work, rank_last: []u32, n_start: i32, target: u32, cost: i32) void {
    assert(cost <= 0);
    assert(rank_last.len > 1);
    var n = n_start;
    var total = cost;
    while (total < 0) : (total += 1) {
        if (rank_last[1] == no_symbol) {
            while (node(work, n).nb_bits == target) n -= 1;
            node(work, n + 1).nb_bits -= 1;
            assert(n >= 0);
            rank_last[1] = @intCast(n + 1);
            continue;
        }
        node(work, rank_last[1] + 1).nb_bits -= 1;
        rank_last[1] += 1;
    }
}

/// `HUF_buildCTableFromTree`: canonical codes, in symbol order within each length.
fn build_from_tree(
    table: *CTable,
    work: *Work,
    non_null: i32,
    max_symbol: u32,
    max_bits: u32,
) void {
    assert(max_bits <= table_log_max);
    assert(max_symbol < 256);
    var nb_per_rank: [table_log_max + 1]u16 = @splat(0);
    var val_per_rank: [table_log_max + 1]u16 = @splat(0);
    var n: i32 = 0;
    while (n <= non_null) : (n += 1) nb_per_rank[node(work, n).nb_bits] += 1;
    var min: u16 = 0;
    var rank = max_bits;
    while (rank > 0) : (rank -= 1) {
        val_per_rank[rank] = min;
        min += nb_per_rank[rank];
        min >>= 1;
    }
    for (0..max_symbol + 1) |i| {
        const leaf = node(work, @intCast(i));
        table.nb_bits[leaf.byte] = leaf.nb_bits;
    }
    for (0..max_symbol + 1) |symbol| {
        const bits = table.nb_bits[symbol];
        table.value[symbol] = if (bits > 0) val_per_rank[bits] else 0;
        val_per_rank[bits] +%= 1;
    }
    table.log = max_bits;
    table.max_symbol = max_symbol;
}

/// `HUF_buildCTable_wksp`. Returns the table's largest code length.
pub fn build_ctable(
    table: *CTable,
    counts: []const u32,
    max_symbol: u32,
    max_bits_in: u32,
) Error!u32 {
    assert(max_symbol < 256);
    assert(counts.len > max_symbol);
    var work: Work = @splat(.{});
    const max_bits = if (max_bits_in == 0) table_log_default else max_bits_in;
    sort(work[1..], counts, max_symbol);
    const non_null = build_tree(&work, max_symbol);
    const height = set_max_height(&work, non_null, max_bits);
    if (height > table_log_max) return error.HufGeneric;
    build_from_tree(table, &work, non_null, max_symbol, height);
    return height;
}

/// `HUF_estimateCompressedSize`, in bytes.
pub fn estimate_size(table: *const CTable, counts: []const u32, max_symbol: u32) usize {
    assert(max_symbol < 256);
    assert(counts.len > max_symbol);
    var bits: usize = 0;
    for (0..max_symbol + 1) |s| bits += @as(usize, table.nb_bits[s]) * counts[s];
    return bits >> 3;
}

/// The fewest bytes `compress_1x` or `compress_4x` can write for symbols counted in `counts`:
/// every coded bit, rounded down, and the jump table of four streams.
fn streams_floor(table: *const CTable, counts: []const u32, max_symbol: u32, four: bool) usize {
    const floor = estimate_size(table, counts, max_symbol) + @as(usize, if (four) 6 else 0);
    assert(floor >= estimate_size(table, counts, max_symbol));
    return floor;
}

/// `HUF_validateCTable`: every symbol present has a code.
pub fn validate(table: *const CTable, counts: []const u32, max_symbol: u32) bool {
    assert(max_symbol < 256);
    assert(counts.len > max_symbol);
    if (table.max_symbol < max_symbol) return false;
    for (0..max_symbol + 1) |s| {
        if (counts[s] != 0 and table.nb_bits[s] == 0) return false;
    }
    return true;
}

/// `HUF_compressWeights`: FSE-compressed weights, 0 when not compressible, 1 for one symbol.
fn compress_weights(out: []u8, weights: []const u8) Error!usize {
    assert(weights.len < 256);
    assert(out.len >= 512);
    if (weights.len <= 1) return 0;
    var counts: [table_log_max + 1]u32 = undefined;
    var max_symbol: u32 = table_log_max;
    const max_count = fse.count_simple(&counts, &max_symbol, weights);
    if (max_count == weights.len) return 1;
    if (max_count == 1) return 0;
    const log = fse.optimal_table_log(6, weights.len, max_symbol);
    var norm: [table_log_max + 1]i16 = undefined;
    fse.normalize(&norm, log, &counts, weights.len, max_symbol, false) catch
        return error.HufGeneric;
    const header_len = fse.write_ncount(out, &norm, max_symbol, log) catch
        return error.HufGeneric;
    var table: fse.CTable = .{ .log = 0, .max_symbol = 0 };
    table.build(&norm, max_symbol, log);
    const stream_len = fse.compress(out[header_len..], weights, &table) orelse return 0;
    return header_len + stream_len;
}

/// `HUF_writeCTable_wksp`: the table description, FSE-compressed or as raw 4-bit weights.
pub fn write_ctable(out: []u8, table: *const CTable, max_symbol: u32, huff_log: u32) Error!usize {
    assert(table.max_symbol == max_symbol);
    assert(table.log == huff_log);
    var bits_to_weight: [table_log_max + 1]u8 = @splat(0);
    for (1..huff_log + 1) |n| bits_to_weight[n] = @intCast(huff_log + 1 - n);
    var weights: [256]u8 = undefined;
    for (0..max_symbol) |n| weights[n] = bits_to_weight[table.nb_bits[n]];
    if (out.len < 1) return error.HufGeneric;
    const header_len = try compress_weights(out[1..], weights[0..max_symbol]);
    if (header_len > 1 and header_len < max_symbol / 2) {
        out[0] = @intCast(header_len);
        return header_len + 1;
    }
    if (max_symbol > 256 - 128) return error.HufGeneric;
    const raw_len = (max_symbol + 1) / 2 + 1;
    if (raw_len > out.len) return error.HufGeneric;
    out[0] = @intCast(128 + (max_symbol - 1));
    weights[max_symbol] = 0;
    var n: usize = 0;
    while (n < max_symbol) : (n += 2) out[n / 2 + 1] = (weights[n] << 4) + weights[n + 1];
    return raw_len;
}

/// `HUF_compress1X_usingCTable`: null when it does not fit.
pub fn compress_1x(out: []u8, src: []const u8, table: *const CTable) ?usize {
    assert(table.log <= table_log_max);
    if (out.len < 8) return null;
    var stream: fse.Stream = .init(out);
    var i = src.len;
    while (i > 0) {
        i -= 1;
        const symbol = src[i];
        assert(table.nb_bits[symbol] <= table_log_max);
        stream.add(table.value[symbol], @intCast(table.nb_bits[symbol]));
    }
    return stream.close();
}

/// `HUF_compress4X_usingCTable`: a 6-byte jump table, then four streams.
pub fn compress_4x(out: []u8, src: []const u8, table: *const CTable) ?usize {
    if (out.len < 6 + 1 + 1 + 1 + 8) return null;
    if (src.len < 12) return null;
    const segment = (src.len + 3) / 4;
    var op: usize = 6;
    var ip: usize = 0;
    for (0..4) |i| {
        const end = if (i == 3) src.len else ip + segment;
        assert(end <= src.len);
        const len = compress_1x(out[op..], src[ip..end], table) orelse return null;
        if (len == 0 or len > 65535) return null;
        if (i < 3) std.mem.writeInt(u16, out[2 * i ..][0..2], @intCast(len), .little);
        op += len;
        ip = end;
    }
    assert(ip == src.len);
    return op;
}

/// `HUF_compressCTable_internal`: the streams after `header_len` table bytes, or 0 when the
/// whole is not smaller than `src.len - 1`.
fn compress_with_table(
    out: []u8,
    header_len: usize,
    src: []const u8,
    four: bool,
    table: *const CTable,
) usize {
    assert(header_len <= out.len);
    assert(src.len > 1);
    const rest = out[header_len..];
    const len = (if (four) compress_4x(rest, src, table) else compress_1x(rest, src, table)) orelse
        return 0;
    const total = header_len + len;
    if (total >= src.len - 1) return 0;
    return total;
}

pub const Flags = struct {
    prefer_repeat: bool,
    suspect_uncompressible: bool,
    /// The caller stores the literals raw when the result is this long or longer.
    discard_from: usize,
};

const suspect_sample_size = 4096;
const suspect_sample_ratio = 10;

fn suspect_incompressible(src: []const u8) bool {
    assert(src.len >= suspect_sample_size * suspect_sample_ratio);
    var counts: [256]u32 = undefined;
    var max_begin: u32 = 255;
    var largest = fse.count_simple(&counts, &max_begin, src[0..suspect_sample_size]);
    var max_end: u32 = 255;
    largest += fse.count_simple(&counts, &max_end, src[src.len - suspect_sample_size ..]);
    assert(largest >= 2);
    return largest <= ((2 * suspect_sample_size) >> 7) + 4;
}

/// `HUF_compress_internal` with `HUF_SYMBOLVALUE_MAX` and `LitHufLog`: the compressed
/// literals (table description included unless the old table is reused), 1 for a single
/// symbol (its byte in `out[0]`), or 0 when not worth it. `table` is the old table, replaced
/// when a new one is used; `repeat` becomes `none` unless the old table was reused.
pub fn compress(
    out: []u8,
    src: []const u8,
    four: bool,
    table: *CTable,
    repeat: *Repeat,
    flags: Flags,
) Error!usize {
    assert(src.len > 0);
    assert(src.len <= block_size_max);
    if (out.len == 0) return 0;
    if (flags.prefer_repeat and repeat.* == .valid) {
        return compress_with_table(out, 0, src, four, table);
    }
    if (flags.suspect_uncompressible and src.len >= suspect_sample_size * suspect_sample_ratio) {
        if (suspect_incompressible(src)) return 0;
    }
    var counts: [256]u32 = undefined;
    var max_symbol: u32 = 255;
    const largest = fse.count_simple(&counts, &max_symbol, src);
    if (largest == src.len) {
        out[0] = src[0];
        return 1;
    }
    if (largest <= (src.len >> 7) + 4) return 0;
    if (repeat.* == .check and !validate(table, &counts, max_symbol)) repeat.* = .none;
    if (flags.prefer_repeat and repeat.* != .none) {
        return compress_with_table(out, 0, src, four, table);
    }
    const log = fse.optimal_table_log_internal(lit_huf_log, src.len, max_symbol, 1);
    var fresh: CTable = .{};
    const huff_log = try build_ctable(&fresh, &counts, max_symbol, log);
    // Without an old table, the result is the new table's streams after its header, which
    // `compress_with_table` refuses at `src.len - 1` bytes and the caller at `discard_from`.
    // The streams alone hold at least the table's estimate (and a 4-stream jump table), so
    // when that reaches either limit the literals stay raw: skip writing the header and the
    // streams (nearly random literals).
    const limit = @min(src.len - 1, flags.discard_from);
    if (repeat.* == .none and streams_floor(&fresh, &counts, max_symbol, four) >= limit) {
        return 0;
    }
    const header_len = try write_ctable(out, &fresh, max_symbol, huff_log);
    if (repeat.* != .none) {
        const old_size = estimate_size(table, &counts, max_symbol);
        const new_size = estimate_size(&fresh, &counts, max_symbol);
        if (old_size <= header_len + new_size or header_len + 12 >= src.len) {
            return compress_with_table(out, 0, src, four, table);
        }
    }
    if (header_len + 12 >= src.len) return 0;
    repeat.* = .none;
    table.* = fresh;
    return compress_with_table(out, header_len, src, four, table);
}

fn literals_header_len(len: usize) usize {
    assert(len < 1 << 20);
    const header_len: usize = 1 + @as(usize, @intFromBool(len > 31)) + @intFromBool(len > 4095);
    assert(header_len <= 3);
    return header_len;
}

fn write_small_header(out: []u8, kind: EncodingType, len: usize) usize {
    const header_len = literals_header_len(len);
    assert(kind == .basic or kind == .rle);
    assert(out.len >= header_len);
    const k: u32 = @backingInt(kind);
    const n: u32 = @intCast(len);
    switch (header_len) {
        1 => out[0] = @intCast(k + (n << 3)),
        2 => std.mem.writeInt(u16, out[0..2], @intCast(k + (1 << 2) + (n << 4)), .little),
        3 => std.mem.writeInt(u24, out[0..3], @intCast(k + (3 << 2) + (n << 4)), .little),
        else => unreachable,
    }
    return header_len;
}

/// `ZSTD_noCompressLiterals`.
pub fn raw_literals(out: []u8, src: []const u8) usize {
    const header_len = write_small_header(out, .basic, src.len);
    assert(out.len >= header_len + src.len);
    @memcpy(out[header_len..][0..src.len], src);
    return header_len + src.len;
}

/// `ZSTD_compressRleLiteralsBlock`.
pub fn rle_literals(out: []u8, src: []const u8) usize {
    assert(src.len > 0);
    const header_len = write_small_header(out, .rle, src.len);
    assert(out.len > header_len);
    out[header_len] = src[0];
    return header_len + 1;
}

fn all_bytes_identical(src: []const u8) bool {
    assert(src.len >= 1);
    for (src[1..]) |byte| {
        if (byte != src[0]) return false;
    }
    return true;
}

/// `ZSTD_minLiteralsToCompress` for dfast.
fn min_literals(repeat: Repeat) usize {
    const shift = @min(9 - 2, 3);
    const min: usize = if (repeat == .valid) 6 else 8 << shift;
    assert(min == 6 or min == 64);
    return min;
}

/// Whether `compress_literals` stores `src` raw when the block is suspected incompressible,
/// decided without copying it: too few literals to compress, or the sampled histograms of
/// `HUF_compress_internal` give up. False means it may compress them.
pub fn suspect_literals_stay_raw(src: []const u8, prev: *const Tables) bool {
    assert(src.len <= block_size_max);
    if (src.len < min_literals(prev.repeat)) return true;
    // `prefer_repeat` (at most 1 KiB of literals) is checked before the samples.
    if (src.len < suspect_sample_size * suspect_sample_ratio) return false;
    comptime assert(suspect_sample_size * suspect_sample_ratio > 1024);
    return suspect_incompressible(src);
}

/// `ZSTD_compressLiterals` at the dfast strategy with literal compression enabled: the
/// literals section of a block. `next` receives the tables the next block may reuse.
pub fn compress_literals(
    out: []u8,
    src: []const u8,
    prev: *const Tables,
    next: *Tables,
    suspect_uncompressible: bool,
) usize {
    assert(src.len <= block_size_max);
    const header_len: usize = 3 + @as(usize, @intFromBool(src.len >= 1024)) +
        @intFromBool(src.len >= 16 * 1024);
    next.* = prev.*;
    if (src.len < min_literals(prev.repeat)) return raw_literals(out, src);
    assert(out.len >= header_len + 1);
    var repeat = prev.repeat;
    const single = src.len < 256 or (repeat == .valid and header_len == 3);
    const min_gain = (src.len >> 6) + 2;
    assert(min_gain < src.len);
    const flags: Flags = .{
        .prefer_repeat = src.len <= 1024,
        .suspect_uncompressible = suspect_uncompressible,
        .discard_from = src.len - min_gain,
    };
    const result = compress(out[header_len..], src, !single, &next.table, &repeat, flags);
    const len = result catch 0;
    const kind: EncodingType = if (repeat != .none) .repeat else .compressed;
    if (len == 0 or len >= src.len - min_gain) {
        next.* = prev.*;
        return raw_literals(out, src);
    }
    if (len == 1 and (src.len >= 8 or all_bytes_identical(src))) {
        next.* = prev.*;
        return rle_literals(out, src);
    }
    if (kind == .compressed) next.repeat = .check;
    write_compressed_header(out, header_len, kind, single, src.len, len);
    return header_len + len;
}

fn write_compressed_header(
    out: []u8,
    header_len: usize,
    kind: EncodingType,
    single: bool,
    regenerated: usize,
    compressed: usize,
) void {
    assert(kind == .compressed or kind == .repeat);
    assert(header_len == 3 or !single);
    const k: u64 = @backingInt(kind);
    const r: u64 = regenerated;
    const c: u64 = compressed;
    switch (header_len) {
        3 => {
            const streams: u64 = @intFromBool(!single);
            const value = k + (streams << 2) + (r << 4) + (c << 14);
            std.mem.writeInt(u24, out[0..3], @truncate(value), .little);
        },
        4 => {
            const value = k + (2 << 2) + (r << 4) + (c << 18);
            std.mem.writeInt(u32, out[0..4], @truncate(value), .little);
        },
        5 => {
            const value = k + (3 << 2) + (r << 4) + (c << 22);
            std.mem.writeInt(u32, out[0..4], @truncate(value), .little);
            out[4] = @truncate(c >> 10);
        },
        else => unreachable,
    }
}
