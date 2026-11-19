//! libzstd 1.5.7's FSE encoder (`fse_compress.c`, `hist.c`, `bitstream.h`), byte for byte:
//! histograms, table-log choice, count normalization (both methods), the normalized-count
//! header, table construction, and two-state encoding.
//!
//! `Stream` keeps libzstd's overflow rule: a stream into `capacity` bytes fails (returns
//! null) once its whole bytes reach `capacity - 8`, the bit container libzstd reserves.

const std = @import("std");
const assert = std.debug.assert;

/// `FSE_MIN_TABLELOG`.
pub const table_log_min = 5;
/// `FSE_MAX_TABLELOG` with `FSE_MAX_MEMORY_USAGE` 14.
pub const table_log_max = 12;
/// `FSE_DEFAULT_TABLELOG` with `FSE_DEFAULT_MEMORY_USAGE` 13.
pub const table_log_default = 11;
pub const symbols_max = 256;

pub const Error = error{FseGeneric};

/// `ZSTD_highbit32`: the index of the highest set bit of a nonzero value.
pub fn highbit32(value: u32) u5 {
    assert(value != 0);
    return @intCast(31 - @clz(value));
}

/// `HIST_count_simple`: counts of `src`'s bytes, trimming `max_symbol` to the largest byte
/// present (0 when empty). Returns the largest count.
pub fn count_simple(counts: []u32, max_symbol: *u32, src: []const u8) u32 {
    assert(counts.len > max_symbol.*);
    @memset(counts[0 .. max_symbol.* + 1], 0);
    if (src.len == 0) {
        max_symbol.* = 0;
        return 0;
    }
    for (src) |byte| {
        assert(byte <= max_symbol.*);
        counts[byte] += 1;
    }
    while (counts[max_symbol.*] == 0) max_symbol.* -= 1;
    var largest: u32 = 0;
    for (counts[0 .. max_symbol.* + 1]) |count| largest = @max(largest, count);
    assert(largest > 0);
    return largest;
}

fn min_table_log(src_size: usize, max_symbol: u32) u32 {
    assert(src_size > 1);
    const bits_src = @as(u32, highbit32(@intCast(src_size))) + 1;
    const bits_symbols = @as(u32, if (max_symbol == 0) 0 else highbit32(max_symbol)) + 2;
    return @min(bits_src, bits_symbols);
}

/// `FSE_optimalTableLog_internal`.
pub fn optimal_table_log_internal(max_log: u32, src_size: usize, max_symbol: u32, minus: u32) u32 {
    assert(src_size > 1);
    const bits_src = @as(u32, highbit32(@intCast(src_size - 1))) -% minus;
    var log = if (max_log == 0) table_log_default else max_log;
    if (bits_src < log) log = bits_src;
    const min_bits = min_table_log(src_size, max_symbol);
    if (min_bits > log) log = min_bits;
    log = std.math.clamp(log, table_log_min, table_log_max);
    return log;
}

/// `FSE_optimalTableLog`.
pub fn optimal_table_log(max_log: u32, src_size: usize, max_symbol: u32) u32 {
    return optimal_table_log_internal(max_log, src_size, max_symbol, 2);
}

const rest_to_beat = [8]u64{ 0, 473195, 504333, 520860, 550000, 700000, 750000, 830000 };

/// `FSE_normalizeCount`: scale `counts[0..=max_symbol]` (summing to `total`) to `2^log`.
/// Does nothing for a single-symbol (RLE) histogram, as libzstd does.
pub fn normalize(
    norm: []i16,
    log_in: u32,
    counts: []const u32,
    total: usize,
    max_symbol: u32,
    use_low_prob: bool,
) Error!void {
    const log = if (log_in == 0) table_log_default else log_in;
    if (log < table_log_min or log > table_log_max) return error.FseGeneric;
    if (log < min_table_log(total, max_symbol)) return error.FseGeneric;
    assert(norm.len > max_symbol and counts.len > max_symbol);
    const low_prob: i16 = if (use_low_prob) -1 else 1;
    const scale: u6 = @intCast(62 - log);
    const step: u64 = (@as(u64, 1) << 62) / @as(u32, @intCast(total));
    const v_step: u64 = @as(u64, 1) << (scale - 20);
    var still: i32 = @as(i32, 1) << @intCast(log);
    var largest: usize = 0;
    var largest_p: i16 = 0;
    const low_threshold: u32 = @intCast(total >> @intCast(log));
    for (counts[0 .. max_symbol + 1], 0..) |count, s| {
        if (count == total) return;
        if (count == 0) {
            norm[s] = 0;
            continue;
        }
        if (count <= low_threshold) {
            norm[s] = low_prob;
            still -= 1;
            continue;
        }
        const scaled = @as(u64, count) * step;
        var proba: i16 = @intCast(scaled >> scale);
        if (proba < 8) {
            const rest = v_step * rest_to_beat[@intCast(proba)];
            if (scaled - (@as(u64, @intCast(proba)) << scale) > rest) proba += 1;
        }
        if (proba > largest_p) {
            largest_p = proba;
            largest = s;
        }
        norm[s] = proba;
        still -= proba;
    }
    if (-still >= (norm[largest] >> 1)) {
        try normalize_m2(norm, log, counts, total, max_symbol, low_prob);
    } else {
        norm[largest] += @intCast(still);
    }
}

const not_yet_assigned: i16 = -2;

/// `FSE_normalizeM2`: the secondary normalization when the primary would starve the
/// largest symbol.
fn normalize_m2(
    norm: []i16,
    log: u32,
    counts: []const u32,
    total_in: usize,
    max_symbol: u32,
    low_prob: i16,
) Error!void {
    var total: u64 = total_in;
    var distributed: u32 = 0;
    const low_threshold: u32 = @intCast(total >> @intCast(log));
    var low_one: u32 = @intCast((total * 3) >> @intCast(log + 1));
    for (counts[0 .. max_symbol + 1], 0..) |count, s| {
        if (count == 0) {
            norm[s] = 0;
        } else if (count <= low_threshold) {
            norm[s] = low_prob;
            distributed += 1;
            total -= count;
        } else if (count <= low_one) {
            norm[s] = 1;
            distributed += 1;
            total -= count;
        } else {
            norm[s] = not_yet_assigned;
        }
    }
    var to_distribute: u32 = (@as(u32, 1) << @intCast(log)) - distributed;
    if (to_distribute == 0) return;
    if (total / to_distribute > low_one) {
        low_one = @intCast((total * 3) / (@as(u64, to_distribute) * 2));
        for (counts[0 .. max_symbol + 1], 0..) |count, s| {
            if (norm[s] == not_yet_assigned and count <= low_one) {
                norm[s] = 1;
                distributed += 1;
                total -= count;
            }
        }
        to_distribute = (@as(u32, 1) << @intCast(log)) - distributed;
    }
    if (distributed == max_symbol + 1) {
        var max_value: usize = 0;
        var max_count: u32 = 0;
        for (counts[0 .. max_symbol + 1], 0..) |count, s| {
            if (count > max_count) {
                max_value = s;
                max_count = count;
            }
        }
        norm[max_value] += @intCast(to_distribute);
        return;
    }
    if (total == 0) {
        var s: usize = 0;
        while (to_distribute > 0) : (s = (s + 1) % (max_symbol + 1)) {
            if (norm[s] > 0) {
                to_distribute -= 1;
                norm[s] += 1;
            }
        }
        return;
    }
    try distribute_m2(norm, log, counts, total, max_symbol, to_distribute);
}

fn distribute_m2(
    norm: []i16,
    log: u32,
    counts: []const u32,
    total: u64,
    max_symbol: u32,
    to_distribute: u32,
) Error!void {
    assert(total > 0 and total <= std.math.maxInt(u32));
    const v_step_log: u6 = @intCast(62 - log);
    const mid: u64 = (@as(u64, 1) << (v_step_log - 1)) - 1;
    const r_step = ((@as(u64, 1) << v_step_log) * to_distribute + mid) / @as(u32, @intCast(total));
    var running = mid;
    for (counts[0 .. max_symbol + 1], 0..) |count, s| {
        if (norm[s] != not_yet_assigned) continue;
        const end = running + @as(u64, count) * r_step;
        const weight: u32 = @intCast((end >> v_step_log) - (running >> v_step_log));
        if (weight < 1) return error.FseGeneric;
        norm[s] = @intCast(weight);
        running = end;
    }
    assert(running >= mid);
}

/// `FSE_writeNCount` into `out` (which must hold `FSE_NCountWriteBound`). Returns its length.
pub fn write_ncount(out: []u8, norm: []const i16, max_symbol: u32, log: u32) Error!usize {
    if (log < table_log_min or log > table_log_max) return error.FseGeneric;
    assert(out.len >> 1 >= ((max_symbol + 1) * log + 6) / 16 + 2);
    const table_size: i32 = @as(i32, 1) << @intCast(log);
    var len: usize = 0;
    var stream: u32 = log - table_log_min;
    var count_bits: u5 = 4;
    var remaining: i32 = table_size + 1;
    var threshold: i32 = table_size;
    var nb_bits: u5 = @intCast(log + 1);
    var symbol: u32 = 0;
    var previous_zero = false;
    while (symbol <= max_symbol and remaining > 1) {
        if (previous_zero) {
            var start = symbol;
            while (symbol <= max_symbol and norm[symbol] == 0) symbol += 1;
            if (symbol == max_symbol + 1) break;
            while (symbol >= start + 24) {
                start += 24;
                stream +%= @as(u32, 0xFFFF) << count_bits;
                put16(out, &len, stream);
                stream >>= 16;
            }
            while (symbol >= start + 3) {
                start += 3;
                stream +%= @as(u32, 3) << count_bits;
                count_bits += 2;
            }
            stream +%= (symbol - start) << count_bits;
            count_bits += 2;
            if (count_bits > 16) {
                put16(out, &len, stream);
                stream >>= 16;
                count_bits -= 16;
            }
        }
        var count: i32 = norm[symbol];
        symbol += 1;
        const max: i32 = (2 * threshold - 1) - remaining;
        remaining -= if (count < 0) -count else count;
        count += 1;
        if (count >= threshold) count += max;
        stream +%= @as(u32, @intCast(count)) << count_bits;
        count_bits += nb_bits;
        if (count < max) count_bits -= 1;
        previous_zero = count == 1;
        if (remaining < 1) return error.FseGeneric;
        while (remaining < threshold) {
            nb_bits -= 1;
            threshold >>= 1;
        }
        if (count_bits > 16) {
            put16(out, &len, stream);
            stream >>= 16;
            count_bits -= 16;
        }
    }
    if (remaining != 1) return error.FseGeneric;
    put16(out, &len, stream);
    len -= 2;
    len += (@as(usize, count_bits) + 7) / 8;
    return len;
}

fn put16(out: []u8, len: *usize, stream: u32) void {
    out[len.*] = @truncate(stream);
    out[len.* + 1] = @truncate(stream >> 8);
    len.* += 2;
}

const SymbolTransform = struct { delta_nb_bits: u32 = 0, delta_find_state: i32 = 0 };

/// `FSE_CTable`: the state table and each symbol's transform.
pub const CTable = struct {
    log: u32,
    max_symbol: u32,
    states: [1 << table_log_max]u16 = undefined,
    symbols: [symbols_max]SymbolTransform = @splat(.{}),

    /// `FSE_buildCTable_wksp`.
    pub fn build(table: *CTable, norm: []const i16, max_symbol: u32, log: u32) void {
        assert(log >= table_log_min and log <= table_log_max);
        assert(max_symbol < symbols_max);
        table.log = log;
        table.max_symbol = max_symbol;
        const size: u32 = @as(u32, 1) << @intCast(log);
        const mask = size - 1;
        const step = (size >> 1) + (size >> 3) + 3;
        var cumul: [symbols_max + 1]u32 = undefined;
        var spread: [1 << table_log_max]u8 = undefined;
        var high: u32 = size - 1;
        cumul[0] = 0;
        for (1..max_symbol + 2) |u| {
            const n = norm[u - 1];
            if (n == -1) {
                cumul[u] = cumul[u - 1] + 1;
                spread[high] = @intCast(u - 1);
                high -%= 1;
            } else {
                assert(n >= 0);
                cumul[u] = cumul[u - 1] + @as(u32, @intCast(n));
            }
        }
        var position: u32 = 0;
        for (0..max_symbol + 1) |symbol| {
            var occurrence: i32 = 0;
            while (occurrence < norm[symbol]) : (occurrence += 1) {
                spread[position] = @intCast(symbol);
                position = (position + step) & mask;
                while (position > high) position = (position + step) & mask;
            }
        }
        assert(position == 0);
        for (0..size) |u| {
            const s = spread[u];
            table.states[cumul[s]] = @intCast(size + u);
            cumul[s] += 1;
        }
        table.build_transforms(norm);
    }

    fn build_transforms(table: *CTable, norm: []const i16) void {
        const log = table.log;
        var total: i32 = 0;
        for (0..table.max_symbol + 1) |s| {
            const n = norm[s];
            switch (n) {
                0 => table.symbols[s].delta_nb_bits =
                    ((log + 1) << 16) - (@as(u32, 1) << @intCast(log)),
                -1, 1 => {
                    table.symbols[s] = .{
                        .delta_nb_bits = (log << 16) - (@as(u32, 1) << @intCast(log)),
                        .delta_find_state = total - 1,
                    };
                    total += 1;
                },
                else => {
                    assert(n > 1);
                    const count: u32 = @intCast(n);
                    const max_bits_out = log - highbit32(count - 1);
                    const min_state_plus = count << @intCast(max_bits_out);
                    table.symbols[s] = .{
                        .delta_nb_bits = (max_bits_out << 16) -% min_state_plus,
                        .delta_find_state = total - n,
                    };
                    total += n;
                },
            }
        }
        assert(total <= @as(i32, 1) << @intCast(log));
    }

    /// `FSE_buildCTable_rle`.
    pub fn build_rle(table: *CTable, symbol: u8) void {
        table.log = 0;
        table.max_symbol = symbol;
        table.states[0] = 0;
        table.states[1] = 0;
        table.symbols[symbol] = .{};
    }
};

/// `FSE_CState_t`.
pub const State = struct {
    value: u64,

    /// `FSE_initCState`.
    pub fn init(table: *const CTable) State {
        return .{ .value = @as(u64, 1) << @intCast(table.log) };
    }

    /// `FSE_initCState2`: start at the smallest state that encodes `symbol`.
    pub fn init2(table: *const CTable, symbol: u32) State {
        const transform = table.symbols[symbol];
        const nb_bits_out = (transform.delta_nb_bits +% (1 << 15)) >> 16;
        const value: u32 = (nb_bits_out << 16) -% transform.delta_nb_bits;
        const index: i64 = @as(i64, value >> @intCast(nb_bits_out)) + transform.delta_find_state;
        return .{ .value = table.states[@intCast(index)] };
    }

    /// `FSE_encodeSymbol`.
    pub fn encode(state: *State, table: *const CTable, stream: *Stream, symbol: u32) void {
        const transform = table.symbols[symbol];
        const nb_bits_out: u6 = @intCast((state.value + transform.delta_nb_bits) >> 16);
        stream.add(state.value, nb_bits_out);
        const base: i64 = @intCast(state.value >> nb_bits_out);
        const index: i64 = base + transform.delta_find_state;
        state.value = table.states[@intCast(index)];
    }

    /// `FSE_flushCState`.
    pub fn flush(state: State, table: *const CTable, stream: *Stream) void {
        stream.add(state.value, @intCast(table.log));
    }
};

/// `BIT_CStream_t` with its overflow rule; bits beyond `out` are counted but not stored.
pub const Stream = struct {
    out: []u8,
    /// Whole bytes emitted so far.
    len: usize = 0,
    container: u64 = 0,
    count: u7 = 0,

    pub fn init(out: []u8) Stream {
        return .{ .out = out };
    }

    /// `BIT_addBits`: the low `bits` bits of `value`.
    pub fn add(self: *Stream, value: u64, bits: u6) void {
        assert(bits < 32);
        if (self.count + bits > 64) self.flush();
        const masked = value & ((@as(u64, 1) << bits) - 1);
        if (bits > 0) self.container |= masked << @intCast(self.count);
        self.count += bits;
        assert(self.count <= 64);
    }

    fn flush(self: *Stream) void {
        while (self.count >= 8) {
            if (self.len < self.out.len) self.out[self.len] = @truncate(self.container);
            self.len += 1;
            self.container >>= 8;
            self.count -= 8;
        }
        assert(self.count < 8);
    }

    /// `BIT_closeCStream`: the end mark, then the stream's size, or null if its whole bytes
    /// reached `capacity - 8` (libzstd's `ptr >= endPtr`).
    pub fn close(self: *Stream) ?usize {
        self.add(1, 1);
        self.flush();
        if (self.out.len <= 8 or self.len >= self.out.len - 8) return null;
        const size = self.len + @intFromBool(self.count > 0);
        if (self.count > 0) self.out[self.len] = @truncate(self.container);
        assert(size <= self.out.len);
        return size;
    }
};

/// `FSE_compress_usingCTable` into `out`; null when `src` is too short or does not fit.
pub fn compress(out: []u8, src: []const u8, table: *const CTable) ?usize {
    if (src.len <= 2) return null;
    if (out.len <= 8) return null;
    var stream: Stream = .init(out);
    var ip = src.len;
    var state_1: State = undefined;
    var state_2: State = undefined;
    if (src.len & 1 != 0) {
        state_1 = .init2(table, src[ip - 1]);
        state_2 = .init2(table, src[ip - 2]);
        state_1.encode(table, &stream, src[ip - 3]);
        ip -= 3;
    } else {
        state_2 = .init2(table, src[ip - 1]);
        state_1 = .init2(table, src[ip - 2]);
        ip -= 2;
    }
    assert(ip % 2 == 0);
    while (ip > 0) : (ip -= 2) {
        state_2.encode(table, &stream, src[ip - 1]);
        state_1.encode(table, &stream, src[ip - 2]);
    }
    state_2.flush(table, &stream);
    state_1.flush(table, &stream);
    return stream.close();
}
