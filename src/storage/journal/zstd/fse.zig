//! FSE (tANS) encoding (RFC 8878 §4.1): normalized distributions, their table descriptions,
//! and encoder states whose bits `std.compress.zstd` decodes.
//!
//! The state spread and the per-symbol transforms follow libzstd's `FSE_buildCTable`, which
//! mirrors the decoder's table construction; an encoder state is `table_size + position`.

const std = @import("std");
const assert = std.debug.assert;
const bits = @import("bits.zig");

/// Largest alphabet: match length codes (53 symbols).
pub const symbols_max = 64;
pub const accuracy_log_min = 5;
pub const accuracy_log_max = 9;
const table_size_max = 1 << accuracy_log_max;

/// Normalized symbol probabilities summing to `1 << accuracy_log`: 0 is absent, -1 is
/// "less than one" (one state, read with the full accuracy log).
pub const Distribution = struct {
    norm: [symbols_max]i16 = @splat(0),
    /// One past the largest symbol with a nonzero probability.
    symbol_count: u8 = 0,
    accuracy_log: u4 = accuracy_log_min,

    /// A distribution from a predefined table, such as `literals_length_default_distribution`.
    pub fn predefined(norm: []const i16, accuracy_log: u4) Distribution {
        assert(norm.len <= symbols_max);
        var result: Distribution = .{ .accuracy_log = accuracy_log };
        @memcpy(result.norm[0..norm.len], norm);
        result.symbol_count = @intCast(norm.len);
        assert(result.total() == @as(u32, 1) << accuracy_log);
        return result;
    }

    fn total(self: *const Distribution) u32 {
        var sum: u32 = 0;
        for (self.norm[0..self.symbol_count]) |norm| sum += @abs(norm);
        return sum;
    }

    /// The bits `counts` cost under this distribution (excluding extra bits), or null if a
    /// counted symbol has no probability.
    pub fn cost(self: *const Distribution, counts: []const u32) ?f64 {
        assert(counts.len <= symbols_max);
        var sum: f64 = 0;
        const log: f64 = @floatFromInt(self.accuracy_log);
        for (counts, 0..) |count, symbol| {
            if (count == 0) continue;
            if (symbol >= self.symbol_count or self.norm[symbol] == 0) return null;
            const probability: f64 = @floatFromInt(@abs(self.norm[symbol]));
            sum += @as(f64, @floatFromInt(count)) * (log - std.math.log2(probability));
        }
        assert(sum >= 0);
        return sum;
    }
};

/// libzstd's `FSE_optimalTableLog`: enough states for the alphabet, no more than the input
/// size justifies.
pub fn optimal_accuracy_log(max_log: u4, total: u32, max_symbol: u8) u4 {
    assert(max_log >= accuracy_log_min and max_log <= accuracy_log_max);
    assert(total >= 2);
    const max_bits_source = std.math.log2_int(u32, total - 1) -| 2;
    const min_bits_source = std.math.log2_int(u32, total) + 1;
    const min_bits_symbols = std.math.log2_int(u32, @max(max_symbol, 1)) + 2;
    var log: u32 = max_log;
    log = @min(log, max_bits_source);
    log = @max(log, @min(min_bits_source, min_bits_symbols));
    return @intCast(std.math.clamp(log, accuracy_log_min, max_log));
}

/// Scales `counts` (at least two distinct symbols) to sum to `1 << accuracy_log`, keeping
/// every counted symbol at least 1.
pub fn normalize(counts: []const u32, accuracy_log: u4) Distribution {
    assert(counts.len <= symbols_max);
    const table_size: u64 = @as(u64, 1) << accuracy_log;
    var result: Distribution = .{ .accuracy_log = accuracy_log };
    var total: u64 = 0;
    for (counts) |count| total += count;
    assert(total >= 2);
    var sum: u64 = 0;
    var largest: usize = 0;
    for (counts, 0..) |count, symbol| {
        if (count == 0) continue;
        const scaled = @max(1, count * table_size / total);
        result.norm[symbol] = @intCast(scaled);
        result.symbol_count = @intCast(symbol + 1);
        sum += scaled;
        if (count > counts[largest]) largest = symbol;
    }
    if (sum <= table_size) {
        result.norm[largest] += @intCast(table_size - sum);
    } else {
        shave(&result, sum - table_size);
    }
    assert(result.total() == table_size);
    return result;
}

/// Takes `excess` probability from the largest entries, keeping each at least 1.
fn shave(distribution: *Distribution, excess_initial: u64) void {
    var excess = excess_initial;
    while (excess > 0) {
        var largest: usize = 0;
        for (distribution.norm[0..distribution.symbol_count], 0..) |norm, symbol| {
            if (norm > distribution.norm[largest]) largest = symbol;
        }
        const room: u64 = @intCast(distribution.norm[largest] - 1);
        assert(room > 0); // The accuracy log leaves room for every symbol.
        const take = @min(room, excess);
        distribution.norm[largest] -= @intCast(take);
        excess -= take;
    }
    assert(excess == 0);
}

/// Writes the table description (RFC 8878 §4.1.1), as libzstd's `FSE_writeNCount`.
pub fn write_description(distribution: *const Distribution, writer: *bits.Writer) void {
    const log = distribution.accuracy_log;
    assert(log >= accuracy_log_min);
    writer.add(log - accuracy_log_min, 4);
    var remaining: i32 = (@as(i32, 1) << log) + 1;
    var threshold: i32 = @as(i32, 1) << log;
    var nb_bits: u6 = @as(u6, log) + 1;
    var symbol: usize = 0;
    var previous_zero = false;
    while (remaining > 1) {
        if (previous_zero) {
            const start = symbol;
            while (distribution.norm[symbol] == 0) symbol += 1;
            var zeros = symbol - start;
            while (zeros >= 3) : (zeros -= 3) writer.add(3, 2);
            writer.add(zeros, 2);
        }
        const norm = distribution.norm[symbol];
        symbol += 1;
        const max = 2 * threshold - 1 - remaining;
        remaining -= @abs(norm);
        var value: i32 = norm + 1;
        if (value >= threshold) value += max;
        writer.add(@intCast(value), nb_bits - @intFromBool(value < max));
        previous_zero = value == 1;
        while (remaining < threshold) {
            nb_bits -= 1;
            threshold >>= 1;
        }
    }
    assert(remaining == 1);
    assert(symbol <= distribution.symbol_count);
}

/// Encoding transforms for one distribution.
pub const Table = struct {
    accuracy_log: u4,
    /// `table_size + position` of each symbol's states, grouped by symbol in position order.
    state_table: [table_size_max]u16,
    delta_nb_bits: [symbols_max]u32,
    delta_find_state: [symbols_max]i32,
    first_state: [symbols_max]u16,

    pub fn init(distribution: *const Distribution) Table {
        const log = distribution.accuracy_log;
        const table_size: u32 = @as(u32, 1) << log;
        assert(distribution.total() == table_size);
        var symbol_at: [table_size_max]u8 = undefined;
        spread(distribution, symbol_at[0..table_size]);

        var table: Table = .{
            .accuracy_log = log,
            .state_table = undefined,
            .delta_nb_bits = @splat(0),
            .delta_find_state = @splat(0),
            .first_state = @splat(0),
        };
        var cumulative: [symbols_max + 1]u32 = @splat(0);
        for (distribution.norm[0..distribution.symbol_count], 0..) |norm, symbol| {
            cumulative[symbol + 1] = cumulative[symbol] + @abs(norm);
        }
        var next = cumulative;
        for (symbol_at[0..table_size], 0..) |symbol, position| {
            table.state_table[next[symbol]] = @intCast(table_size + position);
            next[symbol] += 1;
        }
        for (distribution.norm[0..distribution.symbol_count], 0..) |norm, symbol| {
            if (norm == 0) continue;
            table.set_transform(@intCast(symbol), @abs(norm), cumulative[symbol]);
        }
        assert(cumulative[distribution.symbol_count] == table_size);
        return table;
    }

    fn set_transform(table: *Table, symbol: u8, count: u32, cumulative: u32) void {
        assert(count > 0);
        const log: u32 = table.accuracy_log;
        if (count == 1) {
            table.delta_nb_bits[symbol] = (log << 16) - (@as(u32, 1) << @intCast(log));
        } else {
            const max_bits_out = log - std.math.log2_int(u32, count - 1);
            table.delta_nb_bits[symbol] = (max_bits_out << 16) - (count << @intCast(max_bits_out));
        }
        table.delta_find_state[symbol] = @as(i32, @intCast(cumulative)) - @as(i32, @intCast(count));
        table.first_state[symbol] = table.state_table[cumulative];
        assert(table.first_state[symbol] >= @as(u32, 1) << @intCast(log));
    }
};

/// The decoder's symbol spread: "less than one" symbols at the top, the rest stepped through
/// the remaining positions.
fn spread(distribution: *const Distribution, symbol_at: []u8) void {
    const table_size = symbol_at.len;
    assert(std.math.isPowerOfTwo(table_size));
    var high = table_size - 1;
    for (distribution.norm[0..distribution.symbol_count], 0..) |norm, symbol| {
        if (norm != -1) continue;
        symbol_at[high] = @intCast(symbol);
        high -= 1;
    }
    const step = (table_size >> 1) + (table_size >> 3) + 3;
    var position: usize = 0;
    for (distribution.norm[0..distribution.symbol_count], 0..) |norm, symbol| {
        if (norm <= 0) continue;
        for (0..@intCast(norm)) |_| {
            symbol_at[position] = @intCast(symbol);
            position = (position + step) & (table_size - 1);
            while (position > high) position = (position + step) & (table_size - 1);
        }
    }
    assert(position == 0);
}

/// One encoder state; the decoder reads states and bits in the reverse order they are written.
pub const State = struct {
    value: u32,

    /// A state that decodes `symbol` with at least one bit when the decoder updates it.
    pub fn init(table: *const Table, symbol: u8) State {
        const value = table.first_state[symbol];
        assert(value >= @as(u32, 1) << table.accuracy_log);
        return .{ .value = value };
    }

    /// Moves to a state that decodes `symbol`, writing the bits that lead back to this one.
    pub fn encode(self: *State, table: *const Table, writer: *bits.Writer, symbol: u8) void {
        const nb_bits: u5 = @intCast((self.value + table.delta_nb_bits[symbol]) >> 16);
        assert(nb_bits <= table.accuracy_log);
        writer.add(self.value & ((@as(u32, 1) << nb_bits) - 1), nb_bits);
        const index = @as(i32, @intCast(self.value >> nb_bits)) + table.delta_find_state[symbol];
        self.value = table.state_table[@intCast(index)];
        assert(self.value >= @as(u32, 1) << table.accuracy_log);
    }

    /// Writes the state for the decoder to start from.
    pub fn flush(self: State, table: *const Table, writer: *bits.Writer) void {
        const table_size = @as(u32, 1) << table.accuracy_log;
        assert(self.value >= table_size and self.value < 2 * table_size);
        writer.add(self.value - table_size, table.accuracy_log);
    }
};

const testing = std.testing;

test "normalize keeps every symbol and sums to the table size" {
    const counts = [_]u32{ 1000, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    for (accuracy_log_min..accuracy_log_max + 1) |log| {
        const distribution = normalize(&counts, @intCast(log));
        try testing.expectEqual(@as(u32, 1) << @intCast(log), distribution.total());
        for (counts, 0..) |count, symbol| {
            try testing.expectEqual(count > 0, distribution.norm[symbol] > 0);
        }
        try testing.expectEqual(@as(u8, counts.len), distribution.symbol_count);
    }
}

test "optimal accuracy log stays in range" {
    try testing.expectEqual(@as(u4, 5), optimal_accuracy_log(9, 2, 1));
    try testing.expectEqual(@as(u4, 9), optimal_accuracy_log(9, 100_000, 52));
    try testing.expectEqual(@as(u4, 8), optimal_accuracy_log(8, 100_000, 31));
    try testing.expectEqual(@as(u4, 5), optimal_accuracy_log(6, 255, 11));
    try testing.expectEqual(@as(u4, 6), optimal_accuracy_log(6, 1000, 11));
}
