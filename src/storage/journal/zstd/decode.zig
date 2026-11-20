//! Zstandard frame decoder (RFC 8878) for one frame that declares its content size.
//!
//! `std.compress.zstd` decodes these frames correctly but copies every match one byte at a
//! time, so a compressible journal item decompressed at about 0.6 GB/s where libzstd, which
//! commonware calls, runs at several GB/s. This decoder follows libzstd's checks: every
//! bitstream must be consumed exactly, offsets must stay within the decoded bytes, blocks
//! regenerate at most 128 KiB, a non-zero dictionary ID fails, and a content checksum, when
//! present, must match.
//!
//! Decoding writes straight into the caller's output buffer. Huffman and RLE literals are
//! regenerated into its unwritten tail, as libzstd places them in the destination, so a
//! block's sequences consume them from the end while writing from the front; a match that
//! would reach the unconsumed literals is corruption (the frame regenerates more than it
//! declares).

const std = @import("std");
const assert = std.debug.assert;
const zstd_std = std.compress.zstd;

pub const Error = error{DecompressionFailed};

const magic: u32 = 0xFD2FB528;
const block_size_max = zstd_std.block_size_max;
/// libzstd's `ZSTD_WINDOWLOG_MAX` on 64-bit targets.
const window_log_max = 31;

/// libzstd's `HUF_TABLELOG_MAX`: it writes at most 11 bits but reads 12.
const huffman_bits_max = 12;
const huffman_weights_max = 255;
const huffman_weight_log_max = 6;

const literals_length_symbol_max = 35;
const offset_symbol_max = 31;
const match_length_symbol_max = 52;
const literals_length_log_max = 9;
const offset_log_max = 8;
const match_length_log_max = 9;

/// FSE tables are at most 2^9 states over at most 53 symbols (match lengths).
const fse_states_max = 1 << 9;
const fse_symbols_max = 64;

comptime {
    assert(block_size_max == 128 * 1024);
    assert(match_length_symbol_max < fse_symbols_max);
    assert(zstd_std.literals_length_code_table.len == literals_length_symbol_max + 1);
    assert(zstd_std.match_length_code_table.len == match_length_symbol_max + 1);
}

/// Decodes the single frame that is all of `compressed` into `out`, whose length must be the
/// frame's declared content size.
pub fn decode_frame(compressed: []const u8, out: []u8) Error!void {
    var input: Input = .{ .bytes = compressed };
    const header = try read_frame_header(&input);
    if (header.content_size != out.len) return error.DecompressionFailed;
    const block_limit: usize = @intCast(@min(header.window_size, block_size_max));
    var decoder: Decoder = .{ .out = out, .block_limit = block_limit };
    while (true) {
        const block_header = try input.take_int(u24);
        const last = block_header & 1 == 1;
        const size: usize = block_header >> 3;
        if (size > block_limit) return error.DecompressionFailed;
        switch (@as(u2, @truncate(block_header >> 1))) {
            0 => try decoder.write_bytes(try input.take(size)),
            1 => try decoder.write_byte((try input.take(1))[0], size),
            2 => try decoder.decode_block(try input.take(size)),
            3 => return error.DecompressionFailed,
        }
        if (last) break;
    }
    if (decoder.write != out.len) return error.DecompressionFailed;
    if (header.checksum) {
        const expected = std.mem.readInt(u32, (try input.take(4))[0..4], .little);
        const actual: u32 = @truncate(std.hash.XxHash64.hash(0, out));
        if (expected != actual) return error.DecompressionFailed;
    }
    if (input.pos != compressed.len) return error.DecompressionFailed;
    assert(decoder.write == out.len);
}

/// Forward reader over a byte slice.
const Input = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(input: *Input, len: usize) Error![]const u8 {
        if (input.bytes.len - input.pos < len) return error.DecompressionFailed;
        const slice = input.bytes[input.pos..][0..len];
        input.pos += len;
        assert(input.pos <= input.bytes.len);
        return slice;
    }

    fn take_int(input: *Input, comptime T: type) Error!T {
        comptime assert(@bitSizeOf(T) % 8 == 0);
        const bytes = try input.take(@bitSizeOf(T) / 8);
        return std.mem.readInt(T, bytes[0 .. @bitSizeOf(T) / 8], .little);
    }
};

const FrameHeader = struct { content_size: u64, window_size: u64, checksum: bool };

fn read_frame_header(input: *Input) Error!FrameHeader {
    assert(input.pos == 0);
    if (try input.take_int(u32) != magic) return error.DecompressionFailed;
    const descriptor = (try input.take(1))[0];
    const content_size_flag: u2 = @truncate(descriptor >> 6);
    const single_segment = descriptor & 0x20 != 0;
    if (descriptor & 0x08 != 0) return error.DecompressionFailed; // Reserved bit.
    var window_size: u64 = 0;
    if (!single_segment) {
        const window = (try input.take(1))[0];
        const window_log = 10 + @as(u6, @intCast(window >> 3));
        if (window_log > window_log_max) return error.DecompressionFailed;
        const base = @as(u64, 1) << window_log;
        window_size = base + (base / 8) * (window & 7);
    }
    const dictionary_sizes = [4]usize{ 0, 1, 2, 4 };
    for (try input.take(dictionary_sizes[descriptor & 3])) |byte| {
        // No dictionary is loaded, so a frame that names one fails, as in libzstd.
        if (byte != 0) return error.DecompressionFailed;
    }
    const content_size: u64 = switch (content_size_flag) {
        0 => if (single_segment) (try input.take(1))[0] else return error.DecompressionFailed,
        1 => @as(u64, try input.take_int(u16)) + 256,
        2 => try input.take_int(u32),
        3 => try input.take_int(u64),
    };
    assert(input.pos >= 6);
    return .{
        .content_size = content_size,
        // A single segment's window is its content.
        .window_size = if (single_segment) content_size else window_size,
        .checksum = descriptor & 0x04 != 0,
    };
}

/// Frame state carried between blocks: the output, repeat offsets, and the tables that
/// treeless literals and repeat-mode sequences reuse.
const Decoder = struct {
    out: []u8,
    /// The most a block may regenerate: the window, at most 128 KiB.
    block_limit: usize,
    write: usize = 0,
    repeats: [3]u32 = .{ 1, 4, 8 },
    /// Valid once `huffman_valid`; left undefined so a decoder starts without copying it.
    huffman: Huffman = undefined,
    huffman_valid: bool = false,
    /// Each sequence field's table for the current block (null before the first): a
    /// predefined table or the field's `storage`.
    tables: [3]?*const Fse = @splat(null),
    storage: [3]Fse = undefined,

    fn write_bytes(decoder: *Decoder, bytes: []const u8) Error!void {
        if (decoder.out.len - decoder.write < bytes.len) return error.DecompressionFailed;
        @memcpy(decoder.out[decoder.write..][0..bytes.len], bytes);
        decoder.write += bytes.len;
        assert(decoder.write <= decoder.out.len);
    }

    fn write_byte(decoder: *Decoder, byte: u8, len: usize) Error!void {
        if (decoder.out.len - decoder.write < len) return error.DecompressionFailed;
        @memset(decoder.out[decoder.write..][0..len], byte);
        decoder.write += len;
        assert(decoder.write <= decoder.out.len);
    }

    fn decode_block(decoder: *Decoder, block: []const u8) Error!void {
        assert(block.len <= block_size_max);
        const block_start = decoder.write;
        var input: Input = .{ .bytes = block };
        const literals = try decoder.decode_literals(&input);
        try decoder.decode_sequences(&input, literals);
        if (decoder.write - block_start > decoder.block_limit) return error.DecompressionFailed;
        assert(decoder.write <= decoder.out.len);
    }

    /// The block's literals: a slice of the input for raw literals, else of the output tail.
    fn decode_literals(decoder: *Decoder, input: *Input) Error![]const u8 {
        const header = try read_literals_header(input);
        if (header.regenerated > decoder.block_limit) return error.DecompressionFailed;
        if (header.kind == .raw) return input.take(header.regenerated);
        // Regenerate at the end of the output, past everything this block may write.
        if (decoder.out.len - decoder.write < header.regenerated) {
            return error.DecompressionFailed;
        }
        const tail = decoder.out[decoder.out.len - header.regenerated ..];
        switch (header.kind) {
            .raw => unreachable,
            .rle => @memset(tail, (try input.take(1))[0]),
            .compressed, .treeless => {
                const compressed = try input.take(header.compressed);
                var body = compressed;
                if (header.kind == .compressed) {
                    const used = try read_huffman(compressed, &decoder.huffman);
                    decoder.huffman_valid = true;
                    body = compressed[used..];
                } else if (!decoder.huffman_valid) return error.DecompressionFailed;
                try decode_huffman_literals(&decoder.huffman, body, header.streams, tail);
            },
        }
        assert(tail.len == header.regenerated);
        return tail;
    }

    fn decode_sequences(decoder: *Decoder, input: *Input, literals: []const u8) Error!void {
        const count = try read_sequence_count(input);
        if (count == 0) {
            if (input.pos != input.bytes.len) return error.DecompressionFailed;
            var run: Run = .init(decoder, literals);
            try run.finish();
            return;
        }
        const modes = (try input.take(1))[0];
        if (modes & 3 != 0) return error.DecompressionFailed; // Reserved bits.
        try select_table(input, @truncate(modes >> 6), .literals_length, decoder);
        try select_table(input, @truncate(modes >> 4), .offset, decoder);
        try select_table(input, @truncate(modes >> 2), .match_length, decoder);
        var bits: ReverseBits = try .init(input.bytes[input.pos..]);
        input.pos = input.bytes.len;
        var run: Run = .init(decoder, literals);
        try run.execute(&bits, count);
        if (!bits.finished()) return error.DecompressionFailed;
        try run.finish();
        assert(run.literal_pos == literals.len);
    }
};

const LiteralsKind = enum(u2) { raw, rle, compressed, treeless };

const LiteralsHeader = struct {
    kind: LiteralsKind,
    regenerated: usize,
    compressed: usize = 0,
    streams: u3 = 1,
};

fn read_literals_header(input: *Input) Error!LiteralsHeader {
    const first = (try input.take(1))[0];
    const kind: LiteralsKind = @fromBackingInt(@intCast(@as(u2, @truncate(first))));
    const size_format: u2 = @truncate(first >> 2);
    if (kind == .raw or kind == .rle) {
        const regenerated: usize = switch (size_format) {
            0, 2 => first >> 3,
            1 => (first >> 4) + (@as(usize, (try input.take(1))[0]) << 4),
            3 => blk: {
                const rest = try input.take(2);
                break :blk (first >> 4) + (@as(usize, rest[0]) << 4) +
                    (@as(usize, rest[1]) << 12);
            },
        };
        return .{ .kind = kind, .regenerated = regenerated };
    }
    // Compressed sizes: 10, 10, 14, or 18 bits each after the 4 bits of type and format.
    const extra = [4]usize{ 2, 2, 3, 4 };
    const rest = try input.take(extra[size_format]);
    var value: u64 = first;
    for (rest, 1..) |byte, index| value |= @as(u64, byte) << @intCast(8 * index);
    const width: u6 = switch (size_format) {
        0, 1 => 10,
        2 => 14,
        3 => 18,
    };
    const mask = (@as(u64, 1) << width) - 1;
    const header: LiteralsHeader = .{
        .kind = kind,
        .regenerated = @intCast((value >> 4) & mask),
        .compressed = @intCast((value >> (4 + width)) & mask),
        .streams = if (size_format == 0) 1 else 4,
    };
    assert(header.streams == 1 or header.streams == 4);
    return header;
}

fn read_sequence_count(input: *Input) Error!usize {
    const first = (try input.take(1))[0];
    if (first < 128) return first;
    if (first < 255) return (@as(usize, first - 128) << 8) + (try input.take(1))[0];
    const rest = try input.take(2);
    const count = @as(usize, rest[0]) + (@as(usize, rest[1]) << 8) + 0x7F00;
    assert(count >= 0x7F00);
    return count;
}

const SequenceField = enum(u2) { literals_length, offset, match_length };

const field_symbol_max = [3]u8{
    literals_length_symbol_max,
    offset_symbol_max,
    match_length_symbol_max,
};
const field_log_max = [3]u4{ literals_length_log_max, offset_log_max, match_length_log_max };
const field_predefined = [3]*const Fse{
    &predefined_literals_length,
    &predefined_offset,
    &predefined_match_length,
};

/// Sets the field's table for this block from its compression mode (RFC 8878 §3.1.1.3.2.1):
/// predefined, RLE, an FSE table description, or the previous block's table.
fn select_table(input: *Input, mode: u2, field: SequenceField, decoder: *Decoder) Error!void {
    const index = @backingInt(field);
    const symbol_max = field_symbol_max[index];
    const log_max = field_log_max[index];
    const storage = &decoder.storage[index];
    switch (mode) {
        0 => decoder.tables[index] = field_predefined[index],
        1 => {
            const symbol = (try input.take(1))[0];
            if (symbol > symbol_max) return error.DecompressionFailed;
            storage.set_rle(symbol);
            decoder.tables[index] = storage;
        },
        2 => {
            const counts = try read_counts(input.bytes[input.pos..], symbol_max, log_max);
            input.pos += counts.used;
            try storage.build(counts.norm[0..counts.symbols], counts.accuracy_log);
            decoder.tables[index] = storage;
        },
        3 => if (decoder.tables[index] == null) return error.DecompressionFailed,
    }
    assert(decoder.tables[index].?.accuracy_log <= log_max);
}

/// Executes a block's sequences: literal copies from `literals` and matches from the output.
const Run = struct {
    decoder: *Decoder,
    literals: []const u8,
    literal_pos: usize = 0,

    fn init(decoder: *Decoder, literals: []const u8) Run {
        assert(literals.len <= block_size_max);
        assert(decoder.write <= decoder.out.len);
        return .{ .decoder = decoder, .literals = literals };
    }

    /// The first output byte a match may not reach: every literal not yet copied must still
    /// fit after it (and, for literals in the output tail, it is where they start).
    fn limit(run: *const Run) usize {
        const pending = run.literals.len - run.literal_pos;
        assert(run.decoder.out.len >= pending);
        return run.decoder.out.len - pending;
    }

    fn execute(run: *Run, bits: *ReverseBits, count: usize) Error!void {
        assert(count > 0);
        const decoder = run.decoder;
        const ll_table = decoder.tables[@backingInt(SequenceField.literals_length)].?;
        const of_table = decoder.tables[@backingInt(SequenceField.offset)].?;
        const ml_table = decoder.tables[@backingInt(SequenceField.match_length)].?;
        var ll_state = bits.read(ll_table.accuracy_log);
        var of_state = bits.read(of_table.accuracy_log);
        var ml_state = bits.read(ml_table.accuracy_log);
        for (0..count) |index| {
            const of_entry = of_table.entries[of_state];
            const ml_entry = ml_table.entries[ml_state];
            const ll_entry = ll_table.entries[ll_state];
            const of_code: u5 = @intCast(of_entry.symbol);
            const offset_value = (@as(u32, 1) << of_code) + @as(u32, @intCast(bits.read(of_code)));
            const ml_base, const ml_bits = zstd_std.match_length_code_table[ml_entry.symbol];
            const match_length = ml_base + @as(u32, @intCast(bits.read(ml_bits)));
            const ll_base, const ll_bits = zstd_std.literals_length_code_table[ll_entry.symbol];
            const literal_length = ll_base + @as(u32, @intCast(bits.read(ll_bits)));
            if (index + 1 < count) {
                ll_state = ll_entry.base + @as(u16, @intCast(bits.read(ll_entry.bits)));
                ml_state = ml_entry.base + @as(u16, @intCast(bits.read(ml_entry.bits)));
                of_state = of_entry.base + @as(u16, @intCast(bits.read(of_entry.bits)));
            }
            const offset = try resolve_offset(&decoder.repeats, offset_value, literal_length);
            try run.sequence(literal_length, offset, match_length);
        }
        assert(decoder.write <= run.limit());
    }

    fn sequence(run: *Run, literal_length: usize, offset: usize, match_length: usize) Error!void {
        assert(offset > 0);
        const decoder = run.decoder;
        if (run.literals.len - run.literal_pos < literal_length) return error.DecompressionFailed;
        run.copy_literals(literal_length);
        if (offset > decoder.write) return error.DecompressionFailed;
        if (run.limit() - decoder.write < match_length) return error.DecompressionFailed;
        copy_match(decoder.out, decoder.write, offset, match_length);
        decoder.write += match_length;
        assert(decoder.write <= run.limit());
    }

    fn copy_literals(run: *Run, len: usize) void {
        const decoder = run.decoder;
        assert(run.literals.len - run.literal_pos >= len);
        assert(run.limit() >= decoder.write);
        // Literals in the output tail start at or after the write position.
        std.mem.copyForwards(
            u8,
            decoder.out[decoder.write..][0..len],
            run.literals[run.literal_pos..][0..len],
        );
        run.literal_pos += len;
        decoder.write += len;
    }

    fn finish(run: *Run) Error!void {
        run.copy_literals(run.literals.len - run.literal_pos);
        assert(run.literal_pos == run.literals.len);
        assert(run.decoder.write <= run.decoder.out.len);
    }
};

/// The match offset for `offset_value`, updating the repeat offsets (RFC 8878 §3.1.2.5).
fn resolve_offset(repeats: *[3]u32, offset_value: u32, literal_length: u32) Error!u32 {
    assert(offset_value > 0);
    // A copy: an aggregate assigned to `repeats.*` is written in place, so reading `repeats`
    // inside it would see the fields it already replaced.
    const old = repeats.*;
    if (offset_value > 3) {
        const offset = offset_value - 3;
        repeats.* = .{ offset, old[0], old[1] };
        return offset;
    }
    // A zero literal length shifts the repeat codes by one.
    const index = offset_value - 1 + @intFromBool(literal_length == 0);
    if (index == 0) return old[0];
    const offset = if (index == 3) old[0] -% 1 else old[index];
    if (offset == 0) return error.DecompressionFailed;
    repeats.* = if (index == 1) .{ offset, old[0], old[2] } else .{ offset, old[0], old[1] };
    assert(repeats[0] == offset and repeats[1] == old[0]);
    return offset;
}

/// Copies `len` bytes to `out[write..]` from `offset` bytes back, repeating the pattern when
/// the match overlaps itself.
fn copy_match(out: []u8, write: usize, offset: usize, len: usize) void {
    assert(offset > 0 and offset <= write);
    assert(out.len - write >= len);
    const dst = out[write..][0..len];
    if (offset >= len) {
        @memcpy(dst, out[write - offset ..][0..len]);
    } else if (offset == 1) {
        @memset(dst, out[write - 1]);
    } else {
        // `out[write - offset .. write + done]` repeats with period `offset`, so a chunk
        // copied from `done + offset` bytes back never overlaps itself.
        var done: usize = 0;
        while (done < len) {
            const back = done + offset;
            const chunk = @min(back, len - done);
            @memcpy(dst[done..][0..chunk], out[write + done - back ..][0..chunk]);
            done += chunk;
        }
    }
}

/// Reads a bitstream backward from its last byte, whose highest set bit marks the end.
/// Reads past the start yield zero bits and leave `remaining` negative.
const ReverseBits = struct {
    bytes: []const u8,
    /// Bits not yet read, below the marker.
    remaining: i64,

    fn init(bytes: []const u8) Error!ReverseBits {
        if (bytes.len == 0) return error.DecompressionFailed;
        const last = bytes[bytes.len - 1];
        if (last == 0) return error.DecompressionFailed;
        const marker: i64 = 7 - @as(i64, @clz(last));
        const bits: ReverseBits = .{
            .bytes = bytes,
            .remaining = @as(i64, @intCast(bytes.len - 1)) * 8 + marker,
        };
        assert(bits.remaining >= 0);
        return bits;
    }

    fn finished(bits: *const ReverseBits) bool {
        return bits.remaining == 0;
    }

    fn overflowed(bits: *const ReverseBits) bool {
        return bits.remaining < 0;
    }

    /// The next `n` bits (at most 32) without consuming them.
    fn peek(bits: *const ReverseBits, n: u6) u64 {
        assert(n <= 32);
        if (n == 0 or bits.remaining <= 0) return 0;
        const available: usize = @intCast(bits.remaining);
        const mask = (@as(u64, 1) << n) - 1;
        if (available >= n) {
            const start = available - n;
            return (bits.load(start / 8) >> @intCast(start % 8)) & mask;
        }
        // The stream starts inside these bits: the missing low bits read as zero.
        const low = bits.load(0) & ((@as(u64, 1) << @intCast(available)) - 1);
        return (low << @intCast(n - available)) & mask;
    }

    fn read(bits: *ReverseBits, n: anytype) u64 {
        const count: u6 = @intCast(n);
        const value = bits.peek(count);
        bits.remaining -= count;
        return value;
    }

    /// Eight bytes from `index`, zero-padded past the end.
    fn load(bits: *const ReverseBits, index: usize) u64 {
        assert(index < bits.bytes.len);
        if (bits.bytes.len - index >= 8) {
            return std.mem.readInt(u64, bits.bytes[index..][0..8], .little);
        }
        var word: [8]u8 = @splat(0);
        const tail = bits.bytes[index..];
        @memcpy(word[0..tail.len], tail);
        return std.mem.readInt(u64, &word, .little);
    }
};

/// Reads a bitstream forward from its first byte (FSE table descriptions).
const ForwardBits = struct {
    bytes: []const u8,
    consumed: usize = 0,

    /// The next `n` bits (at most 16), zero past the end.
    fn peek(bits: *const ForwardBits, n: u5) u32 {
        assert(n <= 16);
        var word: [4]u8 = @splat(0);
        const index = bits.consumed / 8;
        if (index < bits.bytes.len) {
            const tail = bits.bytes[index..];
            const len = @min(tail.len, word.len);
            @memcpy(word[0..len], tail[0..len]);
        }
        const value = std.mem.readInt(u32, &word, .little) >> @intCast(bits.consumed % 8);
        return value & ((@as(u32, 1) << n) - 1);
    }

    fn skip(bits: *ForwardBits, n: u5) void {
        bits.consumed += n;
    }

    /// Whole bytes read; more than the input means the description ran past its end.
    fn used(bits: *const ForwardBits) usize {
        return std.math.divCeil(usize, bits.consumed, 8) catch unreachable;
    }
};

const Counts = struct {
    norm: [fse_symbols_max]i16,
    symbols: usize,
    accuracy_log: u4,
    used: usize,
};

/// Reads an FSE table description (RFC 8878 §4.1.1), as libzstd's `FSE_readNCount`.
fn read_counts(bytes: []const u8, symbol_max: u8, log_max: u4) Error!Counts {
    assert(symbol_max < fse_symbols_max);
    var bits: ForwardBits = .{ .bytes = bytes };
    const accuracy_log = bits.peek(4) + 5;
    bits.skip(4);
    if (accuracy_log > log_max) return error.DecompressionFailed;
    var counts: Counts = .{
        .norm = @splat(0),
        .symbols = 0,
        .accuracy_log = @intCast(accuracy_log),
        .used = 0,
    };
    var remaining: i32 = (@as(i32, 1) << @intCast(accuracy_log)) + 1;
    var threshold: i32 = @as(i32, 1) << @intCast(accuracy_log);
    var width: u5 = @intCast(accuracy_log + 1);
    var previous_zero = false;
    var symbol: usize = 0;
    while (remaining > 1 and symbol <= symbol_max) {
        if (previous_zero) {
            // Two-bit repeat flags of zero-probability symbols; 3 means more follow.
            while (true) {
                const repeat = bits.peek(2);
                bits.skip(2);
                symbol += repeat;
                if (repeat != 3) break;
                if (symbol > symbol_max) return error.DecompressionFailed;
            }
            if (symbol > symbol_max) return error.DecompressionFailed;
        }
        const max: i32 = 2 * threshold - 1 - remaining;
        var count: i32 = @intCast(bits.peek(width - 1));
        if (count < max) {
            bits.skip(width - 1);
        } else {
            count = @intCast(bits.peek(width));
            if (count >= threshold) count -= max;
            bits.skip(width);
        }
        count -= 1; // -1 is the "less than one" probability.
        remaining -= if (count < 0) -count else count;
        counts.norm[symbol] = @intCast(count);
        symbol += 1;
        previous_zero = count == 0;
        if (remaining < 1) return error.DecompressionFailed;
        while (remaining < threshold) : (width -= 1) threshold >>= 1;
    }
    if (remaining != 1) return error.DecompressionFailed;
    counts.symbols = symbol;
    counts.used = bits.used();
    if (counts.used > bytes.len) return error.DecompressionFailed;
    assert(counts.symbols > 0 and counts.symbols <= @as(usize, symbol_max) + 1);
    return counts;
}

const FseEntry = struct { symbol: u8, bits: u8, base: u16 };

/// An FSE decoding table: each state names its symbol and how to reach the next state.
const Fse = struct {
    entries: [fse_states_max]FseEntry = undefined,
    accuracy_log: u4 = 0,

    /// The one-state table of a field whose every symbol is `symbol`.
    fn set_rle(table: *Fse, symbol: u8) void {
        table.accuracy_log = 0;
        table.entries[0] = .{ .symbol = symbol, .bits = 0, .base = 0 };
        assert(table.entries[0].symbol == symbol);
        assert(table.entries[0].bits == 0);
    }

    /// Builds the table for normalized counts that sum to `2^accuracy_log` (libzstd's
    /// `FSE_buildDTable`).
    fn build(table: *Fse, norm: []const i16, accuracy_log: u4) Error!void {
        assert(norm.len > 0 and norm.len <= fse_symbols_max);
        const size = @as(usize, 1) << accuracy_log;
        assert(size <= fse_states_max);
        var next: [fse_symbols_max]u16 = undefined;
        var high = size - 1;
        for (norm, 0..) |count, symbol| {
            if (count == -1) {
                table.entries[high] = .{ .symbol = @intCast(symbol), .bits = 0, .base = 0 };
                high -%= 1;
                next[symbol] = 1;
            } else next[symbol] = @intCast(count);
        }
        const step = (size >> 1) + (size >> 3) + 3;
        const mask = size - 1;
        var position: usize = 0;
        for (norm, 0..) |count, symbol| {
            for (0..@max(count, 0)) |_| {
                table.entries[position].symbol = @intCast(symbol);
                position = (position + step) & mask;
                while (position > high) position = (position + step) & mask;
            }
        }
        if (position != 0) return error.DecompressionFailed;
        for (table.entries[0..size]) |*entry| {
            const state = next[entry.symbol];
            next[entry.symbol] += 1;
            const bits: u8 = accuracy_log - @as(u8, std.math.log2_int(u16, state));
            entry.bits = bits;
            entry.base = @intCast((@as(usize, state) << @intCast(bits)) - size);
        }
        table.accuracy_log = accuracy_log;
        assert(table.entries[0].bits <= accuracy_log);
    }
};

fn predefined_table(norm: []const i16, accuracy_log: u4) Fse {
    @setEvalBranchQuota(100_000);
    var table: Fse = .{};
    table.build(norm, accuracy_log) catch unreachable; // The RFC's tables are valid.
    return table;
}

const predefined_literals_length = predefined_table(
    &zstd_std.literals_length_default_distribution,
    6,
);
const predefined_offset = predefined_table(&zstd_std.offset_codes_default_distribution, 5);
const predefined_match_length = predefined_table(
    &zstd_std.match_lengths_default_distribution,
    6,
);

const HuffmanEntry = struct { symbol: u8, bits: u8 };

/// A Huffman decoding table indexed by the next `max_bits` bits.
const Huffman = struct {
    entries: [1 << huffman_bits_max]HuffmanEntry = undefined,
    max_bits: u4 = 0,
};

/// Reads a Huffman tree description into `table`; returns its length in bytes.
fn read_huffman(bytes: []const u8, table: *Huffman) Error!usize {
    var weights: [huffman_weights_max + 1]u8 = undefined;
    if (bytes.len == 0) return error.DecompressionFailed;
    const header = bytes[0];
    var count: usize = 0;
    var used: usize = 0;
    if (header < 128) {
        used = 1 + @as(usize, header);
        if (bytes.len < used) return error.DecompressionFailed;
        count = try read_fse_weights(bytes[1..used], weights[0..huffman_weights_max]);
    } else {
        count = header - 127;
        used = 1 + (count + 1) / 2;
        if (bytes.len < used) return error.DecompressionFailed;
        for (0..count) |index| {
            const byte = bytes[1 + index / 2];
            weights[index] = if (index % 2 == 0) byte >> 4 else byte & 0x0F;
        }
    }
    try build_huffman(weights[0 .. count + 1], table);
    assert(used <= bytes.len);
    return used;
}

/// Decodes Huffman weights compressed with a two-state FSE stream (libzstd's
/// `FSE_decompress_wksp` tail): states alternate until a state update reads past the start.
fn read_fse_weights(bytes: []const u8, weights: *[huffman_weights_max]u8) Error!usize {
    const counts = try read_counts(bytes, huffman_bits_max + 1, huffman_weight_log_max);
    var table: Fse = .{};
    try table.build(counts.norm[0..counts.symbols], counts.accuracy_log);
    var bits: ReverseBits = try .init(bytes[counts.used..]);
    var states: [2]u16 = undefined;
    for (&states) |*state| state.* = @intCast(bits.read(table.accuracy_log));
    var count: usize = 0;
    var turn: usize = 0;
    while (true) : (turn ^= 1) {
        if (count > huffman_weights_max - 2) return error.DecompressionFailed;
        const entry = table.entries[states[turn]];
        weights[count] = entry.symbol;
        count += 1;
        states[turn] = entry.base + @as(u16, @intCast(bits.read(entry.bits)));
        if (bits.overflowed()) {
            weights[count] = table.entries[states[turn ^ 1]].symbol;
            count += 1;
            break;
        }
    }
    assert(count <= huffman_weights_max);
    return count;
}

/// Builds the table from the weights of all symbols but the last, whose weight is implied
/// (`weights` has room for it), as libzstd's `HUF_readStats` and `HUF_readDTableX1`.
fn build_huffman(weights: []u8, table: *Huffman) Error!void {
    assert(weights.len >= 2 and weights.len <= huffman_weights_max + 1);
    const explicit = weights[0 .. weights.len - 1];
    var rank_count: [huffman_bits_max + 2]u32 = @splat(0);
    var total: u32 = 0;
    for (explicit) |weight| {
        if (weight > huffman_bits_max) return error.DecompressionFailed;
        rank_count[weight] += 1;
        total += (@as(u32, 1) << @intCast(weight)) >> 1;
    }
    if (total == 0) return error.DecompressionFailed;
    const max_bits = std.math.log2_int(u32, total) + 1;
    if (max_bits > huffman_bits_max) return error.DecompressionFailed;
    const left = (@as(u32, 1) << @intCast(max_bits)) - total;
    if (!std.math.isPowerOfTwo(left)) return error.DecompressionFailed;
    const last_weight: u8 = std.math.log2_int(u32, left) + 1;
    weights[weights.len - 1] = last_weight;
    rank_count[last_weight] += 1;
    // At least two symbols of weight 1, and an even number of them.
    if (rank_count[1] < 2 or rank_count[1] % 2 != 0) return error.DecompressionFailed;
    var start: [huffman_bits_max + 2]u32 = undefined;
    var next: u32 = 0;
    for (1..@as(usize, max_bits) + 1) |weight| {
        start[weight] = next;
        next += rank_count[weight] << @intCast(weight - 1);
    }
    assert(next == @as(u32, 1) << @intCast(max_bits));
    for (weights, 0..) |weight, symbol| {
        if (weight == 0) continue;
        const len = @as(u32, 1) << @intCast(weight - 1);
        const entry: HuffmanEntry = .{
            .symbol = @intCast(symbol),
            .bits = @intCast(max_bits + 1 - weight),
        };
        @memset(table.entries[start[weight]..][0..len], entry);
        start[weight] += len;
    }
    table.max_bits = @intCast(max_bits);
}

/// Decodes Huffman-coded literals from one stream or four (with a 6-byte jump table).
fn decode_huffman_literals(
    table: *const Huffman,
    body: []const u8,
    streams: u3,
    out: []u8,
) Error!void {
    assert(streams == 1 or streams == 4);
    assert(table.max_bits > 0);
    if (streams == 1) return decode_huffman_stream(table, body, out);
    // libzstd needs the jump table and a byte per stream, and six literals to split.
    if (body.len < 10 or out.len < 6) return error.DecompressionFailed;
    const segment = (out.len + 3) / 4;
    if (3 * segment > out.len) return error.DecompressionFailed;
    var stream_start: usize = 6;
    for (0..4) |index| {
        const stream_len: usize = if (index < 3)
            std.mem.readInt(u16, body[2 * index ..][0..2], .little)
        else
            std.math.sub(usize, body.len, stream_start) catch return error.DecompressionFailed;
        if (body.len - stream_start < stream_len) return error.DecompressionFailed;
        const out_start = index * segment;
        const out_len = if (index < 3) segment else out.len - 3 * segment;
        const stream = body[stream_start..][0..stream_len];
        try decode_huffman_stream(table, stream, out[out_start..][0..out_len]);
        stream_start += stream_len;
    }
    assert(stream_start == body.len);
}

fn decode_huffman_stream(table: *const Huffman, stream: []const u8, out: []u8) Error!void {
    var bits: ReverseBits = try .init(stream);
    const max_bits = table.max_bits;
    assert(max_bits > 0 and max_bits <= huffman_bits_max);
    for (out) |*byte| {
        const entry = table.entries[@intCast(bits.peek(max_bits))];
        byte.* = entry.symbol;
        bits.remaining -= entry.bits;
    }
    if (!bits.finished()) return error.DecompressionFailed;
}
