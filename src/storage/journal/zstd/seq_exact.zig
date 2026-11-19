//! libzstd 1.5.7's sequences section (`zstd_compress_sequences.c`, `ZSTD_seqToCodes`,
//! `ZSTD_buildSequencesStatistics`) for the double-fast strategy without a dictionary, byte
//! for byte.
//!
//! Without a dictionary no FSE table is ever `FSE_repeat_valid`, and dfast (below
//! `ZSTD_lazy`) reuses a previous table only when it is valid, so `set_repeat` is never chosen
//! and the previous block's FSE tables are never read: each block builds its own.

const std = @import("std");
const assert = std.debug.assert;
const zstd_std = std.compress.zstd;
const fse = @import("fse_exact.zig");
const Sequence = @import("dfast.zig").Sequence;

/// `SymbolEncodingType_e`.
pub const EncodingType = enum(u2) { basic = 0, rle = 1, compressed = 2, repeat = 3 };

/// `LONGNBSEQ`.
const long_nb_seq = 0x7F00;

/// Per-sequence code buffers, each at least as long as a block's sequences.
pub const Codes = struct { ll: []u8, of: []u8, ml: []u8 };

/// The three tables one block encodes with.
pub const Tables = struct {
    ll: fse.CTable = .{ .log = 0, .max_symbol = 0 },
    of: fse.CTable = .{ .log = 0, .max_symbol = 0 },
    ml: fse.CTable = .{ .log = 0, .max_symbol = 0 },
};

const ll_small = small_codes(zstd_std.literals_length_code_table, 64);
const ml_small = small_codes(zstd_std.match_length_code_table, 128);

/// `LL_Code` / `ML_Code`: the code of each value below `len`, from the codes' bases.
fn small_codes(comptime table: anytype, comptime len: usize) [len]u8 {
    @setEvalBranchQuota(100_000);
    const bias = table[0][0];
    var codes: [len]u8 = undefined;
    for (&codes, 0..) |*code, value| {
        var c: usize = table.len - 1;
        while (table[c][0] - bias > value) c -= 1;
        code.* = c;
    }
    return codes;
}

/// `ZSTD_LLcode`.
pub fn ll_code(literal_length: u32) u8 {
    const code: u8 = if (literal_length > 63)
        @as(u8, fse.highbit32(literal_length)) + 19
    else
        ll_small[literal_length];
    assert(code < zstd_std.literals_length_code_table.len);
    assert(zstd_std.literals_length_code_table[code][0] <= literal_length);
    return code;
}

/// `ZSTD_MLcode` of `match_length - 3`.
pub fn ml_code(match_length: u32) u8 {
    assert(match_length >= 3);
    const base = match_length - 3;
    const code: u8 = if (base > 127) @as(u8, fse.highbit32(base)) + 36 else ml_small[base];
    assert(zstd_std.match_length_code_table[code][0] <= match_length);
    return code;
}

/// `ZSTD_seqToCodes` (64-bit, so never long offsets).
fn to_codes(seqs: []const Sequence, codes: Codes) void {
    assert(codes.ll.len >= seqs.len);
    assert(codes.of.len >= seqs.len and codes.ml.len >= seqs.len);
    for (seqs, 0..) |seq, i| {
        assert(seq.off_base > 0);
        codes.ll[i] = ll_code(seq.literal_length);
        codes.of[i] = fse.highbit32(seq.off_base);
        codes.ml[i] = ml_code(seq.match_length);
    }
}

/// `ZSTD_selectEncodingType` below `ZSTD_lazy` (`mult` is 8) when no table is valid.
fn select_type(most: usize, nb: usize, default_log: u32, default_allowed: bool) EncodingType {
    assert(nb > 0);
    assert(default_log == 5 or default_log == 6);
    if (most == nb) return if (default_allowed and nb <= 2) .basic else .rle;
    if (default_allowed) {
        const dynamic_min = ((@as(usize, 1) << @intCast(default_log)) * 8) >> 3;
        if (nb < dynamic_min or most < nb >> @intCast(default_log - 1)) return .basic;
    }
    return .compressed;
}

/// One of the three symbol streams: its codes and libzstd's constants for it.
const Field = struct {
    codes: []const u8,
    max: u32,
    fse_log: u32,
    default_norm: []const i16,
    default_log: u32,
};

/// `HIST_countFast_wksp`, `ZSTD_selectEncodingType`, then `ZSTD_buildCTable`: writes the
/// table description into `out` and builds `table`. Returns the type and description size.
const Built = struct { EncodingType, usize };

fn build_field(out: []u8, table: *fse.CTable, field: Field) fse.Error!Built {
    const nb = field.codes.len;
    assert(nb > 0);
    var counts: [64]u32 = undefined;
    var max = field.max;
    const most = fse.count_simple(&counts, &max, field.codes);
    const default_max: u32 = @intCast(field.default_norm.len - 1);
    const kind = select_type(most, nb, field.default_log, max <= default_max);
    switch (kind) {
        .rle => {
            table.build_rle(@intCast(max));
            if (out.len == 0) return error.FseGeneric;
            out[0] = field.codes[0];
            return .{ kind, 1 };
        },
        .basic => {
            table.build(field.default_norm, default_max, field.default_log);
            return .{ kind, 0 };
        },
        .compressed => {
            const log = fse.optimal_table_log(field.fse_log, nb, max);
            var nb_1 = nb;
            if (counts[field.codes[nb - 1]] > 1) {
                counts[field.codes[nb - 1]] -= 1;
                nb_1 -= 1;
            }
            assert(nb_1 > 1);
            var norm: [64]i16 = undefined;
            try fse.normalize(&norm, log, &counts, nb_1, max, nb_1 >= 2048);
            const len = try fse.write_ncount(out, &norm, max, log);
            table.build(&norm, max, log);
            return .{ kind, len };
        },
        .repeat => unreachable,
    }
}

fn add_extras(stream: *fse.Stream, seq: Sequence, codes: Codes, i: usize) void {
    const ll = zstd_std.literals_length_code_table[codes.ll[i]];
    const ml = zstd_std.match_length_code_table[codes.ml[i]];
    assert(seq.literal_length >= ll[0]);
    assert(seq.match_length >= ml[0]);
    stream.add(seq.literal_length - ll[0], ll[1]);
    stream.add(seq.match_length - ml[0], ml[1]);
    stream.add(seq.off_base, @intCast(codes.of[i]));
}

/// `ZSTD_encodeSequences`: null when the stream does not fit.
fn encode_stream(out: []u8, seqs: []const Sequence, codes: Codes, tables: *const Tables) ?usize {
    assert(seqs.len > 0);
    if (out.len <= 8) return null;
    var stream: fse.Stream = .init(out);
    const last = seqs.len - 1;
    var ml: fse.State = .init2(&tables.ml, codes.ml[last]);
    var of: fse.State = .init2(&tables.of, codes.of[last]);
    var ll: fse.State = .init2(&tables.ll, codes.ll[last]);
    add_extras(&stream, seqs[last], codes, last);
    var i = last;
    while (i > 0) {
        i -= 1;
        of.encode(&tables.of, &stream, codes.of[i]);
        ml.encode(&tables.ml, &stream, codes.ml[i]);
        ll.encode(&tables.ll, &stream, codes.ll[i]);
        add_extras(&stream, seqs[i], codes, i);
    }
    ml.flush(&tables.ml, &stream);
    of.flush(&tables.of, &stream);
    ll.flush(&tables.ll, &stream);
    return stream.close();
}

/// The sequences section of a block (from `ZSTD_entropyCompressSeqStore_internal`): the
/// count, then for at least one sequence the modes byte, tables, and bit stream. Null when
/// libzstd falls back to a raw block (no room, or its 1.3.4 workaround).
pub fn compress_sequences(out: []u8, seqs: []const Sequence, codes: Codes) ?usize {
    if (out.len < 4) return null;
    const nb = seqs.len;
    assert(nb < 0x7F00 + 0x10000);
    var op: usize = 0;
    if (nb < 128) {
        out[0] = @intCast(nb);
        op = 1;
    } else if (nb < long_nb_seq) {
        out[0] = @intCast((nb >> 8) + 0x80);
        out[1] = @truncate(nb);
        op = 2;
    } else {
        out[0] = 0xFF;
        std.mem.writeInt(u16, out[1..3], @intCast(nb - long_nb_seq), .little);
        op = 3;
    }
    if (nb == 0) return op;
    to_codes(seqs, codes);
    const head = op;
    op += 1;
    var tables: Tables = .{};
    const fields = [3]Field{
        make_field(codes.ll[0..nb], 35, 9, &zstd_std.literals_length_default_distribution, 6),
        make_field(codes.of[0..nb], 31, 8, &zstd_std.offset_codes_default_distribution, 5),
        make_field(codes.ml[0..nb], 52, 9, &zstd_std.match_lengths_default_distribution, 6),
    };
    const targets = [3]*fse.CTable{ &tables.ll, &tables.of, &tables.ml };
    var modes: u8 = 0;
    var last_count_len: usize = 0;
    for (fields, targets, 0..) |f, table, i| {
        const kind, const len = build_field(out[op..], table, f) catch return null;
        modes |= @as(u8, @backingInt(kind)) << @intCast(6 - 2 * i);
        if (kind == .compressed) last_count_len = len;
        op += len;
    }
    out[head] = modes;
    const stream_len = encode_stream(out[op..], seqs, codes, &tables) orelse return null;
    if (last_count_len > 0 and last_count_len + stream_len < 4) return null;
    return op + stream_len;
}

fn make_field(codes: []const u8, max: u32, fse_log: u32, norm: []const i16, log: u32) Field {
    assert(codes.len > 0);
    assert(norm.len > 0);
    return .{
        .codes = codes,
        .max = max,
        .fse_log = fse_log,
        .default_norm = norm,
        .default_log = log,
    };
}
