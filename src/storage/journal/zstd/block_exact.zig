//! libzstd 1.5.7's block loop for level 3 (`ZSTD_compress_frameChunk`,
//! `ZSTD_compressBlock_internal`, `ZSTD_entropyCompressSeqStore`), byte for byte: dfast
//! sequences, the literals section, the sequences section, and the raw, RLE, and
//! compressed block choices with libzstd's repeat-state confirmation.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const dfast = @import("dfast.zig");
const huf = @import("huf_exact.zig");
const seq = @import("seq_exact.zig");
const params = @import("params.zig");

pub const block_size_max = 128 * 1024;
/// `MIN_CBLOCK_SIZE + ZSTD_blockHeaderSize + 1 + 1`: smaller blocks are stored raw.
const block_len_min = 7;
/// `rleMaxLength` in `ZSTD_compressBlock_internal`.
const rle_max_length = 25;
/// `SUSPECT_UNCOMPRESSIBLE_LITERAL_RATIO`.
const suspect_literal_ratio = 20;
/// Room for one block's literals and sequences sections: any body libzstd keeps is smaller
/// than the block, so this never refuses one it would keep.
fn scratch_len(cap: usize) usize {
    return 2 * cap + 1024;
}

const block_type_raw: u24 = 0;
const block_type_rle: u24 = 1;
const block_type_compressed: u24 = 2;

/// The compression state of one frame.
pub const Encoder = struct {
    state: dfast.State,
    sequences: std.ArrayList(dfast.Sequence),
    /// Literals, per-sequence codes, and the block being written.
    buffer: []u8,
    /// The confirmed repeat offsets and Huffman tables (`prevCBlock`).
    rep: [dfast.rep_num]u32 = .{ 1, 4, 8 },
    tables: huf.Tables = .{},
    /// What a compressed block confirms (`nextCBlock`).
    next_rep: [dfast.rep_num]u32 = undefined,
    next_tables: huf.Tables = .{},
    first: bool = true,
    /// The largest block this frame holds.
    cap: usize,

    pub fn init(gpa: Allocator, len: usize) Allocator.Error!Encoder {
        // Blocks are at most `cap` bytes, so every buffer is sized to it.
        const cap = cap_of(len);
        var state = try dfast.State.init(gpa, params.level3(len));
        errdefer state.deinit(gpa);
        var sequences = try std.ArrayList(dfast.Sequence).initCapacity(gpa, cap);
        errdefer sequences.deinit(gpa);
        const buffer = try gpa.alloc(u8, 4 * cap + scratch_len(cap));
        assert(buffer.len > 4 * cap);
        assert(sequences.capacity >= cap);
        return .{ .state = state, .sequences = sequences, .buffer = buffer, .cap = cap };
    }

    pub fn deinit(enc: *Encoder, gpa: Allocator) void {
        assert(enc.buffer.len > 0);
        gpa.free(enc.buffer);
        enc.sequences.deinit(gpa);
        enc.state.deinit(gpa);
        enc.* = undefined;
    }

    fn cap_of(len: usize) usize {
        return @max(block_len_min, @min(len, block_size_max));
    }

    /// Whether `reset` can start a frame of `len` bytes in this encoder's buffers.
    pub fn fits(enc: *const Encoder, len: usize) bool {
        const cap = cap_of(len);
        return enc.buffer.len >= 4 * cap + scratch_len(cap) and
            enc.sequences.capacity >= cap and enc.state.fits(params.level3(len));
    }

    /// Start a new frame of `len` bytes with a fresh frame's state: the initial repeat
    /// offsets, no Huffman tables, and cleared match tables (a reused `ZSTD_CCtx`).
    pub fn reset(enc: *Encoder, len: usize) void {
        assert(enc.fits(len));
        enc.state.reset(params.level3(len));
        enc.sequences.clearRetainingCapacity();
        enc.rep = .{ 1, 4, 8 };
        enc.tables = .{};
        enc.next_rep = undefined;
        enc.next_tables = .{};
        enc.first = true;
        enc.cap = cap_of(len);
        assert(enc.first and enc.sequences.items.len == 0);
    }

    fn literals(enc: *Encoder) []u8 {
        return enc.buffer[0..enc.cap];
    }

    fn codes(enc: *Encoder) seq.Codes {
        const cap = enc.cap;
        const base = enc.buffer[cap..];
        return .{
            .ll = base[0..cap],
            .of = base[cap..][0..cap],
            .ml = base[2 * cap ..][0..cap],
        };
    }

    fn scratch(enc: *Encoder) []u8 {
        const out = enc.buffer[4 * enc.cap ..][0..scratch_len(enc.cap)];
        assert(4 * enc.cap + out.len <= enc.buffer.len);
        return out;
    }

    /// Appends the blocks of a frame holding `src` (at least one, the last one marked) to
    /// `out`, which must have room for `src.len` plus 3 bytes per block.
    pub fn compress(enc: *Encoder, src: []const u8, out: *std.ArrayList(u8)) void {
        assert(enc.first);
        var start: usize = 0;
        // `savings`: bytes saved so far, block headers included; splitting needs 3.
        var savings: i64 = 0;
        while (true) {
            const remaining = src.len - start;
            const len = if (remaining < block_size_max or savings < 3)
                @min(remaining, block_size_max)
            else
                split_block(src[start..][0..block_size_max]);
            const end = start + len;
            const before = out.items.len;
            enc.write_block(src, start, end, end == src.len, out);
            savings += @as(i64, @intCast(len)) - @as(i64, @intCast(out.items.len - before));
            enc.first = false;
            start = end;
            if (start == src.len) break;
        }
        assert(start == src.len);
    }

    fn write_block(
        enc: *Encoder,
        src: []const u8,
        start: usize,
        end: usize,
        last: bool,
        out: *std.ArrayList(u8),
    ) void {
        assert(start <= end and end <= src.len);
        const len = end - start;
        const block = src[start..end];
        enc.state.enforce_max_dist(end);
        var body_len: usize = 0;
        if (len >= block_len_min) {
            body_len = enc.compress_body(src, start, end);
            if (!enc.first and body_len < rle_max_length and is_rle(block)) body_len = 1;
        }
        if (body_len > 1) {
            enc.rep = enc.next_rep;
            enc.tables = enc.next_tables;
        }
        const last_bit: u24 = @intFromBool(last);
        const header: u24 = switch (body_len) {
            0 => last_bit + (block_type_raw << 1) + (@as(u24, @intCast(len)) << 3),
            1 => last_bit + (block_type_rle << 1) + (@as(u24, @intCast(len)) << 3),
            else => last_bit + (block_type_compressed << 1) + (@as(u24, @intCast(body_len)) << 3),
        };
        var bytes: [3]u8 = undefined;
        std.mem.writeInt(u24, &bytes, header, .little);
        out.appendSliceAssumeCapacity(&bytes);
        switch (body_len) {
            0 => out.appendSliceAssumeCapacity(block),
            1 => out.appendAssumeCapacity(block[0]),
            else => out.appendSliceAssumeCapacity(enc.scratch()[0..body_len]),
        }
    }

    /// The compressed body of `src[start..end]` in `scratch`, or 0 when libzstd would store
    /// the block raw. Sets `next_rep` and `next_tables`.
    fn compress_body(enc: *Encoder, src: []const u8, start: usize, end: usize) usize {
        const len = end - start;
        assert(len >= block_len_min and len <= enc.cap);
        enc.sequences.clearRetainingCapacity();
        enc.next_rep = enc.rep;
        const last_literals = dfast.compress_block(
            &enc.state,
            src,
            start,
            end,
            &enc.sequences,
            &enc.next_rep,
        );
        const seqs = enc.sequences.items;
        // Without sequences the literals are the block itself. Raw literals and the sequence
        // count then outgrow the block, so when Huffman would not shrink them libzstd stores
        // the block raw: decide that from the block, without copying it twice.
        const block_literals = if (seqs.len == 0) src[start..end] else literals: {
            const lit_len = gather_literals(enc.literals(), src, start, end, seqs, last_literals);
            break :literals enc.literals()[0..lit_len];
        };
        if (seqs.len == 0) {
            assert(last_literals == len);
            if (huf.suspect_literals_stay_raw(block_literals, &enc.tables)) return 0;
        }
        const suspect = seqs.len == 0 or block_literals.len / seqs.len >= suspect_literal_ratio;
        const out = enc.scratch();
        const literals_len = huf.compress_literals(
            out,
            block_literals,
            &enc.tables,
            &enc.next_tables,
            suspect,
        );
        const sequences_len = seq.compress_sequences(out[literals_len..], seqs, enc.codes()) orelse
            return 0;
        const body_len = literals_len + sequences_len;
        const min_gain = (len >> 6) + 2;
        if (body_len >= len - min_gain) return 0;
        assert(body_len < block_size_max);
        return body_len;
    }
};

/// `seqStore.litStart`: the literals of each sequence, then the block's last literals.
fn gather_literals(
    out: []u8,
    src: []const u8,
    start: usize,
    end: usize,
    seqs: []const dfast.Sequence,
    last_literals: u32,
) usize {
    var pos = start;
    var len: usize = 0;
    for (seqs) |s| {
        @memcpy(out[len..][0..s.literal_length], src[pos..][0..s.literal_length]);
        len += s.literal_length;
        pos += s.literal_length + s.match_length;
    }
    assert(pos + last_literals == end);
    @memcpy(out[len..][0..last_literals], src[pos..end]);
    len += last_literals;
    assert(len <= end - start);
    return len;
}

/// `ZSTD_splitBlock_byChunks` at dfast's level: byte histograms sampled every 43 bytes of
/// each 8 KiB chunk, cut at the first chunk too different from those before it.
fn split_block(block: []const u8) usize {
    assert(block.len == block_size_max);
    const chunk = 8 * 1024;
    var past: Fingerprint = .record(block[0..chunk]);
    var penalty: u64 = 3;
    var pos: usize = chunk;
    while (pos <= block.len - chunk) : (pos += chunk) {
        const next: Fingerprint = .record(block[pos..][0..chunk]);
        if (past.differs(&next, penalty)) return pos;
        for (&past.events, next.events) |*event, add| event.* += add;
        past.count += next.count;
        if (penalty > 0) penalty -= 1;
    }
    assert(pos == block.len);
    return block.len;
}

/// `Fingerprint` with `hashLog` 8: each sampled byte is its own event.
const Fingerprint = struct {
    events: [256]u64,
    count: u64,

    const sampling_rate = 43;

    fn record(chunk: []const u8) Fingerprint {
        assert(chunk.len >= 2);
        var fp: Fingerprint = .{ .events = @splat(0), .count = 0 };
        const limit = chunk.len - 1;
        var n: usize = 0;
        while (n < limit) : (n += sampling_rate) fp.events[chunk[n]] += 1;
        fp.count = limit / sampling_rate;
        assert(fp.count > 0);
        return fp;
    }

    /// `compareFingerprints`: whether `new`'s distribution is too far from `past`'s.
    fn differs(past: *const Fingerprint, new: *const Fingerprint, penalty: u64) bool {
        assert(past.count > 0 and new.count > 0);
        assert(penalty <= 3);
        var deviation: u64 = 0;
        for (past.events, new.events) |a, b| {
            const x: i64 = @intCast(a * new.count);
            const y: i64 = @intCast(b * past.count);
            deviation += @abs(x - y);
        }
        const threshold = past.count * new.count * (14 + penalty) / 16;
        return deviation >= threshold;
    }
};

/// `ZSTD_isRLE`. Like libzstd's unrolled loop, it ORs the XOR of 128 bytes at a time against
/// the first byte, then checks the tail byte by byte.
pub fn is_rle(block: []const u8) bool {
    assert(block.len > 0);
    const lanes = 32;
    const Lane = @Vector(lanes, u8);
    const first: Lane = @splat(block[0]);
    var index: usize = 0;
    while (index + 4 * lanes <= block.len) : (index += 4 * lanes) {
        const chunk = block[index..][0 .. 4 * lanes];
        var difference: Lane = @as(Lane, chunk[0..lanes].*) ^ first;
        difference |= @as(Lane, chunk[lanes..][0..lanes].*) ^ first;
        difference |= @as(Lane, chunk[2 * lanes ..][0..lanes].*) ^ first;
        difference |= @as(Lane, chunk[3 * lanes ..][0..lanes].*) ^ first;
        if (@reduce(.Or, difference) != 0) return false;
    }
    assert(block.len - index < 4 * lanes);
    for (block[index..]) |byte| {
        if (byte != block[0]) return false;
    }
    return true;
}
