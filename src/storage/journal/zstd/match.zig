//! LZ77 match finding for zstd blocks, after libzstd's "double fast" strategy (levels 2-3):
//! the three repeat offsets, then one candidate from a table hashed on 8 bytes and one from a
//! table hashed on 5 bytes, a 4-byte prefix check before extending, a few positions inside
//! each match indexed, and backward extension into the pending literals. A hash chain four
//! deep with a lazy step (the first version) compressed text slightly worse at twice the time.
//!
//! The matcher also keeps the frame's repeat offsets (RFC 8878 §3.1.2.5) and turns each
//! match offset into the sequence's offset value, so the two never disagree.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const match_length_min = 4;
/// Matches reach back less than the 128 KiB window the frame header declares.
pub const offset_max = (1 << 17) - 1;
/// A repeat or long-table match this long skips the remaining candidates.
const good_length = 8;
/// Matches shorter than this are compared with the best match one byte later.
const lazy_length_max = 6;
const hash_log_min = 8;
const hash_log_max = 16;

pub const Sequence = struct {
    literal_length: u32,
    match_length: u32,
    /// 1-3 select a repeat offset; larger values are the offset plus 3.
    offset_value: u32,
};

const Match = struct { length: u32 = 0, offset: u32 = 0 };

pub const Matcher = struct {
    /// Last position + 1 whose 8 bytes hash to each bucket; 0 is empty.
    long: []u32,
    /// Last position + 1 whose 5 bytes hash to each bucket; 0 is empty.
    short: []u32,
    long_log: u6,
    short_log: u6,
    repeats: [3]u32 = .{ 1, 4, 8 },

    /// A matcher for one frame of `len` bytes.
    pub fn init(gpa: Allocator, len: usize) Allocator.Error!Matcher {
        const log: u6 = @intCast(std.math.clamp(
            std.math.log2_int_ceil(usize, @max(len, 2)),
            hash_log_min,
            hash_log_max,
        ));
        const long = try gpa.alloc(u32, @as(usize, 1) << (log + 1));
        errdefer gpa.free(long);
        const short = try gpa.alloc(u32, @as(usize, 1) << log);
        @memset(long, 0);
        @memset(short, 0);
        return .{ .long = long, .short = short, .long_log = log + 1, .short_log = log };
    }

    pub fn deinit(self: *Matcher, gpa: Allocator) void {
        gpa.free(self.long);
        gpa.free(self.short);
        self.* = undefined;
    }

    fn hash_long(self: *const Matcher, src: []const u8, position: usize) usize {
        const value = std.mem.readInt(u64, src[position..][0..8], .little);
        return @intCast((value *% 0xCF1BBCDCB7A56463) >> @intCast(64 - @as(u7, self.long_log)));
    }

    fn hash_short(self: *const Matcher, src: []const u8, position: usize) usize {
        const value = std.mem.readInt(u64, src[position..][0..8], .little) << 24;
        return @intCast((value *% 0xCF1BBCDCB7A56463) >> @intCast(64 - @as(u7, self.short_log)));
    }

    /// Records `position` in both tables, when 8 bytes remain to hash.
    fn insert(self: *Matcher, src: []const u8, position: usize) void {
        if (position + 8 > src.len) return;
        self.long[self.hash_long(src, position)] = @intCast(position + 1);
        self.short[self.hash_short(src, position)] = @intCast(position + 1);
    }

    /// Splits `src[start..end]` into sequences and literals, matching anywhere earlier in
    /// `src` within the window. Returns the sequence count; `literals_len` gets the literal
    /// bytes, including the block's trailing literals.
    pub fn find(
        self: *Matcher,
        src: []const u8,
        start: usize,
        end: usize,
        sequences: []Sequence,
        literals: []u8,
        literals_len: *usize,
    ) usize {
        assert(start <= end and end <= src.len);
        assert(literals.len >= end - start);
        var count: usize = 0;
        var anchor = start;
        var position = start;
        var literal_count: usize = 0;
        while (position + match_length_min <= end) {
            var best = self.search(src, position, end);
            if (best.length < match_length_min) {
                position += 1 + ((position - anchor) >> 8);
                continue;
            }
            if (best.length < lazy_length_max and position + 1 + match_length_min <= end) {
                const next = self.search(src, position + 1, end);
                if (next.length > best.length) {
                    best = next;
                    position += 1;
                }
            }
            while (position > anchor and position > best.offset and
                src[position - 1] == src[position - 1 - best.offset])
            {
                position -= 1;
                best.length += 1;
            }
            const literal_length = position - anchor;
            @memcpy(literals[literal_count..][0..literal_length], src[anchor..position]);
            literal_count += literal_length;
            sequences[count] = .{
                .literal_length = @intCast(literal_length),
                .match_length = best.length,
                .offset_value = self.offset_value(best.offset, literal_length),
            };
            count += 1;
            // Index a few positions inside the match, as libzstd's double-fast does.
            self.insert(src, position + 2);
            position += best.length;
            anchor = position;
            if (position >= 2) self.insert(src, position - 2);
            if (position >= 1) self.insert(src, position - 1);
        }
        @memcpy(literals[literal_count..][0 .. end - anchor], src[anchor..end]);
        literals_len.* = literal_count + end - anchor;
        assert(count <= sequences.len);
        return count;
    }

    /// The longest match at `position` among the repeat offsets and both tables, which then
    /// record `position`.
    fn search(self: *Matcher, src: []const u8, position: usize, end: usize) Match {
        assert(position < end);
        var best: Match = .{};
        const quad = position + 4 <= end;
        const head4 = if (quad) read32(src, position) else 0;
        for (self.repeats) |offset| {
            if (offset > position or offset > offset_max) continue;
            if (quad and read32(src, position - offset) != head4) continue;
            const length = match_length(src, position - offset, position, end);
            if (length > best.length) best = .{ .length = length, .offset = offset };
        }
        if (position + 8 <= src.len) {
            const candidates = [2]u32{
                self.long[self.hash_long(src, position)],
                self.short[self.hash_short(src, position)],
            };
            for (candidates) |candidate| {
                if (best.length >= good_length) break;
                if (candidate == 0) continue;
                const earlier = candidate - 1;
                assert(earlier < position);
                const offset = position - earlier;
                if (offset > offset_max) continue;
                if (quad and read32(src, earlier) != head4) continue;
                const length = match_length(src, earlier, position, end);
                if (length > best.length) best = .{ .length = length, .offset = @intCast(offset) };
            }
        }
        self.insert(src, position);
        assert(best.length <= end - position);
        return best;
    }

    /// The offset value for a match at `offset` after `literal_length` literals, updating the
    /// repeat offsets as the decoder will.
    fn offset_value(self: *Matcher, offset: u32, literal_length: usize) u32 {
        assert(offset > 0 and offset <= offset_max);
        const r = self.repeats;
        if (literal_length > 0) {
            if (offset == r[0]) return 1;
            if (offset == r[1]) return self.use_repeat(.{ r[1], r[0], r[2] }, 2);
            if (offset == r[2]) return self.use_repeat(.{ r[2], r[0], r[1] }, 3);
        } else {
            if (offset == r[1]) return self.use_repeat(.{ r[1], r[0], r[2] }, 1);
            if (offset == r[2]) return self.use_repeat(.{ r[2], r[0], r[1] }, 2);
            if (r[0] > 1 and offset == r[0] - 1) return self.use_repeat(.{ offset, r[0], r[1] }, 3);
        }
        return self.use_repeat(.{ offset, r[0], r[1] }, offset + 3);
    }

    fn use_repeat(self: *Matcher, repeats: [3]u32, value: u32) u32 {
        assert(value > 0);
        assert(repeats[0] > 0);
        self.repeats = repeats;
        return value;
    }
};

fn read32(src: []const u8, position: usize) u32 {
    return std.mem.readInt(u32, src[position..][0..4], .little);
}

/// Bytes `src[earlier..]` and `src[position..end]` share, compared eight at a time.
fn match_length(src: []const u8, earlier: usize, position: usize, end: usize) u32 {
    assert(earlier < position and position <= end);
    var length: usize = 0;
    while (position + length + 8 <= end) : (length += 8) {
        const a = std.mem.readInt(u64, src[earlier + length ..][0..8], .little);
        const b = std.mem.readInt(u64, src[position + length ..][0..8], .little);
        if (a != b) return @intCast(length + @ctz(a ^ b) / 8);
    }
    while (position + length < end and src[earlier + length] == src[position + length]) {
        length += 1;
    }
    assert(position + length <= end);
    return @intCast(length);
}

const testing = std.testing;

test "matcher finds repeats and reproduces the input" {
    const gpa = testing.allocator;
    const src = "abcdefgh-abcdefgh-abcdefgh-xyz-abcdefgh";
    var matcher: Matcher = try .init(gpa, src.len);
    defer matcher.deinit(gpa);
    var sequences: [src.len]Sequence = undefined;
    var literals: [src.len]u8 = undefined;
    var literals_len: usize = 0;
    const count = matcher.find(src, 0, src.len, &sequences, &literals, &literals_len);
    try testing.expect(count >= 1);
    try testing.expect(literals_len < src.len);
    // Replay with the decoder's repeat-offset rules.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var repeats = [3]u32{ 1, 4, 8 };
    var literal_index: usize = 0;
    for (sequences[0..count]) |sequence| {
        const ll = sequence.literal_length;
        try out.appendSlice(gpa, literals[literal_index..][0..ll]);
        literal_index += ll;
        const offset = decode_offset(&repeats, sequence.offset_value, ll);
        for (0..sequence.match_length) |_| try out.append(gpa, out.items[out.items.len - offset]);
    }
    try out.appendSlice(gpa, literals[literal_index..literals_len]);
    try testing.expectEqualStrings(src, out.items);
}

fn decode_offset(repeats: *[3]u32, value: u32, literal_length: u32) u32 {
    if (value > 3) {
        repeats.* = .{ value - 3, repeats[0], repeats[1] };
        return value - 3;
    }
    const index = value - @intFromBool(literal_length > 0);
    const r = repeats.*;
    switch (index) {
        0 => return r[0],
        1 => repeats.* = .{ r[1], r[0], r[2] },
        2 => repeats.* = .{ r[2], r[0], r[1] },
        else => repeats.* = .{ r[0] - 1, r[0], r[1] },
    }
    return repeats[0];
}
