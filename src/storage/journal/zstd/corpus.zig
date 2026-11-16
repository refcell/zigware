//! Sample inputs for the compressor's tests and benchmarks, generated from a seed.

const std = @import("std");
const assert = std.debug.assert;

const words = [_][]const u8{
    "the",     "of",        "and",     "to",       "in",       "is",          "that",      "for",
    "it",      "as",        "was",     "with",     "be",       "by",          "on",        "not",
    "block",   "journal",   "item",    "section",  "offset",   "position",    "proof",     "root",
    "digest",  "leaf",      "node",    "peak",     "range",    "storage",     "blob",      "sync",
    "commit",  "prune",     "replay",  "recover",  "size",     "partition",   "buffer",    "page",
    "network", "consensus", "vote",    "finalize", "leader",   "epoch",       "view",      "height",
    "message", "peer",      "channel", "timeout",  "notarize", "certificate", "signature", "key",
    "value",   "update",    "delete",  "snapshot", "batch",    "merkle",      "mountain",  "range",
};

/// English-like text: words from a fixed vocabulary, with punctuation and numbers.
pub fn text(random: std.Random, out: []u8) void {
    var len: usize = 0;
    while (len < out.len) {
        var word_buffer: [24]u8 = undefined;
        const word: []const u8 = switch (random.uintLessThan(u8, 16)) {
            0 => std.fmt.bufPrint(&word_buffer, "{d}", .{random.uintLessThan(u32, 100_000)}) catch
                unreachable, // Five digits fit in 24 bytes.
            1 => ".\n",
            2 => ", ",
            else => words[random.uintLessThan(usize, words.len)],
        };
        const take = @min(word.len, out.len - len);
        @memcpy(out[len..][0..take], word[0..take]);
        len += take;
        if (len < out.len and word[word.len - 1] != '\n') {
            out[len] = ' ';
            len += 1;
        }
    }
    assert(len == out.len);
}

/// Journal-like records of 48 bytes: an incrementing sequence number, a slowly increasing
/// timestamp, and one of 16 random 32-byte keys.
pub fn records(random: std.Random, out: []u8) void {
    var keys: [16][32]u8 = undefined;
    for (&keys) |*key| random.bytes(key);
    var record: [48]u8 = undefined;
    var timestamp: u64 = 1_700_000_000_000;
    var len: usize = 0;
    var sequence: u64 = 0;
    while (len < out.len) : (sequence += 1) {
        timestamp += random.uintLessThan(u64, 1_000);
        std.mem.writeInt(u64, record[0..8], sequence, .big);
        std.mem.writeInt(u64, record[8..16], timestamp, .big);
        record[16..48].* = keys[random.uintLessThan(usize, keys.len)];
        const take = @min(record.len, out.len - len);
        @memcpy(out[len..][0..take], record[0..take]);
        len += take;
    }
    assert(len == out.len);
}
