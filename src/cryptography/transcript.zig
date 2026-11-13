//! Transcripts: hash a sequence of messages into a `Summary`, fork them, sign them, and draw
//! deterministic randomness from them (commonware `cryptography/src/transcript.rs`).
//!
//! A transcript is a BLAKE3 hasher. It starts with a one-byte tag (new, resume, fork,
//! noise); `resume`, `fork`, and `noise` key the hasher with the summary they extend. Each
//! committed message is followed by the varint of its length (the bytes appended since the
//! last commit); version 1 writes that varint byte-reversed, so a message cannot imitate a
//! length followed by more data. `summarize` flushes any pending length on a copy.
//! Wire-compatible with commonware: summaries, forks, and noise are byte-identical.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const digest = @import("digest.zig");
const Blake3 = std.crypto.hash.Blake3;

/// The 32-byte digest of a transcript.
pub const Summary = digest.Digest(Blake3.digest_length, "transcript");

const StartTag = enum(u8) { new = 0, resume_from = 1, fork = 2, noise = 3 };

/// How a committed message's length is framed.
pub const Version = enum {
    /// The length varint as is.
    v0,
    /// The length varint byte-reversed.
    v1,
};

/// Hashes `pending` as the framed length of the message just committed.
fn flush(hasher: *Blake3, pending: u64, version: Version) void {
    var bytes: [codec.varint.max_size(u64)]u8 = undefined;
    var writer = codec.Writer.init(&bytes);
    codec.varint.write(u64, pending, &writer);
    const length = writer.written();
    assert(length.len == codec.varint.size(u64, pending));
    if (version == .v1) std.mem.reverse(u8, length);
    hasher.update(length);
}

pub const Transcript = struct {
    hasher: Blake3,
    /// Bytes appended since the last commit.
    pending: u64,
    version: Version,

    fn start(tag: StartTag, summary: ?Summary, version: Version) Transcript {
        var hasher = Blake3.init(.{ .key = if (summary) |s| s.bytes else null });
        hasher.update(&.{@backingInt(tag)});
        return .{ .hasher = hasher, .pending = 0, .version = version };
    }

    /// A transcript for `namespace`, which is committed as its first message.
    pub fn init(namespace: []const u8, version: Version) Transcript {
        var transcript = start(.new, null, version);
        transcript.commit(namespace);
        return transcript;
    }

    /// Continues from `summary` without its history.
    pub fn resume_from(summary: Summary, version: Version) Transcript {
        return start(.resume_from, summary, version);
    }

    /// Appends `data` and ends the message.
    pub fn commit(self: *Transcript, data: []const u8) void {
        self.append(data);
        flush(&self.hasher, self.pending, self.version);
        self.pending = 0;
    }

    /// Appends `data` to the current message without ending it. A message longer than
    /// `u64` bytes is a programming error, checked before anything is hashed.
    pub fn append(self: *Transcript, data: []const u8) void {
        const pending = std.math.add(u64, self.pending, data.len) catch
            @panic("transcript packet exceeds u64::MAX bytes");
        self.hasher.update(data);
        self.pending = pending;
        assert(self.pending >= data.len);
    }

    /// A transcript derived from this one and `label`.
    pub fn fork(self: *const Transcript, label: []const u8) Transcript {
        var out = start(.fork, self.summarize(), self.version);
        out.commit(label);
        return out;
    }

    /// A deterministic random stream derived from this transcript and `label`.
    pub fn noise(self: *const Transcript, label: []const u8) Noise {
        var out = start(.noise, self.summarize(), self.version);
        out.commit(label);
        return .{ .hasher = out.hasher, .position = 0 };
    }

    /// Shuffles `items` (a slice) with Fisher-Yates over `noise(label)`.
    pub fn shuffle(self: *const Transcript, label: []const u8, items: anytype) void {
        var rng = self.noise(label);
        var index = items.len;
        while (index > 1) {
            index -= 1;
            const other = sample(&rng, index + 1);
            assert(other <= index);
            std.mem.swap(@TypeOf(items[0]), &items[index], &items[@intCast(other)]);
        }
    }

    /// A uniform value in `[0, bound)` from `noise(label)`.
    pub fn sample_label(self: *const Transcript, label: []const u8, bound: u64) u64 {
        var rng = self.noise(label);
        return sample(&rng, bound);
    }

    pub fn summarize(self: *const Transcript) Summary {
        var hasher = self.hasher;
        if (self.pending != 0) flush(&hasher, self.pending, self.version);
        var summary: Summary = undefined;
        hasher.final(&summary.bytes);
        return summary;
    }

    /// Signs the summary with an empty namespace.
    pub fn sign(self: *const Transcript, signer: anytype) @TypeOf(signer.*).Signature {
        return sign_summary(self.summarize(), signer);
    }

    pub fn verify(self: *const Transcript, public_key: anytype, signature: anytype) bool {
        return verify_summary(self.summarize(), public_key, signature);
    }
};

/// Signs `summary` with an empty namespace (commonware `Summary::sign`).
pub fn sign_summary(summary: Summary, signer: anytype) @TypeOf(signer.*).Signature {
    return signer.sign("", &summary.bytes);
}

/// Verifies a signature from `sign_summary` (commonware `Summary::verify`).
pub fn verify_summary(summary: Summary, public_key: anytype, signature: anytype) bool {
    return public_key.verify("", &summary.bytes, signature);
}

/// A uniform value in `[0, bound)` by rejection sampling over `next_u64`.
pub fn sample(rng: anytype, bound: u64) u64 {
    assert(bound > 0);
    const zone = bound * (std.math.maxInt(u64) / bound);
    // Each draw is accepted with probability above 1/2.
    while (true) {
        const value = rng.next_u64();
        if (value < zone) return value % bound;
    }
}

/// The BLAKE3 extendable output of a noise transcript, read in order.
pub const Noise = struct {
    hasher: Blake3,
    position: u64,

    pub fn fill_bytes(self: *Noise, dest: []u8) void {
        self.hasher.finalizeSeek(self.position, dest);
        self.position += dest.len;
    }

    pub fn next_u32(self: *Noise) u32 {
        var bytes: [4]u8 = undefined;
        self.fill_bytes(&bytes);
        return std.mem.readInt(u32, &bytes, .little);
    }

    pub fn next_u64(self: *Noise) u64 {
        var bytes: [8]u8 = undefined;
        self.fill_bytes(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }
};

test {
    _ = @import("transcript_test.zig");
}
