//! A mock automaton for aggregation (commonware `aggregation/mocks/application.rs`): the
//! digest of each height is the SHA-256 of `data for height <h>`.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const cryptography = @import("cryptography");
const Height = @import("../../types.zig").Height;

const Sha256 = cryptography.Sha256;

pub const Strategy = union(enum) {
    /// Propose the correct digest for every height.
    correct,
    /// Propose a conflicting digest for every height (a Byzantine validator).
    incorrect,
    /// Decline to propose at `height` (the request is dropped).
    skip: Height,
};

pub const Application = struct {
    pub const Context = Height;
    pub const Digest = Sha256.Digest;

    strategy: Strategy,

    pub fn init(strategy: Strategy) Application {
        return .{ .strategy = strategy };
    }

    fn hash(comptime format: []const u8, height: Height) Digest {
        var buffer: [64]u8 = undefined;
        const payload = std.fmt.bufPrint(&buffer, format, .{height.get()}) catch unreachable;
        assert(payload.len > 0); // Proof above: the longest payload is 40 bytes.
        return Sha256.hash(&.{payload});
    }

    /// The digest correct validators propose at `height`.
    pub fn correct_digest(height: Height) Digest {
        return hash("data for height {d}", height);
    }

    pub fn propose(self: *const Application, io: Io, height: Height) Io.Cancelable!?Digest {
        _ = io;
        return switch (self.strategy) {
            .correct => correct_digest(height),
            .incorrect => hash("conflicting_data for height {d}", height),
            .skip => |skipped| if (skipped == height) null else correct_digest(height),
        };
    }

    pub fn verify(
        self: *const Application,
        io: Io,
        height: Height,
        payload: Digest,
    ) Io.Cancelable!?bool {
        _ = self;
        _ = io;
        return payload.order(correct_digest(height)) == .eq;
    }
};

test "application digests" {
    const correct: Application = .init(.correct);
    const io = std.testing.io;
    const digest = (try correct.propose(io, .new(3))).?;
    const expected = Sha256.hash(&.{"data for height 3"});
    try std.testing.expect(digest.order(expected) == .eq);
    try std.testing.expect((try correct.verify(io, .new(3), digest)).?);
    const incorrect: Application = .init(.incorrect);
    const conflicting = (try incorrect.propose(io, .new(3))).?;
    try std.testing.expect(!(try correct.verify(io, .new(3), conflicting)).?);
    const skip: Application = .init(.{ .skip = .new(2) });
    try std.testing.expectEqual(null, try skip.propose(io, .new(2)));
    try std.testing.expect((try skip.propose(io, .new(1))) != null);
}
