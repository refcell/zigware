//! A value served to the network by a p2p `Producer` (commonware `Bytes`).

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Bytes a producer serves. When `gpa` is set the value owns `bytes`; the engine releases it
/// with `deinit` after sending, and a oneshot channel releases an unreceived one with
/// `discard`.
pub const Produced = struct {
    bytes: []const u8,
    gpa: ?Allocator = null,

    pub fn deinit(produced: Produced) void {
        if (produced.gpa) |gpa| gpa.free(produced.bytes);
    }

    pub fn discard(produced: Produced) void {
        produced.deinit();
    }
};
