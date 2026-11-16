//! Metric labels of the lookup network (commonware `p2p/src/authenticated/lookup/metrics.rs`).

const std = @import("std");
const assert = std.debug.assert;
const p2p = @import("../../root.zig");

/// Per-peer label.
pub fn Peer(comptime P: type) type {
    return struct { peer: P };
}

/// The kind of a message sent to or received from a peer.
pub const MessageType = union(enum) {
    data: p2p.Channel,
    ping,
    invalid,

    /// The label value (commonware's `Display`): `data_<channel>` or the kind's name.
    pub fn format(message: MessageType, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (message) {
            .data => |channel| try writer.print("data_{d}", .{channel}),
            else => try writer.writeAll(@tagName(message)),
        }
    }
};

/// Per-peer, per-message-type label.
pub fn Message(comptime P: type) type {
    return struct {
        const Self = @This();

        peer: P,
        message: MessageType,

        pub fn new_data(peer: P, channel: p2p.Channel) Self {
            return .{ .peer = peer, .message = .{ .data = channel } };
        }

        pub fn new_ping(peer: P) Self {
            return .{ .peer = peer, .message = .ping };
        }

        pub fn new_invalid(peer: P) Self {
            return .{ .peer = peer, .message = .invalid };
        }
    };
}

test "message types render like commonware's Display" {
    var buffer: [32]u8 = undefined;
    const cases = [_]struct { MessageType, []const u8 }{
        .{ .{ .data = 0 }, "data_0" },
        .{ .{ .data = std.math.maxInt(u64) }, "data_18446744073709551615" },
        .{ .ping, "ping" },
        .{ .invalid, "invalid" },
    };
    for (cases) |case| {
        const text = try std.fmt.bufPrint(&buffer, "{f}", .{case[0]});
        try std.testing.expectEqualStrings(case[1], text);
    }
    assert(cases.len == 4);
}
