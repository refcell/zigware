//! commonware `authenticated/data.rs` `test_decode_does_not_allocate`: decoding a received
//! data record allocates nothing and borrows the message from the record. commonware counts
//! allocation calls with a tracking allocator; here the decode runs on a failing allocator.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const Data = @import("data.zig").Data;

test "decoding data does not allocate and borrows the message" {
    const gpa = testing.allocator;
    const original: Data = .{ .channel = 12345, .message = "Hello, world!" };
    // The record arrives in one buffer, as commonware's `frame` builds it.
    const frame = try codec.encode(Data, gpa, original);
    defer gpa.free(frame);
    const decoded = try codec.decode_cfg(Data, testing.failing_allocator, frame, .full());
    try testing.expectEqual(original.channel, decoded.channel);
    try testing.expectEqualStrings(original.message, decoded.message);
    const frame_start = @intFromPtr(frame.ptr);
    const message_start = @intFromPtr(decoded.message.ptr);
    try testing.expect(message_start > frame_start);
    try testing.expect(message_start + decoded.message.len <= frame_start + frame.len);
}
