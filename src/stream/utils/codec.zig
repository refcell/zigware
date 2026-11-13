//! Length-prefixed framing (commonware `stream/src/utils/codec.rs`): every frame is a
//! `UInt<u32>` varint length followed by that many bytes.
//!
//! The transport is any sink/stream pair with the contract in `stream.mocks`:
//! `sink.send([]const []const u8)`, `stream.recv([]u8)` (exactly that many bytes), and
//! `stream.peek(max_len)`. Received frames land in a caller buffer, so receiving never
//! allocates; the buffer must hold `max_message_size` bytes.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const codec = @import("codec");

const max_prefix_size = codec.varint.max_u32_varint_size;

/// Errors that can occur when sending or receiving a length-prefixed frame. Transport errors
/// map to `RecvFailed`/`SendFailed`; cancelation passes through.
pub const Error = error{
    RecvFailed,
    RecvTooLarge,
    InvalidVarint,
    SendFailed,
    SendTooLarge,
} || Io.Cancelable;

/// Returns `len` as a u32 if it does not exceed `max_message_size`.
pub fn validate_frame_len(len: usize, max_message_size: u32) error{SendTooLarge}!u32 {
    if (len > max_message_size) return error.SendTooLarge;
    const result: u32 = @intCast(len);
    assert(result <= max_message_size);
    return result;
}

/// Sends `parts` as one frame with a varint length prefix. The prefix goes out as its own
/// buffer, so the message is not copied.
pub fn send_frame(sink: anytype, parts: []const []const u8, max_message_size: u32) Error!void {
    const parts_max = 15;
    assert(parts.len <= parts_max);
    var total: usize = 0;
    for (parts) |part| total += part.len;
    const len = try validate_frame_len(total, max_message_size);

    var prefix: [max_prefix_size]u8 = undefined;
    var writer = codec.Writer.init(&prefix);
    codec.varint.write(u32, len, &writer);
    var bufs: [parts_max + 1][]const u8 = undefined;
    bufs[0] = writer.written();
    @memcpy(bufs[1..][0..parts.len], parts);
    assert(bufs[0].len == codec.varint.size(u32, len));
    sink.send(bufs[0 .. parts.len + 1]) catch |err| return map_error(err, error.SendFailed);
}

/// Receives one frame into `buffer` and returns its payload. Fails with `RecvTooLarge` when the
/// declared length exceeds `max_message_size`, before reading the payload.
pub fn recv_frame(stream: anytype, buffer: []u8, max_message_size: u32) Error![]u8 {
    assert(buffer.len >= max_message_size);
    const length = try recv_length(stream);
    if (length.len > max_message_size) return error.RecvTooLarge;
    assert(length.skip < max_prefix_size);

    // Read any unconsumed prefix bytes together with the payload, then drop them.
    const total = length.skip + length.len;
    if (total <= buffer.len) {
        try recv(stream, buffer[0..total]);
        std.mem.copyForwards(u8, buffer[0..length.len], buffer[length.skip..total]);
    } else {
        var skipped: [max_prefix_size]u8 = undefined;
        try recv(stream, skipped[0..length.skip]);
        try recv(stream, buffer[0..length.len]);
    }
    return buffer[0..length.len];
}

pub const Length = struct {
    /// Declared payload length.
    len: usize,
    /// Prefix bytes still buffered in the stream (decoded through `peek`, not consumed).
    skip: usize,
};

/// Receives and decodes the varint length prefix.
pub fn recv_length(stream: anytype) Error!Length {
    var decoder = codec.varint.Decoder(u32).init();
    // Every iteration feeds at least one byte, and a u32 varint ends within five.
    var iteration: usize = 0;
    while (iteration < max_prefix_size) : (iteration += 1) {
        // Use buffered prefix bytes before requesting another byte from the stream.
        const peeked = stream.peek(max_prefix_size);
        assert(peeked.len <= max_prefix_size);
        for (peeked, 0..) |byte, index| {
            const value = decoder.feed(byte) catch return error.InvalidVarint;
            if (value) |len| return .{ .len = len, .skip = index + 1 };
        }

        // Consume the peeked bytes already fed and one more byte to make progress.
        var bytes: [max_prefix_size + 1]u8 = undefined;
        const count = peeked.len + 1;
        try recv(stream, bytes[0..count]);
        const value = decoder.feed(bytes[count - 1]) catch return error.InvalidVarint;
        if (value) |len| return .{ .len = len, .skip = 0 };
    }
    // The decoder returns a value or an error by the fifth byte.
    unreachable;
}

fn recv(stream: anytype, out: []u8) Error!void {
    stream.recv(out) catch |err| return map_error(err, error.RecvFailed);
}

fn map_error(err: anyerror, failure: Error) Error {
    if (err == error.Canceled) return error.Canceled;
    assert(failure == error.RecvFailed or failure == error.SendFailed);
    return failure;
}

test {
    _ = @import("codec_test.zig");
}
