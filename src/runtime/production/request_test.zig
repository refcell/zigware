//! commonware `runtime/src/iouring/request.rs` tests: how raw CQE results advance a ring
//! request. The requests are pure state machines, so these run on every platform.
//!
//! Not ported here: commonware's cancellation outcomes (`WaiterState::CancelRequested` with
//! `-ECANCELED` becoming `Timeout`) live in `ring.zig`'s `abort`, which never hands a
//! canceled CQE to a request (ring_test.zig covers them); a CQE that beats its cancellation
//! reaches `on_cqe` like any other, which the `beats cancellation` cases below check. The
//! recv overflow `catch_unwind` is an assertion here, and Zig cannot catch a panic.

const std = @import("std");
const testing = std.testing;
const linux = std.os.linux;
const request = @import("request.zig");

fn neg(code: linux.E) i32 {
    return -@as(i32, @backingInt(code));
}

const max_u32: usize = std.math.maxInt(u32);

// commonware test_cqe_result_from_raw_retryable_codes.
test "cqe results retry on EAGAIN, EWOULDBLOCK, and EINTR only" {
    // Linux defines EWOULDBLOCK as EAGAIN.
    for ([_]linux.E{ .AGAIN, .INTR }) |code| {
        try testing.expect(request.CqeResult.from_raw(neg(code)) == .retry);
    }
    for ([_]i32{ 0, neg(.INVAL), neg(.TIMEDOUT) }) |raw| {
        try testing.expect(request.CqeResult.from_raw(raw) != .retry);
    }
    try testing.expectEqual(request.CqeResult{ .count = 0 }, request.CqeResult.from_raw(0));
    const failure = request.CqeResult.from_raw(neg(.TIMEDOUT));
    try testing.expectEqual(request.CqeResult{ .failure = .TIMEDOUT }, failure);
}

// commonware test_scalar_length_prefix_boundary.
test "an SQE length above u32 max is clamped" {
    for ([_]usize{ 0, 1, max_u32 - 1, max_u32 }) |len| {
        try testing.expectEqual(@as(u32, @intCast(len)), request.scalar_len(len));
    }
    for ([_]usize{ max_u32 + 1, std.math.maxInt(usize) }) |len| {
        try testing.expectEqual(@as(u32, std.math.maxInt(u32)), request.scalar_len(len));
    }
}

// commonware test_scalar_builders_preserve_partial_progress.
test "resubmitted send, recv, and read SQEs start after prior progress" {
    const hello = "hello";
    var send: request.Send = .init(3, &.{hello});
    var recv_buffer: [5]u8 = undefined;
    var recv: request.Recv = .{ .fd = 4, .buffer = &recv_buffer, .exact = true };
    var read_buffer: [5]u8 = undefined;
    var read: request.ReadAt = .{ .fd = 5, .buffer = &read_buffer, .offset = 7 };
    var done: usize = 0;
    for ([_]i32{ 2, 3 }) |progress| {
        const sent = send.operation().sendmsg;
        try testing.expectEqual(@as(usize, 1), sent.msg.iovlen);
        try testing.expectEqual(@intFromPtr(hello.ptr) + done, @intFromPtr(sent.msg.iov[0].base));
        try testing.expectEqual(hello.len - done, sent.msg.iov[0].len);
        const received = recv.operation().recv;
        try testing.expectEqual(@intFromPtr(&recv_buffer) + done, @intFromPtr(received.buffer.ptr));
        try testing.expectEqual(recv_buffer.len - done, received.buffer.len);
        const positioned = read.operation().read;
        try testing.expectEqual(7 + done, positioned.offset);
        try testing.expectEqual(read_buffer.len - done, positioned.buffer.len);
        const last = progress == 3;
        try testing.expectEqual(last, send.on_cqe(progress) != null);
        try testing.expectEqual(last, recv.on_cqe(progress) != null);
        try testing.expectEqual(last, read.on_cqe(progress) != null);
        done += @intCast(progress);
    }
    try testing.expect(send.is_complete());
    try testing.expectEqual(@as(usize, 5), recv.received);
    try testing.expectEqual(@as(usize, 5), read.read);
    try testing.expectEqual(@as(u64, 7), read.offset);
}

// commonware test_active_send_paths.
test "send retries EAGAIN, crosses buffers, and maps errors to SendFailed" {
    var send: request.Send = .init(3, &.{"hello"});
    try testing.expectEqual(null, send.on_cqe(neg(.AGAIN)));
    // Vectored progress crosses a buffer boundary before completing.
    var vectored: request.Send = .init(3, &.{ "abc", "de" });
    try testing.expectEqual(@as(usize, 2), vectored.operation().sendmsg.msg.iovlen);
    try testing.expectEqual(null, vectored.on_cqe(3));
    const rest = vectored.operation().sendmsg.msg;
    try testing.expectEqual(@as(usize, 1), rest.iovlen);
    try testing.expectEqual(@as(usize, 2), rest.iov[0].len);
    try (vectored.on_cqe(2) orelse return error.NotComplete);
    // Progress landing exactly on a boundary skips to the next buffer, past empty ones.
    var boundary: request.Send = .init(3, &.{ "ab", "", "cd" });
    try testing.expectEqual(null, boundary.on_cqe(2));
    try testing.expectEqualStrings("cd", boundary.first());
    for ([_]i32{ 0, neg(.IO) }) |result| {
        var failing: request.Send = .init(3, &.{"hello"});
        const outcome = failing.on_cqe(result) orelse return error.NotComplete;
        try testing.expectError(error.SendFailed, outcome);
    }
    // A send that completed before its cancellation keeps its result.
    var beats_cancellation: request.Send = .init(3, &.{"hello"});
    try (beats_cancellation.on_cqe(5) orelse return error.NotComplete);
}

// commonware test_active_recv_paths.
test "recv retries, completes exactly or partially, and maps EOF and errors" {
    var buffer: [5]u8 = undefined;
    var exact: request.Recv = .{ .fd = 4, .buffer = &buffer, .exact = true };
    try testing.expectEqual(null, exact.on_cqe(neg(.AGAIN)));
    // An exact receive waits for the whole buffer.
    try testing.expectEqual(null, exact.on_cqe(3));
    try testing.expectEqual(@as(usize, 5), try (exact.on_cqe(2) orelse return error.NotComplete));
    // A non-exact receive completes on the first positive byte count.
    var partial: request.Recv = .{ .fd = 4, .buffer = &buffer, .exact = false };
    try testing.expectEqual(@as(usize, 3), try (partial.on_cqe(3) orelse return error.NotComplete));
    for ([_]i32{ 0, neg(.IO) }) |result| {
        var failing: request.Recv = .{ .fd = 4, .buffer = &buffer, .exact = true };
        const outcome = failing.on_cqe(result) orelse return error.NotComplete;
        try testing.expectError(error.RecvFailed, outcome);
    }
    // A receive that completed before its cancellation keeps its bytes.
    var beats_cancellation: request.Recv = .{ .fd = 4, .buffer = &buffer, .exact = true };
    const kept = beats_cancellation.on_cqe(5) orelse return error.NotComplete;
    try testing.expectEqual(@as(usize, 5), try kept);
}

// commonware test_active_read_at_paths.
test "read_at retries, accumulates, and maps short reads and errors" {
    var buffer: [5]u8 = undefined;
    var read: request.ReadAt = .{ .fd = 5, .buffer = &buffer, .offset = 0 };
    try testing.expectEqual(null, read.on_cqe(neg(.AGAIN)));
    try testing.expectEqual(null, read.on_cqe(2));
    try (read.on_cqe(3) orelse return error.NotComplete);
    var eof: request.ReadAt = .{ .fd = 5, .buffer = &buffer, .offset = 0 };
    try testing.expectError(error.BlobInsufficientLength, eof.on_cqe(0) orelse unreachable);
    // A short read then the end of the file is still insufficient.
    var short: request.ReadAt = .{ .fd = 5, .buffer = &buffer, .offset = 0 };
    try testing.expectEqual(null, short.on_cqe(4));
    try testing.expectError(error.BlobInsufficientLength, short.on_cqe(0) orelse unreachable);
    for ([_]linux.E{ .IO, .CANCELED }) |code| {
        var failing: request.ReadAt = .{ .fd = 5, .buffer = &buffer, .offset = 0 };
        try testing.expectError(error.ReadFailed, failing.on_cqe(neg(code)) orelse unreachable);
    }
}

// commonware test_large_single_write_preserves_progress_and_durability: one write above
// u32 max bytes completes across CQEs, each SQE clamped and starting after the last.
test "a write above u32 max bytes completes across CQEs" {
    const len = max_u32 + 1;
    // The request only slices the payload, never reads it, so the bytes need not exist:
    // a fake base address stands in for commonware's demand-paged zero allocation.
    const base: [*]const u8 = @ptrFromInt(0x1000);
    const signed_max: i32 = std.math.maxInt(i32);
    var write: request.WriteAt = .{ .fd = 6, .bytes = base[0..len], .offset = 17 };
    try testing.expectEqual(max_u32, write.operation().write.bytes.len);
    // A signed CQE cannot report the entire u32-sized prefix at once.
    for (0..2) |step| {
        const sqe = write.operation().write;
        try testing.expectEqual(17 + step * @as(u64, signed_max), sqe.offset);
        try testing.expectEqual(null, write.on_cqe(signed_max));
    }
    try testing.expectEqual(@as(usize, 2), write.bytes.len - write.written);
    const tail = write.operation().write;
    try testing.expectEqual(@as(usize, 2), tail.bytes.len);
    try testing.expectEqual(@intFromPtr(base) + len - 2, @intFromPtr(tail.bytes.ptr));
    try (write.on_cqe(2) orelse return error.NotComplete);
    try testing.expectEqual(17 + @as(u64, len), write.offset + write.written);
}

// commonware test_active_write_at_paths.
test "write_at retries, keeps its prefix, and maps 0, EIO, and ECANCELED to WriteFailed" {
    const hello = "hello";
    var write: request.WriteAt = .{ .fd = 6, .bytes = hello, .offset = 0 };
    try testing.expectEqual(null, write.on_cqe(neg(.AGAIN)));
    try testing.expectEqual(null, write.on_cqe(2));
    const resumed = write.operation().write;
    try testing.expectEqual(@as(u64, 2), resumed.offset);
    try testing.expectEqualStrings("llo", resumed.bytes);
    try (write.on_cqe(3) orelse return error.NotComplete);
    for ([_]i32{ 0, neg(.IO), neg(.CANCELED) }) |result| {
        var failing: request.WriteAt = .{ .fd = 6, .bytes = hello, .offset = 0 };
        try testing.expectError(error.WriteFailed, failing.on_cqe(result) orelse unreachable);
    }
}
