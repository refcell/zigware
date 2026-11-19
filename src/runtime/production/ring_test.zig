//! The io_uring workers: file and socket operations, timeouts, cancellation, and the
//! per-thread worker cache.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const ring_mod = @import("ring.zig");
const tcp = @import("network.zig");

const Ring = ring_mod.Ring;
const Worker = ring_mod.Worker;
const io = testing.io;

fn deadline_in_ms(ms: i64) Io.Timeout {
    const timeout: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
    return .{ .deadline = timeout.toTimestamp(io).? };
}

/// Initializes `ring`, or skips the test where the kernel cannot give one: io_uring is
/// unsupported, or setup fails with ENOMEM because the user's locked-memory limit (shared by
/// every process of the user) is used up.
pub fn init_or_skip(ring: *Ring, config: ring_mod.Config) !void {
    ring.init(io, config) catch |err| switch (err) {
        error.Unsupported, error.SystemResources => return error.SkipZigTest,
    };
}

fn init_ring(ring: *Ring, entries: u16) !void {
    return init_or_skip(ring, .{ .entries = entries });
}

/// The calling thread's worker, or a skip where the kernel refuses it a ring.
fn worker_or_skip(ring: *Ring) !*Worker {
    return ring.worker() orelse error.SkipZigTest;
}

test "a ring writes, syncs, and reads a file" {
    var ring: Ring = undefined;
    try init_ring(&ring, 8);
    defer ring.deinit();
    const worker = try worker_or_skip(&ring);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "file", .{ .read = true });
    defer file.close(io);
    const written = try worker.perform(.{ .write = .{
        .fd = file.handle,
        .bytes = "hello ring",
        .offset = 3,
    } }, .none);
    try testing.expectEqual(@as(i32, 10), written);
    const synced = try worker.perform(.{ .fsync = .{ .fd = file.handle } }, .none);
    try testing.expectEqual(@as(i32, 0), synced);
    var buffer: [16]u8 = undefined;
    const read = try worker.perform(.{ .read = .{
        .fd = file.handle,
        .buffer = &buffer,
        .offset = 0,
    } }, .none);
    try testing.expectEqual(@as(i32, 13), read);
    try testing.expectEqualStrings("ring", buffer[9..13]);
    // A bad descriptor fails with its errno.
    const bad = try worker.perform(.{ .fsync = .{ .fd = -1 } }, .none);
    try testing.expectEqual(std.os.linux.E.BADF, ring_mod.errno(bad));
}

/// A connected loopback TCP pair (AF_INET socketpair is unsupported).
fn socket_pair() ![2]Io.net.Socket {
    const any_port: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try any_port.listen(io, .{});
    defer server.deinit(io);
    const dialed = try tcp.connect(io, server.socket.address, .fromSeconds(10));
    errdefer dialed.close(io);
    const accepted = try server.accept(io);
    return .{ accepted.socket, dialed.socket };
}

test "a recv with no data times out, and the ring stays usable" {
    var ring: Ring = undefined;
    try init_ring(&ring, 2); // One operation and its cancellation.
    defer ring.deinit();
    const worker = try worker_or_skip(&ring);
    const pair = try socket_pair();
    defer Io.net.Socket.closeMany(io, &pair);
    var buffer: [4]u8 = undefined;
    const recv: ring_mod.Operation = .{ .recv = .{ .fd = pair[0].handle, .buffer = &buffer } };
    // More timed-out operations than the ring has entries: each cancellation is reaped.
    for (0..5) |_| try testing.expectError(error.Timeout, worker.perform(recv, deadline_in_ms(5)));
    const data = "data";
    try testing.expectEqual(data.len, std.os.linux.write(pair[1].handle, data, data.len));
    try testing.expectEqual(@as(i32, 4), try worker.perform(recv, .none));
    try testing.expectEqualStrings("data", &buffer);
}

test "an expired deadline submits nothing and leaves ready data unread" {
    var ring: Ring = undefined;
    try init_ring(&ring, 2);
    defer ring.deinit();
    const worker = try worker_or_skip(&ring);
    const pair = try socket_pair();
    defer Io.net.Socket.closeMany(io, &pair);
    const data = "data";
    try testing.expectEqual(data.len, std.os.linux.write(pair[1].handle, data, data.len));
    var buffer: [4]u8 = @splat(0);
    const recv: ring_mod.Operation = .{ .recv = .{ .fd = pair[0].handle, .buffer = &buffer } };
    try testing.expectError(error.Timeout, worker.perform(recv, deadline_in_ms(-1)));
    try testing.expectEqualSlices(u8, &@as([4]u8, @splat(0)), &buffer);
    // The data is still in the socket for the next recv.
    try testing.expectEqual(@as(i32, 4), try worker.perform(recv, .none));
    try testing.expectEqualStrings("data", &buffer);
}

test "an operation that completes before its abort keeps its result" {
    var ring: Ring = undefined;
    try init_ring(&ring, 2);
    defer ring.deinit();
    const worker = try worker_or_skip(&ring);
    const pair = try socket_pair();
    defer Io.net.Socket.closeMany(io, &pair);
    var buffer: [4]u8 = undefined;
    const recv: ring_mod.Operation = .{ .recv = .{ .fd = pair[0].handle, .buffer = &buffer } };
    // With data ready the recv completes before its cancellation: it keeps its bytes
    // (commonware's `test_completion_wins_cancellation`).
    const data = "data";
    try testing.expectEqual(data.len, std.os.linux.write(pair[1].handle, data, data.len));
    try testing.expectEqual(@as(i32, 4), try worker.perform_then_abort(recv, error.Timeout));
    try testing.expectEqualStrings("data", &buffer);
    // With nothing to read, the cancellation takes effect.
    try testing.expectError(error.Timeout, worker.perform_then_abort(recv, error.Timeout));
}

/// Consumes this task's cancellation, as `perform` does when it notices one mid-operation,
/// then aborts a recv whose data is ready.
fn canceled_recv(ring: *Ring, fd: std.posix.fd_t) anyerror!i32 {
    var buffer: [4]u8 = undefined;
    const worker = try worker_or_skip(ring);
    try testing.expectError(error.Canceled, io.sleep(.fromSeconds(10), .awake));
    const recv: ring_mod.Operation = .{ .recv = .{ .fd = fd, .buffer = &buffer } };
    const result = try worker.perform_then_abort(recv, error.Canceled);
    try testing.expectEqualStrings("data", &buffer);
    // The completed recv returned its bytes and re-armed the cancellation it consumed
    // (commonware's `test_cancellation_preserves_terminal_results`).
    try testing.expectError(error.Canceled, io.checkCancel());
    return result;
}

test "a canceled recv that completed returns its bytes and stays canceled" {
    var ring: Ring = undefined;
    try init_ring(&ring, 2);
    defer ring.deinit();
    const pair = try socket_pair();
    defer Io.net.Socket.closeMany(io, &pair);
    const data = "data";
    try testing.expectEqual(data.len, std.os.linux.write(pair[1].handle, data, data.len));
    var future = try io.concurrent(canceled_recv, .{ &ring, pair[0].handle });
    try io.sleep(.fromMilliseconds(5), .awake);
    try testing.expectEqual(@as(i32, 4), try future.cancel(io));
}

/// Leaves this task's cancellation pending, then tries a recv whose data is ready.
fn pending_cancel_recv(ring: *Ring, fd: std.posix.fd_t) anyerror!i32 {
    var buffer: [4]u8 = undefined;
    const worker = try worker_or_skip(ring);
    try testing.expectError(error.Canceled, io.sleep(.fromSeconds(10), .awake));
    io.recancel();
    return worker.perform(.{ .recv = .{ .fd = fd, .buffer = &buffer } }, .none);
}

test "a canceled task stages nothing and leaves ready data unread" {
    // commonware's `test_orphaned_reads_and_sends_stop_before_staging_or_after_partial_
    // completion`: a caller retrying after partial progress or EAGAIN stops at its next try.
    var ring: Ring = undefined;
    try init_ring(&ring, 2);
    defer ring.deinit();
    const pair = try socket_pair();
    defer Io.net.Socket.closeMany(io, &pair);
    const data = "data";
    try testing.expectEqual(data.len, std.os.linux.write(pair[1].handle, data, data.len));
    var future = try io.concurrent(pending_cancel_recv, .{ &ring, pair[0].handle });
    try io.sleep(.fromMilliseconds(5), .awake);
    try testing.expectError(error.Canceled, future.cancel(io));
    // The bytes are still in the socket.
    var buffer: [4]u8 = undefined;
    try testing.expectEqual(data.len, std.os.linux.read(pair[0].handle, &buffer, buffer.len));
    try testing.expectEqualStrings("data", &buffer);
}

test "enter treats a timeout as a wait and a broken ring as a failure" {
    // commonware's `test_enter_distinguishes_timeout_from_failure`.
    if (!ring_mod.supported) return error.SkipZigTest;
    const linux = std.os.linux;
    var uring = linux.IoUring.init(2, 0) catch return error.SkipZigTest;
    // An empty ring never completes: timed waits, long and short, end without an error.
    try ring_mod.enter_wait(uring.fd, 0, 0, 5 * std.time.ns_per_ms);
    try ring_mod.enter_wait(uring.fd, 0, 0, 1);
    // A closed ring fails every enter; its mapping is leaked, not unmapped through a
    // descriptor another thread may now own.
    try testing.expectEqual(@as(usize, 0), linux.close(uring.fd));
    try testing.expectError(error.RingFailed, ring_mod.enter_wait(uring.fd, 0, 0, 1));
    try testing.expectError(
        error.RingFailed,
        ring_mod.enter_wait(uring.fd, 0, 0, 5 * std.time.ns_per_ms),
    );
    uring = undefined;
}

fn blocked_recv(ring: *Ring, fd: std.posix.fd_t) anyerror!i32 {
    var buffer: [4]u8 = undefined;
    const worker = try worker_or_skip(ring);
    return worker.perform(.{ .recv = .{ .fd = fd, .buffer = &buffer } }, .none);
}

test "canceling a waiter cancels its operation" {
    var ring: Ring = undefined;
    try init_ring(&ring, 2);
    defer ring.deinit();
    const pair = try socket_pair();
    defer Io.net.Socket.closeMany(io, &pair);
    // Each waiter blocks on its own thread's worker, and notices its cancellation within a
    // slice.
    var futures: [4]Io.Future(anyerror!i32) = undefined;
    for (&futures) |*future| future.* = try io.concurrent(blocked_recv, .{ &ring, pair[0].handle });
    try io.sleep(.fromMilliseconds(5), .awake);
    for (&futures) |*future| try testing.expectError(error.Canceled, future.cancel(io));
}

test "a thread keeps one worker per ring, and a new ring gets a new one" {
    var first: Ring = undefined;
    try init_ring(&first, 2);
    defer first.deinit();
    var second: Ring = undefined;
    try init_ring(&second, 2);
    defer second.deinit();
    const worker = try worker_or_skip(&first);
    try testing.expectEqual(worker, first.worker().?);
    const other = try worker_or_skip(&second);
    try testing.expect(worker != other);
    try testing.expectEqual(worker, first.worker().?);
    try testing.expectEqual(other, second.worker().?);
    const synced = try other.perform(.{ .fsync = .{ .fd = -1 } }, .none);
    try testing.expectEqual(std.os.linux.E.BADF, ring_mod.errno(synced));
}
