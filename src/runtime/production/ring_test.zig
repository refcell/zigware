//! The io_uring workers: file and socket operations, timeouts, cancellation, and the
//! per-thread worker cache.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const ring_mod = @import("ring.zig");

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
    const dialed = try server.socket.address.connect(io, .{ .mode = .stream });
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
