//! TCP network over `std.Io.net` (commonware `runtime/src/network/tokio.rs`).
//!
//! Each connection is one socket split into a sink and a stream, as tokio's `into_split`:
//! closing the sink shuts down the write side, and the socket closes once both halves are
//! closed. The stream reads through a buffer like tokio's `BufReader`, which `peek` exposes.
//! Every send, recv, and dial is bounded by its configured timeout (`error.Timeout`). With
//! `Config.ring`, sends and receives go through io_uring (commonware `network::iouring`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = Io.net;
const posix = std.posix;
const network = @import("../network.zig");
const ring_mod = @import("ring.zig");

const Address = network.Address;
const Error = network.Error;
const log = std.log.scoped(.runtime_network);

/// commonware `network::tokio::Config`, with the same defaults.
pub const Config = struct {
    /// `TCP_NODELAY` for every connection; null leaves the system default.
    tcp_nodelay: ?bool = true,
    /// `SO_LINGER` of zero: closing resets the connection instead of lingering in TIME_WAIT.
    zero_linger: bool = true,
    connect_timeout: Io.Duration = .fromSeconds(10),
    read_timeout: Io.Duration = .fromSeconds(60),
    write_timeout: Io.Duration = .fromSeconds(60),
    /// The stream's read buffer, which `peek` sees; 0 reads unbuffered.
    read_buffer_size: u32 = 64 * 1024,
    /// Runs sends and receives through io_uring; it must outlive every connection.
    ring: ?*ring_mod.Ring = null,
};

/// The socket both halves share; the last half to close closes it.
const Shared = struct {
    gpa: Allocator,
    io: Io,
    stream: net.Stream,
    ring: ?*ring_mod.Ring,
    handles: std.atomic.Value(u8) = .init(2),

    fn release(shared: *Shared) void {
        const previous = shared.handles.fetchSub(1, .acq_rel);
        assert(previous == 1 or previous == 2);
        if (previous != 1) return;
        shared.stream.close(shared.io);
        shared.gpa.destroy(shared);
    }
};

/// Timeouts in the halves are `u64` nanoseconds: an `Io.Duration` (i96) would align the
/// halves to 16 bytes, and `std.Io.Threaded` 0.17.1 (`Future.create`) sizes a future without
/// the result's misalignment, so a 16-byte aligned result overruns it by up to 8 bytes.
fn deadline_after(io: Io, timeout_ns: u64) Io.Timeout {
    assert(timeout_ns > 0);
    const duration: Io.Duration = .fromNanoseconds(timeout_ns);
    const timeout: Io.Timeout = .{ .duration = .{ .raw = duration, .clock = .awake } };
    assert(timeout != .none);
    return .{ .deadline = timeout.toTimestamp(io).? };
}

/// `io.operateTimeout` that never times out before the deadline: `std.Io.Threaded` polls in
/// whole milliseconds rounded down, so it can wake up to a millisecond early. After an early
/// wakeup, wait out the deadline and try once more without blocking.
fn operate_until(
    io: Io,
    operation: Io.Operation,
    deadline: Io.Timeout,
) Io.OperateTimeoutError!Io.Operation.Result {
    assert(deadline == .deadline);
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        assert(attempt < 2);
        return io.operateTimeout(operation, deadline) catch |err| switch (err) {
            error.Timeout => {
                if (attempt > 0) return error.Timeout;
                try deadline.deadline.wait(io);
                continue;
            },
            else => return err,
        };
    }
}

pub const Sink = struct {
    shared: *Shared,
    write_timeout_ns: u64,
    closed: bool = false,

    /// Writes every buffer, in order, as one logical write.
    pub fn send(sink: *Sink, bufs: []const []const u8) Error!void {
        if (sink.closed) return error.Closed;
        sink.write_all(bufs) catch |err| {
            sink.close();
            return err;
        };
        assert(!sink.closed);
    }

    fn write_all(sink: *Sink, bufs: []const []const u8) Error!void {
        const io = sink.shared.io;
        const timeout = deadline_after(io, sink.write_timeout_ns);
        var index: usize = 0;
        var offset: usize = 0;
        while (index < bufs.len) {
            if (offset == bufs[index].len) {
                index += 1;
                offset = 0;
                continue;
            }
            var written = try sink.write_some(bufs[index][offset..], bufs[index + 1 ..], timeout);
            assert(written > 0);
            // Advance past what was written, buffer by buffer.
            while (written > 0) {
                const step = @min(written, bufs[index].len - offset);
                offset += step;
                written -= step;
                if (offset == bufs[index].len and written > 0) {
                    index += 1;
                    offset = 0;
                }
            }
        }
        assert(index == bufs.len);
    }

    /// One write of `first` and then `rest`, as much as the socket takes.
    fn write_some(
        sink: *Sink,
        first: []const u8,
        rest: []const []const u8,
        timeout: Io.Timeout,
    ) Error!usize {
        assert(first.len > 0);
        const shared = sink.shared;
        const fd = shared.stream.socket.handle;
        if (shared.ring) |ring| return ring_send(ring, fd, first, rest, timeout);
        const result = operate_until(shared.io, .{ .net_write = .{
            .socket_handle = fd,
            .header = first,
            .data = if (rest.len == 0) &.{""} else rest,
        } }, timeout) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            error.Timeout => error.Timeout,
            error.ConcurrencyUnavailable => error.SendFailed,
        };
        return result.net_write catch error.SendFailed;
    }

    /// Shut down the write side once; the peer's stream sees the end.
    fn close(sink: *Sink) void {
        if (sink.closed) return;
        sink.closed = true;
        const shared = sink.shared;
        shared.stream.shutdown(shared.io, .send) catch {};
        assert(sink.closed);
    }

    pub fn deinit(sink: *Sink) void {
        sink.close();
        const shared = sink.shared;
        sink.* = undefined;
        shared.release();
    }
};

pub const Stream = struct {
    shared: *Shared,
    read_timeout_ns: u64,
    /// Received bytes not yet consumed are `buffer[start..end]`.
    buffer: []u8,
    start: usize = 0,
    end: usize = 0,
    poisoned: bool = false,

    /// Receives exactly `out.len` bytes.
    pub fn recv(stream: *Stream, out: []u8) Error!void {
        if (stream.poisoned) return error.Closed;
        stream.poisoned = true;
        const timeout = deadline_after(stream.shared.io, stream.read_timeout_ns);
        var filled: usize = 0;
        while (filled < out.len) {
            if (stream.start == stream.end) {
                const wanted = out.len - filled;
                // Large reads bypass the empty buffer, as `BufReader` does.
                if (wanted >= stream.buffer.len) {
                    filled += try stream.read_some(out[filled..], timeout);
                    continue;
                }
                stream.start = 0;
                stream.end = try stream.read_some(stream.buffer, timeout);
            }
            const step = @min(out.len - filled, stream.end - stream.start);
            @memcpy(out[filled..][0..step], stream.buffer[stream.start..][0..step]);
            stream.start += step;
            filled += step;
        }
        assert(filled == out.len);
        assert(stream.start <= stream.end);
        stream.poisoned = false;
    }

    /// One read into `into`; the end of the stream fails.
    fn read_some(stream: *Stream, into: []u8, timeout: Io.Timeout) Error!usize {
        assert(into.len > 0);
        const shared = stream.shared;
        if (shared.ring) |ring| return ring_recv(ring, shared.stream.socket.handle, into, timeout);
        const io = shared.io;
        var data: [1][]u8 = .{into};
        const result = operate_until(io, .{ .net_read = .{
            .socket_handle = stream.shared.stream.socket.handle,
            .data = &data,
        } }, timeout) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            error.Timeout => error.Timeout,
            error.ConcurrencyUnavailable => error.RecvFailed,
        };
        const read = result.net_read catch return error.RecvFailed;
        if (read.data_len == 0) return error.RecvFailed;
        assert(read.data_len <= into.len);
        return read.data_len;
    }

    /// Up to `max_len` buffered bytes not yet consumed; never reads the socket.
    pub fn peek(stream: *const Stream, max_len: usize) []const u8 {
        assert(stream.start <= stream.end);
        const buffered = stream.buffer[stream.start..stream.end];
        return buffered[0..@min(max_len, buffered.len)];
    }

    pub fn deinit(stream: *Stream) void {
        const shared = stream.shared;
        shared.gpa.free(stream.buffer);
        stream.* = undefined;
        shared.release();
    }
};

/// Most buffers one ring send carries (as `std.Io.Threaded` does per write).
const send_iovecs_max = 8;

/// One `sendmsg` of `first` and up to 7 buffers of `rest` through the ring.
fn ring_send(
    ring: *ring_mod.Ring,
    fd: posix.fd_t,
    first: []const u8,
    rest: []const []const u8,
    timeout: Io.Timeout,
) Error!usize {
    var iovecs: [send_iovecs_max]posix.iovec_const = undefined;
    iovecs[0] = .{ .base = first.ptr, .len = first.len };
    const count = 1 + @min(rest.len, send_iovecs_max - 1);
    for (iovecs[1..count], rest[0 .. count - 1]) |*iovec, buf| {
        iovec.* = .{ .base = buf.ptr, .len = buf.len };
    }
    const msg: posix.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iovecs,
        .iovlen = @intCast(count),
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    const sent = try ring_perform(ring, .{ .sendmsg = .{ .fd = fd, .msg = &msg } }, timeout) orelse
        return error.SendFailed;
    if (sent == 0) return error.SendFailed;
    return sent;
}

/// One `recv` into `into` through the ring; the end of the stream fails.
fn ring_recv(ring: *ring_mod.Ring, fd: posix.fd_t, into: []u8, timeout: Io.Timeout) Error!usize {
    const read = try ring_perform(ring, .{ .recv = .{ .fd = fd, .buffer = into } }, timeout) orelse
        return error.RecvFailed;
    if (read == 0) return error.RecvFailed;
    assert(read <= into.len);
    return read;
}

/// Runs a ring operation, retrying interrupted ones: its count, or null if it failed.
fn ring_perform(
    ring: *ring_mod.Ring,
    operation: ring_mod.Operation,
    timeout: Io.Timeout,
) Error!?usize {
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        assert(attempts < 1024); // Interrupts do not repeat without end.
        const result = ring.perform(operation, timeout) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            error.Timeout => error.Timeout,
        };
        if (result >= 0) return @intCast(result);
        switch (ring_mod.errno(result)) {
            .INTR, .AGAIN => continue,
            else => return null,
        }
    }
}

/// Splits a connected socket into its two halves, applying the socket options.
fn split(gpa: Allocator, io: Io, config: *const Config, stream: net.Stream) Error!Halves {
    errdefer stream.close(io);
    configure(config, stream.socket.handle);
    const shared = try gpa.create(Shared);
    errdefer gpa.destroy(shared);
    const buffer = try gpa.alloc(u8, config.read_buffer_size);
    shared.* = .{ .gpa = gpa, .io = io, .stream = stream, .ring = config.ring };
    assert(shared.handles.load(.monotonic) == 2);
    return .{
        .sink = .{ .shared = shared, .write_timeout_ns = nanoseconds(config.write_timeout) },
        .stream = .{
            .shared = shared,
            .read_timeout_ns = nanoseconds(config.read_timeout),
            .buffer = buffer,
        },
    };
}

fn nanoseconds(duration: Io.Duration) u64 {
    assert(duration.nanoseconds > 0);
    return std.math.cast(u64, duration.nanoseconds) orelse std.math.maxInt(u64);
}

const Halves = struct { sink: Sink, stream: Stream };

/// Sets `TCP_NODELAY` and `SO_LINGER`; a failure only warns, as in commonware.
fn configure(config: *const Config, handle: net.Socket.Handle) void {
    if (config.tcp_nodelay) |nodelay| {
        const value: c_int = @intFromBool(nodelay);
        const bytes = std.mem.asBytes(&value);
        posix.setsockopt(handle, posix.IPPROTO.TCP, posix.TCP.NODELAY, bytes) catch |err|
            log.warn("failed to set TCP_NODELAY: {t}", .{err});
    }
    if (config.zero_linger) {
        const value: posix.linger = .{ .onoff = 1, .linger = 0 };
        const bytes = std.mem.asBytes(&value);
        posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.LINGER, bytes) catch |err|
            log.warn("failed to set SO_LINGER: {t}", .{err});
    }
}

pub const Network = struct {
    /// A connection accepted by a listener: the dialer's address and the two halves.
    pub const Accepted = struct {
        address: Address,
        sink: Sink,
        stream: Stream,

        pub fn deinit(accepted: *Accepted) void {
            accepted.sink.deinit();
            accepted.stream.deinit();
        }
    };

    /// A dialed connection.
    pub const Connection = struct {
        sink: Sink,
        stream: Stream,

        pub fn deinit(connection: *Connection) void {
            connection.sink.deinit();
            connection.stream.deinit();
        }
    };

    pub const Listener = struct {
        network: *const Network,
        server: net.Server,

        /// Waits for the next connection.
        pub fn accept(listener: *Listener) Error!Accepted {
            const net_ = listener.network;
            const stream = listener.server.accept(net_.io) catch |err| return switch (err) {
                error.Canceled => error.Canceled,
                else => error.Closed,
            };
            const address = stream.socket.address;
            const halves = try split(net_.gpa, net_.io, &net_.config, stream);
            assert(!halves.sink.closed and !halves.stream.poisoned);
            return .{ .address = address, .sink = halves.sink, .stream = halves.stream };
        }

        pub fn local_addr(listener: *const Listener) Address {
            const address = listener.server.socket.address;
            assert(address.getPort() != 0);
            return address;
        }

        /// Stops listening; connections already accepted stay open.
        pub fn deinit(listener: *Listener) void {
            const gpa = listener.network.gpa;
            listener.server.deinit(listener.network.io);
            gpa.destroy(listener);
        }
    };

    gpa: Allocator,
    io: Io,
    config: Config,

    pub fn init(gpa: Allocator, io: Io, config: Config) Network {
        assert(config.connect_timeout.nanoseconds > 0);
        assert(config.read_timeout.nanoseconds > 0 and config.write_timeout.nanoseconds > 0);
        return .{ .gpa = gpa, .io = io, .config = config };
    }

    pub fn deinit(network_: *Network) void {
        network_.* = undefined;
    }

    /// Listens on `address`; port 0 picks a free port (`Listener.local_addr`).
    pub fn bind(network_: *const Network, address: Address) Error!*Listener {
        const listener = try network_.gpa.create(Listener);
        errdefer network_.gpa.destroy(listener);
        const server = address.listen(network_.io, .{}) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            else => error.BindFailed,
        };
        listener.* = .{ .network = network_, .server = server };
        assert(listener.local_addr().getPort() != 0);
        return listener;
    }

    /// Connects to `address` within the connect timeout.
    pub fn dial(network_: *const Network, address: Address) Error!Connection {
        const io = network_.io;
        const stream = try connect_within(io, address, network_.config.connect_timeout);
        const halves = try split(network_.gpa, io, &network_.config, stream);
        assert(!halves.sink.closed and !halves.stream.poisoned);
        return .{ .sink = halves.sink, .stream = halves.stream };
    }
};

const ConnectResult = net.IpAddress.ConnectError!net.Stream;
const ConnectOutcome = union(enum) { connected: ConnectResult, elapsed: Io.Cancelable!void };

fn connect(io: Io, address: Address) ConnectResult {
    return address.connect(io, .{ .mode = .stream });
}

fn sleep(io: Io, duration: Io.Duration) Io.Cancelable!void {
    return io.sleep(duration, .awake);
}

/// Connects, racing a sleep: `std.Io.Threaded` cannot bound a connect itself. A connect that
/// lands while the timer wins still counts.
fn connect_within(io: Io, address: Address, duration: Io.Duration) Error!net.Stream {
    assert(duration.nanoseconds > 0);
    var buffer: [2]ConnectOutcome = undefined;
    var select: Io.Select(ConnectOutcome) = .init(io, &buffer);
    select.concurrent(.connected, connect, .{ io, address }) catch
        return map_connect(connect(io, address));
    select.concurrent(.elapsed, sleep, .{ io, duration }) catch {
        const result = cancel_connect(&select) orelse return error.ConnectionFailed;
        return map_connect(result);
    };
    const first = select.await() catch |err| {
        if (cancel_connect(&select)) |late| close_connected(io, late);
        return err;
    };
    const late = cancel_connect(&select);
    switch (first) {
        .connected => |result| {
            assert(late == null);
            return map_connect(result);
        },
        .elapsed => |slept| {
            const result = late orelse return error.Timeout;
            slept catch |err| {
                close_connected(io, result);
                return err;
            };
            return map_connect(result) catch |err|
                if (err == error.Canceled) error.Timeout else err;
        },
    }
}

/// Cancels whichever task is still running and returns a connect result it produced.
fn cancel_connect(select: *Io.Select(ConnectOutcome)) ?ConnectResult {
    var result: ?ConnectResult = null;
    var remaining: u32 = 0;
    while (select.cancel()) |late| : (remaining += 1) {
        assert(remaining < 2);
        switch (late) {
            .connected => |outcome| result = outcome,
            .elapsed => {},
        }
    }
    return result;
}

fn close_connected(io: Io, result: ConnectResult) void {
    const stream = result catch return;
    stream.close(io);
}

fn map_connect(result: ConnectResult) Error!net.Stream {
    return result catch |err| switch (err) {
        error.Canceled => error.Canceled,
        error.Timeout => error.Timeout,
        else => error.ConnectionFailed,
    };
}
