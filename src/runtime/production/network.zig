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
const Metrics = @import("../network/metered.zig").Metrics;
const ring_mod = @import("ring.zig");
const request_mod = @import("request.zig");

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
    /// Counts bandwidth when set (commonware `network::metered`).
    metrics: ?*const Metrics,
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
        if (sink.shared.metrics) |metrics| metrics.sent(bufs);
    }

    fn write_all(sink: *Sink, bufs: []const []const u8) Error!void {
        const io = sink.shared.io;
        const timeout = deadline_after(io, sink.write_timeout_ns);
        if (sink.shared.ring) |ring| if (ring.worker()) |worker| {
            return ring_send(worker, sink.shared.stream.socket.handle, bufs, timeout);
        };
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
        // A cancel this call takes stays pending for the caller's next wait.
        shared.stream.shutdown(shared.io, .send) catch |err| {
            if (err == error.Canceled) shared.io.recancel();
        };
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
        if (stream.shared.metrics) |metrics| metrics.received(out.len);
    }

    /// One read into `into`; the end of the stream fails.
    fn read_some(stream: *Stream, into: []u8, timeout: Io.Timeout) Error!usize {
        assert(into.len > 0);
        const shared = stream.shared;
        if (shared.ring) |ring| if (ring.worker()) |worker| {
            var request: request_mod.Recv = .{
                .fd = shared.stream.socket.handle,
                .buffer = into,
                .exact = false,
            };
            // Bounded: each SQE completes or retries an interrupt.
            while (true) {
                const result = try ring_perform(worker, request.operation(), timeout);
                if (request.on_cqe(result)) |done| return done;
            }
        };
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

/// Sends every buffer of `bufs` through the ring, resubmitting from its progress.
fn ring_send(
    worker: *ring_mod.Worker,
    fd: posix.fd_t,
    bufs: []const []const u8,
    timeout: Io.Timeout,
) Error!void {
    var request: request_mod.Send = .init(fd, bufs);
    // Bounded: each SQE completes, retries an interrupt, or makes progress.
    while (!request.is_complete()) {
        const result = try ring_perform(worker, request.operation(), timeout);
        if (request.on_cqe(result)) |done| return done;
    }
}

/// One ring operation's raw result (a count or a negated errno), or its timeout.
fn ring_perform(
    worker: *ring_mod.Worker,
    operation: ring_mod.Operation,
    timeout: Io.Timeout,
) Error!i32 {
    return worker.perform(operation, timeout) catch |err| switch (err) {
        error.Canceled => error.Canceled,
        error.Timeout => error.Timeout,
    };
}

fn ring_worker(ring: ?*ring_mod.Ring) ?*ring_mod.Worker {
    return (ring orelse return null).worker();
}

/// Accepts one connection through the ring (commonware `network::iouring` accepts on its
/// ring), resubmitting after an interrupt or a connection aborted before it was accepted.
fn ring_accept(worker: *ring_mod.Worker, fd: posix.fd_t) Error!net.Stream {
    var storage: SocketAddress = undefined;
    // Bounded: each SQE accepts, fails, or retries a transient error the kernel reports.
    while (true) {
        var length: posix.socklen_t = @sizeOf(SocketAddress);
        const operation: ring_mod.Operation = .{
            .accept = .{ .fd = fd, .addr = &storage.any, .addrlen = &length },
        };
        const result = try ring_perform(worker, operation, .none);
        switch (request_mod.CqeResult.from_raw(result)) {
            .retry => continue,
            .failure => |code| switch (code) {
                .CONNABORTED, .PROTO => continue,
                else => return error.Closed,
            },
            .count => |accepted| {
                const handle: posix.fd_t = @intCast(accepted);
                assert(length <= @sizeOf(SocketAddress));
                return .{ .socket = .{ .handle = handle, .address = address_from(&storage) } };
            },
        }
    }
}

/// Splits a connected socket into its two halves, applying the socket options.
fn split(network_: *const Network, stream: net.Stream) Error!Halves {
    const gpa = network_.gpa;
    const io = network_.io;
    const config = &network_.config;
    errdefer stream.close(io);
    configure(config, stream.socket.handle);
    const shared = try gpa.create(Shared);
    errdefer gpa.destroy(shared);
    const buffer = try gpa.alloc(u8, config.read_buffer_size);
    shared.* = .{
        .gpa = gpa,
        .io = io,
        .stream = stream,
        .ring = config.ring,
        .metrics = network_.metrics,
    };
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
        const errno = set_option(handle, posix.IPPROTO.TCP, posix.TCP.NODELAY, bytes);
        if (errno != .SUCCESS) log.warn("failed to set TCP_NODELAY: {any}", .{errno});
    }
    if (config.zero_linger) {
        const value: posix.linger = .{ .onoff = 1, .linger = 0 };
        const bytes = std.mem.asBytes(&value);
        const errno = set_option(handle, posix.SOL.SOCKET, posix.SO.LINGER, bytes);
        if (errno != .SUCCESS) log.warn("failed to set SO_LINGER: {any}", .{errno});
    }
}

/// `posix.setsockopt` without its `unreachable` on EINVAL, which macOS returns once the peer
/// has reset the connection. Returns the errno, `.SUCCESS` when the option is set.
fn set_option(handle: net.Socket.Handle, level: i32, name: u32, bytes: []const u8) posix.E {
    assert(bytes.len > 0);
    const len: posix.socklen_t = @intCast(bytes.len);
    while (true) {
        const errno = posix.errno(posix.system.setsockopt(handle, level, name, bytes.ptr, len));
        switch (errno) {
            .INTR => continue,
            .BADF, .NOTSOCK, .FAULT => unreachable, // `handle` and `bytes` are this call's own.
            else => return errno,
        }
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
            const stream = if (ring_worker(net_.config.ring)) |worker|
                try ring_accept(worker, listener.server.socket.handle)
            else
                listener.server.accept(net_.io) catch |err| return switch (err) {
                    error.Canceled => error.Canceled,
                    else => error.Closed,
                };
            const address = stream.socket.address;
            const halves = try split(net_, stream);
            assert(!halves.sink.closed and !halves.stream.poisoned);
            if (net_.metrics) |metrics| metrics.inbound_connections.metric().inc();
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
    /// Counts connections and bandwidth when set; the production runner sets it.
    metrics: ?*const Metrics = null,

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
        const server = try listen(address);
        listener.* = .{ .network = network_, .server = server };
        assert(listener.local_addr().getPort() != 0);
        return listener;
    }

    /// Connects to `address` within the connect timeout.
    pub fn dial(network_: *const Network, address: Address) Error!Connection {
        const io = network_.io;
        const stream = try connect(io, address, network_.config.connect_timeout);
        const halves = try split(network_, stream);
        assert(!halves.sink.closed and !halves.stream.poisoned);
        if (network_.metrics) |metrics| metrics.outbound_connections.metric().inc();
        return .{ .sink = halves.sink, .stream = halves.stream };
    }
};

/// tokio's `TcpListener::bind` backlog; the kernel clamps it (`somaxconn`, 128 on macOS).
const listen_backlog = 1024;

/// How long a connect waits in `poll` before checking whether its task was canceled.
const connect_slice_ms = 20;

/// Connects within `duration` with a nonblocking connect, waiting in `poll` slices that check
/// for cancellation between them. Use it instead of `std.Io.net.IpAddress.connect` (AGENTS.md
/// pitfalls). `std.Io.Threaded` cannot bound a connect, and it retries a
/// blocking connect that a stray cancellation signal interrupted: on Darwin the retry fails
/// with EALREADY while the first attempt completes, so the peer accepts a connection the dialer
/// reports failed (the macOS stress failure, docs/lanes/runtime-telemetry.md).
pub fn connect(io: Io, address: Address, duration: Io.Duration) Error!net.Stream {
    const timeout = deadline_after(io, nanoseconds(duration));
    var storage: SocketAddress = undefined;
    const length = socket_address(address, &storage);
    const fd = try socket_open(storage.any.family);
    errdefer _ = posix.system.close(fd);
    switch (posix.errno(posix.system.connect(fd, &storage.any, length))) {
        .SUCCESS => {},
        .INPROGRESS, .INTR, .AGAIN => try connect_wait(io, fd, timeout),
        else => return error.ConnectionFailed,
    }
    try set_nonblocking(fd, false); // `std.Io.Threaded` works on blocking sockets.
    var local: SocketAddress = undefined;
    var local_length: posix.socklen_t = @sizeOf(SocketAddress);
    const named = posix.errno(posix.system.getsockname(fd, &local.any, &local_length));
    if (named != .SUCCESS) return error.ConnectionFailed;
    assert(fd >= 0);
    return .{ .socket = .{ .handle = fd, .address = address_from(&local) } };
}

/// Listens on `address` with SO_REUSEADDR, as tokio's `TcpListener::bind` does on Unix, so a
/// restarted node rebinds its port while the previous run's connections sit in TIME_WAIT.
/// `std.Io.net.IpAddress.listen`'s `reuse_address` also sets SO_REUSEPORT, which would let a
/// second listener share a port that is in use.
fn listen(address: Address) Error!net.Server {
    var storage: SocketAddress = undefined;
    var length = socket_address(address, &storage);
    const fd = socket_open(storage.any.family) catch return error.BindFailed;
    errdefer _ = posix.system.close(fd);
    set_nonblocking(fd, false) catch return error.BindFailed; // `Threaded` accepts blocking.
    const reuse = std.mem.asBytes(&@as(c_int, 1));
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, reuse) catch
        return error.BindFailed;
    if (posix.errno(posix.system.bind(fd, &storage.any, length)) != .SUCCESS) {
        return error.BindFailed;
    }
    if (posix.errno(posix.system.listen(fd, listen_backlog)) != .SUCCESS) {
        return error.BindFailed;
    }
    length = @sizeOf(SocketAddress);
    if (posix.errno(posix.system.getsockname(fd, &storage.any, &length)) != .SUCCESS) {
        return error.BindFailed;
    }
    const local = address_from(&storage);
    assert(local.getPort() != 0);
    return .{ .socket = .{ .handle = fd, .address = local }, .options = {} };
}

const SocketAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

fn socket_address(address: Address, storage: *SocketAddress) posix.socklen_t {
    switch (address) {
        .ip4 => |ip4| {
            // The address bytes are already in network order.
            storage.in = .{
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
            };
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |ip6| {
            storage.in6 = .{
                .port = std.mem.nativeToBig(u16, ip6.port),
                .flowinfo = ip6.flow,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            return @sizeOf(posix.sockaddr.in6);
        },
    }
}

fn address_from(storage: *const SocketAddress) Address {
    return switch (storage.any.family) {
        posix.AF.INET6 => .{ .ip6 = .{
            .port = std.mem.bigToNative(u16, storage.in6.port),
            .bytes = storage.in6.addr,
            .flow = storage.in6.flowinfo,
            .interface = .{ .index = storage.in6.scope_id },
        } },
        else => .{ .ip4 = .{
            .bytes = @bitCast(storage.in.addr),
            .port = std.mem.bigToNative(u16, storage.in.port),
        } },
    };
}

/// A nonblocking, close-on-exec TCP socket.
fn socket_open(family: posix.sa_family_t) Error!posix.socket_t {
    assert(family == posix.AF.INET or family == posix.AF.INET6);
    const rc = posix.system.socket(family, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.ConnectionFailed;
    const fd: posix.socket_t = @intCast(rc);
    errdefer _ = posix.system.close(fd);
    const cloexec = posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC));
    if (posix.errno(cloexec) != .SUCCESS) return error.ConnectionFailed;
    try set_nonblocking(fd, true);
    return fd;
}

fn set_nonblocking(fd: posix.socket_t, nonblocking: bool) Error!void {
    const rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(rc) != .SUCCESS) return error.ConnectionFailed;
    const flag = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    const flags: usize = @intCast(rc);
    const updated = if (nonblocking) flags | flag else flags & ~flag;
    const set = posix.system.fcntl(fd, posix.F.SETFL, updated);
    if (posix.errno(set) != .SUCCESS) return error.ConnectionFailed;
}

/// Waits for a connect in progress to finish, by the deadline, and returns its outcome.
fn connect_wait(io: Io, fd: posix.socket_t, timeout: Io.Timeout) Error!void {
    assert(timeout == .deadline);
    while (true) {
        try io.checkCancel();
        const left_ns = timeout.deadline.durationFromNow(io).raw.nanoseconds;
        if (left_ns <= 0) return error.Timeout;
        const left_ms = @divFloor(left_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms);
        const wait_ms: i32 = @intCast(@min(left_ms, connect_slice_ms));
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
        const ready = posix.poll(&fds, wait_ms) catch return error.ConnectionFailed;
        if (ready > 0) break;
    }
    var failure: i32 = 0;
    var failure_length: posix.socklen_t = @sizeOf(i32);
    const rc = posix.system.getsockopt(
        fd,
        posix.SOL.SOCKET,
        posix.SO.ERROR,
        @ptrCast(&failure),
        &failure_length,
    );
    if (posix.errno(rc) != .SUCCESS or failure != 0) return error.ConnectionFailed;
}
