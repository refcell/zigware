//! Deterministic network (commonware `runtime/src/network/deterministic.rs`): listeners and
//! connections in memory, each connection a pair of mock channels (`runtime.mocks`).
//!
//! A dialer is given an address `127.0.0.1:<port>` with ports assigned in order from 32768.
//! To keep this simple, binding `127.0.0.1` to a port in the ephemeral range fails, and
//! running out of ports (past 65535) panics. As in commonware, a bound address stays bound
//! after its listener closes: dialing it fails and binding it again fails.
//!
//! With an `auditor` (the deterministic runner sets its own), binds, dials, accepts, sends, and
//! receives are recorded as commonware's `network/audited.rs` records them: an attempt, then a
//! success or a failure. With `metrics`, connections and bytes are counted as commonware's
//! `network/metered.rs` counts them (`network/metered.zig`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const mocks = @import("../mocks.zig");
const network = @import("../network.zig");
const Auditor = @import("../deterministic.zig").Auditor;
const Metrics = @import("metered.zig").Metrics;

const Address = network.Address;
const Error = network.Error;

/// Ports assigned to dialers, `ephemeral_port_min..ephemeral_port_end`; binding 127.0.0.1 to
/// one of them fails.
pub const ephemeral_port_min: u16 = 32768;
pub const ephemeral_port_end: u16 = 61000;

pub const Sink = mocks.Sink;
pub const Stream = mocks.Stream;

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
        network: *Network,
        address: Address,
        /// Dialed connections not yet accepted, oldest first.
        pending: std.ArrayList(Accepted) = .empty,
        open: bool = true,

        /// Waits for the next dialed connection.
        pub fn accept(listener: *Listener) Error!Accepted {
            var accepted = try listener.accept_audited();
            if (listener.network.metrics) |metrics| {
                metrics.inbound_connections.metric().inc();
                accepted.sink.metrics = metrics;
                accepted.stream.metrics = metrics;
            }
            return accepted;
        }

        fn accept_audited(listener: *Listener) Error!Accepted {
            const auditor = listener.network.auditor orelse return listener.next();
            const local: mocks.Audit = .init(auditor, listener.address);
            auditor.event("accept_attempt", &.{local.address()});
            var accepted = listener.next() catch |err| {
                auditor.event("accept_failure", &.{ local.address(), @errorName(err) });
                return err;
            };
            const remote: mocks.Audit = .init(auditor, accepted.address);
            auditor.event("accept_success", &.{ local.address(), remote.address() });
            accepted.sink.audit = remote;
            accepted.stream.audit = remote;
            return accepted;
        }

        fn next(listener: *Listener) Error!Accepted {
            const net = listener.network;
            net.lock();
            defer net.unlock();
            while (listener.open and listener.pending.items.len == 0) {
                try net.condition.wait(net.io, &net.mutex);
            }
            if (listener.pending.items.len == 0) return error.ReadFailed;
            assert(listener.open);
            return listener.pending.orderedRemove(0);
        }

        pub fn local_addr(listener: *const Listener) Address {
            return listener.address;
        }

        /// Closes the listener and every connection it has not accepted. Its address stays
        /// bound; the network frees the listener.
        pub fn deinit(listener: *Listener) void {
            const net = listener.network;
            net.lock();
            defer net.unlock();
            listener.close();
            net.condition.broadcast(net.io);
        }

        /// Called with the network locked.
        fn close(listener: *Listener) void {
            for (listener.pending.items) |*pending| pending.deinit();
            listener.pending.clearAndFree(listener.network.gpa);
            listener.open = false;
        }
    };

    gpa: Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
    /// The port the next dialer gets.
    ephemeral: u16 = ephemeral_port_min,
    /// Every listener ever bound, open or closed (their addresses stay bound).
    listeners: std.ArrayList(*Listener) = .empty,
    /// Records network operations when set.
    auditor: ?*Auditor = null,
    /// Counts connections and bytes when set.
    metrics: ?*const Metrics = null,

    pub fn init(gpa: Allocator, io: Io) Network {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(net: *Network) void {
        for (net.listeners.items) |listener| {
            if (listener.open) listener.close();
            net.gpa.destroy(listener);
        }
        net.listeners.deinit(net.gpa);
        net.* = undefined;
    }

    fn lock(net: *Network) void {
        net.mutex.lockUncancelable(net.io);
    }

    fn unlock(net: *Network) void {
        net.mutex.unlock(net.io);
    }

    fn find(net: *Network, address: Address) ?*Listener {
        for (net.listeners.items) |listener| {
            if (listener.address.eql(&address)) return listener;
        }
        return null;
    }

    /// Binds a listener to `address`.
    pub fn bind(net: *Network, address: Address) Error!*Listener {
        const auditor = net.auditor orelse return net.bind_listener(address);
        const local: mocks.Audit = .init(auditor, address);
        auditor.event("bind_attempt", &.{local.address()});
        const listener = net.bind_listener(address) catch |err| {
            auditor.event("bind_failure", &.{ local.address(), @errorName(err) });
            return err;
        };
        auditor.event("bind_success", &.{local.address()});
        return listener;
    }

    fn bind_listener(net: *Network, address: Address) Error!*Listener {
        if (address == .ip4 and std.mem.eql(u8, &address.ip4.bytes, &.{ 127, 0, 0, 1 }) and
            address.ip4.port >= ephemeral_port_min and address.ip4.port < ephemeral_port_end)
        {
            return error.BindFailed;
        }
        net.lock();
        defer net.unlock();
        if (net.find(address) != null) return error.BindFailed;
        try net.listeners.ensureUnusedCapacity(net.gpa, 1);
        const listener = try net.gpa.create(Listener);
        listener.* = .{ .network = net, .address = address };
        net.listeners.appendAssumeCapacity(listener);
        assert(net.find(address) == listener);
        return listener;
    }

    /// Connects to the listener bound to `address`.
    pub fn dial(net: *Network, address: Address) Error!Connection {
        var connection = try net.dial_audited(address);
        if (net.metrics) |metrics| {
            metrics.outbound_connections.metric().inc();
            connection.sink.metrics = metrics;
            connection.stream.metrics = metrics;
        }
        return connection;
    }

    fn dial_audited(net: *Network, address: Address) Error!Connection {
        const auditor = net.auditor orelse return net.connect(address);
        const remote: mocks.Audit = .init(auditor, address);
        auditor.event("dial_attempt", &.{remote.address()});
        var connection = net.connect(address) catch |err| {
            auditor.event("dial_failure", &.{ remote.address(), @errorName(err) });
            return err;
        };
        auditor.event("dial_success", &.{remote.address()});
        connection.sink.audit = remote;
        connection.stream.audit = remote;
        return connection;
    }

    fn connect(net: *Network, address: Address) Error!Connection {
        net.lock();
        defer net.unlock();
        // The dialer's port is assigned (and used up) before the listener is looked up.
        const dialer: Address = .{ .ip4 = .loopback(net.ephemeral) };
        net.ephemeral = std.math.add(u16, net.ephemeral, 1) catch
            @panic("ephemeral port range exhausted");
        const listener = net.find(address) orelse return error.ConnectionFailed;
        if (!listener.open) return error.ConnectionFailed;
        try listener.pending.ensureUnusedCapacity(net.gpa, 1);
        // Listener to dialer, and dialer to listener.
        var to_dialer = try mocks.channel(net.gpa, net.io);
        errdefer {
            to_dialer.sink.deinit();
            to_dialer.stream.deinit();
        }
        const to_listener = try mocks.channel(net.gpa, net.io);
        listener.pending.appendAssumeCapacity(.{
            .address = dialer,
            .sink = to_dialer.sink,
            .stream = to_listener.stream,
        });
        net.condition.broadcast(net.io);
        assert(dialer.ip4.port < net.ephemeral);
        return .{ .sink = to_listener.sink, .stream = to_dialer.stream };
    }
};

test {
    _ = @import("deterministic_test.zig");
}
