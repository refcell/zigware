//! Tests for `timeout.zig`, ported from the upgrader tests in commonware `stream/src/lib.rs`.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const build_options = @import("build_options");
const runtime = @import("runtime");

const Timeout = @import("timeout.zig").Timeout;
const mocks = runtime.mocks;

const gpa = testing.allocator;

const Outcome = enum { success, failure, pending };

const Parameters = struct { namespace: []const u8, max_message_size: u32 };

/// An upgrader whose attempts succeed, fail, or never finish, and that records the namespace
/// and limit each attempt received. Its halves own the connection; anything else closes it.
const OpaqueUpgrader = struct {
    outcome: Outcome,
    received: *std.ArrayList(Parameters),

    pub const PublicKey = u8;
    pub const max_size: u32 = std.math.maxInt(u32);

    pub fn Connection(comptime StreamType: type, comptime SinkType: type) type {
        return struct {
            stream: StreamType,
            sink: SinkType,

            pub fn deinit(connection: *@This(), _: Allocator) void {
                connection.stream.deinit();
                connection.sink.deinit();
            }
        };
    }

    pub fn Accepted(comptime StreamType: type, comptime SinkType: type) type {
        return struct {
            peer: PublicKey,
            connection: Connection(StreamType, SinkType),

            pub fn deinit(accepted: *@This(), allocator: Allocator) void {
                accepted.connection.deinit(allocator);
            }
        };
    }

    pub fn public_key(_: OpaqueUpgrader) PublicKey {
        return 0;
    }

    fn establish(
        upgrader: OpaqueUpgrader,
        io: Io,
        stream: mocks.Stream,
        sink: mocks.Sink,
    ) !Connection(mocks.Stream, mocks.Sink) {
        var owned_stream = stream;
        var owned_sink = sink;
        errdefer owned_stream.deinit();
        errdefer owned_sink.deinit();
        switch (upgrader.outcome) {
            .pending => while (true) try io.sleep(.fromSeconds(1), .awake),
            .failure => return error.Rejected,
            .success => return .{ .stream = owned_stream, .sink = owned_sink },
        }
    }

    pub fn dial(
        upgrader: OpaqueUpgrader,
        _: Allocator,
        io: Io,
        namespace: []const u8,
        max_message_size: u32,
        _: PublicKey,
        stream: mocks.Stream,
        sink: mocks.Sink,
    ) !Connection(mocks.Stream, mocks.Sink) {
        try upgrader.received.append(gpa, .{
            .namespace = namespace,
            .max_message_size = max_message_size,
        });
        return upgrader.establish(io, stream, sink);
    }

    pub fn listen(
        upgrader: OpaqueUpgrader,
        _: Allocator,
        io: Io,
        namespace: []const u8,
        max_message_size: u32,
        bouncer: anytype,
        stream: mocks.Stream,
        sink: mocks.Sink,
    ) !Accepted(mocks.Stream, mocks.Sink) {
        var owned_stream = stream;
        var owned_sink = sink;
        try upgrader.received.append(gpa, .{
            .namespace = namespace,
            .max_message_size = max_message_size,
        });
        const admitted = bouncer.admit(upgrader.public_key()) catch |err| {
            owned_stream.deinit();
            owned_sink.deinit();
            return err;
        };
        if (!admitted) {
            owned_stream.deinit();
            owned_sink.deinit();
            return error.Rejected;
        }
        const connection = try upgrader.establish(io, owned_stream, owned_sink);
        return .{ .peer = 0, .connection = connection };
    }
};

const AdmitAll = struct {
    pub fn admit(_: AdmitAll, _: u8) Io.Cancelable!bool {
        return true;
    }
};

fn run_deterministic(comptime function: anytype, args: anytype) !void {
    for (0..build_options.fuzz_soak) |round| {
        const config: runtime.deterministic.Config = .{
            .seed = soak_seed(0, round),
            .timeout_ns = std.time.ns_per_s,
        };
        var runner = try runtime.deterministic.Runner.init(gpa, config);
        defer runner.deinit();
        try (try runner.start(function, .{runner.io()} ++ args));
    }
}

/// The `round`-th seed of a deterministic test whose unsoaked seed is `base`: `base` first, then
/// `-Dfuzz-soak` rounds in all, spread by `-Dfuzz-seed`. Soaked rounds print their seed, so a
/// failure names the seed to replay.
fn soak_seed(base: u64, round: u64) u64 {
    if (round == 0) return base;
    const seed = base +% build_options.fuzz_seed *% 0x9e3779b97f4a7c15 +% round;
    std.debug.print("dst: seed {d}\n", .{seed});
    return seed;
}

/// The far ends of the two channels an attempt receives.
const Peer = struct {
    stream: mocks.Stream,
    sink: mocks.Sink,

    /// Both ends fail once the attempt released its connection.
    fn expect_released(peer: *Peer) !void {
        try testing.expectError(error.SendFailed, peer.sink.send(&.{"x"}));
        var byte: [1]u8 = undefined;
        try testing.expectError(error.RecvFailed, peer.stream.recv(&byte));
        peer.stream.deinit();
        peer.sink.deinit();
    }
};

/// Runs one dial or listen attempt through `Timeout` over fresh channels.
fn attempt(
    io: Io,
    upgrader: Timeout(OpaqueUpgrader),
    dialer: bool,
    namespace: []const u8,
    max: u32,
    peer: *Peer,
) anyerror!void {
    const out = try mocks.channel(gpa, io);
    const in = try mocks.channel(gpa, io);
    peer.* = .{ .stream = out.stream, .sink = in.sink };
    if (dialer) {
        var connection = try upgrader.dial(gpa, io, namespace, max, 0, in.stream, out.sink);
        connection.deinit(gpa);
    } else {
        const admit: AdmitAll = .{};
        var accepted = try upgrader.listen(gpa, io, namespace, max, admit, in.stream, out.sink);
        accepted.deinit(gpa);
    }
}

fn forwards_parameters(io: Io) !void {
    const cases = [_]Parameters{
        .{ .namespace = &.{ 1, 2, 3 }, .max_message_size = 1 },
        .{ .namespace = "configured", .max_message_size = OpaqueUpgrader.max_size },
    };
    for (cases) |case| {
        var received: std.ArrayList(Parameters) = .empty;
        defer received.deinit(gpa);
        const opaque_upgrader: OpaqueUpgrader = .{ .outcome = .success, .received = &received };
        const upgrader = Timeout(OpaqueUpgrader).init(opaque_upgrader, .fromSeconds(1));
        try testing.expectEqual(@as(u8, 0), upgrader.public_key());

        // Reuse one upgrader for several connections in each direction.
        for (0..2) |_| {
            for ([_]bool{ true, false }) |dialer| {
                var peer: Peer = undefined;
                try attempt(io, upgrader, dialer, case.namespace, case.max_message_size, &peer);
                try peer.expect_released();
            }
        }
        try testing.expectEqual(@as(usize, 4), received.items.len);
        for (received.items) |parameters| {
            try testing.expectEqualSlices(u8, case.namespace, parameters.namespace);
            try testing.expectEqual(case.max_message_size, parameters.max_message_size);
        }
    }
}

test "timeout forwards each attempt's namespace and limit" {
    try run_deterministic(forwards_parameters, .{});
}

fn preserves_result(io: Io, dialer: bool, outcome: Outcome, duration_ms: i64) !void {
    var received: std.ArrayList(Parameters) = .empty;
    defer received.deinit(gpa);
    const opaque_upgrader: OpaqueUpgrader = .{ .outcome = outcome, .received = &received };
    const upgrader = Timeout(OpaqueUpgrader).init(opaque_upgrader, .fromMilliseconds(duration_ms));
    const start = Io.Clock.awake.now(io);
    var peer: Peer = undefined;
    const result = attempt(io, upgrader, dialer, "timeout", 1, &peer);
    switch (outcome) {
        .success => try result,
        .failure => try testing.expectError(error.Rejected, result),
        .pending => {
            try testing.expectError(error.Timeout, result);
            const elapsed_ns = Io.Clock.awake.now(io).nanoseconds - start.nanoseconds;
            const duration_ns = duration_ms * std.time.ns_per_ms;
            // The deadline fires on time. Canceling the attempt then takes a few scheduler
            // cycles (1 ms each), because a canceled fiber must run to unwind; a dropped Rust
            // future does not.
            try testing.expect(elapsed_ns >= duration_ns);
            try testing.expect(elapsed_ns < duration_ns + 5 * std.time.ns_per_ms);
        },
    }
    try peer.expect_released();
}

test "timeout preserves results and releases connections" {
    for ([_]bool{ false, true }) |dialer| {
        for ([_]Outcome{ .success, .failure, .pending }) |outcome| {
            for ([_]i64{ 0, 50 }) |duration_ms| {
                try run_deterministic(preserves_result, .{ dialer, outcome, duration_ms });
            }
        }
    }
}

/// An attempt awaited after its deadline has already timed out: the deadline runs from the
/// call, not from the await (commonware `handshake_starts_timeout_when_called`).
fn starts_timeout_when_called(io: Io, dialer: bool) !void {
    var received: std.ArrayList(Parameters) = .empty;
    defer received.deinit(gpa);
    const opaque_upgrader: OpaqueUpgrader = .{ .outcome = .pending, .received = &received };
    const upgrader = Timeout(OpaqueUpgrader).init(opaque_upgrader, .fromMilliseconds(50));
    var peer: Peer = undefined;
    var future = try io.concurrent(attempt, .{ io, upgrader, dialer, "timeout", 1, &peer });
    try io.sleep(.fromMilliseconds(100), .awake);
    const start = Io.Clock.awake.now(io);
    try testing.expectError(error.Timeout, future.await(io));
    const waited_ns = Io.Clock.awake.now(io).nanoseconds - start.nanoseconds;
    try testing.expect(waited_ns < std.time.ns_per_ms);
    try peer.expect_released();
}

test "timeout starts when the attempt is made" {
    for ([_]bool{ false, true }) |dialer| {
        try run_deterministic(starts_timeout_when_called, .{dialer});
    }
}

/// Never admits; records that its pending admission was dropped (canceled).
const PendingBouncer = struct {
    io: Io,
    dropped: *bool,

    pub fn admit(bouncer: PendingBouncer, _: u8) Io.Cancelable!bool {
        defer bouncer.dropped.* = true;
        while (true) try bouncer.io.sleep(.fromSeconds(1), .awake);
    }
};

fn listen_pending(
    io: Io,
    upgrader: Timeout(OpaqueUpgrader),
    dropped: *bool,
    in_stream: mocks.Stream,
    out_sink: mocks.Sink,
) anyerror!void {
    const bouncer: PendingBouncer = .{ .io = io, .dropped = dropped };
    var accepted = try upgrader.listen(gpa, io, "timeout", 1, bouncer, in_stream, out_sink);
    accepted.deinit(gpa);
}

fn cancels_pending_admission(io: Io, cancel: bool) !void {
    var received: std.ArrayList(Parameters) = .empty;
    defer received.deinit(gpa);
    const opaque_upgrader: OpaqueUpgrader = .{ .outcome = .success, .received = &received };
    const upgrader = Timeout(OpaqueUpgrader).init(opaque_upgrader, .fromMilliseconds(50));
    const out = try mocks.channel(gpa, io);
    const in = try mocks.channel(gpa, io);
    var peer: Peer = .{ .stream = out.stream, .sink = in.sink };
    var dropped = false;
    const args = .{ io, upgrader, &dropped, in.stream, out.sink };
    var future = try io.concurrent(listen_pending, args);
    try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expect(!dropped);
    if (cancel) {
        try testing.expectError(error.Canceled, future.cancel(io));
    } else {
        try testing.expectError(error.Timeout, future.await(io));
    }
    try testing.expect(dropped);
    try peer.expect_released();
}

test "timeout cancels a pending admission" {
    for ([_]bool{ false, true }) |cancel| {
        try run_deterministic(cancels_pending_admission, .{cancel});
    }
}
