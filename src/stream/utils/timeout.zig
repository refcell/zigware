//! A deadline on every upgrader attempt (commonware `stream/src/utils/timeout.rs`).
//!
//! The deadline starts when `dial` or `listen` is called and covers the whole attempt,
//! including the listener's bouncer. On expiry the attempt is canceled (`error.Canceled` at
//! its next cancelation point), which releases its connection, and the call returns
//! `error.Timeout`. Canceling the call itself cancels the attempt the same way.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Wraps upgrader `U` (for example `stream.SakeCups(S, C)`) with a deadline per attempt.
/// Results are those of `U`, with `error.Timeout` added; errors are `anyerror` because the
/// attempt runs as its own task.
pub fn Timeout(comptime U: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = U.PublicKey;
        pub const max_size = U.max_size;

        upgrader: U,
        timeout: Io.Duration,

        /// Wraps `upgrader` with a deadline of `timeout` for each connection attempt.
        pub fn init(upgrader: U, timeout: Io.Duration) Self {
            assert(timeout.nanoseconds >= 0);
            return .{ .upgrader = upgrader, .timeout = timeout };
        }

        pub fn public_key(self: Self) PublicKey {
            return self.upgrader.public_key();
        }

        pub fn dial(
            self: Self,
            gpa: Allocator,
            io: Io,
            namespace: []const u8,
            max_message_size: u32,
            peer: PublicKey,
            stream: anytype,
            sink: anytype,
        ) anyerror!U.Connection(@TypeOf(stream), @TypeOf(sink)) {
            const Connection = U.Connection(@TypeOf(stream), @TypeOf(sink));
            const Attempt = struct {
                fn run(
                    upgrader: U,
                    attempt_gpa: Allocator,
                    attempt_io: Io,
                    attempt_namespace: []const u8,
                    max: u32,
                    attempt_peer: PublicKey,
                    attempt_stream: @TypeOf(stream),
                    attempt_sink: @TypeOf(sink),
                ) anyerror!Connection {
                    return upgrader.dial(
                        attempt_gpa,
                        attempt_io,
                        attempt_namespace,
                        max,
                        attempt_peer,
                        attempt_stream,
                        attempt_sink,
                    );
                }
            };
            const deadline_at = self.expiry(io);
            const args = .{
                self.upgrader, gpa, io, namespace, max_message_size, peer, stream, sink,
            };
            return race(Connection, gpa, io, deadline_at, Attempt.run, args);
        }

        pub fn listen(
            self: Self,
            gpa: Allocator,
            io: Io,
            namespace: []const u8,
            max_message_size: u32,
            bouncer: anytype,
            stream: anytype,
            sink: anytype,
        ) anyerror!U.Accepted(@TypeOf(stream), @TypeOf(sink)) {
            const Accepted = U.Accepted(@TypeOf(stream), @TypeOf(sink));
            const Attempt = struct {
                fn run(
                    upgrader: U,
                    attempt_gpa: Allocator,
                    attempt_io: Io,
                    attempt_namespace: []const u8,
                    max: u32,
                    attempt_bouncer: @TypeOf(bouncer),
                    attempt_stream: @TypeOf(stream),
                    attempt_sink: @TypeOf(sink),
                ) anyerror!Accepted {
                    return upgrader.listen(
                        attempt_gpa,
                        attempt_io,
                        attempt_namespace,
                        max,
                        attempt_bouncer,
                        attempt_stream,
                        attempt_sink,
                    );
                }
            };
            const deadline_at = self.expiry(io);
            const args = .{
                self.upgrader, gpa, io, namespace, max_message_size, bouncer, stream, sink,
            };
            return race(Accepted, gpa, io, deadline_at, Attempt.run, args);
        }

        fn expiry(self: Self, io: Io) Io.Clock.Timestamp {
            return .fromNow(io, .{ .raw = self.timeout, .clock = .awake });
        }
    };
}

fn wait_until(io: Io, deadline: Io.Clock.Timestamp) Io.Cancelable!void {
    return deadline.wait(io);
}

/// Runs `attempt(args...)` until it finishes or `deadline` passes, whichever is first. An
/// attempt that finishes while the deadline task wins still counts, like commonware's biased
/// `select!` that polls the attempt first.
fn race(
    comptime T: type,
    gpa: Allocator,
    io: Io,
    deadline: Io.Clock.Timestamp,
    comptime attempt: anytype,
    args: std.meta.ArgsTuple(@TypeOf(attempt)),
) anyerror!T {
    const Outcome = union(enum) { attempt: anyerror!T, deadline: Io.Cancelable!void };
    var buffer: [2]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);
    select.concurrent(.attempt, attempt, args) catch |err| {
        // The attempt never ran, so the stream and sink (its last two arguments) are still ours.
        var owned = args;
        deinit_transport(&owned[owned.len - 2]);
        deinit_transport(&owned[owned.len - 1]);
        return err;
    };
    select.concurrent(.deadline, wait_until, .{ io, deadline }) catch |err| {
        release(T, gpa, &select);
        return err;
    };
    const first = select.await() catch |err| {
        release(T, gpa, &select);
        return err;
    };
    switch (first) {
        .attempt => |result| {
            release(T, gpa, &select);
            return result;
        },
        .deadline => |slept| {
            const late = cancel_attempt(T, &select);
            if (slept) |_| {} else |err| {
                if (late) |result| release_result(T, gpa, result);
                return err;
            }
            const result = late orelse return error.Timeout;
            if (result) |value| return value else |err| {
                return if (err == error.Canceled) error.Timeout else err;
            }
        },
    }
}

fn deinit_transport(transport: anytype) void {
    if (comptime @hasDecl(@TypeOf(transport.*), "deinit")) transport.deinit();
}

/// Cancels the attempt and returns its result.
fn cancel_attempt(comptime T: type, select: anytype) ?(anyerror!T) {
    var result: ?(anyerror!T) = null;
    var remaining: u32 = 0;
    while (select.cancel()) |late| : (remaining += 1) {
        assert(remaining < 2);
        switch (late) {
            .attempt => |outcome| result = outcome,
            .deadline => {},
        }
    }
    return result;
}

/// Cancels the remaining tasks and releases any connection one of them still produced.
fn release(comptime T: type, gpa: Allocator, select: anytype) void {
    if (cancel_attempt(T, select)) |result| release_result(T, gpa, result);
}

fn release_result(comptime T: type, gpa: Allocator, result: anyerror!T) void {
    if (result) |value| {
        var owned = value;
        owned.deinit(gpa);
    } else |_| {}
}

test {
    _ = @import("timeout_test.zig");
}
