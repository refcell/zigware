//! A read started ahead of its use (commonware's `Handle` returned by `Blob::start_read_many`).
//!
//! The read fills a buffer the caller owns, so the caller keeps that buffer alive until it
//! either `wait`s for the result or `abandon`s the read. Unlike commonware's dropped handle,
//! abandoning still waits for the read to stop, because the bytes land in the caller's buffer.
//! Neither call is a cancelation point: both run to the read's end.
//!
//! - `PendingRead.ready(result)` is already complete; backends without a `start_read` entry
//!   read inline and return it, so their callers see no concurrency.
//! - A started read is a backend's object behind `Started`, which `finish` resolves and
//!   frees once.

const std = @import("std");
const assert = std.debug.assert;
const Error = @import("../storage.zig").Error;

pub const PendingRead = struct {
    state: State,

    const State = union(enum) {
        /// Complete: the failure, or null on success.
        ready: ?Error,
        started: Started,
        /// Already waited or abandoned.
        done,
    };

    /// A backend's in-flight read. `finish` blocks until the read ends, frees the backend's
    /// state, and returns the read's result; with `abandon` set the read may be canceled.
    pub const Started = struct {
        ptr: *anyopaque,
        finish: *const fn (ptr: *anyopaque, abandon: bool) Error!void,
    };

    /// A completed read with `result`.
    pub fn ready(result: Error!void) PendingRead {
        result catch |err| return .{ .state = .{ .ready = err } };
        return .{ .state = .{ .ready = null } };
    }

    pub fn started(read: Started) PendingRead {
        return .{ .state = .{ .started = read } };
    }

    /// The read's result, once it has filled the buffer. Consumes the handle.
    pub fn wait(pending: *PendingRead) Error!void {
        const state = pending.state;
        assert(state != .done);
        pending.state = .done;
        switch (state) {
            .ready => |failure| if (failure) |err| return err,
            .started => |read| return read.finish(read.ptr, false),
            .done => unreachable, // Asserted above.
        }
    }

    /// Stops observing the read; returns once it no longer touches the buffer. Consumes the
    /// handle and discards the result.
    pub fn abandon(pending: *PendingRead) void {
        const state = pending.state;
        assert(state != .done);
        pending.state = .done;
        switch (state) {
            .ready => {},
            // A `Canceled` here is the read task's, from the cancel `abandon` requested, not
            // the caller's: finishing a read is not a cancelation point.
            .started => |read| read.finish(read.ptr, true) catch {},
            .done => unreachable, // Asserted above.
        }
    }

    pub fn is_done(pending: *const PendingRead) bool {
        return pending.state == .done;
    }
};

test "a ready read reports its result once" {
    var ok: PendingRead = .ready({});
    try ok.wait();
    try std.testing.expect(ok.is_done());
    var failed: PendingRead = .ready(error.ReadFailed);
    try std.testing.expectError(error.ReadFailed, failed.wait());
    var dropped: PendingRead = .ready(error.ReadFailed);
    dropped.abandon();
    try std.testing.expect(dropped.is_done());
}
