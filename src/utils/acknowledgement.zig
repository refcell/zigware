//! Acknowledging the completion of a task (commonware `utils/src/acknowledgement.rs`).
//!
//! An `Acknowledgement` is a comptime interface: a type with `handle(gpa, io)` returning a
//! handle and its `Waiter`, `clone`, `acknowledge` (consumes the handle), and `deinit` (drops
//! it). `Exact` resolves its waiter once every clone is acknowledged; dropping any clone
//! without acknowledging cancels the waiter.
//!
//! The shared state is guarded by a `std.Io.Mutex` and the waiter parks on a
//! `std.Io.Condition`, so it runs on any `std.Io`, deterministically on the simulated one.
//! Each handle and the waiter are released exactly once; the state is freed with the last.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// The acknowledgement was canceled: a handle was dropped without acknowledging.
pub const Canceled = error{AcknowledgementCanceled};

/// `Waiter.wait` failed.
pub const WaitError = Canceled || Io.Cancelable;

/// Asserts `T` implements the `Acknowledgement` interface.
pub fn assert_acknowledgement(comptime T: type) void {
    comptime {
        assert(@hasDecl(T, "Waiter"));
        assert(@hasDecl(T, "handle"));
        assert(@hasDecl(T, "clone"));
        assert(@hasDecl(T, "acknowledge"));
        assert(@hasDecl(T, "deinit"));
        assert(@hasDecl(T.Waiter, "wait"));
        assert(@hasDecl(T.Waiter, "deinit"));
    }
}

/// An acknowledgement that resolves after all of its clones are acknowledged.
pub const Exact = struct {
    state: *State,

    pub const Waiter = ExactWaiter;
    pub const Handle = struct { acknowledgement: Exact, waiter: ExactWaiter };

    /// A new acknowledgement (one outstanding) and its waiter.
    pub fn handle(gpa: Allocator, io: Io) Allocator.Error!Handle {
        const state = try gpa.create(State);
        state.* = .{ .gpa = gpa, .io = io };
        assert(state.remaining == 1 and state.references == 2);
        return .{ .acknowledgement = .{ .state = state }, .waiter = .{ .state = state } };
    }

    /// Another handle that must also be acknowledged.
    pub fn clone(self: Exact) Exact {
        const state = self.state;
        state.lock();
        defer state.unlock();
        // A live handle keeps `remaining` above zero, so the waiter cannot resolve yet.
        assert(state.remaining > 0);
        state.remaining += 1;
        state.references += 1;
        return .{ .state = state };
    }

    /// Fulfills this handle, consuming it. The last one resolves the waiter.
    pub fn acknowledge(self: *Exact) void {
        const state = self.state;
        self.* = undefined;
        state.lock();
        assert(state.remaining > 0);
        state.remaining -= 1;
        if (state.remaining == 0) state.condition.broadcast(state.io);
        state.release_locked();
    }

    /// Drops this handle without acknowledging: cancels the waiter.
    pub fn deinit(self: *Exact) void {
        const state = self.state;
        self.* = undefined;
        state.lock();
        state.canceled = true;
        state.condition.broadcast(state.io);
        state.release_locked();
    }
};

/// Waits for an `Exact` acknowledgement to complete or be canceled.
pub const ExactWaiter = struct {
    state: *State,

    /// Waits until every handle is acknowledged (or one is dropped: `AcknowledgementCanceled`).
    pub fn wait(self: *const ExactWaiter) WaitError!void {
        const state = self.state;
        state.lock();
        defer state.unlock();
        while (true) {
            if (try state.outcome()) return;
            try state.condition.wait(state.io, &state.mutex);
        }
    }

    /// The outcome without waiting (Rust `now_or_never`): null while pending.
    pub fn poll(self: *const ExactWaiter) ?Canceled!void {
        const state = self.state;
        state.lock();
        defer state.unlock();
        const done = state.outcome() catch |err| return err;
        return if (done) {} else null;
    }

    /// Drops the waiter; the handles stay usable.
    pub fn deinit(self: *ExactWaiter) void {
        const state = self.state;
        self.* = undefined;
        state.lock();
        state.release_locked();
    }
};

const State = struct {
    gpa: Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
    /// Handles not yet acknowledged.
    remaining: usize = 1,
    canceled: bool = false,
    /// Live handles plus the waiter; zero frees the state.
    references: usize = 2,

    fn lock(state: *State) void {
        state.mutex.lockUncancelable(state.io);
    }

    fn unlock(state: *State) void {
        state.mutex.unlock(state.io);
    }

    /// Done (true), pending (false), or canceled; cancelation wins (lock held).
    fn outcome(state: *const State) Canceled!bool {
        if (state.canceled) return error.AcknowledgementCanceled;
        return state.remaining == 0;
    }

    /// Drops one reference and unlocks, freeing the state with the last one.
    fn release_locked(state: *State) void {
        assert(state.references > 0);
        state.references -= 1;
        // Live handles are unacknowledged, so they never outnumber `remaining`.
        assert(state.references <= state.remaining + 1);
        const last = state.references == 0;
        state.unlock();
        if (last) state.gpa.destroy(state);
    }
};

comptime {
    assert_acknowledgement(Exact);
}

test {
    _ = @import("acknowledgement_test.zig");
}
