//! Mock applications for marshal's verification tests (commonware
//! `marshal/mocks/verifying.rs`).
//!
//! Each follows `application.build`'s contract: `propose(*A, ctx, consensus_context,
//! ancestry) !?Digested(Block)`, optionally `prepare(...)`, and `verify(*A, ctx,
//! consensus_context, ancestry) !bool`. They own the ancestry they are given and free it. Like
//! commonware's `Clone` apps, copies share one state: the gates and the observation log live
//! behind pointers the test owns.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const utils = @import("utils");
const traits = @import("../../traits.zig");

const oneshot = utils.channel.oneshot;
const Handoff = traits.Handoff;

/// Waits until canceled (commonware's `pending()`).
fn pending(io: Io) Io.Cancelable!noreturn {
    while (true) try io.sleep(.fromSeconds(3_600), .awake);
}

fn free_ancestry(ancestry: anytype) void {
    var owned = ancestry;
    owned.deinit();
}

/// Signals that the next proposal started (`started`), then holds it until it is dropped
/// (`dropped` closes).
pub const ProposalGate = struct {
    started: ?oneshot.Sender(void),
    dropped: ?oneshot.Sender(void),

    /// The gate with the receivers a test waits on.
    pub fn init(gpa: Allocator, io: Io) !struct {
        gate: ProposalGate,
        started: oneshot.Receiver(void),
        dropped: oneshot.Receiver(void),
    } {
        var started = try oneshot.channel(void, gpa, io);
        errdefer {
            started.sender.deinit();
            started.receiver.deinit();
        }
        const dropped = try oneshot.channel(void, gpa, io);
        return .{
            .gate = .{ .started = started.sender, .dropped = dropped.sender },
            .started = started.receiver,
            .dropped = dropped.receiver,
        };
    }

    /// Releases senders the application never took.
    pub fn deinit(gate: *ProposalGate) void {
        if (gate.started) |*sender| sender.deinit();
        if (gate.dropped) |*sender| sender.deinit();
        gate.* = undefined;
    }
};

/// Proposes `propose_result` (when set), answers `prepare` with `handoff`, and verifies with
/// `verify_result` unless `reject` rejects the block under verification (commonware
/// `MockVerifyingApp`).
pub fn MockVerifyingApp(comptime B: type) type {
    return struct {
        const Self = @This();
        pub const Block = B;

        gpa: Allocator,
        propose_result: ?B = null,
        verify_result: bool = true,
        handoff: Handoff(void) = .wait,
        /// Gates the next proposal once; the test owns it.
        proposal_gate: ?*ProposalGate = null,
        reject: ?*const fn (*const B) bool = null,

        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa };
        }

        pub fn with_verify_result(gpa: Allocator, verify_result: bool) Self {
            return .{ .gpa = gpa, .verify_result = verify_result };
        }

        pub fn with_propose_result(self: Self, block: B) Self {
            var app = self;
            app.propose_result = block;
            return app;
        }

        pub fn with_reject(self: Self, reject: *const fn (*const B) bool) Self {
            var app = self;
            app.reject = reject;
            return app;
        }

        pub fn with_handoff(self: Self, handoff: Handoff(void)) Self {
            var app = self;
            app.handoff = handoff;
            return app;
        }

        pub fn with_proposal_gate(self: Self, gate: *ProposalGate) Self {
            var app = self;
            app.proposal_gate = gate;
            return app;
        }

        pub fn prepare(
            self: *Self,
            ctx: anytype,
            context: anytype,
            ancestry: anytype,
        ) !Handoff(broadcast.Digested(B)) {
            if (self.handoff.is_wait()) {
                free_ancestry(ancestry);
                return .wait;
            }
            const block = try self.propose(ctx, context, ancestry) orelse return .wait;
            return switch (self.handoff) {
                .vote => .{ .vote = block },
                .stage => .{ .stage = block },
                .wait => unreachable,
            };
        }

        pub fn propose(
            self: *Self,
            ctx: anytype,
            _: anytype,
            ancestry: anytype,
        ) !?broadcast.Digested(B) {
            free_ancestry(ancestry);
            if (self.proposal_gate) |gate| {
                // Take the gate once: later proposals pass.
                if (gate.started) |started| {
                    var dropped = gate.dropped.?;
                    gate.started = null;
                    gate.dropped = null;
                    // Closes when this proposal is dropped (canceled).
                    defer dropped.deinit();
                    var sender = started;
                    sender.send({}) catch {};
                    try pending(ctx.io());
                }
            }
            const block = self.propose_result orelse return null;
            return try broadcast.Digested(B).compute(self.gpa, block);
        }

        pub fn verify(self: *Self, _: anytype, _: anytype, ancestry: anytype) !bool {
            var stream = ancestry;
            defer stream.deinit();
            if (self.reject) |reject| {
                if (stream.peek()) |block| {
                    if (reject(block.inner())) return false;
                }
            }
            return self.verify_result;
        }
    };
}

/// Shared state of a `GatedVerifyingApp`.
pub const Gated = struct {
    started: ?oneshot.Sender(void),
    release: ?oneshot.Receiver(void),

    /// The state with the receiver that hears verification start and the sender that
    /// releases it.
    pub fn init(gpa: Allocator, io: Io) !struct {
        state: Gated,
        started: oneshot.Receiver(void),
        release: oneshot.Sender(void),
    } {
        var started = try oneshot.channel(void, gpa, io);
        errdefer {
            started.sender.deinit();
            started.receiver.deinit();
        }
        const release = try oneshot.channel(void, gpa, io);
        return .{
            .state = .{ .started = started.sender, .release = release.receiver },
            .started = started.receiver,
            .release = release.sender,
        };
    }

    pub fn deinit(state: *Gated) void {
        if (state.started) |*sender| sender.deinit();
        if (state.release) |*receiver| receiver.deinit();
        state.* = undefined;
    }
};

/// Proposes nothing; its first verification signals `started` and waits for `release`, then
/// verifies (commonware `GatedVerifyingApp`).
pub fn GatedVerifyingApp(comptime B: type) type {
    return struct {
        const Self = @This();
        pub const Block = B;

        state: *Gated,

        pub fn propose(
            _: *Self,
            _: anytype,
            _: anytype,
            ancestry: anytype,
        ) !?broadcast.Digested(B) {
            free_ancestry(ancestry);
            return null;
        }

        pub fn verify(self: *Self, _: anytype, _: anytype, ancestry: anytype) !bool {
            free_ancestry(ancestry);
            if (self.state.started) |started| {
                self.state.started = null;
                var sender = started;
                sender.send({}) catch {};
            }
            // commonware panics when the release receiver is missing.
            var release = self.state.release.?;
            self.state.release = null;
            defer release.deinit();
            _ = release.recv() catch |err| if (err == error.Canceled) return err;
            return true;
        }
    };
}

/// A verification's start or cancellation, by block digest (commonware `Verification`).
pub fn Verification(comptime D: type) type {
    return union(enum) { started: D, cancelled: D };
}

/// The observations of a `RecordingVerifyingApp`, in order. Unlocked: the mocks run on the
/// single-threaded deterministic runtime.
pub fn Observed(comptime D: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        items: std.ArrayList(Verification(D)) = .empty,

        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa };
        }

        pub fn deinit(self: *Self) void {
            self.items.deinit(self.gpa);
            self.* = undefined;
        }

        /// Records a start and reserves room for its cancellation.
        fn start(self: *Self, digest: D) Allocator.Error!void {
            try self.items.ensureUnusedCapacity(self.gpa, 2);
            self.items.appendAssumeCapacity(.{ .started = digest });
        }

        fn cancel(self: *Self, digest: D) void {
            assert(self.items.items.len > 0);
            self.items.appendAssumeCapacity(.{ .cancelled = digest });
        }
    };
}

/// Proposes nothing; each verification records that it started, then waits until it is
/// canceled and records that (commonware `RecordingVerifyingApp`).
pub fn RecordingVerifyingApp(comptime B: type) type {
    return struct {
        const Self = @This();
        pub const Block = B;

        observed: *Observed(B.Digest),

        pub fn propose(
            _: *Self,
            _: anytype,
            _: anytype,
            ancestry: anytype,
        ) !?broadcast.Digested(B) {
            free_ancestry(ancestry);
            return null;
        }

        pub fn verify(self: *Self, ctx: anytype, _: anytype, ancestry: anytype) !bool {
            var stream = ancestry;
            const digest = stream.peek().?.digest();
            stream.deinit();
            try self.observed.start(digest);
            defer self.observed.cancel(digest);
            try pending(ctx.io());
        }
    };
}

test {
    _ = @import("verifying_test.zig");
}
