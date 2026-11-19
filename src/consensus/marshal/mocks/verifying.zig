//! Mock applications for marshal's verification tests (commonware
//! `marshal/mocks/verifying.rs`).
//!
//! Each follows `application.build`'s contract: `propose(*A, ctx, consensus_context,
//! ancestry) !?Digested(Block)`, optionally `prepare(...)`, and `verify(*A, ctx,
//! consensus_context, ancestry) !bool`. The build tasks run these methods as `std.Io` tasks,
//! which need concrete parameter types, so each mock takes the runtime context `Ctx`, the
//! consensus context `Context`, and the `Ancestry` type it is handed (commonware's methods are
//! generic over the ancestry instead). They own the ancestry they are given and free it. Like
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

/// A `MockVerifyingApp` proposal: hold at its gate, then its configured block, if any.
fn propose_mock(
    app: anytype,
    io: Io,
    ancestry: anytype,
) !?broadcast.Digested(@TypeOf(app.*).Block) {
    const Block = @TypeOf(app.*).Block;
    free_ancestry(ancestry);
    if (app.proposal_gate) |gate| try gate.hold(io);
    const block = app.propose_result orelse return null;
    return try broadcast.Digested(Block).compute(app.gpa, block);
}

/// A `MockVerifyingApp` verdict: its result, unless `reject` rejects the first block.
fn verify_mock(app: anytype, ancestry: anytype) bool {
    var stream = ancestry;
    defer stream.deinit();
    const reject = app.reject orelse return app.verify_result;
    const block = stream.peek() orelse return app.verify_result;
    return !reject(block.inner()) and app.verify_result;
}

/// `block` handed off under `decision` (vote or stage).
fn handoff_of(decision: Handoff(void), block: anytype) Handoff(@TypeOf(block)) {
    return switch (decision) {
        .vote => .{ .vote = block },
        .stage => .{ .stage = block },
        .wait => unreachable,
    };
}

/// `app` with field `name` set to `value`.
fn with(app: anytype, comptime name: []const u8, value: anytype) @TypeOf(app) {
    var result = app;
    @field(result, name) = value;
    return result;
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

    /// Holds the first proposal that reaches the gate until it is canceled; later ones pass.
    fn hold(gate: *ProposalGate, io: Io) Io.Cancelable!void {
        const started = gate.started orelse return;
        var dropped = gate.dropped.?;
        gate.started = null;
        gate.dropped = null;
        // Closes when this proposal is dropped (canceled).
        defer dropped.deinit();
        var sender = started;
        sender.send({}) catch {};
        try pending(io);
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
pub fn MockVerifyingApp(
    comptime B: type,
    comptime Ctx: type,
    comptime Context: type,
    comptime Ancestry: type,
) type {
    return MockVerifyingAppOver(.{ B, Ctx, Context, Ancestry });
}

fn MockVerifyingAppOver(comptime T: [4]type) type {
    const B = T[0];
    const Ctx = T[1];
    const Context = T[2];
    const Ancestry = T[3];
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
            return with(init(gpa), "verify_result", verify_result);
        }

        pub fn with_propose_result(self: Self, block: B) Self {
            return with(self, "propose_result", block);
        }

        pub fn with_reject(self: Self, reject: *const fn (*const B) bool) Self {
            return with(self, "reject", reject);
        }

        pub fn with_handoff(self: Self, handoff: Handoff(void)) Self {
            return with(self, "handoff", handoff);
        }

        pub fn with_proposal_gate(self: Self, gate: *ProposalGate) Self {
            return with(self, "proposal_gate", gate);
        }

        pub fn prepare(
            self: *Self,
            ctx: Ctx,
            context: Context,
            ancestry: Ancestry,
        ) anyerror!Handoff(broadcast.Digested(B)) {
            if (self.handoff.is_wait()) {
                free_ancestry(ancestry);
                return .wait;
            }
            const block = try self.propose(ctx, context, ancestry) orelse return .wait;
            return handoff_of(self.handoff, block);
        }

        pub fn propose(
            self: *Self,
            ctx: Ctx,
            _: Context,
            ancestry: Ancestry,
        ) anyerror!?broadcast.Digested(B) {
            return propose_mock(self, ctx.io(), ancestry);
        }

        pub fn verify(
            self: *Self,
            _: Ctx,
            _: Context,
            ancestry: Ancestry,
        ) anyerror!bool {
            return verify_mock(self, ancestry);
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
pub fn GatedVerifyingApp(
    comptime B: type,
    comptime Ctx: type,
    comptime Context: type,
    comptime Ancestry: type,
) type {
    return GatedVerifyingAppOver(.{ B, Ctx, Context, Ancestry });
}

fn GatedVerifyingAppOver(comptime T: [4]type) type {
    const B = T[0];
    const Ctx = T[1];
    const Context = T[2];
    const Ancestry = T[3];
    return struct {
        const Self = @This();
        pub const Block = B;

        state: *Gated,

        pub fn propose(
            _: *Self,
            _: Ctx,
            _: Context,
            ancestry: Ancestry,
        ) anyerror!?broadcast.Digested(B) {
            free_ancestry(ancestry);
            return null;
        }

        pub fn verify(
            self: *Self,
            _: Ctx,
            _: Context,
            ancestry: Ancestry,
        ) anyerror!bool {
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
pub fn RecordingVerifyingApp(
    comptime B: type,
    comptime Ctx: type,
    comptime Context: type,
    comptime Ancestry: type,
) type {
    return RecordingVerifyingAppOver(.{ B, Ctx, Context, Ancestry });
}

fn RecordingVerifyingAppOver(comptime T: [4]type) type {
    const B = T[0];
    const Ctx = T[1];
    const Context = T[2];
    const Ancestry = T[3];
    return struct {
        const Self = @This();
        pub const Block = B;

        observed: *Observed(B.Digest),

        pub fn propose(
            _: *Self,
            _: Ctx,
            _: Context,
            ancestry: Ancestry,
        ) anyerror!?broadcast.Digested(B) {
            free_ancestry(ancestry);
            return null;
        }

        pub fn verify(
            self: *Self,
            ctx: Ctx,
            _: Context,
            ancestry: Ancestry,
        ) anyerror!bool {
            var stream = ancestry;
            const digest = stream.peek().?.digest();
            stream.deinit();
            try self.observed.start(digest);
            defer self.observed.cancel(digest);
            try pending(ctx.io());
        }
    };
}

/// Reads the ancestry it is given block by block, recording each digest, and accepts a block
/// only if that ancestry reaches the height-zero block; it never builds one (commonware
/// `WalkingVerifyingApp`). Copies share the caller-owned log.
pub fn WalkingVerifyingApp(
    comptime B: type,
    comptime Ctx: type,
    comptime Context: type,
    comptime Ancestry: type,
) type {
    return struct {
        const Self = @This();
        pub const Block = B;

        gpa: Allocator,
        /// The digests read, in order.
        blocks: *std.ArrayList(B.Digest),

        /// Reads `ancestry` (taken) to its end; whether it reached the height-zero block.
        fn walk(self: *Self, ancestry: Ancestry) !bool {
            var stream = ancestry;
            defer stream.deinit();
            while (try stream.next()) |value| {
                var block = value;
                defer block.deinit();
                try self.blocks.append(self.gpa, block.digest());
                if (block.inner().height().get() == 0) return true;
            }
            return false;
        }

        pub fn propose(
            self: *Self,
            _: Ctx,
            _: Context,
            ancestry: Ancestry,
        ) anyerror!?broadcast.Digested(B) {
            _ = try self.walk(ancestry);
            return null;
        }

        pub fn verify(self: *Self, _: Ctx, _: Context, ancestry: Ancestry) anyerror!bool {
            return self.walk(ancestry);
        }
    };
}

test {
    _ = @import("verifying_test.zig");
}
