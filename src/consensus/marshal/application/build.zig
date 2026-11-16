//! The prepare and propose tasks shared by marshal's application wrappers (commonware
//! `marshal/application/build.rs`).
//!
//! Each task runs the wrapper's proposal checks, then re-proposes the epoch boundary block,
//! declines a parent marshal cannot build on, or builds on the fetched ancestry through the
//! application. A built block is sealed into its staged form and staged in the gates before
//! consensus hears of its digest, so the relay broadcast and certification always find it. A
//! prepare answers a `Handoff` and declines with `wait`; a propose answers the digest and
//! declines by closing the receiver. Dropping the receiver cancels the wait for the parent and
//! the build.
//!
//! The tasks are spawned detached from a runtime context `ctx` (`child`, `spawn`, `io`). They
//! take:
//! - `application`: `propose(*A, ctx, consensus_context, ancestry) !?Digested(A.Block)` and,
//!   optionally, `prepare(*A, ctx, consensus_context, ancestry) !Handoff(Digested(A.Block))`
//!   (without it a prepare declines). The application owns `ancestry`, must free it, and must
//!   be cancelable. It is cloned (`clone`/`deinit`) into the task when it declares them.
//! - `checks`: `call(self) !Resolved(D, S, N, M)` and `release(self, result)`, which frees a
//!   result produced after the receiver closed.
//! - `seal`: `call(self, Digested(A.Block), M) !struct { D, S }`, the staged form and digest.
//! - `registry`: the `gates.Gates(D, V)` that stage `S = V.Block` (cloned into the task).
//!
//! Commonware starts the build timer inside the checks; here `build_duration` is started once
//! the checks resolve, so a timer never crosses a task boundary.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const traits = @import("../../traits.zig");

const oneshot = utils.channel.oneshot;
const Timed = runtime.telemetry.metrics.histogram.Timed;
const Handoff = traits.Handoff;

/// The outcome of the marshal's proposal checks for a parent.
pub fn Resolved(comptime D: type, comptime S: type, comptime N: type, comptime M: type) type {
    return union(enum) {
        /// Re-propose the epoch boundary block `block` (staged form) with digest `digest`.
        reuse: struct { digest: D, block: S },
        /// Marshal cannot build on this parent.
        skip,
        /// The parent is fetched; the application builds on `ancestry`. `metadata` (the
        /// coding configuration, or void) is passed to the seal with the built block.
        build: struct { ancestry: N, metadata: M },
    };
}

fn Return(comptime function: anytype) type {
    return @typeInfo(@TypeOf(function)).@"fn".return_type.?;
}

/// Runs `function(args...)` while `output` still has a receiver. Returns null once the
/// receiver closes first: the call is canceled, and a result it already produced goes to
/// `releaser.release`.
fn unless_closed(
    comptime T: type,
    io: Io,
    output: *const oneshot.Sender(T),
    comptime function: anytype,
    args: anytype,
    releaser: anytype,
) Io.Cancelable!?Return(function) {
    const Outcome = union(enum) { closed: Io.Cancelable!void, done: Return(function) };
    var buffer: [2]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);
    select.concurrent(.closed, oneshot.Sender(T).closed, .{output.*}) catch {
        return error.Canceled;
    };
    // A runtime context and an ancestor stream outgrow a task closure (1 KiB on the
    // deterministic runtime), so the task reads `args` through one pointer; every path below
    // drains the select before this frame returns.
    const Call = struct {
        fn run(call_args: *const @TypeOf(args)) Return(function) {
            return @call(.auto, function, call_args.*);
        }
    };
    select.concurrent(.done, Call.run, .{&args}) catch {
        select.cancelDiscard();
        return error.Canceled;
    };
    const first = select.await() catch |err| {
        while (select.cancel()) |rest| if (rest == .done) releaser.release(rest.done);
        return err;
    };
    while (select.cancel()) |rest| if (rest == .done) releaser.release(rest.done);
    return switch (first) {
        .closed => null,
        .done => |result| result,
    };
}

/// Frees an application build nobody will use.
const BuildReleaser = struct {
    pub fn release(_: BuildReleaser, result: anytype) void {
        const built = result catch return;
        switch (@typeInfo(@TypeOf(built))) {
            .optional => if (built) |block| {
                var owned = block;
                owned.deinit();
            },
            else => switch (built) {
                .vote, .stage => |block| {
                    var owned = block;
                    owned.deinit();
                },
                .wait => {},
            },
        }
    }
};

/// Answers a propose request with the staged digest, at most once.
fn DigestPublisher(comptime D: type) type {
    return struct {
        const Self = @This();
        sender: ?oneshot.Sender(D),

        pub fn call(self: *Self, digest: D) void {
            if (self.sender) |*sender| sender.send(digest) catch {};
            self.sender = null;
        }

        fn deinit(self: *Self) void {
            if (self.sender) |*sender| sender.deinit();
            self.sender = null;
        }
    };
}

/// Answers a prepare request with the staged digest under `decision`, at most once.
fn HandoffPublisher(comptime D: type) type {
    return struct {
        const Self = @This();
        sender: ?oneshot.Sender(Handoff(D)),
        decision: enum { vote, stage } = .stage,

        pub fn call(self: *Self, digest: D) void {
            const value: Handoff(D) = switch (self.decision) {
                .vote => .{ .vote = digest },
                .stage => .{ .stage = digest },
            };
            self.answer(value);
        }

        fn answer(self: *Self, value: Handoff(D)) void {
            if (self.sender) |*sender| sender.send(value) catch {};
            self.sender = null;
        }

        fn deinit(self: *Self) void {
            if (self.sender) |*sender| sender.deinit();
            self.sender = null;
        }
    };
}

fn clone_application(application: anytype) @TypeOf(application) {
    const A = @TypeOf(application);
    if (comptime @typeInfo(A) == .@"struct" and @hasDecl(A, "clone")) return application.clone();
    return application;
}

fn deinit_application(application: anytype) void {
    const A = @typeInfo(@TypeOf(application)).pointer.child;
    if (comptime @typeInfo(A) == .@"struct" and @hasDecl(A, "deinit")) application.deinit();
}

/// Everything a build task owns.
fn Job(
    comptime A: type,
    comptime G: type,
    comptime C: type,
    comptime K: type,
    comptime L: type,
) type {
    return struct {
        application: A,
        registry: G,
        consensus_context: C,
        checks: K,
        seal: L,
        build_duration: ?*const Timed,

        fn deinit(self: *@This()) void {
            deinit_application(&self.application);
            self.registry.deinit();
        }
    };
}

/// Answers a propose request for `consensus_context` from a task spawned from `ctx`. A parent
/// marshal cannot build on, or a build that yields no block, closes the receiver.
pub fn propose(
    comptime D: type,
    ctx: anytype,
    application: anytype,
    registry: anytype,
    consensus_context: anytype,
    checks: anytype,
    seal: anytype,
    build_duration: ?*const Timed,
) !oneshot.Receiver(D) {
    const job: Job(
        @TypeOf(application),
        @TypeOf(registry),
        @TypeOf(consensus_context),
        @TypeOf(checks),
        @TypeOf(seal),
    ) = .{
        .application = clone_application(application),
        .registry = registry.clone(),
        .consensus_context = consensus_context,
        .checks = checks,
        .seal = seal,
        .build_duration = build_duration,
    };
    return spawn(D, ctx.child("propose"), Tasks(D).propose, job);
}

/// Answers a prepare request for `consensus_context` from a task spawned from `ctx`. The
/// boundary block is answered `stage`; a parent marshal cannot build on answers `wait`.
pub fn prepare(
    comptime D: type,
    ctx: anytype,
    application: anytype,
    registry: anytype,
    consensus_context: anytype,
    checks: anytype,
    seal: anytype,
    build_duration: ?*const Timed,
) !oneshot.Receiver(Handoff(D)) {
    const job: Job(
        @TypeOf(application),
        @TypeOf(registry),
        @TypeOf(consensus_context),
        @TypeOf(checks),
        @TypeOf(seal),
    ) = .{
        .application = clone_application(application),
        .registry = registry.clone(),
        .consensus_context = consensus_context,
        .checks = checks,
        .seal = seal,
        .build_duration = build_duration,
    };
    return spawn(Handoff(D), ctx.child("prepare"), Tasks(D).prepare, job);
}

/// Spawns `task(task_ctx, job, sender)` detached; on failure, or from an aborted context, the
/// job is released and the receiver reads closed.
fn spawn(
    comptime T: type,
    ctx: anytype,
    comptime task: anytype,
    job: anytype,
) !oneshot.Receiver(T) {
    var owned = job;
    const gpa = ctx.gpa();
    var pair = oneshot.channel(T, gpa, ctx.io()) catch |err| {
        owned.deinit();
        return err;
    };
    const handle = ctx.spawn(task, .{ owned, pair.sender }) catch |err| {
        owned.deinit();
        pair.sender.deinit();
        pair.receiver.deinit();
        return err;
    };
    if (handle.header == null) {
        // The context was aborted: the task never ran.
        owned.deinit();
        pair.sender.deinit();
        return pair.receiver;
    }
    handle.detach();
    return pair.receiver;
}

/// The task entry points for digests `D`.
fn Tasks(comptime D: type) type {
    return struct {
        fn propose(ctx: anytype, job: anytype, sender: oneshot.Sender(D)) void {
            propose_task(D, ctx, job, sender);
        }

        fn prepare(ctx: anytype, job: anytype, sender: oneshot.Sender(Handoff(D))) void {
            prepare_task(D, ctx, job, sender);
        }
    };
}

fn propose_task(comptime D: type, ctx: anytype, job: anytype, sender: oneshot.Sender(D)) void {
    var owned = job;
    defer owned.deinit();
    var publisher: DigestPublisher(D) = .{ .sender = sender };
    defer publisher.deinit();
    const io = ctx.io();
    const round = owned.consensus_context.round;
    const Checks = @TypeOf(owned.checks);
    const checks = owned.checks;
    const checked = unless_closed(D, io, &publisher.sender.?, Checks.call, .{checks}, checks);
    const resolved = ((checked catch return) orelse return) catch return;
    switch (resolved) {
        .reuse => |reuse| {
            const digest = reuse.digest;
            owned.registry.stage(round, digest, reuse.block, &publisher, "boundary") catch {};
        },
        // Closing the receiver skips the view, which the voter nullifies by timeout.
        .skip => {},
        .build => |build| {
            const timer = if (owned.build_duration) |timed| timed.timer(io) else null;
            const App = @TypeOf(owned.application);
            const app_ctx = ctx.child("app_propose");
            const args = .{ &owned.application, app_ctx, owned.consensus_context, build.ancestry };
            const output = &publisher.sender.?;
            const built = unless_closed(D, io, output, App.propose, args, BuildReleaser{});
            const block = (((built catch return) orelse return) catch return) orelse return;
            if (timer) |started| started.observe(io);
            const digest, const staged = owned.seal.call(block, build.metadata) catch return;
            owned.registry.stage(round, digest, staged, &publisher, "proposed block") catch {};
        },
    }
}

fn prepare_task(
    comptime D: type,
    ctx: anytype,
    job: anytype,
    sender: oneshot.Sender(Handoff(D)),
) void {
    var owned = job;
    defer owned.deinit();
    var publisher: HandoffPublisher(D) = .{ .sender = sender };
    defer publisher.deinit();
    const io = ctx.io();
    const round = owned.consensus_context.round;
    const Checks = @TypeOf(owned.checks);
    const T = Handoff(D);
    const checks = owned.checks;
    const checked = unless_closed(T, io, &publisher.sender.?, Checks.call, .{checks}, checks);
    const resolved = ((checked catch return) orelse return) catch return;
    const build = switch (resolved) {
        // The boundary block carries no application decision: withhold the vote until the
        // parent certifies.
        .reuse => |reuse| {
            const digest = reuse.digest;
            owned.registry.stage(round, digest, reuse.block, &publisher, "boundary") catch {};
            return;
        },
        .skip => return publisher.answer(.wait),
        .build => |build| build,
    };
    const App = @TypeOf(owned.application);
    if (comptime !@hasDecl(App, "prepare")) {
        var ancestry = build.ancestry;
        ancestry.deinit();
        return publisher.answer(.wait);
    }
    const timer = if (owned.build_duration) |timed| timed.timer(io) else null;
    const app_ctx = ctx.child("app_prepare");
    const args = .{ &owned.application, app_ctx, owned.consensus_context, build.ancestry };
    const output = &publisher.sender.?;
    const prepared = unless_closed(T, io, output, App.prepare, args, BuildReleaser{});
    const handoff = ((prepared catch return) orelse return) catch return;
    const block = switch (handoff) {
        .vote => |block| block,
        .stage => |block| block,
        .wait => return publisher.answer(.wait),
    };
    publisher.decision = if (handoff == .vote) .vote else .stage;
    // Only a build that yields a block is timed.
    if (timer) |started| started.observe(io);
    const digest, const staged = owned.seal.call(block, build.metadata) catch return;
    owned.registry.stage(round, digest, staged, &publisher, "prepared block") catch {};
}

test {
    _ = @import("build_test.zig");
}
