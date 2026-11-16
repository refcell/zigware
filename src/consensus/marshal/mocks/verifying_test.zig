//! Tests for the verifying mock applications.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const cryptography = @import("cryptography");
const ancestry = @import("../ancestry.zig");
const block_mod = @import("block.zig");
const verifying = @import("verifying.zig");

const Sha256 = cryptography.Sha256;
const B = block_mod.EmptyBlock(Sha256);
const Ctx = runtime.deterministic.Context;
const Digested = @import("broadcast").Digested(B);
const Ancestry = ancestry.Bounded(B);
const Mock = verifying.MockVerifyingApp(B, Ctx, void, Ancestry);
const gpa = testing.allocator;

fn block_at(height: u64) B {
    return B.init(Sha256.Digest.empty, .new(height), height);
}

/// A one-block ancestry starting at `height`.
fn ancestry_at(height: u64) !ancestry.Bounded(B) {
    const blocks = [_]Digested{try block_mod.ready(B, gpa, block_at(height))};
    return ancestry.from_iter(B, gpa, &blocks);
}

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

fn rejects_odd(block: *const B) bool {
    return block.height().get() % 2 == 1;
}

fn mock_verify(ctx: Ctx) !void {
    var app = Mock.init(gpa).with_reject(&rejects_odd);
    try testing.expect(try app.verify(ctx, {}, try ancestry_at(2)));
    try testing.expect(!try app.verify(ctx, {}, try ancestry_at(3)));
    var failing = Mock.with_verify_result(gpa, false);
    try testing.expect(!try failing.verify(ctx, {}, try ancestry_at(2)));
}

test "the mock app verifies with its result unless it rejects the block" {
    try run(mock_verify);
}

fn mock_propose(ctx: Ctx) !void {
    var empty = Mock.init(gpa);
    try testing.expectEqual(null, try empty.propose(ctx, {}, try ancestry_at(1)));
    try testing.expect((try empty.prepare(ctx, {}, try ancestry_at(1))).is_wait());
    const built = block_at(5);
    var app = Mock.init(gpa).with_propose_result(built);
    var proposed = (try app.propose(ctx, {}, try ancestry_at(4))).?;
    defer proposed.deinit();
    try testing.expect(proposed.digest().eql(built.digest()));
    // A wait handoff declines prepare; stage hands over the proposal.
    try testing.expect((try app.prepare(ctx, {}, try ancestry_at(4))).is_wait());
    var staging = app.with_handoff(.{ .stage = {} });
    const handoff = try staging.prepare(ctx, {}, try ancestry_at(4));
    var staged = handoff.stage;
    defer staged.deinit();
    try testing.expect(staged.digest().eql(built.digest()));
}

test "the mock app proposes its block and hands it off as configured" {
    try run(mock_propose);
}

const Proposer = Mock;

fn propose_task(app: *Proposer, ctx: Ctx) anyerror!?Digested {
    return app.propose(ctx, {}, try ancestry_at(1));
}

fn gated_proposal(ctx: Ctx) !void {
    const io = ctx.io();
    var gated = try verifying.ProposalGate.init(gpa, io);
    defer gated.gate.deinit();
    defer gated.started.deinit();
    defer gated.dropped.deinit();
    var app = Proposer.init(gpa).with_propose_result(block_at(2)).with_proposal_gate(&gated.gate);
    var task = try io.concurrent(propose_task, .{ &app, ctx });
    try gated.started.recv();
    try testing.expectError(error.Canceled, task.cancel(io));
    // Dropping the proposal closes `dropped`; the next proposal passes the spent gate.
    try testing.expectError(error.Closed, gated.dropped.recv());
    var next = (try app.propose(ctx, {}, try ancestry_at(1))).?;
    next.deinit();
}

test "a proposal gate signals the start and the drop of one proposal" {
    try run(gated_proposal);
}

const GatedApp = verifying.GatedVerifyingApp(B, Ctx, void, Ancestry);

fn verify_task(app: *GatedApp, ctx: Ctx) anyerror!bool {
    return app.verify(ctx, {}, try ancestry_at(1));
}

fn gated_verify(ctx: Ctx) !void {
    const io = ctx.io();
    var gated = try verifying.Gated.init(gpa, io);
    defer gated.state.deinit();
    defer gated.started.deinit();
    var app: GatedApp = .{ .state = &gated.state };
    try testing.expectEqual(null, try app.propose(ctx, {}, try ancestry_at(1)));
    var task = try io.concurrent(verify_task, .{ &app, ctx });
    try gated.started.recv();
    try gated.release.send({});
    try testing.expect(try task.await(io));
}

test "the gated app holds its first verification until released" {
    try run(gated_verify);
}

const Recorder = verifying.RecordingVerifyingApp(B, Ctx, void, Ancestry);

fn record_task(app: *Recorder, ctx: Ctx, height: u64) anyerror!bool {
    return app.verify(ctx, {}, try ancestry_at(height));
}

fn recording(ctx: Ctx) !void {
    const io = ctx.io();
    var observed = verifying.Observed(Sha256.Digest).init(gpa);
    defer observed.deinit();
    var app: Recorder = .{ .observed = &observed };
    var first = try io.concurrent(record_task, .{ &app, ctx, 1 });
    try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expectError(error.Canceled, first.cancel(io));
    var second = try io.concurrent(record_task, .{ &app, ctx, 2 });
    try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expectError(error.Canceled, second.cancel(io));
    const one = block_at(1).digest();
    const two = block_at(2).digest();
    const V = verifying.Verification(Sha256.Digest);
    const expected = [_]V{
        .{ .started = one },
        .{ .cancelled = one },
        .{ .started = two },
        .{ .cancelled = two },
    };
    try testing.expectEqual(expected.len, observed.items.items.len);
    for (expected, observed.items.items) |want, got| {
        try testing.expectEqual(std.meta.activeTag(want), std.meta.activeTag(got));
        const want_digest = switch (want) {
            inline else => |digest| digest,
        };
        const got_digest = switch (got) {
            inline else => |digest| digest,
        };
        try testing.expect(want_digest.eql(got_digest));
    }
}

test "the recording app logs each verification's start and cancellation" {
    try run(recording);
}
