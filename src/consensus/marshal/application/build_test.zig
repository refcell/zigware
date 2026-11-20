//! Tests for marshal's prepare and propose tasks, on the deterministic runtime's Context.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const cryptography = @import("cryptography");
const types = @import("../../types.zig");
const traits = @import("../../traits.zig");
const simplex_types = @import("../../simplex/types.zig");
const mocks = @import("../mocks/root.zig");
const standard = @import("../standard/root.zig");
const gates = @import("gates.zig");
const build = @import("build.zig");

const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const B = mocks.EmptyBlock(Sha256);
const V = standard.Standard(B);
const Key = cryptography.ed25519.PublicKey;
const Round = types.Round;
const Handoff = traits.Handoff;
const Ctx = runtime.deterministic.Context;
const ConsensusContext = simplex_types.Context(D, Key);
const TestGates = gates.Gates(D, V);
const gpa = testing.allocator;
const Receiver = @import("utils").channel.oneshot.Receiver;
const soak = @import("../mocks/soak.zig");

/// The ancestry handed to the application: only the parent height.
const Ancestry = struct {
    height: u64,

    pub fn deinit(_: *Ancestry) void {}
};
const Resolved = build.Resolved(D, V.Block, Ancestry, void);

const parent_digest = D.fill(3);
const round: Round = .new(.zero(), .new(5));

fn consensus_context() ConsensusContext {
    const leader = cryptography.ed25519.PrivateKey.from_seed(1).public_key();
    return .{ .round = round, .leader = leader, .parent = .{ .new(4), parent_digest } };
}

/// The block the test application builds on `height`.
fn built(height: u64) B {
    return B.init(parent_digest, .new(height + 1), 7);
}

const TestApp = struct {
    calls: *u32,
    answer: enum { vote, stage, wait } = .vote,

    pub fn propose(self: *TestApp, _: Ctx, _: ConsensusContext, ancestry: Ancestry) !?V.Block {
        self.calls.* += 1;
        return try mocks.ready(B, gpa, built(ancestry.height));
    }

    pub fn prepare(
        self: *TestApp,
        _: Ctx,
        _: ConsensusContext,
        ancestry: Ancestry,
    ) !Handoff(V.Block) {
        self.calls.* += 1;
        if (self.answer == .wait) return .wait;
        const block = try mocks.ready(B, gpa, built(ancestry.height));
        return if (self.answer == .vote) .{ .vote = block } else .{ .stage = block };
    }
};

/// Resolves to `resolved`, or waits an hour first when `wait` is set. `ended` records that
/// the call returned (also when canceled).
const Checks = struct {
    resolved: Resolved,
    wait: ?Io = null,
    ended: ?*bool = null,

    pub fn call(self: Checks) !Resolved {
        defer if (self.ended) |ended| {
            ended.* = true;
        };
        if (self.wait) |io| try io.sleep(.fromSeconds(3600), .awake);
        return self.resolved;
    }

    pub fn release(_: Checks, result: anytype) void {
        const resolved = result catch return;
        if (resolved == .reuse) {
            var block = resolved.reuse.block;
            block.deinit();
        }
    }
};

const Seal = struct {
    pub fn call(_: Seal, block: V.Block, _: void) !struct { D, V.Block } {
        return .{ block.digest(), block };
    }
};

/// Builds on `height`; blocks built on different heights stage under different keys.
fn build_at(height: u64) Checks {
    return .{ .resolved = .{ .build = .{ .ancestry = .{ .height = height }, .metadata = {} } } };
}

const build_checks = build_at(4);

/// Takes the proposal staged under `digest` and acknowledges it as persisted.
fn persist(registry: TestGates, digest: D) !void {
    const staged, const sent = (try registry.take_staged(round, digest)).?;
    try testing.expect(!sent);
    var block = staged.block;
    defer block.deinit();
    try testing.expect(block.digest().eql(digest));
    var ack = staged.ack;
    try ack.send({});
}

fn propose(ctx: Ctx, registry: TestGates, app: TestApp, checks: Checks) !Receiver(D) {
    return build.propose(D, ctx, app, registry, consensus_context(), checks, Seal{}, null);
}

fn prepare(ctx: Ctx, registry: TestGates, app: TestApp, checks: Checks) !Receiver(Handoff(D)) {
    return build.prepare(D, ctx, app, registry, consensus_context(), checks, Seal{}, null);
}

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    try soak.run(gpa, .{}, body, .{});
}

test "propose stages the built block before publishing its digest" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var registry: TestGates = try .init(gpa, ctx.io());
            defer registry.deinit();
            var calls: u32 = 0;
            const app: TestApp = .{ .calls = &calls };
            var receiver = try propose(ctx, registry, app, build_checks);
            defer receiver.deinit();
            const digest = try receiver.recv();
            try testing.expect(digest.eql(built(4).digest()));
            try persist(registry, digest);
            try testing.expectEqual(1, calls);
        }
    }.body);
}

test "propose closes the receiver on a parent it cannot build on" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var registry: TestGates = try .init(gpa, ctx.io());
            defer registry.deinit();
            var calls: u32 = 0;
            const checks: Checks = .{ .resolved = .skip };
            const app: TestApp = .{ .calls = &calls };
            var receiver = try propose(ctx, registry, app, checks);
            defer receiver.deinit();
            try testing.expectError(error.Closed, receiver.recv());
            try testing.expectEqual(0, calls);
        }
    }.body);
}

test "propose and prepare re-propose the boundary block without the application" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var registry: TestGates = try .init(gpa, ctx.io());
            defer registry.deinit();
            var calls: u32 = 0;
            const app: TestApp = .{ .calls = &calls };
            const boundary = B.init(parent_digest, .new(9), 1);

            var block = try mocks.ready(B, gpa, boundary);
            var checks: Checks = .{ .resolved = .{ .reuse = .{
                .digest = boundary.digest(),
                .block = block,
            } } };
            var proposed = try propose(ctx, registry, app, checks);
            defer proposed.deinit();
            try testing.expect((try proposed.recv()).eql(boundary.digest()));
            try persist(registry, boundary.digest());

            // A take marks its key sent, so the prepare uses another boundary candidate.
            const other = B.init(parent_digest, .new(9), 2);
            block = try mocks.ready(B, gpa, other);
            checks = .{ .resolved = .{ .reuse = .{
                .digest = other.digest(),
                .block = block,
            } } };
            var prepared = try prepare(ctx, registry, app, checks);
            defer prepared.deinit();
            const answer = try prepared.recv();
            try testing.expect(answer.stage.eql(other.digest()));
            try persist(registry, other.digest());
            try testing.expectEqual(0, calls);
        }
    }.body);
}

fn expect_prepare(ctx: Ctx, registry: TestGates, app: TestApp, checks: Checks) !Handoff(D) {
    var receiver = try prepare(ctx, registry, app, checks);
    defer receiver.deinit();
    const answer = try receiver.recv();
    switch (answer) {
        .vote, .stage => |digest| try persist(registry, digest),
        .wait => {},
    }
    return answer;
}

test "prepare answers under the application's decision" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var registry: TestGates = try .init(gpa, ctx.io());
            defer registry.deinit();
            var calls: u32 = 0;
            const vote = try expect_prepare(ctx, registry, .{ .calls = &calls }, build_at(4));
            try testing.expect(vote.vote.eql(built(4).digest()));
            const stage_app: TestApp = .{ .calls = &calls, .answer = .stage };
            const stage = try expect_prepare(ctx, registry, stage_app, build_at(5));
            try testing.expect(stage.stage.eql(built(5).digest()));
            const wait_app: TestApp = .{ .calls = &calls, .answer = .wait };
            const wait = try expect_prepare(ctx, registry, wait_app, build_at(6));
            try testing.expect(wait == .wait);
            try testing.expectEqual(3, calls);
            // A parent marshal cannot build on answers wait without the application.
            const skip: Checks = .{ .resolved = .skip };
            try testing.expect((try expect_prepare(ctx, registry, wait_app, skip)) == .wait);
            try testing.expectEqual(3, calls);
        }
    }.body);
}

test "dropping the receiver cancels the wait for the parent" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var registry: TestGates = try .init(gpa, ctx.io());
            defer registry.deinit();
            var calls: u32 = 0;
            var ended = false;
            const checks: Checks = .{ .resolved = .skip, .wait = ctx.io(), .ended = &ended };
            const app: TestApp = .{ .calls = &calls };
            var receiver = try propose(ctx, registry, app, checks);
            try ctx.sleep(.fromMilliseconds(10));
            try testing.expect(!ended);
            receiver.deinit();
            try ctx.sleep(.fromMilliseconds(10));
            try testing.expect(ended);
            try testing.expectEqual(0, calls);
        }
    }.body);
}
