//! The standard actor's cache writes, notarized decode, finalization sync, staged dispatch,
//! relay sends, forward, and hint_finalized (commonware `standard/mod.rs`, lines
//! 10612-12604).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const cryptography = @import("cryptography");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks_block = @import("../../mocks/block.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;
const B = harness.B;
const oneshot = utils.channel.oneshot;
const Started = common.Started(harness.Provider, App, common.RecordingBuffer);

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

/// A fixture and a buffered actor started at genesis (commonware `start_standard_actor` with
/// a `RecordingBuffer` and a manually acknowledging application).
const Env = struct {
    fixture: harness.Fixture,
    started: Started,

    fn init(self: *Env, ctx: Ctx, comptime label: []const u8) !void {
        var rng = utils.rng.test_rng();
        self.fixture = try harness.fixture(gpa, &rng);
        errdefer self.fixture.deinit(gpa);
        var name: [128]u8 = undefined;
        const me = self.fixture.participants[0];
        const prefix = try std.fmt.bufPrint(&name, label ++ "-{f}", .{me});
        self.started = try common.start_standard_actor(
            harness.Provider,
            App,
            common.RecordingBuffer,
            ctx.child("validator").with_attribute("index", 0),
            prefix,
            .init(&self.fixture.schemes[0]),
            try App.manual_ack(gpa, ctx.io()),
            try common.RecordingBuffer.init(gpa, ctx.io()),
            .{ .genesis = try H.genesis_block(gpa, harness.num_validators) },
        );
    }

    fn deinit(self: *Env) void {
        self.started.crash();
        self.fixture.deinit(gpa);
    }

    fn buffer(self: *const Env) common.RecordingBuffer {
        return self.started.buffer.?;
    }

    fn finalize(
        self: *const Env,
        round: Round,
        parent_view: u64,
        block: anytype,
    ) !harness.Finalization {
        const proposal = harness.Proposal.init(round, .new(parent_view), block.digest());
        return harness.make_finalization(gpa, &self.fixture, proposal, harness.quorum);
    }
};

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// Block 1 over genesis's parent, stamped `timestamp`.
fn block_one(timestamp: u64) !B {
    return harness.make_raw_block(gpa, harness.genesis_parent(), .new(1), timestamp);
}

fn ready(block: B) !common.Block {
    return mocks_block.ready(B, gpa, block);
}

fn send_count_nonzero(buffer: common.RecordingBuffer) bool {
    return buffer.send_count() > 0;
}

fn targeted_nonempty(resolver: common.RecordingResolver) bool {
    return !resolver.targeted_is_empty();
}

fn proposed_conflicting_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "proposed-conflict");
    defer env.deinit();
    const round = round_at(1);
    const block_a = try block_one(100);
    const block_b = try block_one(200);
    try testing.expect(!block_a.digest().eql(block_b.digest()));
    const mailbox = &env.started.mailbox;
    var persist_a = try oneshot.channel(void, gpa, ctx.io());
    defer persist_a.receiver.deinit();
    _ = try mailbox.proposed(round, try ready(block_a), .all, persist_a.sender);
    var persist_b = try oneshot.channel(void, gpa, ctx.io());
    defer persist_b.receiver.deinit();
    _ = try mailbox.proposed(round, try ready(block_b), .all, persist_b.sender);
    // Each ack arrives once its proposal is durable.
    try persist_a.receiver.recv();
    try persist_b.receiver.recv();
    const sends = try env.buffer().sends(gpa);
    defer common.RecordingBuffer.free_sends(gpa, sends);
    // Both conflicting proposals dispatch.
    try testing.expectEqual(2, sends.len);
    try testing.expect(sends[0].block.digest().eql(block_a.digest()));
    try testing.expect(sends[1].block.digest().eql(block_b.digest()));
}

test "standard proposed conflicting blocks both ack" {
    try run(proposed_conflicting_body);
}

fn forward_cached_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "forward-cached");
    defer env.deinit();
    const round = round_at(1);
    const block = try block_one(100);
    const digest = block.digest();
    const mailbox = &env.started.mailbox;
    try testing.expect(try mailbox.verified(round, try ready(block)));
    // A cached block forwards to exactly the given peers.
    const targets = env.fixture.participants[1..3];
    _ = try mailbox.forward(round, digest, .{ .some = try gpa.dupe(harness.K, targets) });
    try common.wait_until(ctx, 5000, "buffer.send", env.buffer(), send_count_nonzero);
    const sends = try env.buffer().sends(gpa);
    defer common.RecordingBuffer.free_sends(gpa, sends);
    try testing.expectEqual(1, sends.len);
    try testing.expect(std.meta.eql(sends[0].round, round));
    try testing.expect(sends[0].block.digest().eql(digest));
    try testing.expect(sends[0].recipients == .some);
    try testing.expectEqualSlices(harness.K, targets, sends[0].recipients.some);
}

test "standard forward cached block sends to peers" {
    try run(forward_cached_body);
}

fn hint_below_floor_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "hint-below-floor");
    defer env.deinit();
    const mailbox = &env.started.mailbox;
    // Raise the floor above the hint about to be sent.
    const parent = cryptography.Sha256.hash(&.{"floor-parent"});
    const commitment = H.genesis_parent_commitment(harness.num_validators);
    const anchor = try H.make_test_block(
        gpa,
        parent,
        commitment,
        .new(10),
        10,
        harness.num_validators,
    );
    const floor_round = round_at(10);
    try mailbox.set_floor(try env.finalize(floor_round, 9, &anchor));
    try testing.expect(try mailbox.verified(floor_round, anchor));
    try ctx.sleep(.fromMilliseconds(50));
    // A hint at or below the floor is stale and fetches nothing.
    try mailbox.hint_finalized(.new(5), env.fixture.participants[1..2]);
    try ctx.sleep(.fromMilliseconds(50));
    try testing.expect(env.started.resolver.targeted_is_empty());
}

test "standard hint finalized below floor is a no-op" {
    try run(hint_below_floor_body);
}

fn has_finalization(mailbox: anytype, height: Height) !bool {
    var finalization = (try mailbox.get_finalization(height)) orelse return false;
    finalization.deinit(gpa);
    return true;
}

fn hint_already_finalized_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "hint-already-final");
    defer env.deinit();
    const round = round_at(1);
    const block = try block_one(100);
    var finalization = try env.finalize(round, 0, &block);
    defer finalization.deinit(gpa);
    const mailbox = &env.started.mailbox;
    try testing.expect(try mailbox.verified(round, try ready(block)));
    _ = mailbox.report(.{ .finalization = finalization });
    while (!try has_finalization(mailbox, .new(1))) try ctx.sleep(.fromMilliseconds(10));
    // A locally finalized height needs no fetch.
    try mailbox.hint_finalized(.new(1), env.fixture.participants[1..2]);
    try ctx.sleep(.fromMilliseconds(50));
    try testing.expect(env.started.resolver.targeted_is_empty());
}

test "standard hint finalized skips when already finalized" {
    try run(hint_already_finalized_body);
}

fn hint_targeted_fetch_body(ctx: Ctx) anyerror!void {
    var env: Env = undefined;
    try env.init(ctx, "hint-targets");
    defer env.deinit();
    const target = env.fixture.participants[1];
    try env.started.mailbox.hint_finalized(.new(7), &.{target});
    const resolver = env.started.resolver;
    try common.wait_until(ctx, 5000, "fetch_targeted", resolver, targeted_nonempty);
    const keys = try resolver.targeted_keys(gpa);
    defer gpa.free(keys);
    // Exactly one targeted fetch, for the finalization at height 7, from the hinted peer.
    try testing.expectEqual(1, keys.len);
    try testing.expect(keys[0] == .finalized);
    try testing.expectEqual(Height.new(7), keys[0].finalized);
    try testing.expectEqualSlices(harness.K, &.{target}, resolver.targeted_targets(0));
}

test "standard hint finalized emits a targeted fetch" {
    try run(hint_targeted_fetch_body);
}
