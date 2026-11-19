//! commonware `simplex/actors/voter/mod.rs` nullify fast-path tests: a voter whose view can no
//! longer produce a notarize (a failed, dropped, or abandoned proposal, or the leader's own
//! nullify hint) nullifies at once instead of waiting out its 10 s timeouts.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const h = @import("harness.zig");

const Ctx = h.Ctx;
const View = h.View;
const Sha256 = h.Sha256;
const epoch = h.default_epoch;

/// commonware's fast-path configuration: timeouts far beyond the 1 s the tests wait.
const slow_timeouts: h.Options = .{
    .leader_timeout_ms = 10_000,
    .certification_timeout_ms = 10_000,
    .timeout_retry_ms = 60 * 60 * 1000,
    .batcher_capacity = 32,
};

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
        .timeout_ns = 20 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

const Position = struct { view: View, leader: u32 };

/// The first update: the voter's starting view and its leader.
fn first_update(ctx: Ctx, stack: *h.VoterStack) !Position {
    const message = (try stack.next_batcher(ctx, 1_000)) orelse return error.NoUpdate;
    if (message != .update) return error.UnexpectedMessage;
    return .{ .view = message.update.current, .leader = message.update.leader.get() };
}

/// Finalizes `at.view` with payload `hash(view)` and returns the next view it enters.
fn finalize_and_advance(ctx: Ctx, net: *h.Network, stack: *h.VoterStack, at: Position) !Position {
    const gpa = ctx.gpa();
    const view = at.view.get();
    var label: [8]u8 = undefined;
    std.mem.writeInt(u64, &label, view, .big);
    const parent: View = .new(view -| 1);
    const proposal: h.Proposal = .init(.new(epoch, at.view), parent, Sha256.hash(&.{&label}));
    const finalization = try h.build(gpa, .finalization, net.schemes(), proposal, net.quorum());
    try stack.mailbox.recovered(gpa, .{ .finalization = finalization });
    // Bounded by the runner's timeout.
    while (true) {
        const message = (try stack.next_batcher(ctx, 5_000)) orelse return error.TimedOut;
        if (message != .update or message.update.current.get() <= view) continue;
        return .{ .view = message.update.current, .leader = message.update.leader.get() };
    }
}

/// Finalizes views until one whose leader is (`leading`) or is not (`!leading`) us.
fn advance_until(
    ctx: Ctx,
    net: *h.Network,
    stack: *h.VoterStack,
    start: Position,
    leading: bool,
) !Position {
    var at = start;
    // Round-robin over 5 participants: a matching view is at most 5 views away.
    for (0..8) |_| {
        if ((at.leader == 0) == leading) return at;
        at = try finalize_and_advance(ctx, net, stack, at);
    }
    return error.NoMatchingView;
}

/// Broadcasts a proposal at `at` over the finalized `view - 1` (payload `hash(view - 1)`), from
/// its leader, and hands it to the voter.
fn propose(net: *h.Network, stack: *h.VoterStack, at: Position, label: []const u8) !void {
    const view = at.view.get();
    const proposal = h.proposal_at(epoch, view, label);
    var parent_label: [8]u8 = undefined;
    std.mem.writeInt(u64, &parent_label, view - 1, .big);
    var buffer: [128]u8 = undefined;
    var writer: codec.Writer = .init(&buffer);
    proposal.round.write(&writer);
    codec.write(h.Digest, Sha256.hash(&.{&parent_label}), &writer);
    codec.write(u64, 7, &writer);
    net.relay.broadcast(net.keys()[at.leader], .all, proposal.payload, writer.written());
    try stack.mailbox.proposal(proposal);
}

/// Waits `limit_ms` of simulated time for our nullify at `view`; true when it came.
fn nullified_within(ctx: Ctx, stack: *h.VoterStack, view: View, limit_ms: u64) !bool {
    var waited: u64 = 0;
    while (waited <= limit_ms) {
        if (stack.batcher.try_recv()) |message| {
            if (message != .constructed) continue;
            const vote = message.constructed;
            if (vote == .nullify and vote.view().get() == view.get()) return true;
            continue;
        } else |err| switch (err) {
            error.Empty => {},
            else => return error.MailboxClosed,
        }
        try ctx.sleep(.fromMilliseconds(1));
        waited += 1;
    }
    return false;
}

fn expect_fast_nullify(ctx: Ctx, stack: *h.VoterStack, view: View) !void {
    // With 10 s timeouts, a nullify within 1 s came from the fast path.
    if (!try nullified_within(ctx, stack, view, 1_000)) return error.NoFastNullify;
}

// commonware test_verification_failure_emits_nullify_immediately
test "voter verification failure emits nullify immediately" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var net: h.Network = undefined;
            try net.start(ctx, 5, "consensus");
            defer net.deinit();
            var options = slow_timeouts;
            options.fail_verification = true;
            options.verify_latency_ms = 10;
            options.partition = "voter_verify_fail_test";
            var stack: h.VoterStack = undefined;
            try stack.start(ctx, &net, options);
            defer stack.stop();
            const start = try first_update(ctx, &stack);
            const at = try advance_until(ctx, &net, &stack, start, false);
            try propose(&net, &stack, at, "test_proposal");
            try expect_fast_nullify(ctx, &stack, at.view);
        }
    }.body);
}

// commonware test_leader_nullify_timeout_hint_fast_paths_nullify
test "voter leader nullify timeout hint fast paths nullify" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var net: h.Network = undefined;
            try net.start(ctx, 5, "leader_nullify_timeout_hint_fast_paths_nullify");
            defer net.deinit();
            var options = slow_timeouts;
            options.partition = "voter_leader_nullify_fast_path";
            var stack: h.VoterStack = undefined;
            try stack.start(ctx, &net, options);
            defer stack.stop();
            const start = try first_update(ctx, &stack);
            // As a verifier, the leader's nullify hint nullifies at once.
            const at = try advance_until(ctx, &net, &stack, start, false);
            const round: h.Round = .new(epoch, at.view);
            try stack.mailbox.timeout(round, .leader_nullify);
            try expect_fast_nullify(ctx, &stack, at.view);
            // A duplicate hint does not nullify again.
            try stack.mailbox.timeout(round, .leader_nullify);
            try testing.expect(!try nullified_within(ctx, &stack, at.view, 300));
        }
    }.body);
}

// commonware test_dropped_propose_emits_nullify_immediately
test "voter dropped propose emits nullify immediately" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var net: h.Network = undefined;
            try net.start(ctx, 5, "dropped_propose_emits_nullify_immediately");
            defer net.deinit();
            var options = slow_timeouts;
            options.drop_proposals = true;
            options.partition = "voter_drop_propose_test";
            var stack: h.VoterStack = undefined;
            try stack.start(ctx, &net, options);
            defer stack.stop();
            const start = try first_update(ctx, &stack);
            // As the leader, a dropped propose response nullifies at once.
            const at = try advance_until(ctx, &net, &stack, start, true);
            try expect_fast_nullify(ctx, &stack, at.view);
        }
    }.body);
}

// commonware test_dropped_verify_emits_nullify_immediately
test "voter dropped verify emits nullify immediately" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var net: h.Network = undefined;
            try net.start(ctx, 5, "dropped_verify_emits_nullify_immediately");
            defer net.deinit();
            var options = slow_timeouts;
            options.partition = "voter_drop_verify_test";
            var stack: h.VoterStack = undefined;
            try stack.start(ctx, &net, options);
            defer stack.stop();
            stack.application.drop_verifications = true;
            const start = try first_update(ctx, &stack);
            const at = try advance_until(ctx, &net, &stack, start, false);
            try propose(&net, &stack, at, "drop_verify");
            try expect_fast_nullify(ctx, &stack, at.view);
            // A dropped verify counts as an ignored proposal.
            const encoded = try ctx.scope.encode(gpa);
            defer gpa.free(encoded);
            var lines = std.mem.splitScalar(u8, encoded, '\n');
            var counted = false;
            while (lines.next()) |line| {
                if (std.mem.indexOf(u8, line, "_timeouts") == null) continue;
                if (std.mem.indexOf(u8, line, "reason=\"IgnoredProposal\"") == null) continue;
                counted = counted or !std.mem.endsWith(u8, line, " 0");
            }
            try testing.expect(counted);
        }
    }.body);
}
