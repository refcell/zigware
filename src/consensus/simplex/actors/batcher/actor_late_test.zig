//! commonware `consensus/src/simplex/actors/batcher/mod.rs` actor tests in the parallel
//! lane's share of the split with consensus-simplex: conflicting votes (4935), same-term
//! optimistic future votes (6506, 6513), activity-window reporting (6819, 6966), and
//! constructed votes ahead of the view (7128). They run on ed25519 only: commonware's runs
//! over its other schemes check the same batcher logic on other signatures. The harness
//! runs in epoch 0 with `fill` payloads where commonware uses epoch 333 and hashed
//! payloads; neither changes what the batcher admits or assembles.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const types = @import("../../types.zig");
const h = @import("actor_test.zig");

const gpa = testing.allocator;
const Harness = h.Harness;
const VoterMessage = h.VoterMessage;
const Proposal = types.Proposal(h.Digest);

fn sleep_ms(io: Io, ms: i64) !void {
    try io.sleep(.fromMilliseconds(ms), .awake);
}

fn proposal_at(view: u64, parent: u64, fill: u8) Proposal {
    return .init(.new(.new(0), .new(view)), .new(parent), .fill(fill));
}

fn deliver_notarize(harness: *Harness, signer: usize, value: Proposal) !void {
    const bytes = try h.notarize_proposal_bytes(&harness.fixture, signer, value);
    try harness.votes.deliver(harness.fixture.participants[signer], bytes);
}

fn construct_notarize(harness: *Harness, value: Proposal) !void {
    const Notarize = types.Notarize(h.Scheme, h.Digest);
    const own = (try Notarize.sign(gpa, &harness.fixture.schemes[0], value)).?;
    try harness.mailbox.constructed(.{ .notarize = own });
}

/// Whether the voter received a certificate within `ms`, draining other messages
/// (commonware's `select!` of `voter_receiver.recv()` against a sleep).
fn got_certificate(harness: *Harness, ms: i64) !bool {
    try sleep_ms(harness.io, ms);
    var certificate = false;
    while (harness.voter.try_recv()) |message| {
        defer VoterMessage.discard(message);
        certificate = certificate or message == .verified;
    } else |err| try testing.expectEqual(error.Empty, err);
    return certificate;
}

/// Waits up to `ms` for a notarization of `view`, skipping other voter messages.
fn expect_notarization(harness: *Harness, view: u64, ms: u32) !void {
    for (0..ms) |_| {
        while (harness.voter.try_recv()) |message| {
            defer VoterMessage.discard(message);
            if (message != .verified) continue;
            const certificate = &message.verified.certificate;
            if (certificate.* != .notarization) continue;
            if (certificate.notarization.proposal.round.view.get() == view) return;
        } else |err| try testing.expectEqual(error.Empty, err);
        try sleep_ms(harness.io, 1);
    }
    return error.NoNotarization;
}

/// Waits up to `ms` for a reported notarize of `view`.
fn expect_reported_notarize(harness: *Harness, view: u64, ms: u32) !void {
    for (0..ms) |_| {
        if (harness.log.count(.notarize, view) > 0) return;
        try sleep_ms(harness.io, 1);
    }
    return error.NotReported;
}

// commonware `test_conflicting_votes_dont_produce_invalid_certificate`: of 7 participants,
// the leader votes for A and four others for B. Neither reaches a quorum of 5, so no
// certificate forms, not even after our own vote and a third vote for A.
test "batcher assembles no certificate from conflicting votes" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            try harness.start_with(io, null, .{ .participants = 7 });
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try sleep_ms(io, 10);
            const value_a = proposal_at(1, 0, 0xa);
            const value_b = proposal_at(1, 0, 0xb);
            try deliver_notarize(&harness, 1, value_a);
            try sleep_ms(io, 50);
            const forwarded = try harness.voter.try_recv();
            defer VoterMessage.discard(forwarded);
            try testing.expect(forwarded == .proposal);
            try testing.expect(forwarded.proposal.eql(value_a));
            for (2..6) |signer| try deliver_notarize(&harness, signer, value_b);
            try sleep_ms(io, 100);
            try testing.expect(!try got_certificate(&harness, 100));
            try construct_notarize(&harness, value_a);
            try deliver_notarize(&harness, 6, value_a);
            try sleep_ms(io, 100);
            try testing.expect(!try got_certificate(&harness, 100));
            try testing.expectEqual(0, harness.log.blocked.items.len);
        }
    };
    try h.run_deterministic(Root.run);
}

// commonware `test_same_term_optimistic_future_votes_are_admitted`: with terms of 10 views
// and two optimistic views, the admission window at view 1 reaches view 6. A vote there
// is reported; one for view 7 is dropped.
test "batcher admits same-term optimistic future votes up to the window" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            const options: Harness.Options = .{
                .participants = 5,
                .term_length = 10,
                .optimistic_views = 2,
            };
            try harness.start_with(io, null, options);
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try sleep_ms(io, 10);
            try deliver_notarize(&harness, 1, proposal_at(6, 5, 6));
            try expect_reported_notarize(&harness, 6, 1000);
            try deliver_notarize(&harness, 1, proposal_at(7, 6, 7));
            try sleep_ms(io, 50);
            try testing.expectEqual(0, harness.log.count(.notarize, 7));
            try testing.expectEqual(1, harness.log.count(.notarize, 6));
        }
    };
    try h.run_deterministic(Root.run);
}

// commonware `test_same_term_optimistic_future_votes_can_construct_notarization`: with terms
// of 5 views and two optimistic views, a quorum for view 3 at view 1 makes a notarization
// without waiting for the view to advance.
test "batcher notarizes a same-term optimistic future view" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            const options: Harness.Options = .{
                .participants = 5,
                .term_length = 5,
                .optimistic_views = 2,
            };
            try harness.start_with(io, null, options);
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try sleep_ms(io, 10);
            const value = proposal_at(3, 2, 3);
            // quorum(5) = 4 network votes.
            for (1..5) |signer| try deliver_notarize(&harness, signer, value);
            try expect_notarization(&harness, 3, 2000);
        }
    };
    try h.run_deterministic(Root.run);
}

// commonware `test_startup_votes_below_activity_window_not_reported`: restored at floor 10
// with a retention of 2, a view-1 vote that arrives before the first update is not
// reported, while a live vote after the update is.
test "batcher does not report startup votes below the activity window" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            const options: Harness.Options = .{
                .participants = 5,
                .view_retention = 2,
                .floor = 10,
            };
            try harness.start_with(io, null, options);
            defer harness.stop();
            try deliver_notarize(&harness, 1, proposal_at(1, 0, 1));
            try sleep_ms(io, 50);
            try harness.mailbox.update(.new(11), .init(1), .new(10), null);
            try sleep_ms(io, 10);
            try deliver_notarize(&harness, 1, proposal_at(11, 10, 11));
            try expect_reported_notarize(&harness, 11, 1000);
            try testing.expectEqual(0, harness.log.count(.notarize, 1));
        }
    };
    try h.run_deterministic(Root.run);
}

// commonware `test_votes_below_finalized_within_activity_window_reported`: finalized at 10
// with a retention of 2, a straggler vote for view 9 is still reported but one for view 7,
// below the activity window, is not.
test "batcher reports votes below finalized within the activity window" {
    const Root = struct {
        fn run(io: Io) !void {
            var harness: Harness = undefined;
            const options: Harness.Options = .{ .participants = 5, .view_retention = 2 };
            try harness.start_with(io, null, options);
            defer harness.stop();
            try harness.mailbox.update(.new(11), .init(1), .new(10), null);
            try sleep_ms(io, 10);
            try deliver_notarize(&harness, 1, proposal_at(7, 6, 7));
            try sleep_ms(io, 50);
            try deliver_notarize(&harness, 1, proposal_at(9, 8, 9));
            try expect_reported_notarize(&harness, 9, 1000);
            try testing.expectEqual(0, harness.log.count(.notarize, 7));
        }
    };
    try h.run_deterministic(Root.run);
}

fn metrics_contain(registry: *runtime.telemetry.metrics.Registry, needle: []const u8) !bool {
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    return std.mem.indexOf(u8, text, needle) != null;
}

// commonware `test_constructed_votes_are_not_future_bounded`: our own vote for view 6 at
// view 1 is added to the verifier, unlike network input that far ahead. Entering view 6
// reactivates it, and three network votes complete the notarization.
test "batcher does not future-bound constructed votes" {
    const Root = struct {
        fn run(io: Io) !void {
            const metrics = runtime.telemetry.metrics;
            var registry = metrics.Registry.init(gpa);
            defer registry.deinit();
            var harness: Harness = undefined;
            const scope = metrics.Scope.init(&registry).child("batcher");
            try harness.start_with(io, scope, .{ .participants = 5 });
            defer harness.stop();
            try harness.mailbox.update(.new(1), .init(1), .zero(), null);
            try sleep_ms(io, 10);
            const value = proposal_at(6, 1, 6);
            try construct_notarize(&harness, value);
            try sleep_ms(io, 50);
            try testing.expect(try metrics_contain(&registry, "added_total 1"));
            try harness.mailbox.update(.new(6), .init(0), .zero(), null);
            try sleep_ms(io, 10);
            // quorum(5) - 1 = 3 network votes on top of ours.
            for (1..4) |signer| try deliver_notarize(&harness, signer, value);
            try expect_notarization(&harness, 6, 5000);
        }
    };
    try h.run_deterministic(Root.run);
}
