//! commonware `actors/voter/state.rs` tests, on the deterministic runtime (the state reads
//! time through `std.Io`).

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const Io = std.Io;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const elector = @import("../../elector.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const context = @import("../context.zig");
const state_mod = @import("state.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const Elector = elector.RoundRobinElector;
pub const State = state_mod.State(Scheme, Elector, Digest);
const Proposal = types.Proposal(Digest);
const Notarize = types.Notarize(Scheme, Digest);
const Finalize = types.Finalize(Scheme, Digest);
const Nullify = types.Nullify(Scheme);
const Notarization = types.Notarization(Scheme, Digest);
const Finalization = types.Finalization(Scheme, Digest);
const Nullification = types.Nullification(Scheme);
const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
const View = consensus_types.View;
const Rnd = consensus_types.Round;
const Duration = utils.Duration;
const gpa = testing.allocator;
const sequential = parallel.sequential;
const genesis_view = state_mod.genesis_view;
const second_ns: i96 = std.time.ns_per_s;

pub fn genesis() Digest {
    return .fill(0);
}

pub fn proposal(epoch: u64, view: u64, parent: u64, payload: u8) Proposal {
    return .init(.new(.new(epoch), .new(view)), .new(parent), .fill(payload));
}

pub fn build_notarization(f: *const Fixture, value: Proposal) !Notarization {
    var votes: [4]Notarize = undefined;
    const n = f.schemes.len;
    assert(n <= votes.len);
    for (votes[0..n], f.schemes) |*vote, *scheme| {
        vote.* = (try Notarize.sign(gpa, scheme, value)).?;
    }
    return Notarization.from_votes(gpa, &f.verifier, votes[0..n], sequential);
}

pub fn build_finalization(f: *const Fixture, value: Proposal) !Finalization {
    var votes: [4]Finalize = undefined;
    const n = f.schemes.len;
    assert(n <= votes.len);
    for (votes[0..n], f.schemes) |*vote, *scheme| {
        vote.* = (try Finalize.sign(gpa, scheme, value)).?;
    }
    return Finalization.from_votes(gpa, &f.verifier, votes[0..n], sequential);
}

pub fn build_nullification(f: *const Fixture, round: Rnd) !Nullification {
    var votes: [4]Nullify = undefined;
    const n = f.schemes.len;
    assert(n <= votes.len);
    for (votes[0..n], f.schemes) |*vote, *scheme| {
        vote.* = (try Nullify.sign(gpa, scheme, round)).?;
    }
    return Nullification.from_votes(gpa, &f.verifier, votes[0..n], sequential);
}

pub const Options = struct {
    /// Index of the signing scheme, or null for the verifier.
    signer: ?usize = null,
    epoch: u64 = 1,
    view_retention: u64 = 10,
    term_length: u32 = 1,
    stall_timeout_ms: u64 = 30_000,
    optimistic_views: u64 = 0,
    leader_timeout_ms: u64 = 1000,
    certification_timeout_ms: u64 = 2000,
    timeout_retry_ms: u64 = 3000,
    validators: u32 = 4,
    /// Terms that may be skipped past the last finalization (0 disables skipping).
    skip_budget: u64 = 4,
};

/// A fixture of `validators` participants and a state that entered view 1. Must not move
/// once started.
pub const Env = struct {
    fixture: Fixture,
    elector: Elector,
    state: State,

    pub fn start(self: *Env, io: Io, options: Options) !void {
        var rng = utils.rng.test_rng();
        self.fixture = try ed25519.fixture(Digest, gpa, &rng, "ns", options.validators);
        errdefer self.fixture.deinit(gpa);
        var builder = elector.RoundRobin(cryptography.Sha256).default();
        if (options.term_length > 1) builder = builder.with_term(
            .new(utils.NonZero(u32).init(options.term_length).?),
            .from_millis(options.stall_timeout_ms),
            .new(options.optimistic_views),
        );
        self.elector = try builder.build(gpa, options.validators);
        const scheme = if (options.signer) |i| &self.fixture.schemes[i] else &self.fixture.verifier;
        self.state = State.init(gpa, io, .{
            .scheme = scheme,
            .elector = self.elector,
            .epoch = .new(options.epoch),
            .view_retention = .new(options.view_retention),
            .leader_timeout = .from_millis(options.leader_timeout_ms),
            .certification_timeout = .from_millis(options.certification_timeout_ms),
            .timeout_retry = .from_millis(options.timeout_retry_ms),
            .skip_budget = options.skip_budget,
        });
        try self.state.set_genesis(genesis());
    }

    pub fn stop(self: *Env) void {
        self.state.deinit();
        self.elector.deinit(gpa);
        self.fixture.deinit(gpa);
    }
};

pub fn run(comptime function: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
}

pub fn expect_err(result: anytype, expected: state_mod.ParentPayloadError) !void {
    try testing.expect(result == .err);
    try testing.expectEqualDeep(expected, result.err);
}

test "voter state timeout helpers reuse and reset deadlines" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 4, .view_retention = 2 });
            defer env.stop();
            const state = &env.state;
            const retry = 3 * second_ns;
            const first = state.next_timeout();
            try testing.expectEqual(first, state.next_timeout());
            const vote = (try state.construct_nullify(state.current_view(), .leader_timeout)).?;
            try testing.expect(!vote.retry);
            try io.sleep(.fromSeconds(2), .awake);
            const later = context.now_ns(io);
            const third = state.next_timeout();
            try testing.expectEqual(later + retry, third.deadline);
            try testing.expectEqual(.retry, third.reason);
            try testing.expectEqual(third, state.next_timeout());
            try io.sleep(.fromSeconds(10), .awake);
            try testing.expectEqual(third, state.next_timeout());
            const again = (try state.construct_nullify(state.current_view(), .retry)).?;
            try testing.expect(again.retry);
            const sixth = state.next_timeout();
            try testing.expectEqual(context.now_ns(io) + retry, sixth.deadline);
        }
    }.body);
}

test "voter state constructs nullify for the current view only" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 4, .view_retention = 2 });
            defer env.stop();
            const state = &env.state;
            const current = state.current_view();
            const next = current.next();
            try testing.expectEqual(null, try state.construct_nullify(next, .leader_timeout));
            const nullified = try build_nullification(&env.fixture, .new(.new(4), current));
            try testing.expect(try state.add_nullification(nullified));
            try testing.expectEqual(next, state.current_view());
            try testing.expectEqual(null, try state.construct_nullify(current, .leader_timeout));
            try testing.expect(!(try state.construct_nullify(next, .leader_timeout)).?.retry);
            try testing.expect((try state.construct_nullify(next, .retry)).?.retry);
        }
    }.body);
}

test "voter state prunes rounds below min active" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 7 });
            defer env.stop();
            const state = &env.state;
            for (0..5) |view| _ = try state.create_round(.new(view));
            const finalized = try build_finalization(&env.fixture, proposal(1, 20, 0, 1));
            _ = try state.add_finalization(finalized);
            var removed: std.ArrayList(View) = .empty;
            defer removed.deinit(gpa);
            try state.prune(&removed);
            try testing.expectEqual(5, removed.items.len);
            for (removed.items, 0..) |view, i| try testing.expectEqual(i, view.get());
            try testing.expectEqual(2, state.rounds.len()); // 20 and 21
        }
    }.body);
}

test "voter state parent payload needs a certified parent" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 2, .epoch = 4, .view_retention = 2 });
            defer env.stop();
            const state = &env.state;
            const parent = proposal(1, 1, 0, 1);
            const child = proposal(1, 2, 1, 9);
            const not_certified: state_mod.ParentPayloadError = .{
                .parent_not_certified = .{ .proposal_view = .new(2), .parent_view = .new(1) },
            };
            try expect_err(state.parent_payload(&child), not_certified);
            _ = try state.add_notarization(try build_notarization(&env.fixture, parent));
            try expect_err(state.parent_payload(&child), not_certified);
            try state.set_certify_outstanding(.new(1));
            _ = try state.certified(.new(1), true);
            const result = state.parent_payload(&child);
            try testing.expect(result == .payload and result.payload.eql(parent.payload));
        }
    }.body);
}

test "voter state parent payload needs nullifications and no intra-term skips" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .view_retention = 5 });
            defer env.stop();
            const state = &env.state;
            const parent = try build_notarization(&env.fixture, proposal(1, 1, 0, 2));
            _ = try state.add_notarization(parent);
            _ = try state.create_round(.new(2));
            const child = proposal(1, 3, 1, 3);
            try expect_err(state.parent_payload(&child), .{ .missing_nullification = .{
                .proposal_view = .new(3),
                .parent_view = .new(1),
                .missing_view = .new(2),
            } });
        }
    }.body);
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .view_retention = 20, .term_length = 5 });
            defer env.stop();
            const state = &env.state;
            const parent = try build_notarization(&env.fixture, proposal(1, 1, 0, 1));
            _ = try state.add_notarization(parent);
            _ = try state.certified(.new(1), true);
            try expect_err(state.parent_payload(&proposal(1, 3, 1, 2)), .{
                .intra_term_proposal_skips_views = .{
                    .proposal_view = .new(3),
                    .parent_view = .new(1),
                },
            });
        }
    }.body);
}

pub fn candidate_views(state: *State, out: *std.ArrayList(Proposal)) !void {
    out.clearRetainingCapacity();
    var fetches: std.ArrayList(state_mod.CertificateFetch) = .empty;
    defer fetches.deinit(gpa);
    try state.certify_candidates(out, &fetches);
}

fn certification_proposal(view: u64) Proposal {
    return proposal(1, view, 0, @intCast(view));
}

test "voter state certification lifecycle" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{});
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            var ready: std.ArrayList(Proposal) = .empty;
            defer ready.deinit(gpa);
            for (3..9) |view| {
                const notarized = try build_notarization(f, certification_proposal(view));
                _ = try state.add_notarization(notarized);
            }
            try candidate_views(state, &ready);
            try testing.expectEqual(6, ready.items.len);
            for ([_]u64{ 3, 4, 5, 7 }) |view| try state.set_certify_outstanding(.new(view));
            try candidate_views(state, &ready);
            try testing.expectEqual(0, ready.items.len);
            try testing.expect(try state.certified(.new(7), true) != null);
            try testing.expect(!state.is_certify_aborted(.new(7)));
            // Finalizing view 5 aborts the requests for views 3, 4, and 5.
            _ = try state.add_finalization(try build_finalization(f, certification_proposal(5)));
            for ([_]u64{ 3, 4, 5 }) |view| try testing.expect(state.is_certify_aborted(.new(view)));
            for ([_]u64{ 6, 7, 8 }) |view| {
                try testing.expect(!state.is_certify_aborted(.new(view)));
            }
            try candidate_views(state, &ready);
            try testing.expectEqual(0, ready.items.len);
            _ = try state.add_notarization(try build_notarization(f, certification_proposal(9)));
            try candidate_views(state, &ready);
            try testing.expectEqual(1, ready.items.len);
            try testing.expectEqual(9, ready.items[0].view().get());
            try state.set_certify_outstanding(.new(9));
            _ = try state.add_notarization(try build_notarization(f, certification_proposal(10)));
            try candidate_views(state, &ready);
            try testing.expectEqual(1, ready.items.len);
            try testing.expectEqual(10, ready.items[0].view().get());
            _ = try state.add_finalization(try build_finalization(f, certification_proposal(9)));
            try testing.expect(state.is_certify_aborted(.new(9)));
            _ = try state.add_notarization(try build_notarization(f, certification_proposal(11)));
            try candidate_views(state, &ready);
            try testing.expectEqual(1, ready.items.len);
            try testing.expectEqual(11, ready.items[0].view().get());
        }
    }.body);
}

const terms_of_five: Options = .{
    .signer = 0,
    .view_retention = 20,
    .term_length = 5,
    .stall_timeout_ms = 4000,
};

test "voter state nullification skips to the next term start" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_five);
            defer env.stop();
            try testing.expectEqual(1, env.state.current_view().get());
            const nullified = try build_nullification(&env.fixture, .new(.new(1), .new(1)));
            try testing.expect(try env.state.add_nullification(nullified));
            try testing.expectEqual(6, env.state.current_view().get());
        }
    }.body);
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0 });
            defer env.stop();
            const nullified = try build_nullification(&env.fixture, .new(.new(1), .new(1)));
            try testing.expect(try env.state.add_nullification(nullified));
            try testing.expectEqual(2, env.state.current_view().get());
        }
    }.body);
}

test "voter state term safety blocks finalize after nullify" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_five);
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            const view: View = state.current_view();
            try testing.expectEqual(1, view.get());
            try testing.expect(!(try state.construct_nullify(view, .leader_timeout)).?.retry);
            const first = proposal(1, 1, 0, 42);
            const first_notarized = try build_notarization(f, first);
            try testing.expect((try state.add_notarization(first_notarized)).added);
            try testing.expect(try state.certified(view, true) != null);
            try testing.expectEqual(2, state.current_view().get());
            const second = proposal(1, 2, 1, 43);
            try testing.expect(try state.set_proposal(.new(2), &second));
            try testing.expect(state.try_verify() == .ready);
            try testing.expect(state.verified(.new(2)));
            const second_notarized = try build_notarization(f, second);
            try testing.expect((try state.add_notarization(second_notarized)).added);
            try testing.expect(try state.certified(.new(2), true) != null);
            try testing.expectEqual(null, try state.construct_finalize(.new(2)));
            // The late finalization of view 1 unblocks the finalize vote for view 2.
            _ = try state.add_finalization(try build_finalization(f, first));
            try testing.expect(try state.construct_finalize(.new(2)) != null);
        }
    }.body);
}

test "voter state entry certificate prefers finalization, nullification, notarization" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .view_retention = 20 });
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            const value = proposal(1, 1, 0, 17);
            _ = try state.add_notarization(try build_notarization(f, value));
            try testing.expect(try state.certified(.new(1), true) != null);
            var best = (try state.get_best_certificate()).?;
            try testing.expect(best == .notarization);
            best.deinit(gpa);
            const nullified = try build_nullification(f, .new(.new(1), .new(1)));
            try testing.expect(try state.add_nullification(nullified));
            best = (try state.get_best_certificate()).?;
            try testing.expect(best == .nullification);
            best.deinit(gpa);
            _ = try state.add_finalization(try build_finalization(f, value));
            best = (try state.get_best_certificate()).?;
            try testing.expect(best == .finalization);
            best.deinit(gpa);
        }
    }.body);
}

test "voter state only notarizes before nullify" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .view_retention = 5 });
            defer env.stop();
            const state = &env.state;
            const view = state.current_view();
            _ = try state.set_proposal(view, &proposal(1, 1, 0, 1));
            try testing.expect(state.try_verify() == .ready);
            try testing.expect(state.verified(view));
            try testing.expect(!(try state.construct_nullify(view, .leader_timeout)).?.retry);
            try testing.expectEqual(null, try state.construct_notarize(view));
        }
    }.body);
}

test "voter state try verify waits for missing parent certification" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{
                .view_retention = 5,
                .leader_timeout_ms = 10_000,
                .certification_timeout_ms = 10_000,
                .timeout_retry_ms = 30_000,
            });
            defer env.stop();
            const state = &env.state;
            try testing.expect(try state.enter_view(.new(2)));
            try testing.expect(try state.set_proposal(.new(2), &proposal(1, 2, 1, 7)));
            const initial = state.next_timeout();
            try testing.expect(initial.deadline > context.now_ns(io));
            try testing.expect(state.try_verify() != .ready);
            try testing.expectEqual(initial, state.next_timeout());
        }
    }.body);
}

test "voter state honest path: propose, notarize, certify, finalize" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            // Participant 1 leads view 1 (epoch 0 with round robin elects index 1 at view 1).
            try env.start(io, .{ .signer = 1, .epoch = 0 });
            defer env.stop();
            const state = &env.state;
            const request = state.try_propose().?;
            try testing.expect(!request.is_handoff());
            try testing.expectEqual(1, request.view().get());
            try testing.expect(request.context().parent[1].eql(genesis()));
            const context_ = request.context();
            try testing.expect(state.proposed(&context_, .fill(5)));
            try testing.expectEqual(null, state.try_propose());
            const vote = (try state.construct_notarize(.new(1))).?;
            try testing.expect(vote.proposal.payload.eql(Digest.fill(5)));
            const value = vote.proposal;
            _ = try state.add_notarization(try build_notarization(&env.fixture, value));
            var ready: std.ArrayList(Proposal) = .empty;
            defer ready.deinit(gpa);
            try candidate_views(state, &ready);
            try testing.expectEqual(1, ready.items.len);
            try state.set_certify_outstanding(.new(1));
            _ = try state.certified(.new(1), true);
            try testing.expectEqual(2, state.current_view().get());
            try testing.expect(try state.construct_finalize(.new(1)) != null);
            _ = try state.add_finalization(try build_finalization(&env.fixture, value));
            try testing.expectEqual(1, state.last_finalized().get());
        }
    }.body);
}

test "voter state declarations all compile" {
    std.testing.refAllDecls(State);
    std.testing.refAllDecls(State.Round);
}

const ms_ns: i96 = std.time.ns_per_ms;

/// Sets view `view`'s proposal (naming `parent`), verifies it, and adds its notarization.
fn verify_and_notarize(env: *Env, view: u64, parent: u64, payload: u8) !void {
    const state = &env.state;
    const value = proposal(env.state.epoch.get(), view, parent, payload);
    try testing.expect(try state.set_proposal(.new(view), &value));
    try testing.expect(state.try_verify() == .ready);
    try testing.expect(state.verified(.new(view)));
    const added = try state.add_notarization(try build_notarization(&env.fixture, value));
    try testing.expect(added.added);
}

test "voter state nullify preserves retry backoff after the first timeout vote" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 30, .view_retention = 2 });
            defer env.stop();
            const state = &env.state;
            const view = state.current_view();
            try testing.expect(!(try state.construct_nullify(view, .leader_timeout)).?.retry);
            try io.sleep(.fromSeconds(2), .awake);
            const retry_deadline = state.next_timeout();
            try testing.expectEqual(context.now_ns(io) + 3 * second_ns, retry_deadline.deadline);
            try testing.expectEqual(.retry, retry_deadline.reason);
            // Repeated timeout hints for the same view do not reset the retry backoff.
            state.trigger_timeout(view, .leader_nullify);
            try testing.expectEqual(retry_deadline, state.next_timeout());
        }
    }.body);
}

test "voter state nullify takes its reason from next timeout" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 31, .view_retention = 2 });
            defer env.stop();
            const state = &env.state;
            const view = state.current_view();
            state.trigger_timeout(view, .missing_proposal);
            const latched = state.next_timeout();
            try testing.expectEqual(.missing_proposal, latched.reason);
            try testing.expect(!(try state.construct_nullify(view, latched.reason)).?.retry);
            // Retries follow the retry cadence whatever reason is passed.
            const retried = state.next_timeout();
            try testing.expectEqual(.retry, retried.reason);
            try testing.expect((try state.construct_nullify(view, retried.reason)).?.retry);
        }
    }.body);
}

test "voter state notarization keeps the certification timeout pending certification" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 32, .view_retention = 2 });
            defer env.stop();
            const state = &env.state;
            const view = state.current_view();
            const value = proposal(32, view.get(), 0, 52);
            // A proposal clears the leader timeout and leaves the certification timeout.
            try testing.expect(try state.set_proposal(view, &value));
            const certification = state.next_timeout();
            try testing.expectEqual(context.now_ns(io) + 2 * second_ns, certification.deadline);
            try testing.expectEqual(.certification_timeout, certification.reason);
            const added = try state.add_notarization(try build_notarization(&env.fixture, value));
            try testing.expect(added.added and added.equivocator == null);
            try testing.expectEqual(certification, state.next_timeout());
            // A certification stalled past its timeout leaves the view timed out.
            try io.sleep(.fromSeconds(3), .awake);
            try testing.expect(state.next_timeout().deadline <= context.now_ns(io));
        }
    }.body);
}

const terms_of_three: Options = .{
    .signer = 0,
    .epoch = 33,
    .term_length = 3,
    .stall_timeout_ms = 4000,
};

test "voter state stall timeout tracks the oldest unfinalized view" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_three);
            defer env.stop();
            const state = &env.state;
            const oldest = context.now_ns(io) + 4 * second_ns;
            try verify_and_notarize(&env, 1, 0, 1);
            try io.sleep(.fromSeconds(1), .awake);
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expectEqual(2, state.current_view().get());
            try verify_and_notarize(&env, 2, 1, 2);
            try io.sleep(.fromMilliseconds(1500), .awake);
            try testing.expect(try state.certified(.new(2), true) != null);
            try testing.expectEqual(3, state.current_view().get());
            const v3_certification = context.now_ns(io) + 2 * second_ns;
            const v3 = proposal(33, 3, 2, 3);
            try testing.expect(try state.set_proposal(.new(3), &v3));
            try testing.expect(state.try_verify() == .ready);
            try testing.expect(state.verified(.new(3)));
            const stall = state.next_timeout();
            try testing.expectEqual(oldest, stall.deadline);
            try testing.expectEqual(.stall_timeout, stall.reason);
            // Once the round's own timeout expired too, its reason takes precedence.
            try io.sleep(.fromSeconds(2), .awake);
            const expired = state.next_timeout();
            try testing.expectEqual(v3_certification, expired.deadline);
            try testing.expectEqual(.certification_timeout, expired.reason);
        }
    }.body);
}

test "voter state stall timeout ignores prior terms" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = terms_of_three;
            options.epoch = 34;
            options.stall_timeout_ms = 12_000;
            options.leader_timeout_ms = 10_000;
            options.certification_timeout_ms = 11_000;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            try io.sleep(.fromSeconds(3), .awake);
            const nullified = try build_nullification(&env.fixture, .new(.new(34), .new(1)));
            try testing.expect(try state.add_nullification(nullified));
            try testing.expectEqual(4, state.current_view().get());
            const leader = context.now_ns(io) + 10 * second_ns;
            // View 1's stall deadline has passed; a leak from the prior term would win here.
            try io.sleep(.fromMilliseconds(9500), .awake);
            const timeout = state.next_timeout();
            try testing.expectEqual(leader, timeout.deadline);
            try testing.expectEqual(.leader_timeout, timeout.reason);
        }
    }.body);
}

test "voter state retry takes precedence over an expired same-term timeout" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{
                .signer = 0,
                .epoch = 35,
                .term_length = 3,
                .stall_timeout_ms = 30,
                .leader_timeout_ms = 10,
                .certification_timeout_ms = 20,
                .timeout_retry_ms = 3,
            });
            defer env.stop();
            const state = &env.state;
            const oldest = context.now_ns(io) + 30 * ms_ns;
            const value = proposal(35, 1, 0, 35);
            const added = try state.add_notarization(try build_notarization(&env.fixture, value));
            try testing.expect(added.added);
            try io.sleep(.fromMilliseconds(25), .awake);
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expectEqual(2, state.current_view().get());
            try io.sleep(.fromMilliseconds(5), .awake);
            const stall = state.next_timeout();
            try testing.expectEqual(oldest, stall.deadline);
            try testing.expectEqual(.stall_timeout, stall.reason);
            const view = state.current_view();
            try testing.expect(!(try state.construct_nullify(view, .stall_timeout)).?.retry);
            // An expired same-term deadline must not override the retry cadence.
            const retry = state.next_timeout();
            try testing.expectEqual(context.now_ns(io) + 3 * ms_ns, retry.deadline);
            try testing.expectEqual(.retry, retry.reason);
        }
    }.body);
}

test "voter state local nullify preserves the stall timeout" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = terms_of_three;
            options.epoch = 36;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            const view = state.current_view();
            const oldest = context.now_ns(io) + 4 * second_ns;
            // The actor's timeout sequence: latch the reason, then construct the nullify.
            state.trigger_timeout(view, .leader_timeout);
            try testing.expect(!(try state.construct_nullify(view, .leader_timeout)).?.retry);
            const value = proposal(36, 1, 0, 36);
            const added = try state.add_notarization(try build_notarization(&env.fixture, value));
            try testing.expect(added.added);
            try io.sleep(.fromSeconds(4), .awake);
            try testing.expect(try state.certified(view, true) != null);
            try testing.expectEqual(2, state.current_view().get());
            const stall = state.next_timeout();
            try testing.expectEqual(oldest, stall.deadline);
            try testing.expectEqual(.stall_timeout, stall.reason);
        }
    }.body);
}

/// Builds and records `payload` as our view-1 proposal on genesis, then casts our notarize
/// vote for it (commonware `propose_and_notarize_view1`).
pub fn propose_and_notarize_view1(env: *Env, payload: u8) !Proposal {
    const state = &env.state;
    _ = try state.create_round(.new(1));
    const request: State.Context = .{
        .round = .new(state.epoch, .new(1)),
        .leader = env.fixture.participants[0],
        .parent = .{ genesis_view, genesis() },
    };
    try testing.expect(state.proposed(&request, .fill(payload)));
    try testing.expect(try state.construct_notarize(.new(1)) != null);
    return proposal(state.epoch.get(), 1, 0, payload);
}

test "voter state stall timeout survives a certificate jump" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = terms_of_three;
            options.epoch = 7;
            options.term_length = 5;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            // Certifying view 7 (term 6..10) at view 1 jumps to view 8; view 6 was never
            // entered and has no deadline.
            const value = proposal(7, 7, 0, 7);
            const added = try state.add_notarization(try build_notarization(&env.fixture, value));
            try testing.expect(added.added);
            const entered = context.now_ns(io);
            try testing.expect(try state.certified(.new(7), true) != null);
            try testing.expectEqual(8, state.current_view().get());
            // The anchor is the oldest entered, unfinalized view of the term (view 8).
            try testing.expectEqual(entered + 4 * second_ns, state.next_stall_timeout().?);
        }
    }.body);
}

test "voter state arms no stall deadline when unconfigured" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 33 });
            defer env.stop();
            const entered = context.now_ns(io);
            try testing.expectEqual(null, env.state.next_stall_timeout());
            const timeout = env.state.next_timeout();
            try testing.expectEqual(entered + second_ns, timeout.deadline);
            try testing.expectEqual(.leader_timeout, timeout.reason);
        }
    }.body);
}

test "voter state expired latch keeps its reason over an expired anchor" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = terms_of_three;
            options.epoch = 9;
            options.timeout_retry_ms = 10_000;
            try env.start(io, options);
            defer env.stop();
            // The term's stall deadline expires, then an event latches a timeout.
            try io.sleep(.fromSeconds(5), .awake);
            env.state.trigger_timeout(env.state.current_view(), .leader_nullify);
            try testing.expectEqual(.leader_nullify, env.state.next_timeout().reason);
        }
    }.body);
}

test "voter state ignores timeouts for old rounds" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 12, .view_retention = 3 });
            defer env.stop();
            const state = &env.state;
            const deadline_v1 = state.next_timeout();
            state.trigger_timeout(.zero(), .inactivity);
            try testing.expectEqual(1, state.current_view().get());
            try testing.expectEqual(deadline_v1, state.next_timeout());
            // The ignored timeout creates no round for view 0.
            try testing.expect(state.rounds.get(.zero()) == null);
            const nullified = try build_nullification(&env.fixture, .new(.new(12), .new(1)));
            try testing.expect(try state.add_nullification(nullified));
            try testing.expectEqual(2, state.current_view().get());
            const deadline_v2 = state.next_timeout();
            state.trigger_timeout(.new(1), .inactivity);
            try testing.expectEqual(2, state.current_view().get());
            try testing.expectEqual(deadline_v2, state.next_timeout());
        }
    }.body);
}

const optimistic_terms: Options = .{
    .signer = 1,
    .epoch = 15,
    .term_length = 5,
    .stall_timeout_ms = 20_000,
    .optimistic_views = 1,
    .leader_timeout_ms = 10_000,
    .certification_timeout_ms = 10_000,
    .timeout_retry_ms = 30_000,
};

/// Finalizes our view-1 proposal so the state enters view 2.
fn enter_view_two(env: *Env, payload: u8) !void {
    const parent = try propose_and_notarize_view1(env, payload);
    const added = try env.state.add_finalization(try build_finalization(&env.fixture, parent));
    try testing.expect(added.added);
    try testing.expectEqual(2, env.state.current_view().get());
}

test "voter state inactivity timeout ignores a buffered current proposal" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, optimistic_terms);
            defer env.stop();
            const state = &env.state;
            try enter_view_two(&env, 118);
            // A buffered, unverified proposal suppresses the inactivity hint.
            const child = proposal(15, 2, 1, 119);
            try testing.expect(try state.set_proposal(.new(2), &child));
            const now = context.now_ns(io);
            state.trigger_timeout(.new(2), .inactivity);
            const certification = state.next_timeout();
            try testing.expectEqual(.certification_timeout, certification.reason);
            try testing.expectEqual(now + 10 * second_ns, certification.deadline);
            // The leader's own nullify still latches an immediate timeout.
            state.trigger_timeout(.new(2), .leader_nullify);
            const latched = state.next_timeout();
            try testing.expectEqual(.leader_nullify, latched.reason);
            try testing.expectEqual(now, latched.deadline);
        }
    }.body);
}

test "voter state inactivity timeout latches on an equivocated proposal" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = optimistic_terms;
            options.stall_timeout_ms = 4000;
            options.leader_timeout_ms = 1000;
            options.certification_timeout_ms = 2000;
            options.timeout_retry_ms = 3000;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            try enter_view_two(&env, 120);
            try testing.expect(try state.set_proposal(.new(2), &proposal(15, 2, 1, 121)));
            try testing.expect(!try state.set_proposal(.new(2), &proposal(15, 2, 1, 122)));
            const now = context.now_ns(io);
            state.trigger_timeout(.new(2), .inactivity);
            const latched = state.next_timeout();
            try testing.expectEqual(.inactivity, latched.reason);
            try testing.expectEqual(now, latched.deadline);
        }
    }.body);
}

test "voter state entering the next view resets expired timeout state" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 13, .view_retention = 3 });
            defer env.stop();
            const state = &env.state;
            state.trigger_timeout(.new(1), .leader_timeout);
            try testing.expect(state.next_timeout().deadline <= context.now_ns(io));
            try testing.expect(!(try state.construct_nullify(.new(1), .leader_timeout)).?.retry);
            const retry = state.next_timeout();
            try testing.expectEqual(context.now_ns(io) + 3 * second_ns, retry.deadline);
            try testing.expectEqual(.retry, retry.reason);
            // The next view starts with a fresh leader timeout, not the old retry.
            const nullified = try build_nullification(&env.fixture, .new(.new(13), .new(1)));
            try testing.expect(try state.add_nullification(nullified));
            try testing.expectEqual(2, state.current_view().get());
            const fresh = state.next_timeout();
            try testing.expectEqual(context.now_ns(io) + second_ns, fresh.deadline);
            try testing.expectEqual(.leader_timeout, fresh.reason);
            try testing.expect(fresh.deadline != retry.deadline);
        }
    }.body);
}

/// Skips each of `views` on an inactivity hint (an immediate timeout, a first nullify, and
/// a nullification).
fn skip_views(env: *Env, io: Io, views: []const u64) !void {
    const state = &env.state;
    for (views) |value| {
        const view: View = .new(value);
        try testing.expectEqual(view, state.current_view());
        const now = context.now_ns(io);
        state.trigger_timeout(view, .inactivity);
        const timeout = state.next_timeout();
        try testing.expectEqual(now, timeout.deadline);
        try testing.expectEqual(.inactivity, timeout.reason);
        try testing.expect(!(try state.construct_nullify(view, .inactivity)).?.retry);
        const epoch = state.epoch.get();
        const nullified = try build_nullification(&env.fixture, .new(.new(epoch), view));
        try testing.expect(try state.add_nullification(nullified));
    }
}

/// An inactivity hint at `view` is deferred to the leader deadline (no skip budget left).
fn expect_deferred(env: *Env, io: Io, view: u64) !void {
    const now = context.now_ns(io);
    env.state.trigger_timeout(.new(view), .inactivity);
    const timeout = env.state.next_timeout();
    try testing.expectEqual(now + second_ns, timeout.deadline);
    try testing.expectEqual(.leader_timeout, timeout.reason);
}

test "voter state skip budget allows repeated leaders" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 7, .validators = 2, .skip_budget = 3 });
            defer env.stop();
            const first_leader = env.state.leader_index(.new(1)).?;
            try skip_views(&env, io, &.{ 1, 2, 3 });
            try testing.expectEqual(first_leader, env.state.leader_index(.new(3)).?);
            try expect_deferred(&env, io, 4);
        }
    }.body);
}

test "voter state skip budget counts terms" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 7, .term_length = 5, .skip_budget = 2 });
            defer env.stop();
            try skip_views(&env, io, &.{ 1, 6 });
            try expect_deferred(&env, io, 11);
        }
    }.body);
}

test "voter state finalization restores a pending skip" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .epoch = 9, .skip_budget = 1 });
            defer env.stop();
            const state = &env.state;
            const value = proposal(9, 1, 0, 123);
            const added = try state.add_notarization(try build_notarization(&env.fixture, value));
            try testing.expect(added.added);
            var ready: std.ArrayList(Proposal) = .empty;
            defer ready.deinit(gpa);
            try candidate_views(state, &ready);
            try testing.expectEqual(1, ready.items.len);
            try testing.expect(ready.items[0].eql(value));
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expectEqual(2, state.current_view().get());
            const now = context.now_ns(io);
            // Certified but unfinalized view 1 spends the budget, so the hint waits.
            try expect_deferred(&env, io, 2);
            _ = try state.add_finalization(try build_finalization(&env.fixture, value));
            try testing.expectEqual(2, state.current_view().get());
            const restored = state.next_timeout();
            try testing.expectEqual(now, restored.deadline);
            try testing.expectEqual(.inactivity, restored.reason);
        }
    }.body);
}

test "voter state with skipping disabled defers inactivity to the leader deadline" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .epoch = 7, .skip_budget = 0 });
            defer env.stop();
            try expect_deferred(&env, io, 1);
        }
    }.body);
}

test "voter state with skipping disabled defers a leader nullify" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .epoch = 7, .skip_budget = 0 });
            defer env.stop();
            const state = &env.state;
            const now = context.now_ns(io);
            try testing.expect(try state.set_proposal(.new(1), &proposal(7, 1, 0, 124)));
            state.trigger_timeout(.new(1), .leader_nullify);
            const timeout = state.next_timeout();
            try testing.expectEqual(now + 2 * second_ns, timeout.deadline);
            try testing.expectEqual(.certification_timeout, timeout.reason);
        }
    }.body);
}

test "voter state repeated timeout hints keep the first expired deadline" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 0, .epoch = 12, .view_retention = 3 });
            defer env.stop();
            const state = &env.state;
            const view = state.current_view();
            state.trigger_timeout(view, .leader_nullify);
            const expired = state.next_timeout();
            try io.sleep(.fromSeconds(1), .awake);
            state.trigger_timeout(view, .leader_timeout);
            try testing.expectEqual(expired, state.next_timeout());
            try testing.expect(!(try state.construct_nullify(view, .leader_nullify)).?.retry);
            state.trigger_timeout(view, .leader_timeout);
            try testing.expect((try state.construct_nullify(view, .retry)).?.retry);
        }
    }.body);
}

/// With terms of 5 views: certifies a view-3 parent (payload `payload`), adds a
/// nullification for each of `nullified`, and returns view `child`'s parent payload.
fn anchored_parent_payload(
    io: Io,
    payload: u8,
    nullified: []const u64,
    child: u64,
) !State.PayloadResult {
    var env: Env = undefined;
    try env.start(io, .{ .view_retention = 20, .term_length = 5 });
    defer env.stop();
    const state = &env.state;
    const parent = proposal(1, 3, 0, payload);
    const added = try state.add_notarization(try build_notarization(&env.fixture, parent));
    try testing.expect(added.added);
    try testing.expect(try state.certified(.new(3), true) != null);
    for (nullified) |view| {
        const nullification = try build_nullification(&env.fixture, .new(.new(1), .new(view)));
        try testing.expect(try state.add_nullification(nullification));
    }
    return state.parent_payload(&proposal(1, child, 3, 7));
}

pub fn expect_payload(result: State.PayloadResult, payload: u8) !void {
    try testing.expect(result == .payload);
    try testing.expect(result.payload.eql(Digest.fill(payload)));
}

test "voter state parent payload uses term-skip nullification anchors" {
    try run(struct {
        fn body(io: Io) !void {
            // View 11 starts term 3, so the intra-term skip check does not apply.
            try expect_payload(try anchored_parent_payload(io, 42, &.{ 4, 6 }, 11), 42);
            // View 16 starts term 4: the rest of term 1 and terms 2 and 3 are anchored.
            try expect_payload(try anchored_parent_payload(io, 42, &.{ 4, 6, 11 }, 16), 42);
        }
    }.body);
}

test "voter state parent payload accepts a certified parent covered by a nullification" {
    try run(struct {
        fn body(io: Io) !void {
            // The parent view's own nullification covers the rest of term 1.
            try expect_payload(try anchored_parent_payload(io, 42, &.{ 3, 6 }, 11), 42);
        }
    }.body);
}

test "voter state parent payload reports a missing term anchor" {
    try run(struct {
        fn body(io: Io) !void {
            // Term 2's nullification (view 6) is missing.
            try expect_err(try anchored_parent_payload(io, 9, &.{4}, 11), .{
                .missing_nullification = .{
                    .proposal_view = .new(11),
                    .parent_view = .new(3),
                    .missing_view = .new(6),
                },
            });
        }
    }.body);
}

test "voter state broadcasts each certificate once" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .epoch = 11, .view_retention = 6 });
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            _ = try state.add_notarization(try build_notarization(f, proposal(11, 3, 0, 50)));
            try testing.expect(state.broadcast_notarization(.new(3)) != null);
            try testing.expect(state.broadcast_notarization(.new(3)) == null);
            try testing.expect(state.notarization(.new(3)) != null);
            const nullified = try build_nullification(f, .new(.new(11), .new(4)));
            _ = try state.add_nullification(nullified);
            try testing.expect(state.broadcast_nullification(.new(4)) != null);
            try testing.expect(state.broadcast_nullification(.new(4)) == null);
            try testing.expect(state.nullification(.new(4)) != null);
            _ = try state.add_finalization(try build_finalization(f, proposal(11, 5, 0, 51)));
            try testing.expect(state.broadcast_finalization(.new(5)) != null);
            try testing.expect(state.broadcast_finalization(.new(5)) == null);
            try testing.expect(state.finalization(.new(5)) != null);
        }
    }.body);
}

/// Adds a full-quorum notarization of `value`, which must be new.
pub fn add_notarized(state: *State, f: *const Fixture, value: Proposal) !void {
    const added = try state.add_notarization(try build_notarization(f, value));
    try testing.expect(added.added);
}

pub fn round_at(epoch: u64, view: u64) Rnd {
    return .new(.new(epoch), .new(view));
}

/// commonware `setup_state_with(4, signer 1, epoch 9, retention 10, terms of 5, ...)`.
pub fn terms_of_five_epoch_nine(optimistic_views: u64) Options {
    return .{
        .signer = 1,
        .epoch = 9,
        .term_length = 5,
        .optimistic_views = optimistic_views,
    };
}

test "voter state optimistic views zero disables intra-term lookahead" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_five_epoch_nine(0));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            const parent = try propose_and_notarize_view1(&env, 93);
            try add_notarized(state, f, parent);
            const child = proposal(9, 2, 1, 94);
            try testing.expect(try state.set_proposal(.new(2), &child));
            // With the lookahead disabled no view is inside the issuance window, so
            // verification requests the uncertified parent's notarization.
            const verify = state.try_verify();
            try testing.expect(verify == .resolve);
            try testing.expectEqual(1, verify.resolve.view.get());
            try testing.expectEqual(.notarization, verify.resolve.kind);
            try add_notarized(state, f, child);
            var candidates: std.ArrayList(Proposal) = .empty;
            defer candidates.deinit(gpa);
            try candidate_views(state, &candidates);
            try testing.expectEqual(1, candidates.items.len);
            try testing.expectEqual(1, candidates.items[0].round.view.get());
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expect(state.try_verify() == .ready);
        }
    }.body);
}

test "voter state try verify requests an uncertified cross-term parent" {
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_five_epoch_nine(2));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            // One nullification covers the rest of term 1 and enters term 2 at view 6.
            const nullification = try build_nullification(f, round_at(9, 3));
            try testing.expect(try state.add_nullification(nullification));
            try testing.expectEqual(6, state.current_view().get());
            // An older term-start parent needs a certificate, requested from the leader.
            const child = proposal(9, 6, 2, 44);
            try testing.expect(try state.set_proposal(.new(6), &child));
            const leader = f.participants[state.leader_index(.new(6)).?.get()];
            const verify = state.try_verify();
            try testing.expect(verify == .resolve);
            try testing.expectEqual(6, verify.resolve.proposal.get());
            try testing.expectEqual(2, verify.resolve.view.get());
            try testing.expectEqual(.notarization, verify.resolve.kind);
            try testing.expectEqualDeep(leader, verify.resolve.target);
            // The round deduplicates the request while it is outstanding.
            try testing.expect(state.try_verify() == .wait);
            // Certifying the fetched parent makes the proposal verifiable.
            const parent = proposal(9, 2, 1, 43);
            try add_notarized(state, f, parent);
            try testing.expect(try state.certified(.new(2), true) != null);
            const ready = state.try_verify();
            try testing.expect(ready == .ready);
            try testing.expectEqual(2, ready.ready.context.parent[0].get());
            try testing.expectEqualDeep(parent.payload, ready.ready.context.parent[1]);
            try testing.expectEqualDeep(child, ready.ready.proposal);
        }
    }.body);
}
