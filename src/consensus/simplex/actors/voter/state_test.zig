//! commonware `actors/voter/state.rs` tests, on the deterministic runtime (the state reads
//! time through `std.Io`).

const std = @import("std");
const testing = std.testing;
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
const State = state_mod.State(Scheme, Elector, Digest);
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

fn genesis() Digest {
    return .fill(0);
}

fn proposal(epoch: u64, view: u64, parent: u64, payload: u8) Proposal {
    return .init(.new(.new(epoch), .new(view)), .new(parent), .fill(payload));
}

fn build_notarization(f: *const Fixture, value: Proposal) !Notarization {
    var votes: [4]Notarize = undefined;
    for (&votes, 0..) |*vote, i| vote.* = (try Notarize.sign(gpa, &f.schemes[i], value)).?;
    return Notarization.from_votes(gpa, &f.verifier, &votes, sequential);
}

fn build_finalization(f: *const Fixture, value: Proposal) !Finalization {
    var votes: [4]Finalize = undefined;
    for (&votes, 0..) |*vote, i| vote.* = (try Finalize.sign(gpa, &f.schemes[i], value)).?;
    return Finalization.from_votes(gpa, &f.verifier, &votes, sequential);
}

fn build_nullification(f: *const Fixture, round: Rnd) !Nullification {
    var votes: [4]Nullify = undefined;
    for (&votes, 0..) |*vote, i| vote.* = (try Nullify.sign(gpa, &f.schemes[i], round)).?;
    return Nullification.from_votes(gpa, &f.verifier, &votes, sequential);
}

const Options = struct {
    /// Index of the signing scheme, or null for the verifier.
    signer: ?usize = null,
    epoch: u64 = 1,
    view_retention: u64 = 10,
    term_length: u32 = 1,
    stall_timeout_secs: u64 = 30,
    optimistic_views: u64 = 0,
    leader_timeout_secs: u64 = 1,
    certification_timeout_secs: u64 = 2,
    timeout_retry_secs: u64 = 3,
};

/// A 4-participant fixture and a state that entered view 1. Must not move once started.
const Env = struct {
    fixture: Fixture,
    elector: Elector,
    state: State,

    fn start(self: *Env, io: Io, options: Options) !void {
        var rng = utils.rng.test_rng();
        self.fixture = try ed25519.fixture(Digest, gpa, &rng, "ns", 4);
        errdefer self.fixture.deinit(gpa);
        var builder = elector.RoundRobin(cryptography.Sha256).default();
        if (options.term_length > 1) builder = builder.with_term(
            .new(utils.NonZero(u32).init(options.term_length).?),
            .from_secs(options.stall_timeout_secs),
            .new(options.optimistic_views),
        );
        self.elector = try builder.build(gpa, 4);
        const scheme = if (options.signer) |i| &self.fixture.schemes[i] else &self.fixture.verifier;
        self.state = State.init(gpa, io, .{
            .scheme = scheme,
            .elector = self.elector,
            .epoch = .new(options.epoch),
            .view_retention = .new(options.view_retention),
            .leader_timeout = .from_secs(options.leader_timeout_secs),
            .certification_timeout = .from_secs(options.certification_timeout_secs),
            .timeout_retry = .from_secs(options.timeout_retry_secs),
            .skip_budget = 4,
        });
        try self.state.set_genesis(genesis());
    }

    fn stop(self: *Env) void {
        self.state.deinit();
        self.elector.deinit(gpa);
        self.fixture.deinit(gpa);
    }
};

fn run(comptime function: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
}

fn expect_err(result: anytype, expected: state_mod.ParentPayloadError) !void {
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

fn candidate_views(state: *State, out: *std.ArrayList(Proposal)) !void {
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
    .stall_timeout_secs = 4,
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
                .leader_timeout_secs = 10,
                .certification_timeout_secs = 10,
                .timeout_retry_secs = 30,
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
