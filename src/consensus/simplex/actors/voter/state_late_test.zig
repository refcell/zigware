//! commonware `actors/voter/state.rs` tests from
//! `try_verify_only_resolves_ancestry_once_certification_requested` to the end (the earlier
//! ones are in `state_test.zig`, whose fixture and helpers these share).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const base = @import("state_test.zig");
const cryptography = @import("cryptography");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const state_mod = @import("state.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const Notarize = types.Notarize(Scheme, Digest);
const Nullify = types.Nullify(Scheme);
const Proposal = types.Proposal(Digest);
const View = consensus_types.View;

const Env = base.Env;
const Options = base.Options;
const proposal = base.proposal;
const run = base.run;
const build_notarization = base.build_notarization;
const build_finalization = base.build_finalization;
const build_nullification = base.build_nullification;
const add_notarized = base.add_notarized;
const round_at = base.round_at;
const genesis_view = state_mod.genesis_view;
const CertificateFetch = state_mod.CertificateFetch;
const gpa = testing.allocator;

/// Signer 0 with terms of `term_length` views (commonware's `round_robin_with_term`).
fn terms(term_length: u32, view_retention: u64) Options {
    return .{
        .signer = 0,
        .view_retention = view_retention,
        .term_length = term_length,
        .stall_timeout_ms = 4000,
    };
}

const terms_of_three = terms(3, 20);
const terms_of_five = terms(5, 20);

/// Adds the notarization of `value`, which must be new.
fn notarize_with(env: *Env, value: Proposal) !void {
    const notarized = try build_notarization(&env.fixture, value);
    try testing.expect((try env.state.add_notarization(notarized)).added);
}

/// Adds the finalization of `value`.
fn finalize_with(env: *Env, value: Proposal) !void {
    _ = try env.state.add_finalization(try build_finalization(&env.fixture, value));
}

/// Sets view `view`'s proposal, verifies it, adds its notarization, and certifies it.
fn certify(env: *Env, view: u64, parent: u64, payload: u8) !void {
    const state = &env.state;
    const value = proposal(1, view, parent, payload);
    try testing.expect(try state.set_proposal(.new(view), &value));
    try testing.expect(state.try_verify() == .ready);
    try testing.expect(state.verified(.new(view)));
    try notarize_with(env, value);
    try testing.expect(try state.certified(.new(view), true) != null);
}

test "voter state nullification at a term end skips to the next term start" {
    // commonware `nullification_at_term_end_skips_correctly`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_three);
            defer env.stop();
            const state = &env.state;
            try finalize_with(&env, proposal(1, 1, 0, 10));
            try testing.expectEqual(2, state.current_view().get());
            try finalize_with(&env, proposal(1, 2, 1, 11));
            try testing.expectEqual(3, state.current_view().get());
            const nullified = try build_nullification(&env.fixture, .new(.new(1), .new(3)));
            try testing.expect(try state.add_nullification(nullified));
            try testing.expectEqual(4, state.current_view().get());
        }
    }.body);
}

test "voter state same-term nullify does not block notarize" {
    // commonware `same_term_nullify_does_not_block_notarize`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_five);
            defer env.stop();
            const state = &env.state;
            try testing.expect(!(try state.construct_nullify(.new(1), .leader_timeout)).?.retry);
            const first = proposal(1, 1, 0, 42);
            try notarize_with(&env, first);
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expectEqual(2, state.current_view().get());
            try testing.expect(try state.set_proposal(.new(2), &proposal(1, 2, 1, 43)));
            try testing.expect(state.try_verify() == .ready);
            try testing.expect(state.verified(.new(2)));
            try testing.expect(try state.construct_notarize(.new(2)) != null);
        }
    }.body);
}

test "voter state a recovered parent finalization allows a same-term child finalize" {
    // commonware `recovered_parent_finalization_allows_same_term_child_finalize`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_five);
            defer env.stop();
            const state = &env.state;
            try testing.expect(try state.enter_view(.new(2)));
            const child = proposal(1, 2, 1, 44);
            try testing.expect(try state.set_proposal(.new(2), &child));
            try notarize_with(&env, child);
            try testing.expect(try state.certified(.new(2), true) != null);
            try testing.expectEqual(null, try state.construct_finalize(.new(2)));
            try finalize_with(&env, proposal(1, 1, 0, 45));
            try testing.expect(try state.construct_finalize(.new(2)) != null);
        }
    }.body);
}

test "voter state a certified child without a parent anchor cannot finalize" {
    // commonware `certified_child_without_parent_anchor_cannot_finalize`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_five);
            defer env.stop();
            const state = &env.state;
            const parent = proposal(1, 1, 0, 50);
            try notarize_with(&env, parent);
            const child = proposal(1, 2, 1, 51);
            try testing.expect(try state.set_proposal(.new(2), &child));
            try notarize_with(&env, child);
            const certification: types.Certification = .{
                .round = .new(.new(1), .new(2)),
                .certified = true,
            };
            try state.replay(&.{ .certification = certification });
            // Finalize waits for the parent's explicit certification anchor.
            try testing.expectEqual(null, try state.construct_finalize(.new(2)));
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expect(try state.construct_finalize(.new(2)) != null);
        }
    }.body);
}

test "voter state replay restores term nullify tracking for term safety" {
    // commonware `replay_restores_term_nullify_tracking_for_term_safety`.
    try run(struct {
        fn body(io: Io) !void {
            var baseline: Env = undefined;
            try baseline.start(io, terms_of_five);
            defer baseline.stop();
            try certify(&baseline, 1, 0, 98);
            try testing.expect(try baseline.state.construct_finalize(.new(1)) != null);
            const second = proposal(1, 2, 1, 99);
            try testing.expect(try baseline.state.set_proposal(.new(2), &second));
            try notarize_with(&baseline, second);
            try testing.expect(try baseline.state.certified(.new(2), true) != null);
            try testing.expect(try baseline.state.construct_finalize(.new(2)) != null);

            // The same validator restarts after a nullify at view 1 and a notarize of it.
            var restarted: Env = undefined;
            try restarted.start(io, terms_of_five);
            defer restarted.stop();
            const state = &restarted.state;
            const scheme = &restarted.fixture.schemes[0];
            const nullify = (try Nullify.sign(gpa, scheme, .new(.new(1), .new(1)))).?;
            try state.replay(&.{ .nullify = nullify });
            const first = proposal(1, 1, 0, 98);
            const notarize = (try Notarize.sign(gpa, scheme, first)).?;
            try state.replay(&.{ .notarize = notarize });
            try notarize_with(&restarted, first);
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expect(try state.set_proposal(.new(2), &second));
            try notarize_with(&restarted, second);
            try testing.expect(try state.certified(.new(2), true) != null);
            try testing.expectEqual(null, try state.construct_finalize(.new(2)));
        }
    }.body);
}

const terms_of_twenty = terms(20, 2);

test "voter state a pruned inert nullify does not block finalize" {
    // commonware `pruned_inert_nullify_does_not_block_finalize`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_twenty);
            defer env.stop();
            const state = &env.state;
            const vote = (try state.construct_nullify(.new(1), .leader_timeout)).?;
            try testing.expect(!vote.retry);
            const finalized = proposal(1, 10, 0, 10);
            try finalize_with(&env, finalized);
            try testing.expectEqual(10, state.last_finalized().get());
            try testing.expectEqual(8, state.min_active().get());
            var removed: std.ArrayList(View) = .empty;
            defer removed.deinit(gpa);
            try state.prune(&removed);
            var pruned_one = false;
            for (removed.items) |view| pruned_one = pruned_one or view.get() == 1;
            try testing.expect(pruned_one);
            try certify(&env, 11, 10, 11);
            try testing.expect(try state.construct_finalize(.new(11)) != null);

            // A restart replaying the nullify and the finalization keeps the nullify inert.
            var restarted: Env = undefined;
            try restarted.start(io, terms_of_twenty);
            defer restarted.stop();
            try restarted.state.replay(&.{ .nullify = vote.nullify });
            var replayed = try build_finalization(&env.fixture, finalized);
            defer replayed.deinit(gpa);
            try restarted.state.replay(&.{ .finalization = replayed });
            try finalize_with(&restarted, finalized);
            try testing.expectEqual(10, restarted.state.last_finalized().get());
            try certify(&restarted, 11, 10, 11);
            try testing.expect(try restarted.state.construct_finalize(.new(11)) != null);
        }
    }.body);
}

test "voter state term safety allows finalize in a new term after nullify" {
    // commonware `term_safety_allows_finalize_in_new_term_after_nullify`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_three);
            defer env.stop();
            const state = &env.state;
            try testing.expect(!(try state.construct_nullify(.new(1), .leader_timeout)).?.retry);
            const nullified = try build_nullification(&env.fixture, .new(.new(1), .new(1)));
            try testing.expect(try state.add_nullification(nullified));
            try testing.expectEqual(4, state.current_view().get());
            try certify(&env, 4, 0, 55);
            try testing.expect(try state.construct_finalize(.new(4)) != null);
        }
    }.body);
}

test "voter state views within a term share a leader" {
    // commonware `same_leader_within_term`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_of_three);
            defer env.stop();
            const state = &env.state;
            const leader = state.leader_index(.new(1)).?;
            for ([_]u64{ 1, 2, 3 }, [_]u8{ 10, 11, 12 }) |view, payload| {
                const value = proposal(1, view, view - 1, payload);
                try finalize_with(&env, value);
                try testing.expectEqual(view + 1, state.current_view().get());
                if (view < 3) try testing.expectEqual(leader, state.leader_index(.new(view + 1)).?);
            }
            try testing.expect(state.leader_index(.new(4)) != null);
        }
    }.body);
}

/// commonware `setup_state_with(4, signer 1, epoch 9, view_retention, term_length,
/// optimistic_views, 4)`.
fn epoch_nine(term_length: u32, view_retention: u64, optimistic_views: u64) Options {
    return .{
        .signer = 1,
        .epoch = 9,
        .view_retention = view_retention,
        .term_length = term_length,
        .stall_timeout_ms = 4000,
        .optimistic_views = optimistic_views,
    };
}

/// Certification candidates and parent fetches taken by one `certify_candidates` call.
const Candidates = struct {
    ready: std.ArrayList(Proposal) = .empty,
    fetches: std.ArrayList(CertificateFetch) = .empty,

    fn take(self: *Candidates, state: *base.State) !void {
        self.ready.clearRetainingCapacity();
        self.fetches.clearRetainingCapacity();
        try state.certify_candidates(&self.ready, &self.fetches);
    }

    fn deinit(self: *Candidates) void {
        self.ready.deinit(gpa);
        self.fetches.deinit(gpa);
    }

    fn expect_fetch(self: *const Candidates, proposal_view: u64, view: u64) !void {
        try testing.expectEqual(0, self.ready.items.len);
        try testing.expectEqual(1, self.fetches.items.len);
        try testing.expectEqual(proposal_view, self.fetches.items[0].proposal.get());
        try testing.expectEqual(view, self.fetches.items[0].view.get());
    }

    fn expect_ready(self: *const Candidates, view: u64) !void {
        try testing.expectEqual(1, self.ready.items.len);
        try testing.expectEqual(view, self.ready.items[0].round.view.get());
        try testing.expectEqual(0, self.fetches.items.len);
    }

    fn expect_empty(self: *const Candidates) !void {
        try testing.expectEqual(0, self.ready.items.len);
        try testing.expectEqual(0, self.fetches.items.len);
    }
};

/// Notarizes and certifies view 1 through the candidate path (commonware
/// `certify_first_view`).
fn certify_first_view(env: *Env) !void {
    try add_notarized(&env.state, &env.fixture, proposal(9, 1, 0, 101));
    var candidates: Candidates = .{};
    defer candidates.deinit();
    try candidates.take(&env.state);
    try candidates.expect_ready(1);
    try testing.expect(try env.state.certified(.new(1), true) != null);
}

/// Expects `verify` to request `kind` for `view` on behalf of `proposal_view` from `target`.
fn expect_resolve(
    verify: base.State.Verify,
    proposal_view: u64,
    view: u64,
    target: Scheme.PublicKey,
) !void {
    try testing.expect(verify == .resolve);
    try testing.expectEqual(proposal_view, verify.resolve.proposal.get());
    try testing.expectEqual(view, verify.resolve.view.get());
    try testing.expectEqual(.notarization, verify.resolve.kind);
    try testing.expectEqualDeep(target, verify.resolve.target);
}

test "voter state try verify resolves ancestry only once certification is requested" {
    // commonware `try_verify_only_resolves_ancestry_once_certification_requested`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            const child = proposal(9, 6, 2, 44);
            try add_notarized(state, f, child);
            try candidates.take(state);
            try candidates.expect_ready(6);
            try testing.expectEqualDeep(child, candidates.ready.items[0]);
            try state.set_certify_outstanding(.new(6));
            try testing.expect(try state.add_nullification(
                try build_nullification(f, round_at(9, 3)),
            ));
            try testing.expectEqual(6, state.current_view().get());
            const leader = f.participants[state.leader_index(.new(6)).?.get()];
            try expect_resolve(state.try_verify(), 6, 2, leader);
            const parent = proposal(9, 2, 1, 43);
            try add_notarized(state, f, parent);
            try testing.expect(try state.certified(.new(2), true) != null);
            try base.expect_payload(state.parent_payload(&child), 43);
            const successor = proposal(9, 7, 6, 45);
            try testing.expect(try state.set_proposal(.new(7), &successor));
            try testing.expect(state.rounds.get(.new(6)).?.pending_verification() != null);
            // The scan claims view 6 without sending it, then reaches view 7.
            const verify = state.try_verify();
            try testing.expect(verify == .ready);
            try testing.expectEqualDeep(successor, verify.ready.proposal);
            try testing.expect(state.rounds.get(.new(6)).?.pending_verification() == null);
            try testing.expect(state.try_verify() == .wait);
        }
    }.body);
}

test "voter state optimistic child certification waits for its parent" {
    // commonware `optimistic_child_certification_waits_for_parent`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            const parent = try base.propose_and_notarize_view1(&env, 101);
            try add_notarized(state, f, parent);
            const child = proposal(9, 2, 1, 102);
            try testing.expect(try state.set_proposal(.new(2), &child));
            try testing.expect(state.try_verify() == .ready);
            try testing.expect(state.verified(.new(2)));
            try add_notarized(state, f, child);
            // Only the parent is a candidate: the child waits for its certification.
            try candidates.take(state);
            try candidates.expect_ready(1);
            try testing.expect(try state.certified(.new(1), false) != null);
            try testing.expect(try state.add_nullification(
                try build_nullification(f, round_at(9, 1)),
            ));
            const found = state.find_parent(.new(6));
            try testing.expect(found == .found);
            try testing.expectEqual(genesis_view, found.found[0]);
            try testing.expect(found.found[1].eql(base.genesis()));
            try base.expect_err(state.parent_payload(&proposal(9, 6, 2, 103)), .{
                .parent_not_certified = .{ .proposal_view = .new(6), .parent_view = .new(2) },
            });
            try candidates.take(state);
            try testing.expectEqual(0, candidates.ready.items.len);
        }
    }.body);
}

test "voter state a certification fetch widens a targeted verification request" {
    // commonware `certification_fetch_widens_targeted_verification_request`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 0));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try certify_first_view(&env);
            const p3 = proposal(9, 3, 2, 103);
            try state.set_leader(.new(3), null);
            try testing.expect(try state.set_proposal(.new(3), &p3));
            try expect_resolve(state.try_verify(), 3, 2, f.participants[2]);
            // The notarized view 3 asks every peer for view 2, once.
            try add_notarized(state, f, p3);
            try candidates.take(state);
            try candidates.expect_fetch(3, 2);
            try candidates.take(state);
            try candidates.expect_empty();
            try add_notarized(state, f, proposal(9, 2, 1, 102));
            try candidates.take(state);
            try candidates.expect_ready(2);
            try testing.expect(try state.certified(.new(2), true) != null);
            try candidates.take(state);
            try candidates.expect_ready(3);
        }
    }.body);
}

test "voter state certify candidates fetch across a wide gap" {
    // commonware `certify_candidates_fetches_across_wide_gap`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(10, 20, 2));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try certify_first_view(&env);
            try add_notarized(state, f, proposal(9, 6, 5, 106));
            try testing.expect(!state.leader_is_set(.new(6)));
            try testing.expect(!state.leader_is_set(.new(5)));
            try candidates.take(state);
            try candidates.expect_fetch(6, 5);
            try testing.expect(state.leader_index(.new(2)) != null);
            try add_notarized(state, f, proposal(9, 5, 4, 105));
            try candidates.take(state);
            try candidates.expect_fetch(5, 4);
        }
    }.body);
}

test "voter state certify candidates fetch a term end without a leader" {
    // commonware `certify_candidates_fetches_term_end_without_leader`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 20, 2));
            defer env.stop();
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try certify_first_view(&env);
            try add_notarized(&env.state, &env.fixture, proposal(9, 10, 9, 110));
            try candidates.take(&env.state);
            try candidates.expect_fetch(10, 9);
        }
    }.body);
}

test "voter state certify candidates exempt a term start from the parent precheck" {
    // commonware `certify_candidates_exempts_term_start_from_parent_precheck`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 20, 2));
            defer env.stop();
            var candidates: Candidates = .{};
            defer candidates.deinit();
            const term_start = proposal(9, 6, 1, 61);
            try add_notarized(&env.state, &env.fixture, term_start);
            try candidates.take(&env.state);
            try candidates.expect_ready(6);
            try testing.expectEqualDeep(term_start, candidates.ready.items[0]);
        }
    }.body);
}

test "voter state certify candidates drop malformed candidates" {
    // commonware `certify_candidates_drops_malformed_candidates`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 20, 2));
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try certify_first_view(&env);
            // A parent at its own view, and an intra-term skip of view 2 and 3.
            try add_notarized(state, &env.fixture, proposal(9, 2, 2, 60));
            try add_notarized(state, &env.fixture, proposal(9, 4, 1, 61));
            try candidates.take(state);
            try candidates.expect_empty();
            try testing.expectEqual(0, state.certification_candidates.len());
        }
    }.body);
}

test {
    _ = base;
}
