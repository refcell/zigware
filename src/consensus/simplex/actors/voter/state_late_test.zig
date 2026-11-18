//! commonware `actors/voter/state.rs` tests from
//! `try_verify_only_resolves_ancestry_once_certification_requested` to the end (the earlier
//! ones are in `state_test.zig`, whose fixture and helpers these share).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const assert = std.debug.assert;
const base = @import("state_test.zig");
const parallel = @import("parallel");
const context = @import("../context.zig");
const elector = @import("../../elector.zig");
const utils = @import("utils");
const cryptography = @import("cryptography");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const state_mod = @import("state.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const Notarize = types.Notarize(Scheme, Digest);
const Nullify = types.Nullify(Scheme);
const Finalize = types.Finalize(Scheme, Digest);
const Proposal = types.Proposal(Digest);
const View = consensus_types.View;
const Rnd = consensus_types.Round;
const Participant = consensus_types.Participant;

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

/// Records `payload` as our own proposal for `view` on `parent`.
fn record_proposed(env: *Env, view: u64, parent: u64, payload: u8) !void {
    _ = try env.state.create_round(.new(view));
    try testing.expect(env.state.record_proposed(proposal(9, view, parent, payload)));
}

/// Sets, verifies, and votes to notarize the peer proposal `value`.
fn verify_and_vote(env: *Env, value: Proposal) !void {
    const state = &env.state;
    try testing.expect(try state.set_proposal(value.round.view, &value));
    try testing.expect(state.try_verify() == .ready);
    try testing.expect(state.verified(value.round.view));
    try testing.expect(try state.construct_notarize(value.round.view) != null);
}

/// Expects `verify` to be ready for `value` on parent `parent` with `parent_payload`.
fn expect_ready(verify: base.State.Verify, value: Proposal, parent: u64, payload: Digest) !void {
    try testing.expect(verify == .ready);
    try testing.expectEqualDeep(value, verify.ready.proposal);
    try testing.expectEqual(parent, verify.ready.context.parent[0].get());
    try testing.expect(verify.ready.context.parent[1].eql(payload));
}

test "voter state optimistic views bound the chain length" {
    // commonware `optimistic_views_bounds_chain_length`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 1));
            defer env.stop();
            const state = &env.state;
            try record_proposed(&env, 1, 0, 95);
            const second = proposal(9, 2, 1, 96);
            try testing.expect(try state.set_proposal(.new(2), &second));
            // A future same-term view waits for our notarize vote on its parent.
            try testing.expect(state.try_verify() == .wait);
            try testing.expect(try state.construct_notarize(.new(1)) != null);
            const verify = state.try_verify();
            try expect_ready(verify, second, 1, .fill(95));
            try testing.expectEqual(2, verify.ready.context.round.view.get());
            try testing.expect(state.verified(.new(2)));
            try testing.expect(try state.construct_notarize(.new(2)) != null);
            // One optimistic view: a second hop past the anchor waits.
            try testing.expect(try state.set_proposal(.new(3), &proposal(9, 3, 2, 97)));
            try testing.expect(state.try_verify() == .wait);
        }
    }.body);
}

/// A dynamic elector that panics when asked to elect past view 1 without a certificate
/// (commonware's `RequireCertificateElector`).
const RequireCertificateElector = struct {
    pub const mode: elector.Mode = .dynamic;
    pub const Input = ?*const Scheme.Certificate;

    pub fn terms(_: RequireCertificateElector) elector.Terms {
        return .stable(.new(utils.NonZero(u32).init(5).?), .from_secs(30), .new(1));
    }

    pub fn elect(_: RequireCertificateElector, round: Rnd, certificate: Input) Participant {
        if (certificate == null and round.view.get() != 1) {
            @panic("certificate required after view 1");
        }
        return .init(0);
    }
};

test "voter state an optimistic successor inherits its leader without a null election" {
    // commonware `optimistic_successor_inherits_leader_without_none_election`.
    try run(struct {
        fn body(io: Io) !void {
            var rng = utils.rng.test_rng();
            var fixture = try ed25519.fixture(Digest, gpa, &rng, "ns", 4);
            defer fixture.deinit(gpa);
            const Dynamic = state_mod.State(Scheme, RequireCertificateElector, Digest);
            var state = Dynamic.init(gpa, io, .{
                .scheme = &fixture.verifier,
                .elector = .{},
                .epoch = .new(99),
                .view_retention = .new(10),
                .leader_timeout = .from_millis(1000),
                .certification_timeout = .from_millis(2000),
                .timeout_retry = .from_millis(3000),
                .skip_budget = 4,
            });
            defer state.deinit();
            try state.set_genesis(base.genesis());
            try testing.expect(try state.set_proposal(.new(1), &proposal(99, 1, 0, 9)));
            try testing.expect(state.leader_is_set(.new(2)));
        }
    }.body);
}

test "voter state catching up from a parent finalization allows a child notarize" {
    // commonware `catch_up_from_parent_finalization_allows_child_notarize`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const parent = proposal(9, 1, 0, 111);
            try testing.expect((try state.add_finalization(
                try build_finalization(&env.fixture, parent),
            )).added);
            try testing.expectEqual(2, state.current_view().get());
            const child = proposal(9, 2, 1, 112);
            try testing.expect(try state.set_proposal(.new(2), &child));
            try expect_ready(state.try_verify(), child, 1, parent.payload);
            try testing.expect(state.verified(.new(2)));
            try testing.expect(try state.construct_notarize(.new(2)) != null);
        }
    }.body);
}

test "voter state catching up from a parent certification allows a child notarize" {
    // commonware `catch_up_from_parent_certification_allows_child_notarize`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const parent = proposal(9, 1, 0, 113);
            try add_notarized(state, &env.fixture, parent);
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expectEqual(2, state.current_view().get());
            const child = proposal(9, 2, 1, 114);
            try testing.expect(try state.set_proposal(.new(2), &child));
            try expect_ready(state.try_verify(), child, 1, parent.payload);
            try testing.expect(state.verified(.new(2)));
            try testing.expect(try state.construct_notarize(.new(2)) != null);
        }
    }.body);
}

test "voter state the forwardable proposal tracks certificate state" {
    // commonware `forwardable_proposal_tracks_certificate_state`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .epoch = 13 });
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            const view: View = .new(1);
            const value = proposal(13, 1, 0, 116);
            try add_notarized(state, f, value);
            try testing.expect(state.forwardable_proposal(view) != null);
            try testing.expect(try state.certified(view, false) != null);
            try testing.expect(state.forwardable_proposal(view) == null);
            try testing.expect(try state.add_nullification(
                try build_nullification(f, round_at(13, 1)),
            ));
            try testing.expectEqual(2, state.current_view().get());
            try testing.expect(state.forwardable_proposal(view) == null);
            try testing.expect((try state.add_finalization(
                try build_finalization(f, value),
            )).added);
            try testing.expect(state.forwardable_proposal(view) != null);
        }
    }.body);
}

test "voter state a displaced ancestor does not supersede verification" {
    // commonware `displaced_ancestor_does_not_supersede_verification`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            const c2 = proposal(9, 2, 1, 124);
            try verify_and_vote(&env, proposal(9, 1, 0, 123));
            try verify_and_vote(&env, c2);
            const d3 = proposal(9, 3, 2, 125);
            try testing.expect(try state.set_proposal(.new(3), &d3));
            try expect_ready(state.try_verify(), d3, 2, c2.payload);
            // A conflicting view-1 notarization displaces D3's grandparent, not its binding.
            try add_notarized(state, f, proposal(9, 1, 0, 126));
            try testing.expect(state.parent_payload(&d3) == .err);
            try testing.expect(!state.verification_superseded(.new(3)));
            try add_notarized(state, f, c2);
            try base.expect_payload(state.parent_payload(&d3), 124);
            try testing.expect(state.verified(.new(3)));
            try testing.expect(try state.construct_notarize(.new(3)) != null);
        }
    }.body);
}

test "voter state a matching notarization does not supersede verification" {
    // commonware `matching_notarization_does_not_supersede_verification`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const p1 = proposal(9, 1, 0, 123);
            try testing.expect(try state.set_proposal(.new(1), &p1));
            try testing.expect(state.try_verify() == .ready);
            try add_notarized(state, &env.fixture, p1);
            try testing.expect(!state.verification_superseded(.new(1)));
            try testing.expect(state.verified(.new(1)));
            try testing.expect(try state.construct_notarize(.new(1)) != null);
        }
    }.body);
}

/// Verifies and votes for a view-1 parent of `parent_payload`, then starts verifying the
/// view-2 child of `child_payload` on it.
fn verify_child_of(env: *Env, parent_payload: u8, child_payload: u8) !Proposal {
    const state = &env.state;
    try verify_and_vote(env, proposal(9, 1, 0, parent_payload));
    const child = proposal(9, 2, 1, child_payload);
    try testing.expect(try state.set_proposal(.new(2), &child));
    try expect_ready(state.try_verify(), child, 1, .fill(parent_payload));
    return child;
}

test "voter state a pending optimistic child verification rejects a replaced parent" {
    // commonware `pending_optimistic_child_verification_rejects_replaced_parent_notarization`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const child = try verify_child_of(&env, 117, 118);
            const replaced = try build_notarization(&env.fixture, proposal(9, 1, 0, 119));
            const added = try state.add_notarization(replaced);
            try testing.expect(added.added);
            try testing.expect(added.equivocator != null);
            try base.expect_payload(state.parent_payload(&child), 119);
            try testing.expect(!state.verified(.new(2)));
            try testing.expectEqual(null, try state.construct_notarize(.new(2)));
        }
    }.body);
}

test "voter state a failed optimistic child verification ignores a replaced parent verdict" {
    // commonware `failed_optimistic_child_verification_ignores_replaced_parent_verdict`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const child = try verify_child_of(&env, 120, 121);
            try add_notarized(state, &env.fixture, proposal(9, 1, 0, 122));
            try base.expect_payload(state.parent_payload(&child), 122);
            state.verification_failed(.new(2), .invalid_proposal);
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expectEqual(2, state.current_view().get());
            try testing.expect(state.next_timeout().reason != .invalid_proposal);
        }
    }.body);
}

test "voter state a failed verification ignores a replaced proposal verdict" {
    // commonware `failed_verification_ignores_replaced_proposal_verdict`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            try testing.expect(try state.set_proposal(.new(1), &proposal(9, 1, 0, 127)));
            try testing.expect(state.try_verify() == .ready);
            try add_notarized(state, &env.fixture, proposal(9, 1, 0, 128));
            state.verification_failed(.new(1), .invalid_proposal);
            try testing.expect(state.next_timeout().reason != .invalid_proposal);
        }
    }.body);
}

test "voter state a verified optimistic child notarize rejects a replaced parent finalization" {
    // commonware `verified_optimistic_child_notarize_rejects_replaced_parent_finalization`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const child = try verify_child_of(&env, 120, 121);
            try testing.expect(state.verified(.new(2)));
            const replaced = try build_finalization(&env.fixture, proposal(9, 1, 0, 122));
            const added = try state.add_finalization(replaced);
            try testing.expect(added.added);
            try testing.expect(added.equivocator != null);
            try base.expect_payload(state.parent_payload(&child), 122);
            try testing.expectEqual(null, try state.construct_notarize(.new(2)));
        }
    }.body);
}

test "voter state a failed certification blocks an optimistic child notarize" {
    // commonware `failed_certification_blocks_optimistic_child_notarize`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 1));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            const parent = proposal(9, 1, 0, 116);
            try verify_and_vote(&env, parent);
            try add_notarized(state, f, parent);
            const child = proposal(9, 2, 1, 117);
            try testing.expect(try state.set_proposal(.new(2), &child));
            try testing.expect(state.try_verify() == .ready);
            try testing.expect(state.verified(.new(2)));
            try testing.expect(try state.certified(.new(1), false) != null);
            try testing.expect(try state.construct_nullify(.new(1), .failed_certification) != null);
            // A failed-certified parent must not unlock the optimistic child's notarize.
            try testing.expectEqual(null, try state.construct_notarize(.new(2)));
            try add_notarized(state, f, child);
            try candidates.take(state);
            try testing.expectEqual(0, candidates.ready.items.len);
            try testing.expect((try state.add_finalization(
                try build_finalization(f, parent),
            )).added);
            try testing.expect(try state.construct_notarize(.new(2)) != null);
            try candidates.take(state);
            try testing.expectEqual(1, candidates.ready.items.len);
            try testing.expectEqualDeep(child, candidates.ready.items[0]);
        }
    }.body);
}

test "voter state a replayed failed ancestor blocks its descendant until finalization" {
    // commonware `replayed_failed_ancestor_blocks_direct_descendant_until_finalization`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const ancestor = proposal(9, 1, 0, 116);
            const descendant = proposal(9, 2, 1, 117);
            try add_notarized(state, &env.fixture, ancestor);
            try add_notarized(state, &env.fixture, descendant);
            const failed: types.Artifact(Scheme, Digest) = .{
                .certification = .{ .round = ancestor.round, .certified = false },
            };
            try state.replay(&failed);
            try testing.expectEqual(null, state.optimistic_ancestry_payload(.new(2)));
            try testing.expect((try state.add_finalization(
                try build_finalization(&env.fixture, descendant),
            )).added);
            const payload = state.optimistic_ancestry_payload(.new(2)).?;
            try testing.expect(payload.eql(descendant.payload));
        }
    }.body);
}

test "voter state a failed certification blocks a locally proposed optimistic child" {
    // commonware `failed_certification_blocks_locally_proposed_optimistic_child_notarize`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(5, 10, 1);
            options.signer = 2;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            const parent = try base.propose_and_notarize_view1(&env, 118);
            const request = state.try_propose().?.context();
            try testing.expectEqual(2, request.view().get());
            try testing.expectEqual(1, request.parent[0].get());
            try testing.expect(request.parent[1].eql(parent.payload));
            try add_notarized(state, &env.fixture, parent);
            try testing.expect(try state.certified(.new(1), false) != null);
            try testing.expect(try state.construct_nullify(.new(1), .failed_certification) != null);
            const child = Proposal.init(request.round, request.parent[0], .fill(119));
            try testing.expect(!state.proposed(&request, child.payload));
            try testing.expect(state.record_proposed(child));
            try testing.expectEqual(null, try state.construct_notarize(.new(2)));
        }
    }.body);
}

test "voter state same-term notarize respects the outbound window" {
    // commonware `same_term_notarize_respects_outbound_window`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(5, 10, 2);
            options.signer = 0;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            // Views 1 to 3 are in the outbound window from current view 1; view 4 is not.
            for (1..5) |view| {
                const value = proposal(9, view, view - 1, @intCast(view));
                try testing.expect(try state.set_proposal(.new(view), &value));
                try testing.expect(state.verified(.new(view)));
                const vote = try state.construct_notarize(.new(view));
                try testing.expectEqual(view < 4, vote != null);
            }
        }
    }.body);
}

test "voter state certify candidates wait for parent certification" {
    // commonware `certify_candidates_wait_for_parent_certification`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 1));
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try add_notarized(state, &env.fixture, proposal(9, 1, 0, 98));
            try add_notarized(state, &env.fixture, proposal(9, 2, 1, 99));
            try candidates.take(state);
            try candidates.expect_ready(1);
            try testing.expect(try state.certified(.new(1), true) != null);
            try candidates.take(state);
            try candidates.expect_ready(2);
        }
    }.body);
}

test "voter state blocked certification candidates wake parent first" {
    // commonware `blocked_certification_candidates_wake_parent_first`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(10, 10, 3));
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try certify_first_view(&env);
            const proposals = [_]Proposal{
                proposal(9, 2, 1, 102),
                proposal(9, 3, 2, 103),
                proposal(9, 4, 3, 104),
            };
            var index = proposals.len;
            while (index > 0) {
                index -= 1;
                try add_notarized(state, &env.fixture, proposals[index]);
            }
            for (proposals) |value| {
                try candidates.take(state);
                try candidates.expect_ready(value.round.view.get());
                try testing.expectEqualDeep(value, candidates.ready.items[0]);
                // Parent-blocked descendants stay dormant.
                try testing.expectEqual(0, state.certification_candidates.len());
                try testing.expect(try state.certified(value.round.view, true) != null);
            }
        }
    }.body);
}

test "voter state finalization wakes a child after a failed parent certification" {
    // commonware `finalization_wakes_child_after_failed_parent_certification`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_nine(5, 10, 2));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try certify_first_view(&env);
            const parent = proposal(9, 2, 1, 102);
            const child = proposal(9, 3, 2, 103);
            try add_notarized(state, f, parent);
            try add_notarized(state, f, child);
            try candidates.take(state);
            try candidates.expect_ready(2);
            try testing.expectEqual(0, state.certification_candidates.len());
            try testing.expect(try state.certified(.new(2), false) != null);
            try candidates.take(state);
            try testing.expectEqual(0, candidates.ready.items.len);
            try testing.expect((try state.add_finalization(
                try build_finalization(f, parent),
            )).added);
            try candidates.take(state);
            try testing.expectEqual(1, candidates.ready.items.len);
            try testing.expectEqualDeep(child, candidates.ready.items[0]);
        }
    }.body);
}

test "voter state the optimistic frontier slides with a direct notarization" {
    // commonware `optimistic_frontier_slides_with_direct_notarization`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(5, 10, 2);
            options.epoch = 10;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            _ = try base.propose_and_notarize_view1(&env, 98);
            const second = proposal(10, 2, 1, 99);
            try testing.expect(try state.set_proposal(.new(2), &second));
            try testing.expect(state.verified(.new(2)));
            try testing.expect(try state.construct_notarize(.new(2)) != null);
            // The issuance window first stops at view 3.
            try testing.expect(state.rounds.get(.new(3)) != null);
            try testing.expect(state.rounds.get(.new(4)) == null);
            try add_notarized(state, &env.fixture, second);
            try testing.expect(state.rounds.get(.new(4)) != null);
        }
    }.body);
}

test "voter state the optimistic frontier walk spans a whole term" {
    // commonware `optimistic_frontier_walk_does_not_scan_rounds`, without its
    // `issuance_window_probes` counter, which comes with the actor metrics.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(131, 10, 64);
            options.epoch = 10;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            for (1..66) |view| {
                const value = proposal(10, view, view - 1, @truncate(view));
                try testing.expect(try state.set_proposal(.new(view), &value));
            }
            const held = state.rounds.get(.new(65)).?.proposal().?.*;
            try add_notarized(state, &env.fixture, held);
            for (66..131) |view| try testing.expect(state.leader_index(.new(view)) != null);
            try testing.expect(state.leader_index(.new(131)) == null);
        }
    }.body);
}

test "voter state the optimistic frontier slides despite a far-future round" {
    // commonware `optimistic_frontier_slides_despite_far_future_round`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(20, 10, 2);
            options.epoch = 10;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(10, 10, 9, 96));
            try add_notarized(state, &env.fixture, proposal(10, 1, 0, 97));
            for (2..5) |view| try testing.expect(state.leader_index(.new(view)) != null);
        }
    }.body);
}

test "voter state an indirect notarization still requires certification for finalize" {
    // commonware `indirect_notarization_still_requires_certification_for_finalize`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(5, 10, 1);
            options.epoch = 10;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            const parent = try base.propose_and_notarize_view1(&env, 101);
            const descendant = proposal(10, 2, 1, 102);
            try testing.expect(try state.set_proposal(.new(2), &descendant));
            try testing.expect(state.verified(.new(2)));
            const added = try state.add_notarization(
                try build_notarization(&env.fixture, descendant),
            );
            try testing.expect(added.added);
            try testing.expect(added.equivocator == null);
            try testing.expect(state.optimistic_ancestry_payload(.new(1)).?.eql(.fill(101)));
            const round = state.rounds.get(.new(1)).?;
            try testing.expect(round.proposal() != null);
            try testing.expect(round.is_verified());
            try testing.expectEqual(null, try state.construct_finalize(.new(1)));
            try add_notarized(state, &env.fixture, parent);
            try testing.expectEqual(null, try state.construct_finalize(.new(1)));
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expect(try state.construct_finalize(.new(1)) != null);
        }
    }.body);
}

test "voter state an indirect notarization requires verified unequivocated ancestors" {
    // commonware `indirect_notarization_requires_verified_unequivocated_ancestors`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(5, 10, 2);
            options.epoch = 11;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            _ = try base.propose_and_notarize_view1(&env, 111);
            _ = try state.create_round(.new(2));
            try testing.expect(state.record_proposed(proposal(11, 2, 1, 112)));
            try testing.expect(try state.construct_notarize(.new(2)) != null);
            // A conflicting view-2 proposal equivocates the round.
            try testing.expect(!try state.set_proposal(.new(2), &proposal(11, 2, 1, 113)));
            const third = proposal(11, 3, 2, 114);
            try testing.expect(try state.set_proposal(.new(3), &third));
            try testing.expect(state.verified(.new(3)));
            try add_notarized(state, &env.fixture, third);
            try testing.expectEqual(null, state.optimistic_ancestry_payload(.new(2)));
        }
    }.body);
}

/// Signer 0, epoch 11, terms of 5 views (commonware `setup_state_with(4, 0, 11, ...)`).
fn epoch_eleven(view_retention: u64, optimistic_views: u64) Options {
    var options = epoch_nine(5, view_retention, optimistic_views);
    options.signer = 0;
    options.epoch = 11;
    return options;
}

/// A notarization of `value` from every signer but signer 0 (commonware's `schemes[1..]`).
fn notarization_without_signer0(f: *const base.Fixture, value: Proposal) !base.Notarization {
    var votes: [3]Notarize = undefined;
    for (&votes, f.schemes[1..4]) |*vote, *scheme| {
        vote.* = (try Notarize.sign(gpa, scheme, value)).?;
    }
    return base.Notarization.from_votes(gpa, &f.verifier, &votes, parallel.sequential);
}

test "voter state an optimistic notarize requires parent participation within the term" {
    // commonware `optimistic_notarize_requires_parent_participation_within_term`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_eleven(10, 2));
            defer env.stop();
            const state = &env.state;
            try testing.expect(try state.enter_view(.new(2)));
            _ = try state.create_round(.new(2));
            try testing.expect(state.record_proposed(proposal(11, 2, 1, 118)));
            try testing.expectEqual(null, try state.construct_notarize(.new(2)));
            _ = try state.create_round(.new(1));
            try testing.expect(state.record_proposed(proposal(11, 1, 0, 119)));
            try testing.expect(try state.construct_notarize(.new(1)) != null);
            try testing.expect(try state.construct_notarize(.new(2)) != null);
        }
    }.body);
}

test "voter state an optimistic notarize accepts a directly notarized parent" {
    // commonware `optimistic_notarize_accepts_directly_notarized_parent`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_eleven(10, 2));
            defer env.stop();
            const state = &env.state;
            const parent = try notarization_without_signer0(&env.fixture, proposal(11, 1, 0, 120));
            try testing.expect((try state.add_notarization(parent)).added);
            try testing.expect(try state.set_proposal(.new(2), &proposal(11, 2, 1, 121)));
            try testing.expect(state.verified(.new(2)));
            try testing.expect(try state.construct_notarize(.new(2)) != null);
        }
    }.body);
}

test "voter state an optimistic notarize blocks on a parent's failed certification" {
    // commonware `optimistic_notarize_blocks_on_parent_failed_certification`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_eleven(10, 2));
            defer env.stop();
            const state = &env.state;
            const parent = try notarization_without_signer0(&env.fixture, proposal(11, 1, 0, 122));
            try testing.expect((try state.add_notarization(parent)).added);
            try testing.expect(try state.certified(.new(1), false) != null);
            try testing.expect(try state.set_proposal(.new(2), &proposal(11, 2, 1, 123)));
            try testing.expect(state.verified(.new(2)));
            try testing.expectEqual(null, try state.construct_notarize(.new(2)));
        }
    }.body);
}

test "voter state a finalization anchors the optimistic issuance window" {
    // commonware `finalization_anchors_optimistic_issuance_window`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_eleven(10, 1));
            defer env.stop();
            const state = &env.state;
            try testing.expect((try state.add_finalization(
                try build_finalization(&env.fixture, proposal(11, 1, 0, 130)),
            )).added);
            try testing.expect(state.notarization(.new(1)) == null);
            for ([_]u64{ 2, 3 }, [_]u8{ 131, 132 }) |view, payload| {
                const value = proposal(11, view, view - 1, payload);
                try testing.expect(try state.set_proposal(.new(view), &value));
                try testing.expect(state.verified(.new(view)));
                // The finalized view 1 anchors the window for both views.
                try testing.expect(try state.construct_notarize(.new(view)) != null);
            }
        }
    }.body);
}

test "voter state prune drops stale optimistic anchors" {
    // commonware `prune_drops_stale_optimistic_anchors`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_eleven(1, 2));
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(11, 1, 0, 140));
            try add_notarized(state, &env.fixture, proposal(11, 2, 1, 141));
            try testing.expect(state.in_issuance_window(.new(4)));
            try testing.expect((try state.add_finalization(
                try build_finalization(&env.fixture, proposal(11, 4, 3, 142)),
            )).added);
            var removed: std.ArrayList(View) = .empty;
            defer removed.deinit(gpa);
            try state.prune(&removed);
            try testing.expectEqualSlices(View, &.{ .new(1), .new(2) }, removed.items);
            // Pruned views must not anchor the issuance window.
            try testing.expect(!state.in_issuance_window(.new(4)));
        }
    }.body);
}

test "voter state an optimistic finalize blocks on an uncertified parent" {
    // commonware `optimistic_finalize_blocks_on_uncertified_parent`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, epoch_eleven(10, 2));
            defer env.stop();
            const state = &env.state;
            const parent = try notarization_without_signer0(&env.fixture, proposal(11, 1, 0, 124));
            try testing.expect((try state.add_notarization(parent)).added);
            const child = proposal(11, 2, 1, 125);
            try testing.expect(try state.set_proposal(.new(2), &child));
            try testing.expect(state.verified(.new(2)));
            try testing.expect(try state.construct_notarize(.new(2)) != null);
            try add_notarized(state, &env.fixture, child);
            try testing.expect(try state.certified(.new(2), true) != null);
            // Finalize waits for the parent's explicit certification.
            try testing.expectEqual(null, try state.construct_finalize(.new(2)));
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expect(try state.construct_finalize(.new(2)) != null);
        }
    }.body);
}

test "voter state a failed certification still nullifies the current view" {
    // commonware `failed_certification_still_nullifies_current_view`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_eleven(10, 1);
            options.epoch = 13;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(13, 1, 0, 115));
            try testing.expectEqual(1, state.current_view().get());
            try testing.expect(try state.certified(.new(1), false) != null);
            const first = (try state.construct_nullify(.new(1), .failed_certification)).?;
            try testing.expect(!first.retry);
            try testing.expectEqual(1, first.nullify.round.view.get());
            const retry = (try state.construct_nullify(.new(1), .retry)).?;
            try testing.expect(retry.retry);
            try testing.expectEqual(1, retry.nullify.round.view.get());
        }
    }.body);
}

test "voter state a nullification sets the entry certificate" {
    // commonware `nullification_sets_entry_certificate`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .view_retention = 20, .term_length = 5 });
            defer env.stop();
            const state = &env.state;
            const nullified = try build_nullification(&env.fixture, round_at(1, 1));
            try testing.expect(try state.add_nullification(nullified));
            try testing.expectEqual(6, state.current_view().get());
            var best = (try state.get_best_certificate()).?;
            defer best.deinit(gpa);
            try testing.expect(best == .nullification);
            try testing.expectEqual(1, best.nullification.round.view.get());
        }
    }.body);
}

test "voter state parent payload returns the genesis payload" {
    // commonware `parent_payload_returns_genesis_payload`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .view_retention = 5 });
            defer env.stop();
            const state = &env.state;
            const nullified = try build_nullification(&env.fixture, round_at(1, 1));
            try testing.expect(try state.add_nullification(nullified));
            try base.expect_payload(state.parent_payload(&proposal(1, 2, 0, 8)), 0);
        }
    }.body);
}

test "voter state parent payload rejects a parent before the last finalization" {
    // commonware `parent_payload_rejects_parent_before_finalized`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .view_retention = 5 });
            defer env.stop();
            const state = &env.state;
            try finalize_with(&env, proposal(1, 3, 0, 1));
            try base.expect_err(state.parent_payload(&proposal(1, 4, 2, 6)), .{
                .parent_before_finalized = .{
                    .proposal_view = .new(4),
                    .parent_view = .new(2),
                    .last_finalized = .new(3),
                },
            });
        }
    }.body);
}

/// The verifier's state with slow timeouts (commonware's fast-path test configuration).
fn slow_timeouts(term_length: u32, view_retention: u64) Options {
    return .{
        .view_retention = view_retention,
        .term_length = term_length,
        .stall_timeout_ms = 4000,
        .optimistic_views = if (term_length > 1) 2 else 0,
        .leader_timeout_ms = 10_000,
        .certification_timeout_ms = 10_000,
        .timeout_retry_ms = 30_000,
    };
}

test "voter state try verify fast-paths an intra-term view skip" {
    // commonware `try_verify_fast_paths_intra_term_view_skip`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, slow_timeouts(5, 20));
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 2, 0, 1));
            try testing.expect(state.leader_index(.new(3)) != null);
            try testing.expect(try state.set_proposal(.new(3), &proposal(1, 3, 1, 2)));
            const initial = state.next_timeout();
            try testing.expect(initial.deadline > context.now_ns(io));
            try testing.expect(state.try_verify() == .wait);
            try testing.expectEqual(null, try state.construct_nullify(.new(3), .leader_timeout));
            try testing.expectEqual(initial, state.next_timeout());
        }
    }.body);
}

test "voter state try verify fast-paths a parent before the last finalization" {
    // commonware `try_verify_fast_paths_parent_before_finalized`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, slow_timeouts(1, 5));
            defer env.stop();
            const state = &env.state;
            try finalize_with(&env, proposal(1, 3, 0, 1));
            try testing.expectEqual(4, state.current_view().get());
            try testing.expect(try state.set_proposal(.new(4), &proposal(1, 4, 2, 6)));
            try testing.expect(state.next_timeout().deadline > context.now_ns(io));
            try testing.expect(state.try_verify() != .ready);
            // The invalid proposal expires the view's timeout at once.
            try testing.expect(state.next_timeout().deadline <= context.now_ns(io));
        }
    }.body);
}

/// Signer 0 in epoch `epoch` with rotating leaders and a retention of `view_retention`.
fn signer0(epoch: u64, view_retention: u64) Options {
    return .{ .signer = 0, .epoch = epoch, .view_retention = view_retention };
}

test "voter state a replayed local notarize restores the verified leader proposal" {
    // commonware `replayed_local_notarize_restores_verified_leader_proposal`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, signer0(2, 5));
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            const value = proposal(2, 2, 1, 42);
            const local_vote = (try Notarize.sign(gpa, &env.fixture.schemes[0], value)).?;
            const parent = proposal(2, 1, 0, 41);
            try add_notarized(state, &env.fixture, parent);
            try testing.expect(try state.certified(.new(1), true) != null);
            try candidates.take(state);
            try testing.expectEqual(0, state.leader_index(.new(2)).?.get());
            try state.replay(&.{ .notarize = local_vote });
            try testing.expectEqualDeep(value, state.rounds.get(.new(2)).?.proposal().?.*);
            // Replay restores that we already cast our notarize vote.
            try testing.expectEqual(null, try state.construct_notarize(.new(2)));
            try testing.expect(state.try_verify() != .ready);
            try add_notarized(state, &env.fixture, value);
            try candidates.take(state);
            try candidates.expect_ready(2);
        }
    }.body);
}

test "voter state a replayed local notarize restores an optimistic child verification" {
    // commonware `replayed_local_notarize_restores_optimistic_child_verification`.
    try run(struct {
        fn body(io: Io) !void {
            var options = epoch_nine(5, 10, 2);
            options.epoch = 12;
            var probe: Env = undefined;
            try probe.start(io, options);
            const leader = probe.state.leader_index(.new(1)).?.get();
            probe.stop();
            options.signer = (leader + 1) % 4;
            var live: Env = undefined;
            try live.start(io, options);
            defer live.stop();
            const parent = proposal(12, 1, 0, 123);
            try testing.expect(try live.state.set_proposal(.new(1), &parent));
            try testing.expect(live.state.try_verify() == .ready);
            try testing.expect(live.state.verified(.new(1)));
            const local_vote = (try live.state.construct_notarize(.new(1))).?;
            const child = proposal(12, 2, 1, 124);
            try testing.expect(try live.state.set_proposal(.new(2), &child));
            try testing.expect(live.state.try_verify() == .ready);
            var restarted: Env = undefined;
            try restarted.start(io, options);
            defer restarted.stop();
            try restarted.state.replay(&.{ .notarize = local_vote });
            try testing.expect(try restarted.state.set_proposal(.new(2), &child));
            // The replayed vote preserves the optimistic child's verification.
            try testing.expect(restarted.state.try_verify() == .ready);
        }
    }.body);
}

test "voter state certifies external candidates for leader-controlled views" {
    // commonware `certify_external_candidates_for_leader_controlled_views`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, signer0(2, 5));
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            const value = proposal(2, 2, 1, 43);
            try testing.expect(try state.enter_view(.new(2)));
            try state.set_leader(.new(2), null);
            try testing.expectEqual(0, state.leader_index(.new(2)).?.get());
            const added = try state.add_notarization(try build_notarization(&env.fixture, value));
            try testing.expect(added.added);
            try testing.expect(added.equivocator == null);
            try candidates.take(state);
            try candidates.expect_ready(2);
            try testing.expectEqualDeep(value, candidates.ready.items[0]);
        }
    }.body);
}

/// Replays our notarize vote for `vote`, then adds and replays the conflicting
/// `conflicting` notarization; finalize must stay blocked.
fn replay_conflict(env: *Env, vote: Notarize, conflicting: *const base.Notarization) !void {
    const state = &env.state;
    try state.replay(&.{ .notarize = vote });
    _ = try state.add_notarization(try conflicting.clone(gpa));
    try state.replay(&.{ .notarization = conflicting.* });
    try testing.expectEqual(null, try state.construct_finalize(.new(4)));
}

test "voter state replay restores conflict state" {
    // commonware `replay_restores_conflict_state`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, signer0(1, 5));
            defer env.stop();
            // commonware signs these in epoch 3 while the state runs epoch 1.
            const proposal_a = proposal(3, 4, 0, 21);
            const proposal_b = proposal(3, 4, 0, 22);
            const local_vote = (try Notarize.sign(gpa, &env.fixture.schemes[0], proposal_a)).?;
            var conflicting = try notarization_without_signer0(&env.fixture, proposal_b);
            defer conflicting.deinit(gpa);
            try replay_conflict(&env, local_vote, &conflicting);
            var restarted: Env = undefined;
            try restarted.start(io, signer0(1, 5));
            defer restarted.stop();
            try replay_conflict(&restarted, local_vote, &conflicting);
        }
    }.body);
}

/// A finalization of `value` from `signers` only.
fn finalization_from(
    f: *const base.Fixture,
    signers: []const usize,
    value: Proposal,
) !base.Finalization {
    var votes: [4]Finalize = undefined;
    assert(signers.len <= votes.len);
    for (votes[0..signers.len], signers) |*vote, signer| {
        vote.* = (try Finalize.sign(gpa, &f.schemes[signer], value)).?;
    }
    return base.Finalization.from_votes(
        gpa,
        &f.verifier,
        votes[0..signers.len],
        parallel.sequential,
    );
}

test "voter state a restart equivocation's parent payload tracks the finalized proposal" {
    // commonware `restart_equivocation_parent_payload_tracks_finalized_proposal`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 1, .view_retention = 5 });
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            try testing.expectEqual(1, state.current_view().get());
            try testing.expectEqual(2, state.leader_index(.new(1)).?.get());
            const local_vote = (try Notarize.sign(gpa, &f.schemes[1], proposal(1, 1, 0, 1))).?;
            try state.replay(&.{ .notarize = local_vote });
            const proposal_y = proposal(1, 1, 0, 2);
            try testing.expect(!try state.set_proposal(.new(1), &proposal_y));
            const added = try state.add_finalization(
                try finalization_from(f, &.{ 0, 2, 3 }, proposal_y),
            );
            try testing.expect(added.added);
            try testing.expectEqualDeep(f.participants[2], added.equivocator.?);
            try testing.expectEqual(2, state.current_view().get());
            const child = proposal(1, 2, 1, 3);
            try testing.expect(try state.set_proposal(.new(2), &child));
            try expect_ready(state.try_verify(), child, 1, proposal_y.payload);
        }
    }.body);
}

test "voter state replay restores indirect notarization state" {
    // commonware `replay_restores_indirect_notarization_state`.
    try run(struct {
        fn body(io: Io) !void {
            var options = epoch_nine(5, 10, 2);
            options.epoch = 12;
            var env: Env = undefined;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            const ancestor = proposal(12, 1, 0, 121);
            const descendant = proposal(12, 2, 1, 122);
            _ = try state.create_round(.new(1));
            try testing.expect(state.record_proposed(ancestor));
            const local_vote = (try state.construct_notarize(.new(1))).?;
            try testing.expect(try state.set_proposal(.new(2), &descendant));
            try testing.expect(state.verified(.new(2)));
            var notarized = try build_notarization(&env.fixture, descendant);
            defer notarized.deinit(gpa);
            try testing.expect((try state.add_notarization(try notarized.clone(gpa))).added);
            try testing.expect(state.optimistic_ancestry_payload(.new(1)).?.eql(.fill(121)));

            var restarted: Env = undefined;
            try restarted.start(io, options);
            defer restarted.stop();
            const again = &restarted.state;
            try testing.expect(try again.set_proposal(.new(2), &descendant));
            try testing.expect(again.verified(.new(2)));
            _ = try again.add_notarization(try notarized.clone(gpa));
            try again.replay(&.{ .notarization = notarized });
            try testing.expectEqual(null, again.optimistic_ancestry_payload(.new(1)));
            try again.replay(&.{ .notarize = local_vote });
            try testing.expect(again.optimistic_ancestry_payload(.new(1)).?.eql(.fill(121)));
        }
    }.body);
}

test "voter state trigger timeout latches an optimistic future view" {
    // commonware `trigger_timeout_latches_optimistic_future_view`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(5, 10, 1);
            options.signer = 0;
            options.epoch = 14;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            const parent = try base.propose_and_notarize_view1(&env, 116);
            try testing.expect(try state.set_proposal(.new(2), &proposal(14, 2, 1, 117)));
            try testing.expectEqual(1, state.current_view().get());
            const initial = state.next_timeout();
            const latched_at = context.now_ns(io);
            state.trigger_timeout(.new(2), .invalid_proposal);
            try testing.expectEqual(null, try state.construct_nullify(.new(2), .invalid_proposal));
            try testing.expectEqual(initial, state.next_timeout());
            try add_notarized(state, &env.fixture, parent);
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expectEqual(2, state.current_view().get());
            const latched = state.next_timeout();
            try testing.expectEqual(latched_at, latched.deadline);
            try testing.expectEqual(.invalid_proposal, latched.reason);
            try testing.expect(try state.construct_nullify(.new(2), .invalid_proposal) != null);
        }
    }.body);
}

test "voter state try verify latches an invalid optimistic future proposal" {
    // commonware `try_verify_latches_invalid_optimistic_future_proposal`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(5, 10, 2);
            options.epoch = 15;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            const parent = proposal(15, 1, 0, 150);
            try testing.expect(try state.set_proposal(.new(1), &parent));
            try testing.expect(state.try_verify() == .ready);
            // View 2 names genesis as its parent, skipping view 1 inside the term.
            try testing.expect(try state.set_proposal(.new(2), &proposal(15, 2, 0, 151)));
            try testing.expectEqual(1, state.current_view().get());
            const initial = state.next_timeout();
            const latched_at = context.now_ns(io);
            try testing.expect(state.try_verify() == .wait);
            try testing.expectEqual(initial, state.next_timeout());
            try add_notarized(state, &env.fixture, parent);
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expectEqual(2, state.current_view().get());
            const latched = state.next_timeout();
            try testing.expectEqual(latched_at, latched.deadline);
            try testing.expectEqual(.invalid_proposal, latched.reason);
        }
    }.body);
}

/// A notarization of `value` from `signers` only.
fn notarization_from(
    f: *const base.Fixture,
    signers: []const usize,
    value: Proposal,
) !base.Notarization {
    var votes: [4]Notarize = undefined;
    assert(signers.len <= votes.len);
    for (votes[0..signers.len], signers) |*vote, signer| {
        vote.* = (try Notarize.sign(gpa, &f.schemes[signer], value)).?;
    }
    return base.Notarization.from_votes(
        gpa,
        &f.verifier,
        votes[0..signers.len],
        parallel.sequential,
    );
}

test "voter state certify candidates skip views at or below the last finalization" {
    // commonware `certify_candidates_skips_views_at_or_below_last_finalized`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, signer0(1, 10));
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try add_notarized(state, &env.fixture, proposal(1, 2, 0, 2));
            try add_notarized(state, &env.fixture, proposal(1, 3, 0, 3));
            try finalize_with(&env, proposal(1, 2, 0, 2));
            try state.certification_candidates.insert(gpa, .new(2));
            try testing.expectEqual(2, state.last_finalized().get());
            try testing.expect(state.rounds.get(.new(2)).?.pending_certification() != null);
            try candidates.take(state);
            try candidates.expect_ready(3);
        }
    }.body);
}

test "voter state a nullification keeps a notarization as a certification candidate" {
    // commonware `nullification_keeps_notarization_as_certification_candidate`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{});
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try add_notarized(state, &env.fixture, proposal(1, 2, 0, 42));
            const nullified = try build_nullification(&env.fixture, round_at(1, 2));
            try testing.expect(try state.add_nullification(nullified));
            try candidates.take(state);
            try candidates.expect_ready(2);
        }
    }.body);
}

test "voter state a nullification does not abort an in-flight certification" {
    // commonware `nullification_does_not_abort_inflight_certification`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{});
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try add_notarized(state, &env.fixture, proposal(1, 2, 0, 24));
            try candidates.take(state);
            try candidates.expect_ready(2);
            try state.set_certify_outstanding(.new(2));
            const nullified = try build_nullification(&env.fixture, round_at(1, 2));
            try testing.expect(try state.add_nullification(nullified));
            try testing.expect(!state.is_certify_aborted(.new(2)));
            try testing.expect(try state.certified(.new(2), true) != null);
            try testing.expect(state.explicit_ancestry_payload(.new(2)) != null);
        }
    }.body);
}

test "voter state conflicting parent headers share a payload but certify the notarized one" {
    // commonware `conflicting_parent_headers_share_payload_but_certify_notarized_proposal`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 1 });
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try add_notarized(state, f, proposal(1, 1, 0, 31));
            try testing.expect(try state.certified(.new(1), true) != null);
            const nullified_proposal = proposal(1, 2, 1, 32);
            try add_notarized(state, f, nullified_proposal);
            try candidates.take(state);
            try candidates.expect_ready(2);
            try testing.expectEqualDeep(nullified_proposal, candidates.ready.items[0]);
            try state.set_certify_outstanding(.new(2));
            try testing.expect(try state.add_nullification(
                try build_nullification(f, round_at(1, 2)),
            ));
            try testing.expectEqual(3, state.current_view().get());
            try testing.expectEqual(0, state.leader_index(.new(3)).?.get());
            // Same payload, different parents: the header naming view 1 is bad.
            const bad = proposal(1, 3, 1, 33);
            const good = proposal(1, 3, 2, 33);
            try testing.expect(!bad.eql(good));
            try testing.expect(try state.set_proposal(.new(3), &bad));
            try expect_ready(state.try_verify(), bad, 1, .fill(31));
            state.trigger_timeout(.new(3), .invalid_proposal);
            try testing.expect(!(try state.construct_nullify(.new(3), .invalid_proposal)).?.retry);
            const added = try state.add_notarization(try notarization_from(f, &.{ 0, 2, 3 }, good));
            try testing.expect(added.added);
            try testing.expect(added.equivocator != null);
            try candidates.take(state);
            try candidates.expect_ready(3);
            try testing.expectEqualDeep(good, candidates.ready.items[0]);
        }
    }.body);
}

test "voter state a late certification after a nullification lets the child build on it" {
    // commonware `nullification_then_late_certification_allows_child_to_build_on_parent`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, signer0(1, 10));
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 2, 0, 91));
            try testing.expect(try state.add_nullification(
                try build_nullification(&env.fixture, round_at(1, 2)),
            ));
            try testing.expectEqual(0, state.leader_index(.new(3)).?.get());
            try testing.expectEqual(null, state.try_propose());
            try testing.expect(try state.certified(.new(2), true) != null);
            const request = state.try_propose().?.context();
            try testing.expectEqual(3, request.view().get());
            try testing.expectEqual(2, request.parent[0].get());
            try testing.expect(request.parent[1].eql(.fill(91)));
        }
    }.body);
}

test "voter state a late certification after a nullification unblocks follower verify" {
    // commonware `nullification_then_late_certification_unblocks_follower_verify`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 1 });
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 2, 0, 77));
            try testing.expect(try state.add_nullification(
                try build_nullification(&env.fixture, round_at(1, 2)),
            ));
            try testing.expectEqual(3, state.current_view().get());
            try testing.expectEqual(0, state.leader_index(.new(3)).?.get());
            const child = proposal(1, 3, 2, 78);
            try testing.expect(try state.set_proposal(.new(3), &child));
            try testing.expect(state.try_verify() != .ready);
            try testing.expect(try state.certified(.new(2), true) != null);
            const verify = state.try_verify();
            try expect_ready(verify, child, 2, .fill(77));
            try testing.expectEqual(3, verify.ready.context.round.view.get());
        }
    }.body);
}

/// Signer `signer` with terms of 5 views, no lookahead, and a retention of `view_retention`.
fn terms_signer(signer: usize, view_retention: u64) Options {
    return .{
        .signer = signer,
        .view_retention = view_retention,
        .term_length = 5,
        .stall_timeout_ms = 4000,
    };
}

test "voter state try propose requires the immediate parent within a term" {
    // commonware `try_propose_requires_immediate_parent_within_term`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_signer(2, 10));
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 1, 0, 93));
            try testing.expect(try state.certified(.new(1), true) != null);
            var nullified = try build_nullification(&env.fixture, round_at(1, 2));
            defer nullified.deinit(gpa);
            try state.replay(&.{ .nullification = nullified });
            try testing.expect(try state.enter_view(.new(3)));
            try state.set_leader(.new(3), null);
            try testing.expectEqual(2, state.leader_index(.new(3)).?.get());
            try testing.expectEqual(null, state.try_propose());
        }
    }.body);
}

test "voter state try propose allows a cross-term parent at a term start" {
    // commonware `try_propose_allows_cross_term_parent_at_term_start`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, terms_signer(3, 20));
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 3, 0, 94));
            try testing.expect(try state.certified(.new(3), true) != null);
            try testing.expect(try state.add_nullification(
                try build_nullification(&env.fixture, round_at(1, 4)),
            ));
            try testing.expectEqual(6, state.current_view().get());
            try state.set_leader(.new(6), null);
            try testing.expectEqual(3, state.leader_index(.new(6)).?.get());
            const request = state.try_propose().?.context();
            try testing.expectEqual(6, request.view().get());
            try testing.expectEqual(3, request.parent[0].get());
            try testing.expect(request.parent[1].eql(.fill(94)));
        }
    }.body);
}

/// Epoch 9, terms of 5 views, two optimistic views, signer `signer` of `validators`.
fn handoff_options(validators: u32, signer: usize) Options {
    var options = epoch_nine(5, 10, 2);
    options.validators = validators;
    options.signer = signer;
    return options;
}

/// Notarizes and certifies view 4 (commonware `certify_view_4`).
fn certify_view_4(env: *Env) !Proposal {
    const certified = proposal(9, 4, 3, 64);
    try add_notarized(&env.state, &env.fixture, certified);
    try testing.expect(try env.state.certified(.new(4), true) != null);
    var candidates: Candidates = .{};
    defer candidates.deinit();
    try candidates.take(&env.state);
    return certified;
}

/// Certifies view 4 and votes for the verified view-5 tip that ends the term (commonware
/// `prepare_term_boundary`). Returns the tip.
fn prepare_term_boundary(env: *Env) !Proposal {
    const state = &env.state;
    _ = try certify_view_4(env);
    try testing.expectEqual(5, state.current_view().get());
    const tip = proposal(9, 5, 4, 65);
    try testing.expect(try state.set_proposal(.new(5), &tip));
    try testing.expect(state.try_verify() == .ready);
    try testing.expect(state.verified(.new(5)));
    try testing.expectEqual(null, state.leader_index(.new(6)));
    try testing.expect(try state.construct_notarize(.new(5)) != null);
    return tip;
}

/// As the only participant: proposes and votes for the view-5 tip and its view-6 handoff
/// child, then notarizes both (commonware `notarize_single_participant_handoff`).
fn notarize_single_participant_handoff(env: *Env) ![2]Proposal {
    const state = &env.state;
    _ = try certify_view_4(env);
    const tip = proposal(9, 5, 4, 65);
    const child = proposal(9, 6, 5, 66);
    for ([_]Proposal{ tip, child }) |value| {
        const request = state.try_propose().?.context();
        try testing.expect(state.proposed(&request, value.payload));
        try testing.expect(try state.construct_notarize(value.round.view) != null);
    }
    try add_notarized(state, &env.fixture, tip);
    try add_notarized(state, &env.fixture, child);
    return .{ tip, child };
}

/// Replays signer `signer`'s own notarize vote for `value`.
fn replay_vote(env: *Env, signer: usize, value: Proposal) !void {
    const vote = (try Notarize.sign(gpa, &env.fixture.schemes[signer], value)).?;
    try env.state.replay(&.{ .notarize = vote });
}

test "voter state a pipelined handoff proposes on an uncertified term end" {
    // commonware `pipelined_handoff_proposes_on_uncertified_term_end`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            const tip = try prepare_term_boundary(&env);
            // Voting for the outgoing tip stamps the incoming term's leader.
            try testing.expectEqual(3, state.leader_index(.new(6)).?.get());
            const request = state.try_propose().?.context();
            try testing.expectEqual(6, request.view().get());
            try testing.expectEqual(5, request.parent[0].get());
            try testing.expect(request.parent[1].eql(tip.payload));
            try testing.expectEqual(5, state.current_view().get());
            const ours = proposal(9, 6, 5, 66);
            try testing.expect(state.proposed(&request, ours.payload));
            const vote = (try state.construct_notarize(.new(6))).?;
            try testing.expectEqualDeep(ours, vote.proposal);
            try testing.expectEqual(5, state.current_view().get());
            try add_notarized(state, &env.fixture, tip);
            try testing.expect(try state.certified(.new(5), true) != null);
            try testing.expectEqual(6, state.current_view().get());
            try add_notarized(state, &env.fixture, ours);
            try candidates.take(state);
            try testing.expectEqual(0, candidates.fetches.items.len);
            var has_ours = false;
            for (candidates.ready.items) |item| has_ours = has_ours or item.round.view.get() == 6;
            try testing.expect(has_ours);
            try testing.expect(try state.certified(.new(6), true) != null);
            try testing.expectEqual(7, state.current_view().get());
        }
    }.body);
}

test "voter state a handoff on a certified parent with our own nullify keeps the build" {
    // commonware `pipelined_handoff_certified_parent_own_nullify_keeps_pending_build`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            const parent = try prepare_term_boundary(&env);
            const handoff = state.try_propose().?;
            try testing.expect(handoff.is_handoff());
            const request = handoff.context();
            try testing.expectEqual(6, request.view().get());
            try testing.expectEqual(5, request.parent[0].get());
            try add_notarized(state, &env.fixture, parent);
            try testing.expect(try state.certified(.new(5), true) != null);
            try testing.expectEqual(request.view(), state.current_view());
            try testing.expect(try state.construct_nullify(.new(6), .leader_timeout) != null);
            try testing.expect(!state.supersede_proposal_request(&request));
            try testing.expectEqual(null, state.pending_handoff_abandonment(&request));
            try testing.expect(!state.proposed(&request, .fill(91)));
            try testing.expectEqual(null, state.try_propose());
        }
    }.body);
}

/// Makes the handoff request obsolete through `advance`: 0 a nullification of view 6, 1 a
/// finalization of view 11, 2 a certified notarization of view 11.
fn obsolete_handoff(io: Io, advance: u8) !void {
    var env: Env = undefined;
    try env.start(io, handoff_options(4, 3));
    defer env.stop();
    const state = &env.state;
    const f = &env.fixture;
    const parent = try prepare_term_boundary(&env);
    const handoff = state.try_propose().?;
    try testing.expect(handoff.is_handoff());
    const request = handoff.context();
    const peers = [_]usize{ 0, 1, 2 };
    const later = proposal(9, 11, 10, 91);
    switch (advance) {
        0 => {
            var nullify_votes: [3]Nullify = undefined;
            for (&nullify_votes, peers) |*vote, signer| {
                vote.* = (try Nullify.sign(gpa, &f.schemes[signer], request.round)).?;
            }
            const nullified = try types.Nullification(Scheme).from_votes(
                gpa,
                &f.verifier,
                &nullify_votes,
                parallel.sequential,
            );
            try testing.expect(try state.add_nullification(nullified));
            try testing.expectEqual(11, state.current_view().get());
        },
        1 => {
            const added = try state.add_finalization(try finalization_from(f, &peers, later));
            try testing.expect(added.added);
            try testing.expectEqual(12, state.current_view().get());
        },
        2 => {
            const added = try state.add_notarization(try notarization_from(f, &peers, later));
            try testing.expect(added.added);
            try testing.expectEqual(5, state.current_view().get());
            var candidates: Candidates = .{};
            defer candidates.deinit();
            try candidates.take(state);
            var found = false;
            for (candidates.ready.items) |item| found = found or item.eql(later);
            try testing.expect(found);
            try testing.expectEqual(0, candidates.fetches.items.len);
            try testing.expect(try state.certified(.new(11), true) != null);
            try testing.expectEqual(12, state.current_view().get());
        },
        else => unreachable,
    }
    try testing.expect(!state.parent_certified(.{ request.parent[0], request.parent[1] }));
    try testing.expectEqual(null, state.highest_nullification_in_term(parent.round.view));
    try testing.expect(request.view().get() < state.current_view().get());
}

test "voter state later certificates make a handoff request obsolete" {
    // commonware `pipelined_handoff_later_certificates_make_request_obsolete`.
    try run(struct {
        fn body(io: Io) !void {
            for (0..3) |advance| try obsolete_handoff(io, @intCast(advance));
        }
    }.body);
}

/// Takes the candidates twice: first only `parent` is ready, then, once it certifies,
/// only `child`.
fn expect_parent_then_child(env: *Env, parent: Proposal, child: Proposal) !void {
    var candidates: Candidates = .{};
    defer candidates.deinit();
    try candidates.take(&env.state);
    try candidates.expect_ready(parent.round.view.get());
    try testing.expectEqualDeep(parent, candidates.ready.items[0]);
    try testing.expect(try env.state.certified(parent.round.view, true) != null);
    try candidates.take(&env.state);
    try candidates.expect_ready(child.round.view.get());
    try testing.expectEqualDeep(child, candidates.ready.items[0]);
}

test "voter state a pipelined handoff certification waits for its parent" {
    // commonware `pipelined_handoff_certification_waits_for_parent`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(1, 0));
            defer env.stop();
            const tip, const child = try notarize_single_participant_handoff(&env);
            // Only the parent may cross the certification barrier first.
            try expect_parent_then_child(&env, tip, child);
        }
    }.body);
}

test "voter state the pipelined handoff certification barrier survives a restart" {
    // commonware `pipelined_handoff_certification_barrier_survives_restart`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(1, 0));
            defer env.stop();
            _ = try certify_view_4(&env);
            const tip = proposal(9, 5, 4, 65);
            const child = proposal(9, 6, 5, 66);
            try replay_vote(&env, 0, tip);
            try replay_vote(&env, 0, child);
            try add_notarized(&env.state, &env.fixture, tip);
            try add_notarized(&env.state, &env.fixture, child);
            try expect_parent_then_child(&env, tip, child);
        }
    }.body);
}

/// Replays `value`'s notarization, then adds it.
fn replay_and_add_notarization(env: *Env, value: Proposal) !void {
    var notarized = try build_notarization(&env.fixture, value);
    defer notarized.deinit(gpa);
    try env.state.replay(&.{ .notarization = notarized });
    try add_notarized(&env.state, &env.fixture, value);
}

test "voter state a singleton certificate before the child vote keeps the gate" {
    // commonware `singleton_certificate_before_child_vote_keeps_gate`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(1, 0));
            defer env.stop();
            const state = &env.state;
            var candidates: Candidates = .{};
            defer candidates.deinit();
            _ = try certify_view_4(&env);
            const tip = proposal(9, 5, 4, 65);
            const child = proposal(9, 6, 5, 66);
            try replay_vote(&env, 0, tip);
            try replay_and_add_notarization(&env, tip);
            try replay_vote(&env, 0, child);
            try testing.expect(state.rounds.get(.new(6)).?.verifying() == null);
            try replay_and_add_notarization(&env, child);
            try candidates.take(state);
            try candidates.expect_ready(5);
            try testing.expectEqual(null, try state.construct_finalize(.new(6)));
            try testing.expect(try state.certified(.new(5), true) != null);
            try candidates.take(state);
            try candidates.expect_ready(6);
            try testing.expectEqualDeep(child, candidates.ready.items[0]);
        }
    }.body);
}

/// Nullifies view 5, replays signer `signer`'s vote for a view-6 proposal on view 4, and
/// expects the conflicting notarized view-6 proposal on view 5 to certify (commonware
/// `certify_conflicting_term_start`).
fn certify_conflicting_term_start(state: anytype, f: *const base.Fixture, signer: usize) !void {
    try testing.expect(try state.add_nullification(try build_nullification(f, round_at(9, 5))));
    const vote = (try Notarize.sign(gpa, &f.schemes[signer], proposal(9, 6, 4, 61))).?;
    try state.replay(&.{ .notarize = vote });
    const conflicting = proposal(9, 6, 5, 62);
    var others: [3]usize = undefined;
    var count: usize = 0;
    for (0..4) |index| if (index != signer) {
        others[count] = index;
        count += 1;
    };
    assert(count == others.len);
    const added = try state.add_notarization(try notarization_from(f, &others, conflicting));
    try testing.expect(added.added);
    var ready: std.ArrayList(Proposal) = .empty;
    defer ready.deinit(gpa);
    var fetches: std.ArrayList(CertificateFetch) = .empty;
    defer fetches.deinit(gpa);
    try state.certify_candidates(&ready, &fetches);
    try testing.expectEqual(1, ready.items.len);
    try testing.expectEqualDeep(conflicting, ready.items[0]);
    try testing.expectEqual(0, fetches.items.len);
}

test "voter state the term-start gate skips a non-leader vote" {
    // commonware `term_start_gate_skips_non_leader_vote`.
    try run(struct {
        fn body(io: Io) !void {
            for (0..3) |signer| {
                var env: Env = undefined;
                try env.start(io, handoff_options(4, signer));
                defer env.stop();
                try testing.expectEqual(3, env.state.handoff_leader(.new(6)).?.get());
                try certify_conflicting_term_start(&env.state, &env.fixture, signer);
            }
        }
    }.body);
}

test "voter state the term-start gate skips a dynamic elector" {
    // commonware `term_start_gate_skips_dynamic_elector`.
    try run(struct {
        fn body(io: Io) !void {
            var rng = utils.rng.test_rng();
            var fixture = try ed25519.fixture(Digest, gpa, &rng, "ns", 4);
            defer fixture.deinit(gpa);
            const Dynamic = state_mod.State(Scheme, RequireCertificateElector, Digest);
            var state = Dynamic.init(gpa, io, .{
                .scheme = &fixture.schemes[1],
                .elector = .{},
                .epoch = .new(9),
                .view_retention = .new(10),
                .leader_timeout = .from_millis(1000),
                .certification_timeout = .from_millis(2000),
                .timeout_retry = .from_millis(3000),
                .skip_budget = 4,
            });
            defer state.deinit();
            try state.set_genesis(base.genesis());
            try certify_conflicting_term_start(&state, &fixture, 1);
        }
    }.body);
}

test "voter state a pipelined handoff finalize waits for parent certification" {
    // commonware `pipelined_handoff_finalize_waits_for_parent_certification`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(1, 0));
            defer env.stop();
            const state = &env.state;
            _ = try notarize_single_participant_handoff(&env);
            try testing.expect(try state.certified(.new(6), true) != null);
            try testing.expectEqual(null, try state.construct_finalize(.new(6)));
            try testing.expect(try state.certified(.new(5), true) != null);
            try testing.expect(try state.construct_finalize(.new(6)) != null);
        }
    }.body);
}

test "voter state a pipelined handoff replay restores the early leader" {
    // commonware `pipelined_handoff_replay_restores_early_leader`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            _ = try certify_view_4(&env);
            try testing.expectEqual(5, state.current_view().get());
            const tip = proposal(9, 5, 4, 65);
            try testing.expectEqual(null, state.leader_index(.new(6)));
            try replay_vote(&env, 3, tip);
            try testing.expectEqual(3, state.leader_index(.new(6)).?.get());
            const request = state.try_propose().?.context();
            try testing.expectEqual(6, request.view().get());
            try testing.expectEqual(5, request.parent[0].get());
            try testing.expect(request.parent[1].eql(tip.payload));
            const ours = proposal(9, 6, 5, 66);
            try testing.expect(state.proposed(&request, ours.payload));
            const vote = (try state.construct_notarize(.new(6))).?;
            try testing.expectEqualDeep(ours, vote.proposal);
        }
    }.body);
}

test "voter state a pipelined handoff child replay prevents a rebuild" {
    // commonware `pipelined_handoff_child_replay_prevents_rebuild`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            const certified = try certify_view_4(&env);
            const child = proposal(9, 6, 5, 66);
            try replay_vote(&env, 3, proposal(9, 5, 4, 65));
            try replay_vote(&env, 3, child);
            try testing.expectEqual(null, state.try_propose());
            try testing.expectEqual(null, try state.construct_notarize(.new(6)));
            var nullify_votes: [3]Nullify = undefined;
            for (&nullify_votes, 0..) |*vote, signer| {
                vote.* = (try Nullify.sign(gpa, &f.schemes[signer], round_at(9, 5))).?;
            }
            const nullified = try types.Nullification(Scheme).from_votes(
                gpa,
                &f.verifier,
                &nullify_votes,
                parallel.sequential,
            );
            try testing.expect(try state.add_nullification(nullified));
            try base.expect_payload(state.parent_payload_for(.new(6), .new(4)), 64);
            try testing.expectEqual(null, state.try_propose());
            const alternate: base.State.Context = .{
                .round = round_at(9, 6),
                .leader = f.participants[3],
                .parent = .{ .new(4), certified.payload },
            };
            _ = state.proposed(&alternate, .fill(67));
            try testing.expectEqualDeep(child, state.rounds.get(.new(6)).?.proposal().?.*);
        }
    }.body);
}

/// Votes for a view-6 handoff child on the tip, then certifies a conflicting view-5
/// notarization; returns the conflicting proposal.
fn handoff_then_conflict(state: anytype, f: *const base.Fixture, tip: Proposal) !Proposal {
    const request = state.try_propose().?.context();
    try testing.expectEqual(5, request.parent[0].get());
    try testing.expect(request.parent[1].eql(tip.payload));
    try testing.expect(state.proposed(&request, proposal(9, 6, 5, 66).payload));
    try testing.expect(try state.construct_notarize(.new(6)) != null);
    const conflict = proposal(9, 5, 4, 75);
    const added = try state.add_notarization(try notarization_from(f, &.{ 0, 1, 2 }, conflict));
    try testing.expect(added.added);
    try testing.expect(try state.certified(.new(5), true) != null);
    try testing.expectEqual(6, state.current_view().get());
    // Proposing now would build on a dead chain.
    try testing.expect(state.try_propose() == null);
    try testing.expectEqual(null, state.optimistic_ancestry_payload(.new(6)));
    return conflict;
}

test "voter state a pipelined handoff's conflicting parent blocks a same-term successor" {
    // commonware `pipelined_handoff_conflicting_parent_blocks_same_term_successor`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const tip = try prepare_term_boundary(&env);
            _ = try handoff_then_conflict(&env.state, &env.fixture, tip);
        }
    }.body);
}

/// A scheduled elector with rotating terms where participant 3 leads views 6 and 7
/// (commonware's `RepeatLeaderElector`).
const RepeatLeaderElector = struct {
    pub const mode: elector.Mode = .scheduled;
    pub const Input = void;

    pub fn terms(_: RepeatLeaderElector) elector.Terms {
        return .rotating();
    }

    pub fn elect(_: RepeatLeaderElector, round: Rnd, _: void) Participant {
        const view = round.view.get();
        if (view == 6 or view == 7) return .init(3);
        return .init(@intCast(view % 3));
    }
};

test "voter state a pipelined handoff's conflicting parent blocks a consecutive handoff" {
    // commonware `pipelined_handoff_conflicting_parent_blocks_consecutive_handoff`.
    try run(struct {
        fn body(io: Io) !void {
            var rng = utils.rng.test_rng();
            var fixture = try ed25519.fixture(Digest, gpa, &rng, "ns", 4);
            defer fixture.deinit(gpa);
            const Repeat = state_mod.State(Scheme, RepeatLeaderElector, Digest);
            var state = Repeat.init(gpa, io, .{
                .scheme = &fixture.schemes[3],
                .elector = .{},
                .epoch = .new(9),
                .view_retention = .new(10),
                .leader_timeout = .from_millis(1000),
                .certification_timeout = .from_millis(2000),
                .timeout_retry = .from_millis(3000),
                .skip_budget = 4,
            });
            defer state.deinit();
            try state.set_genesis(base.genesis());
            const added = try state.add_notarization(
                try build_notarization(&fixture, proposal(9, 4, 3, 64)),
            );
            try testing.expect(added.added);
            try testing.expect(try state.certified(.new(4), true) != null);
            try testing.expectEqual(5, state.current_view().get());
            const tip = proposal(9, 5, 4, 65);
            try testing.expect(try state.set_proposal(.new(5), &tip));
            try testing.expect(state.try_verify() == .ready);
            try testing.expect(state.verified(.new(5)));
            try testing.expect(try state.construct_notarize(.new(5)) != null);
            const conflict = try handoff_then_conflict(&state, &fixture, tip);
            var nullify_votes: [3]Nullify = undefined;
            for (&nullify_votes, 0..) |*vote, signer| {
                vote.* = (try Nullify.sign(gpa, &fixture.schemes[signer], round_at(9, 6))).?;
            }
            try testing.expect(try state.add_nullification(try types.Nullification(Scheme)
                .from_votes(gpa, &fixture.verifier, &nullify_votes, parallel.sequential)));
            const request = state.try_propose().?.context();
            try testing.expectEqual(7, request.view().get());
            try testing.expectEqual(5, request.parent[0].get());
            try testing.expect(request.parent[1].eql(conflict.payload));
        }
    }.body);
}

test "voter state a pipelined handoff does not require the recovered parent's leader" {
    // commonware `pipelined_handoff_does_not_require_recovered_parent_leader`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 0));
            defer env.stop();
            const state = &env.state;
            try testing.expect(try state.add_nullification(
                try build_nullification(&env.fixture, round_at(9, 5)),
            ));
            try testing.expectEqual(6, state.current_view().get());
            const tip = proposal(9, 10, 9, 110);
            try add_notarized(state, &env.fixture, tip);
            try testing.expectEqual(null, state.leader_index(.new(10)));
            try testing.expectEqual(0, state.leader_index(.new(11)).?.get());
            const request = state.try_propose().?;
            try testing.expect(request.is_handoff());
            const handoff = request.context();
            try testing.expectEqual(11, handoff.view().get());
            try testing.expectEqual(10, handoff.parent[0].get());
            try testing.expect(handoff.parent[1].eql(tip.payload));
        }
    }.body);
}

test "voter state a pipelined handoff keeps a valid fallback after a late certification" {
    // commonware `pipelined_handoff_keeps_valid_fallback_after_late_certification`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            const tip = try prepare_term_boundary(&env);
            try add_notarized(state, &env.fixture, tip);
            try testing.expect(try state.add_nullification(
                try build_nullification(&env.fixture, round_at(9, 5)),
            ));
            try testing.expectEqual(6, state.current_view().get());
            const request = state.try_propose().?;
            try testing.expect(request == .propose);
            const fallback = request.context();
            try testing.expectEqual(4, fallback.parent[0].get());
            try testing.expect(fallback.parent[1].eql(.fill(64)));
            try testing.expect(try state.certified(.new(5), true) != null);
            const ours = proposal(9, 6, 4, 66);
            try testing.expect(!state.supersede_proposal_request(&fallback));
            try testing.expect(state.proposed(&fallback, ours.payload));
            const vote = (try state.construct_notarize(.new(6))).?;
            try testing.expectEqualDeep(ours, vote.proposal);
        }
    }.body);
}

test "voter state a pipelined handoff retries after its parent is invalidated" {
    // commonware `pipelined_handoff_retries_after_parent_invalidation`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            _ = try prepare_term_boundary(&env);
            const initial = state.try_propose().?.context();
            try testing.expectEqual(5, initial.parent[0].get());
            try testing.expect(state.try_propose() == null);
            try testing.expect(try state.add_nullification(
                try build_nullification(&env.fixture, round_at(9, 5)),
            ));
            try testing.expect(state.supersede_proposal_request(&initial));
            const request = state.try_propose().?;
            try testing.expect(request == .propose);
            const retry = request.context();
            try testing.expectEqual(6, retry.view().get());
            try testing.expectEqual(4, retry.parent[0].get());
            try testing.expect(retry.parent[1].eql(.fill(64)));
            try testing.expect(state.try_propose() == null);
            const rebuilt = proposal(9, 6, 4, 67);
            try testing.expect(state.proposed(&retry, rebuilt.payload));
            const vote = (try state.construct_notarize(.new(6))).?;
            try testing.expectEqualDeep(rebuilt, vote.proposal);
        }
    }.body);
}

test "voter state a rejected build keeps a single propose per view" {
    // commonware `rejected_build_keeps_single_propose_per_view`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            _ = try certify_view_4(&env);
            try testing.expect(try state.add_nullification(
                try build_nullification(f, round_at(9, 5)),
            ));
            try testing.expectEqual(6, state.current_view().get());
            const start = state.try_propose().?.context();
            try testing.expectEqual(4, start.parent[0].get());
            const term_start = proposal(9, 6, 4, 66);
            try testing.expect(state.proposed(&start, term_start.payload));
            try testing.expect(try state.construct_notarize(.new(6)) != null);
            const added = try state.add_notarization(
                try notarization_from(f, &.{ 0, 1, 2 }, term_start),
            );
            try testing.expect(added.added);
            const request = state.try_propose().?;
            try testing.expect(request == .propose);
            const next = request.context();
            try testing.expectEqual(7, next.view().get());
            try testing.expectEqual(6, next.parent[0].get());
            try testing.expect(next.parent[1].eql(term_start.payload));
            try testing.expect(try state.certified(.new(6), false) != null);
            try testing.expect(!state.supersede_proposal_request(&next));
            try testing.expect(!state.proposed(&next, .fill(67)));
            try finalize_with(&env, term_start);
            try testing.expect(state.try_propose() == null);
        }
    }.body);
}

test "voter state a pipelined handoff withholds notarize after a failed certification" {
    // commonware `pipelined_handoff_withholds_notarize_after_failed_certification`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            const tip = try prepare_term_boundary(&env);
            const request = state.try_propose().?.context();
            try add_notarized(state, &env.fixture, tip);
            try testing.expect(try state.certified(.new(5), false) != null);
            try testing.expect(!state.proposed(&request, .fill(66)));
            try testing.expectEqual(null, try state.construct_notarize(.new(6)));
        }
    }.body);
}

test "voter state a pipelined handoff withholds notarize after an equivocation" {
    // commonware `pipelined_handoff_withholds_notarize_after_equivocation`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            _ = try prepare_term_boundary(&env);
            const request = state.try_propose().?.context();
            try testing.expect(!try state.set_proposal(.new(5), &proposal(9, 5, 4, 99)));
            try testing.expect(!state.proposed(&request, .fill(66)));
            try testing.expectEqual(null, try state.construct_notarize(.new(6)));
        }
    }.body);
}

test "voter state a pipelined handoff withholds notarize after a conflicting parent" {
    // commonware `pipelined_handoff_withholds_notarize_after_conflicting_parent_certificate`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, handoff_options(4, 3));
            defer env.stop();
            const state = &env.state;
            const tip = try prepare_term_boundary(&env);
            const request = state.try_propose().?.context();
            try testing.expectEqual(5, request.parent[0].get());
            try testing.expect(request.parent[1].eql(tip.payload));
            const conflicting = proposal(9, 5, 4, 99);
            const added = try state.add_notarization(
                try notarization_from(&env.fixture, &.{ 0, 1, 2 }, conflicting),
            );
            try testing.expect(added.added);
            try testing.expect(added.equivocator != null);
            try testing.expectEqual(5, state.current_view().get());
            try testing.expect(!state.proposed(&request, .fill(66)));
            try testing.expectEqual(null, try state.construct_notarize(.new(6)));
        }
    }.body);
}

/// A peer's handoff child keeps explicit verification whether its proposal arrives before
/// the tip's notarization or after (commonware `peer_verification_stays_explicit`).
fn peer_verification_stays_explicit(io: Io, proposal_first: bool) !void {
    var env: Env = undefined;
    try env.start(io, handoff_options(4, 1));
    defer env.stop();
    const state = &env.state;
    const f = &env.fixture;
    const tip = try prepare_term_boundary(&env);
    try testing.expectEqual(null, state.leader_index(.new(6)));
    try testing.expect(state.try_propose() == null);
    const child = proposal(9, 6, 5, 66);
    if (proposal_first) {
        try testing.expect(try state.set_proposal(.new(6), &child));
        try testing.expect(state.try_verify() == .wait);
        try add_notarized(state, f, tip);
    } else {
        try add_notarized(state, f, tip);
        try testing.expect(try state.set_proposal(.new(6), &child));
    }
    const leader = f.participants[state.leader_index(.new(6)).?.get()];
    try expect_resolve(state.try_verify(), 6, 5, leader);
    try testing.expect(try state.certified(.new(5), true) != null);
    try expect_ready(state.try_verify(), child, 5, tip.payload);
}

test "voter state a pipelined handoff keeps peer verification explicit" {
    // commonware `pipelined_handoff_keeps_peer_verification_explicit`.
    try run(struct {
        fn body(io: Io) !void {
            try peer_verification_stays_explicit(io, false);
        }
    }.body);
}

test "voter state a pipelined handoff keeps an early peer proposal explicit" {
    // commonware `pipelined_handoff_keeps_early_peer_proposal_explicit`.
    try run(struct {
        fn body(io: Io) !void {
            try peer_verification_stays_explicit(io, true);
        }
    }.body);
}

test "voter state a pipelined handoff pipelines rotating terms" {
    // commonware `pipelined_handoff_pipelines_rotating_terms`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .signer = 3, .epoch = 9 });
            defer env.stop();
            const state = &env.state;
            const first = proposal(9, 1, 0, 67);
            try testing.expect(try state.set_proposal(.new(1), &first));
            try testing.expect(state.try_verify() == .ready);
            try testing.expect(state.verified(.new(1)));
            try testing.expect(try state.construct_notarize(.new(1)) != null);
            const request = state.try_propose().?.context();
            try testing.expectEqual(2, request.view().get());
            try testing.expectEqual(1, request.parent[0].get());
            try testing.expect(request.parent[1].eql(first.payload));
            try testing.expectEqual(1, state.current_view().get());
        }
    }.body);
}

/// Expects `verify` to request `kind` for `view` on behalf of `proposal_view`.
fn expect_resolve_of(
    verify: base.State.Verify,
    proposal_view: u64,
    view: u64,
    kind: @TypeOf(verify.resolve.kind),
) !void {
    try testing.expect(verify == .resolve);
    try testing.expectEqual(proposal_view, verify.resolve.proposal.get());
    try testing.expectEqual(view, verify.resolve.view.get());
    try testing.expectEqual(kind, verify.resolve.kind);
}

test "voter state a late parent certificate unblocks a notarized chain after a term skip" {
    // commonware `late_parent_certificate_unblocks_notarized_chain_after_term_skip`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            var options = epoch_nine(5, 20, 3);
            options.signer = 3;
            options.epoch = 1;
            try env.start(io, options);
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            const others = [_]usize{ 0, 1, 2 };
            var candidates: Candidates = .{};
            defer candidates.deinit();
            const added = try state.add_notarization(
                try notarization_from(f, &others, proposal(1, 1, 0, 1)),
            );
            try testing.expect(added.added);
            try testing.expect(try state.certified(.new(1), true) != null);
            for ([_]u64{ 3, 4 }) |view| {
                const value = proposal(1, view, view - 1, @intCast(view));
                try testing.expect((try state.add_notarization(
                    try notarization_from(f, &others, value),
                )).added);
            }
            try candidates.take(state);
            try testing.expectEqual(0, candidates.ready.items.len);
            var nullify_votes: [3]Nullify = undefined;
            for (&nullify_votes, others) |*vote, signer| {
                vote.* = (try Nullify.sign(gpa, &f.schemes[signer], round_at(1, 2))).?;
            }
            try testing.expect(try state.add_nullification(try types.Nullification(Scheme)
                .from_votes(gpa, &f.verifier, &nullify_votes, parallel.sequential)));
            try testing.expectEqual(6, state.current_view().get());
            try testing.expectEqual(3, state.leader_index(.new(6)).?.get());
            // The term-start proposal skips the blocked chain.
            const request = state.try_propose().?.context();
            try testing.expectEqual(1, request.parent[0].get());
            try testing.expect(request.parent[1].eql(.fill(1)));
            try testing.expect((try state.add_notarization(
                try notarization_from(f, &others, proposal(1, 2, 1, 2)),
            )).added);
            for ([_]u64{ 2, 3 }) |view| {
                try candidates.take(state);
                try candidates.expect_ready(view);
                try testing.expect(try state.certified(.new(view), true) != null);
            }
            const finalized = try finalization_from(f, &others, proposal(1, 4, 3, 4));
            try testing.expect((try state.add_finalization(finalized)).added);
            try candidates.take(state);
            try testing.expectEqual(0, candidates.ready.items.len);
            try testing.expectEqual(6, state.current_view().get());
        }
    }.body);
}

/// commonware `setup_follower_state`: signer 1, rotating leaders, slow timeouts.
const follower: Options = .{
    .signer = 1,
    .leader_timeout_ms = 10_000,
    .certification_timeout_ms = 10_000,
    .timeout_retry_ms = 30_000,
};

test "voter state a late nullification unblocks follower verify" {
    // commonware `late_nullification_unblocks_follower_verify`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, follower);
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 1, 0, 88));
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expect(try state.enter_view(.new(3)));
            try state.set_leader(.new(3), null);
            try testing.expectEqual(3, state.current_view().get());
            try testing.expectEqual(0, state.leader_index(.new(3)).?.get());
            const child = proposal(1, 3, 1, 89);
            try testing.expect(try state.set_proposal(.new(3), &child));
            const initial = state.next_timeout();
            try testing.expect(initial.deadline > context.now_ns(io));
            try testing.expect(state.try_verify() != .ready);
            try testing.expectEqual(initial, state.next_timeout());
            try testing.expect(try state.add_nullification(
                try build_nullification(&env.fixture, round_at(1, 2)),
            ));
            const verify = state.try_verify();
            try expect_ready(verify, child, 1, .fill(88));
            try testing.expectEqual(3, verify.ready.context.round.view.get());
        }
    }.body);
}

test "voter state resolution requests the first missing view" {
    // commonware `resolution_requests_first_missing_view`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, follower);
            defer env.stop();
            const state = &env.state;
            var notarized = try build_notarization(&env.fixture, proposal(1, 2, 0, 88));
            defer notarized.deinit(gpa);
            try testing.expect((try state.add_notarization(try notarized.clone(gpa))).added);
            try testing.expect(try state.certified(.new(2), true) != null);
            try state.set_leader(.new(3), null);
            try testing.expectEqual(3, state.current_view().get());
            try testing.expect(try state.set_proposal(.new(3), &proposal(1, 3, 1, 89)));
            const verify = state.try_verify();
            try expect_resolve_of(verify, 3, 2, .nullification);
            try testing.expectEqualDeep(env.fixture.participants[0], verify.resolve.target);
            // A repeated notarization is dropped (and freed) by the state.
            try testing.expect(!(try state.add_notarization(try notarized.clone(gpa))).added);
            try testing.expect(state.try_verify() == .wait);
        }
    }.body);
}

test "voter state resolution requests an uncertified parent" {
    // commonware `resolution_requests_uncertified_parent`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, follower);
            defer env.stop();
            const state = &env.state;
            const f = &env.fixture;
            try testing.expect(try state.add_nullification(
                try build_nullification(f, round_at(1, 1)),
            ));
            try testing.expect(try state.add_nullification(
                try build_nullification(f, round_at(1, 2)),
            ));
            try testing.expectEqual(3, state.current_view().get());
            try testing.expect(try state.set_proposal(.new(3), &proposal(1, 3, 1, 90)));
            try expect_resolve_of(state.try_verify(), 3, 1, .notarization);
            try testing.expect(!try state.add_nullification(
                try build_nullification(f, round_at(1, 1)),
            ));
            try testing.expect(state.try_verify() == .wait);
        }
    }.body);
}

test "voter state resolution is silent for a parent below the floor" {
    // commonware `resolution_silent_for_parent_below_floor`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, follower);
            defer env.stop();
            const state = &env.state;
            try testing.expect((try state.add_finalization(
                try build_finalization(&env.fixture, proposal(1, 2, 0, 91)),
            )).added);
            try testing.expectEqual(3, state.current_view().get());
            try testing.expect(try state.set_proposal(.new(3), &proposal(1, 3, 1, 92)));
            try testing.expect(state.try_verify() == .wait);
        }
    }.body);
}

test "voter state resolution starts at the first gap before a displaced certificate" {
    // commonware `resolution_starts_at_first_gap_before_displaced_certificate`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, follower);
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 3, 1, 95));
            try testing.expect(try state.certified(.new(3), true) != null);
            try testing.expect(try state.add_nullification(
                try build_nullification(&env.fixture, round_at(1, 4)),
            ));
            try testing.expectEqual(5, state.current_view().get());
            try testing.expect(try state.set_proposal(.new(5), &proposal(1, 5, 1, 96)));
            try expect_resolve_of(state.try_verify(), 5, 2, .nullification);
        }
    }.body);
}

test "voter state resolution rearms in the next round" {
    // commonware `resolution_rearms_in_next_round`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, follower);
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 2, 0, 97));
            try testing.expect(try state.certified(.new(2), true) != null);
            try state.set_leader(.new(3), null);
            try testing.expect(try state.set_proposal(.new(3), &proposal(1, 3, 1, 98)));
            try expect_resolve_of(state.try_verify(), 3, 2, .nullification);
            for ([_]u64{ 3, 4 }) |view| {
                try testing.expect(try state.add_nullification(
                    try build_nullification(&env.fixture, round_at(1, view)),
                ));
            }
            try testing.expectEqual(5, state.current_view().get());
            try testing.expect(try state.set_proposal(.new(5), &proposal(1, 5, 1, 99)));
            try expect_resolve_of(state.try_verify(), 5, 2, .nullification);
        }
    }.body);
}

test "voter state resolution does not wait for a local conflict" {
    // commonware `resolution_does_not_wait_for_local_conflict`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, follower);
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 2, 0, 100));
            try testing.expect(try state.enter_view(.new(3)));
            try state.set_leader(.new(3), null);
            try testing.expect(try state.set_proposal(.new(3), &proposal(1, 3, 1, 101)));
            try expect_resolve_of(state.try_verify(), 3, 2, .nullification);
            try testing.expect(try state.certified(.new(2), true) != null);
            try testing.expect(state.try_verify() == .wait);
        }
    }.body);
}

test "voter state resolution requests a named parent with a term cover" {
    // commonware `resolution_requests_named_parent_with_term_cover`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, .{ .term_length = 3 });
            defer env.stop();
            const state = &env.state;
            try testing.expect(try state.add_nullification(
                try build_nullification(&env.fixture, round_at(1, 1)),
            ));
            try testing.expectEqual(4, state.current_view().get());
            try testing.expect(try state.set_proposal(.new(4), &proposal(1, 4, 2, 102)));
            try expect_resolve_of(state.try_verify(), 4, 2, .notarization);
        }
    }.body);
}

test "voter state resolution requests an absent certificate" {
    // commonware `resolution_requests_absent_certificate`.
    try run(struct {
        fn body(io: Io) !void {
            var env: Env = undefined;
            try env.start(io, follower);
            defer env.stop();
            const state = &env.state;
            try add_notarized(state, &env.fixture, proposal(1, 1, 0, 93));
            try testing.expect(try state.certified(.new(1), true) != null);
            try testing.expect(try state.enter_view(.new(3)));
            try state.set_leader(.new(3), null);
            try testing.expect(try state.set_proposal(.new(3), &proposal(1, 3, 1, 94)));
            try expect_resolve_of(state.try_verify(), 3, 2, .nullification);
        }
    }.body);
}

const Artifact = types.Artifact(Scheme, Digest);

/// A journal of artifacts the test owns.
const Journal = struct {
    items: std.ArrayList(Artifact) = .empty,

    fn push(self: *Journal, artifact: Artifact) !void {
        try self.items.append(gpa, artifact);
    }

    fn deinit(self: *Journal) void {
        for (self.items.items) |*artifact| artifact.deinit(gpa);
        self.items.deinit(gpa);
    }
};

/// Sets, verifies, and votes for `value`; returns the vote as a journal artifact
/// (commonware `journaled_vote`).
fn journaled_vote(state: *base.State, value: Proposal) !Artifact {
    try testing.expect(try state.set_proposal(value.round.view, &value));
    try testing.expect(state.try_verify() == .ready);
    try testing.expect(state.verified(value.round.view));
    return .{ .notarize = (try state.construct_notarize(value.round.view)).? };
}

/// Votes for, notarizes, and certifies views 1 to `tip`, journaling each step
/// (commonware `certified_chain`).
fn certified_chain(env: *Env, journal: *Journal, tip: u64) !void {
    const state = &env.state;
    for (1..tip + 1) |view| {
        const value = proposal(9, view, view - 1, @intCast(view));
        try journal.push(try journaled_vote(state, value));
        const notarized = try build_notarization(&env.fixture, value);
        try journal.push(.{ .notarization = notarized });
        try testing.expect((try state.add_notarization(try notarized.clone(gpa))).added);
        try testing.expect(try state.certified(value.round.view, true) != null);
        try journal.push(.{ .certification = .{ .round = value.round, .certified = true } });
    }
}

/// Starts signer `signer`'s state and replays `journal` into it, adding each notarization
/// and certification as recovery does (commonware `replayed_state`).
fn replayed_state(env: *Env, io: Io, signer: usize, journal: *const Journal) !void {
    try env.start(io, handoff_options(4, signer));
    errdefer env.stop();
    const state = &env.state;
    for (journal.items.items) |*artifact| {
        try state.replay(artifact);
        switch (artifact.*) {
            .notarization => |*notarized| {
                const added = try state.add_notarization(try notarized.clone(gpa));
                try testing.expect(added.added);
            },
            .certification => |certification| {
                const view = certification.round.view;
                try testing.expect(try state.certified(view, certification.certified) != null);
            },
            else => {},
        }
    }
}

test "voter state a same-view replacement cannot prepare the displaced tip" {
    // commonware `same_view_replacement_cannot_prepare_displaced_tip`.
    try run(struct {
        fn body(io: Io) !void {
            var live: Env = undefined;
            try live.start(io, handoff_options(4, 3));
            defer live.stop();
            var journal: Journal = .{};
            defer journal.deinit();
            try certified_chain(&live, &journal, 4);
            const tip = proposal(9, 5, 4, 15);
            try journal.push(try journaled_vote(&live.state, tip));
            const stale = live.state.try_propose().?.context();
            try testing.expectEqual(5, stale.parent[0].get());
            try testing.expect(stale.parent[1].eql(tip.payload));
            const replacement = proposal(9, 5, 4, 25);
            try journal.push(.{
                .notarization = try notarization_from(&live.fixture, &.{ 0, 1, 2 }, replacement),
            });

            var restarted: Env = undefined;
            try replayed_state(&restarted, io, 3, &journal);
            defer restarted.stop();
            const state = &restarted.state;
            const found = state.find_parent(.new(6));
            try testing.expect(found == .found);
            try testing.expectEqual(5, found.found[0].get());
            try testing.expect(found.found[1].eql(replacement.payload));
            try testing.expect(!state.proposed(&stale, .fill(66)));
            try testing.expectEqual(null, try state.construct_notarize(.new(6)));
            try testing.expect(try state.certified(.new(5), true) != null);
            const request = state.try_propose().?;
            try testing.expect(!request.is_handoff());
            try testing.expectEqual(5, request.context().parent[0].get());
            try testing.expect(request.context().parent[1].eql(replacement.payload));
        }
    }.body);
}

test {
    _ = base;
}
