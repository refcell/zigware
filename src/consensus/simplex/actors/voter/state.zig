//! The voter's per-epoch state machine (commonware `actors/voter/state.rs`): tracks proposals
//! and certificates for each view, decides when to propose, verify, certify, and vote, and
//! enforces the ancestry and same-term vote-safety rules. Vote aggregation and verification
//! belong to the batcher.
//!
//! Rounds live in a view-sorted `ViewMap`, and the `BTreeSet`s are `ViewSet`s. Times are
//! runtime nanoseconds. The optimistic-ancestry recursion is an iterative walk down the
//! uncertified chain. Metrics are not ported yet.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const config_mod = @import("../../config.zig");
const lookahead_mod = @import("../../lookahead.zig");
const metrics = @import("../../metrics.zig");
const context = @import("../context.zig");
const ask = @import("../ask.zig");
const round_mod = @import("round.zig");
const views_mod = @import("views.zig");

const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const ViewDelta = consensus_types.ViewDelta;
const Participant = consensus_types.Participant;
const TermLength = consensus_types.TermLength;
const Rnd = consensus_types.Round;
const TimeoutReason = metrics.TimeoutReason;
const Instant = round_mod.Instant;
const Duration = @import("utils").Duration;
const ViewSet = views_mod.ViewSet;

/// The view number of the genesis block.
pub const genesis_view: View = .zero();

/// Why a proposal's ancestry cannot yet produce a verification context.
pub const ParentPayloadError = union(enum) {
    parent_not_before_proposal: struct { proposal_view: View, parent_view: View },
    intra_term_proposal_skips_views: struct { proposal_view: View, parent_view: View },
    parent_before_finalized: struct {
        proposal_view: View,
        parent_view: View,
        last_finalized: View,
    },
    missing_nullification: struct { proposal_view: View, parent_view: View, missing_view: View },
    parent_not_certified: struct { proposal_view: View, parent_view: View },

    /// Whether the error permanently invalidates the proposal.
    pub fn invalid_proposal(self: ParentPayloadError) bool {
        return switch (self) {
            .parent_not_before_proposal,
            .intra_term_proposal_skips_views,
            .parent_before_finalized,
            => true,
            .missing_nullification, .parent_not_certified => false,
        };
    }
};

/// A certificate fetch justified by a blocked certification.
pub const CertificateFetch = struct {
    /// View of the candidate that exposed the missing certificate.
    proposal: View,
    /// View whose notarization is needed.
    view: View,
};

pub fn Config(comptime S: type, comptime E: type) type {
    return struct {
        scheme: *const S,
        elector: E,
        epoch: Epoch,
        view_retention: ViewDelta,
        leader_timeout: Duration,
        certification_timeout: Duration,
        timeout_retry: Duration,
        skip_budget: u64,
    };
}

fn nanos(duration: Duration) u64 {
    return @intCast(duration.as_nanos());
}

pub fn State(comptime S: type, comptime E: type, comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Round = round_mod.Round(S, D);
        const Proposal = types.Proposal(D);
        const Notarization = types.Notarization(S, D);
        const Nullification = types.Nullification(S);
        const Finalization = types.Finalization(S, D);
        const Notarize = types.Notarize(S, D);
        const Finalize = types.Finalize(S, D);
        const Nullify = types.Nullify(S);
        const Certificate = types.Certificate(S, D);
        pub const Context = types.Context(D, S.PublicKey);
        const Rounds = views_mod.ViewMap(Round);
        const Parent = struct { View, D };

        /// A proposal opportunity: `prepare` for a pipelined handoff on the outgoing term's
        /// uncertified final view, `propose` on certified or intra-term ancestry.
        pub const ProposalRequest = union(enum) {
            prepare: Context,
            propose: Context,

            pub fn is_handoff(self: ProposalRequest) bool {
                return self == .prepare;
            }

            pub fn context(self: ProposalRequest) Context {
                return switch (self) {
                    inline else => |value| value,
                };
            }

            pub fn view(self: ProposalRequest) View {
                return self.context().view();
            }
        };

        /// Outcome of `try_verify`.
        pub const Verify = union(enum) {
            ready: struct { context: Context, proposal: Proposal },
            resolve: struct { proposal: View, view: View, kind: ask.Kind, target: S.PublicKey },
            wait,
        };

        /// `find_parent`: the parent and its payload, or the view missing a certificate.
        pub const FindParent = union(enum) {
            found: Parent,
            missing: View,

            fn eql(self: FindParent, parent: Parent) bool {
                return switch (self) {
                    .found => |found| found[0] == parent[0] and digest_eql(found[1], parent[1]),
                    .missing => false,
                };
            }
        };

        pub const PayloadResult = union(enum) { payload: D, err: ParentPayloadError };

        gpa: Allocator,
        io: Io,
        scheme: *const S,
        elector: E,
        epoch: Epoch,
        lookahead: lookahead_mod.Lookahead,
        view_retention: ViewDelta,
        leader_timeout_ns: u64,
        certification_timeout_ns: u64,
        timeout_retry_ns: u64,
        skip_budget: u64,
        view: View = genesis_view,
        last_finalized_: View = genesis_view,
        genesis: ?D = null,
        rounds: Rounds = .empty,
        /// Monotone cursor for the oldest entered, unfinalized view (the stall anchor).
        stall_anchor: View = genesis_view,
        /// Views we voted to nullify (term safety for later same-term finalize votes).
        nullify_views: ViewSet = .empty,
        /// Views with nullification certificates.
        nullification_views: ViewSet = .empty,
        /// Views with a local certification rejection not covered by finalization.
        failed_certifications: ViewSet = .empty,
        certification_candidates: ViewSet = .empty,
        outstanding_certifications: ViewSet = .empty,
        /// Registered by the voter on its `state` scope; null in unit tests without one.
        metrics: ?Metrics = null,

        pub const Metrics = metrics.StateMetrics(S.PublicKey);

        pub fn init(gpa: Allocator, io: Io, cfg: Config(S, E)) Self {
            const terms = cfg.elector.terms();
            return .{
                .gpa = gpa,
                .io = io,
                .scheme = cfg.scheme,
                .elector = cfg.elector,
                .epoch = cfg.epoch,
                .lookahead = .init(terms),
                .view_retention = cfg.view_retention,
                .leader_timeout_ns = nanos(cfg.leader_timeout),
                .certification_timeout_ns = nanos(cfg.certification_timeout),
                .timeout_retry_ns = nanos(cfg.timeout_retry),
                .skip_budget = cfg.skip_budget,
            };
        }

        fn release_round(round: *Round, gpa: Allocator) void {
            round.deinit(gpa);
        }

        pub fn deinit(self: *Self) void {
            self.rounds.deinit(self.gpa, release_round);
            self.nullify_views.deinit(self.gpa);
            self.nullification_views.deinit(self.gpa);
            self.failed_certifications.deinit(self.gpa);
            self.certification_candidates.deinit(self.gpa);
            self.outstanding_certifications.deinit(self.gpa);
            if (self.metrics) |*registered| registered.deinit();
            self.* = undefined;
        }

        fn digest_eql(a: D, b: D) bool {
            return codec.order(D, a, b) == .eq;
        }

        fn now(self: *const Self) Instant {
            return context.now_ns(self.io);
        }

        fn round_at(self: *const Self, view: View) ?*Round {
            return self.rounds.get(view);
        }

        /// Whether `view` is within the optimistic issuance window: a directly notarized
        /// anchor exists at most `optimistic_views` hops below it (genesis counts).
        pub fn in_issuance_window(self: *const Self, view: View) bool {
            const floor = self.lookahead.issuance_floor(view) orelse return false;
            if (floor == genesis_view) return true;
            if (view.get() <= floor.get()) return false;
            var probes: u64 = 0;
            defer if (self.metrics) |registered| {
                registered.issuance_window_probes.metric().inc_by(probes);
            };
            for (self.rounds.range(floor, view.previous().?)) |entry| {
                probes += 1;
                if (entry.value.is_directly_notarized()) return true;
            }
            return false;
        }

        /// Whether `pending` is inside the issuance window that directly notarized `anchor`
        /// opens.
        fn in_issuance_window_from(self: *const Self, anchor: View, pending: View) bool {
            if (anchor.get() >= pending.get()) return false;
            const floor = self.lookahead.issuance_floor(pending) orelse return false;
            return floor.get() <= anchor.get();
        }

        /// Seeds the state machine with the genesis payload and enters view 1.
        pub fn set_genesis(self: *Self, genesis: D) Allocator.Error!void {
            assert(self.genesis == null);
            self.genesis = genesis;
            _ = try self.enter_view(genesis_view.next());
            try self.set_leader(genesis_view.next(), null);
        }

        /// Seeds the state machine from the configured floor. Returns the floor finalization
        /// to report, if any (taken as broadcast). Takes ownership of `floor`.
        pub fn set_floor(self: *Self, floor: config_mod.Floor(S, D)) !?*const Finalization {
            switch (floor) {
                .genesis => |genesis| {
                    try self.set_genesis(genesis);
                    return null;
                },
                .finalized => |floor_finalization| {
                    const view = floor_finalization.view();
                    _ = try self.add_finalization(floor_finalization);
                    return self.broadcast_finalization(view);
                },
            }
        }

        pub fn current_view(self: *const Self) View {
            return self.view;
        }

        pub fn last_finalized(self: *const Self) View {
            return self.last_finalized_;
        }

        /// The lowest view that must stay in memory for the activity timeout.
        pub fn min_active(self: *const Self) View {
            return self.viewport().floor();
        }

        fn term_length(self: *const Self) TermLength {
            return self.lookahead.term_length;
        }

        fn viewport(self: *const Self) lookahead_mod.Viewport {
            return .{
                .finalized = self.last_finalized_,
                .current = self.view,
                .view_retention = self.view_retention,
                .lookahead = self.lookahead,
            };
        }

        pub fn admits_vote(self: *const Self, pending: View) bool {
            return self.viewport().admits_vote(pending);
        }

        pub fn admits_certificate(self: *const Self, pending: View) bool {
            return self.viewport().admits_certificate(pending);
        }

        fn admits_outbound(self: *const Self, view: View) bool {
            return self.lookahead.admits_outbound(self.view, view);
        }

        /// Whether the local signer is participant `index`.
        pub fn is_me(self: *const Self, index: Participant) bool {
            const membership = self.scheme.me() orelse return false;
            const signer = membership.signer_index() orelse return false;
            return signer.get() == index.get();
        }

        /// Advances to `view`, arming its deadlines.
        pub fn enter_view(self: *Self, view: View) Allocator.Error!bool {
            if (view.get() <= self.view.get()) return false;
            const at = self.now();
            const stall: ?Instant = if (self.elector.terms().stall_timeout) |timeout|
                at + nanos(timeout)
            else
                null;
            const round = try self.create_round(view);
            round.mark_entered(at);
            round.open_span();
            round.set_deadlines(
                at + self.leader_timeout_ns,
                at + self.certification_timeout_ns,
                stall,
            );
            self.view = view;
            assert(self.view == view);
            if (self.metrics) |registered| {
                // A view beyond the gauge's range leaves it unchanged, as commonware's try_set.
                _ = registered.current_view.metric().try_set(view.get()) catch {};
            }
            return true;
        }

        pub fn leader_is_set(self: *const Self, view: View) bool {
            const round = self.round_at(view) orelse return false;
            return round.leader() != null;
        }

        fn elector_input(certificate: ?*const S.Certificate) E.Input {
            if (E.mode == .scheduled) return {};
            return certificate;
        }

        /// Sets the leader of `view` unless already set.
        pub fn set_leader(
            self: *Self,
            view: View,
            certificate: ?*const S.Certificate,
        ) Allocator.Error!void {
            if (self.leader_is_set(view)) return;
            const leader = self.elector.elect(.new(self.epoch, view), elector_input(certificate));
            (try self.create_round(view)).set_leader(leader);
        }

        /// Copies the same-term stable leader of `from` into `to` when `to` has none.
        fn inherit_leader(self: *Self, from: View, to: View) Allocator.Error!void {
            if (self.leader_is_set(to)) return;
            const source = self.round_at(from) orelse return;
            const leader = source.leader() orelse return;
            const index = leader.index;
            (try self.create_round(to)).set_leader(index);
        }

        pub fn create_round(self: *Self, view: View) Allocator.Error!*Round {
            const init_round = Round.init(self.scheme, .new(self.epoch, view));
            return self.rounds.get_or_put(self.gpa, view, init_round);
        }

        /// The next timeout and its reason.
        pub fn next_timeout(self: *Self) round_mod.Timeout {
            const at = self.now();
            const allow_latched = self.has_skip_budget();
            const round = self.round_at(self.view) orelse @panic("current round must exist");
            const retry_ns = self.timeout_retry_ns;
            const round_timeout = round.next_timeout(at, retry_ns, allow_latched) orelse
                @panic("current round must always have a timeout");
            // Once retrying a nullify, the retry cadence governs.
            if (round_timeout.reason == .retry) return round_timeout;
            // The stall anchor overrides only a round timeout that has not itself expired.
            const stall = self.next_stall_timeout() orelse return round_timeout;
            if (stall <= round_timeout.deadline and at < round_timeout.deadline) {
                return .{ .deadline = stall, .reason = .stall_timeout };
            }
            return round_timeout;
        }

        /// Whether the current term has skip budget left.
        fn has_skip_budget(self: *const Self) bool {
            const length = self.term_length();
            const first_unfinalized = self.last_finalized_.next().term_index(length);
            const current = self.view.term_index(length);
            assert(current >= first_unfinalized); // The current term never precedes it.
            return current - first_unfinalized < self.skip_budget;
        }

        /// The oldest entered, unfinalized view's stall deadline in the current term,
        /// advancing the cached anchor past skipped rounds.
        pub fn next_stall_timeout(self: *Self) ?Instant {
            const term_start = self.view.term_start(self.term_length());
            const unfinalized = self.last_finalized_.next();
            const floor: View = .new(@max(unfinalized.get(), term_start.get()));
            const start: View = .new(@max(self.stall_anchor.get(), floor.get()));
            for (self.rounds.range(start, self.view)) |entry| {
                const deadline = entry.value.stall_deadline() orelse continue;
                self.stall_anchor = entry.view;
                return deadline;
            }
            return null;
        }

        pub const NullifyVote = struct { retry: bool, nullify: Nullify };

        /// A nullify vote for the current view, if eligible. `reason` labels the timeout
        /// metric, which counts timed-out views, not retries.
        pub fn construct_nullify(self: *Self, view: View, reason: TimeoutReason) !?NullifyVote {
            if (view != self.view) return null;
            const round = try self.create_round(view);
            const retry = round.construct_nullify() orelse return null;
            const leader = round.leader();
            const nullify = try Nullify.sign(self.gpa, self.scheme, .new(self.epoch, view)) orelse
                return null;
            try self.nullify_views.insert(self.gpa, view);
            if (self.metrics) |registered| if (!retry) if (leader) |info| {
                try metrics.inc(registered.timeouts, .{ .leader = info.key, .reason = reason });
            };
            return .{ .retry = retry, .nullify = nullify };
        }

        /// The best certificate to help peers enter the current view (owned by the caller):
        /// finalization, then at a term start the previous term's highest nullification, then
        /// notarization.
        pub fn get_best_certificate(self: *const Self) Allocator.Error!?Certificate {
            const prev = self.view.previous() orelse @panic("never in the genesis view");
            if (prev == genesis_view) return null;
            if (self.finalization(prev)) |value| {
                return .{ .finalization = try value.clone(self.gpa) };
            }
            if (self.view.is_term_start(self.term_length())) {
                if (self.highest_nullification_in_term(prev)) |nullified| {
                    if (self.nullification(nullified)) |value| {
                        return .{ .nullification = try value.clone(self.gpa) };
                    }
                }
            }
            if (self.notarization(prev)) |value| {
                return .{ .notarization = try value.clone(self.gpa) };
            }
            return null;
        }

        pub const Added = Round.Added;

        /// Inserts a notarization (taking ownership) and prepares the next view's leader.
        /// Does not advance until certification passes.
        pub fn add_notarization(self: *Self, certificate: Notarization) Allocator.Error!Added {
            var owned = certificate;
            const view = owned.view();
            errdefer owned.deinit(self.gpa);
            try self.set_leader(view.next(), &owned.certificate);
            const round = try self.create_round(view);
            const result = round.add_notarization(owned);
            if (!result.added) {
                owned.deinit(self.gpa);
                return result;
            }
            if (view.get() > self.last_finalized_.get()) {
                try self.certification_candidates.insert(self.gpa, view);
            }
            try self.slide_optimistic_frontier(view);
            return result;
        }

        /// Inserts a nullification (taking ownership) and enters the next term's first view.
        /// Pending certification for the view is not canceled.
        pub fn add_nullification(self: *Self, certificate: Nullification) Allocator.Error!bool {
            var owned = certificate;
            const view = owned.view();
            errdefer owned.deinit(self.gpa);
            const next_view = view.next_term_start(self.term_length());
            _ = try self.enter_view(next_view);
            try self.set_leader(next_view, &owned.certificate);
            const round = try self.create_round(view);
            const added = round.add_nullification(owned);
            if (!added) owned.deinit(self.gpa);
            try self.nullification_views.insert(self.gpa, view);
            if (self.metrics) |registered| if (added) if (round.leader()) |info| {
                try metrics.inc(registered.nullifications, .{ .leader = info.key });
            };
            return added;
        }

        /// Inserts a finalization (taking ownership), updates the finalized view, and
        /// advances.
        pub fn add_finalization(self: *Self, certificate: Finalization) Allocator.Error!Added {
            var owned = certificate;
            const view = owned.view();
            errdefer owned.deinit(self.gpa);
            if (view.get() > self.last_finalized_.get()) self.finalize_through(view);
            _ = try self.enter_view(view.next());
            try self.set_leader(view.next(), &owned.certificate);
            const round = try self.create_round(view);
            const result = round.add_finalization(owned);
            if (!result.added) {
                owned.deinit(self.gpa);
                return result;
            }
            try self.wake_certification_child(view);
            try self.slide_optimistic_frontier(view);
            return result;
        }

        /// Raises the finalized view to `view`: rejections, candidates, and outstanding
        /// certifications at or below it no longer matter.
        fn finalize_through(self: *Self, view: View) void {
            assert(view.get() > self.last_finalized_.get());
            self.last_finalized_ = view;
            self.failed_certifications.retain_from(view.next());
            self.certification_candidates.retain_from(view.next());
            const end = self.outstanding_certifications.lower_bound(view.next());
            for (self.outstanding_certifications.items.items[0..end]) |outstanding| {
                if (self.round_at(outstanding)) |round| round.abort_certify();
            }
            self.outstanding_certifications.retain_from(view.next());
        }

        /// Whether an optimistic in-term `view` has usable ancestry for its parent.
        fn optimistic_parent_ready(self: *const Self, view: View) bool {
            const parent = self.previous_in_term(view) orelse return true;
            return self.optimistic_ancestry_payload(parent) != null;
        }

        /// A notarize vote for `view` when we are ready to sign.
        pub fn construct_notarize(self: *Self, view: View) !?Notarize {
            if (!self.admits_outbound(view)) return null;
            const round = self.round_at(view) orelse return null;
            if (!round.can_construct_notarize()) return null;
            if (self.in_issuance_window(view) and !self.optimistic_parent_ready(view)) return null;
            if (!self.verification_matches(view)) return null;
            const candidate = (round.construct_notarize() orelse return null).*;
            try self.prepare_optimistic_successor(view);
            return Notarize.sign(self.gpa, self.scheme, candidate);
        }

        /// A finalize vote, unless a same-term nullify vote not covered by a finalization
        /// blocks it.
        pub fn construct_finalize(self: *Self, view: View) !?Finalize {
            if (view.get() <= self.last_finalized_.get()) return null;
            if (!self.admits_outbound(view)) return null;
            if (self.highest_local_nullify_in_term(view)) |nullified| {
                if (nullified.get() > self.last_finalized_.get()) return null;
            }
            const round = self.round_at(view) orelse return null;
            const held = round.proposal() orelse return null;
            if (!self.explicit_parent_ready(held)) return null;
            const candidate = (round.construct_finalize() orelse return null).*;
            return Finalize.sign(self.gpa, self.scheme, candidate);
        }

        pub fn broadcast_notarization(self: *Self, view: View) ?*const Notarization {
            const round = self.round_at(view) orelse return null;
            return round.broadcast_notarization();
        }

        pub fn broadcast_nullification(self: *Self, view: View) ?*const Nullification {
            const round = self.round_at(view) orelse return null;
            return round.broadcast_nullification();
        }

        pub fn broadcast_finalization(self: *Self, view: View) ?*const Finalization {
            const round = self.round_at(view) orelse return null;
            return round.broadcast_finalization();
        }

        pub fn notarization(self: *const Self, view: View) ?*const Notarization {
            const round = self.round_at(view) orelse return null;
            return round.notarization();
        }

        pub fn nullification(self: *const Self, view: View) ?*const Nullification {
            const round = self.round_at(view) orelse return null;
            return round.nullification();
        }

        pub fn finalization(self: *const Self, view: View) ?*const Finalization {
            const round = self.round_at(view) orelse return null;
            return round.finalization();
        }

        pub fn forwardable_proposal(self: *const Self, view: View) ?Proposal {
            const round = self.round_at(view) orelse return null;
            const value = round.forwardable_proposal() orelse return null;
            return value.*;
        }

        /// Replays a journaled artifact: restores round flags and the safety indexes, and
        /// never advances the view. The artifact stays the caller's.
        pub fn replay(self: *Self, artifact: *const types.Artifact(S, D)) Allocator.Error!void {
            const view = artifact.view();
            switch (artifact.*) {
                .nullify => try self.nullify_views.insert(self.gpa, view),
                .nullification => try self.nullification_views.insert(self.gpa, view),
                .certification => |certification| {
                    if (!certification.certified and view.get() > self.last_finalized_.get()) {
                        try self.failed_certifications.insert(self.gpa, view);
                    }
                },
                else => {},
            }
            // Replay visits parents first. A parent without a direct certificate still holds
            // our vote's proposal, so the child's binding to that payload can be restored.
            var binding: ?Round.Verifying = null;
            if (artifact.* == .notarize) {
                const proposal_ = artifact.notarize.proposal;
                if (self.round_at(proposal_.parent)) |parent| {
                    if (!parent.is_directly_notarized()) if (parent.proposal()) |held| {
                        binding = .{ .proposal = proposal_, .parent_payload = held.payload };
                    };
                }
            }
            const round = try self.create_round(view);
            round.replay(artifact);
            if (binding) |bound| round.set_verifying(bound.proposal, bound.parent_payload);
            if (artifact.* == .notarize) try self.prepare_optimistic_successor(view);
        }

        pub fn leader_index(self: *const Self, view: View) ?Participant {
            const round = self.round_at(view) orelse return null;
            const leader = round.leader() orelse return null;
            return leader.index;
        }

        pub fn leader_key(self: *const Self, view: View) ?S.PublicKey {
            const round = self.round_at(view) orelse return null;
            const leader = round.leader() orelse return null;
            return leader.key;
        }

        pub fn elapsed_since_start(self: *const Self, view: View) ?u64 {
            const round = self.round_at(view) orelse return null;
            return round.elapsed_since_start(self.now());
        }

        pub fn elapsed_since_entry(self: *const Self, view: View) ?u64 {
            const round = self.round_at(view) orelse return null;
            return round.elapsed_since_entry(self.now());
        }

        /// Latches the first timeout of `view` (current or a tracked future view). An
        /// inactivity hint is ignored once an unequivocated proposal proves the leader active.
        pub fn trigger_timeout(self: *Self, view: View, reason: TimeoutReason) void {
            if (view.get() < self.view.get()) return;
            const round = self.round_at(view) orelse return;
            if (reason == .inactivity and round.has_unequivocated_proposal()) return;
            round.latch_timeout(self.now(), reason);
        }

        /// A proposal request for the lowest admissible tracked view ready to propose.
        pub fn try_propose(self: *Self) ?ProposalRequest {
            const limit = self.view.next_term_start(self.term_length());
            var cursor = self.view;
            // Bounded by the tracked rounds between the current view and `limit`.
            while (self.rounds.next_view(cursor)) |view| {
                if (view.get() > limit.get()) break;
                cursor = view.next();
                if (view == genesis_view or !self.admits_outbound(view)) continue;
                const round = self.round_at(view).?;
                if (!round.should_propose()) continue;
                // Resolve ancestry before claiming the one-shot build request.
                const parent = switch (self.find_parent(view)) {
                    .found => |found| found,
                    .missing => continue,
                };
                const is_handoff = view.is_term_start(self.term_length()) and
                    !self.parent_certified(parent);
                if (is_handoff and self.voted_nullify(self.view)) continue;
                const leader = round.try_propose() orelse continue;
                const request: Context = .{
                    .round = .new(self.epoch, view),
                    .leader = leader.key,
                    .parent = .{ parent[0], parent[1] },
                };
                return if (is_handoff) .{ .prepare = request } else .{ .propose = request };
            }
            return null;
        }

        /// Whether `parent` certified or finalized with exactly this payload.
        pub fn parent_certified(self: *const Self, parent: Parent) bool {
            const payload = self.explicit_ancestry_payload(parent[0]) orelse return false;
            return digest_eql(payload, parent[1]);
        }

        pub fn voted_nullify(self: *const Self, view: View) bool {
            return self.nullify_views.contains(view);
        }

        /// Why a pending handoff build on `request` should stop, or null while its result
        /// may still be used.
        pub fn pending_handoff_abandonment(
            self: *const Self,
            request: *const Context,
        ) ?metrics.HandoffAbandonedReason {
            if (self.parent_certified(.{ request.parent[0], request.parent[1] })) return null;
            if (self.voted_nullify(self.view)) return .parent_nullify;
            if (self.captured_parent_valid(request, self.find_parent(request.view()))) return null;
            return .ancestry_invalidated;
        }

        /// Records a proposal the automaton built, if its captured parent is still valid.
        pub fn proposed(self: *Self, request: *const Context, payload: D) bool {
            if (!self.captured_parent_valid(request, self.find_parent(request.view()))) {
                return false;
            }
            const value = Proposal.init(request.round, request.parent[0], payload);
            const round = self.round_at(value.view()) orelse return false;
            if (!round.proposed(self.now(), value)) return false;
            assert(round.proposal().?.eql(value));
            // Bind the captured parent payload, as replay does.
            round.set_verifying(value, request.parent[1]);
            return true;
        }

        /// Records `value` as our proposal without checking its parent (commonware
        /// `record_proposed`, which `proposed` runs after its parent check).
        pub fn record_proposed(self: *Self, value: Proposal) bool {
            const round = self.round_at(value.view()) orelse return false;
            return round.proposed(self.now(), value);
        }

        /// Releases the build latch when the captured parent is no longer valid and a
        /// replacement is selectable. Returns whether to drop the pending request.
        pub fn supersede_proposal_request(self: *Self, request: *const Context) bool {
            const preferred = self.find_parent(request.view());
            if (preferred == .missing or self.captured_parent_valid(request, preferred)) {
                return false;
            }
            self.release_proposal_request(request.view());
            return true;
        }

        /// Releases the build latch of `view` so `try_propose` can request it again.
        pub fn release_proposal_request(self: *Self, view: View) void {
            const round = self.round_at(view) orelse return;
            round.clear_proposal_request();
        }

        /// Whether the parent `request` captured is still usable: preferred, or still valid
        /// ancestry for the view.
        fn captured_parent_valid(
            self: *const Self,
            request: *const Context,
            preferred: FindParent,
        ) bool {
            if (preferred.eql(.{ request.parent[0], request.parent[1] })) return true;
            return switch (self.parent_payload_for(request.view(), request.parent[0])) {
                .payload => |payload| digest_eql(payload, request.parent[1]),
                .err => false,
            };
        }

        /// Sets the leader's proposal from the batcher. Returns whether to verify it.
        pub fn set_proposal(self: *Self, view: View, value: *const Proposal) !bool {
            try self.prepare_optimistic_successor(view);
            return (try self.create_round(view)).set_proposal(value);
        }

        /// The ancestry fetch a verification error justifies. An uncertified parent inside
        /// the issuance window is pending, not missing.
        fn resolve_ancestry(
            self: *const Self,
            err: ParentPayloadError,
        ) ?struct { View, ask.Kind } {
            return switch (err) {
                .missing_nullification => |missing| .{ missing.missing_view, .nullification },
                .parent_not_certified => |missing| {
                    if (self.in_issuance_window(missing.proposal_view)) return null;
                    return .{ missing.parent_view, .notarization };
                },
                else => null,
            };
        }

        /// Work for the lowest admissible tracked proposal awaiting verification.
        pub fn try_verify(self: *Self) Verify {
            const limit = self.view.next_term_start(self.term_length());
            var cursor = self.view;
            // Bounded by the tracked rounds between the current view and `limit`.
            while (self.rounds.next_view(cursor)) |view| {
                if (view.get() > limit.get()) break;
                cursor = view.next();
                if (!self.admits_outbound(view)) continue;
                const round = self.round_at(view).?;
                const leader, const value = round.pending_verification() orelse continue;
                const resolved = switch (self.parent_payload(&value)) {
                    .payload => |payload| payload,
                    .err => |err| {
                        if (err.invalid_proposal()) {
                            self.trigger_timeout(view, .invalid_proposal);
                            continue;
                        }
                        const missing, const kind = self.resolve_ancestry(err) orelse continue;
                        if (!round.request(missing)) continue;
                        return .{ .resolve = .{
                            .proposal = value.view(),
                            .view = missing,
                            .kind = kind,
                            .target = leader.key,
                        } };
                    },
                };
                // The claim retires the round from later scans, even when withheld.
                if (round.request_verify() != .send) continue;
                round.set_verifying(value, resolved);
                return .{ .ready = .{
                    .context = .{
                        .round = value.round,
                        .leader = leader.key,
                        .parent = .{ value.parent, resolved },
                    },
                    .proposal = value,
                } };
            }
            return .wait;
        }

        /// Whether a verification completion describes a proposal or parent since replaced;
        /// drops the stale binding.
        fn verification_is_stale(self: *Self, view: View) bool {
            if (self.verification_matches(view)) return false;
            if (self.round_at(view)) |round| round.clear_verifying();
            return true;
        }

        /// Whether a certificate replaced the proposal the in-flight verification is bound to.
        pub fn verification_superseded(self: *const Self, view: View) bool {
            const round = self.round_at(view) orelse return false;
            const bound = round.verifying() orelse return false;
            const held = round.proposal() orelse return true;
            return !held.eql(bound.proposal);
        }

        /// Marks verification complete when the peer payload validates.
        pub fn verified(self: *Self, view: View) bool {
            if (self.verification_is_stale(view)) return false;
            const round = self.round_at(view) orelse return false;
            return round.verified();
        }

        /// Latches `reason` after the automaton rejected or dropped a proposal.
        pub fn verification_failed(self: *Self, view: View, reason: TimeoutReason) void {
            if (self.verification_is_stale(view)) return;
            self.trigger_timeout(view, reason);
        }

        /// Records an in-flight certification request for `view`.
        pub fn set_certify_outstanding(self: *Self, view: View) Allocator.Error!void {
            const round = self.round_at(view) orelse return;
            round.set_certify_outstanding();
            try self.outstanding_certifications.insert(self.gpa, view);
        }

        /// Queues a blocked child once its required parent certifies or finalizes.
        fn wake_certification_child(self: *Self, parent: View) Allocator.Error!void {
            const child = parent.next();
            if (child.get() <= self.last_finalized_.get()) return;
            const round = self.round_at(child) orelse return;
            const held = round.proposal() orelse return;
            if (round.notarization() == null) return;
            const required = self.required_certification_parent(held) orelse return;
            if (required != parent) return;
            try self.certification_candidates.insert(self.gpa, child);
        }

        /// Takes the certification candidates: appends the proposals ready for
        /// certification to `ready` and the fetches for missing parents to `fetches`.
        pub fn certify_candidates(
            self: *Self,
            ready: *std.ArrayList(Proposal),
            fetches: *std.ArrayList(CertificateFetch),
        ) Allocator.Error!void {
            var candidates = self.certification_candidates;
            self.certification_candidates = .empty;
            defer candidates.deinit(self.gpa);
            for (candidates.items.items) |view| {
                if (view.get() <= self.last_finalized_.get()) continue;
                const round = self.round_at(view) orelse continue;
                const held = (round.proposal() orelse continue).*;
                if (self.certification_parent_ready(&held)) |err| {
                    if (err.invalid_proposal()) continue;
                    // Dormant candidates wake only through `wake_certification_child`.
                    assert(err == .parent_not_certified);
                    if (self.certification_fetch(err)) |fetch| try fetches.append(self.gpa, fetch);
                    continue;
                }
                if (round.pending_certification()) |candidate| {
                    try ready.append(self.gpa, candidate);
                }
            }
        }

        /// The fetch a blocked certification justifies: the parent's notarization, unless we
        /// already hold it (its certification is pending).
        fn certification_fetch(self: *const Self, err: ParentPayloadError) ?CertificateFetch {
            const blocked = switch (err) {
                .parent_not_certified => |blocked| blocked,
                else => return null,
            };
            if (self.notarization(blocked.parent_view) != null) return null;
            return .{ .proposal = blocked.proposal_view, .view = blocked.parent_view };
        }

        /// Marks certification complete. Returns the view's notarization (null when pruned).
        pub fn certified(
            self: *Self,
            view: View,
            is_success: bool,
        ) Allocator.Error!?*const Notarization {
            const round = self.round_at(view) orelse return null;
            round.certified(is_success);
            const notarized = round.notarization() orelse
                @panic("notarization must exist for certified view");
            self.outstanding_certifications.remove(view);
            if (!is_success and view.get() > self.last_finalized_.get()) {
                try self.failed_certifications.insert(self.gpa, view);
            }
            if (is_success) {
                // The stall deadline stays armed so the term can still be abandoned.
                _ = try self.enter_view(view.next());
                try self.wake_certification_child(view);
            } else {
                self.trigger_timeout(view, .failed_certification);
            }
            return notarized;
        }

        /// Whether `view`'s root span is open (commonware `view_span` is not `MISSING_SPAN`).
        pub fn view_span_open(self: *const Self, view: View) bool {
            const round = self.round_at(view) orelse return false;
            return round.span_open();
        }

        /// Closes the root span of every decided view (at or below the finalized view), so
        /// each view's trace ends when the chain commits it.
        pub fn close_decided_spans(self: *Self) void {
            const decided = self.rounds.range(genesis_view, self.last_finalized_);
            for (decided) |entry| self.rounds.get(entry.view).?.close_span();
            assert(!self.view_span_open(self.last_finalized_));
        }

        /// Drops rounds below the activity horizon and stale safety indexes; appends the
        /// removed views to `removed`.
        pub fn prune(self: *Self, removed: *std.ArrayList(View)) Allocator.Error!void {
            const min = self.min_active();
            try self.rounds.prune_below(self.gpa, min, release_round, removed);
            self.nullification_views.retain_from(min);
            self.nullify_views.retain_from(min);
            assert(self.rounds.len() == 0 or self.rounds.entries.items[0].view.get() >= min.get());
            if (self.metrics) |registered| {
                _ = registered.tracked_views.metric().try_set(self.rounds.len()) catch {};
            }
        }

        fn genesis_payload(self: *const Self) D {
            return self.genesis orelse @panic("genesis must be present");
        }

        /// The payload of `view`'s explicitly certified (or finalized) proposal.
        pub fn explicit_ancestry_payload(self: *const Self, view: View) ?D {
            if (view == genesis_view) return self.genesis_payload();
            const round = self.round_at(view) orelse return null;
            return round.certified_payload();
        }

        /// The highest view of `view`'s term, at or below it, with a nullification.
        fn highest_nullification_in_term(self: *const Self, view: View) ?View {
            const low, const high = view.covering_range(self.term_length());
            return self.nullification_views.highest_in(low, high);
        }

        /// The highest view below `view` in its term that we voted to nullify.
        fn highest_local_nullify_in_term(self: *const Self, view: View) ?View {
            const term_start = view.term_start(self.term_length());
            return self.nullify_views.highest_below(term_start, view);
        }

        /// `parent`'s payload under the rule `child` is entitled to: optimistic inside the
        /// issuance window, explicit outside it.
        fn ancestry_payload_for_child(self: *const Self, child: View, parent: View) ?D {
            if (self.in_issuance_window(child)) return self.optimistic_ancestry_payload(parent);
            return self.explicit_ancestry_payload(parent);
        }

        /// Whether `view` or a same-term predecessor has an unresolved certification
        /// rejection.
        fn has_failed_optimistic_ancestry(self: *const Self, view: View) bool {
            const term_start = view.term_start(self.term_length());
            return self.failed_certifications.highest_in(term_start, view) != null;
        }

        /// The leader of the term starting at `view`, elected before the certificate that
        /// unlocks it exists (null when `view` starts no term or the elector is dynamic).
        fn handoff_leader(self: *const Self, view: View) ?Participant {
            if (!view.is_term_start(self.term_length())) return null;
            if (E.mode != .scheduled) return null;
            return self.elector.elect(.new(self.epoch, view), {});
        }

        /// Whether `parent` can support a pipelined handoff: it ends a term we lead next, and
        /// the outgoing term has no nullification.
        fn is_handoff_parent(self: *const Self, parent: View) bool {
            const leader = self.handoff_leader(parent.next()) orelse return false;
            if (!self.is_me(leader)) return false;
            return self.highest_nullification_in_term(parent) == null;
        }

        const Link = struct { payload: D, parent: ?View, expected_parent: ?D };

        /// One step of `optimistic_ancestry_payload`: a terminal payload (genesis or a direct
        /// certificate, `parent` null), or our own uncertified proposal with its parent and
        /// recorded binding; null when `view` is not usable.
        fn optimistic_link(self: *const Self, view: View) ?Link {
            if (view == genesis_view) {
                const payload = self.genesis_payload();
                return .{ .payload = payload, .parent = null, .expected_parent = null };
            }
            const round = self.round_at(view) orelse return null;
            if (round.is_directly_notarized()) {
                if (self.has_failed_optimistic_ancestry(view)) return null;
                const payload = round.certificate_ancestry_payload() orelse return null;
                return .{ .payload = payload, .parent = null, .expected_parent = null };
            }
            if (!self.in_issuance_window(view.next()) and !self.is_handoff_parent(view)) {
                return null;
            }
            if (!round.has_unequivocated_proposal()) return null;
            if (!round.broadcast_notarize() or !round.is_verified()) return null;
            const held = round.proposal() orelse return null;
            if (held.parent.get() < self.last_finalized_.get()) return null;
            if (held.parent.get() >= view.get()) return null;
            if (self.first_unnullified_view(held.parent, held.view()) != null) return null;
            const expected: ?D = if (round.verifying()) |bound| bound.parent_payload else null;
            return .{ .payload = held.payload, .parent = held.parent, .expected_parent = expected };
        }

        /// The payload of a parent usable as optimistic ancestry: a certificate-backed
        /// payload, or our own verified, unequivocated, notarize-broadcast proposal whose
        /// whole uncertified chain is usable and matches each recorded parent binding.
        pub fn optimistic_ancestry_payload(self: *const Self, start: View) ?D {
            var view = start;
            var top: ?D = null;
            var expected: ?D = null;
            // Each link moves to a strictly lower tracked view (or genesis).
            const links_max = self.rounds.len() + 1;
            for (0..links_max) |_| {
                const link = self.optimistic_link(view) orelse return null;
                if (top == null) top = link.payload;
                if (expected) |binding| if (!digest_eql(binding, link.payload)) return null;
                view = link.parent orelse return top;
                expected = link.expected_parent;
            }
            return null;
        }

        /// Pushes the optimistic frontier one view: a same-term successor inherits the stable
        /// leader; at a term end, the incoming leader stamps itself once it voted.
        fn prepare_optimistic_successor(self: *Self, view: View) Allocator.Error!void {
            const next = view.next();
            if (self.in_issuance_window(next)) return self.inherit_leader(view, next);
            const round = self.round_at(view) orelse return;
            if (!round.broadcast_notarize()) return;
            const leader = self.handoff_leader(next) orelse return;
            if (!self.is_me(leader) or self.leader_is_set(next)) return;
            (try self.create_round(next)).set_leader(leader);
        }

        /// Extends the optimistic frontier through the issuance window `view`'s notarization
        /// opened.
        fn slide_optimistic_frontier(self: *Self, view: View) Allocator.Error!void {
            var frontier = view;
            var next = frontier.next();
            // The window spans at most `optimistic_views + 1` views above the anchor.
            const steps_max = self.lookahead.optimistic_views.get() + 2;
            for (0..steps_max) |_| {
                if (!self.in_issuance_window_from(view, next)) return;
                try self.inherit_leader(frontier, next);
                frontier = next;
                next = frontier.next();
            }
            unreachable; // Proof: the issuance window bounds the walk.
        }

        /// Whether the binding recorded for `view` (proposal and parent payload) still holds.
        fn verification_matches(self: *const Self, view: View) bool {
            const round = self.round_at(view) orelse return true;
            const bound = round.verifying() orelse return true;
            const held = round.proposal() orelse return false;
            if (!held.eql(bound.proposal)) return false;
            switch (self.parent_payload(held)) {
                .payload => |payload| if (digest_eql(payload, bound.parent_payload)) return true,
                .err => {},
            }
            // Our own pipelined handoff binds the uncertified parent `find_parent` selects.
            const leader = self.leader_index(view) orelse return false;
            if (!self.is_me(leader)) return false;
            return self.find_parent(view).eql(.{ held.parent, bound.parent_payload });
        }

        fn previous_in_term(self: *const Self, view: View) ?View {
            if (view == genesis_view or view.is_term_start(self.term_length())) return null;
            return view.previous().?;
        }

        /// The first view in `(after, before)` without a covering nullification.
        fn first_unnullified_view(self: *const Self, after: View, before: View) ?View {
            var cursor = after.next();
            // Each step jumps to the next term start, so the loop runs at most once per term.
            while (cursor.get() < before.get()) {
                if (self.highest_nullification_in_term(cursor) == null) return cursor;
                cursor = cursor.next_term_start(self.term_length());
            }
            return null;
        }

        pub fn is_certify_aborted(self: *const Self, view: View) bool {
            const round = self.round_at(view) orelse return false;
            return round.is_certify_aborted();
        }

        /// The parent for `view`: in a term, the previous view under the child's ancestry
        /// rule; at a term start, the highest certified view below (or genesis) with every
        /// view between nullified, or a pipelined handoff parent.
        pub fn find_parent(self: *const Self, view: View) FindParent {
            const previous = view.previous() orelse @panic("genesis has no parent");
            if (!view.is_term_start(self.term_length())) {
                const payload = self.ancestry_payload_for_child(view, previous) orelse
                    return .{ .missing = previous };
                return .{ .found = .{ previous, payload } };
            }
            var candidate: Parent = .{ genesis_view, undefined };
            var found = false;
            const below = self.rounds.range(genesis_view, previous);
            var index = below.len;
            while (index > 0) {
                index -= 1;
                const payload = below[index].value.certified_payload() orelse continue;
                candidate = .{ below[index].view, payload };
                found = true;
                break;
            }
            if (!found) candidate[1] = self.genesis orelse
                @panic("genesis must be set when finding parent with no certified views");
            if (self.first_unnullified_view(candidate[0], view)) |missing| {
                if (self.is_handoff_parent(previous)) {
                    if (self.optimistic_ancestry_payload(previous)) |payload| {
                        return .{ .found = .{ previous, payload } };
                    }
                }
                return .{ .missing = missing };
            }
            return .{ .found = candidate };
        }

        pub fn parent_payload(self: *const Self, value: *const Proposal) PayloadResult {
            return self.parent_payload_for(value.view(), value.parent);
        }

        /// The parent's payload when it precedes `view`, is not below the finalized view, is
        /// certified (or finalized), and every view between is nullified.
        fn parent_payload_for(self: *const Self, view: View, parent: View) PayloadResult {
            if (self.validate_parent_span(view, parent)) |err| return .{ .err = err };
            if (self.ancestry_payload_for_child(view, parent)) |payload| {
                return .{ .payload = payload };
            }
            return .{ .err = not_certified(view, parent) };
        }

        /// Null when certification may run for `value`; certification waits for explicitly
        /// certified (or finalized) parent ancestry.
        fn certification_parent_ready(
            self: *const Self,
            value: *const Proposal,
        ) ?ParentPayloadError {
            const view = value.view();
            if (ensure_parent_precedes(view, value.parent)) |err| return err;
            const required = self.required_certification_parent(value) orelse return null;
            if (self.validate_parent_span(view, value.parent)) |err| return err;
            if (self.explicit_ancestry_payload(required) != null) return null;
            return not_certified(view, value.parent);
        }

        /// The parent whose explicit certification gates `value`: the in-term predecessor,
        /// or, for a term-start proposal naming its predecessor, that predecessor once we (as
        /// the early-elected leader) broadcast a notarize vote in its view.
        fn required_certification_parent(self: *const Self, value: *const Proposal) ?View {
            const view = value.view();
            if (self.previous_in_term(view)) |previous| return previous;
            const previous = view.previous() orelse return null;
            if (value.parent != previous) return null;
            const leader = self.handoff_leader(view) orelse return null;
            if (!self.is_me(leader)) return null;
            const round = self.round_at(view) orelse return null;
            if (!round.broadcast_notarize()) return null;
            return previous;
        }

        fn explicit_parent_ready(self: *const Self, value: *const Proposal) bool {
            const parent = self.required_certification_parent(value) orelse return true;
            return self.explicit_ancestry_payload(parent) != null;
        }

        fn not_certified(view: View, parent: View) ParentPayloadError {
            return .{ .parent_not_certified = .{ .proposal_view = view, .parent_view = parent } };
        }

        fn ensure_parent_precedes(view: View, parent: View) ?ParentPayloadError {
            if (view.get() > parent.get()) return null;
            return .{ .parent_not_before_proposal = .{
                .proposal_view = view,
                .parent_view = parent,
            } };
        }

        /// The structural rules linking a proposal to its parent view.
        fn validate_parent_span(self: *const Self, view: View, parent: View) ?ParentPayloadError {
            if (ensure_parent_precedes(view, parent)) |err| return err;
            if (parent.get() < self.last_finalized_.get()) return .{ .parent_before_finalized = .{
                .proposal_view = view,
                .parent_view = parent,
                .last_finalized = self.last_finalized_,
            } };
            if (!view.is_term_start(self.term_length()) and view != parent.next()) {
                return .{ .intra_term_proposal_skips_views = .{
                    .proposal_view = view,
                    .parent_view = parent,
                } };
            }
            if (self.first_unnullified_view(parent, view)) |missing| {
                return .{ .missing_nullification = .{
                    .proposal_view = view,
                    .parent_view = parent,
                    .missing_view = missing,
                } };
            }
            return null;
        }
    };
}

test {
    _ = @import("state_test.zig");
    _ = @import("state_late_test.zig");
}
