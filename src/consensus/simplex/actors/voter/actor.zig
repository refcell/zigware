//! The voter actor (commonware `actors/voter/actor.rs`): drives proposal, verification,
//! certification, voting, timeouts, and recovery from its journal.
//!
//! `P` declares `Scheme`, `Elector`, `Digest`, `Blocker`, `Automaton` (a certifiable
//! automaton, held by pointer), `Relay`, `Reporter`, and `Sender` (a p2p sender).
//!
//! Commonware's `select_loop!` becomes one `Inbox`: the mailbox is pumped into it, and each
//! automaton request runs as a task that pushes its response. A task is canceled to abort its
//! request; ids discard responses that raced the cancelation. Reported activities and relayed
//! payloads are borrowed for the call. Metrics and tracing spans are not ported yet.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const traits = @import("../../../traits.zig");
const types = @import("../../types.zig");
const config_mod = @import("../../config.zig");
const metrics = @import("../../metrics.zig");
const inbox_mod = @import("../inbox.zig");
const batcher_ingress = @import("../batcher/ingress.zig");
const resolver_ingress = @import("../resolver/ingress.zig");
const ingress = @import("ingress.zig");
const state_mod = @import("state.zig");

const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const ViewDelta = consensus_types.ViewDelta;
const Rnd = consensus_types.Round;
const Duration = utils.Duration;
const TimeoutReason = metrics.TimeoutReason;
const variable = storage.journal.segmented.variable;

pub fn Config(comptime P: type) type {
    return struct {
        scheme: *const P.Scheme,
        elector: P.Elector,
        blocker: P.Blocker,
        automaton: *P.Automaton,
        relay: P.Relay,
        reporter: P.Reporter,
        /// Owned by the actor.
        floor: config_mod.Floor(P.Scheme, P.Digest),
        partition: []const u8,
        epoch: Epoch,
        mailbox_size: u32,
        leader_timeout: Duration,
        certification_timeout: Duration,
        timeout_retry: Duration,
        skip_budget: u64,
        view_retention: ViewDelta,
        replay_buffer: usize,
        write_buffer: usize,
        cache_ref: *runtime.buffer.paged.CacheRef,
        storage: runtime.storage.Storage,
    };
}

pub fn Actor(comptime P: type) type {
    return struct {
        const Self = @This();
        const S = P.Scheme;
        const D = P.Digest;
        const State = state_mod.State(S, P.Elector, D);
        const Message = ingress.Message(S, D);
        pub const Mailbox = ingress.Mailbox(S, D);
        const BatcherMailbox = batcher_ingress.Mailbox(S, D);
        const ResolverMailbox = resolver_ingress.Mailbox(S, D);
        const Artifact = types.Artifact(S, D);
        const Activity = types.Activity(S, D);
        const Certificate = types.Certificate(S, D);
        const Notarization = types.Notarization(S, D);
        const Nullification = types.Nullification(S);
        const Finalization = types.Finalization(S, D);
        const Notarize = types.Notarize(S, D);
        const Finalize = types.Finalize(S, D);
        const Nullify = types.Nullify(S);
        const Vote = types.Vote(S, D);
        const Proposal = types.Proposal(D);
        const Journal = variable.Journal(Artifact);
        const Handoff = traits.Handoff(D);
        const Plan = @import("../../lookahead.zig").Plan(S.PublicKey);

        const Response = union(enum) { prepared: Handoff, proposed: D };
        const Event = union(enum) {
            mailbox: Message,
            proposed: struct { id: u64, response: ?Response },
            verified: struct { id: u64, round: Rnd, result: ?bool },
            certified: struct { id: u64, round: Rnd, result: ?bool },
            closed,
        };

        fn release(event: Event) void {
            if (event == .mailbox) Message.discard(event.mailbox);
        }

        const Inbox = inbox_mod.Inbox(Event, 64, release);

        /// Lifecycle of the pending proposal request.
        const ProposalState = union(enum) {
            /// The automaton is answering a handoff request.
            preparing,
            /// The automaton is answering an ordinary request.
            proposing,
            /// A handoff without a pending build; an ordinary request follows once the exact
            /// parent certifies.
            waiting,
            /// A relayed candidate whose broadcast and vote wait for parent certification.
            held: D,
            /// A handoff whose response closed; it forfeits the view once the parent certifies.
            closed,
        };

        const PendingProposal = struct {
            request: State.ProposalRequest,
            state: ProposalState,
            id: u64,
            future: ?Io.Future(void),
        };
        const PendingVerify = struct { round: Rnd, id: u64, future: Io.Future(void) };
        const CertifyTask = struct { view: View, id: u64, future: Io.Future(void) };

        /// Built and recorded during one iteration, published after the journal sync.
        const Staged = struct {
            nullify: ?struct { vote: Nullify, entry: ?Certificate } = null,
            certification: ?struct { certified: bool, notarization: *const Notarization } = null,
            notarize: ?Notarize = null,
            notarization: ?*const Notarization = null,
            nullification: ?*const Nullification = null,
            finalize: ?Finalize = null,
            finalization: ?*const Finalization = null,
        };

        /// What one event leaves for the `on_end` phase.
        const Outcome = union(enum) {
            skip,
            stop,
            notify: struct { view: View, staged: Staged },
        };

        /// The channels `run` owns.
        const Links = struct {
            inbox: *Inbox,
            batcher: BatcherMailbox,
            resolver: ResolverMailbox,
            vote_sender: *P.Sender,
            certificate_sender: *P.Sender,
        };

        gpa: Allocator,
        io: Io,
        state: State,
        blocker: P.Blocker,
        automaton: *P.Automaton,
        relay: P.Relay,
        reporter: P.Reporter,
        floor: ?config_mod.Floor(S, D),
        storage: runtime.storage.Storage,
        journal_config: Journal.Cfg,
        journal: ?Journal = null,
        dirty_section: ?View = null,
        mailbox_receiver: @import("actor").mailbox.Receiver(Message),
        pending_propose: ?PendingProposal = null,
        pending_verify: ?PendingVerify = null,
        certify_tasks: std.ArrayList(CertifyTask) = .empty,
        next_id: u64 = 0,

        pub fn init(gpa: Allocator, io: Io, cfg: Config(P)) !struct { Self, Mailbox } {
            const pair = try @import("actor").mailbox.new(Message, gpa, io, cfg.mailbox_size);
            const state = State.init(gpa, io, .{
                .scheme = cfg.scheme,
                .elector = cfg.elector,
                .epoch = cfg.epoch,
                .view_retention = cfg.view_retention,
                .leader_timeout = cfg.leader_timeout,
                .certification_timeout = cfg.certification_timeout,
                .timeout_retry = cfg.timeout_retry,
                .skip_budget = cfg.skip_budget,
            });
            const self: Self = .{
                .gpa = gpa,
                .io = io,
                .state = state,
                .blocker = cfg.blocker,
                .automaton = cfg.automaton,
                .relay = cfg.relay,
                .reporter = cfg.reporter,
                .floor = cfg.floor,
                .storage = cfg.storage,
                .journal_config = .{
                    .partition = cfg.partition,
                    .codec_config = cfg.scheme.certificate_codec_config(),
                    .cache_ref = cfg.cache_ref,
                    .write_buffer = cfg.write_buffer,
                    .replay_buffer = cfg.replay_buffer,
                },
                .mailbox_receiver = pair.receiver,
            };
            assert(self.journal == null);
            return .{ self, .{ .sender = pair.sender } };
        }

        pub fn deinit(self: *Self) void {
            assert(self.pending_propose == null and self.pending_verify == null);
            assert(self.certify_tasks.items.len == 0);
            if (self.floor) |*floor| switch (floor.*) {
                .finalized => |*finalization| finalization.deinit(self.gpa),
                .genesis => {},
            };
            if (self.journal) |*journal| journal.deinit();
            self.certify_tasks.deinit(self.gpa);
            self.mailbox_receiver.deinit();
            self.state.deinit();
            self.* = undefined;
        }

        // Journal.

        /// Appends `artifact` (borrowed) to its view's section; inert until replay attaches
        /// the journal. One iteration appends to a single section.
        fn append_journal(self: *Self, artifact: Artifact) !void {
            const journal = &(self.journal orelse return);
            const view = artifact.view();
            _ = try journal.append(view.get(), artifact);
            if (self.dirty_section) |dirty| {
                assert(dirty == view); // One iteration appends to a single journal section.
            } else self.dirty_section = view;
        }

        /// Syncs the section this iteration wrote, if any.
        fn sync_journal(self: *Self) !void {
            const view = self.dirty_section orelse return;
            try self.journal.?.sync(&.{view.get()});
            self.dirty_section = null;
        }

        /// Drops views and journal sections below the activity floor.
        fn prune_views(self: *Self) !void {
            var removed: std.ArrayList(View) = .empty;
            defer removed.deinit(self.gpa);
            try self.state.prune(&removed);
            if (removed.items.len == 0) return;
            if (self.journal) |*journal| _ = try journal.prune(self.state.min_active().get());
        }

        // Network.

        fn send_encoded(self: *Self, sender: *P.Sender, comptime T: type, value: T) !void {
            const bytes = try codec.encode(T, self.gpa, value);
            defer self.gpa.free(bytes);
            const sent = try sender.send(.all, &.{bytes}, true);
            self.gpa.free(sent);
        }

        /// Publishes a durable local vote to the batcher and every peer.
        fn publish_vote(self: *Self, links: *const Links, vote: Vote) !void {
            assert(self.dirty_section == null); // Votes are durable before they leave.
            try links.batcher.constructed(vote);
            try self.send_encoded(links.vote_sender, Vote, vote);
        }

        fn broadcast_certificate(self: *Self, links: *const Links, certificate: Certificate) !void {
            assert(self.dirty_section == null);
            try self.send_encoded(links.certificate_sender, Certificate, certificate);
        }

        fn block_equivocator(self: *Self, equivocator: ?S.PublicKey) void {
            const key = equivocator orelse return;
            _ = self.blocker.block(key);
        }

        // Automaton requests.

        fn take_id(self: *Self) u64 {
            self.next_id += 1;
            return self.next_id;
        }

        fn propose_task(self: *Self, inbox: *Inbox, request: State.ProposalRequest, id: u64) void {
            const response: ?Response = switch (request) {
                .prepare => |context| prepared: {
                    const handoff = traits.prepare(self.automaton, self.io, context) catch return;
                    break :prepared if (handoff) |value| .{ .prepared = value } else null;
                },
                .propose => |context| proposed: {
                    const payload = self.automaton.propose(self.io, context) catch return;
                    break :proposed if (payload) |value| .{ .proposed = value } else null;
                },
            };
            _ = inbox.push(.{ .proposed = .{ .id = id, .response = response } });
        }

        fn verify_task(
            self: *Self,
            inbox: *Inbox,
            context: State.Context,
            payload: D,
            id: u64,
        ) void {
            const result = self.automaton.verify(self.io, context, payload) catch return;
            const verified: @FieldType(Event, "verified") = .{
                .id = id,
                .round = context.round,
                .result = result,
            };
            _ = inbox.push(.{ .verified = verified });
        }

        fn certify_task(self: *Self, inbox: *Inbox, round: Rnd, payload: D, id: u64) void {
            const result = traits.certify(self.automaton, self.io, round, payload) catch return;
            _ = inbox.push(.{ .certified = .{ .id = id, .round = round, .result = result } });
        }

        /// Requests a proposal when the state machine has one ready.
        fn try_propose(self: *Self, inbox: *Inbox) !void {
            assert(self.pending_propose == null);
            const request = self.state.try_propose() orelse return;
            const id = self.take_id();
            const future = try self.io.concurrent(propose_task, .{ self, inbox, request, id });
            self.pending_propose = .{
                .request = request,
                .state = if (request.is_handoff()) .preparing else .proposing,
                .id = id,
                .future = future,
            };
        }

        /// Requests verification, or ancestry from the resolver.
        fn try_verify(self: *Self, links: *const Links) !void {
            assert(self.pending_verify == null);
            const ready = switch (self.state.try_verify()) {
                .ready => |ready| ready,
                .resolve => |resolve| {
                    return links.resolver.resolve(
                        resolve.proposal,
                        resolve.view,
                        resolve.kind,
                        resolve.target,
                    );
                },
                .wait => return,
            };
            const id = self.take_id();
            const args = .{ self, links.inbox, ready.context, ready.proposal.payload, id };
            const future = try self.io.concurrent(verify_task, args);
            self.pending_verify = .{ .round = ready.context.round, .id = id, .future = future };
        }

        fn drop_proposal_request(self: *Self) void {
            var pending = self.pending_propose orelse return;
            if (pending.future) |*future| future.cancel(self.io);
            self.pending_propose = null;
        }

        fn drop_verify_request(self: *Self) void {
            var pending = self.pending_verify orelse return;
            pending.future.cancel(self.io);
            self.pending_verify = null;
        }

        /// Drops obsolete application requests and dispatches eligible new ones.
        fn reconcile(self: *Self, links: *const Links) !void {
            const current = self.state.current_view();
            if (self.pending_propose) |pending| {
                const request_context = pending.request.context();
                if (pending.request.view().get() < current.get() or
                    self.state.supersede_proposal_request(&request_context))
                {
                    self.drop_proposal_request();
                }
            }
            if (self.pending_verify) |pending| {
                const view = pending.round.view;
                if (view.get() < current.get() or self.state.verification_superseded(view)) {
                    self.drop_verify_request();
                }
            }
            self.reconcile_handoff();
            if (self.pending_propose == null) try self.try_propose(links.inbox);
            if (self.pending_verify == null) try self.try_verify(links);
        }

        /// Cancels an abandoned handoff build, and resolves a waiting or closed handoff once
        /// its exact parent certifies.
        fn reconcile_handoff(self: *Self) void {
            const pending = &(self.pending_propose orelse return);
            const request_context = pending.request.context();
            if (pending.request == .prepare and pending.state == .preparing) {
                if (self.state.pending_handoff_abandonment(&request_context) != null) {
                    if (pending.future) |*future| future.cancel(self.io);
                    pending.future = null;
                    pending.state = .waiting;
                }
            }
            if (pending.state != .waiting and pending.state != .closed) return;
            const parent = request_context.parent;
            if (!self.state.parent_certified(.{ parent[0], parent[1] })) return;
            const view = pending.request.view();
            if (pending.state == .closed) {
                self.state.trigger_timeout(view, .missing_proposal);
            } else {
                self.state.release_proposal_request(view);
            }
            self.pending_propose = null;
        }

        /// Requests certification of every ready candidate, and fetches blocked parents.
        fn start_certifications(self: *Self, links: *const Links) !void {
            var ready: std.ArrayList(Proposal) = .empty;
            defer ready.deinit(self.gpa);
            var fetches: std.ArrayList(state_mod.CertificateFetch) = .empty;
            defer fetches.deinit(self.gpa);
            try self.state.certify_candidates(&ready, &fetches);
            for (fetches.items) |fetch| {
                try links.resolver.resolve(fetch.proposal, fetch.view, .notarization, null);
            }
            try self.certify_tasks.ensureUnusedCapacity(self.gpa, ready.items.len);
            for (ready.items) |candidate| {
                const id = self.take_id();
                const args = .{ self, links.inbox, candidate.round, candidate.payload, id };
                const future = try self.io.concurrent(certify_task, args);
                const view = candidate.view();
                const task: CertifyTask = .{ .view = view, .id = id, .future = future };
                self.certify_tasks.appendAssumeCapacity(task);
                try self.state.set_certify_outstanding(view);
            }
        }

        /// Cancels certification requests for views the state aborted or pruned.
        fn sweep_certifications(self: *Self) void {
            var index: usize = 0;
            while (index < self.certify_tasks.items.len) {
                const task = &self.certify_tasks.items[index];
                const tracked = self.state.rounds.get(task.view) != null;
                if (tracked and !self.state.is_certify_aborted(task.view)) {
                    index += 1;
                    continue;
                }
                task.future.cancel(self.io);
                _ = self.certify_tasks.swapRemove(index);
            }
        }

        fn cancel_all(self: *Self) void {
            self.drop_proposal_request();
            self.drop_verify_request();
            for (self.certify_tasks.items) |*task| task.future.cancel(self.io);
            self.certify_tasks.clearRetainingCapacity();
        }

        // Certificates.

        fn handle_nullification(self: *Self, nullification: Nullification) !bool {
            const view = nullification.view();
            if (!try self.state.add_nullification(nullification)) return false;
            try self.append_journal(.{ .nullification = self.state.nullification(view).?.* });
            return true;
        }

        fn handle_notarization(self: *Self, notarization: Notarization) !bool {
            const view = notarization.view();
            const added = try self.state.add_notarization(notarization);
            if (added.added) {
                try self.append_journal(.{ .notarization = self.state.notarization(view).?.* });
            }
            self.block_equivocator(added.equivocator);
            return added.added;
        }

        fn handle_finalization(self: *Self, finalization: Finalization) !bool {
            const view = finalization.view();
            const added = try self.state.add_finalization(finalization);
            if (added.added) {
                try self.append_journal(.{ .finalization = self.state.finalization(view).?.* });
            }
            self.block_equivocator(added.equivocator);
            return added.added;
        }

        fn handle_certification(self: *Self, view: View, success: bool) !?*const Notarization {
            const notarization = try self.state.certified(view, success) orelse return null;
            const round: Rnd = .new(self.state.epoch, view);
            const certification: types.Certification = .{ .round = round, .certified = success };
            try self.append_journal(.{ .certification = certification });
            return notarization;
        }

        /// Takes ownership of `certificate`; returns whether it was new.
        fn handle_certificate(self: *Self, certificate: Certificate) !bool {
            return switch (certificate) {
                .notarization => |notarization| self.handle_notarization(notarization),
                .nullification => |nullification| self.handle_nullification(nullification),
                .finalization => |finalization| self.handle_finalization(finalization),
            };
        }

        /// A clone of the certificate of `kind` the state holds for `view`.
        fn clone_certificate(
            self: *Self,
            kind: std.meta.Tag(Certificate),
            view: View,
        ) !Certificate {
            return switch (kind) {
                .notarization => .{
                    .notarization = try self.state.notarization(view).?.clone(self.gpa),
                },
                .nullification => .{
                    .nullification = try self.state.nullification(view).?.clone(self.gpa),
                },
                .finalization => .{
                    .finalization = try self.state.finalization(view).?.clone(self.gpa),
                },
            };
        }

        // Votes.

        fn prepare_notarize(self: *Self, view: View) !?Notarize {
            const notarize = try self.state.construct_notarize(view) orelse return null;
            try self.append_journal(.{ .notarize = notarize });
            return notarize;
        }

        fn prepare_finalize(self: *Self, view: View) !?Finalize {
            const finalize = try self.state.construct_finalize(view) orelse return null;
            try self.append_journal(.{ .finalize = finalize });
            return finalize;
        }

        /// Builds a nullify vote for the current view (journaled on the first attempt), with
        /// the best entry certificate on a retry.
        fn timeout(self: *Self, reason: TimeoutReason) !Staged {
            const view = self.state.current_view();
            const vote = try self.state.construct_nullify(view, reason) orelse return .{};
            if (!vote.retry) {
                try self.append_journal(.{ .nullify = vote.nullify });
                return .{ .nullify = .{ .vote = vote.nullify, .entry = null } };
            }
            const entry = try self.state.get_best_certificate();
            return .{ .nullify = .{ .vote = vote.nullify, .entry = entry } };
        }

        /// Builds and records the votes that became available for `view`, and takes its
        /// certificates not yet broadcast.
        fn construct(self: *Self, view: View, staged: *Staged) !void {
            staged.notarize = try self.prepare_notarize(view);
            staged.notarization = self.state.broadcast_notarization(view);
            staged.nullification = self.state.broadcast_nullification(view);
            staged.finalize = try self.prepare_finalize(view);
            staged.finalization = self.state.broadcast_finalization(view);
        }

        // Responses.

        /// Records the automaton's proposal. Returns the view to notify when recorded.
        fn process_proposed(
            self: *Self,
            request: State.ProposalRequest,
            payload: ?D,
        ) ?View {
            const request_context = request.context();
            const view = request_context.view();
            const value = payload orelse {
                self.state.trigger_timeout(view, .missing_proposal);
                return null;
            };
            if (view.get() < self.state.current_view().get()) return null;
            if (!self.state.proposed(&request_context, value)) return null;
            // Relay before the notarize vote's journal sync: extra payload bytes are harmless.
            _ = self.relay.broadcast(value, .{ .propose = .{ .round = request_context.round } });
            return view;
        }

        fn handle_proposed(self: *Self, id: u64, response: ?Response) !Outcome {
            const pending = self.pending_propose orelse return .skip;
            if (pending.id != id or pending.future == null) return .skip; // Stale response.
            var future = pending.future.?;
            future.await(self.io);
            self.pending_propose = null;
            const request = pending.request;
            const payload: ?D = if (response) |value| switch (value) {
                .proposed => |payload| payload,
                .prepared => |handoff| switch (handoff) {
                    .wait => return self.retain_handoff(pending, .waiting),
                    .stage => |payload| staged: {
                        const parent = request.context().parent;
                        const ready = self.state.parent_certified(.{ parent[0], parent[1] });
                        if (ready) break :staged payload;
                        // Relay now so distribution overlaps parent certification.
                        const plan: Plan = .{ .prepare = .{ .round = request.context().round } };
                        _ = self.relay.broadcast(payload, plan);
                        return self.retain_handoff(pending, .{ .held = payload });
                    },
                    .vote => |payload| payload,
                },
            } else null;
            if (payload == null and request.is_handoff()) {
                return self.retain_handoff(pending, .closed);
            }
            const view = self.process_proposed(request, payload) orelse return .skip;
            return .{ .notify = .{ .view = view, .staged = .{} } };
        }

        fn retain_handoff(self: *Self, pending: PendingProposal, state: ProposalState) Outcome {
            assert(self.pending_propose == null);
            var retained = pending;
            retained.future = null;
            retained.state = state;
            self.pending_propose = retained;
            return .skip;
        }

        /// A held candidate whose parent certified: only its broadcast and vote remain.
        fn release_held(self: *Self) ?View {
            const pending = self.pending_propose orelse return null;
            const payload = switch (pending.state) {
                .held => |payload| payload,
                else => return null,
            };
            const parent = pending.request.context().parent;
            if (!self.state.parent_certified(.{ parent[0], parent[1] })) return null;
            self.pending_propose = null;
            return self.process_proposed(pending.request, payload);
        }

        fn handle_verified(self: *Self, id: u64, round: Rnd, result: ?bool) Outcome {
            var pending = self.pending_verify orelse return .skip;
            if (pending.id != id) return .skip; // Stale response.
            pending.future.await(self.io);
            self.pending_verify = null;
            const view = round.view;
            if (result) |valid| {
                if (valid) {
                    _ = self.state.verified(view);
                } else self.state.verification_failed(view, .invalid_proposal);
            } else self.state.verification_failed(view, .ignored_proposal);
            return .{ .notify = .{ .view = view, .staged = .{} } };
        }

        fn handle_certified(self: *Self, id: u64, round: Rnd, result: ?bool) !Outcome {
            const index = for (self.certify_tasks.items, 0..) |task, i| {
                if (task.id == id) break i;
            } else return .skip; // Canceled.
            var task = self.certify_tasks.swapRemove(index);
            task.future.await(self.io);
            // A missing verdict is re-requested on restart; failing it could halt the view.
            const certified = result orelse return .skip;
            const notarization = try self.handle_certification(round.view, certified) orelse
                return .skip;
            return .{ .notify = .{ .view = round.view, .staged = .{ .certification = .{
                .certified = certified,
                .notarization = notarization,
            } } } };
        }

        /// Handles a message from the batcher or resolver (taking ownership).
        fn handle_message(self: *Self, links: *const Links, message: Message) !Outcome {
            switch (message) {
                .proposal => |proposal| {
                    const view = proposal.view();
                    if (!self.state.admits_vote(view)) return .skip;
                    if (!try self.state.set_proposal(view, &proposal)) return .skip;
                    return .{ .notify = .{ .view = view, .staged = .{} } };
                },
                .verified => |verified| {
                    const certificate = verified.certificate;
                    assert(verified.gpa.ptr == self.gpa.ptr); // One allocator per engine.
                    const view = certificate.view();
                    if (!self.state.admits_certificate(view)) {
                        Message.discard(message);
                        return .skip;
                    }
                    const kind = std.meta.activeTag(certificate);
                    if (try self.handle_certificate(certificate)) {
                        const clone = try self.clone_certificate(kind, view);
                        try links.resolver.updated(self.gpa, clone);
                    }
                    return .{ .notify = .{ .view = view, .staged = .{} } };
                },
                .timeout => |timeout_message| {
                    const view = timeout_message.round.view;
                    self.state.trigger_timeout(view, timeout_message.reason);
                    return .{ .notify = .{ .view = view, .staged = .{} } };
                },
            }
        }

        // Publication.

        /// Publishes the staged votes and certificates (after the journal sync).
        fn notify(self: *Self, links: *const Links, staged: *Staged) !void {
            assert(self.dirty_section == null); // The journal is synced before broadcast.
            if (staged.certification) |certification| {
                const clone = try certification.notarization.clone(self.gpa);
                try links.resolver.certified(self.gpa, clone, certification.certified);
                if (certification.certified) {
                    _ = self.reporter.report(.{ .certification = certification.notarization.* });
                }
            }
            if (staged.nullify) |*nullify| {
                try self.publish_vote(links, .{ .nullify = nullify.vote });
                if (nullify.entry) |*entry| {
                    defer entry.deinit(self.gpa);
                    try self.broadcast_certificate(links, entry.*);
                }
                nullify.entry = null;
            }
            if (staged.notarize) |notarize| try self.publish_vote(links, .{ .notarize = notarize });
            if (staged.notarization) |notarization| {
                try self.broadcast_certificate(links, .{ .notarization = notarization.* });
                _ = self.reporter.report(.{ .notarization = notarization.* });
            }
            if (staged.nullification) |nullification| {
                try self.broadcast_certificate(links, .{ .nullification = nullification.* });
                _ = self.reporter.report(.{ .nullification = nullification.* });
            }
            if (staged.finalize) |finalize| try self.publish_vote(links, .{ .finalize = finalize });
            if (staged.finalization) |finalization| {
                try self.broadcast_certificate(links, .{ .finalization = finalization.* });
                _ = self.reporter.report(.{ .finalization = finalization.* });
            }
        }

        // Startup.

        /// Applies the floor and replays the journal. Returns the floor finalization still to
        /// journal, if any.
        fn recover(self: *Self, links: *const Links) !?View {
            const floor = self.floor.?;
            self.floor = null;
            const replay_floor = floor.view();
            var floor_view: ?View = null;
            if (try self.state.set_floor(floor)) |finalization| {
                floor_view = finalization.view();
                try links.resolver.updated(self.gpa, .{
                    .finalization = try finalization.clone(self.gpa),
                });
                _ = self.reporter.report(.{ .finalization = finalization.* });
            }
            var recovery = try Journal.init(self.gpa, self.storage, self.journal_config);
            errdefer recovery.deinit();
            // Bounded by the journal's contents.
            while (try recovery.next()) |entry| {
                var artifact = entry.item;
                defer artifact.deinit(self.gpa);
                if (artifact == .finalization and artifact.view().get() >= replay_floor.get()) {
                    floor_view = null;
                }
                if (artifact.view().get() <= replay_floor.get()) continue;
                try self.replay_artifact(links, &artifact);
            }
            self.journal = try recovery.finish();
            try links.resolver.replayed();
            return floor_view;
        }

        /// Restores one journaled artifact (borrowed) and forwards what it implies.
        fn replay_artifact(self: *Self, links: *const Links, artifact: *const Artifact) !void {
            try self.state.replay(artifact);
            const view = artifact.view();
            switch (artifact.*) {
                .notarize => |notarize| _ = self.reporter.report(.{ .notarize = notarize }),
                .nullify => |nullify| _ = self.reporter.report(.{ .nullify = nullify }),
                .finalize => |finalize| _ = self.reporter.report(.{ .finalize = finalize }),
                .certification => |certification| {
                    const success = certification.certified;
                    const notarization = try self.handle_certification(view, success) orelse return;
                    const clone = try notarization.clone(self.gpa);
                    try links.resolver.certified(self.gpa, clone, success);
                    if (success) _ = self.reporter.report(.{ .certification = notarization.* });
                },
                inline .notarization, .nullification, .finalization => |certificate, tag| {
                    _ = try self.handle_certificate(@unionInit(
                        Certificate,
                        @tagName(tag),
                        try certificate.clone(self.gpa),
                    ));
                    try links.resolver.updated(self.gpa, @unionInit(
                        Certificate,
                        @tagName(tag),
                        try certificate.clone(self.gpa),
                    ));
                    _ = self.reporter.report(@unionInit(Activity, @tagName(tag), certificate));
                },
            }
        }

        // Event loop.

        /// Runs until the mailbox closes or the task is canceled. Takes ownership of the
        /// mailboxes; the senders stay the caller's.
        pub fn run(
            self: *Self,
            batcher: BatcherMailbox,
            resolver: ResolverMailbox,
            vote_sender: *P.Sender,
            certificate_sender: *P.Sender,
        ) !void {
            var inbox: Inbox = undefined;
            inbox.init(self.io);
            var links: Links = .{
                .inbox = &inbox,
                .batcher = batcher,
                .resolver = resolver,
                .vote_sender = vote_sender,
                .certificate_sender = certificate_sender,
            };
            defer links.batcher.deinit();
            defer links.resolver.deinit();
            defer inbox.shutdown();
            defer self.cancel_all();
            try inbox.forward(.mailbox, &self.mailbox_receiver);
            if (try self.recover(&links)) |view| {
                try self.append_journal(.{ .finalization = self.state.finalization(view).?.* });
                try self.sync_journal();
            }
            const current = self.state.current_view();
            const leader = self.state.leader_index(current) orelse @panic("leader not set");
            try links.batcher.update(current, leader, self.state.last_finalized(), null);
            // Runs for the actor's lifetime; each turn handles one event.
            while (try self.iteration(&links)) {}
            if (self.journal) |*journal| try journal.sync_all();
        }

        /// One `select_loop!` turn. Returns false once the mailbox closed.
        fn iteration(self: *Self, links: *const Links) !bool {
            try self.reconcile(links);
            try self.start_certifications(links);
            try self.prune_views();
            self.sweep_certifications();
            const start = self.state.current_view();
            const outcome = try self.next_outcome(links);
            var notified = switch (outcome) {
                .stop => return false,
                .skip => return true,
                .notify => |notified| notified,
            };
            try self.construct(notified.view, &notified.staged);
            try self.reconcile(links);
            try self.sync_journal();
            try self.notify(links, &notified.staged);
            const current = self.state.current_view();
            if (current.get() > start.get()) {
                const leader = self.state.leader_index(current) orelse @panic("leader not set");
                const previous = current.previous().?;
                const forwardable = self.state.forwardable_proposal(previous);
                try links.batcher.update(current, leader, self.state.last_finalized(), forwardable);
            }
            return true;
        }

        /// Waits for the next event or the timeout and handles it.
        fn next_outcome(self: *Self, links: *const Links) !Outcome {
            if (self.release_held()) |view| return .{ .notify = .{ .view = view, .staged = .{} } };
            const deadline = self.state.next_timeout();
            const event = try links.inbox.next_until(deadline.deadline) orelse {
                const staged = try self.timeout(deadline.reason);
                return .{ .notify = .{ .view = self.state.current_view(), .staged = staged } };
            };
            return switch (event) {
                .closed => .stop,
                .mailbox => |message| self.handle_message(links, message),
                .proposed => |proposed| self.handle_proposed(proposed.id, proposed.response),
                .verified => |done| self.handle_verified(done.id, done.round, done.result),
                .certified => |done| self.handle_certified(done.id, done.round, done.result),
            };
        }
    };
}
