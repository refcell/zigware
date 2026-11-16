//! The batcher actor (commonware `actors/batcher/actor.rs`): receives votes and certificates
//! from the network, checks and batches them per round, builds certificates once a quorum
//! verifies, and hands certificates to the voter.
//!
//! `P` declares `Scheme`, `Blocker`, `Digest`, `Reporter`, `Relay`, `Strategy`, and
//! `Receiver` (a p2p receiver). Events go to `tracer` under commonware's target; its spans
//! and metrics are not ported yet.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const actor = @import("actor");
const p2p = @import("p2p");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const config_mod = @import("../../config.zig");
const lookahead_mod = @import("../../lookahead.zig");
const metrics = @import("../../metrics.zig");
const context = @import("../context.zig");
const inbox_mod = @import("../inbox.zig");
const ingress = @import("ingress.zig");
const round_mod = @import("round.zig");
const voter_ingress = @import("../voter/ingress.zig");
const Tracer = @import("runtime").telemetry.traces.Tracer;

/// The tracing target of the batcher's events (commonware's module path).
pub const trace_target = "commonware_consensus::simplex::actors::batcher";

const View = consensus_types.View;
const Epoch = consensus_types.Epoch;
const Participant = consensus_types.Participant;
const ViewDelta = consensus_types.ViewDelta;

pub fn Config(comptime P: type) type {
    return struct {
        scheme: *const P.Scheme,
        blocker: P.Blocker,
        reporter: P.Reporter,
        track_historical_votes: bool,
        relay: P.Relay,
        strategy: P.Strategy,
        view_retention: ViewDelta,
        skip: config_mod.SkipPolicy,
        epoch: Epoch,
        mailbox_size: u32,
        lookahead: lookahead_mod.Lookahead,
        forward: config_mod.ForwardPolicy,
        floor: View,
    };
}

pub fn Actor(comptime P: type) type {
    return struct {
        const Self = @This();
        const S = P.Scheme;
        const D = P.Digest;
        const Round = round_mod.Round(S, P.Blocker, D, P.Reporter);
        const Message = ingress.Message(S, D);
        const NetMessage = p2p.Message(S.PublicKey);
        const VoterMailbox = voter_ingress.Mailbox(S, D);
        pub const Mailbox = ingress.Mailbox(S, D);

        const Event = union(enum) {
            mailbox: Message,
            vote: NetMessage,
            certificate: NetMessage,
            closed,
        };

        fn release(event: Event) void {
            switch (event) {
                .vote, .certificate => |message| {
                    var owned = message;
                    owned.deinit();
                },
                .mailbox, .closed => {},
            }
        }

        const Inbox = inbox_mod.Inbox(Event, 64, release);
        const Entry = struct { view: View, round: *Round };
        const Current = struct {
            view: View,
            leader: ?Participant,
            leader_nullify_hinted: bool,
        };

        gpa: Allocator,
        io: Io,
        cfg: Config(P),
        mailbox_receiver: actor.mailbox.Receiver(Message),
        last_activity: []?i96,
        required_active: u32,
        current: Current = .{ .view = .zero(), .leader = null, .leader_nullify_hinted = false },
        finalized: View,
        /// Rounds by ascending view.
        work: std.ArrayList(Entry) = .empty,
        dirty_views: std.ArrayList(View) = .empty,
        /// Receives the batcher's events; the engine sets it from its context.
        tracer: Tracer = .none,

        pub fn init(gpa: Allocator, io: Io, cfg: Config(P)) !struct { Self, Mailbox } {
            const participants = cfg.scheme.participants();
            const count: u32 = @intCast(participants.len());
            assert(count > 0);
            const pair = try actor.mailbox.new(Message, gpa, io, cfg.mailbox_size);
            errdefer {
                var receiver = pair.receiver;
                receiver.deinit();
                var sender = pair.sender;
                sender.deinit();
            }
            const last_activity = try gpa.alloc(?i96, count);
            @memset(last_activity, null);
            var required_active = participants.quorum(S.Faults);
            if (signer_of(cfg.scheme) != null) required_active -= 1;
            const self: Self = .{
                .gpa = gpa,
                .io = io,
                .cfg = cfg,
                .mailbox_receiver = pair.receiver,
                .last_activity = last_activity,
                .required_active = required_active,
                .finalized = cfg.floor,
            };
            return .{ self, .{ .sender = pair.sender } };
        }

        pub fn deinit(self: *Self) void {
            for (self.work.items) |entry| self.destroy_round(entry.round);
            self.work.deinit(self.gpa);
            self.dirty_views.deinit(self.gpa);
            self.gpa.free(self.last_activity);
            self.mailbox_receiver.deinit();
            self.* = undefined;
        }

        fn signer_of(scheme: *const S) ?Participant {
            const membership = scheme.me() orelse return null;
            return membership.signer_index();
        }

        /// Runs until the mailbox or a network channel closes, or the task is canceled. Takes
        /// ownership of `voter`; the receivers stay the caller's.
        pub fn run(
            self: *Self,
            voter: VoterMailbox,
            votes: *P.Receiver,
            certificates: *P.Receiver,
        ) (Io.Cancelable || Io.ConcurrentError || Allocator.Error)!void {
            var voter_mailbox = voter;
            defer voter_mailbox.deinit();
            var inbox: Inbox = undefined;
            inbox.init(self.io);
            defer inbox.shutdown();
            try inbox.forward(.mailbox, &self.mailbox_receiver);
            try inbox.forward(.vote, votes);
            try inbox.forward(.certificate, certificates);
            // Runs for the actor's lifetime; each turn handles one event.
            while (true) {
                const event = try inbox.next();
                switch (event) {
                    .closed => {
                        self.tracer.event(.debug, "source closed, stopping batcher", .{});
                        return;
                    },
                    .mailbox => |message| try self.handle_mailbox(voter_mailbox, message),
                    .certificate => |message| {
                        var owned = message;
                        defer owned.deinit();
                        try self.handle_certificate(voter_mailbox, owned.peer, owned.payload);
                    },
                    .vote => |message| {
                        var owned = message;
                        defer owned.deinit();
                        try self.handle_vote(voter_mailbox, owned.peer, owned.payload);
                    },
                }
                try self.process_dirty(voter_mailbox);
            }
        }

        fn handle_mailbox(self: *Self, voter: VoterMailbox, message: Message) !void {
            switch (message) {
                .update => |update| try self.handle_update(voter, update),
                .constructed => |vote| {
                    const view = vote.view();
                    if (!self.viewport().retains(view)) return;
                    const round = try self.round_for_view(view);
                    _ = try round.accept_vote(self.gpa, vote, true);
                    try self.dirty_views.append(self.gpa, view);
                },
            }
        }

        fn handle_update(self: *Self, voter: VoterMailbox, update: Message.Update) !void {
            const me = signer_of(self.cfg.scheme);
            const am_leader = me != null and me.?.get() == update.leader.get();
            self.current = .{
                .view = update.current,
                .leader = update.leader,
                .leader_nullify_hinted = false,
            };
            self.finalized = update.finalized;
            _ = try self.round_for_view(update.current);
            try self.dirty_views.append(self.gpa, update.current);
            const limit = self.cfg.lookahead.admission_limit(update.current);
            for (self.work.items) |entry| {
                const ahead = entry.view.get() > update.current.get();
                if (!ahead or entry.view.get() > limit.get()) continue;
                self.stamp_leader(entry.view, entry.round);
                try self.dirty_views.append(self.gpa, entry.view);
            }
            const reason = self.timeout_reason(update.leader, am_leader);
            if (reason) |why| {
                self.current.leader_nullify_hinted = why == .leader_nullify;
                try voter.timeout(.new(self.cfg.epoch, update.current), why);
            }
            const proposal = update.forwardable_proposal orelse return;
            if (!self.cfg.forward.is_enabled()) return;
            const round = self.find(proposal.view()) orelse return;
            try self.forward_proposal(round, proposal, update.leader);
        }

        fn timeout_reason(
            self: *Self,
            leader: Participant,
            am_leader: bool,
        ) ?metrics.TimeoutReason {
            const skip = switch (self.cfg.skip) {
                .disabled => return null,
                .enabled => |skip| skip,
            };
            if (self.leader_nullified()) return .leader_nullify;
            if (am_leader) return null;
            const timeout_ns: i96 = @intCast(skip.timeout.as_nanos());
            if (self.is_active(leader, timeout_ns)) return null;
            return .inactivity;
        }

        fn handle_certificate(
            self: *Self,
            voter: VoterMailbox,
            sender: S.PublicKey,
            payload: []const u8,
        ) !void {
            const Certificate = types.Certificate(S, D);
            const cfg = self.cfg.scheme.certificate_codec_config();
            var message = codec.decode_cfg(Certificate, self.gpa, payload, cfg) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                _ = self.cfg.blocker.block(sender); // Decoding error.
                return;
            };
            var owned = true;
            defer if (owned) message.deinit(self.gpa);
            if (message.epoch() != self.cfg.epoch) {
                _ = self.cfg.blocker.block(sender); // Epoch mismatch.
                return;
            }
            const view = message.view();
            self.record_peer_activity(sender);
            if (!self.viewport().admits_certificate(view)) return;
            const kind = std.meta.activeTag(message);
            if (self.find(view)) |existing| if (existing.has_certificate(kind)) {
                self.tracer.event(.trace, "skipping duplicate certificate", .{
                    .view = view.get(),
                    .kind = kind,
                });
                return;
            };
            var rng: context.IoRng = .{ .io = self.io };
            const scheme = self.cfg.scheme;
            if (!try message.verify(self.gpa, &rng, scheme, self.cfg.strategy)) {
                _ = self.cfg.blocker.block(sender); // Invalid certificate.
                return;
            }
            const round = try self.round_for_view(view);
            if (try round.record_certificate(self.gpa, &message)) {
                try self.dirty_views.append(self.gpa, view);
            }
            owned = false;
            try voter.recovered(self.gpa, message);
        }

        fn handle_vote(
            self: *Self,
            voter: VoterMailbox,
            sender: S.PublicKey,
            payload: []const u8,
        ) !void {
            const Vote = types.Vote(S, D);
            const message = codec.decode(Vote, self.gpa, payload) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                _ = self.cfg.blocker.block(sender); // Decoding error.
                return;
            };
            if (message.epoch() != self.cfg.epoch) {
                _ = self.cfg.blocker.block(sender); // Epoch mismatch.
                return;
            }
            const view = message.view();
            self.record_peer_activity(sender);
            if (!self.viewport().admits_vote(view)) return;
            const round = try self.round_for_view(view);
            if (!try round.add_network(self.gpa, sender, message)) return;
            if (self.cfg.skip == .enabled and self.leader_nullified()) {
                self.current.leader_nullify_hinted = true;
                try voter.timeout(.new(self.cfg.epoch, self.current.view), .leader_nullify);
            }
            try self.dirty_views.append(self.gpa, view);
        }

        /// Forwards proposals and builds certificates in every view that changed.
        fn process_dirty(self: *Self, voter: VoterMailbox) !void {
            const me = signer_of(self.cfg.scheme);
            for (self.dirty_views.items) |view| {
                if (view.get() <= self.finalized.get()) continue;
                const round = self.find(view) orelse continue;
                if (me) |signer| if (round.try_forward_proposal(signer)) |proposal| {
                    try voter.proposal(proposal);
                };
                if (!self.cfg.lookahead.admits(self.current.view, view)) {
                    self.tracer.event(.trace, "skipping out-of-window round processing", .{
                        .current = self.current.view.get(),
                        .view = view.get(),
                    });
                    continue;
                }
                try self.process_view(voter, view, round);
            }
            self.dirty_views.clearRetainingCapacity();
            const window = self.viewport();
            var pruned: usize = 0;
            while (pruned < self.work.items.len and !window.retains(self.work.items[pruned].view)) {
                self.destroy_round(self.work.items[pruned].round);
                pruned += 1;
            }
            self.work.replaceRangeAssumeCapacity(0, pruned, &.{});
        }

        fn process_view(self: *Self, voter: VoterMailbox, view: View, round: *Round) !void {
            var rng: context.IoRng = .{ .io = self.io };
            const participants = self.cfg.scheme.participants();
            // Each batch either consumes pending votes (at most one of each kind per
            // participant) or builds one of the three certificates.
            const attempts_max = 3 * (participants.len() + 1);
            assert(attempts_max > 3);
            for (0..attempts_max) |_| {
                var batch = try round.try_construct(self.gpa, &rng, self.cfg.strategy) orelse {
                    self.tracer.event(.trace, "no verifier ready", .{ .view = view.get() });
                    return;
                };
                defer batch.deinit(self.gpa);
                for (batch.invalid) |participant| {
                    const key = participants.key(participant) orelse continue;
                    _ = self.cfg.blocker.block(key.*); // Invalid signature.
                }
                if (batch.certificate) |certificate| {
                    batch.certificate = null;
                    self.tracer.event(.debug, "recovered certificate, forwarding to voter", .{
                        .view = view.get(),
                        .kind = std.meta.activeTag(certificate),
                    });
                    try voter.recovered(self.gpa, certificate);
                }
                if (batch.processed != 0) {
                    self.tracer.event(.trace, "processed votes", .{
                        .view = view.get(),
                        .batch = batch.processed,
                    });
                }
            }
            unreachable; // Proof: the verifier runs out of work within `attempts_max` batches.
        }

        fn viewport(self: *const Self) lookahead_mod.Viewport {
            return .{
                .finalized = self.finalized,
                .current = self.current.view,
                .view_retention = self.cfg.view_retention,
                .lookahead = self.cfg.lookahead,
            };
        }

        fn find(self: *const Self, view: View) ?*Round {
            for (self.work.items) |entry| if (entry.view == view) return entry.round;
            return null;
        }

        fn round_for_view(self: *Self, view: View) !*Round {
            if (self.find(view)) |round| {
                self.stamp_leader(view, round);
                return round;
            }
            const round = try self.gpa.create(Round);
            errdefer self.gpa.destroy(round);
            const at: consensus_types.Round = .new(self.cfg.epoch, view);
            const cfg = &self.cfg;
            round.* = if (view.get() < self.current.view.get() and !cfg.track_historical_votes)
                Round.skipped(at, cfg.scheme, cfg.blocker, cfg.reporter)
            else
                Round.init(at, cfg.scheme, cfg.blocker, cfg.reporter, cfg.track_historical_votes);
            var index: usize = 0;
            while (index < self.work.items.len and self.work.items[index].view.get() < view.get()) {
                index += 1;
            }
            try self.work.insert(self.gpa, index, .{ .view = view, .round = round });
            self.stamp_leader(view, round);
            return round;
        }

        fn destroy_round(self: *Self, round: *Round) void {
            round.deinit(self.gpa);
            self.gpa.destroy(round);
        }

        fn stamp_leader(self: *Self, view: View, round: *Round) void {
            const leader = self.current.leader orelse return;
            const current = self.current.view;
            if (view == current or self.cfg.lookahead.in_admission_window(current, view)) {
                round.set_leader(leader);
            }
        }

        fn leader_nullified(self: *const Self) bool {
            if (self.current.leader_nullify_hinted) return false;
            const leader = self.current.leader orelse return false;
            const round = self.find(self.current.view) orelse return false;
            return round.has_nullify(leader);
        }

        fn record_peer_activity(self: *Self, sender: S.PublicKey) void {
            const participant = self.cfg.scheme.participants().index(sender) orelse return;
            assert(participant.get() < self.last_activity.len);
            self.last_activity[participant.get()] = context.now_ns(self.io);
        }

        /// Whether `participant` was active within `timeout_ns`, or too few participants were
        /// active to tell.
        fn is_active(self: *const Self, participant: Participant, timeout_ns: i96) bool {
            const min_time = @max(context.now_ns(self.io) - timeout_ns, 0);
            var active: u32 = 0;
            for (self.last_activity) |activity| {
                if (activity) |at| if (at >= min_time) {
                    active += 1;
                };
            }
            if (active < self.required_active) return true;
            const last = self.last_activity[participant.get()] orelse return false;
            return last >= min_time;
        }

        fn forward_proposal(
            self: *Self,
            round: *Round,
            proposal: types.Proposal(D),
            next_leader: Participant,
        ) !void {
            const targets = switch (self.cfg.forward) {
                .disabled => return,
                .silent_voters => try round.missing_voters(self.gpa, &proposal),
                .silent_leader => targets: {
                    if (!round.is_missing_voter(&proposal, next_leader)) return;
                    break :targets try self.gpa.dupe(Participant, &.{next_leader});
                },
            };
            defer self.gpa.free(targets);
            var peers: std.ArrayList(S.PublicKey) = .empty;
            defer peers.deinit(self.gpa);
            const me = if (self.cfg.scheme.me()) |membership| membership.index() else null;
            const participants = self.cfg.scheme.participants();
            for (targets) |target| {
                if (me) |index| if (index.get() == target.get()) continue;
                const key = participants.key(target) orelse continue;
                try peers.append(self.gpa, key.*);
            }
            if (peers.items.len == 0) return;
            _ = self.cfg.relay.broadcast(proposal.payload, .{ .forward = .{
                .round = proposal.round,
                .recipients = .{ .some = peers.items },
            } });
        }
    };
}
