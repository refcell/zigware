//! The aggregation engine (commonware `aggregation/engine.rs`).
//!
//! The engine requests the digest of each height in its window from the automaton, signs an
//! ack over it, gossips the ack with its tip (`TipAck`), and assembles a certificate once a
//! quorum of acks for the same item arrives. Its tip is the lowest height without a
//! certificate; it fast-forwards to the highest tip at least one honest validator reported
//! (`SafeTip`), and work below `tip - activity_timeout` is pruned. Its own acks, certificates,
//! and tips are journaled so a restart rebuilds its state.
//!
//! Event loop: the network receiver, the epoch subscription, and the digest requests run as
//! `std.Io` tasks that hand their results to the engine through `Inbox` and wake it; due
//! rebroadcasts bound the wait. Each turn first requests the next digest while the window has
//! room, then handles one event in commonware's `select_loop!` order: epoch updates, digests,
//! network messages, then rebroadcasts. The engine stops when the network or the epoch
//! subscription closes, or when its task is canceled.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const types = @import("types.zig");
const config_mod = @import("config.zig");
const metrics_mod = @import("metrics.zig");
const SafeTip = @import("safe_tip.zig").SafeTip;
const HeightMap = @import("height_map.zig").HeightMap;

const Epoch = consensus_types.Epoch;
const Height = consensus_types.Height;
const Participant = consensus_types.Participant;
const journal = @import("storage").journal.segmented.variable;

/// Draws from the runtime RNG through `std.Io` (commonware's context as `CryptoRng`).
pub const IoRng = struct {
    io: Io,

    pub fn next_u64(rng: IoRng) u64 {
        var bytes: [8]u8 = undefined;
        rng.io.random(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }

    pub fn next_u32(rng: IoRng) u32 {
        return @truncate(rng.next_u64());
    }

    pub fn fill_bytes(rng: IoRng, dest: []u8) void {
        rng.io.random(dest);
    }
};

pub fn Engine(comptime P: type) type {
    comptime config_mod.assert_parameters(P);
    return struct {
        const Self = @This();
        const S = P.Scheme;
        const D = P.Digest;
        const PublicKey = S.PublicKey;
        const Ack = types.Ack(S, D);
        const TipAck = types.TipAck(S, D);
        const Certificate = types.Certificate(S, D);
        const Activity = types.Activity(S, D);
        const Journal = journal.Journal(Activity);
        pub const Config = config_mod.Config(P);
        pub const RunError = Allocator.Error || Journal.Error || Io.Cancelable ||
            Io.ConcurrentError || error{ NetworkClosed, SchemeMissing };

        /// A height without a certificate. `digest` is null until the automaton supplies it;
        /// until then acks may carry any digest.
        const Pending = struct {
            digest: ?D,
            /// Ascending by (epoch, signer); at most one ack per pair.
            acks: std.ArrayList(Ack) = .empty,
        };

        const DigestResult = struct {
            height: Height,
            /// Null when the automaton declined (commonware's canceled receiver).
            digest: ?D,
            timer: runtime.telemetry.metrics.histogram.Timer,
        };

        /// What the tasks hand the engine, guarded by `mutex`. `condition` wakes the engine
        /// and `slot_free` the receiver task. Each condition has exactly one waiter: a
        /// `std.Io.Condition` counts signals, not waiters, so a timed-out waiter can consume a
        /// signal meant for another one and leave it asleep.
        const Inbox = struct {
            mutex: Io.Mutex = .init,
            condition: Io.Condition = .init,
            slot_free: Io.Condition = .init,
            /// The newest epoch not yet handled.
            epoch: ?Epoch = null,
            epoch_closed: bool = false,
            /// Finished digest requests in completion order; capacity is reserved per request.
            digests: std.ArrayList(DigestResult) = .empty,
            /// Digest requests still running, each with a reserved slot in `digests`.
            digests_outstanding: usize = 0,
            /// Network messages in arrival order (a ring of `messages_count` from
            /// `messages_head`); the receiver task waits while it is full. Each hand-off between
            /// tasks costs a scheduler cycle, so the receiver moves every message already
            /// available at once instead of one per cycle.
            messages: [message_capacity]p2p.Message(PublicKey) = undefined,
            messages_head: u32 = 0,
            messages_count: u32 = 0,
            network_closed: bool = false,

            fn push_message(inbox: *Inbox, message: p2p.Message(PublicKey)) void {
                assert(inbox.messages_count < message_capacity);
                assert(inbox.messages_head < message_capacity);
                const tail = (inbox.messages_head + inbox.messages_count) % message_capacity;
                inbox.messages[tail] = message;
                inbox.messages_count += 1;
            }

            fn pop_message(inbox: *Inbox) ?p2p.Message(PublicKey) {
                assert(inbox.messages_count <= message_capacity);
                if (inbox.messages_count == 0) return null;
                const message = inbox.messages[inbox.messages_head];
                inbox.messages_head = (inbox.messages_head + 1) % message_capacity;
                inbox.messages_count -= 1;
                return message;
            }
        };

        /// Network messages buffered between the receiver task and the engine.
        const message_capacity = 256;

        const Event = union(enum) {
            epoch: Epoch,
            digest: DigestResult,
            message: p2p.Message(PublicKey),
            rebroadcast: Height,
            stopped,
        };

        gpa: Allocator,
        io: Io,
        storage: runtime.storage.Storage,
        config: Config,
        metrics: metrics_mod.Metrics,

        epoch: Epoch = .zero(),
        tip: Height = .zero(),
        safe_tip: SafeTip(PublicKey) = .empty,
        pending: HeightMap(Pending) = .empty,
        /// Heights with a certificate, kept to prune with the tip.
        confirmed: HeightMap(Certificate) = .empty,
        /// When to rebroadcast each verified height without a certificate (awake clock, ns).
        rebroadcast_deadlines: utils.PrioritySet(Height, i96) = .empty,
        journal: ?Journal = null,
        inbox: Inbox = .{},
        /// The receiver, epoch, and digest tasks.
        tasks: Io.Group = .init,

        /// An engine registering its metrics under `scope`, owning `config.reporter`.
        /// Release with `destroy` after its run ends.
        pub fn create(
            gpa: Allocator,
            io: Io,
            storage: runtime.storage.Storage,
            scope: *const runtime.telemetry.metrics.Scope,
            config: Config,
        ) Allocator.Error!*Self {
            config.assert_valid();
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.* = .{
                .gpa = gpa,
                .io = io,
                .storage = storage,
                .config = config,
                .metrics = try .init(scope),
            };
            return self;
        }

        pub fn destroy(self: *Self) void {
            const gpa = self.gpa;
            assert(self.journal == null);
            self.clear_state();
            self.safe_tip.deinit(gpa);
            self.pending.deinit(gpa);
            self.confirmed.deinit(gpa);
            self.rebroadcast_deadlines.deinit(gpa);
            self.inbox.digests.deinit(gpa);
            while (self.inbox.pop_message()) |message| {
                var owned = message;
                owned.deinit();
            }
            self.metrics.deinit();
            // The engine owns its reporter, as in commonware (dropped with the engine).
            if (comptime @hasDecl(P.Reporter, "deinit")) self.config.reporter.deinit();
            gpa.destroy(self);
        }

        fn clear_state(self: *Self) void {
            for (self.pending.items()) |*entry| entry.value.acks.deinit(self.gpa);
            self.pending.entries.clearRetainingCapacity();
            for (self.confirmed.items()) |*entry| entry.value.deinit(self.gpa);
            self.confirmed.entries.clearRetainingCapacity();
        }

        fn Runner(comptime Sender: type, comptime Receiver: type) type {
            return struct {
                fn run(self: *Self, sender: Sender, receiver: Receiver) RunError!void {
                    var owned_sender = sender;
                    var owned_receiver = receiver;
                    defer owned_sender.deinit();
                    defer owned_receiver.deinit();
                    return self.run(&owned_sender, &owned_receiver);
                }
            };
        }

        /// Runs the engine in a new task until the network or epoch subscription closes or
        /// the task is canceled. Takes ownership of `sender` and `receiver`.
        pub fn start(
            self: *Self,
            sender: anytype,
            receiver: anytype,
        ) Io.ConcurrentError!Io.Future(RunError!void) {
            const R = Runner(@TypeOf(sender), @TypeOf(receiver));
            return self.io.concurrent(R.run, .{ self, sender, receiver });
        }

        /// Runs the engine on the calling task (see `start`).
        pub fn run(self: *Self, sender: anytype, receiver: anytype) RunError!void {
            const latest, var subscription = try self.config.monitor.subscribe();
            defer subscription.deinit();
            self.epoch = latest;
            {
                var recovery = try self.open_journal();
                self.replay(&recovery) catch |err| {
                    recovery.deinit();
                    return err;
                };
                self.journal = try recovery.finish();
            }
            // A canceled run is an unclean shutdown (commonware drops the future): only what
            // was already synced survives. A run that stops on its own syncs everything.
            var stopped = false;
            defer self.close_journal(stopped);
            defer self.tasks.cancel(self.io);
            for (self.pending.items()) |entry| {
                if (entry.value.digest == null) try self.get_digest(entry.height);
            }
            const scheme = self.scheme_for(self.epoch) orelse
                @panic("current epoch scheme must exist");
            try self.safe_tip.init(self.gpa, scheme.participants());
            try self.tasks.concurrent(self.io, receive_task(@TypeOf(receiver.*)), .{
                self,
                receiver,
            });
            try self.tasks.concurrent(self.io, epoch_task(@TypeOf(subscription)), .{
                self,
                &subscription,
            });
            while (true) {
                _ = self.metrics.tip.metric().try_set(self.tip.get()) catch 0;
                const upcoming = self.next();
                // `next` returns at least the tip.
                if (upcoming.delta_from(self.tip).?.get() < self.config.window) {
                    try self.pending.put_new(self.gpa, upcoming, .{ .digest = null });
                    try self.get_digest(upcoming);
                    continue;
                }
                switch (try self.wait()) {
                    .stopped => {
                        stopped = true;
                        return;
                    },
                    .epoch => |epoch| try self.handle_epoch(epoch),
                    .digest => |result| try self.handle_digest_result(result, sender),
                    .message => |message| {
                        var owned = message;
                        defer owned.deinit();
                        try self.handle_message(owned.peer, owned.payload);
                    },
                    .rebroadcast => |height| try self.handle_rebroadcast(height, sender),
                }
            }
        }

        fn close_journal(self: *Self, flush: bool) void {
            var owned = self.journal.?;
            self.journal = null;
            // On failure the unsynced tail is lost; replay repairs a torn section.
            if (flush) owned.sync_all() catch {};
            owned.deinit();
        }

        /// The scheme for `epoch`, or null when the provider has none.
        fn scheme_for(self: *const Self, epoch: Epoch) ?*const S {
            return self.config.provider.scheme(epoch);
        }

        fn now(self: *const Self) i96 {
            return Io.Timestamp.now(self.io, .awake).nanoseconds;
        }

        fn deadline_after_timeout(self: *const Self) i96 {
            const timeout: i96 = @intCast(self.config.rebroadcast_timeout.as_nanos());
            assert(timeout > 0);
            return self.now() + timeout;
        }

        /// Waits for the next event, in commonware's arm order.
        fn wait(self: *Self) Io.Cancelable!Event {
            const inbox = &self.inbox;
            try inbox.mutex.lock(self.io);
            defer inbox.mutex.unlock(self.io);
            while (true) {
                if (inbox.epoch_closed) return .stopped;
                if (inbox.epoch) |epoch| {
                    inbox.epoch = null;
                    return .{ .epoch = epoch };
                }
                if (inbox.digests.items.len > 0) {
                    return .{ .digest = inbox.digests.orderedRemove(0) };
                }
                if (inbox.pop_message()) |message| {
                    inbox.slot_free.signal(self.io);
                    return .{ .message = message };
                }
                if (inbox.network_closed) return .stopped;
                const next_rebroadcast = self.rebroadcast_deadlines.peek();
                const deadline = if (next_rebroadcast) |entry| entry.priority else null;
                if (deadline) |due| if (self.now() >= due) {
                    return .{ .rebroadcast = self.rebroadcast_deadlines.pop().?.item };
                };
                const timeout: Io.Timeout = if (deadline) |due|
                    .{ .deadline = .{ .raw = .{ .nanoseconds = due }, .clock = .awake } }
                else
                    .none;
                const waited = inbox.condition.waitTimeout(self.io, &inbox.mutex, timeout);
                waited catch |err| switch (err) {
                    error.Timeout => {},
                    error.Canceled => return error.Canceled,
                };
            }
        }

        fn receive_task(comptime Receiver: type) fn (*Self, *Receiver) void {
            return struct {
                fn receive(self: *Self, receiver: *Receiver) void {
                    const inbox = &self.inbox;
                    while (true) {
                        var message = receiver.recv() catch |err| {
                            if (err != error.Canceled) self.mark_closed(&inbox.network_closed);
                            return;
                        };
                        inbox.mutex.lock(self.io) catch {
                            message.deinit();
                            return;
                        };
                        defer inbox.mutex.unlock(self.io);
                        while (inbox.messages_count == message_capacity) {
                            inbox.slot_free.wait(self.io, &inbox.mutex) catch {
                                message.deinit();
                                return;
                            };
                        }
                        inbox.push_message(message);
                        inbox.condition.signal(self.io);
                    }
                }
            }.receive;
        }

        fn epoch_task(comptime Subscription: type) fn (*Self, *Subscription) void {
            return struct {
                fn follow(self: *Self, subscription: *Subscription) void {
                    const inbox = &self.inbox;
                    while (true) {
                        const received = subscription.recv() catch return; // canceled
                        const epoch = received orelse {
                            self.mark_closed(&inbox.epoch_closed);
                            return;
                        };
                        inbox.mutex.lockUncancelable(self.io);
                        defer inbox.mutex.unlock(self.io);
                        inbox.epoch = epoch;
                        inbox.condition.broadcast(self.io);
                    }
                }
            }.follow;
        }

        fn mark_closed(self: *Self, flag: *bool) void {
            self.inbox.mutex.lockUncancelable(self.io);
            defer self.inbox.mutex.unlock(self.io);
            flag.* = true;
            self.inbox.condition.broadcast(self.io);
        }

        /// Requests the digest of `height`, which must be pending, from the automaton.
        fn get_digest(self: *Self, height: Height) (Allocator.Error || Io.ConcurrentError)!void {
            assert(self.pending.contains(height));
            const inbox = &self.inbox;
            {
                inbox.mutex.lockUncancelable(self.io);
                defer inbox.mutex.unlock(self.io);
                const needed = inbox.digests.items.len + inbox.digests_outstanding + 1;
                try inbox.digests.ensureTotalCapacity(self.gpa, needed);
                inbox.digests_outstanding += 1;
            }
            const timer = self.metrics.digest_duration.timer(self.io);
            try self.tasks.concurrent(self.io, digest_task, .{ self, height, timer });
        }

        fn digest_task(
            self: *Self,
            height: Height,
            timer: runtime.telemetry.metrics.histogram.Timer,
        ) void {
            const proposed = self.config.automaton.propose(self.io, height);
            const inbox = &self.inbox;
            inbox.mutex.lockUncancelable(self.io);
            defer inbox.mutex.unlock(self.io);
            assert(inbox.digests_outstanding > 0);
            inbox.digests_outstanding -= 1;
            const digest = proposed catch return; // canceled
            // Proof: `get_digest` reserved a slot for this request.
            const result: DigestResult = .{ .height = height, .digest = digest, .timer = timer };
            inbox.digests.appendAssumeCapacity(result);
            inbox.condition.broadcast(self.io);
        }

        fn handle_epoch(self: *Self, epoch: Epoch) RunError!void {
            assert(epoch.get() >= self.epoch.get());
            self.epoch = epoch;
            const scheme = self.scheme_for(epoch) orelse @panic("current epoch scheme must exist");
            self.safe_tip.reconcile(scheme.participants());
            // Drop acks from epochs below the bounds.
            const min_epoch = epoch.saturating_sub(self.config.epoch_bounds[0]);
            for (self.pending.items()) |*entry| {
                const acks = &entry.value.acks;
                var kept: usize = 0;
                for (acks.items) |ack| {
                    if (ack.epoch.get() < min_epoch.get()) continue;
                    acks.items[kept] = ack;
                    kept += 1;
                }
                acks.shrinkRetainingCapacity(kept);
            }
            // Heights verified without signing authority have no rebroadcast deadline:
            // schedule one for each still unconfirmed once this node can sign.
            const membership = scheme.me() orelse return;
            if (membership.signer_index() == null) return;
            const current = self.now();
            for (self.pending.items()) |entry| {
                if (entry.value.digest == null) continue;
                if (self.confirmed.contains(entry.height)) continue;
                if (self.rebroadcast_deadlines.contains(entry.height)) continue;
                try self.rebroadcast_deadlines.put(self.gpa, entry.height, current);
            }
        }

        fn handle_digest_result(self: *Self, result: DigestResult, sender: anytype) RunError!void {
            const digest = result.digest orelse {
                try self.metrics.digest.inc(.dropped);
                return;
            };
            result.timer.observe(self.io);
            try self.handle_digest(result.height, digest, sender);
        }

        /// Records the automaton's digest for a pending height, replays the acks that match
        /// it, then signs, applies, and broadcasts this node's ack.
        fn handle_digest(self: *Self, height: Height, digest: D, sender: anytype) RunError!void {
            const entry = self.pending.get(height) orelse return; // pruned since requested
            if (entry.digest != null) return; // already verified
            var acks = entry.acks;
            entry.* = .{ .digest = digest };
            defer acks.deinit(self.gpa);
            var index: usize = 0;
            while (index < acks.items.len) {
                const epoch = acks.items[index].epoch;
                while (index < acks.items.len and acks.items[index].epoch == epoch) : (index += 1) {
                    const ack = &acks.items[index];
                    if (codec.order(D, ack.item.digest, digest) != .eq) continue;
                    _ = try self.handle_ack(ack);
                }
                // Stop once a certificate formed.
                if (self.confirmed.contains(height)) break;
            }
            const ack = try self.sign_ack(height, digest) orelse return;
            try self.rebroadcast_deadlines.put(self.gpa, height, self.deadline_after_timeout());
            _ = try self.handle_ack(&ack);
            self.broadcast(ack, sender);
        }

        /// The position of the ack from `signer` in `epoch`, or where it would go.
        fn find_ack(acks: []const Ack, epoch: Epoch, signer: Participant) struct { usize, bool } {
            var low: usize = 0;
            var high: usize = acks.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                const ack = acks[middle];
                var by = Epoch.order(ack.epoch, epoch);
                if (by == .eq) by = Participant.order(ack.attestation.signer, signer);
                switch (by) {
                    .lt => low = middle + 1,
                    .gt => high = middle,
                    .eq => return .{ middle, true },
                }
            }
            return .{ low, false };
        }

        /// Adds an ack and forms a certificate when its epoch has a quorum for its digest.
        /// Returns whether the ack was accepted: an ack for an unknown scheme, a height that is
        /// not pending, or the wrong digest is rejected; a duplicate is accepted as a no-op.
        fn handle_ack(self: *Self, ack: *const Ack) RunError!bool {
            const scheme = self.scheme_for(ack.epoch) orelse return false;
            const quorum = scheme.participants().quorum(utils.N3f1);
            const entry = self.pending.get(ack.item.height) orelse return false;
            if (entry.digest) |digest| {
                if (codec.order(D, ack.item.digest, digest) != .eq) return false;
            }
            const signer = ack.attestation.signer;
            const index, const found = find_ack(entry.acks.items, ack.epoch, signer);
            if (found) return true;
            try entry.acks.insert(self.gpa, index, ack.*);
            var matching: std.ArrayList(Ack) = .empty;
            defer matching.deinit(self.gpa);
            for (entry.acks.items) |other| {
                if (other.epoch != ack.epoch) continue;
                if (codec.order(D, other.item.digest, ack.item.digest) != .eq) continue;
                try matching.append(self.gpa, other);
            }
            if (matching.items.len < quorum) return true;
            // Every stored ack is verified and signer-unique, so a same-item quorum satisfies
            // the scheme's assembly contract.
            const strategy = self.config.strategy;
            const assembled = Certificate.from_acks(self.gpa, scheme, matching.items, strategy);
            const certificate = assembled catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => @panic("verified acknowledgement quorum must assemble"),
            };
            self.metrics.certificates.metric().inc();
            try self.handle_certificate(certificate);
            return true;
        }

        /// Stores a new certificate (taking ownership), journals and reports it, and
        /// advances the tip past every contiguous certified height.
        fn handle_certificate(self: *Self, certificate: Certificate) RunError!void {
            var owned = certificate;
            const height = owned.item.height;
            if (self.confirmed.contains(height)) {
                owned.deinit(self.gpa);
                return;
            }
            self.confirmed.put_new(self.gpa, height, owned) catch |err| {
                owned.deinit(self.gpa);
                return err;
            };
            const certified: Activity = .{ .certified = self.confirmed.get(height).?.* };
            try self.record(certified);
            try self.sync(height);
            _ = self.config.reporter.report(certified);
            if (height != self.tip) return;
            var new_tip = height.next();
            while (self.confirmed.contains(new_tip) and new_tip.get() < std.math.maxInt(u64)) {
                new_tip = new_tip.next();
            }
            if (new_tip.get() > self.tip.get()) try self.fast_forward_tip(new_tip);
        }

        /// Rebroadcasts this node's ack for a verified height without a certificate, signing
        /// one first if the current epoch has none yet.
        fn handle_rebroadcast(self: *Self, height: Height, sender: anytype) RunError!void {
            const entry = self.pending.get(height) orelse return; // confirmed and pruned
            const digest = entry.digest orelse return;
            const scheme = self.scheme_for(self.epoch) orelse return;
            const membership = scheme.me() orelse return;
            const signer = membership.signer_index() orelse return;
            const index, const found = find_ack(entry.acks.items, self.epoch, signer);
            const ack = if (found) entry.acks.items[index] else signed: {
                const ack = try self.sign_ack(height, digest) orelse return;
                _ = try self.handle_ack(&ack);
                break :signed ack;
            };
            try self.rebroadcast_deadlines.put(self.gpa, height, self.deadline_after_timeout());
            self.broadcast(ack, sender);
        }

        /// Handles one network message from `peer`: its tip, then its ack.
        fn handle_message(self: *Self, peer: PublicKey, payload: []const u8) RunError!void {
            var guard = self.metrics.acks.guard(.invalid);
            defer guard.finish() catch {}; // A metric that cannot allocate is skipped.
            const tip_ack = codec.decode(TipAck, self.gpa, payload) catch {
                _ = self.config.blocker.block(peer);
                return;
            };
            if (self.safe_tip.update(peer, tip_ack.tip) != null) {
                const safe = self.safe_tip.get();
                if (safe.get() > self.tip.get()) try self.fast_forward_tip(safe);
            }
            self.validate_ack(&tip_ack.ack, peer) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |invalid| {
                    if (types.blockable(invalid)) _ = self.config.blocker.block(peer);
                    return;
                },
            };
            if (!try self.handle_ack(&tip_ack.ack)) {
                guard.set(.failure);
                return;
            }
            guard.set(.success);
        }

        /// Checks that an ack from `peer` is worth processing: in the epoch bounds, signed by
        /// `peer`, in the activity window, not certified or duplicated, with a valid signature.
        fn validate_ack(
            self: *Self,
            ack: *const Ack,
            peer: PublicKey,
        ) (types.Error || Allocator.Error)!void {
            const bound_lo = self.epoch.saturating_sub(self.config.epoch_bounds[0]);
            const bound_hi = self.epoch.saturating_add(self.config.epoch_bounds[1]);
            if (ack.epoch.get() < bound_lo.get() or ack.epoch.get() > bound_hi.get()) {
                return error.AckEpochOutsideBounds;
            }
            const scheme = self.scheme_for(ack.epoch) orelse return error.UnknownEpoch;
            const signer = scheme.participants().index(peer) orelse return error.UnknownValidator;
            if (signer.get() != ack.attestation.signer.get()) return error.PeerMismatch;
            const height = ack.item.height;
            const threshold = self.tip.saturating_sub(self.config.activity_timeout);
            if (height.get() < threshold.get()) return error.AckCertified;
            if (height.delta_from(self.tip)) |delta| {
                if (delta.get() >= self.config.window) return error.AckHeight;
            }
            if (self.confirmed.contains(height)) return error.AckCertified;
            if (self.pending.get(height)) |entry| {
                if (entry.digest) |digest| {
                    if (codec.order(D, ack.item.digest, digest) != .eq) return error.AckDigest;
                }
                if (find_ack(entry.acks.items, ack.epoch, ack.attestation.signer)[1]) {
                    return error.AckDuplicate;
                }
            }
            const rng: IoRng = .{ .io = self.io };
            if (!try ack.verify(self.gpa, rng, scheme, self.config.strategy)) {
                return error.InvalidAckSignature;
            }
        }

        /// Signs and journals an ack for `height` in the current epoch, or returns null when
        /// this node cannot sign in it.
        fn sign_ack(self: *Self, height: Height, digest: D) RunError!?Ack {
            const scheme = self.scheme_for(self.epoch) orelse return null;
            const item: types.Item(D) = .{ .height = height, .digest = digest };
            const ack = try Ack.sign(self.gpa, scheme, self.epoch, item) orelse return null;
            try self.record(.{ .ack = ack });
            try self.sync(height);
            return ack;
        }

        /// Sends `ack` with this node's tip to every peer. As in commonware, a send that the
        /// network refuses (closed, rate limited) is dropped: rebroadcasts retry.
        fn broadcast(self: *Self, ack: Ack, sender: anytype) void {
            const message: TipAck = .{ .tip = self.tip, .ack = ack };
            var buffer: [TipAck.max_encode_size]u8 = undefined;
            const encoded = codec.encode_to(TipAck, message, &buffer);
            assert(encoded.len == message.encode_size());
            const sent = sender.send(.all, &.{encoded}, self.config.priority_acks) catch return;
            self.gpa.free(sent);
        }

        /// The lowest height with neither a digest request nor a certificate.
        fn next(self: *const Self) Height {
            var result = self.tip;
            if (self.pending.last()) |last| result = .new(@max(result.get(), last.next().get()));
            if (self.confirmed.last()) |last| result = .new(@max(result.get(), last.next().get()));
            assert(result.get() >= self.tip.get());
            return result;
        }

        /// Raises the tip to `tip`, pruning heights below `tip - activity_timeout`.
        fn fast_forward_tip(self: *Self, tip: Height) RunError!void {
            assert(tip.get() > self.tip.get());
            const threshold = tip.saturating_sub(self.config.activity_timeout);
            for (self.pending.below(threshold)) |*entry| entry.value.acks.deinit(self.gpa);
            self.pending.remove_below(threshold);
            for (self.confirmed.below(threshold)) |*entry| entry.value.deinit(self.gpa);
            self.confirmed.remove_below(threshold);
            const activity: Activity = .{ .tip = tip };
            try self.record(activity);
            try self.sync(tip);
            _ = self.config.reporter.report(activity);
            _ = try self.journal.?.prune(self.section(threshold));
            self.tip = tip;
        }

        fn section(self: *const Self, height: Height) u64 {
            return height.get() / self.config.journal_heights_per_section;
        }

        fn record(self: *Self, activity: Activity) Journal.Error!void {
            _ = try self.journal.?.append(self.section(activity.height()), activity);
        }

        fn sync(self: *Self, height: Height) Journal.Error!void {
            try self.journal.?.sync(&.{self.section(height)});
        }

        fn open_journal(self: *Self) Journal.Error!Journal.Recovery {
            return Journal.init(self.gpa, self.storage, .{
                .partition = self.config.journal_partition,
                .compression = self.config.journal_compression,
                .codec_config = S.certificate_codec_config_unbounded(),
                .cache_ref = self.config.journal_page_cache,
                .write_buffer = self.config.journal_write_buffer,
                .replay_buffer = self.config.journal_replay_buffer,
            });
        }

        /// Rebuilds the tip, certificates, and pending acks from the journal, reporting each
        /// replayed activity. Heights left without a digest are requested by `run`.
        fn replay(self: *Self, recovery: *Journal.Recovery) RunError!void {
            var acks: std.ArrayList(Ack) = .empty;
            defer acks.deinit(self.gpa);
            var tip: Height = .zero();
            while (try recovery.next()) |entry| {
                var activity = entry.item;
                defer activity.deinit(self.gpa);
                _ = self.config.reporter.report(activity);
                switch (activity) {
                    .tip => |height| tip = .new(@max(tip.get(), height.get())),
                    .ack => |ack| try acks.append(self.gpa, ack),
                    .certified => |*certificate| {
                        if (self.confirmed.contains(certificate.item.height)) continue;
                        const copy = try certificate.clone(self.gpa);
                        try self.confirmed.put_new(self.gpa, certificate.item.height, copy);
                    },
                }
            }
            self.tip = tip;
            const threshold = tip.saturating_sub(self.config.activity_timeout);
            for (self.confirmed.below(threshold)) |*entry| entry.value.deinit(self.gpa);
            self.confirmed.remove_below(threshold);
            std.mem.sort(Ack, acks.items, {}, ack_less);
            var first: usize = 0;
            while (first < acks.items.len) {
                const height = acks.items[first].item.height;
                var end = first;
                while (end < acks.items.len and acks.items[end].item.height == height) end += 1;
                defer first = end;
                if (height.get() < threshold.get() or self.confirmed.contains(height)) continue;
                try self.replay_height(height, acks.items[first..end]);
            }
            // Every height from the tip to `next` is pending or confirmed after a restart.
            const next_height = self.next();
            var height = self.tip;
            while (height.get() < next_height.get()) : (height = height.next()) {
                if (self.pending.contains(height) or self.confirmed.contains(height)) continue;
                try self.pending.put_new(self.gpa, height, .{ .digest = null });
            }
        }

        fn ack_less(_: void, a: Ack, b: Ack) bool {
            if (a.item.height != b.item.height) return a.item.height.get() < b.item.height.get();
            if (a.epoch != b.epoch) return a.epoch.get() < b.epoch.get();
            return a.attestation.signer.get() < b.attestation.signer.get();
        }

        /// Restores one height's journaled acks (ascending by epoch and signer). This node's
        /// own ack in the current epoch means it verified the digest: keep only matching acks
        /// and rebroadcast at once. Otherwise the height waits for its digest.
        fn replay_height(self: *Self, height: Height, acks: []const Ack) RunError!void {
            assert(acks.len > 0);
            const digest: ?D = digest: {
                const scheme = self.scheme_for(self.epoch) orelse break :digest null;
                const membership = scheme.me() orelse break :digest null;
                const signer = membership.signer_index() orelse break :digest null;
                for (acks) |ack| {
                    if (ack.epoch != self.epoch) continue;
                    if (ack.attestation.signer.get() == signer.get()) break :digest ack.item.digest;
                }
                break :digest null;
            };
            var pending: Pending = .{ .digest = digest };
            errdefer pending.acks.deinit(self.gpa);
            for (acks) |ack| {
                if (digest) |verified| {
                    if (codec.order(D, ack.item.digest, verified) != .eq) continue;
                }
                const signer = ack.attestation.signer;
                const index, const found = find_ack(pending.acks.items, ack.epoch, signer);
                if (found) continue;
                try pending.acks.insert(self.gpa, index, ack);
            }
            try self.pending.put_new(self.gpa, height, pending);
            if (digest != null) try self.rebroadcast_deadlines.put(self.gpa, height, self.now());
        }
    };
}

// Tests of the engine's handlers (commonware `aggregation/engine.rs` tests). The
// `assembly_failure_panics` test (`should_panic`) has no counterpart: Zig tests cannot catch a
// panic.

const testing = std.testing;

const TestHarness = struct {
    const cryptography = @import("cryptography");
    const parallel = @import("parallel");
    const mocks = @import("mocks/root.zig");
    const scheme_mod = @import("scheme.zig");
    const TestDigest = cryptography.Sha256.Digest;
    const TestScheme = scheme_mod.ed25519.Scheme(TestDigest);

    /// Counts certificates reported by the engine.
    const CertificateCounter = struct {
        pub const Activity = types.Activity(TestScheme, TestDigest);
        certified: u32 = 0,

        pub fn report(self: *CertificateCounter, activity: Activity) @import("actor").Feedback {
            if (activity == .certified) self.certified += 1;
            return .ok;
        }
    };

    const NoopBlocker = struct {
        pub fn block(_: NoopBlocker, _: TestScheme.PublicKey) @import("actor").Feedback {
            return .ok;
        }
    };

    /// Accepts every broadcast and sends nothing.
    const InertSender = struct {
        gpa: Allocator,
        sent: u32 = 0,

        pub fn send(
            self: *InertSender,
            _: p2p.Recipients(TestScheme.PublicKey),
            parts: []const []const u8,
            _: bool,
        ) Allocator.Error![]TestScheme.PublicKey {
            assert(parts.len == 1 and parts[0].len > 0);
            self.sent += 1;
            return self.gpa.alloc(TestScheme.PublicKey, 0);
        }
    };

    const Parameters = struct {
        pub const Scheme = TestScheme;
        pub const Provider = *mocks.Provider(TestScheme);
        pub const Digest = TestDigest;
        pub const Automaton = mocks.Application;
        pub const Reporter = CertificateCounter;
        pub const Monitor = *mocks.Monitor;
        pub const Blocker = NoopBlocker;
        pub const Strategy = parallel.Sequential;
    };
    const TestEngine = Engine(Parameters);

    gpa: Allocator,
    fixture: cryptography.certificate.mocks.Fixture(TestScheme),
    provider: mocks.Provider(TestScheme),
    monitor: *mocks.Monitor,
    cache: runtime.buffer.paged.CacheRef,
    engine: *TestEngine,
    epoch: Epoch,

    /// An engine at `epoch` with an empty journal open, so handlers that journal can be
    /// driven directly. Nothing is replayed and the safe tip is left uninitialized.
    fn init(
        self: *TestHarness,
        io: Io,
        storage: runtime.storage.Storage,
        scope: runtime.telemetry.metrics.Scope,
        partition: []const u8,
    ) !void {
        const gpa = testing.allocator;
        var rng = utils.rng.TestRng.init(0);
        self.gpa = gpa;
        self.epoch = .new(111);
        self.fixture = try scheme_mod.ed25519.fixture(TestScheme, gpa, &rng, partition, 4);
        self.provider = .init(gpa);
        _ = try self.provider.register(self.epoch, try self.fixture.schemes[0].clone(gpa));
        self.monitor = try mocks.Monitor.create(gpa, io, self.epoch);
        self.cache = try .init(gpa, 1024, 10);
        self.engine = try TestEngine.create(gpa, io, storage, &scope, .{
            .monitor = self.monitor,
            .provider = &self.provider,
            .automaton = .init(.correct),
            .reporter = .{},
            .blocker = .{},
            .priority_acks = false,
            .rebroadcast_timeout = utils.Duration.from_secs(1),
            .epoch_bounds = .{ .new(1), .new(1) },
            .window = 1,
            .activity_timeout = .new(10),
            .journal_partition = partition,
            .journal_write_buffer = 4096,
            .journal_replay_buffer = 4096,
            .journal_heights_per_section = 6,
            .journal_compression = null,
            .journal_page_cache = &self.cache,
            .strategy = parallel.sequential,
        });
        self.engine.epoch = self.epoch;
        var recovery = try self.engine.open_journal();
        try testing.expectEqual(null, try recovery.next());
        self.engine.journal = try recovery.finish();
    }

    fn deinit(self: *TestHarness) void {
        self.engine.close_journal(true);
        self.engine.destroy();
        self.cache.deinit();
        self.monitor.destroy();
        self.provider.deinit();
        self.fixture.deinit(self.gpa);
    }

    fn ack(self: *TestHarness, signer: usize, height: Height, digest: TestDigest) !TestEngine.Ack {
        const item: types.Item(TestDigest) = .{ .height = height, .digest = digest };
        const scheme = &self.fixture.schemes[signer];
        return (try TestEngine.Ack.sign(self.gpa, scheme, self.epoch, item)).?;
    }

    const Body = fn (Io, runtime.storage.Storage, runtime.telemetry.metrics.Scope) anyerror!void;

    fn run(comptime body: Body) !void {
        var runner = try runtime.deterministic.Runner.init(testing.allocator, .{
            .timeout_ns = 10 * std.time.ns_per_s,
        });
        defer runner.deinit();
        try (try runner.start(body, .{ runner.io(), runner.storage(), runner.metrics() }));
    }
};

test "a digest for a height that is not pending is dropped" {
    try TestHarness.run(struct {
        fn body(
            io: Io,
            storage: runtime.storage.Storage,
            scope: runtime.telemetry.metrics.Scope,
        ) anyerror!void {
            var harness: TestHarness = undefined;
            try harness.init(io, storage, scope, "aggregation-digest-not-pending");
            defer harness.deinit();
            const engine = harness.engine;
            var sender: TestHarness.InertSender = .{ .gpa = testing.allocator };
            const Sha256 = TestHarness.cryptography.Sha256;
            // Verifying a pending height keeps the ack a peer sent before the digest was known
            // and adds this node's own.
            const height: Height = .zero();
            const digest = Sha256.hash(&.{"payload"});
            const early = try harness.ack(1, height, digest);
            try engine.pending.put_new(engine.gpa, height, .{ .digest = null });
            try engine.pending.get(height).?.acks.append(engine.gpa, early);
            try engine.handle_digest(height, digest, &sender);
            const verified = engine.pending.get(height).?;
            try testing.expect(verified.digest.?.order(digest) == .eq);
            try testing.expectEqual(2, verified.acks.items.len);
            try testing.expect(engine.rebroadcast_deadlines.contains(height));
            try testing.expectEqual(1, sender.sent);
            // A digest for a height pruned since it was requested is dropped.
            const pruned: Height = .new(1);
            try engine.handle_digest(pruned, Sha256.hash(&.{"pruned"}), &sender);
            try testing.expect(!engine.pending.contains(pruned));
            try testing.expect(!engine.rebroadcast_deadlines.contains(pruned));
            // A digest for a height already verified keeps the verified digest and its acks.
            try engine.handle_digest(height, Sha256.hash(&.{"replacement"}), &sender);
            const kept = engine.pending.get(height).?;
            try testing.expect(kept.digest.?.order(digest) == .eq);
            try testing.expectEqual(2, kept.acks.items.len);
            try testing.expectEqual(1, sender.sent);
        }
    }.body);
}

test "a certificate for a confirmed height is dropped" {
    try TestHarness.run(struct {
        fn body(
            io: Io,
            storage: runtime.storage.Storage,
            scope: runtime.telemetry.metrics.Scope,
        ) anyerror!void {
            var harness: TestHarness = undefined;
            try harness.init(io, storage, scope, "aggregation-certificate-confirmed");
            defer harness.deinit();
            const engine = harness.engine;
            const height: Height = .zero();
            const digest = TestHarness.cryptography.Sha256.hash(&.{"payload"});
            try engine.pending.put_new(engine.gpa, height, .{ .digest = digest });
            var acks: [4]TestHarness.TestEngine.Ack = undefined;
            for (&acks, 0..) |*slot, signer| slot.* = try harness.ack(signer, height, digest);
            // Three of the four acks form a certificate: it advances the tip and is reported
            // once.
            for (acks[0..3]) |*ack| try testing.expect(try engine.handle_ack(ack));
            try testing.expectEqual(1, engine.confirmed.len());
            try testing.expectEqual(Height.new(1), engine.tip);
            try testing.expectEqual(1, engine.config.reporter.certified);
            // The fourth ack assembles the certificate again; the confirmed height drops it
            // without a second report.
            try testing.expect(try engine.handle_ack(&acks[3]));
            try testing.expectEqual(1, engine.confirmed.len());
            try testing.expectEqual(Height.new(1), engine.tip);
            try testing.expectEqual(1, engine.config.reporter.certified);
        }
    }.body);
}
