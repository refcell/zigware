//! Discovery phase of the DKG probe (commonware `glue/src/dkg/probe/actor/discovery.rs`).
//!
//! Once a subscriber appears, discovery activates the bootstrap snapshot and solicits its
//! dealers' latest finalizations. `f + 1` verified replies from distinct dealers select the
//! floor. A floor in epoch zero resolves from the genesis info. Otherwise discovery asks every
//! peer for the floor epoch's boundary finalization, then asks one verified responder at a time
//! for the boundary block, and packages the block's `EpochInfo` with the floor into an
//! `Artifact` for every subscriber.
//!
//! The driver (`actor.zig`) owns the mailbox, the network, and the retry deadline. Each handler
//! returns whether it sent a new request, which rearms the deadline. Sends go through the
//! `sender` argument: `send(recipients, parts, priority) ![]PublicKey`, whose result the caller
//! frees.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");
const probe = @import("mod.zig");
const wire = @import("wire.zig");
const sample_mod = @import("../../stateful/probe/sample.zig");
const types = @import("../types.zig");

const oneshot = utils.channel.oneshot;
const Epoch = consensus.Epoch;
const Height = consensus.Height;

/// Discovery over `P`, which declares `Scheme` (the certificate scheme), `Variant` (the
/// marshal variant, whose application block declares `Variant`, `PublicKey`, and
/// `Directory`), `Manager` (a dkg `Manager`), and `Blocker` (`block(peer)`).
pub fn Discovery(comptime P: type) type {
    return struct {
        const Self = @This();
        const S = P.Scheme;
        const V = P.Variant;
        const B = V.ApplicationBlock;
        pub const PublicKey = S.PublicKey;
        pub const Finalization = consensus.simplex.types.Finalization(S, V.Commitment);
        pub const Artifact = probe.Artifact(S, V.Commitment, B.Variant, B.Directory);
        pub const Bootstrap = probe.Bootstrap(PublicKey, B.Directory);
        pub const Info = types.EpochInfo(B.Variant, PublicKey, B.Directory);
        pub const Sample = sample_mod.Sample(S, V.Commitment);
        const Message = wire.Message(S, V);

        const Candidate = struct {
            peer: PublicKey,
            finalization: Finalization,
        };

        /// The boundary fetch for the floor's epoch.
        const Pending = struct {
            height: Height,
            floor: Finalization,
            in_flight: ?Candidate = null,
            candidates: std.Deque(Candidate) = .empty,

            fn deinit(pending: *Pending, gpa: Allocator) void {
                pending.floor.deinit(gpa);
                if (pending.in_flight) |*candidate| candidate.finalization.deinit(gpa);
                while (pending.candidates.popFront()) |candidate| {
                    var owned = candidate;
                    owned.finalization.deinit(gpa);
                }
                pending.candidates.deinit(gpa);
                pending.* = undefined;
            }
        };

        pub const Config = struct {
            manager: P.Manager,
            /// The checkpoint (owned).
            bootstrap: Bootstrap,
            /// A persisted state-sync floor's epoch, if any: replies below it are ignored.
            floor_epoch: ?Epoch,
            /// The all-epoch certificate verifier (borrowed for discovery's lifetime).
            verifier: *const S,
            /// Genesis's epoch info (owned).
            genesis: Info,
            blocker: P.Blocker,
            blocks_per_epoch: u64,
            block_cfg: codec.Cfg(B),
        };

        gpa: Allocator,
        manager: P.Manager,
        bootstrap: Bootstrap,
        verifier: *const S,
        genesis: Info,
        blocker: P.Blocker,
        epocher: consensus.types.FixedEpocher,
        block_cfg: codec.Cfg(B),
        sample: Sample,
        artifact: ?Artifact = null,
        subscribers: std.ArrayList(oneshot.Sender(Artifact)) = .empty,
        pending: ?Pending = null,
        attached: bool = false,

        pub fn init(gpa: Allocator, config: Config) Self {
            assert(config.blocks_per_epoch > 0);
            assert(!config.bootstrap.participants.dealers.is_empty());
            // Ignore replies below the bootstrap epoch or the persisted floor's epoch.
            const floor_epoch = config.floor_epoch orelse config.bootstrap.epoch;
            const minimum: Epoch = .new(@max(floor_epoch.get(), config.bootstrap.epoch.get()));
            return .{
                .gpa = gpa,
                .manager = config.manager,
                .bootstrap = config.bootstrap,
                .verifier = config.verifier,
                .genesis = config.genesis,
                .blocker = config.blocker,
                .epocher = .new(utils.NonZero(u64).init(config.blocks_per_epoch).?),
                .block_cfg = config.block_cfg,
                .sample = .init(gpa, minimum),
            };
        }

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            for (self.subscribers.items) |*subscriber| subscriber.deinit();
            self.subscribers.deinit(gpa);
            self.sample.deinit();
            if (self.pending) |*pending| pending.deinit(gpa);
            if (self.artifact) |*artifact| artifact.deinit();
            self.bootstrap.deinit(gpa);
            self.genesis.deinit(gpa);
            self.* = undefined;
        }

        /// Drops subscribers whose receivers are gone (commonware's `retain(!is_closed)`).
        pub fn retain_open(self: *Self) void {
            var kept: usize = 0;
            for (self.subscribers.items) |subscriber| {
                var owned = subscriber;
                if (owned.is_closed()) {
                    owned.deinit();
                    continue;
                }
                self.subscribers.items[kept] = owned;
                kept += 1;
            }
            self.subscribers.shrinkRetainingCapacity(kept);
        }

        /// Drops every pending subscriber, closing its receiver (the probe stopped).
        pub fn drop_subscribers(self: *Self) void {
            for (self.subscribers.items) |*subscriber| subscriber.deinit();
            self.subscribers.clearRetainingCapacity();
        }

        /// Whether discovery hands off to service: marshal is attached and nobody waits.
        pub fn finished(self: *Self) bool {
            self.retain_open();
            return self.attached and self.subscribers.items.len == 0;
        }

        /// Whether the retry deadline is armed: no artifact yet and a subscriber waits.
        pub fn retrying(self: *Self) bool {
            self.retain_open();
            return self.artifact == null and self.subscribers.items.len > 0;
        }

        pub fn attach(self: *Self) void {
            self.attached = true;
        }

        /// Takes a subscription and returns whether it started a solicitation. Answers at once
        /// if the artifact is known. Fails with `BootstrapActivation` if the manager cannot
        /// activate the snapshot; the driver then shuts down.
        pub fn subscribe(
            self: *Self,
            response: oneshot.Sender(Artifact),
            sender: anytype,
        ) !bool {
            var owned = response;
            if (self.artifact) |*artifact| {
                try deliver(self.gpa, &owned, artifact);
                return false;
            }
            const solicit = self.subscribers.items.len == 0 and self.sample.get_floor() == null;
            self.subscribers.append(self.gpa, owned) catch |err| {
                owned.deinit();
                return err;
            };
            if (!solicit) return false;
            // Activate the snapshot only when soliciting: a node that never bootstraps must not
            // claim a peer-set ID above the epochs its orchestrator still enters.
            var tracked = try self.bootstrap.participants.tracked_peers(self.gpa);
            defer tracked.deinit(self.gpa);
            const epoch = self.bootstrap.epoch;
            self.manager.track(epoch, tracked.view(), &self.bootstrap.directory) catch {
                return error.BootstrapActivation;
            };
            try self.request_latest(sender);
            return true;
        }

        /// The retry deadline elapsed: retry the boundary fetch, or re-solicit the sample.
        pub fn retry(self: *Self, sender: anytype) !void {
            if (self.pending) |*pending| {
                // The in-flight responder had its chance; try the next one.
                if (pending.in_flight) |*candidate| candidate.finalization.deinit(self.gpa);
                pending.in_flight = null;
                try self.request_next_block(sender);
            } else if (self.sample.get_floor() == null) {
                try self.request_latest(sender);
            }
        }

        /// Clears collected replies and solicits the dealers' latest finalizations.
        fn request_latest(self: *Self, sender: anytype) !void {
            self.sample.reset();
            const dealers = self.bootstrap.participants.dealers.items;
            assert(dealers.len > 0);
            try self.send(sender, .{ .some = dealers }, .latest_request);
        }

        fn send(
            self: *Self,
            sender: anytype,
            recipients: p2p.Recipients(PublicKey),
            message: Message,
        ) !void {
            const bytes = try message.encode(self.gpa);
            defer self.gpa.free(bytes);
            const attempted = try sender.send(recipients, &.{bytes}, false);
            self.gpa.free(attempted);
        }

        fn block(self: *Self, peer: PublicKey) void {
            _ = self.blocker.block(peer);
        }

        /// Handles a peer's message and returns whether it sent a new request. Requests are
        /// ignored (service answers them); malformed responses block the peer.
        pub fn receive(
            self: *Self,
            peer: PublicKey,
            payload: []const u8,
            sender: anytype,
            rng: anytype,
            strategy: anytype,
        ) !bool {
            const cfg = cryptography.certificate.Scoped(S).verifier(self.verifier)
                .certificate_codec_config();
            const response = wire.read_response(S, V, self.gpa, payload, cfg) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                self.block(peer);
                return false;
            } orelse return false;
            switch (response) {
                .latest => |finalization| {
                    return self.handle_latest(peer, finalization, sender, rng, strategy);
                },
                .boundary => |finalization| {
                    var owned = finalization;
                    if (self.pending == null) {
                        owned.deinit(self.gpa);
                        return false;
                    }
                    return self.handle_boundary_finalization(peer, owned, sender, rng, strategy);
                },
                .block => |body| {
                    if (self.pending == null) return false;
                    const epoch = body.epoch;
                    return self.handle_boundary_block(peer, epoch, body.body, sender, strategy);
                },
            }
        }

        fn verify(
            self: *Self,
            finalization: *const Finalization,
            rng: anytype,
            strategy: anytype,
        ) !bool {
            const scoped = cryptography.certificate.Scoped(S).verifier(self.verifier);
            return finalization.verify(self.gpa, rng, scoped, strategy);
        }

        /// Records a latest-finalization reply (taken) that passes the discovery rules and
        /// returns whether a boundary request was sent.
        fn handle_latest(
            self: *Self,
            peer: PublicKey,
            finalization: Finalization,
            sender: anytype,
            rng: anytype,
            strategy: anytype,
        ) !bool {
            var owned = finalization;
            // Once the floor is selected or the peer contributed this round, replies are
            // ignored without verification.
            if (!self.sample.awaits(peer)) {
                owned.deinit(self.gpa);
                return false;
            }
            if (self.bootstrap.participants.dealers.position(peer) == null) {
                owned.deinit(self.gpa);
                self.block(peer); // A latest finalization from a non-member.
                return false;
            }
            if (owned.epoch().get() < self.sample.minimum_epoch.get()) {
                owned.deinit(self.gpa); // Stale, not proof of misbehavior.
                return false;
            }
            const valid = self.verify(&owned, rng, strategy) catch |err| {
                owned.deinit(self.gpa);
                return err;
            };
            if (!valid) {
                owned.deinit(self.gpa);
                self.block(peer);
                return false;
            }
            if (self.subscribers.items.len == 0) {
                owned.deinit(self.gpa);
                self.sample.reset();
                return false;
            }
            try self.sample.record(peer, owned);
            return self.select(sender);
        }

        /// Selects the highest finalization once `f + 1` distinct dealers replied, then begins
        /// the boundary fetch for the floor's epoch. Returns whether a request was sent.
        fn select(self: *Self, sender: anytype) !bool {
            const Judge = struct {
                // Every recorded reply was verified under the all-epoch verifier.
                pub fn judgeable(_: @This(), _: *const Finalization) bool {
                    return true;
                }
            };
            const committee = self.bootstrap.participants.dealers.len();
            const selected = try self.sample.select(committee, Judge{}) orelse return false;
            var floor = try selected.clone(self.gpa);
            errdefer floor.deinit(self.gpa);
            const target = floor.epoch();
            if (target.is_zero()) {
                // Epoch zero is anchored by genesis and has no boundary block.
                const info = try self.genesis.clone(self.gpa);
                try self.resolve(.{
                    .gpa = self.gpa,
                    .finalization = null,
                    .info = info,
                    .floor = floor,
                });
                return false;
            }
            const previous = target.previous().?;
            const height = self.epocher.last(previous) orelse {
                // Unreachable without a forged quorum: re-sample rather than wedge.
                floor.deinit(self.gpa);
                self.sample.reset();
                return false;
            };
            try self.send(sender, .all, .{ .boundary_request = target });
            self.pending = .{ .height = height, .floor = floor };
            return true;
        }

        fn handle_boundary_finalization(
            self: *Self,
            peer: PublicKey,
            finalization: Finalization,
            sender: anytype,
            rng: anytype,
            strategy: anytype,
        ) !bool {
            var owned = finalization;
            var keep = false;
            defer if (!keep) owned.deinit(self.gpa);
            const pending = &self.pending.?;
            // The floor's epoch is non-zero: epoch zero resolves without a boundary fetch.
            const expected = pending.floor.epoch().previous().?;
            const epoch = owned.epoch();
            if (epoch.get() < expected.get()) return false; // A stale boundary response.
            if (epoch.get() != expected.get()) {
                self.block(peer);
                return false;
            }
            if (has_candidate(pending, peer)) return false;
            if (!try self.verify(&owned, rng, strategy)) {
                self.block(peer);
                return false;
            }
            try pending.candidates.pushBack(self.gpa, .{ .peer = peer, .finalization = owned });
            keep = true;
            if (pending.in_flight != null) return false;
            try self.request_next_block(sender);
            return true;
        }

        fn has_candidate(pending: *const Pending, peer: PublicKey) bool {
            if (pending.in_flight) |candidate| {
                if (candidate.peer.eql(peer)) return true;
            }
            var iterator = pending.candidates.iterator();
            while (iterator.next()) |candidate| {
                if (candidate.peer.eql(peer)) return true;
            }
            return false;
        }

        /// Decodes the in-flight responder's block against its verified commitment. A bad
        /// block blocks the peer and moves on to the next responder at once.
        fn handle_boundary_block(
            self: *Self,
            peer: PublicKey,
            epoch: Epoch,
            body: []const u8,
            sender: anytype,
            strategy: anytype,
        ) !bool {
            const pending = &self.pending.?;
            const candidate = pending.in_flight orelse return false;
            if (!candidate.peer.eql(peer)) return false;
            if (pending.floor.epoch().get() != epoch.get()) return false;
            pending.in_flight = null;
            var finalization = candidate.finalization;
            const commitment = finalization.proposal.payload;
            const cfg = self.block_cfg;
            const decoded = wire.read_block(V, self.gpa, body, commitment, cfg, strategy);
            const value = decoded catch |err| {
                finalization.deinit(self.gpa);
                if (err == error.OutOfMemory) return error.OutOfMemory;
                self.block(peer); // An invalid boundary block.
                try self.request_next_block(sender);
                return true;
            };
            const artifact = try self.artifact_from_block(finalization, value) orelse {
                self.block(peer); // A boundary block without the floor epoch's info.
                try self.request_next_block(sender);
                return true;
            };
            try self.resolve(artifact);
            return false;
        }

        /// Asks the next verified responder for the block, or every peer for boundary
        /// finalizations when none remains.
        fn request_next_block(self: *Self, sender: anytype) !void {
            const pending = &self.pending.?;
            assert(pending.in_flight == null);
            const epoch = pending.floor.epoch();
            const candidate = pending.candidates.popFront() orelse {
                return self.send(sender, .all, .{ .boundary_request = epoch });
            };
            pending.in_flight = candidate;
            try self.send(sender, .{ .one = candidate.peer }, .{ .block_request = epoch });
        }

        /// The artifact `block` (taken) carries, or null if it is not the floor epoch's
        /// boundary block. Takes `finalization`.
        fn artifact_from_block(
            self: *Self,
            finalization: Finalization,
            block_value: V.Block,
        ) !?Artifact {
            const pending = &self.pending.?;
            var owned = finalization;
            errdefer owned.deinit(self.gpa);
            var shared = V.into_shared(block_value);
            defer shared.deinit();
            const inner = shared.inner();
            if (inner.height().get() != pending.height.get()) {
                owned.deinit(self.gpa);
                return null;
            }
            var payload = try inner.payload(self.gpa) orelse {
                owned.deinit(self.gpa);
                return null;
            };
            const floor_epoch = pending.floor.epoch().get();
            if (payload != .epoch_info or payload.epoch_info.epoch.get() != floor_epoch) {
                payload.deinit(self.gpa);
                owned.deinit(self.gpa);
                return null;
            }
            errdefer payload.deinit(self.gpa);
            const floor = try pending.floor.clone(self.gpa);
            return .{
                .gpa = self.gpa,
                .finalization = owned,
                .info = payload.epoch_info,
                .floor = floor,
            };
        }

        /// Publishes `artifact` (taken) to every subscriber and caches it.
        fn resolve(self: *Self, artifact: Artifact) !void {
            assert(self.artifact == null);
            if (self.pending) |*pending| pending.deinit(self.gpa);
            self.pending = null;
            self.artifact = artifact;
            const subscribers = self.subscribers.items;
            defer self.subscribers.clearRetainingCapacity();
            for (subscribers, 0..) |*subscriber, index| {
                deliver(self.gpa, subscriber, &self.artifact.?) catch |err| {
                    for (subscribers[index + 1 ..]) |*rest| rest.deinit();
                    return err;
                };
            }
        }

        /// Sends a copy of `artifact` through `response` (released either way).
        pub fn deliver(
            gpa: Allocator,
            response: *oneshot.Sender(Artifact),
            artifact: *const Artifact,
        ) Allocator.Error!void {
            const copy = artifact.clone(gpa) catch |err| {
                response.deinit();
                return err;
            };
            response.send(copy) catch copy.discard();
        }
    };
}
