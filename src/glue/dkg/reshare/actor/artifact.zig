//! The inclusion window's artifact derivation (commonware `reshare/actor/inclusion.rs`):
//! verifying a dealer-log set, deriving the `EpochInfo` the epoch's final block must carry,
//! committing the finalized one, and recording dealer logs from finalized blocks.
//!
//! Commonware runs verification as a spawned CPU task. Here `verify` runs on the caller's
//! task (the window decides when to call it). Where commonware panics on invalid local
//! state or a provider contract violation, these return errors.

const std = @import("std");
const parallel = @import("parallel");
const assert = std.debug.assert;
const target = "commonware_glue::dkg::reshare::actor::inclusion";
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../../types.zig");
const network = @import("../../network.zig");
const inclusion = @import("inclusion.zig");
const actor_mod = @import("actor.zig");

const Epoch = consensus.Epoch;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = cryptography.bls12381.primitives.group.Share;
const N3f1 = utils.N3f1;

/// Local-state and provider failures where commonware panics.
pub const ArtifactError = error{
    /// Finalizing this node's player failed on its persisted state.
    InvalidLocalState,
    /// Neither a committed epoch nor one-shot DKG participants are available.
    MissingParticipants,
    /// A directory does not name exactly the requested peers.
    MismatchedDirectory,
    /// A one-shot DKG participant reconstructed an output without a share.
    MissingDkgShare,
    /// The final block omitted the payload this node reconstructed.
    MissingFinalPayload,
    EmptyFutureParticipants,
    OversizedFutureParticipants,
};

/// Artifact functions for `Actor(T)`.
pub fn Artifacts(comptime T: type) type {
    return struct {
        const Actor = actor_mod.Actor(T);
        const V = Actor.V;
        const P = Actor.P;
        const D = Actor.D;
        const Info = Actor.Info;
        const Set = utils.ordered.Set(P);
        const Dir = network.DirectoryOps(P, D);
        pub const Logs = inclusion.PendingLogs(V, P);
        pub const Ceremony = inclusion.Ceremony(V, P);
        pub const Payload = types.Payload(V, P, D);

        /// The `EpochInfo` a final block must carry and this node's share of it.
        pub const Artifact = struct {
            info: Info,
            share: ?Share,

            pub fn deinit(self: *Artifact, gpa: Allocator) void {
                self.info.deinit(gpa);
                if (self.share) |*share| share.private.zeroize();
                self.* = undefined;
            }
        };

        /// The artifact derived from one dealer-log set (null for a failed DKG).
        pub const Cached = struct { logs: Logs, artifact: ?Artifact };

        /// The artifact of the last derived log set and the epoch-after-next's players,
        /// which the provider must return identically for every request.
        pub const Cache = struct {
            next_players: ?Set = null,
            cached: ?Cached = null,

            pub const empty: Cache = .{};

            pub fn deinit(self: *Cache, gpa: Allocator) void {
                if (self.next_players) |*players| players.deinit(gpa);
                if (self.cached) |*cached| {
                    cached.logs.deinit(gpa);
                    if (cached.artifact) |*artifact| artifact.deinit(gpa);
                }
                self.* = undefined;
            }

            /// The cached entry if it was derived from exactly `logs`.
            pub fn get(self: *const Cache, logs: Logs) ?*const Cached {
                const cached = if (self.cached) |*cached| cached else return null;
                return if (cached.logs.eql(logs)) cached else null;
            }
        };

        /// The players of the committed epoch, or the one-shot DKG participants.
        fn round_players(self: *const Actor, store: *const Actor.Store) ArtifactError!Set {
            if (store.current_info()) |current| return current.players;
            return switch (self.mode) {
                .dkg => |dkg| dkg.participants,
                .reshare => error.MissingParticipants,
            };
        }

        /// Verifies and selects `logs` (borrowed) for `info`'s round: the output and, when
        /// this node is a player, its share; null when the logs yield no output (commonware
        /// `VerificationTask::run`).
        pub fn verify(
            self: *Actor,
            epoch: Epoch,
            info: *const Actor.Round,
            store: *const Actor.Store,
            logs: Logs,
        ) !?Ceremony {
            const gpa = self.gpa;
            const players = try round_players(self, store);
            var selection = fd.Logs(V, P, N3f1).init(info);
            defer selection.deinit(gpa);
            const pairs = try gpa.alloc(Actor.Store.LogPair, logs.len());
            defer gpa.free(pairs);
            for (logs.entries.items, pairs) |entry, *pair| {
                _ = try selection.record(gpa, entry.key, try entry.log.clone(gpa));
                pair.* = .{ entry.key, entry.log };
            }
            assert(selection.entries.items.len == logs.len());
            var rng = self.rng();
            const signer = self.config.signer;
            const ours = players.position(signer.public_key()) != null;
            var player = if (ours)
                try store.create_player_with_logs(N3f1, T.Signer, epoch, signer, info, pairs)
            else
                null;
            defer if (player) |*value| value.deinit();
            if (player) |*value| {
                const crypto = &value.player;
                const finalized = crypto.finalize(
                    N3f1,
                    gpa,
                    &rng,
                    &selection,
                    null,
                    parallel.sequential,
                ) catch |err|
                    switch (err) {
                        error.InsufficientLogs => {
                            const fields = .{ .epoch = epoch, .failure = err };
                            const t = self.tracer.with_target(target);
                            t.event(.warn, "failed to finalize player", fields);
                            return null;
                        },
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.InvalidLocalState,
                    };
                return .{ .output = finalized.output, .share = finalized.share };
            }
            const output = fd.observe(
                V,
                P,
                N3f1,
                gpa,
                &rng,
                &selection,
                null,
                parallel.sequential,
            ) catch |err|
                switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {
                        const fields = .{ .epoch = epoch, .@"error" = err };
                        const t = self.tracer.with_target(target);
                        t.event(.warn, "failed to observe reshare outcome", fields);
                        return null;
                    },
                };
            return .{ .output = output, .share = null };
        }

        /// The deduplicated union of three participant lists.
        fn requested(gpa: Allocator, a: Set, b: Set, c: Set) !Set {
            const all = try gpa.alloc(P, a.len() + b.len() + c.len());
            var at: usize = 0;
            for ([_]Set{ a, b, c }) |set| {
                @memcpy(all[at..][0..set.len()], set.as_slice());
                at += set.len();
            }
            assert(at == all.len);
            return Set.from_owned_dedup(gpa, all);
        }

        /// The epoch-after-next's players, from the cache or one provider lookup.
        fn next_players(self: *Actor, epoch: Epoch, cache: *Cache) !Set {
            if (cache.next_players) |players| return players.clone(self.gpa);
            const provider = self.config.participants_provider;
            var players = try provider.participants(self.io, self.gpa, epoch.next().next());
            errdefer players.deinit(self.gpa);
            try inclusion.validate_future_participants(players, self.config.max_participants);
            cache.next_players = try players.clone(self.gpa);
            return players;
        }

        /// The provider's directory for `epoch` over exactly `peers` (borrowed).
        fn directory(self: *Actor, epoch: Epoch, peers: Set) !D {
            const provider = self.config.participants_provider;
            var result = try provider.directory(self.io, self.gpa, epoch, peers);
            errdefer Dir.deinit(&result, self.gpa);
            if (!Dir.matches(result, peers)) return error.MismatchedDirectory;
            return result;
        }

        /// Derives the `EpochInfo` the final block must carry from `ceremony`, the
        /// verification result for `logs` (borrowed), and caches it (commonware `artifact`).
        /// A successful ceremony installs its output; a failed reshare carries the current
        /// output forward with this node's share of it; a failed one-shot DKG yields null.
        /// The result is owned by `cache`.
        pub fn derive(
            self: *Actor,
            epoch: Epoch,
            store: *Actor.Store,
            logs: Logs,
            ceremony: ?*const Ceremony,
            cache: *Cache,
        ) !?*const Artifact {
            if (cache.get(logs)) |cached| return if (cached.artifact) |*a| a else null;
            const gpa = self.gpa;
            var artifact = try build(self, epoch, store, ceremony, cache);
            errdefer if (artifact) |*value| value.deinit(gpa);
            const logs_copy = try logs.clone(gpa);
            if (cache.cached) |*old| {
                old.logs.deinit(gpa);
                if (old.artifact) |*value| value.deinit(gpa);
            }
            cache.cached = .{ .logs = logs_copy, .artifact = artifact };
            assert(cache.get(logs) != null);
            return if (cache.cached.?.artifact) |*value| value else null;
        }

        fn build(
            self: *Actor,
            epoch: Epoch,
            store: *Actor.Store,
            ceremony: ?*const Ceremony,
            cache: *Cache,
        ) !?Artifact {
            const current = store.current_info() orelse
                return build_dkg(self, epoch, ceremony);
            const gpa = self.gpa;
            var next = try next_players(self, epoch, cache);
            errdefer next.deinit(gpa);
            const success = ceremony != null;
            const output = if (ceremony) |value| value.output else current.output;
            var peers = try requested(gpa, output.players, current.next_players, next);
            defer peers.deinit(gpa);
            var dir = try directory(self, epoch.next(), peers);
            errdefer Dir.deinit(&dir, gpa);
            const share: ?Share = if (ceremony) |value| value.share else blk: {
                const key = self.config.signer.public_key();
                if (current.output.players.position(key) == null) break :blk null;
                break :blk try store.share(epoch);
            };
            var output_copy = try output.clone(gpa);
            errdefer output_copy.deinit(gpa);
            const players = try current.next_players.clone(gpa);
            return .{
                .info = .{
                    .outcome = if (success) .success else .failure,
                    .epoch = epoch.next(),
                    .output = output_copy,
                    .players = players,
                    .next_players = next,
                    .directory = dir,
                },
                .share = share,
            };
        }

        /// A one-shot DKG's artifact: the ceremony's output for `epoch` itself.
        fn build_dkg(self: *Actor, epoch: Epoch, ceremony: ?*const Ceremony) !?Artifact {
            const dkg = switch (self.mode) {
                .dkg => |value| value,
                .reshare => return error.MissingParticipants,
            };
            const value = ceremony orelse return null;
            const share = value.share orelse return error.MissingDkgShare;
            const gpa = self.gpa;
            var peers = try requested(gpa, value.output.players, dkg.participants, .empty);
            defer peers.deinit(gpa);
            if (!Dir.matches(dkg.directory, peers)) return error.MismatchedDirectory;
            var output = try value.output.clone(gpa);
            errdefer output.deinit(gpa);
            var players = try dkg.participants.clone(gpa);
            errdefer players.deinit(gpa);
            const dir = try Dir.clone(dkg.directory, gpa);
            return .{
                .info = .{
                    .outcome = .success,
                    .epoch = epoch,
                    .output = output,
                    .players = players,
                    .next_players = .empty,
                    .directory = dir,
                },
                .share = share,
            };
        }

        /// The response for `artifact` (copied): a missing artifact is `available` with no
        /// payload in one-shot DKG and `unavailable` in continuous reshare, whose final block
        /// always carries an `EpochInfo` (commonware `artifact_response`).
        pub fn response(self: *const Actor, artifact: ?*const Artifact) !Actor.Message.Response {
            const gpa = self.gpa;
            const value = artifact orelse return switch (self.mode) {
                .dkg => .{ .available = .{ .gpa = gpa, .payload = null } },
                .reshare => .unavailable,
            };
            const info = try value.info.clone(gpa);
            assert(info.epoch.get() == value.info.epoch.get());
            return .{ .available = .{ .gpa = gpa, .payload = .{ .epoch_info = info } } };
        }

        /// Commits the `EpochInfo` the final block of `epoch` carries (`payload`, taken) and,
        /// in continuous reshare, registers its scheme. This node's share is committed only
        /// when `artifact` matches the finalized info. A failed one-shot DKG's final block
        /// carries no payload, and nothing is committed (commonware
        /// `handle_finalized_epoch_info`).
        pub fn commit_final(
            self: *Actor,
            epoch: Epoch,
            store: *Actor.Store,
            artifact: ?*const Artifact,
            payload: ?Payload,
        ) !void {
            const gpa = self.gpa;
            const dkg = self.mode == .dkg;
            var owned = payload orelse {
                if (!dkg) return error.MissingEpochInfo;
                if (artifact != null) return error.MissingFinalPayload;
                return;
            };
            if (owned != .epoch_info) {
                owned.deinit(gpa);
                return error.MissingEpochInfo;
            }
            var info = owned.epoch_info;
            defer info.deinit(gpa);
            const expected = if (dkg) epoch else epoch.next();
            if (info.epoch.get() != expected.get()) return error.WrongEpochInfo;
            switch (info.outcome) {
                .success => {
                    const key = self.config.signer.public_key();
                    self.metrics.record_success(info.output, key);
                },
                .failure => self.metrics.failed_epochs.metric().inc(),
            }
            const matching = artifact != null and artifact.?.info.eql(info);
            const share: ?Share = if (matching) artifact.?.share else null;
            var rng_state: actor_mod.IoRandom = undefined;
            const seed = try store.seed_or_random(expected, self.random(&rng_state));
            try store.commit_epoch(try info.clone(gpa), seed, share);
            self.tracer.with_target(target).event(.info, "completed reshare ceremony", .{
                .epoch = info.epoch,
                .round = info.epoch.get(),
                .success = info.outcome == .success,
            });
            if (!dkg) try self.register_epoch(&info, share);
        }

        /// Durably records a correctly signed dealer log a finalized block carries
        /// (`payload`, taken). Invalid signatures and, once an epoch is committed, logs from
        /// outside its dealers are ignored. Observing this node's own log drops `dealer`'s
        /// signed log (commonware `observe_dealer_log`).
        pub fn observe_dealer_log(
            self: *Actor,
            info: *const Actor.Round,
            store: *Actor.Store,
            epoch: Epoch,
            dealer: ?*Actor.Dealer,
            payload: ?Payload,
        ) !void {
            const gpa = self.gpa;
            var owned = payload orelse return;
            defer owned.deinit(gpa);
            if (owned != .dealer_log) return;
            const signed = &owned.dealer_log;
            if (!try fd.check_log(V, P, gpa, info, signed)) {
                const fields = .{ .epoch = epoch };
                self.tracer.with_target(target).event(.warn, "ignoring invalid dealer log", fields);
                return;
            }
            // `check_log` authenticates the signature, not dealer membership: drop logs from
            // outside the committed epoch's players so a leader cannot grow storage.
            if (store.current_info()) |current| {
                if (current.output.players.position(signed.dealer) == null) {
                    const text = "ignoring dealer log from non-dealer";
                    self.tracer.with_target(target).event(.warn, text, .{ .epoch = epoch });
                    return;
                }
            }
            const ours = signed.dealer.eql(self.config.signer.public_key());
            const stored = try store.append_log(epoch, signed.dealer, signed.log);
            self.tracer.with_target(target).event(.info, "observed dealer log on chain", .{
                .epoch = epoch,
                .dealer = signed.dealer,
                .ours = ours,
                .stored = stored,
            });
            if (ours) if (dealer) |value| value.clear_finalized();
        }
    };
}
