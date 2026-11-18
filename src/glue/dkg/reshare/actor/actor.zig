//! The reshare actor (commonware `reshare/actor/mod.rs`, `setup.rs`, and `follower.rs`).
//!
//! Each iteration of the run loop handles the epoch holding the first height the actor has not
//! applied: `setup` loads the epoch's `EpochInfo`, registers its scheme, and restores this
//! node's dealer and player; `follow` applies the chain without participating until an epoch's
//! final block. The dealing, inclusion, and one-shot DKG windows follow.
//!
//! The actor's type parameters come in one comptime struct `T`, checked by `assert_types`: the
//! mailbox's `Block`, `Ack`, and `Ancestry`, plus `Signer`, `Manager`, `Blocker`, `Provider`
//! (a `ParticipantsProvider`), `SecretStore`, `Registrar`, `Marshal`, and `Strategy`. `Marshal`
//! is the part of marshal's mailbox the actor reads: `get_block(identifier) !?Digested(Block)`
//! with `.{ .height = h }`. Collaborators the caller owns are passed by pointer.
//!
//! Commonware panics on marshal or provider contract violations (a conflicting, skipped, or
//! unlinked finalized block; a boundary without the expected `EpochInfo`). Here those are
//! `ContractError`s, so the actor's tests check them; the run loop stops on them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor_pkg = @import("actor");
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const metrics_pkg = @import("runtime").telemetry.metrics;
const dkg = @import("../../root.zig");
const types = @import("../../types.zig");
const Fence = @import("../../fence.zig").Fence;
const store_mod = @import("../store.zig");
const mailbox_mod = @import("../mailbox.zig");
const reshare_metrics = @import("../metrics.zig");
const setup = @import("setup.zig");

const Epoch = consensus.Epoch;
const EpochPhase = consensus.types.EpochPhase;
const FixedEpocher = consensus.types.FixedEpocher;
const Height = consensus.Height;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = cryptography.bls12381.primitives.group.Share;
const SharingMode = cryptography.bls12381.primitives.Mode;
const Summary = cryptography.transcript.Summary;
const N3f1 = utils.N3f1;
const log = std.log.scoped(.dkg_reshare);

/// Whether a window ran to its end (`proceed`) or the actor must stop (`stop`): Rust's
/// `ControlFlow`.
pub const Flow = enum { proceed, stop };

/// Marshal or provider contract violations, where commonware panics.
pub const ContractError = error{
    ConflictingFinalizedBlock,
    SkippedFinalizedHeight,
    UnlinkedFinalizedBlock,
    UnknownHeight,
    MissingEpochInfo,
    WrongEpochInfo,
    BoundaryEpochMismatch,
    InvalidParticipants,
};

/// Asserts `T` carries the actor's type parameters (see the file header).
pub fn assert_types(comptime T: type) void {
    comptime {
        mailbox_mod.assert_types(T);
        const decls = .{
            "Signer",      "Manager",   "Blocker", "Provider",
            "SecretStore", "Registrar", "Marshal", "Strategy",
        };
        for (decls) |decl| {
            if (!@hasDecl(T, decl)) @compileError(@typeName(T) ++ " lacks reshare." ++ decl);
        }
        dkg.assert_secret_store(T.SecretStore);
        dkg.assert_registrar(T.Registrar);
        dkg.assert_participants_provider(T.Provider);
    }
}

/// Configuration for `Actor` (commonware `Config`, without the journal and secret store,
/// which `run` takes).
pub fn Config(comptime T: type) type {
    return struct {
        /// Signs player acknowledgements and dealer logs.
        signer: T.Signer,
        /// Tracks peers during one-shot DKG.
        manager: *T.Manager,
        /// Blocks peers that send invalid protocol messages.
        blocker: *T.Blocker,
        /// Source of future participant sets and transport directories.
        participants_provider: *T.Provider,
        /// Parallel strategy for cryptographic verification.
        strategy: T.Strategy,
        /// Receives each epoch's signer, member, or verifier scheme.
        registrar: *T.Registrar,
        /// Reads finalized blocks.
        marshal: T.Marshal,
        /// Marked after each epoch's scheme is registered.
        fence: *Fence,
        /// Application namespace for transcript separation.
        namespace: []const u8,
        sharing_mode: SharingMode,
        reveal: fd.Reveal,
        mailbox_size: u32,
        /// Maximum entries in each decoded or provider-supplied participant set.
        max_participants: u32,
        /// Epoch length; the second half of each epoch is the inclusion window.
        blocks_per_epoch: u64,
    };
}

/// The reshare actor for one node.
pub fn Actor(comptime T: type) type {
    comptime assert_types(T);
    return struct {
        const Self = @This();
        pub const V = T.Block.Variant;
        pub const P = T.Block.PublicKey;
        pub const D = T.Block.Directory;
        pub const Store = store_mod.Store(V, P, D, T.SecretStore);
        pub const Info = Store.Info;
        pub const Mailbox = mailbox_mod.Mailbox(T);
        pub const Message = mailbox_mod.Message(T);
        pub const Digested = broadcast.Digested(T.Block);
        pub const Dealer = store_mod.Dealer(V, T.Signer);
        pub const Player = store_mod.Player(V, T.Signer);
        pub const Round = fd.Info(V, P);
        pub const Tip = setup.FinalizedTip(T.Block.Digest);
        pub const Metrics = reshare_metrics.Metrics(P);

        /// An epoch prepared for participation. `info` is heap-held because the dealer and
        /// player borrow it.
        pub const PreparedEpoch = struct {
            epoch: Epoch,
            phase: EpochPhase,
            info: *Round,
            dealer: ?Dealer,
            player: ?Player,

            pub fn deinit(prepared: *PreparedEpoch, gpa: Allocator) void {
                if (prepared.dealer) |*dealer| dealer.deinit();
                if (prepared.player) |*player| player.deinit();
                prepared.info.deinit(gpa);
                gpa.destroy(prepared.info);
                prepared.* = undefined;
            }
        };

        pub const Setup = union(enum) { follow, participate: PreparedEpoch };

        /// State-sync epoch material paired with the height of its certified floor.
        pub const StateSyncStart = struct { info: Info, floor: Height };

        pub const Preparation = struct {
            epoch: Epoch,
            phase: EpochPhase,
            participants: types.Participants(P),
            previous: ?fd.Output(V, P),
            share: ?Share,
            seed: Summary,
        };

        gpa: Allocator,
        io: Io,
        mailbox: actor_pkg.mailbox.Receiver(Message),
        config: Config(T),
        epocher: FixedEpocher,
        metrics: Metrics,
        /// Latest finalized block the actor has applied.
        tip: ?Tip = null,

        /// Creates an actor and the mailbox that feeds it.
        pub fn init(
            gpa: Allocator,
            io: Io,
            scope: *const metrics_pkg.Scope,
            config: Config(T),
        ) !struct { Self, Mailbox } {
            assert(config.mailbox_size > 0);
            assert(config.max_participants > 0);
            const length = utils.NonZero(u64).init(config.blocks_per_epoch) orelse
                return error.InvalidEpochLength;
            const pair = try actor_pkg.mailbox.new(Message, gpa, io, config.mailbox_size);
            var receiver = pair.receiver;
            var sender = pair.sender;
            errdefer receiver.deinit();
            errdefer sender.deinit();
            const reshare_metrics_value = try Metrics.init(gpa, scope);
            const self: Self = .{
                .gpa = gpa,
                .io = io,
                .mailbox = receiver,
                .config = config,
                .epocher = .new(length),
                .metrics = reshare_metrics_value,
            };
            return .{ self, Mailbox.init(gpa, io, sender) };
        }

        pub fn deinit(self: *Self) void {
            self.mailbox.deinit();
            self.metrics.deinit();
            self.* = undefined;
        }

        /// Whether the actor already applied `block`. A block at or below the tip is a
        /// redelivery; one above it must be at the next height with the tip as its parent.
        pub fn covered(self: *const Self, block: *const Digested) ContractError!bool {
            const tip = self.tip orelse return false;
            const height = block.inner().height().get();
            if (height == tip.height.get()) {
                if (!block.digest().eql(tip.digest)) return error.ConflictingFinalizedBlock;
            } else if (height > tip.height.get()) {
                if (height != tip.height.get() + 1) return error.SkippedFinalizedHeight;
                if (!block.inner().parent().eql(tip.digest)) return error.UnlinkedFinalizedBlock;
            }
            return height <= tip.height.get();
        }

        /// Records `block` as the tip after its effects complete.
        pub fn advance(self: *Self, block: *const Digested) void {
            const height = block.inner().height();
            assert(self.tip == null or height.get() > self.tip.?.height.get());
            self.tip = .{ .height = height, .digest = block.digest() };
            assert(self.tip.?.height.get() == height.get());
        }

        /// The runtime's RNG as a `std.Random` (commonware draws from the context).
        fn random(self: *Self, state: *IoRandom) std.Random {
            state.* = .{ .io = self.io };
            return std.Random.init(state, IoRandom.fill);
        }

        /// This node's share of `info.output` (`setup.recovered_share`).
        pub fn recovered_share(self: *Self, store: *Store, info: *const Info) !?Share {
            return setup.recovered_share(V, store, self.config.signer.public_key(), info);
        }

        /// Registers the scheme for `info` in this node's role, then marks the fence.
        pub fn register_epoch(self: *Self, info: *const Info, share: ?Share) !void {
            const gpa = self.gpa;
            var players = try info.output.players.clone(gpa);
            errdefer players.deinit(gpa);
            const public = try info.output.public.clone(gpa);
            const key = self.config.signer.public_key();
            const scheme_info = types.SchemeInfo(V, P).init(key, players, public, share);
            const registrar = self.config.registrar;
            const fence = self.config.fence;
            try setup.register_and_mark(registrar, self.io, fence, info.epoch, scheme_info);
        }

        /// The `EpochInfo` of the finalized boundary block that introduced `epoch` (null when
        /// marshal does not have it).
        fn boundary_epoch_info(self: *Self, epoch: Epoch) !?Info {
            const height = if (epoch.previous()) |previous|
                self.epocher.last(previous) orelse return error.UnknownHeight
            else
                Height.zero();
            var block = try self.config.marshal.get_block(.{ .height = height }) orelse return null;
            defer block.deinit();
            return try self.epoch_info_of(&block);
        }

        /// The `EpochInfo` a boundary or final block carries (owned).
        fn epoch_info_of(self: *Self, block: *const Digested) !Info {
            var payload = try block.inner().payload(self.gpa) orelse return error.MissingEpochInfo;
            if (payload != .epoch_info) {
                payload.deinit(self.gpa);
                return error.MissingEpochInfo;
            }
            return payload.epoch_info;
        }

        /// Loads the epoch after the tip, registers its scheme, and restores this node's
        /// dealer and player (commonware `setup`). Takes `state_sync`.
        pub fn setup_epoch(self: *Self, store: *Store, state_sync: ?StateSyncStart) !Setup {
            self.metrics.set_phase(.setup);
            var pending = state_sync;
            defer if (pending) |*start| start.info.deinit(self.gpa);
            const height = if (self.tip) |tip| tip.height.next() else Height.zero();
            const bounds = self.epocher.containing(height) orelse return error.UnknownHeight;
            const epoch = bounds.epoch;
            self.metrics.set_epoch(epoch.get());

            // Prefer the epoch committed earlier in this run, then state sync, then the
            // finalized boundary block.
            const current = store.current_info();
            const committed = current != null and current.?.epoch.get() == epoch.get();
            const floor = if (pending) |start| start.floor else null;
            const skipped = setup.state_sync_skips_inclusion_prefix(self.epocher, floor);
            var info: Info = if (committed)
                try current.?.clone(self.gpa)
            else if (pending) |start| blk: {
                pending = null;
                break :blk start.info;
            } else try self.boundary_epoch_info(epoch) orelse return .follow;
            defer info.deinit(self.gpa);
            if (info.epoch.get() != epoch.get()) return error.BoundaryEpochMismatch;
            return self.enter_epoch(store, &info, bounds.phase(), committed, skipped);
        }

        /// Validates, commits, and registers `info`, then prepares participation unless the
        /// actor must follow.
        fn enter_epoch(
            self: *Self,
            store: *Store,
            info: *const Info,
            phase: EpochPhase,
            committed: bool,
            skipped: bool,
        ) !Setup {
            const epoch = info.epoch;
            var participants = try info.participants(self.gpa);
            errdefer participants.deinit(self.gpa);
            const max = self.config.max_participants;
            participants.validate(V, max, &info.output, epoch.get()) catch
                return error.InvalidParticipants;

            // Persist the epoch's share and seed before registering its scheme, and prune
            // only once the epoch is durable.
            const share = try self.recovered_share(store, info);
            var rng_state: IoRandom = undefined;
            const seed = try store.seed_or_random(epoch, self.random(&rng_state));
            if (!committed) {
                try store.commit_epoch(try info.clone(self.gpa), seed, share);
                try self.register_epoch(info, share);
            }
            try store.prune(epoch.previous() orelse epoch);

            // A floor after the midpoint skipped blocks that may carry dealer logs.
            if (skipped) {
                if (share != null) {
                    log.info("validator synced past epoch {d}'s midpoint: it cannot vote " ++
                        "to finalize the epoch's last block", .{epoch.get()});
                }
                participants.deinit(self.gpa);
                return .follow;
            }
            const previous = try info.output.clone(self.gpa);
            return .{ .participate = try self.prepare_epoch(store, .{
                .epoch = epoch,
                .phase = phase,
                .participants = participants,
                .previous = previous,
                .share = share,
                .seed = seed,
            }) };
        }

        /// Builds the round and this node's dealer and player for an epoch (takes
        /// `preparation`'s participants and previous output).
        pub fn prepare_epoch(self: *Self, store: *Store, preparation: Preparation) !PreparedEpoch {
            const gpa = self.gpa;
            var participants = preparation.participants;
            defer participants.deinit(gpa);
            var previous = preparation.previous;
            self.metrics.reconcile(participants.dealers, participants.players);
            const round = try gpa.create(Round);
            errdefer gpa.destroy(round);
            const has_previous = previous != null;
            round.* = blk: {
                errdefer if (previous) |*output| output.deinit(gpa);
                var dealers = try participants.dealers.clone(gpa);
                errdefer dealers.deinit(gpa);
                const players = try participants.players.clone(gpa);
                const config = self.config;
                const round_number = preparation.epoch.get();
                break :blk try Round.init(
                    N3f1,
                    gpa,
                    config.namespace,
                    round_number,
                    previous,
                    config.sharing_mode,
                    config.reveal,
                    dealers,
                    players,
                );
            };
            errdefer round.deinit(gpa);

            // Reshare dealers need the prior share; epoch-zero DKG has no prior output.
            const signer = self.config.signer;
            const key = signer.public_key();
            const epoch = preparation.epoch;
            const can_deal = !has_previous or preparation.share != null;
            const created: ?Dealer = if (participants.dealers.position(key) != null and can_deal)
                try store.create_dealer(
                    N3f1,
                    T.Signer,
                    epoch,
                    signer,
                    round,
                    preparation.share,
                    preparation.seed,
                )
            else
                null;
            const players = participants.players.len();
            var dealer = setup.dealer_for_phase(preparation.phase, players, created);
            errdefer if (dealer) |*value| value.deinit();
            const player: ?Player = if (participants.players.position(key) != null)
                try store.create_player(N3f1, T.Signer, epoch, signer, round)
            else
                null;
            return .{
                .epoch = epoch,
                .phase = preparation.phase,
                .info = round,
                .dealer = dealer,
                .player = player,
            };
        }

        /// Follows the chain without participating until the next final block of an epoch is
        /// applied, then commits and registers that block's `EpochInfo` (commonware `follow`).
        /// Stops when the mailbox closes.
        pub fn follow(self: *Self, store: *Store) !Flow {
            self.metrics.set_phase(.following);
            // Each pass consumes one message; the mailbox bounds what arrives.
            while (try self.mailbox.recv()) |message| {
                switch (message.body) {
                    .next_log => |body| answer(body.response, null),
                    .release_log => {},
                    .epoch_info => |body| {
                        var ancestry = body.ancestry;
                        ancestry.deinit();
                        answer(body.response, .unavailable);
                    },
                    .finalized => |body| {
                        if (try self.follow_finalized(store, body.block, body.response)) {
                            return .proceed;
                        }
                    },
                }
            }
            return .stop;
        }

        fn follow_finalized(self: *Self, store: *Store, block: Digested, ack: T.Ack) !bool {
            var owned_block = block;
            defer owned_block.deinit();
            var response = ack;
            errdefer response.deinit();
            if (try self.covered(&owned_block)) {
                response.acknowledge();
                return false;
            }
            const height = owned_block.inner().height();
            const bounds = self.epocher.containing(height) orelse return error.UnknownHeight;
            const done = height.get() == bounds.last.get();
            if (done) try self.follow_boundary(store, &owned_block, bounds.epoch);
            self.advance(&owned_block);
            response.acknowledge();
            return done;
        }

        /// Commits and registers the next epoch's `EpochInfo` from `epoch`'s final block.
        fn follow_boundary(self: *Self, store: *Store, block: *const Digested, epoch: Epoch) !void {
            var info = try self.epoch_info_of(block);
            defer info.deinit(self.gpa);
            if (info.epoch.get() != epoch.next().get()) return error.WrongEpochInfo;
            var rng_state: IoRandom = undefined;
            const seed = try store.seed_or_random(info.epoch, self.random(&rng_state));
            const share = try self.recovered_share(store, &info);
            try store.commit_epoch(try info.clone(self.gpa), seed, share);
            try self.register_epoch(&info, share);
        }
    };
}

/// Sends `value` on a responder; a requester that already left loses nothing.
pub fn answer(sender: anytype, value: anytype) void {
    var responder = sender;
    responder.send(value) catch {};
}

const IoRandom = struct {
    io: Io,

    fn fill(self: *IoRandom, buffer: []u8) void {
        self.io.random(buffer);
    }
};

test {
    _ = @import("actor_test.zig");
}
