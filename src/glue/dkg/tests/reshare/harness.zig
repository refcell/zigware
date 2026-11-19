//! The reshare end-to-end harness (commonware `glue::dkg::tests::reshare::harness`):
//! validators without state sync, on the discovery or the lookup network (`lookup.zig`).
//!
//! `ReshareEngine` is the plan's engine definition. It deals epoch zero's output from a fixed
//! seed to the schedule's first committee and seeds each player's secret store with its
//! share. Secret stores and the `Ledger` live in the definition, so they survive restarts
//! within a run. `ValidatorState` reads a validator's marshal for the properties. The DKG
//! channel drops the ceremonies of `failures` (commonware `FilteredReceiver::epochs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const simulate = @import("../../../simulate/mod.zig");
const network = @import("../../network.zig");
const mocks = @import("../mocks.zig");
const properties = @import("properties.zig");
const support = @import("support.zig");
const validator = @import("validator.zig");
pub const lookup = @import("lookup.zig");

const Epoch = consensus.Epoch;
const ed25519 = cryptography.ed25519;
pub const Key = ed25519.PublicKey;
const MinPk = cryptography.bls12381.primitives.MinPk;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = cryptography.bls12381.primitives.group.Share;
const Net = p2p.simulated.Network(Key);
const Set = utils.ordered.Set(Key);
const Context = simulate.engine.Context;
const Duration = utils.time.Duration;

const test_quota = p2p.Quota.per_second(1024);
/// The six channels, in `Validator.Channels` order: votes, certificates, resolver, backfill,
/// broadcast, dkg.
const channel_count = 6;
const dkg_channel = 5;

pub const FilteredNetwork = struct {
    pub const Sender = Net.Sender;
    pub const Receiver = mocks.FilteredReceiver(Net.Receiver);
};

pub const Types = struct {
    pub const Variant = MinPk;
    pub const Directory = lookup.TestDirectory;
    pub const Manager = lookup.TestManager;
    pub const PeerProvider = Net.Manager;
    pub const Blocker = Net.Control;
    pub const SecretStore = mocks.MemorySecretStore;
    pub const Context = runtime.deterministic.Context;
    pub const Network = FilteredNetwork;
};
pub const Validator = validator.Validator(Types);
pub const Info = Validator.Info;
const Boundary = properties.Boundary(Info);

/// A validator's view for the properties (commonware `ValidatorState`).
pub const ValidatorState = struct {
    pub const Info = validator.Validator(Types).Info;

    gpa: Allocator,
    key: Key,
    /// Borrowed from the engine definition.
    ledger: *const support.Ledger,
    marshal: *Marshal,

    /// A marshal mailbox clone this state owns, published by the validator once marshal is up.
    pub const Marshal = struct { mailbox: ?Validator.MarshalMailbox = null };

    pub fn public_key(self: *const ValidatorState) Key {
        return self.key;
    }

    pub fn processed_height(self: *const ValidatorState) u64 {
        return self.ledger.processed_of(self.key);
    }

    pub fn registrations(self: *const ValidatorState) []const properties.Registration {
        return self.ledger.registrations_of(self.key);
    }

    pub fn state_sync_height(self: *const ValidatorState) ?u64 {
        return self.ledger.state_sync_of(self.key);
    }

    /// What this validator's finalized block at `height` carries.
    pub fn boundary(self: *const ValidatorState, gpa: Allocator, height: u64) !Boundary {
        const mailbox = self.marshal.mailbox orelse return .missing;
        var block = try mailbox.get_block(.{ .height = .new(height) }) orelse return .missing;
        defer block.deinit();
        const info = block.inner().epoch_info() orelse {
            return if (try block.inner().payload(gpa)) |payload| other: {
                var owned = payload;
                owned.deinit(gpa);
                break :other .other_payload;
            } else .no_payload;
        };
        return .{ .info = try info.clone(gpa) };
    }
};

/// What the plan starts for one validator.
pub const Started = struct {
    context: Context,
    config: Validator.Config,
    channels: Validator.Channels,
};

pub const ReshareEngine = struct {
    pub const PublicKey = Key;
    pub const Engine = Started;
    pub const State = ValidatorState;

    gpa: Allocator,
    network: lookup.Network,
    signers: []ed25519.PrivateKey,
    keys: []Key,
    committee_sizes: []usize,
    rotation_stride: usize,
    initial: Info,
    /// The initial deal's shares, by participant index (null outside epoch zero's players).
    initial_shares: []?Share,
    stores: []mocks.MemorySecretStore,
    managers: []Types.Manager,
    ledger: support.Ledger,
    sharing_mode: cryptography.bls12381.primitives.sharing.Mode = .non_zero_counter,
    /// Epochs whose ceremonies fail: every validator drops their DKG messages.
    failures: []const u64 = &.{},
    /// commonware `with_elector`; the default rotates the leader every view.
    elector: Validator.ElectorConfig = .default(),

    /// commonware `ReshareEngine::new`: five participants, committees of four.
    pub fn create(gpa: Allocator) !ReshareEngine {
        return with_committees(gpa, 5, &.{4}, 1);
    }

    /// `create` on `network_kind`.
    pub fn create_on(gpa: Allocator, network_kind: lookup.Network) !ReshareEngine {
        return with_network(gpa, network_kind, 5, &.{4}, 1);
    }

    /// `with_network` on the discovery network.
    pub fn with_committees(
        gpa: Allocator,
        total: u32,
        committee_sizes: []const usize,
        rotation_stride: usize,
    ) !ReshareEngine {
        return with_network(gpa, .discovery, total, committee_sizes, rotation_stride);
    }

    /// commonware `with_committees`: each epoch's players start `rotation_stride` after the
    /// previous epoch's.
    pub fn with_network(
        gpa: Allocator,
        network_kind: lookup.Network,
        total: u32,
        committee_sizes: []const usize,
        rotation_stride: usize,
    ) !ReshareEngine {
        assert(committee_sizes.len > 0 and total <= validator.max_participants);
        for (committee_sizes) |size| assert(size > 0 and size <= total);
        var self: ReshareEngine = undefined;
        self.gpa = gpa;
        self.network = network_kind;
        self.sharing_mode = .non_zero_counter;
        self.failures = &.{};
        self.elector = .default();
        self.rotation_stride = rotation_stride;
        self.committee_sizes = try gpa.dupe(usize, committee_sizes);
        errdefer gpa.free(self.committee_sizes);
        self.signers = try gpa.alloc(ed25519.PrivateKey, total);
        errdefer gpa.free(self.signers);
        for (self.signers, 0..) |*signer, seed| signer.* = .from_seed(seed + 1000);
        self.keys = try gpa.alloc(Key, total);
        errdefer gpa.free(self.keys);
        for (self.keys, self.signers) |*key, signer| key.* = signer.public_key();
        try self.deal_initial();
        errdefer self.free_initial();
        self.ledger = try .init(gpa, self.keys);
        errdefer self.ledger.deinit();
        self.stores = try gpa.alloc(mocks.MemorySecretStore, total);
        errdefer gpa.free(self.stores);
        self.managers = try gpa.alloc(Types.Manager, total);
        try self.seed_stores();
        return self;
    }

    /// commonware's trusted initial deal from `TestRng::new(10)` to epoch zero's players.
    fn deal_initial(self: *ReshareEngine) !void {
        const gpa = self.gpa;
        const committees = self.schedule();
        const players = try committees.players(gpa, 0);
        var rng = utils.rng.TestRng.init(10);
        var dealt = try fd.deal(MinPk, Key, utils.N3f1, gpa, &rng, .non_zero_counter, players);
        defer dealt.shares.deinit(gpa);
        errdefer dealt.output.deinit(gpa);
        self.initial_shares = try gpa.alloc(?Share, self.keys.len);
        errdefer gpa.free(self.initial_shares);
        @memset(self.initial_shares, null);
        for (dealt.shares.keys.items, dealt.shares.values) |key, share| {
            self.initial_shares[self.index_of(key)] = share;
        }
        var output_players = try dealt.output.players.clone(gpa);
        errdefer output_players.deinit(gpa);
        var next_players = try committees.players(gpa, 1);
        errdefer next_players.deinit(gpa);
        const directory = try self.initial_directory(output_players, next_players);
        self.initial = .{
            .outcome = .success,
            .epoch = .zero(),
            .output = dealt.output,
            .players = output_players,
            .next_players = next_players,
            .directory = directory,
        };
        assert((self.initial.directory.addresses == null) == (self.network == .discovery));
    }

    /// commonware's `network.directory(initial_peers)`: epoch zero's dealers, players, and
    /// next players.
    fn initial_directory(
        self: *const ReshareEngine,
        players: Set,
        next_players: Set,
    ) !lookup.TestDirectory {
        const gpa = self.gpa;
        const joined = try std.mem.concat(gpa, Key, &.{ players.items, next_players.items });
        defer gpa.free(joined);
        var peers = try Set.from_dedup(gpa, joined);
        defer peers.deinit(gpa);
        assert(peers.items.len >= players.items.len);
        return lookup.TestDirectory.of(gpa, self.network, self.keys, peers);
    }

    fn free_initial(self: *ReshareEngine) void {
        for (self.initial_shares) |*share| if (share.*) |*held| held.private.zeroize();
        self.gpa.free(self.initial_shares);
        self.initial.deinit(self.gpa);
    }

    /// Fresh secret stores holding the initial shares (commonware `store`'s first call).
    fn seed_stores(self: *ReshareEngine) !void {
        for (self.stores, self.initial_shares) |*store, share| {
            store.* = .init(self.gpa);
            if (share) |held| try store.put_share(Epoch.zero(), held);
        }
    }

    pub fn deinit(self: *ReshareEngine) void {
        const gpa = self.gpa;
        for (self.stores) |*store| store.deinit();
        gpa.free(self.stores);
        gpa.free(self.managers);
        self.ledger.deinit();
        self.free_initial();
        gpa.free(self.keys);
        gpa.free(self.signers);
        gpa.free(self.committee_sizes);
        self.* = undefined;
    }

    /// Fresh stores and records, for the next seed.
    pub fn reset(self: *ReshareEngine) !void {
        for (self.stores) |*store| store.deinit();
        try self.seed_stores();
        self.ledger.reset();
    }

    pub fn schedule(self: *const ReshareEngine) properties.CommitteeSchedule {
        return .{
            .participants = self.keys,
            .committee_sizes = self.committee_sizes,
            .rotation_stride = self.rotation_stride,
        };
    }

    fn index_of(self: *const ReshareEngine, key: Key) usize {
        for (self.keys, 0..) |item, at| if (item.eql(key)) return at;
        unreachable; // Every dealt player is a participant.
    }

    pub fn participants(self: *const ReshareEngine) []const Key {
        return self.keys;
    }

    pub fn channels(_: *const ReshareEngine) []const simulate.ChannelSpec {
        const specs = comptime blk: {
            var list: [channel_count]simulate.ChannelSpec = undefined;
            for (&list, 0..) |*spec, index| spec.* = .{ .channel = index, .quota = test_quota };
            break :blk list;
        };
        return &specs;
    }

    pub fn max_message_size(_: *const ReshareEngine) u32 {
        const Scheme = Validator.Scheme;
        const Digest = Validator.Block.Digest;
        const participants_max = validator.max_participants;
        const orchestrator_bound = @import("../../orchestrator/root.zig").limits
            .max_payload_size(Scheme, Digest, participants_max);
        const mode = mocks.max_supported_mode;
        const payload = @import("../../bootstrap/mod.zig")
            .max_payload_size(MinPk, lookup.TestDirectory, participants_max, mode);
        return p2p.max_message_size(&.{ orchestrator_bound, payload, 1 << 20 });
    }

    pub fn init(self: *const ReshareEngine, ctx: simulate.InitContext(Key)) !struct {
        Started,
        ValidatorState,
    } {
        assert(ctx.channels.len == channel_count);
        const gpa = self.gpa;
        const index = ctx.index;
        // commonware: a node restarting means its processed hold served its purpose. A node
        // that processed a block before is restarting.
        const ledger: *support.Ledger = @constCast(&self.ledger);
        if (ledger.processed_of(ctx.public_key) > 0) ledger.release_hold(ctx.public_key);
        const marshal = try gpa.create(ValidatorState.Marshal);
        marshal.* = .{};
        // commonware `Network::manager`: a node starts, and restarts, with no peer sets, and
        // tracks sets for itself alone.
        const control = ctx.oracle.control(ctx.public_key);
        try control.reset_peer_sets();
        const manager = &self.managers[index];
        manager.* = .init(gpa, self.network, control);
        var wrapped: [channel_count]Validator.Channel = undefined;
        for (&wrapped, ctx.channels, 0..) |*channel, registered, at| {
            const filter: mocks.Filter = if (at == dkg_channel and self.failures.len > 0)
                .{ .epochs = self.failures }
            else
                .none;
            const receiver: FilteredNetwork.Receiver = .{
                .inner = registered.receiver,
                .filter = filter,
            };
            channel.* = .{ .sender = registered.sender, .receiver = receiver };
        }
        const state: ValidatorState = .{
            .gpa = gpa,
            .key = ctx.public_key,
            .ledger = &self.ledger,
            .marshal = marshal,
        };
        var settings = self.config(ctx, manager);
        settings.published = &marshal.mailbox;
        const started: Started = .{
            .context = ctx.context,
            .config = settings,
            .channels = .{
                .votes = wrapped[0],
                .certificates = wrapped[1],
                .resolver = wrapped[2],
                .backfill = wrapped[3],
                .broadcast = wrapped[4],
                .dkg = wrapped[5],
            },
        };
        return .{ started, state };
    }

    fn config(
        self: *const ReshareEngine,
        ctx: simulate.InitContext(Key),
        manager: *Types.Manager,
    ) Validator.Config {
        const index = ctx.index;
        assert(self.keys[index].eql(ctx.public_key));
        const self_mut: *ReshareEngine = @constCast(self);
        return .{
            .signer = self.signers[index],
            .manager = manager,
            .peer_provider = manager.provider(),
            .blocker = ctx.oracle.control(ctx.public_key),
            .secret_store = &self_mut.stores[index],
            .ledger = &self_mut.ledger,
            .monitor = ctx.monitor,
            .schedule = self.schedule(),
            .initial = &self.initial,
            .network = self.network,
            .sharing_mode = self.sharing_mode,
            .elector = self.elector,
            .partition_prefix = prefixes[index],
        };
    }

    const prefixes = [_][]const u8{
        "reshare-e2e-0",  "reshare-e2e-1",  "reshare-e2e-2",  "reshare-e2e-3",
        "reshare-e2e-4",  "reshare-e2e-5",  "reshare-e2e-6",  "reshare-e2e-7",
        "reshare-e2e-8",  "reshare-e2e-9",  "reshare-e2e-10", "reshare-e2e-11",
        "reshare-e2e-12", "reshare-e2e-13", "reshare-e2e-14", "reshare-e2e-15",
    };

    pub fn start(started: Started) !simulate.engine.Handle {
        return started.context.spawn(run_node, .{started});
    }

    pub fn deinit_state(state: *ValidatorState) void {
        if (state.marshal.mailbox) |*mailbox| mailbox.deinit();
        state.gpa.destroy(state.marshal);
        state.* = undefined;
    }
};

/// Runs a validator until the plan stops it (commonware `start`). A validator that stops on
/// its own fails the run.
fn run_node(ctx: Context, started: Started) void {
    const result = Validator.run(ctx.child("validator"), started.config, started.channels);
    result catch |err| {
        if (err == error.Canceled) return;
        ctx.io().checkCancel() catch return;
        std.debug.panic("reshare validator failed: {t}", .{err});
    };
    ctx.io().checkCancel() catch return;
    @panic("reshare validator stopped");
}

/// commonware `stable_leaders`: terms of two views, a 5 s stall timeout, and two optimistic
/// views, so every dealer of the largest committee (7) leads a term in an epoch's inclusion
/// window.
pub fn stable_leaders() Validator.ElectorConfig {
    const length = utils.NonZero(u32).init(2).?;
    return Validator.ElectorConfig.default().with_term(.new(length), .from_secs(5), .new(2));
}

/// commonware's `#[values(RoundRobin::default(), stable_leaders())]`.
pub const electors = [_]Validator.ElectorConfig{ .default(), stable_leaders() };

/// The link of commonware's reshare plans: `PlanBuilder`'s default (10ms latency, 5ms jitter),
/// not the dkg harness's 20ms `good_link`. Timing-sensitive ceremonies (full rotation) depend
/// on it.
pub const good_link: p2p.simulated.Link = simulate.plan.default_link;

pub const Plan = simulate.Plan(ReshareEngine);
