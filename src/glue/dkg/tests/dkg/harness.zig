//! The one-shot DKG end-to-end harness (commonware `glue::dkg::tests::dkg::harness`).
//!
//! `DkgEngine` is a `simulate` engine definition: every participant runs the bootstrap
//! `Engine` on six simulated channels, and its `NodeState` records the reported completion.
//! Secret stores live in the engine definition, so they survive a participant's restarts
//! within a run, and `inits` records whether each incarnation started with its epoch-zero
//! share. `run_plan` runs a plan once per seed with fresh stores and checks `DkgOutcome`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const simulate = @import("../../../simulate/mod.zig");
const network = @import("../../network.zig");
const bootstrap = @import("../../bootstrap/mod.zig");
const mocks = @import("../mocks.zig");
const properties = @import("properties.zig");

const Epoch = consensus.Epoch;
const ed25519 = cryptography.ed25519;
const Key = ed25519.PublicKey;
const MinPk = cryptography.bls12381.primitives.MinPk;
const Unit = utils.sequence.Unit;
const Set = utils.ordered.Set(Key);
const Net = p2p.simulated.Network(Key);
const Context = simulate.engine.Context;
const Duration = utils.time.Duration;
pub const Info = properties.Info;

const namespace = "_COMMONWARE_GLUE_DKG_INITIAL_E2E";
pub const epoch_length = 32;
const test_quota = p2p.Quota.per_second(1024);
/// The six channels, in `Bootstrap.Channels` order: votes, certificates, resolver, backfill,
/// broadcast, dkg.
const channel_count = 6;
const dkg_channel = 5;

/// What every channel of a participant carries: the simulated network's sender and a
/// receiver that drops what its filter selects.
pub const FilteredNetwork = struct {
    pub const Sender = Net.Sender;
    pub const Receiver = mocks.FilteredReceiver(Net.Receiver);
};

pub const Types = struct {
    pub const Variant = MinPk;
    pub const Directory = Unit;
    pub const Manager = network.KeyOnlyManager(Net.Manager);
    pub const PeerProvider = Net.Manager;
    pub const Blocker = Net.Control;
    pub const SecretStore = mocks.MemorySecretStore;
    pub const Context = runtime.deterministic.Context;
    pub const Network = FilteredNetwork;
};
pub const Bootstrap = bootstrap.Engine(Types);

/// One incarnation's view of its completion, shared with its node task.
const Inner = struct {
    gpa: Allocator,
    store: *mocks.MemorySecretStore,
    completed: bool = false,
    /// Owned.
    info: ?Info = null,
};

/// A participant's state for the plan's properties (commonware `NodeState`).
pub const NodeState = struct {
    inner: *Inner,

    pub fn completed(self: *const NodeState) bool {
        return self.inner.completed;
    }

    pub fn info(self: *const NodeState) ?*const Info {
        return if (self.inner.info) |*value| value else null;
    }

    pub fn has_share(self: *const NodeState, epoch: Epoch) bool {
        return self.inner.store.has_share(epoch);
    }

    /// One once the participant completed (commonware `ProcessedHeight`).
    pub fn processed_height(self: *const NodeState) u64 {
        return @intFromBool(self.inner.completed);
    }
};

/// A started participant: everything its node task takes.
pub const Started = struct {
    context: Context,
    config: bootstrap.Config(Types),
    manager: *Types.Manager,
    channels: Bootstrap.Channels,
    inner: *Inner,
};

pub const DkgEngine = struct {
    pub const PublicKey = Key;
    pub const Engine = Started;
    pub const State = NodeState;

    gpa: Allocator,
    /// Sorted by public key.
    signers: []ed25519.PrivateKey,
    keys: []Key,
    participants_set: Set,
    stores: []mocks.MemorySecretStore,
    inits: []std.ArrayList(bool),
    /// Drop every DKG message on every participant.
    filtered_dkg: bool = false,
    /// Drop every consensus message this participant receives.
    deaf: ?usize = null,

    pub fn create(gpa: Allocator, total: u32) !DkgEngine {
        assert(total > 0);
        const signers = try gpa.alloc(ed25519.PrivateKey, total);
        errdefer gpa.free(signers);
        for (signers, 0..) |*signer, seed| signer.* = .from_seed(seed);
        std.mem.sort(ed25519.PrivateKey, signers, {}, by_public_key);
        const keys = try gpa.alloc(Key, total);
        errdefer gpa.free(keys);
        for (keys, signers) |*item, signer| item.* = signer.public_key();
        var participants_set = try Set.from_dedup(gpa, keys);
        errdefer participants_set.deinit(gpa);
        assert(participants_set.len() == total);
        const stores = try gpa.alloc(mocks.MemorySecretStore, total);
        errdefer gpa.free(stores);
        for (stores) |*store| store.* = .init(gpa);
        const inits = try gpa.alloc(std.ArrayList(bool), total);
        for (inits) |*list| list.* = .empty;
        return .{
            .gpa = gpa,
            .signers = signers,
            .keys = keys,
            .participants_set = participants_set,
            .stores = stores,
            .inits = inits,
        };
    }

    fn by_public_key(_: void, a: ed25519.PrivateKey, b: ed25519.PrivateKey) bool {
        return a.public_key().order(b.public_key()) == .lt;
    }

    pub fn deinit(self: *DkgEngine) void {
        for (self.inits) |*list| list.deinit(self.gpa);
        self.gpa.free(self.inits);
        for (self.stores) |*store| store.deinit();
        self.gpa.free(self.stores);
        self.participants_set.deinit(self.gpa);
        self.gpa.free(self.keys);
        self.gpa.free(self.signers);
        self.* = undefined;
    }

    /// Empties every secret store and init record, for the next seed.
    pub fn reset(self: *DkgEngine) void {
        for (self.stores) |*store| {
            store.deinit();
            store.* = .init(self.gpa);
        }
        for (self.inits) |*list| list.clearRetainingCapacity();
    }

    pub fn participant(self: *const DkgEngine, index: usize) Key {
        return self.keys[index];
    }

    /// Whether each incarnation of participant `index` started with its epoch-zero share.
    pub fn inits_of(self: *const DkgEngine, index: usize) []const bool {
        return self.inits[index].items;
    }

    pub fn participants(self: *const DkgEngine) []const Key {
        return self.keys;
    }

    pub fn channels(_: *const DkgEngine) []const simulate.ChannelSpec {
        const specs = comptime blk: {
            var list: [channel_count]simulate.ChannelSpec = undefined;
            for (&list, 0..) |*spec, index| spec.* = .{ .channel = index, .quota = test_quota };
            break :blk list;
        };
        return &specs;
    }

    pub fn max_message_size(self: *const DkgEngine) u32 {
        const count: u32 = @intCast(self.keys.len);
        const payload = bootstrap.max_payload_size(MinPk, Unit, count, mocks.max_supported_mode);
        return p2p.max_message_size(&.{payload});
    }

    fn filter(self: *const DkgEngine, index: usize, channel: usize) mocks.Filter {
        if (channel == dkg_channel) return if (self.filtered_dkg) .all else .none;
        const consensus_channel = channel < 3;
        return if (consensus_channel and self.deaf == index) .all else .none;
    }

    pub fn init(self: *const DkgEngine, ctx: simulate.InitContext(Key)) !struct {
        Started,
        NodeState,
    } {
        assert(ctx.channels.len == channel_count);
        const gpa = self.gpa;
        const index = ctx.index;
        const store = &self.stores[index];
        try self.inits[index].append(gpa, store.has_share(Epoch.zero()));
        var node_state = try self.state(index);
        errdefer deinit_state(&node_state);
        const inner = node_state.inner;
        const manager = try gpa.create(Types.Manager);
        manager.* = .init(ctx.oracle.manager());
        var wrapped: [channel_count]Bootstrap.Channel = undefined;
        for (&wrapped, ctx.channels, 0..) |*channel, registered, at| {
            const receiver: FilteredNetwork.Receiver = .{
                .inner = registered.receiver,
                .filter = self.filter(index, at),
            };
            channel.* = .{ .sender = registered.sender, .receiver = receiver };
        }
        const started: Started = .{
            .context = ctx.context,
            .config = self.config(ctx, manager, store),
            .manager = manager,
            .channels = .{
                .votes = wrapped[0],
                .certificates = wrapped[1],
                .resolver = wrapped[2],
                .backfill = wrapped[3],
                .broadcast = wrapped[4],
                .dkg = wrapped[5],
            },
            .inner = inner,
        };
        return .{ started, node_state };
    }

    /// A fresh incarnation's state for participant `index`: it shares the participant's
    /// secret store but none of an earlier incarnation's completion. Free with `deinit_state`.
    pub fn state(self: *const DkgEngine, index: usize) !NodeState {
        assert(index < self.stores.len);
        const inner = try self.gpa.create(Inner);
        inner.* = .{ .gpa = self.gpa, .store = &self.stores[index] };
        assert(!inner.completed);
        return .{ .inner = inner };
    }

    fn config(
        self: *const DkgEngine,
        ctx: simulate.InitContext(Key),
        manager: *Types.Manager,
        store: *mocks.MemorySecretStore,
    ) bootstrap.Config(Types) {
        const signer = self.signers[ctx.index];
        assert(signer.public_key().eql(ctx.public_key));
        return .{
            .signer = signer,
            .manager = manager,
            .peer_provider = ctx.oracle.manager(),
            .blocker = ctx.oracle.control(ctx.public_key),
            .secret_store = store,
            .namespace = namespace,
            .sharing_mode = .non_zero_counter,
            .reveal = .v1,
            .max_supported_mode = mocks.max_supported_mode,
            .partition_prefix = prefixes[ctx.index],
            .write_buffer = 2048,
            .replay_buffer = 2048,
            .mailbox_size = 100,
            .fetch_timeout = .from_secs(2),
            .fetch_retry_delay = .from_millis(100),
            .items_per_section = 10,
            .participants = self.participants_set,
            .directory = .{},
            .blocks_per_epoch = epoch_length,
        };
    }

    const prefixes = [_][]const u8{
        "dkg-0", "dkg-1", "dkg-2",  "dkg-3",  "dkg-4",  "dkg-5",  "dkg-6",  "dkg-7",
        "dkg-8", "dkg-9", "dkg-10", "dkg-11", "dkg-12", "dkg-13", "dkg-14", "dkg-15",
    };

    pub fn start(started: Started) !simulate.engine.Handle {
        return started.context.spawn(run_node, .{started});
    }

    pub fn deinit_state(node_state: *NodeState) void {
        const inner = node_state.inner;
        if (inner.info) |*info| info.deinit(inner.gpa);
        inner.gpa.destroy(inner);
        node_state.* = undefined;
    }
};

/// Runs a participant's engine, records its completion, and keeps it serving until the plan
/// stops the node (commonware `start`). An engine that stops on its own fails the run.
fn run_node(ctx: Context, started: Started) void {
    const gpa = started.inner.gpa;
    defer gpa.destroy(started.manager);
    var running = Bootstrap.start(ctx.child("dkg"), started.config, started.channels) catch |err|
        std.debug.panic("DKG engine failed to start: {t}", .{err});
    defer running.completion.deinit();
    var completion = running.completion.recv() catch |err| {
        stop(running.handle);
        if (err == error.Canceled) return;
        // A crash aborts this task's subtree: the engine can end, closing its completion,
        // before this task reaches a cancelation point.
        ctx.io().checkCancel() catch return;
        std.debug.panic("DKG engine stopped before completing: {t}", .{err});
    };
    started.inner.completed = true;
    started.inner.info = completion.info;
    completion.info = null;
    completion.deinit();
    const ended = running.handle.join();
    if (ended) |result| {
        result catch |err| std.debug.panic("DKG engine failed after completion: {t}", .{err});
        @panic("DKG engine stopped after completion");
    } else |_| {}
}

fn stop(handle: runtime.context.Handle(anyerror!void)) void {
    const ended = handle.abort();
    if (ended) |result| result catch {} else |_| {}
}

/// commonware `good_link`.
pub const good_link: p2p.simulated.Link = .{
    .latency = Duration.from_millis(20),
    .jitter = Duration.from_millis(5),
    .success_rate = 1.0,
};

pub const Plan = simulate.Plan(DkgEngine);

/// Runs `engine` on `link` with `crashes` once per seed in `seeds`, each from empty secret
/// stores, and checks the expected outcome (commonware `run_plan`).
pub fn run_plan(
    engine: *DkgEngine,
    link: p2p.simulated.Link,
    crashes: []const simulate.action.Crash(Key),
    comptime expected: properties.ExpectedOutcome,
    seeds: []const u64,
) !void {
    const Outcome = properties.DkgOutcome(NodeState, expected);
    const outcome: Outcome = .{ .participants = engine.participants_set };
    const exit_condition: simulate.exit.ProcessedHeightAtLeast = .{ .required = 1 };
    for (seeds) |seed| {
        engine.reset();
        const plan: Plan = .{
            .engine = engine,
            .seed = seed,
            .link = link,
            .crashes = crashes,
            .required_finalizations = 0,
            .exit_condition = .from(&exit_condition),
            .timeout = .from_secs(300),
            .properties = &.{.from(&outcome)},
        };
        var result = try plan.run(engine.gpa);
        result.deinit();
    }
}
