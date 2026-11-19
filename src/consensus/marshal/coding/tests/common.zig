//! Helpers shared by the coding actor tests (commonware `marshal/coding/mod.rs`, lines
//! 160-686): a recording coding buffer and resolver, `test_config`,
//! `start_coding_actor_with_recording`, `start_shard_mailbox`, and the block helpers
//! `genesis_block`, `genesis_coding_commitment`, `missing_candidate`, `undecodable`, and
//! `coding_chain`.
//!
//! Handles share state the way commonware's `Arc<Mutex<..>>` clones do: `clone` adds a
//! reference and `deinit` drops one. Locks are `Io.Mutex`, so the helpers stay deterministic
//! under the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor_api = @import("actor");
const broadcast = @import("broadcast");
const p2p = @import("p2p");
const parallel = @import("parallel");
const resolver_api = @import("resolver");
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const simplex_types = @import("../../../simplex/types.zig");
const store = @import("../../store.zig");
const core = @import("../../core/root.zig");
const variant = @import("../../core/variant.zig");
const handler = @import("../../resolver/handler.zig");
const shared_harness = @import("../../mocks/harness.zig");
const verifying = @import("../../mocks/verifying.zig");
const ancestry = @import("../../ancestry.zig");
const harness = @import("../harness.zig");
const coding_types = @import("../types.zig");
const marshaled = @import("../marshaled.zig");
const shards = @import("../shards/root.zig");

const oneshot = utils.channel.oneshot;
const Height = types.Height;
pub const Round = types.Round;
const View = types.View;

pub const H = harness.CodingHarness;
pub const CodingB = harness.CodingB;
pub const CodingCtx = harness.CodingCtx;
pub const Sha256 = harness.Sha256;
pub const D = shared_harness.D;
pub const K = shared_harness.K;
pub const S = harness.CodingScheme;
pub const Provider = harness.CodingProvider;
pub const Fixture = harness.CodingFixture;
pub const V = harness.CodingVariant;
pub const Commitment = harness.TestCommitment;
/// A coded block, as marshal hands blocks around (commonware `Arc<TestCodedBlock>`).
pub const Block = V.Block;
pub const Shard = coding_types.Shard(CodingB, harness.RS, Sha256);
pub const ResolverKey = handler.Key(Commitment);
pub const Annotation = handler.Annotation;
pub const Fetch = resolver_api.Fetch(ResolverKey, Annotation);
pub const Recipients = p2p.Recipients(K);
pub const Ctx = runtime.deterministic.Context;
pub const Outcome = resolver_api.Outcome;
pub const Notarization = H.Notarization;
pub const Proposal = simplex_types.Proposal(Commitment);
pub const App = @import("../../mocks/application.zig").Application(CodingB);
pub const ShardEngine = shards.Engine(harness.ShardTypes);
pub const ShardMailbox = ShardEngine.Mailbox;
pub const Marshal = core.Mailbox(S, V);
pub const Ancestry = ancestry.AncestorStream(Marshal);
pub const MockVerifyingApp = verifying.MockVerifyingApp(CodingB, Ctx, CodingCtx, Ancestry);

/// The wrapper over application `A` (commonware `Marshaled<_, _, A, ...>`).
pub fn MarshaledOf(comptime A: type) type {
    return marshaled.Marshaled(struct {
        pub const Context = Ctx;
        pub const Application = A;
        pub const Block = CodingB;
        pub const Coding = harness.RS;
        pub const Hasher = Sha256;
        pub const Provider = harness.CodingProvider;
        pub const Strategy = parallel.Sequential;
        pub const Epocher = types.FixedEpocher;
    });
}

/// commonware's `Runner::timed(30s)`.
pub const timed: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };

pub fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(std.testing.allocator, timed);
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

pub fn round_at(epoch: u64, view: u64) Round {
    return .new(.new(epoch), .new(view));
}

/// Locked state shared by every handle, freed with the last one.
fn Shared(comptime State: type) type {
    return struct {
        const Self = @This();
        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        references: u32 = 1,
        state: State = .{},

        fn create(gpa: Allocator, io: Io) Allocator.Error!*Self {
            const self = try gpa.create(Self);
            self.* = .{ .gpa = gpa, .io = io };
            return self;
        }

        fn lock(self: *Self) *State {
            self.mutex.lockUncancelable(self.io);
            return &self.state;
        }

        fn unlock(self: *Self) void {
            self.mutex.unlock(self.io);
        }

        fn retain(self: *Self) void {
            _ = self.lock();
            defer self.unlock();
            assert(self.references > 0);
            self.references += 1;
        }

        /// Drops a reference; true when it was the last (the caller frees the state).
        fn release(self: *Self) bool {
            _ = self.lock();
            defer self.unlock();
            assert(self.references > 0);
            self.references -= 1;
            return self.references == 0;
        }
    };
}

/// One recorded `send`: the round, the block, and the recipients (owned copies).
pub const BufferSend = struct { round: Round, block: Block, recipients: Recipients };

/// A coding buffer that serves inserted blocks and records subscriptions without resolving
/// them (commonware `RecordingCodingBuffer`).
pub const RecordingCodingBuffer = struct {
    pub const PublicKey = K;
    const Receiver = oneshot.Receiver(Block);
    const State = struct {
        blocks: std.ArrayList(Block) = .empty,
        evict_on_next_hit: bool = false,
        digest_subscriptions: std.ArrayList(oneshot.Sender(Block)) = .empty,
        commitment_subscriptions: std.ArrayList(oneshot.Sender(Block)) = .empty,
        sends: std.ArrayList(BufferSend) = .empty,
    };

    shared: *Shared(State),

    pub fn init(gpa: Allocator, io: Io) Allocator.Error!RecordingCodingBuffer {
        return .{ .shared = try .create(gpa, io) };
    }

    pub fn clone(self: RecordingCodingBuffer) RecordingCodingBuffer {
        self.shared.retain();
        return self;
    }

    pub fn deinit(self: *RecordingCodingBuffer) void {
        const shared = self.shared;
        self.* = undefined;
        if (!shared.release()) return;
        const gpa = shared.gpa;
        const state = &shared.state;
        for (state.blocks.items) |*block| block.deinit(gpa);
        for ([_]*std.ArrayList(oneshot.Sender(Block)){
            &state.digest_subscriptions,
            &state.commitment_subscriptions,
        }) |list| {
            for (list.items) |*sender| sender.deinit();
            list.deinit(gpa);
        }
        for (state.sends.items) |*item| {
            item.block.deinit(gpa);
            item.recipients.deinit(gpa);
        }
        state.blocks.deinit(gpa);
        state.sends.deinit(gpa);
        gpa.destroy(shared);
    }

    /// Serves `block` (owned) once: the next hit removes it (commonware `insert_transient`).
    pub fn insert_transient(self: RecordingCodingBuffer, block: Block) Allocator.Error!void {
        var owned = block;
        errdefer owned.deinit(self.shared.gpa);
        const state = self.shared.lock();
        defer self.shared.unlock();
        try state.blocks.append(self.shared.gpa, owned);
        state.evict_on_next_hit = true;
    }

    pub fn contains(self: RecordingCodingBuffer, commitment: Commitment) bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return position(state, commitment) != null;
    }

    fn position(state: *const State, commitment: Commitment) ?usize {
        for (state.blocks.items, 0..) |*block, index| {
            if (block.commitment().eql(commitment)) return index;
        }
        return null;
    }

    pub fn subscription_count(self: RecordingCodingBuffer) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.digest_subscriptions.items.len + state.commitment_subscriptions.items.len;
    }

    pub fn commitment_subscription_count(self: RecordingCodingBuffer) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.commitment_subscriptions.items.len;
    }

    pub fn send_count(self: RecordingCodingBuffer) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.sends.items.len;
    }

    /// The round and commitment of the recorded send at `index`.
    pub fn sent(self: RecordingCodingBuffer, index: usize) struct { Round, Commitment } {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const item = &state.sends.items[index];
        return .{ item.round, item.block.commitment() };
    }

    fn subscribe(self: RecordingCodingBuffer, commitment: bool) Allocator.Error!?Receiver {
        const gpa = self.shared.gpa;
        var pair = try oneshot.channel(Block, gpa, self.shared.io);
        const state = self.shared.lock();
        defer self.shared.unlock();
        const list = if (commitment)
            &state.commitment_subscriptions
        else
            &state.digest_subscriptions;
        list.append(gpa, pair.sender) catch |err| {
            pair.sender.deinit();
            pair.receiver.deinit();
            return err;
        };
        return pair.receiver;
    }

    pub fn find_by_digest(_: *RecordingCodingBuffer, _: D) error{}!?Block {
        return null;
    }

    pub fn find_by_commitment(
        self: *RecordingCodingBuffer,
        commitment: Commitment,
    ) error{}!?Block {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const index = position(state, commitment) orelse return null;
        if (state.evict_on_next_hit) {
            state.evict_on_next_hit = false;
            return state.blocks.orderedRemove(index);
        }
        return state.blocks.items[index].clone();
    }

    pub fn subscribe_by_digest(self: *RecordingCodingBuffer, _: D) Allocator.Error!?Receiver {
        return self.subscribe(false);
    }

    pub fn subscribe_by_commitment(
        self: *RecordingCodingBuffer,
        _: Commitment,
    ) Allocator.Error!?Receiver {
        return self.subscribe(true);
    }

    /// Records `block` (owned) and a copy of `recipients` (borrowed).
    pub fn send(
        self: *RecordingCodingBuffer,
        round: Round,
        block: Block,
        recipients: Recipients,
    ) Allocator.Error!void {
        const gpa = self.shared.gpa;
        var owned = block;
        errdefer owned.deinit(gpa);
        const copy = try clone_recipients(gpa, recipients);
        errdefer copy.deinit(gpa);
        const state = self.shared.lock();
        defer self.shared.unlock();
        try state.sends.append(gpa, .{ .round = round, .block = owned, .recipients = copy });
    }

    comptime {
        variant.assert_buffer(RecordingCodingBuffer);
    }
};

fn clone_recipients(gpa: Allocator, recipients: Recipients) Allocator.Error!Recipients {
    return switch (recipients) {
        .all => .all,
        .one => |peer| .{ .one = peer },
        .some => |peers| .{ .some = try gpa.dupe(K, peers) },
    };
}

/// A recorded `fetch_targeted` call: the key and its targets (owned).
pub const TargetedFetch = struct { key: ResolverKey, targets: []const K };

/// A resolver that records each fetch (commonware `RecordingResolver`). It holds the handler
/// that feeds the actor's resolver receiver, so the receiver stays open, and can answer the
/// next fetch through it.
pub const RecordingResolver = struct {
    pub const Subscriber = Annotation;
    pub const PublicKey = K;
    pub const Key = handler.Key(Commitment);
    const State = struct {
        fetches: std.ArrayList(Fetch) = .empty,
        targeted: std.ArrayList(TargetedFetch) = .empty,
        auto_delivery: ?[]u8 = null,
        delivery_responses: std.ArrayList(oneshot.Receiver(Outcome)) = .empty,
        handler: ?handler.Handler(Commitment) = null,
    };

    shared: *Shared(State),

    /// A resolver and the receiver its handler feeds (commonware `holding`).
    pub fn holding(
        gpa: Allocator,
        io: Io,
        scope: *const runtime.telemetry.metrics.Scope,
    ) Allocator.Error!struct {
        receiver: actor_api.mailbox.Receiver(handler.Message(Commitment)),
        resolver: RecordingResolver,
    } {
        const channel = try handler.init(Commitment, gpa, io, scope, 100);
        const shared = Shared(State).create(gpa, io) catch |err| {
            var owned = channel;
            owned.handler.deinit();
            owned.receiver.deinit();
            return err;
        };
        shared.state.handler = channel.handler;
        return .{ .receiver = channel.receiver, .resolver = .{ .shared = shared } };
    }

    pub fn clone(self: RecordingResolver) RecordingResolver {
        self.shared.retain();
        return self;
    }

    pub fn deinit(self: *RecordingResolver) void {
        const shared = self.shared;
        self.* = undefined;
        if (!shared.release()) return;
        const gpa = shared.gpa;
        const state = &shared.state;
        if (state.handler) |*value| value.deinit();
        if (state.auto_delivery) |bytes| gpa.free(bytes);
        for (state.delivery_responses.items) |*response| response.deinit();
        for (state.targeted.items) |item| gpa.free(item.targets);
        state.fetches.deinit(gpa);
        state.targeted.deinit(gpa);
        state.delivery_responses.deinit(gpa);
        gpa.destroy(shared);
    }

    /// Closes the handler, which ends an actor reading its receiver.
    pub fn close(self: RecordingResolver) void {
        const state = self.shared.lock();
        defer self.shared.unlock();
        if (state.handler) |*value| value.deinit();
        state.handler = null;
    }

    /// A handle on the handler, to send the actor resolver messages (commonware's `sender`).
    pub fn handler_clone(self: RecordingResolver) handler.Handler(Commitment) {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const value = state.handler orelse @panic("recording resolver sender missing");
        return value.clone();
    }

    fn record_fetch(self: RecordingResolver, item: Fetch) Allocator.Error!void {
        const gpa = self.shared.gpa;
        const state = self.shared.lock();
        defer self.shared.unlock();
        try state.fetches.append(gpa, item);
        const value = state.auto_delivery orelse return;
        const sender = state.handler orelse return;
        state.auto_delivery = null;
        defer gpa.free(value);
        try state.delivery_responses.ensureUnusedCapacity(gpa, 1);
        const subscribers = [_]Annotation{item.subscriber};
        const delivery: handler.Message(Commitment).Delivery = .{
            .key = item.key,
            .subscribers = &subscribers,
        };
        const response = try sender.deliver(delivery, value);
        state.delivery_responses.appendAssumeCapacity(response);
    }

    /// Answers the next fetch with a copy of `value` (borrowed).
    pub fn respond_to_next_fetch(self: RecordingResolver, value: []const u8) Allocator.Error!void {
        const copy = try self.shared.gpa.dupe(u8, value);
        const state = self.shared.lock();
        defer self.shared.unlock();
        if (state.auto_delivery != null) {
            @panic("recording resolver already has an automatic delivery");
        }
        state.auto_delivery = copy;
    }

    /// Delivers `value` (borrowed) for `item` and returns whether marshal accepted it.
    pub fn deliver(self: RecordingResolver, item: Fetch, value: []const u8) !bool {
        var sender = self.handler_clone();
        defer sender.deinit();
        const subscribers = [_]Annotation{item.subscriber};
        var response = try sender.deliver(.{ .key = item.key, .subscribers = &subscribers }, value);
        defer response.deinit();
        const outcome = response.recv() catch @panic("delivery response missing");
        return std.meta.eql(outcome, Outcome{ .resolved = .complete });
    }

    /// Whether marshal accepted the newest automatic delivery.
    pub fn wait_for_delivery_response(self: RecordingResolver) !bool {
        var response = blk: {
            const state = self.shared.lock();
            defer self.shared.unlock();
            break :blk state.delivery_responses.pop() orelse @panic("delivery response missing");
        };
        defer response.deinit();
        const outcome = response.recv() catch @panic("delivery response sender dropped");
        return std.meta.eql(outcome, Outcome{ .resolved = .complete });
    }

    /// Copies of the recorded fetches; the caller frees the slice.
    pub fn fetches(self: RecordingResolver, gpa: Allocator) Allocator.Error![]Fetch {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return gpa.dupe(Fetch, state.fetches.items);
    }

    pub fn fetch_count(self: RecordingResolver) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.fetches.items.len;
    }

    /// Whether some recorded fetch asked for `key` on behalf of `subscriber`.
    pub fn fetched(self: RecordingResolver, key: ResolverKey, subscriber: Annotation) bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        for (state.fetches.items) |item| {
            if (item.key.eql(key) and item.subscriber.eql(subscriber)) return true;
        }
        return false;
    }

    pub fn targeted_is_empty(self: RecordingResolver) bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.targeted.items.len == 0;
    }

    /// The keys of the targeted fetches; the caller frees the slice.
    pub fn targeted_keys(self: RecordingResolver, gpa: Allocator) Allocator.Error![]ResolverKey {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const out = try gpa.alloc(ResolverKey, state.targeted.items.len);
        for (state.targeted.items, out) |item, *key| key.* = item.key;
        return out;
    }

    pub fn fetch(self: *RecordingResolver, item: Fetch) Allocator.Error!resolver_api.Feedback {
        try self.record_fetch(item);
        return .ok;
    }

    pub fn fetch_all(
        self: *RecordingResolver,
        items: []const Fetch,
    ) Allocator.Error!resolver_api.Feedback {
        for (items) |item| try self.record_fetch(item);
        return .ok;
    }

    pub fn retain(
        _: *RecordingResolver,
        _: resolver_api.Predicate(ResolverKey, Annotation),
    ) Allocator.Error!resolver_api.Feedback {
        return .ok;
    }

    pub fn fetch_targeted(
        self: *RecordingResolver,
        item: Fetch,
        targets: []const K,
    ) Allocator.Error!resolver_api.Feedback {
        assert(targets.len > 0);
        const gpa = self.shared.gpa;
        const copy = try gpa.dupe(K, targets);
        errdefer gpa.free(copy);
        const state = self.shared.lock();
        defer self.shared.unlock();
        try state.targeted.append(gpa, .{ .key = item.key, .targets = copy });
        return .ok;
    }

    pub fn fetch_all_targeted(
        self: *RecordingResolver,
        items: []const resolver_api.Targeted(ResolverKey, Annotation, K),
    ) Allocator.Error!resolver_api.Feedback {
        for (items) |item| _ = try self.fetch_targeted(item.fetch, item.targets);
        return .ok;
    }

    comptime {
        resolver_api.assert_targeted_resolver(RecordingResolver);
    }
};

/// The finalized-block store over the immutable block archive.
pub const ImmutableBlocks = store.Blocks(harness.Archives.BlockArchive, V.StoredBlock);

/// The coding actor of the direct tests, with application `A`.
pub fn Actor(comptime A: type) type {
    return ActorOver(A, ImmutableBlocks);
}

/// `Actor` over the finalized-block store `FinalizedBlocks`.
pub fn ActorOver(comptime A: type, comptime FinalizedBlocks: type) type {
    const Stores = harness.Archives;
    return core.Actor(struct {
        pub const Scheme = S;
        pub const Provider = harness.CodingProvider;
        pub const Epocher = types.FixedEpocher;
        pub const Strategy = parallel.Sequential;
        pub const ApplicationBlock = CodingB;
        pub const Block = V.Block;
        pub const Commitment = harness.TestCommitment;
        pub const Variant = V;
        pub const Acknowledgement = shared_harness.Exact;
        pub const Certificates = store.Certificates(
            Stores.FinalizationArchive,
            S,
            D,
            harness.TestCommitment,
        );
        pub const Blocks = FinalizedBlocks;
        pub const Application = A;
        pub const Buffer = RecordingCodingBuffer;
        pub const Resolver = RecordingResolver;
    });
}

/// commonware `test_config`: the actor configuration the direct tests share, starting at
/// genesis (owned by the config). `page_cache` must outlive the actor.
pub fn test_config(
    comptime A: type,
    gpa: Allocator,
    prefix: []const u8,
    provider: Provider,
    page_cache: *runtime.buffer.paged.CacheRef,
) !A.Config {
    const genesis = try H.genesis_block(gpa, shared_harness.num_validators);
    return .{
        .provider = provider,
        .epocher = .new(utils.NonZero(u64).init(shared_harness.blocks_per_epoch).?),
        .start = .{ .genesis = genesis },
        .partition_prefix = prefix,
        .mailbox_size = 100,
        .view_retention = .new(10),
        .prunable_items_per_section = 10,
        .page_cache = page_cache,
        .replay_buffer = 1024,
        .key_write_buffer = 1024,
        .value_write_buffer = 1024,
        .block_codec_config = {},
        .max_repair = 10,
        .max_pending_acks = 1,
        .strategy = parallel.sequential,
    };
}

/// A running actor from `start_coding_actor_with_recording` with the archives it borrows
/// (commonware's returned `(mailbox, resolver, handle)`).
pub const ActorStack = struct {
    const A = Actor(App);

    gpa: Allocator,
    stores: *harness.Archives,
    prefix: []u8,
    mailbox: Marshal,
    resolver: RecordingResolver,
    handle: runtime.context.Handle(anyerror!void),

    /// Aborts the actor and releases its storage.
    pub fn stop(self: *ActorStack) void {
        const ended = self.handle.abort() catch {};
        ended catch {};
        self.mailbox.deinit();
        self.resolver.deinit();
        self.stores.deinit();
        self.gpa.destroy(self.stores);
        self.gpa.free(self.prefix);
        self.* = undefined;
    }
};

/// commonware `start_coding_actor_with_recording`: opens the immutable archives under
/// `prefix` and starts an actor at genesis with the default application, the recording
/// resolver, and a clone of `buffer` (borrowed).
pub fn start_coding_actor_with_recording(
    ctx: Ctx,
    prefix: []const u8,
    provider: Provider,
    buffer: RecordingCodingBuffer,
) !ActorStack {
    const A = ActorStack.A;
    const gpa = ctx.gpa();
    const owned_prefix = try gpa.dupe(u8, prefix);
    errdefer gpa.free(owned_prefix);
    const stores = try gpa.create(harness.Archives);
    errdefer gpa.destroy(stores);
    try stores.open(ctx, owned_prefix);
    errdefer stores.deinit();
    const config = try test_config(A, gpa, owned_prefix, provider, &stores.cache_ref);
    const initialized = try A.init(
        ctx.child("actor"),
        .{ .archive = &stores.finalizations },
        .{ .archive = &stores.blocks },
        config,
    );
    var holding = try RecordingResolver.holding(gpa, ctx.io(), &ctx.scope.child("resolver"));
    errdefer holding.resolver.deinit();
    var app = try App.init(gpa, ctx.io());
    errdefer app.deinit();
    const handle = try initialized.actor.start(
        app,
        buffer.clone(),
        holding.receiver,
        holding.resolver.clone(),
    );
    return .{
        .gpa = gpa,
        .stores = stores,
        .prefix = owned_prefix,
        .mailbox = initialized.mailbox,
        .resolver = holding.resolver,
        .handle = handle,
    };
}

/// A shards engine on a simulated network of `participants`, as participant 0 (commonware
/// `start_shard_mailbox`).
pub const ShardStack = struct {
    network: shared_harness.TestNetwork,
    mailbox: ShardMailbox,
    future: Io.Future(ShardEngine.Error!void),

    /// A clone of the engine's mailbox (the wrapper takes ownership of one).
    pub fn shards(self: *const ShardStack) ShardMailbox {
        return self.mailbox.clone();
    }

    pub fn stop(self: *ShardStack) void {
        const io = self.network.io;
        self.mailbox.deinit();
        _ = self.future.cancel(io) catch {};
        self.network.stop();
        self.* = undefined;
    }
};

/// Starts a shard stack in place (it must not move: the engine borrows its network).
pub fn start_shard_mailbox(
    self: *ShardStack,
    ctx: Ctx,
    participants: []const K,
    provider: Provider,
) !void {
    const gpa = ctx.gpa();
    const me = participants[0];
    self.network = try .start(gpa, ctx.io(), 1, participants, 1024 * 1024);
    errdefer self.network.stop();
    const oracle = self.network.network.oracle();
    const control = oracle.control(me);
    const scope = ctx.scope.child("shards");
    const created = try ShardEngine.init(gpa, ctx.io(), &scope, .{
        .scheme_provider = provider,
        .blocker = control,
        .block_codec_config = {},
        .strategy = parallel.sequential,
        .mailbox_size = 10,
        .peer_buffer_size = 64,
        .records = harness.records,
        .peer_provider = oracle.manager(),
    });
    self.mailbox = created.mailbox;
    errdefer self.mailbox.deinit();
    const channel = try control.register(0, shared_harness.test_quota);
    self.future = try created.engine.start(channel.sender, channel.receiver);
}

/// commonware's `MarshaledConfig` for the direct tests, over `marshal` and `shards` (owned).
pub fn marshaled_config(
    comptime M: type,
    application: M.Application,
    marshal: Marshal,
    shard_mailbox: ShardMailbox,
    provider: Provider,
) M.Config {
    return .{
        .application = application,
        .marshal = marshal,
        .shards = shard_mailbox,
        .scheme_provider = provider,
        .strategy = parallel.sequential,
        .epocher = .new(utils.NonZero(u64).init(shared_harness.blocks_per_epoch).?),
    };
}

/// The genesis application block (commonware `genesis_block`).
pub fn genesis_block(gpa: Allocator) !CodingB {
    return harness.make_coding_genesis_block(gpa);
}

/// Genesis's trusted commitment (commonware `genesis_coding_commitment`).
pub fn genesis_coding_commitment(gpa: Allocator, block: *const CodingB) !Commitment {
    const context_digest = try coding_types.hash_context(Sha256, gpa, block.context());
    const config = harness.genesis_coding_config;
    return .init(block.digest(), block.digest(), context_digest, config);
}

/// `block` (owned) coded under `config` (commonware `encode_block`).
pub fn encode_block(gpa: Allocator, block: CodingB, config: @import("coding").Config) !Block {
    const digested = try broadcast.Digested(CodingB).compute(gpa, block);
    return Block.encode(gpa, digested, config, parallel.sequential);
}

pub fn committee_config() @import("coding").Config {
    return coding_types.coding_config_for_participants(shared_harness.num_validators);
}

/// A candidate at height 1 proposed by `me` in view 1 over genesis, which no buffer holds
/// (commonware `missing_candidate`).
pub fn missing_candidate(gpa: Allocator, me: K) !struct { context: CodingCtx, block: Block } {
    const genesis = try genesis_block(gpa);
    const context: CodingCtx = .{
        .round = round_at(0, 1),
        .leader = me,
        .parent = .{ .zero(), try genesis_coding_commitment(gpa, &genesis) },
    };
    const candidate = try harness.make_coding_block(gpa, context, genesis.digest(), .new(1), 100);
    const block = try encode_block(gpa, candidate, committee_config());
    assert(block.height().get() == 1);
    return .{ .context = context, .block = block };
}

/// The shards of `missing_candidate` rebound to a commitment that claims another digest: the
/// shards verify against the commitment's coding root, but the decoded block fails
/// validation (commonware `undecodable`). The caller frees the shards.
pub fn undecodable(
    gpa: Allocator,
    me: K,
) !struct { commitment: Commitment, shards: [shared_harness.num_validators]Shard } {
    var candidate = try missing_candidate(gpa, me);
    defer candidate.block.deinit(gpa);
    const real = candidate.block.commitment();
    const commitment: Commitment =
        .init(Sha256.hash(&.{"undecodable"}), real.root(), real.context(), real.config());
    var out: [shared_harness.num_validators]Shard = undefined;
    var made: usize = 0;
    errdefer for (out[0..made]) |*shard| shard.deinit(gpa);
    for (&out, 0..) |*shard, index| {
        shard.* = (try candidate.block.shard(gpa, @intCast(index))) orelse
            return error.MissingShard;
        shard.commitment_value = commitment;
        made += 1;
    }
    return .{ .commitment = commitment, .shards = out };
}

/// One block of `coding_chain`.
pub const ChainLink = struct { round: Round, block: Block };

/// `out.len` coded blocks above genesis, each proposed by `leader` at the view matching its
/// height and naming the block below it as its parent (commonware `coding_chain`). The caller
/// frees the blocks.
pub fn coding_chain(gpa: Allocator, leader: K, out: []ChainLink) !void {
    const genesis = try genesis_block(gpa);
    var parent_view: View = .zero();
    var parent_commitment = try genesis_coding_commitment(gpa, &genesis);
    var parent_digest = genesis.digest();
    var made: usize = 0;
    errdefer for (out[0..made]) |*link| link.block.deinit(gpa);
    for (out, 1..) |*link, height| {
        const round = round_at(0, height);
        const context: CodingCtx = .{
            .round = round,
            .leader = leader,
            .parent = .{ parent_view, parent_commitment },
        };
        const timestamp = height * 100;
        const at: Height = .new(height);
        const raw = try harness.make_coding_block(gpa, context, parent_digest, at, timestamp);
        const block = try encode_block(gpa, raw, committee_config());
        parent_view = round.view;
        parent_commitment = block.commitment();
        parent_digest = block.digest();
        link.* = .{ .round = round, .block = block };
        made += 1;
    }
}

/// `(notarization, block).encode()`: the value of a notarized delivery. The caller frees it.
pub fn encode_notarized(
    gpa: Allocator,
    notarization: *const Notarization,
    block: *const Block,
) ![]u8 {
    const codec = @import("codec");
    const size = notarization.encode_size() + block.encode_size();
    const bytes = try gpa.alloc(u8, size);
    errdefer gpa.free(bytes);
    var writer: codec.Writer = .init(bytes);
    notarization.write(&writer);
    block.write(&writer);
    assert(writer.written().len == size);
    return bytes;
}

/// One validator from `CodingHarness::setup_validator` on its own simulated network, wrapped
/// by `Marshaled` over its marshal and shard mailboxes. Must not move.
pub const ValidatorStack = struct {
    pub const Validator = H.Validator(App);
    pub const M = MarshaledOf(MockVerifyingApp);

    network: shared_harness.TestNetwork,
    validator: *Validator,
    /// The validator's identity (participant 0).
    validator_key: K,
    marshaled: M,

    /// Starts participant 0 of `validators` with the default application.
    pub fn start(self: *ValidatorStack, ctx: Ctx, validators: *const Fixture) !void {
        return self.start_with(ctx, validators, MockVerifyingApp.init(ctx.gpa()));
    }

    /// Starts participant 0 of `validators`, wrapping `application` (owned).
    pub fn start_with(
        self: *ValidatorStack,
        ctx: Ctx,
        validators: *const Fixture,
        application: MockVerifyingApp,
    ) !void {
        const gpa = ctx.gpa();
        const participants = validators.participants;
        self.network = try .start(gpa, ctx.io(), 1, participants, 1024 * 1024);
        errdefer self.network.stop();
        const provider: Provider = .init(&validators.schemes[0]);
        var app = try App.init(gpa, ctx.io());
        errdefer app.deinit();
        const node_ctx = ctx.child("validator").with_attribute("index", 0);
        const network = self.network.network;
        self.validator_key = participants[0];
        self.validator = try Validator.setup(node_ctx, network, participants[0], provider, 1, app);
        errdefer self.validator.crash();
        const marshal = self.validator.mailbox.clone();
        const shard_mailbox = self.validator.extra.clone();
        const config = marshaled_config(M, application, marshal, shard_mailbox, provider);
        self.marshaled = try .init(ctx.child("marshaled"), config);
    }

    /// The validator's shards engine mailbox (borrowed).
    pub fn shards(self: *const ValidatorStack) *const ShardMailbox {
        return &self.validator.extra;
    }

    pub fn stop(self: *ValidatorStack) void {
        self.marshaled.deinit();
        self.validator.crash();
        self.network.stop();
        self.* = undefined;
    }
};

/// The block `context` names over `parent` at `height`, coded for the committee.
pub fn coded(gpa: Allocator, context: CodingCtx, parent: D, height: u64, timestamp: u64) !Block {
    const raw = try harness.make_coding_block(gpa, context, parent, .new(height), timestamp);
    return encode_block(gpa, raw, committee_config());
}

/// `block.encode()`: a coded block's wire bytes (it writes but is not decodable as written).
/// The caller frees them.
pub fn encode_coded(gpa: Allocator, block: *const Block) ![]u8 {
    const codec = @import("codec");
    const size = block.encode_size();
    const bytes = try gpa.alloc(u8, size);
    errdefer gpa.free(bytes);
    var writer: codec.Writer = .init(bytes);
    block.write(&writer);
    assert(writer.written().len == size);
    return bytes;
}
