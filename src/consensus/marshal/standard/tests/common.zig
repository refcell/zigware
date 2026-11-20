//! Helpers shared by the standard actor tests (commonware `marshal/standard/mod.rs`, lines
//! 6221-6739 and 10362-10611): a recording buffer and resolver, a no-op consumer, a static
//! producer, `wait_until`, two reporters, `start_standard_actor`, paced and prunable stores,
//! and `test_config`.
//!
//! Handles share state the way commonware's `Arc<Mutex<..>>` clones do: `clone` adds a
//! reference and `deinit` drops one. Locks are `Io.Mutex`, so the helpers stay deterministic
//! under the deterministic runtime. commonware's `CloneCounter` (a mock context counting
//! implicit `Clone`s) has no counterpart: Zig clones only where the code says so.

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
const storage = @import("storage");
const utils = @import("utils");
const types = @import("../../../types.zig");
const config_api = @import("../../config.zig");
const store = @import("../../store.zig");
const update = @import("../../update.zig");
const core = @import("../../core/root.zig");
const variant = @import("../../core/variant.zig");
const handler = @import("../../resolver/handler.zig");
const harness = @import("../../mocks/harness.zig");

const oneshot = utils.channel.oneshot;
const Height = types.Height;
const Round = types.Round;

pub const B = harness.B;
pub const D = harness.D;
pub const K = harness.K;
pub const S = harness.S;
pub const Exact = harness.Exact;
pub const Finalization = harness.Finalization;
pub const V = harness.StandardHarness.Variant;
/// A block with its digest, as marshal hands blocks around (commonware `Digested<B>`).
pub const Block = V.Block;
pub const Update = update.Update(B, Exact);
pub const Key = handler.Key(D);
pub const Annotation = handler.Annotation;
pub const Fetch = resolver_api.Fetch(Key, Annotation);
pub const Recipients = p2p.Recipients(K);
pub const Start = config_api.Start(S, D, Block);
pub const Ctx = runtime.deterministic.Context;
pub const Outcome = resolver_api.Outcome;

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

/// A buffer that records each `send`, holds subscriptions until a test delivers or closes
/// them, and serves locally inserted blocks (commonware `RecordingBuffer`).
pub const RecordingBuffer = struct {
    pub const PublicKey = K;
    const Receiver = oneshot.Receiver(Block);
    const Subscription = ?oneshot.Sender(Block);
    const State = struct {
        blocks: std.ArrayList(Block) = .empty,
        /// A clone of the last block `find` handed out; only this handle remains once marshal
        /// dropped it (commonware's `Weak`).
        last_handed: ?Block = null,
        evict_on_next_hit: bool = false,
        /// Whether each hit hands out a new object, as commonware's buffer hands a new `Arc`
        /// per hit, kept in `handed` (each a `Weak` once only that handle remains).
        fresh: bool = false,
        handed: std.ArrayList(Block) = .empty,
        digest_subscriptions: std.ArrayList(Subscription) = .empty,
        commitment_subscriptions: std.ArrayList(Subscription) = .empty,
        sends: std.ArrayList(BufferSend) = .empty,
    };

    shared: *Shared(State),

    pub fn init(gpa: Allocator, io: Io) Allocator.Error!RecordingBuffer {
        return .{ .shared = try .create(gpa, io) };
    }

    pub fn clone(self: RecordingBuffer) RecordingBuffer {
        self.shared.retain();
        return self;
    }

    pub fn deinit(self: *RecordingBuffer) void {
        const shared = self.shared;
        self.* = undefined;
        if (!shared.release()) return;
        const gpa = shared.gpa;
        const state = &shared.state;
        for (state.blocks.items) |*block| block.deinit();
        if (state.last_handed) |*block| block.deinit();
        for (state.handed.items) |*block| block.deinit();
        state.handed.deinit(gpa);
        for ([_]*std.ArrayList(Subscription){
            &state.digest_subscriptions,
            &state.commitment_subscriptions,
        }) |list| {
            for (list.items) |*slot| if (slot.*) |*sender| sender.deinit();
            list.deinit(gpa);
        }
        for (state.sends.items) |*sent| {
            sent.block.deinit();
            sent.recipients.deinit(gpa);
        }
        state.blocks.deinit(gpa);
        state.sends.deinit(gpa);
        gpa.destroy(shared);
    }

    /// Serves `block` (owned) from now on.
    pub fn insert(self: RecordingBuffer, block: Block) Allocator.Error!void {
        var owned = block;
        errdefer owned.deinit();
        const state = self.shared.lock();
        defer self.shared.unlock();
        try state.blocks.append(self.shared.gpa, owned);
    }

    /// Serves `block` (owned) once: the next hit removes it.
    pub fn insert_transient(self: RecordingBuffer, block: Block) Allocator.Error!void {
        try self.insert(block);
        const state = self.shared.lock();
        defer self.shared.unlock();
        state.evict_on_next_hit = true;
    }

    pub fn contains(self: RecordingBuffer, digest: D) bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return position(state, digest) != null;
    }

    fn position(state: *const State, digest: D) ?usize {
        for (state.blocks.items, 0..) |block, index| {
            if (block.digest().eql(digest)) return index;
        }
        return null;
    }

    fn find(self: RecordingBuffer, digest: D) ?Block {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const index = position(state, digest) orelse return null;
        if (state.fresh) return hand_fresh(self.shared.gpa, state, index);
        const block = if (state.evict_on_next_hit) blk: {
            state.evict_on_next_hit = false;
            break :blk state.blocks.orderedRemove(index);
        } else state.blocks.items[index].clone();
        if (state.last_handed) |*previous| previous.deinit();
        state.last_handed = block.clone();
        assert(block.digest().eql(digest));
        return block;
    }

    /// Hands a new object for the block at `index`, recording a handle in `handed`. A test
    /// mock: allocation failure panics, since `find` cannot fail.
    fn hand_fresh(gpa: Allocator, state: *State, index: usize) Block {
        const source = state.blocks.items[index];
        state.handed.ensureUnusedCapacity(gpa, 1) catch @panic("OOM");
        const block = Block.precomputed(gpa, source.inner().*, source.digest()) catch
            @panic("OOM");
        state.handed.appendAssumeCapacity(block.clone());
        return block;
    }

    /// From now on, each hit hands out a new object, tracked by `handed_released` and
    /// `handed_same`.
    pub fn hand_fresh_copies(self: RecordingBuffer) void {
        const state = self.shared.lock();
        defer self.shared.unlock();
        state.fresh = true;
    }

    /// How many objects hits handed out since `hand_fresh_copies`.
    pub fn handed_count(self: RecordingBuffer) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.handed.items.len;
    }

    /// Whether marshal released the `index`th handed object (commonware
    /// `handed.upgrade().is_none()`).
    pub fn handed_released(self: RecordingBuffer, index: usize) bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.handed.items[index].shared.references.load(.acquire) == 1;
    }

    /// Whether `block` is the `index`th handed object (commonware `Arc::ptr_eq`).
    pub fn handed_same(self: RecordingBuffer, index: usize, block: Block) bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.handed.items[index].shared == block.shared;
    }

    /// Whether marshal released the last block `find` handed it (commonware's
    /// `last_handed().upgrade().is_none()`); null before any hit.
    pub fn last_handed_released(self: RecordingBuffer) ?bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const block = state.last_handed orelse return null;
        return block.shared.references.load(.acquire) == 1;
    }

    /// The recorded sends, as clones the caller frees with `free_sends`.
    pub fn sends(self: RecordingBuffer, gpa: Allocator) Allocator.Error![]BufferSend {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const out = try gpa.alloc(BufferSend, state.sends.items.len);
        var made: usize = 0;
        errdefer free_sends(gpa, out[0..made]);
        for (state.sends.items, out) |sent, *copy| {
            copy.* = .{
                .round = sent.round,
                .block = sent.block.clone(),
                .recipients = try clone_recipients(gpa, sent.recipients),
            };
            made += 1;
        }
        return out;
    }

    pub fn free_sends(gpa: Allocator, sent: []BufferSend) void {
        for (sent) |*item| {
            item.block.deinit();
            item.recipients.deinit(gpa);
        }
        gpa.free(sent);
    }

    pub fn send_count(self: RecordingBuffer) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.sends.items.len;
    }

    pub fn subscription_count(self: RecordingBuffer) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.digest_subscriptions.items.len + state.commitment_subscriptions.items.len;
    }

    pub fn commitment_subscription_count(self: RecordingBuffer) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.commitment_subscriptions.items.len;
    }

    /// Whether the commitment subscription at `index` was closed or already answered.
    pub fn commitment_subscription_closed(self: RecordingBuffer, index: usize) bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const slot = state.commitment_subscriptions.items[index];
        const sender = slot orelse return true;
        return sender.is_closed();
    }

    /// Closes the commitment subscription at `index` without delivering a block. The slot
    /// stays, so indices stay stable.
    pub fn close_commitment_subscription(self: RecordingBuffer, index: usize) void {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const slot = &state.commitment_subscriptions.items[index];
        if (slot.*) |*sender| sender.deinit();
        slot.* = null;
    }

    /// Sends `block` (owned) to the commitment subscription at `index` and reports whether its
    /// receiver was still open. The slot stays, so indices stay stable.
    pub fn deliver_commitment_subscription(self: RecordingBuffer, index: usize, block: Block) bool {
        var owned = block;
        const state = self.shared.lock();
        defer self.shared.unlock();
        const slot = &state.commitment_subscriptions.items[index];
        var sender = slot.* orelse {
            owned.deinit();
            return false;
        };
        slot.* = null;
        sender.send(owned) catch {
            owned.deinit();
            return false;
        };
        return true;
    }

    fn subscribe(self: RecordingBuffer, commitment: bool) Allocator.Error!?Receiver {
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

    pub fn find_by_digest(self: *RecordingBuffer, digest: D) error{}!?Block {
        return self.find(digest);
    }

    pub fn find_by_commitment(self: *RecordingBuffer, commitment: D) error{}!?Block {
        return self.find(commitment);
    }

    pub fn subscribe_by_digest(self: *RecordingBuffer, _: D) Allocator.Error!?Receiver {
        return self.subscribe(false);
    }

    pub fn subscribe_by_commitment(self: *RecordingBuffer, _: D) Allocator.Error!?Receiver {
        return self.subscribe(true);
    }

    /// Records `block` (owned) and a copy of `recipients` (borrowed).
    pub fn send(
        self: *RecordingBuffer,
        round: Round,
        block: Block,
        recipients: Recipients,
    ) Allocator.Error!void {
        var owned = block;
        errdefer owned.deinit();
        const gpa = self.shared.gpa;
        const copy = try clone_recipients(gpa, recipients);
        errdefer copy.deinit(gpa);
        const state = self.shared.lock();
        defer self.shared.unlock();
        try state.sends.append(gpa, .{ .round = round, .block = owned, .recipients = copy });
    }

    comptime {
        variant.assert_buffer(RecordingBuffer);
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
pub const TargetedFetch = struct { key: Key, targets: []const K };

/// A resolver that records each fetch (commonware `RecordingResolver`). It holds the handler
/// that feeds the actor's resolver receiver, so the receiver stays open, and can answer the
/// next fetch through it.
pub const RecordingResolver = struct {
    pub const Subscriber = Annotation;
    pub const PublicKey = K;
    pub const Key = handler.Key(D);
    const State = struct {
        fetches: std.ArrayList(Fetch) = .empty,
        active_fetches: std.ArrayList(Fetch) = .empty,
        targeted: std.ArrayList(TargetedFetch) = .empty,
        retains: u64 = 0,
        auto_delivery: ?[]u8 = null,
        delivery_responses: std.ArrayList(oneshot.Receiver(Outcome)) = .empty,
        handler: ?handler.Handler(D) = null,
    };

    shared: *Shared(State),

    /// A resolver and the receiver its handler feeds (commonware `holding`).
    pub fn holding(
        gpa: Allocator,
        io: Io,
        scope: *const runtime.telemetry.metrics.Scope,
    ) Allocator.Error!struct {
        receiver: actor_api.mailbox.Receiver(handler.Message(D)),
        resolver: RecordingResolver,
    } {
        const channel = try handler.init(D, gpa, io, scope, 100);
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
        state.active_fetches.deinit(gpa);
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

    /// A handle on the handler, to send the actor resolver messages (commonware `enqueue`).
    pub fn handler_clone(self: RecordingResolver) handler.Handler(D) {
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
        try state.active_fetches.append(gpa, item);
        const value = state.auto_delivery orelse return;
        const sender = state.handler orelse return;
        state.auto_delivery = null;
        defer gpa.free(value);
        try state.delivery_responses.ensureUnusedCapacity(gpa, 1);
        const subscribers = [_]Annotation{item.subscriber};
        const delivery: handler.Message(D).Delivery = .{
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

    /// The fetches no `retain` has dropped; the caller frees the slice.
    pub fn active_fetches(self: RecordingResolver, gpa: Allocator) Allocator.Error![]Fetch {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return gpa.dupe(Fetch, state.active_fetches.items);
    }

    /// Whether some recorded fetch asked for `key`.
    pub fn fetched(self: RecordingResolver, key: handler.Key(D)) bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        for (state.fetches.items) |item| if (item.key.eql(key)) return true;
        return false;
    }

    pub fn fetch_count(self: RecordingResolver) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.fetches.items.len;
    }

    /// The keys of the targeted fetches; the caller frees the slice.
    pub fn targeted_keys(self: RecordingResolver, gpa: Allocator) Allocator.Error![]handler.Key(D) {
        const state = self.shared.lock();
        defer self.shared.unlock();
        const out = try gpa.alloc(handler.Key(D), state.targeted.items.len);
        for (state.targeted.items, out) |item, *key| key.* = item.key;
        return out;
    }

    /// The targets of the targeted fetch at `index` (borrowed until `deinit`).
    pub fn targeted_targets(self: RecordingResolver, index: usize) []const K {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.targeted.items[index].targets;
    }

    pub fn targeted_is_empty(self: RecordingResolver) bool {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.targeted.items.len == 0;
    }

    pub fn retain_count(self: RecordingResolver) u64 {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.retains;
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
        self: *RecordingResolver,
        predicate: resolver_api.Predicate(handler.Key(D), Annotation),
    ) Allocator.Error!resolver_api.Feedback {
        const state = self.shared.lock();
        defer self.shared.unlock();
        var kept: usize = 0;
        for (state.active_fetches.items) |item| {
            if (!predicate.call(item.key, item.subscriber)) continue;
            state.active_fetches.items[kept] = item;
            kept += 1;
        }
        state.active_fetches.shrinkRetainingCapacity(kept);
        state.retains += 1;
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
        items: []const resolver_api.Targeted(handler.Key(D), Annotation, K),
    ) Allocator.Error!resolver_api.Feedback {
        for (items) |item| _ = try self.fetch_targeted(item.fetch, item.targets);
        return .ok;
    }

    comptime {
        resolver_api.assert_targeted_resolver(RecordingResolver);
    }
};

/// A consumer that refuses every delivery (commonware `NoopConsumer`).
pub const NoopConsumer = struct {
    pub const Key = handler.Key(D);
    pub const Value = []const u8;
    pub const Subscriber = Annotation;
    pub const Outcome = bool;

    gpa: Allocator,
    io: Io,

    pub fn deliver(
        self: NoopConsumer,
        delivery: resolver_api.Delivery(handler.Key(D), Annotation),
        value: []const u8,
    ) Allocator.Error!oneshot.Receiver(bool) {
        _ = .{ delivery, value };
        var pair = try oneshot.channel(bool, self.gpa, self.io);
        pair.sender.send(false) catch unreachable; // Proof: the receiver is open.
        assert(pair.receiver.is_ready());
        return pair.receiver;
    }

    comptime {
        resolver_api.assert_consumer(NoopConsumer);
    }
};

/// A producer that serves `value` for `key` only (commonware `StaticProducer`).
pub const StaticProducer = struct {
    pub const Key = handler.Key(D);
    const Produced = resolver_api.p2p.Produced;

    gpa: Allocator,
    io: Io,
    key: handler.Key(D),
    /// Borrowed; outlives the producer.
    value: []const u8,

    pub fn produce(
        self: StaticProducer,
        key: handler.Key(D),
    ) Allocator.Error!oneshot.Receiver(Produced) {
        var pair = try oneshot.channel(Produced, self.gpa, self.io);
        if (!key.eql(self.key)) {
            pair.sender.deinit();
            return pair.receiver;
        }
        pair.sender.send(.{ .bytes = self.value }) catch unreachable; // Proof: receiver open.
        assert(pair.receiver.is_ready());
        return pair.receiver;
    }

    comptime {
        resolver_api.p2p.assert_producer(StaticProducer);
    }
};

/// Polls `cond(context)` on a 10 ms tick until it holds; fails once `deadline_ms` passes
/// (commonware panics with "`label` did not hold within `deadline`").
pub fn wait_until(
    ctx: Ctx,
    deadline_ms: u64,
    label: []const u8,
    context: anytype,
    comptime cond: fn (@TypeOf(context)) bool,
) !void {
    const start = ctx.current();
    while (!cond(context)) {
        const elapsed = start.durationTo(ctx.current()).toNanoseconds();
        if (elapsed > @as(i96, deadline_ms) * std.time.ns_per_ms) {
            std.log.err("{s} did not hold within {d}ms", .{ label, deadline_ms });
            return error.WaitTimedOut;
        }
        try ctx.sleep(.fromMilliseconds(10));
    }
    assert(cond(context));
}

/// A reporter that signals when application delivery starts at or above a height and holds
/// those blocks' acknowledgements open (commonware `HoldingBlockReporter`).
pub const HoldingBlockReporter = struct {
    pub const Activity = Update;
    const State = struct {
        started: ?oneshot.Sender(Height) = null,
        pending: std.ArrayList(Exact) = .empty,
        min_signal_height: Height = .zero(),
    };

    shared: *Shared(State),

    pub const Created = struct {
        reporter: HoldingBlockReporter,
        started: oneshot.Receiver(Height),
    };

    pub fn init(gpa: Allocator, io: Io) Allocator.Error!Created {
        return init_from(gpa, io, .zero());
    }

    /// Signals and holds only above `height`.
    pub fn init_after(gpa: Allocator, io: Io, height: Height) Allocator.Error!Created {
        return init_from(gpa, io, height.next());
    }

    pub fn init_from(gpa: Allocator, io: Io, min_signal_height: Height) Allocator.Error!Created {
        var pair = try oneshot.channel(Height, gpa, io);
        errdefer {
            pair.sender.deinit();
            pair.receiver.deinit();
        }
        const shared = try Shared(State).create(gpa, io);
        shared.state.started = pair.sender;
        shared.state.min_signal_height = min_signal_height;
        return .{ .reporter = .{ .shared = shared }, .started = pair.receiver };
    }

    pub fn clone(self: HoldingBlockReporter) HoldingBlockReporter {
        self.shared.retain();
        return self;
    }

    /// The last handle drops the held acknowledgements unacknowledged, as commonware's drop.
    pub fn deinit(self: *HoldingBlockReporter) void {
        const shared = self.shared;
        self.* = undefined;
        if (!shared.release()) return;
        const state = &shared.state;
        if (state.started) |*sender| sender.deinit();
        for (state.pending.items) |*ack| ack.deinit();
        state.pending.deinit(shared.gpa);
        shared.gpa.destroy(shared);
    }

    pub fn pending_count(self: HoldingBlockReporter) usize {
        const state = self.shared.lock();
        defer self.shared.unlock();
        return state.pending.items.len;
    }

    /// Acknowledges every held block.
    pub fn acknowledge_all(self: HoldingBlockReporter) void {
        const state = self.shared.lock();
        defer self.shared.unlock();
        for (state.pending.items) |*ack| ack.acknowledge();
        state.pending.clearRetainingCapacity();
    }

    pub fn report(self: *HoldingBlockReporter, activity: Activity) actor_api.Feedback {
        switch (activity) {
            .tip => {},
            .block => |value| {
                var block = value.block;
                defer block.deinit();
                var ack = value.ack;
                const state = self.shared.lock();
                defer self.shared.unlock();
                if (block.inner().height().get() < state.min_signal_height.get()) {
                    ack.acknowledge();
                    return .ok;
                }
                if (state.started) |*sender| {
                    sender.send(block.inner().height()) catch {};
                    state.started = null;
                }
                state.pending.append(self.shared.gpa, ack) catch @panic("out of memory");
            },
        }
        return .ok;
    }
};

/// A reporter that forwards every update to the test (commonware `ApplicationReporter` over
/// an unbounded channel). `next` waits for the oldest; once the test calls `close`, reports
/// return `.closed`.
pub const ApplicationReporter = struct {
    pub const Activity = Update;
    const State = struct {
        updates: std.ArrayList(Update) = .empty,
        closed: bool = false,
        arrived: Io.Condition = .init,
    };

    shared: *Shared(State),

    pub fn init(gpa: Allocator, io: Io) Allocator.Error!ApplicationReporter {
        return .{ .shared = try .create(gpa, io) };
    }

    pub fn clone(self: ApplicationReporter) ApplicationReporter {
        self.shared.retain();
        return self;
    }

    pub fn deinit(self: *ApplicationReporter) void {
        const shared = self.shared;
        self.* = undefined;
        if (!shared.release()) return;
        for (shared.state.updates.items) |*item| item.deinit();
        shared.state.updates.deinit(shared.gpa);
        shared.gpa.destroy(shared);
    }

    /// Stops accepting updates (commonware drops the receiver) and drops queued ones.
    pub fn close(self: ApplicationReporter) void {
        const state = self.shared.lock();
        defer self.shared.unlock();
        state.closed = true;
        for (state.updates.items) |*item| item.deinit();
        state.updates.clearRetainingCapacity();
    }

    /// The oldest update (owned by the caller), waiting for one.
    pub fn next(self: ApplicationReporter) Io.Cancelable!Update {
        const shared = self.shared;
        const state = shared.lock();
        defer shared.unlock();
        assert(!state.closed);
        while (state.updates.items.len == 0) try state.arrived.wait(shared.io, &shared.mutex);
        return state.updates.orderedRemove(0);
    }

    pub fn report(self: *ApplicationReporter, activity: Activity) actor_api.Feedback {
        var owned = activity;
        const shared = self.shared;
        const state = shared.lock();
        defer shared.unlock();
        if (state.closed) {
            owned.deinit();
            return .closed;
        }
        state.updates.append(shared.gpa, owned) catch @panic("out of memory");
        state.arrived.signal(shared.io);
        return .ok;
    }
};

/// The immutable archives `start_standard_actor` opens: `<prefix>-finalizations-by-height-*`
/// and `<prefix>-finalized_blocks-*`, as commonware's.
pub const ImmutableStores = harness.Archives(B);

/// The marshal actor for direct tests, with application `App`, buffer `Buf`
/// (`RecordingBuffer`, or `variant.NoBuffer` for commonware's `start_unbuffered`), provider
/// `Prov`, and finalized stores `Certs` and `Blocks` (`store` adapters, or the paced ones).
pub fn Actor(
    comptime Prov: type,
    comptime App: type,
    comptime Buf: type,
    comptime Certs: type,
    comptime Stored: type,
) type {
    const Params = struct {
        pub const Scheme = S;
        pub const Provider = Prov;
        pub const Epocher = types.FixedEpocher;
        pub const Strategy = parallel.Sequential;
        pub const ApplicationBlock = B;
        pub const Block = V.Block;
        pub const Commitment = D;
        pub const Variant = V;
        pub const Acknowledgement = Exact;
        pub const Certificates = Certs;
        pub const Blocks = Stored;
        pub const Application = App;
        pub const Buffer = Buf;
        pub const Resolver = RecordingResolver;
    };
    return core.Actor(Params);
}

pub const Unbuffered = variant.NoBuffer(V, K);
pub const ImmutableCertificates = store.Certificates(ImmutableStores.FinalizationArchive, S, D, D);
pub const ImmutableBlocks = store.Blocks(ImmutableStores.BlockArchive, B);

/// commonware `test_config`: the actor configuration the direct tests share, starting at
/// genesis (owned by the config). `page_cache` must outlive the actor.
pub fn test_config(
    comptime A: type,
    gpa: Allocator,
    prefix: []const u8,
    provider: anytype,
    max_pending_acks: u32,
    page_cache: *runtime.buffer.paged.CacheRef,
) !A.Config {
    assert(max_pending_acks > 0);
    const genesis = try harness.StandardHarness.genesis_block(gpa, harness.num_validators);
    return .{
        .provider = provider,
        .epocher = .new(utils.NonZero(u64).init(harness.blocks_per_epoch).?),
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
        .max_pending_acks = max_pending_acks,
        .strategy = parallel.sequential,
    };
}

/// A running actor from `start_standard_actor` with the archives it borrows (commonware's
/// returned `(mailbox, buffer, resolver, handle)`).
pub fn Started(comptime Prov: type, comptime App: type, comptime Buf: type) type {
    return struct {
        const Self = @This();
        pub const A = Actor(Prov, App, Buf, ImmutableCertificates, ImmutableBlocks);

        gpa: Allocator,
        stores: *ImmutableStores,
        prefix: []u8,
        mailbox: A.Mailbox,
        /// The test's handle on the buffer (the actor holds a clone), when buffered.
        buffer: ?Buf,
        resolver: RecordingResolver,
        handle: runtime.context.Handle(anyerror!void),

        /// Aborts the actor, as a crash or a restart would, and releases its storage so a
        /// later start can reopen the same partitions.
        pub fn crash(self: *Self) void {
            const ended = self.handle.abort() catch {};
            ended catch {};
            self.release();
        }

        /// Closes the mailbox and resolver so the actor ends, then returns how it ended.
        pub fn stop(self: *Self) !void {
            self.mailbox.deinit();
            self.resolver.close();
            const result = self.handle.join();
            self.release_after_mailbox();
            try try result;
        }

        /// Waits for the actor to end on its own (its inputs stay open), then releases it.
        pub fn join(self: *Self) !void {
            const result = self.handle.join();
            self.release();
            try try result;
        }

        fn release(self: *Self) void {
            self.mailbox.deinit();
            self.release_after_mailbox();
        }

        fn release_after_mailbox(self: *Self) void {
            if (self.buffer) |*buffer| deinit_value(buffer);
            self.resolver.deinit();
            self.stores.deinit();
            self.gpa.destroy(self.stores);
            self.gpa.free(self.prefix);
            self.* = undefined;
        }
    };
}

/// commonware `start_standard_actor`: opens the immutable archives under `prefix` and starts
/// an actor with the recording resolver, `application` (owned), and `buffer` (owned; null for
/// an unbuffered actor, whose `Buf` is `Unbuffered`).
pub fn start_standard_actor(
    comptime Prov: type,
    comptime App: type,
    comptime Buf: type,
    ctx: Ctx,
    prefix: []const u8,
    provider: Prov,
    application: App,
    buffer: ?Buf,
    start: Start,
) !Started(Prov, App, Buf) {
    const A = Started(Prov, App, Buf).A;
    const gpa = ctx.gpa();
    var app = application;
    errdefer deinit_value(&app);
    var buf = buffer;
    errdefer if (buf) |*value| deinit_value(value);
    const owned_prefix = try gpa.dupe(u8, prefix);
    errdefer gpa.free(owned_prefix);
    const stores = try gpa.create(ImmutableStores);
    errdefer gpa.destroy(stores);
    try stores.open(ctx, owned_prefix);
    errdefer stores.deinit();
    var config = try test_config(A, gpa, owned_prefix, provider, 1, &stores.cache_ref);
    // `start` replaces the config's genesis, which the config owned.
    switch (config.start) {
        .genesis => |*genesis| genesis.deinit(),
        .floor => |*floor| floor.deinit(gpa),
    }
    config.start = start;
    const initialized = try A.init(
        ctx.child("actor"),
        .{ .archive = &stores.finalizations },
        .{ .archive = &stores.blocks },
        config,
    );
    var holding = try RecordingResolver.holding(gpa, ctx.io(), &ctx.scope.child("mailbox"));
    const actor_buffer: Buf = if (buf) |value| clone_value(value) else if (Buf == Unbuffered)
        .{ .gpa = gpa }
    else
        @panic("a buffered actor needs a buffer");
    const handle = try initialized.actor.start(
        app,
        actor_buffer,
        holding.receiver,
        holding.resolver.clone(),
    );
    return .{
        .gpa = gpa,
        .stores = stores,
        .prefix = owned_prefix,
        .mailbox = initialized.mailbox,
        .buffer = buf,
        .resolver = holding.resolver,
        .handle = handle,
    };
}

fn clone_value(value: anytype) @TypeOf(value) {
    if (comptime std.meta.hasMethod(@TypeOf(value), "clone")) return value.clone();
    return value;
}

fn deinit_value(value: anytype) void {
    if (comptime std.meta.hasMethod(@TypeOf(value.*), "deinit")) value.deinit();
}

/// A `store.Certificates` whose syncs sleep `pace_ms` first (commonware `PacedStore`).
pub fn PacedCertificates(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const Scheme = T.Scheme;
        pub const BlockDigest = T.BlockDigest;
        pub const Commitment = T.Commitment;
        pub const Error = T.Error || Io.Cancelable;
        comptime {
            assert(T.Finalization == Finalization);
        }

        inner: T,
        ctx: Ctx,
        pace_ms: u64,

        pub fn put(
            self: Self,
            height: Height,
            digest: BlockDigest,
            finalization: *const Finalization,
        ) Error!void {
            try self.inner.put(height, digest, finalization);
        }

        pub fn sync(self: Self) Error!void {
            try pace(self.ctx, self.pace_ms);
            try self.inner.sync();
        }

        /// Starts the inner sync; it counts as durable `pace_ms` later (commonware's
        /// `PacedStore` sleeps inside the sync handle).
        pub fn start_sync(self: Self) Error!store.Durable {
            return paced_completion(self.ctx, try self.inner.start_sync(), self.pace_ms);
        }

        pub fn get(self: Self, id: store.Identifier(BlockDigest)) Error!?Finalization {
            return self.inner.get(id);
        }

        pub fn has(self: Self, height: Height) Error!bool {
            return self.inner.has(height);
        }

        pub fn prune(self: Self, min: Height) Error!void {
            try self.inner.prune(min);
        }

        pub fn last_index(self: Self) ?Height {
            return self.inner.last_index();
        }

        pub fn ranges_from(self: Self, from: Height) []const storage.rmap.Range {
            return self.inner.ranges_from(from);
        }
    };
}

/// A `store.Blocks` whose syncs sleep `pace_ms` first (commonware `PacedStore`).
pub fn PacedBlocks(comptime T: type, comptime StoredBlock: type) type {
    return struct {
        const Self = @This();
        pub const Digest = T.Digest;
        pub const Error = T.Error || Io.Cancelable;

        inner: T,
        ctx: Ctx,
        pace_ms: u64,

        pub fn put(self: Self, digest: Digest, block: anytype) Error!void {
            try self.inner.put(digest, block);
        }

        pub fn sync(self: Self) Error!void {
            try pace(self.ctx, self.pace_ms);
            try self.inner.sync();
        }

        /// Starts the inner sync; it counts as durable `pace_ms` later (commonware's
        /// `PacedStore` sleeps inside the sync handle).
        pub fn start_sync(self: Self) Error!store.Durable {
            return paced_completion(self.ctx, try self.inner.start_sync(), self.pace_ms);
        }

        pub fn get(self: Self, id: store.Identifier(Digest)) Error!?StoredBlock {
            return self.inner.get(id);
        }

        pub fn prune(self: Self, min: Height) Error!void {
            try self.inner.prune(min);
        }

        pub fn missing_items(self: Self, start: Height, out: []u64) []u64 {
            return self.inner.missing_items(start, out);
        }

        pub fn next_gap(self: Self, value: Height) struct { ?Height, ?Height } {
            return self.inner.next_gap(value);
        }

        pub fn last_index(self: Self) ?Height {
            return self.inner.last_index();
        }
    };
}

fn pace(ctx: Ctx, pace_ms: u64) Io.Cancelable!void {
    assert(pace_ms > 0);
    try ctx.sleep(.fromMilliseconds(@intCast(pace_ms)));
}

/// A completion of `inner` (taken) that completes `pace_ms` after it starts at the earliest
/// (commonware `PacedStore`'s handle sleeps before awaiting the inner one). A task that cannot
/// be spawned reports `OutOfMemory`.
fn paced_completion(ctx: Ctx, inner: store.Durable, pace_ms: u64) Allocator.Error!store.Durable {
    errdefer inner.release();
    assert(pace_ms > 0);
    const producer = try store.Durable.init_pending(ctx.gpa(), ctx.io());
    const handed = producer.retain();
    const args = .{ producer, inner, pace_ms };
    const handle = ctx.child("paced_sync").spawn(finish_paced, args) catch {
        handed.release();
        producer.release();
        return error.OutOfMemory;
    };
    handle.detach();
    return handed;
}

fn finish_paced(ctx: Ctx, producer: store.Durable, inner: store.Durable, pace_ms: u64) void {
    defer producer.release();
    pace(ctx, pace_ms) catch |err| {
        inner.release();
        return producer.finish(err);
    };
    producer.finish(inner.wait_release());
}

/// The prunable finalized stores the direct actor tests open (commonware
/// `prunable_finalized_stores`): `<prefix>-fbh-*` for finalizations and `<prefix>-fb-*` for
/// blocks, ten items per section. Must not move once opened.
pub fn PrunableStores(comptime StoredBlock: type) type {
    return struct {
        const Self = @This();
        const Translator = storage.translator.EightCap;
        pub const FinalizationArchive = storage.archive.prunable.Archive(
            Translator,
            [32]u8,
            Finalization,
        );
        pub const BlockArchive = storage.archive.prunable.Archive(Translator, [32]u8, StoredBlock);
        pub const Certificates = store.Certificates(FinalizationArchive, S, D, D);
        pub const Blocks = store.Blocks(BlockArchive, StoredBlock);
        const kinds = [_][]const u8{
            "fbh-metadata", "fbh-key", "fbh-value", "fb-metadata", "fb-key", "fb-value",
        };

        gpa: Allocator,
        cache_ref: runtime.buffer.paged.CacheRef,
        names: [kinds.len][]u8,
        finalizations: FinalizationArchive,
        blocks: BlockArchive,

        pub fn open(self: *Self, ctx: Ctx, prefix: []const u8) !void {
            const gpa = ctx.gpa();
            self.gpa = gpa;
            var made: usize = 0;
            errdefer for (self.names[0..made]) |name| gpa.free(name);
            for (kinds, &self.names) |kind, *name| {
                name.* = try std.fmt.allocPrint(gpa, "{s}-{s}", .{ prefix, kind });
                made += 1;
            }
            self.cache_ref = try .init(gpa, harness.page_size, harness.page_cache_size);
            errdefer self.cache_ref.deinit();
            const certificate_config = S.certificate_codec_config_unbounded();
            const label = "finalizations_by_height";
            self.finalizations = try open_prunable(
                Finalization,
                ctx,
                self,
                0,
                label,
                certificate_config,
            );
            errdefer self.finalizations.deinit();
            self.blocks = try open_prunable(StoredBlock, ctx, self, 3, "finalized_blocks", {});
        }

        pub fn deinit(self: *Self) void {
            self.blocks.deinit();
            self.finalizations.deinit();
            self.cache_ref.deinit();
            for (self.names) |name| self.gpa.free(name);
            self.* = undefined;
        }

        pub fn certificates(self: *Self) Certificates {
            return .{ .archive = &self.finalizations };
        }

        pub fn blocks_store(self: *Self) Blocks {
            return .{ .archive = &self.blocks };
        }

        /// Both stores, pacing their syncs by `pace_ms` (commonware `paced_finalized_stores`).
        pub fn paced(self: *Self, ctx: Ctx, pace_ms: u64) struct {
            PacedCertificates(Certificates),
            PacedBlocks(Blocks, StoredBlock),
        } {
            assert(pace_ms > 0);
            const certificates_pacer = ctx.child("finalizations_pacer");
            const blocks_pacer = ctx.child("blocks_pacer");
            return .{
                .{ .inner = self.certificates(), .ctx = certificates_pacer, .pace_ms = pace_ms },
                .{ .inner = self.blocks_store(), .ctx = blocks_pacer, .pace_ms = pace_ms },
            };
        }

        fn open_prunable(
            comptime Value: type,
            ctx: Ctx,
            self: *Self,
            comptime first: usize,
            comptime label: []const u8,
            codec_config: anytype,
        ) !storage.archive.prunable.Archive(Translator, [32]u8, Value) {
            return .init(ctx.gpa(), ctx.storage, ctx.scope.child(label), .{
                .translator = .{},
                .metadata_partition = self.names[first],
                .key_partition = self.names[first + 1],
                .key_cache_ref = &self.cache_ref,
                .value_partition = self.names[first + 2],
                .codec_config = codec_config,
                .items_per_section = 10,
                .key_write_buffer = 1024,
                .value_write_buffer = 1024,
                .replay_buffer = 1024,
            });
        }
    };
}

const testing = std.testing;

test "start_standard_actor dispatches genesis and stops cleanly" {
    try @import("../../mocks/soak.zig").run(testing.allocator, .{}, struct {
        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            const App = @import("../../mocks/application.zig").Application(B);
            const application = try App.init(gpa, ctx.io());
            var observer = application.clone();
            defer observer.deinit();
            const buffer = try RecordingBuffer.init(gpa, ctx.io());
            const genesis = try harness.StandardHarness.genesis_block(gpa, harness.num_validators);
            var started = try start_standard_actor(
                harness.Provider,
                App,
                RecordingBuffer,
                ctx,
                "common",
                .init(&fixture.verifier),
                application,
                buffer,
                .{ .genesis = genesis },
            );
            try wait_until(ctx, 1000, "genesis dispatched", observer, struct {
                fn cond(app: App) bool {
                    return app.contains(.zero());
                }
            }.cond);
            try testing.expectEqual(0, started.buffer.?.send_count());
            try testing.expect(started.resolver.targeted_is_empty());
            try started.stop();
        }
    }.body, .{});
}

test "recording buffer serves, evicts transient blocks, and tracks subscriptions" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var buffer = try RecordingBuffer.init(gpa, io);
    defer buffer.deinit();
    const raw = try harness.make_raw_block(gpa, harness.genesis_parent(), .new(1), 7);
    const block = try @import("../../mocks/block.zig").ready(B, gpa, raw);
    const digest = block.digest();
    try buffer.insert_transient(block);
    try testing.expect(buffer.contains(digest));
    try testing.expect(buffer.last_handed_released() == null);
    var found = (try buffer.find_by_digest(digest)).?;
    try testing.expect(!buffer.contains(digest));
    try testing.expectEqual(false, buffer.last_handed_released().?);
    found.deinit();
    try testing.expectEqual(true, buffer.last_handed_released().?);

    var first = (try buffer.subscribe_by_commitment(digest)).?;
    defer first.deinit();
    var second = (try buffer.subscribe_by_commitment(digest)).?;
    try testing.expectEqual(2, buffer.subscription_count());
    second.deinit();
    try testing.expect(buffer.commitment_subscription_closed(1));
    try testing.expect(!buffer.commitment_subscription_closed(0));
    const again = try @import("../../mocks/block.zig").ready(
        B,
        gpa,
        try harness.make_raw_block(gpa, harness.genesis_parent(), .new(1), 7),
    );
    try testing.expect(buffer.deliver_commitment_subscription(0, again));
    var delivered = try first.recv();
    defer delivered.deinit();
    try testing.expect(delivered.digest().eql(digest));
    try testing.expect(buffer.commitment_subscription_closed(0));
    try testing.expectEqual(2, buffer.commitment_subscription_count());
}
