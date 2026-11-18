//! The marshal actor (commonware `marshal/core/actor.rs`): receives uncertified blocks from
//! the broadcast buffer, certificates from consensus, and backfill from the resolver, and
//! rebuilds the total order of finalized blocks for the application.
//!
//! One task runs the actor. Pump tasks feed its mailbox and the resolver handler into one
//! bounded inbox; buffer waiters and a watcher on the application's current acknowledgement
//! push their completions into the same inbox. The actor handles events in arrival order,
//! except that a resolved acknowledgement is handled before any mailbox or resolver event
//! (commonware's biased `select_loop!` prefers waiters, then acknowledgements, then the
//! mailbox, then the resolver). Zigware's archives are durable when a write or sync returns, so
//! commonware's pooled syncs complete inside the event that starts them, and the durability
//! acks of `proposed`, `verified`, and `certified` fire once the write returns. A storage or
//! allocation error stops the actor with that error (commonware panics).
//!
//! The handlers live in `actor_ingress.zig` (mailbox), `actor_backfill.zig` (resolver), and
//! `actor_finalize.zig` (storage, floors, repair, and dispatch).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor_api = @import("actor");
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");
const inbox_api = @import("../../simplex/actors/inbox.zig");
const config_api = @import("../config.zig");
const update_api = @import("../update.zig");
const store = @import("../store.zig");
const handler = @import("../resolver/handler.zig");
const variant = @import("variant.zig");
const acks = @import("acks.zig");
const cache_api = @import("cache.zig");
const certified_api = @import("certified.zig");
const durability = @import("durability.zig");
const floor = @import("floor.zig");
const mailbox_api = @import("mailbox.zig");
const staged_api = @import("staged.zig");
const stream_api = @import("stream.zig");
const subscriptions = @import("subscriptions.zig");
const ingress = @import("actor_ingress.zig");
const backfill = @import("actor_backfill.zig");
const finalize = @import("actor_finalize.zig");

const oneshot = utils.channel.oneshot;
const metrics = runtime.telemetry.metrics;
const Height = types.Height;
const Round = types.Round;
const Cutoff = floor.Cutoff;
const Floor = floor.Floor;
const Processed = floor.Processed;

/// Events buffered between the sources and the actor. Pumps block once it is full, so the
/// mailbox's overflow policy still applies.
const inbox_capacity = 8;

/// Most bytes of a partition name the actor formats.
const partition_size_max = 160;

/// `P` declares the `config.Config` parameters (`Scheme`, `Provider`, `Epocher`, `Strategy`,
/// `ApplicationBlock`, `Block`, `Commitment`) plus `Variant` (`variant.assert_variant`),
/// `Acknowledgement` (`utils.acknowledgement`), `Certificates` (`store.Certificates`),
/// `Blocks` (`store.Blocks`), `Application` (a `Reporter` of `Update`), `Buffer`
/// (`variant.assert_buffer`), and `Resolver` (a targeted resolver of `handler.Key`), and
/// optionally `Context` (default `runtime.deterministic.Context`).
pub fn Actor(comptime P: type) type {
    comptime config_api.assert_parameters(P);
    comptime variant.assert_variant(P.Variant);
    comptime variant.assert_buffer(P.Buffer);
    comptime assert(P.Block == P.Variant.Block);
    return struct {
        const Self = @This();
        pub const V = P.Variant;
        pub const S = P.Scheme;
        pub const A = P.Acknowledgement;
        pub const Block = V.Block;
        pub const Digest = V.Block.Digest;
        pub const Commitment = V.Commitment;
        pub const Message = mailbox_api.Message(S, V);
        pub const Mailbox = mailbox_api.Mailbox(S, V);
        pub const Finalization = simplex_types.Finalization(S, Commitment);
        pub const Notarization = simplex_types.Notarization(S, Commitment);
        pub const Update = update_api.Update(V.ApplicationBlock, A);
        pub const Config = config_api.Config(P);
        pub const HandlerMessage = handler.Message(Commitment);
        pub const Key = handler.Key(Commitment);
        pub const Request = handler.Request(Commitment);
        pub const SubscriptionKey = subscriptions.KeyFor(V);
        pub const Context = if (@hasDecl(P, "Context"))
            P.Context
        else
            runtime.deterministic.Context;
        pub const FloorState = floor.State(S, Commitment, Aborter);
        pub const Cache = cache_api.Manager(V, S);
        pub const Inbox = inbox_api.Inbox(Event, inbox_capacity, release_event);

        /// What `init` returns: the actor (start it with `start`), its mailbox, and the floor
        /// it restored.
        pub const Initialized = struct { actor: *Self, mailbox: Mailbox, floor: Floor };

        pub const Event = union(enum) {
            mailbox: Message,
            resolver: HandlerMessage,
            waiter: Completion,
            /// The armed application acknowledgement of this generation resolved.
            ack: u64,
            closed,
        };

        /// A finished buffer waiter: the block, or the key of a subscription whose buffer
        /// subscription closed.
        pub const Completion = struct {
            id: u64,
            gpa: Allocator,
            result: union(enum) { block: Block, closed: SubscriptionKey },
        };

        ctx: Context,
        gpa: Allocator,
        io: Io,
        mailbox_receiver: actor_api.mailbox.Receiver(Message),
        provider: P.Provider,
        epocher: P.Epocher,
        view_retention: types.ViewDelta,
        max_repair: u32,
        block_codec_config: codec.Cfg(P.ApplicationBlock),
        strategy: P.Strategy,
        /// Durable floor and floor updates not yet applied.
        floor: FloorState,
        /// Application delivery cursor and round floor metadata.
        stream: stream_api.Stream,
        pending_acks: acks.PendingAcks(A),
        /// Highest known finalized height.
        tip: Height,
        block_subscriptions: subscriptions.Subscriptions(V, Aborter),
        /// Commitments known certified above the finalized tip.
        certified: certified_api.Certified(Commitment),
        dispatch_gate: durability.DispatchGate,
        /// Finalized blocks awaiting dispatch.
        staged: staged_api.Staged(V),
        cache: Cache,
        finalizations_by_height: P.Certificates,
        finalized_blocks: P.Blocks,
        finalized_height: metrics.Gauge,
        processed_height: metrics.Gauge,
        cache_prefix: []u8,
        /// Set by `start`.
        application: P.Application = undefined,
        buffer: P.Buffer = undefined,
        resolver: P.Resolver = undefined,
        resolver_receiver: actor_api.mailbox.Receiver(HandlerMessage) = undefined,
        started: bool = false,
        inbox: Inbox = undefined,
        waiters: Waiters = undefined,
        /// The task waiting on the current application acknowledgement.
        ack_watch: ?Io.Future(void) = null,
        ack_generation: u64 = 0,

        /// Opens the actor's storage under `ctx` and restores its floor. `finalized_blocks`
        /// and `finalizations_by_height` borrow archives the caller frees after the actor
        /// ends. Takes ownership of `config.start`.
        pub fn init(
            ctx: Context,
            finalizations_by_height: P.Certificates,
            finalized_blocks: P.Blocks,
            config: Config,
        ) !Initialized {
            config.assert_valid();
            const gpa = ctx.gpa();
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.* = .{
                .ctx = ctx,
                .gpa = gpa,
                .io = ctx.io(),
                .mailbox_receiver = undefined,
                .provider = config.provider,
                .epocher = config.epocher,
                .view_retention = config.view_retention,
                .max_repair = config.max_repair,
                .block_codec_config = config.block_codec_config,
                .strategy = config.strategy,
                .floor = undefined,
                .stream = undefined,
                .pending_acks = try .init(gpa, config.max_pending_acks),
                .tip = .zero(),
                .block_subscriptions = .empty,
                .certified = .empty,
                .dispatch_gate = .{},
                .staged = undefined,
                .cache = undefined,
                .finalizations_by_height = finalizations_by_height,
                .finalized_blocks = finalized_blocks,
                .finalized_height = undefined,
                .processed_height = undefined,
                .cache_prefix = &.{},
            };
            errdefer self.pending_acks.deinit(gpa);
            self.staged = try .init(gpa, config.max_pending_acks *| 2);
            errdefer self.staged.deinit(gpa);
            self.cache_prefix = try std.fmt.allocPrint(gpa, "{s}-cache", .{
                config.partition_prefix,
            });
            errdefer gpa.free(self.cache_prefix);
            var start_anchor = config.start;
            const configured = try self.open_storage(config, &start_anchor);
            errdefer if (configured) |value| {
                var owned = value;
                owned.deinit(gpa);
            };
            errdefer self.stream.deinit();
            errdefer self.cache.deinit();
            const restored = try self.restore();
            self.floor = .init(configured, restored.floor, restored.witnessed);
            return self.open_mailbox(config);
        }

        fn open_mailbox(self: *Self, config: Config) !Initialized {
            const scope = self.ctx.scope.child("mailbox");
            const pair = try actor_api.mailbox.new_with_metrics(
                Message,
                self.gpa,
                self.io,
                &scope,
                config.mailbox_size,
            );
            self.mailbox_receiver = pair.receiver;
            const mailbox = Mailbox.init(self.gpa, self.io, pair.sender, config.max_pending_acks);
            assert(!self.started);
            return .{ .actor = self, .mailbox = mailbox, .floor = self.floor.snapshot() };
        }

        /// Opens the cache and stream and stores the genesis anchor; returns the configured
        /// floor (owned).
        fn open_storage(
            self: *Self,
            config: Config,
            anchor_or_floor: *config_api.Start(S, Commitment, Block),
        ) !?Finalization {
            const cache_config: cache_api.Config = .{
                .partition_prefix = self.cache_prefix,
                .prunable_items_per_section = config.prunable_items_per_section,
                .replay_buffer = config.replay_buffer,
                .key_write_buffer = config.key_write_buffer,
                .value_write_buffer = config.value_write_buffer,
                .key_page_cache = config.page_cache,
            };
            const scope = self.ctx.scope.child("cache");
            const codec_config = config.block_codec_config;
            self.cache = try .init(self.gpa, self.ctx.storage, scope, cache_config, codec_config);
            errdefer self.cache.deinit();
            // The application metadata name is retained for legacy support.
            var name: [partition_size_max]u8 = undefined;
            const partition = std.fmt.bufPrint(&name, "{s}-application-metadata", .{
                config.partition_prefix,
            }) catch @panic("partition prefix too long");
            self.stream = try .init(self.gpa, self.ctx.storage, partition);
            errdefer self.stream.deinit();
            switch (anchor_or_floor.*) {
                .genesis => |*anchor| {
                    defer V.deinit_block(self.gpa, anchor);
                    const last = self.stream.processed_height();
                    try ensure_genesis_anchor(self, anchor, last);
                    return null;
                },
                .floor => |finalization| return finalization,
            }
        }

        const Restored = struct { floor: Floor, witnessed: Round };

        /// Raises the stream's round floor to what the archives justify (see
        /// `finalize.derive_cutoff`) and registers the height metrics.
        fn restore(self: *Self) !Restored {
            const last_processed_height = self.stream.processed_height();
            const derived = try finalize.derive_cutoff(self, last_processed_height);
            if (derived.cutoff.order(self.stream.cutoff()) == .gt) {
                try self.stream.set_cutoff(derived.cutoff);
                try self.stream.sync();
            }
            const last_processed: ?Processed = if (last_processed_height) |height|
                finalize.processed(self, height)
            else
                null;
            self.finalized_height = try self.ctx.scope.gauge(
                "finalized_height",
                "Finalized height of application",
            );
            errdefer self.finalized_height.deinit();
            self.processed_height = try self.ctx.scope.gauge(
                "processed_height",
                "Processed height of application",
            );
            if (last_processed_height) |height| {
                _ = self.processed_height.metric().try_set(height.get()) catch 0;
            }
            const restored: Floor = .init(last_processed, self.stream.cutoff());
            return .{ .floor = restored, .witnessed = derived.witnessed };
        }

        /// Stores `anchor` (borrowed) as the genesis block unless the archive already holds it
        /// or the application processed past it.
        fn ensure_genesis_anchor(
            self: *Self,
            anchor: *const Block,
            last_processed: ?Height,
        ) !void {
            const gpa = self.gpa;
            const finalized_blocks = self.finalized_blocks;
            const height = anchor.inner().height();
            if (height.get() != 0) @panic("genesis anchor must be at height zero");
            const commitment = V.commitment(anchor);
            if (try finalized_blocks.get(.{ .index = height })) |stored| {
                var block = V.restore_across(gpa, stored, self.strategy) catch |err| {
                    codec.free(V.StoredBlock, gpa, stored);
                    return err;
                };
                defer V.deinit_block(gpa, &block);
                if (block.inner().height().get() != height.get()) {
                    @panic("stored genesis block height mismatch");
                }
                if (!V.commitment(&block).eql(commitment)) {
                    @panic("stored genesis block does not match configured anchor");
                }
                return;
            }
            // A stale anchor below the processed height is ignored.
            if (last_processed) |existing| if (height.get() < existing.get()) return;
            const stored = try V.into_stored(gpa, anchor);
            defer codec.free(V.StoredBlock, gpa, stored);
            try finalized_blocks.put(anchor.digest(), &stored);
            try finalized_blocks.sync();
        }

        /// Takes ownership of the application, buffer, and resolver (the handler's receiver
        /// and the resolver mailbox) and runs the actor until its mailbox or the handler
        /// closes, an acknowledgement is dropped, or the task is aborted. The actor frees
        /// itself when it ends.
        pub fn start(
            self: *Self,
            application: P.Application,
            buffer: P.Buffer,
            resolver_receiver: actor_api.mailbox.Receiver(HandlerMessage),
            resolver: P.Resolver,
        ) !runtime.context.Handle(anyerror!void) {
            assert(!self.started);
            self.application = application;
            self.buffer = buffer;
            self.resolver_receiver = resolver_receiver;
            self.resolver = resolver;
            self.started = true;
            const ctx = self.ctx;
            return ctx.spawn(run, .{self});
        }

        /// Frees an actor that was never started.
        pub fn deinit(self: *Self) void {
            assert(!self.started);
            self.free_state();
        }

        fn run(_: Context, self: *Self) anyerror!void {
            assert(self.started);
            defer self.shutdown();
            self.inbox.init(self.io);
            self.waiters = .{ .gpa = self.gpa, .io = self.io, .inbox = &self.inbox };
            try self.inbox.forward(.mailbox, &self.mailbox_receiver);
            try self.inbox.forward(.resolver, &self.resolver_receiver);
            try finalize.startup(self);
            while (true) {
                // Every event that buffers stream metadata syncs it before it returns.
                assert(self.stream.is_synced());
                // Drop dropped subscribers; a subscription without any aborts its waiter.
                self.block_subscriptions.retain_open(self.gpa);
                const event = self.inbox.next() catch return;
                if (!try self.handle(event)) return;
            }
        }

        /// Handles one event; false stops the actor.
        fn handle(self: *Self, event: Event) !bool {
            switch (event) {
                .closed => return false,
                .waiter => |done| try self.handle_waiter(done),
                .ack => |generation| return self.handle_ack(generation),
                .mailbox => |message| {
                    if (!try self.drain_ready_acks()) {
                        release_event(event);
                        return false;
                    }
                    try ingress.handle(self, message);
                },
                .resolver => |message| {
                    if (!try self.drain_ready_acks()) {
                        release_event(event);
                        return false;
                    }
                    try backfill.handle(self, message);
                },
            }
            return true;
        }

        /// Handles a resolved acknowledgement before a mailbox or resolver event, as
        /// commonware's biased `select_loop!` does, even when its watcher has not yet queued
        /// it. False stops the actor (a dropped acknowledgement).
        fn drain_ready_acks(self: *Self) !bool {
            const current = self.pending_acks.current() orelse return true;
            if (current.waiter.poll() == null) return true;
            // The watcher's `ack` event, if already queued, finds no watch and is ignored.
            if (self.ack_watch) |*watch| watch.cancel(self.io);
            self.ack_watch = null;
            return self.process_ready_acks();
        }

        fn handle_waiter(self: *Self, done: Completion) !void {
            var completion = done;
            // An aborted waiter's result is no longer wanted.
            if (!self.waiters.finish(completion.id)) return release_completion(completion);
            switch (completion.result) {
                .block => |*block| {
                    defer V.deinit_block(self.gpa, block);
                    _ = try finalize.ingest(self, block);
                },
                // A closed buffer subscription marks the key as permanently unavailable.
                .closed => |key| self.block_subscriptions.remove(self.gpa, key),
            }
        }

        /// Handles the ready acknowledgements in order and syncs their progress once; false
        /// when the application dropped one (commonware stops marshal).
        fn handle_ack(self: *Self, generation: u64) !bool {
            if (generation != self.ack_generation) return true;
            var watch = self.ack_watch orelse return true;
            self.ack_watch = null;
            watch.await(self.io);
            return self.process_ready_acks();
        }

        /// Advances the processed height over every resolved acknowledgement (at least one),
        /// syncs it, and dispatches more blocks.
        fn process_ready_acks(self: *Self) !bool {
            assert(self.ack_watch == null);
            var handled: u32 = 0;
            while (self.pending_acks.pop_ready()) |ready| {
                const height, const result = ready;
                result catch return false;
                // Only archived blocks are dispatched, so the block is stored.
                try finalize.update_processed(self, .{ .block = height });
                try finalize.cover_processed(self, height);
                handled += 1;
            }
            assert(handled > 0);
            try self.stream.sync();
            try finalize.try_dispatch_blocks(self);
            return true;
        }

        /// Watches the current acknowledgement unless a watcher already does.
        pub fn arm_ack(self: *Self) !void {
            if (self.ack_watch != null) return;
            const current = self.pending_acks.current() orelse return;
            self.ack_generation += 1;
            self.ack_watch = try self.io.concurrent(watch_ack, .{
                &self.inbox,
                &current.waiter,
                self.ack_generation,
            });
        }

        /// Drops every pending acknowledgement and its watcher.
        pub fn clear_acks(self: *Self) void {
            if (self.ack_watch) |*watch| watch.cancel(self.io);
            self.ack_watch = null;
            self.pending_acks.clear();
            assert(self.pending_acks.current() == null);
        }

        fn watch_ack(inbox: *Inbox, waiter: *const A.Waiter, generation: u64) void {
            waiter.wait() catch |err| switch (err) {
                error.Canceled => return,
                // A dropped acknowledgement is reported too: it stops the actor.
                else => {},
            };
            _ = inbox.push(.{ .ack = generation });
        }

        /// Stops the sources and waiters and frees the actor.
        fn shutdown(self: *Self) void {
            self.inbox.shutdown();
            if (self.ack_watch) |*watch| watch.cancel(self.io);
            self.ack_watch = null;
            // Subscriptions and the pending floor abort their waiters first.
            self.free_state();
        }

        fn free_state(self: *Self) void {
            const gpa = self.gpa;
            self.block_subscriptions.deinit(gpa);
            self.floor.deinit(gpa);
            if (self.started) {
                self.waiters.deinit();
                self.resolver_receiver.deinit();
                deinit_owned(&self.application);
                deinit_owned(&self.buffer);
                deinit_owned(&self.resolver);
            }
            self.mailbox_receiver.deinit();
            self.pending_acks.deinit(gpa);
            self.certified.deinit(gpa);
            self.dispatch_gate.deinit(gpa);
            self.staged.deinit(gpa);
            self.cache.deinit();
            self.stream.deinit();
            self.finalized_height.deinit();
            self.processed_height.deinit();
            gpa.free(self.cache_prefix);
            gpa.destroy(self);
        }

        fn deinit_owned(value: anytype) void {
            const T = @TypeOf(value.*);
            if (comptime std.meta.hasMethod(T, "deinit")) value.deinit();
        }

        fn release_completion(done: Completion) void {
            switch (done.result) {
                .block => |block| {
                    var owned = block;
                    V.deinit_block(done.gpa, &owned);
                },
                .closed => {},
            }
        }

        fn release_event(event: Event) void {
            switch (event) {
                .mailbox => |message| Message.discard(message),
                .resolver => |message| HandlerMessage.discard(message),
                .waiter => |done| release_completion(done),
                .ack, .closed => {},
            }
        }

        /// Buffer waiters: each waits on a buffer subscription in its own task and reports
        /// the block (or the closed subscription) through the inbox.
        pub const Waiters = struct {
            gpa: Allocator,
            io: Io,
            inbox: *Inbox,
            tasks: std.AutoArrayHashMapUnmanaged(u64, Io.Future(void)) = .empty,
            next_id: u64 = 0,

            const Kind = union(enum) {
                subscription: SubscriptionKey,
                /// A floor anchor waiter: a closed subscription keeps it pending until the
                /// floor is replaced, applied, or superseded.
                floor,
            };

            /// Waits on `receiver` (taking ownership) for the subscription `key`.
            pub fn push(
                self: *Waiters,
                key: SubscriptionKey,
                receiver: oneshot.Receiver(Block),
            ) !Aborter {
                return self.spawn(.{ .subscription = key }, receiver);
            }

            /// Waits on `receiver` (taking ownership) for a floor anchor.
            pub fn push_floor(self: *Waiters, receiver: oneshot.Receiver(Block)) !Aborter {
                return self.spawn(.floor, receiver);
            }

            fn spawn(self: *Waiters, kind: Kind, receiver: oneshot.Receiver(Block)) !Aborter {
                var owned = receiver;
                errdefer owned.deinit();
                try self.tasks.ensureUnusedCapacity(self.gpa, 1);
                const id = self.next_id;
                self.next_id += 1;
                const args = .{ self.inbox, self.gpa, id, kind, owned };
                const future = try self.io.concurrent(wait, args);
                self.tasks.putAssumeCapacityNoClobber(id, future);
                return .{ .waiters = self, .id = id };
            }

            fn wait(
                inbox: *Inbox,
                gpa: Allocator,
                id: u64,
                kind: Kind,
                receiver: oneshot.Receiver(Block),
            ) void {
                var owned = receiver;
                defer owned.deinit();
                const block = owned.recv() catch |err| switch (err) {
                    error.Canceled => return,
                    error.Closed => switch (kind) {
                        .subscription => |key| {
                            const closed: Event = .{ .waiter = .{
                                .id = id,
                                .gpa = gpa,
                                .result = .{ .closed = key },
                            } };
                            _ = inbox.push(closed);
                            return;
                        },
                        .floor => return,
                    },
                };
                const event: Event = .{ .waiter = .{
                    .id = id,
                    .gpa = gpa,
                    .result = .{ .block = block },
                } };
                if (!inbox.push(event)) release_event(event);
            }

            fn cancel(self: *Waiters, id: u64) void {
                var entry = self.tasks.fetchSwapRemove(id) orelse return;
                entry.value.cancel(self.io);
            }

            /// Reaps a finished waiter; false when it was aborted first.
            fn finish(self: *Waiters, id: u64) bool {
                var entry = self.tasks.fetchSwapRemove(id) orelse return false;
                entry.value.await(self.io);
                return true;
            }

            fn deinit(self: *Waiters) void {
                for (self.tasks.values()) |*future| future.cancel(self.io);
                self.tasks.deinit(self.gpa);
                self.* = undefined;
            }
        };

        /// Aborts one buffer waiter (commonware's `Aborter` from `AbortablePool::push`).
        pub const Aborter = struct {
            waiters: *Waiters,
            id: u64,

            pub fn abort(self: *Aborter) void {
                self.waiters.cancel(self.id);
            }
        };
    };
}

test {
    _ = @import("actor_test.zig");
}
