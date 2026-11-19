//! The `Stateful` actor (commonware `glue/src/stateful/actor/core/mod.rs`).
//!
//! `Stateful(P)` keeps speculative and finalized state for an application. Consensus and marshal
//! reach it through its `Mailbox` (the marshal application and finalized-block `Reporter`).
//! `start` runs the actor as a concurrent task: it recovers from marshal, opening the database
//! set at the processed block's commitments and recording completion in the `SyncPlan`, then
//! serves requests through `Processing` until the mailbox closes or the task is cancelled.
//! Messages sent before recovery completes wait in the mailbox, in order.
//!
//! `P` declares `App` (see `Processor`), `Databases` (with `open(env, config, ?SyncTargets)`),
//! `Marshal` (marshal's core mailbox, or a type with its `get_anchor`, `get_block`, `get_info`,
//! `subscribe_parent`, `prune`, `clone`, and `deinit`), and `Plan` (`SyncPlan(S, V)`).
//! Marshal's blocks are the standard variant's `Digested(App.Block)`.
//!
//! With a persisted floor in the plan, the actor first runs state sync toward it (commonware's
//! `sync` path): `Syncing` declines proposals, defers verifications, and retains finalized
//! blocks until the synced state is handed off, then processing continues from it. That needs
//! `P.Resolvers` (see `db.state_sync.attach_databases`) and the Config's `sync_config`,
//! `resolvers`, and marshal's `floor`; without them a floor fails with
//! `error.StateSyncUnavailable`. Marshal then also needs `subscribe_by_commitment`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const consensus = @import("consensus");
const db = @import("../../db/mod.zig");
const pruning = @import("../processor/pruning.zig");
const processing_mod = @import("processing.zig");
const syncing_mod = @import("syncing.zig");
const state_sync = @import("../../db/state_sync.zig");

const Height = consensus.Height;

/// The replay block provider over marshal's mailbox: parents by subscription, finalized
/// digests by height.
pub fn MarshalProvider(comptime M: type) type {
    return struct {
        const Self = @This();
        pub const Block = M.Block;

        marshal: M,

        pub fn clone(self: *const Self) Self {
            return .{ .marshal = self.marshal.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.marshal.deinit();
            self.* = undefined;
        }

        pub fn subscribe_parent(
            self: *const Self,
            child: anytype,
            bound: anytype,
        ) !M.ParentReceiver {
            return self.marshal.subscribe_parent(child, bound);
        }

        /// The finalized block's digest at `at`, if marshal knows it.
        pub fn canonical_digest(self: *const Self, at: Height) !?Block.Digest {
            const info = try self.marshal.get_info(.{ .height = at }) orelse return null;
            assert(info.height.get() == at.get());
            return info.digest;
        }
    };
}

pub fn Stateful(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const App = P.App;
        pub const Databases = P.Databases;
        pub const Marshal = P.Marshal;
        pub const Plan = P.Plan;
        pub const Provider = MarshalProvider(Marshal);
        const Q = struct {
            pub const App = P.App;
            pub const Databases = P.Databases;
            pub const Provider = MarshalProvider(P.Marshal);
            pub const Marshal = P.Marshal;
        };
        pub const Processing = processing_mod.Processing(Q);
        pub const Processor = Processing.Processor;
        pub const Mailbox = Processing.Mailbox;
        pub const Message = Processing.Message;
        const SyncTargets = Databases.SyncTargets;
        const has_sync = @hasDecl(P, "Resolvers");
        pub const Resolvers = if (has_sync) P.Resolvers else void;
        const SyncP = struct {
            pub const App = P.App;
            pub const Databases = P.Databases;
            pub const Provider = MarshalProvider(P.Marshal);
            pub const Marshal = P.Marshal;
            pub const Plan = P.Plan;
            pub const Resolvers = Self.Resolvers;
        };
        pub const Syncing = syncing_mod.Syncing(SyncP);

        pub const Config = struct {
            /// The inner application (copied into each call).
            app: App,
            /// Storage, metrics, and runtime for the database set.
            env: db.Env,
            db_config: Databases.Config,
            /// Taken: the actor owns this mailbox handle.
            marshal: Marshal,
            /// Capacity of the actor's mailbox.
            mailbox_size: u32,
            /// The startup plan; marshal must start from its `marshal_start`. Borrowed.
            plan: *Plan,
            /// Periodic database and marshal pruning (none when null).
            prune_config: ?pruning.PruneConfig = null,
            /// Marshal's pending acknowledgement window (`max_pending_acks`).
            max_pending_acks: u64 = 1,
            /// Chooses the prune schedule's phase.
            random: ?std.Random = null,
            /// State sync (needed only when the plan holds a floor): engine tuning, the
            /// resolvers it fetches through and attaches the databases to, and the floor marshal
            /// returned at initialization. Resolvers also serve peers once the databases open,
            /// on either startup path. They borrow the databases, which the actor closes when it
            /// returns (commonware's resolvers hold `Arc` clones): stop them before the actor
            /// ends, as src/glue/stateful/tests/single_db.zig's `stateful_task` does.
            sync_config: ?state_sync.SyncEngineConfig = null,
            resolvers: ?Resolvers = null,
            floor: ?consensus.marshal.core.Floor = null,
        };

        gpa: Allocator,
        io: Io,
        config: Config,
        receiver: Processing.Receiver,
        pruning: ?Processor.Pruning,

        /// The actor (heap-allocated; it must not move) and its mailbox. The actor handles no
        /// message until `start`.
        pub fn init(gpa: Allocator, io: Io, config: Config) !struct { *Self, Mailbox } {
            assert(config.mailbox_size > 0);
            var schedule: ?Processor.Pruning = null;
            if (config.prune_config) |prune_config| {
                const source = config.random orelse return error.InvalidPruneConfig;
                const acks = config.max_pending_acks;
                schedule = try .random(gpa, prune_config, acks, source);
            }
            errdefer if (schedule) |*value| value.deinit(gpa);
            const pair = try actor.mailbox.new(Message, gpa, io, config.mailbox_size);
            const self = gpa.create(Self) catch |err| {
                var receiver = pair.receiver;
                receiver.deinit();
                var sender = pair.sender;
                sender.deinit();
                return err;
            };
            self.* = .{
                .gpa = gpa,
                .io = io,
                .config = config,
                .receiver = pair.receiver,
                .pruning = schedule,
            };
            return .{ self, Mailbox.init(gpa, io, pair.sender) };
        }

        /// Releases the actor once its task has ended (or it never started).
        pub fn deinit(self: *Self) void {
            self.receiver.deinit();
            if (self.pruning) |*schedule| schedule.deinit(self.gpa);
            self.config.marshal.deinit();
            const gpa = self.gpa;
            gpa.destroy(self);
        }

        /// Runs the actor as a concurrent task; await the future before `deinit`.
        pub fn start(self: *Self) Io.ConcurrentError!Io.Future(anyerror!void) {
            return self.io.concurrent(run, .{self});
        }

        /// Recovers from marshal and serves requests until the mailbox closes.
        pub fn run(self: *Self) anyerror!void {
            if (self.config.plan.floor() == null) return self.recover();
            if (comptime !has_sync) return error.StateSyncUnavailable;
            return self.sync();
        }

        /// The processed block marshal recovers from: its anchor, or the block at the recorded
        /// completion height when that is higher (commonware `syncer::open`). Owned.
        fn recovery_block(self: *Self) !Processor.Digested {
            const marshal = self.config.marshal;
            const anchor = try marshal.get_anchor();
            const completed = self.config.plan.completed() orelse Height.zero();
            const processed = if (anchor) |value| value.processed.height() else Height.zero();
            const height = if (completed.get() > processed.get()) completed else processed;
            if (anchor) |value| {
                if (value.processed.height().get() == height.get()) return value.block;
                var stale = value.block;
                stale.deinit();
            }
            const block = try marshal.get_block(.{ .height = height }) orelse
                @panic("marshal must return completed state sync block");
            assert(block.inner().height().get() == height.get());
            return block;
        }

        /// Opens the database set from marshal, records completion, then runs processing.
        fn recover(self: *Self) anyerror!void {
            var block = try self.recovery_block();
            defer block.deinit();
            const inner = block.inner();
            const targets: SyncTargets = App.sync_targets(inner);
            const config = &self.config;
            var databases = try Databases.open(config.env, config.db_config, targets);
            defer databases.deinit();
            try config.plan.set_completed(inner.height());
            // Serve the opened databases to syncing peers (commonware `recover`).
            if (comptime has_sync) {
                if (config.resolvers) |resolvers| {
                    try state_sync.attach_databases(resolvers, databases);
                }
            }
            const anchor: Processor.Anchor = .{
                .height = inner.height(),
                .round = inner.context().round,
                .digest = block.digest(),
            };
            const schedule = self.pruning;
            self.pruning = null; // The processor owns the schedule now.
            var processor = try Processor.init(
                self.gpa,
                self.io,
                config.app,
                databases,
                anchor,
                schedule,
            );
            defer processor.deinit();
            return self.process(&processor, &.{});
        }

        /// Runs processing over `processor`, first scheduling `deferred` (taken).
        fn process(
            self: *Self,
            processor: *Processor,
            deferred: []const Processing.Mailbox.VerificationRequest,
        ) anyerror!void {
            const provider: Provider = .{ .marshal = self.config.marshal.clone() };
            var processing: Processing = .init(
                self.gpa,
                self.io,
                &self.receiver,
                provider,
                self.config.marshal,
                processor,
            );
            defer processing.deinit();
            for (deferred) |request| processing.defer_verification(request);
            return processing.run();
        }

        /// Runs state sync toward the plan's floor, then processing from the synced state.
        fn sync(self: *Self) anyerror!void {
            const config = &self.config;
            const sync_config = config.sync_config orelse return error.StateSyncUnavailable;
            const resolvers = config.resolvers orelse return error.StateSyncUnavailable;
            const floor = config.floor orelse return error.StateSyncUnavailable;
            var schedule = self.pruning;
            self.pruning = null; // Syncing, then the processor, owns the schedule.
            var syncing = Syncing.init(.{
                .app = config.app,
                .env = config.env,
                .db_config = config.db_config,
                .sync_config = sync_config,
                .resolvers = resolvers,
                .receiver = &self.receiver,
                .marshal = config.marshal,
                .floor = floor,
                .plan = config.plan,
                .provider = .{ .marshal = config.marshal.clone() },
                .pruning = schedule,
                .max_pending_acks = config.max_pending_acks,
            }) catch |err| {
                if (schedule) |*value| value.deinit(self.gpa);
                return err;
            };
            defer syncing.deinit();
            var ready = try syncing.run() orelse return;
            defer ready.databases.deinit();
            defer ready.processor.deinit();
            defer ready.deferred.deinit(self.gpa);
            // `process` takes the requests; the list's deinit frees only its buffer. Clearing it
            // first would overwrite them (`clearRetainingCapacity` sets items undefined).
            const deferred = ready.deferred.items;
            return self.process(&ready.processor, deferred);
        }
    };
}
