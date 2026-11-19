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
//! Not yet ported: startup from a persisted state sync floor (commonware's `sync` path, the
//! `Syncing` mode and the syncer actor) waits on the db state sync engines, so `run` fails with
//! `error.StateSyncUnavailable` when the plan holds a floor. Attaching the databases to the
//! state sync resolvers is likewise left to the caller for now.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const consensus = @import("consensus");
const db = @import("../../db/mod.zig");
const pruning = @import("../processor/pruning.zig");
const processing_mod = @import("processing.zig");

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

        pub fn subscribe_parent(self: *const Self, child: anytype) !M.ParentReceiver {
            return self.marshal.subscribe_parent(child);
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
            if (self.config.plan.floor() != null) return error.StateSyncUnavailable;
            return self.recover();
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
            const provider: Provider = .{ .marshal = config.marshal.clone() };
            var processing: Processing = .init(
                self.gpa,
                self.io,
                &self.receiver,
                provider,
                config.marshal,
                &processor,
            );
            defer processing.deinit();
            return processing.run();
        }
    };
}
