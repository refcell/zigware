//! The `Stateful` actor's syncing mode (commonware `glue/src/stateful/actor/core/syncing.rs`).
//!
//! `Syncing(P)` serves the actor's mailbox while state sync runs in its `Syncer`: proposals are
//! declined, verifications deferred, and finalized blocks retained with their marshal
//! acknowledgements. Once marshal's pending acknowledgement window is full, the window's newest
//! block becomes the sync target and every retained block is acknowledged. When the syncer
//! publishes its artifact, the retained blocks are classified against its anchor: those at or
//! below it are already in the synced state and are acknowledged at once; those above it are
//! applied through a new `Processor`, and acknowledged after one barrier covers them all.
//! Completion is then recorded in the plan, a due prune runs, the databases are attached to
//! their resolvers, and database subscribers receive them.
//!
//! `run` returns the `Ready` state processing continues from (commonware moves straight into
//! `Processing`): the processor, its databases, and the deferred verifications. `P` declares
//! `App`, `Databases`, `Provider` (the processor's block provider), `Marshal` (`get_anchor`,
//! `get_block`, `subscribe_by_commitment`, `prune`, and `clone`), `Plan` (a `SyncPlan`), and
//! `Resolvers` (see `state_sync.attach_databases`; the syncer fetches through it too).
//!
//! Errors where commonware panics: `MarshalWindowExceeded` (marshal delivered more blocks than
//! its window), `ConflictingAnchor`, `ConflictingDuplicate`, and `SkippedHeight` (retained
//! blocks that do not extend the sync anchor), and the syncer's own error when it stops before
//! publishing.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const consensus = @import("consensus");
const runtime = @import("runtime");
const utils = @import("utils");
const db = @import("../../db/mod.zig");
const state_sync = @import("../../db/state_sync.zig");
const processing_mod = @import("processing.zig");
const syncer_mod = @import("../syncer/actor.zig");

const Height = consensus.Height;
const Floor = consensus.marshal.core.Floor;
const Exact = utils.acknowledgement.Exact;
const oneshot = utils.channel.oneshot;
const metrics = runtime.telemetry.metrics;

/// Errors where commonware panics.
pub const Error = error{
    MarshalWindowExceeded,
    ConflictingAnchor,
    ConflictingDuplicate,
    SkippedHeight,
};

/// The subset of commonware's `StatefulMetrics` syncing updates: `sync_done` is set once
/// completion is recorded.
pub const Metrics = struct {
    sync_done: ?metrics.Gauge = null,
};

/// How a retained finalization relates to the converged sync anchor.
pub const Handoff = enum {
    /// Below the anchor: acknowledged without application hooks.
    covered,
    /// At the anchor: acknowledged without application hooks.
    reflected,
    /// Above the anchor, or a duplicate report of one: applied once, acknowledged after the
    /// handoff barrier.
    apply,
};

/// A finalized block retained with its marshal acknowledgement while state sync runs.
pub fn PendingFinalization(comptime B: type) type {
    return struct {
        block: B,
        /// Null once acknowledged.
        acknowledgement: ?Exact,
        handoff: Handoff = .apply,

        /// Acknowledges the block to marshal.
        pub fn acknowledge(self: *@This()) void {
            var acknowledgement = self.acknowledgement.?;
            self.acknowledgement = null;
            acknowledgement.acknowledge();
        }

        pub fn deinit(self: *@This()) void {
            if (self.acknowledgement) |*acknowledgement| acknowledgement.deinit();
            if (comptime @hasDecl(B, "deinit")) self.block.deinit();
            self.* = undefined;
        }
    };
}

/// Sorts `finalized` by height and classifies each block against `anchor` (commonware
/// `classify`). A live floor change can redeliver a suffix, so a block above the anchor may
/// appear more than once; every copy is `apply`. Fails when the block at the anchor's height
/// has another digest, a duplicate differs from its original, or a block skips a height.
pub fn classify(
    comptime B: type,
    anchor: syncer_mod.AnchorOf(B),
    finalized: []PendingFinalization(B),
) Error!void {
    const Less = struct {
        fn less(_: void, a: PendingFinalization(B), b: PendingFinalization(B)) bool {
            return height_of(&a.block) < height_of(&b.block);
        }
    };
    std.sort.pdq(PendingFinalization(B), finalized, {}, Less.less);
    var previous = anchor;
    for (finalized) |*pending| {
        const height = height_of(&pending.block);
        const digest = pending.block.digest();
        if (height < anchor.height.get()) {
            pending.handoff = .covered;
        } else if (height == anchor.height.get()) {
            if (!std.meta.eql(digest, anchor.digest)) return error.ConflictingAnchor;
            pending.handoff = .reflected;
        } else if (height == previous.height.get()) {
            if (!std.meta.eql(digest, previous.digest)) return error.ConflictingDuplicate;
            pending.handoff = .apply;
        } else {
            if (height != previous.height.get() + 1) return error.SkippedHeight;
            previous = syncer_mod.anchor_of(&pending.block);
            pending.handoff = .apply;
        }
    }
}

fn height_of(block: anytype) u64 {
    return syncer_mod.inner_of(block).height().get();
}

pub fn Syncing(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const App = P.App;
        pub const Databases = P.Databases;
        pub const Marshal = P.Marshal;
        const Q = struct {
            pub const App = P.App;
            pub const Databases = P.Databases;
            pub const Provider = P.Provider;
            pub const Marshal = P.Marshal;
        };
        pub const Processing = processing_mod.Processing(Q);
        pub const Processor = Processing.Processor;
        pub const Message = Processing.Message;
        pub const Receiver = Processing.Receiver;
        pub const VerificationRequest = Processing.Mailbox.VerificationRequest;
        pub const Block = Processor.Digested;
        pub const Pending = PendingFinalization(Block);
        const SyncerP = struct {
            pub const App = P.App;
            pub const Databases = P.Databases;
            pub const Resolvers = P.Resolvers;
            pub const Marshal = P.Marshal;
            pub const Finalization = P.Plan.Finalization;
            /// The standard variant's commitment is the block digest.
            pub fn commitment(block: *const Block) P.App.Block.Digest {
                return block.digest();
            }
        };
        pub const Syncer = syncer_mod.Syncer(SyncerP, db.Env);
        pub const Artifact = Syncer.Artifact;

        /// The state processing continues from, owned by the caller: deinit the processor,
        /// then the databases; schedule each deferred verification.
        pub const Ready = struct {
            processor: Processor,
            databases: Databases,
            deferred: std.ArrayList(VerificationRequest),
        };

        pub const Config = struct {
            app: App,
            /// The environment the synced databases open in.
            env: db.Env,
            db_config: Databases.Config,
            sync_config: state_sync.SyncEngineConfig,
            resolvers: P.Resolvers,
            /// Borrowed: the actor's mailbox receiver.
            receiver: *Receiver,
            /// Borrowed for the syncer's and the handoff's lifetime.
            marshal: Marshal,
            /// Marshal's durable floor returned with its mailbox.
            floor: Floor,
            /// Borrowed; it holds the selected floor.
            plan: *P.Plan,
            /// The replay provider the handoff applies blocks with (taken).
            provider: P.Provider,
            /// Taken by the processor.
            pruning: ?Processor.Pruning = null,
            /// Marshal's pending acknowledgement window.
            max_pending_acks: u64,
            metrics: Metrics = .{},
        };

        const Wake = union(enum) {
            artifact: oneshot.RecvError!Artifact,
            message: Io.Cancelable!?Message,
        };

        gpa: Allocator,
        io: Io,
        config: Config,
        syncer: Syncer.Mailbox,
        /// The syncer task `init` started; null when `assemble`d around another syncer.
        syncer_task: ?Io.Future(anyerror!void),
        completion: oneshot.Receiver(Artifact),
        deferred: std.ArrayList(VerificationRequest) = .empty,
        subscribers: std.ArrayList(oneshot.Sender(Databases)) = .empty,
        pending: std.ArrayList(Pending) = .empty,
        /// Set once the artifact's databases moved to `Ready`.
        handed_off: bool = false,

        /// Starts the syncer from the plan's floor (commonware's `sync` startup path).
        pub fn init(config: Config) !Self {
            assert(config.max_pending_acks > 0);
            const finalization = config.plan.floor() orelse unreachable; // Syncing needs one.
            const gpa = config.env.gpa;
            const io = config.env.io;
            var completion = try oneshot.channel(Artifact, gpa, io);
            errdefer completion.receiver.deinit();
            const created = Syncer.create(.{
                .env = config.env,
                .db_config = config.db_config,
                .sync_config = config.sync_config,
                .resolvers = config.resolvers,
                .finalization = finalization,
                .marshal = config.marshal,
                .floor = config.floor,
                .completion = completion.sender,
            }) catch |err| {
                completion.sender.deinit();
                return err;
            };
            const task = created.syncer.start() catch |err| {
                created.syncer.destroy();
                var mailbox = created.mailbox;
                mailbox.deinit();
                return err;
            };
            var self = assemble(config, created.mailbox, completion.receiver);
            self.syncer_task = task;
            return self;
        }

        /// A syncing actor around `syncer` and the `completion` its artifact arrives on, with
        /// no syncer task of its own (commonware's tests build `Syncing` this way). Takes both.
        pub fn assemble(
            config: Config,
            syncer: Syncer.Mailbox,
            completion: oneshot.Receiver(Artifact),
        ) Self {
            assert(config.max_pending_acks > 0);
            assert(config.plan.floor() != null);
            return .{
                .gpa = config.env.gpa,
                .io = config.env.io,
                .config = config,
                .syncer = syncer,
                .syncer_task = null,
                .completion = completion,
            };
        }

        /// Stops the syncer and releases every retained request unanswered.
        pub fn deinit(self: *Self) void {
            self.syncer.deinit();
            if (self.syncer_task) |*task| _ = task.cancel(self.io) catch {};
            if (self.completion.try_recv()) |artifact| {
                // Published but never handed off.
                if (!self.handed_off) {
                    var databases = artifact.databases;
                    databases.deinit();
                }
            } else |_| {}
            self.completion.deinit();
            for (self.deferred.items) |*request| release_verification(request);
            self.deferred.deinit(self.gpa);
            for (self.subscribers.items) |*subscriber| subscriber.deinit();
            self.subscribers.deinit(self.gpa);
            for (self.pending.items) |*pending| pending.deinit();
            self.pending.deinit(self.gpa);
            if (self.config.pruning) |*schedule| schedule.deinit(self.gpa);
            if (comptime @hasDecl(P.Provider, "deinit")) self.config.provider.deinit();
            self.* = undefined;
        }

        fn release_verification(request: *VerificationRequest) void {
            request.ancestry.deinit();
            request.verification.deinit();
        }

        /// Serves the mailbox until state sync converges and hands off: the processing state,
        /// or null when the mailbox closed or the task was cancelled first.
        pub fn run(self: *Self) !?Ready {
            var buffer: [2]Wake = undefined;
            var select: Io.Select(Wake) = .init(self.io, &buffer);
            defer while (select.cancel()) |rest| self.discard(rest);
            try select.concurrent(.artifact, recv_artifact, .{&self.completion});
            try select.concurrent(.message, recv_message, .{self.config.receiver});
            while (true) {
                const wake = select.await() catch return null;
                const artifact = switch (wake) {
                    .artifact => |result| result catch |err| switch (err) {
                        error.Canceled => return null,
                        // The syncer stopped before publishing: report why.
                        error.Closed => return self.syncer_failure(),
                    },
                    .message => |result| artifact: {
                        const message = (result catch return null) orelse return null;
                        const handoff = try self.handle(message);
                        try select.concurrent(.message, recv_message, .{self.config.receiver});
                        break :artifact handoff orelse continue;
                    },
                };
                // Proof: the artifact's handles are the completion's; a later completion wake
                // carries the same handles, and `discard` releases it only on shutdown.
                self.handed_off = true;
                try classify(Block, artifact.anchor, self.pending.items);
                return try self.transition(artifact);
            }
        }

        fn syncer_failure(self: *Self) anyerror {
            var task = self.syncer_task orelse return error.SyncerStopped;
            self.syncer_task = null;
            task.await(self.io) catch |err| return err;
            return error.SyncerStopped;
        }

        fn recv_artifact(completion: *oneshot.Receiver(Artifact)) oneshot.RecvError!Artifact {
            return completion.recv();
        }

        fn recv_message(receiver: *Receiver) Io.Cancelable!?Message {
            return receiver.recv();
        }

        fn discard(self: *Self, wake: Wake) void {
            switch (wake) {
                .artifact => |result| if (result) |artifact| {
                    if (self.handed_off) return;
                    var databases = artifact.databases;
                    databases.deinit();
                } else |_| {},
                .message => |result| if (result catch null) |message| Message.discard(message),
            }
        }

        /// Handles one mailbox message; the artifact when a retarget found sync converged.
        fn handle(self: *Self, message: Message) !?Artifact {
            switch (message) {
                .propose => |request| {
                    var owned = request;
                    owned.decline(); // State sync in progress.
                },
                .verify => |request| {
                    self.retain_live();
                    var owned = request;
                    self.deferred.append(self.gpa, owned) catch |err| {
                        release_verification(&owned);
                        return err;
                    };
                },
                .finalized => |value| return self.finalized(value.block, value.acknowledgement),
                .subscribe_databases => |sender| {
                    self.retain_live();
                    var owned = sender;
                    if (owned.is_closed()) {
                        owned.deinit();
                        return null;
                    }
                    self.subscribers.append(self.gpa, owned) catch |err| {
                        owned.deinit();
                        return err;
                    };
                },
            }
            return null;
        }

        /// Drops cancelled verifications and closed database subscribers.
        fn retain_live(self: *Self) void {
            var kept: usize = 0;
            for (self.deferred.items) |*request| {
                if (request.verification.is_closed()) {
                    release_verification(request);
                } else {
                    self.deferred.items[kept] = request.*;
                    kept += 1;
                }
            }
            self.deferred.shrinkRetainingCapacity(kept);
            kept = 0;
            for (self.subscribers.items) |*subscriber| {
                if (subscriber.is_closed()) {
                    subscriber.deinit();
                } else {
                    self.subscribers.items[kept] = subscriber.*;
                    kept += 1;
                }
            }
            self.subscribers.shrinkRetainingCapacity(kept);
        }

        /// Retains `block` with its acknowledgement; once marshal's window is full, records its
        /// newest block as the sync target and acknowledges every retained block. Returns the
        /// artifact when state sync finished first.
        pub fn finalized(self: *Self, block: Block, acknowledgement: Exact) !?Artifact {
            var pending: Pending = .{ .block = block, .acknowledgement = acknowledgement };
            self.pending.append(self.gpa, pending) catch |err| {
                pending.deinit();
                return err;
            };
            const window = self.config.max_pending_acks;
            if (self.pending.items.len < window) return null;
            if (self.pending.items.len > window) return error.MarshalWindowExceeded;
            const newest = &self.pending.items[self.pending.items.len - 1].block;
            const anchor = syncer_mod.anchor_of(newest);
            const targets = App.sync_targets(syncer_mod.inner_of(newest));
            if (try self.syncer.retarget(anchor, targets)) |artifact| return artifact;
            for (self.pending.items) |*retained| {
                retained.acknowledge();
                retained.deinit();
            }
            self.pending.clearRetainingCapacity();
            return null;
        }

        /// Applies the retained blocks above the anchor (classified by `classify`), records
        /// completion, and hands the databases to resolvers and subscribers (commonware
        /// `transition`). Takes the artifact's databases.
        pub fn transition(self: *Self, artifact: Artifact) !Ready {
            const config = &self.config;
            const schedule = config.pruning;
            config.pruning = null; // The processor owns the schedule now.
            const databases = artifact.databases;
            var processor = try Processor.init(
                self.gpa,
                self.io,
                config.app,
                databases,
                artifact.anchor,
                schedule,
            );
            errdefer processor.deinit();
            const applied = try self.apply_handoffs(&processor, artifact.anchor.height);
            // Completion is an irreversible startup floor: persist it only once every handoff
            // through it is durable, and before pruning or exposing the databases.
            try config.plan.set_completed(applied.completed);
            if (config.metrics.sync_done) |gauge| _ = gauge.metric().set(1);
            if (applied.prune) |prune| {
                try databases.prune(&prune.qmdb_target);
                try config.marshal.prune(prune.marshal_height);
            }
            // Attach the databases to peer resolvers before giving subscribers access.
            try state_sync.attach_databases(config.resolvers, databases);
            for (self.subscribers.items) |*subscriber| {
                subscriber.send(databases) catch {}; // The subscriber left.
            }
            self.subscribers.clearRetainingCapacity();
            const deferred = self.deferred;
            self.deferred = .empty;
            return .{ .processor = processor, .databases = databases, .deferred = deferred };
        }

        const Applied = struct { completed: Height, prune: ?Processor.Prune };

        /// Acknowledges covered and reflected blocks, applies the rest once each, and
        /// acknowledges those after one barrier makes the applied suffix durable.
        fn apply_handoffs(self: *Self, processor: *Processor, anchor: Height) !Applied {
            var result: Applied = .{ .completed = anchor, .prune = null };
            var applied_count: usize = 0;
            for (self.pending.items) |*pending| {
                if (pending.handoff != .apply) {
                    pending.acknowledge();
                    continue;
                }
                applied_count += 1;
                if (processor.redelivered(&pending.block)) continue;
                const provider = &self.config.provider;
                const outcome = try processor.finalize(provider, &pending.block, false);
                assert(outcome.barrier == null);
                if (outcome.prune) |prune| result.prune = prune;
                result.completed = syncer_mod.inner_of(&pending.block).height();
            }
            if (applied_count > 0) {
                var barrier = try processor.execution.databases.finalize();
                try barrier.durable();
            }
            for (self.pending.items) |*pending| {
                if (pending.handoff == .apply) pending.acknowledge();
                pending.deinit();
            }
            self.pending.clearRetainingCapacity();
            return result;
        }
    };
}

test {
    std.testing.refAllDecls(@This());
}
