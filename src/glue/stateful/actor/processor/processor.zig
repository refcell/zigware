//! The processor's build and finalization paths (commonware
//! `glue/src/stateful/actor/processor/mod.rs`: `Processor::new`, `propose`, `cache_proposed`,
//! `boundary`, `redelivered`, `finalize`, and `Applied`).
//!
//! `Processor(P)` owns the application handle, the shared `Execution` (heap-allocated, since
//! flights and verifiers point at it), and the optional prune schedule. Beyond `Execution`'s
//! contract, `P.App` declares `Captured`, `capture(*App, io, Block.Context, *const Block,
//! *const Merkleized, Readers) !Captured`, and `finalized(*App, io, Block.Context, *const
//! Block, Captured, Readers) !void`. To build, it declares `Context` (the consensus context,
//! with a `round` field), `Input`, `propose(*App, io, Context, *Ancestry, Unmerkleized, Input)
//! !?Proposed(App)`, and optionally `prepare(...) !Handoff(Proposed(App))`; both take the
//! batches and the input.
//!
//! Commonware panics when a finalized block fails to reproduce its state; so does this port.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const consensus = @import("consensus");
const db = @import("../../db/mod.zig");
const execution_mod = @import("execution.zig");
const pruning = @import("pruning.zig");
const verifier_mod = @import("verifier.zig");

const ancestry_mod = consensus.marshal.ancestry;

/// `ProcessorOf` keyed by `P`'s `App`, `Databases`, and `Provider` only, so every `P` that
/// declares the same three (such as the core actor's, which adds `Recover`) shares one type.
/// A block the application built and its merkleized state (commonware `Proposed`).
pub fn Proposed(comptime App: type) type {
    return struct { block: App.Block, merkleized: App.Merkleized };
}

pub fn Processor(comptime P: type) type {
    return ProcessorOf(P.App, P.Databases, P.Provider);
}

fn ProcessorOf(comptime App_: type, comptime Databases_: type, comptime Provider_: type) type {
    const P = struct {
        pub const App = App_;
        pub const Databases = Databases_;
        pub const Provider = Provider_;
    };
    return struct {
        const Self = @This();
        pub const Execution = execution_mod.Execution(P);
        pub const App = P.App;
        pub const Databases = P.Databases;
        pub const Provider = P.Provider;
        pub const Digested = Execution.Digested;
        pub const Digest = Execution.Digest;
        pub const Anchor = Execution.Anchor;
        pub const SyncTargets = Databases.SyncTargets;
        pub const Pruning = pruning.Pruning(SyncTargets);
        pub const Prune = pruning.Prune(SyncTargets);
        pub const Boundary = Execution.State.Boundary;
        pub const Verifier = verifier_mod.Verifier(P);
        pub const Ancestry = Execution.Ancestry;
        pub const Built = Proposed(App);
        const Handoff = consensus.Handoff;

        /// The result of applying a finalized block (commonware `Applied`).
        pub const Applied = struct {
            /// A barrier covering the block, when the caller asked for one.
            barrier: ?db.Barrier,
            /// The prune that became due with this finalization.
            prune: ?Prune,
        };

        gpa: Allocator,
        app: App,
        execution: *Execution,
        pruning: ?Pruning,

        /// A processor whose `databases` hold the applied state of `anchor`.
        pub fn init(
            gpa: Allocator,
            io: Io,
            app: App,
            databases: Databases,
            anchor: Anchor,
            schedule: ?Pruning,
        ) Allocator.Error!Self {
            const execution = try gpa.create(Execution);
            execution.* = .init(gpa, io, databases, anchor);
            return .{ .gpa = gpa, .app = app, .execution = execution, .pruning = schedule };
        }

        /// Every flight must have been released. The databases stay with the caller.
        pub fn deinit(self: *Self) void {
            self.execution.deinit();
            self.gpa.destroy(self.execution);
            if (self.pruning) |*schedule| schedule.deinit(self.gpa);
            self.* = undefined;
        }

        /// A verifier sharing this processor's speculative state.
        pub fn verifier(self: *Self) Verifier {
            return .{ .app = self.app, .execution = self.execution };
        }

        pub fn branch_anchor(self: *Self) Anchor {
            return self.execution.branch_anchor();
        }

        pub fn flights_idle(self: *Self) bool {
            return self.execution.flights_idle();
        }

        /// The cached state that stays valid once `block` is finalized.
        pub fn boundary(self: *Self, block: *const Digested) !Boundary {
            const execution = self.execution;
            execution.mutex.lockUncancelable(execution.io);
            defer execution.mutex.unlock(execution.io);
            return execution.state.boundary(block.digest(), block.inner().context().round);
        }

        /// Builds on the parent at the head of `ancestry` through the application's `propose`
        /// and caches the state before answering. Null when the application builds nothing or
        /// the parent is neither cached nor the anchor. The caller runs no finalization
        /// meanwhile. Panics when the built state misses the block's commitments.
        pub fn propose(
            self: *Self,
            context: App.Context,
            ancestry: *Ancestry,
            input: App.Input,
        ) !?Digested {
            const parent = (ancestry.peek() orelse unreachable).digest(); // Recovered first.
            const batches = self.execution.fork_batches(parent) catch |err| switch (err) {
                error.Invalid => return null,
                else => |other| return other,
            };
            var app = self.app;
            const io = self.execution.io;
            const built = try app.propose(io, context, ancestry, batches, input) orelse return null;
            return try self.cache_proposed(context.round, parent, built);
        }

        /// Like `propose`, before the parent certifies: the block under the application's
        /// decision, or `.wait` (always, when the application has no `prepare`).
        pub fn prepare(
            self: *Self,
            context: App.Context,
            ancestry: *Ancestry,
            input: App.Input,
        ) !Handoff(Digested) {
            if (comptime !@hasDecl(App, "prepare")) {
                if (comptime @hasDecl(App, "deinit_input")) {
                    var dropped = input;
                    App.deinit_input(&dropped);
                }
                return .wait;
            }
            const parent = (ancestry.peek() orelse unreachable).digest();
            const batches = self.execution.fork_batches(parent) catch |err| switch (err) {
                error.Invalid => return .wait,
                else => |other| return other,
            };
            var app = self.app;
            const decision = try app.prepare(self.execution.io, context, ancestry, batches, input);
            const round = context.round;
            return switch (decision) {
                .wait => .wait,
                .vote => |built| .{ .vote = try self.cache_proposed(round, parent, built) },
                .stage => |built| .{ .stage = try self.cache_proposed(round, parent, built) },
            };
        }

        /// Caches a built block's state (taken) on `parent` and returns the block with its
        /// digest. Only a finalization discards `parent`'s state, and none runs during a build.
        fn cache_proposed(
            self: *Self,
            round: consensus.Round,
            parent: Digest,
            built: Built,
        ) !Digested {
            var merkleized = built.merkleized;
            const targets = App.sync_targets(&built.block);
            if (!Databases.matches_sync_targets(&merkleized, &targets)) {
                @panic("proposed state must match block commitments");
            }
            const block = Digested.compute(self.gpa, built.block) catch |err| {
                db.deinit_merkleized(Databases.Merkleized, &merkleized);
                return err;
            };
            errdefer block.discard();
            const entry: Execution.Entry = .{
                .round = round,
                .parent = parent,
                .merkleized = merkleized,
            };
            if (!try self.execution.cache_pending(block.digest(), entry)) {
                @panic("proposal parent must remain compatible until the proposal completes");
            }
            return block;
        }

        /// Whether `block` is at or below the branch anchor's height. A different block at the
        /// anchor's height is a conflicting finalization (commonware panics).
        pub fn redelivered(self: *Self, block: *const Digested) bool {
            const anchor = self.branch_anchor();
            const height = block.inner().height().get();
            if (height == anchor.height.get()) {
                if (!std.meta.eql(block.digest(), anchor.digest)) {
                    @panic("received conflicting finalized block at anchor height");
                }
            }
            return height <= anchor.height.get();
        }

        /// The finalized block's state: its cached batch, or its reproduction on the applied
        /// state (the winner's parent is the applied state, since finalizations arrive in
        /// height order).
        fn finalized_batch(
            self: *Self,
            provider: *const Provider,
            block: *const Digested,
            targets: *const SyncTargets,
        ) !Databases.Merkleized {
            const execution = self.execution;
            {
                execution.mutex.lockUncancelable(execution.io);
                defer execution.mutex.unlock(execution.io);
                if (execution.flights.contains(block.digest())) {
                    @panic("finalized block must not be processed when its finalization starts");
                }
                if (execution.state.get(block.digest())) |entry| {
                    return db.clone_merkleized(Databases.Merkleized, &entry.merkleized);
                }
            }
            const batches = try execution.databases.new_batches();
            var ancestry = try execution.stream(provider, &.{block.clone()});
            defer ancestry.deinit();
            var app = self.app;
            const context = block.inner().context();
            const processed = app.process(execution.io, context, &ancestry, batches, .finalized);
            var batch = try processed orelse
                @panic("finalize reconstruction must process the block");
            if (!Databases.matches_sync_targets(&batch, targets)) {
                db.deinit_merkleized(Databases.Merkleized, &batch);
                @panic("finalize reconstruction must match block commitments");
            }
            return batch;
        }

        /// Applies the next finalized `block` and discards cached state that does not descend
        /// from it. The caller lets every execution step outside `boundary(block)` finish first
        /// and admits no request until this returns. With `start_barrier`, the result holds a
        /// barrier covering `block` and every earlier applied block.
        pub fn finalize(
            self: *Self,
            provider: *const Provider,
            block: *const Digested,
            start_barrier: bool,
        ) !Applied {
            const inner = block.inner();
            const anchor = self.branch_anchor();
            const finalized: Anchor = .{
                .height = inner.height(),
                .round = inner.context().round,
                .digest = block.digest(),
            };
            assert(finalized.height.get() == anchor.height.get() + 1);
            assert(std.meta.eql(inner.parent(), anchor.digest));

            const targets = App.sync_targets(inner);
            var batch = try self.finalized_batch(provider, block, &targets);
            defer db.deinit_merkleized(Databases.Merkleized, &batch);
            const execution = self.execution;
            _ = try execution.retain_branch(finalized, inner.parent(), &batch);

            var app = self.app;
            const io = execution.io;
            const context = inner.context();
            const databases = execution.databases;
            const captured = try app.capture(io, context, inner, &batch, databases.readers());
            try databases.apply(&batch);
            const barrier: ?db.Barrier = if (start_barrier) try databases.finalize() else null;
            try app.finalized(io, context, inner, captured, databases.readers());
            const prune = if (self.pruning) |*schedule|
                schedule.observe(finalized.height, targets)
            else
                null;

            execution.mutex.lockUncancelable(io);
            const retained = execution.state.remove(finalized.digest);
            execution.mutex.unlock(io);
            // The finalized root stays cached through its hook, so retained requests fork from it.
            assert(retained);
            return .{ .barrier = barrier, .prune = prune };
        }
    };
}
