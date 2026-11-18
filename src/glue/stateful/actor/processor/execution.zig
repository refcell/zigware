//! The processor's shared execution layer (commonware `glue/src/stateful/actor/processor/mod.rs`:
//! `Execution`, its flight registry, `fork_batches`, `process_candidate`, `prepare_replay`,
//! `next_replay`, and `rebuild_pending`).
//!
//! `Execution(P)` holds the database set and the speculative `Pending` state behind one mutex,
//! which the processor and its verifiers share. `P` declares:
//!
//! - `App`: the application, a cheap handle copied for each call (Rust `Clone`), with
//!   `App.Block` (a block with `Digest`, `digest`, `parent`, `height`, and `context()` whose
//!   `round` field is its consensus round), `App.sync_targets(*const Block) SyncTargets`, and
//!   `process(*App, io, Block.Context, *Ancestry, Unmerkleized, Finality) !?Merkleized`, which
//!   takes the batches. `Ancestry` is the type-erased `Boxed(Block)`.
//! - `Databases`: a database set (`db.Shared(T)` or `db.Tuple`).
//! - `Provider`: marshal's `BlockProvider` for `App.Block`.
//!
//! A flight is the candidate processing of one block. Concurrent requests for the block join
//! the same flight and share its result; the last request to leave cancels it if it is still
//! running and frees it. Commonware's `Shared` future becomes a task started with
//! `io.concurrent` that stores its result and sets an event. A flight leaves the registry when
//! it completes or when its last request leaves; a request admitted after that starts a fresh
//! flight, which the pending cache makes idempotent.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const boxed = @import("boxed.zig");
const pending_mod = @import("pending.zig");

const Height = consensus.types.Height;
const ancestry_mod = consensus.marshal.ancestry;

/// Whether `process` may rely on the block's finalization (commonware `Finality`).
pub const Finality = enum {
    /// Not known to be finalized: the block must pass every validity check.
    candidate,
    /// Finalized by the network: checks that do not affect the resulting state may be skipped.
    finalized,
};

/// Failures while acquiring or processing state for a request (commonware
/// `PrepareBatchesError`).
pub const PrepareBatchesError = error{
    /// The block or its ancestry is invalid.
    Invalid,
    /// Ancestry ended before the required state could be recovered.
    Incomplete,
};

pub fn Execution(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const App = P.App;
        pub const Databases = P.Databases;
        pub const Provider = P.Provider;
        pub const Block = App.Block;
        pub const Digest = Block.Digest;
        pub const Digested = broadcast.Digested(Block);
        pub const Ancestry = boxed.Boxed(Block);
        pub const Stream = ancestry_mod.AncestorStream(Provider);
        pub const State = pending_mod.Pending(Digest, Databases.Merkleized);
        pub const Anchor = State.Anchor;
        pub const Entry = State.Entry;
        const Flights = std.AutoHashMapUnmanaged(Digest, *Flight);

        gpa: Allocator,
        io: Io,
        databases: Databases,
        /// Guards `state` and `flights`; held only for short, non-blocking sections.
        mutex: Io.Mutex = .init,
        state: State,
        /// Live flights, at most one per digest.
        flights: Flights = .empty,

        /// Execution over `databases`, which hold the applied state of `anchor`.
        pub fn init(gpa: Allocator, io: Io, databases: Databases, anchor: Anchor) Self {
            return .{ .gpa = gpa, .io = io, .databases = databases, .state = .init(gpa, anchor) };
        }

        /// Every flight must have been released.
        pub fn deinit(self: *Self) void {
            assert(self.flights.count() == 0);
            self.flights.deinit(self.gpa);
            self.state.deinit();
            self.* = undefined;
        }

        fn lock(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
        }

        fn unlock(self: *Self) void {
            self.mutex.unlock(self.io);
        }

        pub fn branch_anchor(self: *Self) Anchor {
            self.lock();
            defer self.unlock();
            return self.state.branch;
        }

        pub fn pending_contains(self: *Self, digest: Digest) bool {
            self.lock();
            defer self.unlock();
            return self.state.contains(digest);
        }

        /// Whether no candidate processing is in flight.
        pub fn flights_idle(self: *Self) bool {
            self.lock();
            defer self.unlock();
            return self.flights.count() == 0;
        }

        /// Caches `entry` (taking it) as `digest`'s speculative state; see `Pending.cache`.
        pub fn cache_pending(self: *Self, digest: Digest, entry: Entry) Allocator.Error!bool {
            self.lock();
            defer self.unlock();
            return self.state.cache(digest, entry);
        }

        /// Caches a copy of `batch` as `anchor`'s state, discards cached state that does not
        /// descend from it, and makes it the branch anchor. Returns how many forks it pruned.
        pub fn retain_branch(self: *Self, anchor: Anchor, parent: Digest, batch: anytype) !u64 {
            self.lock();
            defer self.unlock();
            return self.state.retain_branch(anchor, parent, batch);
        }

        /// Batches forked from `parent`'s state: its cached state, or the applied databases
        /// when `parent` is the branch anchor (whose cached state wins while it finalizes).
        pub fn fork_batches(self: *Self, parent: Digest) !Databases.Unmerkleized {
            {
                self.lock();
                defer self.unlock();
                if (self.state.get(parent)) |entry| {
                    return Databases.fork_batches(&entry.merkleized);
                }
                if (!std.meta.eql(self.state.branch.digest, parent)) return error.Invalid;
            }
            return self.databases.new_batches();
        }

        /// Processes the first block of `ancestry` on its parent's state as a candidate and
        /// caches the result. `error.Invalid` when the parent cannot be forked, the application
        /// rejects the block, the state misses its commitments, or it can no longer be cached.
        pub fn process_candidate(self: *Self, app: App, ancestry: *Ancestry) !void {
            const block = ancestry.peek() orelse unreachable; // Flights start on their block.
            const digest = block.digest();
            const parent = block.inner().parent();
            const context = block.inner().context();
            const targets = App.sync_targets(block.inner());

            const batches = try self.fork_batches(parent);
            var application = app;
            var merkleized = try application.process(
                self.io,
                context,
                ancestry,
                batches,
                .candidate,
            ) orelse return error.Invalid;
            if (!Databases.matches_sync_targets(&merkleized, &targets)) {
                merkleized.deinit();
                return error.Invalid;
            }
            const entry: Entry = .{
                .round = context.round,
                .parent = parent,
                .merkleized = merkleized,
            };
            if (!try self.cache_pending(digest, entry)) return error.Invalid;
            assert(self.pending_contains(digest));
        }

        /// The candidate processing of one block, shared by the requests that joined it.
        pub const Flight = struct {
            execution: *Self,
            digest: Digest,
            app: App,
            ancestry: Ancestry,
            /// Requests holding the flight; guarded by the execution's mutex.
            joiners: u32 = 1,
            spawned: bool = false,
            done: Io.Event = .unset,
            /// Set before `done`.
            result: ?anyerror = null,
            future: Io.Future(void) = undefined,

            fn run(flight: *Flight) void {
                const execution = flight.execution;
                const result = execution.process_candidate(flight.app, &flight.ancestry);
                flight.ancestry.deinit();
                execution.lock();
                execution.unregister(flight);
                flight.result = if (result) |_| null else |err| err;
                execution.unlock();
                flight.done.set(execution.io);
            }

            /// Waits for the flight's result. The caller still releases the flight.
            pub fn wait(flight: *Flight) !void {
                try flight.done.wait(flight.execution.io);
                if (flight.result) |err| return err;
            }
        };

        /// Removes `flight` from the registry if it is still the digest's registered flight.
        /// The caller holds the mutex.
        fn unregister(self: *Self, flight: *Flight) void {
            const registered = self.flights.get(flight.digest) orelse return;
            if (registered != flight) return;
            const removed = self.flights.remove(flight.digest);
            assert(removed);
        }

        /// The candidate processing of the first block of `ancestry` (taken), or null when the
        /// block's state is cached or is the branch anchor. Joins the block's live flight, or
        /// starts one with its own copy of `app`. The caller releases a returned flight.
        pub fn join_flight(self: *Self, app: App, ancestry: Ancestry) !?*Flight {
            var owned = ancestry;
            const digest = (owned.peek() orelse unreachable).digest(); // Starts on its block.
            self.lock();
            if (std.meta.eql(self.state.branch.digest, digest) or self.state.contains(digest)) {
                self.unlock();
                owned.deinit();
                return null;
            }
            if (self.flights.get(digest)) |flight| {
                flight.joiners += 1;
                self.unlock();
                owned.deinit();
                return flight;
            }
            const flight = self.register(app, digest, owned) catch |err| {
                self.unlock();
                owned.deinit();
                return err;
            };
            self.unlock();
            flight.future = self.io.concurrent(Flight.run, .{flight}) catch |err| {
                // Requests that joined meanwhile see the failure as the flight's result.
                flight.ancestry.deinit();
                self.lock();
                self.unregister(flight);
                flight.result = err;
                self.unlock();
                flight.done.set(self.io);
                return flight;
            };
            flight.spawned = true;
            return flight;
        }

        /// Registers a new flight for `digest`. The caller holds the mutex.
        fn register(self: *Self, app: App, digest: Digest, ancestry: Ancestry) !*Flight {
            assert(!self.flights.contains(digest));
            const flight = try self.gpa.create(Flight);
            errdefer self.gpa.destroy(flight);
            flight.* = .{ .execution = self, .digest = digest, .app = app, .ancestry = ancestry };
            try self.flights.put(self.gpa, digest, flight);
            return flight;
        }

        /// Drops one request's hold on `flight`. The last one cancels a running flight, waits
        /// for it to stop, and frees it.
        pub fn release(self: *Self, flight: *Flight) void {
            self.lock();
            assert(flight.joiners > 0);
            flight.joiners -= 1;
            const last = flight.joiners == 0;
            // Unregister before unlocking: a request that found the flight between this unlock
            // and the task's own unregister would join a flight that is about to be freed.
            if (last) self.unregister(flight);
            self.unlock();
            if (!last) return;
            // Canceling a completed flight only joins its task.
            if (flight.spawned) flight.future.cancel(self.io);
            assert(flight.done.isSet());
            self.gpa.destroy(flight);
        }

        /// Awaits the candidate processing of the first block of `ancestry` (taken), or returns
        /// at once if its state is cached or is the branch anchor (commonware `process_shared`).
        pub fn process_shared(self: *Self, app: App, ancestry: Ancestry) !void {
            const flight = try self.join_flight(app, ancestry) orelse return;
            defer self.release(flight);
            return flight.wait();
        }

        /// Missing blocks between cached or applied state and a requested block.
        pub const ReplayPath = struct {
            /// Missing blocks, newest first, so the next block to process is last.
            blocks: std.ArrayList(Digested) = .empty,
            /// Parent of the next block to process.
            parent: Digested,

            pub fn deinit(path: *ReplayPath, gpa: Allocator) void {
                for (path.blocks.items) |*block| block.deinit();
                path.blocks.deinit(gpa);
                path.parent.deinit();
                path.* = undefined;
            }
        };

        /// Whether `digest` is the branch anchor or cached, and the branch anchor.
        fn known(self: *Self, digest: Digest) struct { bool, Anchor } {
            self.lock();
            defer self.unlock();
            const branch = self.state.branch;
            return .{ std.meta.eql(branch.digest, digest) or self.state.contains(digest), branch };
        }

        /// Collects the missing blocks between `target` (taken) and cached or applied state,
        /// without forking batches. `error.Invalid` when the walk reaches the anchor's height
        /// without meeting the anchor or the provider returns a block that is not the parent one
        /// height below; `error.Incomplete` when the provider stops before delivering a parent.
        pub fn prepare_replay(self: *Self, provider: *Provider, target: Digested) !ReplayPath {
            var path: ReplayPath = .{ .parent = target };
            errdefer path.deinit(self.gpa);
            const start_height = target.inner().height().get();
            // Each step moves one height down, and the walk stops at the anchor's height.
            while (true) {
                const cursor = &path.parent;
                const cursor_known, const anchor = self.known(cursor.digest());
                if (cursor_known) break;
                const cursor_height = cursor.inner().height();
                if (cursor_height.get() <= anchor.height.get()) return error.Invalid;
                assert(path.blocks.items.len < start_height);
                var parent = try fetch_parent(provider, cursor);
                errdefer parent.deinit();
                if (!ancestry_mod.has_contiguous_height(parent.inner().height(), cursor_height) or
                    !std.meta.eql(parent.digest(), cursor.inner().parent()))
                {
                    return error.Invalid;
                }
                try path.blocks.append(self.gpa, path.parent);
                path.parent = parent;
            }
            return path;
        }

        fn fetch_parent(provider: *Provider, child: *const Digested) !Digested {
            var receiver = try provider.subscribe_parent(child);
            defer receiver.deinit();
            return receiver.recv() catch |err| switch (err) {
                error.Closed => return error.Incomplete,
                else => |other| return other,
            };
        }

        /// A boxed stream over `initial` (taken; newest first) that fetches earlier ancestors
        /// from a copy of `provider`.
        pub fn stream(self: *Self, provider: *const Provider, initial: []const Digested) !Ancestry {
            const stream_provider = if (comptime @hasDecl(Provider, "clone"))
                provider.clone()
            else
                provider.*;
            const ancestry = Stream.init(self.gpa, self.io, stream_provider, initial, null);
            const owned = ancestry catch |err| {
                for (initial) |handle| handle.discard();
                return err;
            };
            return Ancestry.init(self.gpa, owned);
        }

        /// The ancestry of the next block on `path` (the block, then its parent), or null once
        /// the path is exhausted. Each block forks from the state of the one before it, so the
        /// caller processes a block before asking for the next.
        pub fn next_replay(self: *Self, provider: *const Provider, path: *ReplayPath) !?Ancestry {
            if (path.blocks.items.len == 0) return null;
            const block = path.blocks.getLast();
            const ancestry = try self.stream(provider, &.{ block.clone(), path.parent.clone() });
            _ = path.blocks.pop();
            path.parent.deinit();
            path.parent = block;
            return ancestry;
        }

        /// Restores the speculative state of `target` (taken) and its missing ancestors.
        pub fn rebuild_pending(self: *Self, app: App, provider: *Provider, target: Digested) !void {
            var path = try self.prepare_replay(provider, target);
            defer path.deinit(self.gpa);
            const steps = path.blocks.items.len;
            var processed: usize = 0;
            while (try self.next_replay(provider, &path)) |ancestry| : (processed += 1) {
                assert(processed < steps);
                try self.process_shared(app, ancestry);
            }
            assert(processed == steps);
        }
    };
}
