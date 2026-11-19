//! The `Stateful` actor's processing loop (commonware
//! `glue/src/stateful/actor/core/processing.rs`'s `Processing`).
//!
//! `Processing(P)` serves proposals, verifications, and finalizations against the live database
//! set until the mailbox closes or the actor's task is cancelled. Verifications run
//! concurrently through `Verifications`; a proposal first recovers its parent's state there,
//! then builds on the actor. While a build runs, new verifications start at once (one may
//! certify the parent the application waits for) and other messages queue in mailbox order.
//!
//! A finalization pauses the speculative requests it would invalidate, applies the block, and
//! holds marshal's acknowledgement until a database barrier covers it, so marshal's processed
//! height never passes durable state. At most one barrier is active: the loop waits on it
//! beside requests and the mailbox, and heights applied meanwhile wait for the next barrier,
//! so finalizations coalesce while a slow sync runs. A due prune waits for the active barrier,
//! then runs once queued work and the mailbox are empty, after every execution step finished.
//!
//! `P` declares `App`, `Databases`, `Provider` (the block provider for replays), and `Marshal`
//! (with `prune(Marshal, Height) !void`, as marshal's core mailbox).
//!
//! Errors: a database failure (a failed barrier, apply, or prune) is fatal and ends `run` with
//! the error; cancellation ends it with `error.Canceled`. Requests still queued are released
//! unanswered by `deinit` (no verdict, and marshal redelivers unacknowledged blocks).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const consensus = @import("consensus");
const utils = @import("utils");
const durability_mod = @import("durability.zig");
const mailbox_mod = @import("mailbox.zig");
const verifications_mod = @import("verifications.zig");
const processor_mod = @import("../processor/processor.zig");

const Height = consensus.Height;
const Exact = utils.acknowledgement.Exact;
const Durability = durability_mod.Durability;

/// `ProcessingOf` keyed by `P`'s `App`, `Databases`, `Provider`, and `Marshal` only, so the
/// actor and its syncing mode share one type.
pub fn Processing(comptime P: type) type {
    return ProcessingOf(.{ P.App, P.Databases, P.Provider, P.Marshal });
}

/// `key` is `{ App, Databases, Provider, Marshal }`.
fn ProcessingOf(comptime key: [4]type) type {
    const P = struct {
        pub const App = key[0];
        pub const Databases = key[1];
        pub const Provider = key[2];
        pub const Marshal = key[3];
    };
    return struct {
        const Self = @This();
        pub const Mailbox = mailbox_mod.Mailbox(P);
        pub const Message = Mailbox.Message;
        pub const ProposalRequest = Mailbox.ProposalRequest;
        pub const Receiver = actor.mailbox.Receiver(Message);
        pub const Marshal = P.Marshal;
        /// The handler's view of `P`: a recovered proposal is a `ProposalRequest`.
        const Q = struct {
            pub const App = P.App;
            pub const Databases = P.Databases;
            pub const Provider = P.Provider;
            pub const Recover = ProposalRequest;
        };
        pub const Processor = processor_mod.Processor(Q);
        pub const Verifications = verifications_mod.Verifications(Q);
        const Prune = Processor.Prune;
        const Digested = Processor.Digested;

        /// Work handled in order (commonware `Action`).
        pub const Action = union(enum) {
            message: Message,
            /// A proposal whose parent state has been recovered.
            build: ProposalRequest,

            fn discard(action: Action) void {
                var owned = action;
                switch (owned) {
                    .message => |message| Message.discard(message),
                    .build => |*request| request.deinit(),
                }
            }
        };

        gpa: Allocator,
        io: Io,
        receiver: *Receiver,
        provider: P.Provider,
        marshal: Marshal,
        processor: *Processor,
        verifications: Verifications,
        durability: Durability,
        /// Deferred messages and ready builds, in order.
        actions: std.Deque(Action) = .empty,
        pending_prune: ?Prune = null,

        /// A loop over `processor`'s state, fed by `receiver`. Both stay with the caller and
        /// must outlive the loop.
        pub fn init(
            gpa: Allocator,
            io: Io,
            receiver: *Receiver,
            provider: P.Provider,
            marshal: Marshal,
            processor: *Processor,
        ) Self {
            const copy = if (comptime @hasDecl(P.Provider, "clone")) provider.clone() else provider;
            return .{
                .gpa = gpa,
                .io = io,
                .receiver = receiver,
                .provider = provider,
                .marshal = marshal,
                .processor = processor,
                .verifications = .init(gpa, io, processor.verifier(), copy),
                .durability = .init(gpa, processor.branch_anchor().height),
            };
        }

        /// Releases every queued request unanswered and every pending acknowledgement
        /// unacknowledged.
        pub fn deinit(self: *Self) void {
            self.verifications.deinit();
            while (self.actions.popFront()) |action| action.discard();
            self.actions.deinit(self.gpa);
            self.durability.deinit();
            if (comptime @hasDecl(P.Provider, "deinit")) self.provider.deinit();
            self.* = undefined;
        }

        /// Schedules a verification that arrived before processing started (commonware
        /// `deferred_verifications`).
        pub fn defer_verification(self: *Self, request: Mailbox.VerificationRequest) void {
            self.verifications.schedule(.{ .verify = .{
                .ancestry = request.ancestry,
                .verification = request.verification,
            } });
        }

        /// Serves requests until the mailbox closes (returns) or the task is cancelled.
        pub fn run(self: *Self) !void {
            // The actor loop runs for the actor's lifetime; each pass handles one step.
            while (try self.tick()) {}
        }

        /// One pass of the loop; false once processing stops.
        fn tick(self: *Self) !bool {
            if (self.durability.settled()) try self.durability.complete();
            // A pending prune suppresses successor barriers.
            if (self.pending_prune == null and self.durability.needs_barrier()) {
                try self.start_barrier();
            }
            // Publish ready verdicts before admitting another action.
            self.complete_ready();
            const prune_needs_barrier =
                self.pending_prune != null and self.durability.needs_barrier();
            if (!prune_needs_barrier) {
                if (self.actions.popFront()) |action| {
                    try self.handle(action);
                    return true;
                }
                if (self.receiver.try_recv()) |message| {
                    try self.handle(.{ .message = message });
                    return true;
                } else |err| switch (err) {
                    error.Empty => {},
                    error.Disconnected => if (self.pending_prune == null) return false,
                }
            }
            if (self.pending_prune) |prune| {
                self.pending_prune = null;
                try self.run_prune(prune);
                return true;
            }
            return self.wait_idle();
        }

        /// Starts a barrier covering all applied state; the loop completes it once settled.
        fn start_barrier(self: *Self) !void {
            assert(self.durability.needs_barrier());
            const barrier = try self.processor.execution.databases.finalize();
            self.durability.set_barrier(barrier);
            assert(!self.durability.needs_barrier());
        }

        /// Handles every finished request phase and queues the builds they made ready.
        fn complete_ready(self: *Self) void {
            self.verifications.complete_ready();
            self.queue_builds();
        }

        fn queue_builds(self: *Self) void {
            const builds = &self.verifications.builds;
            for (builds.items) |request| {
                self.actions.pushBack(self.gpa, .{ .build = request }) catch {
                    var dropped = request;
                    dropped.deinit(); // Unanswered: the proposer reads no block.
                };
            }
            builds.clearRetainingCapacity();
        }

        /// Queues a message that arrived while other work was selected.
        fn queue(self: *Self, message: Message) void {
            self.actions.pushBack(self.gpa, .{ .message = message }) catch Message.discard(message);
        }

        const Wait = union(enum) {
            ready: Io.Cancelable!void,
            message: Io.Cancelable!?Message,
            barrier: Io.Cancelable!void,
        };

        /// Waits for a request phase to end or a message to arrive; false once the mailbox
        /// closes.
        fn wait_idle(self: *Self) !bool {
            var buffer: [3]Wait = undefined;
            var select: Io.Select(Wait) = .init(self.io, &buffer);
            try select.concurrent(.ready, Verifications.wait_ready, .{&self.verifications});
            select.concurrent(.message, Receiver.recv, .{self.receiver}) catch |err| {
                select.cancelDiscard();
                return err;
            };
            if (self.durability.barrier != null) {
                const settle = Durability.settle;
                select.concurrent(.barrier, settle, .{&self.durability}) catch |err| {
                    while (select.cancel()) |rest| self.absorb(rest);
                    return err;
                };
            }
            const first = select.await() catch |err| {
                while (select.cancel()) |rest| self.absorb(rest);
                return err;
            };
            while (select.cancel()) |rest| self.absorb(rest);
            switch (first) {
                .ready, .barrier => |result| try result, // The next pass completes it.
                .message => |result| {
                    const message = try result orelse return false;
                    self.queue(message);
                },
            }
            return true;
        }

        /// Keeps a message a cancelled receive already took.
        fn absorb(self: *Self, outcome: Wait) void {
            switch (outcome) {
                .ready, .barrier => {},
                .message => |result| {
                    const message = (result catch return) orelse return;
                    self.queue(message);
                },
            }
        }

        fn handle(self: *Self, action: Action) !void {
            switch (action) {
                .build => |request| try self.build(request),
                .message => |message| switch (message) {
                    .propose => |request| self.verifications.schedule(.{ .recover = request }),
                    .verify => |request| self.defer_verification(request),
                    .finalized => |value| try self.finalized(value.block, value.acknowledgement),
                    .subscribe_databases => |sender| {
                        var owned = sender;
                        // The set stays with the actor; a caller that left needs no answer.
                        owned.send(self.processor.execution.databases) catch {};
                    },
                },
            }
        }

        /// A build's answer, held until the build's watcher stops (it reads the proposal).
        const Built = union(enum) {
            none,
            block: Digested,
            handoff: Mailbox.Built,

            fn discard(built: Built) void {
                switch (built) {
                    .none => {},
                    .block => |block| block.discard(),
                    .handoff => |handoff| handoff.discard(),
                }
            }
        };

        const Building = union(enum) {
            built: Built,
            /// The proposer left (commonware drops the build's future).
            cancelled: Io.Cancelable!void,
            ready: Io.Cancelable!void,
            message: Io.Cancelable!?Message,
        };

        /// Builds a recovered proposal (taken) and answers it. Verifications keep starting and
        /// completing meanwhile; other messages and newly ready builds queue in order. A
        /// proposer that leaves cancels the build at once, so queued work is not held behind it.
        fn build(self: *Self, request: ProposalRequest) !void {
            var owned = request;
            if (owned.is_cancelled()) return owned.deinit();
            var buffer: [4]Building = undefined;
            var select: Io.Select(Building) = .init(self.io, &buffer);
            select.concurrent(.built, build_task, .{ self, &owned }) catch |err| {
                owned.deinit();
                return err;
            };
            var built: Built = .none;
            const outcome = self.await_build(&select, &owned, &built);
            // Stop the build, its watcher, and the receivers before answering: they read the
            // request. Each pass collects one of at most four tasks.
            while (select.cancel()) |rest| self.absorb_building(rest, &built);
            answer(&owned, built);
            return outcome;
        }

        fn await_build(
            self: *Self,
            select: *Io.Select(Building),
            owned: *ProposalRequest,
            built: *Built,
        ) !void {
            // Without a watcher the build only notices a departed proposer when it ends.
            select.concurrent(.cancelled, ProposalRequest.closed, .{owned}) catch {};
            try select.concurrent(.ready, Verifications.wait_ready, .{&self.verifications});
            try select.concurrent(.message, Receiver.recv, .{self.receiver});
            // Each pass handles one completion; the build's end or the proposer's departure
            // ends the loop.
            while (true) switch (try select.await()) {
                .built => |result| {
                    built.* = result;
                    return;
                },
                .cancelled => |result| return result,
                .ready => |result| {
                    try result;
                    self.complete_ready();
                    try select.concurrent(.ready, Verifications.wait_ready, .{&self.verifications});
                },
                .message => |result| {
                    // A closed mailbox stops receiving until the build finishes.
                    const message = try result orelse continue;
                    self.route_during_build(message);
                    try select.concurrent(.message, Receiver.recv, .{self.receiver});
                },
            };
        }

        fn route_during_build(self: *Self, message: Message) void {
            switch (message) {
                .verify => |request| self.defer_verification(request),
                else => self.queue(message),
            }
        }

        fn absorb_building(self: *Self, outcome: Building, built: *Built) void {
            switch (outcome) {
                .built => |result| {
                    assert(built.* == .none);
                    built.* = result;
                },
                .cancelled, .ready => {},
                .message => |result| {
                    const message = (result catch return) orelse return;
                    self.route_during_build(message);
                },
            }
        }

        /// Runs the application's build; an error (or cancellation) builds nothing. The build
        /// consumes the request's input; `answer` releases the rest.
        fn build_task(self: *Self, request: *ProposalRequest) Built {
            const processor = self.processor;
            switch (request.proposal) {
                .propose => {
                    const built = processor.propose(
                        request.context,
                        &request.ancestry,
                        request.upstream,
                    ) catch null;
                    return if (built) |block| .{ .block = block } else .none;
                },
                .prepare => {
                    const handoff = processor.prepare(
                        request.context,
                        &request.ancestry,
                        request.upstream,
                    ) catch return .none;
                    return .{ .handoff = .{ .handoff = handoff } };
                },
            }
        }

        /// Answers a built proposal (taken with `built`): nothing built drops the sender
        /// unsent, which the proposer reads as no block (`.wait` for a prepare).
        fn answer(request: *ProposalRequest, built: Built) void {
            request.ancestry.deinit();
            switch (request.proposal) {
                .propose => |*sender| switch (built) {
                    .block => |block| sender.send(block) catch block.discard(),
                    else => {
                        built.discard();
                        sender.deinit();
                    },
                },
                .prepare => |*sender| switch (built) {
                    .handoff => |handoff| sender.send(handoff) catch handoff.discard(),
                    else => {
                        built.discard();
                        sender.deinit();
                    },
                },
            }
            request.* = undefined;
        }

        /// Applies a finalized block (taken) and holds its acknowledgement (taken) until a
        /// barrier covers it. A redelivered block only waits for durability.
        fn finalized(self: *Self, block: Digested, acknowledgement: Exact) !void {
            var owned_block = block;
            defer owned_block.deinit();
            var owned_ack = acknowledgement;
            const height = owned_block.inner().height();
            if (self.processor.redelivered(&owned_block)) {
                return self.durability.record_duplicate(height, owned_ack);
            }
            const applied = applied: {
                errdefer owned_ack.deinit();
                const boundary = try self.processor.boundary(&owned_block);
                try self.verifications.pause(boundary);
                defer self.verifications.@"resume"();
                const start = self.durability.barrier == null;
                const result = try self.finalize_driven(&owned_block, start);
                // Steps that finished as the finalization ended still select their successors
                // under its boundary: a successor the finalized block made stale is rejected
                // unprocessed rather than admitted once admission reopens.
                self.complete_ready();
                break :applied result;
            };
            // Acknowledge once a barrier covers this height, so a restart replays the unsynced
            // suffix. `record` takes the acknowledgement, also on error.
            try self.durability.record(height, owned_ack);
            if (applied.barrier) |barrier| {
                self.durability.set_barrier(barrier);
            }
            if (applied.prune) |prune| self.pending_prune = prune;
        }

        const Finalizing = struct {
            processing: *Self,
            block: *const Digested,
            start_barrier: bool,
            /// Written by the task before it sets `finished`.
            outcome: ?anyerror!Processor.Applied = null,
            finished: std.atomic.Value(bool) = .init(false),

            fn run(finalizing: *Finalizing) void {
                const processing = finalizing.processing;
                finalizing.outcome = processing.processor.finalize(
                    &processing.provider,
                    finalizing.block,
                    finalizing.start_barrier,
                );
                finalizing.finished.store(true, .release);
                processing.verifications.interrupt();
            }
        };

        /// Finalizes `block` on another task while this one drives the speculative requests
        /// under the finalization's admission, as commonware polls them while its finalized
        /// hook runs: a retained request goes on to its next step, or is rejected when the
        /// finalized block makes that step stale, before the hook returns.
        fn finalize_driven(self: *Self, block: *const Digested, start: bool) !Processor.Applied {
            assert(self.verifications.admission == .finalizing);
            var finalizing: Finalizing = .{
                .processing = self,
                .block = block,
                .start_barrier = start,
            };
            var future = self.io.concurrent(Finalizing.run, .{&finalizing}) catch
                return self.processor.finalize(&self.provider, block, start);
            self.verifications.drive(&finalizing.finished) catch |err| {
                future.cancel(self.io);
                return err;
            };
            future.await(self.io);
            assert(finalizing.finished.load(.acquire));
            return finalizing.outcome.?;
        }

        /// Prunes the databases and marshal once every execution step has finished and a
        /// barrier covers the prune target.
        fn run_prune(self: *Self, prune: Prune) !void {
            // Pruning waits for the active barrier (it removes history a branch may read).
            if (self.durability.barrier != null) try self.durability.complete();
            try self.verifications.pause(null);
            defer self.verifications.@"resume"();
            assert(self.processor.flights_idle());
            if (!self.durability.covers(prune.barrier_height)) {
                assert(self.durability.needs_barrier());
                try self.start_barrier();
                try self.durability.complete();
                assert(self.durability.covers(prune.barrier_height));
            }
            try self.processor.execution.databases.prune(&prune.qmdb_target);
            try self.marshal.prune(prune.marshal_height);
        }
    };
}
