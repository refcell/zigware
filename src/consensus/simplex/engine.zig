//! The simplex engine (commonware `simplex/engine.rs`): wires the batcher, voter, and resolver
//! actors together over three network channels.
//!
//! `P` declares `Context` (a `runtime.Context`), `Scheme`, `Elector` (built; the caller keeps
//! it), `Blocker`, `Digest`, `Automaton` (a pointer to the automaton), `Relay`, `Reporter`,
//! `Strategy`, and the channel types `Sender` and `Receiver`. The engine runs under a
//! `runtime.Context`: each actor is a child task (`batcher`, `voter`, `resolver`), and the
//! engine stops them all once any of them stops or the engine's task is aborted.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const consensus_types = @import("../types.zig");
const config_mod = @import("config.zig");
const lookahead = @import("lookahead.zig");
const batcher = @import("actors/batcher/actor.zig");
const voter = @import("actors/voter/actor.zig");
const resolver = @import("actors/resolver/actor.zig");

/// The tracing target of the engine's events (commonware's module path).
const trace_target = "commonware_consensus::simplex::engine";

/// One network channel: a sender and a receiver (both owned by the engine once started).
pub fn Channel(comptime P: type) type {
    return struct { sender: P.Sender, receiver: P.Receiver };
}

pub fn Engine(comptime P: type) type {
    return struct {
        const Self = @This();

        const BatcherParams = struct {
            pub const Scheme = P.Scheme;
            pub const Digest = P.Digest;
            pub const Blocker = P.Blocker;
            pub const Reporter = P.Reporter;
            pub const Relay = P.Relay;
            pub const Strategy = P.Strategy;
            pub const Receiver = P.Receiver;
        };
        const VoterParams = struct {
            pub const Scheme = P.Scheme;
            pub const Elector = P.Elector;
            pub const Digest = P.Digest;
            pub const Blocker = P.Blocker;
            pub const Automaton = @typeInfo(P.Automaton).pointer.child;
            pub const Relay = P.Relay;
            pub const Reporter = P.Reporter;
            pub const Sender = P.Sender;
        };
        const ResolverParams = struct {
            pub const Scheme = P.Scheme;
            pub const Digest = P.Digest;
            pub const Blocker = P.Blocker;
            pub const Strategy = P.Strategy;
            pub const NetSender = P.Sender;
            pub const NetReceiver = P.Receiver;
        };
        const Ctx = P.Context;
        pub const Config = config_mod.Config(P);
        const Batcher = batcher.Actor(BatcherParams);
        const Voter = voter.Actor(VoterParams);
        const VoterError = @typeInfo(@typeInfo(@TypeOf(Voter.run)).@"fn".return_type.?)
            .error_union.error_set;
        /// A voter storage or I/O error ends the engine with that error (marshal's rule):
        /// zigware cannot contain a panicking task the way commonware's runtime does.
        pub const RunError = Ctx.SpawnError || VoterError;
        pub const RunResult = RunError!void;
        const Resolver = resolver.Actor(ResolverParams);

        gpa: Allocator,
        io: Io,
        /// A copy of the configured scheme; its owned data stays the caller's.
        scheme: P.Scheme,
        batcher: Batcher,
        batcher_mailbox: Batcher.Mailbox,
        voter: Voter,
        voter_mailbox: Voter.Mailbox,
        resolver: Resolver,
        resolver_mailbox: Resolver.Mailbox,
        /// Set when any actor stops.
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        stopped: bool = false,
        /// The voter's error, set before it marks the engine stopped.
        voter_failure: ?VoterError = null,

        /// Builds the actors on `ctx`'s allocator, runtime, and storage (commonware
        /// `Engine::new`). The engine must not move: actors borrow its scheme. Start it with
        /// `ctx.spawn(Engine.run, .{ engine, votes, certificates, backfill })`.
        pub fn init(self: *Self, ctx: Ctx, cfg: Config) !void {
            const gpa = ctx.gpa();
            const io = ctx.io();
            var rng: @import("actors/context.zig").IoRng = .{ .io = io };
            cfg.assert_valid(gpa, &rng);
            const skip_budget: u64 = switch (cfg.skip) {
                .disabled => 0,
                .enabled => |skip| skip.budget.resolve(cfg.scheme.participants().len()),
            };
            const terms = cfg.elector.terms();
            // Stall timeout must be greater than certification timeout.
            if (terms.stall_timeout) |stall| assert(stall.order(cfg.certification_timeout) == .gt);
            self.gpa = gpa;
            self.io = io;
            self.mutex = .init;
            self.condition = .init;
            self.stopped = false;
            self.voter_failure = null;
            self.scheme = cfg.scheme;
            self.batcher, self.batcher_mailbox = try Batcher.init(gpa, io, .{
                .scheme = &self.scheme,
                .blocker = cfg.blocker,
                .reporter = cfg.reporter,
                .track_historical_votes = cfg.track_historical_votes,
                .relay = cfg.relay,
                .strategy = cfg.strategy,
                .epoch = cfg.epoch,
                .mailbox_size = cfg.mailbox_size,
                .view_retention = cfg.view_retention,
                .skip = cfg.skip,
                .lookahead = .init(terms),
                .forward = cfg.forward,
                .floor = cfg.floor.view(),
                .scope = ctx.scope.child("batcher"),
            });
            errdefer self.batcher.deinit();
            self.voter, self.voter_mailbox = try Voter.init(gpa, io, .{
                .scheme = &self.scheme,
                .elector = cfg.elector,
                .blocker = cfg.blocker,
                .automaton = cfg.automaton,
                .relay = cfg.relay,
                .reporter = cfg.reporter,
                .floor = cfg.floor,
                .partition = cfg.partition,
                .epoch = cfg.epoch,
                .mailbox_size = cfg.mailbox_size,
                .leader_timeout = cfg.leader_timeout,
                .certification_timeout = cfg.certification_timeout,
                .timeout_retry = cfg.timeout_retry,
                .skip_budget = skip_budget,
                .view_retention = cfg.view_retention,
                .replay_buffer = cfg.replay_buffer,
                .write_buffer = cfg.write_buffer,
                .cache_ref = cfg.page_cache,
                .storage = ctx.storage,
                .scope = ctx.scope.child("voter"),
            });
            errdefer self.voter.deinit();
            self.resolver, self.resolver_mailbox = try Resolver.init(gpa, io, .{
                .scheme = &self.scheme,
                .blocker = cfg.blocker,
                .strategy = cfg.strategy,
                .epoch = cfg.epoch,
                .mailbox_size = cfg.mailbox_size,
                .fetch_timeout = cfg.fetch_timeout,
                .fetch_retry_delay = cfg.fetch_retry_delay,
                .term_length = terms.length,
            });
        }

        /// Releases the actors. Call after the engine's task ended.
        pub fn deinit(self: *Self) void {
            self.batcher.deinit();
            self.voter.deinit();
            self.resolver.deinit();
            self.* = undefined;
        }

        fn mark_stopped(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.stopped = true;
            self.condition.broadcast(self.io);
        }

        /// Waits until an actor stopped or the runtime stopped the engine.
        pub fn wait_stopped(self: *Self) Io.Cancelable!void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            // Each wake re-checks the flag; the wait ends when an actor stops or on cancel.
            while (!self.stopped) try self.condition.wait(self.io, &self.mutex);
            assert(self.stopped);
        }

        fn run_batcher(
            ctx: Ctx,
            self: *Self,
            voter_mailbox: Voter.Mailbox,
            votes: *P.Receiver,
            certificates: *P.Receiver,
        ) void {
            defer self.mark_stopped();
            self.batcher.tracer = ctx.tracer(batcher.trace_target);
            self.batcher.run(voter_mailbox, votes, certificates) catch |err| switch (err) {
                error.Canceled => {},
                else => std.debug.panic("simplex batcher failed: {t}", .{err}),
            };
        }

        fn run_voter(
            ctx: Ctx,
            self: *Self,
            vote_sender: *P.Sender,
            certificate_sender: *P.Sender,
        ) void {
            defer self.mark_stopped();
            self.voter.tracer = ctx.tracer(voter.trace_target);
            self.voter.run(
                self.batcher_mailbox,
                self.resolver_mailbox,
                vote_sender,
                certificate_sender,
            ) catch |err| switch (err) {
                error.Canceled => {},
                else => {
                    ctx.tracer(trace_target).event(.warn, "voter failed: {t}", .{err});
                    assert(self.voter_failure == null);
                    // Published before mark_stopped, whose mutex orders it for `run`.
                    self.voter_failure = err;
                },
            };
        }

        fn run_resolver(
            ctx: Ctx,
            self: *Self,
            voter_mailbox: Voter.Mailbox,
            backfill: Channel(P),
        ) void {
            defer self.mark_stopped();
            self.resolver.tracer = ctx.tracer(resolver.trace_target);
            const scope = ctx.scope;
            self.resolver.run(scope, voter_mailbox, backfill.sender, backfill.receiver) catch |err|
                switch (err) {
                    error.Canceled => {},
                    else => std.debug.panic("simplex resolver failed: {t}", .{err}),
                };
        }

        /// Marks the engine stopped once the runtime stops (commonware selects on
        /// `context.stopped()`), releasing the signal so `stop` can complete.
        fn watch_shutdown(ctx: Ctx, self: *Self) void {
            var shutdown = ctx.stopped();
            defer shutdown.deinit();
            _ = shutdown.wait() catch return; // Canceled: the engine ended first.
            assert(shutdown.peek() != null);
            ctx.tracer(trace_target).event(.debug, "context shutdown, stopping engine", .{});
            self.mark_stopped();
        }

        /// The engine task: runs the actors until any of them stops or the runtime stops
        /// (commonware's `select!` over `stopped()` and the three handles), then aborts the
        /// rest.
        pub fn run(
            ctx: Ctx,
            self: *Self,
            votes: Channel(P),
            certificates: Channel(P),
            backfill: Channel(P),
        ) RunResult {
            var channels = .{ votes, certificates };
            defer {
                channels[0].sender.deinit();
                channels[0].receiver.deinit();
                channels[1].sender.deinit();
                channels[1].receiver.deinit();
            }
            const batcher_task = try ctx.child("batcher").spawn(run_batcher, .{
                self,
                self.voter_mailbox.clone(),
                &channels[0].receiver,
                &channels[1].receiver,
            });
            const resolver_task = try ctx.child("resolver").spawn(run_resolver, .{
                self, self.voter_mailbox, backfill,
            });
            const voter_task = try ctx.child("voter").spawn(run_voter, .{
                self, &channels[0].sender, &channels[1].sender,
            });
            const shutdown_task = try ctx.child("shutdown").spawn(watch_shutdown, .{self});
            defer {
                shutdown_task.abort() catch {};
                voter_task.abort() catch {};
                resolver_task.abort() catch {};
                batcher_task.abort() catch {};
            }
            self.wait_stopped() catch return; // Canceled: the engine is being aborted.
            // Returning runs the deferred aborts, so the other actors stop first.
            if (self.voter_failure) |err| return err;
        }
    };
}
