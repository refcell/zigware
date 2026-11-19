//! The standard wrapper that verifies inline (commonware `marshal/standard/inline.rs`): an
//! application over whole blocks, wrapped as consensus's `Automaton`, `CertifiableAutomaton`,
//! `Relay`, and `Reporter`.
//!
//! `verify` waits for the block, runs the epoch and re-proposal precheck, checks the parent,
//! and asks the application, while it persists the block in the verified cache concurrently.
//! The store's durability opens the round's certification gate, so `certify` usually answers
//! at once; otherwise it fetches the notarized block and persists it as certified. `propose`
//! and `prepare` build through `application.build`, re-proposing the epoch's last block.
//!
//! The wrapper is created on the heap (`create`) and shared by pointer: consensus uses one
//! `*Inline` as its automaton, relay, and reporter. Its tasks are spawned detached from the
//! wrapper's runtime context and borrow the wrapper, so destroy it only after its runtime
//! stopped them. The application follows `application.build`'s contract, with
//! `verify(*A, ctx, consensus_context, ancestry) !bool` (see `validation`).
//!
//! Zig's `Automaton` calls block on `std.Io` instead of returning receivers: each call starts
//! the commonware task and waits for its answer, and canceling the call drops the receiver,
//! which stops the task as dropping commonware's receiver does. The block store started by
//! `verify` runs on regardless.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const runtime = @import("runtime");
const utils = @import("utils");
const traits = @import("../../traits.zig");
const types = @import("../../types.zig");
const simplex = @import("../../simplex/root.zig");
const simplex_types = @import("../../simplex/types.zig");
const build = @import("../application/build.zig");
const gates = @import("../application/gates.zig");
const relay = @import("../application/relay.zig");
const mailbox_mod = @import("../core/mailbox.zig");
const variant = @import("variant.zig");
const validation = @import("validation.zig");

const oneshot = utils.channel.oneshot;
const Timed = runtime.telemetry.metrics.histogram.Timed;
const Feedback = actor.Feedback;
const Handoff = traits.Handoff;
const GateOutcome = gates.GateOutcome;
const Round = types.Round;

/// Sends `value` once and releases the sender; a closed receiver drops it (commonware
/// `send_lossy`).
pub fn send_lossy(comptime T: type, sender: *?oneshot.Sender(T), value: T) void {
    if (sender.*) |*live| live.send(value) catch {};
    sender.* = null;
}

/// Releases a sender that never sent.
pub fn drop_sender(comptime T: type, sender: *?oneshot.Sender(T)) void {
    if (sender.*) |*live| live.deinit();
    sender.* = null;
}

/// The value a consensus call waits for on `receiver` (taken): null when the task declined
/// or stopped.
pub fn answer(comptime T: type, receiver: oneshot.Receiver(T)) Io.Cancelable!?T {
    var owned = receiver;
    defer owned.deinit();
    return owned.recv() catch |err| switch (err) {
        error.Closed => null,
        error.Canceled => error.Canceled,
    };
}

pub fn clone_application(application: anytype) @TypeOf(application) {
    const A = @TypeOf(application);
    if (comptime @typeInfo(A) == .@"struct" and @hasDecl(A, "clone")) return application.clone();
    return application;
}

pub fn deinit_application(application: anytype) void {
    const A = @typeInfo(@TypeOf(application)).pointer.child;
    if (comptime @typeInfo(A) == .@"struct" and @hasDecl(A, "deinit")) application.deinit();
}

/// `result` with every error but cancelation read as no answer (null): consensus's automaton
/// calls return only `Io.Cancelable`, and commonware answers a task it could not start (no
/// memory, no runtime to spawn on) by dropping the oneshot, which consensus reads as no
/// verdict.
pub fn cancelable(comptime T: type, result: anytype) Io.Cancelable!?T {
    const value = result catch |err| {
        const any: anyerror = err;
        if (any == error.Canceled) return error.Canceled;
        return null;
    };
    return value;
}

test "a wrapper call answers null on any error but cancelation" {
    const Result = error{ OutOfMemory, ConcurrencyUnavailable, Canceled }!?u8;
    const failed: Result = error.OutOfMemory;
    try std.testing.expectEqual(@as(?u8, null), try cancelable(u8, failed));
    const unspawned: Result = error.ConcurrencyUnavailable;
    try std.testing.expectEqual(@as(?u8, null), try cancelable(u8, unspawned));
    const canceled: Result = error.Canceled;
    try std.testing.expectError(error.Canceled, cancelable(u8, canceled));
    const answered: Result = 7;
    try std.testing.expectEqual(@as(?u8, 7), try cancelable(u8, answered));
}

/// Spawns `task(task_ctx, job, sender)` detached from `ctx`, returning the receiver. When the
/// context was aborted the task never runs: the job is released and the receiver reads closed.
pub fn spawn_detached(
    comptime T: type,
    ctx: anytype,
    comptime task: anytype,
    job: anytype,
) !oneshot.Receiver(T) {
    var owned = job;
    var pair = oneshot.channel(T, ctx.gpa(), ctx.io()) catch |err| {
        owned.deinit();
        return err;
    };
    const handle = ctx.spawn(task, .{ owned, pair.sender }) catch |err| {
        owned.deinit();
        pair.sender.deinit();
        pair.receiver.deinit();
        return err;
    };
    if (handle.header == null) {
        owned.deinit();
        pair.sender.deinit();
        return pair.receiver;
    }
    handle.detach();
    return pair.receiver;
}

/// The inline wrapper over runtime context `Ctx`, signing scheme `S`, application `A`, block
/// `B`, and epocher `ES`.
pub fn Inline(
    comptime Ctx: type,
    comptime S: type,
    comptime A: type,
    comptime B: type,
    comptime ES: type,
) type {
    return InlineOver(.{ Ctx, S, A, B, ES });
}

fn InlineOver(comptime T: [5]type) type {
    const Ctx = T[0];
    const S = T[1];
    const A = T[2];
    const B = T[3];
    const ES = T[4];
    comptime traits.assert_block(B);
    comptime types.assert_epocher(ES);
    return struct {
        const Self = @This();
        pub const V = variant.Standard(B);
        pub const Digest = B.Digest;
        pub const PublicKey = S.PublicKey;
        pub const Context = simplex_types.Context(Digest, PublicKey);
        pub const Plan = simplex.Plan(PublicKey);
        pub const Activity = simplex_types.Activity(S, Digest);
        pub const Marshal = mailbox_mod.Mailbox(S, V);
        pub const Registry = gates.Gates(Digest, V);
        const StreamResult = @typeInfo(@TypeOf(Marshal.ancestor_stream)).@"fn".return_type.?;
        const Stream = @typeInfo(StreamResult).error_union.payload;
        const Resolved = build.Resolved(Digest, V.Block, Stream, void);

        gpa: Allocator,
        ctx: Ctx,
        application: A,
        marshal: Marshal,
        epocher: ES,
        registry: Registry,
        build_duration: Timed,
        proposal_parent_fetch_duration: Timed,
        ancestor_fetch_duration: Timed,

        /// Wraps `application` (taken) over `marshal` (taken), registering its histograms
        /// under `ctx`'s scope.
        pub fn create(ctx: Ctx, application: A, marshal: Marshal, epocher: ES) !*Self {
            const gpa = ctx.gpa();
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            const scope = &ctx.scope;
            var build_duration = try Timed.register(
                scope,
                "build_duration",
                "Histogram of time taken for the application to build a new block, in seconds",
            );
            errdefer build_duration.deinit();
            var parent_fetch = try Timed.register(
                scope,
                "parent_fetch_duration",
                "Histogram of time taken to fetch a parent block in proposal, in seconds",
            );
            errdefer parent_fetch.deinit();
            var ancestor_fetch = try Timed.register(
                scope,
                "ancestor_fetch_duration",
                "Histogram of time taken to fetch a block via the ancestry stream, in seconds",
            );
            errdefer ancestor_fetch.deinit();
            self.* = .{
                .gpa = gpa,
                .ctx = ctx,
                .application = application,
                .marshal = marshal,
                .epocher = epocher,
                .registry = try .init(gpa, ctx.io()),
                .build_duration = build_duration,
                .proposal_parent_fetch_duration = parent_fetch,
                .ancestor_fetch_duration = ancestor_fetch,
            };
            return self;
        }

        /// Call once the runtime stopped every task the wrapper spawned.
        pub fn destroy(self: *Self) void {
            const gpa = self.gpa;
            self.registry.deinit();
            self.build_duration.deinit();
            self.proposal_parent_fetch_duration.deinit();
            self.ancestor_fetch_duration.deinit();
            deinit_application(&self.application);
            self.marshal.deinit();
            self.* = undefined;
            gpa.destroy(self);
        }

        /// The proposal checks (commonware `checks`): fetch the parent, re-propose the epoch's
        /// last block, or build on the parent's ancestry. Borrows the wrapper.
        const Checks = struct {
            wrapper: *Self,
            context: Context,

            pub fn call(checks: Checks) !Resolved {
                const self = checks.wrapper;
                const io = self.ctx.io();
                const context = checks.context;
                const parent_view, const parent_commitment = context.parent;
                const fallback: mailbox_mod.CommitmentFallback = .{
                    .fetch_by_round = .new(context.epoch(), parent_view),
                };
                const marshal = self.marshal;
                var request = try marshal.subscribe_by_commitment(parent_commitment, fallback);
                defer request.deinit();
                const timer = self.proposal_parent_fetch_duration.timer(io);
                var parent = request.recv() catch |err| switch (err) {
                    // The parent never arrives: skip the proposal.
                    error.Closed => return .skip,
                    error.Canceled => return error.Canceled,
                };
                timer.observe(io);
                // The current epoch exists while consensus asks to propose in it.
                const last = self.epocher.last(context.epoch()).?;
                if (parent.inner().height().get() == last.get()) {
                    return .{ .reuse = .{ .digest = parent.digest(), .block = parent } };
                }
                const initial = [1]V.Block{parent};
                const fetch = &self.ancestor_fetch_duration;
                // Bounded by the proposal round: it ends the need for every ancestor fetched.
                const bound = context.round;
                const stream = self.marshal.ancestor_stream(&initial, bound, fetch) catch |err| {
                    parent.deinit();
                    return err;
                };
                return .{ .build = .{ .ancestry = stream, .metadata = {} } };
            }

            pub fn release(_: Checks, result: anytype) void {
                const resolved = result catch return;
                switch (resolved) {
                    .reuse => |reuse| {
                        var block = reuse.block;
                        block.deinit();
                    },
                    .skip => {},
                    .build => |ready| {
                        var stream = ready.ancestry;
                        stream.deinit();
                    },
                }
            }
        };

        /// A standard block is staged as itself, under its digest.
        const Seal = struct {
            pub fn call(_: Seal, block: V.Block, _: void) !struct { Digest, V.Block } {
                return .{ block.digest(), block };
            }
        };

        // Automaton.

        /// Builds a block on `context`'s parent; null when the parent never arrives or the
        /// application declines.
        pub fn propose(self: *Self, io: Io, context: Context) Io.Cancelable!?Digest {
            return cancelable(Digest, self.propose_call(io, context));
        }

        fn propose_call(self: *Self, io: Io, context: Context) !?Digest {
            _ = io;
            const checks: Checks = .{ .wrapper = self, .context = context };
            const receiver = try build.propose(
                Digest,
                self.ctx,
                self.application,
                self.registry,
                context,
                checks,
                Seal{},
                &self.build_duration,
            );
            return answer(Digest, receiver);
        }

        /// Verifies the block `digest` under `context`; null when verification stopped.
        pub fn verify(self: *Self, io: Io, context: Context, digest: Digest) Io.Cancelable!?bool {
            return cancelable(bool, self.verify_call(io, context, digest));
        }

        fn verify_call(self: *Self, io: Io, context: Context, digest: Digest) !?bool {
            _ = io;
            const round = context.round;
            // spawn_detached releases the job on failure, so only earlier failures free here.
            var block_request = try self.marshal.subscribe_by_digest(digest, .wait);
            var durable = oneshot.channel(GateOutcome, self.gpa, self.ctx.io()) catch |err| {
                block_request.deinit();
                return err;
            };
            self.registry.insert(round, digest, durable.receiver) catch |err| {
                block_request.deinit();
                durable.receiver.deinit();
                durable.sender.deinit();
                return err;
            };
            const job: VerifyJob = .{
                .wrapper = self,
                .context = context,
                .digest = digest,
                .block_request = block_request,
                .durable = durable.sender,
            };
            const task_ctx = self.ctx.child("inline_verify").with_attribute("round", round);
            const receiver = try spawn_detached(bool, task_ctx, verify_task, job);
            return answer(bool, receiver);
        }

        // CertifiableAutomaton.

        /// Builds a handoff candidate on an uncertified parent; `wait` declines.
        pub fn prepare(self: *Self, io: Io, context: Context) Io.Cancelable!?Handoff(Digest) {
            return cancelable(Handoff(Digest), self.prepare_call(io, context));
        }

        fn prepare_call(self: *Self, io: Io, context: Context) !?Handoff(Digest) {
            _ = io;
            const checks: Checks = .{ .wrapper = self, .context = context };
            const receiver = try build.prepare(
                Digest,
                self.ctx,
                self.application,
                self.registry,
                context,
                checks,
                Seal{},
                &self.build_duration,
            );
            return answer(Handoff(Digest), receiver);
        }

        /// Certifies the notarized block `digest` at `round`: the verify task's verdict once
        /// its store is durable, or else the block fetched and persisted as certified.
        pub fn certify(self: *Self, io: Io, round: Round, digest: Digest) Io.Cancelable!?bool {
            return cancelable(bool, self.certify_call(io, round, digest));
        }

        fn certify_call(self: *Self, io: Io, round: Round, digest: Digest) !?bool {
            _ = io;
            const persist: Persist = .{ .marshal = self.marshal, .round = round };
            var gate = self.registry.claim(round, digest, persist);
            // spawn_detached releases the job (and its gate) on failure.
            if (gate != null) self.marshal.hint_notarized(round, digest) catch |err| {
                gate.?.deinit();
                return err;
            };
            const job: CertifyJob = .{
                .wrapper = self,
                .round = round,
                .digest = digest,
                .gate = gate,
            };
            const task_ctx = self.ctx.child("inline_certify").with_attribute("round", round);
            const receiver = try spawn_detached(bool, task_ctx, certify_task, job);
            return answer(bool, receiver);
        }

        /// Persists a claimed staged proposal through the verified cache.
        const Persist = struct {
            marshal: Marshal,
            round: Round,

            pub fn call(persist: Persist, block: V.Block, ack: gates.Ack) void {
                // Rust aborts on allocation failure; the claim cannot return it.
                persist.marshal.verified_deferred(persist.round, block, ack) catch
                    @panic("out of memory");
            }
        };

        // Relay.

        pub fn broadcast(self: *Self, commitment: Digest, plan: Plan) Feedback {
            const registry = self.registry;
            // Rust aborts on allocation failure; a relay cannot return it.
            return relay.broadcast(S, V, registry, self.marshal, commitment, plan) catch
                @panic("out of memory");
        }

        // Reporter.

        /// Retires gates through the finalized round (or the activity's epoch start), then
        /// forwards the activity (borrowed) to marshal.
        pub fn report(self: *Self, activity: Activity) Feedback {
            const retired: Round = switch (activity) {
                .finalization => |finalization| finalization.round(),
                else => .new(activity.epoch(), .zero()),
            };
            self.registry.retain_after(retired);
            return self.marshal.report(activity);
        }

        /// What a verify task owns.
        const VerifyJob = struct {
            wrapper: *Self,
            context: Context,
            digest: Digest,
            block_request: oneshot.Receiver(V.Block),
            durable: ?oneshot.Sender(GateOutcome),

            fn deinit(job: *VerifyJob) void {
                job.block_request.deinit();
                drop_sender(GateOutcome, &job.durable);
            }
        };

        fn verify_task(task_ctx: Ctx, job: VerifyJob, sender: oneshot.Sender(bool)) void {
            var owned = job;
            defer owned.deinit();
            var tx: ?oneshot.Sender(bool) = sender;
            defer drop_sender(bool, &tx);
            const self = owned.wrapper;
            const io = task_ctx.io();
            const context = owned.context;
            const digest = owned.digest;
            // Subscribe to the parent now, so its fetch overlaps the wait for the block.
            var parent_request: ?oneshot.Receiver(V.Block) = null;
            defer if (parent_request) |*request| request.deinit();
            if (!digest.eql(context.parent[1])) {
                const fallback: mailbox_mod.CommitmentFallback = .{
                    .fetch_by_round = .new(context.epoch(), context.parent[0]),
                };
                const parent = context.parent[1];
                parent_request = self.marshal.subscribe_by_commitment(parent, fallback) catch
                    return;
            }
            const output = &tx.?;
            const request = &owned.block_request;
            const fetched = gates.recv_unless_closed(bool, V.Block, io, output, request);
            const block = ((fetched catch return) orelse return) catch return;
            const precheck = validation.precheck_epoch_and_reproposal(
                self.epocher,
                self.marshal,
                context,
                digest,
                block,
            );
            const decision = (precheck catch return) orelse return;
            switch (decision) {
                .complete => |valid| {
                    send_lossy(bool, &tx, valid);
                    const outcome: GateOutcome = if (valid) .{ .ready = true } else .recover;
                    send_lossy(GateOutcome, &owned.durable, outcome);
                },
                .@"continue" => |candidate| {
                    verify_candidate(task_ctx, &owned, candidate, &parent_request.?, &tx);
                },
            }
        }

        /// Stores `candidate` (taken) while checking its parent and asking the application
        /// (commonware's joined `store` and `verify_then_vote`).
        fn verify_candidate(
            task_ctx: Ctx,
            job: *VerifyJob,
            candidate: V.Block,
            parent_request: *oneshot.Receiver(V.Block),
            tx: *?oneshot.Sender(bool),
        ) void {
            var block = candidate;
            defer block.deinit();
            const self = job.wrapper;
            const io = task_ctx.io();
            const round = job.context.round;
            // The store runs beside verification; without a concurrent task, it runs first.
            const stored_block = block.clone();
            const store_args = .{ self.marshal, round, stored_block, &job.durable };
            var store = io.concurrent(store_task, store_args);
            defer if (store) |*running| running.await(io) else |_| {};
            if (store) |_| {} else |_| store_task(self.marshal, round, stored_block, &job.durable);
            const context = job.context;
            const checked = validation.await_and_validate_parent(
                bool,
                io,
                context.parent[1],
                &block,
                parent_request,
                &tx.*.?,
            );
            const check = (checked catch return) orelse return;
            const parent = switch (check) {
                .invalid => return send_lossy(bool, tx, false),
                .valid => |parent| parent,
            };
            var application = clone_application(self.application);
            defer deinit_application(&application);
            const verdict = validation.run_app_verify(
                bool,
                task_ctx,
                context,
                block.clone(),
                parent,
                &application,
                self.marshal,
                &tx.*.?,
                &self.ancestor_fetch_duration,
            ) catch return;
            if (verdict) |valid| send_lossy(bool, tx, valid);
        }

        /// Persists `block` (taken) as verified; durability opens the round's gate.
        fn store_task(
            marshal: Marshal,
            round: Round,
            block: V.Block,
            durable: *?oneshot.Sender(GateOutcome),
        ) void {
            const stored = marshal.verified(round, block) catch return;
            if (stored) send_lossy(GateOutcome, durable, .{ .ready = true });
        }

        /// What a certify task owns.
        const CertifyJob = struct {
            wrapper: *Self,
            round: Round,
            digest: Digest,
            gate: ?gates.Gate,

            fn deinit(job: *CertifyJob) void {
                if (job.gate) |*gate| gate.deinit();
                job.gate = null;
            }
        };

        fn certify_task(task_ctx: Ctx, job: CertifyJob, sender: oneshot.Sender(bool)) void {
            var owned = job;
            defer owned.deinit();
            var tx: ?oneshot.Sender(bool) = sender;
            defer drop_sender(bool, &tx);
            const self = owned.wrapper;
            const io = task_ctx.io();
            if (owned.gate) |*gate| {
                const waited = gates.recv_unless_closed(bool, GateOutcome, io, &tx.?, gate);
                const outcome = (waited catch return) orelse return;
                if (outcome) |value| switch (value) {
                    .ready => |verdict| return send_lossy(bool, &tx, verdict),
                    .recover => {},
                } else |_| {}
            }
            const fallback: mailbox_mod.DigestFallback = .{ .fetch_by_round = owned.round };
            var request = self.marshal.subscribe_by_digest(owned.digest, fallback) catch return;
            defer request.deinit();
            const fetched = gates.recv_unless_closed(bool, V.Block, io, &tx.?, &request);
            const block = ((fetched catch return) orelse return) catch return;
            const stored = self.marshal.certified(owned.round, block) catch return;
            if (!stored) return;
            send_lossy(bool, &tx, true);
        }
    };
}

test {
    _ = @import("inline_test.zig");
}
