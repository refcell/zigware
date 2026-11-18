//! The standard wrapper that defers verification (commonware `marshal/standard/deferred.rs`):
//! an application over whole blocks that carry their consensus context, wrapped as
//! consensus's `Automaton`, `CertifiableAutomaton`, `Relay`, and `Reporter`.
//!
//! `verify` votes once the block is available, inside the context's epoch, and embeds the
//! consensus context; it does not wait for the application. The application's verdict runs in
//! the background beside the block's store and resolves the round's certification gate once
//! the block is both valid and durable, so `certify` waits on it before the finalize vote.
//! Without a gate (never verified here, a restart, or a recovery request), `certify` fetches
//! the notarized block and verifies it under its embedded context, which the notarizing
//! quorum's honest members checked. Certifying a block drops the round's other gates, which
//! stops verification of conflicting blocks. `propose` and `prepare` build through
//! `application.build`, re-proposing the epoch's last block, and build only on a parent that
//! links to its own context parent.
//!
//! Like `standard.Inline`, the wrapper is created on the heap and shared by pointer, its tasks
//! borrow it, and each Zig `Automaton` call blocks until the commonware receiver would
//! resolve (canceling the call drops the receiver).

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
const app_validation = @import("../application/validation.zig");
const mailbox_mod = @import("../core/mailbox.zig");
const variant = @import("variant.zig");
const validation = @import("validation.zig");
const inline_mod = @import("inline.zig");

const oneshot = utils.channel.oneshot;
const Timed = runtime.telemetry.metrics.histogram.Timed;
const Feedback = actor.Feedback;
const Handoff = traits.Handoff;
const GateOutcome = gates.GateOutcome;
const Stage = app_validation.Stage;
const Round = types.Round;
const send_lossy = inline_mod.send_lossy;
const drop_sender = inline_mod.drop_sender;
const answer = inline_mod.answer;
const spawn_detached = inline_mod.spawn_detached;

/// Passes a gate outcome through unchanged.
const Identity = struct {
    pub fn call(_: Identity, outcome: GateOutcome) ?GateOutcome {
        return outcome;
    }
};

/// A ready outcome's verdict; `recover` has none.
const ReadyVerdict = struct {
    pub fn call(_: ReadyVerdict, outcome: GateOutcome) ?bool {
        return switch (outcome) {
            .ready => |verdict| verdict,
            .recover => null,
        };
    }
};

/// The deferred wrapper over runtime context `Ctx`, signing scheme `S`, application `A`,
/// certifiable block `B`, and epocher `ES`.
pub fn Deferred(
    comptime Ctx: type,
    comptime S: type,
    comptime A: type,
    comptime B: type,
    comptime ES: type,
) type {
    return DeferredOver(.{ Ctx, S, A, B, ES });
}

fn DeferredOver(comptime T: [5]type) type {
    const Ctx = T[0];
    const S = T[1];
    const A = T[2];
    const B = T[3];
    const ES = T[4];
    comptime traits.assert_certifiable_block(B);
    comptime types.assert_epocher(ES);
    comptime assert(B.Context == simplex_types.Context(B.Digest, S.PublicKey));
    return struct {
        const Self = @This();
        pub const V = variant.Standard(B);
        pub const Digest = B.Digest;
        pub const PublicKey = S.PublicKey;
        pub const Context = B.Context;
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
            inline_mod.deinit_application(&self.application);
            self.marshal.deinit();
            self.* = undefined;
            gpa.destroy(self);
        }

        /// The proposal checks (commonware `checks`): fetch the parent, skip a parent that
        /// does not link to its own context parent, re-propose the epoch's last block, or
        /// build on the parent's ancestry. Borrows the wrapper.
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
                var request = try self.marshal.subscribe_by_commitment(parent_commitment, fallback);
                defer request.deinit();
                const timer = self.proposal_parent_fetch_duration.timer(io);
                var parent = request.recv() catch |err| switch (err) {
                    // The parent never arrives: skip the proposal.
                    error.Closed => return .skip,
                    error.Canceled => return error.Canceled,
                };
                timer.observe(io);
                // Votes precede the link check, so an uncertified parent may be unlinked. A
                // parent at view zero is the epoch's genesis, which has nothing to link to.
                const linked = parent.inner().parent().eql(parent.inner().context().parent[1]);
                if (parent_view.get() != 0 and !linked) {
                    parent.deinit();
                    return .skip;
                }
                // The current epoch exists while consensus asks to propose in it.
                const last = self.epocher.last(context.epoch()).?;
                if (parent.inner().height().get() == last.get()) {
                    return .{ .reuse = .{ .digest = parent.digest(), .block = parent } };
                }
                const initial = [1]V.Block{parent};
                const fetch = &self.ancestor_fetch_duration;
                const stream = self.marshal.ancestor_stream(&initial, fetch) catch |err| {
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

        /// Builds a block on `context`'s parent; null when the parent never arrives, does not
        /// link, or the application declines.
        pub fn propose(self: *Self, io: Io, context: Context) !?Digest {
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

        /// Votes on the block `digest` under `context` once it is available and embeds
        /// `context`, leaving the application's verdict to `certify`; null when verification
        /// stopped (consensus or the gate dropped it, or the block never arrives).
        pub fn verify(self: *Self, io: Io, context: Context, digest: Digest) !?bool {
            _ = io;
            const round = context.round;
            // Register the wait before the gate, so a buffered block cannot slip past both.
            var block_request = try self.marshal.subscribe_by_digest(digest, .wait);
            var gate = oneshot.channel(GateOutcome, self.gpa, self.ctx.io()) catch |err| {
                block_request.deinit();
                return err;
            };
            self.registry.insert(round, digest, gate.receiver) catch |err| {
                block_request.deinit();
                gate.receiver.deinit();
                gate.sender.deinit();
                return err;
            };
            const job: OptimisticJob = .{
                .wrapper = self,
                .context = context,
                .digest = digest,
                .block_request = block_request,
                .gate = gate.sender,
            };
            const task_ctx = self.ctx.child("optimistic_verify").with_attribute("round", round);
            const receiver = try spawn_detached(bool, task_ctx, optimistic_task, job);
            return answer(bool, receiver);
        }

        // CertifiableAutomaton.

        /// Builds a handoff candidate on an uncertified parent; `wait` declines.
        pub fn prepare(self: *Self, io: Io, context: Context) !?Handoff(Digest) {
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

        /// Certifies the notarized block `digest` at `round`: the gate's verdict once the
        /// block is valid and durable, or else a verification under the block's embedded
        /// context.
        pub fn certify(self: *Self, io: Io, round: Round, digest: Digest) !?bool {
            _ = io;
            const persist: Persist = .{ .marshal = self.marshal, .round = round };
            const receiver = if (self.registry.claim(round, digest, persist)) |gate|
                try self.certify_from_existing_task(round, digest, gate)
            else
                try self.certify_from_embedded_context(round, digest);
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

        /// What an optimistic verify task owns.
        const OptimisticJob = struct {
            wrapper: *Self,
            context: Context,
            digest: Digest,
            block_request: oneshot.Receiver(V.Block),
            gate: ?oneshot.Sender(GateOutcome),

            pub fn deinit(job: *OptimisticJob) void {
                job.block_request.deinit();
                drop_sender(GateOutcome, &job.gate);
            }
        };

        fn optimistic_task(task_ctx: Ctx, job: OptimisticJob, sender: oneshot.Sender(bool)) void {
            var owned = job;
            defer owned.deinit();
            var tx: ?oneshot.Sender(bool) = sender;
            defer drop_sender(bool, &tx);
            const self = owned.wrapper;
            const io = task_ctx.io();
            const context = owned.context;
            const digest = owned.digest;
            // Fetch the parent beside the block; a re-proposal is its own parent and skips it.
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
            const fetched = recv_block(io, &tx.?, &owned.gate.?, &owned.block_request);
            const block = ((fetched catch return) orelse return) catch return;
            const precheck = validation.precheck_epoch_and_reproposal(
                self.epocher,
                self.marshal,
                context,
                digest,
                block,
            );
            const decision = (precheck catch return) orelse return;
            var candidate = switch (decision) {
                .complete => |valid| {
                    // The precheck reads only the height and the gate's epoch, so its verdict
                    // holds for any header of this `(round, digest)`.
                    send_lossy(GateOutcome, &owned.gate, .{ .ready = valid });
                    return send_lossy(bool, &tx, valid);
                },
                .@"continue" => |candidate| candidate,
            };
            // The notarizing quorum's honest members check the embedded context here, so a
            // Byzantine proposer cannot embed a context that differs from consensus's.
            if (!candidate.inner().context().eql(context)) {
                candidate.deinit();
                send_lossy(GateOutcome, &owned.gate, .recover);
                return send_lossy(bool, &tx, false);
            }
            const request = parent_request.?;
            parent_request = null;
            const deferred = self.deferred_verify(context, candidate, request, .verified) catch
                return;
            send_lossy(bool, &tx, true);
            // The gate now owns the deferred work: dropping it (a finalization, or a
            // conflicting certification) stops that work.
            const gate = owned.gate.?;
            owned.gate = null;
            gates.forward(GateOutcome, GateOutcome, io, gate, deferred, Identity{}) catch {};
        }

        /// The block on `request` unless consensus (`tx`) or the gate drops its receiver first
        /// (null).
        fn recv_block(
            io: Io,
            tx: *const oneshot.Sender(bool),
            gate: *const oneshot.Sender(GateOutcome),
            request: *oneshot.Receiver(V.Block),
        ) Io.Cancelable!?(oneshot.RecvError!V.Block) {
            const Outcome = union(enum) {
                consensus: Io.Cancelable!void,
                gate: Io.Cancelable!void,
                received: oneshot.RecvError!V.Block,
            };
            var buffer: [3]Outcome = undefined;
            var select: Io.Select(Outcome) = .init(io, &buffer);
            select.concurrent(.consensus, oneshot.Sender(bool).closed, .{tx.*}) catch {
                return error.Canceled;
            };
            select.concurrent(.gate, oneshot.Sender(GateOutcome).closed, .{gate.*}) catch {
                select.cancelDiscard();
                return error.Canceled;
            };
            select.concurrent(.received, oneshot.Receiver(V.Block).recv, .{request}) catch {
                select.cancelDiscard();
                return error.Canceled;
            };
            const first = try select.await();
            while (select.cancel()) |rest| {
                if (rest == .received) if (rest.received) |value| {
                    var late = value;
                    late.deinit();
                } else |_| {};
            }
            return switch (first) {
                .consensus, .gate => null,
                .received => |result| result,
            };
        }

        /// Verifies `block` (taken) on `parent_request` (taken) in the background while it is
        /// stored under `stage`, resolving to ready once it is both valid and durable
        /// (commonware `deferred_verify`).
        fn deferred_verify(
            self: *Self,
            context: Context,
            block: V.Block,
            parent_request: oneshot.Receiver(V.Block),
            stage: Stage,
        ) !oneshot.Receiver(GateOutcome) {
            const job: DeferredJob = .{
                .wrapper = self,
                .context = context,
                .block = block,
                .parent_request = parent_request,
                .stage = stage,
            };
            const round = context.round;
            const task_ctx = self.ctx.child("deferred_verify").with_attribute("round", round);
            return spawn_detached(GateOutcome, task_ctx, deferred_task, job);
        }

        /// What a deferred verify task owns.
        const DeferredJob = struct {
            wrapper: *Self,
            context: Context,
            block: V.Block,
            parent_request: oneshot.Receiver(V.Block),
            stage: Stage,

            pub fn deinit(job: *DeferredJob) void {
                job.block.deinit();
                job.parent_request.deinit();
            }
        };

        fn deferred_task(
            task_ctx: Ctx,
            job: DeferredJob,
            sender: oneshot.Sender(GateOutcome),
        ) void {
            var owned = job;
            defer owned.deinit();
            var tx: ?oneshot.Sender(GateOutcome) = sender;
            defer drop_sender(GateOutcome, &tx);
            const self = owned.wrapper;
            const io = task_ctx.io();
            const round = owned.context.round;
            // The store depends on neither the parent nor the verdict, so it starts first;
            // without a concurrent task, it runs before verification.
            const stored = owned.block.clone();
            const store_args = .{ self.marshal, owned.stage, round, stored };
            var store: ?Io.Future(bool) = io.concurrent(store_task, store_args) catch null;
            const durable_now = if (store == null) @call(.auto, store_task, store_args) else false;
            const verdict = verify_block(task_ctx, &owned, &tx.?);
            const durable = if (store) |*running| running.await(io) else durable_now;
            // The cache may already hold an invalid block; the gate's verdict is the
            // authority.
            if (gates.resolve(verdict, durable)) |valid| {
                send_lossy(GateOutcome, &tx, .{ .ready = valid });
            }
        }

        /// The application's verdict on the job's block, after its parent checks out; null
        /// when `tx`'s receiver closed or the parent never arrives.
        fn verify_block(
            task_ctx: Ctx,
            job: *DeferredJob,
            tx: *const oneshot.Sender(GateOutcome),
        ) ?bool {
            const self = job.wrapper;
            const io = task_ctx.io();
            const context = job.context;
            const checked = validation.await_and_validate_parent(
                GateOutcome,
                io,
                context.parent[1],
                &job.block,
                &job.parent_request,
                tx,
            );
            const check = (checked catch return null) orelse return null;
            const parent = switch (check) {
                .invalid => return false,
                .valid => |parent| parent,
            };
            var application = inline_mod.clone_application(self.application);
            defer inline_mod.deinit_application(&application);
            return validation.run_app_verify(
                GateOutcome,
                task_ctx,
                context,
                job.block.clone(),
                parent,
                &application,
                self.marshal,
                tx,
                &self.ancestor_fetch_duration,
            ) catch null;
        }

        /// Persists `block` (taken) under `stage`; false when marshal could not.
        fn store_task(marshal: Marshal, stage: Stage, round: Round, block: V.Block) bool {
            return stage.store(marshal, round, block) catch false;
        }

        /// Waits on the claimed `gate` (taken), hinting marshal to fetch the notarized block
        /// in case local delivery never comes; recovers through the embedded context.
        fn certify_from_existing_task(
            self: *Self,
            round: Round,
            digest: Digest,
            gate: gates.Gate,
        ) !oneshot.Receiver(bool) {
            var owned = gate;
            self.marshal.hint_notarized(round, digest) catch |err| {
                owned.deinit();
                return err;
            };
            const job: ExistingJob = .{
                .wrapper = self,
                .round = round,
                .digest = digest,
                .gate = owned,
            };
            const task_ctx = self.ctx.child("certify_existing").with_attribute("round", round);
            return spawn_detached(bool, task_ctx, existing_task, job);
        }

        /// What a certify task on an existing gate owns.
        const ExistingJob = struct {
            wrapper: *Self,
            round: Round,
            digest: Digest,
            gate: gates.Gate,

            pub fn deinit(job: *ExistingJob) void {
                job.gate.deinit();
            }

            /// The recovery `gates.drive` falls back to.
            pub fn call(job: ExistingJob) !oneshot.Receiver(bool) {
                return job.wrapper.certify_from_embedded_context(job.round, job.digest);
            }
        };

        fn existing_task(task_ctx: Ctx, job: ExistingJob, sender: oneshot.Sender(bool)) void {
            gates.drive(task_ctx.io(), sender, job.gate, job) catch {};
        }

        /// Fetches the notarized block `digest` and certifies it under its embedded context
        /// (commonware `certify_from_embedded_context`). The fetch, not only local delivery,
        /// lets a validator the leader skipped recover the block.
        fn certify_from_embedded_context(
            self: *Self,
            round: Round,
            digest: Digest,
        ) !oneshot.Receiver(bool) {
            const fallback: mailbox_mod.DigestFallback = .{ .fetch_by_round = round };
            const request = try self.marshal.subscribe_by_digest(digest, fallback);
            const job: EmbeddedJob = .{ .wrapper = self, .round = round, .request = request };
            const task_ctx = self.ctx.child("certify").with_attribute("round", round);
            return spawn_detached(bool, task_ctx, embedded_task, job);
        }

        /// What an embedded-context certify task owns.
        const EmbeddedJob = struct {
            wrapper: *Self,
            round: Round,
            request: oneshot.Receiver(V.Block),

            pub fn deinit(job: *EmbeddedJob) void {
                job.request.deinit();
            }
        };

        fn embedded_task(task_ctx: Ctx, job: EmbeddedJob, sender: oneshot.Sender(bool)) void {
            var owned = job;
            defer owned.deinit();
            var tx: ?oneshot.Sender(bool) = sender;
            defer drop_sender(bool, &tx);
            const self = owned.wrapper;
            const io = task_ctx.io();
            const round = owned.round;
            const fetched = gates.recv_unless_closed(bool, V.Block, io, &tx.?, &owned.request);
            var block = ((fetched catch return) orelse return) catch return;
            const embedded = block.inner().context();
            const height = block.inner().height();
            // A boundary block certified in a later view of its epoch is a re-proposal: its
            // notarization settles it, so it is only persisted.
            const epocher = self.epocher;
            const reproposal = app_validation.is_inferred_reproposal_at_certify;
            if (reproposal(epocher, height, embedded.round, round)) {
                const stored = self.marshal.certified(round, block) catch return;
                if (stored) send_lossy(bool, &tx, true);
                return;
            }
            const parent_view, const parent_commitment = embedded.parent;
            const fallback: mailbox_mod.CommitmentFallback = .{
                .fetch_by_round = .new(embedded.epoch(), parent_view),
            };
            const parent_request = self.marshal.subscribe_by_commitment(
                parent_commitment,
                fallback,
            ) catch return block.deinit();
            const verdict = self.deferred_verify(embedded, block, parent_request, .certified) catch
                return;
            const output = tx.?;
            tx = null;
            gates.forward(bool, GateOutcome, io, output, verdict, ReadyVerdict{}) catch {};
        }
    };
}

test {
    _ = @import("deferred_test.zig");
    _ = @import("deferred_harness_test.zig");
}
