//! The tasks of the coding marshal's application wrapper (marshaled.zig) and the helpers they
//! share. Each task owns a job: a handle to the wrapper and the channels it answers on.
//! Releasing a job (when its task ends, or when it never ran) closes every channel it still
//! holds, which is how commonware's dropped senders and receivers read here.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const coding = @import("coding");
const utils = @import("utils");

const types = @import("types.zig");
const validation = @import("validation.zig");
const core_mailbox = @import("../core/mailbox.zig");
const gates = @import("../application/gates.zig");
const app_validation = @import("../application/validation.zig");
const consensus_types = @import("../../types.zig");

const oneshot = utils.channel.oneshot;
const CodingConfig = coding.Config;
const GateOutcome = gates.GateOutcome;
const Stage = app_validation.Stage;
const Round = consensus_types.Round;
const CommitmentFallback = core_mailbox.CommitmentFallback;

pub fn Return(comptime function: anytype) type {
    return @typeInfo(@TypeOf(function)).@"fn".return_type.?;
}

/// Runs `function(args...)` while `output` still has a receiver. Returns null once the
/// receiver closes first: the call is canceled, and a result it already produced goes to
/// `release`.
pub fn unless_closed(
    comptime T: type,
    io: Io,
    output: *const oneshot.Sender(T),
    comptime function: anytype,
    args: anytype,
    comptime release: fn (Return(function)) void,
) Io.Cancelable!?Return(function) {
    const Outcome = union(enum) { closed: Io.Cancelable!void, done: Return(function) };
    var buffer: [2]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);
    select.concurrent(.closed, oneshot.Sender(T).closed, .{output.*}) catch {
        return error.Canceled;
    };
    // A runtime context and an ancestor stream outgrow a task closure (1 KiB on the
    // deterministic runtime), so the task reads `args` through one pointer; every path below
    // drains the select before this frame returns.
    const Call = struct {
        fn run(call_args: *const @TypeOf(args)) Return(function) {
            return @call(.auto, function, call_args.*);
        }
    };
    select.concurrent(.done, Call.run, .{&args}) catch {
        select.cancelDiscard();
        return error.Canceled;
    };
    const first = select.await() catch |err| {
        while (select.cancel()) |rest| if (rest == .done) release(rest.done);
        return err;
    };
    while (select.cancel()) |rest| if (rest == .done) release(rest.done);
    assert(first == .closed or first == .done);
    return switch (first) {
        .closed => null,
        .done => |result| result,
    };
}

/// Releases a received value nobody will use.
fn Discard(comptime U: type) type {
    return struct {
        fn call(result: oneshot.RecvError!U) void {
            const value = result catch return;
            if (comptime @typeInfo(U) == .@"struct" and @hasDecl(U, "discard")) U.discard(value);
        }
    };
}

/// Drops a result nobody will use that owns nothing.
fn Ignore(comptime R: type) type {
    return struct {
        fn call(_: R) void {}
    };
}

/// The value of `input` unless `output`'s receiver closes first (null).
pub fn recv_unless_closed(
    comptime T: type,
    comptime U: type,
    io: Io,
    output: *const oneshot.Sender(T),
    input: *oneshot.Receiver(U),
) Io.Cancelable!?(oneshot.RecvError!U) {
    const recv = oneshot.Receiver(U).recv;
    return unless_closed(T, io, output, recv, .{input}, Discard(U).call);
}

/// Sends `value` through `sender`, if still held, and releases it.
pub fn answer(comptime T: type, sender: *?oneshot.Sender(T), value: T) void {
    if (sender.*) |*held| held.send(value) catch {};
    sender.* = null;
    assert(sender.* == null);
}

pub fn release_sender(comptime T: type, sender: *?oneshot.Sender(T)) void {
    if (sender.*) |*held| held.deinit();
    sender.* = null;
}

pub fn release_receiver(comptime T: type, receiver: *?oneshot.Receiver(T)) void {
    if (receiver.*) |*held| held.deinit();
    receiver.* = null;
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

/// Spawns `task(task_ctx, job)` detached from `ctx`; when it cannot run, `job` is released,
/// which closes the channels it holds.
pub fn spawn(ctx: anytype, comptime task: anytype, job: anytype) !void {
    var owned = job;
    const handle = ctx.spawn(task, .{owned}) catch |err| {
        owned.deinit();
        return err;
    };
    if (handle.header == null) return owned.deinit(); // The context was aborted.
    handle.detach();
}

/// The coding config of `scheme`'s participants (commonware's
/// `coding_config_for_participants` over `scheme.participants().len()`).
pub fn coding_config(scheme: anytype) CodingConfig {
    const participants = scheme.participants().len();
    if (participants > std.math.maxInt(u16)) @panic("too many participants");
    const config = types.coding_config_for_participants(@intCast(participants));
    assert(config.minimum_shards + config.extra_shards == participants);
    return config;
}

/// Maps a gate outcome to a certify verdict: recovery applies no verdict.
const ReadyMap = struct {
    pub fn call(_: ReadyMap, outcome: GateOutcome) ?bool {
        return switch (outcome) {
            .ready => |valid| valid,
            .recover => null,
        };
    }
};

/// Maps the assigned shard's verification to a verify verdict.
const VerifiedMap = struct {
    pub fn call(_: VerifiedMap, _: void) ?bool {
        return true;
    }
};

/// The jobs and tasks of the wrapper `M` (marshaled.zig's `Marshaled`).
pub fn Tasks(comptime M: type) type {
    return struct {
        const CodedBlock = M.CodedBlock;
        const Commitment = M.Commitment;
        const Context = M.Context;
        const E = M.RuntimeContext;
        const A = M.Application;
        const H = M.Hasher;
        const V = M.V;
        const Digested = broadcast.Digested(V.ApplicationBlock);

        /// The block a deferred verification checks: prefetched, or awaited locally.
        pub const Candidate = union(enum) {
            block: CodedBlock,
            request: oneshot.Receiver(CodedBlock),

            pub fn deinit(candidate: *Candidate, gpa: Allocator) void {
                switch (candidate.*) {
                    .block => |*block| V.deinit_block(gpa, block),
                    .request => |*request| request.deinit(),
                }
            }
        };

        pub const VerifyJob = struct {
            marshaled: M,
            application: A,
            consensus_context: Context,
            commitment: Commitment,
            candidate: ?Candidate,
            stage: Stage,
            output: ?oneshot.Sender(GateOutcome),

            pub fn deinit(job: *VerifyJob) void {
                const gpa = job.marshaled.shared.context.gpa();
                if (job.candidate) |*candidate| candidate.deinit(gpa);
                job.candidate = null;
                release_sender(GateOutcome, &job.output);
                deinit_application(&job.application);
                job.marshaled.deinit();
            }
        };

        /// Commonware's `deferred_verify` task.
        pub fn deferred_verify(ctx: E, job: VerifyJob) void {
            var owned = job;
            defer owned.deinit();
            run_deferred_verify(ctx, &owned) catch {};
        }

        fn run_deferred_verify(ctx: E, job: *VerifyJob) !void {
            const shared = job.marshaled.shared;
            const io = ctx.io();
            const consensus_context = job.consensus_context;
            const parent_view, const parent_commitment = consensus_context.parent;
            // Fetch the parent alongside the candidate. Its round comes from the caller's
            // context (certified, or quorum-defended), never from the unverified block.
            var parent_request = try shared.marshal.subscribe_by_commitment(parent_commitment, .{
                .fetch_by_round = .new(consensus_context.epoch(), parent_view),
            });
            defer parent_request.deinit();
            var block = try take_candidate(io, job) orelse return;
            defer V.deinit_block(ctx.gpa(), &block);
            // Store at once: the caches provide availability, not a validity decision, so
            // the gate resolves true only once the verdict is valid and the store durable.
            const round = consensus_context.round;
            const stored = V.clone_block(&block);
            var store = io.async(store_candidate, .{ shared.marshal, job.stage, round, stored });
            const verdict = verify_candidate(ctx, job, &block, &parent_request) catch |err| {
                _ = store.cancel(io);
                return err;
            };
            const durable = store.await(io);
            const resolved = gates.resolve(verdict, durable) orelse return;
            answer(GateOutcome, &job.output, .{ .ready = resolved });
        }

        fn store_candidate(marshal: M.Mailbox, stage: Stage, round: Round, block: CodedBlock) bool {
            return stage.store(marshal, round, block) catch false;
        }

        /// The candidate block, or null when consensus dropped the gate or the block never
        /// reconstructs locally (candidates are never requested from peers).
        fn take_candidate(io: Io, job: *VerifyJob) Io.Cancelable!?CodedBlock {
            var candidate = job.candidate.?;
            job.candidate = null;
            switch (candidate) {
                .block => |block| return block,
                .request => |*request| {
                    defer request.deinit();
                    const output = &job.output.?;
                    const received = try recv_unless_closed(
                        GateOutcome,
                        CodedBlock,
                        io,
                        output,
                        request,
                    ) orelse return null;
                    return received catch |err| switch (err) {
                        error.Closed => null,
                        error.Canceled => error.Canceled,
                    };
                },
            }
        }

        /// The application's verdict on `block` once its parent arrives: false when the block
        /// breaks a coded invariant, null when verification stops early.
        fn verify_candidate(
            ctx: E,
            job: *VerifyJob,
            block: *const CodedBlock,
            parent_request: *oneshot.Receiver(CodedBlock),
        ) Io.Cancelable!?bool {
            const shared = job.marshaled.shared;
            const gpa = ctx.gpa();
            const output = &job.output.?;
            const received = try recv_unless_closed(
                GateOutcome,
                CodedBlock,
                ctx.io(),
                output,
                parent_request,
            ) orelse return null;
            var parent = received catch |err| switch (err) {
                error.Closed => return null,
                error.Canceled => return error.Canceled,
            };
            defer V.deinit_block(gpa, &parent);
            const parent_view: *const CodedBlock = &parent;
            const consensus_context = job.consensus_context;
            const parent_commitment = consensus_context.parent[1];
            validation.validate_block(
                H,
                gpa,
                shared.epocher,
                block,
                parent_view,
                consensus_context,
                job.commitment,
                parent_commitment,
            ) catch |err| return switch (err) {
                error.OutOfMemory => null,
                else => false,
            };
            return verify_application(ctx, job, block, parent_view);
        }

        /// Asks the application, over the ancestry of `block` and `parent`, while the gate
        /// is held.
        fn verify_application(
            ctx: E,
            job: *VerifyJob,
            block: *const CodedBlock,
            parent: *const CodedBlock,
        ) Io.Cancelable!?bool {
            const shared = job.marshaled.shared;
            const io = ctx.io();
            var initial = [2]Digested{ block.inner_digested(), parent.inner_digested() };
            const fetch = &shared.timers.ancestor_fetch_duration;
            // Unbounded: the coding provider bounds each parent by its child's context.
            const stream = shared.marshal.ancestor_stream(&initial, null, fetch) catch {
                for (&initial) |*shared_block| shared_block.deinit();
                return null;
            };
            const timer = shared.timers.verify_duration.timer(io);
            const app_ctx = ctx.child("app_verify");
            const args = .{ &job.application, app_ctx, job.consensus_context, stream };
            const output = &job.output.?;
            const Verify = Return(A.verify);
            const result = try unless_closed(GateOutcome, io, output, A.verify, args, Ignore(
                Verify,
            ).call);
            timer.observe(io);
            const verdict = result orelse return null;
            return verdict catch null;
        }

        pub const EmbeddedJob = struct {
            marshaled: M,
            round: Round,
            payload: Commitment,
            request: ?oneshot.Receiver(CodedBlock),
            output: ?oneshot.Sender(bool),

            pub fn deinit(job: *EmbeddedJob) void {
                release_receiver(CodedBlock, &job.request);
                release_sender(bool, &job.output);
                job.marshaled.deinit();
            }
        };

        /// Commonware's `certify_from_embedded_context` task.
        pub fn certify_embedded(ctx: E, job: EmbeddedJob) void {
            var owned = job;
            defer owned.deinit();
            run_certify_embedded(ctx, &owned) catch {};
        }

        fn run_certify_embedded(ctx: E, job: *EmbeddedJob) !void {
            const io = ctx.io();
            const shared = job.marshaled.shared;
            const output = &job.output.?;
            const request = &job.request.?;
            const received = try recv_unless_closed(bool, CodedBlock, io, output, request) orelse
                return;
            const block = received catch |err| switch (err) {
                error.Closed => return,
                error.Canceled => return error.Canceled,
            };
            const embedded = block.context();
            // Re-proposals keep their original embedded context: a boundary block certified
            // in a later view of its epoch is one, and is certified without verifying.
            const reproposal = app_validation.is_inferred_reproposal_at_certify(
                shared.epocher,
                block.height(),
                embedded.round,
                job.round,
            );
            if (reproposal) {
                // A notarization exists, so the block goes to the notarized cache.
                if (try shared.marshal.certified(job.round, block)) answer(bool, &job.output, true);
                return;
            }
            const marshaled = job.marshaled;
            const verdict = try marshaled.deferred_verify(embedded, job.payload, block, .certified);
            const sender = job.output.?;
            job.output = null;
            try gates.forward(bool, GateOutcome, io, sender, verdict, ReadyMap{});
        }

        pub const ExistingJob = struct {
            marshaled: M,
            round: Round,
            payload: Commitment,
            gate: ?gates.Gate,
            output: ?oneshot.Sender(bool),

            pub fn deinit(job: *ExistingJob) void {
                release_receiver(GateOutcome, &job.gate);
                release_sender(bool, &job.output);
                job.marshaled.deinit();
            }
        };

        /// Recovers through the embedded context when the gate gives no verdict.
        const Fallback = struct {
            marshaled: M,
            round: Round,
            payload: Commitment,

            pub fn call(self: Fallback) !oneshot.Receiver(bool) {
                return self.marshaled.certify_from_embedded_context(self.round, self.payload);
            }
        };

        /// Commonware's `certify_from_existing_task` task.
        pub fn certify_existing(ctx: E, job: ExistingJob) void {
            var owned = job;
            defer owned.deinit();
            const output = owned.output.?;
            owned.output = null;
            const gate = owned.gate.?;
            owned.gate = null;
            const fallback: Fallback = .{
                .marshaled = owned.marshaled,
                .round = owned.round,
                .payload = owned.payload,
            };
            gates.drive(ctx.io(), output, gate, fallback) catch {};
        }

        pub const ValidityJob = struct {
            input: ?oneshot.Receiver(void),
            output: ?oneshot.Sender(bool),

            pub fn deinit(job: *ValidityJob) void {
                release_receiver(void, &job.input);
                release_sender(bool, &job.output);
            }
        };

        /// Answers a signer's verify once its assigned shard is verified.
        pub fn shard_validity(ctx: E, job: ValidityJob) void {
            var owned = job;
            const input = owned.input.?;
            const output = owned.output.?;
            owned = .{ .input = null, .output = null };
            gates.forward(bool, void, ctx.io(), output, input, VerifiedMap{}) catch {};
        }

        pub const ReproposalJob = struct {
            marshaled: ?M,
            round: Round,
            payload: Commitment,
            request: ?oneshot.Receiver(CodedBlock) = null,
            gate: ?oneshot.Sender(GateOutcome) = null,
            output: ?oneshot.Sender(bool) = null,

            pub fn deinit(job: *ReproposalJob) void {
                release_receiver(CodedBlock, &job.request);
                release_sender(GateOutcome, &job.gate);
                release_sender(bool, &job.output);
                if (job.marshaled) |*marshaled| marshaled.deinit();
                job.marshaled = null;
            }
        };

        /// Commonware's re-proposal verification task.
        pub fn verify_reproposal(ctx: E, job: ReproposalJob) void {
            var owned = job;
            defer owned.deinit();
            run_verify_reproposal(ctx, &owned) catch {};
        }

        fn run_verify_reproposal(ctx: E, job: *ReproposalJob) !void {
            const shared = job.marshaled.?.shared;
            var block = try reproposal_block(ctx.io(), job) orelse return;
            // The boundary check reads only the block's height and the round's epoch, and the
            // commitment binds the original context, so a rejection is a safe gate verdict.
            const epoch = job.round.epoch;
            const height = block.height();
            if (!app_validation.is_valid_reproposal_at_verify(shared.epocher, height, epoch)) {
                V.deinit_block(ctx.gpa(), &block);
                answer(GateOutcome, &job.gate, .{ .ready = false });
                answer(bool, &job.output, false);
                return;
            }
            // Announce only after the boundary check: the shard engine reads the participants
            // from the round's epoch, which the commitment does not bind for a re-proposal.
            shared.shards.gather(job.payload, job.round) catch |err| {
                V.deinit_block(ctx.gpa(), &block);
                return err;
            };
            if (!try shared.marshal.verified(job.round, block)) return;
            answer(GateOutcome, &job.gate, .{ .ready = true });
            answer(bool, &job.output, true);
        }

        /// The re-proposed block, or null once consensus drops the verify request or the
        /// gates drop the certification gate, or when the block cannot be fetched (an
        /// availability issue, not a proof of invalidity).
        fn reproposal_block(io: Io, job: *ReproposalJob) Io.Cancelable!?CodedBlock {
            const Outcome = union(enum) {
                verify_closed: Io.Cancelable!void,
                gate_closed: Io.Cancelable!void,
                block: oneshot.RecvError!CodedBlock,
            };
            var buffer: [3]Outcome = undefined;
            var select: Io.Select(Outcome) = .init(io, &buffer);
            const output = job.output.?;
            select.concurrent(.verify_closed, oneshot.Sender(bool).closed, .{output}) catch {
                return error.Canceled;
            };
            const gate = job.gate.?;
            const gate_closed = oneshot.Sender(GateOutcome).closed;
            select.concurrent(.gate_closed, gate_closed, .{gate}) catch {
                select.cancelDiscard();
                return error.Canceled;
            };
            const recv = oneshot.Receiver(CodedBlock).recv;
            select.concurrent(.block, recv, .{&job.request.?}) catch {
                select.cancelDiscard();
                return error.Canceled;
            };
            const discard = Discard(CodedBlock).call;
            const first = select.await() catch |err| {
                while (select.cancel()) |rest| if (rest == .block) discard(rest.block);
                return err;
            };
            while (select.cancel()) |rest| if (rest == .block) discard(rest.block);
            return switch (first) {
                .verify_closed, .gate_closed => null,
                .block => |result| result catch |err| switch (err) {
                    error.Closed => null,
                    error.Canceled => error.Canceled,
                },
            };
        }

        /// The proposal checks (commonware `checks`) for the build tasks: skip without a
        /// scheme, a parent marshal cannot obtain, or a parent outside the epoch; re-propose
        /// the epoch's last block; otherwise build on the parent's ancestry under the epoch's
        /// coding config.
        pub const Checks = struct {
            shared: *M.Shared,
            consensus_context: Context,
            parent_fallback: CommitmentFallback,

            pub fn call(self: Checks) !M.Resolved {
                const shared = self.shared;
                const io = shared.context.io();
                const gpa = shared.context.gpa();
                const consensus_context = self.consensus_context;
                const epoch = consensus_context.epoch();
                const scheme = shared.scheme_provider.scheme(epoch) orelse return .skip;
                const config = coding_config(scheme);
                const parent_view, const parent_commitment = consensus_context.parent;
                var request = try shared.marshal.subscribe_by_commitment(
                    parent_commitment,
                    self.parent_fallback,
                );
                defer request.deinit();
                const timer = shared.timers.parent_fetch_duration.timer(io);
                var parent = request.recv() catch |err| switch (err) {
                    error.Closed => return .skip,
                    error.Canceled => return error.Canceled,
                };
                timer.observe(io);
                // A handoff parent may be uncertified at any height: build only on one in the
                // request's epoch. View zero is the epoch's genesis, the previous boundary.
                const in_epoch = app_validation.is_block_in_expected_epoch(
                    shared.epocher,
                    parent.height(),
                    epoch,
                );
                if (parent_view.get() != 0 and !in_epoch) {
                    V.deinit_block(gpa, &parent);
                    return .skip;
                }
                const last = shared.epocher.last(epoch) orelse @panic("current epoch should exist");
                if (parent.height().get() == last.get()) {
                    return .{ .reuse = .{ .digest = parent.commitment(), .block = parent } };
                }
                defer V.deinit_block(gpa, &parent);
                return .{ .build = .{
                    .ancestry = try ancestry_of(shared, &parent),
                    .metadata = config,
                } };
            }

            pub fn release(_: Checks, result: anytype) void {
                var resolved = result catch return;
                switch (resolved) {
                    .reuse => |*reuse| reuse.block.discard(),
                    .build => |*built| built.ancestry.deinit(),
                    .skip => {},
                }
            }
        };

        fn ancestry_of(shared: *M.Shared, parent: *const CodedBlock) !M.Ancestry {
            var initial = [1]Digested{parent.inner_digested()};
            const fetch = &shared.timers.ancestor_fetch_duration;
            // Unbounded: the coding provider bounds each parent by its child's context.
            return shared.marshal.ancestor_stream(&initial, null, fetch) catch |err| {
                initial[0].deinit();
                return err;
            };
        }

        /// Erasure codes a built block into its staged form (the build tasks' seal).
        pub const Seal = struct {
            shared: *M.Shared,

            pub fn call(
                self: Seal,
                block: Digested,
                config: CodingConfig,
            ) !struct { Commitment, CodedBlock } {
                const shared = self.shared;
                const io = shared.context.io();
                const timer = shared.timers.erasure_encode_duration.timer(io);
                const gpa = shared.context.gpa();
                const encoded = CodedBlock.encode(gpa, block, config, shared.strategy);
                const coded = encoded catch |err| {
                    var owned = block;
                    owned.deinit();
                    return err;
                };
                timer.observe(io);
                assert(coded.config().eql(config));
                return .{ coded.commitment(), coded };
            }
        };

        /// Persists a claimed staged proposal without broadcasting it.
        pub const Persist = struct {
            marshal: M.Mailbox,
            round: Round,

            pub fn call(self: Persist, block: CodedBlock, ack: oneshot.Sender(void)) void {
                // Rust aborts on allocation failure.
                self.marshal.verified_deferred(self.round, block, ack) catch
                    @panic("out of memory");
            }
        };

        /// The application handle a build task owns: a wrapper handle, which keeps the
        /// checks' and seal's shared state alive, and a clone of the application.
        pub const Handle = if (@hasDecl(A, "prepare")) PreparingHandle else PlainHandle;

        const PlainHandle = struct {
            marshaled: M,
            application: A,

            pub fn clone(self: PlainHandle) PlainHandle {
                return clone_handle(PlainHandle, self);
            }

            pub fn deinit(self: *PlainHandle) void {
                deinit_handle(self);
            }

            pub fn propose(
                self: *PlainHandle,
                ctx: E,
                consensus_context: Context,
                stream: M.Ancestry,
            ) Return(A.propose) {
                return self.application.propose(ctx, consensus_context, stream);
            }
        };

        const PreparingHandle = struct {
            marshaled: M,
            application: A,

            pub fn clone(self: PreparingHandle) PreparingHandle {
                return clone_handle(PreparingHandle, self);
            }

            pub fn deinit(self: *PreparingHandle) void {
                deinit_handle(self);
            }

            pub fn propose(
                self: *PreparingHandle,
                ctx: E,
                consensus_context: Context,
                stream: M.Ancestry,
            ) Return(A.propose) {
                return self.application.propose(ctx, consensus_context, stream);
            }

            pub fn prepare(
                self: *PreparingHandle,
                ctx: E,
                consensus_context: Context,
                stream: M.Ancestry,
            ) Return(A.prepare) {
                return self.application.prepare(ctx, consensus_context, stream);
            }
        };

        fn clone_handle(comptime T: type, handle: T) T {
            const marshaled = handle.marshaled.clone();
            assert(marshaled.shared == handle.marshaled.shared);
            const application = clone_application(handle.application);
            return .{ .marshaled = marshaled, .application = application };
        }

        fn deinit_handle(handle: anytype) void {
            deinit_application(&handle.application);
            handle.marshaled.deinit();
            handle.* = undefined;
        }
    };
}
