//! The consensus application wrapper of the coding marshal (commonware
//! `marshal/coding/marshaled.rs`): epochs, erasure coded broadcast, and block dissemination.
//!
//! `Marshaled` wraps an application and serves the consensus engine as its automaton, relay,
//! and reporter. A proposal is built through `application.build`, erasure coded, and staged
//! before consensus hears of its commitment; the relay broadcast hands it to marshal, which
//! disperses its shards. At the last block of an epoch the boundary block is re-proposed
//! instead of building blocks the epoch transition would cut out.
//!
//! Verifying a proposal checks the coding config and the context digest its commitment binds,
//! starts gathering its shards, and starts a deferred verification that waits for the block to
//! reconstruct locally, then checks it against its parent and the context and asks the
//! application. A signer answers only once its assigned shard is verified; a node that cannot
//! sign answers at once. Certification consumes the deferred verification's gate, or, without
//! one (a certificate for a block never verified here, or a restart), recovers the block by
//! round and verifies it under its embedded context.
//!
//! Commonware's automaton methods return a oneshot receiver: here the `start_*` methods do,
//! and `propose`, `verify`, `prepare`, and `certify` block on that receiver to meet the Zig
//! `Automaton` contract (consensus/traits.zig). Dropping a receiver, or canceling a blocking
//! call, abandons the work as commonware's dropped receiver does.
//!
//! The application provides `propose` (and optionally `prepare`) as application/build.zig
//! describes, and `verify(*A, ctx, consensus_context, ancestry) !bool`, which owns the
//! ancestry, must free it, and must be cancelable. It is cloned (`clone`/`deinit`) into each
//! task when it declares them. The wrapper is a shared handle (`clone`/`deinit`); its tasks
//! hold their own handle, so they may outlive the caller's.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const broadcast = @import("broadcast");
const coding = @import("coding");
const runtime = @import("runtime");
const utils = @import("utils");

const types = @import("types.zig");
const validation = @import("validation.zig");
const variant = @import("variant.zig");
const shards_mailbox = @import("shards/mailbox.zig");
const ancestry = @import("../ancestry.zig");
const core_mailbox = @import("../core/mailbox.zig");
const build = @import("../application/build.zig");
const gates = @import("../application/gates.zig");
const relay = @import("../application/relay.zig");
const app_validation = @import("../application/validation.zig");
const traits = @import("../../traits.zig");
const consensus_types = @import("../../types.zig");
const simplex = @import("../../simplex/root.zig");
const simplex_types = @import("../../simplex/types.zig");

const oneshot = utils.channel.oneshot;
const Feedback = actor.Feedback;
const CodingConfig = coding.Config;
const Timed = runtime.telemetry.metrics.histogram.Timed;
const GateOutcome = gates.GateOutcome;
const Stage = app_validation.Stage;
const Round = consensus_types.Round;
const Handoff = traits.Handoff;

/// The scheme a provider `Z` returns from `scheme(epoch) ?*const Scheme`.
fn SchemeOf(comptime Z: type) type {
    const Return = @typeInfo(@TypeOf(Z.scheme)).@"fn".return_type.?;
    return @typeInfo(@typeInfo(Return).optional.child).pointer.child;
}

const tasks_module = @import("marshaled_tasks.zig");
const Tasks = tasks_module.Tasks;
const answer = tasks_module.answer;
const release_sender = tasks_module.release_sender;
const clone_application = tasks_module.clone_application;
const deinit_application = tasks_module.deinit_application;
const spawn = tasks_module.spawn;

/// The wrapper's configuration (commonware `MarshaledConfig`), moved into `Marshaled.init`.
pub fn MarshaledConfig(
    comptime A: type,
    comptime Mailbox: type,
    comptime Shards: type,
    comptime Z: type,
    comptime St: type,
    comptime ES: type,
) type {
    return struct {
        /// The application to wrap.
        application: A,
        /// The marshal actor's mailbox (owned).
        marshal: Mailbox,
        /// The shards engine's mailbox (owned).
        shards: Shards,
        /// The signing scheme of each epoch (`scheme(epoch) ?*const Scheme`).
        scheme_provider: Z,
        /// The strategy that erasure codes built blocks.
        strategy: St,
        /// The epoch boundaries.
        epocher: ES,
    };
}

/// The application wrapper over the types `T` declares: `Context` (the runtime context),
/// `Application`, `Block` (the application block), `Coding` (the coding scheme), `Hasher` (of
/// contexts), `Provider` (of each epoch's signing scheme), `Strategy` (erasure codes built
/// blocks), and `Epocher`.
pub fn Marshaled(comptime T: type) type {
    const E = T.Context;
    const A = T.Application;
    const B = T.Block;
    const C = T.Coding;
    const H = T.Hasher;
    const Z = T.Provider;
    const St = T.Strategy;
    const ES = T.Epocher;
    return struct {
        const Self = @This();
        comptime {
            consensus_types.assert_epocher(ES);
        }
        pub const Scheme = SchemeOf(Z);
        pub const PublicKey = Scheme.PublicKey;
        pub const V = variant.Coding(B, C, H, PublicKey);
        pub const Commitment = V.Commitment;
        pub const CodedBlock = V.Block;
        pub const Mailbox = core_mailbox.Mailbox(Scheme, V);
        pub const Shards = shards_mailbox.Mailbox(B, C, H);
        pub const Gates = gates.Gates(Commitment, V);
        pub const Config = MarshaledConfig(A, Mailbox, Shards, Z, St, ES);
        pub const Ancestry = ancestry.AncestorStream(Mailbox);
        /// The automaton's and relay's digest.
        pub const Digest = Commitment;
        /// The consensus context a proposal is made and verified in.
        pub const Context = simplex_types.Context(Commitment, PublicKey);
        pub const Plan = simplex.Plan(PublicKey);
        pub const Activity = simplex_types.Activity(Scheme, Commitment);
        pub const Resolved = build.Resolved(Commitment, CodedBlock, Ancestry, CodingConfig);
        pub const RuntimeContext = E;
        pub const Application = A;
        pub const Hasher = H;
        const tasks = Tasks(Self);

        /// The state the handles share (commonware's clones of each field).
        pub const Shared = struct {
            references: std.atomic.Value(u32),
            context: E,
            application: A,
            marshal: Mailbox,
            shards: Shards,
            scheme_provider: Z,
            strategy: St,
            epocher: ES,
            gates: Gates,
            timers: Timers,
        };

        shared: *Shared,

        /// Wraps `config.application`, registering the wrapper's histograms in `context`.
        pub fn init(context: E, config: Config) !Self {
            const gpa = context.gpa();
            const shared = try gpa.create(Shared);
            errdefer gpa.destroy(shared);
            var timers = try Timers.init(&context.scope);
            errdefer timers.deinit();
            var registry: Gates = try .init(gpa, context.io());
            errdefer registry.deinit();
            shared.* = .{
                .references = .init(1),
                .context = context,
                .application = config.application,
                .marshal = config.marshal,
                .shards = config.shards,
                .scheme_provider = config.scheme_provider,
                .strategy = config.strategy,
                .epocher = config.epocher,
                .gates = registry,
                .timers = timers,
            };
            assert(shared.references.load(.monotonic) == 1);
            return .{ .shared = shared };
        }

        /// Another handle to the same wrapper.
        pub fn clone(self: Self) Self {
            const previous = self.shared.references.fetchAdd(1, .monotonic);
            assert(previous > 0);
            return .{ .shared = self.shared };
        }

        /// Drops this handle; the last one releases the application, both mailboxes, the
        /// gates, and the histograms.
        pub fn deinit(self: *Self) void {
            const shared = self.shared;
            self.* = undefined;
            const previous = shared.references.fetchSub(1, .acq_rel);
            assert(previous > 0);
            if (previous > 1) return;
            deinit_application(&shared.application);
            shared.marshal.deinit();
            shared.shards.deinit();
            shared.gates.deinit();
            shared.timers.deinit();
            const gpa = shared.context.gpa();
            gpa.destroy(shared);
        }

        /// The gates the wrapper registers and prunes (for tests).
        pub fn gates_of(self: Self) Gates {
            return self.shared.gates;
        }

        fn allocator(self: Self) Allocator {
            return self.shared.context.gpa();
        }

        /// The coding config of the participants of `epoch`'s scheme, or null without one.
        fn coding_config(self: Self, epoch: consensus_types.Epoch) ?struct {
            config: CodingConfig,
            scheme: *const Scheme,
        } {
            const scheme = self.shared.scheme_provider.scheme(epoch) orelse return null;
            return .{ .config = tasks_module.coding_config(scheme), .scheme = scheme };
        }

        /// Starts verifying the block of `commitment` against `consensus_context` (commonware
        /// `deferred_verify`), from `prefetched` (owned) or the block once it reconstructs
        /// locally, which is subscribed before this returns. The gate resolves ready once the
        /// application's verdict is known and, for a valid block, the block is durable at
        /// `stage`.
        pub fn deferred_verify(
            self: Self,
            consensus_context: Context,
            commitment: Commitment,
            prefetched: ?CodedBlock,
            stage: Stage,
        ) !gates.Gate {
            var candidate: tasks.Candidate = if (prefetched) |block| .{ .block = block } else .{
                .request = try self.shared.marshal.subscribe_by_commitment(commitment, .wait),
            };
            const io = self.shared.context.io();
            var pair = oneshot.channel(GateOutcome, self.allocator(), io) catch |err| {
                candidate.deinit(self.allocator());
                return err;
            };
            errdefer pair.receiver.deinit();
            const ctx = self.shared.context.child("deferred_verify")
                .with_attribute("round", consensus_context.round);
            try spawn(ctx, tasks.deferred_verify, tasks.VerifyJob{
                .marshaled = self.clone(),
                .application = clone_application(self.shared.application),
                .consensus_context = consensus_context,
                .commitment = commitment,
                .candidate = candidate,
                .stage = stage,
                .output = pair.sender,
            });
            assert(prefetched != null or candidate == .request);
            return pair.receiver;
        }

        /// Certifies a block this node holds no gate for: recovers it by `round` and verifies
        /// it under its embedded context (a re-proposal is certified without verifying).
        pub fn certify_from_embedded_context(
            self: Self,
            round: Round,
            payload: Commitment,
        ) !oneshot.Receiver(bool) {
            const request = try self.shared.marshal.subscribe_by_commitment(payload, .{
                .fetch_by_round = round,
            });
            var job: tasks.EmbeddedJob = .{
                .marshaled = self.clone(),
                .round = round,
                .payload = payload,
                .request = request,
                .output = null,
            };
            const io = self.shared.context.io();
            var pair = oneshot.channel(bool, self.allocator(), io) catch |err| {
                job.deinit();
                return err;
            };
            errdefer pair.receiver.deinit();
            job.output = pair.sender;
            const ctx = self.shared.context.child("certify").with_attribute("round", round);
            try spawn(ctx, tasks.certify_embedded, job);
            assert(job.request != null);
            return pair.receiver;
        }

        /// Certifies through the gate `task` (taking it): a ready verdict applies, and
        /// recovery falls back to the embedded context.
        fn certify_from_existing_task(
            self: Self,
            round: Round,
            payload: Commitment,
            task: gates.Gate,
        ) !oneshot.Receiver(bool) {
            var gate = task;
            // Verification waits only for local data; now that a notarization exists, a
            // block that never reconstructs is recovered by round.
            self.shared.marshal.hint_notarized(round, payload) catch |err| {
                gate.deinit();
                return err;
            };
            const io = self.shared.context.io();
            var pair = oneshot.channel(bool, self.allocator(), io) catch |err| {
                gate.deinit();
                return err;
            };
            errdefer pair.receiver.deinit();
            const ctx = self.shared.context.child("certify_existing")
                .with_attribute("round", round);
            try spawn(ctx, tasks.certify_existing, tasks.ExistingJob{
                .marshaled = self.clone(),
                .round = round,
                .payload = payload,
                .gate = gate,
                .output = pair.sender,
            });
            return pair.receiver;
        }

        /// Starts a proposal (commonware `Automaton::propose`): the receiver yields the
        /// staged commitment, or closes when no block is proposed.
        pub fn start_propose(self: Self, consensus_context: Context) !oneshot.Receiver(Digest) {
            const parent_view = consensus_context.parent[0];
            const fallback: core_mailbox.CommitmentFallback = .{
                .fetch_by_round = .new(consensus_context.epoch(), parent_view),
            };
            const checks: tasks.Checks = .{
                .shared = self.shared,
                .consensus_context = consensus_context,
                .parent_fallback = fallback,
            };
            const handle: tasks.Handle = .{
                .marshaled = self,
                .application = self.shared.application,
            };
            assert(handle.marshaled.shared == self.shared);
            const shared = self.shared;
            const seal: tasks.Seal = .{ .shared = shared };
            const timer = &shared.timers.build_duration;
            const registry = shared.gates;
            return build.propose(
                Digest,
                shared.context,
                handle,
                registry,
                consensus_context,
                checks,
                seal,
                timer,
            );
        }

        /// Starts a term-start proposal on an uncertified parent (commonware
        /// `CertifiableAutomaton::prepare`): the same checks as a proposal, but a parent
        /// missing locally is awaited rather than fetched.
        pub fn start_prepare(
            self: Self,
            consensus_context: Context,
        ) !oneshot.Receiver(Handoff(Digest)) {
            const checks: tasks.Checks = .{
                .shared = self.shared,
                .consensus_context = consensus_context,
                .parent_fallback = .wait,
            };
            const handle: tasks.Handle = .{
                .marshaled = self,
                .application = self.shared.application,
            };
            assert(handle.marshaled.shared == self.shared);
            const shared = self.shared;
            const seal: tasks.Seal = .{ .shared = shared };
            const timer = &shared.timers.build_duration;
            const registry = shared.gates;
            return build.prepare(
                Digest,
                shared.context,
                handle,
                registry,
                consensus_context,
                checks,
                seal,
                timer,
            );
        }

        /// Starts verifying the proposal `payload` (commonware `Automaton::verify`).
        pub fn start_verify(
            self: Self,
            consensus_context: Context,
            payload: Commitment,
        ) !oneshot.Receiver(bool) {
            const io = self.shared.context.io();
            var pair = try oneshot.channel(bool, self.allocator(), io);
            errdefer pair.receiver.deinit();
            // Without a scheme for the epoch we cannot vote: the receiver closes.
            const epoch = self.coding_config(consensus_context.epoch()) orelse {
                pair.sender.deinit();
                return pair.receiver;
            };
            const is_reproposal = payload.eql(consensus_context.parent[1]);
            // A re-proposal's commitment keeps the original proposal's context.
            const proposal_context: ?Context = if (is_reproposal) null else consensus_context;
            const valid = validation.validate_proposal(
                H,
                self.allocator(),
                payload,
                epoch.config,
                proposal_context,
            );
            valid catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.CodingConfig, error.ContextDigest => {
                    pair.sender.send(false) catch {};
                    return pair.receiver;
                },
            };
            if (is_reproposal) {
                try self.verify_reproposal(consensus_context, payload, pair.sender);
                return pair.receiver;
            }
            try self.verify_proposal(consensus_context, payload, epoch.scheme, pair.sender);
            return pair.receiver;
        }

        /// Verifies a fresh proposal: gathers its shards, starts its deferred verification
        /// as its certification gate, and answers once the assigned shard is verified (at
        /// once for a node that cannot sign).
        fn verify_proposal(
            self: Self,
            consensus_context: Context,
            payload: Commitment,
            scheme: *const Scheme,
            output: oneshot.Sender(bool),
        ) !void {
            var sender: ?oneshot.Sender(bool) = output;
            errdefer release_sender(bool, &sender);
            const round = consensus_context.round;
            // The context digest validated above binds this round to the commitment.
            try self.shared.shards.gather(payload, round);
            // The gate, not consensus's receiver, cancels the deferred verification:
            // nullification drops the verify receiver, but certification still needs it.
            var task = try self.deferred_verify(consensus_context, payload, null, .verified);
            self.shared.gates.insert(round, payload, task) catch |err| {
                task.deinit();
                return err;
            };
            const me = scheme.me();
            const signer = if (me) |membership| membership.signer_index() != null else false;
            // A node that cannot sign casts no notarize vote: it waits for nothing.
            if (!signer) return answer(bool, &sender, true);
            const validity = try self.shared.shards.subscribe_assigned_shard_verified(payload);
            const ctx = self.shared.context.child("shard_validity_wait")
                .with_attribute("round", round);
            const job: tasks.ValidityJob = .{ .input = validity, .output = sender };
            sender = null;
            try spawn(ctx, tasks.shard_validity, job);
        }

        /// Verifies a re-proposal: the block named its own parent, so it is acquired by the
        /// parent's round and accepted when it is the epoch's boundary block.
        fn verify_reproposal(
            self: Self,
            consensus_context: Context,
            payload: Commitment,
            output: oneshot.Sender(bool),
        ) !void {
            var job: tasks.ReproposalJob = .{
                .marshaled = self.clone(),
                .round = consensus_context.round,
                .payload = payload,
                .request = null,
                .gate = null,
                .output = output,
            };
            errdefer job.deinit();
            const parent_view = consensus_context.parent[0];
            job.request = try self.shared.marshal.subscribe_by_commitment(payload, .{
                .fetch_by_round = .new(consensus_context.epoch(), parent_view),
            });
            // Register the gate before spawning, so certify always finds it.
            var gate = try oneshot.channel(GateOutcome, self.allocator(), self.shared.context.io());
            job.gate = gate.sender;
            self.shared.gates.insert(job.round, payload, gate.receiver) catch |err| {
                gate.receiver.deinit();
                return err;
            };
            const ctx = self.shared.context.child("verify_reproposal")
                .with_attribute("round", job.round);
            const owned = job;
            job = .{ .marshaled = null, .round = owned.round, .payload = payload };
            try spawn(ctx, tasks.verify_reproposal, owned);
        }

        /// Starts certifying `payload` at `round` (commonware
        /// `CertifiableAutomaton::certify`).
        pub fn start_certify(
            self: Self,
            round: Round,
            payload: Commitment,
        ) !oneshot.Receiver(bool) {
            // Certify may come without a verify, or while a re-proposal's verify still waits
            // for its block: it may be the first request to gather the commitment.
            try self.shared.shards.gather(payload, round);
            const persist: tasks.Persist = .{ .marshal = self.shared.marshal, .round = round };
            if (self.shared.gates.claim(round, payload, persist)) |task| {
                return self.certify_from_existing_task(round, payload, task);
            }
            return self.certify_from_embedded_context(round, payload);
        }

        /// `Automaton::propose`: the staged commitment, or null when no block is proposed.
        pub fn propose(self: *Self, io: Io, consensus_context: Context) Io.Cancelable!?Digest {
            _ = io;
            const started = self.start_propose(consensus_context);
            var receiver = started catch |err| return declined(Digest, err);
            return received(Digest, &receiver);
        }

        /// `Automaton::verify`: null when verification cannot conclude.
        pub fn verify(
            self: *Self,
            io: Io,
            consensus_context: Context,
            payload: Digest,
        ) Io.Cancelable!?bool {
            _ = io;
            const started = self.start_verify(consensus_context, payload);
            var receiver = started catch |err| return declined(bool, err);
            return received(bool, &receiver);
        }

        /// `CertifiableAutomaton::prepare`.
        pub fn prepare(
            self: *Self,
            io: Io,
            consensus_context: Context,
        ) Io.Cancelable!?Handoff(Digest) {
            _ = io;
            const started = self.start_prepare(consensus_context);
            var receiver = started catch |err| return declined(Handoff(Digest), err);
            return received(Handoff(Digest), &receiver);
        }

        /// `CertifiableAutomaton::certify`.
        pub fn certify(self: *Self, io: Io, round: Round, payload: Digest) Io.Cancelable!?bool {
            _ = io;
            const started = self.start_certify(round, payload);
            var receiver = started catch |err| return declined(bool, err);
            return received(bool, &receiver);
        }

        /// A request that could not start reads as a closed receiver; Rust aborts on
        /// allocation failure.
        fn declined(comptime Value: type, err: anyerror) Io.Cancelable!?Value {
            return switch (err) {
                error.OutOfMemory => @panic("out of memory"),
                error.Canceled => error.Canceled,
                else => null,
            };
        }

        fn received(comptime Value: type, receiver: *oneshot.Receiver(Value)) Io.Cancelable!?Value {
            defer receiver.deinit();
            return receiver.recv() catch |err| switch (err) {
                error.Closed => null,
                error.Canceled => error.Canceled,
            };
        }

        /// `Relay::broadcast`: relays a staged proposal through marshal. The coding variant
        /// does not forward: peers reconstruct blocks from shards.
        pub fn broadcast(self: *Self, commitment: Commitment, plan: Plan) Feedback {
            if (plan == .forward) return .ok;
            const shared = self.shared;
            const registry = shared.gates;
            const feedback = relay.broadcast(Scheme, V, registry, shared.marshal, commitment, plan);
            // Rust aborts on allocation failure; a relay cannot return it.
            return feedback catch @panic("out of memory");
        }

        /// `Reporter::report`: releases the gates of the rounds `activity` (borrowed) retires,
        /// then forwards it to marshal. A finalization retires its round and those below; any
        /// other activity retires every earlier epoch.
        pub fn report(self: *Self, activity: Activity) Feedback {
            const retired: Round = switch (activity) {
                .finalization => |finalization| finalization.round(),
                else => .new(activity.epoch(), .zero()),
            };
            self.shared.gates.retain_after(retired);
            return self.shared.marshal.report(activity);
        }
    };
}

/// The histograms of a wrapper (commonware `Marshaled`'s `Timed` fields).
const Timers = struct {
    build_duration: Timed,
    verify_duration: Timed,
    parent_fetch_duration: Timed,
    ancestor_fetch_duration: Timed,
    erasure_encode_duration: Timed,

    fn init(scope: *const runtime.telemetry.metrics.Scope) Allocator.Error!Timers {
        var built = try Timed.register(scope, "build_duration", "Histogram of time taken " ++
            "for the application to build a new block, in seconds");
        errdefer built.deinit();
        var verified = try Timed.register(scope, "verify_duration", "Histogram of time " ++
            "taken for the application to verify a block, in seconds");
        errdefer verified.deinit();
        var parent = try Timed.register(scope, "parent_fetch_duration", "Histogram of time " ++
            "taken to fetch a parent block in proposal, in seconds");
        errdefer parent.deinit();
        var ancestor = try Timed.register(scope, "ancestor_fetch_duration", "Histogram of " ++
            "time taken to fetch a block via the ancestry stream, in seconds");
        errdefer ancestor.deinit();
        const erasure = try Timed.register(scope, "erasure_encode_duration", "Histogram of " ++
            "time taken to erasure encode a built block on the strategy, in seconds");
        return .{
            .build_duration = built,
            .verify_duration = verified,
            .parent_fetch_duration = parent,
            .ancestor_fetch_duration = ancestor,
            .erasure_encode_duration = erasure,
        };
    }

    fn deinit(timers: *Timers) void {
        timers.build_duration.deinit();
        timers.verify_duration.deinit();
        timers.parent_fetch_duration.deinit();
        timers.ancestor_fetch_duration.deinit();
        timers.erasure_encode_duration.deinit();
        timers.* = undefined;
    }
};

test {
    _ = @import("marshaled_test.zig");
}
