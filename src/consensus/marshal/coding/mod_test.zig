//! commonware `marshal/coding/mod.rs`'s tests, on the coding harness (harness.zig) and the
//! direct-actor helpers (tests/common.zig).

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const harness = @import("harness.zig");
const shared = @import("../mocks/harness.zig");
const core_mailbox = @import("../core/mailbox.zig");
const common = @import("tests/common.zig");
const broadcast = @import("broadcast");
const parallel = @import("parallel");
const consensus_types = @import("../../types.zig");
const handler = @import("../resolver/handler.zig");

const gpa = testing.allocator;
const Mailbox = core_mailbox.Mailbox(shared.S, harness.CodingVariant);
const Ctx = common.Ctx;
const H = common.H;
const quorum = shared.quorum;

test "mailbox provides application blocks" {
    // commonware asserts `Mailbox<S, Coding<..>>: BlockProvider<Block = CodingB>`.
    try testing.expect(Mailbox.Block == harness.CodingB);
    try testing.expect(@hasDecl(Mailbox, "subscribe_parent"));
    try testing.expect(@hasDecl(Mailbox.ParentReceiver, "recv"));
}

/// The validators' fixture, seeded as commonware's `test_rng`.
fn fixture() !common.Fixture {
    var rng = utils.rng.test_rng();
    return H.fixture(gpa, &rng);
}

test "coding notarized delivery rejects dishonest payload config" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            const honest = common.committee_config();
            const dishonest = @import("types.zig").coding_config_for_participants(
                shared.num_validators + 3,
            );
            try testing.expect(!honest.eql(dishonest));

            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("actor_stack"),
                "coding-dishonest-payload-config",
                provider,
                buffer,
            );
            defer stack.stop();

            const genesis = try common.genesis_block(gpa);
            const round = common.round_at(0, 1);
            const context: common.CodingCtx = .{
                .round = round,
                .leader = validators.participants[0],
                .parent = .{ .zero(), try common.genesis_coding_commitment(gpa, &genesis) },
            };
            const candidate =
                try harness.make_coding_block(gpa, context, genesis.digest(), .new(1), 100);
            var block = try common.encode_block(gpa, candidate, dishonest);
            defer block.deinit(gpa);
            const proposal = common.Proposal.init(round, .zero(), block.commitment());
            var notarization = try H.make_notarization(gpa, &validators, proposal, quorum);
            defer notarization.deinit(gpa);
            const value = try common.encode_notarized(gpa, &notarization, &block);
            defer gpa.free(value);

            const accepted = try stack.resolver.deliver(.{
                .key = .{ .notarized = round },
                .subscriber = .{ .notarization = round },
            }, value);
            // Notarized delivery should reject a dishonest coding config.
            try testing.expect(!accepted);

            try ctx.sleep(.fromMilliseconds(100));
            // Dishonest deliveries must not store a block or archive a finalization.
            try testing.expect(try stack.mailbox.get_block(.{ .height = .new(1) }) == null);
            try testing.expect(try stack.mailbox.get_finalization(.new(1)) == null);
        }
    }.body);
}

test "coding block provider parent fetches by commitment" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("actor_stack"),
                "coding-provider-parent-commitment",
                provider,
                buffer,
            );
            defer stack.stop();

            const me = validators.participants[0];
            var parent = try common.missing_candidate(gpa, me);
            defer parent.block.deinit(gpa);
            // The child is in epoch 1; the validator does not hold its parent.
            const context: common.CodingCtx = .{
                .round = common.round_at(1, 2),
                .leader = me,
                .parent = .{ parent.context.round.view, parent.block.commitment() },
            };
            const raw =
                try harness.make_coding_block(gpa, context, parent.block.digest(), .new(2), 200);
            var child = try broadcast.Digested(common.CodingB).compute(gpa, raw);
            defer child.deinit();
            var subscription = try stack.mailbox.subscribe_parent(&child, null);
            defer subscription.deinit();

            try ctx.sleep(.fromMilliseconds(100));
            // Parent walkback should use the coding parent commitment.
            try testing.expectEqual(1, buffer.commitment_subscription_count());
            // The request is bounded by the parent's view in the child's epoch: the parent is
            // in epoch 0, so the bound shows which epoch the provider read.
            const fetches = try stack.resolver.fetches(gpa);
            defer gpa.free(fetches);
            try testing.expectEqual(1, fetches.len);
            const expected: common.Annotation = .{ .untrusted = .{
                .height = .new(1),
                .round = common.round_at(1, parent.context.round.view.get()),
            } };
            try testing.expect(fetches[0].subscriber.eql(expected));
        }
    }.body);
}

/// A running wrapper over a recorded actor and a shards engine (commonware's
/// `actor_stack`, `shard_stack`, and `Marshaled::new`). Must not move.
const Stack = struct {
    const M = common.MarshaledOf(common.MockVerifyingApp);

    buffer: common.RecordingCodingBuffer,
    actor: common.ActorStack,
    shards: common.ShardStack,
    marshaled: M,

    fn start(
        self: *Stack,
        ctx: Ctx,
        prefix: []const u8,
        validators: *const common.Fixture,
        provider: common.Provider,
    ) !void {
        self.buffer = try .init(gpa, ctx.io());
        errdefer self.buffer.deinit();
        const actor_ctx = ctx.child("actor_stack");
        self.actor =
            try common.start_coding_actor_with_recording(actor_ctx, prefix, provider, self.buffer);
        errdefer self.actor.stop();
        const shard_ctx = ctx.child("shard_stack");
        try common.start_shard_mailbox(&self.shards, shard_ctx, validators.participants, provider);
        errdefer self.shards.stop();
        const app = common.MockVerifyingApp.init(gpa);
        const marshal = self.actor.mailbox.clone();
        const config = common.marshaled_config(M, app, marshal, self.shards.shards(), provider);
        self.marshaled = try .init(ctx.child("marshaled"), config);
    }

    fn stop(self: *Stack) void {
        self.marshaled.deinit();
        self.shards.stop();
        self.actor.stop();
        self.buffer.deinit();
    }
};

/// A committee member's scheme without a signing share (commonware `S::member`).
fn member_scheme(validators: *const common.Fixture, me: common.K) !common.S {
    const verifier = &validators.verifier;
    const set = try verifier.participants().clone(gpa);
    if (shared.fast_schemes) {
        return (try common.S.member(gpa, shared.namespace, set, me)).?;
    }
    const sharing = try verifier.polynomial().clone(gpa);
    return (try common.S.member(gpa, shared.namespace, set, sharing, me)).?;
}

test "coding verify missing candidate waits without fetching" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var stack: Stack = undefined;
            try stack.start(ctx, "coding-verify-missing-candidate", &validators, provider);
            defer stack.stop();
            var candidate = try common.missing_candidate(gpa, validators.participants[0]);
            defer candidate.block.deinit(gpa);
            const commitment = candidate.block.commitment();

            var verify = try stack.marshaled.start_verify(candidate.context, commitment);
            defer verify.deinit();
            try ctx.sleep(.fromMilliseconds(100));

            // A missing candidate registers a local buffer wait and fetches nothing.
            try testing.expect(stack.buffer.subscription_count() > 0);
            try testing.expectEqual(0, stack.actor.resolver.fetch_count());
            try testing.expect(stack.actor.resolver.targeted_is_empty());
            // A signer's verification waits for its assigned shard.
            try testing.expectError(error.Empty, verify.try_recv());
        }
    }.body);
}

test "coding verify member accepts without assigned shard" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const me = validators.participants[0];
            var member = try member_scheme(&validators, me);
            defer member.deinit(gpa);
            try testing.expect(member.me().? == .member);
            const provider: common.Provider = .init(&member);
            var stack: Stack = undefined;
            try stack.start(ctx, "coding-verify-member", &validators, provider);
            defer stack.stop();
            var candidate = try common.missing_candidate(gpa, me);
            defer candidate.block.deinit(gpa);

            // No shard reaches the member, so prompt acceptance shows that verification did
            // not wait for the member's assigned shard.
            const commitment = candidate.block.commitment();
            var verify = try stack.marshaled.start_verify(candidate.context, commitment);
            defer verify.deinit();
            try ctx.sleep(.fromSeconds(1));
            try testing.expectEqual(true, try verify.try_recv());
        }
    }.body);
}

/// Whether `resolver` fetched the notarized block of `round` for a notarization subscriber.
fn fetched_by_round(resolver: common.RecordingResolver, round: common.Round) bool {
    return resolver.fetched(.{ .notarized = round }, .{ .notarization = round });
}

/// Primes the resolver to answer the next fetch with `candidate` notarized at its round.
fn respond_notarized(
    stack: *Stack,
    validators: *const common.Fixture,
    candidate: *const common.Block,
    round: common.Round,
) !void {
    const proposal = common.Proposal.init(round, .zero(), candidate.commitment());
    var notarization = try H.make_notarization(gpa, validators, proposal, quorum);
    defer notarization.deinit(gpa);
    const value = try common.encode_notarized(gpa, &notarization, candidate);
    defer gpa.free(value);
    try stack.actor.resolver.respond_to_next_fetch(value);
}

/// commonware's certify-recovery body; `verify_first` starts a verification first.
fn certify_fetches_by_round(ctx: Ctx, prefix: []const u8, verify_first: bool) !void {
    var validators = try fixture();
    defer validators.deinit(gpa);
    const provider: common.Provider = .init(&validators.schemes[0]);
    var stack: Stack = undefined;
    try stack.start(ctx, prefix, &validators, provider);
    defer stack.stop();
    var candidate = try common.missing_candidate(gpa, validators.participants[0]);
    defer candidate.block.deinit(gpa);
    const commitment = candidate.block.commitment();
    const round = candidate.context.round;
    var verify: ?utils.channel.oneshot.Receiver(bool) = null;
    defer if (verify) |*receiver| receiver.deinit();
    if (verify_first) verify = try stack.marshaled.start_verify(candidate.context, commitment);

    try respond_notarized(&stack, &validators, &candidate.block, round);
    var certify = try stack.marshaled.start_certify(round, commitment);
    defer certify.deinit();
    // The fetched notarized candidate certifies, and its delivery validates.
    try testing.expect(try certify.recv());
    const resolver = stack.actor.resolver;
    try testing.expect(try resolver.wait_for_delivery_response());
    try testing.expect(fetched_by_round(resolver, round));
    // The missing candidate registered a local buffer wait; nothing was targeted.
    try testing.expect(stack.buffer.subscription_count() > 0);
    try testing.expect(resolver.targeted_is_empty());
}

test "coding certify missing candidate fetches by round" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try certify_fetches_by_round(ctx, "coding-certify-missing-candidate", false);
        }
    }.body);
}

test "coding certify pending verify fetches by round" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try certify_fetches_by_round(ctx, "coding-certify-pending-verify", true);
        }
    }.body);
}

const gates = @import("../application/gates.zig");

/// A gate whose verification was dropped.
fn dropped_gate() !gates.Gate {
    var pair = try utils.channel.oneshot.channel(gates.GateOutcome, gpa, testing.io);
    pair.sender.deinit();
    return pair.receiver;
}

/// Registers a certification gate at view 5 of epoch 0 and at `notarized`, has the wrapper
/// report a notarization at `notarized`, and returns whether the gate at view 5 of epoch 0
/// remains (commonware `epoch_zero_gate_remains`).
fn epoch_zero_gate_remains(ctx: Ctx, notarized: common.Round) !bool {
    var validators = try fixture();
    defer validators.deinit(gpa);
    const provider: common.Provider = .init(&validators.schemes[0]);
    var stack: Stack = undefined;
    try stack.start(ctx, "coding-epoch-gates", &validators, provider);
    defer stack.stop();
    var candidate = try common.missing_candidate(gpa, validators.participants[0]);
    defer candidate.block.deinit(gpa);
    const commitment = candidate.block.commitment();
    const earlier = common.round_at(0, 5);
    const registry = stack.marshaled.gates_of();
    for ([_]common.Round{ earlier, notarized }) |round| {
        var gate = try dropped_gate();
        registry.insert(round, commitment, gate) catch |err| {
            gate.deinit();
            return err;
        };
    }
    const proposal = common.Proposal.init(notarized, .zero(), commitment);
    var notarization = try H.make_notarization(gpa, &validators, proposal, quorum);
    defer notarization.deinit(gpa);
    _ = stack.marshaled.report(.{ .notarization = notarization });

    // Certification of the notarized round follows its notarization, so the report must
    // keep its gate.
    var kept = registry.take(notarized, commitment) orelse return error.NotarizedGateDropped;
    kept.deinit();
    var remaining = registry.take(earlier, commitment) orelse return false;
    remaining.deinit();
    return true;
}

test "coding later epoch activity releases earlier epoch" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try testing.expect(!try epoch_zero_gate_remains(ctx, common.round_at(1, 1)));
        }
    }.body);
}

test "coding same epoch activity keeps gates" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try testing.expect(try epoch_zero_gate_remains(ctx, common.round_at(0, 7)));
        }
    }.body);
}

test "coding certify retains transient buffer hit through eviction" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var stack: Stack = undefined;
            try stack.start(ctx, "coding-certify-transient-buffer", &validators, provider);
            defer stack.stop();
            const candidate = try common.missing_candidate(gpa, validators.participants[0]);
            const commitment = candidate.block.commitment();
            const round = candidate.context.round;

            // The next lookup returns ownership while removing the buffer entry, modeling
            // shard engine eviction.
            try stack.buffer.insert_transient(candidate.block);
            var verify = try stack.marshaled.start_verify(candidate.context, commitment);
            defer verify.deinit();
            var certify = try stack.marshaled.start_certify(round, commitment);
            defer certify.deinit();

            // Ordered after the verification wait and the certification hint in the marshal
            // mailbox: once it returns, the one-shot hit and the eviction have both occurred.
            _ = try stack.actor.mailbox.get_processed();
            try testing.expect(!stack.buffer.contains(commitment));
            // Certify succeeds through the shared verification gate.
            try testing.expect(try certify.recv());
        }
    }.body);
}

/// The validator's verdict on `payload` under `context`.
fn verify_now(stack: *common.ValidatorStack, context: common.CodingCtx, payload: anytype) !bool {
    var receiver = try stack.marshaled.start_verify(context, payload);
    defer receiver.deinit();
    return receiver.recv();
}

/// The validator's certification of `payload` at `round`.
fn certify_now(stack: *common.ValidatorStack, round: common.Round, payload: anytype) !bool {
    var receiver = try stack.marshaled.start_certify(round, payload);
    defer receiver.deinit();
    return receiver.recv();
}

test "coding certify first block fetches genesis parent" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();

            const genesis = try common.genesis_block(gpa);
            const round = common.round_at(0, 1);
            const context: common.CodingCtx = .{
                .round = round,
                .leader = validators.participants[0],
                .parent = .{ .zero(), try common.genesis_coding_commitment(gpa, &genesis) },
            };
            const block = try common.coded(gpa, context, genesis.digest(), 1, 100);
            const commitment = block.commitment();
            try stack.shards().disperse(round, block);
            try ctx.sleep(.fromMilliseconds(10));

            // Shard validity passes, and the height-1 block certifies on genesis.
            try testing.expect(try verify_now(&stack, context, commitment));
            try testing.expect(try certify_now(&stack, round, commitment));
        }
    }.body);
}

test "coding repair reads buffer only ancestor" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const n = shared.num_validators;

            // A 2-block chain cached only in the shard engine.
            const genesis_parent = H.genesis_parent_commitment(n);
            const root = shared.genesis_parent();
            const parent = try H.make_test_block(gpa, root, genesis_parent, .new(1), 1, n);
            const parent_commitment = H.commitment(&parent);
            const descendant =
                try H.make_test_block(gpa, H.digest(&parent), parent_commitment, .new(2), 2, n);
            const descendant_commitment = H.commitment(&descendant);
            const shards = stack.shards();
            try shards.disperse(common.round_at(0, 1), parent);
            try shards.disperse(common.round_at(0, 2), descendant);
            inline for (.{ parent_commitment, descendant_commitment }) |commitment| {
                var found = (try shards.get(commitment)) orelse return error.NotCached;
                found.deinit(gpa);
            }

            // Only the descendant is finalized: repair walks its parent link and reads the
            // parent from the shard engine.
            const round = common.round_at(0, 2);
            const proposal = common.Proposal.init(round, .new(1), descendant_commitment);
            var finalization = try H.make_finalization(gpa, &validators, proposal, quorum);
            defer finalization.deinit(gpa);
            const mailbox = &stack.validator.mailbox;
            _ = mailbox.report(.{ .finalization = finalization });

            var waited: u32 = 0;
            while (true) : (waited += 1) {
                if (waited > 10_000) return error.TestTimedOut;
                var archived = (try mailbox.get_block(.{ .height = .new(2) })) orelse {
                    try ctx.sleep(.fromMilliseconds(1));
                    continue;
                };
                archived.deinit(gpa);
                break;
            }
            // Repair archived the parent from the shard engine.
            var repaired = (try mailbox.get_block(.{ .height = .new(1) })) orelse
                return error.ParentNotArchived;
            defer repaired.deinit(gpa);
            try testing.expect(repaired.commitment().eql(parent_commitment));
        }
    }.body);
}

test "certify lower view after higher view" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const me = validators.participants[0];
            const shards = stack.shards();

            const genesis = try common.genesis_block(gpa);
            const parent_context: common.CodingCtx = .{
                .round = common.round_at(0, 1),
                .leader = shared.default_leader(),
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            const parent = try common.coded(gpa, parent_context, genesis.digest(), 1, 100);
            const parent_digest = parent.digest();
            const parent_commitment = parent.commitment();
            try shards.disperse(common.round_at(0, 1), parent);

            // Blocks A (view 5) and B (view 10) at height 2 over the same parent.
            var contexts: [2]common.CodingCtx = undefined;
            var commitments: [2]common.Commitment = undefined;
            for ([_]u64{ 5, 10 }, [_]u64{ 200, 300 }, 0..) |view, timestamp, index| {
                contexts[index] = .{
                    .round = common.round_at(0, view),
                    .leader = me,
                    .parent = .{ .new(1), parent_commitment },
                };
                const block = try common.coded(gpa, contexts[index], parent_digest, 2, timestamp);
                commitments[index] = block.commitment();
                try shards.disperse(contexts[index].round, block);
            }
            try ctx.sleep(.fromMilliseconds(10));

            // Verify A, then B; certify B first, then A (which must still resolve).
            for (contexts, commitments) |context, commitment| {
                _ = try verify_now(&stack, context, commitment);
            }
            try testing.expect(try certify_now(&stack, contexts[1].round, commitments[1]));
            var certify_a = try stack.marshaled.start_certify(contexts[0].round, commitments[0]);
            defer certify_a.deinit();
            try ctx.sleep(.fromSeconds(5));
            try testing.expectEqual(true, try certify_a.try_recv());
        }
    }.body);
}

/// Waits up to `limit_ms` for `receiver` (a `oneshot.Receiver(void)`) to resolve, polling
/// every 10 ms.
fn recv_within(ctx: Ctx, receiver: *utils.channel.oneshot.Receiver(void), limit_ms: u64) !void {
    var waited: u64 = 0;
    while (waited < limit_ms) : (waited += 10) {
        receiver.try_recv() catch |err| switch (err) {
            error.Empty => {
                try ctx.sleep(.fromMilliseconds(10));
                continue;
            },
            error.Closed => return error.Closed,
        };
        return;
    }
    return error.TestTimedOut;
}

/// The chain the re-proposal tests build: heights 1 through 18 dispersed at the views of
/// their heights, the height-10 block's view and commitment, and the epoch boundary block
/// (height 19, the last of epoch 0).
const BoundaryChain = struct {
    non_boundary_view: u64,
    non_boundary: common.Commitment,
    boundary_round: common.Round,
    boundary: common.Block,

    fn build(gpa_: std.mem.Allocator, me: common.K, shards: anytype) !BoundaryChain {
        const genesis = try common.genesis_block(gpa_);
        var parent = genesis.digest();
        var last_view: u64 = 0;
        var last_commitment = harness.genesis_commitment();
        var result: BoundaryChain = undefined;
        for (1..shared.blocks_per_epoch - 1) |height| {
            const round = common.round_at(0, height);
            const context: common.CodingCtx = .{
                .round = round,
                .leader = me,
                .parent = .{ .new(last_view), last_commitment },
            };
            const block = try common.coded(gpa_, context, parent, height, height * 100);
            last_commitment = block.commitment();
            if (height == 10) {
                result.non_boundary_view = height;
                result.non_boundary = last_commitment;
            }
            parent = block.digest();
            last_view = height;
            try shards.disperse(round, block);
        }
        const boundary_height = shared.blocks_per_epoch - 1;
        result.boundary_round = common.round_at(0, boundary_height);
        const context: common.CodingCtx = .{
            .round = result.boundary_round,
            .leader = me,
            .parent = .{ .new(last_view), last_commitment },
        };
        const timestamp = boundary_height * 100;
        result.boundary = try common.coded(gpa_, context, parent, boundary_height, timestamp);
        return result;
    }
};

/// The context of a re-proposal of `payload` (proposed at `parent_view`) at `round`.
fn reproposal(
    round: common.Round,
    leader: common.K,
    parent_view: u64,
    payload: common.Commitment,
) common.CodingCtx {
    return .{ .round = round, .leader = leader, .parent = .{ .new(parent_view), payload } };
}

/// Sends participant 0's shard of `block` from `from` over the shard channel.
fn send_assigned_shard(
    stack: *common.ValidatorStack,
    from: common.K,
    block: *const common.Block,
) !void {
    const codec = @import("codec");
    const control = stack.network.network.oracle().control(from);
    var registered = try control.register(2, shared.test_quota);
    defer registered.deinit();
    var shard = (try block.shard(gpa, 0)) orelse return error.MissingShard;
    defer shard.deinit(gpa);
    const bytes = try codec.encode(common.Shard, gpa, shard);
    defer gpa.free(bytes);
    const me = stack.validator_key;
    const sent = try registered.sender.send(.{ .one = me }, &.{bytes}, true);
    gpa.free(sent);
}

test "marshaled reproposal validation" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const participants = validators.participants;
            const me = participants[0];
            try stack.network.link_all(participants[0..2], shared.link);
            const shards = stack.shards();
            var chain = try BoundaryChain.build(gpa, me, shards);
            defer chain.boundary.deinit(gpa);
            const boundary = chain.boundary.commitment();
            const boundary_view = chain.boundary_round.view.get();
            try shards.gather(boundary, chain.boundary_round);
            try shards.disperse(chain.boundary_round, chain.boundary.clone());
            try ctx.sleep(.fromMilliseconds(10));

            // A re-proposal of the boundary block in its epoch has valid shards; once the
            // assigned shard arrives from the re-proposer, it certifies.
            const round = common.round_at(0, 20);
            const context = reproposal(round, participants[1], boundary_view, boundary);
            try testing.expect(try verify_now(&stack, context, boundary));
            var assigned = try shards.subscribe_assigned_shard_verified(boundary);
            defer assigned.deinit();
            try send_assigned_shard(&stack, participants[1], &chain.boundary);
            try recv_within(ctx, &assigned, 5_000);
            try testing.expect(try certify_now(&stack, round, boundary));

            // Re-proposing it again as the parent view advances gives the same verdict.
            const repeated = common.round_at(0, boundary_view + 2);
            const repeated_context = reproposal(repeated, me, round.view.get(), boundary);
            try testing.expect(try verify_now(&stack, repeated_context, boundary));
            try testing.expect(try certify_now(&stack, repeated, boundary));

            // A re-proposal of a block that is not an epoch's last is rejected by the boundary
            // gate (the block itself validates under its own context).
            const invalid = common.round_at(0, 15);
            const non_boundary = chain.non_boundary;
            const invalid_context = reproposal(invalid, me, chain.non_boundary_view, non_boundary);
            try testing.expect(!try verify_now(&stack, invalid_context, non_boundary));
            try testing.expect(!try certify_now(&stack, invalid, non_boundary));

            // A re-proposal in another epoch is rejected.
            const cross = common.round_at(1, 20);
            const cross_context = reproposal(cross, me, boundary_view, boundary);
            try testing.expect(!try verify_now(&stack, cross_context, boundary));
            try testing.expect(!try certify_now(&stack, cross, boundary));
        }
    }.body);
}

test "invalid reproposal does not open reconstruction" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const participants = validators.participants;
            try stack.network.link_all(participants[0..2], shared.link);
            const shards = stack.shards();

            // A mid-epoch block stored in core marshal without opening shard reconstruction.
            const original_round = common.round_at(0, 5);
            const original_context: common.CodingCtx = .{
                .round = original_round,
                .leader = participants[1],
                .parent = .{ .new(4), harness.genesis_commitment() },
            };
            const parent = harness.Sha256.hash(&.{"parent"});
            var block = try common.coded(gpa, original_context, parent, 5, 500);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try testing.expect(try stack.validator.mailbox.verified(original_round, block.clone()));
            try testing.expect(try shards.get(commitment) == null);

            // Re-proposing the old block as epoch 1's genesis parent is invalid; the payload is
            // the parent, so verify takes the re-proposal path.
            const round = common.round_at(1, 1);
            const context = reproposal(round, participants[1], 0, commitment);
            var assigned = try shards.subscribe_assigned_shard_verified(commitment);
            defer assigned.deinit();
            try testing.expect(!try verify_now(&stack, context, commitment));

            // The re-proposer delivers this node's assigned shard. Without reconstruction state
            // it stays buffered, so assigned shard verification cannot complete.
            try send_assigned_shard(&stack, participants[1], &block);
            try ctx.sleep(.fromSeconds(1));
            try testing.expectError(error.Empty, assigned.try_recv());
        }
    }.body);
}

/// Gathers a window of filler commitments in the views from `first` (commonware's `fill`),
/// which evicts the shard engine's older records.
fn fill(shards: *const common.ShardMailbox, first: u64) !void {
    for (first..first + harness.records) |view| {
        var view_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &view_bytes, view, .big);
        const commitment: common.Commitment = .init(
            harness.Sha256.hash(&.{&view_bytes}),
            harness.Sha256.hash(&.{"filler_root"}),
            harness.Sha256.hash(&.{"filler_context"}),
            common.committee_config(),
        );
        try shards.gather(commitment, common.round_at(0, view));
    }
}

/// Whether the shard engine holds `commitment` reconstructed.
fn cached(shards: *const common.ShardMailbox, commitment: common.Commitment) !bool {
    var found = (try shards.get(commitment)) orelse return false;
    found.deinit(gpa);
    return true;
}

test "coding reproposal verify fetches block by parent round" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const pair = validators.participants[0..2];
            var network: shared.TestNetwork = try .start(gpa, ctx.io(), 1, pair, 1024 * 1024);
            defer network.stop();
            const Validator = common.ValidatorStack.Validator;
            var nodes: [2]*Validator = undefined;
            var started: usize = 0;
            defer for (nodes[0..started]) |node| node.crash();
            for (&nodes, pair, 0..) |*node, me, index| {
                const node_ctx = ctx.child("validator").with_attribute("index", index);
                const provider: common.Provider = .init(&validators.schemes[index]);
                const app = try common.App.init(gpa, ctx.io());
                node.* = try Validator.setup(node_ctx, network.network, me, provider, 1, app);
                started += 1;
            }
            try network.link_all(pair, shared.link);

            // The boundary block of epoch 0, originally proposed at view 5.
            const original_round = common.round_at(0, 5);
            const original_context: common.CodingCtx = .{
                .round = original_round,
                .leader = pair[0],
                .parent = .{ .new(4), harness.genesis_commitment() },
            };
            const parent = harness.Sha256.hash(&.{"parent"});
            const height = shared.blocks_per_epoch - 1;
            var block = try common.coded(gpa, original_context, parent, height, 1900);
            defer block.deinit(gpa);
            const commitment = block.commitment();

            // Serving a fetch by round needs the block and the round's notarization.
            try testing.expect(try nodes[0].mailbox.verified(original_round, block.clone()));
            const proposal = common.Proposal.init(original_round, .new(4), commitment);
            var notarization = try H.make_notarization(gpa, &validators, proposal, quorum);
            defer notarization.deinit(gpa);
            _ = nodes[0].mailbox.report(.{ .notarization = notarization });

            // The re-proposal names its own parent, so verification targets the parent
            // round. Validator 1 never held the payload.
            try testing.expect(!try cached(&nodes[1].extra, commitment));
            const M = common.ValidatorStack.M;
            const provider: common.Provider = .init(&validators.schemes[1]);
            const app = common.MockVerifyingApp.init(gpa);
            const marshal = nodes[1].mailbox.clone();
            const shards = nodes[1].extra.clone();
            const config = common.marshaled_config(M, app, marshal, shards, provider);
            var marshaled = try M.init(ctx.child("marshaled"), config);
            defer marshaled.deinit();
            const context = reproposal(common.round_at(0, 7), pair[1], 5, commitment);
            var verify = try marshaled.start_verify(context, commitment);
            defer verify.deinit();
            try testing.expect(try verdict_within(ctx, &verify, 30_000));
        }
    }.body);
}

test "coding reproposal recreates shard state after eviction" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const participants = validators.participants;
            const me = participants[0];
            try stack.network.link_all(participants[0..2], shared.link);
            const shards = stack.shards();
            const marshal = &stack.validator.mailbox;

            // The boundary block, stored in core marshal (the durable backstop) and cached in
            // the shard engine.
            const boundary_height = shared.blocks_per_epoch - 1;
            const boundary_round = common.round_at(0, boundary_height);
            const boundary_context: common.CodingCtx = .{
                .round = boundary_round,
                .leader = me,
                .parent = .{ .new(boundary_height - 1), harness.genesis_commitment() },
            };
            const parent = harness.Sha256.hash(&.{"parent"});
            var block = try common.coded(gpa, boundary_context, parent, boundary_height, 1900);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            try testing.expect(try marshal.verified(boundary_round, block.clone()));
            try shards.gather(commitment, boundary_round);
            try shards.disperse(boundary_round, block.clone());
            try testing.expect(try cached(shards, commitment));

            // Records for a window of later views evict the cached block.
            try fill(shards, boundary_height + 1);
            try testing.expect(!try cached(shards, commitment));

            // A re-proposal above those views verifies from the core backstop, and gathers
            // again, so the recreated state accepts the re-proposer's assigned shard.
            const round = common.round_at(0, 40);
            const context = reproposal(round, participants[1], boundary_height, commitment);
            try testing.expect(try verify_now(&stack, context, commitment));
            var assigned = try shards.subscribe_assigned_shard_verified(commitment);
            defer assigned.deinit();
            try send_assigned_shard(&stack, participants[1], &block);
            try recv_within(ctx, &assigned, 5_000);

            // Later records evict the recreated state, so a new assigned-shard subscription
            // waits; the block in core marshal keeps subscriptions and certification live.
            try fill(shards, round.view.get() + 1);
            var evicted = try shards.subscribe_assigned_shard_verified(commitment);
            defer evicted.deinit();
            try testing.expect(!try cached(shards, commitment));
            try testing.expectError(error.Empty, evicted.try_recv());
            var subscription = try marshal.subscribe_by_commitment(commitment, .wait);
            defer subscription.deinit();
            var core_block = try subscription.recv();
            defer core_block.deinit(gpa);
            try testing.expect(core_block.commitment().eql(commitment));
            try testing.expect(try certify_now(&stack, round, commitment));
        }
    }.body);
}

/// Waits up to `limit_ms` for a verdict on `receiver`, polling every 10 ms.
fn verdict_within(ctx: Ctx, receiver: *utils.channel.oneshot.Receiver(bool), limit_ms: u64) !bool {
    var waited: u64 = 0;
    while (waited < limit_ms) : (waited += 10) {
        return receiver.try_recv() catch |err| switch (err) {
            error.Empty => {
                try ctx.sleep(.fromMilliseconds(10));
                continue;
            },
            error.Closed => return error.Closed,
        };
    }
    return error.TestTimedOut;
}

test "marshaled rejects mismatched context digest" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const participants = validators.participants;
            const shards = stack.shards();

            const genesis = try common.genesis_block(gpa);
            const parent_context: common.CodingCtx = .{
                .round = common.round_at(0, 1),
                .leader = shared.default_leader(),
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            const parent = try common.coded(gpa, parent_context, genesis.digest(), 1, 100);
            const parent_digest = parent.digest();
            const parent_commitment = parent.commitment();
            try shards.disperse(common.round_at(0, 1), parent);

            // A block whose commitment binds context A, verified under context B.
            const context_a: common.CodingCtx = .{
                .round = common.round_at(0, 2),
                .leader = participants[0],
                .parent = .{ .new(1), parent_commitment },
            };
            var block = try common.coded(gpa, context_a, parent_digest, 2, 200);
            defer block.deinit(gpa);
            const context_b: common.CodingCtx = .{
                .round = common.round_at(0, 3),
                .leader = participants[1],
                .parent = .{ .new(1), parent_commitment },
            };
            var verify = try stack.marshaled.start_verify(context_b, block.commitment());
            defer verify.deinit();
            // Rejected, and promptly.
            try testing.expect(!try verdict_within(ctx, &verify, 5_000));
        }
    }.body);
}

test "reproposal certify recovers after verify receiver drop" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const me = validators.participants[0];
            const shards = stack.shards();

            // A valid boundary re-proposal whose block stays unavailable until the
            // optimistic verify receiver is dropped.
            const genesis = try common.genesis_block(gpa);
            const boundary_height = shared.blocks_per_epoch - 1;
            const boundary_round = common.round_at(0, boundary_height);
            const boundary_context: common.CodingCtx = .{
                .round = boundary_round,
                .leader = me,
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            const timestamp = boundary_height * 100;
            const root = genesis.digest();
            const block = try common.coded(gpa, boundary_context, root, boundary_height, timestamp);
            const commitment = block.commitment();
            const round = common.round_at(0, boundary_height + 1);
            const context = reproposal(round, me, boundary_height, commitment);

            var verify = try stack.marshaled.start_verify(context, commitment);
            verify.deinit();
            try ctx.sleep(.fromMilliseconds(10));
            try shards.disperse(boundary_round, block);
            try ctx.sleep(.fromMilliseconds(10));

            // Certify recovers through the embedded-context path instead of the stale gate.
            var certify = try stack.marshaled.start_certify(round, commitment);
            defer certify.deinit();
            try testing.expect(try verdict_within(ctx, &certify, 5_000));
        }
    }.body);
}

/// Sends `shard` (borrowed) from `from` to the validator over the shard channel.
fn send_shard(stack: *common.ValidatorStack, from: common.K, shard: *const common.Shard) !void {
    const codec = @import("codec");
    const control = stack.network.network.oracle().control(from);
    var registered = try control.register(2, shared.test_quota);
    defer registered.deinit();
    const bytes = try codec.encode(common.Shard, gpa, shard.*);
    defer gpa.free(bytes);
    const sent = try registered.sender.send(.{ .one = stack.validator_key }, &.{bytes}, true);
    gpa.free(sent);
}

/// Has participants 1 and 2 send their shards of `undecodable`'s rebound commitment, after
/// `gather` opens its reconstruction: the shards verify, but the decoded block fails.
fn fail_reconstruction(
    stack: *common.ValidatorStack,
    participants: []const common.K,
    missing: anytype,
    round: common.Round,
) !void {
    // Ordered after the subscription that reaches the shard engine.
    _ = try stack.validator.mailbox.get_processed();
    try stack.shards().gather(missing.commitment, round);
    try stack.network.link_all(participants[0..3], shared.link);
    for (participants[1..3], missing.shards[1..3]) |peer, *shard| {
        try send_shard(stack, peer, shard);
    }
}

test "reproposal missing block does not synthesize false" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const participants = validators.participants;
            const me = participants[0];
            var missing = try common.undecodable(gpa, me);
            defer for (&missing.shards) |*shard| shard.deinit(gpa);
            const round = common.round_at(0, 1);
            const context = reproposal(round, me, 0, missing.commitment);

            // Verify must not synthesize `false` when the block cannot be fetched: a failed
            // reconstruction closes it without a verdict.
            var verify = try stack.marshaled.start_verify(context, missing.commitment);
            defer verify.deinit();
            try fail_reconstruction(&stack, participants, missing, round);
            try testing.expectError(error.Closed, verdict_within(ctx, &verify, 5_000));

            // Certify stays pending on the recovery path instead of surfacing the closed gate.
            var certify = try stack.marshaled.start_certify(round, missing.commitment);
            defer certify.deinit();
            try ctx.sleep(.fromMilliseconds(100));
            try testing.expectError(error.Empty, certify.try_recv());
        }
    }.body);
}

test "core subscription closes when coding reconstruction fails" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const participants = validators.participants;
            var missing = try common.undecodable(gpa, participants[0]);
            defer for (&missing.shards) |*shard| shard.deinit(gpa);
            const round = common.round_at(0, 1);

            // A core subscription subscribes to the coding buffer and registers waiters.
            const mailbox = &stack.validator.mailbox;
            const fallback: core_mailbox.CommitmentFallback = .{ .fetch_by_round = round };
            var block = try mailbox.subscribe_by_commitment(missing.commitment, fallback);
            defer block.deinit();
            try fail_reconstruction(&stack, participants, missing, round);

            // The core actor closes the subscription promptly.
            var waited: u64 = 0;
            while (waited < 5_000) : (waited += 10) {
                var value = block.try_recv() catch |err| switch (err) {
                    error.Empty => {
                        try ctx.sleep(.fromMilliseconds(10));
                        continue;
                    },
                    error.Closed => return,
                };
                value.deinit(gpa);
                return error.UnexpectedBlock;
            }
            return error.TestTimedOut;
        }
    }.body);
}

/// Whether `receiver` delivers a block with `commitment` within `limit_ms`.
fn block_within(
    ctx: Ctx,
    receiver: *utils.channel.oneshot.Receiver(common.Block),
    commitment: common.Commitment,
    limit_ms: u64,
) !bool {
    var waited: u64 = 0;
    while (waited < limit_ms) : (waited += 10) {
        var block = receiver.try_recv() catch |err| switch (err) {
            error.Empty => {
                try ctx.sleep(.fromMilliseconds(10));
                continue;
            },
            error.Closed => return error.Closed,
        };
        defer block.deinit(gpa);
        return block.commitment().eql(commitment);
    }
    return error.TestTimedOut;
}

test "coding floor preserves registered commitment subscription" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const shards = stack.shards();
            const mailbox = &stack.validator.mailbox;
            const n = shared.num_validators;

            const missing_round = common.round_at(0, 1);
            const root = shared.genesis_parent();
            const genesis = H.genesis_parent_commitment(n);
            const missing = try H.make_test_block(gpa, root, genesis, .new(1), 100, n);
            const missing_commitment = missing.commitment();
            try shards.gather(missing_commitment, missing_round);
            var subscription = try mailbox.subscribe_by_commitment(missing_commitment, .wait);
            defer subscription.deinit();
            try ctx.sleep(.fromMilliseconds(100));

            // A floor above the missing block, installed from the shard engine.
            const floor_round = common.round_at(0, 2);
            const floor =
                try H.make_test_block(gpa, missing.digest(), missing_commitment, .new(2), 200, n);
            const floor_commitment = floor.commitment();
            try shards.disperse(floor_round, floor);
            var cached_floor = (try shards.get(floor_commitment)) orelse return error.NotCached;
            cached_floor.deinit(gpa);
            const proposal = common.Proposal.init(floor_round, .new(1), floor_commitment);
            const finalization = try H.make_finalization(gpa, &validators, proposal, quorum);
            try mailbox.set_floor(finalization);
            var waited: u32 = 0;
            while (true) : (waited += 1) {
                if (waited > 3_000) return error.TestTimedOut;
                const processed = try mailbox.get_processed();
                if (processed) |value| if (std.meta.eql(value, .{ .block = .new(2) })) break;
                try ctx.sleep(.fromMilliseconds(10));
            }

            // The floor kept the registered subscription: local ingress resolves it.
            try shards.disperse(common.round_at(0, 3), missing);
            try testing.expect(try block_within(ctx, &subscription, missing_commitment, 5_000));
        }
    }.body);
}

/// A fixed epocher that knows no epoch above `max_epoch` (commonware `LimitedEpocher`).
const LimitedEpocher = struct {
    inner: consensus_types.FixedEpocher,
    max_epoch: u64,

    pub fn containing(
        self: LimitedEpocher,
        height: consensus_types.Height,
    ) ?consensus_types.EpochInfo {
        const bounds = self.inner.containing(height) orelse return null;
        if (bounds.epoch.get() > self.max_epoch) return null;
        return bounds;
    }

    pub fn first(self: LimitedEpocher, epoch: consensus_types.Epoch) ?consensus_types.Height {
        if (epoch.get() > self.max_epoch) return null;
        return self.inner.first(epoch);
    }

    pub fn last(self: LimitedEpocher, epoch: consensus_types.Epoch) ?consensus_types.Height {
        if (epoch.get() > self.max_epoch) return null;
        return self.inner.last(epoch);
    }
};

const LimitedMarshaled = @import("marshaled.zig").Marshaled(struct {
    pub const Context = Ctx;
    pub const Application = common.MockVerifyingApp;
    pub const Block = common.CodingB;
    pub const Coding = harness.RS;
    pub const Hasher = harness.Sha256;
    pub const Provider = harness.CodingProvider;
    pub const Strategy = parallel.Sequential;
    pub const Epocher = LimitedEpocher;
});

test "marshaled rejects unsupported epoch" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const shards = stack.shards();
            const epoch_length = utils.NonZero(u64).init(shared.blocks_per_epoch).?;
            var marshaled = try LimitedMarshaled.init(ctx.child("limited"), .{
                .application = common.MockVerifyingApp.init(gpa),
                .marshal = stack.validator.mailbox.clone(),
                .shards = shards.clone(),
                .scheme_provider = .init(&validators.schemes[0]),
                .strategy = parallel.sequential,
                .epocher = .{ .inner = .new(epoch_length), .max_epoch = 0 },
            });
            defer marshaled.deinit();

            // The parent is the last block of epoch 0 (supported).
            const genesis = try common.genesis_block(gpa);
            const parent_round = common.round_at(0, 19);
            const parent_context: common.CodingCtx = .{
                .round = parent_round,
                .leader = shared.default_leader(),
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            const parent = try common.coded(gpa, parent_context, genesis.digest(), 19, 1000);
            const parent_digest = parent.digest();
            const parent_commitment = parent.commitment();
            try shards.disperse(parent_round, parent);

            // The block is the first of epoch 1, which the epocher does not support.
            const round = common.round_at(1, 20);
            const block_context: common.CodingCtx = .{
                .round = round,
                .leader = shared.default_leader(),
                .parent = .{ .new(19), parent_commitment },
            };
            const block = try common.coded(gpa, block_context, parent_digest, 20, 2000);
            const commitment = block.commitment();
            try shards.disperse(round, block);
            try ctx.sleep(.fromMilliseconds(10));

            const context: common.CodingCtx = .{
                .round = round,
                .leader = validators.participants[0],
                .parent = .{ .new(19), parent_commitment },
            };
            var verify = try marshaled.start_verify(context, commitment);
            verify.deinit();
            var certify = try marshaled.start_certify(round, commitment);
            defer certify.deinit();
            // A block in an unsupported epoch is rejected.
            try testing.expect(!try certify.recv());
        }
    }.body);
}

/// Verifies, then certifies, `commitment` (dispersed under `context`) and returns the
/// deferred verification's verdict.
fn certify_after_verify(
    stack: *common.ValidatorStack,
    context: common.CodingCtx,
    commitment: common.Commitment,
) !bool {
    var verify = try stack.marshaled.start_verify(context, commitment);
    verify.deinit();
    return certify_now(stack, context.round, commitment);
}

test "marshaled rejects invalid ancestry" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const me = validators.participants[0];
            const shards = stack.shards();
            const epoch_length = shared.blocks_per_epoch;

            // An honest parent at height 21 (epoch 1).
            const genesis = try common.genesis_block(gpa);
            const parent_round = common.round_at(1, 21);
            const parent_context: common.CodingCtx = .{
                .round = parent_round,
                .leader = shared.default_leader(),
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            const parent =
                try common.coded(gpa, parent_context, genesis.digest(), epoch_length + 1, 1000);
            const parent_digest = parent.digest();
            const parent_commitment = parent.commitment();
            try shards.disperse(parent_round, parent);

            // A Byzantine block at a non-contiguous height (21 to 35).
            const round = common.round_at(1, 35);
            const context: common.CodingCtx = .{
                .round = round,
                .leader = me,
                .parent = .{ .new(21), parent_commitment },
            };
            const skipping = try common.coded(gpa, context, parent_digest, epoch_length + 15, 2000);
            const skipping_commitment = skipping.commitment();
            try shards.disperse(round, skipping);
            try ctx.sleep(.fromMilliseconds(10));
            try testing.expect(!try certify_after_verify(&stack, context, skipping_commitment));

            // A Byzantine block at the right height naming the wrong parent digest.
            const second_round = common.round_at(1, 22);
            const second_context: common.CodingCtx = .{
                .round = second_round,
                .leader = me,
                .parent = .{ .new(21), parent_commitment },
            };
            const wrong_parent = genesis.digest();
            const orphan =
                try common.coded(gpa, second_context, wrong_parent, epoch_length + 2, 3000);
            const orphan_commitment = orphan.commitment();
            try shards.disperse(second_round, orphan);
            try ctx.sleep(.fromMilliseconds(10));
            const verdict = try certify_after_verify(&stack, second_context, orphan_commitment);
            try testing.expect(!verdict);
        }
    }.body);
}

/// commonware's certify-without-prior-verify body: certifies a dispersed height-2 block that
/// was never verified here, with an application answering `verify_result`.
fn certify_without_prior_verify(ctx: Ctx, verify_result: bool) !bool {
    var validators = try fixture();
    defer validators.deinit(gpa);
    var stack: common.ValidatorStack = undefined;
    const app = common.MockVerifyingApp.with_verify_result(gpa, verify_result);
    try stack.start_with(ctx, &validators, app);
    defer stack.stop();
    const shards = stack.shards();

    const genesis = try common.genesis_block(gpa);
    const parent_round = common.round_at(0, 1);
    const parent_context: common.CodingCtx = .{
        .round = parent_round,
        .leader = shared.default_leader(),
        .parent = .{ .zero(), harness.genesis_commitment() },
    };
    const parent = try common.coded(gpa, parent_context, genesis.digest(), 1, 100);
    const parent_digest = parent.digest();
    const parent_commitment = parent.commitment();
    try shards.disperse(parent_round, parent);
    const round = common.round_at(0, 2);
    const context: common.CodingCtx = .{
        .round = round,
        .leader = validators.participants[0],
        .parent = .{ .new(1), parent_commitment },
    };
    const child = try common.coded(gpa, context, parent_digest, 2, 200);
    const commitment = child.commitment();
    try shards.disperse(round, child);
    try ctx.sleep(.fromMilliseconds(10));

    var certify = try stack.marshaled.start_certify(round, commitment);
    defer certify.deinit();
    return verdict_within(ctx, &certify, 5_000);
}

test "certify without prior verify crash recovery" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            // A valid block certifies without a prior verify.
            try testing.expect(try certify_without_prior_verify(ctx, true));
        }
    }.body);
}

test "certify without prior verify honors application rejection" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            // Certify propagates the application's rejection.
            try testing.expect(!try certify_without_prior_verify(ctx, false));
        }
    }.body);
}

test "certify reconstructs from buffered gossip shards" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const participants = validators.participants;
            const shards = stack.shards();
            // No peer runs a marshal actor, so round-bound block fetches go unanswered.
            try stack.network.link_all(participants, shared.link);

            // The parent is local; the notarized candidate was never seen here.
            const genesis = try common.genesis_block(gpa);
            const parent_round = common.round_at(0, 1);
            const parent_context: common.CodingCtx = .{
                .round = parent_round,
                .leader = shared.default_leader(),
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            const parent = try common.coded(gpa, parent_context, genesis.digest(), 1, 100);
            const parent_digest = parent.digest();
            const parent_commitment = parent.commitment();
            try shards.disperse(parent_round, parent);
            const round = common.round_at(0, 2);
            const context: common.CodingCtx = .{
                .round = round,
                .leader = participants[1],
                .parent = .{ .new(1), parent_commitment },
            };
            var child = try common.coded(gpa, context, parent_digest, 2, 200);
            defer child.deinit(gpa);

            // Each peer sends its sender-indexed gossip shard; until a gather for the
            // commitment the shard engine only buffers them.
            for (participants[1..], 1..) |peer, index| {
                var shard = (try child.shard(gpa, @intCast(index))) orelse
                    return error.MissingShard;
                defer shard.deinit(gpa);
                try send_shard(&stack, peer, &shard);
            }
            try ctx.sleep(.fromMilliseconds(250));

            // Certify reports the commitment, drains the buffered shards, and verifies the
            // reconstructed block through its embedded context.
            var certify = try stack.marshaled.start_certify(round, child.commitment());
            defer certify.deinit();
            try testing.expect(try verdict_within(ctx, &certify, 5_000));
        }
    }.body);
}

/// What consensus asks of the validator in `assigned_shard_is_checked_and_gossiped`.
const Asked = enum {
    /// `verify`, before the assigned shard arrives.
    verify,
    /// `certify`, without `verify`.
    certify,
    /// `certify`, while the `verify` of a re-proposal awaits its block.
    certify_during_verify,
};

/// The other participants' shard channels, registered once and kept open.
const Peers = struct {
    channels: [shared.num_validators - 1]shared.Network.Registered,
    made: usize,

    fn open(self: *Peers, stack: *common.ValidatorStack, participants: []const common.K) !void {
        self.made = 0;
        errdefer self.close();
        for (&self.channels, participants[1..]) |*channel, peer| {
            const control = stack.network.network.oracle().control(peer);
            channel.* = try control.register(2, shared.test_quota);
            self.made += 1;
        }
    }

    fn close(self: *Peers) void {
        for (self.channels[0..self.made]) |*channel| channel.deinit();
        self.made = 0;
    }

    /// Sends `block`'s shard `index` from peer `from` (an index into the peers) to `to`.
    fn send(self: *Peers, from: usize, to: common.K, block: *const common.Block, index: u16) !void {
        const codec = @import("codec");
        var shard = (try block.shard(gpa, index)) orelse return error.MissingShard;
        defer shard.deinit(gpa);
        const bytes = try codec.encode(common.Shard, gpa, shard);
        defer gpa.free(bytes);
        const sent = try self.channels[from].sender.send(.{ .one = to }, &.{bytes}, true);
        gpa.free(sent);
    }
};

/// Waits for the last peer to receive `child`'s shard 0 (the validator's assigned shard)
/// from `me` as gossip.
fn expect_gossiped(ctx: Ctx, peers: *Peers, me: common.K, child: *const common.Block) !void {
    const codec = @import("codec");
    var assigned = (try child.shard(gpa, 0)) orelse return error.MissingShard;
    defer assigned.deinit(gpa);
    const expected = try codec.encode(common.Shard, gpa, assigned);
    defer gpa.free(expected);
    var waited: u64 = 0;
    while (waited < 5_000) : (waited += 10) {
        var message = peers.channels[2].receiver.try_recv() catch |err| switch (err) {
            error.Empty => {
                try ctx.sleep(.fromMilliseconds(10));
                continue;
            },
            error.Disconnected => return error.Disconnected,
        };
        defer message.deinit();
        try testing.expect(message.peer.eql(me));
        try testing.expectEqualSlices(u8, expected, message.payload);
        return;
    }
    return error.TestTimedOut;
}

/// Runs one validator whose peers only send shards, and asks it to verify or certify a
/// proposal of peer 1 (commonware `assigned_shard_is_checked_and_gossiped`).
fn assigned_shard_is_checked_and_gossiped(ctx: Ctx, asked: Asked) !void {
    var validators = try fixture();
    defer validators.deinit(gpa);
    var stack: common.ValidatorStack = undefined;
    try stack.start(ctx, &validators);
    defer stack.stop();
    const participants = validators.participants;
    const me = participants[0];
    var peers: Peers = undefined;
    try peers.open(&stack, participants);
    defer peers.close();
    // No peer runs a marshal actor, so round-bound block fetches go unanswered.
    try stack.network.link_all(participants, shared.link);

    // The parent is available locally.
    const genesis = try common.genesis_block(gpa);
    const parent_round = common.round_at(0, 1);
    const parent_context: common.CodingCtx = .{
        .round = parent_round,
        .leader = shared.default_leader(),
        .parent = .{ .zero(), harness.genesis_commitment() },
    };
    const parent = try common.coded(gpa, parent_context, genesis.digest(), 1, 100);
    const parent_digest = parent.digest();
    const parent_commitment = parent.commitment();
    try testing.expect(try stack.validator.mailbox.verified(parent_round, parent));

    // Peer 1 proposes a child at view 2; it is the epoch's boundary block when a re-proposal
    // is verified.
    const child_context: common.CodingCtx = .{
        .round = common.round_at(0, 2),
        .leader = participants[1],
        .parent = .{ .new(1), parent_commitment },
    };
    const height: u64 = if (asked == .certify_during_verify) shared.blocks_per_epoch - 1 else 2;
    var child = try common.coded(gpa, child_context, parent_digest, height, 200);
    defer child.deinit(gpa);
    const commitment = child.commitment();

    if (asked == .verify) {
        // Verification waits for the assigned shard, then resolves once the leader sends it.
        var verify = try stack.marshaled.start_verify(child_context, commitment);
        defer verify.deinit();
        try ctx.sleep(.fromMilliseconds(250));
        try testing.expectError(error.Empty, verify.try_recv());
        try peers.send(0, me, &child, 0);
        try testing.expect(try verdict_within(ctx, &verify, 5_000));
    } else {
        // A re-proposal at view 3 is verified first; it fetches the block before it reports
        // the commitment, and no peer answers.
        var round = child_context.round;
        var pending: ?utils.channel.oneshot.Receiver(bool) = null;
        defer if (pending) |*receiver| receiver.deinit();
        if (asked == .certify_during_verify) {
            round = common.round_at(0, 3);
            const context = reproposal(round, participants[1], 2, commitment);
            pending = try stack.marshaled.start_verify(context, commitment);
        }
        // The leader sends the assigned shard and one peer gossips its own: two decode.
        try peers.send(0, me, &child, 0);
        try peers.send(1, me, &child, 2);
        try ctx.sleep(.fromMilliseconds(250));
        if (pending) |*receiver| try testing.expectError(error.Empty, receiver.try_recv());
        var certify = try stack.marshaled.start_certify(round, commitment);
        defer certify.deinit();
        try testing.expect(try verdict_within(ctx, &certify, 5_000));
    }

    try expect_gossiped(ctx, &peers, me, &child);
}

test "certify reconstructs with buffered assigned shard" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try assigned_shard_is_checked_and_gossiped(ctx, .certify);
        }
    }.body);
}

test "certify reconstructs while reproposal verify awaits block" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try assigned_shard_is_checked_and_gossiped(ctx, .certify_during_verify);
        }
    }.body);
}

test "verify resolves once assigned shard arrives" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try assigned_shard_is_checked_and_gossiped(ctx, .verify);
        }
    }.body);
}

const mocks_store = @import("../mocks/store.zig");
const RecordedBlocks = mocks_store.Recording(common.ImmutableBlocks, common.V.StoredBlock);
const StagingActor = common.ActorOver(common.App, RecordedBlocks);

/// A stored block's identity in the recorded puts. commonware records the stored payload's
/// address; the Zig archive stores a value copy, so the put carries the block's timestamp.
fn timestamp_address(block: *const common.V.StoredBlock) usize {
    return @intCast(block.inner().timestamp);
}

test "coding dispatch delivers staged block without archive read" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const prefix = "coding-staged-dispatch";
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stores: harness.Archives = undefined;
            try stores.open(ctx, prefix);
            defer stores.deinit();
            var log = mocks_store.Log.init(gpa);
            defer log.deinit();
            const blocks: RecordedBlocks =
                .init(.{ .archive = &stores.blocks }, &log, &timestamp_address);
            const provider: common.Provider = .init(&validators.schemes[0]);
            const config =
                try common.test_config(StagingActor, gpa, prefix, provider, &stores.cache_ref);
            const initialized = try StagingActor.init(
                ctx.child("actor"),
                .{ .archive = &stores.finalizations },
                blocks,
                config,
            );
            var mailbox = initialized.mailbox;
            defer mailbox.deinit();
            var holding =
                try common.RecordingResolver.holding(gpa, ctx.io(), &ctx.scope.child("resolver"));
            defer holding.resolver.deinit();
            var application = try common.App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var handle = try initialized.actor.start(
                application.clone(),
                buffer.clone(),
                holding.receiver,
                holding.resolver.clone(),
            );
            defer {
                const ended = handle.abort() catch {};
                ended catch {};
            }
            try testing.expectEqual(0, (try application.acknowledged()).get());
            // Store a verified block, then finalize it through consensus.
            const genesis = try common.genesis_block(gpa);
            const round = common.round_at(0, 1);
            const context: common.CodingCtx = .{
                .round = round,
                .leader = shared.default_leader(),
                .parent = .{ .zero(), try common.genesis_coding_commitment(gpa, &genesis) },
            };
            var block = try common.coded(gpa, context, genesis.digest(), 1, 100);
            defer block.deinit(gpa);
            try testing.expect(try mailbox.verified(round, block.clone()));
            const proposal = common.Proposal.init(round, .zero(), block.commitment());
            var finalization = try H.make_finalization(gpa, &validators, proposal, quorum);
            defer finalization.deinit(gpa);
            _ = mailbox.report(.{ .finalization = finalization });
            try testing.expectEqual(1, (try application.acknowledged()).get());

            var delivered = application.block(.new(1)) orelse return error.BlockMissing;
            defer delivered.deinit();
            try testing.expect(delivered.digest().eql(block.digest()));
            const ops = log.ops.items;
            const written = for (ops, 0..) |op, index| {
                if (op == .put and op.put.height.get() == 1) break index;
            } else return error.BlockNotWritten;
            // Storage holds the block dispatched to the application.
            const address: usize = @intCast(delivered.inner().timestamp);
            try testing.expectEqual(address, ops[written].put.payload_address);
            // Dispatch must not read the finalized block back from the archive.
            for (ops[written..]) |op| try testing.expect(!op.eql(.{ .get = .new(1) }));
        }
    }.body);
}

test "malformed commitment config rejected at deserialization" {
    const codec = @import("codec");
    // All-zero bytes carry an invalid coding config (zero shard counts).
    const malformed: [common.Commitment.fixed_size]u8 = @splat(0);
    try testing.expect(std.meta.isError(codec.decode(common.Commitment, gpa, &malformed)));
    // A valid commitment still round-trips.
    const valid: common.Commitment = .init(
        harness.Sha256.hash(&.{"block"}),
        harness.Sha256.hash(&.{"root"}),
        harness.Sha256.hash(&.{"context"}),
        common.committee_config(),
    );
    const encoded = codec.encode_fixed(common.Commitment, valid);
    const decoded = try codec.decode(common.Commitment, gpa, &encoded);
    try testing.expect(decoded.eql(valid));
}

test "certify propagates application verify failure" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            const app = common.MockVerifyingApp.with_verify_result(gpa, false);
            try stack.start_with(ctx, &validators, app);
            defer stack.stop();
            const me = validators.participants[0];
            const shards = stack.shards();

            const genesis = try common.genesis_block(gpa);
            const parent_round = common.round_at(0, 1);
            const parent_context: common.CodingCtx = .{
                .round = parent_round,
                .leader = me,
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            const parent = try common.coded(gpa, parent_context, genesis.digest(), 1, 100);
            const parent_digest = parent.digest();
            const parent_commitment = parent.commitment();
            try shards.disperse(parent_round, parent);
            // A valid child passes the optimistic pre-checks.
            const round = common.round_at(0, 2);
            const context: common.CodingCtx = .{
                .round = round,
                .leader = me,
                .parent = .{ .new(1), parent_commitment },
            };
            const block = try common.coded(gpa, context, parent_digest, 2, 200);
            const commitment = block.commitment();
            try shards.disperse(round, block);
            try ctx.sleep(.fromMilliseconds(10));
            try testing.expect(try verify_now(&stack, context, commitment));
            // Certify observes the deferred application failure.
            try testing.expect(!try certify_now(&stack, round, commitment));
        }
    }.body);
}

test "certify not poisoned by equivocating parent verify" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: common.ValidatorStack = undefined;
            try stack.start(ctx, &validators);
            defer stack.stop();
            const me = validators.participants[0];
            const shards = stack.shards();

            // View 1: the parent this validator last certified.
            const genesis = try common.genesis_block(gpa);
            const certified_context: common.CodingCtx = .{
                .round = common.round_at(0, 1),
                .leader = shared.default_leader(),
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            const certified = try common.coded(gpa, certified_context, genesis.digest(), 1, 100);
            const certified_digest = certified.digest();
            const certified_commitment = certified.commitment();
            try shards.disperse(certified_context.round, certified);
            // View 2: notarized by the network but only nullified here.
            const notarized_context: common.CodingCtx = .{
                .round = common.round_at(0, 2),
                .leader = me,
                .parent = .{ .new(1), certified_commitment },
            };
            const notarized = try common.coded(gpa, notarized_context, certified_digest, 2, 200);
            const notarized_digest = notarized.digest();
            const notarized_commitment = notarized.commitment();
            try shards.disperse(notarized_context.round, notarized);
            // View 3 builds on view 2.
            const round = common.round_at(0, 3);
            const block_context: common.CodingCtx = .{
                .round = round,
                .leader = me,
                .parent = .{ .new(2), notarized_commitment },
            };
            const block = try common.coded(gpa, block_context, notarized_digest, 3, 300);
            const commitment = block.commitment();
            try shards.disperse(round, block);

            // The equivocating proposal names view 1 as parent; the commitment's context
            // digest exposes it, so verify rejects it without registering a gate.
            const equivocating: common.CodingCtx = .{
                .round = round,
                .leader = me,
                .parent = .{ .new(1), certified_commitment },
            };
            var verify = try stack.marshaled.start_verify(equivocating, commitment);
            defer verify.deinit();
            try testing.expect(!try verdict_within(ctx, &verify, 5_000));
            // Certification of the notarized commitment recovers through its embedded context.
            var certify = try stack.marshaled.start_certify(round, commitment);
            defer certify.deinit();
            try testing.expect(try verdict_within(ctx, &certify, 5_000));
        }
    }.body);
}

test "backfill block mismatched commitment" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const pair = validators.participants[0..2];
            var network: shared.TestNetwork = try .start(gpa, ctx.io(), 1, pair, 1024 * 1024);
            defer network.stop();
            const Validator = common.ValidatorStack.Validator;
            var nodes: [2]*Validator = undefined;
            var started: usize = 0;
            defer for (nodes[0..started]) |node| node.crash();
            for (&nodes, pair, 0..) |*node, me, index| {
                const node_ctx = ctx.child("validator").with_attribute("index", index);
                const provider: common.Provider = .init(&validators.schemes[index]);
                const app = try common.App.init(gpa, ctx.io());
                node.* = try Validator.setup(node_ctx, network.network, me, provider, 1, app);
                started += 1;
            }
            try network.link_all(pair, shared.link);

            // Same total shards (4) with another split: another root and config.
            const config_a = common.committee_config();
            const config_b: @import("coding").Config = .{
                .minimum_shards = config_a.minimum_shards + 1,
                .extra_shards = config_a.extra_shards - 1,
            };
            const genesis = try common.genesis_block(gpa);
            const round = common.round_at(0, 1);
            const context: common.CodingCtx = .{
                .round = round,
                .leader = pair[0],
                .parent = .{ .zero(), harness.genesis_commitment() },
            };
            const raw = try harness.make_coding_block(gpa, context, genesis.digest(), .new(1), 100);
            var block_a = try common.encode_block(gpa, raw, config_a);
            defer block_a.deinit(gpa);
            const block_b = try common.encode_block(gpa, raw, config_b);
            try testing.expect(block_a.digest().eql(block_b.digest()));
            try testing.expect(!block_a.commitment().eql(block_b.commitment()));

            // Validator 1 holds the block under the other coding.
            try testing.expect(try nodes[1].mailbox.verified(round, block_b));
            // Validator 0 finalizes the first commitment, fetches it, and must reject
            // validator 1's response, whose coding config does not match the key.
            const proposal = common.Proposal.init(round, .zero(), block_a.commitment());
            var finalization = try H.make_finalization(gpa, &validators, proposal, quorum);
            defer finalization.deinit(gpa);
            _ = nodes[0].mailbox.report(.{ .finalization = finalization });
            try ctx.sleep(.fromSeconds(5));
            try testing.expect(try nodes[0].mailbox.get_block(.{ .height = .new(1) }) == null);
            try testing.expect(try nodes[0].mailbox.get_finalization(.new(1)) == null);
        }
    }.body);
}

/// Whether the shards of `block` were never computed (a delivery that skipped re-coding).
fn shards_absent(block: *const common.Block) !bool {
    var shard = (try block.shard(gpa, 0)) orelse return true;
    shard.deinit(gpa);
    return false;
}

/// Whether `resolver` fetched `commitment` for a finalized-by-round subscriber.
fn fetched_finalized_by_round(
    resolver: common.RecordingResolver,
    commitment: common.Commitment,
) !bool {
    const fetches = try resolver.fetches(gpa);
    defer gpa.free(fetches);
    for (fetches) |item| {
        if (item.key != .block or !item.key.block.eql(commitment)) continue;
        if (item.subscriber == .finalized and item.subscriber.finalized == .by_round) return true;
    }
    return false;
}

/// Whether the actor stores a block at `height`.
fn stored_at(stack: *common.ActorStack, height: u64) !bool {
    var block = (try stack.mailbox.get_block(.{ .height = .new(height) })) orelse return false;
    block.deinit(gpa);
    return true;
}

test "coding finalized block delivery skips recoding" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("validator"),
                "finalized-block-delivery",
                provider,
                buffer,
            );
            defer stack.stop();
            var candidate = try common.missing_candidate(gpa, validators.participants[0]);
            defer candidate.block.deinit(gpa);
            const commitment = candidate.block.commitment();
            var subscription = try stack.mailbox.subscribe_by_commitment(commitment, .wait);
            defer subscription.deinit();
            try ctx.sleep(.fromMilliseconds(100));

            // The finalization names the commitment, so the fetched block is rebuilt from it
            // without recomputing the coding root.
            const round = candidate.context.round;
            const proposal = common.Proposal.init(round, .zero(), commitment);
            var finalization = try H.make_finalization(gpa, &validators, proposal, quorum);
            defer finalization.deinit(gpa);
            const value = try common.encode_coded(gpa, &candidate.block);
            defer gpa.free(value);
            try stack.resolver.respond_to_next_fetch(value);
            _ = stack.mailbox.report(.{ .finalization = finalization });
            var delivered = try subscription.recv();
            defer delivered.deinit(gpa);
            try testing.expect(delivered.commitment().eql(commitment));
            try testing.expect(try shards_absent(&delivered));
            try testing.expect(try stack.resolver.wait_for_delivery_response());
            try testing.expect(try fetched_finalized_by_round(stack.resolver, commitment));
            try testing.expect(try stored_at(&stack, 1));
        }
    }.body);
}

test "coding coalesced block delivery trusts finalized subscriber" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("validator"),
                "coalesced-block-delivery",
                provider,
                buffer,
            );
            defer stack.stop();
            var candidate = try common.missing_candidate(gpa, validators.participants[0]);
            defer candidate.block.deinit(gpa);
            const commitment = candidate.block.commitment();
            const height: consensus_types.Height = .new(1);
            var subscription = try stack.mailbox.subscribe_by_commitment(commitment, .wait);
            defer subscription.deinit();
            try ctx.sleep(.fromMilliseconds(100));

            // One key carries an untrusted ancestry subscriber and a finalized-chain one; the
            // finalized subscriber alone binds the coding root, so the shared delivery decodes
            // without recomputing it and lands in the finalized archive.
            const subscribers = [_]common.Annotation{
                .{ .untrusted = .{ .height = height, .round = null } },
                .{ .finalized = .{ .by_height = height } },
            };
            const value = try common.encode_coded(gpa, &candidate.block);
            defer gpa.free(value);
            var sender = stack.resolver.handler_clone();
            defer sender.deinit();
            const Delivery = handler.Message(common.Commitment).Delivery;
            const key: common.ResolverKey = .{ .block = commitment };
            const delivery: Delivery = .{ .key = key, .subscribers = &subscribers };
            var response = try sender.deliver(delivery, value);
            defer response.deinit();
            const outcome = try response.recv();
            try testing.expect(std.meta.eql(outcome, common.Outcome{ .resolved = .complete }));
            var delivered = try subscription.recv();
            defer delivered.deinit(gpa);
            try testing.expect(delivered.commitment().eql(commitment));
            try testing.expect(try shards_absent(&delivered));
            try testing.expect(try stored_at(&stack, 1));
        }
    }.body);
}

test "coding finalized block delivery rejects digest mismatch" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("validator"),
                "finalized-block-digest-mismatch",
                provider,
                buffer,
            );
            defer stack.stop();
            var candidate = try common.missing_candidate(gpa, validators.participants[0]);
            defer candidate.block.deinit(gpa);
            const commitment = candidate.block.commitment();
            const genesis = try common.genesis_block(gpa);
            var other = try common.coded(gpa, candidate.context, genesis.digest(), 1, 101);
            defer other.deinit(gpa);
            try testing.expect(!other.digest().eql(candidate.block.digest()));

            // The finalized decode skips the root, so the digest check rejects a different
            // block under the same coding config.
            const round = candidate.context.round;
            const proposal = common.Proposal.init(round, .zero(), commitment);
            var finalization = try H.make_finalization(gpa, &validators, proposal, quorum);
            defer finalization.deinit(gpa);
            const value = try common.encode_coded(gpa, &other);
            defer gpa.free(value);
            try stack.resolver.respond_to_next_fetch(value);
            _ = stack.mailbox.report(.{ .finalization = finalization });
            try ctx.sleep(.fromMilliseconds(100));
            try testing.expect(!try stack.resolver.wait_for_delivery_response());
            try testing.expect(!try stored_at(&stack, 1));
        }
    }.body);
}

/// Whether the shards of `block` were computed (a delivery that proved its root by re-coding).
fn shards_present(block: *const common.Block) !bool {
    return !try shards_absent(block);
}

test "coding ancestry block delivery recomputes root" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("validator"),
                "ancestry-block-delivery",
                provider,
                buffer,
            );
            defer stack.stop();
            var chain: [3]common.ChainLink = undefined;
            try common.coding_chain(gpa, validators.participants[0], &chain);
            defer for (&chain) |*link| link.block.deinit(gpa);

            // Certification persists the candidate before the application verdict; that
            // write alone must not authenticate its ancestry, so each fetch below still
            // proves its coding root by re-encoding.
            const candidate = &chain[2];
            const payload = candidate.block.commitment();
            const proposal = common.Proposal.init(candidate.round, .new(2), payload);
            var notarization = try H.make_notarization(gpa, &validators, proposal, quorum);
            defer notarization.deinit(gpa);
            _ = stack.mailbox.report(.{ .notarization = notarization });
            const copy = candidate.block.clone();
            try testing.expect(try stack.mailbox.certified(candidate.round, copy));
            for ([_]usize{ 1, 0 }) |index| {
                const block = &chain[index];
                const value = try common.encode_coded(gpa, &block.block);
                defer gpa.free(value);
                try stack.resolver.respond_to_next_fetch(value);
                const commitment = block.block.commitment();
                const fallback: core_mailbox.CommitmentFallback =
                    .{ .fetch_by_commitment = .{ .height = .new(index + 1) } };
                var subscription = try stack.mailbox.subscribe_by_commitment(commitment, fallback);
                defer subscription.deinit();
                var delivered = try subscription.recv();
                defer delivered.deinit(gpa);
                try testing.expect(delivered.commitment().eql(commitment));
                // Ancestry delivery recomputes the shards.
                try testing.expect(try shards_present(&delivered));
                try testing.expect(try stack.resolver.wait_for_delivery_response());
            }
            const fetches = try stack.resolver.fetches(gpa);
            defer gpa.free(fetches);
            try testing.expectEqual(2, fetches.len);
            for (fetches) |item| {
                try testing.expect(item.key == .block and item.subscriber == .untrusted);
            }
        }
    }.body);
}

test "coding notarized delivery recomputes root" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("validator"),
                "notarized-block-delivery",
                provider,
                buffer,
            );
            defer stack.stop();
            var candidate = try common.missing_candidate(gpa, validators.participants[0]);
            defer candidate.block.deinit(gpa);
            const commitment = candidate.block.commitment();
            const round = candidate.context.round;
            // A notarization does not bind the coding root to the block, so the delivery
            // proves it by re-encoding.
            const proposal = common.Proposal.init(round, .zero(), commitment);
            var notarization = try H.make_notarization(gpa, &validators, proposal, quorum);
            defer notarization.deinit(gpa);
            const value = try common.encode_notarized(gpa, &notarization, &candidate.block);
            defer gpa.free(value);
            try stack.resolver.respond_to_next_fetch(value);
            const fallback: core_mailbox.CommitmentFallback = .{ .fetch_by_round = round };
            var subscription = try stack.mailbox.subscribe_by_commitment(commitment, fallback);
            defer subscription.deinit();
            var delivered = try subscription.recv();
            defer delivered.deinit(gpa);
            try testing.expect(delivered.commitment().eql(commitment));
            try testing.expect(try shards_present(&delivered));
            try testing.expect(try stack.resolver.wait_for_delivery_response());
        }
    }.body);
}

/// commonware's untrusted-delivery body: a commitment whose root encodes another block,
/// delivered with (`notarized`) or without a notarization, must be rejected.
fn untrusted_rejects_mismatched_root(ctx: Ctx, notarized: bool) !void {
    var validators = try fixture();
    defer validators.deinit(gpa);
    const provider: common.Provider = .init(&validators.schemes[0]);
    var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
    defer buffer.deinit();
    var stack = try common.start_coding_actor_with_recording(
        ctx.child("validator"),
        "untrusted-delivery-mismatched-root",
        provider,
        buffer,
    );
    defer stack.stop();
    var candidate = try common.missing_candidate(gpa, validators.participants[0]);
    defer candidate.block.deinit(gpa);
    const config = candidate.block.config();
    const genesis = try common.genesis_block(gpa);
    var other = try common.coded(gpa, candidate.context, genesis.digest(), 1, 101);
    defer other.deinit(gpa);
    const expected = candidate.block.commitment();
    const commitment: common.Commitment =
        .init(expected.block(), other.commitment().root(), expected.context(), config);
    try testing.expect(!commitment.root().eql(expected.root()));
    // Every assigned shard of the other block verifies against the advertised root.
    const root = commitment.root();
    for (try other.shards(gpa, parallel.sequential), 0..) |*shard, index| {
        _ = try harness.RS.check(config, &root, @intCast(index), shard, parallel.sequential);
    }

    const round = candidate.context.round;
    var notarization: ?H.Notarization = null;
    defer if (notarization) |*value| value.deinit(gpa);
    const value = if (notarized) blk: {
        const proposal = common.Proposal.init(round, .zero(), commitment);
        notarization = try H.make_notarization(gpa, &validators, proposal, quorum);
        break :blk try common.encode_notarized(gpa, &notarization.?, &candidate.block);
    } else try common.encode_coded(gpa, &candidate.block);
    defer gpa.free(value);
    const fallback: core_mailbox.CommitmentFallback = if (notarized)
        .{ .fetch_by_round = round }
    else
        .{ .fetch_by_commitment = .{ .height = .new(1) } };
    try stack.resolver.respond_to_next_fetch(value);
    var subscription = try stack.mailbox.subscribe_by_commitment(commitment, fallback);
    defer subscription.deinit();
    while (stack.resolver.fetch_count() == 0) try ctx.sleep(.fromMilliseconds(1));
    try testing.expect(!try stack.resolver.wait_for_delivery_response());
    try testing.expectError(error.Empty, subscription.try_recv());
    const digest = candidate.block.digest();
    try testing.expect(try stack.mailbox.get_block(.{ .digest = digest }) == null);
}

test "coding untrusted delivery rejects mismatched root" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try untrusted_rejects_mismatched_root(ctx, false);
        }
    }.body);
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            try untrusted_rejects_mismatched_root(ctx, true);
        }
    }.body);
}

/// The heights of the recorded fetches with a certified subscriber, in order (at most 8).
fn certified_fetch_heights(resolver: common.RecordingResolver, out: *[8]u64) ![]u64 {
    const fetches = try resolver.fetches(gpa);
    defer gpa.free(fetches);
    var count: usize = 0;
    for (fetches) |item| {
        if (item.subscriber != .certified) continue;
        out[count] = item.subscriber.certified.get();
        count += 1;
    }
    return out[0..count];
}

/// commonware's certified-ancestry body: certifying a child keeps certification evidence for
/// its parent (fetched, or `cached_parent`, subscribed `by_digest` or by commitment) and, once
/// the parent resolves, its grandparent, so none of them is re-coded.
fn certified_ancestry_skips_recoding(ctx: Ctx, cached_parent: bool, by_digest: bool) !void {
    var validators = try fixture();
    defer validators.deinit(gpa);
    const provider: common.Provider = .init(&validators.schemes[0]);
    var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
    defer buffer.deinit();
    var stack = try common.start_coding_actor_with_recording(
        ctx.child("validator"),
        "certified-ancestry-delivery",
        provider,
        buffer,
    );
    defer stack.stop();
    var chain: [3]common.ChainLink = undefined;
    try common.coding_chain(gpa, validators.participants[0], &chain);
    defer for (&chain) |*link| link.block.deinit(gpa);
    const grandparent = &chain[0].block;
    const parent = &chain[1].block;
    const child = &chain[2];
    if (cached_parent) {
        try testing.expect(try stack.mailbox.verified(chain[1].round, parent.clone()));
    }
    try testing.expect(try stack.mailbox.verified(child.round, child.block.clone()));
    const proposal = common.Proposal.init(child.round, .new(2), child.block.commitment());
    var notarization = try H.make_notarization(gpa, &validators, proposal, quorum);
    defer notarization.deinit(gpa);
    _ = stack.mailbox.report(.{ .certification = notarization });

    // Local retrieval and remote delivery both keep the certification evidence.
    if (!cached_parent) {
        const value = try common.encode_coded(gpa, parent);
        defer gpa.free(value);
        try stack.resolver.respond_to_next_fetch(value);
    }
    var subscription = if (by_digest)
        try stack.mailbox.subscribe_by_digest(parent.digest(), .wait)
    else
        try stack.mailbox.subscribe_by_commitment(parent.commitment(), .{
            .fetch_by_commitment = .{ .height = .new(2) },
        });
    defer subscription.deinit();
    var delivered = try subscription.recv();
    defer delivered.deinit(gpa);
    try testing.expect(try shards_absent(&delivered));
    if (cached_parent) {
        try testing.expectEqual(0, stack.resolver.fetch_count());
    } else {
        try testing.expect(try stack.resolver.wait_for_delivery_response());
    }

    // Resolving the parent extends the evidence to the grandparent.
    const value = try common.encode_coded(gpa, grandparent);
    defer gpa.free(value);
    try stack.resolver.respond_to_next_fetch(value);
    var lower = try stack.mailbox.subscribe_by_commitment(grandparent.commitment(), .{
        .fetch_by_commitment = .{ .height = .new(1) },
    });
    defer lower.deinit();
    var ancestor = try lower.recv();
    defer ancestor.deinit(gpa);
    try testing.expect(try shards_absent(&ancestor));
    try testing.expect(try stack.resolver.wait_for_delivery_response());
    var heights: [8]u64 = undefined;
    const certified = try certified_fetch_heights(stack.resolver, &heights);
    const expected: []const u64 = if (cached_parent) &.{1} else &.{ 2, 1 };
    try testing.expectEqualSlices(u64, expected, certified);
}

test "coding certified ancestry delivery skips recoding" {
    inline for (.{ .{ false, false }, .{ true, false }, .{ true, true } }) |shape| {
        try common.run(struct {
            fn body(ctx: Ctx) anyerror!void {
                try certified_ancestry_skips_recoding(ctx, shape[0], shape[1]);
            }
        }.body);
    }
}

/// A direct coding actor whose application acknowledges by hand (commonware's
/// `Application::manual_ack()` actor of the delivery tests). Must not move.
const ManualStack = struct {
    const A = common.Actor(common.App);

    stores: harness.Archives,
    mailbox: A.Mailbox,
    resolver: common.RecordingResolver,
    application: common.App,
    buffer: common.RecordingCodingBuffer,
    handle: @import("runtime").context.Handle(anyerror!void),

    fn start(
        self: *ManualStack,
        ctx: Ctx,
        prefix: []const u8,
        validators: *const common.Fixture,
    ) !void {
        try self.stores.open(ctx, prefix);
        errdefer self.stores.deinit();
        const provider: common.Provider = .init(&validators.schemes[0]);
        const config = try common.test_config(A, gpa, prefix, provider, &self.stores.cache_ref);
        const initialized = try A.init(
            ctx.child("actor"),
            .{ .archive = &self.stores.finalizations },
            .{ .archive = &self.stores.blocks },
            config,
        );
        self.mailbox = initialized.mailbox;
        const scope = ctx.scope.child("resolver");
        var holding = try common.RecordingResolver.holding(gpa, ctx.io(), &scope);
        self.resolver = holding.resolver;
        self.application = try common.App.manual_ack(gpa, ctx.io());
        self.buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
        self.handle = try initialized.actor.start(
            self.application.clone(),
            self.buffer.clone(),
            holding.receiver,
            holding.resolver.clone(),
        );
    }

    fn stop(self: *ManualStack) void {
        const ended = self.handle.abort() catch {};
        ended catch {};
        self.mailbox.deinit();
        self.application.deinit();
        self.buffer.deinit();
        self.resolver.deinit();
        self.stores.deinit();
    }
};

/// `(finalization, block).encode()` for an application block. The caller frees it.
fn encode_finalized(
    finalization: *const H.Finalization,
    block: *const common.CodingB,
) ![]u8 {
    const codec = @import("codec");
    const size = finalization.encode_size() + block.encode_size();
    const bytes = try gpa.alloc(u8, size);
    var writer: codec.Writer = .init(bytes);
    finalization.write(&writer);
    block.write(&writer);
    std.debug.assert(writer.written().len == size);
    return bytes;
}

test "coding finalized height delivery rejects digest mismatch" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            var stack: ManualStack = undefined;
            try stack.start(ctx, "finalized-height-digest-mismatch", &validators);
            defer stack.stop();
            const mailbox = &stack.mailbox;
            try testing.expectEqual(0, (try stack.application.acknowledged()).get());

            var honest = try common.missing_candidate(gpa, validators.participants[0]);
            defer honest.block.deinit(gpa);
            const height = honest.block.height();
            var other = try common.coded(gpa, honest.context, honest.block.parent(), 1, 101);
            defer other.deinit(gpa);
            const round = honest.context.round;
            const proposal = common.Proposal.init(round, .zero(), honest.block.commitment());
            var finalization = try H.make_finalization(gpa, &validators, proposal, quorum);
            defer finalization.deinit(gpa);
            // Same height and context, different bytes: the signed digest is the honest one.
            try testing.expect(std.meta.eql(honest.block.context(), other.context()));
            try testing.expect(finalization.proposal.payload.block().eql(honest.block.digest()));
            try testing.expect(!finalization.proposal.payload.block().eql(other.digest()));

            var subscriptions = [_]utils.channel.oneshot.Receiver(common.Block){
                try mailbox.subscribe_by_commitment(honest.block.commitment(), .wait),
                try mailbox.subscribe_by_commitment(other.commitment(), .wait),
                try mailbox.subscribe_by_digest(honest.block.digest(), .wait),
                try mailbox.subscribe_by_digest(other.digest(), .wait),
            };
            defer for (&subscriptions) |*subscription| subscription.deinit();
            const processed = try mailbox.get_processed();
            const tip = stack.application.tip();

            // A valid finalization must reject different bundled block bytes.
            const value = try encode_finalized(&finalization, other.inner());
            defer gpa.free(value);
            const accepted = try stack.resolver.deliver(.{
                .key = .{ .finalized = height },
                .subscriber = .{ .finalized = .{ .by_height = height } },
            }, value);
            try testing.expect(!accepted);
            try testing.expect(try mailbox.get_block(.{ .height = height }) == null);
            try testing.expect(try mailbox.get_block(.{ .digest = honest.block.digest() }) == null);
            try testing.expect(try mailbox.get_block(.{ .digest = other.digest() }) == null);
            try testing.expect(try mailbox.get_finalization(height) == null);
            try testing.expect(std.meta.eql(try mailbox.get_processed(), processed));
            for (&subscriptions) |*subscription| {
                try testing.expectError(error.Empty, subscription.try_recv());
            }
            try testing.expectEqual(1, stack.application.block_count());
            try testing.expect(!stack.application.contains(height));
            const pending = try stack.application.pending_ack_heights(gpa);
            defer gpa.free(pending);
            try testing.expectEqual(0, pending.len);
            try testing.expect(std.meta.eql(stack.application.tip(), tip));
        }
    }.body);
}

/// Waits until `resolver` recorded more than `count` fetches.
fn wait_fetches(ctx: Ctx, resolver: common.RecordingResolver, count: usize) !void {
    var waited: u32 = 0;
    while (resolver.fetch_count() <= count) : (waited += 1) {
        if (waited > 5_000) return error.TestTimedOut;
        try ctx.sleep(.fromMilliseconds(1));
    }
}

/// A competing branch of four blocks at views 11 through 14 above genesis.
fn competing_branch(me: common.K, out: *[4]common.Block) !void {
    const genesis = try common.genesis_block(gpa);
    var parent_view: u64 = 0;
    var parent_commitment = try common.genesis_coding_commitment(gpa, &genesis);
    var made: usize = 0;
    errdefer for (out[0..made]) |*block| block.deinit(gpa);
    for (out, 1..) |*block, height| {
        const context: common.CodingCtx = .{
            .round = common.round_at(0, height + 10),
            .leader = me,
            .parent = .{ .new(parent_view), parent_commitment },
        };
        block.* = try common.coded(gpa, context, parent_commitment.block(), height, height * 100);
        made += 1;
        parent_view = height + 10;
        parent_commitment = block.commitment();
    }
}

/// Caches a certified ancestor at height 2 of `chain` and checks it was delivered under
/// certification evidence, without re-coding.
fn cache_certified_ancestor(
    stack: *common.ActorStack,
    validators: *const common.Fixture,
    chain: *[3]common.ChainLink,
) !void {
    const child = &chain[2];
    try testing.expect(try stack.mailbox.verified(child.round, child.block.clone()));
    const proposal = common.Proposal.init(child.round, .new(2), child.block.commitment());
    var notarization = try H.make_notarization(gpa, validators, proposal, quorum);
    defer notarization.deinit(gpa);
    _ = stack.mailbox.report(.{ .certification = notarization });
    const ancestor = &chain[1].block;
    const value = try common.encode_coded(gpa, ancestor);
    defer gpa.free(value);
    try stack.resolver.respond_to_next_fetch(value);
    const fallback: core_mailbox.CommitmentFallback = .{
        .fetch_by_commitment = .{ .height = .new(2) },
    };
    var subscription = try stack.mailbox.subscribe_by_commitment(ancestor.commitment(), fallback);
    defer subscription.deinit();
    var certified = try subscription.recv();
    defer certified.deinit(gpa);
    try testing.expect(try stack.resolver.wait_for_delivery_response());
    try testing.expect(try shards_absent(&certified));
    const fetches = try stack.resolver.fetches(gpa);
    defer gpa.free(fetches);
    try testing.expect(fetches[0].subscriber.eql(.{ .certified = .new(2) }));
}

/// Delivers the competing ancestors the verifier fetches: neither the certified fork nor a
/// cached untrusted child authenticates them, so each is fetched untrusted and re-coded, and
/// the certified fork's bytes are refused for the first.
fn serve_competing_ancestry(
    ctx: Ctx,
    stack: *common.ActorStack,
    branch: *const [4]common.Block,
    certified: *const common.Block,
) !void {
    for ([_]usize{ 1, 0 }, 0..) |position, index| {
        const ancestor = &branch[position];
        try wait_fetches(ctx, stack.resolver, index + 1);
        const fetches = try stack.resolver.fetches(gpa);
        defer gpa.free(fetches);
        const item = fetches[index + 1];
        try testing.expect(item.key.eql(.{ .block = ancestor.commitment() }));
        // The walk bounds each request by the round the child's context names for it.
        const expected: common.Annotation = .{ .untrusted = .{
            .height = ancestor.height(),
            .round = ancestor.context().round,
        } };
        try testing.expect(item.subscriber.eql(expected));
        var subscription = try stack.mailbox.subscribe_by_commitment(ancestor.commitment(), .wait);
        defer subscription.deinit();
        _ = try stack.mailbox.get_processed();
        if (index == 0) {
            const wrong = try common.encode_coded(gpa, certified);
            defer gpa.free(wrong);
            try testing.expect(!try stack.resolver.deliver(item, wrong));
            try testing.expectError(error.Empty, subscription.try_recv());
        }
        const value = try common.encode_coded(gpa, ancestor);
        defer gpa.free(value);
        try testing.expect(try stack.resolver.deliver(item, value));
        var delivered = try subscription.recv();
        defer delivered.deinit(gpa);
        try testing.expect(delivered.commitment().eql(ancestor.commitment()));
        // Untrusted ancestry is re-coded.
        try testing.expect(try shards_present(&delivered));
    }
}

/// Finalizes `branch`'s tip and waits until every branch block is finalized by height.
fn finalize_competing_branch(
    ctx: Ctx,
    stack: *common.ActorStack,
    validators: *const common.Fixture,
    branch: *const [4]common.Block,
) !void {
    const candidate = &branch[3];
    const proposal = common.Proposal.init(
        candidate.context().round,
        branch[2].context().round.view,
        candidate.commitment(),
    );
    var finalization = try H.make_finalization(gpa, validators, proposal, quorum);
    defer finalization.deinit(gpa);
    _ = stack.mailbox.report(.{ .finalization = finalization });
    var waited: u32 = 0;
    while (true) : (waited += 1) {
        if (waited > 5_000) return error.TestTimedOut;
        const processed = try stack.mailbox.get_processed();
        if (processed) |value| if (std.meta.eql(value, .{ .block = .new(4) })) break;
        try ctx.sleep(.fromMilliseconds(1));
    }
    for (branch) |*block| {
        var finalized = (try stack.mailbox.get_block(.{ .height = block.height() })) orelse
            return error.BlockMissing;
        defer finalized.deinit(gpa);
        try testing.expect(finalized.commitment().eql(block.commitment()));
    }
}

/// A digest subscription to `block` resolves at once with `block`.
fn expect_subscribed(stack: *common.ActorStack, block: *const common.Block) !void {
    var subscription = try stack.mailbox.subscribe_by_digest(block.digest(), .wait);
    defer subscription.deinit();
    var received = try subscription.recv();
    defer received.deinit(gpa);
    try testing.expect(received.commitment().eql(block.commitment()));
}

const WalkingMarshaled = common.MarshaledOf(common.WalkingVerifyingApp);

test "coding optimistic ancestry conflicts with certified cache" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("validator"),
                "optimistic-ancestry-conflict",
                provider,
                buffer,
            );
            defer stack.stop();
            const me = validators.participants[0];
            var certified_chain: [3]common.ChainLink = undefined;
            try common.coding_chain(gpa, me, &certified_chain);
            defer for (&certified_chain) |*link| link.block.deinit(gpa);
            try cache_certified_ancestor(&stack, &validators, &certified_chain);

            // Later views extend a competing branch at the same heights; only its candidate
            // and the candidate's parent are available before verification.
            var branch: [4]common.Block = undefined;
            try competing_branch(me, &branch);
            defer for (&branch) |*block| block.deinit(gpa);
            const candidate = &branch[3];
            const parent = &branch[2];
            try testing.expect(!branch[1].digest().eql(certified_chain[1].block.digest()));
            try testing.expect(try stack.mailbox.verified(parent.context().round, parent.clone()));
            const candidate_round = candidate.context().round;
            try testing.expect(try stack.mailbox.verified(candidate_round, candidate.clone()));
            try expect_subscribed(&stack, parent);

            var shard_stack: common.ShardStack = undefined;
            const shards_ctx = ctx.child("shards");
            const participants = validators.participants;
            try common.start_shard_mailbox(&shard_stack, shards_ctx, participants, provider);
            defer shard_stack.stop();
            var walked: std.ArrayList(common.D) = .empty;
            defer walked.deinit(gpa);
            const app: common.WalkingVerifyingApp = .{ .gpa = gpa, .blocks = &walked };
            const marshal = stack.mailbox.clone();
            const shards = shard_stack.shards();
            const config =
                common.marshaled_config(WalkingMarshaled, app, marshal, shards, provider);
            var marshaled = try WalkingMarshaled.init(ctx.child("marshaled"), config);
            defer marshaled.deinit();
            var verify = try marshaled.start_verify(candidate.context(), candidate.commitment());
            defer verify.deinit();
            try serve_competing_ancestry(ctx, &stack, &branch, &certified_chain[1].block);

            // Both forks stay cached and are retrieved by their own digests.
            for ([_]*const common.Block{ &certified_chain[1].block, &branch[1] }) |ancestor| {
                var stored = (try stack.mailbox.get_block(.{ .digest = ancestor.digest() })) orelse
                    return error.AncestorMissing;
                defer stored.deinit(gpa);
                try testing.expect(stored.commitment().eql(ancestor.commitment()));
            }
            var certify = try marshaled.start_certify(candidate_round, candidate.commitment());
            defer certify.deinit();
            try testing.expect(try certify.recv());
            // The verifier walked the competing branch down to genesis.
            try testing.expectEqual(5, walked.items.len);
            for (walked.items[0..4], 0..) |digest, index| {
                try testing.expect(digest.eql(branch[3 - index].digest()));
            }

            // Finalization follows the competing branch despite the certified height-2 block.
            try finalize_competing_branch(ctx, &stack, &validators, &branch);
            try testing.expectEqual(3, stack.resolver.fetch_count());
        }
    }.body);
}

/// The subscribers of the recorded certified and untrusted fetches, in order (at most 8).
fn ancestry_annotations(
    resolver: common.RecordingResolver,
    out: *[8]common.Annotation,
) ![]common.Annotation {
    const fetches = try resolver.fetches(gpa);
    defer gpa.free(fetches);
    var count: usize = 0;
    for (fetches) |item| {
        if (item.subscriber != .certified and item.subscriber != .untrusted) continue;
        out[count] = item.subscriber;
        count += 1;
    }
    return out[0..count];
}

/// An untrusted annotation at `height` carrying `got`'s round, if any.
/// Delivers `parent` for `fetch`, then subscribes to `grandparent` and checks processing is
/// still held below it. Returns the grandparent subscription.
fn deliver_below_tip(
    stack: *common.ActorStack,
    fetch: common.Fetch,
    parent: *const common.Block,
    grandparent: *const common.Block,
) !utils.channel.oneshot.Receiver(common.Block) {
    const value = try common.encode_coded(gpa, parent);
    defer gpa.free(value);
    try testing.expect(try stack.resolver.deliver(fetch, value));
    var subscription = try stack.mailbox.subscribe_by_commitment(grandparent.commitment(), .{
        .fetch_by_commitment = .{ .height = grandparent.height() },
    });
    errdefer subscription.deinit();
    const processed = try stack.mailbox.get_processed();
    const processed_height = if (processed) |position| position.height().get() else 0;
    try testing.expect(processed_height < grandparent.height().get());
    return subscription;
}

test "coding certification retention follows finalized tip" {
    try common.run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var validators = try fixture();
            defer validators.deinit(gpa);
            const provider: common.Provider = .init(&validators.schemes[0]);
            var buffer = try common.RecordingCodingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var stack = try common.start_coding_actor_with_recording(
                ctx.child("validator"),
                "certification-retention",
                provider,
                buffer,
            );
            defer stack.stop();
            const mailbox = &stack.mailbox;
            var chain: [3]common.ChainLink = undefined;
            try common.coding_chain(gpa, validators.participants[0], &chain);
            defer for (&chain) |*link| link.block.deinit(gpa);
            const grandparent = &chain[0].block;
            const parent = &chain[1].block;
            const child = &chain[2];

            // A certified parent fetch starts before the child is finalized.
            try testing.expect(try mailbox.verified(child.round, child.block.clone()));
            const proposal = common.Proposal.init(child.round, .new(2), child.block.commitment());
            var notarization = try H.make_notarization(gpa, &validators, proposal, quorum);
            defer notarization.deinit(gpa);
            _ = mailbox.report(.{ .certification = notarization });
            const fallback: core_mailbox.CommitmentFallback =
                .{ .fetch_by_commitment = .{ .height = parent.height() } };
            var subscriptions: [4]utils.channel.oneshot.Receiver(common.Block) = undefined;
            var made: usize = 0;
            defer for (subscriptions[0..made]) |*subscription| subscription.deinit();
            subscriptions[0] = try mailbox.subscribe_by_commitment(parent.commitment(), fallback);
            made += 1;
            _ = try mailbox.get_processed();
            const fetches = try stack.resolver.fetches(gpa);
            defer gpa.free(fetches);
            const fetch = fetches[fetches.len - 1];
            try testing.expect(fetch.subscriber.eql(.{ .certified = parent.height() }));

            // Finalization advances the tip while missing ancestors hold back processing.
            var finalization = try H.make_finalization(gpa, &validators, proposal, quorum);
            defer finalization.deinit(gpa);
            _ = mailbox.report(.{ .finalization = finalization });
            const info = (try mailbox.get_info(.{ .height = child.block.height() })) orelse
                return error.InfoMissing;
            try testing.expect(info.digest.eql(child.block.digest()));
            subscriptions[1] = try mailbox.subscribe_by_commitment(parent.commitment(), fallback);
            made += 1;
            // A late certification must not restore evidence below the tip.
            _ = mailbox.report(.{ .certification = notarization });
            subscriptions[2] = try mailbox.subscribe_by_commitment(parent.commitment(), fallback);
            made += 1;
            _ = try mailbox.get_processed();

            // The original fetch still arrives, but retains no older ancestry evidence.
            subscriptions[3] = try deliver_below_tip(&stack, fetch, parent, grandparent);
            made += 1;
            var out: [8]common.Annotation = undefined;
            const annotations = try ancestry_annotations(stack.resolver, &out);
            try testing.expectEqual(4, annotations.len);
            // These subscriptions pass no round, so neither do their requests.
            const expected = [_]common.Annotation{
                .{ .certified = parent.height() },
                .{ .untrusted = .{ .height = parent.height(), .round = null } },
                .{ .untrusted = .{ .height = parent.height(), .round = null } },
                .{ .untrusted = .{ .height = grandparent.height(), .round = null } },
            };
            for (expected, annotations) |want, got| try testing.expect(want.eql(got));
        }
    }.body);
}

test {
    _ = common;
}
