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
            const context: common.CodingCtx = .{
                .round = common.round_at(0, 2),
                .leader = me,
                .parent = .{ parent.context.round.view, parent.block.commitment() },
            };
            const raw =
                try harness.make_coding_block(gpa, context, parent.block.digest(), .new(2), 200);
            var child = try broadcast.Digested(common.CodingB).compute(gpa, raw);
            defer child.deinit();
            var subscription = try stack.mailbox.subscribe_parent(&child);
            defer subscription.deinit();

            try ctx.sleep(.fromMilliseconds(100));
            // Parent walkback should use the coding parent commitment.
            try testing.expectEqual(1, buffer.commitment_subscription_count());
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

test {
    _ = common;
}
