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

test {
    _ = common;
}
