//! Tests of the coding marshal's application wrapper (marshaled.zig). Commonware's own tests
//! of `Marshaled` run in `coding/mod.rs` on the marshal harness; these drive the wrapper
//! against scripted marshal and shard mailboxes on the deterministic runtime.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const coding = @import("coding");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");

const types = @import("types.zig");
const marshaled_module = @import("marshaled.zig");
const harness = @import("shards/engine_harness.zig");
const mocks_block = @import("../mocks/block.zig");
const consensus_types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const RS = coding.ReedSolomon(Sha256);
const Ctx = runtime.deterministic.Context;
const Scheme = harness.Scheme;
const TestCommitment = types.CommitmentOf(Sha256, RS, Sha256);
const TestContext = simplex_types.Context(TestCommitment, PublicKey);
const InnerBlock = mocks_block.Block(Sha256, TestContext);
const TestCoding = @import("variant.zig").Coding(InnerBlock, RS, Sha256, PublicKey);
const TestMailbox = @import("../core/mailbox.zig").Mailbox(Scheme, TestCoding);
const Ancestry = @import("../ancestry.zig").AncestorStream(TestMailbox);

const participants_count = 4;

/// One scheme, for epoch zero only.
const TestProvider = struct {
    value: *const Scheme,

    pub fn scheme(provider: TestProvider, epoch: consensus_types.Epoch) ?*const Scheme {
        if (epoch.get() != 0) return null;
        return provider.value;
    }
};

/// Verifies every block as `valid`, counting the calls.
const TestApp = struct {
    valid: bool,
    calls: *u32,

    /// Builds the next block on the parent the ancestry starts from.
    pub fn propose(_: *TestApp, _: Ctx, context: TestContext, stream: Ancestry) !?Digested {
        var owned = stream;
        defer owned.deinit();
        var parent = try owned.next() orelse return null;
        defer parent.deinit();
        const height = parent.inner().height().get() + 1;
        const block = try InnerBlock.init(gpa, context, parent.digest(), .new(height), 30);
        return try Digested.compute(gpa, block);
    }

    pub fn verify(self: *TestApp, _: Ctx, _: TestContext, stream: Ancestry) !bool {
        var owned = stream;
        owned.deinit();
        self.calls.* += 1;
        return self.valid;
    }
};

const M = marshaled_module.Marshaled(struct {
    pub const Context = Ctx;
    pub const Application = TestApp;
    pub const Block = InnerBlock;
    pub const Coding = RS;
    pub const Hasher = Sha256;
    pub const Provider = TestProvider;
    pub const Strategy = parallel.Sequential;
    pub const Epocher = consensus_types.FixedEpocher;
});
const Digested = @import("broadcast").Digested(InnerBlock);
const V = M.V;

test {
    testing.refAllDecls(M);
}

comptime {
    @import("../../traits.zig").assert_certifiable_automaton(M);
    @import("../../traits.zig").assert_relay(M);
    @import("../../traits.zig").assert_reporter(M);
}

/// The wrapper with scripted mailboxes: the test reads what it sends to marshal and shards.
const Fixture = struct {
    keys: [participants_count]PrivateKey,
    peers: [participants_count]PublicKey,
    scheme: Scheme,
    calls: u32 = 0,
    marshal: actor.mailbox.Receiver(M.Mailbox.M),
    shards: actor.mailbox.Receiver(M.Shards.Msg),
    marshaled: M,

    /// A fixture of participant `signer`'s view (null: a verifier that cannot sign).
    fn init(fixture: *Fixture, ctx: Ctx, signer: ?usize, valid: bool) !void {
        harness.sorted_keys(&fixture.keys, &fixture.peers, 1);
        const set = try Scheme.Participants.init(gpa, &fixture.peers);
        fixture.scheme = if (signer) |index|
            (try Scheme.signer(gpa, harness.scheme_namespace, set, fixture.keys[index])).?
        else
            try Scheme.verifier(gpa, harness.scheme_namespace, set);
        fixture.calls = 0;
        const io = ctx.io();
        const marshal = try actor.mailbox.new(M.Mailbox.M, gpa, io, 64);
        const shards = try actor.mailbox.new(M.Shards.Msg, gpa, io, 64);
        fixture.marshal = marshal.receiver;
        fixture.shards = shards.receiver;
        fixture.marshaled = try .init(ctx, .{
            .application = .{ .valid = valid, .calls = &fixture.calls },
            .marshal = .init(gpa, io, marshal.sender, 8),
            .shards = .{ .gpa = gpa, .io = io, .sender = shards.sender },
            .scheme_provider = .{ .value = &fixture.scheme },
            .strategy = parallel.sequential,
            .epocher = .new(utils.NonZero(u64).init(10).?),
        });
    }

    fn deinit(fixture: *Fixture) void {
        fixture.marshaled.deinit();
        while (fixture.marshal.try_recv()) |message| M.Mailbox.M.discard(message) else |_| {}
        while (fixture.shards.try_recv()) |message| M.Shards.Msg.discard(message) else |_| {}
        fixture.marshal.deinit();
        fixture.shards.deinit();
        fixture.scheme.deinit(gpa);
    }

    /// The next message to the shards engine.
    fn next_shard_message(fixture: *Fixture) !M.Shards.Msg {
        return fixture.shards.try_recv();
    }
};

fn coding_config() coding.Config {
    return types.coding_config_for_participants(participants_count);
}

/// Codes `block` for the fixture's committee.
fn encode(block: InnerBlock) !V.Block {
    const shared = try Digested.compute(gpa, block);
    return V.Block.encode(gpa, shared, coding_config(), parallel.sequential);
}

/// The context of a proposal at `view` on `parent` (proposed at `parent_view`).
fn context_at(view: u64, parent_view: u64, parent: TestCommitment) TestContext {
    const leader = PrivateKey.from_seed(1).public_key();
    return .{
        .round = .new(.zero(), .new(view)),
        .leader = leader,
        .parent = .{ .new(parent_view), parent },
    };
}

/// A parent at height 1 (proposed in view 1) and its child at height 2 (proposed in view 2).
const Chain = struct {
    parent: V.Block,
    child: V.Block,
    context: TestContext,

    fn init() !Chain {
        const genesis: TestCommitment = .init(.empty, .empty, .empty, coding_config());
        const parent_context = context_at(1, 0, genesis);
        const parent_block = try InnerBlock.init(gpa, parent_context, .empty, .new(1), 10);
        var parent = try encode(parent_block);
        errdefer parent.deinit(gpa);
        const context = context_at(2, 1, parent.commitment());
        const child_block = try InnerBlock.init(gpa, context, parent.digest(), .new(2), 20);
        const child = try encode(child_block);
        return .{ .parent = parent, .child = child, .context = context };
    }

    fn deinit(chain: *Chain) void {
        chain.parent.deinit(gpa);
        chain.child.deinit(gpa);
    }
};

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

/// The verdict of the blocking `Automaton::verify`.
fn expect_verify(marshaled: M, context: TestContext, payload: TestCommitment) !?bool {
    var handle = marshaled;
    return handle.verify(testing.io, context, payload);
}

test "verify rejects a proposal with an unexpected coding config or context digest" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var fixture: Fixture = undefined;
            try fixture.init(ctx, 0, true);
            defer fixture.deinit();
            var chain = try Chain.init();
            defer chain.deinit();
            const good = chain.child.commitment();
            const config: coding.Config = .{ .minimum_shards = 1, .extra_shards = 3 };
            const wrong_config: TestCommitment =
                .init(good.block(), good.root(), good.context(), config);
            try testing.expectEqual(false, try expect_verify(
                fixture.marshaled,
                chain.context,
                wrong_config,
            ));
            const wrong_context: TestCommitment =
                .init(good.block(), good.root(), Sha256.hash(&.{"other"}), coding_config());
            try testing.expectEqual(false, try expect_verify(
                fixture.marshaled,
                chain.context,
                wrong_context,
            ));
            // Neither reached the shards engine nor marshal.
            try testing.expectError(error.Empty, fixture.next_shard_message());
            try testing.expectError(error.Empty, fixture.marshal.try_recv());
        }
    }.body);
}

test "verify closes the receiver without a scheme for the epoch" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var fixture: Fixture = undefined;
            try fixture.init(ctx, 0, true);
            defer fixture.deinit();
            var chain = try Chain.init();
            defer chain.deinit();
            var context = chain.context;
            context.round = .new(.new(1), .new(2));
            const verdict = try expect_verify(fixture.marshaled, context, chain.child.commitment());
            try testing.expectEqual(null, verdict);
        }
    }.body);
}

test "a node that cannot sign accepts a valid proposal at once and registers its gate" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var fixture: Fixture = undefined;
            try fixture.init(ctx, null, true);
            defer fixture.deinit();
            var chain = try Chain.init();
            defer chain.deinit();
            const payload = chain.child.commitment();
            const verdict = try expect_verify(fixture.marshaled, chain.context, payload);
            try testing.expectEqual(true, verdict);
            // The proposal's shards are gathered for its round.
            const gathered = try fixture.next_shard_message();
            try testing.expect(gathered == .gather);
            try testing.expect(gathered.gather.commitment.eql(payload));
            // Its deferred verification is certification's gate.
            const round = chain.context.round;
            var gate = fixture.marshaled.gates_of().take(round, payload) orelse
                return error.TestExpectedGate;
            gate.deinit();
        }
    }.body);
}

/// Answers marshal's requests with the chain's blocks and acknowledges stores, for
/// `messages` messages.
fn serve(fixture: *Fixture, chain: *const Chain, messages: u32) !void {
    for (0..messages) |_| {
        const message = (try fixture.marshal.recv()) orelse return error.TestUnexpectedClose;
        switch (message.body) {
            .subscribe_by_commitment => |request| {
                var response = request.response;
                const child = request.commitment.eql(chain.child.commitment());
                const source = if (child) &chain.child else &chain.parent;
                const block = V.clone_block(source);
                response.send(block) catch V.Block.discard(block);
            },
            inline .verified, .certified => |store| {
                var ack = store.ack;
                ack.send({}) catch {};
                var block = store.block;
                V.deinit_block(gpa, &block);
            },
            else => M.Mailbox.M.discard(message),
        }
    }
}

fn gate_outcome(fixture: *Fixture, chain: *const Chain) !?bool {
    const payload = chain.child.commitment();
    var gate = try fixture.marshaled.deferred_verify(chain.context, payload, null, .verified);
    defer gate.deinit();
    // The candidate, its parent, and the candidate's store.
    try serve(fixture, chain, 3);
    const outcome = gate.recv() catch |err| switch (err) {
        error.Closed => return null,
        error.Canceled => return error.Canceled,
    };
    return outcome.ready;
}

test "deferred verification resolves its gate with the application's verdict" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            inline for (.{ true, false }) |valid| {
                var fixture: Fixture = undefined;
                try fixture.init(ctx, 0, valid);
                defer fixture.deinit();
                var chain = try Chain.init();
                defer chain.deinit();
                try testing.expectEqual(valid, try gate_outcome(&fixture, &chain));
                try testing.expectEqual(1, fixture.calls);
            }
        }
    }.body);
}

test "deferred verification rejects a block that breaks a coded invariant" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var fixture: Fixture = undefined;
            try fixture.init(ctx, 0, true);
            defer fixture.deinit();
            var chain = try Chain.init();
            defer chain.deinit();
            // The consensus context names another parent view than the block embeds.
            chain.context.parent[0] = .new(0);
            try testing.expectEqual(false, try gate_outcome(&fixture, &chain));
            try testing.expectEqual(0, fixture.calls);
        }
    }.body);
}

test "propose codes the built block and stages it under its commitment" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var fixture: Fixture = undefined;
            try fixture.init(ctx, 0, true);
            defer fixture.deinit();
            var chain = try Chain.init();
            defer chain.deinit();
            // Propose in view 3 on the child (height 2, view 2).
            const context = context_at(3, 2, chain.child.commitment());
            var receiver = try fixture.marshaled.start_propose(context);
            defer receiver.deinit();
            try serve(&fixture, &chain, 1);
            const digest = try receiver.recv();
            const expected = try InnerBlock.init(gpa, context, chain.child.digest(), .new(3), 30);
            try testing.expect(digest.block().eql(expected.digest()));
            try testing.expect(digest.config().eql(coding_config()));
            const context_digest = try types.hash_context(Sha256, gpa, context);
            try testing.expect(digest.context().eql(context_digest));
            const registry = fixture.marshaled.gates_of();
            const staged, const sent = (try registry.take_staged(context.round, digest)).?;
            try testing.expect(!sent);
            var block = staged.block;
            defer V.deinit_block(gpa, &block);
            try testing.expect(block.commitment().eql(digest));
            var ack = staged.ack;
            try ack.send({});
        }
    }.body);
}

test "propose re-proposes the epoch's last block" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var fixture: Fixture = undefined;
            try fixture.init(ctx, 0, true);
            defer fixture.deinit();
            var chain = try Chain.init();
            defer chain.deinit();
            // A boundary block at height 9, the last of epoch zero (length 10).
            const parent_context = context_at(8, 2, chain.child.commitment());
            const child_digest = chain.child.digest();
            const boundary = try InnerBlock.init(gpa, parent_context, child_digest, .new(9), 9);
            chain.parent.deinit(gpa);
            chain.parent = try encode(boundary);
            const context = context_at(9, 8, chain.parent.commitment());
            var receiver = try fixture.marshaled.start_propose(context);
            defer receiver.deinit();
            try serve(&fixture, &chain, 1);
            const digest = try receiver.recv();
            try testing.expect(digest.eql(chain.parent.commitment()));
            try testing.expectEqual(0, fixture.calls);
            const registry = fixture.marshaled.gates_of();
            const staged, _ = (try registry.take_staged(context.round, digest)).?;
            var block = staged.block;
            defer V.deinit_block(gpa, &block);
            var ack = staged.ack;
            try ack.send({});
        }
    }.body);
}

test "certify consumes the verification's gate without verifying again" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var fixture: Fixture = undefined;
            try fixture.init(ctx, null, true);
            defer fixture.deinit();
            var chain = try Chain.init();
            defer chain.deinit();
            const payload = chain.child.commitment();
            const round = chain.context.round;
            const verdict = try expect_verify(fixture.marshaled, chain.context, payload);
            try testing.expectEqual(true, verdict);
            var certified = try fixture.marshaled.start_certify(round, payload);
            defer certified.deinit();
            // The candidate, its parent, its store, and the notarized hint.
            try serve(&fixture, &chain, 4);
            try testing.expect(try certified.recv());
            try testing.expectEqual(1, fixture.calls);
            // The gate was claimed.
            try testing.expect(fixture.marshaled.gates_of().take(round, payload) == null);
        }
    }.body);
}
