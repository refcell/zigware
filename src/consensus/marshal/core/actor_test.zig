//! Smoke tests for the marshal actor on the deterministic runtime. Commonware's own actor
//! tests (standard/mod.rs) run on the shared harness.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const actor_api = @import("actor");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const resolver_api = @import("resolver");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const types = @import("../../types.zig");
const simplex = @import("../../simplex/root.zig");
const simplex_types = @import("../../simplex/types.zig");
const mocks_block = @import("../mocks/block.zig");
const Standard = @import("../standard/variant.zig").Standard;
const store = @import("../store.zig");
const update = @import("../update.zig");
const handler = @import("../resolver/handler.zig");
const variant = @import("variant.zig");
const actor = @import("actor.zig");
const soak = @import("../mocks/soak.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const TestBlock = mocks_block.EmptyBlock(Sha256);
const V = Standard(TestBlock);
const S = simplex.scheme.ed25519.Scheme(D);
const Exact = utils.acknowledgement.Exact;
const Finalization = simplex_types.Finalization(S, D);
const Finalize = simplex_types.Finalize(S, D);
const Proposal = simplex_types.Proposal(D);
const Fixture = cryptography.certificate.mocks.Fixture(S);
const Translator = storage.translator.EightCap;
const BlockArchive = storage.archive.prunable.Archive(Translator, [32]u8, TestBlock);
const FinalizationArchive = storage.archive.prunable.Archive(Translator, [32]u8, Finalization);
const Ctx = runtime.deterministic.Context;
const Key = handler.Key(D);
const Fetch = resolver_api.Fetch(Key, handler.Annotation);

/// What the application saw: dispatched heights (acknowledged at once) and tips.
const Recorder = struct {
    heights: std.ArrayList(u64) = .empty,
    tips: std.ArrayList(u64) = .empty,
    fetches: std.ArrayList(Key) = .empty,

    fn deinit(self: *Recorder) void {
        self.heights.deinit(gpa);
        self.tips.deinit(gpa);
        self.fetches.deinit(gpa);
    }
};

const TestApplication = struct {
    pub const Activity = update.Update(TestBlock, Exact);

    recorder: *Recorder,

    pub fn report(self: *TestApplication, activity: Activity) actor_api.Feedback {
        switch (activity) {
            .tip => |tip| self.recorder.tips.append(gpa, tip.height.get()) catch
                @panic("out of memory"),
            .block => |value| {
                var block = value.block;
                defer block.deinit();
                var ack = value.ack;
                self.recorder.heights.append(gpa, block.inner().height().get()) catch
                    @panic("out of memory");
                ack.acknowledge();
            },
        }
        return .ok;
    }
};

const TestResolver = struct {
    pub const Key = handler.Key(D);
    pub const Subscriber = handler.Annotation;
    pub const PublicKey = S.PublicKey;

    recorder: *Recorder,

    pub fn fetch(self: *TestResolver, item: Fetch) Allocator.Error!resolver_api.Feedback {
        return self.fetch_all(&.{item});
    }

    pub fn fetch_all(
        self: *TestResolver,
        items: []const Fetch,
    ) Allocator.Error!resolver_api.Feedback {
        for (items) |item| try self.recorder.fetches.append(gpa, item.key);
        return .ok;
    }

    pub fn fetch_targeted(
        self: *TestResolver,
        item: Fetch,
        _: []const PublicKey,
    ) Allocator.Error!resolver_api.Feedback {
        return self.fetch(item);
    }

    pub fn retain(
        _: *TestResolver,
        _: resolver_api.Predicate(handler.Key(D), handler.Annotation),
    ) Allocator.Error!resolver_api.Feedback {
        return .ok;
    }
};

const Params = struct {
    pub const Scheme = S;
    pub const Provider = cryptography.certificate.ConstantProvider(S);
    pub const Epocher = types.FixedEpocher;
    pub const Strategy = parallel.Sequential;
    pub const ApplicationBlock = TestBlock;
    pub const Block = V.Block;
    pub const Commitment = D;
    pub const Variant = V;
    pub const Acknowledgement = Exact;
    pub const Certificates = store.Certificates(FinalizationArchive, S, D, D);
    pub const Blocks = store.Blocks(BlockArchive, TestBlock);
    pub const Application = TestApplication;
    pub const Buffer = variant.NoBuffer(V, S.PublicKey);
    pub const Resolver = TestResolver;
};
const TestActor = actor.Actor(Params);

fn finalization(
    fixture: *const Fixture,
    round: types.Round,
    parent: u64,
    payload: D,
) !Finalization {
    const proposal = Proposal.init(round, .new(parent), payload);
    var votes: [3]Finalize = undefined;
    for (&votes, fixture.schemes[0..3]) |*vote, *scheme| {
        vote.* = (try Finalize.sign(gpa, scheme, proposal)).?;
    }
    return Finalization.from_votes(gpa, &fixture.verifier, &votes, parallel.sequential);
}

const Archives = struct {
    cache_ref: runtime.buffer.paged.CacheRef,
    blocks: BlockArchive,
    finalizations: FinalizationArchive,

    fn open(self: *Archives, ctx: Ctx, fixture: *const Fixture, comptime prefix: []const u8) !void {
        self.cache_ref = try .init(gpa, 1024, 10);
        errdefer self.cache_ref.deinit();
        self.blocks = try .init(gpa, ctx.storage, ctx.scope.child(prefix ++ "_blocks"), .{
            .translator = .{},
            .metadata_partition = prefix ++ "-blocks-metadata",
            .key_partition = prefix ++ "-blocks-key",
            .key_cache_ref = &self.cache_ref,
            .value_partition = prefix ++ "-blocks-value",
            .codec_config = {},
            .items_per_section = 4,
            .key_write_buffer = 1024,
            .value_write_buffer = 1024,
            .replay_buffer = 1024,
        });
        errdefer self.blocks.deinit();
        const scope = ctx.scope.child(prefix ++ "_finalizations");
        self.finalizations = try .init(gpa, ctx.storage, scope, .{
            .translator = .{},
            .metadata_partition = prefix ++ "-finalizations-metadata",
            .key_partition = prefix ++ "-finalizations-key",
            .key_cache_ref = &self.cache_ref,
            .value_partition = prefix ++ "-finalizations-value",
            .codec_config = fixture.verifier.certificate_codec_config(),
            .items_per_section = 4,
            .key_write_buffer = 1024,
            .value_write_buffer = 1024,
            .replay_buffer = 1024,
        });
    }

    fn deinit(self: *Archives) void {
        self.finalizations.deinit();
        self.blocks.deinit();
        self.cache_ref.deinit();
    }
};

fn config(
    archives: *Archives,
    fixture: *const Fixture,
    genesis: V.Block,
    prefix: []const u8,
) TestActor.Config {
    return .{
        .provider = .init(&fixture.verifier),
        .epocher = .new(utils.NonZero(u64).init(1000).?),
        .start = .{ .genesis = genesis },
        .partition_prefix = prefix,
        .mailbox_size = 16,
        .view_retention = .new(10),
        .prunable_items_per_section = 4,
        .page_cache = &archives.cache_ref,
        .replay_buffer = 1024,
        .key_write_buffer = 1024,
        .value_write_buffer = 1024,
        .block_codec_config = {},
        .max_repair = 4,
        .max_pending_acks = 2,
        .strategy = parallel.sequential,
    };
}

/// One marshal actor with its archives, recorder, and resolver handler.
const Node = struct {
    archives: Archives,
    recorder: Recorder,
    mailbox: TestActor.Mailbox,
    channel: handler.Channel(D),
    handle: runtime.context.Handle(anyerror!void),
    genesis_digest: D,

    /// Opens and starts a node whose partitions start with `prefix`. Must not move.
    fn start(self: *Node, ctx: Ctx, fixture: *const Fixture, comptime prefix: []const u8) !void {
        try self.archives.open(ctx, fixture, prefix);
        errdefer self.archives.deinit();
        self.recorder = .{};
        const genesis = try V.Block.compute(gpa, .init(.empty, .zero(), 0));
        self.genesis_digest = genesis.digest();
        const initialized = try TestActor.init(
            ctx.child(prefix),
            .{ .archive = &self.archives.finalizations },
            .{ .archive = &self.archives.blocks },
            config(&self.archives, fixture, genesis, prefix),
        );
        self.mailbox = initialized.mailbox;
        self.channel = try handler.init(D, gpa, ctx.io(), &ctx.scope, 16);
        self.handle = try initialized.actor.start(
            .{ .recorder = &self.recorder },
            .{ .gpa = gpa },
            self.channel.receiver,
            .{ .recorder = &self.recorder },
        );
    }

    /// Stops the actor by closing its mailbox and handler, then frees the node.
    fn stop(self: *Node) !void {
        self.mailbox.deinit();
        self.channel.handler.deinit();
        const result = self.handle.join();
        self.recorder.deinit();
        self.archives.deinit();
        try try result;
    }

    /// What the actor serves for `key`.
    fn produce(self: *Node, key: Key) ![]const u8 {
        var receiver = try self.channel.handler.produce(key);
        defer receiver.deinit();
        const produced = try receiver.recv();
        return produced.bytes;
    }

    /// Delivers `value` for `key` to the actor's consumer side and returns the outcome.
    fn deliver(
        self: *Node,
        key: Key,
        annotation: handler.Annotation,
        value: []const u8,
    ) !resolver_api.Outcome {
        const Delivery = handler.Message(D).Delivery;
        const delivery: Delivery = .{ .key = key, .subscribers = &.{annotation} };
        var receiver = try self.channel.handler.deliver(delivery, value);
        defer receiver.deinit();
        return receiver.recv();
    }
};

/// A chain of `blocks.len` blocks above the genesis digest `parent`.
fn build_chain(blocks: []V.Block, genesis: D) !void {
    var parent = genesis;
    for (blocks, 1..) |*block, height| {
        block.* = try V.Block.compute(gpa, .init(parent, .new(height), height));
        parent = block.digest();
    }
}

fn round_at(height: u64) types.Round {
    return .new(.zero(), .new(height));
}

/// Verifies and finalizes `blocks[index]` (height `index + 1`) at `node`.
fn finalize_at(node: *Node, fixture: *const Fixture, blocks: []const V.Block, index: usize) !void {
    const height = index + 1;
    try testing.expect(try node.mailbox.verified(round_at(height), blocks[index].clone()));
    var value = try finalization(fixture, round_at(height), height - 1, blocks[index].digest());
    defer value.deinit(gpa);
    _ = node.mailbox.report(.{ .finalization = value });
}

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    try soak.run(gpa, .{}, body, .{});
}

test "finalized blocks reach the application in height order" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try simplex.scheme.ed25519.fixture(D, gpa, &rng, "marshal", 4);
            defer fixture.deinit(gpa);
            var node: Node = undefined;
            try node.start(ctx, &fixture, "node");
            var blocks: [3]V.Block = undefined;
            try build_chain(&blocks, node.genesis_digest);
            defer for (&blocks) |*block| block.deinit();
            // Finalize heights 3, 1, 2 out of order; dispatch stays in height order.
            for ([_]usize{ 2, 0, 1 }) |index| try finalize_at(&node, &fixture, &blocks, index);
            try ctx.sleep(.fromMilliseconds(100));
            try testing.expectEqualSlices(u64, &.{ 0, 1, 2, 3 }, node.recorder.heights.items);
            try testing.expectEqualSlices(u64, &.{3}, node.recorder.tips.items);
            const info = (try node.mailbox.get_info(.latest)).?;
            try testing.expectEqual(3, info.height.get());
            try node.stop();
        }
    }.body);
}

test "a lagging node backfills finalized blocks a peer produces" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try simplex.scheme.ed25519.fixture(D, gpa, &rng, "marshal", 4);
            defer fixture.deinit(gpa);
            var ahead: Node = undefined;
            try ahead.start(ctx, &fixture, "ahead");
            var behind: Node = undefined;
            try behind.start(ctx, &fixture, "behind");
            var blocks: [3]V.Block = undefined;
            try build_chain(&blocks, ahead.genesis_digest);
            defer for (&blocks) |*block| block.deinit();
            for (0..3) |index| try finalize_at(&ahead, &fixture, &blocks, index);
            try ctx.sleep(.fromMilliseconds(50));
            try testing.expectEqualSlices(u64, &.{ 0, 1, 2, 3 }, ahead.recorder.heights.items);

            // The peer serves the finalization and block at height 3.
            const finalized = try ahead.produce(.{ .finalized = .new(3) });
            defer gpa.free(finalized);
            const by_height: handler.Annotation = .{ .finalized = .{ .by_height = .new(3) } };
            const outcome = try behind.deliver(.{ .finalized = .new(3) }, by_height, finalized);
            try testing.expectEqual(resolver_api.Outcome{ .resolved = .complete }, outcome);
            try ctx.sleep(.fromMilliseconds(50));
            // Repair walks back from height 3 and asks for its parent by commitment.
            const parent_key: Key = .{ .block = blocks[1].digest() };
            try testing.expect(fetched(&behind.recorder, parent_key));
            try testing.expectEqualSlices(u64, &.{0}, behind.recorder.heights.items);

            // Serving the missing parents lets the walkback fill the gap and dispatch.
            for ([_]usize{ 1, 0 }) |index| {
                const key: Key = .{ .block = blocks[index].digest() };
                const block = try ahead.produce(key);
                defer gpa.free(block);
                const bound: handler.Annotation = .{ .finalized = .{
                    .by_height = .new(index + 1),
                } };
                const result = try behind.deliver(key, bound, block);
                try testing.expectEqual(resolver_api.Outcome{ .resolved = .complete }, result);
                try ctx.sleep(.fromMilliseconds(20));
            }
            try testing.expectEqualSlices(u64, &.{ 0, 1, 2, 3 }, behind.recorder.heights.items);

            // A finalization signed for another payload fails batch verification.
            var forged = try finalization(&fixture, round_at(3), 2, blocks[0].digest());
            defer forged.deinit(gpa);
            forged.proposal.payload = blocks[2].digest();
            const bytes = try encode_finalized(forged, blocks[2]);
            defer gpa.free(bytes);
            const invalid = try behind.deliver(.{ .finalized = .new(3) }, by_height, bytes);
            try testing.expectEqual(resolver_api.Outcome.invalid, invalid);

            try behind.stop();
            try ahead.stop();
        }
    }.body);
}

fn fetched(recorder: *const Recorder, key: Key) bool {
    for (recorder.fetches.items) |item| if (item.eql(key)) return true;
    return false;
}

fn encode_finalized(value: Finalization, block: V.Block) ![]u8 {
    const size = value.encode_size() + block.encode_size();
    const bytes = try gpa.alloc(u8, size);
    var writer = @import("codec").Writer.init(bytes);
    value.write(&writer);
    block.write(&writer);
    return bytes;
}
