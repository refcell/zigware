//! Actor-level tests of commonware's `glue::dkg::reshare::actor` (`inclusion.rs`'s
//! `mod tests`), driven through the actor's mailbox. Commonware's `should_panic` cases check
//! the actor's `ContractError`s here.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const mocks = @import("../../tests/mocks.zig");
const Fence = @import("../../fence.zig").Fence;
const actor_mod = @import("actor.zig");

const Epoch = consensus.Epoch;
const Exact = utils.acknowledgement.Exact;
const Set = utils.ordered.Set(mocks.TestPublicKey);
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const metrics = runtime.telemetry.metrics;
const TestActor = actor_mod.Actor(mocks.ActorTypes);
const Digested = TestActor.Digested;
const gpa = testing.allocator;
const namespace = "_COMMONWARE_GLUE_DKG_RESHARE_INCLUSION_TEST";

/// Owns everything a singleton actor test keeps alive (commonware `InclusionHarness`).
pub const Harness = struct {
    io: Io,
    store_harness: mocks.StoreHarness,
    secrets: mocks.MemorySecretStore,
    store: TestActor.Store,
    consumer: mocks.MockConsumer,
    provider: mocks.StaticParticipants,
    manager: mocks.InertManager = .{},
    blocker: mocks.MockBlocker,
    fence: Fence,
    registry: metrics.Registry,
    actor: TestActor,
    mailbox: TestActor.Mailbox,
    public_key: mocks.TestPublicKey,

    pub fn init(self: *Harness, io: Io, partition: []const u8, blocks_per_epoch: u64) !void {
        const signer = mocks.TestSigner.from_seed(0);
        self.io = io;
        self.public_key = signer.public_key();
        self.store_harness = try .init(gpa);
        self.secrets = .init(gpa);
        self.store = try self.store_harness.open(gpa, partition, &self.secrets);
        self.consumer = .init(gpa);
        self.provider = .{ .participants_value = try Set.from_dedup(gpa, &.{self.public_key}) };
        self.manager = .{};
        self.blocker = .init(gpa);
        self.fence = Fence.init(io);
        self.registry = .init(gpa);
        const scope = metrics.Scope.init(&self.registry).child("reshare");
        self.actor, self.mailbox = try TestActor.init(gpa, io, &scope, .{
            .signer = signer,
            .manager = &self.manager,
            .blocker = &self.blocker,
            .participants_provider = &self.provider,
            .strategy = .{},
            .registrar = &self.consumer,
            .marshal = .{},
            .fence = &self.fence,
            .namespace = namespace,
            .sharing_mode = .non_zero_counter,
            .reveal = .v1,
            .mailbox_size = 16,
            .max_participants = 16,
            .blocks_per_epoch = blocks_per_epoch,
        });
    }

    pub fn deinit(self: *Harness) void {
        self.mailbox.deinit();
        self.actor.deinit();
        self.registry.deinit();
        self.fence.close();
        self.blocker.deinit();
        self.provider.participants_value.deinit(gpa);
        self.consumer.deinit();
        self.store.deinit();
        self.secrets.deinit();
        self.store_harness.deinit();
    }

    /// Reports a finalized block (a new handle) and returns its acknowledgement's waiter.
    pub fn deliver(self: *Harness, block: *const Digested) !Exact.Waiter {
        const handle = try Exact.handle(gpa, self.io);
        const Update = consensus.marshal.Update(mocks.TestBlock, Exact);
        const ack = handle.acknowledgement;
        const update: Update = .{ .block = .{ .block = block.clone(), .ack = ack } };
        _ = try self.mailbox.report(update);
        return handle.waiter;
    }

    /// The chain genesis, child, child, ... of `len` blocks led by this node.
    pub fn chain(self: *Harness, blocks: []Digested) !void {
        var raw = mocks.genesis_block(self.public_key);
        for (blocks) |*block| {
            block.* = try Digested.precomputed(gpa, raw, raw.digest());
            raw = mocks.child(&raw);
        }
    }

    /// Epoch `epoch`'s info over this node alone, with a trusted output dealt from seed zero.
    pub fn singleton_info(self: *Harness, epoch: u64) !TestActor.Info {
        var rng = utils.rng.TestRng.init(0);
        const participants = try Set.from_dedup(gpa, &.{self.public_key});
        const V = mocks.TestBlsVariant;
        const P = mocks.TestPublicKey;
        var dealt = try fd.deal(V, P, utils.N3f1, gpa, &rng, .non_zero_counter, participants);
        for (dealt.shares.values) |*share| share.private.zeroize();
        dealt.shares.deinit(gpa);
        return .{
            .outcome = .success,
            .epoch = .new(epoch),
            .output = dealt.output,
            .players = try dealt.output.players.clone(gpa),
            .next_players = try dealt.output.players.clone(gpa),
            .directory = .{},
        };
    }

    /// The canonical child of `parent` carrying `info` (copied).
    pub fn boundary(self: *Harness, parent: *const Digested, info: TestActor.Info) !Digested {
        _ = self;
        const raw = try mocks.child(parent.inner()).with_payload(gpa, 16, .{ .epoch_info = info });
        return Digested.precomputed(gpa, raw, raw.digest());
    }
};

fn free_blocks(blocks: []Digested) void {
    for (blocks) |*block| block.deinit();
}

/// Expects every waiter acknowledged, then releases them.
fn expect_acknowledged(waiters: []Exact.Waiter) !void {
    for (waiters) |*waiter| {
        defer waiter.deinit();
        try (waiter.poll() orelse return error.Unacknowledged);
    }
}

fn run(comptime body: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try (try runner.start(body, .{runner.io()}));
}

// commonware `follower_boundary_redelivery_is_acknowledged` (the follow and setup half; the
// next epoch's dealing lands with the dealing window): a follower covers the boundary it
// commits, so setup resumes in the next epoch.
test "actor: a follower commits the boundary and setup resumes after it" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "follower-redelivery", 4);
            defer h.deinit();
            var blocks: [4]Digested = undefined;
            try h.chain(blocks[0..3]);
            var next = try h.singleton_info(1);
            defer next.deinit(gpa);
            blocks[3] = try h.boundary(&blocks[2], next);
            defer free_blocks(&blocks);

            // Following acknowledges a repeated block and commits epoch one at the boundary.
            var waiters: [5]Exact.Waiter = undefined;
            for (&waiters, [_]usize{ 0, 1, 1, 2, 3 }) |*waiter, index| {
                waiter.* = try h.deliver(&blocks[index]);
            }
            try testing.expectEqual(.proceed, try h.actor.follow(&h.store));
            try expect_acknowledged(&waiters);
            try testing.expectEqual(@as(u64, 1), h.store.current_info().?.epoch.get());
            try testing.expectEqualSlices(u64, &.{1}, h.consumer.entered.items);

            // Setup resumes at the first height after the covered boundary.
            var prepared = switch (try h.actor.setup_epoch(&h.store, null)) {
                .participate => |value| value,
                .follow => return error.ExpectedParticipation,
            };
            defer prepared.deinit(gpa);
            try testing.expectEqual(@as(u64, 1), prepared.epoch.get());
            try testing.expectEqual(.early, prepared.phase);
            try testing.expect(prepared.player != null);
        }
    }.body);
}

// commonware `follower_wrong_epoch_info_panics`: info for an epoch other than the next is a
// contract violation, so nothing is committed, registered, or fenced.
test "actor: a follower rejects epoch info for the wrong epoch" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "follower-wrong-epoch", 4);
            defer h.deinit();
            var blocks: [4]Digested = undefined;
            try h.chain(blocks[0..3]);
            var wrong = try h.singleton_info(2);
            defer wrong.deinit(gpa);
            blocks[3] = try h.boundary(&blocks[2], wrong);
            defer free_blocks(&blocks);
            var waiters: [4]Exact.Waiter = undefined;
            for (&waiters, 0..) |*waiter, index| waiter.* = try h.deliver(&blocks[index]);
            defer for (&waiters) |*waiter| waiter.deinit();
            try testing.expectError(error.WrongEpochInfo, h.actor.follow(&h.store));
            try testing.expect(h.store.current_info() == null);
            try testing.expectEqual(@as(usize, 0), h.consumer.entered.items.len);
        }
    }.body);
}

/// Follows `blocks[0..prefix]`, then delivers `bad` and expects `expected`.
fn expect_follow_rejects(
    io: Io,
    partition: []const u8,
    prefix: usize,
    bad: mocks.TestBlock,
    expected: anyerror,
) !void {
    var h: Harness = undefined;
    try h.init(io, partition, 8);
    defer h.deinit();
    var blocks: [4]Digested = undefined;
    try h.chain(&blocks);
    defer free_blocks(&blocks);
    var waiters: [5]Exact.Waiter = undefined;
    for (waiters[0..prefix], 0..) |*waiter, index| waiter.* = try h.deliver(&blocks[index]);
    var bad_block = try Digested.precomputed(gpa, bad, bad.digest());
    defer bad_block.deinit();
    waiters[prefix] = try h.deliver(&bad_block);
    defer for (waiters[0 .. prefix + 1]) |*waiter| waiter.deinit();
    try testing.expectError(expected, h.actor.follow(&h.store));
}

// commonware `conflicting_redelivery_panics`, `skipped_inclusion_height_panics`, and
// `unlinked_inclusion_successor_panics`, checked through the follower: a finalized block that
// conflicts with the applied tip, skips a height, or does not extend the tip is rejected.
test "actor: finalized blocks must extend the applied tip" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            const leader = mocks.TestSigner.from_seed(0).public_key();
            const genesis = mocks.genesis_block(leader);
            const canonical = mocks.child(&genesis);
            const second = mocks.child(&canonical);
            const context = genesis.context();
            const late = std.math.maxInt(u64);
            const sibling = mocks.TestBlock.init(context, genesis.digest(), .new(1), late);
            try testing.expect(!sibling.digest().eql(canonical.digest()));
            const conflicting = error.ConflictingFinalizedBlock;
            try expect_follow_rejects(io, "conflicting", 2, sibling, conflicting);
            const skipping = mocks.child(&mocks.child(&second));
            try expect_follow_rejects(io, "skipped", 2, skipping, error.SkippedFinalizedHeight);
            const unlinked = mocks.TestBlock.init(context, canonical.digest(), .new(3), late);
            try expect_follow_rejects(io, "unlinked", 3, unlinked, error.UnlinkedFinalizedBlock);
        }
    }.body);
}
