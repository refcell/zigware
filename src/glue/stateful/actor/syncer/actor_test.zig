//! commonware `glue/src/stateful/actor/syncer/actor.rs` tests, on a mock marshal (the start
//! block `resolve` picks in each marshal state) and commonware's wedged database set.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const consensus = @import("consensus");
const runtime = @import("runtime");
const utils = @import("utils");
const actor_mod = @import("actor.zig");
const state_sync = @import("../../db/state_sync.zig");
const db_sync = @import("../../db/sync.zig");

const gpa = testing.allocator;
const oneshot = utils.channel.oneshot;
const ring = utils.channel.ring;
const Height = consensus.Height;
const Round = consensus.Round;
const core = consensus.marshal.core;
const Digest = [32]u8;
const Anchor = db_sync.Anchor(Digest);

const Block = struct {
    pub const Digest = [32]u8;
    number: u64,
    /// Distinguishes two blocks at one height.
    fork: u8 = 0,

    pub fn digest(self: *const Block) [32]u8 {
        var bytes: [32]u8 = @splat(self.fork);
        std.mem.writeInt(u64, bytes[0..8], self.number, .big);
        return bytes;
    }

    pub fn height(self: *const Block) Height {
        return .new(self.number);
    }

    pub fn context(self: *const Block) struct { round: Round } {
        return .{ .round = .new(.zero(), .new(self.number)) };
    }
};

const Finalization = struct {
    view: u64,
    proposal: struct { payload: Digest },

    pub fn round(self: *const Finalization) Round {
        return .new(.zero(), .new(self.view));
    }

    fn of(block: Block) Finalization {
        return .{ .view = block.number, .proposal = .{ .payload = block.digest() } };
    }
};

/// A marshal holding `blocks` by height, processed at `processed`, delivering
/// `subscribed` to a commitment subscription.
const MockMarshal = struct {
    blocks: []const Block,
    processed: ?core.Processed,
    subscribed: ?Block = null,
    io: Io = testing.io,

    pub const Anchored = struct { processed: core.Processed, block: Block };

    pub fn get_anchor(self: MockMarshal) !?Anchored {
        const processed = self.processed orelse return null;
        const block = (try self.get_block(.{ .height = processed.anchor() })).?;
        return .{ .processed = processed, .block = block };
    }

    pub fn get_block(self: MockMarshal, identifier: core.Identifier(Digest)) !?Block {
        for (self.blocks) |block| {
            if (block.number == identifier.height.get()) return block;
        }
        return null;
    }

    pub fn subscribe_by_commitment(
        self: MockMarshal,
        _: Digest,
        _: core.CommitmentFallback,
    ) !oneshot.Receiver(Block) {
        var pair = try oneshot.channel(Block, gpa, self.io);
        if (self.subscribed) |block| try pair.sender.send(block) else pair.sender.deinit();
        return pair.receiver;
    }
};

/// commonware's `WedgeSet`: its sync holds the tip receiver without draining it, then
/// completes once every other task parked, dropping a forwarded update still queued.
const WedgeSet = struct {
    value: u64,
    pub const Config = u64;
    pub const SyncTargets = u64;

    pub fn open(_: anytype, config: u64, expected: u64) !WedgeSet {
        try testing.expectEqual(config, expected);
        return .{ .value = config };
    }

    pub fn deinit(_: *WedgeSet) void {}

    pub fn sync(
        comptime D: type,
        env: anytype,
        _: u64,
        _: anytype,
        anchor: db_sync.Anchor(D),
        _: u64,
        tip_updates: ring.Receiver(db_sync.TipUpdate(D, u64)),
        _: state_sync.SyncEngineConfig,
    ) !state_sync.SetSynced(WedgeSet, D) {
        var tips = tip_updates;
        defer tips.deinit();
        try env.io.sleep(.fromSeconds(1), .awake);
        return .{ .databases = .{ .value = 0 }, .anchor = anchor };
    }
};

const P = struct {
    pub const App = struct {
        pub const Block = actor_mod_Block;
        pub fn sync_targets(block: *const actor_mod_Block) u64 {
            return block.number;
        }
    };
    pub const Databases = WedgeSet;
    pub const Resolvers = void;
    pub const Marshal = MockMarshal;
    pub const Finalization = actor_mod_Finalization;
    pub fn commitment(block: *const actor_mod_Block) Digest {
        return block.digest();
    }
};
const actor_mod_Block = Block;
const actor_mod_Finalization = Finalization;

const Env = struct { gpa: std.mem.Allocator, io: Io };
const TestSyncer = actor_mod.Syncer(P, Env);

fn chain(comptime count: u64) [count]Block {
    var blocks: [count]Block = undefined;
    for (&blocks, 0..) |*block, i| block.* = .{ .number = i };
    return blocks;
}

fn resolved(marshal: MockMarshal, floor: core.Floor, selected: Block) !u64 {
    const finalization = Finalization.of(selected);
    const block = try actor_mod.resolve(P, gpa, marshal, floor, &finalization);
    return block.number;
}

test "stateful syncer: resolve covers durable marshal progress" {
    const blocks = chain(2);
    // Marshal processed past the selected floor, whose round its cutoff covers.
    const marshal: MockMarshal = .{ .blocks = &blocks, .processed = .{ .block = .new(1) } };
    const floor = core.Floor.init(.{ .block = .new(1) }, .{ .round = .new(.zero(), .new(1)) });
    try testing.expectEqual(@as(u64, 1), try resolved(marshal, floor, blocks[0]));
}

test "stateful syncer: resolve selects only the matching retained successor" {
    const blocks = chain(5);
    const cases = [_][3]u64{ .{ 3, 3, 3 }, .{ 4, 4, 4 }, .{ 4, 3, 3 }, .{ 4, 2, 3 } };
    for (cases) |case| {
        const height, const selected, const expected = case;
        // Processed through the floor's predecessor; the floor block is retained above it.
        const processed = core.Processed{ .block = .new(height - 1) };
        const marshal: MockMarshal = .{ .blocks = blocks[0 .. height + 1], .processed = processed };
        const floor = core.Floor.init(processed, .{ .round = .new(.zero(), .new(height)) });
        try testing.expectEqual(expected, try resolved(marshal, floor, blocks[selected]));
    }
    // A retained successor that is another fork is not the selected floor.
    const forked = [_]Block{ blocks[0], blocks[1], .{ .number = 2, .fork = 9 } };
    const processed = core.Processed{ .block = .new(1) };
    const marshal: MockMarshal = .{ .blocks = &forked, .processed = processed };
    const floor = core.Floor.init(processed, .{ .round = .new(.zero(), .new(2)) });
    try testing.expectEqual(@as(u64, 1), try resolved(marshal, floor, blocks[2]));
}

test "stateful syncer: resolve waits for the floor block after startup" {
    const blocks = chain(5);
    // The cutoff does not cover the floor's round: the subscribed floor block is the start,
    // unless marshal has since processed past it.
    const floor = core.Floor.init(null, .zero());
    var marshal: MockMarshal = .{ .blocks = &blocks, .processed = null, .subscribed = blocks[2] };
    try testing.expectEqual(@as(u64, 2), try resolved(marshal, floor, blocks[2]));
    marshal.processed = .{ .block = .new(1) };
    try testing.expectEqual(@as(u64, 2), try resolved(marshal, floor, blocks[2]));
    marshal.processed = .{ .block = .new(3) };
    try testing.expectEqual(@as(u64, 3), try resolved(marshal, floor, blocks[2]));
    // Processed but absent at the floor's height does not pass it.
    marshal.processed = .{ .absent = .new(2) };
    try testing.expectEqual(@as(u64, 2), try resolved(marshal, floor, blocks[2]));
    // A floor installed at 4 leaves 3 processed but absent: its anchor is the floor block.
    marshal.processed = .{ .absent = .new(3) };
    try testing.expectEqual(@as(u64, 4), try resolved(marshal, floor, blocks[2]));
    marshal.subscribed = null;
    marshal.processed = null;
    try testing.expectError(error.BlockUnavailable, resolved(marshal, floor, blocks[2]));
}

test "stateful syncer: open uses the later of completion and marshal progress" {
    const blocks = chain(6);
    const env: Env = .{ .gpa = gpa, .io = testing.io };
    var marshal: MockMarshal = .{ .blocks = &blocks, .processed = .{ .block = .new(3) } };
    // Each `open` checks the set opens at its anchor block's targets.
    const at_processed = try actor_mod.open(P, env, marshal, 3, .new(2));
    try testing.expectEqual(@as(u64, 3), at_processed.anchor.height.get());
    const at_completed = try actor_mod.open(P, env, marshal, 5, .new(5));
    try testing.expectEqual(@as(u64, 5), at_completed.anchor.height.get());
    marshal.processed = null;
    const at_genesis = try actor_mod.open(P, env, marshal, 0, null);
    try testing.expectEqual(@as(u64, 0), at_genesis.anchor.height.get());
    try testing.expectError(error.BlockUnavailable, actor_mod.open(P, env, marshal, 9, .new(9)));
}

fn retarget(mailbox: TestSyncer.Mailbox) TestSyncer.Mailbox.Error!?TestSyncer.Artifact {
    var owned = mailbox;
    defer owned.deinit();
    const anchor: Anchor = .{
        .height = .new(1),
        .round = .new(.zero(), .new(1)),
        .digest = @splat(1),
    };
    return owned.retarget(anchor, 1);
}

fn stranded(io: Io) !void {
    const blocks = chain(1);
    const finalization = Finalization.of(blocks[0]);
    var completion = try oneshot.channel(TestSyncer.Artifact, gpa, io);
    defer completion.receiver.deinit();
    const created = try TestSyncer.create(.{
        .env = .{ .gpa = gpa, .io = io },
        .db_config = 0,
        .sync_config = .{
            .fetch_batch_size = 1,
            .apply_batch_size = 1,
            .max_outstanding_requests = 1,
        },
        .resolvers = {},
        .finalization = &finalization,
        .marshal = .{ .blocks = &blocks, .processed = null, .subscribed = blocks[0], .io = io },
        .floor = .init(null, .zero()),
        .completion = completion.sender,
    });
    var task = try created.syncer.start();
    // The update is forwarded into the ring and its observation parks before the sync
    // completes; the stranded observation resolves through a retry returning the artifact.
    var update = try io.concurrent(retarget, .{created.mailbox});
    const result = (try update.await(io)) orelse return error.TestExpectedArtifact;
    try testing.expectEqual(@as(u64, 0), result.anchor.height.get());
    const artifact = try completion.receiver.recv();
    try testing.expectEqual(@as(u64, 0), artifact.anchor.height.get());
    try task.await(io);
}

test "stateful syncer: a stranded tip update resolves to the artifact" {
    const timeout_ns = 10 * std.time.ns_per_s;
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .timeout_ns = timeout_ns });
    defer runner.deinit();
    try try runner.start(stranded, .{runner.io()});
}
