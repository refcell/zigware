//! Tests for standard verification (commonware `marshal/standard/validation.rs` tests).

const std = @import("std");
const testing = std.testing;
const broadcast = @import("broadcast");
const codec = @import("codec");
const cryptography = @import("cryptography");
const types = @import("../../types.zig");
const validation = @import("validation.zig");

const Sha256 = cryptography.Sha256;
const Height = types.Height;
const gpa = testing.allocator;

/// A block whose digest is a field, so tests can break linkage without rehashing.
const TestBlock = struct {
    digest_value: Sha256.Digest,
    parent_value: Sha256.Digest,
    height_value: Height,

    pub const Digest = Sha256.Digest;

    pub fn digest(self: TestBlock) Sha256.Digest {
        return self.digest_value;
    }

    pub fn parent(self: TestBlock) Sha256.Digest {
        return self.parent_value;
    }

    pub fn height(self: TestBlock) Height {
        return self.height_value;
    }

    pub fn write(self: TestBlock, writer: *codec.Writer) void {
        self.digest_value.write(writer);
        self.parent_value.write(writer);
        self.height_value.write(writer);
    }

    pub fn read(allocator: std.mem.Allocator, reader: *codec.Reader, _: void) !TestBlock {
        return .{
            .digest_value = try Sha256.Digest.read(allocator, reader, {}),
            .parent_value = try Sha256.Digest.read(allocator, reader, {}),
            .height_value = try Height.read(allocator, reader, {}),
        };
    }
};

const Ready = broadcast.Digested(TestBlock);

fn hash(text: []const u8) Sha256.Digest {
    return Sha256.hash(&.{text});
}

/// A parent at height 6 and its child at height 7.
fn baseline() struct { TestBlock, TestBlock } {
    const parent: TestBlock = .{
        .digest_value = hash("parent"),
        .parent_value = hash("grandparent"),
        .height_value = .new(6),
    };
    const block: TestBlock = .{
        .digest_value = hash("block"),
        .parent_value = parent.digest_value,
        .height_value = .new(7),
    };
    return .{ parent, block };
}

fn ready(block: TestBlock) !Ready {
    return Ready.precomputed(gpa, block, block.digest());
}

fn expect_validation(
    expected: validation.Error!void,
    parent: TestBlock,
    block: TestBlock,
    parent_digest: ?Sha256.Digest,
) !void {
    var parent_ready = try ready(parent);
    defer parent_ready.deinit();
    var block_ready = try ready(block);
    defer block_ready.deinit();
    const expected_parent = parent_digest orelse parent_ready.digest();
    const result = validation.validate_block(&block_ready, &parent_ready, expected_parent);
    try testing.expectEqual(expected, result);
}

test "a child one height above its expected parent is valid" {
    // commonware `test_validate_block_ok`.
    const parent, const block = baseline();
    try expect_validation({}, parent, block, null);
}

test "a block naming another parent fails" {
    // commonware `test_validate_block_parent_digest_error`.
    const parent, var block = baseline();
    block.parent_value = hash("wrong_parent");
    try expect_validation(error.ParentDigest, parent, block, null);
}

test "a parent other than the expected one fails" {
    // commonware `test_validate_block_expected_parent_digest_error`.
    const parent, const block = baseline();
    try expect_validation(error.ExpectedParentDigest, parent, block, hash("wrong_expected_parent"));
}

test "a block not one height above its parent fails" {
    // commonware `test_validate_block_height_error`.
    const parent, var block = baseline();
    block.height_value = .new(9);
    try expect_validation(error.Height, parent, block, null);
}

const runtime = @import("runtime");
const utils = @import("utils");
const simplex_types = @import("../../simplex/types.zig");
const soak = @import("../mocks/soak.zig");
const oneshot = utils.channel.oneshot;
const Io = std.Io;
const PublicKey = cryptography.ed25519.PublicKey;
const Context = simplex_types.Context(Sha256.Digest, PublicKey);
const Decision = validation.Decision(Ready);

/// Epochs of 10 heights: epoch 0 ends at height 9.
const epocher: types.FixedEpocher = .new(utils.NonZero(u64).init(10).?);

/// Records `verified` calls and answers with `accept` (marshal gone when false).
const FakeMarshal = struct {
    verified_round: ?types.Round = null,
    accept: bool = true,

    pub fn verified(self: *FakeMarshal, round: types.Round, block: Ready) !bool {
        var owned = block;
        owned.deinit();
        self.verified_round = round;
        return self.accept;
    }
};

fn context_at(epoch: u64, parent_digest: Sha256.Digest) Context {
    return .{
        .round = .new(.new(epoch), .new(5)),
        .leader = cryptography.ed25519.PrivateKey.from_seed(0).public_key(),
        .parent = .{ .new(4), parent_digest },
    };
}

fn at_height(height: u64) TestBlock {
    _, var block = baseline();
    block.height_value = .new(height);
    return block;
}

/// Runs the precheck on `block`, freeing a continued block; returns the decision's verdict
/// (null when it continues) and whether marshal saw a verified block.
fn precheck(context: Context, block: TestBlock, accept: bool) !struct { ?bool, bool, bool } {
    var marshal: FakeMarshal = .{ .accept = accept };
    const decision = try validation.precheck_epoch_and_reproposal(
        epocher,
        &marshal,
        context,
        block.digest(),
        try ready(block),
    ) orelse return .{ null, marshal.verified_round != null, true };
    return switch (decision) {
        .complete => |valid| .{ valid, marshal.verified_round != null, false },
        .@"continue" => |continued| {
            var owned = continued;
            owned.deinit();
            return .{ null, marshal.verified_round != null, false };
        },
    };
}

test "the precheck rejects a block outside the context's epoch" {
    const block = at_height(7);
    const result = try precheck(context_at(1, block.parent_value), block, true);
    try testing.expectEqual(@as(?bool, false), result[0]);
    try testing.expect(!result[1]);
}

test "the precheck continues an ordinary proposal" {
    const block = at_height(7);
    const result = try precheck(context_at(0, block.parent_value), block, true);
    try testing.expectEqual(@as(?bool, null), result[0]);
    try testing.expect(!result[1] and !result[2]);
}

test "a re-proposal is valid only at the epoch boundary, once marshal stores it" {
    const inside = at_height(7);
    const early = try precheck(context_at(0, inside.digest()), inside, true);
    try testing.expectEqual(@as(?bool, false), early[0]);
    try testing.expect(!early[1]);
    const boundary = at_height(9);
    const valid = try precheck(context_at(0, boundary.digest()), boundary, true);
    try testing.expectEqual(@as(?bool, true), valid[0]);
    try testing.expect(valid[1]);
    // Marshal gone: no verdict.
    const gone = try precheck(context_at(0, boundary.digest()), boundary, false);
    try testing.expect(gone[2] and gone[1]);
}

/// Awaits a parent that `deliver` sends (or drops), under a verdict channel whose receiver
/// is closed first when `consensus_gone`.
fn await_parent(io: Io, deliver: ?TestBlock, consensus_gone: bool) !?bool {
    const parent, const block = baseline();
    var block_ready = try ready(block);
    defer block_ready.deinit();
    var verdict = try oneshot.channel(bool, gpa, io);
    defer verdict.sender.deinit();
    if (consensus_gone) verdict.receiver.deinit();
    defer if (!consensus_gone) verdict.receiver.deinit();
    var request = try oneshot.channel(Ready, gpa, io);
    defer request.receiver.deinit();
    if (consensus_gone) {
        request.sender.deinit();
    } else if (deliver) |sent| {
        request.sender.send(try ready(sent)) catch unreachable;
    } else {
        request.sender.deinit();
    }
    const check = try validation.await_and_validate_parent(
        bool,
        io,
        parent.digest(),
        &block_ready,
        &request.receiver,
        &verdict.sender,
    ) orelse return null;
    return switch (check) {
        .valid => |owned| {
            var valid = owned;
            defer valid.deinit();
            try testing.expect(valid.digest().eql(parent.digest()));
            return true;
        },
        .invalid => false,
    };
}

fn parent_checks(io: Io) !void {
    const parent, _ = baseline();
    try testing.expectEqual(@as(?bool, true), try await_parent(io, parent, false));
    var unrelated = parent;
    unrelated.digest_value = hash("unrelated");
    try testing.expectEqual(@as(?bool, false), try await_parent(io, unrelated, false));
    try testing.expectEqual(@as(?bool, null), try await_parent(io, null, false));
    try testing.expectEqual(@as(?bool, null), try await_parent(io, null, true));
}

test "the parent wait validates linkage and stops when either side goes away" {
    try soak.run_io(gpa, .{ .seed = 0 }, parent_checks);
}

const actor = @import("actor");
const mocks = @import("../mocks/root.zig");
const standard = @import("root.zig");
const mailbox_mod = @import("../core/mailbox.zig");
const Ctx = runtime.deterministic.Context;
const EmptyBlock = mocks.EmptyBlock(Sha256);
const V = standard.Standard(EmptyBlock);

/// A scheme whose certificates are plain integers; verification never inspects them.
const PlainScheme = struct {
    pub const Certificate = u64;
    pub const PublicKey = cryptography.ed25519.PublicKey;
};
const TestMailbox = mailbox_mod.Mailbox(PlainScheme, V);
const Stream = @typeInfo(@TypeOf(TestMailbox.ancestor_stream)).@"fn".return_type.?;
const AncestorStream = @typeInfo(Stream).error_union.payload;

/// Verifies with `verdict` after recording the ancestry's first two heights, or waits an
/// hour first when `stall` is set.
const VerifyApp = struct {
    verdict: bool,
    stall: bool = false,
    heights: [2]u64 = .{ 0, 0 },

    pub fn verify(self: *VerifyApp, ctx: Ctx, _: Context, ancestry: AncestorStream) !bool {
        var stream = ancestry;
        defer stream.deinit();
        for (&self.heights) |*height| {
            var block = (try stream.next()) orelse return error.TestUnexpectedResult;
            defer block.deinit();
            height.* = block.inner().height().get();
        }
        if (self.stall) try ctx.io().sleep(.fromSeconds(3_600), .awake);
        return self.verdict;
    }
};

/// Runs `run_app_verify` for a block at height 2 on its parent at height 1 through a closed
/// mailbox (the stream never fetches); drops the verdict receiver first when `consensus_gone`.
fn app_verify(ctx: Ctx, app: *VerifyApp, consensus_gone: bool) !?bool {
    const io = ctx.io();
    var pair = try actor.mailbox.new(TestMailbox.M, gpa, io, 1);
    var marshal: TestMailbox = .init(gpa, io, pair.sender, 1);
    defer marshal.deinit();
    pair.receiver.deinit();
    const parent_block = EmptyBlock.init(Sha256.Digest.empty, .new(1), 1);
    const parent = try mocks.ready(EmptyBlock, gpa, parent_block);
    const child = mocks.ready(EmptyBlock, gpa, .init(parent_block.digest(), .new(2), 2)) catch |err|
        {
            var owned = parent;
            owned.deinit();
            return err;
        };
    var verdict = try oneshot.channel(bool, gpa, io);
    defer verdict.sender.deinit();
    if (consensus_gone) verdict.receiver.deinit();
    defer if (!consensus_gone) verdict.receiver.deinit();
    const context = context_at(0, parent_block.digest());
    const sender = &verdict.sender;
    return validation.run_app_verify(bool, ctx, context, child, parent, app, marshal, sender, null);
}

fn app_verify_cases(ctx: Ctx) !void {
    var accept: VerifyApp = .{ .verdict = true };
    try testing.expectEqual(@as(?bool, true), try app_verify(ctx, &accept, false));
    // The ancestry starts at the block under verification, then its parent.
    try testing.expectEqual([2]u64{ 2, 1 }, accept.heights);
    var reject: VerifyApp = .{ .verdict = false };
    try testing.expectEqual(@as(?bool, false), try app_verify(ctx, &reject, false));
    // Consensus dropping the receiver stops a stalled verification.
    var stalled: VerifyApp = .{ .verdict = true, .stall = true };
    try testing.expectEqual(@as(?bool, null), try app_verify(ctx, &stalled, true));
}

test "application verification runs over the block and its parent" {
    try soak.run(gpa, .{ .seed = 0 }, app_verify_cases, .{});
}
