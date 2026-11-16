//! Tests for the marshal mailbox and its overflow policy (commonware `core/mailbox.rs`).

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const utils = @import("utils");
const cryptography = @import("cryptography");
const types = @import("../../types.zig");
const mocks = @import("../mocks/root.zig");
const standard = @import("../standard/root.zig");
const mailbox = @import("mailbox.zig");
const Processed = @import("floor.zig").Processed;

const oneshot = utils.channel.oneshot;
const Height = types.Height;
const Round = types.Round;
const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const Proposal = @import("../../simplex/types.zig").Proposal(D);
const B = mocks.EmptyBlock(Sha256);
const V = standard.Standard(B);
const Key = cryptography.ed25519.PublicKey;
const gpa = testing.allocator;
const io = testing.io;

/// A scheme whose certificates are plain integers: the policy never inspects them.
const PlainScheme = struct {
    pub const Certificate = u64;
    pub const PublicKey = Key;
};
const TestMessage = mailbox.Message(PlainScheme, V);
const TestPending = mailbox.Pending(PlainScheme, V);
const TestMailbox = mailbox.Mailbox(PlainScheme, V);
const Body = TestMessage.Body;

fn public_key(seed: u64) Key {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

fn round(height: u64) Round {
    return .new(.zero(), .new(height));
}

fn raw_block(height: u64) B {
    return B.init(D.empty, .new(height), height);
}

fn block(height: u64) !V.Block {
    return mocks.ready(B, gpa, raw_block(height));
}

fn commitment(height: u64) D {
    return raw_block(height).digest();
}

fn message(body: Body) TestMessage {
    return .{ .gpa = gpa, .body = body };
}

fn finalization(height: u64) TestMessage.Finalization {
    const proposal: Proposal = .init(round(height), .zero(), commitment(height));
    return .{ .proposal = proposal, .certificate = height };
}

/// A request message and the receiver of its response.
fn Request(comptime T: type) type {
    return struct { message: TestMessage, receiver: oneshot.Receiver(T) };
}

fn get_info(height: u64) !Request(?TestMessage.Info) {
    const pair = try oneshot.channel(?TestMessage.Info, gpa, io);
    return .{ .message = message(.{ .get_info = .{
        .identifier = .{ .height = .new(height) },
        .response = pair.sender,
    } }), .receiver = pair.receiver };
}

fn get_block(height: u64) !Request(?V.Block) {
    const pair = try oneshot.channel(?V.Block, gpa, io);
    return .{ .message = message(.{ .get_block = .{
        .identifier = .{ .height = .new(height) },
        .response = pair.sender,
    } }), .receiver = pair.receiver };
}

fn get_finalization(height: u64) !Request(?TestMessage.Finalization) {
    const pair = try oneshot.channel(?TestMessage.Finalization, gpa, io);
    return .{ .message = message(.{ .get_finalization = .{
        .height = .new(height),
        .response = pair.sender,
    } }), .receiver = pair.receiver };
}

fn subscribe_by_digest(height: u64, fallback: mailbox.DigestFallback) !Request(V.Block) {
    const pair = try oneshot.channel(V.Block, gpa, io);
    return .{ .message = message(.{ .subscribe_by_digest = .{
        .digest = commitment(height),
        .fallback = fallback,
        .response = pair.sender,
    } }), .receiver = pair.receiver };
}

fn subscribe_by_commitment(height: u64, fallback: mailbox.CommitmentFallback) !Request(V.Block) {
    const pair = try oneshot.channel(V.Block, gpa, io);
    return .{ .message = message(.{ .subscribe_by_commitment = .{
        .commitment = commitment(height),
        .fallback = fallback,
        .response = pair.sender,
    } }), .receiver = pair.receiver };
}

/// A `proposed`, `verified`, or `certified` message at `height` and the receiver of its ack.
fn durable(comptime kind: std.meta.Tag(Body), height: u64) !Request(void) {
    const pair = try oneshot.channel(void, gpa, io);
    const owned = try block(height);
    const body: Body = switch (kind) {
        .proposed => .{ .proposed = .{
            .round = round(height),
            .block = owned,
            .recipients = .all,
            .ack = pair.sender,
        } },
        .verified, .certified => @unionInit(Body, @tagName(kind), .{
            .round = round(height),
            .block = owned,
            .ack = pair.sender,
        }),
        else => comptime unreachable,
    };
    return .{ .message = message(body), .receiver = pair.receiver };
}

fn hint_finalized(height: u64, target: Key) !TestMessage {
    const targets = try gpa.dupe(Key, &.{target});
    return message(.{ .hint_finalized = .{ .height = .new(height), .targets = targets } });
}

fn hint_notarized(height: u64) TestMessage {
    return message(.{ .hint_notarized = .{
        .round = round(height),
        .commitment = commitment(height),
    } });
}

fn set_floor(height: u64) TestMessage {
    return message(.{ .set_floor = finalization(height) });
}

fn prune(height: u64) TestMessage {
    return message(.{ .prune = .new(height) });
}

fn handle(overflow: *TestPending, value: TestMessage) !void {
    try TestMessage.handle(gpa, overflow, value);
}

fn push_back(overflow: *TestPending, value: TestMessage) !void {
    try overflow.messages.pushBack(gpa, .{ .message = value });
}

/// Accepts every drained message.
const Collector = struct {
    items: std.ArrayList(TestMessage),

    fn init() !Collector {
        return .{ .items = try .initCapacity(gpa, 16) };
    }

    pub fn push(self: *Collector, value: TestMessage) ?TestMessage {
        self.items.appendAssumeCapacity(value);
        return null;
    }

    fn deinit(self: *Collector) void {
        for (self.items.items) |value| TestMessage.discard(value);
        self.items.deinit(gpa);
    }
};

fn drain(overflow: *TestPending) !Collector {
    var collector: Collector = try .init();
    overflow.drain(&collector);
    return collector;
}

/// Whether a queued message with an open responder matches `predicate`.
fn has_open(overflow: *const TestPending, context: anytype) bool {
    for (0..overflow.messages.len) |index| {
        const entry = overflow.messages.atPtr(index);
        if (entry.* != .message) continue;
        const queued = &entry.message;
        if (!queued.response_closed() and context.matches(queued)) return true;
    }
    return false;
}

const HeightRead = struct {
    tag: std.meta.Tag(Body),
    height: u64,

    fn matches(self: HeightRead, queued: *const TestMessage) bool {
        if (std.meta.activeTag(queued.body) != self.tag) return false;
        return switch (queued.body) {
            inline .get_info, .get_block => |body| body.identifier == .height and
                body.identifier.height.get() == self.height,
            .get_finalization => |body| body.height.get() == self.height,
            else => false,
        };
    }
};

fn has_read(overflow: *const TestPending, tag: std.meta.Tag(Body), height: u64) bool {
    return has_open(overflow, HeightRead{ .tag = tag, .height = height });
}

const Subscription = struct {
    height: u64,

    fn matches(self: Subscription, queued: *const TestMessage) bool {
        return switch (queued.body) {
            .subscribe_by_digest => |body| body.digest.eql(commitment(self.height)),
            .subscribe_by_commitment => |body| body.commitment.eql(commitment(self.height)),
            else => false,
        };
    }
};

fn has_subscription(overflow: *const TestPending, height: u64) bool {
    return has_open(overflow, Subscription{ .height = height });
}

fn has_block_message(overflow: *const TestPending, height: u64) bool {
    for (0..overflow.messages.len) |index| {
        const entry = overflow.messages.atPtr(index);
        if (entry.* != .message) continue;
        switch (entry.message.body) {
            inline .proposed, .verified, .certified => |body| {
                if (body.block.inner().height().get() == height) return true;
            },
            else => {},
        }
    }
    return false;
}

fn contains(targets: []const Key, target: Key) bool {
    for (targets) |candidate| {
        if (candidate.eql(target)) return true;
    }
    return false;
}

fn expect_read(drained: TestMessage, tag: std.meta.Tag(Body), height: u64) !void {
    try testing.expect((HeightRead{ .tag = tag, .height = height }).matches(&drained));
}

fn expect_floor(drained: TestMessage, height: u64) !void {
    try testing.expect(drained.body == .set_floor);
    try testing.expectEqual(round(height), drained.body.set_floor.round());
}

fn expect_prune(drained: TestMessage, height: u64) !void {
    try testing.expect(drained.body == .prune);
    try testing.expectEqual(height, drained.body.prune.get());
}

test "durable methods report failure when mailbox closed" {
    var pair = try actor.mailbox.new(TestMessage, gpa, io, 1);
    var closed: TestMailbox = .init(gpa, io, pair.sender, 1);
    defer closed.deinit();
    pair.receiver.deinit();

    var ack = try oneshot.channel(void, gpa, io);
    defer ack.receiver.deinit();
    try testing.expectEqual(.closed, try closed.proposed(round(1), try block(1), .all, ack.sender));
    try testing.expectError(error.Closed, ack.receiver.recv());
    try testing.expect(!try closed.verified(round(2), try block(2)));
    try testing.expect(!try closed.certified(round(3), try block(3)));
    // Requests to a closed mailbox read as missing.
    try testing.expectEqual(null, try closed.get_processed());
    try testing.expectEqual(null, try closed.get_block(.latest));
}

test "policy coalesces hint targets" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    const first = public_key(1);
    const second = public_key(2);

    try handle(&overflow, try hint_finalized(10, first));
    try handle(&overflow, try hint_finalized(10, first));
    try handle(&overflow, try hint_finalized(10, second));

    try testing.expectEqual(1, overflow.messages.len);
    const targets = overflow.hint_targets(.new(10)).?;
    try testing.expectEqual(2, targets.len);
    try testing.expect(contains(targets, first));
    try testing.expect(contains(targets, second));
}

test "policy preserves commitment subscription fallbacks" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    var wait = try subscribe_by_commitment(1, .wait);
    defer wait.receiver.deinit();
    var by_round = try subscribe_by_commitment(2, .{ .fetch_by_round = round(2) });
    defer by_round.receiver.deinit();
    var by_commitment = try subscribe_by_commitment(3, .{ .fetch_by_commitment = .new(3) });
    defer by_commitment.receiver.deinit();

    try handle(&overflow, wait.message);
    try handle(&overflow, by_round.message);
    try handle(&overflow, by_commitment.message);

    var drained = try drain(&overflow);
    defer drained.deinit();
    const items = drained.items.items;
    try testing.expectEqual(3, items.len);
    try testing.expect(items[0].body.subscribe_by_commitment.fallback == .wait);
    const second = items[1].body.subscribe_by_commitment.fallback;
    try testing.expectEqual(round(2), second.fetch_by_round);
    const third = items[2].body.subscribe_by_commitment.fallback;
    try testing.expectEqual(3, third.fetch_by_commitment.get());
}

test "policy handles closed subscriptions" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);

    var pending_closed = try subscribe_by_digest(1, .{ .fetch_by_round = round(1) });
    pending_closed.receiver.deinit();
    try push_back(&overflow, pending_closed.message);
    var pending_open = try subscribe_by_commitment(2, .{ .fetch_by_round = round(2) });
    defer pending_open.receiver.deinit();
    try push_back(&overflow, pending_open.message);
    var current_closed = try subscribe_by_digest(3, .{ .fetch_by_round = round(3) });
    current_closed.receiver.deinit();
    try handle(&overflow, current_closed.message);

    try testing.expect(!has_subscription(&overflow, 1));
    try testing.expect(has_subscription(&overflow, 2));
    try testing.expect(!has_subscription(&overflow, 3));
    try testing.expectError(error.Empty, pending_open.receiver.try_recv());
}

test "policy handles closed responses" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);

    var pending_closed = try get_block(1);
    pending_closed.receiver.deinit();
    try push_back(&overflow, pending_closed.message);
    var pending_open = try get_info(2);
    defer pending_open.receiver.deinit();
    try push_back(&overflow, pending_open.message);
    var current_closed = try get_finalization(3);
    current_closed.receiver.deinit();
    try handle(&overflow, current_closed.message);

    try testing.expect(!has_read(&overflow, .get_block, 1));
    try testing.expect(has_read(&overflow, .get_info, 2));
    try testing.expect(!has_read(&overflow, .get_finalization, 3));
    try testing.expectError(error.Empty, pending_open.receiver.try_recv());
}

/// Refuses every message, closing a receiver on the first attempt.
const Refuser = struct {
    attempts: u32 = 0,
    receiver: ?*oneshot.Receiver(?V.Block),

    pub fn push(self: *Refuser, value: TestMessage) ?TestMessage {
        self.attempts += 1;
        if (self.receiver) |receiver| receiver.deinit();
        self.receiver = null;
        return value;
    }
};

test "policy drain stops after returned response closes" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    var first = try get_block(1);
    var second = try get_info(2);
    defer second.receiver.deinit();
    try push_back(&overflow, first.message);
    try push_back(&overflow, second.message);

    var refuser: Refuser = .{ .receiver = &first.receiver };
    overflow.drain(&refuser);
    try testing.expectEqual(1, refuser.attempts);

    var drained = try drain(&overflow);
    defer drained.deinit();
    try testing.expectEqual(1, drained.items.items.len);
    const only = drained.items.items[0];
    try expect_read(only, .get_info, 2);
    try testing.expect(!only.response_closed());
    try testing.expectError(error.Empty, second.receiver.try_recv());
}

test "policy drains fifo" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    const first = public_key(1);
    const second = public_key(2);
    var subscribe = try subscribe_by_digest(1, .wait);
    defer subscribe.receiver.deinit();
    var processed = try oneshot.channel(?Processed, gpa, io);
    defer processed.receiver.deinit();

    try handle(&overflow, subscribe.message);
    try handle(&overflow, try hint_finalized(10, first));
    try handle(&overflow, hint_notarized(1));
    try handle(&overflow, try hint_finalized(10, second));
    try handle(&overflow, message(.{ .get_processed = .{ .response = processed.sender } }));

    var drained = try drain(&overflow);
    defer drained.deinit();
    const items = drained.items.items;
    try testing.expectEqual(4, items.len);
    const subscribed = items[0].body.subscribe_by_digest;
    try testing.expect(subscribed.digest.eql(commitment(1)));
    try testing.expect(subscribed.fallback == .wait);
    const hint = items[1].body.hint_finalized;
    try testing.expectEqual(10, hint.height.get());
    try testing.expectEqual(2, hint.targets.len);
    try testing.expect(contains(hint.targets, first));
    try testing.expect(contains(hint.targets, second));
    try testing.expectEqual(round(1), items[2].body.hint_notarized.round);
    try testing.expect(items[3].body == .get_processed);
}

test "policy keeps highest floor and prune" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);

    try handle(&overflow, set_floor(5));
    try handle(&overflow, set_floor(3));
    try handle(&overflow, set_floor(8));
    try handle(&overflow, prune(4));
    try handle(&overflow, prune(2));
    try handle(&overflow, prune(7));

    try testing.expectEqual(round(8), overflow.floor.?.body.set_floor.round());
    try testing.expectEqual(7, overflow.height().?.get());
    try testing.expectEqual(0, overflow.messages.len);

    var drained = try drain(&overflow);
    defer drained.deinit();
    try testing.expectEqual(2, drained.items.items.len);
    try expect_floor(drained.items.items[0], 8);
    try expect_prune(drained.items.items[1], 7);
}

test "policy replaces floor and drops stale pending on drain" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    overflow.floor = set_floor(5);
    var info_4 = try get_info(4);
    defer info_4.receiver.deinit();
    var block_7 = try get_block(7);
    defer block_7.receiver.deinit();
    var block_8 = try get_block(8);
    defer block_8.receiver.deinit();
    try push_back(&overflow, info_4.message);
    try push_back(&overflow, block_7.message);
    try handle(&overflow, try hint_finalized(8, public_key(1)));
    try push_back(&overflow, block_8.message);
    try handle(&overflow, set_floor(8));
    try handle(&overflow, prune(8));

    try testing.expectEqual(round(8), overflow.floor.?.body.set_floor.round());
    try testing.expectEqual(1, overflow.messages.len);
    try testing.expect(!has_read(&overflow, .get_info, 4));
    try testing.expect(!has_read(&overflow, .get_block, 7));
    try testing.expect(has_read(&overflow, .get_block, 8));
    try testing.expectEqual(null, overflow.hint_targets(.new(8)));

    var drained = try drain(&overflow);
    defer drained.deinit();
    try testing.expectEqual(3, drained.items.items.len);
    try expect_floor(drained.items.items[0], 8);
    try expect_prune(drained.items.items[1], 8);
    try expect_read(drained.items.items[2], .get_block, 8);
}

test "policy replaces prune and drops stale pending on drain" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    overflow.prune = prune(5);
    var finalization_4 = try get_finalization(4);
    defer finalization_4.receiver.deinit();
    var block_6 = try get_block(6);
    defer block_6.receiver.deinit();
    var block_7 = try get_block(7);
    defer block_7.receiver.deinit();
    try push_back(&overflow, finalization_4.message);
    try push_back(&overflow, block_6.message);
    try handle(&overflow, try hint_finalized(6, public_key(2)));
    try push_back(&overflow, block_7.message);
    try handle(&overflow, prune(7));

    try testing.expectEqual(7, overflow.height().?.get());
    try testing.expectEqual(1, overflow.messages.len);
    try testing.expect(!has_read(&overflow, .get_finalization, 4));
    try testing.expect(!has_read(&overflow, .get_block, 6));
    try testing.expect(has_read(&overflow, .get_block, 7));
    try testing.expectEqual(null, overflow.hint_targets(.new(6)));

    var drained = try drain(&overflow);
    defer drained.deinit();
    try testing.expectEqual(2, drained.items.items.len);
    try expect_prune(drained.items.items[0], 7);
    try expect_read(drained.items.items[1], .get_block, 7);
}

fn expect_prune_drops_closed(comptime tag: std.meta.Tag(Body)) !void {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    const make = if (tag == .get_block) get_block else get_finalization;
    var closed = try make(8);
    closed.receiver.deinit();
    var open = try make(8);
    defer open.receiver.deinit();
    try push_back(&overflow, closed.message);
    try push_back(&overflow, open.message);

    try handle(&overflow, prune(7));
    try testing.expectEqual(1, overflow.messages.len);
    try testing.expect(has_read(&overflow, tag, 8));
    try testing.expectError(error.Empty, open.receiver.try_recv());
}

test "policy prune drops closed pending" {
    try expect_prune_drops_closed(.get_block);
    try expect_prune_drops_closed(.get_finalization);
}

test "policy skips retain when prune height does not increase" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    try handle(&overflow, prune(10));
    var closed = try get_block(11);
    closed.receiver.deinit();
    try push_back(&overflow, closed.message);

    try handle(&overflow, set_floor(9));
    try testing.expectEqual(1, overflow.messages.len);
    try handle(&overflow, prune(9));
    try testing.expectEqual(1, overflow.messages.len);
    try handle(&overflow, prune(12));
    try testing.expectEqual(0, overflow.messages.len);
}

test "policy drops stale requests against pending floor and prune" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    var infos: [4]Request(?TestMessage.Info) = undefined;
    for (&infos, 4..) |*request, height| request.* = try get_info(height);
    defer for (&infos) |*request| request.receiver.deinit();
    var blocks: [4]Request(?V.Block) = undefined;
    for (&blocks, 4..) |*request, height| request.* = try get_block(height);
    defer for (&blocks) |*request| request.receiver.deinit();
    var finalization_4 = try get_finalization(4);
    defer finalization_4.receiver.deinit();
    var finalization_6 = try get_finalization(6);
    defer finalization_6.receiver.deinit();

    try handle(&overflow, set_floor(5));
    try handle(&overflow, infos[0].message);
    try handle(&overflow, infos[1].message);
    try handle(&overflow, blocks[0].message);
    try handle(&overflow, blocks[1].message);
    try handle(&overflow, finalization_4.message);
    try handle(&overflow, try hint_finalized(5, public_key(1)));
    try handle(&overflow, try hint_finalized(6, public_key(2)));

    try handle(&overflow, prune(7));
    try testing.expectEqual(7, overflow.height().?.get());
    try handle(&overflow, infos[2].message);
    try handle(&overflow, finalization_6.message);
    try testing.expect(!has_read(&overflow, .get_finalization, 6));
    try handle(&overflow, blocks[2].message);
    try handle(&overflow, infos[3].message);
    try testing.expect(has_read(&overflow, .get_info, 7));
    try handle(&overflow, blocks[3].message);
    try testing.expect(has_read(&overflow, .get_block, 7));

    var drained = try drain(&overflow);
    defer drained.deinit();
    const items = drained.items.items;
    try testing.expectEqual(4, items.len);
    try expect_floor(items[0], 5);
    try expect_prune(items[1], 7);
    try expect_read(items[2], .get_info, 7);
    try expect_read(items[3], .get_block, 7);
}

test "policy keeps block messages and waiters" {
    var overflow: TestPending = .empty;
    defer overflow.deinit(gpa);
    var proposed = try durable(.proposed, 4);
    defer proposed.receiver.deinit();
    var verified = try durable(.verified, 6);
    defer verified.receiver.deinit();
    var certified = try durable(.certified, 8);
    defer certified.receiver.deinit();
    try push_back(&overflow, proposed.message);
    try push_back(&overflow, verified.message);
    try push_back(&overflow, certified.message);

    try handle(&overflow, set_floor(7));
    try testing.expect(has_block_message(&overflow, 4));
    try testing.expect(has_block_message(&overflow, 6));
    try testing.expect(has_block_message(&overflow, 8));
    try testing.expectError(error.Empty, proposed.receiver.try_recv());
    try testing.expectError(error.Empty, verified.receiver.try_recv());
    try testing.expectError(error.Empty, certified.receiver.try_recv());

    try handle(&overflow, prune(9));
    try testing.expect(has_block_message(&overflow, 8));
    try testing.expectError(error.Empty, certified.receiver.try_recv());

    var stale = try durable(.proposed, 8);
    defer stale.receiver.deinit();
    try handle(&overflow, stale.message);
    try testing.expect(has_block_message(&overflow, 8));
    try testing.expectError(error.Empty, stale.receiver.try_recv());

    var current = try durable(.verified, 9);
    defer current.receiver.deinit();
    try handle(&overflow, current.message);
    try testing.expect(has_block_message(&overflow, 9));
    try testing.expectError(error.Empty, current.receiver.try_recv());

    var drained = try drain(&overflow);
    defer drained.deinit();
    try testing.expect(drained.items.items[0].body == .set_floor);
    try testing.expect(drained.items.items[1].body == .prune);
}

const simplex = @import("../../simplex/root.zig");
const Ed25519 = simplex.scheme.ed25519.Scheme(D);
const Ed25519Mailbox = mailbox.Mailbox(Ed25519, V);
const Ed25519Message = mailbox.Message(Ed25519, V);

test "report forwards copies of certificates and ignores votes" {
    const types_simplex = simplex.types;
    const Notarize = types_simplex.Notarize(Ed25519, D);
    var rng = utils.rng.test_rng();
    var fixture = try simplex.scheme.ed25519.fixture(D, gpa, &rng, "marshal", 4);
    defer fixture.deinit(gpa);
    const proposal: Proposal = .init(round(3), .zero(), commitment(3));
    var notarizes: [3]Notarize = undefined;
    for (&notarizes, fixture.schemes[0..3]) |*notarize, *scheme| {
        notarize.* = (try Notarize.sign(gpa, scheme, proposal)).?;
    }
    const sequential = @import("parallel").sequential;
    var notarization = try types_simplex.Notarization(Ed25519, D).from_votes(
        gpa,
        &fixture.verifier,
        &notarizes,
        sequential,
    );
    defer notarization.deinit(gpa);

    var pair = try actor.mailbox.new(Ed25519Message, gpa, io, 4);
    defer pair.receiver.deinit();
    var reporter: Ed25519Mailbox = .init(gpa, io, pair.sender, 1);
    defer reporter.deinit();
    try testing.expectEqual(.ok, reporter.report(.{ .notarize = notarizes[0] }));
    try testing.expectEqual(.ok, reporter.report(.{ .notarization = notarization }));
    try testing.expectEqual(.ok, reporter.report(.{ .certification = notarization }));

    const expected = [_]std.meta.Tag(Ed25519Message.Body){ .notarization, .certification };
    for (expected) |tag| {
        const received = try pair.receiver.try_recv();
        defer Ed25519Message.discard(received);
        try testing.expectEqual(tag, std.meta.activeTag(received.body));
        const forwarded = switch (received.body) {
            .notarization, .certification => |value| value,
            else => unreachable,
        };
        try testing.expect(forwarded.eql(notarization));
        // A copy: the reporter's caller keeps its certificate.
        try testing.expect(forwarded.certificate.signatures.ptr !=
            notarization.certificate.signatures.ptr);
    }
    try testing.expectError(error.Empty, pair.receiver.try_recv());
}
