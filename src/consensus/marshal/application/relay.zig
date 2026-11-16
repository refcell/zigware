//! Consensus-relay plumbing shared by marshal's application wrappers (commonware
//! `marshal/application/relay.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const actor = @import("actor");
const p2p = @import("p2p");
const simplex = @import("../../simplex/root.zig");
const gates = @import("gates.zig");
const core_mailbox = @import("../core/mailbox.zig");

/// Relays a consensus broadcast `plan` through `marshal` for a proposal staged in `registry`.
///
/// A prepare plan sends the staged candidate to all peers, at most once, and keeps it staged
/// without storing it. A propose plan locks the staged proposal in: it sends the proposal to
/// all peers unless a prepare plan already did, and persists it either way, acknowledging
/// through the staged ack. A forward plan re-sends a stored block to the plan's recipients
/// (borrowed; marshal gets a copy).
///
/// A propose plan that finds nothing staged sends nothing. Certification claims our own
/// proposal only after a notarization, which needs our vote, and consensus casts that vote only
/// after the propose plan. Within a process, a proposal is therefore missing only when its
/// round is decided, and a prepare plan may already have sent the block. Prepare and propose
/// plans send nothing for a round at or below the decided cutoff of the gates.
pub fn broadcast(
    comptime S: type,
    comptime V: type,
    registry: gates.Gates(V.Commitment, V),
    marshal: core_mailbox.Mailbox(S, V),
    commitment: V.Commitment,
    plan: simplex.Plan(S.PublicKey),
) Allocator.Error!actor.Feedback {
    switch (plan) {
        .prepare => |prepare| {
            const block = try registry.send_staged(prepare.round, commitment) orelse return .ok;
            return marshal.prepared(prepare.round, block, .all);
        },
        .propose => |propose| {
            const taken = try registry.take_staged(propose.round, commitment) orelse return .ok;
            const staged, const sent = taken;
            if (sent) {
                try marshal.verified_deferred(propose.round, staged.block, staged.ack);
                return .ok;
            }
            return marshal.proposed(propose.round, staged.block, .all, staged.ack);
        },
        .forward => |forward| {
            const recipients = try copy_recipients(S.PublicKey, marshal.gpa, forward.recipients);
            return marshal.forward(forward.round, commitment, recipients);
        },
    }
}

/// An owned copy of `recipients` (a `some` slice is duplicated).
fn copy_recipients(
    comptime P: type,
    gpa: Allocator,
    recipients: p2p.Recipients(P),
) Allocator.Error!p2p.Recipients(P) {
    return switch (recipients) {
        .all, .one => recipients,
        .some => |peers| .{ .some = try gpa.dupe(P, peers) },
    };
}

const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const cryptography = @import("cryptography");
const types = @import("../../types.zig");
const mocks = @import("../mocks/root.zig");
const standard = @import("../standard/root.zig");

const oneshot = utils.channel.oneshot;
const Round = types.Round;
const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const B = mocks.EmptyBlock(Sha256);
const TestVariant = standard.Standard(B);
const Key = cryptography.ed25519.PublicKey;
const test_gpa = testing.allocator;

const PlainScheme = struct {
    pub const Certificate = u64;
    pub const PublicKey = Key;
};
const TestGates = gates.Gates(D, TestVariant);
const TestMailbox = core_mailbox.Mailbox(PlainScheme, TestVariant);
const TestMessage = TestMailbox.M;
const Tag = std.meta.Tag(TestMessage.Body);

fn round(view: u64) Round {
    return .new(.zero(), .new(view));
}

fn raw_block(view: u64) B {
    return B.init(D.empty, .new(view), view);
}

/// Publishes the staged digest once.
const Publisher = struct {
    sender: ?oneshot.Sender(D),

    pub fn call(self: *Publisher, digest: D) void {
        if (self.sender) |*sender| sender.send(digest) catch {};
        self.sender = null;
    }
};

fn stage_task(registry: TestGates, view: u64, published: oneshot.Sender(D)) anyerror!void {
    var owned = registry;
    defer owned.deinit();
    var publisher: Publisher = .{ .sender = published };
    defer if (publisher.sender) |*sender| sender.deinit();
    const block = try mocks.ready(B, test_gpa, raw_block(view));
    try owned.stage(round(view), block.digest(), block, &publisher, "test");
}

/// Stages the block at `view` in a task, returning once its digest is published.
fn spawn_stage(io: Io, registry: TestGates, view: u64) !Io.Future(anyerror!void) {
    var published = try oneshot.channel(D, test_gpa, io);
    defer published.receiver.deinit();
    var future = try io.concurrent(stage_task, .{ registry.clone(), view, published.sender });
    errdefer future.cancel(io) catch {};
    const digest = try published.receiver.recv();
    try testing.expect(digest.eql(raw_block(view).digest()));
    return future;
}

/// Receives the next message, checks its kind and round, and hands it back.
fn expect_message(
    receiver: *actor.mailbox.Receiver(TestMessage),
    tag: Tag,
    view: u64,
) !TestMessage {
    const received = try receiver.try_recv();
    errdefer TestMessage.discard(received);
    try testing.expectEqual(tag, std.meta.activeTag(received.body));
    const at: Round = switch (received.body) {
        inline .prepared, .proposed, .verified, .forward => |body| body.round,
        else => unreachable,
    };
    try testing.expectEqual(round(view), at);
    return received;
}

fn relay(
    registry: TestGates,
    marshal: TestMailbox,
    commitment: D,
    plan: simplex.Plan(Key),
) !actor.Feedback {
    return broadcast(PlainScheme, TestVariant, registry, marshal, commitment, plan);
}

fn relay_body(io: Io) anyerror!void {
    var registry: TestGates = try .init(test_gpa, io);
    defer registry.deinit();
    var pair = try actor.mailbox.new(TestMessage, test_gpa, io, 8);
    defer pair.receiver.deinit();
    var marshal: TestMailbox = .init(test_gpa, io, pair.sender, 1);
    defer marshal.deinit();
    const Plan = simplex.Plan(Key);

    // A prepared candidate is sent once, then persisted (not resent) when proposed.
    var first = try spawn_stage(io, registry, 1);
    const digest_1 = raw_block(1).digest();
    const prepare: Plan = .{ .prepare = .{ .round = round(1) } };
    try testing.expectEqual(.ok, try relay(registry, marshal, digest_1, prepare));
    TestMessage.discard(try expect_message(&pair.receiver, .prepared, 1));
    try testing.expectEqual(.ok, try relay(registry, marshal, digest_1, prepare));
    try testing.expectError(error.Empty, pair.receiver.try_recv());
    const propose_1: Plan = .{ .propose = .{ .round = round(1) } };
    _ = try relay(registry, marshal, digest_1, propose_1);
    var verified = try expect_message(&pair.receiver, .verified, 1);
    try verified.body.verified.ack.send({});
    verified.body.verified.ack = undefined;
    TestVariant.deinit_block(test_gpa, &verified.body.verified.block);
    try first.await(io);
    // Nothing is staged any more.
    _ = try relay(registry, marshal, digest_1, propose_1);
    try testing.expectError(error.Empty, pair.receiver.try_recv());

    // An unsent proposal is sent and persisted together.
    var second = try spawn_stage(io, registry, 2);
    const digest_2 = raw_block(2).digest();
    const propose_2: Plan = .{ .propose = .{ .round = round(2) } };
    _ = try relay(registry, marshal, digest_2, propose_2);
    var proposed = try expect_message(&pair.receiver, .proposed, 2);
    try testing.expect(proposed.body.proposed.recipients == .all);
    try proposed.body.proposed.ack.send({});
    TestVariant.deinit_block(test_gpa, &proposed.body.proposed.block);
    try second.await(io);

    // A forward copies the plan's recipients.
    const peers = [_]Key{cryptography.ed25519.PrivateKey.from_seed(1).public_key()};
    const forward: Plan = .{ .forward = .{ .round = round(3), .recipients = .{ .some = &peers } } };
    _ = try relay(registry, marshal, digest_2, forward);
    const forwarded = try expect_message(&pair.receiver, .forward, 3);
    defer TestMessage.discard(forwarded);
    const sent_to = forwarded.body.forward.recipients.some;
    try testing.expect(sent_to.ptr != &peers);
    try testing.expect(sent_to[0].eql(peers[0]));
}

test "relay prepares once, persists on propose, and forwards copies" {
    var runner = try runtime.deterministic.Runner.init(test_gpa, .{ .seed = 0 });
    defer runner.deinit();
    try (try runner.start(relay_body, .{runner.io()}));
}
