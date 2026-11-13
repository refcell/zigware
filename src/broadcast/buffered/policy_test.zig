//! Overflow policy tests, ported from commonware `broadcast/src/buffered/mod.rs`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const cryptography = @import("cryptography");
const broadcast_digested = @import("../digested.zig");
const p2p = @import("p2p");
const utils = @import("utils");

const ingress = @import("ingress.zig");
const TestMessage = @import("mocks.zig").TestMessage;

const Key = cryptography.ed25519.PublicKey;
const Msg = ingress.Message(Key, TestMessage);
const Overflow = Msg.Overflow;
const Item = broadcast_digested.Digested(TestMessage);
const Digest = TestMessage.Digest;
const oneshot = utils.channel.oneshot;
const gpa = testing.allocator;

fn key(seed: u64) Key {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

fn digest_of(content: []const u8) Digest {
    return cryptography.Sha256.hash(&.{content});
}

fn item(content: []const u8) !Item {
    return Item.compute(gpa, try TestMessage.shared(gpa, content));
}

/// Collects drained messages; returns the `reject_at`-th one (counting from 1) back.
const Collector = struct {
    drained: std.ArrayList(Msg) = .empty,
    reject_at: ?usize = null,
    attempts: usize = 0,
    /// Dropped when the first message is pushed (closing its responder's receiver).
    drop_on_push: ?*oneshot.Receiver(ingress.GetResult(TestMessage)) = null,

    pub fn push(collector: *Collector, message: Msg) ?Msg {
        collector.attempts += 1;
        if (collector.drop_on_push) |receiver| {
            receiver.deinit();
            collector.drop_on_push = null;
            return message;
        }
        if (collector.reject_at == collector.attempts) return message;
        collector.drained.append(gpa, message) catch @panic("out of memory");
        return null;
    }

    fn deinit(collector: *Collector) void {
        for (collector.drained.items) |message| Msg.discard(message);
        collector.drained.deinit(gpa);
    }
};

fn handle(overflow: *Overflow, message: Msg) !void {
    try Msg.handle(gpa, overflow, message);
}

fn subscribe(overflow: *Overflow, digest: Digest) !oneshot.Receiver(Item) {
    const pair = try oneshot.channel(Item, gpa, testing.io);
    try handle(overflow, .{ .subscribe = .{ .digest = digest, .responder = pair.sender } });
    return pair.receiver;
}

fn get(overflow: *Overflow, digest: Digest) !oneshot.Receiver(ingress.GetResult(TestMessage)) {
    const pair = try oneshot.channel(ingress.GetResult(TestMessage), gpa, testing.io);
    try handle(overflow, .{ .get = .{ .digest = digest, .responder = pair.sender } });
    return pair.receiver;
}

fn broadcast(overflow: *Overflow, recipients: p2p.Recipients(Key), message: Item) !void {
    const owned: p2p.Recipients(Key) = switch (recipients) {
        .some => |peers| .{ .some = try gpa.dupe(Key, peers) },
        else => recipients,
    };
    try handle(overflow, .{ .broadcast = .{
        .gpa = gpa,
        .recipients = owned,
        .message = message.clone(),
    } });
}

fn drain_all(overflow: *Overflow, collector: *Collector) void {
    overflow.drain(collector);
}

fn expect_some(recipients: p2p.Recipients(Key), expected: []const Key) !void {
    try testing.expect(recipients == .some);
    try testing.expectEqual(expected.len, recipients.some.len);
    for (expected, recipients.some) |want, got| try testing.expect(want.eql(got));
}

test "policy handles closed responders" {
    var overflow: Overflow = .empty;
    defer overflow.deinit(gpa);
    var closed_subscribe = try subscribe(&overflow, digest_of("pending_subscribe"));
    closed_subscribe.deinit();
    var open_subscribe = try subscribe(&overflow, digest_of("open_subscribe"));
    defer open_subscribe.deinit();
    var closed_get = try get(&overflow, digest_of("pending_get"));
    closed_get.deinit();
    var open_get = try get(&overflow, digest_of("open_get"));
    defer open_get.deinit();
    // A request whose receiver is already gone is not queued at all.
    const pair = try oneshot.channel(ingress.GetResult(TestMessage), gpa, testing.io);
    var current = pair.receiver;
    current.deinit();
    const digest = digest_of("current_get");
    try handle(&overflow, .{ .get = .{ .digest = digest, .responder = pair.sender } });
    try testing.expectEqual(@as(usize, 4), overflow.queue.len);

    var collector: Collector = .{};
    defer collector.deinit();
    drain_all(&overflow, &collector);
    try testing.expectEqual(@as(usize, 2), collector.drained.items.len);
    const first = collector.drained.items[0];
    try testing.expect(first == .subscribe);
    try testing.expect(first.subscribe.digest.eql(digest_of("open_subscribe")));
    try testing.expect(!first.subscribe.responder.is_closed());
    const second = collector.drained.items[1];
    try testing.expect(second == .get);
    try testing.expect(second.get.digest.eql(digest_of("open_get")));
    try testing.expect(!second.get.responder.is_closed());
}

test "policy coalesces duplicate broadcasts and merges recipients" {
    var message = try item("duplicate broadcast");
    defer message.deinit();
    const first = key(1);
    const second = key(2);
    var overflow: Overflow = .empty;
    defer overflow.deinit(gpa);
    for (0..1_000) |_| try broadcast(&overflow, .{ .one = first }, message);
    try broadcast(&overflow, .{ .some = &.{second} }, message);

    // Draining yields one broadcast with each recipient exactly once.
    var collector: Collector = .{};
    defer collector.deinit();
    drain_all(&overflow, &collector);
    try testing.expectEqual(@as(usize, 1), collector.drained.items.len);
    const drained = collector.drained.items[0];
    try testing.expect(drained == .broadcast);
    var sorted = [_]Key{ first, second };
    std.sort.pdq(Key, &sorted, {}, Key.less_than);
    try expect_some(drained.broadcast.recipients, &sorted);

    // Repeated broadcasts to all peers coalesce into one broadcast to all peers.
    var all_overflow: Overflow = .empty;
    defer all_overflow.deinit(gpa);
    for (0..1_000) |_| try broadcast(&all_overflow, .all, message);
    var all_collector: Collector = .{};
    defer all_collector.deinit();
    drain_all(&all_overflow, &all_collector);
    try testing.expectEqual(@as(usize, 1), all_collector.drained.items.len);
    try testing.expect(all_collector.drained.items[0].broadcast.recipients == .all);
}

test "policy coalesces at first broadcast position" {
    var message = try item("first position");
    defer message.deinit();
    const first = key(1);
    const second = key(2);
    var overflow: Overflow = .empty;
    defer overflow.deinit(gpa);
    try broadcast(&overflow, .{ .one = first }, message);
    var receiver = try get(&overflow, digest_of("unrelated get"));
    defer receiver.deinit();
    try broadcast(&overflow, .{ .one = second }, message);

    // The merged broadcast drains before the get.
    var collector: Collector = .{};
    defer collector.deinit();
    drain_all(&overflow, &collector);
    try testing.expectEqual(@as(usize, 2), collector.drained.items.len);
    try testing.expect(collector.drained.items[0] == .broadcast);
    var sorted = [_]Key{ first, second };
    std.sort.pdq(Key, &sorted, {}, Key.less_than);
    try expect_some(collector.drained.items[0].broadcast.recipients, &sorted);
    try testing.expect(collector.drained.items[1] == .get);
}

/// A message that counts how often its digest is computed.
const CountingMessage = struct {
    value: u64,
    calls: *u32,

    pub const Digest = cryptography.Sha256.Digest;

    pub fn digest(message: *const CountingMessage) CountingMessage.Digest {
        message.calls.* += 1;
        const bytes = std.mem.toBytes(std.mem.nativeToBig(u64, message.value));
        return cryptography.Sha256.hash(&.{&bytes});
    }
};

test "policy reuses carried digests of overflow broadcasts" {
    const messages = 1_000;
    const Counting = ingress.Message(Key, CountingMessage);
    const CountingItem = broadcast_digested.Digested(CountingMessage);
    var calls: u32 = 0;
    var overflow: Counting.Overflow = .empty;
    defer overflow.deinit(gpa);
    // Supply digests directly so fixture construction does not count.
    for (0..messages) |value| {
        const bytes = std.mem.toBytes(std.mem.nativeToBig(u64, value));
        const digest = cryptography.Sha256.hash(&.{&bytes});
        const message: CountingMessage = .{ .value = value, .calls = &calls };
        const carried = try CountingItem.precomputed(gpa, message, digest);
        try Counting.handle(gpa, &overflow, .{ .broadcast = .{
            .gpa = gpa,
            .recipients = .{ .one = key(1) },
            .message = carried,
        } });
    }
    // Every broadcast drains without recomputing a digest.
    const Counter = struct {
        drained: usize = 0,
        pub fn push(counter: *@This(), message: Counting) ?Counting {
            counter.drained += 1;
            Counting.discard(message);
            return null;
        }
    };
    var counter: Counter = .{};
    overflow.drain(&counter);
    try testing.expectEqual(@as(usize, messages), counter.drained);
    try testing.expectEqual(@as(u32, 0), calls);
}

test "rejected broadcast remains indexed for coalescing" {
    var message = try item("rejected broadcast");
    defer message.deinit();
    const first = key(1);
    const second = key(2);
    var overflow: Overflow = .empty;
    defer overflow.deinit(gpa);
    try broadcast(&overflow, .{ .one = first }, message);

    // Simulate a full mailbox, then extend the rejected broadcast's recipients.
    var rejecting: Collector = .{ .reject_at = 1 };
    defer rejecting.deinit();
    drain_all(&overflow, &rejecting);
    try testing.expectEqual(@as(usize, 0), rejecting.drained.items.len);
    try broadcast(&overflow, .{ .one = second }, message);

    // Accepting the drain yields one broadcast addressed to both peers.
    var collector: Collector = .{};
    defer collector.deinit();
    drain_all(&overflow, &collector);
    try testing.expectEqual(@as(usize, 1), collector.drained.items.len);
    var sorted = [_]Key{ first, second };
    std.sort.pdq(Key, &sorted, {}, Key.less_than);
    try expect_some(collector.drained.items[0].broadcast.recipients, &sorted);
}

test "policy drain continues until rejected message" {
    var overflow: Overflow = .empty;
    defer overflow.deinit(gpa);
    var closed = try subscribe(&overflow, digest_of("closed"));
    closed.deinit();
    var first = try get(&overflow, digest_of("first"));
    defer first.deinit();
    var second = try get(&overflow, digest_of("second"));
    defer second.deinit();
    var third = try get(&overflow, digest_of("third"));
    defer third.deinit();

    // The third push is rejected: the closed request is skipped, two drain, one stays.
    var collector: Collector = .{ .reject_at = 3 };
    defer collector.deinit();
    drain_all(&overflow, &collector);
    try testing.expectEqual(@as(usize, 2), collector.drained.items.len);
    try testing.expect(collector.drained.items[0].get.digest.eql(digest_of("first")));
    try testing.expect(collector.drained.items[1].get.digest.eql(digest_of("second")));
    for (collector.drained.items) |message| {
        try testing.expect(!message.get.responder.is_closed());
    }

    collector.reject_at = null;
    drain_all(&overflow, &collector);
    try testing.expectEqual(@as(usize, 3), collector.drained.items.len);
    try testing.expect(collector.drained.items[2].get.digest.eql(digest_of("third")));
    try testing.expect(!collector.drained.items[2].get.responder.is_closed());
}

test "policy drain stops after returned message closes" {
    var overflow: Overflow = .empty;
    defer overflow.deinit(gpa);
    var first = try get(&overflow, digest_of("first"));
    var second = try get(&overflow, digest_of("second"));
    defer second.deinit();

    // The pusher drops the first receiver and hands the message back: one attempt.
    var returning: Collector = .{ .drop_on_push = &first };
    defer returning.deinit();
    drain_all(&overflow, &returning);
    try testing.expectEqual(@as(usize, 1), returning.attempts);

    // The now-closed first request is skipped.
    var collector: Collector = .{};
    defer collector.deinit();
    drain_all(&overflow, &collector);
    try testing.expectEqual(@as(usize, 1), collector.drained.items.len);
    const drained = collector.drained.items[0];
    try testing.expect(drained.get.digest.eql(digest_of("second")));
    try testing.expect(!drained.get.responder.is_closed());
    assert(overflow.is_empty());
}
