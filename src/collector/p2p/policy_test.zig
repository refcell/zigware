//! Overflow policy tests, ported from commonware `collector/src/p2p/ingress.rs`.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const p2p = @import("p2p");

const ingress = @import("ingress.zig");
const Request = @import("mocks.zig").types.Request;

const Key = cryptography.ed25519.PublicKey;
const Msg = ingress.Message(Key, Request);
const gpa = testing.allocator;

fn peer(seed: u64) Key {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

fn handle(overflow: *Msg.Overflow, message: Msg) !void {
    try Msg.handle(gpa, overflow, message);
}

fn send(overflow: *Msg.Overflow, request: Request, recipients: p2p.Recipients(Key)) !void {
    const message: Msg = .{ .send = .{ .gpa = gpa, .request = request, .recipients = recipients } };
    try handle(overflow, message);
}

fn cancel(overflow: *Msg.Overflow, commitment: Request.Commitment) !void {
    try handle(overflow, .{ .cancel = .{ .commitment = commitment } });
}

fn expect_send(message: Msg, request: Request, recipient: ?Key) !void {
    try testing.expect(message == .send);
    try testing.expectEqual(request, message.send.request);
    if (recipient) |want| {
        try testing.expect(message.send.recipients == .one);
        try testing.expect(message.send.recipients.one.eql(want));
    }
}

fn expect_cancel(message: Msg, commitment: Request.Commitment) !void {
    try testing.expect(message == .cancel);
    try testing.expect(message.cancel.commitment.eql(commitment));
}

test "cancel prunes queued sends and is retained" {
    const request1: Request = .{ .id = 1, .data = 10 };
    const request2: Request = .{ .id = 2, .data = 20 };
    var overflow: Msg.Overflow = .empty;
    defer overflow.deinit(gpa);
    try send(&overflow, request1, .{ .one = peer(1) });
    try send(&overflow, request2, .{ .one = peer(2) });
    try cancel(&overflow, request1.commitment());
    try testing.expectEqual(@as(usize, 2), overflow.len);
    try expect_send(overflow.at(0), request2, peer(2));
    try expect_cancel(overflow.at(1), request1.commitment());
}

test "cancel coalesces duplicate cancels in place" {
    const request1: Request = .{ .id = 1, .data = 10 };
    const request2: Request = .{ .id = 2, .data = 20 };
    var overflow: Msg.Overflow = .empty;
    defer overflow.deinit(gpa);
    try cancel(&overflow, request1.commitment());
    try cancel(&overflow, request2.commitment());
    try send(&overflow, request1, .{ .one = peer(1) });
    try cancel(&overflow, request1.commitment());
    try testing.expectEqual(@as(usize, 2), overflow.len);
    try expect_cancel(overflow.at(0), request1.commitment());
    try expect_cancel(overflow.at(1), request2.commitment());
}

test "send same request keeps recipients separate" {
    const request: Request = .{ .id = 1, .data = 10 };
    var overflow: Msg.Overflow = .empty;
    defer overflow.deinit(gpa);
    try send(&overflow, request, .{ .one = peer(1) });
    try send(&overflow, request, .{ .one = peer(2) });
    try testing.expectEqual(@as(usize, 2), overflow.len);
    try expect_send(overflow.at(0), request, peer(1));
    try expect_send(overflow.at(1), request, peer(2));
}

test "send same commitment different digest keeps payloads separate" {
    const request1: Request = .{ .id = 1, .data = 10 };
    const request2: Request = .{ .id = 1, .data = 20 };
    var overflow: Msg.Overflow = .empty;
    defer overflow.deinit(gpa);
    try send(&overflow, request1, .{ .one = peer(1) });
    try send(&overflow, request2, .{ .one = peer(2) });
    try testing.expectEqual(@as(usize, 2), overflow.len);
    try expect_send(overflow.at(0), request1, peer(1));
    try expect_send(overflow.at(1), request2, peer(2));
}

test "send with all recipients keeps payloads separate" {
    const request: Request = .{ .id = 1, .data = 10 };
    var overflow: Msg.Overflow = .empty;
    defer overflow.deinit(gpa);
    try send(&overflow, request, .{ .one = peer(1) });
    try send(&overflow, request, .all);
    try testing.expectEqual(@as(usize, 2), overflow.len);
    try testing.expect(overflow.at(0).send.recipients == .one);
    try testing.expect(overflow.at(1).send.recipients == .all);
}
