//! commonware `actors/resolver/ingress.rs` tests: the mailbox overflow policies.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const resolver = @import("resolver");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const ask = @import("../ask.zig");
const ingress = @import("ingress.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const View = consensus_types.View;
const Round = consensus_types.Round;
const Kind = ask.Kind;
const Message = ingress.Message(Scheme, Digest);
const Certificate = types.Certificate(Scheme, Digest);
const HandlerMessage = ingress.HandlerMessage;
const oneshot = utils.channel.oneshot;
const gpa = testing.allocator;
const sequential = parallel.sequential;

fn round(view: u64) Round {
    return .new(.new(1), .new(view));
}

fn proposal(view: u64) types.Proposal(Digest) {
    return .init(round(view), .new(view -| 1), .fill(@intCast(view)));
}

/// commonware's `fixture()` (5 participants), signing every certificate with all of them.
const Certificates = struct {
    fixture: cryptography.certificate.mocks.Fixture(Scheme),

    fn init() !Certificates {
        var rng = utils.rng.test_rng();
        return .{ .fixture = try ed25519.fixture(Digest, gpa, &rng, "resolver-policy", 5) };
    }

    fn deinit(self: *Certificates) void {
        self.fixture.deinit(gpa);
    }

    fn nullification(self: *const Certificates, view: u64) !Certificate {
        const Nullify = types.Nullify(Scheme);
        var votes: [5]Nullify = undefined;
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Nullify.sign(gpa, scheme, round(view))).?;
        }
        const value = try types.Nullification(Scheme).from_votes(
            gpa,
            &self.fixture.verifier,
            &votes,
            sequential,
        );
        return .{ .nullification = value };
    }

    fn notarization(self: *const Certificates, view: u64) !types.Notarization(Scheme, Digest) {
        const Notarize = types.Notarize(Scheme, Digest);
        var votes: [5]Notarize = undefined;
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Notarize.sign(gpa, scheme, proposal(view))).?;
        }
        const Notarization = types.Notarization(Scheme, Digest);
        return Notarization.from_votes(gpa, &self.fixture.verifier, &votes, sequential);
    }

    fn finalization(self: *const Certificates, view: u64) !Certificate {
        const Finalize = types.Finalize(Scheme, Digest);
        var votes: [5]Finalize = undefined;
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Finalize.sign(gpa, scheme, proposal(view))).?;
        }
        const Finalization = types.Finalization(Scheme, Digest);
        const value = try Finalization.from_votes(
            gpa,
            &self.fixture.verifier,
            &votes,
            sequential,
        );
        return .{ .finalization = value };
    }

    fn certificate_msg(
        self: *const Certificates,
        kind: std.meta.Tag(Certificate),
        view: u64,
    ) !Message {
        const certificate = switch (kind) {
            .nullification => try self.nullification(view),
            .finalization => try self.finalization(view),
            .notarization => unreachable, // No test hands over a bare notarization update.
        };
        return .{ .updated = .{ .gpa = gpa, .certificate = certificate } };
    }

    fn certified_msg(self: *const Certificates, view: u64, success: bool) !Message {
        return .{ .certified = .{
            .gpa = gpa,
            .notarization = try self.notarization(view),
            .success = success,
        } };
    }

    /// A resolve restricted to the first participant (commonware `resolve_msg`).
    fn resolve_msg(self: *const Certificates, proposal_view: u64, view: u64, kind: Kind) Message {
        return .{ .resolve = .{
            .proposal = .new(proposal_view),
            .view = .new(view),
            .kind = kind,
            .target = self.fixture.participants[0],
        } };
    }
};

fn unrestricted_resolve_msg(proposal_view: u64, view: u64, kind: Kind) Message {
    return .{ .resolve = .{
        .proposal = .new(proposal_view),
        .view = .new(view),
        .kind = kind,
        .target = null,
    } };
}

fn Drained(comptime M: type) type {
    return struct {
        items: std.ArrayList(M) = .empty,

        pub fn push(self: *@This(), message: M) ?M {
            self.items.append(gpa, message) catch @panic("out of memory");
            return null;
        }
    };
}

/// Every message the overflow hands back, in order; the overflow is released.
fn drain(overflow: *Message.Overflow) ![]Message {
    var drained: Drained(Message) = .{};
    overflow.drain(&drained);
    try testing.expect(overflow.is_empty());
    overflow.deinit(gpa);
    return drained.items.toOwnedSlice(gpa);
}

fn release(messages: []Message) void {
    for (messages) |message| Message.discard(message);
    gpa.free(messages);
}

fn handle(overflow: *Message.Overflow, message: Message) !void {
    try Message.handle(gpa, overflow, message);
}

fn expect_certificate(message: Message, kind: std.meta.Tag(Certificate), view: u64) !void {
    try testing.expect(message == .updated);
    try testing.expectEqual(kind, std.meta.activeTag(message.updated.certificate));
    try testing.expectEqual(view, message.updated.certificate.view().get());
}

fn expect_certified(message: Message, view: u64, success: bool) !void {
    try testing.expect(message == .certified);
    try testing.expectEqual(view, message.certified.notarization.view().get());
    try testing.expectEqual(success, message.certified.success);
}

fn expect_resolve(message: Message, proposal_view: u64, view: u64, kind: Kind) !void {
    try testing.expect(message == .resolve);
    try testing.expectEqual(proposal_view, message.resolve.proposal.get());
    try testing.expectEqual(view, message.resolve.view.get());
    try testing.expectEqual(kind, message.resolve.kind);
}

const Pusher = struct {
    items: std.ArrayList(HandlerMessage) = .empty,

    pub fn push(self: *Pusher, message: HandlerMessage) ?HandlerMessage {
        self.items.append(gpa, message) catch @panic("out of memory");
        return null;
    }
};

fn deliver(view: u64) !struct { HandlerMessage, oneshot.Receiver(resolver.Outcome) } {
    const pair = try oneshot.channel(resolver.Outcome, gpa, testing.io);
    const asks = try gpa.alloc(ask.Ask, 1);
    asks[0] = .backfill();
    const message: HandlerMessage = .{ .deliver = .{
        .gpa = gpa,
        .view = .new(view),
        .data = try gpa.alloc(u8, 0),
        .asks = asks,
        .response = pair.sender,
    } };
    return .{ message, pair.receiver };
}

test "handle retains open deliveries only (handle_retains_open_deliveries_only)" {
    var overflow: HandlerMessage.Overflow = .empty;
    defer overflow.deinit(gpa);
    // An overflowed produce request is dropped and its requester sees the closed response.
    const produce = try oneshot.channel(resolver.p2p.Produced, gpa, testing.io);
    var produced = produce.receiver;
    defer produced.deinit();
    try HandlerMessage.handle(gpa, &overflow, .{
        .produce = .{ .view = .new(1), .response = produce.sender },
    });
    try testing.expectError(error.Closed, produced.try_recv());
    // Deliveries are retained, and drain skips one whose requester left.
    const closed_delivery, var closed = try deliver(2);
    try HandlerMessage.handle(gpa, &overflow, closed_delivery);
    const open_delivery, var open = try deliver(3);
    defer open.deinit();
    try HandlerMessage.handle(gpa, &overflow, open_delivery);
    closed.deinit();
    var pusher: Pusher = .{};
    defer {
        for (pusher.items.items) |message| HandlerMessage.discard(message);
        pusher.items.deinit(gpa);
    }
    overflow.drain(&pusher);
    try testing.expect(overflow.is_empty());
    try testing.expectEqual(1, pusher.items.items.len);
    const message = pusher.items.items[0];
    try testing.expect(message == .deliver);
    try testing.expectEqual(3, message.deliver.view.get());
}

test "finalization prunes stale certificates and results" {
    var c = try Certificates.init();
    defer c.deinit();
    var overflow: Message.Overflow = .empty;
    try handle(&overflow, try c.certificate_msg(.nullification, 2));
    try handle(&overflow, try c.certified_msg(2, false));
    try handle(&overflow, try c.certificate_msg(.nullification, 5));
    try handle(&overflow, try c.certified_msg(5, false));
    try handle(&overflow, try c.certificate_msg(.finalization, 3));
    const drained = try drain(&overflow);
    defer release(drained);
    try testing.expectEqual(3, drained.len);
    try expect_certificate(drained[0], .finalization, 3);
    try expect_certificate(drained[1], .nullification, 5);
    try expect_certified(drained[2], 5, false);
}

test "finalization prunes resolve by requested view" {
    var c = try Certificates.init();
    defer c.deinit();
    var overflow: Message.Overflow = .empty;
    try handle(&overflow, c.resolve_msg(10, 2, .nullification));
    try handle(&overflow, c.resolve_msg(10, 5, .notarization));
    try handle(&overflow, try c.certificate_msg(.finalization, 3));
    const drained = try drain(&overflow);
    defer release(drained);
    try testing.expectEqual(2, drained.len);
    try expect_certificate(drained[0], .finalization, 3);
    try expect_resolve(drained[1], 10, 5, .notarization);
}

test "resolve deduplicates by proposal, view, and kind" {
    var c = try Certificates.init();
    defer c.deinit();
    var overflow: Message.Overflow = .empty;
    for ([_]Kind{ .nullification, .nullification, .notarization }) |kind| {
        try handle(&overflow, c.resolve_msg(10, 3, kind));
    }
    const drained = try drain(&overflow);
    defer release(drained);
    try testing.expectEqual(2, drained.len);
    try expect_resolve(drained[0], 10, 3, .nullification);
    try expect_resolve(drained[1], 10, 3, .notarization);
}

test "resolve retains target across kinds (resolve_retains_target_across_kinds)" {
    var c = try Certificates.init();
    defer c.deinit();
    var overflow: Message.Overflow = .empty;
    try handle(&overflow, c.resolve_msg(10, 3, .nullification));
    try handle(&overflow, unrestricted_resolve_msg(10, 3, .notarization));
    const drained = try drain(&overflow);
    defer release(drained);
    try testing.expectEqual(2, drained.len);
    try expect_resolve(drained[0], 10, 3, .nullification);
    try testing.expect(drained[0].resolve.target != null);
    try expect_resolve(drained[1], 10, 3, .notarization);
    try testing.expect(drained[1].resolve.target == null);
}

test "resolve widens duplicate to unrestricted (resolve_widens_duplicate_to_unrestricted)" {
    var c = try Certificates.init();
    defer c.deinit();
    for ([_]bool{ false, true }) |unrestricted_first| {
        const restricted = c.resolve_msg(10, 3, .notarization);
        const unrestricted = unrestricted_resolve_msg(10, 3, .notarization);
        var overflow: Message.Overflow = .empty;
        try handle(&overflow, if (unrestricted_first) unrestricted else restricted);
        try handle(&overflow, if (unrestricted_first) restricted else unrestricted);
        const drained = try drain(&overflow);
        defer release(drained);
        try testing.expectEqual(1, drained.len);
        try expect_resolve(drained[0], 10, 3, .notarization);
        try testing.expect(drained[0].resolve.target == null);
    }
}

test "duplicate certified result is ignored (duplicate_certified_result_is_ignored)" {
    var c = try Certificates.init();
    defer c.deinit();
    var overflow: Message.Overflow = .empty;
    try handle(&overflow, try c.certified_msg(4, false));
    try handle(&overflow, try c.certified_msg(4, true));
    const drained = try drain(&overflow);
    defer release(drained);
    try testing.expectEqual(1, drained.len);
    try expect_certified(drained[0], 4, false);
}

test "resolver queued finalization rejects covered messages" {
    var c = try Certificates.init();
    defer c.deinit();
    var overflow: Message.Overflow = .empty;
    try handle(&overflow, try c.certificate_msg(.finalization, 3));
    try handle(&overflow, try c.certificate_msg(.nullification, 2));
    try handle(&overflow, try c.certified_msg(2, false));
    try handle(&overflow, try c.certificate_msg(.finalization, 2));
    try handle(&overflow, c.resolve_msg(10, 2, .nullification));
    try handle(&overflow, try c.certificate_msg(.nullification, 4));
    try handle(&overflow, c.resolve_msg(10, 4, .notarization));
    const drained = try drain(&overflow);
    defer release(drained);
    try testing.expectEqual(3, drained.len);
    try expect_certificate(drained[0], .finalization, 3);
    try expect_certificate(drained[1], .nullification, 4);
    try expect_resolve(drained[2], 10, 4, .notarization);
}

test "resolver duplicate finalization is dropped" {
    var c = try Certificates.init();
    defer c.deinit();
    var overflow: Message.Overflow = .empty;
    try handle(&overflow, try c.certificate_msg(.finalization, 3));
    try handle(&overflow, try c.certificate_msg(.finalization, 3));
    const drained = try drain(&overflow);
    defer release(drained);
    try testing.expectEqual(1, drained.len);
    try expect_certificate(drained[0], .finalization, 3);
}

test "resolver newer finalization replaces older pruning floor" {
    var c = try Certificates.init();
    defer c.deinit();
    var overflow: Message.Overflow = .empty;
    try handle(&overflow, try c.certificate_msg(.finalization, 3));
    try handle(&overflow, try c.certificate_msg(.nullification, 4));
    try handle(&overflow, try c.certified_msg(4, false));
    try handle(&overflow, try c.certificate_msg(.finalization, 5));
    const drained = try drain(&overflow);
    defer release(drained);
    try testing.expectEqual(1, drained.len);
    try expect_certificate(drained[0], .finalization, 5);
}

test "resolver duplicate certificate is ignored" {
    var c = try Certificates.init();
    defer c.deinit();
    var overflow: Message.Overflow = .empty;
    try handle(&overflow, try c.certificate_msg(.nullification, 4));
    try handle(&overflow, try c.certified_msg(4, true));
    try handle(&overflow, try c.certificate_msg(.nullification, 4));
    const drained = try drain(&overflow);
    defer release(drained);
    try testing.expectEqual(2, drained.len);
    try expect_certificate(drained[0], .nullification, 4);
    try expect_certified(drained[1], 4, true);
}

// A queued finalization prunes lower messages but never the replay marker, which keeps its
// place behind the messages it followed.
test "replay marker survives finalization (replay_marker_survives_finalization)" {
    var c = try Certificates.init();
    defer c.deinit();
    for ([_]bool{ false, true }) |finalization_first| {
        var overflow: Message.Overflow = .empty;
        try handle(&overflow, try c.certificate_msg(.nullification, 2));
        if (finalization_first) try handle(&overflow, try c.certificate_msg(.finalization, 3));
        try handle(&overflow, .replayed);
        if (!finalization_first) try handle(&overflow, try c.certificate_msg(.finalization, 3));
        try handle(&overflow, try c.certificate_msg(.nullification, 5));
        const drained = try drain(&overflow);
        defer release(drained);
        try testing.expectEqual(3, drained.len);
        try expect_certificate(drained[0], .finalization, 3);
        try testing.expect(drained[1] == .replayed);
        try expect_certificate(drained[2], .nullification, 5);
    }
}
