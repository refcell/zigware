//! commonware `actors/voter/ingress.rs` tests not covered by `actors/ingress_test.zig`.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const ingress = @import("ingress.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const Message = ingress.Message(Scheme, Digest);
const Certificate = types.Certificate(Scheme, Digest);
const gpa = testing.allocator;

fn round(view: u64) consensus_types.Round {
    return .new(.new(1), .new(view));
}

fn proposal(view: u64) types.Proposal(Digest) {
    return .init(round(view), .new(view -| 1), .fill(@intCast(view)));
}

const Drained = struct {
    items: std.ArrayList(Message) = .empty,

    pub fn push(self: *Drained, message: Message) ?Message {
        self.items.append(gpa, message) catch @panic("out of memory");
        return null;
    }
};

test "voter queued finalization rejects covered messages" {
    var rng = utils.rng.test_rng();
    var fixture = try ed25519.fixture(Digest, gpa, &rng, "voter-policy", 5);
    defer fixture.deinit(gpa);
    const Finalize = types.Finalize(Scheme, Digest);
    const Nullify = types.Nullify(Scheme);
    const Certificates = struct {
        fn finalization(f: anytype, view: u64) !Message {
            var votes: [5]Finalize = undefined;
            for (&votes, f.schemes) |*vote, *scheme| {
                vote.* = (try Finalize.sign(gpa, scheme, proposal(view))).?;
            }
            const value = try types.Finalization(Scheme, Digest).from_votes(
                gpa,
                &f.verifier,
                &votes,
                parallel.sequential,
            );
            const certificate: Certificate = .{ .finalization = value };
            return .{ .verified = .{ .gpa = gpa, .certificate = certificate } };
        }

        fn nullification(f: anytype, view: u64) !Message {
            var votes: [5]Nullify = undefined;
            for (&votes, f.schemes) |*vote, *scheme| {
                vote.* = (try Nullify.sign(gpa, scheme, round(view))).?;
            }
            const value = try types.Nullification(Scheme).from_votes(
                gpa,
                &f.verifier,
                &votes,
                parallel.sequential,
            );
            const certificate: Certificate = .{ .nullification = value };
            return .{ .verified = .{ .gpa = gpa, .certificate = certificate } };
        }
    };
    var overflow: Message.Overflow = .empty;
    try Message.handle(gpa, &overflow, try Certificates.finalization(&fixture, 3));
    // Everything at or below the queued finalization's view is dropped on arrival.
    try Message.handle(gpa, &overflow, .{ .proposal = proposal(3) });
    try Message.handle(gpa, &overflow, .{
        .timeout = .{ .round = round(2), .reason = .leader_timeout },
    });
    try Message.handle(gpa, &overflow, try Certificates.nullification(&fixture, 2));
    try Message.handle(gpa, &overflow, try Certificates.finalization(&fixture, 2));
    try Message.handle(gpa, &overflow, .{ .proposal = proposal(4) });
    var drained: Drained = .{};
    defer {
        for (drained.items.items) |message| Message.discard(message);
        drained.items.deinit(gpa);
    }
    overflow.drain(&drained);
    try testing.expect(overflow.is_empty());
    overflow.deinit(gpa);
    const items = drained.items.items;
    try testing.expectEqual(2, items.len);
    try testing.expect(items[0] == .verified);
    try testing.expect(items[0].verified.certificate == .finalization);
    try testing.expectEqual(3, items[0].verified.certificate.view().get());
    try testing.expect(items[1] == .proposal);
    try testing.expectEqual(4, items[1].proposal.view().get());
}
