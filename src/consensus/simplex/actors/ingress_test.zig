//! commonware `actors/batcher/ingress.rs` and `actors/voter/ingress.rs` overflow tests.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../types.zig");
const types = @import("../types.zig");
const ed25519 = @import("../scheme/ed25519.zig");
const batcher = @import("batcher/ingress.zig");
const voter = @import("voter/ingress.zig");

const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const View = consensus_types.View;
const Round = consensus_types.Round;
const Vote = types.Vote(Scheme, Digest);
const gpa = testing.allocator;

fn round(view: u64) Round {
    return .new(.new(1), .new(view));
}

fn proposal(view: u64) types.Proposal(Digest) {
    return .init(round(view), .new(view -| 1), .fill(@intCast(view)));
}

/// A vote with a placeholder signature: the policies look only at kinds and views.
fn vote(comptime kind: std.meta.Tag(Vote), view: u64) Vote {
    const attestation = Scheme.Attestation.init(.init(0), .{ .raw = @splat(0) });
    return switch (kind) {
        .notarize => .{
            .notarize = .{ .proposal = proposal(view), .attestation = attestation },
        },
        .nullify => .{ .nullify = .{ .round = round(view), .attestation = attestation } },
        .finalize => .{
            .finalize = .{ .proposal = proposal(view), .attestation = attestation },
        },
    };
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

fn drain(comptime M: type, overflow: *M.Overflow) ![]M {
    var drained: Drained(M) = .{};
    overflow.drain(&drained);
    try testing.expect(overflow.is_empty());
    overflow.deinit(gpa);
    return drained.items.toOwnedSlice(gpa);
}

const BatcherMessage = batcher.Message(Scheme, Digest);

fn update(current: u64, finalized: u64) BatcherMessage {
    return .{ .update = .{
        .current = .new(current),
        .leader = .init(0),
        .finalized = .new(finalized),
        .forwardable_proposal = null,
    } };
}

fn batcher_views(messages: []const BatcherMessage) ![]u64 {
    const views = try gpa.alloc(u64, messages.len);
    for (messages, views) |message, *view| view.* = message.view().get();
    return views;
}

fn expect_batcher(steps: []const BatcherMessage, expected: []const u64) !void {
    var overflow: BatcherMessage.Overflow = .empty;
    for (steps) |step| try BatcherMessage.handle(gpa, &overflow, step);
    const drained = try drain(BatcherMessage, &overflow);
    defer gpa.free(drained);
    const views = try batcher_views(drained);
    defer gpa.free(views);
    try testing.expectEqualSlices(u64, expected, views);
}

test "batcher overflow policy" {
    // Update prunes stale constructed votes, and later stale votes are dropped.
    try expect_batcher(&.{ .{ .constructed = vote(.nullify, 2) }, update(3, 1) }, &.{3});
    try expect_batcher(&.{ update(3, 1), .{ .constructed = vote(.nullify, 2) } }, &.{3});
    // A newer update replaces an older one and keeps a current vote.
    try expect_batcher(
        &.{ update(2, 1), .{ .constructed = vote(.nullify, 3) }, update(3, 1) },
        &.{ 3, 3 },
    );
    // A stale update is dropped; the same current with a higher finalized view replaces.
    try expect_batcher(&.{ update(5, 4), update(4, 3) }, &.{5});
    var overflow: BatcherMessage.Overflow = .empty;
    try BatcherMessage.handle(gpa, &overflow, update(5, 3));
    try BatcherMessage.handle(gpa, &overflow, update(5, 4));
    try testing.expectEqual(4, overflow.update.?.finalized.get());
    overflow.deinit(gpa);
    // Duplicate constructed votes are ignored.
    const nullify = vote(.nullify, 5);
    try expect_batcher(&.{ .{ .constructed = nullify }, .{ .constructed = nullify } }, &.{5});
    // A lower update is dropped without merging its finalized view.
    try expect_batcher(
        &.{ update(5, 0), .{ .constructed = vote(.finalize, 3) }, update(4, 4) },
        &.{ 5, 3 },
    );
    // Finalize votes above the finalized view survive, in arrival order.
    try expect_batcher(
        &.{
            .{ .constructed = vote(.finalize, 4) },
            .{ .constructed = vote(.finalize, 2) },
            update(3, 1),
        },
        &.{ 3, 4, 2 },
    );
    // Notarize votes below the current view are pruned.
    try expect_batcher(&.{ .{ .constructed = vote(.notarize, 4) }, update(5, 3) }, &.{5});
}

const VoterMessage = voter.Message(Scheme, Digest);

const Certificates = struct {
    fixture: cryptography.certificate.mocks.Fixture(Scheme),
    rng: utils.rng.TestRng,

    fn init() !Certificates {
        var rng = utils.rng.test_rng();
        const fixture = try ed25519.fixture(Digest, gpa, &rng, "voter-policy", 4);
        return .{ .fixture = fixture, .rng = rng };
    }

    fn deinit(self: *Certificates) void {
        self.fixture.deinit(gpa);
    }

    fn verified(
        self: *Certificates,
        kind: std.meta.Tag(types.Certificate(Scheme, Digest)),
        view: u64,
    ) !VoterMessage {
        const schemes = self.fixture.schemes[0..3];
        const strategy = parallel.sequential;
        const certificate: types.Certificate(Scheme, Digest) = switch (kind) {
            .nullification => nullification: {
                var votes: [3]types.Nullify(Scheme) = undefined;
                for (&votes, schemes) |*each, *scheme| {
                    each.* = (try types.Nullify(Scheme).sign(gpa, scheme, round(view))).?;
                }
                const Nullification = types.Nullification(Scheme);
                const value = try Nullification.from_votes(gpa, &schemes[0], &votes, strategy);
                break :nullification .{ .nullification = value };
            },
            .finalization, .notarization => finalization: {
                const Finalize = types.Finalize(Scheme, Digest);
                var votes: [3]Finalize = undefined;
                for (&votes, schemes) |*each, *scheme| {
                    each.* = (try Finalize.sign(gpa, scheme, proposal(view))).?;
                }
                const Finalization = types.Finalization(Scheme, Digest);
                const value = try Finalization.from_votes(gpa, &schemes[0], &votes, strategy);
                break :finalization .{ .finalization = value };
            },
        };
        return .{ .verified = .{ .gpa = gpa, .certificate = certificate } };
    }
};

fn timeout(view: u64, reason: @import("../metrics.zig").TimeoutReason) VoterMessage {
    return .{ .timeout = .{ .round = round(view), .reason = reason } };
}

fn expect_voter(
    overflow: *VoterMessage.Overflow,
    expected: []const std.meta.Tag(VoterMessage),
    views: []const u64,
) !void {
    const drained = try drain(VoterMessage, overflow);
    defer {
        for (drained) |message| VoterMessage.discard(message);
        gpa.free(drained);
    }
    try testing.expectEqual(expected.len, drained.len);
    for (drained, expected, views) |message, tag, view| {
        try testing.expectEqual(tag, std.meta.activeTag(message));
        try testing.expectEqual(view, message.view().get());
    }
}

test "voter overflow keeps the latest finalization first and prunes below it" {
    var certificates = try Certificates.init();
    defer certificates.deinit();
    var overflow: VoterMessage.Overflow = .empty;
    try VoterMessage.handle(gpa, &overflow, .{ .proposal = proposal(2) });
    try VoterMessage.handle(gpa, &overflow, timeout(2, .leader_timeout));
    try VoterMessage.handle(gpa, &overflow, try certificates.verified(.nullification, 2));
    try VoterMessage.handle(gpa, &overflow, .{ .proposal = proposal(4) });
    try VoterMessage.handle(gpa, &overflow, try certificates.verified(.finalization, 3));
    // Covered by the queued finalization: dropped.
    try VoterMessage.handle(gpa, &overflow, .{ .proposal = proposal(3) });
    try VoterMessage.handle(gpa, &overflow, try certificates.verified(.finalization, 3));
    try VoterMessage.handle(gpa, &overflow, try certificates.verified(.finalization, 2));
    try expect_voter(&overflow, &.{ .verified, .proposal }, &.{ 3, 4 });

    // A newer finalization replaces the older one and its pruning floor.
    overflow = .empty;
    try VoterMessage.handle(gpa, &overflow, try certificates.verified(.finalization, 3));
    try VoterMessage.handle(gpa, &overflow, .{ .proposal = proposal(4) });
    try VoterMessage.handle(gpa, &overflow, try certificates.verified(.finalization, 5));
    try expect_voter(&overflow, &.{.verified}, &.{5});

    // A repeated certificate is ignored.
    overflow = .empty;
    try VoterMessage.handle(gpa, &overflow, try certificates.verified(.nullification, 5));
    try VoterMessage.handle(gpa, &overflow, try certificates.verified(.nullification, 5));
    try expect_voter(&overflow, &.{.verified}, &.{5});
}

test "voter overflow deduplicates proposals and timeouts" {
    var overflow: VoterMessage.Overflow = .empty;
    try VoterMessage.handle(gpa, &overflow, .{ .proposal = proposal(4) });
    try VoterMessage.handle(gpa, &overflow, .{ .proposal = proposal(4) });
    try VoterMessage.handle(gpa, &overflow, timeout(4, .leader_timeout));
    try VoterMessage.handle(gpa, &overflow, timeout(4, .inactivity));
    try expect_voter(&overflow, &.{ .proposal, .timeout }, &.{ 4, 4 });

    // A leader nullify upgrades a queued inactivity timeout, never the reverse.
    for ([_][2]@import("../metrics.zig").TimeoutReason{
        .{ .inactivity, .leader_nullify },
        .{ .leader_nullify, .inactivity },
    }) |reasons| {
        overflow = .empty;
        try VoterMessage.handle(gpa, &overflow, timeout(4, reasons[0]));
        try VoterMessage.handle(gpa, &overflow, timeout(4, reasons[1]));
        try testing.expectEqual(.leader_nullify, overflow.messages.at(0).timeout.reason);
        try expect_voter(&overflow, &.{.timeout}, &.{4});
    }
}
