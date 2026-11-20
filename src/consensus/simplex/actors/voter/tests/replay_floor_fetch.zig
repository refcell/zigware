//! commonware `simplex/actors/voter/mod.rs`
//! `test_restart_replay_fetches_only_above_recovered_floor`: a voter journals a notarization
//! (with its certification verdict), a finalization, and a nullification; after a restart, the
//! resolver state fed the restarted voter's messages fetches only the nullification gaps above
//! the recovered floor, and the voter enters the view after both the nullified term and the
//! floor.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const actor_pkg = @import("actor");
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../../../../types.zig");
const resolver_state = @import("../../resolver/state.zig");

const TermLength = consensus_types.TermLength;

/// One case: the term length, the notarized view, the notarization's certification verdict
/// (null for no notarization), whether a finalization at the next view is journaled, the
/// nullified view, and the views the resolver should fetch.
const Case = struct {
    term: u32,
    notarized: u64,
    verdict: ?bool,
    with_finalization: bool,
    nullified: u64,
    expected: []const u64,
};

const cases = [_]Case{
    .{
        .term = 1,
        .notarized = 10_000,
        .verdict = true,
        .with_finalization = true,
        .nullified = 10_004,
        .expected = &.{ 10_002, 10_003 },
    },
    .{
        .term = 1,
        .notarized = 10_000,
        .verdict = true,
        .with_finalization = false,
        .nullified = 10_003,
        .expected = &.{ 10_001, 10_002 },
    },
    .{
        .term = 1,
        .notarized = 10_000,
        .verdict = null,
        .with_finalization = false,
        .nullified = 3,
        .expected = &.{ 1, 2 },
    },
    .{
        .term = 1,
        .notarized = 3,
        .verdict = false,
        .with_finalization = false,
        .nullified = 3,
        .expected = &.{ 1, 2 },
    },
    .{
        .term = 5,
        .notarized = 10_001,
        .verdict = true,
        .with_finalization = true,
        .nullified = 10_004,
        .expected = &.{10_003},
    },
    .{
        .term = 1,
        .notarized = 10_000,
        .verdict = null,
        .with_finalization = true,
        .nullified = 10_000,
        .expected = &.{},
    },
};

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const epoch = h.default_epoch;
        const State = resolver_state.State(h.Scheme, h.Digest);
        const Effect = resolver_state.Effect;
        const partition = "replay_floor_catchup";

        fn never(_: h.Round, _: h.Digest) bool {
            return false;
        }

        fn term_length(case: Case) TermLength {
            return .new(utils.NonZero(u32).init(case.term).?);
        }

        fn options(case: Case) h.Options {
            var result = h.floor_start(partition, null, std.math.maxInt(u64));
            if (case.term > 1) result.elector = h.term_elector(case.term, 20_000, 0);
            result.certifier = if (case.verdict == false) .{ .custom = never } else .always;
            return result;
        }

        /// The case's certificates in view order (`count` of them).
        fn certificates(
            ctx: Ctx,
            net: *const h.Network,
            case: Case,
            out: *[3]h.Certificate,
        ) !usize {
            const gpa = ctx.gpa();
            var count: usize = 0;
            errdefer for (out[0..count]) |*certificate| certificate.deinit(gpa);
            if (case.verdict != null) {
                const subject = h.proposal_at(epoch, case.notarized, "replay-notarized");
                const built = try h.build(gpa, .notarization, net.schemes(), subject, net.quorum());
                out[count] = .{ .notarization = built };
                count += 1;
            }
            if (case.with_finalization) {
                const subject = h.proposal_at(epoch, case.notarized + 1, "replay-finalized");
                const built = try h.build(gpa, .finalization, net.schemes(), subject, net.quorum());
                out[count] = .{ .finalization = built };
                count += 1;
            }
            const round: h.Round = .new(epoch, .new(case.nullified));
            const built = try h.build(gpa, .nullification, net.schemes(), round, net.quorum());
            out[count] = .{ .nullification = built };
            count += 1;
            std.mem.sort(h.Certificate, out[0..count], {}, struct {
                fn less(_: void, a: h.Certificate, b: h.Certificate) bool {
                    return a.view().get() < b.view().get();
                }
            }.less);
            return count;
        }

        /// Hands `certificate` to the live voter and waits for the view advance after its
        /// sync and, for a notarization, the durable certification verdict. A notarization
        /// that fails certification does not advance the view, so only its verdict counts.
        fn journal_through(
            ctx: Ctx,
            stack: *h.VoterStack,
            case: Case,
            certificate: h.Certificate,
        ) !void {
            const gpa = ctx.gpa();
            const view = certificate.view();
            const advanced_to = if (certificate == .nullification)
                view.term_end(term_length(case)).next()
            else
                view.next();
            const expected: ?bool = if (certificate == .notarization) case.verdict else null;
            try stack.mailbox.recovered(gpa, try certificate.clone(gpa));
            var advanced = expected == false;
            var certified = expected == null;
            var waited: u64 = 0;
            while (!(advanced and certified)) : (waited += 1) {
                if (waited > 20_000) return error.TimedOut;
                if (stack.batcher.try_recv()) |message| {
                    if (message == .update and message.update.current.get() == advanced_to.get()) {
                        advanced = true;
                    }
                    continue;
                } else |_| {}
                if (stack.resolver.try_recv()) |message| {
                    defer message.discard();
                    if (message == .certified) {
                        const verdict = message.certified;
                        const same = verdict.notarization.view().get() == view.get();
                        if (same and expected == verdict.success) certified = true;
                    }
                    continue;
                } else |_| {}
                try ctx.sleep(.fromMilliseconds(1));
            }
        }

        /// Routes the restarted voter's resolver messages through a one-slot mailbox (so the
        /// end-of-replay marker must survive the overflow policy), checks every journaled
        /// certificate at or above the floor is forwarded, and returns the fetched views.
        fn replayed_fetches(
            ctx: Ctx,
            stack: *h.VoterStack,
            case: Case,
            journaled: []const h.Certificate,
            finalized: u64,
            fetches: *std.ArrayList(u64),
        ) !void {
            const gpa = ctx.gpa();
            const pair = try actor_pkg.mailbox.new(h.ResolverMessage, gpa, ctx.io(), 1);
            var sender = pair.sender;
            defer sender.deinit();
            var receiver = pair.receiver;
            defer receiver.deinit();
            var remaining: [3]bool = @splat(false);
            for (journaled, remaining[0..journaled.len]) |certificate, *flag| {
                flag.* = certificate.view().get() >= finalized;
            }
            while (true) {
                const message = (try stack.next_resolver(ctx, 20_000)) orelse return error.TimedOut;
                if (message == .updated) {
                    const forwarded = &message.updated.certificate;
                    try mark_forwarded(gpa, journaled, &remaining, forwarded);
                }
                const replayed = message == .replayed;
                try testing.expect((try sender.enqueue(message)).accepted());
                if (replayed) break;
            }
            for (remaining) |flag| try testing.expect(!flag);
            var state: State = .init(gpa, term_length(case));
            defer state.deinit();
            var effects: std.ArrayList(Effect) = .empty;
            defer effects.deinit(gpa);
            while (receiver.try_recv()) |message| {
                defer message.discard();
                switch (message) {
                    .updated => |updated| try state.updated(&updated.certificate, &effects),
                    .certified => |verdict| {
                        try state.certified(&verdict.notarization, verdict.success, &effects);
                    },
                    .resolve => {},
                    .replayed => try state.replayed(&effects),
                }
            } else |_| {}
            for (effects.items) |effect| {
                if (effect == .fetch) try fetches.append(gpa, effect.fetch.view.get());
            }
        }

        fn mark_forwarded(
            gpa: std.mem.Allocator,
            journaled: []const h.Certificate,
            remaining: *[3]bool,
            certificate: *const h.Certificate,
        ) !void {
            const got = try codec.encode(h.Certificate, gpa, certificate.*);
            defer gpa.free(got);
            for (journaled, remaining[0..journaled.len]) |expected, *flag| {
                const want = try codec.encode(h.Certificate, gpa, expected);
                defer gpa.free(want);
                if (std.mem.eql(u8, want, got)) flag.* = false;
            }
        }

        fn run_case(comptime case: Case) !void {
            try h.soak(30 * std.time.ns_per_s, struct {
                fn body(ctx: Ctx) anyerror!void {
                    try case_body(ctx, case);
                }
            }.body);
        }

        fn case_body(ctx: Ctx, case: Case) !void {
            const gpa = ctx.gpa();
            var net: h.Network = undefined;
            try net.start(ctx, 5, "replay_floor_catchup");
            defer net.deinit();
            var journaled: [3]h.Certificate = undefined;
            const count = try certificates(ctx, &net, case, &journaled);
            defer for (journaled[0..count]) |*certificate| certificate.deinit(gpa);
            const finalized: u64 = if (case.with_finalization) case.notarized + 1 else 0;
            var stack: h.VoterStack = undefined;
            try stack.start(ctx, &net, options(case));
            defer stack.stop();
            for (journaled[0..count]) |certificate| {
                try journal_through(ctx, &stack, case, certificate);
            }
            try stack.restart(ctx, &net, options(case));
            var fetches: std.ArrayList(u64) = .empty;
            defer fetches.deinit(gpa);
            try replayed_fetches(ctx, &stack, case, journaled[0..count], finalized, &fetches);
            try testing.expectEqualSlices(u64, case.expected, fetches.items);
            const nullified: consensus_types.View = .new(case.nullified);
            const nullified_end = nullified.term_end(term_length(case)).next();
            const entered = @max(nullified_end.get(), finalized + 1);
            try stack.expect_update(ctx, entered, finalized);
        }

        // commonware test_restart_replay_fetches_only_above_recovered_floor: restart does not
        // request nullifications the recovered floor or a journaled nullification covers, but
        // still requests the gaps above the floor, across six journal shapes.
        test "voter restart replay fetches only above recovered floor" {
            try h.covers(.ed25519);
            inline for (cases) |case| try run_case(case);
        }
    };
}
