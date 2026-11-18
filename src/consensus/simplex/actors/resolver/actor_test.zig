//! commonware `actors/resolver/actor.rs` tests. The handler-level cases drive the actor's
//! `handle_mailbox` and `handle_resolver` against `RecordingResolver`, as commonware's do.

const std = @import("std");
const testing = std.testing;
const actor = @import("actor");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const resolver = @import("resolver");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const ask = @import("../ask.zig");
const ingress = @import("ingress.zig");
const actor_mod = @import("actor.zig");

const TestDigest = cryptography.Sha256.Digest;
const TestScheme = ed25519.Scheme(TestDigest);
const Digest = TestDigest;
const Scheme = TestScheme;
const PublicKey = Scheme.PublicKey;
const View = consensus_types.View;
const Epoch = consensus_types.Epoch;
const Ask = ask.Ask;
const Kind = ask.Kind;
const Key = ingress.Handler.Key;
const Fetch = resolver.Fetch(Key, Ask);
const Feedback = actor.Feedback;
const Certificate = types.Certificate(Scheme, Digest);
const Notarization = types.Notarization(Scheme, Digest);
const Effect = @import("state.zig").Effect;
const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
const gpa = testing.allocator;
const sequential = parallel.sequential;

const namespace = "resolver-actor";
const epoch: Epoch = .new(9);
const term_length: consensus_types.TermLength = .new(utils.NonZero(u32).init(5).?);

const NoopBlocker = struct {
    pub const PublicKey = TestScheme.PublicKey;
    pub fn block(_: NoopBlocker, _: TestScheme.PublicKey) Feedback {
        return .ok;
    }
};

/// The actor's type parameters. The network halves are never used: these tests do not
/// `run` the actor, so its engine type is never analyzed.
const Params = struct {
    pub const Scheme = TestScheme;
    pub const Digest = TestDigest;
    pub const Blocker = NoopBlocker;
    pub const Strategy = parallel.Sequential;
    pub const NetSender = void;
    pub const NetReceiver = void;
};

const Actor = actor_mod.Actor(Params);
const Message = Actor.Message;

const Entry = struct { view: u64, subscriber: Ask };

fn ask_less(_: void, a: Ask, b: Ask) bool {
    return a.order(b) == .lt;
}

/// Tracks the pending requests the way the resolver engine would (commonware
/// `RecordingResolver`).
const RecordingResolver = struct {
    outstanding: std.ArrayList(Entry) = .empty,
    targeted: std.ArrayList(struct { view: u64, subscriber: Ask, target: PublicKey }) = .empty,
    batches: std.ArrayList([]u64) = .empty,
    singles: std.ArrayList(u64) = .empty,

    fn deinit(self: *RecordingResolver) void {
        for (self.batches.items) |batch| gpa.free(batch);
        self.batches.deinit(gpa);
        self.outstanding.deinit(gpa);
        self.targeted.deinit(gpa);
        self.singles.deinit(gpa);
    }

    fn insert(self: *RecordingResolver, item: Fetch) !void {
        const entry: Entry = .{ .view = item.key.get(), .subscriber = item.subscriber };
        for (self.outstanding.items) |existing| {
            if (std.meta.eql(existing, entry)) return;
        }
        try self.outstanding.append(gpa, entry);
    }

    pub fn fetch(self: *RecordingResolver, item: Fetch) !Feedback {
        try self.singles.append(gpa, item.key.get());
        try self.insert(item);
        return .ok;
    }

    pub fn fetch_all(self: *RecordingResolver, items: []const Fetch) !Feedback {
        const keys = try gpa.alloc(u64, items.len);
        errdefer gpa.free(keys);
        for (items, keys) |item, *key| key.* = item.key.get();
        try self.batches.append(gpa, keys);
        for (items) |item| try self.insert(item);
        return .ok;
    }

    pub fn retain(self: *RecordingResolver, predicate: resolver.Predicate(Key, Ask)) !Feedback {
        var index: usize = 0;
        while (index < self.outstanding.items.len) {
            const entry = self.outstanding.items[index];
            if (predicate.call(.init(entry.view), entry.subscriber)) {
                index += 1;
            } else {
                _ = self.outstanding.orderedRemove(index);
            }
        }
        return .ok;
    }

    pub fn fetch_targeted(
        self: *RecordingResolver,
        item: Fetch,
        targets: []const PublicKey,
    ) !Feedback {
        std.debug.assert(targets.len > 0);
        try self.targeted.append(gpa, .{
            .view = item.key.get(),
            .subscriber = item.subscriber,
            .target = targets[0],
        });
        try self.insert(item);
        return .ok;
    }

    /// The distinct outstanding views, ascending.
    fn expect_outstanding(self: *const RecordingResolver, expected: []const u64) !void {
        var views: std.ArrayList(u64) = .empty;
        defer views.deinit(gpa);
        for (self.outstanding.items) |entry| {
            if (std.mem.indexOfScalar(u64, views.items, entry.view) == null) {
                try views.append(gpa, entry.view);
            }
        }
        std.mem.sort(u64, views.items, {}, std.sort.asc(u64));
        try testing.expectEqualSlices(u64, expected, views.items);
    }

    fn subscriptions(self: *const RecordingResolver, view: u64, out: []Ask) []Ask {
        var count: usize = 0;
        for (self.outstanding.items) |entry| {
            if (entry.view != view) continue;
            out[count] = entry.subscriber;
            count += 1;
        }
        // Commonware's set iterates in `Ask` order.
        std.mem.sort(Ask, out[0..count], {}, ask_less);
        return out[0..count];
    }
};

/// commonware `build_notarization`/`build_finalization`'s proposal for `view`.
fn build_proposal(view: u64) types.Proposal(Digest) {
    return .init(.new(epoch, .new(view)), .new(view -| 1), .fill(@intCast(view)));
}

/// A fixture and an actor that finished replay (commonware `build_actor`).
const Env = struct {
    fixture: Fixture,
    actor: Actor,
    mailbox: Actor.Mailbox,
    recorder: RecordingResolver = .{},

    fn start(self: *Env) !void {
        var rng = utils.rng.test_rng();
        self.fixture = try ed25519.fixture(Digest, gpa, &rng, namespace, 4);
        errdefer self.fixture.deinit(gpa);
        self.actor, self.mailbox = try Actor.init(gpa, testing.io, .{
            .scheme = &self.fixture.verifier,
            .blocker = .{},
            .strategy = sequential,
            .epoch = epoch,
            .mailbox_size = 8,
            .fetch_timeout = .from_secs(1),
            .fetch_retry_delay = .from_millis(100),
            .term_length = term_length,
        });
        self.recorder = .{};
        var effects: std.ArrayList(Effect) = .empty;
        defer effects.deinit(gpa);
        try self.actor.state.replayed(&effects);
        try testing.expectEqual(0, effects.items.len);
    }

    fn stop(self: *Env) void {
        self.recorder.deinit();
        self.mailbox.deinit();
        self.actor.deinit();
        self.fixture.deinit(gpa);
    }

    fn nullification(self: *const Env, view: u64) !Certificate {
        const Nullify = types.Nullify(Scheme);
        var votes: [4]Nullify = undefined;
        const round: consensus_types.Round = .new(epoch, .new(view));
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Nullify.sign(gpa, scheme, round)).?;
        }
        const Nullification = types.Nullification(Scheme);
        const value = try Nullification.from_votes(gpa, &self.fixture.verifier, &votes, sequential);
        return .{ .nullification = value };
    }

    fn finalization(self: *const Env, view: u64) !Certificate {
        const Finalize = types.Finalize(Scheme, Digest);
        var votes: [4]Finalize = undefined;
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Finalize.sign(gpa, scheme, build_proposal(view))).?;
        }
        const Finalization = types.Finalization(Scheme, Digest);
        const value = try Finalization.from_votes(gpa, &self.fixture.verifier, &votes, sequential);
        return .{ .finalization = value };
    }

    fn notarization(self: *const Env, view: u64) !Notarization {
        const Notarize = types.Notarize(Scheme, Digest);
        var votes: [4]Notarize = undefined;
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Notarize.sign(gpa, scheme, build_proposal(view))).?;
        }
        return Notarization.from_votes(gpa, &self.fixture.verifier, &votes, sequential);
    }

    fn certified(self: *Env, notarization_value: Notarization, success: bool) !void {
        const message: Message = .{ .certified = .{
            .gpa = gpa,
            .notarization = notarization_value,
            .success = success,
        } };
        try self.actor.handle_mailbox(&self.recorder, message);
    }

    /// Opens a background repair fetch at `view` directly on the resolver.
    fn backfill(self: *Env, view: u64) !void {
        _ = try self.recorder.fetch(.{ .key = .init(view), .subscriber = Ask.backfill() });
    }

    fn updated(self: *Env, certificate: Certificate) !void {
        const message: Message = .{ .updated = .{ .gpa = gpa, .certificate = certificate } };
        try self.actor.handle_mailbox(&self.recorder, message);
    }

    fn resolve(self: *Env, proposal: u64, view: u64, kind: Kind, target: ?PublicKey) !void {
        const message: Message = .{ .resolve = .{
            .proposal = .new(proposal),
            .view = .new(view),
            .kind = kind,
            .target = target,
        } };
        try self.actor.handle_mailbox(&self.recorder, message);
    }
};

// One scan reaches the resolver as a single batch. An update that only settles an
// outstanding fetch retires it and sends no batch.
test "resolver actor scan fetches issue as one batch (scan_fetches_issue_as_one_batch)" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try env.updated(try env.nullification(20));
    try testing.expectEqual(1, env.recorder.batches.items.len);
    try testing.expectEqualSlices(u64, &.{ 1, 6, 11, 16 }, env.recorder.batches.items[0]);
    try env.updated(try env.nullification(6));
    try testing.expectEqual(1, env.recorder.batches.items.len);
    try testing.expectEqual(0, env.recorder.singles.items.len);
    try env.recorder.expect_outstanding(&.{ 1, 11, 16 });
}

test "resolver actor updates maintain the pending set (updates_maintain_*_pending_set)" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    // The first certificate emits requests at the term anchors.
    try env.updated(try env.nullification(20));
    try env.recorder.expect_outstanding(&.{ 1, 6, 11, 16 });
    // A covering nullification retires only its own term's requests.
    try env.updated(try env.nullification(6));
    try env.recorder.expect_outstanding(&.{ 1, 11, 16 });
    // A mid-term floor raise drops the requests below it and re-scans the term tail (5).
    try env.updated(try env.finalization(4));
    try env.recorder.expect_outstanding(&.{ 5, 11, 16 });
    // A below-floor nullification covering the floor's term retires its term end (5).
    try env.updated(try env.nullification(2));
    try env.recorder.expect_outstanding(&.{ 11, 16 });
    // A floor raise drops the request at the floor view and re-scans the tail (12).
    try env.updated(try env.finalization(11));
    try env.recorder.expect_outstanding(&.{ 12, 16 });
    // A nullification at the floor retires mid-term requests inside its range.
    try env.updated(try env.nullification(11));
    try env.recorder.expect_outstanding(&.{16});
}

// A resolve without a target opens an untargeted fetch instead of being dropped.
test "resolver actor resolve without target falls back to an untargeted fetch" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try env.resolve(10, 9, .notarization, null);
    try testing.expectEqual(0, env.recorder.targeted.items.len);
    try env.recorder.expect_outstanding(&.{9});
    var out: [4]Ask = undefined;
    const asks = env.recorder.subscriptions(9, &out);
    try testing.expectEqual(1, asks.len);
    try testing.expectEqual(Ask.ancestry(.notarization), asks[0]);
}

fn expect_targeted(env: *const Env, index: usize, view: u64, item: Ask, target: usize) !void {
    const entry = env.recorder.targeted.items[index];
    try testing.expectEqual(view, entry.view);
    try testing.expectEqual(item, entry.subscriber);
    try testing.expectEqual(env.fixture.participants[target], entry.target);
}

fn expect_subscriptions(env: *const Env, view: u64, expected: []const Ask) !void {
    var out: [8]Ask = undefined;
    try testing.expectEqualSlices(Ask, expected, env.recorder.subscriptions(view, &out));
}

// A covering nullification completes background repair and the targeted nullification ask,
// but keeps the targeted parent ask that the opposite evidence makes necessary.
fn targeted_first_key(env: *Env) !void {
    const peers = env.fixture.participants;
    try env.resolve(10, 3, .nullification, peers[0]);
    try env.resolve(11, 3, .notarization, peers[1]);
    try env.backfill(3);
    try testing.expectEqual(2, env.recorder.targeted.items.len);
    try expect_targeted(env, 0, 3, .ancestry(.nullification), 0);
    try expect_targeted(env, 1, 3, .ancestry(.notarization), 1);
    try expect_subscriptions(env, 3, &.{
        .backfill(), .ancestry(.nullification), .ancestry(.notarization),
    });
    try env.updated(try env.nullification(3));
    try expect_subscriptions(env, 3, &.{.ancestry(.notarization)});
    try env.resolve(14, 3, .nullification, peers[2]);
    try env.resolve(14, 4, .nullification, peers[2]);
    try testing.expectEqual(2, env.recorder.targeted.items.len);
}

// The mirror case: the exact certified parent completes only the targeted parent ask, not
// the nullification needed to skip that view.
fn targeted_second_key(env: *Env) !void {
    const peers = env.fixture.participants;
    const second = consensus_types.View.new(3).next_term_start(env.actor.state.term()).get();
    try testing.expectEqual(6, second);
    try env.resolve(12, second, .nullification, peers[2]);
    try env.resolve(13, second, .notarization, peers[3]);
    try env.backfill(second);
    try env.updated(.{ .notarization = try env.notarization(second) });
    try env.certified(try env.notarization(second), true);
    // The certified floor satisfies background repair; the nullification ask survives.
    try expect_subscriptions(env, second, &.{.ancestry(.nullification)});
    try env.resolve(14, second, .notarization, peers[0]);
    try testing.expectEqual(4, env.recorder.targeted.items.len);
}

test "resolver actor targeted fetches drop only when their ask is satisfied" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try targeted_first_key(&env);
    try targeted_second_key(&env);
    // A numeric floor raise alone identifies no ancestry requirement: both targeted asks
    // survive until matching evidence or finalization arrives.
    try env.actor.apply_effects(&env.recorder, &.{.{ .raised = .new(6) }});
    try env.recorder.expect_outstanding(&.{ 3, 6 });
    // Finalization retires every key at or below it, and a delayed request stays retired.
    try env.updated(try env.finalization(6));
    try env.recorder.expect_outstanding(&.{});
    try env.resolve(7, 3, .notarization, env.fixture.participants[0]);
    try env.recorder.expect_outstanding(&.{});
    try testing.expectEqual(4, env.recorder.targeted.items.len);
}
