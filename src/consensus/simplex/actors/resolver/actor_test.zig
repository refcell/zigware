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
const codec = @import("codec");
const oneshot = utils.channel.oneshot;
const HandlerMessage = ingress.HandlerMessage;
const complete: resolver.Outcome = .{ .resolved = .complete };
const partial: resolver.Outcome = .{ .resolved = .partial };

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

/// Records what the actor forwards to the voter, encoded (commonware's voter mailbox).
const RecordingVoter = struct {
    recovered_certificates: std.ArrayList([]u8) = .empty,

    fn deinit(self: *RecordingVoter) void {
        for (self.recovered_certificates.items) |bytes| gpa.free(bytes);
        self.recovered_certificates.deinit(gpa);
    }

    pub fn recovered(self: *RecordingVoter, _: std.mem.Allocator, certificate: Certificate) !void {
        var owned = certificate;
        defer owned.deinit(gpa);
        const bytes = try codec.encode(Certificate, gpa, owned);
        errdefer gpa.free(bytes);
        try self.recovered_certificates.append(gpa, bytes);
    }
};

/// commonware `build_notarization`/`build_finalization`'s proposal for `view`.
fn build_proposal(view: u64) types.Proposal(Digest) {
    return build_proposal_in(epoch, view);
}

fn build_proposal_in(in_epoch: Epoch, view: u64) types.Proposal(Digest) {
    return .init(.new(in_epoch, .new(view)), .new(view -| 1), .fill(@intCast(view)));
}

/// A fixture and an actor that finished replay (commonware `build_actor`).
const Env = struct {
    fixture: Fixture,
    actor: Actor,
    mailbox: Actor.Mailbox,
    recorder: RecordingResolver = .{},
    voter: RecordingVoter = .{},

    fn start(self: *Env) !void {
        return self.start_with(term_length);
    }

    fn start_with(self: *Env, term: consensus_types.TermLength) !void {
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
            .term_length = term,
        });
        self.recorder = .{};
        self.voter = .{};
        var effects: std.ArrayList(Effect) = .empty;
        defer effects.deinit(gpa);
        try self.actor.state.replayed(&effects);
        try testing.expectEqual(0, effects.items.len);
    }

    fn stop(self: *Env) void {
        self.voter.deinit();
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
        return self.finalization_in(epoch, view);
    }

    fn finalization_in(self: *const Env, in_epoch: Epoch, view: u64) !Certificate {
        const Finalize = types.Finalize(Scheme, Digest);
        var votes: [4]Finalize = undefined;
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Finalize.sign(gpa, scheme, build_proposal_in(in_epoch, view))).?;
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

    /// Delivers `certificate` (taken) as a peer's response for `view`. Returns the verdict,
    /// or null when the actor dropped the response without one.
    fn deliver(
        self: *Env,
        view: u64,
        certificate: Certificate,
        asks: []const Ask,
    ) !?resolver.Outcome {
        var owned = certificate;
        defer owned.deinit(gpa);
        const data = try codec.encode(Certificate, gpa, owned);
        return self.deliver_bytes(view, data, asks);
    }

    /// Delivers `data` (taken) as a peer's response for `view`.
    fn deliver_bytes(self: *Env, view: u64, data: []u8, asks: []const Ask) !?resolver.Outcome {
        return self.deliver_spanned(view, data, asks, null);
    }

    /// Delivers `data` (taken) for `view` from the fetch whose span is `span` (taken).
    fn deliver_spanned(
        self: *Env,
        view: u64,
        data: []u8,
        asks: []const Ask,
        span: ?*Span,
    ) !?resolver.Outcome {
        errdefer gpa.free(data);
        const pair = try oneshot.channel(resolver.Outcome, gpa, testing.io);
        var receiver = pair.receiver;
        defer receiver.deinit();
        const owned_asks = try gpa.dupe(Ask, asks);
        const message: HandlerMessage = .{ .deliver = .{
            .gpa = gpa,
            .view = .new(view),
            .data = data,
            .asks = owned_asks,
            .response = pair.sender,
            .span = span,
        } };
        try self.actor.handle_resolver(message, &self.voter, &self.recorder);
        return receiver.try_recv() catch |err| switch (err) {
            error.Closed => null,
            error.Empty => unreachable,
        };
    }

    /// Whether the actor accepts `certificate` (taken) as a response for `view`; returns
    /// the parsed certificate's view.
    fn validate(self: *Env, view: u64, certificate: Certificate) !?u64 {
        const data = try encoded(certificate);
        defer gpa.free(data);
        var parsed = try self.actor.validate(.new(view), data) orelse return null;
        defer parsed.deinit(gpa);
        return parsed.view().get();
    }

    fn settled(self: *const Env, view: u64, kind: Kind) bool {
        return self.actor.state.settled(.new(view), kind);
    }

    fn produce(self: *const Env, view: u64) ?[]const u8 {
        return self.actor.state.produce(.new(view));
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

/// The encoding of `certificate` (taken), as a peer would serve it.
fn encoded(certificate: Certificate) ![]u8 {
    var owned = certificate;
    defer owned.deinit(gpa);
    return codec.encode(Certificate, gpa, owned);
}

/// Records and certifies the notarization at `view` (commonware `updated` then `certified`).
fn certify(env: *Env, view: u64, success: bool) !void {
    try env.updated(.{ .notarization = try env.notarization(view) });
    try env.certified(try env.notarization(view), success);
}

test "resolver actor prefers the exact certified notarization over nullification and floor" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try env.updated(try env.nullification(3));
    try certify(&env, 3, true);
    try certify(&env, 4, true);
    // Both a covering nullification and the exact certified parent are held for view 3.
    try testing.expect(env.settled(3, .nullification));
    try testing.expect(env.settled(3, .notarization));
    const expected = try encoded(.{ .notarization = try env.notarization(3) });
    defer gpa.free(expected);
    try testing.expectEqualSlices(u8, expected, env.produce(3).?);
}

test "resolver actor higher certified floor does not hide an older finalization" {
    var responder: Env = undefined;
    try responder.start();
    defer responder.stop();
    try responder.updated(try responder.finalization(3));
    try certify(&responder, 6, true);
    // The retained finalization, not the floor's notarization, settles the ask at view 3.
    const data = try gpa.dupe(u8, responder.produce(3).?);
    var requester: Env = undefined;
    try requester.start();
    defer requester.stop();
    const outcome = try requester.deliver_bytes(3, data, &.{.ancestry(.notarization)});
    try testing.expectEqual(complete, outcome.?);
}

test "resolver actor serves a notarization only after certification" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    const outcome = try env.deliver(3, .{ .notarization = try env.notarization(3) }, &.{
        .ancestry(.notarization),
    });
    try testing.expectEqual(complete, outcome.?);
    try testing.expectEqual(null, env.produce(3));
    try env.certified(try env.notarization(3), true);
    const expected = try encoded(.{ .notarization = try env.notarization(3) });
    defer gpa.free(expected);
    try testing.expectEqualSlices(u8, expected, env.produce(3).?);
}

test "resolver actor nullification satisfies a target at the certified floor" {
    var env: Env = undefined;
    try env.start_with(.one);
    defer env.stop();
    const peers = env.fixture.participants;
    // Certify view 3, then request its coexisting nullification for a proposal skipping it.
    try certify(&env, 3, true);
    try certify(&env, 8, true);
    try env.resolve(10, 3, .nullification, peers[0]);
    try expect_subscriptions(&env, 3, &.{.ancestry(.nullification)});
    // Observing the nullification retires the exact targeted ask; the floor stays.
    try env.updated(try env.nullification(3));
    try env.recorder.expect_outstanding(&.{});
    const floor = try encoded(.{ .notarization = try env.notarization(8) });
    defer gpa.free(floor);
    try testing.expectEqualSlices(u8, floor, env.produce(6).?);
    try env.resolve(11, 3, .nullification, peers[1]);
    try testing.expectEqual(1, env.recorder.targeted.items.len);
}

test "resolver actor higher certified floor does not suppress an exact parent fetch" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try certify(&env, 6, true);
    try env.resolve(8, 4, .notarization, env.fixture.participants[0]);
    try testing.expectEqual(1, env.recorder.targeted.items.len);
    try expect_targeted(&env, 0, 4, .ancestry(.notarization), 0);
}

test "resolver actor certification failure retires the parent target" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    const peers = env.fixture.participants;
    try env.resolve(10, 5, .notarization, peers[0]);
    try certify(&env, 5, false);
    // A false verdict is permanent: parent repair retires, and background repair asks for
    // the nullification that can now cover the failed view.
    try expect_subscriptions(&env, 5, &.{.backfill()});
    try env.resolve(11, 5, .notarization, peers[1]);
    try testing.expectEqual(1, env.recorder.targeted.items.len);
}

test "resolver actor parent delivery completes on possession, not certification" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    const outcome = try env.deliver(6, .{ .notarization = try env.notarization(6) }, &.{
        .ancestry(.notarization),
    });
    try testing.expectEqual(complete, outcome.?);
    // Possession settles the ask; the notarization is not served until it certifies.
    try testing.expect(env.settled(6, .notarization));
    try testing.expectEqual(null, env.produce(6));
}

test "resolver actor failed certification retires the parent ask until finalization" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try certify(&env, 6, false);
    try testing.expect(env.actor.state.uncertifiable(.new(6)));
    try testing.expectEqual(null, env.produce(6));
    // A floor raise above the view does not resurrect the ask.
    try certify(&env, 9, true);
    const targeted = env.recorder.targeted.items.len;
    try env.resolve(11, 6, .notarization, env.fixture.participants[0]);
    try testing.expectEqual(targeted, env.recorder.targeted.items.len);
}

test "resolver actor tombstoned notarization delivery retires without recording" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try certify(&env, 6, false);
    // The failed verdict settled this snapshot's ask: no verdict, no voter notification.
    const outcome = try env.deliver(6, .{ .notarization = try env.notarization(6) }, &.{
        .ancestry(.notarization),
    });
    try testing.expectEqual(null, outcome);
    try testing.expect(env.actor.state.uncertifiable(.new(6)));
    try testing.expectEqual(null, env.produce(6));
    try testing.expectEqual(0, env.voter.recovered_certificates.items.len);
    // Finalization is the tombstone's retirement boundary.
    try env.updated(try env.finalization(7));
    try testing.expect(!env.actor.state.uncertifiable(.new(6)));
}

test "resolver actor valid nullification does not complete a parent delivery" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    const outcome = try env.deliver(4, try env.nullification(3), &.{.ancestry(.notarization)});
    try testing.expectEqual(resolver.Outcome.unresolved, outcome.?);
}

test "resolver actor unrelated higher certified notarization does not complete a parent" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try certify(&env, 6, true);
    const outcome = try env.deliver(4, .{ .notarization = try env.notarization(6) }, &.{
        .ancestry(.notarization),
    });
    try testing.expectEqual(resolver.Outcome.unresolved, outcome.?);
}

test "resolver actor higher notarization does not complete a backfill delivery" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    // A peer's higher floor covers nothing at the requested view.
    const outcome = try env.deliver(4, .{ .notarization = try env.notarization(6) }, &.{
        .backfill(),
    });
    try testing.expectEqual(resolver.Outcome.unresolved, outcome.?);
}

test "resolver actor already certified notarization delivery retires the snapshot" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try certify(&env, 6, true);
    // A second valid aggregate for the same proposal from a different signer subset.
    // Certification belongs to the proposal, not to one encoding of its certificate.
    const Notarize = types.Notarize(Scheme, Digest);
    var votes: [3]Notarize = undefined;
    for (&votes, env.fixture.schemes[0..3]) |*vote, *scheme| {
        vote.* = (try Notarize.sign(gpa, scheme, build_proposal(6))).?;
    }
    const verifier = &env.fixture.verifier;
    const alternate = try Notarization.from_votes(gpa, verifier, &votes, sequential);
    const outcome = try env.deliver(6, .{ .notarization = alternate }, &.{
        .ancestry(.notarization),
    });
    try testing.expectEqual(null, outcome);
    try testing.expect(!env.settled(6, .nullification));
}

test "resolver actor finalization completes every delivery ask" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    const outcome = try env.deliver(4, try env.finalization(6), &.{
        .backfill(), .ancestry(.nullification), .ancestry(.notarization),
    });
    try testing.expectEqual(complete, outcome.?);
}

test "resolver actor mixed delivery credits only newly settled asks" {
    inline for (.{ Kind.nullification, Kind.notarization }) |kind| {
        var env: Env = undefined;
        try env.start();
        defer env.stop();
        // Coalesce backfill and both ancestry kinds under one key.
        const asks: []const Ask = &.{
            .backfill(), .ancestry(.nullification), .ancestry(.notarization),
        };
        for (asks) |item| _ = try env.recorder.fetch(.{ .key = .init(4), .subscriber = item });
        // The first response earns credit; replaying the snapshot settles nothing new.
        for ([_]resolver.Outcome{ partial, .unresolved }) |expected| {
            const certificate: Certificate = switch (kind) {
                .nullification => try env.nullification(4),
                .notarization => .{ .notarization = try env.notarization(4) },
            };
            try testing.expectEqual(expected, (try env.deliver(4, certificate, asks)).?);
        }
        try testing.expect(env.settled(4, kind));
        // Nullification satisfies backfill and nullification ancestry; notarization only
        // notarization ancestry.
        try expect_subscriptions(&env, 4, switch (kind) {
            .nullification => &.{.ancestry(.notarization)},
            .notarization => &.{ .backfill(), .ancestry(.nullification) },
        });
    }
}

test "resolver actor stale delivery records new evidence without credit" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    // Settle the notarization ask at 4, keeping a nullification ask outstanding there.
    try env.updated(.{ .notarization = try env.notarization(4) });
    const higher = consensus_types.View.new(4).next_term_start(term_length).get();
    try env.resolve(higher, 4, .nullification, null);
    // The stale snapshot's later certificate is still useful evidence.
    const expected = try encoded(.{ .notarization = try env.notarization(higher) });
    defer gpa.free(expected);
    const outcome = try env.deliver(4, .{ .notarization = try env.notarization(higher) }, &.{
        .ancestry(.notarization),
    });
    // No scoring verdict, and the nullification subscriber stays attached to the key.
    try testing.expectEqual(null, outcome);
    try testing.expect(!env.settled(4, .nullification));
    try expect_subscriptions(&env, 4, &.{.ancestry(.nullification)});
    // The evidence reaches both the resolver state and the voter.
    try testing.expect(env.settled(higher, .notarization));
    try testing.expectEqual(1, env.voter.recovered_certificates.items.len);
    try testing.expectEqualSlices(u8, expected, env.voter.recovered_certificates.items[0]);
}

test "resolver actor settled key ignores a delivery without validation" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    const expected = try encoded(try env.finalization(6));
    defer gpa.free(expected);
    try env.updated(try env.finalization(6));
    try testing.expect(env.settled(4, .nullification));
    try testing.expect(env.settled(4, .notarization));
    // Garbage queued before local settlement is ignored without decoding or penalty.
    const outcome = try env.deliver_bytes(4, try gpa.dupe(u8, "unverifiable"), &.{
        .backfill(), .ancestry(.nullification), .ancestry(.notarization),
    });
    try testing.expectEqual(resolver.Outcome.ignored, outcome.?);
    try testing.expect(!env.settled(7, .nullification));
    try testing.expectEqualSlices(u8, expected, env.produce(6).?);
    try testing.expectEqual(0, env.voter.recovered_certificates.items.len);
}

test "resolver actor nullification-only settled key still validates a delivery" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try env.updated(try env.nullification(4));
    try testing.expect(env.settled(4, .nullification));
    try testing.expect(!env.settled(4, .notarization));
    const data = try gpa.dupe(u8, "unverifiable");
    const outcome = try env.deliver_bytes(4, data, &.{.ancestry(.nullification)});
    try testing.expectEqual(resolver.Outcome.invalid, outcome.?);
}

test "resolver actor notarization-only settled key still validates a delivery" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try env.updated(.{ .notarization = try env.notarization(4) });
    try testing.expect(!env.settled(4, .nullification));
    try testing.expect(env.settled(4, .notarization));
    const data = try gpa.dupe(u8, "unverifiable");
    const outcome = try env.deliver_bytes(4, data, &.{.ancestry(.notarization)});
    try testing.expectEqual(resolver.Outcome.invalid, outcome.?);
}

test "resolver actor validate accepts a nullification covering the view in its term" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try testing.expect(consensus_types.View.new(6).same_term(.new(10), term_length));
    try testing.expectEqual(6, (try env.validate(10, try env.nullification(6))).?);
}

test "resolver actor validate rejects a nullification from a different term" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try testing.expectEqual(null, try env.validate(11, try env.nullification(10)));
}

test "resolver actor validate rejects a nullification above the requested view" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try testing.expectEqual(null, try env.validate(8, try env.nullification(9)));
}

test "resolver actor failed verdict survives a higher certified floor" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try certify(&env, 7, false);
    try certify(&env, 9, true);
    // The tombstone survives the higher floor, which is served in place of view 7.
    try testing.expect(env.actor.state.uncertifiable(.new(7)));
    const floor = try encoded(.{ .notarization = try env.notarization(9) });
    defer gpa.free(floor);
    try testing.expectEqualSlices(u8, floor, env.produce(7).?);
    // Failed certification does not make signed protocol evidence invalid.
    const evidence: Certificate = .{ .notarization = try env.notarization(7) };
    try testing.expectEqual(7, (try env.validate(7, evidence)).?);
}

test "resolver actor validate rejects a finalization from a different epoch" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    try testing.expectEqual(null, try env.validate(7, try env.finalization_in(.new(10), 7)));
}

// zigware-only: commonware has no case for this rejection, and a plant that lets lower
// notarizations through survived every ported test.
test "resolver actor validate rejects a notarization below the requested view" {
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    const below: Certificate = .{ .notarization = try env.notarization(5) };
    try testing.expectEqual(null, try env.validate(6, below));
    const exact: Certificate = .{ .notarization = try env.notarization(6) };
    try testing.expectEqual(6, (try env.validate(6, exact)).?);
}

test "resolver actor validates a delivery inside its deliver span" {
    const traces = @import("runtime").telemetry.traces;
    var collector = traces.Collector.init(gpa, .{});
    defer collector.deinit();
    var subscriber = collector.subscriber();
    subscriber.level = .debug;
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    env.actor.tracer = .init(subscriber, "commonware_consensus::simplex::actors::resolver");
    const outcome = try env.deliver(3, .{ .notarization = try env.notarization(3) }, &.{
        .ancestry(.notarization),
    });
    try testing.expectEqual(complete, outcome.?);
    const spans = struct {
        fn nested(_: void, event: traces.collector.RecordedEvent) bool {
            const message = "received certificate for request";
            if (!std.mem.eql(u8, event.metadata.content, message)) return false;
            if (event.spans.len != 2) return false;
            return std.mem.eql(u8, event.spans[0].content, "simplex.resolver.validate") and
                std.mem.eql(u8, event.spans[1].content, "simplex.resolver.deliver");
        }
    };
    try collector.get_all().expect_event({}, spans.nested);
}

const Span = @import("runtime").telemetry.traces.Span;

// commonware `pr_5097_regression`: the resolver engine can release its handles to a fetch
// span after the actor checked the delivery is still wanted; the delivery then holds the
// only handle, and processing must still run under that span.
test "resolver actor processes a delivery under its fetch span (pr_5097_regression)" {
    const traces = @import("runtime").telemetry.traces;
    var collector = traces.Collector.init(gpa, .{});
    defer collector.deinit();
    var subscriber = collector.subscriber();
    subscriber.level = .debug;
    var env: Env = undefined;
    try env.start();
    defer env.stop();
    env.actor.tracer = .init(subscriber, "commonware_consensus::simplex::actors::resolver");
    const fetch = try gpa.create(Span);
    {
        // The fetch's tracer goes out of scope with its request; the span outlives it.
        const tracer: traces.Tracer = .init(subscriber, "test");
        fetch.* = tracer.span("test.fetch", .{});
    }
    const data = try encoded(.{ .notarization = try env.notarization(3) });
    _ = try env.deliver_spanned(3, data, &.{.ancestry(.notarization)}, fetch);
    const parented = struct {
        fn check(_: void, event: traces.collector.RecordedEvent) bool {
            for (0..event.spans.len -| 1) |index| {
                const inner = event.spans[index].content;
                const outer = event.spans[index + 1].content;
                if (std.mem.eql(u8, inner, "simplex.resolver.deliver") and
                    std.mem.eql(u8, outer, "test.fetch")) return true;
            }
            return false;
        }
    };
    try collector.get_all().expect_event({}, parented.check);
}
