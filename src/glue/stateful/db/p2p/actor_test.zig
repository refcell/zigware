//! commonware `glue/src/stateful/db/p2p/actor.rs` tests of the actor's handlers, driven
//! directly with a recording resolver (no engine), on a mock database.

const std = @import("std");
const testing = std.testing;
const actor_package = @import("actor");
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const resolver = @import("resolver");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("../mod.zig");
const actor_mod = @import("actor.zig");
const test_io = @import("../../test_io.zig");

const gpa = testing.allocator;
const sync = storage.qmdb.sync;
const mpsc = utils.channel.mpsc;
const oneshot = utils.channel.oneshot;
const metrics = runtime.telemetry.metrics;
const Family = storage.mmr.Family;
const Digest = cryptography.Sha256.Digest;
const PublicKey = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(PublicKey);
const Request = sync.Request(Family);
const Response = sync.Response(Family, u64, Digest);
const Produced = resolver.p2p.Produced;

/// A database serving one encoded response for requests at `size` (commonware's
/// `FeedbackSource` when `feedback` is set), failing every other request.
const MockDb = struct {
    encoded: []const u8,
    size: u64,
    feedback: ?sync.Feedback(Response) = null,

    pub const SyncSource = struct {
        pub const Family = storage.mmr.Family;
        pub const Op = u64;
        pub const Digest = cryptography.Sha256.Digest;
        pub const Error = error{RangeOutOfBounds} || codec.Error;

        database: *MockDb,

        pub fn serve(
            self: *SyncSource,
            allocator: std.mem.Allocator,
            request: Request,
        ) Error!sync.Served(Response) {
            if (request.size() != self.database.size) return error.RangeOutOfBounds;
            const cfg: Response.Cfg = .{ .max_ops = 16, .op = {} };
            const response = try codec.decode_cfg(Response, allocator, self.database.encoded, cfg);
            const feedback = self.database.feedback;
            self.database.feedback = null;
            return .{ .response = response, .feedback = feedback };
        }
    };

    pub fn sync_source(self: *MockDb) SyncSource {
        return .{ .database = self };
    }

    pub fn deinit(self: *MockDb) void {
        if (self.feedback) |*feedback| feedback.deinit();
        gpa.free(self.encoded);
    }
};

const TestActor = actor_mod.Actor(actor_mod.Params(
    PublicKey,
    Net.Manager,
    Net.Control,
    MockDb,
    Net.Sender,
    Net.Receiver,
));
const Subscriber = TestActor.Subscriber;
const Candidate = sync.source.Candidate(Response);

/// Records registrations and cancellations (commonware's `RecordingResolver`).
const Recording = struct {
    const Entry = struct { key: Request, id: u64 };

    fetches: std.ArrayList(Entry) = .empty,
    subscriptions: std.ArrayList(Entry) = .empty,
    retains: usize = 0,

    pub fn fetch(
        self: *Recording,
        item: resolver.Fetch(Request, Subscriber),
    ) !actor_package.Feedback {
        const entry: Entry = .{ .key = item.key, .id = item.subscriber.id };
        try self.fetches.append(gpa, entry);
        try self.subscriptions.append(gpa, entry);
        return .ok;
    }

    pub fn retain(
        self: *Recording,
        predicate: resolver.Predicate(Request, Subscriber),
    ) !actor_package.Feedback {
        self.retains += 1;
        var index: usize = 0;
        while (index < self.subscriptions.items.len) {
            const entry = self.subscriptions.items[index];
            if (predicate.call(entry.key, .{ .id = entry.id, .reply = {} })) {
                index += 1;
            } else _ = self.subscriptions.orderedRemove(index);
        }
        return .ok;
    }

    fn deinit(self: *Recording) void {
        self.fetches.deinit(gpa);
        self.subscriptions.deinit(gpa);
    }

    fn ids(self: *const Recording, buffer: []u64) []u64 {
        for (self.subscriptions.items, 0..) |entry, i| buffer[i] = entry.id;
        return buffer[0..self.subscriptions.items.len];
    }
};

/// An actor that is not running, with its registry.
const Fixture = struct {
    registry: metrics.Registry,
    actor: *TestActor,
    mailbox: TestActor.Mailbox,
    recording: Recording = .{},

    fn init(fixture: *Fixture, database: ?db.Shared(MockDb)) !void {
        fixture.* = .{ .registry = .init(gpa), .actor = undefined, .mailbox = undefined };
        errdefer fixture.registry.deinit();
        const scope = metrics.Scope.init(&fixture.registry).child("actor");
        const created = try TestActor.create(gpa, test_io.io, scope, test_config(database));
        fixture.actor = created.actor;
        fixture.mailbox = created.mailbox;
    }

    /// The subscription id of the `index`th fetch.
    fn id(fixture: *const Fixture, index: usize) u64 {
        return fixture.recording.fetches.items[index].id;
    }

    /// Hands the actor a fetch whose caller already left.
    fn get_operations_closed(fixture: *Fixture, request: Request) !void {
        var pair = try mpsc.channel(Candidate, gpa, test_io.io, 1);
        pair.receiver.deinit();
        try fixture.actor.handle_mailbox_message(&fixture.recording, .{ .get_operations = .{
            .request = request,
            .response = pair.sender,
        } });
    }

    fn deinit(fixture: *Fixture) void {
        fixture.mailbox.deinit();
        fixture.actor.destroy();
        fixture.recording.deinit();
        fixture.registry.deinit();
    }

    fn pending(fixture: *const Fixture) i64 {
        return fixture.actor.metrics.pending_requests.metric().get();
    }

    /// Registers a caller for `request` (commonware's `GetOperations` message); returns the
    /// caller's candidate receiver.
    fn get_operations(fixture: *Fixture, request: Request) !mpsc.Receiver(Candidate) {
        const pair = try mpsc.channel(Candidate, gpa, test_io.io, 1);
        try fixture.actor.handle_mailbox_message(&fixture.recording, .{ .get_operations = .{
            .request = request,
            .response = pair.sender,
        } });
        return pair.receiver;
    }

    /// Delivers `value` for `request` to subscriptions `ids`; returns the verdict receiver.
    fn deliver(
        fixture: *Fixture,
        request: Request,
        ids: []const u64,
        value: []const u8,
    ) !oneshot.Receiver(bool) {
        const subscribers = try gpa.alloc(Subscriber, ids.len);
        for (ids, subscribers) |sub_id, *subscriber| subscriber.* = .{ .id = sub_id, .reply = {} };
        const verdict = try oneshot.channel(bool, gpa, test_io.io);
        try fixture.actor.handle_deliver(.{
            .gpa = gpa,
            .delivery = .{ .key = request, .subscribers = subscribers },
            .value = try gpa.dupe(u8, value),
            .response = verdict.sender,
        });
        return verdict.receiver;
    }

    fn next_work(fixture: *Fixture) !void {
        try fixture.actor.next_work(&fixture.recording);
    }
};

fn test_config(database: ?db.Shared(MockDb)) TestActor.Cfg {
    return .{
        .peer_provider = undefined, // Unused: these actors never start.
        .blocker = undefined,
        .database = database,
        .mailbox_size = 16,
        .me = null,
        .fetch_timeout = .from_millis(10),
        .fetch_retry_delay = .from_millis(10),
        .max_serve_ops = 16,
        .priority_requests = false,
        .priority_responses = false,
    };
}

fn request_at(size: u64) Request {
    return .{ .operations = .{ .size = size, .start = 0, .max_ops = 1 } };
}

/// A decodable operations response for testing request/response shape checks.
fn encoded_payload(leaves: u64, operations: []const u64) ![]u8 {
    const response: Response = .{ .operations = .{
        .proof = .{ .leaves = leaves },
        .operations = @constCast(operations),
    } };
    return codec.encode(Response, gpa, response);
}

fn mock_db(size: u64, feedback: ?sync.Feedback(Response)) !db.Shared(MockDb) {
    const encoded = try encoded_payload(size, &.{ 7, 8 });
    return db.Shared(MockDb).init(gpa, test_io.io, "mock", .{
        .encoded = encoded,
        .size = size,
        .feedback = feedback,
    });
}

fn produce(fixture: *Fixture, request: Request) !oneshot.Receiver(Produced) {
    const pair = try oneshot.channel(Produced, gpa, test_io.io);
    try fixture.actor.handle_produce(request, pair.sender);
    return pair.receiver;
}

fn expect_closed(receiver: *oneshot.Receiver(Produced)) !void {
    defer receiver.deinit();
    try testing.expectError(error.Closed, receiver.recv());
}

/// Takes the caller's candidate, checks its encoding, and sends `verdict` (null abstains).
fn judge(candidates: *mpsc.Receiver(Candidate), expected: []const u8, verdict: ?bool) !void {
    var candidate = (try candidates.recv()).?;
    defer candidate.response.deinit(gpa);
    const encoded = try codec.encode(Response, gpa, candidate.response);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, expected, encoded);
    if (verdict) |valid| try candidate.verdict.send(valid) else candidate.verdict.deinit();
}

test "stateful p2p actor: produce is denied before attach" {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    // An unattached actor releases the peer request without waiting for a database.
    var response = try produce(&fixture, request_at(1));
    try expect_closed(&response);
    try testing.expectEqual(@as(u64, 1), fixture.actor.metrics.serve_requests.get(.dropped));
}

test "stateful p2p actor: the same request is served after attach" {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const database = try mock_db(3, null);
    defer database.deinit();
    try fixture.actor.handle_mailbox_message(&fixture.recording, .{ .attach_database = database });
    try testing.expectEqual(@as(i64, 1), fixture.actor.metrics.has_database.metric().get());
    var response = try produce(&fixture, request_at(3));
    defer response.deinit();
    const produced = try response.recv();
    defer produced.deinit();
    try testing.expectEqualSlices(u8, database.cell.database.?.encoded, produced.bytes);
    try fixture.next_work();
    try testing.expectEqual(@as(u64, 1), fixture.actor.metrics.serve_requests.get(.success));
}

test "stateful p2p actor: produce drops source feedback without judging" {
    var verdict = try oneshot.channel(bool, gpa, test_io.io);
    defer verdict.receiver.deinit();
    var candidates = try mpsc.channel(Candidate, gpa, test_io.io, 1);
    defer candidates.sender.deinit();
    const database = try mock_db(3, .init(verdict.sender, candidates.receiver));
    defer database.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(database);
    defer fixture.deinit();
    var response = try produce(&fixture, request_at(3));
    defer response.deinit();
    const produced = try response.recv();
    defer produced.deinit();
    try testing.expectEqualSlices(u8, database.cell.database.?.encoded, produced.bytes);
    try testing.expectError(error.Closed, verdict.receiver.recv());
    try fixture.next_work();
}

test "stateful p2p actor: produce rejects a request above max_serve_ops" {
    const database = try mock_db(3, null);
    defer database.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(database);
    defer fixture.deinit();
    // Oversized requests release their response before starting a read.
    const oversized: Request = .{ .operations = .{ .size = 3, .start = 0, .max_ops = 1000 } };
    var response = try produce(&fixture, oversized);
    try expect_closed(&response);
    try testing.expectEqual(@as(u64, 1), fixture.actor.metrics.serve_requests.get(.dropped));
    try testing.expectEqual(@as(u64, 0), fixture.actor.metrics.serve_requests.get(.success));
}

test "stateful p2p actor: concurrent serves complete once the database is available" {
    try test_io.run_on_deterministic(concurrent_serves_complete);
}

fn concurrent_serves_complete() anyerror!void {
    // commonware `concurrent_serves_complete_after_database_is_available`.
    const database = try mock_db(3, null);
    defer database.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(database);
    defer fixture.deinit();
    // Hold the database so the second request arrives while the first read is pending.
    var slot = try database.write();
    const requests = [2]Request{
        request_at(3),
        .{ .operations = .{ .size = 3, .start = 0, .max_ops = 2 } },
    };
    var responses: [2]oneshot.Receiver(Produced) = undefined;
    for (requests, &responses) |request, *response| response.* = try produce(&fixture, request);
    defer for (&responses) |*response| response.deinit();
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    // Restore access before asserting, so a failure cannot leave the reads blocked.
    // A reply that arrived or was dropped means a pending read blocked another serve.
    var replies_pending = true;
    for (&responses) |*response| {
        if (response.try_recv()) |produced| {
            produced.deinit();
            replies_pending = false;
        } else |err| replies_pending = replies_pending and err == error.Empty;
    }
    slot.put();
    try testing.expect(replies_pending);
    for (requests) |_| try fixture.next_work();
    for (&responses) |*response| {
        const produced = try response.recv();
        defer produced.deinit();
        try testing.expectEqualSlices(u8, database.cell.database.?.encoded, produced.bytes);
    }
    try testing.expectEqual(@as(u64, 2), fixture.actor.metrics.serve_requests.get(.success));
}

test "stateful p2p actor: a failed serve does not block another request" {
    const database = try mock_db(3, null);
    defer database.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(database);
    defer fixture.deinit();
    // Queue an unavailable history beside a request the database can serve.
    var failed = try produce(&fixture, request_at(4));
    var served = try produce(&fixture, request_at(3));
    defer served.deinit();
    for (0..2) |_| try fixture.next_work();
    try expect_closed(&failed);
    const produced = try served.recv();
    defer produced.deinit();
    try testing.expectEqualSlices(u8, database.cell.database.?.encoded, produced.bytes);
    const serves = fixture.actor.metrics.serve_requests;
    try testing.expectEqual(@as(u64, 1), serves.get(.failure));
    try testing.expectEqual(@as(u64, 1), serves.get(.success));
}

test "stateful p2p actor: get_operations registers each caller and cancels exact ids" {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request = request_at(1);
    // A delayed close waiter must preserve a fresh caller for the same key.
    var old = try fixture.get_operations(request);
    const old_id = fixture.id(0);
    old.deinit();
    var fresh = try fixture.get_operations(request);
    const fresh_id = fixture.id(1);
    try testing.expect(fresh_id != old_id);
    try fixture.next_work();
    var buffer: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 2), fixture.recording.fetches.items.len);
    try testing.expectEqual(@as(usize, 1), fixture.recording.retains);
    try testing.expectEqualSlices(u64, &.{fresh_id}, fixture.recording.ids(&buffer));
    try testing.expectEqual(@as(i64, 1), fixture.pending());

    fresh.deinit();
    try fixture.next_work();
    try testing.expectEqual(@as(usize, 2), fixture.recording.retains);
    try testing.expectEqual(@as(usize, 0), fixture.recording.subscriptions.items.len);
    try testing.expectEqual(@as(i64, 0), fixture.pending());
}

test "stateful p2p actor: completed request cleanup preserves a new subscriber" {
    // commonware `completed_request_cleanup_preserves_new_subscriber`.
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request = request_at(1);
    var completed = try fixture.get_operations(request);
    const payload = try encoded_payload(0, &.{});
    defer gpa.free(payload);
    var verdict = try fixture.deliver(request, &.{fixture.id(0)}, payload);
    defer verdict.deinit();
    try judge(&completed, payload, true);
    try testing.expect(try verdict.recv());
    // Accepting ends the caller's fetch, and the resolver retires the old subscription
    // before a new caller arrives.
    completed.deinit();
    fixture.recording.subscriptions.clearRetainingCapacity();
    var fresh = try fixture.get_operations(request);
    // The delayed cleanup of the completed request preserves the new subscription.
    try fixture.next_work();
    var buffer: [4]u64 = undefined;
    try testing.expectEqualSlices(u64, &.{fixture.id(1)}, fixture.recording.ids(&buffer));
    try testing.expectEqual(@as(i64, 1), fixture.pending());
    fresh.deinit();
    try fixture.next_work();
    try testing.expectEqual(@as(usize, 0), fixture.recording.subscriptions.items.len);
    try testing.expectEqual(@as(i64, 0), fixture.pending());
}

test "stateful p2p actor: a canceled mailbox request is skipped before registration" {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    try fixture.get_operations_closed(request_at(1));
    try testing.expectEqual(@as(usize, 0), fixture.recording.fetches.items.len);
    try testing.expectEqual(@as(i64, 0), fixture.pending());
}

test "stateful p2p actor: partial caller cancellation preserves the live subscriber" {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request = request_at(1);
    var canceled = try fixture.get_operations(request);
    var live = try fixture.get_operations(request);
    defer live.deinit();
    const ids = [2]u64{ fixture.id(0), fixture.id(1) };

    // The delivery still names a caller whose receiver has closed.
    canceled.deinit();
    try fixture.next_work();
    var buffer: [4]u64 = undefined;
    try testing.expectEqualSlices(u64, ids[1..], fixture.recording.ids(&buffer));
    try testing.expectEqual(@as(i64, 1), fixture.pending());

    const payload = try encoded_payload(0, &.{});
    defer gpa.free(payload);
    var verdict = try fixture.deliver(request, &ids, payload);
    defer verdict.deinit();
    try judge(&live, payload, true);
    // A singleton verdict reaches the resolver without glue work.
    try testing.expect(try verdict.recv());
}

test "stateful p2p actor: request id exhaustion precedes submission" {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request = request_at(1);
    var existing = try fixture.get_operations(request);
    defer existing.deinit();
    const existing_id = fixture.id(0);
    fixture.actor.next_id = std.math.maxInt(u64);
    var pair = try mpsc.channel(Candidate, gpa, test_io.io, 1);
    defer pair.receiver.deinit();
    // Exhaustion fails before resolver submission can reuse an id.
    const result = fixture.actor.handle_mailbox_message(&fixture.recording, .{
        .get_operations = .{ .request = request, .response = pair.sender },
    });
    try testing.expectError(error.RequestIdOverflow, result);
    try testing.expectEqual(@as(?Candidate, null), try pair.receiver.recv());
    try testing.expectEqual(@as(usize, 1), fixture.recording.fetches.items.len);
    try testing.expectEqual(existing_id, fixture.id(0));
    try testing.expectEqual(@as(i64, 1), fixture.pending());
}

test "stateful p2p actor: a malformed or mismatched delivery preserves the waiting caller" {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request: Request = .{ .boundary = .{ .size = 1, .start = 0 } };
    var receiver = try fixture.get_operations(request);
    defer receiver.deinit();
    const id = fixture.id(0);
    const mismatched = try encoded_payload(0, &.{});
    defer gpa.free(mismatched);
    // Both failures judge the original subscription and leave its caller waiting.
    for ([_][]const u8{ "malformed-response", mismatched }) |payload| {
        var verdict = try fixture.deliver(request, &.{id}, payload);
        defer verdict.deinit();
        try testing.expect(!try verdict.recv());
        try testing.expectEqual(@as(usize, 1), fixture.recording.subscriptions.items.len);
        try testing.expectError(error.Empty, receiver.try_recv());
    }
    try testing.expectEqual(@as(u64, 2), fixture.actor.metrics.deliveries.get(.invalid));
}

test "stateful p2p actor: a stale delivery cannot drain a reopened request" {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request = request_at(1);
    var old = try fixture.get_operations(request);
    const old_id = fixture.id(0);
    old.deinit();
    try fixture.next_work();
    var fresh = try fixture.get_operations(request);
    defer fresh.deinit();
    var later = try fixture.get_operations(request);
    defer later.deinit();
    const fresh_id = fixture.id(1);
    const later_id = fixture.id(2);
    try testing.expect(fresh_id > old_id);

    // A stale malformed delivery cannot consume either replacement's channel.
    var stale = try fixture.deliver(request, &.{old_id}, "");
    defer stale.deinit();
    try testing.expectError(error.Closed, stale.recv());
    try testing.expectError(error.Empty, fresh.try_recv());

    // A captured snapshot reaches only its named recipient.
    const payload = try encoded_payload(0, &.{});
    defer gpa.free(payload);
    var verdict = try fixture.deliver(request, &.{fresh_id}, payload);
    defer verdict.deinit();
    try judge(&fresh, payload, true);
    try testing.expect(try verdict.recv());
    try testing.expectError(error.Empty, later.try_recv());
    var later_verdict = try fixture.deliver(request, &.{later_id}, payload);
    defer later_verdict.deinit();
    try judge(&later, payload, true);
    try testing.expect(try later_verdict.recv());
}

test "stateful p2p actor: a delivery without a live recipient is unjudged" {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request = request_at(1);
    var receiver = try fixture.get_operations(request);
    const id = fixture.id(0);
    receiver.deinit();
    const payload = try encoded_payload(0, &.{});
    defer gpa.free(payload);
    var verdict = try fixture.deliver(request, &.{id}, payload);
    defer verdict.deinit();
    try testing.expectError(error.Closed, verdict.recv());
    try fixture.next_work();
    try testing.expectEqual(@as(usize, 0), fixture.recording.subscriptions.items.len);
    try testing.expectEqual(@as(u64, 1), fixture.actor.metrics.deliveries.get(.dropped));
}

/// Fans one delivery out to two callers who judge it with `verdicts`; returns the verdict
/// the resolver receives (null when unjudged).
fn fan_out(verdicts: [2]?bool) !?bool {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request = request_at(1);
    var callers = [2]mpsc.Receiver(Candidate){
        try fixture.get_operations(request),
        try fixture.get_operations(request),
    };
    defer for (&callers) |*caller| caller.deinit();
    const ids = [2]u64{ fixture.id(0), fixture.id(1) };
    const payload = try encoded_payload(0, &.{});
    defer gpa.free(payload);
    var verdict = try fixture.deliver(request, &ids, payload);
    defer verdict.deinit();
    // The second caller judges first: the verdict still follows subscriber order.
    try judge(&callers[1], payload, verdicts[1]);
    try judge(&callers[0], payload, verdicts[0]);
    return verdict.recv() catch |err| switch (err) {
        error.Closed => null,
        else => err,
    };
}

test "stateful p2p actor: a fan-out applies the first verdict in subscriber order" {
    try testing.expectEqual(@as(?bool, true), try fan_out(.{ true, false }));
    try testing.expectEqual(@as(?bool, false), try fan_out(.{ false, true }));
    // A caller that drops its verdict abstains.
    try testing.expectEqual(@as(?bool, true), try fan_out(.{ null, true }));
}

test "stateful p2p actor: an abandoned fan-out is unjudged and retracts every subscriber" {
    try test_io.run_on_deterministic(abandoned_fan_out_retracts);
}

fn abandoned_fan_out_retracts() anyerror!void {
    try testing.expectEqual(@as(?bool, null), try fan_out(.{ null, null }));
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request = request_at(1);
    var first = try fixture.get_operations(request);
    var second = try fixture.get_operations(request);
    const ids = [2]u64{ fixture.id(0), fixture.id(1) };
    const payload = try encoded_payload(0, &.{});
    defer gpa.free(payload);
    var verdict = try fixture.deliver(request, &ids, payload);
    defer verdict.deinit();
    first.deinit();
    second.deinit();
    try testing.expectError(error.Closed, verdict.recv());
    while (fixture.pending() != 0) try fixture.next_work();
    try testing.expectEqual(@as(usize, 0), fixture.recording.subscriptions.items.len);
}

/// commonware `fanout_waits_for_slow_receipt_and_preserves_other_demand_on_cancel` with
/// caller `rejecting` judging first.
fn check_slow_receipt(rejecting: usize) !void {
    var fixture: Fixture = undefined;
    try fixture.init(null);
    defer fixture.deinit();
    const request = request_at(1);
    var callers = [2]?mpsc.Receiver(Candidate){
        try fixture.get_operations(request),
        try fixture.get_operations(request),
    };
    defer for (&callers) |*caller| if (caller.*) |*receiver| receiver.deinit();
    const slow = 1 - rejecting;
    const payload = try encoded_payload(0, &.{});
    defer gpa.free(payload);
    var verdict = try fixture.deliver(request, &.{ fixture.id(0), fixture.id(1) }, payload);
    defer verdict.deinit();

    // One caller rejects; the verdict waits until the slow caller took its candidate.
    try judge(&callers[rejecting].?, payload, false);
    try test_io.io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectError(error.Empty, verdict.try_recv());

    // The rejecting caller leaves while the slow candidate is still queued. A fresh
    // registration survives both the old closure and the verdict.
    callers[rejecting].?.deinit();
    callers[rejecting] = null;
    try fixture.next_work();
    var fresh = try fixture.get_operations(request);
    defer fresh.deinit();
    try judge(&callers[slow].?, payload, false);
    try testing.expect(!try verdict.recv());
    var buffer: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 3), fixture.recording.fetches.items.len);
    const expected = [2]u64{ fixture.id(slow), fixture.id(2) };
    try testing.expectEqualSlices(u64, &expected, fixture.recording.ids(&buffer));

    // Both survivors take the retry without registering again.
    var retry = try fixture.deliver(request, &expected, payload);
    defer retry.deinit();
    try judge(&callers[slow].?, payload, true);
    try judge(&fresh, payload, true);
    try testing.expect(try retry.recv());
    try testing.expectEqual(@as(usize, 3), fixture.recording.fetches.items.len);
}

test "stateful p2p actor: a fan-out waits for a slow receipt and keeps other demand" {
    try check_slow_receipt(0);
    try check_slow_receipt(1);
}
