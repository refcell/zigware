//! Tests of commonware's `glue::dkg::reshare::actor::inclusion` (`mod tests`): the
//! pending-log scan, the request queue, verification retention, and the future-participant
//! check. The tests that drive a whole inclusion window land with the actor.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const mocks = @import("../../tests/mocks.zig");
const inclusion = @import("inclusion.zig");

const Height = consensus.Height;
const PrivateKey = mocks.TestSigner;
const P = mocks.TestPublicKey;
const V = mocks.TestBlsVariant;
const B = mocks.TestBlock;
const Set = utils.ordered.Set(P);
const N3f1 = utils.N3f1;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Summary = cryptography.transcript.Summary;
const Digested = broadcast.Digested(B);
const Bounded = consensus.marshal.ancestry.Bounded(B);
const Logs = inclusion.PendingLogs(V, P);
const Scan = inclusion.PendingLogScan(V, P, mocks.TestDigest);
const oneshot = utils.channel.oneshot;
const gpa = testing.allocator;
const namespace = "_COMMONWARE_GLUE_DKG_RESHARE_INCLUSION_TEST";

fn signers() [4]PrivateKey {
    var keys: [4]PrivateKey = undefined;
    for (&keys, 0..) |*key, seed| key.* = .from_seed(seed);
    return keys;
}

fn players() !Set {
    var keys: [4]P = undefined;
    for (&keys, signers()) |*key, signer| key.* = signer.public_key();
    return Set.from_dedup(gpa, &keys);
}

fn info() !fd.Info(V, P) {
    const mode = .non_zero_counter;
    const dealers = try players();
    return fd.Info(V, P).init(N3f1, gpa, namespace, 0, null, mode, .v1, dealers, try players());
}

fn epocher(length: u64) consensus.types.FixedEpocher {
    return .new(utils.NonZero(u64).init(length).?);
}

const Tip = @import("setup.zig").FinalizedTip(mocks.TestDigest);

fn scan(round: *const fd.Info(V, P), tip: ?Tip) Scan {
    return .{
        .epoch = .zero(),
        .info = round,
        .epocher = epocher(8),
        .finalized_tip = tip,
        .final_height = .new(7),
    };
}

fn block(parent: mocks.TestDigest, height: u64, timestamp: u64) B {
    const genesis = mocks.genesis_block(signers()[0].public_key());
    return .init(genesis.context(), parent, .new(height), timestamp);
}

fn genesis_digest() mocks.TestDigest {
    return mocks.genesis_block(signers()[0].public_key()).digest();
}

fn ready(value: B) !Digested {
    return Digested.precomputed(gpa, value, value.digest());
}

/// An ancestry yielding `blocks` (newest first).
fn ancestry_of(blocks: []const B) !Bounded {
    var handles: [4]Digested = undefined;
    for (blocks, handles[0..blocks.len]) |value, *handle| handle.* = try ready(value);
    return consensus.marshal.ancestry.from_iter(B, gpa, handles[0..blocks.len]);
}

fn scan_blocks(scan_value: Scan, blocks: []const B) !?Logs {
    var stream = try ancestry_of(blocks);
    defer stream.deinit();
    return inclusion.pending_logs(B, gpa, scan_value, &stream);
}

/// The signed log of `signers()[index]`'s dealer for epoch zero, seeded with `seed`.
fn signed_log(index: usize, seed: u8) !fd.SignedDealerLog(V, P) {
    var harness = try mocks.StoreHarness.init(gpa);
    defer harness.deinit();
    var secrets: mocks.MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try harness.open(gpa, "inclusion-dealer-log", &secrets);
    defer store.deinit();
    var round = try info();
    defer round.deinit(gpa);
    const summary: Summary = .{ .bytes = @splat(seed) };
    const signer = signers()[index];
    const epoch: consensus.Epoch = .zero();
    const created = try store.create_dealer(N3f1, PrivateKey, epoch, signer, &round, null, summary);
    var dealer = created.?;
    defer dealer.deinit();
    try testing.expect(try dealer.finalize(N3f1));
    return dealer.finalized.?.clone(gpa);
}

pub fn dealer_logs(index: usize) !Logs {
    var signed = try signed_log(index, 2);
    defer signed.deinit(gpa);
    var logs: Logs = .empty;
    errdefer logs.deinit(gpa);
    try testing.expect(try logs.put_first(gpa, signed.dealer, try signed.log.clone(gpa)));
    return logs;
}

// commonware `future_participants_rejects_empty_provider_set` and
// `future_participants_rejects_oversized_provider_set` (panics there, errors here).
test "inclusion: future participants must be non-empty and bounded" {
    var all = try players();
    defer all.deinit(gpa);
    var none = try Set.from_dedup(gpa, &.{});
    defer none.deinit(gpa);
    const validate = inclusion.validate_future_participants;
    try testing.expectError(error.EmptyFutureParticipants, validate(none, 4));
    try testing.expectError(error.OversizedFutureParticipants, validate(all, 3));
    try validate(all, 4);
}

// commonware `pending_logs_rejects_ancestry_truncated_before_inclusion_start`.
test "inclusion: a scan rejects ancestry truncated before the inclusion window" {
    var round = try info();
    defer round.deinit(gpa);
    const four = block(genesis_digest(), 4, 4);
    const five = block(four.digest(), 5, 5);
    const six = block(five.digest(), 6, 6);
    try testing.expect(try scan_blocks(scan(&round, null), &.{ six, five }) == null);
}

// commonware `pending_logs_stop_at_the_first_unfinalized_block`: blocks at or below the
// finalized tip are never read.
test "inclusion: a scan stops at the first unfinalized block" {
    var round = try info();
    defer round.deinit(gpa);
    const four = block(genesis_digest(), 4, 4);
    const five = block(four.digest(), 5, 5);
    const six = block(five.digest(), 6, 6);
    var stream = try ancestry_of(&.{ six, five, four });
    defer stream.deinit();
    const tip: Tip = .{ .height = Height.new(4), .digest = four.digest() };
    var logs = (try inclusion.pending_logs(B, gpa, scan(&round, tip), &stream)).?;
    defer logs.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), logs.len());
    try testing.expect(stream.peek().?.digest().eql(four.digest()));
}

// commonware `pending_logs_authenticates_a_fully_finalized_parent`: when the final block's
// parent is the finalized tip, the scan accepts ancestry that starts at that parent
// (proposal) or at the final block (verification), and rejects a conflicting parent.
test "inclusion: a scan authenticates a fully finalized parent" {
    var round = try info();
    defer round.deinit(gpa);
    const canonical = block(genesis_digest(), 6, 6);
    const candidate = block(canonical.digest(), 7, 7);
    const detached = block(genesis_digest(), 6, 7);
    try testing.expect(!canonical.digest().eql(detached.digest()));
    const tip: Tip = .{ .height = Height.new(6), .digest = canonical.digest() };
    var proposal = (try scan_blocks(scan(&round, tip), &.{canonical})).?;
    defer proposal.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), proposal.len());
    var verification = (try scan_blocks(scan(&round, tip), &.{ candidate, canonical })).?;
    defer verification.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), verification.len());
    try testing.expect(try scan_blocks(scan(&round, tip), &.{detached}) == null);
}

// commonware `pending_logs_rejects_view_detached_by_finalization`.
test "inclusion: a scan rejects a view detached by finalization" {
    var round = try info();
    defer round.deinit(gpa);
    const canonical_four = block(genesis_digest(), 4, 4);
    const losing_four = block(genesis_digest(), 4, 5);
    try testing.expect(!canonical_four.digest().eql(losing_four.digest()));
    const five = block(losing_four.digest(), 5, 6);
    const six = block(five.digest(), 6, 7);
    const tip: Tip = .{ .height = Height.new(4), .digest = canonical_four.digest() };
    try testing.expect(try scan_blocks(scan(&round, tip), &.{ six, five }) == null);
}

// Each dealer's earliest valid log wins, as in the journal: a scan reads blocks newest first
// but authenticates them in chain order.
test "inclusion: a scan keeps each dealer's earliest log" {
    var round = try info();
    defer round.deinit(gpa);
    var earlier = try signed_log(0, 2);
    defer earlier.deinit(gpa);
    var later = try signed_log(0, 3);
    defer later.deinit(gpa);
    try testing.expect(!earlier.log.eql(later.log));
    const four = block(genesis_digest(), 4, 4);
    // The stream's handles own the blocks' encoded payloads.
    const five = try block(four.digest(), 5, 5).with_payload(gpa, 16, .{ .dealer_log = earlier });
    const six = try block(five.digest(), 6, 6).with_payload(gpa, 16, .{ .dealer_log = later });
    // Without a finalized tip, the scan covers heights from the midpoint (4) up.
    var stream = try ancestry_of(&.{ six, five, four });
    defer stream.deinit();
    var logs = (try inclusion.pending_logs(B, gpa, scan(&round, null), &stream)).?;
    defer logs.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), logs.len());
    try testing.expect(logs.entries.items[0].key.eql(earlier.dealer));
    try testing.expect(logs.entries.items[0].log.eql(earlier.log));
}

/// An ancestry whose next block never arrives.
const StalledAncestry = struct {
    pub const Block = B;
    receiver: oneshot.Receiver(void),

    pub fn peek(_: *const StalledAncestry) ?*const Digested {
        return null;
    }

    pub fn next(self: *StalledAncestry) Io.Cancelable!?Digested {
        self.receiver.recv() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => return null,
        };
        return null;
    }
};

fn scan_stalled(round: *const fd.Info(V, P), stream: *StalledAncestry) !?Logs {
    return inclusion.pending_logs(B, gpa, scan(round, null), stream);
}

// commonware `pending_logs_cancels_stalled_ancestry_when_runtime_stops`: here canceling the
// scan's task ends it.
test "inclusion: canceling a scan ends a stalled ancestry read" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try (try runner.start(struct {
        fn body(io: Io) anyerror!void {
            var round = try info();
            defer round.deinit(gpa);
            var pair = try oneshot.channel(void, gpa, io);
            defer pair.sender.deinit();
            var stream: StalledAncestry = .{ .receiver = pair.receiver };
            defer stream.receiver.deinit();
            var task = try io.concurrent(scan_stalled, .{ &round, &stream });
            try io.sleep(.fromMilliseconds(10), .awake);
            try testing.expectError(error.Canceled, task.cancel(io));
        }
    }.body, .{runner.io()}));
}

fn verified(logs: Logs) !inclusion.VerifiedLogs(V, P) {
    return .{ .logs = try logs.clone(gpa), .ceremony = null };
}

// commonware `verification_retains_completed_result_for_exact_reuse`.
test "inclusion: verification retains a completed result for exact reuse" {
    var completed = try dealer_logs(0);
    defer completed.deinit(gpa);
    var canonical = try dealer_logs(1);
    defer canonical.deinit(gpa);
    var verification: inclusion.Verification(V, P) = .empty;
    defer verification.deinit(gpa);
    verification.retain(gpa, try verified(completed), canonical);
    try testing.expect(verification.ready(completed) != null);
    try testing.expect(verification.ready(canonical) == null);
}

// commonware `verification_retains_canonical_result_over_speculative_completion`.
test "inclusion: verification keeps the canonical result over a speculative one" {
    var canonical = try dealer_logs(0);
    defer canonical.deinit(gpa);
    var speculative = try dealer_logs(1);
    defer speculative.deinit(gpa);
    var verification: inclusion.Verification(V, P) = .empty;
    defer verification.deinit(gpa);
    verification.retain(gpa, try verified(canonical), canonical);
    verification.retain(gpa, try verified(speculative), canonical);
    try testing.expect(verification.ready(canonical) != null);
    try testing.expect(verification.ready(speculative) == null);
}

const Requests = inclusion.ArtifactRequests(Bounded, u8);

fn request(sender: oneshot.Sender(u8)) !Requests.Request {
    return .{ .ancestry = try ancestry_of(&.{}), .response = sender };
}

// commonware `canceled_request_is_not_selected`.
test "inclusion: a canceled request is not selected" {
    var requests: Requests = .empty;
    defer requests.deinit(gpa);
    var pair = try oneshot.channel(u8, gpa, testing.io);
    try testing.expect(try requests.push(gpa, try request(pair.sender)));
    pair.receiver.deinit();
    try testing.expect(requests.pop() == null);
}

// commonware `requests_are_selected_in_arrival_order`.
test "inclusion: requests are selected in arrival order" {
    var requests: Requests = .empty;
    defer requests.deinit(gpa);
    var earlier = try oneshot.channel(u8, gpa, testing.io);
    defer earlier.receiver.deinit();
    var later = try oneshot.channel(u8, gpa, testing.io);
    defer later.receiver.deinit();
    try testing.expect(try requests.push(gpa, try request(earlier.sender)));
    try testing.expect(try requests.push(gpa, try request(later.sender)));
    for ([_]u8{ 1, 2 }) |value| {
        var selected = requests.pop().?;
        selected.ancestry.deinit();
        try selected.response.send(value);
    }
    try testing.expectEqual(@as(u8, 1), try earlier.receiver.try_recv());
    try testing.expectEqual(@as(u8, 2), try later.receiver.try_recv());
    try testing.expect(requests.pop() == null);
}
