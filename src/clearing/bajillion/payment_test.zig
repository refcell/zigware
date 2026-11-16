//! Tests of `payment.zig` (commonware `bajillion/payment.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const payment = @import("payment.zig");
const matrix_module = @import("matrix.zig");
const mod = @import("mod.zig");
const t = @import("testing.zig");

const Sha256 = t.Sha256;
const Digest = t.Digest;
const PublicKey = t.PublicKey;
const TestAmounts = t.TestAmounts;
const TestState = payment.State(PublicKey, Digest);
const TestRequest = payment.Request(PublicKey, Digest, u64);
const TestStates = payment.States(PublicKey, Digest, u64);
const TestLatest = payment.Latest(PublicKey, Digest, u64);
const TestAdmission = payment.Admission(PublicKey, Digest, u64);
const TestReceipt = payment.Receipt(PublicKey, PublicKey, Digest, u64);
const TestChallenge = payment.Challenge(PublicKey, PublicKey, Digest, u64);
const TestMatrix = matrix_module.Matrix(PublicKey, Sha256, u64);
const gpa = testing.allocator;

/// Alice's countersigned state of epoch 2 committing to `payments` on top of `previous`, or
/// null if `payments` is empty.
fn latest_state(payments: *const TestAmounts, previous: Digest) ?TestState {
    if (payments.is_empty()) return null;
    return .{
        .epoch = 2,
        .account = t.account(0),
        .payments = payments.root(Sha256),
        .previous = previous,
    };
}

/// The states alice signs to pay `batch` in epoch 2 on top of `previous`, where `payments` is
/// her latest countersigned map of epoch 2.
fn states(batch: []const [2]u64, payments: *const TestAmounts, previous: Digest) !TestStates {
    const state = latest_state(payments, previous);
    const latest: ?TestLatest = if (state) |*s| .{ .state = s, .payments = payments } else null;
    const owned = try t.amounts(gpa, batch);
    return TestRequest.states(Sha256, gpa, 2, t.account(0), owned, latest, previous);
}

/// A receipt from a payment map paying two receivers.
fn receipt(namespace: *const mod.Namespace) !TestReceipt {
    var derived = try states(&.{ .{ 2, 4 }, .{ 3, 5 } }, &TestAmounts.empty, t.empty_root());
    defer derived.deinit(gpa);
    const alice = t.user(0);
    const operator = t.operator_key();
    const receipts = (try TestReceipt.issue(
        Sha256,
        gpa,
        derived.current,
        derived.current.sign(&alice, namespace),
        derived.current.acknowledge(&operator, namespace),
        &derived.payments,
        &.{t.account(3)},
    )).?;
    defer gpa.free(receipts);
    try testing.expectEqual(@as(usize, 1), receipts.len);
    return receipts[0];
}

fn expect_admission(actual: *const TestAdmission, expected: *const TestAdmission) !void {
    switch (expected.*) {
        .retry => |state| try testing.expect(actual.* == .retry and actual.retry.eql(state)),
        .new => |new| {
            try testing.expect(actual.* == .new);
            try testing.expect(actual.new.state.eql(new.state));
            try testing.expect(actual.new.payments.eql(&new.payments));
            try testing.expect(actual.new.signature.eql(new.signature));
        },
    }
}

// A request signed from its states verifies in each epoch it has a state for, and the operator
// admits the state the sender derived, with or without earlier payments in the epoch.
test "payment: signed states are admitted" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var before = try t.amounts(gpa, &.{.{ 4, 1 }});
    defer before.deinit(gpa);
    const previous = before.root(Sha256);
    var paid = try t.amounts(gpa, &.{ .{ 1, 3 }, .{ 2, 4 } });
    defer paid.deinit(gpa);
    for ([_]*const TestAmounts{ &TestAmounts.empty, &paid }) |payments| {
        try expect_admitted(&namespace, payments, previous);
    }
}

/// A retry of the countersigned state is admitted as one, whatever its batch.
fn expect_retry(
    namespace: *const mod.Namespace,
    request: *const TestRequest,
    derived: *const TestStates,
    previous: Digest,
) !void {
    var retried = try request.clone(gpa);
    defer retried.deinit(gpa);
    retried.batch.deinit(gpa);
    retried.batch = try t.amounts(gpa, &.{.{ 7, 1 }});
    const countersigned: TestLatest = .{ .state = &derived.current, .payments = &derived.payments };
    const verified = try retried.verify(Sha256, namespace, 2);
    var retry = try verified.admit(Sha256, gpa, countersigned, previous);
    defer retry.deinit(gpa);
    try expect_admission(&retry, &.{ .retry = derived.current });
}

fn expect_admitted(
    namespace: *const mod.Namespace,
    payments: *const TestAmounts,
    previous: Digest,
) !void {
    var derived = try states(&.{ .{ 1, 5 }, .{ 3, 6 } }, payments, previous);
    defer derived.deinit(gpa);
    const alice = t.user(0);
    var signed = try derived.sign(gpa, &alice, namespace);
    defer signed.deinit(gpa);
    var combined = try payments.combine(gpa, &derived.batch);
    defer combined.deinit(gpa);
    try testing.expect(derived.payments.eql(&combined));
    try testing.expect(derived.current.payments.eql(derived.payments.root(Sha256)));
    try testing.expect(derived.next.payments.eql(derived.batch.root(Sha256)));
    try testing.expect(derived.next.previous.eql(payments.root(Sha256)));

    // The request crosses the wire with its distinct claimed roots intact. Decoding refuses a
    // batch beyond the receiver limit and a truncated encoding.
    const encoded = try codec.encode(TestRequest, gpa, signed);
    defer gpa.free(encoded);
    var request = try codec.decode_cfg(TestRequest, gpa, encoded, 2);
    defer request.deinit(gpa);
    try testing.expect(request.eql(&signed));
    try testing.expect(!request.payments.eql(request.previous));
    try testing.expect(!request.payments.eql(request.latest));
    try testing.expectError(error.InvalidLength, codec.decode_cfg(TestRequest, gpa, encoded, 1));
    const truncated = encoded[0 .. encoded.len - 1];
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(TestRequest, gpa, truncated, 2));

    // In its own epoch, the request extends the sender's latest map.
    const state = latest_state(payments, previous);
    const latest: ?TestLatest = if (state) |*s| .{ .state = s, .payments = payments } else null;
    const verified = try request.verify(Sha256, namespace, 2);
    var admission = try verified.admit(Sha256, gpa, latest, previous);
    defer admission.deinit(gpa);
    try expect_admission(&admission, &.{ .new = .{
        .state = derived.current,
        .payments = derived.payments,
        .signature = request.signatures.current,
    } });

    try expect_retry(namespace, &request, &derived, previous);

    // In the next epoch, the request pays only its batch on top of the map the close of its
    // epoch settles. The admission carries the signature over the next state.
    const next = try request.verify(Sha256, namespace, 3);
    var next_admission = try next.admit(Sha256, gpa, null, payments.root(Sha256));
    defer next_admission.deinit(gpa);
    try testing.expect(!request.signatures.next.eql(request.signatures.current));
    try expect_admission(&next_admission, &.{ .new = .{
        .state = derived.next,
        .payments = derived.batch,
        .signature = request.signatures.next,
    } });

    // If the close of its epoch settles the map with the batch added, the next state does not
    // build on the sender's row, so it is never admitted.
    try testing.expectError(
        error.InvalidSignature,
        next.admit(Sha256, gpa, null, derived.current.payments),
    );
}

// A key outside the process signs each state's encoding in the state namespace, and the request
// filled from those signatures is the one an in-process signer produces.
test "payment: external signatures fill the same request" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const signer = t.user(0);
    var paid = try t.amounts(gpa, &.{.{ 2, 1 }});
    defer paid.deinit(gpa);
    var derived = try states(&.{.{ 1, 5 }}, &paid, t.empty_root());
    defer derived.deinit(gpa);
    const current_bytes = try codec.encode(TestState, gpa, derived.current);
    defer gpa.free(current_bytes);
    const next_bytes = try codec.encode(TestState, gpa, derived.next);
    defer gpa.free(next_bytes);
    var external = try derived.request(gpa, .{
        .current = signer.sign(namespace.state, current_bytes),
        .next = signer.sign(namespace.state, next_bytes),
    });
    defer external.deinit(gpa);
    var internal = try derived.sign(gpa, &signer, &namespace);
    defer internal.deinit(gpa);
    try testing.expect(external.eql(&internal));
}

fn derive(
    epoch: mod.Epoch,
    batch: []const [2]u64,
    latest: ?TestLatest,
    previous: Digest,
) !TestStates {
    const owned = try t.amounts(gpa, batch);
    return TestRequest.states(Sha256, gpa, epoch, t.account(0), owned, latest, previous);
}

// States do not derive from an empty batch, an epoch with no successor, an overflowing map, a
// previous root other than the latest state's, or a latest state whose root already holds the
// batch.
test "payment: states refuse unpayable batches" {
    const empty_root = t.empty_root();
    try testing.expectError(error.NoReceivers, derive(2, &.{}, null, empty_root));
    const last = std.math.maxInt(u64);
    try testing.expectError(error.Overflow, derive(last, &.{.{ 1, 1 }}, null, empty_root));
    var full = try t.amounts(gpa, &.{.{ 1, std.math.maxInt(u64) }});
    defer full.deinit(gpa);
    const full_state = latest_state(&full, empty_root).?;
    const at_limit: TestLatest = .{ .state = &full_state, .payments = &full };
    try testing.expectError(error.Overflow, derive(2, &.{.{ 1, 1 }}, at_limit, empty_root));

    // A request that extends a countersigned map on another root could settle that map's
    // payments again.
    var paid = try t.amounts(gpa, &.{.{ 1, 2 }});
    defer paid.deinit(gpa);
    var batch = try t.amounts(gpa, &.{.{ 1, 3 }});
    defer batch.deinit(gpa);
    const paid_state = latest_state(&paid, empty_root).?;
    const record: TestLatest = .{ .state = &paid_state, .payments = &paid };
    const batch_root = batch.root(Sha256);
    try testing.expectError(error.InvalidPrevious, derive(2, &.{.{ 1, 3 }}, record, batch_root));

    // A state that commits to the map with the batch added, given with the map before it, would
    // make the next state build on the map the current state pays.
    var both = try paid.combine(gpa, &batch);
    defer both.deinit(gpa);
    const ahead = latest_state(&both, empty_root).?;
    const stale: TestLatest = .{ .state = &ahead, .payments = &paid };
    try testing.expectError(error.InvalidLatest, derive(2, &.{.{ 1, 3 }}, stale, empty_root));
}

// A request is checked against its own signature before any record of its sender is needed.
test "payment: verify refuses requests the sender did not sign" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var derived = try states(&.{.{ 1, 5 }}, &TestAmounts.empty, t.empty_root());
    defer derived.deinit(gpa);
    const alice = t.user(0);
    var request = try derived.sign(gpa, &alice, &namespace);
    defer request.deinit(gpa);

    // The request has states for its epoch and the next only.
    for ([_]mod.Epoch{ 1, 4 }) |epoch| {
        try testing.expectError(error.WrongEpoch, request.verify(Sha256, &namespace, epoch));
    }

    // A request paying no one is refused, even though its state for its own epoch carries a
    // valid signature.
    var empty = request;
    empty.batch = TestAmounts.empty;
    try testing.expectError(error.NoReceivers, empty.verify(Sha256, &namespace, 2));

    // The signatures cover the account, the claimed roots, the next state's batch, and the
    // deployment.
    var nine = try t.amounts(gpa, &.{.{ 9, 9 }});
    defer nine.deinit(gpa);
    const other = nine.root(Sha256);
    var other_batch = try t.amounts(gpa, &.{.{ 1, 6 }});
    defer other_batch.deinit(gpa);
    var tampered: [5]TestRequest = @splat(request);
    tampered[0].account = t.account(1);
    tampered[1].payments = other;
    tampered[2].previous = other;
    tampered[3].batch = other_batch;
    tampered[4].latest = other;
    const epochs = [_]mod.Epoch{ 2, 2, 2, 3, 3 };
    for (&tampered, epochs) |*forged, epoch| {
        try testing.expectError(error.InvalidSignature, forged.verify(Sha256, &namespace, epoch));
    }
    var elsewhere = try mod.Namespace.init(gpa, "other");
    defer elsewhere.deinit(gpa);
    for ([_]mod.Epoch{ 2, 3 }) |epoch| {
        try testing.expectError(error.InvalidSignature, request.verify(Sha256, &elsewhere, epoch));
    }
}

fn admit_signed(
    namespace: *const mod.Namespace,
    derived: *const TestStates,
    latest: ?TestLatest,
    previous: Digest,
) !TestAdmission {
    const alice = t.user(0);
    var request = try derived.sign(gpa, &alice, namespace);
    defer request.deinit(gpa);
    return (try request.verify(Sha256, namespace, 2)).admit(Sha256, gpa, latest, previous);
}

// The operator admits only the state it would countersign itself.
test "payment: admit refuses states off the record" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const empty_root = t.empty_root();
    var paid = try t.amounts(gpa, &.{.{ 1, 3 }});
    defer paid.deinit(gpa);
    const state = latest_state(&paid, empty_root).?;
    const record: TestLatest = .{ .state = &state, .payments = &paid };

    // A state built on another previous map, a state that does not extend the latest map, and a
    // batch that would overflow the latest map are all refused.
    var four = try t.amounts(gpa, &.{.{ 4, 1 }});
    defer four.deinit(gpa);
    var elsewhere = try states(&.{.{ 1, 5 }}, &paid, four.root(Sha256));
    defer elsewhere.deinit(gpa);
    var stale = try states(&.{.{ 1, 5 }}, &TestAmounts.empty, empty_root);
    defer stale.deinit(gpa);
    for ([_]*const TestStates{ &elsewhere, &stale }) |derived| {
        const refused = admit_signed(&namespace, derived, record, empty_root);
        try testing.expectError(error.InvalidSignature, refused);
    }
    var full = try t.amounts(gpa, &.{.{ 1, std.math.maxInt(u64) }});
    defer full.deinit(gpa);
    var fresh = try states(&.{.{ 1, 1 }}, &TestAmounts.empty, empty_root);
    defer fresh.deinit(gpa);
    var at_limit = state;
    at_limit.payments = full.root(Sha256);
    const full_record: TestLatest = .{ .state = &at_limit, .payments = &full };
    const overflowing = admit_signed(&namespace, &fresh, full_record, empty_root);
    try testing.expectError(error.InvalidSignature, overflowing);

    // The state extending the latest map is admitted.
    var next = try states(&.{.{ 1, 5 }}, &paid, empty_root);
    defer next.deinit(gpa);
    var admission = try admit_signed(&namespace, &next, record, empty_root);
    defer admission.deinit(gpa);
    try testing.expect(admission == .new);
}

// A receipt issued from a countersigned state verifies and round-trips.
test "payment: issued receipts verify" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var issued = try receipt(&namespace);
    defer issued.deinit(gpa);
    const operator = t.operator_key().public_key();
    try testing.expect(issued.verify(Sha256, &namespace, &operator));
    try testing.expectEqual(@as(u64, 5), issued.amount);
    const encoded = try codec.encode(TestReceipt, gpa, issued);
    defer gpa.free(encoded);
    var decoded = try codec.decode(TestReceipt, gpa, encoded);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&issued));
}

// Issuing refuses a map the state does not commit to and a receiver the map does not pay.
test "payment: issue refuses maps that do not commit to the state" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var derived = try states(&.{ .{ 2, 4 }, .{ 3, 5 } }, &TestAmounts.empty, t.empty_root());
    defer derived.deinit(gpa);
    const alice = t.user(0);
    const operator = t.operator_key();
    const signature = derived.current.sign(&alice, &namespace);
    const acknowledgement = derived.current.acknowledge(&operator, &namespace);
    var partial = try t.amounts(gpa, &.{.{ 2, 4 }});
    defer partial.deinit(gpa);
    const issue = struct {
        fn call(
            d: *const TestStates,
            s: t.Signature,
            a: t.Signature,
            map: *const TestAmounts,
            receiver: u64,
        ) !?[]TestReceipt {
            return TestReceipt.issue(Sha256, gpa, d.current, s, a, map, &.{t.account(receiver)});
        }
    }.call;
    try testing.expectEqual(null, try issue(&derived, signature, acknowledgement, &partial, 2));
    const unpaid = try issue(&derived, signature, acknowledgement, &derived.payments, 1);
    try testing.expectEqual(null, unpaid);
    const receipts = (try issue(&derived, signature, acknowledgement, &derived.payments, 2)).?;
    defer {
        for (receipts) |*r| r.deinit(gpa);
        gpa.free(receipts);
    }
    try testing.expectEqual(@as(u64, 4), receipts[0].amount);
}

// A receipt verifies only with its own fields, operator key, and namespace.
test "payment: receipt rejects tampering" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var issued = try receipt(&namespace);
    defer issued.deinit(gpa);
    const operator = t.operator_key().public_key();
    const other = t.account(9);
    var tampered: [6]TestReceipt = @splat(issued);
    tampered[0].amount = issued.amount + 1;
    tampered[1].amount = 0;
    tampered[2].receiver = other;
    tampered[3].position = issued.position ^ 1;
    tampered[4].acknowledgement = issued.signature;
    tampered[5].state.epoch += 1;
    for (&tampered) |*forged| try testing.expect(!forged.verify(Sha256, &namespace, &operator));
    try testing.expect(!issued.verify(Sha256, &namespace, &other));
    var elsewhere = try mod.Namespace.init(gpa, "other");
    defer elsewhere.deinit(gpa);
    try testing.expect(!issued.verify(Sha256, &elsewhere, &operator));
}

// A receipt signed by another account does not verify, even with a valid countersignature.
test "payment: receipt needs the sender signature" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var issued = try receipt(&namespace);
    defer issued.deinit(gpa);
    const operator = t.operator_key().public_key();
    const mallory = t.user(9);
    issued.signature = issued.state.sign(&mallory, &namespace);
    const ack = &issued.acknowledgement;
    try testing.expect(issued.state.verify_acknowledgement(&namespace, &operator, ack));
    try testing.expect(!issued.verify(Sha256, &namespace, &operator));
}

// The operator's countersignature never verifies as the sender's signature, even when the
// operator signs with the sender's key.
test "payment: signatures are domain separated" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var issued = try receipt(&namespace);
    defer issued.deinit(gpa);
    const alice = t.user(0);
    const countersignature = issued.state.acknowledge(&alice, &namespace);
    try testing.expect(!issued.state.verify(&namespace, &countersignature));
    try testing.expect(issued.state.verify(&namespace, &issued.signature));
}

fn matrix_of(sender: PublicKey, pays: []const [2]u64) !TestMatrix {
    const map = try t.amounts(gpa, pays);
    return TestMatrix.from_sorted(gpa, &.{.{ sender, map, map.root(Sha256) }});
}

fn challenge(
    issued: *const TestReceipt,
    value: *const TestMatrix,
    receiver: *const PublicKey,
) !TestChallenge {
    return .{
        .receipt = try issued.clone(gpa),
        .opening = try value.open(gpa, &issued.state.account, receiver),
    };
}

// A challenge is checked against the posted close of its own epoch, and every refusal before the
// receipt's signatures costs only hashes.
test "payment: challenge checks the close before the signatures" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var issued = try receipt(&namespace);
    defer issued.deinit(gpa);
    const operator = t.operator_key().public_key();
    const sender = issued.state.account;
    var underpaying = try matrix_of(sender, &.{.{ 3, 4 }});
    defer underpaying.deinit();
    var paying = try matrix_of(sender, &.{.{ 3, 5 }});
    defer paying.deinit();
    const under_root = underpaying.root();
    const paying_root = paying.root();

    // A receipt the close credits in part contradicts it, and the challenge round-trips.
    var valid = try challenge(&issued, &underpaying, &issued.receiver);
    defer valid.deinit(gpa);
    try valid.verify(Sha256, &namespace, &operator, 2, &under_root);
    const encoded = try codec.encode(TestChallenge, gpa, valid);
    defer gpa.free(encoded);
    var decoded = try codec.decode(TestChallenge, gpa, encoded);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&valid));

    // Neither an earlier nor a later epoch's close is the receipt's.
    for ([_]mod.Epoch{ 0, 1, 3, std.math.maxInt(u64) }) |other| {
        const result = valid.verify(Sha256, &namespace, &operator, other, &under_root);
        try testing.expectError(error.WrongEpoch, result);
    }

    // A receipt whose signatures do not verify is refused only once its opening verifies and the
    // close contradicts it.
    var forged = try issued.clone(gpa);
    defer forged.deinit(gpa);
    forged.signature = t.user(9).sign("forged", "receipt");
    var misopened = try challenge(&forged, &underpaying, &t.account(2));
    defer misopened.deinit(gpa);
    const ns = &namespace;
    const op = &operator;
    try testing.expectError(error.InvalidOpening, misopened.verify(Sha256, ns, op, 2, &under_root));
    var against_under = try challenge(&forged, &underpaying, &forged.receiver);
    defer against_under.deinit(gpa);
    try testing.expectError(
        error.InvalidOpening,
        against_under.verify(Sha256, ns, op, 2, &paying_root),
    );
    var against_paying = try challenge(&forged, &paying, &forged.receiver);
    defer against_paying.deinit(gpa);
    try testing.expectError(
        error.NoContradiction,
        against_paying.verify(Sha256, ns, op, 2, &paying_root),
    );
    try testing.expectError(
        error.InvalidReceipt,
        against_under.verify(Sha256, ns, op, 2, &under_root),
    );
}
