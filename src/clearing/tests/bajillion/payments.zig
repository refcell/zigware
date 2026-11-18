//! Paying and receiving through the operator, without validators or a ledger (commonware
//! `clearing/tests/bajillion/payments.rs`).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const parallel = @import("parallel");
const bajillion = @import("../../bajillion/mod.zig");
const m = @import("main.zig");

const gpa = m.gpa;
const Outcome = m.roles.sender.Outcome;
const Opening = bajillion.Opening(m.PublicKey, m.Digest, u64);
const Matrix = bajillion.Matrix(m.PublicKey, m.Sha256, u64);
const Request = m.TestSender.Request;
const Receipt = m.TestSender.Receipt;

/// The close's matrix root and an opening of `from`'s row in it; the caller frees the opening.
fn open_row(closed: *const m.TestClose, from: u64) !struct { m.Digest, Opening } {
    var matrix = try closed.matrix(m.Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    return .{ matrix.root(), try matrix.open(gpa, &m.account(from), &m.account(from)) };
}

/// Resolves the post of `closed` as the close of `epoch` at `from` with an opening of its row.
fn posted(from: *m.TestSender, index: u64, epoch: m.Epoch, closed: *const m.TestClose) !Outcome {
    const root, var opening = try open_row(closed, index);
    defer opening.deinit(gpa);
    return from.posted(epoch, &root, &opening);
}

/// Closes `op`'s epoch without processing a queued request, dropping the close.
fn close_and_drop(op: *m.TestOperator) !void {
    var closed = try m.close(op);
    closed.deinit(gpa);
}

/// Funds users through `op`, dropping the funding close.
fn fund(op: *m.TestOperator, balances: []const [2]u64) !void {
    var closed = try m.fund(op, balances);
    closed.deinit(gpa);
}

/// Checks that `got` holds exactly `entries`.
fn expect_payments(got: ?*const m.Amounts, entries: []const [2]u64) !void {
    const held = got orelse return error.TestUnexpectedResult;
    var expected = try m.amounts(entries);
    defer expected.deinit(gpa);
    try testing.expect(held.eql(&expected));
}

/// `from` sends `batch` in `epoch`, `op` refuses it with `expected`, and `from` drops it.
fn refuse(
    from: *m.TestSender,
    op: *m.TestOperator,
    epoch: m.Epoch,
    batch: []const [2]u64,
    expected: anyerror,
) !void {
    var request = try from.send(epoch, try m.amounts(batch));
    defer request.deinit(gpa);
    try testing.expectError(expected, op.accept(&request));
    try from.refused();
}

/// An operator in epoch 3, alice, her request of epoch 2 to pay carol 5, and the close of epoch
/// 2. The operator refused the request because alice had paid bob her whole balance of 10, and
/// she dropped it. The close settles her payment to bob and processes a deposit of 5 to her.
const Dropped = struct {
    operator: m.TestOperator,
    alice: m.TestSender,
    refused: Request,
    posted: m.TestClose,

    fn init() !Dropped {
        var operator = try m.operator();
        errdefer operator.deinit();
        try fund(&operator, &.{.{ 0, 10 }});
        var alice = try m.sender(0);
        errdefer alice.deinit();

        // Alice pays bob her whole balance, then asks to pay carol 5. The operator refuses the
        // request. It was delivered only once, so alice drops it.
        _ = try m.pay(&alice, &operator, 2, &.{.{ 1, 10 }});
        var refused = try alice.send(2, try m.amounts(&.{.{ 2, 5 }}));
        errdefer refused.deinit(gpa);
        try testing.expectError(error.InsufficientBalance, operator.accept(&refused));
        try alice.refused();

        // The close of epoch 2 settles her payment to bob and processes a deposit of 5 to her.
        var queues = try m.Queues.init(2, &.{.{ 0, 5 }}, &.{});
        defer queues.deinit();
        var closed = try m.close_epoch(&operator, &queues.queue(), 1, 0);
        errdefer closed.deinit(gpa);
        try testing.expectEqual(@as(u64, 5), operator.balance(&m.account(0)));
        return .{ .operator = operator, .alice = alice, .refused = refused, .posted = closed };
    }

    fn deinit(self: *Dropped) void {
        self.posted.deinit(gpa);
        self.refused.deinit(gpa);
        self.alice.deinit();
        self.operator.deinit();
    }
};

// One request pays several receivers, each receipt carries the cumulative amount paid, and the
// operator's record matches the sender's.
test "payments: payments preconfirm receivers" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();
    var bob = try m.receiver(1, 2);
    defer bob.deinit();
    var carol = try m.receiver(2, 2);
    defer carol.deinit();

    // One request pays both receivers, each of which gets a receipt for its cumulative amount.
    var request = try alice.send(2, try m.amounts(&.{ .{ 1, 10 }, .{ 2, 5 } }));
    defer request.deinit(gpa);
    const acknowledgement = try operator.accept(&request);
    const receipts = try alice.acknowledged(&acknowledgement);
    defer m.free_receipts(receipts);
    try testing.expectEqual(@as(usize, 2), receipts.len);
    for (receipts) |*receipt| {
        if (receipt.receiver.eql(m.account(1))) {
            try testing.expectEqual(@as(u64, 10), try bob.receive(receipt));
        } else {
            try testing.expectEqual(@as(u64, 5), try carol.receive(receipt));
        }
    }

    // Later payments to the same receiver accumulate.
    var later = try alice.send(2, try m.amounts(&.{.{ 1, 7 }}));
    defer later.deinit(gpa);
    const acknowledged = try operator.accept(&later);
    const more = try alice.acknowledged(&acknowledged);
    defer m.free_receipts(more);
    try testing.expectEqual(@as(usize, 1), more.len);
    try testing.expectEqual(@as(u64, 17), try bob.receive(&more[0]));
    try testing.expectEqual(@as(u64, 17), bob.amount(2, &m.account(0)));
    try testing.expectEqual(@as(u64, 5), carol.amount(2, &m.account(0)));
    try expect_payments(alice.payments(2), &.{ .{ 1, 17 }, .{ 2, 5 } });
    try testing.expect(operator.payments(&m.account(0)).?.eql(alice.payments(2).?));
    try testing.expectEqual(@as(u64, 78), operator.live(&m.account(0)));
}

// The operator admits no payment beyond what the sender can still spend, and incoming payments
// become spendable only once a close settles them.
test "payments: operator refuses overdrafts" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 10 }});
    var alice = try m.sender(0);
    defer alice.deinit();

    // Alice spends her 10 in two requests. A request beyond what remains is refused, and she
    // drops it.
    _ = try m.pay(&alice, &operator, 2, &.{.{ 1, 8 }});
    try refuse(&alice, &operator, 2, &.{.{ 1, 3 }}, error.InsufficientBalance);
    try testing.expect(alice.pending() == null);
    _ = try m.pay(&alice, &operator, 2, &.{.{ 1, 2 }});
    try testing.expectEqual(@as(u64, 0), operator.live(&m.account(0)));

    // Incoming payments are not spendable until a close processes them.
    var bob = try m.sender(1);
    defer bob.deinit();
    try refuse(&bob, &operator, 2, &.{.{ 2, 1 }}, error.InsufficientBalance);
    try close_and_drop(&operator);
    try testing.expectEqual(@as(u64, 10), operator.balance(&m.account(1)));
    _ = try m.pay(&bob, &operator, 3, &.{.{ 2, 10 }});
}

// The operator countersigns only a state its sender signed for the current epoch, on top of the
// map the last close settled for the sender.
test "payments: operator refuses states the sender did not sign" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{ .{ 0, 100 }, .{ 1, 100 } });

    // The request must have a state for the current epoch.
    for ([_]m.Epoch{ 3, 4 }) |epoch| {
        var fresh = try m.sender(0);
        defer fresh.deinit();
        var request = try fresh.send(epoch, try m.amounts(&.{.{ 2, 1 }}));
        defer request.deinit(gpa);
        try testing.expectError(error.WrongEpoch, operator.accept(&request));
    }

    // The signature must cover the batch, the account, and the deployment.
    var fresh = try m.sender(0);
    defer fresh.deinit();
    var request = try fresh.send(2, try m.amounts(&.{.{ 2, 1 }}));
    defer request.deinit(gpa);
    var tampered = try request.clone(gpa);
    defer tampered.deinit(gpa);
    tampered.batch.deinit(gpa);
    tampered.batch = try m.amounts(&.{.{ 2, 2 }});
    try testing.expectError(error.InvalidSignature, operator.accept(&tampered));
    var moved = try request.clone(gpa);
    defer moved.deinit(gpa);
    moved.account = m.account(1);
    try testing.expectError(error.InvalidSignature, operator.accept(&moved));
    var other_ns = try bajillion.Namespace.init(gpa, "other");
    defer other_ns.deinit(gpa);
    var other = try m.TestSender.init(gpa, m.user(0), &other_ns, m.operator_key().public_key());
    defer other.deinit();
    var foreign = try other.send(2, try m.amounts(&.{.{ 2, 1 }}));
    defer foreign.deinit(gpa);
    try testing.expectError(error.InvalidSignature, operator.accept(&foreign));

    // The state must extend the map the last close settled for the sender. A sender that lost
    // track of its payments cannot pay on top of a different map.
    var alice = try m.sender(0);
    defer alice.deinit();
    _ = try m.pay(&alice, &operator, 2, &.{.{ 2, 1 }});
    try close_and_drop(&operator);
    var forgetful = try m.sender(0);
    defer forgetful.deinit();
    var lost = try forgetful.send(3, try m.amounts(&.{.{ 2, 1 }}));
    defer lost.deinit(gpa);
    try testing.expectError(error.InvalidSignature, operator.accept(&lost));
    _ = try m.pay(&alice, &operator, 3, &.{.{ 2, 1 }});
}

// The operator refuses a request that pays no receiver, even one its account signed, so no
// close holds a row that validators cannot decode.
test "payments: operator refuses requests that pay no receiver" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const empty_root = m.Amounts.empty.root(m.Sha256);
    const state: bajillion.State(m.PublicKey, m.Digest) = .{
        .epoch = 2,
        .account = m.account(1),
        .payments = empty_root,
        .previous = empty_root,
    };
    var next = state;
    next.epoch = 3;
    const signer = m.user(1);
    const request: Request = .{
        .epoch = 2,
        .account = m.account(1),
        .batch = m.Amounts.empty,
        .previous = state.previous,
        .latest = next.previous,
        .payments = state.payments,
        .signatures = .{ .current = state.sign(&signer, &ns), .next = next.sign(&signer, &ns) },
    };
    try testing.expectError(error.NoReceivers, operator.accept(&request));
    try testing.expect(operator.payments(&m.account(1)) == null);
}

// A retried request is countersigned again without paying twice, and an earlier request is
// neither countersigned nor paid once a later one extended the map.
test "payments: operator acknowledges retried requests once" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();

    // The first acknowledgement is lost, and the sender sends the same request again.
    var first = try alice.send(2, try m.amounts(&.{.{ 1, 10 }}));
    defer first.deinit(gpa);
    _ = try operator.accept(&first);
    const acknowledgement = try operator.accept(alice.pending().?);
    const receipts = try alice.acknowledged(&acknowledgement);
    defer m.free_receipts(receipts);
    try testing.expectEqual(@as(u64, 10), receipts[0].amount);
    try testing.expectEqual(@as(u64, 90), operator.live(&m.account(0)));

    // A retried request that spent the rest of the balance is acknowledged again, and its
    // receipt carries the cumulative amount.
    var second = try alice.send(2, try m.amounts(&.{.{ 1, 90 }}));
    defer second.deinit(gpa);
    _ = try operator.accept(&second);
    try testing.expectEqual(@as(u64, 0), operator.live(&m.account(0)));
    const retried = try operator.accept(&second);
    const again = try alice.acknowledged(&retried);
    defer m.free_receipts(again);
    try testing.expectEqual(@as(u64, 100), again[0].amount);

    // An earlier request is neither acknowledged nor paid again once a later one extended the
    // map.
    try testing.expectError(error.InvalidSignature, operator.accept(&first));
    try expect_payments(operator.payments(&m.account(0)), &.{.{ 1, 100 }});
    try testing.expectEqual(@as(u64, 0), operator.live(&m.account(0)));
}

// A sender keeps one request pending at a time and never signs for an epoch before one it holds
// a countersigned map in.
test "payments: sender rules" {
    // An empty batch is refused, and no request is pending to drop.
    var alice = try m.sender(0);
    defer alice.deinit();
    try testing.expectError(error.NoReceivers, alice.send(1, m.Amounts.empty));
    try testing.expectError(error.NotPending, alice.refused());

    // One request at a time.
    var request = try alice.send(1, try m.amounts(&.{.{ 1, 1 }}));
    defer request.deinit(gpa);
    try testing.expect(alice.pending().?.eql(&request));
    try testing.expectError(error.Pending, alice.send(1, try m.amounts(&.{.{ 1, 1 }})));

    // Never back to an epoch before one the sender has paid in.
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 10 }});
    var paying = try m.sender(0);
    defer paying.deinit();
    _ = try m.pay(&paying, &operator, 2, &.{.{ 1, 1 }});
    try testing.expectError(error.LaterEpoch, paying.send(1, try m.amounts(&.{.{ 1, 1 }})));
    var current = try paying.send(2, try m.amounts(&.{.{ 1, 1 }}));
    current.deinit(gpa);
}

// A sender records a map only on an acknowledgement of its pending state by the deployment's
// operator.
test "payments: sender rejects foreign acknowledgements" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{ .{ 0, 10 }, .{ 1, 10 } });
    var alice = try m.sender(0);
    defer alice.deinit();
    var bob = try m.sender(1);
    defer bob.deinit();

    // An acknowledgement of bob's state does not count for alice's request.
    var request = try alice.send(2, try m.amounts(&.{.{ 2, 1 }}));
    defer request.deinit(gpa);
    var bobs_request = try bob.send(2, try m.amounts(&.{.{ 2, 1 }}));
    defer bobs_request.deinit(gpa);
    const bobs = try operator.accept(&bobs_request);
    try testing.expectError(error.InvalidAcknowledgement, alice.acknowledged(&bobs));

    // An acknowledgement from another operator does not count.
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const impostor_key = m.PrivateKey.from_seed(1_001);
    var impostor = try m.TestOperator.init(gpa, impostor_key, &ns, m.limits);
    defer impostor.deinit();
    try fund(&impostor, &.{.{ 0, 10 }});
    const forged = try impostor.accept(&request);
    try testing.expectError(error.InvalidAcknowledgement, alice.acknowledged(&forged));

    // The operator's own acknowledgement records the map once.
    const acknowledgement = try operator.accept(&request);
    const receipts = try alice.acknowledged(&acknowledgement);
    defer m.free_receipts(receipts);
    try testing.expectEqual(@as(usize, 1), receipts.len);
    try testing.expectError(error.NotPending, alice.acknowledged(&acknowledgement));
}

// A request that reaches the operator after its epoch closed settles in the next, but not once
// its own epoch settled it.
test "payments: request settles in the next epoch" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();
    var bob = try m.receiver(1, 2);
    defer bob.deinit();

    // The request is for epoch 2, but reaches the operator after it closed epoch 2.
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 10 }}));
    defer request.deinit(gpa);
    try close_and_drop(&operator);
    const acknowledgement = try operator.accept(&request);
    const receipts = try alice.acknowledged(&acknowledgement);
    defer m.free_receipts(receipts);
    try testing.expectEqual(@as(m.Epoch, 3), receipts[0].state.epoch);
    try testing.expectEqual(@as(u64, 10), try bob.receive(&receipts[0]));
    try testing.expect(alice.payments(2) == null);
    try expect_payments(alice.payments(3), &.{.{ 1, 10 }});

    // After a request settles in its own epoch, its state for the next epoch does not extend
    // the settled map, so the operator cannot settle it again.
    var later = try alice.send(3, try m.amounts(&.{.{ 1, 5 }}));
    defer later.deinit(gpa);
    m.free_receipts(try alice.acknowledged(&try operator.accept(&later)));
    try close_and_drop(&operator);
    try testing.expectError(error.InvalidSignature, operator.accept(&later));
}

// A posted close settles, drops, or keeps pending the sender's request. The request's
// acknowledgement may have been lost.
test "payments: posted close resolves pending requests" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});

    // The operator admitted the request and the close settles it, but its acknowledgement was
    // lost.
    var alice = try m.sender(0);
    defer alice.deinit();
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 10 }}));
    defer request.deinit(gpa);
    _ = try operator.accept(&request);
    var closed = try m.close(&operator);
    try testing.expectEqual(Outcome.settled, try posted(&alice, 0, 2, &closed));
    closed.deinit(gpa);
    try testing.expect(alice.pending() == null);
    try expect_payments(alice.payments(2), &.{.{ 1, 10 }});

    // A request the close of its epoch did not settle stays pending, because its state for the
    // next epoch may still settle. It is dropped once that epoch's close did not settle it
    // either. Neither close has a row of hers, and she recorded no map of either epoch.
    var third = try alice.send(3, try m.amounts(&.{.{ 1, 10 }}));
    defer third.deinit(gpa);
    closed = try m.close(&operator);
    try testing.expectEqual(Outcome.match, try posted(&alice, 0, 3, &closed));
    closed.deinit(gpa);
    try testing.expect(alice.pending().?.eql(&third));
    closed = try m.close(&operator);
    try testing.expectEqual(Outcome.match, try posted(&alice, 0, 4, &closed));
    closed.deinit(gpa);
    try testing.expect(alice.pending() == null);
    try testing.expect(alice.payments(3) == null);
    try testing.expect(alice.payments(4) == null);

    // The operator admits a request in the epoch after its own, and the sender takes the post
    // only with an opening under the posted root.
    var fifth = try alice.send(5, try m.amounts(&.{.{ 1, 10 }}));
    defer fifth.deinit(gpa);
    closed = try m.close(&operator);
    try testing.expectEqual(Outcome.match, try posted(&alice, 0, 5, &closed));
    closed.deinit(gpa);
    try testing.expect(alice.pending().?.eql(&fifth));
    _ = try operator.accept(&fifth);
    var sixth = try m.close(&operator);
    defer sixth.deinit(gpa);
    const root, var opening = try open_row(&sixth, 0);
    defer opening.deinit(gpa);
    var funding = try m.fund(&operator, &.{.{ 7, 1 }});
    defer funding.deinit(gpa);
    const other, var unused = try open_row(&funding, 0);
    unused.deinit(gpa);
    try testing.expectError(error.InvalidOpening, alice.posted(6, &other, &opening));
    try testing.expectEqual(Outcome.settled, try alice.posted(6, &root, &opening));
    try expect_payments(alice.payments(6), &.{.{ 1, 10 }});
}

// A post drops a pending request once neither of its states can settle. When the close of the
// request's epoch settles a row other than the map its state for the next epoch builds on, the
// sender pays again in the next epoch without waiting for that epoch's close. The post also
// tells her that the close did not settle the map she recorded.
test "payments: posted other row drops request" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();
    _ = try m.pay(&alice, &operator, 2, &.{.{ 1, 5 }});

    // The operator forgets her countersigned map, so the close of epoch 2 has no row of hers.
    // Her pending request extends that map in epoch 2 and builds on it in epoch 3, so neither
    // of its states can settle. The map she recorded did not settle either.
    var pending = try alice.send(2, try m.amounts(&.{.{ 1, 5 }}));
    pending.deinit(gpa);
    operator.forget(&m.account(0));
    var closed = try m.close(&operator);
    defer closed.deinit(gpa);
    try testing.expectEqual(Outcome.conflict, try posted(&alice, 0, 2, &closed));
    try testing.expect(alice.pending() == null);

    // Her next request builds on the posted row, and the operator admits it.
    _ = try m.pay(&alice, &operator, 3, &.{.{ 1, 5 }});
    try expect_payments(alice.payments(3), &.{.{ 1, 5 }});
}

// A post of the epoch before a pending request's own does not drop it, even when the close
// settles a different map of the sender than the one the request builds on. The request's
// state for the epoch after its own builds on a row that has not posted, so it can still
// settle.
test "payments: post before request epoch keeps it pending" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();

    // Alice holds two countersigned maps of epoch 2, the second extending the first. Before
    // the close of epoch 2 posts, she sends a request of epoch 3 on top of the second.
    for (0..2) |_| _ = try m.pay(&alice, &operator, 2, &.{.{ 1, 1 }});
    var request = try alice.send(3, try m.amounts(&.{.{ 1, 1 }}));
    defer request.deinit(gpa);

    // The posted close of epoch 2 settles her first map, so her state of epoch 3 cannot settle.
    // Her state of epoch 4 builds on her row of epoch 3, and that row has not posted. She
    // recorded a second map for epoch 2, and the close did not settle that map.
    var first = try m.row(2, 0, try m.amounts(&.{.{ 1, 1 }}), &m.Amounts.empty);
    defer first.deinit(gpa);
    var queues = try m.Queues.init(2, &.{}, &.{});
    defer queues.deinit();
    const operator_key = m.operator_key();
    var forged = try m.forge(&operator_key, &queues.queue(), &.{first}, &.{}, 0, 0);
    defer forged.deinit(gpa);
    try testing.expectEqual(Outcome.conflict, try posted(&alice, 0, 2, &forged));
    try testing.expect(alice.pending().?.eql(&request));
}

// A post is final for its epoch, so an acknowledgement that arrives after it records nothing
// (S2). The operator countersigns alice's request and forgets the admission before its cut. The
// post leaves the request pending for the next epoch, and the late acknowledgement is refused.
test "payments: acknowledgement after the post records nothing" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();

    // The operator countersigns the request, then forgets the admission before its cut.
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 5 }}));
    defer request.deinit(gpa);
    const late = try operator.accept(&request);
    operator.forget(&m.account(0));
    var closed = try m.close(&operator);
    defer closed.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), closed.rows.len);

    // The close has no row of hers and she recorded no map of epoch 2. Her state of epoch 3
    // builds on the empty map, so the request stays pending.
    try testing.expectEqual(Outcome.match, try posted(&alice, 0, 2, &closed));

    // The acknowledgement of her state of epoch 2 arrives after the post and records nothing.
    try testing.expectError(error.Closed, alice.acknowledged(&late));
    try testing.expect(alice.pending().?.eql(&request));
    try testing.expect(alice.payments(2) == null);
}

// A refusal of a request in its own epoch does not retire its state for the next epoch (S4).
// Once the close settles the map that state builds on, a replayed copy is admitted if the sender
// can afford it. A request for another batch then fails, and a request for the same batch
// repeats the admitted state, so the batch pays once.
test "payments: replayed request settles at most once" {
    var s = try Dropped.init();
    defer s.deinit();

    // Alice resolves the post of epoch 2 before a new request of epoch 3 pays the dropped batch
    // again (S6). The close settled the map she recorded.
    try testing.expectEqual(Outcome.match, try posted(&s.alice, 0, 2, &s.posted));

    // A replayed copy reaches the operator in epoch 3. Its state for epoch 3 builds on the row
    // the close settled and its batch fits her balance, so the operator admits it. Alice has no
    // pending request, so she cannot record its acknowledgement.
    const replayed = try s.operator.accept(&s.refused);
    try expect_payments(s.operator.payments(&m.account(0)), &.{.{ 2, 5 }});
    try testing.expectError(error.NotPending, s.alice.acknowledged(&replayed));

    // A request of hers for another batch does not extend the admitted state and is refused.
    try refuse(&s.alice, &s.operator, 3, &.{.{ 3, 1 }}, error.InvalidSignature);

    // A request for the same batch signs the admitted state, so the operator countersigns it
    // again. Alice's record then holds the map the close of epoch 3 settles, and carol is paid
    // once.
    var again = try s.alice.send(3, try m.amounts(&.{.{ 2, 5 }}));
    defer again.deinit(gpa);
    const acknowledgement = try s.operator.accept(&again);
    try testing.expect(acknowledgement.eql(replayed));
    m.free_receipts(try s.alice.acknowledged(&acknowledgement));
    try expect_payments(s.alice.payments(3), &.{.{ 2, 5 }});
    var closed = try m.close(&s.operator);
    defer closed.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), closed.rows.len);
    try expect_payments(&closed.rows[0].payments, &.{.{ 2, 5 }});
    try testing.expectEqual(@as(u64, 0), s.operator.balance(&m.account(0)));
    try testing.expectEqual(@as(u64, 5), s.operator.balance(&m.account(2)));
}

// A dropped request can still settle, and the post of that epoch tells its sender (S4, S5). A
// copy of alice's dropped request reaches the operator in the next epoch, and that epoch's close
// settles it while she signs nothing. She recorded no map of that epoch, so the post reports a
// conflict, and an opening of the row shows that carol was paid.
test "payments: post reports a dropped request that settled" {
    var s = try Dropped.init();
    defer s.deinit();

    // The close of epoch 2 settled the map alice recorded.
    try testing.expectEqual(Outcome.match, try posted(&s.alice, 0, 2, &s.posted));

    // A copy of the dropped request reaches the operator in epoch 3 and is admitted. Alice signs
    // nothing in epoch 3, and the close of epoch 3 settles the batch she dropped.
    _ = try s.operator.accept(&s.refused);
    var closed = try m.close(&s.operator);
    defer closed.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), closed.rows.len);
    try expect_payments(&closed.rows[0].payments, &.{.{ 2, 5 }});
    try testing.expect(s.alice.payments(3) == null);

    // The post of epoch 3 proves a row she recorded no map for. An opening of carol's entry
    // shows the payment a new request must not make again.
    const root, var opening = try open_row(&closed, 0);
    defer opening.deinit(gpa);
    try testing.expectEqual(Outcome.conflict, try s.alice.posted(3, &root, &opening));
    var matrix = try closed.matrix(m.Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    var entry = try matrix.open(gpa, &m.account(0), &m.account(2));
    defer entry.deinit(gpa);
    const paid = try entry.verify(m.Sha256, &root, &m.account(0), &m.account(2));
    try testing.expectEqual(@as(u64, 5), paid);
}

// A posted row settles a request only if it matches the request's state for the row's epoch.
// The state for the next epoch pays only the batch, so a close of the request's own epoch that
// settles an earlier map equal to the batch leaves it pending, and the next close settles it.
test "payments: state settles only in its own epoch" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();
    _ = try m.pay(&alice, &operator, 2, &.{.{ 1, 10 }});

    // Her request paying bob 10 more reaches the operator after it closed epoch 2. That close
    // settles her map paying bob 10, the same map her state for epoch 3 commits to.
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 10 }}));
    defer request.deinit(gpa);
    var closed = try m.close(&operator);
    try testing.expectEqual(Outcome.match, try posted(&alice, 0, 2, &closed));
    closed.deinit(gpa);
    try testing.expect(alice.pending().?.eql(&request));
    try expect_payments(alice.payments(2), &.{.{ 1, 10 }});

    // The operator admits it in epoch 3, and the close of epoch 3 settles it.
    _ = try operator.accept(&request);
    closed = try m.close(&operator);
    defer closed.deinit(gpa);
    try testing.expectEqual(Outcome.settled, try posted(&alice, 0, 3, &closed));
    try expect_payments(alice.payments(3), &.{.{ 1, 10 }});
}

// An operator admits no more senders, receivers in one sender's payment map, or soft
// withdrawals in an epoch than its limits allow. Requests within them still succeed, and the
// close it builds at the limits decodes with them.
test "payments: operator admits within its limits" {
    const limits: bajillion.Limits = .{ .rows = 2, .receivers = 2, .withdrawals = 1 };
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    var operator = try m.TestOperator.init(gpa, m.operator_key(), &ns, limits);
    defer operator.deinit();
    try fund(&operator, &.{ .{ 0, 100 }, .{ 1, 100 }, .{ 2, 100 } });
    var alice = try m.sender(0);
    defer alice.deinit();
    var bob = try m.sender(1);
    defer bob.deinit();
    var carol = try m.sender(2);
    defer carol.deinit();

    // Alice pays two receivers and bob one, filling the senders and alice's map.
    _ = try m.pay(&alice, &operator, 2, &.{ .{ 1, 5 }, .{ 2, 5 } });
    var retried = try bob.send(2, try m.amounts(&.{.{ 0, 5 }}));
    defer retried.deinit(gpa);
    m.free_receipts(try bob.acknowledged(&try operator.accept(&retried)));

    // A third sender, or a third receiver in alice's map, would not fit the close.
    try refuse(&carol, &operator, 2, &.{.{ 0, 5 }}, error.Full);
    try refuse(&alice, &operator, 2, &.{.{ 3, 1 }}, error.Full);

    // A request the account did not sign is refused as unsigned even when it would not fit, so
    // the refusal does not reveal which accounts pay or how many receivers they paid.
    var impostor = try m.sender(9);
    defer impostor.deinit();
    for ([_][2]u64{ .{ 2, 0 }, .{ 0, 3 } }) |pair| {
        var request = try impostor.send(2, try m.amounts(&.{.{ pair[1], 1 }}));
        defer request.deinit(gpa);
        request.account = m.account(pair[0]);
        try testing.expectError(error.InvalidSignature, operator.accept(&request));
        try impostor.refused();
    }

    // Alice still pays a receiver she paid, and a retried request is acknowledged again.
    _ = try m.pay(&alice, &operator, 2, &.{.{ 1, 1 }});
    _ = try operator.accept(&retried);

    // A withdrawal the account did not sign is refused as unsigned while room is left.
    const zero = m.user(0);
    const one = m.user(1);
    const nine = m.user(9);
    var forged = m.Withdrawal.sign(&nine, &ns, 2, 10, 0);
    forged.account = m.account(1);
    try testing.expectError(error.InvalidWithdrawal, operator.withdraw(forged));

    // A soft withdrawal of another epoch is refused with room left, so it never reaches a
    // close that validators would refuse.
    for ([_]m.Epoch{ 1, 3 }) |epoch| {
        const stale = m.Withdrawal.sign(&zero, &ns, epoch, 10, 0);
        try testing.expectError(error.WrongEpoch, operator.withdraw(stale));
    }

    // One soft withdrawal fills the epoch's, so another account's is refused as full. The
    // forged one is still refused as unsigned, and collecting the admitted one again has no
    // effect.
    const withdrawal = m.Withdrawal.sign(&zero, &ns, 2, 10, 0);
    try operator.withdraw(withdrawal);
    const other = m.Withdrawal.sign(&one, &ns, 2, 10, 0);
    try testing.expectError(error.Full, operator.withdraw(other));
    try testing.expectError(error.InvalidWithdrawal, operator.withdraw(forged));
    try operator.withdraw(withdrawal);

    // The close at the limits decodes with them.
    var closed = try m.close(&operator);
    defer closed.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), closed.rows.len);
    try testing.expectEqual(@as(usize, 1), closed.withdrawals.len);
    const encoded = try codec.encode(m.TestClose, gpa, closed);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(m.TestClose, gpa, encoded, limits);
    defer decoded.deinit(gpa);
    try testing.expect(try m.closes_equal(&decoded, &closed));
}

/// Checks that `op` refuses `request` as unsigned without reading any record.
fn refused_unread(op: *m.TestOperator, request: *const Request) !void {
    const reads = op.reads();
    try testing.expectError(error.InvalidSignature, op.accept(request));
    try testing.expectEqual(reads, op.reads());
}

// A request the account did not sign is refused for its signature alone, before the operator
// reads any record of the account, so the refusal is the same whatever the account holds or
// paid. That holds for amounts the account can and cannot pay, for a state of the next epoch,
// and for a batch that would overflow its map.
test "payments: unsigned requests are refused before any read" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 10 }});

    // An impostor signs requests for alice's account, for amounts she can and cannot pay, in
    // the current epoch and as the next state of a request for the epoch before.
    var impostor = try m.sender(9);
    defer impostor.deinit();
    for ([_][2]u64{ .{ 2, 5 }, .{ 2, 11 }, .{ 1, 5 } }) |pair| {
        var request = try impostor.send(pair[0], try m.amounts(&.{.{ 1, pair[1] }}));
        defer request.deinit(gpa);
        request.account = m.account(0);
        try refused_unread(&operator, &request);
        try impostor.refused();
    }

    // Alice's own request reads her records. Once she has paid, a forged batch that would
    // overflow her map is refused alike.
    var alice = try m.sender(0);
    defer alice.deinit();
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 3 }}));
    defer request.deinit(gpa);
    const reads = operator.reads();
    m.free_receipts(try alice.acknowledged(&try operator.accept(&request)));
    try testing.expect(operator.reads() > reads);
    const max = std.math.maxInt(u64);
    var overflowing = try impostor.send(2, try m.amounts(&.{.{ 1, max }}));
    defer overflowing.deinit(gpa);
    overflowing.account = m.account(0);
    try refused_unread(&operator, &overflowing);
    try expect_payments(operator.payments(&m.account(0)), &.{.{ 1, 3 }});
}

/// Alice restarted from a copy of what `from` persisted.
fn restart_alice(from: *const m.TestSender) !m.TestSender {
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    var persisted = try from.persisted.clone(gpa);
    errdefer persisted.deinit(gpa);
    return m.TestSender.restart(gpa, m.user(0), &ns, m.operator_key().public_key(), persisted);
}

// A sender restarted from what it persisted still awaits its pending request. After the
// acknowledgement, a restart issues the same receipts again from the countersigned state, both
// signatures, and the map the sender recorded, and pays on top of that map.
test "payments: sender restarts from its records" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();

    // The request is persisted before it is sent.
    var request = try alice.send(2, try m.amounts(&.{ .{ 1, 10 }, .{ 2, 5 } }));
    defer request.deinit(gpa);
    var restarted = try restart_alice(&alice);
    defer restarted.deinit();
    try testing.expect(restarted.pending().?.eql(&request));
    const receipts = try restarted.acknowledged(&try operator.accept(&request));
    defer m.free_receipts(receipts);

    // The acknowledgement is persisted with the request cleared, before any receipt is
    // released.
    var again = try restart_alice(&restarted);
    defer again.deinit();
    try testing.expect(again.pending() == null);
    var receivers: [2]m.PublicKey = undefined;
    for (receipts, &receivers) |*receipt, *receiver| receiver.* = receipt.receiver;
    const reissued = try again.receipts(2, &receivers);
    defer m.free_receipts(reissued);
    try testing.expectEqual(receipts.len, reissued.len);
    for (receipts, reissued) |*a, *b| try testing.expect(a.eql(b));
    _ = try m.pay(&again, &operator, 2, &.{.{ 1, 1 }});
    try expect_payments(again.payments(2), &.{ .{ 1, 11 }, .{ 2, 5 } });
}

// A receiver relies only on a verified receipt that pays it, in an epoch whose close has not
// posted, before a halt, and only if it raises the amount held.
test "payments: receiver rejects receipts it cannot rely on" {
    // Alice pays bob 10 and carol 5 in one request.
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();
    var request = try alice.send(2, try m.amounts(&.{ .{ 1, 10 }, .{ 2, 5 } }));
    defer request.deinit(gpa);
    const receipts = try alice.acknowledged(&try operator.accept(&request));
    defer m.free_receipts(receipts);
    const bob_index: usize = if (receipts[0].receiver.eql(m.account(1))) 0 else 1;
    const for_bob = &receipts[bob_index];
    const for_carol = &receipts[1 - bob_index];

    // Bob refuses carol's receipt and a raised amount, and a receiver expecting another
    // operator refuses his. He relies on his own once, and refuses it again as not increasing.
    var bob = try m.receiver(1, 2);
    defer bob.deinit();
    try testing.expectError(error.WrongReceiver, bob.receive(for_carol));
    var tampered = try for_bob.clone(gpa);
    defer tampered.deinit(gpa);
    tampered.amount += 1;
    try testing.expectError(error.InvalidReceipt, bob.receive(&tampered));
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const other_operator = m.PrivateKey.from_seed(1_001).public_key();
    var misled = try m.TestReceiver.init(gpa, m.account(1), &ns, other_operator, 2);
    defer misled.deinit();
    try testing.expectError(error.InvalidReceipt, misled.receive(for_bob));
    try testing.expectEqual(@as(u64, 10), try bob.receive(for_bob));
    try testing.expectError(error.NotIncreasing, bob.receive(for_bob));

    // Once bob holds 10 from alice, a receipt he cannot rely on is refused for that reason
    // alone, so the refusal reveals nothing about what he holds.
    var forged = try for_bob.clone(gpa);
    defer forged.deinit(gpa);
    forged.amount = 5;
    const nine = m.user(9);
    forged.signature = nine.sign("forged", "receipt");
    forged.acknowledgement = nine.sign("forged", "receipt");
    try testing.expectError(error.InvalidReceipt, bob.receive(&forged));
    try testing.expectError(error.WrongReceiver, bob.receive(for_carol));

    // Bob audits epoch 2 only once he records that its close posted.
    var empty = try Matrix.empty(gpa);
    defer empty.deinit();
    var opening = try empty.open(gpa, &m.account(0), &m.account(1));
    defer opening.deinit(gpa);
    const empty_root = empty.root();
    try testing.expectError(error.NotClosed, bob.audit(2, &empty_root, &m.account(0), &opening));

    // A receiver rejects receipts for an epoch whose close posted, and every receipt once the
    // ledger halts.
    var late = try m.receiver(1, 2);
    defer late.deinit();
    late.posted(2);
    try testing.expectError(error.Closed, late.receive(for_bob));
    var halted = try m.receiver(1, 2);
    defer halted.deinit();
    halted.halt();
    try testing.expectError(error.Halted, halted.receive(for_bob));
}

/// User `index` receiving, resumed from `halted` and the receipts `held`.
fn resume_receiver(index: u64, next: m.Epoch, halted: bool, held: []const Receipt) !m.TestReceiver {
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const operator = m.operator_key().public_key();
    return m.TestReceiver.resume_from(gpa, m.account(index), &ns, operator, next, halted, held);
}

// A receiver resumes from its persisted receipts, in any order, keeping the largest from each
// sender, its recorded halt, and receipts of closed epochs. It refuses receipts that pay
// another account.
test "payments: resumed receiver keeps its strongest receipts and halt" {
    var operator = try m.operator();
    defer operator.deinit();
    try fund(&operator, &.{.{ 0, 100 }});
    var alice = try m.sender(0);
    defer alice.deinit();
    var first = try alice.send(2, try m.amounts(&.{.{ 1, 10 }}));
    defer first.deinit(gpa);
    const lowers = try alice.acknowledged(&try operator.accept(&first));
    defer m.free_receipts(lowers);
    var second = try alice.send(2, try m.amounts(&.{.{ 1, 5 }}));
    defer second.deinit(gpa);
    const uppers = try alice.acknowledged(&try operator.accept(&second));
    defer m.free_receipts(uppers);
    const lower = &lowers[lowers.len - 1];
    const upper = &uppers[uppers.len - 1];

    // Receipts restored in any order keep the largest amount from each sender.
    for ([_][2]Receipt{ .{ upper.*, lower.* }, .{ lower.*, upper.* } }) |held| {
        var bob = try resume_receiver(1, 2, false, &held);
        defer bob.deinit();
        try testing.expectEqual(@as(u64, 15), bob.amount(2, &m.account(0)));
        try testing.expectError(error.NotIncreasing, bob.receive(lower));
    }

    // A receiver that saw the ledger halt keeps refusing receipts after resuming.
    var halted = try resume_receiver(1, 2, true, &.{lower.*});
    defer halted.deinit();
    try testing.expectError(error.Halted, halted.receive(upper));

    // Receipts of an epoch whose close posted are kept for its audit, and none pays another
    // account.
    var bob = try resume_receiver(1, 3, false, &.{lower.*});
    defer bob.deinit();
    try testing.expectEqual(@as(u64, 10), bob.amount(2, &m.account(0)));
    try testing.expectError(error.WrongReceiver, resume_receiver(2, 3, false, &.{lower.*}));
}

// A post updates the sender only with a valid opening of its row, even a post of an epoch its
// pending request does not involve.
test "payments: posted close needs a valid opening" {
    var alice = try m.sender(0);
    defer alice.deinit();
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 5 }}));
    defer request.deinit(gpa);
    var queues = try m.Queues.init(1, &.{}, &.{});
    defer queues.deinit();
    var paying = try m.row(1, 0, try m.amounts(&.{.{ 1, 7 }}), &m.Amounts.empty);
    defer paying.deinit(gpa);
    const operator_key = m.operator_key();
    var forged = try m.forge(&operator_key, &queues.queue(), &.{paying}, &.{}, 0, 0);
    defer forged.deinit(gpa);
    var populated = try forged.matrix(m.Sha256, gpa, parallel.sequential);
    defer populated.deinit();
    var empty = try Matrix.empty(gpa);
    defer empty.deinit();
    var opening = try populated.open(gpa, &m.account(0), &m.account(1));
    defer opening.deinit(gpa);
    const empty_root = empty.root();
    try testing.expectError(error.InvalidOpening, alice.posted(1, &empty_root, &opening));
    try testing.expect(alice.pending() != null);
}
